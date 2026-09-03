//! Dashboard data - fetches and stores cluster information

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
use kube::api::GroupVersionKind;
use kube::discovery::Discovery;
use kube::{Api, Client};

use crate::kube_client;
use std::collections::{HashMap, HashSet};

/// All dashboard data
#[derive(Clone, Debug, Default)]
pub struct DashboardData {
    pub cluster_info: ClusterInfo,
    pub nodes: Vec<NodeInfo>,
    pub namespaces: Vec<NamespaceInfo>,
    pub security: SecurityOverview,
    pub finops: FinOpsOverview,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub provider_configs: Vec<ProviderConfigInfo>,
    pub auth_providers: Vec<AuthProviderInfo>,
    pub rightsizing: Vec<RightsizingRec>,
}

impl DashboardData {
    /// Load all dashboard data from the cluster
    pub async fn load() -> anyhow::Result<Self> {
        let client = kube_client::client().await?;

        // One discovery scan up front so every dynamic-CRD lookup can skip
        // missing GVKs instead of triggering 404s through the kube client.
        let discovery = Discovery::new(client.clone()).run().await?;

        let cluster_info = Self::load_cluster_info(&client).await?;
        let nodes = Self::load_nodes(&client).await?;
        let namespaces = Self::load_namespaces(&client).await?;
        let security = Self::load_security_overview(&client, &discovery).await?;
        let finops = Self::calculate_finops(&client, &discovery, &nodes, &namespaces).await?;
        let vulnerabilities = Self::load_vulnerabilities(&client, &discovery).await?;
        let provider_configs = Self::load_provider_configs(&client, &discovery).await?;
        let auth_providers = Self::load_auth_providers(&client, &discovery).await?;
        let rightsizing = Self::load_rightsizing(&client, &discovery).await;

        Ok(Self {
            cluster_info,
            nodes,
            namespaces,
            security,
            finops,
            vulnerabilities,
            provider_configs,
            auth_providers,
            rightsizing,
        })
    }

    async fn load_cluster_info(client: &Client) -> anyhow::Result<ClusterInfo> {
        let nodes: Api<Node> = Api::all(client.clone());
        let node_list = nodes.list(&Default::default()).await?;

        let namespaces: Api<Namespace> = Api::all(client.clone());
        let ns_list = namespaces.list(&Default::default()).await?;

        let pods: Api<Pod> = Api::all(client.clone());
        let pod_list = pods.list(&Default::default()).await?;

        let running_pods = pod_list
            .items
            .iter()
            .filter(|p| {
                p.status
                    .as_ref()
                    .and_then(|s| s.phase.as_ref())
                    .map(|p| p == "Running")
                    .unwrap_or(false)
            })
            .count();

        // Get cluster version from first node
        let version = node_list
            .items
            .first()
            .and_then(|n| n.status.as_ref())
            .and_then(|s| s.node_info.as_ref())
            .map(|i| i.kubelet_version.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        // Detect provider from node labels
        let provider = node_list
            .items
            .first()
            .and_then(|n| n.metadata.labels.as_ref())
            .map(|labels| {
                if labels.contains_key("eks.amazonaws.com/nodegroup") {
                    "AWS EKS".to_string()
                } else if labels.contains_key("cloud.google.com/gke-nodepool") {
                    "Google GKE".to_string()
                } else if labels.contains_key("kubernetes.azure.com/cluster") {
                    "Azure AKS".to_string()
                } else if labels.contains_key("minikube.k8s.io/name") {
                    "Minikube".to_string()
                } else if labels.contains_key("node.kubernetes.io/instance-type") {
                    "Kind".to_string()
                } else {
                    "Unknown".to_string()
                }
            })
            .unwrap_or_else(|| "Unknown".to_string());

        Ok(ClusterInfo {
            name: "current-context".to_string(), // TODO: Get from kubeconfig
            version,
            provider,
            node_count: node_list.items.len(),
            namespace_count: ns_list.items.len(),
            pod_count: pod_list.items.len(),
            running_pods,
            status: ClusterStatus::Healthy,
        })
    }

    async fn load_nodes(client: &Client) -> anyhow::Result<Vec<NodeInfo>> {
        let nodes: Api<Node> = Api::all(client.clone());
        let node_list = nodes.list(&Default::default()).await?;

        let mut result = Vec::new();
        for node in node_list.items {
            let name = node.metadata.name.clone().unwrap_or_default();
            let labels = node.metadata.labels.clone().unwrap_or_default();

            let status = node.status.as_ref();
            let conditions = status.and_then(|s| s.conditions.as_ref());

            let ready = conditions
                .map(|c| {
                    c.iter()
                        .any(|cond| cond.type_ == "Ready" && cond.status == "True")
                })
                .unwrap_or(false);

            let allocatable = status.and_then(|s| s.allocatable.as_ref());
            let cpu_allocatable = allocatable
                .and_then(|a| a.get("cpu"))
                .map(|q| q.0.clone())
                .unwrap_or_else(|| "0".to_string());
            let memory_allocatable = allocatable
                .and_then(|a| a.get("memory"))
                .map(|q| q.0.clone())
                .unwrap_or_else(|| "0".to_string());

            let node_info = status.and_then(|s| s.node_info.as_ref());
            let os = node_info
                .map(|i| i.os_image.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            let container_runtime = node_info
                .map(|i| i.container_runtime_version.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            let instance_type = labels
                .get("node.kubernetes.io/instance-type")
                .cloned()
                .or_else(|| labels.get("beta.kubernetes.io/instance-type").cloned())
                .unwrap_or_else(|| "Unknown".to_string());

            let zone = labels
                .get("topology.kubernetes.io/zone")
                .cloned()
                .or_else(|| {
                    labels
                        .get("failure-domain.beta.kubernetes.io/zone")
                        .cloned()
                })
                .unwrap_or_else(|| "Unknown".to_string());

            result.push(NodeInfo {
                name,
                status: if ready {
                    NodeStatus::Ready
                } else {
                    NodeStatus::NotReady
                },
                cpu_allocatable,
                memory_allocatable,
                cpu_usage: 0.0,    // Would need metrics-server
                memory_usage: 0.0, // Would need metrics-server
                pod_count: 0,      // Would need to count per node
                instance_type,
                zone,
                os,
                container_runtime,
                labels: labels.into_iter().collect(),
            });
        }

        Ok(result)
    }

    async fn load_namespaces(client: &Client) -> anyhow::Result<Vec<NamespaceInfo>> {
        let namespaces: Api<Namespace> = Api::all(client.clone());
        let ns_list = namespaces.list(&Default::default()).await?;

        let pods: Api<Pod> = Api::all(client.clone());
        let pod_list = pods.list(&Default::default()).await?;

        // Count pods per namespace
        let mut pod_counts: HashMap<String, usize> = HashMap::new();
        for pod in &pod_list.items {
            let ns = pod
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            *pod_counts.entry(ns).or_insert(0) += 1;
        }

        let mut result = Vec::new();
        for ns in ns_list.items {
            let name = ns.metadata.name.clone().unwrap_or_default();
            let labels = ns.metadata.labels.clone().unwrap_or_default();

            let status = ns
                .status
                .as_ref()
                .and_then(|s| s.phase.as_ref())
                .map(|p| {
                    if p == "Active" {
                        NamespaceStatus::Active
                    } else {
                        NamespaceStatus::Terminating
                    }
                })
                .unwrap_or(NamespaceStatus::Active);

            result.push(NamespaceInfo {
                name: name.clone(),
                status,
                pod_count: *pod_counts.get(&name).unwrap_or(&0),
                labels: labels.into_iter().collect(),
            });
        }

        Ok(result)
    }

    /// Load real security findings from the Policy Reports Working Group CRD
    /// (`wgpolicyk8s.io/v1alpha2`). Kyverno, Trivy, Falco, and others all
    /// write to this group, so a single query covers every installed source.
    ///
    /// Returns empty when the CRD isn't present (cluster has no policy
    /// engine) — Discovery-gated like every other dynamic loader.
    async fn load_security_overview(
        client: &Client,
        discovery: &Discovery,
    ) -> anyhow::Result<SecurityOverview> {
        use kube::api::DynamicObject;

        const MAX_ISSUES: usize = 500;

        let mut issues: Vec<SecurityIssue> = Vec::new();

        // Namespaced PolicyReports — one per workload in most installs.
        if let Some(ar) = Self::resolve_gvk(discovery, "wgpolicyk8s.io", "v1alpha2", "PolicyReport")
        {
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
            if let Ok(list) = api.list(&Default::default()).await {
                for report in list.items {
                    issues.extend(extract_policy_findings(&report));
                }
            }
        }

        // Cluster-scoped PolicyReports — cluster-policy violations.
        if let Some(ar) = Self::resolve_gvk(
            discovery,
            "wgpolicyk8s.io",
            "v1alpha2",
            "ClusterPolicyReport",
        ) {
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
            if let Ok(list) = api.list(&Default::default()).await {
                for report in list.items {
                    issues.extend(extract_policy_findings(&report));
                }
            }
        }

        // Severity-desc, then keep the worst N for table size sanity.
        issues.sort_by_key(|i| severity_rank(&i.severity));
        issues.truncate(MAX_ISSUES);

        let critical = issues
            .iter()
            .filter(|i| i.severity == Severity::Critical)
            .count() as u32;
        let high = issues
            .iter()
            .filter(|i| i.severity == Severity::High)
            .count() as u32;
        // Score = simple traffic-light view; weighted critical/high higher.
        // 100 = no findings, 0 = lots. Real, not fabricated.
        let weighted = (critical * 10 + high * 3 + (issues.len() as u32 - critical - high)) as i64;
        let score = (100i64 - weighted).clamp(0, 100) as u32;

        Ok(SecurityOverview {
            score,
            issues,
            last_scan: Some(chrono::Utc::now().to_rfc3339()),
        })
    }

    async fn load_vulnerabilities(
        client: &Client,
        discovery: &Discovery,
    ) -> anyhow::Result<Vec<VulnerabilityInfo>> {
        use kube::api::DynamicObject;

        /// Cap output — a real cluster easily has thousands of findings;
        /// the dashboard only needs the worst N.
        const MAX_VULNS: usize = 200;

        let Some(api_resource) = Self::resolve_gvk(
            discovery,
            "aquasecurity.github.io",
            "v1alpha1",
            "VulnerabilityReport",
        ) else {
            return Ok(vec![]);
        };
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

        let list = match api.list(&Default::default()).await {
            Ok(l) => l,
            Err(_) => return Ok(vec![]),
        };

        let mut out: Vec<VulnerabilityInfo> = Vec::new();
        for report in list.items {
            let owner_ns = report.metadata.namespace.clone().unwrap_or_default();
            let resource_label = report
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get("trivy-operator.resource.name").cloned())
                .unwrap_or_else(|| report.metadata.name.clone().unwrap_or_default());
            let image = report
                .data
                .pointer("/report/artifact/repository")
                .and_then(|v| v.as_str())
                .map(|repo| {
                    let tag = report
                        .data
                        .pointer("/report/artifact/tag")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if tag.is_empty() {
                        repo.to_string()
                    } else {
                        format!("{repo}:{tag}")
                    }
                })
                .unwrap_or_default();

            let Some(vulns) = report
                .data
                .pointer("/report/vulnerabilities")
                .and_then(|v| v.as_array())
            else {
                continue;
            };

            for v in vulns {
                let severity = match v.get("severity").and_then(|s| s.as_str()).unwrap_or("") {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MEDIUM" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Info,
                };
                out.push(VulnerabilityInfo {
                    id: v
                        .get("vulnerabilityID")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string(),
                    severity,
                    package: v
                        .get("resource")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string(),
                    installed_version: v
                        .get("installedVersion")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string(),
                    fixed_version: v
                        .get("fixedVersion")
                        .and_then(|s| s.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                    image: image.clone(),
                    resource: if owner_ns.is_empty() {
                        resource_label.clone()
                    } else {
                        format!("{owner_ns}/{resource_label}")
                    },
                    description: v
                        .get("title")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }

        // Worst first, then cap.
        out.sort_by_key(|v| match v.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Warning => 3,
            Severity::Low => 4,
            Severity::Info => 5,
        });
        out.truncate(MAX_VULNS);
        Ok(out)
    }

    /// Load VPA recommendations (the data Goldilocks exposes in its UI).
    /// Goldilocks creates a VPA in `Off` mode per opted-in workload; the
    /// VPA recommender writes its sizing suggestions to
    /// `.status.recommendation.containerRecommendations[]`. We list those,
    /// then join against Deployments (current requests/limits, init markers)
    /// and HPAs (conflict detection) so each row is actionable in isolation.
    async fn load_rightsizing(client: &Client, discovery: &Discovery) -> Vec<RightsizingRec> {
        use kube::api::DynamicObject;

        let Some(vpa_ar) = Self::resolve_gvk(
            discovery,
            "autoscaling.k8s.io",
            "v1",
            "VerticalPodAutoscaler",
        ) else {
            return vec![];
        };
        let vpa_api: Api<DynamicObject> = Api::all_with(client.clone(), &vpa_ar);
        let Ok(vpas) = vpa_api.list(&Default::default()).await else {
            return vec![];
        };

        // (ns, kind, name, container) → current requests/limits.
        // Also (ns, kind, name, container) → is-init-container? for role flagging.
        let mut current: HashMap<(String, String, String, String), CurrentResources> =
            HashMap::new();
        let mut init_containers: HashSet<(String, String, String, String)> = HashSet::new();
        let deploy_api: Api<Deployment> = Api::all(client.clone());
        if let Ok(deploys) = deploy_api.list(&Default::default()).await {
            for d in deploys.items {
                let ns = d.metadata.namespace.clone().unwrap_or_default();
                let name = d.metadata.name.clone().unwrap_or_default();
                let kind = "Deployment".to_string();
                let Some(spec) = d.spec else { continue };
                let pod_spec = spec.template.spec;
                if let Some(pod_spec) = pod_spec {
                    for c in pod_spec.containers {
                        let cur = CurrentResources::from_container_resources(c.resources.as_ref());
                        current.insert((ns.clone(), kind.clone(), name.clone(), c.name), cur);
                    }
                    for c in pod_spec.init_containers.unwrap_or_default() {
                        init_containers.insert((
                            ns.clone(),
                            kind.clone(),
                            name.clone(),
                            c.name.clone(),
                        ));
                        let cur = CurrentResources::from_container_resources(c.resources.as_ref());
                        current.insert((ns.clone(), kind.clone(), name.clone(), c.name), cur);
                    }
                }
            }
        }

        // (ns, kind, name) → ["cpu", "memory"] resources the HPA scales on.
        // Used to badge VPA recommendations as HPA-conflicting (acting on a
        // VPA cpu rec for a workload with a CPU HPA is a footgun).
        let mut hpa_conflicts: HashMap<(String, String, String), Vec<String>> = HashMap::new();
        let hpa_api: Api<HorizontalPodAutoscaler> = Api::all(client.clone());
        if let Ok(hpas) = hpa_api.list(&Default::default()).await {
            for hpa in hpas.items {
                let ns = hpa.metadata.namespace.unwrap_or_default();
                let spec = hpa.spec;
                let target = spec.scale_target_ref;
                let mut resources: Vec<String> = Vec::new();
                if let Some(metrics) = spec.metrics {
                    for m in metrics {
                        if let Some(r) = m.resource {
                            resources.push(r.name);
                        }
                    }
                }
                if !resources.is_empty() {
                    hpa_conflicts.insert((ns, target.kind, target.name), resources);
                }
            }
        }

        let now = chrono::Utc::now();
        let mut out: Vec<RightsizingRec> = Vec::new();
        for vpa in vpas.items {
            let ns = vpa.metadata.namespace.clone().unwrap_or_default();
            let target_ref = vpa.data.pointer("/spec/targetRef");
            let workload_kind = target_ref
                .and_then(|t| t.get("kind"))
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let workload = target_ref
                .and_then(|t| t.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();

            // VPA condition parsing: LowConfidence + RecommendationProvided
            // dictate the freshness signal users need before applying.
            let mut low_confidence = false;
            let mut last_update_age_secs: Option<u64> = None;
            if let Some(conds) = vpa
                .data
                .pointer("/status/conditions")
                .and_then(|v| v.as_array())
            {
                for c in conds {
                    let typ = c.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let status = c.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    match (typ, status) {
                        ("LowConfidence", "True") => low_confidence = true,
                        ("RecommendationProvided", "True") => {
                            if let Some(t) = c.get("lastTransitionTime").and_then(|v| v.as_str()) {
                                if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(t) {
                                    let secs =
                                        (now - ts.with_timezone(&chrono::Utc)).num_seconds().max(0)
                                            as u64;
                                    last_update_age_secs = Some(secs);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            let hpa = hpa_conflicts
                .get(&(ns.clone(), workload_kind.clone(), workload.clone()))
                .cloned()
                .unwrap_or_default();

            let Some(recs) = vpa
                .data
                .pointer("/status/recommendation/containerRecommendations")
                .and_then(|v| v.as_array())
            else {
                continue;
            };

            for rec in recs {
                let container = rec
                    .get("containerName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                let pick = |path: &str, field: &str| -> String {
                    rec.pointer(path)
                        .and_then(|v| v.get(field))
                        .and_then(|v| v.as_str())
                        .map(humanize_quantity)
                        .unwrap_or_else(|| "-".to_string())
                };

                let key = (
                    ns.clone(),
                    workload_kind.clone(),
                    workload.clone(),
                    container.clone(),
                );
                let cur = current.get(&key).cloned().unwrap_or_default();
                let container_role = if init_containers.contains(&key) {
                    ContainerRole::Init
                } else if is_sidecar(&container) {
                    ContainerRole::Sidecar
                } else {
                    ContainerRole::App
                };

                out.push(RightsizingRec {
                    namespace: ns.clone(),
                    workload_kind: workload_kind.clone(),
                    workload: workload.clone(),
                    container,
                    container_role,
                    current_cpu_request: cur.cpu_request,
                    current_cpu_limit: cur.cpu_limit,
                    current_memory_request: cur.memory_request,
                    current_memory_limit: cur.memory_limit,
                    target_cpu: pick("/target", "cpu"),
                    target_memory: pick("/target", "memory"),
                    burstable_cpu_request: pick("/lowerBound", "cpu"),
                    burstable_cpu_limit: pick("/upperBound", "cpu"),
                    burstable_memory_request: pick("/lowerBound", "memory"),
                    burstable_memory_limit: pick("/upperBound", "memory"),
                    hpa_conflicts: hpa.clone(),
                    low_confidence,
                    last_update_age_secs,
                });
            }
        }

        out.sort_by(|a, b| {
            (
                a.namespace.as_str(),
                a.workload.as_str(),
                a.container.as_str(),
            )
                .cmp(&(
                    b.namespace.as_str(),
                    b.workload.as_str(),
                    b.container.as_str(),
                ))
        });
        out
    }

    /// Resolve a GVK against a cached discovery scan. Returns None if the
    /// API doesn't exist on the cluster — letting callers skip the list call
    /// instead of producing 404 warns via kube_client.
    fn resolve_gvk(
        discovery: &Discovery,
        group: &str,
        version: &str,
        kind: &str,
    ) -> Option<kube::api::ApiResource> {
        let gvk = GroupVersionKind::gvk(group, version, kind);
        discovery
            .resolve_gvk(&gvk)
            .map(|(api_resource, _)| api_resource)
    }

    async fn load_provider_configs(
        client: &Client,
        discovery: &Discovery,
    ) -> anyhow::Result<Vec<ProviderConfigInfo>> {
        use kube::api::DynamicObject;

        let mut provider_configs = Vec::new();

        // Define the provider config types to look for
        let provider_types = vec![
            (
                "aws.upbound.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::AWS,
            ),
            (
                "gcp.upbound.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::GCP,
            ),
            (
                "azure.upbound.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::Azure,
            ),
            (
                "kubernetes.crossplane.io",
                "v1alpha1",
                "ProviderConfig",
                ProviderType::Kubernetes,
            ),
            (
                "helm.crossplane.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::Helm,
            ),
            (
                "tf.upbound.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::Terraform,
            ),
            // Legacy Crossplane provider APIs
            (
                "aws.crossplane.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::AWS,
            ),
            (
                "gcp.crossplane.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::GCP,
            ),
            (
                "azure.crossplane.io",
                "v1beta1",
                "ProviderConfig",
                ProviderType::Azure,
            ),
        ];

        for (group, version, kind, provider_type) in provider_types {
            let Some(api_resource) = Self::resolve_gvk(discovery, group, version, kind) else {
                continue; // CRD not installed
            };
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

            match api.list(&Default::default()).await {
                Ok(list) => {
                    for item in list.items {
                        let name = item.metadata.name.clone().unwrap_or_default();

                        // Extract status from the dynamic object
                        let (status, message, last_sync) = Self::extract_provider_status(&item);

                        // Extract credentials source
                        let credentials_source = Self::extract_credentials_source(&item);

                        // Extract secret reference
                        let secret_ref = Self::extract_secret_ref(&item);

                        // Count associated resources (ProviderConfigUsage)
                        let associated_resources =
                            Self::count_provider_usages(client, discovery, &name, group).await;

                        provider_configs.push(ProviderConfigInfo {
                            name,
                            provider_type: provider_type.clone(),
                            status,
                            credentials_source,
                            secret_ref,
                            associated_resources,
                            last_sync,
                            message,
                        });
                    }
                }
                Err(_) => {
                    // API doesn't exist or not accessible - skip silently
                    continue;
                }
            }
        }

        Ok(provider_configs)
    }

    fn extract_provider_status(
        obj: &kube::api::DynamicObject,
    ) -> (ProviderStatus, Option<String>, Option<String>) {
        let status = obj.data.get("status");

        if let Some(status) = status {
            let conditions = status.get("conditions").and_then(|c| c.as_array());

            if let Some(conditions) = conditions {
                let mut is_ready = false;
                let mut message = None;
                let mut last_sync = None;

                for cond in conditions {
                    let cond_type = cond.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    let cond_status = cond
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("False");

                    if cond_type == "Ready" || cond_type == "Healthy" {
                        is_ready = cond_status == "True";
                        message = cond
                            .get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string());
                        last_sync = cond
                            .get("lastTransitionTime")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string());
                    }
                }

                let provider_status = if is_ready {
                    ProviderStatus::Healthy
                } else if message.is_some() {
                    ProviderStatus::Error
                } else {
                    ProviderStatus::Degraded
                };

                return (provider_status, message, last_sync);
            }
        }

        (ProviderStatus::Unknown, None, None)
    }

    fn extract_credentials_source(obj: &kube::api::DynamicObject) -> String {
        let spec = obj.data.get("spec");

        if let Some(spec) = spec {
            // Check for credentials source field
            if let Some(creds) = spec.get("credentials") {
                if let Some(source) = creds.get("source").and_then(|s| s.as_str()) {
                    return source.to_string();
                }
            }

            // Check for source directly in spec (some providers)
            if let Some(source) = spec.get("source").and_then(|s| s.as_str()) {
                return source.to_string();
            }
        }

        "Unknown".to_string()
    }

    fn extract_secret_ref(obj: &kube::api::DynamicObject) -> Option<String> {
        let spec = obj.data.get("spec")?;
        let creds = spec.get("credentials")?;
        let secret_ref = creds.get("secretRef")?;

        let name = secret_ref.get("name").and_then(|n| n.as_str())?;
        let namespace = secret_ref
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("default");
        let key = secret_ref
            .get("key")
            .and_then(|k| k.as_str())
            .unwrap_or("credentials");

        Some(format!("{}/{}:{}", namespace, name, key))
    }

    async fn count_provider_usages(
        client: &Client,
        discovery: &Discovery,
        provider_name: &str,
        group: &str,
    ) -> usize {
        use kube::api::DynamicObject;

        // Try to list ProviderConfigUsage resources
        let Some(api_resource) =
            Self::resolve_gvk(discovery, group, "v1beta1", "ProviderConfigUsage")
        else {
            return 0;
        };
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

        match api.list(&Default::default()).await {
            Ok(list) => list
                .items
                .iter()
                .filter(|item| {
                    item.data
                        .get("providerConfigRef")
                        .and_then(|r| r.get("name"))
                        .and_then(|n| n.as_str())
                        .map(|n| n == provider_name)
                        .unwrap_or(false)
                })
                .count(),
            Err(_) => 0,
        }
    }

    async fn load_auth_providers(
        client: &Client,
        discovery: &Discovery,
    ) -> anyhow::Result<Vec<AuthProviderInfo>> {
        let mut auth_providers = Vec::new();

        // Load Crossplane Providers (pkg.crossplane.io/v1/Provider)
        auth_providers.extend(Self::load_crossplane_providers(client, discovery).await);

        // Load External Secrets ClusterSecretStores
        auth_providers.extend(Self::load_cluster_secret_stores(client, discovery).await);

        // Load External Secrets SecretStores (namespaced)
        auth_providers.extend(Self::load_secret_stores(client, discovery).await);

        // Load ServiceAccounts with IRSA/Workload Identity annotations
        auth_providers.extend(Self::load_workload_identity_accounts(client).await);

        Ok(auth_providers)
    }

    async fn load_crossplane_providers(
        client: &Client,
        discovery: &Discovery,
    ) -> Vec<AuthProviderInfo> {
        use kube::api::DynamicObject;

        let mut providers = Vec::new();

        // Crossplane Provider CRD (pkg.crossplane.io/v1/Provider)
        let Some(api_resource) =
            Self::resolve_gvk(discovery, "pkg.crossplane.io", "v1", "Provider")
        else {
            return providers;
        };
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

        if let Ok(list) = api.list(&Default::default()).await {
            for item in list.items {
                let name = item.metadata.name.clone().unwrap_or_default();

                // Extract package info
                let package = item
                    .data
                    .get("spec")
                    .and_then(|s| s.get("package"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("Unknown")
                    .to_string();

                // Extract status
                let (status, message, last_sync) = Self::extract_provider_status(&item);

                // Check for installed/healthy condition
                let installed = item
                    .data
                    .get("status")
                    .and_then(|s| s.get("conditions"))
                    .and_then(|c| c.as_array())
                    .map(|conditions| {
                        conditions.iter().any(|c| {
                            c.get("type").and_then(|t| t.as_str()) == Some("Installed")
                                && c.get("status").and_then(|s| s.as_str()) == Some("True")
                        })
                    })
                    .unwrap_or(false);

                let final_status = if installed {
                    status
                } else {
                    ProviderStatus::Error
                };

                providers.push(AuthProviderInfo {
                    name,
                    namespace: None,
                    auth_type: AuthProviderType::CrossplaneProvider,
                    status: final_status,
                    backend: package,
                    secret_ref: None,
                    service_account: None,
                    last_sync,
                    message,
                });
            }
        }

        providers
    }

    async fn load_cluster_secret_stores(
        client: &Client,
        discovery: &Discovery,
    ) -> Vec<AuthProviderInfo> {
        use kube::api::DynamicObject;

        let mut stores = Vec::new();

        // External Secrets ClusterSecretStore
        let Some(api_resource) = Self::resolve_gvk(
            discovery,
            "external-secrets.io",
            "v1beta1",
            "ClusterSecretStore",
        ) else {
            return stores;
        };
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

        if let Ok(list) = api.list(&Default::default()).await {
            for item in list.items {
                let name = item.metadata.name.clone().unwrap_or_default();

                // Determine backend type from spec.provider
                let (backend, secret_ref, service_account) =
                    Self::extract_secret_store_backend(&item);

                // Extract status
                let (status, message, last_sync) = Self::extract_secret_store_status(&item);

                stores.push(AuthProviderInfo {
                    name,
                    namespace: None,
                    auth_type: AuthProviderType::ClusterSecretStore,
                    status,
                    backend,
                    secret_ref,
                    service_account,
                    last_sync,
                    message,
                });
            }
        }

        stores
    }

    async fn load_secret_stores(client: &Client, discovery: &Discovery) -> Vec<AuthProviderInfo> {
        use kube::api::DynamicObject;

        let mut stores = Vec::new();

        // External Secrets SecretStore (namespaced)
        let Some(api_resource) =
            Self::resolve_gvk(discovery, "external-secrets.io", "v1beta1", "SecretStore")
        else {
            return stores;
        };
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

        if let Ok(list) = api.list(&Default::default()).await {
            for item in list.items {
                let name = item.metadata.name.clone().unwrap_or_default();
                let namespace = item.metadata.namespace.clone();

                // Determine backend type from spec.provider
                let (backend, secret_ref, service_account) =
                    Self::extract_secret_store_backend(&item);

                // Extract status
                let (status, message, last_sync) = Self::extract_secret_store_status(&item);

                stores.push(AuthProviderInfo {
                    name,
                    namespace,
                    auth_type: AuthProviderType::SecretStore,
                    status,
                    backend,
                    secret_ref,
                    service_account,
                    last_sync,
                    message,
                });
            }
        }

        stores
    }

    fn extract_secret_store_backend(
        obj: &kube::api::DynamicObject,
    ) -> (String, Option<String>, Option<String>) {
        let spec = obj.data.get("spec");
        let provider = spec.and_then(|s| s.get("provider"));

        if let Some(provider) = provider {
            // Check each provider type
            if let Some(aws) = provider.get("aws") {
                let service = aws
                    .get("service")
                    .and_then(|s| s.as_str())
                    .unwrap_or("SecretsManager");
                let secret_ref = aws
                    .get("auth")
                    .and_then(|a| a.get("secretRef"))
                    .and_then(|s| s.get("accessKeyIDSecretRef"))
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                let sa = aws
                    .get("auth")
                    .and_then(|a| a.get("jwt"))
                    .and_then(|j| j.get("serviceAccountRef"))
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                return (format!("AWS {}", service), secret_ref, sa);
            }

            if let Some(gcp) = provider.get("gcpsm") {
                let secret_ref = gcp
                    .get("auth")
                    .and_then(|a| a.get("secretRef"))
                    .and_then(|s| s.get("secretAccessKeySecretRef"))
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                let sa = gcp
                    .get("auth")
                    .and_then(|a| a.get("workloadIdentity"))
                    .and_then(|w| w.get("serviceAccountRef"))
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                return ("GCP Secret Manager".to_string(), secret_ref, sa);
            }

            if let Some(azure) = provider.get("azurekv") {
                let vault_url = azure
                    .get("vaultUrl")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let secret_ref = azure
                    .get("authSecretRef")
                    .and_then(|s| s.get("clientSecret"))
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                let sa = azure
                    .get("serviceAccountRef")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                return (format!("Azure KeyVault ({})", vault_url), secret_ref, sa);
            }

            if let Some(vault) = provider.get("vault") {
                let server = vault
                    .get("server")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown");
                let secret_ref = vault
                    .get("auth")
                    .and_then(|a| a.get("tokenSecretRef"))
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                let sa = vault
                    .get("auth")
                    .and_then(|a| a.get("kubernetes"))
                    .and_then(|k| k.get("serviceAccountRef"))
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
                return (format!("Vault ({})", server), secret_ref, sa);
            }

            if provider.get("kubernetes").is_some() {
                return ("Kubernetes".to_string(), None, None);
            }
        }

        ("Unknown".to_string(), None, None)
    }

    fn extract_secret_store_status(
        obj: &kube::api::DynamicObject,
    ) -> (ProviderStatus, Option<String>, Option<String>) {
        let status = obj.data.get("status");

        if let Some(status) = status {
            let conditions = status.get("conditions").and_then(|c| c.as_array());

            if let Some(conditions) = conditions {
                for cond in conditions {
                    let cond_type = cond.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    let cond_status = cond
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("False");

                    if cond_type == "Ready" {
                        let is_ready = cond_status == "True";
                        let message = cond
                            .get("message")
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string());
                        let last_sync = cond
                            .get("lastTransitionTime")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string());

                        let provider_status = if is_ready {
                            ProviderStatus::Healthy
                        } else {
                            ProviderStatus::Error
                        };

                        return (provider_status, message, last_sync);
                    }
                }
            }
        }

        (ProviderStatus::Unknown, None, None)
    }

    async fn load_workload_identity_accounts(client: &Client) -> Vec<AuthProviderInfo> {
        use k8s_openapi::api::core::v1::ServiceAccount;

        let mut accounts = Vec::new();
        let sa_api: Api<ServiceAccount> = Api::all(client.clone());

        if let Ok(list) = sa_api.list(&Default::default()).await {
            for sa in list.items {
                let name = sa.metadata.name.clone().unwrap_or_default();
                let namespace = sa.metadata.namespace.clone();
                let annotations = sa.metadata.annotations.clone().unwrap_or_default();

                // Check for AWS IRSA
                if let Some(role_arn) = annotations.get("eks.amazonaws.com/role-arn") {
                    accounts.push(AuthProviderInfo {
                        name: name.clone(),
                        namespace: namespace.clone(),
                        auth_type: AuthProviderType::AwsIrsa,
                        status: ProviderStatus::Healthy,
                        backend: role_arn.clone(),
                        secret_ref: None,
                        service_account: Some(name.clone()),
                        last_sync: None,
                        message: None,
                    });
                }

                // Check for GCP Workload Identity
                if let Some(gsa) = annotations.get("iam.gke.io/gcp-service-account") {
                    accounts.push(AuthProviderInfo {
                        name: name.clone(),
                        namespace: namespace.clone(),
                        auth_type: AuthProviderType::GcpWorkloadIdentity,
                        status: ProviderStatus::Healthy,
                        backend: gsa.clone(),
                        secret_ref: None,
                        service_account: Some(name.clone()),
                        last_sync: None,
                        message: None,
                    });
                }

                // Check for Azure Workload Identity
                if let Some(client_id) = annotations.get("azure.workload.identity/client-id") {
                    let tenant_id = annotations
                        .get("azure.workload.identity/tenant-id")
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    accounts.push(AuthProviderInfo {
                        name: name.clone(),
                        namespace: namespace.clone(),
                        auth_type: AuthProviderType::AzureWorkloadIdentity,
                        status: ProviderStatus::Healthy,
                        backend: format!("{}@{}", client_id, tenant_id),
                        secret_ref: None,
                        service_account: Some(name),
                        last_sync: None,
                        message: None,
                    });
                }
            }
        }

        accounts
    }

    async fn calculate_finops(
        client: &Client,
        discovery: &Discovery,
        nodes: &[NodeInfo],
        namespaces: &[NamespaceInfo],
    ) -> anyhow::Result<FinOpsOverview> {
        // Prefer the platform's ResourceStats CR (populated by resource-stats-operator)
        // over a node-count placeholder. Falls back if the CRD isn't installed.
        if Self::resolve_gvk(
            discovery,
            "platform.yurikrupnik.com",
            "v1alpha1",
            "ResourceStats",
        )
        .is_some()
        {
            if let Some(finops) = Self::finops_from_resource_stats(client).await {
                return Ok(finops);
            }
        }

        Ok(Self::finops_placeholder(nodes, namespaces))
    }

    /// Build FinOpsOverview from the freshest cluster-scoped ResourceStats CR.
    /// Returns None when there's no usable CR yet (CRD installed but operator
    /// hasn't written status) so the caller can fall back.
    async fn finops_from_resource_stats(client: &Client) -> Option<FinOpsOverview> {
        use resource_stats_types::resource_stats::{ResourceStats, StatsScope};

        let api: Api<ResourceStats> = Api::all(client.clone());
        let list = api.list(&Default::default()).await.ok()?;

        // Pick the freshest Cluster-scoped CR with a costSummary.
        let cr = list
            .items
            .into_iter()
            .filter(|r| r.spec.scope == StatsScope::Cluster)
            .filter(|r| {
                r.status
                    .as_ref()
                    .and_then(|s| s.cost_summary.as_ref())
                    .is_some()
            })
            .max_by_key(|r| {
                r.status
                    .as_ref()
                    .and_then(|s| s.last_collection_time.clone())
            })?;

        let status = cr.status?;
        let cost = status.cost_summary?;
        let hourly = cost.total_per_hour.parse::<f64>().unwrap_or(0.0);
        let monthly = cost
            .projected_monthly
            .parse::<f64>()
            .unwrap_or(hourly * 730.0);

        // Aggregate per-namespace from podStats.
        let mut by_ns: HashMap<String, f64> = HashMap::new();
        for pod in &status.pod_stats {
            if let Some(rate) = pod
                .cost_per_hour
                .as_deref()
                .and_then(|s| s.parse::<f64>().ok())
            {
                *by_ns.entry(pod.namespace.clone()).or_insert(0.0) += rate;
            }
        }
        let cost_by_namespace: Vec<NamespaceCost> = by_ns
            .into_iter()
            .map(|(namespace, hourly_cost)| NamespaceCost {
                namespace,
                hourly_cost,
                monthly_cost: hourly_cost * 730.0,
            })
            .collect();

        // Surface efficiency as a savings hint when reported.
        let mut recommendations = Vec::new();
        let mut savings_opportunities = 0.0;
        if let Some(eff) = cost.efficiency_score {
            if eff < 0.8 {
                let waste = monthly * (1.0 - eff);
                savings_opportunities = waste;
                recommendations.push(CostRecommendation {
                    category: RecommendationCategory::RightSizing,
                    potential_savings: waste,
                    description: format!(
                        "Cluster running at {:.0}% efficiency — right-size workloads",
                        eff * 100.0
                    ),
                    affected_resources: vec![],
                });
            }
        }

        Some(FinOpsOverview {
            total_hourly_cost: hourly,
            total_monthly_cost: hourly * 730.0,
            projected_monthly_cost: monthly,
            cost_by_namespace,
            recommendations,
            savings_opportunities,
        })
    }

    /// Fallback estimate when no ResourceStats data is available.
    /// Spreads node-rate evenly across namespaces — a coarse stand-in until
    /// the operator wires per-namespace cost.
    fn finops_placeholder(nodes: &[NodeInfo], namespaces: &[NamespaceInfo]) -> FinOpsOverview {
        let node_count = nodes.len();
        let estimated_hourly = node_count as f64 * 0.10; // $0.10/node/hour placeholder

        let cost_by_namespace: Vec<NamespaceCost> = if namespaces.is_empty() {
            Vec::new()
        } else {
            let per_ns = estimated_hourly / namespaces.len() as f64;
            namespaces
                .iter()
                .map(|n| NamespaceCost {
                    namespace: n.name.clone(),
                    hourly_cost: per_ns,
                    monthly_cost: per_ns * 730.0,
                })
                .collect()
        };

        FinOpsOverview {
            total_hourly_cost: estimated_hourly,
            total_monthly_cost: estimated_hourly * 730.0,
            projected_monthly_cost: estimated_hourly * 730.0,
            cost_by_namespace,
            recommendations: vec![CostRecommendation {
                category: RecommendationCategory::RightSizing,
                potential_savings: 0.0,
                description: "Install resource-stats-operator for real cost data".to_string(),
                affected_resources: vec![],
            }],
            savings_opportunities: 0.0,
        }
    }
}

// ============ Data Types ============

#[derive(Clone, Debug, Default)]
pub struct ClusterInfo {
    pub name: String,
    pub version: String,
    pub provider: String,
    pub node_count: usize,
    pub namespace_count: usize,
    pub pod_count: usize,
    pub running_pods: usize,
    pub status: ClusterStatus,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum ClusterStatus {
    #[default]
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub name: String,
    pub status: NodeStatus,
    pub cpu_allocatable: String,
    pub memory_allocatable: String,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub pod_count: usize,
    pub instance_type: String,
    pub zone: String,
    pub os: String,
    pub container_runtime: String,
    pub labels: HashMap<String, String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum NodeStatus {
    Ready,
    NotReady,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct NamespaceInfo {
    pub name: String,
    pub status: NamespaceStatus,
    pub pod_count: usize,
    pub labels: HashMap<String, String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum NamespaceStatus {
    Active,
    Terminating,
}

#[derive(Clone, Debug, Default)]
pub struct SecurityOverview {
    pub score: u32,
    pub issues: Vec<SecurityIssue>,
    pub last_scan: Option<String>,
}

/// One policy-engine finding. Sourced from any `wgpolicyk8s.io PolicyReport` —
/// Kyverno, Trivy, Falco, etc. all write to that schema.
#[derive(Clone, Debug)]
pub struct SecurityIssue {
    pub severity: Severity,
    pub category: SecurityCategory,
    pub resource: String,
    pub message: String,
    pub remediation: String,
    pub source: String,
    pub policy: String,
    pub rule: String,
    pub result: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Warning,
    Low,
    Info,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SecurityCategory {
    Vulnerability,
    Misconfiguration,
    Rbac,
    NetworkPolicy,
    PodSecurity,
    Secrets,
}

#[derive(Clone, Debug)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub severity: Severity,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub image: String,
    pub resource: String,
    pub description: String,
}

#[derive(Clone, Debug, Default)]
pub struct FinOpsOverview {
    pub total_hourly_cost: f64,
    pub total_monthly_cost: f64,
    pub projected_monthly_cost: f64,
    pub cost_by_namespace: Vec<NamespaceCost>,
    pub recommendations: Vec<CostRecommendation>,
    pub savings_opportunities: f64,
}

#[derive(Clone, Debug)]
pub struct NamespaceCost {
    pub namespace: String,
    pub hourly_cost: f64,
    pub monthly_cost: f64,
}

#[derive(Clone, Debug)]
pub struct CostRecommendation {
    pub category: RecommendationCategory,
    pub potential_savings: f64,
    pub description: String,
    pub affected_resources: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RecommendationCategory {
    RightSizing,
    SpotInstances,
    Reserved,
    UnusedResources,
    IdleResources,
}

/// Render a k8s Quantity-like value in human form. VPA writes memory as raw
/// byte counts (e.g. "231735296"); we collapse those into the decimal units
/// Goldilocks' UI uses ("232M"). CPU / suffixed values pass through.
fn humanize_quantity(s: &str) -> String {
    if let Ok(n) = s.parse::<u64>() {
        if n >= 1_000_000_000 {
            return format!("{:.1}G", n as f64 / 1_000_000_000.0);
        }
        if n >= 1_000_000 {
            return format!("{}M", n / 1_000_000);
        }
        if n >= 1_000 {
            return format!("{}k", n / 1_000);
        }
        return n.to_string();
    }
    s.to_string()
}

/// Parse a k8s Quantity into a f64. CPU "100m" → 0.1, memory "128Mi" → bytes.
/// Returns None for "-" / empty / unparseable so callers can skip coloring.
pub fn parse_quantity(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return None;
    }
    if let Ok(n) = s.parse::<f64>() {
        return Some(n);
    }
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, suffix) = s.split_at(split);
    let n: f64 = num.parse().ok()?;
    let mult = match suffix {
        "m" => 0.001,
        "" => 1.0,
        "k" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        "T" => 1e12,
        "Ki" => 1024.0,
        "Mi" => 1024.0 * 1024.0,
        "Gi" => 1024.0_f64.powi(3),
        "Ti" => 1024.0_f64.powi(4),
        _ => return None,
    };
    Some(n * mult)
}

/// Compact age renderer: 90 → "1m", 7200 → "2h", 172800 → "2d".
pub fn humanize_age(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Common sidecar container names. Sidecars are NOT patchable in the workload
/// manifest (a mutating webhook will overwrite the resources on next pod
/// creation) — they need annotation- or operator-level patches.
const SIDECAR_NAMES: &[&str] = &[
    "istio-proxy",
    "istio-init",
    "linkerd-proxy",
    "linkerd-init",
    "vault-agent",
    "vault-agent-init",
    "oauth2-proxy",
    "envoy-sidecar",
    "fluent-bit",
    "fluentd",
    "dapr-sidecar",
    "opa",
    "consul-connect-inject-init",
    "consul-connect-envoy-sidecar",
    "cloud-sql-proxy",
];

/// Sort key — lower number = worse severity (used to sort findings).
pub fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Warning => 3,
        Severity::Low => 4,
        Severity::Info => 5,
    }
}

/// Flatten a wgpolicyk8s.io PolicyReport (or ClusterPolicyReport) into one
/// SecurityIssue per non-passing rule result. `pass` and `skip` results are
/// dropped — only `fail`/`warn`/`error` are surfaced.
fn extract_policy_findings(report: &kube::api::DynamicObject) -> Vec<SecurityIssue> {
    let report_ns = report.metadata.namespace.as_deref().unwrap_or("");
    let scope = report.data.get("scope");
    // scope is the target the report is about: kind/name/namespace
    let target_kind = scope
        .and_then(|s| s.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let target_name = scope
        .and_then(|s| s.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let target_ns = scope
        .and_then(|s| s.get("namespace"))
        .and_then(|v| v.as_str())
        .unwrap_or(report_ns);

    let resource_label = if target_ns.is_empty() {
        format!("{}/{}", target_kind, target_name)
    } else {
        format!("{}/{}/{}", target_ns, target_kind, target_name)
    };

    let Some(results) = report.data.get("results").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for r in results {
        let result = r.get("result").and_then(|v| v.as_str()).unwrap_or("");
        // Pass + skip are non-actionable — drop them so the view is just issues.
        if !matches!(result, "fail" | "warn" | "error") {
            continue;
        }
        let severity = match r.get("severity").and_then(|v| v.as_str()).unwrap_or("") {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            "info" => Severity::Info,
            _ => match result {
                "error" => Severity::High,
                "warn" => Severity::Warning,
                _ => Severity::Medium,
            },
        };
        let source = r
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("policy")
            .to_string();
        let policy = r
            .get("policy")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let rule = r
            .get("rule")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let message = r
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        out.push(SecurityIssue {
            severity,
            category: SecurityCategory::Misconfiguration,
            resource: resource_label.clone(),
            message,
            remediation: String::new(),
            source,
            policy,
            rule,
            result: result.to_string(),
        });
    }
    out
}

fn is_sidecar(name: &str) -> bool {
    SIDECAR_NAMES.iter().any(|s| *s == name)
}

// ============ Rightsizing (Goldilocks / VPA) Types ============

/// One VPA container recommendation, joined with workload state (current
/// requests, init/sidecar role, HPA conflict, VPA freshness) so each row is
/// trustworthy in isolation.
#[derive(Clone, Debug, Default)]
pub struct RightsizingRec {
    pub namespace: String,
    pub workload_kind: String,
    pub workload: String,
    pub container: String,
    pub container_role: ContainerRole,
    pub current_cpu_request: Option<String>,
    pub current_cpu_limit: Option<String>,
    pub current_memory_request: Option<String>,
    pub current_memory_limit: Option<String>,
    /// VPA `target` — single value the recommender thinks is best.
    pub target_cpu: String,
    pub target_memory: String,
    /// VPA `lowerBound` (use as request for Burstable QoS).
    pub burstable_cpu_request: String,
    pub burstable_memory_request: String,
    /// VPA `upperBound` (use as limit for Burstable QoS).
    pub burstable_cpu_limit: String,
    pub burstable_memory_limit: String,
    /// HPA on the same workload watches these resources ("cpu" / "memory").
    /// Non-empty = applying VPA recs on these resources will fight the HPA.
    pub hpa_conflicts: Vec<String>,
    /// VPA reports LowConfidence=True — not enough samples to trust the rec.
    pub low_confidence: bool,
    /// Seconds since the VPA last refreshed its recommendation, if known.
    pub last_update_age_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ContainerRole {
    #[default]
    App,
    Sidecar,
    Init,
}

#[derive(Clone, Debug, Default)]
struct CurrentResources {
    cpu_request: Option<String>,
    cpu_limit: Option<String>,
    memory_request: Option<String>,
    memory_limit: Option<String>,
}

impl CurrentResources {
    fn from_container_resources(
        r: Option<&k8s_openapi::api::core::v1::ResourceRequirements>,
    ) -> Self {
        let Some(r) = r else { return Self::default() };
        let get =
            |map: Option<
                &std::collections::BTreeMap<
                    String,
                    k8s_openapi::apimachinery::pkg::api::resource::Quantity,
                >,
            >,
             key: &str| { map.and_then(|m| m.get(key)).map(|q| q.0.clone()) };
        Self {
            cpu_request: get(r.requests.as_ref(), "cpu"),
            cpu_limit: get(r.limits.as_ref(), "cpu"),
            memory_request: get(r.requests.as_ref(), "memory"),
            memory_limit: get(r.limits.as_ref(), "memory"),
        }
    }
}

// ============ Crossplane Provider Types ============

/// Crossplane Provider Configuration info
#[derive(Clone, Debug)]
pub struct ProviderConfigInfo {
    pub name: String,
    pub provider_type: ProviderType,
    pub status: ProviderStatus,
    pub credentials_source: String,
    pub secret_ref: Option<String>,
    pub associated_resources: usize,
    pub last_sync: Option<String>,
    pub message: Option<String>,
}

/// Provider type (cloud provider)
#[derive(Clone, Debug, PartialEq)]
pub enum ProviderType {
    AWS,
    GCP,
    Azure,
    Kubernetes,
    Helm,
    Terraform,
    Other(String),
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::AWS => write!(f, "AWS"),
            ProviderType::GCP => write!(f, "GCP"),
            ProviderType::Azure => write!(f, "Azure"),
            ProviderType::Kubernetes => write!(f, "Kubernetes"),
            ProviderType::Helm => write!(f, "Helm"),
            ProviderType::Terraform => write!(f, "Terraform"),
            ProviderType::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Provider config status
#[derive(Clone, Debug, PartialEq)]
pub enum ProviderStatus {
    Healthy,
    Degraded,
    Error,
    Unknown,
}

/// Crossplane managed resource association
#[derive(Clone, Debug)]
pub struct ProviderResourceAssociation {
    pub resource_name: String,
    pub resource_kind: String,
    pub namespace: Option<String>,
    pub ready: bool,
    pub synced: bool,
}

// ============ Authentication Provider Types ============

/// Authentication provider information
#[derive(Clone, Debug)]
pub struct AuthProviderInfo {
    pub name: String,
    pub namespace: Option<String>,
    pub auth_type: AuthProviderType,
    pub status: ProviderStatus,
    pub backend: String,
    pub secret_ref: Option<String>,
    pub service_account: Option<String>,
    pub last_sync: Option<String>,
    pub message: Option<String>,
}

/// Type of authentication provider
#[derive(Clone, Debug, PartialEq)]
pub enum AuthProviderType {
    /// Crossplane Provider (pkg.crossplane.io/Provider)
    CrossplaneProvider,
    /// External Secrets SecretStore
    SecretStore,
    /// External Secrets ClusterSecretStore
    ClusterSecretStore,
    /// AWS IRSA (IAM Roles for Service Accounts)
    AwsIrsa,
    /// GCP Workload Identity
    GcpWorkloadIdentity,
    /// Azure Workload Identity
    AzureWorkloadIdentity,
    /// HashiCorp Vault
    Vault,
    /// Generic/Other
    Other(String),
}

impl std::fmt::Display for AuthProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthProviderType::CrossplaneProvider => write!(f, "Crossplane Provider"),
            AuthProviderType::SecretStore => write!(f, "SecretStore"),
            AuthProviderType::ClusterSecretStore => write!(f, "ClusterSecretStore"),
            AuthProviderType::AwsIrsa => write!(f, "AWS IRSA"),
            AuthProviderType::GcpWorkloadIdentity => write!(f, "GCP Workload Identity"),
            AuthProviderType::AzureWorkloadIdentity => write!(f, "Azure Workload Identity"),
            AuthProviderType::Vault => write!(f, "Vault"),
            AuthProviderType::Other(s) => write!(f, "{}", s),
        }
    }
}
