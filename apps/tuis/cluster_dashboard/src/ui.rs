//! UI rendering for the cluster dashboard

use crate::{
    data::{
        humanize_age, parse_quantity, AuthProviderType, ContainerRole, DashboardData, NodeStatus,
        ProviderStatus, RightsizingRec, SecurityIssue, Severity,
    },
    Dashboard, View,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{
        Block, Borders, Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Table, TableState,
        Tabs, Wrap,
    },
    Frame,
};

/// Render the entire dashboard
pub fn render(frame: &mut Frame, dashboard: &Dashboard, data: &DashboardData) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header/tabs
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(frame.area());

    render_header(frame, chunks[0], dashboard);
    render_main_content(frame, chunks[1], dashboard, data);
    render_status_bar(frame, chunks[2], dashboard, data);

    // Render search popup if active
    if dashboard.is_searching {
        render_search_popup(frame, dashboard);
    }
}

fn render_header(frame: &mut Frame, area: Rect, dashboard: &Dashboard) {
    let titles: Vec<Line> = [
        View::Overview,
        View::Nodes,
        View::Security,
        View::FinOps,
        View::Providers,
        View::Rightsizing,
    ]
    .iter()
    .map(|v| Line::from(format!(" {} {} ", v.key(), v.title())))
    .collect();

    let selected = match dashboard.current_view {
        View::Overview => 0,
        View::Nodes => 1,
        View::Security | View::VulnerabilityDetail => 2,
        View::FinOps => 3,
        View::Providers | View::ProviderDetail => 4,
        View::Rightsizing => 5,
        _ => 0,
    };

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Cluster Dashboard "),
        )
        .select(selected)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(tabs, area);
}

fn render_main_content(frame: &mut Frame, area: Rect, dashboard: &Dashboard, data: &DashboardData) {
    match dashboard.current_view {
        View::Overview => render_overview(frame, area, data),
        View::Nodes => render_nodes(frame, area, dashboard, data),
        View::Security => render_security(frame, area, dashboard, data),
        View::FinOps => render_finops(frame, area, dashboard, data),
        View::Providers => render_providers(frame, area, dashboard, data),
        View::Rightsizing => render_rightsizing(frame, area, dashboard, data),
        View::Help => render_help(frame, area),
        View::VulnerabilityDetail => render_security_detail(frame, area, dashboard, data),
        View::ProviderDetail => render_provider_detail(frame, area, dashboard, data),
    }
}

fn render_overview(frame: &mut Frame, area: Rect, data: &DashboardData) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(chunks[0]);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(0),
        ])
        .split(chunks[1]);

    // Cluster Info
    let cluster_info = vec![
        format!("Cluster: {}", data.cluster_info.name),
        format!("Version: {}", data.cluster_info.version),
        format!("Provider: {}", data.cluster_info.provider),
        format!("Nodes: {}", data.cluster_info.node_count),
        format!("Namespaces: {}", data.cluster_info.namespace_count),
        format!(
            "Pods: {}/{}",
            data.cluster_info.running_pods, data.cluster_info.pod_count
        ),
    ];
    let cluster_block = Paragraph::new(cluster_info.join("\n"))
        .block(Block::default().borders(Borders::ALL).title(" Cluster "));
    frame.render_widget(cluster_block, left_chunks[0]);

    // Node Summary
    let ready_nodes = data
        .nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Ready)
        .count();
    let node_info = vec![
        format!("Total: {}", data.nodes.len()),
        format!("Ready: {}", ready_nodes),
        format!("Not Ready: {}", data.nodes.len() - ready_nodes),
    ];
    let node_block = Paragraph::new(node_info.join("\n"))
        .block(Block::default().borders(Borders::ALL).title(" Nodes "));
    frame.render_widget(node_block, left_chunks[1]);

    // Security Score
    let security_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Security Score "),
        )
        .gauge_style(Style::default().fg(if data.security.score >= 80 {
            Color::Green
        } else if data.security.score >= 60 {
            Color::Yellow
        } else {
            Color::Red
        }))
        .percent(data.security.score as u16)
        .label(format!("{}%", data.security.score));
    frame.render_widget(security_gauge, right_chunks[0]);

    // FinOps Summary
    let finops_info = vec![
        format!("Monthly Cost: ${:.2}", data.finops.total_monthly_cost),
        format!("Hourly Cost: ${:.2}", data.finops.total_hourly_cost),
        format!(
            "Savings Opportunities: ${:.2}",
            data.finops.savings_opportunities
        ),
    ];
    let finops_block = Paragraph::new(finops_info.join("\n"))
        .block(Block::default().borders(Borders::ALL).title(" FinOps "));
    frame.render_widget(finops_block, right_chunks[1]);

    // Rightsizing summary
    let workloads: std::collections::BTreeSet<(&str, &str)> = data
        .rightsizing
        .iter()
        .map(|r| (r.namespace.as_str(), r.workload.as_str()))
        .collect();
    let hpa_conflict = data
        .rightsizing
        .iter()
        .filter(|r| !r.hpa_conflicts.is_empty())
        .count();
    let low_conf = data.rightsizing.iter().filter(|r| r.low_confidence).count();
    let rs_info = vec![
        format!("Containers: {}", data.rightsizing.len()),
        format!("Workloads: {}", workloads.len()),
        format!("HPA conflicts: {}", hpa_conflict),
        format!("Low confidence: {}", low_conf),
    ];
    let rs_block = Paragraph::new(rs_info.join("\n")).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Rightsizing "),
    );
    frame.render_widget(rs_block, right_chunks[2]);
}

fn render_nodes(frame: &mut Frame, area: Rect, dashboard: &Dashboard, data: &DashboardData) {
    let header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Status"),
        Cell::from("CPU"),
        Cell::from("Memory"),
        Cell::from("Instance Type"),
        Cell::from("Zone"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .height(1);

    let len = data.nodes.len();
    let selected = dashboard.selected_index.min(len.saturating_sub(1));

    let rows: Vec<Row> = data
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let style = if i == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            let status_style = match node.status {
                NodeStatus::Ready => Style::default().fg(Color::Green),
                NodeStatus::NotReady => Style::default().fg(Color::Red),
                NodeStatus::Unknown => Style::default().fg(Color::Yellow),
            };

            Row::new(vec![
                Cell::from(node.name.clone()),
                Cell::from(format!("{:?}", node.status)).style(status_style),
                Cell::from(node.cpu_allocatable.clone()),
                Cell::from(node.memory_allocatable.clone()),
                Cell::from(node.instance_type.clone()),
                Cell::from(node.zone.clone()),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(10),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Nodes "));

    let mut state = list_state(len, dashboard.selected_index);
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_security(frame: &mut Frame, area: Rect, dashboard: &Dashboard, data: &DashboardData) {
    if data.security.issues.is_empty() {
        let msg = Paragraph::new(
            "No security findings.\n\n\
            This view reads PolicyReport / ClusterPolicyReport CRs from\n\
            `wgpolicyk8s.io/v1alpha2`, which Kyverno, Trivy, Falco, etc.\n\
            all write to.\n\n\
            If you expected findings here:\n  \
            - confirm a policy engine is installed (kubectl get polr -A)\n  \
            - check it has actually produced results (.results[])",
        )
        .block(Block::default().borders(Borders::ALL).title(" Security "))
        .wrap(Wrap { trim: false });
        frame.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let header = Row::new(vec![
        Cell::from("Severity"),
        Cell::from("Source"),
        Cell::from("Policy / Rule"),
        Cell::from("Resource"),
        Cell::from("Message"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .height(1);

    let len = data.security.issues.len();
    let selected = dashboard.selected_index.min(len.saturating_sub(1));

    let rows: Vec<Row> = data
        .security
        .issues
        .iter()
        .enumerate()
        .map(|(i, issue)| security_row(issue, i, selected))
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(8),
            Constraint::Percentage(8),
            Constraint::Percentage(24),
            Constraint::Percentage(25),
            Constraint::Percentage(35),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Security findings — PolicyReport (Kyverno / Trivy / etc.) "),
    );

    let mut state = list_state(len, dashboard.selected_index);
    frame.render_stateful_widget(table, chunks[0], &mut state);

    // Bottom footer — totals by severity + source breakdown
    frame.render_widget(security_footer(data), chunks[1]);
}

fn security_row<'a>(issue: &'a SecurityIssue, i: usize, selected: usize) -> Row<'a> {
    let base = if i == selected {
        Style::default().bg(Color::DarkGray)
    } else {
        Style::default()
    };
    let severity_style = match issue.severity {
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::Red),
        Severity::Medium => Style::default().fg(Color::Yellow),
        Severity::Warning => Style::default().fg(Color::LightYellow),
        Severity::Low => Style::default().fg(Color::Cyan),
        Severity::Info => Style::default().fg(Color::Gray),
    };
    let policy_cell = if issue.rule.is_empty() {
        issue.policy.clone()
    } else {
        format!("{} / {}", issue.policy, issue.rule)
    };
    Row::new(vec![
        Cell::from(format!("{:?}", issue.severity)).style(severity_style),
        Cell::from(issue.source.clone()),
        Cell::from(truncate_string(&policy_cell, 36)),
        Cell::from(truncate_string(&issue.resource, 38)),
        Cell::from(truncate_string(&issue.message, 60)),
    ])
    .style(base)
}

fn security_footer<'a>(data: &'a DashboardData) -> Paragraph<'a> {
    use std::collections::BTreeMap;
    let crit = data
        .security
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Critical)
        .count();
    let high = data
        .security
        .issues
        .iter()
        .filter(|i| i.severity == Severity::High)
        .count();
    let med = data
        .security
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Medium)
        .count();
    let low = data
        .security
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Low)
        .count();

    let mut by_source: BTreeMap<&str, usize> = BTreeMap::new();
    for i in &data.security.issues {
        *by_source.entry(i.source.as_str()).or_default() += 1;
    }
    let sources: String = by_source
        .into_iter()
        .map(|(s, n)| format!("{s}:{n}"))
        .collect::<Vec<_>>()
        .join(" · ");

    let text = format!(
        "{} findings · {} critical · {} high · {} medium · {} low | sources: {}",
        data.security.issues.len(),
        crit,
        high,
        med,
        low,
        if sources.is_empty() {
            "(none)".to_string()
        } else {
            sources
        },
    );
    Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" Status "))
}

fn render_finops(frame: &mut Frame, area: Rect, dashboard: &Dashboard, data: &DashboardData) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left: Cost by namespace
    let header = Row::new(vec![
        Cell::from("Namespace"),
        Cell::from("Hourly"),
        Cell::from("Monthly"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .height(1);

    let len = data.finops.cost_by_namespace.len();
    let selected = dashboard.selected_index.min(len.saturating_sub(1));

    let rows: Vec<Row> = data
        .finops
        .cost_by_namespace
        .iter()
        .enumerate()
        .map(|(i, ns_cost)| {
            let style = if i == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(ns_cost.namespace.clone()),
                Cell::from(format!("${:.2}", ns_cost.hourly_cost)),
                Cell::from(format!("${:.2}", ns_cost.monthly_cost)),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(50),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Cost by Namespace "),
    );

    let mut state = list_state(len, dashboard.selected_index);
    frame.render_stateful_widget(table, chunks[0], &mut state);

    // Right: Recommendations
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(chunks[1]);

    let summary = vec![
        format!("Total Monthly: ${:.2}", data.finops.total_monthly_cost),
        format!("Projected: ${:.2}", data.finops.projected_monthly_cost),
        format!(
            "Savings Available: ${:.2}",
            data.finops.savings_opportunities
        ),
    ];
    let summary_block = Paragraph::new(summary.join("\n"))
        .block(Block::default().borders(Borders::ALL).title(" Summary "));
    frame.render_widget(summary_block, right_chunks[0]);

    let items: Vec<ListItem> = data
        .finops
        .recommendations
        .iter()
        .map(|rec| {
            ListItem::new(format!(
                "[${:.0}] {:?}: {}",
                rec.potential_savings, rec.category, rec.description
            ))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recommendations "),
    );
    frame.render_widget(list, right_chunks[1]);
}

fn render_rightsizing(frame: &mut Frame, area: Rect, dashboard: &Dashboard, data: &DashboardData) {
    if data.rightsizing.is_empty() {
        let msg = Paragraph::new(
            "No VPA recommendations found.\n\n\
            This view reads VerticalPodAutoscaler resources written by\n\
            Goldilocks (one per workload in opted-in namespaces).\n\n\
            To enable:\n  \
            1. Install Goldilocks (Fairwinds chart)\n  \
            2. Label namespaces:  goldilocks.fairwinds.com/enabled=\"true\"\n  \
            3. Wait a few minutes for the VPA recommender to collect samples",
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Rightsizing (Goldilocks / VPA) "),
        )
        .wrap(Wrap { trim: false });
        frame.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let header = Row::new(vec![
        Cell::from("Workload"),
        Cell::from("Container"),
        Cell::from("Conf"),
        Cell::from("CPU req"),
        Cell::from("CPU lim"),
        Cell::from("Mem req"),
        Cell::from("Mem lim"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .height(1);

    let len = data.rightsizing.len();
    let selected = dashboard.selected_index.min(len.saturating_sub(1));

    let rows: Vec<Row> = data
        .rightsizing
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let base = if i == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            rightsizing_row(r, base)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(22),
            Constraint::Percentage(20),
            Constraint::Percentage(8),
            Constraint::Percentage(13),
            Constraint::Percentage(13),
            Constraint::Percentage(12),
            Constraint::Percentage(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Rightsizing — Burstable QoS (Goldilocks / VPA) — current → rec "),
    );

    let mut state = list_state(len, dashboard.selected_index);
    frame.render_stateful_widget(table, chunks[0], &mut state);

    // Bottom status footer — totals + freshness, so users can sanity-check
    // what they're looking at without leaving the view.
    frame.render_widget(rightsizing_footer(data), chunks[1]);
}

fn rightsizing_row(r: &RightsizingRec, base: Style) -> Row<'_> {
    let workload_cell = format!("{}/{}", r.namespace, r.workload);
    let container_cell = {
        let mut s = match r.container_role {
            ContainerRole::App => r.container.clone(),
            ContainerRole::Sidecar => format!("↳ {} [sc]", r.container),
            ContainerRole::Init => format!("⇣ {} [init]", r.container),
        };
        if !r.hpa_conflicts.is_empty() {
            s.push_str(&format!(" ⚠HPA({})", r.hpa_conflicts.join(",")));
        }
        s
    };
    let container_style = match r.container_role {
        ContainerRole::Sidecar | ContainerRole::Init => Style::default().fg(Color::DarkGray),
        ContainerRole::App if !r.hpa_conflicts.is_empty() => Style::default().fg(Color::Yellow),
        ContainerRole::App => Style::default(),
    };

    let (conf_text, conf_style) = confidence_label(r);

    let cpu_req = delta_cell(&r.current_cpu_request, &r.burstable_cpu_request, r, "cpu");
    let cpu_lim = delta_cell(&r.current_cpu_limit, &r.burstable_cpu_limit, r, "cpu");
    let mem_req = delta_cell(
        &r.current_memory_request,
        &r.burstable_memory_request,
        r,
        "memory",
    );
    let mem_lim = delta_cell(
        &r.current_memory_limit,
        &r.burstable_memory_limit,
        r,
        "memory",
    );

    Row::new(vec![
        Cell::from(workload_cell),
        Cell::from(container_cell).style(container_style),
        Cell::from(conf_text).style(conf_style),
        cpu_req,
        cpu_lim,
        mem_req,
        mem_lim,
    ])
    .style(base)
}

/// Confidence indicator from VPA conditions.
///   ● fresh + high conf | ◐ low confidence | ○ no rec / unknown
fn confidence_label(r: &RightsizingRec) -> (String, Style) {
    let age = r.last_update_age_secs;
    if r.low_confidence {
        return (
            match age {
                Some(s) => format!("◐ {}", humanize_age(s)),
                None => "◐ ?".to_string(),
            },
            Style::default().fg(Color::Yellow),
        );
    }
    match age {
        Some(s) if s < 3600 => (
            format!("○ {}", humanize_age(s)),
            Style::default().fg(Color::Yellow),
        ),
        Some(s) if s < 86400 * 7 => (
            format!("● {}", humanize_age(s)),
            Style::default().fg(Color::Green),
        ),
        Some(s) => (
            format!("● {}", humanize_age(s)),
            Style::default().fg(Color::Green),
        ),
        None => ("○ ?".to_string(), Style::default().fg(Color::Gray)),
    }
}

/// Render a "current → recommended" cell with semantic coloring:
///   red  — rec > current (under-provisioned, OOM/throttle risk)
///   green — rec ≪ current (significantly over-provisioned, savings)
///   default — already within reasonable range
/// HPA-conflicting cells on the conflicting resource are flattened to yellow
/// instead so users see "don't touch this" rather than "save money here".
fn delta_cell<'a>(
    current: &Option<String>,
    recommended: &str,
    r: &RightsizingRec,
    resource: &str,
) -> Cell<'a> {
    let cur_display = current.as_deref().unwrap_or("—");
    let text = format!("{} → {}", cur_display, recommended);

    let hpa_conflict = r.hpa_conflicts.iter().any(|s| s == resource);
    let cur = current.as_deref().and_then(parse_quantity);
    let rec = parse_quantity(recommended);

    let style = match (cur, rec) {
        _ if hpa_conflict => Style::default().fg(Color::Yellow),
        (Some(c), Some(rv)) if c > 0.0 => {
            let ratio = rv / c;
            if ratio > 1.10 {
                Style::default().fg(Color::Red)
            } else if ratio < 0.33 {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            }
        }
        _ => Style::default(),
    };
    Cell::from(text).style(style)
}

fn rightsizing_footer<'a>(data: &'a DashboardData) -> Paragraph<'a> {
    use std::collections::BTreeSet;
    let workloads: BTreeSet<(&str, &str)> = data
        .rightsizing
        .iter()
        .map(|r| (r.namespace.as_str(), r.workload.as_str()))
        .collect();
    let namespaces: BTreeSet<&str> = data
        .rightsizing
        .iter()
        .map(|r| r.namespace.as_str())
        .collect();
    let sidecars = data
        .rightsizing
        .iter()
        .filter(|r| r.container_role == ContainerRole::Sidecar)
        .count();
    let inits = data
        .rightsizing
        .iter()
        .filter(|r| r.container_role == ContainerRole::Init)
        .count();
    let hpa_conflicts = data
        .rightsizing
        .iter()
        .filter(|r| !r.hpa_conflicts.is_empty())
        .count();
    let low_conf = data.rightsizing.iter().filter(|r| r.low_confidence).count();
    let newest_age = data
        .rightsizing
        .iter()
        .filter_map(|r| r.last_update_age_secs)
        .min();

    let last = newest_age
        .map(humanize_age)
        .unwrap_or_else(|| "?".to_string());
    let summary = format!(
        "{} workloads · {} containers ({} sidecars · {} init) · {} ns · {} HPA-conflict · {} low-conf · last VPA update: {}",
        workloads.len(),
        data.rightsizing.len(),
        sidecars,
        inits,
        namespaces.len(),
        hpa_conflicts,
        low_conf,
        last,
    );
    Paragraph::new(summary).block(Block::default().borders(Borders::ALL).title(" Status "))
}

fn render_help(frame: &mut Frame, area: Rect) {
    let help_text = vec![
        "Keyboard Shortcuts:",
        "",
        "  Navigation:",
        "    1-8     Switch between views",
        "    j/↓     Move down",
        "    k/↑     Move up",
        "    PgUp    Page up",
        "    PgDn    Page down",
        "    Home    Go to top",
        "    Esc     Go back / Cancel",
        "",
        "  Actions:",
        "    Enter   Select / Toggle",
        "    r       Refresh data",
        "    /       Search",
        "    ?       Show this help",
        "    q       Quit",
        "",
        "  Views:",
        "    1 Overview     - Cluster summary",
        "    2 Nodes        - Node status and resources",
        "    3 Security     - Policy findings (Kyverno / Trivy)",
        "    4 FinOps       - Cost by namespace",
        "    5 Providers    - Crossplane provider configs & auth",
        "    6 Rightsizing  - VPA recommendations (Goldilocks)",
    ];

    let paragraph = Paragraph::new(help_text.join("\n"))
        .block(Block::default().borders(Borders::ALL).title(" Help "))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

/// Detail view for the security finding the user has selected in tab 3.
/// Reads from the SAME list the Security tab renders (issues), fixing the
/// previous bug where Enter indexed into `vulnerabilities` while selection
/// was over `issues`.
fn render_security_detail(
    frame: &mut Frame,
    area: Rect,
    dashboard: &Dashboard,
    data: &DashboardData,
) {
    if dashboard.selected_index >= data.security.issues.len() {
        let message = Paragraph::new("No finding selected. Press Esc to go back.").block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Finding Detail "),
        );
        frame.render_widget(message, area);
        return;
    }

    let issue = &data.security.issues[dashboard.selected_index];
    let mut lines = vec![
        format!("Severity:   {:?}", issue.severity),
        format!("Result:     {}", issue.result),
        format!("Source:     {}", issue.source),
        format!("Policy:     {}", issue.policy),
        format!("Rule:       {}", issue.rule),
        format!("Category:   {:?}", issue.category),
        format!("Resource:   {}", issue.resource),
        String::new(),
        "Message:".to_string(),
        issue.message.clone(),
    ];
    if !issue.remediation.is_empty() {
        lines.push(String::new());
        lines.push("Remediation:".to_string());
        lines.push(issue.remediation.clone());
    }
    lines.push(String::new());
    lines.push("Esc — back to findings list".to_string());

    let paragraph = Paragraph::new(lines.join("\n"))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Finding Detail "),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn render_providers(frame: &mut Frame, area: Rect, dashboard: &Dashboard, data: &DashboardData) {
    let has_configs = !data.provider_configs.is_empty();
    let has_auth = !data.auth_providers.is_empty();

    if !has_configs && !has_auth {
        let message = Paragraph::new(
            "No Crossplane Providers or Auth Providers found.\n\n\
            This view displays:\n\
            • Crossplane ProviderConfigs (AWS, GCP, Azure, etc.)\n\
            • Crossplane Provider packages\n\
            • External Secrets SecretStores & ClusterSecretStores\n\
            • ServiceAccounts with IRSA/Workload Identity\n\n\
            Install Crossplane or External Secrets Operator to see providers here.",
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Providers & Auth "),
        );
        frame.render_widget(message, area);
        return;
    }

    // Main layout: summary + two tables (configs and auth)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),      // Summary
            Constraint::Percentage(45), // Provider Configs
            Constraint::Percentage(45), // Auth Providers
        ])
        .split(area);

    // Summary section
    let config_healthy = data
        .provider_configs
        .iter()
        .filter(|p| p.status == ProviderStatus::Healthy)
        .count();
    let config_error = data
        .provider_configs
        .iter()
        .filter(|p| p.status == ProviderStatus::Error)
        .count();
    let auth_healthy = data
        .auth_providers
        .iter()
        .filter(|p| p.status == ProviderStatus::Healthy)
        .count();
    let auth_error = data
        .auth_providers
        .iter()
        .filter(|p| p.status == ProviderStatus::Error)
        .count();

    let summary =
        format!(
        "Provider Configs: {} ({}✓ {}✗) | Auth Providers: {} ({}✓ {}✗) | [Tab to switch sections]",
        data.provider_configs.len(), config_healthy, config_error,
        data.auth_providers.len(), auth_healthy, auth_error,
    );
    let summary_block =
        Paragraph::new(summary).block(Block::default().borders(Borders::ALL).title(" Summary "));
    frame.render_widget(summary_block, chunks[0]);

    // Provider Configs table
    let config_header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Type"),
        Cell::from("Status"),
        Cell::from("Credentials"),
        Cell::from("Secret Ref"),
        Cell::from("Resources"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .height(1);

    let cfg_len = data.provider_configs.len();
    let auth_len = data.auth_providers.len();
    let total = cfg_len + auth_len;
    let selected = dashboard.selected_index.min(total.saturating_sub(1));

    let config_rows: Vec<Row> = data
        .provider_configs
        .iter()
        .enumerate()
        .map(|(i, provider)| {
            let style = if i == selected && selected < cfg_len {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            let status_style = match provider.status {
                ProviderStatus::Healthy => Style::default().fg(Color::Green),
                ProviderStatus::Degraded => Style::default().fg(Color::Yellow),
                ProviderStatus::Error => Style::default().fg(Color::Red),
                ProviderStatus::Unknown => Style::default().fg(Color::Gray),
            };

            let status_text = match provider.status {
                ProviderStatus::Healthy => "✓",
                ProviderStatus::Degraded => "◐",
                ProviderStatus::Error => "✗",
                ProviderStatus::Unknown => "?",
            };

            Row::new(vec![
                Cell::from(truncate_string(&provider.name, 20)),
                Cell::from(provider.provider_type.to_string()),
                Cell::from(status_text).style(status_style),
                Cell::from(truncate_string(&provider.credentials_source, 15)),
                Cell::from(
                    provider
                        .secret_ref
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Cell::from(provider.associated_resources.to_string()),
            ])
            .style(style)
        })
        .collect();

    let config_table = Table::new(
        config_rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(12),
            Constraint::Percentage(8),
            Constraint::Percentage(15),
            Constraint::Percentage(30),
            Constraint::Percentage(15),
        ],
    )
    .header(config_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Crossplane ProviderConfigs "),
    );

    let mut config_state = TableState::default();
    if cfg_len > 0 && selected < cfg_len {
        config_state.select(Some(selected));
    }
    frame.render_stateful_widget(config_table, chunks[1], &mut config_state);

    // Auth Providers table
    let auth_header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Type"),
        Cell::from("Status"),
        Cell::from("Backend"),
        Cell::from("Namespace"),
        Cell::from("Service Account"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .height(1);

    let auth_rows: Vec<Row> = data
        .auth_providers
        .iter()
        .enumerate()
        .map(|(i, auth)| {
            let adjusted_index = i + cfg_len;
            let style = if adjusted_index == selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            let status_style = match auth.status {
                ProviderStatus::Healthy => Style::default().fg(Color::Green),
                ProviderStatus::Degraded => Style::default().fg(Color::Yellow),
                ProviderStatus::Error => Style::default().fg(Color::Red),
                ProviderStatus::Unknown => Style::default().fg(Color::Gray),
            };

            let status_text = match auth.status {
                ProviderStatus::Healthy => "✓",
                ProviderStatus::Degraded => "◐",
                ProviderStatus::Error => "✗",
                ProviderStatus::Unknown => "?",
            };

            let type_color = match auth.auth_type {
                AuthProviderType::CrossplaneProvider => Color::Cyan,
                AuthProviderType::SecretStore | AuthProviderType::ClusterSecretStore => {
                    Color::Magenta
                }
                AuthProviderType::AwsIrsa => Color::Yellow,
                AuthProviderType::GcpWorkloadIdentity => Color::Blue,
                AuthProviderType::AzureWorkloadIdentity => Color::LightBlue,
                AuthProviderType::Vault => Color::LightGreen,
                AuthProviderType::Other(_) => Color::Gray,
            };

            Row::new(vec![
                Cell::from(truncate_string(&auth.name, 20)),
                Cell::from(auth.auth_type.to_string()).style(Style::default().fg(type_color)),
                Cell::from(status_text).style(status_style),
                Cell::from(truncate_string(&auth.backend, 25)),
                Cell::from(
                    auth.namespace
                        .clone()
                        .unwrap_or_else(|| "(cluster)".to_string()),
                ),
                Cell::from(
                    auth.service_account
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                ),
            ])
            .style(style)
        })
        .collect();

    let auth_table = Table::new(
        auth_rows,
        [
            Constraint::Percentage(18),
            Constraint::Percentage(18),
            Constraint::Percentage(8),
            Constraint::Percentage(24),
            Constraint::Percentage(16),
            Constraint::Percentage(16),
        ],
    )
    .header(auth_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Auth Providers (Crossplane Pkgs, SecretStores, Workload Identity) "),
    );

    let mut auth_state = TableState::default();
    if auth_len > 0 && selected >= cfg_len {
        auth_state.select(Some(selected - cfg_len));
    }
    frame.render_stateful_widget(auth_table, chunks[2], &mut auth_state);
}

fn render_provider_detail(
    frame: &mut Frame,
    area: Rect,
    dashboard: &Dashboard,
    data: &DashboardData,
) {
    let total_items = data.provider_configs.len() + data.auth_providers.len();

    if dashboard.selected_index >= total_items {
        let message = Paragraph::new("No provider selected. Press Esc to go back.").block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Provider Detail "),
        );
        frame.render_widget(message, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(0)])
        .split(area);

    // Determine if we're showing a ProviderConfig or an AuthProvider
    if dashboard.selected_index < data.provider_configs.len() {
        // Show ProviderConfig detail
        let provider = &data.provider_configs[dashboard.selected_index];

        let status_indicator = match provider.status {
            ProviderStatus::Healthy => "● Healthy",
            ProviderStatus::Degraded => "◐ Degraded",
            ProviderStatus::Error => "○ Error",
            ProviderStatus::Unknown => "? Unknown",
        };

        let details = vec![
            format!("Name: {}", provider.name),
            format!("Type: ProviderConfig"),
            format!("Provider: {}", provider.provider_type),
            format!("Status: {}", status_indicator),
            format!("Credentials Source: {}", provider.credentials_source),
            format!(
                "Secret Reference: {}",
                provider.secret_ref.as_deref().unwrap_or("N/A")
            ),
            format!("Associated Resources: {}", provider.associated_resources),
            format!(
                "Last Sync: {}",
                provider.last_sync.as_deref().unwrap_or("N/A")
            ),
            String::new(),
            format!("Message: {}", provider.message.as_deref().unwrap_or("None")),
        ];

        let info_block = Paragraph::new(details.join("\n"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" ProviderConfig Detail "),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(info_block, chunks[0]);

        let cmd1 = format!(
            "  kubectl describe providerconfig {} -o yaml",
            provider.name
        );
        let cmd2 = format!("  kubectl get providerconfig {} -o yaml", provider.name);
        let actions = vec![
            "kubectl Commands:".to_string(),
            String::new(),
            cmd1,
            cmd2,
            String::new(),
            "Navigation:".to_string(),
            "  Esc - Return to providers list".to_string(),
            "  r   - Refresh data".to_string(),
        ];

        let actions_block = Paragraph::new(actions.join("\n"))
            .block(Block::default().borders(Borders::ALL).title(" Actions "))
            .wrap(Wrap { trim: false });
        frame.render_widget(actions_block, chunks[1]);
    } else {
        // Show AuthProvider detail
        let auth_index = dashboard.selected_index - data.provider_configs.len();
        let auth = &data.auth_providers[auth_index];

        let status_indicator = match auth.status {
            ProviderStatus::Healthy => "● Healthy",
            ProviderStatus::Degraded => "◐ Degraded",
            ProviderStatus::Error => "○ Error",
            ProviderStatus::Unknown => "? Unknown",
        };

        let details = vec![
            format!("Name: {}", auth.name),
            format!("Type: {}", auth.auth_type),
            format!("Status: {}", status_indicator),
            format!("Backend: {}", auth.backend),
            format!(
                "Namespace: {}",
                auth.namespace.as_deref().unwrap_or("(cluster-scoped)")
            ),
            format!(
                "Secret Reference: {}",
                auth.secret_ref.as_deref().unwrap_or("N/A")
            ),
            format!(
                "Service Account: {}",
                auth.service_account.as_deref().unwrap_or("N/A")
            ),
            format!("Last Sync: {}", auth.last_sync.as_deref().unwrap_or("N/A")),
            String::new(),
            format!("Message: {}", auth.message.as_deref().unwrap_or("None")),
        ];

        let info_block = Paragraph::new(details.join("\n"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Auth Provider Detail "),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(info_block, chunks[0]);

        let kubectl_cmd = match auth.auth_type {
            AuthProviderType::CrossplaneProvider => {
                format!(
                    "  kubectl describe provider.pkg.crossplane.io {}",
                    auth.name
                )
            }
            AuthProviderType::ClusterSecretStore => {
                format!("  kubectl describe clustersecretstore {}", auth.name)
            }
            AuthProviderType::SecretStore => {
                let ns = auth.namespace.as_deref().unwrap_or("default");
                format!("  kubectl describe secretstore {} -n {}", auth.name, ns)
            }
            AuthProviderType::AwsIrsa
            | AuthProviderType::GcpWorkloadIdentity
            | AuthProviderType::AzureWorkloadIdentity => {
                let ns = auth.namespace.as_deref().unwrap_or("default");
                format!("  kubectl describe serviceaccount {} -n {}", auth.name, ns)
            }
            _ => format!("  kubectl get {} -o yaml", auth.name),
        };

        let actions = vec![
            "kubectl Commands:".to_string(),
            String::new(),
            kubectl_cmd,
            String::new(),
            "Navigation:".to_string(),
            "  Esc - Return to providers list".to_string(),
            "  r   - Refresh data".to_string(),
        ];

        let actions_block = Paragraph::new(actions.join("\n"))
            .block(Block::default().borders(Borders::ALL).title(" Actions "))
            .wrap(Wrap { trim: false });
        frame.render_widget(actions_block, chunks[1]);
    }
}

fn render_status_bar(frame: &mut Frame, area: Rect, dashboard: &Dashboard, data: &DashboardData) {
    let status = if let Some(ref msg) = dashboard.status_message {
        msg.clone()
    } else {
        format!(
            "Nodes: {} | Namespaces: {} | Pods: {} | Issues: {} | Press ? for help, q to quit",
            data.cluster_info.node_count,
            data.cluster_info.namespace_count,
            data.cluster_info.pod_count,
            data.security.issues.len(),
        )
    };

    let status_bar = Paragraph::new(status)
        .style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(status_bar, area);
}

fn render_search_popup(frame: &mut Frame, dashboard: &Dashboard) {
    let area = centered_rect(60, 3, frame.area());
    frame.render_widget(Clear, area);

    let search = Paragraph::new(format!("Search: {}_", dashboard.search_query)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Search (Esc to cancel) "),
    );
    frame.render_widget(search, area);
}

fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((r.height - height) / 2),
            Constraint::Length(height),
            Constraint::Length((r.height - height) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn list_state(len: usize, selected: usize) -> TableState {
    let mut s = TableState::default();
    if len > 0 {
        s.select(Some(selected.min(len - 1)));
    }
    s
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
