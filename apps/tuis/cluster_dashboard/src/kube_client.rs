//! Kube client construction with kubectl-compatible proxy bypass.
//!
//! `kube` picks up `HTTPS_PROXY`/`https_proxy` but ignores `NO_PROXY` and does
//! not special-case loopback, so a local `HTTPS_PROXY` breaks talking to a
//! kind/minikube apiserver on `127.0.0.1`. Go's `net/http` (and therefore
//! kubectl) always bypasses loopback and honours `NO_PROXY`; mirror that here.

use kube::{Client, Config};

/// Build a client from the ambient kubeconfig, dropping the inferred proxy when
/// the apiserver host must be reached directly.
pub async fn client() -> anyhow::Result<Client> {
    let mut config = Config::infer().await?;

    if config.proxy_url.is_some() {
        let host = config.cluster_url.host().unwrap_or_default().to_string();
        if bypass_proxy(&host, no_proxy_env().as_deref()) {
            config.proxy_url = None;
        }
    }

    Ok(Client::try_from(config)?)
}

fn no_proxy_env() -> Option<String> {
    std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .ok()
}

/// Go `httpproxy` semantics, minus CIDR entries: loopback is always direct,
/// `*` bypasses everything, and entries match the host exactly or as a domain
/// suffix.
fn bypass_proxy(host: &str, no_proxy: Option<&str>) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if is_loopback(host) {
        return true;
    }

    let Some(no_proxy) = no_proxy else {
        return false;
    };

    no_proxy.split(',').map(str::trim).any(|entry| {
        if entry.is_empty() {
            return false;
        }
        if entry == "*" {
            return true;
        }
        let entry = entry.trim_start_matches('.');
        host.eq_ignore_ascii_case(entry)
            || (host.len() > entry.len()
                && host.as_bytes()[host.len() - entry.len() - 1] == b'.'
                && host[host.len() - entry.len()..].eq_ignore_ascii_case(entry))
    })
}

fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::bypass_proxy;

    #[test]
    fn loopback_is_always_direct() {
        assert!(bypass_proxy("127.0.0.1", None));
        assert!(bypass_proxy("localhost", None));
        assert!(bypass_proxy("::1", None));
        assert!(bypass_proxy("[::1]", None));
    }

    #[test]
    fn remote_host_uses_proxy_by_default() {
        assert!(!bypass_proxy("k8s.example.com", None));
        assert!(!bypass_proxy(
            "k8s.example.com",
            Some("localhost,127.0.0.1")
        ));
    }

    #[test]
    fn no_proxy_entries_match_host_and_suffix() {
        assert!(bypass_proxy("k8s.example.com", Some("k8s.example.com")));
        assert!(bypass_proxy("k8s.example.com", Some(".example.com")));
        assert!(bypass_proxy("k8s.example.com", Some("example.com")));
        assert!(bypass_proxy("k8s.example.com", Some("*")));
        assert!(!bypass_proxy("notexample.com", Some("example.com")));
        assert!(!bypass_proxy("example.com.evil.net", Some("example.com")));
    }
}
