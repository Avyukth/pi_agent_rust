//! URL checks shared by live and explicitly simulated browser backends.

use crate::error::{Error, Result};
use url::Url;

pub(super) fn check_navigation(raw: &str, allowlist: Option<&[String]>) -> Result<()> {
    if raw == "about:blank" {
        return Ok(());
    }
    let url = Url::parse(raw).map_err(|e| Error::tool("browser", format!("invalid URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::tool(
            "browser",
            "navigation requires HTTP(S) without URL credentials, or about:blank",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::tool("browser", "navigation URL has no host"))?;
    if let Some(allowed) = allowlist
        && !allowed.iter().any(|rule| host_matches(host, rule))
    {
        return Err(Error::tool(
            "browser",
            format!("navigation to {raw} blocked by domain allowlist"),
        ));
    }
    Ok(())
}

fn host_matches(host: &str, rule: &str) -> bool {
    let rule = rule.trim().to_ascii_lowercase();
    if rule == "*" {
        return true;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let (subdomains, domain) = rule
        .strip_prefix("*.")
        .map_or((false, rule.as_str()), |s| (true, s));
    // Parse rules as hosts, never as substrings of a URL. This also normalizes IDNA.
    let Ok(parsed) = url::Host::parse(domain.trim_end_matches('.')) else {
        return false;
    };
    let domain = parsed.to_string();
    if subdomains {
        host.len() > domain.len() + 1 && host.ends_with(&format!(".{domain}"))
    } else {
        host == domain
    }
}

/// CDP is a powerful unauthenticated local control channel. Do not let endpoint
/// discovery turn an explicit loopback attachment into arbitrary remote access.
pub(super) fn endpoint(raw: &str, websocket: bool) -> Result<Url> {
    let url = Url::parse(raw)
        .map_err(|e| Error::tool("browser", format!("invalid CDP endpoint: {e}")))?;
    let local = match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        // The current native WebSocket handshake does not support IPv6 URL
        // authorities reliably. Require IPv4 loopback rather than misroute it.
        _ => false,
    };
    if !local
        || url.scheme() != if websocket { "ws" } else { "http" }
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (!websocket && url.path() != "/")
        || (websocket && !url.path().starts_with("/devtools/browser/"))
    {
        return Err(Error::tool(
            "browser",
            "CDP endpoint must be an unauthenticated IPv4-loopback or localhost URL (HTTP discovery / WebSocket browser target)",
        ));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches_hosts_not_userinfo_paths_queries_or_suffixes() {
        let rules = vec!["example.com".into()];
        for url in ["https://example.com/", "https://EXAMPLE.com.:443/docs"] {
            assert!(check_navigation(url, Some(&rules)).is_ok(), "{url}");
        }
        for url in [
            "https://evil.test/?next=example.com",
            "https://evil.test/example.com",
            "https://example.com.evil.test",
            "https://notexample.com",
            "https://example.com@evil.test",
            "https://sub.example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hello",
        ] {
            assert!(check_navigation(url, Some(&rules)).is_err(), "{url}");
        }
    }

    #[test]
    fn wildcard_has_a_label_boundary_and_empty_policy_denies_network() {
        assert!(host_matches("a.b.example.com", "*.example.com"));
        assert!(!host_matches("example.com", "*.example.com"));
        assert!(!host_matches("notexample.com", "*.example.com"));
        assert!(!host_matches("example.com", "https://example.com"));
        assert!(check_navigation("about:blank", Some(&[])).is_ok());
        assert!(check_navigation("https://example.com", Some(&[])).is_err());
    }

    #[test]
    fn cdp_discovery_rejects_remote_credentialed_and_ambiguous_endpoints() {
        assert!(endpoint("http://127.0.0.1:9222", false).is_ok());
        assert!(endpoint("ws://localhost:9222/devtools/browser/uuid", true).is_ok());
        for raw in [
            "http://example.com:9222",
            "http://127.0.0.1.evil.test:9222",
            "http://user:pass@localhost:9222",
            "http://localhost:9222/?token=x",
            "http://localhost:9222/proxy",
            "file:///json/version",
        ] {
            assert!(endpoint(raw, false).is_err(), "{raw}");
        }
    }
}
