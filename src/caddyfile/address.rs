//! Site address parsing, ported from `caddyconfig/httpcaddyfile/addresses.go`
//! (`ParseAddress`) and the `specificity` helper in `httptype.go`. A site
//! address like `https://example.com:8443/path` is split into scheme, host,
//! port and path, which the adapter turns into host/path matchers.

use anyhow::{Result, bail};

const DEFAULT_HTTP_PORT: &str = "80";
const DEFAULT_HTTPS_PORT: &str = "443";

/// A parsed site address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Address {
    pub original: String,
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub path: String,
}

impl Address {
    /// Faithful port of `ParseAddress`. Splits `str` into scheme/host/port/path.
    pub fn parse(s: &str) -> Result<Address> {
        const MAX_LEN: usize = 4096;
        let mut remaining = s;
        if remaining.len() > MAX_LEN {
            remaining = &remaining[..MAX_LEN];
        }
        let remaining = remaining.trim();
        let mut a = Address {
            original: remaining.to_string(),
            ..Default::default()
        };

        // Extract scheme.
        let mut rest = remaining;
        if let Some((scheme, after)) = remaining.split_once("://") {
            a.scheme = scheme.to_string();
            rest = after;
        }

        // Extract host and port (and path).
        let (hostport, path) = match rest.split_once('/') {
            Some((hp, p)) => (hp, Some(p)),
            None => (rest, None),
        };
        let (host, port) = split_host_port(hostport);
        a.host = host;
        a.port = port;
        if let Some(p) = path {
            a.path = format!("/{p}");
        }

        // Validate the port.
        if !a.port.is_empty() {
            match a.port.parse::<i64>() {
                Ok(n) if (0..=65535).contains(&n) => {}
                Ok(n) => bail!("port {n} is out of range"),
                Err(e) => bail!("invalid port '{}': {e}", a.port),
            }
        }

        match a.scheme.as_str() {
            "" | "http" | "https" => {}
            "wss" => bail!("the scheme wss:// is only supported in browsers; use https:// instead"),
            "ws" => bail!("the scheme ws:// is only supported in browsers; use http:// instead"),
            other => bail!("unsupported URL scheme {other}://"),
        }

        Ok(a)
    }

    /// Renders the address back to its canonical string form. Port of
    /// `Address.String`.
    pub fn to_address_string(&self) -> String {
        if self.host.is_empty() && self.port.is_empty() {
            return String::new();
        }
        let scheme = if !self.scheme.is_empty() {
            self.scheme.clone()
        } else if self.port == DEFAULT_HTTPS_PORT {
            "https".to_string()
        } else {
            "http".to_string()
        };
        let mut s = format!("{scheme}://");
        let nonstandard = (scheme == "https" && self.port != DEFAULT_HTTPS_PORT)
            || (scheme == "http" && self.port != DEFAULT_HTTP_PORT);
        if !self.port.is_empty() && nonstandard {
            s.push_str(&join_host_port(&self.host, &self.port));
        } else {
            s.push_str(&self.host);
        }
        if !self.path.is_empty() {
            s.push_str(&self.path);
        }
        s
    }
}

/// Splits a `host:port` string. Mirrors Go's `net.SplitHostPort` for the cases
/// the Caddyfile uses, falling back to "all host, no port" when there's no
/// usable colon. Handles bracketed IPv6 literals.
fn split_host_port(s: &str) -> (String, String) {
    if s.is_empty() {
        return (String::new(), String::new());
    }
    // Bracketed IPv6: [::1]:8080 or [::1]
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = &rest[..close];
            let after = &rest[close + 1..];
            if let Some(port) = after.strip_prefix(':') {
                return (host.to_string(), port.to_string());
            }
            return (host.to_string(), String::new());
        }
        // Malformed; treat whole thing as host.
        return (s.to_string(), String::new());
    }
    // A single trailing colon separating host and port. Multiple colons without
    // brackets => treat as bare host (an unbracketed IPv6, which Caddy leaves
    // as the host).
    match (s.find(':'), s.rfind(':')) {
        (Some(i), Some(j)) if i == j => (s[..i].to_string(), s[i + 1..].to_string()),
        _ => (s.to_string(), String::new()),
    }
}

/// Joins a host and port, bracketing IPv6 literals.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Computes the "specificity" of a host or path string for sorting site blocks
/// (more specific first). Port of `specificity` in httptype.go: it's the length
/// minus wildcards and minus the length of any `{...}` placeholders.
pub fn specificity(s: &str) -> i64 {
    let mut l = s.len() as i64 - s.matches('*').count() as i64;
    let mut s = s;
    while !s.is_empty() {
        let Some(start) = s.find('{') else {
            return l;
        };
        let Some(end_rel) = s[start..].find('}') else {
            return l;
        };
        let end = end_rel + start + 1;
        l -= (end - start) as i64;
        s = &s[end..];
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scheme_host_port_path() {
        let a = Address::parse("https://example.com:8443/api").unwrap();
        assert_eq!(a.scheme, "https");
        assert_eq!(a.host, "example.com");
        assert_eq!(a.port, "8443");
        assert_eq!(a.path, "/api");
    }

    #[test]
    fn parses_bare_host() {
        let a = Address::parse("example.com").unwrap();
        assert_eq!(a.scheme, "");
        assert_eq!(a.host, "example.com");
        assert_eq!(a.port, "");
        assert_eq!(a.path, "");
    }

    #[test]
    fn parses_port_only() {
        let a = Address::parse(":8080").unwrap();
        assert_eq!(a.host, "");
        assert_eq!(a.port, "8080");
    }

    #[test]
    fn rejects_bad_port() {
        assert!(Address::parse(":99999").is_err());
    }

    #[test]
    fn rejects_unsupported_schemes_like_caddy() {
        let err = Address::parse("foo://example.com").unwrap_err().to_string();
        assert_eq!(err, "unsupported URL scheme foo://");

        let err = Address::parse("wss://example.com").unwrap_err().to_string();
        assert_eq!(
            err,
            "the scheme wss:// is only supported in browsers; use https:// instead"
        );

        let err = Address::parse("ws://example.com").unwrap_err().to_string();
        assert_eq!(
            err,
            "the scheme ws:// is only supported in browsers; use http:// instead"
        );
    }

    #[test]
    fn port_errors_take_priority_over_unsupported_schemes_like_caddy() {
        let err = Address::parse("wss://example.com:70000")
            .unwrap_err()
            .to_string();
        assert_eq!(err, "port 70000 is out of range");
    }

    #[test]
    fn specificity_discounts_wildcards_and_placeholders() {
        // Pure length math: each '*' and each {placeholder} span is subtracted.
        // (Wildcard-host de-prioritization is handled separately in the sort.)
        assert_eq!(specificity("/foo*"), 4);
        assert_eq!(specificity("example.com"), 11);
        assert!(specificity("a.example.com") > specificity("example.com"));
        assert!(specificity("/{http.foo}/x") < specificity("/abc/x"));
    }
}
