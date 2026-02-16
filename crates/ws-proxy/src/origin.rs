use thiserror::Error;

#[derive(Debug, Error)]
pub enum OriginRejection {
    #[error("malformed Origin header")]
    Malformed,
    #[error("origin '{origin}' is not in the allowlist")]
    NotAllowed { origin: String },
}

/// Returns `true` if the origin is a localhost variant.
fn is_localhost(origin: &str) -> bool {
    // Strip the scheme (http:// or https://) if present, then check the host.
    let host = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .unwrap_or(origin);

    // Handle bracketed IPv6 addresses like [::1] or [::1]:9000
    if host.starts_with('[') {
        // Extract the bracketed host (e.g., "[::1]" from "[::1]:9000")
        return match host.find(']') {
            Some(end) => {
                let bracketed = &host[..=end];
                matches!(bracketed, "[::1]")
            }
            None => false,
        };
    }

    // For non-bracketed hosts, strip port by splitting on the last colon
    // (but only if the result looks like host:port, not an IPv6 like ::1)
    if host == "::1" {
        return true;
    }

    // Split on the last colon for host:port separation
    let host_no_port = match host.rfind(':') {
        Some(pos) => {
            // Verify what comes after is a port number
            let after = &host[pos + 1..];
            if after.chars().all(|c| c.is_ascii_digit()) {
                &host[..pos]
            } else {
                host
            }
        }
        None => host,
    };

    matches!(host_no_port, "localhost" | "127.0.0.1")
}

/// Performs simple glob matching where `*` matches any sequence of characters.
///
/// Only the `*` wildcard is supported (no `?`, no `[...]` ranges). Multiple
/// `*` characters are allowed.
fn glob_match(pattern: &str, value: &str) -> bool {
    // Split the pattern by '*' and verify that the value contains each segment
    // in order.
    let segments: Vec<&str> = pattern.split('*').collect();

    if segments.len() == 1 {
        // No wildcard -- exact match.
        return pattern == value;
    }

    let mut remaining = value;

    for (i, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            continue;
        }

        if i == 0 {
            // First segment must be a prefix.
            if let Some(rest) = remaining.strip_prefix(segment) {
                remaining = rest;
            } else {
                return false;
            }
        } else if i == segments.len() - 1 {
            // Last segment must be a suffix.
            if !remaining.ends_with(segment) {
                return false;
            }
            remaining = "";
        } else {
            // Middle segments: find the first occurrence.
            if let Some(pos) = remaining.find(segment) {
                remaining = &remaining[pos + segment.len()..];
            } else {
                return false;
            }
        }
    }

    true
}

/// Validates the Origin header from an HTTP upgrade request.
///
/// - If no Origin header is present, the request is allowed (CLI clients
///   typically do not send an Origin header).
/// - Localhost origins (`127.0.0.1`, `::1`, `localhost` on any port) are always
///   allowed regardless of the allowlist.
/// - Otherwise, the origin is checked against the user-configured `allowlist`.
///   Each entry in the allowlist may contain `*` as a wildcard that matches any
///   sequence of characters.
/// - Returns `Err(OriginRejection)` if the origin is malformed or not allowed.
pub fn validate_origin(
    origin_header: Option<&str>,
    allowlist: &[String],
) -> Result<(), OriginRejection> {
    let origin = match origin_header {
        // No Origin header -- allow (CLI clients don't send it).
        None => return Ok(()),
        Some(o) if o.is_empty() => return Err(OriginRejection::Malformed),
        Some(o) => o,
    };

    // Always allow localhost origins.
    if is_localhost(origin) {
        return Ok(());
    }

    // Check against each pattern in the allowlist.
    for pattern in allowlist {
        if glob_match(pattern, origin) {
            return Ok(());
        }
    }

    Err(OriginRejection::NotAllowed {
        origin: origin.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // validate_origin
    // -----------------------------------------------------------------------

    #[test]
    fn no_origin_header_is_allowed() {
        assert!(validate_origin(None, &[]).is_ok());
    }

    #[test]
    fn empty_origin_is_malformed() {
        let result = validate_origin(Some(""), &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OriginRejection::Malformed));
    }

    #[test]
    fn localhost_is_always_allowed() {
        let empty: Vec<String> = vec![];
        assert!(validate_origin(Some("http://localhost"), &empty).is_ok());
        assert!(validate_origin(Some("http://localhost:3000"), &empty).is_ok());
        assert!(validate_origin(Some("http://127.0.0.1"), &empty).is_ok());
        assert!(validate_origin(Some("http://127.0.0.1:8080"), &empty).is_ok());
        assert!(validate_origin(Some("http://[::1]"), &empty).is_ok());
        assert!(validate_origin(Some("http://[::1]:9000"), &empty).is_ok());
        assert!(validate_origin(Some("https://localhost"), &empty).is_ok());
    }

    #[test]
    fn non_localhost_rejected_with_empty_allowlist() {
        let empty: Vec<String> = vec![];
        let result = validate_origin(Some("https://example.com"), &empty);
        assert!(result.is_err());
        match result.unwrap_err() {
            OriginRejection::NotAllowed { origin } => {
                assert_eq!(origin, "https://example.com");
            }
            other => panic!("expected NotAllowed, got {:?}", other),
        }
    }

    #[test]
    fn exact_match_in_allowlist() {
        let allowlist = vec!["https://example.com".to_string()];
        assert!(validate_origin(Some("https://example.com"), &allowlist).is_ok());
    }

    #[test]
    fn glob_wildcard_in_allowlist() {
        let allowlist = vec!["https://*.example.com".to_string()];
        assert!(validate_origin(Some("https://app.example.com"), &allowlist).is_ok());
        assert!(validate_origin(Some("https://staging.example.com"), &allowlist).is_ok());
        // The pattern requires the prefix "https://" and the suffix ".example.com"
        assert!(validate_origin(Some("https://evil.com"), &allowlist).is_err());
    }

    #[test]
    fn multiple_wildcards() {
        let allowlist = vec!["https://*.example.*".to_string()];
        assert!(validate_origin(Some("https://app.example.com"), &allowlist).is_ok());
        assert!(validate_origin(Some("https://app.example.org"), &allowlist).is_ok());
    }

    #[test]
    fn multiple_allowlist_entries() {
        let allowlist = vec![
            "https://alpha.com".to_string(),
            "https://beta.com".to_string(),
        ];
        assert!(validate_origin(Some("https://alpha.com"), &allowlist).is_ok());
        assert!(validate_origin(Some("https://beta.com"), &allowlist).is_ok());
        assert!(validate_origin(Some("https://gamma.com"), &allowlist).is_err());
    }

    // -----------------------------------------------------------------------
    // is_localhost
    // -----------------------------------------------------------------------

    #[test]
    fn is_localhost_bare_names() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("::1"));
        assert!(is_localhost("[::1]"));
    }

    #[test]
    fn is_localhost_with_scheme_and_port() {
        assert!(is_localhost("http://localhost:5173"));
        assert!(is_localhost("https://127.0.0.1:443"));
    }

    #[test]
    fn is_localhost_false_for_remote() {
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("http://example.com"));
    }

    // -----------------------------------------------------------------------
    // glob_match
    // -----------------------------------------------------------------------

    #[test]
    fn glob_exact() {
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(!glob_match("abc", "ab"));
    }

    #[test]
    fn glob_star_at_end() {
        assert!(glob_match("abc*", "abcdef"));
        assert!(glob_match("abc*", "abc"));
        assert!(!glob_match("abc*", "ab"));
    }

    #[test]
    fn glob_star_at_start() {
        assert!(glob_match("*.com", "example.com"));
        assert!(glob_match("*.com", ".com"));
        assert!(!glob_match("*.com", "example.org"));
    }

    #[test]
    fn glob_star_in_middle() {
        assert!(glob_match("a*c", "abc"));
        assert!(glob_match("a*c", "aXYZc"));
        assert!(!glob_match("a*c", "aXYZd"));
    }

    #[test]
    fn glob_only_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }
}
