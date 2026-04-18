//! Pure helpers for working with HTTP headers and tokens.
//!
//! Zero I/O, no state — the easiest slice of the CA to unit-test.
//! Includes the constant-time compare used for admin-token validation
//! (see [`constant_time_equal`]).

use crate::constants::ADMIN_TOKEN_MIN_LEN;

/// Strip the query string from an HTTP path and trim whitespace.
///
/// ```text
/// "/health?foo=1"  →  "/health"
/// "  /admin/keys "  →  "/admin/keys"
/// ```
///
/// The returned slice borrows from `raw`, so no allocation happens.
pub fn normalize_http_path(raw: &str) -> &str {
    raw.split('?').next().unwrap_or(raw).trim()
}

/// Case-insensitive header lookup within a single raw headers block.
///
/// `headers_block` is the full `\r\n`-separated string **before** the
/// blank line terminator. `name_lc` must be supplied lowercase — callers
/// are assumed to have already lowercased the name (the caller knows its
/// own literal).
///
/// Returns the trimmed value, or `None` if the header is absent.
///
/// Intentionally naive (scans every line, allocates the lowercased line):
/// the CA serves a handful of headers per request, so this is not hot.
pub fn header_value(headers_block: &str, name_lc: &str) -> Option<String> {
    let prefix = format!("{name_lc}:");
    for line in headers_block.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with(&prefix) {
            return line.splitn(2, ':').nth(1).map(|s| s.trim().to_string());
        }
    }
    None
}

/// Constant-time byte comparison of two strings.
///
/// Returns `true` iff `a` and `b` are byte-for-byte equal. The runtime is
/// independent of the **position** of the first differing byte, which
/// defeats the naive timing side channel on token comparison.
///
/// Length mismatches are folded into the accumulator so a short token
/// still costs the same wall-clock time as a full-length one against a
/// short candidate — without this, an attacker could probe token length.
pub fn constant_time_equal(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut diff = a_bytes.len() ^ b_bytes.len();
    let max_len = a_bytes.len().max(b_bytes.len());
    for idx in 0..max_len {
        let av = a_bytes.get(idx).copied().unwrap_or(0);
        let bv = b_bytes.get(idx).copied().unwrap_or(0);
        diff |= (av ^ bv) as usize;
    }
    diff == 0
}

/// Reject admin tokens that are too short or on the well-known weak list.
///
/// Returns `Err(&'static str)` with a human-readable reason on failure.
/// The error type is `&'static str` (not `crate::error::Error`) to keep
/// this module dependency-light and cheaply testable.
pub fn validate_admin_token_strength(token: &str) -> Result<(), &'static str> {
    if token.len() < ADMIN_TOKEN_MIN_LEN {
        return Err("token length must be >= 32 bytes");
    }
    let weak_values = ["dev-admin-token", "admin", "password", "123456", "changeme"];
    if weak_values.iter().any(|v| constant_time_equal(token, v)) {
        return Err("token value is too weak");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_query() {
        assert_eq!(normalize_http_path("/health?foo=1"), "/health");
        assert_eq!(normalize_http_path("/health"), "/health");
    }

    #[test]
    fn normalize_trims_whitespace() {
        assert_eq!(normalize_http_path("  /admin/keys  "), "/admin/keys");
    }

    #[test]
    fn normalize_preserves_root() {
        assert_eq!(normalize_http_path("/"), "/");
    }

    #[test]
    fn header_value_case_insensitive() {
        let block = "Host: example.com\r\nX-Admin-Token: abc\r\nUser-Agent: test";
        assert_eq!(header_value(block, "x-admin-token"), Some("abc".to_string()));
        // Case of header NAME in the block doesn't matter; only the lookup lowercase.
        assert_eq!(header_value(block, "host"), Some("example.com".to_string()));
    }

    #[test]
    fn header_value_missing_returns_none() {
        let block = "Host: example.com";
        assert_eq!(header_value(block, "x-admin-token"), None);
    }

    #[test]
    fn header_value_trims_spaces() {
        let block = "X-Foo:    bar   ";
        assert_eq!(header_value(block, "x-foo"), Some("bar".to_string()));
    }

    #[test]
    fn header_value_only_first_colon_is_separator() {
        // RFC 7230: field-value may contain a colon. Only the *first* colon
        // separates name from value.
        let block = "X-Trace: abc:def:ghi";
        assert_eq!(header_value(block, "x-trace"), Some("abc:def:ghi".to_string()));
    }

    #[test]
    fn constant_time_equal_matches_equal() {
        assert!(constant_time_equal("hello", "hello"));
    }

    #[test]
    fn constant_time_equal_rejects_different_same_length() {
        assert!(!constant_time_equal("hello", "world"));
    }

    #[test]
    fn constant_time_equal_rejects_length_mismatch() {
        assert!(!constant_time_equal("short", "much-longer-string"));
        // Prefix match with mismatched length must still fail — an attacker
        // who can compare against prefixes would otherwise bypass.
        assert!(!constant_time_equal("abc", "abcd"));
    }

    #[test]
    fn constant_time_equal_handles_empty() {
        assert!(constant_time_equal("", ""));
        assert!(!constant_time_equal("", "x"));
        assert!(!constant_time_equal("x", ""));
    }

    #[test]
    fn token_strength_rejects_short() {
        // 31 chars — one short of ADMIN_TOKEN_MIN_LEN (32).
        let short = "a".repeat(31);
        assert!(validate_admin_token_strength(&short).is_err());
    }

    #[test]
    fn token_strength_rejects_weak_values() {
        // "admin" is in the weak list, and also too short — so this ends
        // up failing on the length check first. Pad the weak value to
        // minimum length to prove the weak-list check is reachable.
        let padded = format!("{:<32}", "admin");
        // Padded to 32 chars but not exactly matching "admin" — passes.
        assert!(validate_admin_token_strength(&padded).is_ok());
        // Exact weak match (pad to length but keep value) — we need a value
        // that's already >= 32 chars AND matches constant_time_equal against
        // one of the weak_values. In practice all weak_values are <32 chars
        // so the length check catches them first. Verify this is the real
        // defense: no long token equals a weak literal.
        for weak in ["dev-admin-token", "admin", "password", "123456", "changeme"] {
            assert!(
                weak.len() < ADMIN_TOKEN_MIN_LEN,
                "weak literal {weak:?} must be shorter than min len \
                 (otherwise it could be accepted)"
            );
        }
    }

    #[test]
    fn token_strength_accepts_strong() {
        let strong = "X7q9-Z4m.AaB2+CcD3/EeF4=GgH5iIjJ"; // 32 chars, non-weak
        assert!(validate_admin_token_strength(strong).is_ok());
    }
}
