//! Admin API authentication: validate `X-Admin-Token` against current
//! and optional previous env-var values.
//!
//! Env access goes through [`EnvSource`] so tests can inject values
//! without polluting the process environment.
//!
//! # Rotation window
//!
//! Operators rotating the admin token set the OLD value into
//! `SECRET_PROXY_CA_ADMIN_TOKEN_PREV` before rolling the new value
//! into `SECRET_PROXY_CA_ADMIN_TOKEN`. During the window, requests
//! bearing either value succeed. Once rotation completes, the operator
//! clears `*_PREV` and the old token stops working.
//!
//! # Failure disambiguation (caller depends on exact strings)
//!
//! Two failure modes must remain distinguishable — the handler maps
//! them to different HTTP status codes:
//!
//! | Failure             | Error string prefix    | HTTP status           |
//! |---------------------|------------------------|-----------------------|
//! | Env var unset/empty | `"admin API disabled…"`| 503 Service Unavailable |
//! | Token mismatch      | `"invalid admin token"`| 401 Unauthorized      |
//!
//! The caller greps the prefix. Future work (Phase 2) can swap in a
//! proper `enum AdminDecision`; until then, preserve the exact strings
//! or pytest will break.

use crate::constants::{ADMIN_TOKEN_ENV, ADMIN_TOKEN_PREV_ENV};
use crate::http::headers::{constant_time_equal, header_value};

/// Abstract source for env vars. `ProcessEnv` is the production impl
/// that reads from `std::env`; tests use an in-memory mock.
pub trait EnvSource {
    fn get(&self, key: &str) -> Option<String>;
}

/// Production [`EnvSource`] reading from `std::env::var`.
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Validate `X-Admin-Token` header against current + optional previous
/// token env vars. Default env source is the process environment;
/// use [`check_admin_token_with_env`] to inject a mock in tests.
pub fn check_admin_token(headers_block: &str) -> Result<(), &'static str> {
    check_admin_token_with_env(headers_block, &ProcessEnv)
}

/// Testable core. Caller-controlled `env` lets the test matrix cover all
/// rotation states without touching the process environment.
pub fn check_admin_token_with_env(
    headers_block: &str,
    env: &dyn EnvSource,
) -> Result<(), &'static str> {
    let expected = match env.get(ADMIN_TOKEN_ENV) {
        Some(t) if !t.is_empty() => t,
        _ => return Err("admin API disabled (set SECRET_PROXY_CA_ADMIN_TOKEN)"),
    };
    let expected_prev = env
        .get(ADMIN_TOKEN_PREV_ENV)
        .filter(|t| !t.is_empty());

    let provided = header_value(headers_block, "x-admin-token").unwrap_or_default();
    let current_match = constant_time_equal(&provided, &expected);
    let previous_match = expected_prev
        .as_ref()
        .map(|prev| constant_time_equal(&provided, prev))
        .unwrap_or(false);
    if !(current_match || previous_match) {
        return Err("invalid admin token");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory [`EnvSource`] for tests.
    struct MockEnv(HashMap<String, String>);

    impl MockEnv {
        fn new() -> Self {
            Self(HashMap::new())
        }
        fn with(mut self, key: &str, val: &str) -> Self {
            self.0.insert(key.to_string(), val.to_string());
            self
        }
    }

    impl EnvSource for MockEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn headers_with_token(token: &str) -> String {
        format!("X-Admin-Token: {token}\r\n")
    }

    #[test]
    fn env_not_set_returns_disabled_error() {
        let env = MockEnv::new();
        let err = check_admin_token_with_env("", &env).unwrap_err();
        assert!(
            err.contains("disabled"),
            "503 path must mention 'disabled', got: {err}"
        );
    }

    #[test]
    fn env_empty_string_returns_disabled_error() {
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, "");
        let err = check_admin_token_with_env("", &env).unwrap_err();
        assert!(err.contains("disabled"), "empty env must behave like unset");
    }

    #[test]
    fn correct_current_token_accepted() {
        let tok = "x".repeat(32);
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, &tok);
        let headers = headers_with_token(&tok);
        assert!(check_admin_token_with_env(&headers, &env).is_ok());
    }

    #[test]
    fn missing_header_rejected_as_invalid() {
        // Env is set (admin enabled) but request has no X-Admin-Token →
        // 401 "invalid admin token" (NOT "disabled"). This distinction
        // matters: ops page on 401 but not on 503.
        let tok = "x".repeat(32);
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, &tok);
        let err = check_admin_token_with_env("", &env).unwrap_err();
        assert_eq!(err, "invalid admin token");
    }

    #[test]
    fn wrong_token_rejected() {
        let good = "x".repeat(32);
        let bad = "y".repeat(32);
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, &good);
        let err = check_admin_token_with_env(&headers_with_token(&bad), &env).unwrap_err();
        assert_eq!(err, "invalid admin token");
    }

    #[test]
    fn previous_token_accepted_during_rotation() {
        // Rotation window: both SECRET_PROXY_CA_ADMIN_TOKEN and
        // SECRET_PROXY_CA_ADMIN_TOKEN_PREV are set; request with the
        // old value succeeds.
        let new_tok = "a".repeat(32);
        let old_tok = "b".repeat(32);
        let env = MockEnv::new()
            .with(ADMIN_TOKEN_ENV, &new_tok)
            .with(ADMIN_TOKEN_PREV_ENV, &old_tok);
        assert!(check_admin_token_with_env(&headers_with_token(&new_tok), &env).is_ok());
        assert!(check_admin_token_with_env(&headers_with_token(&old_tok), &env).is_ok());
    }

    #[test]
    fn previous_token_absent_rejects_old_value() {
        // Post-rotation: PREV cleared; old token must stop working.
        let new_tok = "a".repeat(32);
        let old_tok = "b".repeat(32);
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, &new_tok);
        // No PREV set.
        let err =
            check_admin_token_with_env(&headers_with_token(&old_tok), &env).unwrap_err();
        assert_eq!(err, "invalid admin token");
    }

    #[test]
    fn previous_token_empty_string_is_same_as_absent() {
        // Operators may set PREV="" to signal "no window". Must be
        // treated identically to unset (no false-positive match on
        // empty provided header).
        let new_tok = "a".repeat(32);
        let env = MockEnv::new()
            .with(ADMIN_TOKEN_ENV, &new_tok)
            .with(ADMIN_TOKEN_PREV_ENV, "");
        // Empty header bypasses neither:
        let err = check_admin_token_with_env("", &env).unwrap_err();
        assert_eq!(err, "invalid admin token");
    }

    #[test]
    fn length_mismatch_rejected_constant_time() {
        // A 32-char expected token vs a 31-char provided token must
        // fail. The timing-safety of constant_time_equal is tested in
        // the pure headers module; here we just confirm the wrapper
        // plumbs it correctly (shorter provided → still fail).
        let tok = "x".repeat(32);
        let short = "x".repeat(31);
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, &tok);
        let err =
            check_admin_token_with_env(&headers_with_token(&short), &env).unwrap_err();
        assert_eq!(err, "invalid admin token");
    }

    #[test]
    fn header_name_case_insensitive_lookup() {
        // openclaw's HTTP client might lowercase headers (hyper style)
        // or capitalize (curl style). Our admin check must accept both.
        let tok = "x".repeat(32);
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, &tok);
        let lower = format!("x-admin-token: {tok}\r\n");
        let upper = format!("X-Admin-Token: {tok}\r\n");
        let mixed = format!("x-ADMIN-token: {tok}\r\n");
        assert!(check_admin_token_with_env(&lower, &env).is_ok());
        assert!(check_admin_token_with_env(&upper, &env).is_ok());
        assert!(check_admin_token_with_env(&mixed, &env).is_ok());
    }

    #[test]
    fn multiple_unrelated_headers_do_not_confuse_lookup() {
        let tok = "x".repeat(32);
        let env = MockEnv::new().with(ADMIN_TOKEN_ENV, &tok);
        let headers = format!(
            "Host: localhost\r\n\
             Content-Type: application/json\r\n\
             X-Admin-Token: {tok}\r\n\
             User-Agent: test\r\n",
        );
        assert!(check_admin_token_with_env(&headers, &env).is_ok());
    }
}
