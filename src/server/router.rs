//! Pure HTTP routing: `(method, path) → RouteAction`.
//!
//! This module does exactly one thing: map a method + path pair to the
//! action the server should take. No I/O, no TEEC, no state. The caller
//! (currently `serve::handle_http_connection`; eventually
//! `server::connection`) is responsible for actually executing that
//! action.
//!
//! Behavior is preserved byte-for-byte from the inline if/else-if chain
//! in `serve.rs::handle_http_connection`:
//!   - `GET /health` → `Health`
//!   - `GET /admin/keys/slots` → `AdminListSlots`
//!   - `POST /admin/keys/provision` → `AdminProvision`
//!   - `POST /admin/keys/remove` → `AdminRemove`
//!   - `POST /admin/whitelist/add` → `AdminAddWhitelist`
//!   - non-POST on any other path → `MethodNotAllowed`
//!   - POST on any other path (including `/`, `/proxy`) → `Proxy`
//!
//! Note the last rule: **any POST not explicitly matched is treated as
//! a proxy request**. openclaw sends POST to `/` or `/proxy`
//! interchangeably; both must route the same way.

/// The action the server should take for a given (method, path) pair.
///
/// Intentionally coarse — each variant represents a handler boundary,
/// not a fine-grained parse of the request. The handler is free to
/// reject the request for other reasons (bad body, missing auth, etc.)
/// after routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    /// `GET /health` — no auth, TEEC list_slots probe.
    Health,
    /// `GET /admin/keys/slots` — admin token required.
    AdminListSlots,
    /// `POST /admin/keys/provision` — admin token required, body carries key.
    AdminProvision,
    /// `POST /admin/keys/remove` — admin token required, body carries slot.
    AdminRemove,
    /// `POST /admin/whitelist/add` — admin token required, body carries pattern.
    AdminAddWhitelist,
    /// `POST` to any unmatched path — treated as a proxy request.
    Proxy,
    /// Request did not match any known route and cannot be handled
    /// by the proxy catch-all (non-POST method to unmatched path).
    MethodNotAllowed,
}

/// Pure router. `method` should be the uppercase HTTP method as
/// produced by `http::request::parse_request`; `path` should be the
/// query-stripped, trimmed path.
pub fn route(method: &str, path: &str) -> RouteAction {
    match (method, path) {
        ("GET", "/health") => RouteAction::Health,
        ("GET", "/admin/keys/slots") => RouteAction::AdminListSlots,
        ("POST", "/admin/keys/provision") => RouteAction::AdminProvision,
        ("POST", "/admin/keys/remove") => RouteAction::AdminRemove,
        ("POST", "/admin/whitelist/add") => RouteAction::AdminAddWhitelist,
        // Any POST not in the admin allow-list is a proxy request.
        // openclaw's secret-proxy-wrapper sends to `/` or `/proxy`;
        // both route the same way. Pytest `test_proxy_format` pins
        // this catch-all behavior.
        ("POST", _) => RouteAction::Proxy,
        // Everything else (GET on non-admin paths, PUT/DELETE/PATCH,
        // etc.) is 405. The handler emits body
        // `{"ok":false,"error":"method not allowed for this path"}`.
        _ => RouteAction::MethodNotAllowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_health() {
        assert_eq!(route("GET", "/health"), RouteAction::Health);
    }

    #[test]
    fn get_health_case_sensitive_on_method() {
        // The router assumes method was uppercased by the parser. A
        // lowercase "get" here represents a bug upstream — the router
        // refuses rather than silently normalizing, making the upstream
        // contract explicit.
        assert_eq!(route("get", "/health"), RouteAction::MethodNotAllowed);
    }

    #[test]
    fn get_admin_slots() {
        assert_eq!(
            route("GET", "/admin/keys/slots"),
            RouteAction::AdminListSlots
        );
    }

    #[test]
    fn post_admin_provision() {
        assert_eq!(
            route("POST", "/admin/keys/provision"),
            RouteAction::AdminProvision
        );
    }

    #[test]
    fn post_admin_remove() {
        assert_eq!(
            route("POST", "/admin/keys/remove"),
            RouteAction::AdminRemove
        );
    }

    #[test]
    fn get_admin_provision_is_method_not_allowed() {
        // Provision is POST-only; GET should fall through to 405.
        assert_eq!(
            route("GET", "/admin/keys/provision"),
            RouteAction::MethodNotAllowed
        );
    }

    #[test]
    fn post_admin_whitelist_add() {
        assert_eq!(
            route("POST", "/admin/whitelist/add"),
            RouteAction::AdminAddWhitelist
        );
    }

    #[test]
    fn post_slash_is_proxy() {
        assert_eq!(route("POST", "/"), RouteAction::Proxy);
    }

    #[test]
    fn post_proxy_alias_is_proxy() {
        // openclaw sends to either / or /proxy interchangeably.
        assert_eq!(route("POST", "/proxy"), RouteAction::Proxy);
    }

    #[test]
    fn post_unknown_path_is_proxy_catch_all() {
        // Any POST not matched explicitly goes to the proxy handler —
        // unusual paths like `/v1/messages` included.
        assert_eq!(route("POST", "/v1/messages"), RouteAction::Proxy);
        assert_eq!(route("POST", "/anything"), RouteAction::Proxy);
    }

    #[test]
    fn get_unknown_path_is_method_not_allowed() {
        // GET is only allowed on /health and /admin/keys/slots.
        assert_eq!(route("GET", "/"), RouteAction::MethodNotAllowed);
        assert_eq!(route("GET", "/unknown"), RouteAction::MethodNotAllowed);
    }

    #[test]
    fn put_delete_patch_are_method_not_allowed() {
        for method in ["PUT", "DELETE", "PATCH", "OPTIONS"] {
            assert_eq!(
                route(method, "/health"),
                RouteAction::MethodNotAllowed,
                "{method} should be rejected"
            );
            assert_eq!(
                route(method, "/"),
                RouteAction::MethodNotAllowed,
                "{method} / should be rejected (not even proxy catch-all)"
            );
        }
    }

    #[test]
    fn health_query_string_normalization_is_parsers_job() {
        // The parser strips query strings before calling route(), so
        // the router itself matches only the normalized path. If query
        // strings leak in, routing treats them as unmatched paths.
        assert_eq!(
            route("GET", "/health?probe=deep"),
            RouteAction::MethodNotAllowed
        );
    }
}
