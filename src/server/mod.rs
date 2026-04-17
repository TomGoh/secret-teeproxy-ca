//! Serve-mode HTTP server primitives.
//!
//! Scope after Step 4:
//! - [`router`] — pure `route(method, path) → RouteAction` enum.
//! - [`admin`] — `check_admin_token` with injectable env source.
//!
//! Future steps (Step 9) will add `config`, `connection`, and
//! top-level `run()` as this module grows to absorb the rest of
//! `serve::handle_http_connection`.

pub mod admin;
pub mod router;
