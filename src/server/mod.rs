//! Serve-mode HTTP server.
//!
//! # Module layout
//!
//! - [`admin`]       — `X-Admin-Token` validation with injectable env.
//! - [`config`]      — `ServerConfig` parsed from `--port` + defaults.
//! - [`connection`]  — per-connection HTTP handler (admin API, health,
//!                     proxy passthrough → `relay::session`).
//! - [`router`]      — pure `(method, path) → RouteAction` enum.
//! - [`run`]         — top-level entry (`secret_proxy_ca serve` → here).
//!
//! # Data flow
//!
//! ```text
//! openclaw (streamSimple)
//!   → HTTP POST to CA  (port from ServerConfig, default 19030)
//!   → server::run      (accept loop, one TcpStream per connection)
//!   → server::connection::handle_connection
//!     ├─ GET  /health              → TA list_slots probe
//!     ├─ GET  /admin/keys/slots    → teec_list_slots (token required)
//!     ├─ POST /admin/keys/provision → teec_provision_key (token required)
//!     ├─ POST /admin/keys/remove   → teec_remove_key (token required)
//!     ├─ POST /admin/whitelist/add → teec_add_whitelist (token required)
//!     └─ POST /                    → handle_proxy_post
//!                                    → CMD_PROXY_REQUEST to TA
//!                                    → relay::session::run_relay_loop
//!                                      (TCP upstream ↔ TA ↔ SSE client)
//! ```
//!
//! # What this module does NOT own
//!
//! - The TEEC session: managed by `teec::RealTeec` (Drop closes).
//! - The relay loop: `relay::session::run_relay_loop` + `relay::core`
//!   state machine. `connection::handle_proxy_post` only issues the
//!   initial CMD_PROXY_REQUEST and hands off.
//! - Stress / soak / recovery testing: pytest harness under `tests/`.

pub mod admin;
pub mod config;
pub mod connection;
pub mod router;

use std::net::TcpListener;

use log::{error, info, warn};

use crate::constants::{ADMIN_TOKEN_ENV, ADMIN_TOKEN_PREV_ENV, TA_UUID};
use crate::http::headers::validate_admin_token_strength;
use crate::teec::RealTeec;

pub use config::ServerConfig;

/// Top-level serve-mode entry. Invoked by main.rs for the `serve`
/// CLI subcommand. Parses [`ServerConfig`], opens a persistent
/// [`RealTeec`] session, binds the TCP listener, runs the accept loop.
///
/// The `RealTeec` session lives for the whole `run()` call — on clean
/// shutdown the Drop impl closes the session + finalizes the context
/// in the GP TEE mandated order.
///
/// # Errors
///
/// Returns `Err` only for startup failures (bad admin token, TEEC
/// init failure, TCP bind failure). Per-connection handler errors are
/// logged and the accept loop continues.
pub fn run(args: &[String]) -> Result<(), String> {
    let cfg = ServerConfig::from_args(args);

    info!("serve mode starting on port {}", cfg.port);

    // Initialize TEEC (persistent, reused across all requests).
    let mut teec = RealTeec::open(TA_UUID)?;
    info!("TEEC session established (persistent)");

    // Validate admin token strength at startup — if set to a weak
    // value, fail fast rather than let the rotation window settle on
    // a guessable token. An unset env var means "admin API disabled,"
    // which is the safe default: the handler returns 503.
    if let Ok(token) = std::env::var(ADMIN_TOKEN_ENV) {
        if token.is_empty() {
            return Err(format!("{ADMIN_TOKEN_ENV} is set but empty"));
        }
        validate_admin_token_strength(&token)
            .map_err(|e| format!("invalid {ADMIN_TOKEN_ENV}: {e}"))?;
        if let Ok(prev_token) = std::env::var(ADMIN_TOKEN_PREV_ENV) {
            if !prev_token.is_empty() {
                validate_admin_token_strength(&prev_token)
                    .map_err(|e| format!("invalid {ADMIN_TOKEN_PREV_ENV}: {e}"))?;
            }
        }
    } else {
        warn!("admin API disabled: set {ADMIN_TOKEN_ENV} to enable admin endpoints");
    }

    let listener = TcpListener::bind(format!("0.0.0.0:{}", cfg.port))
        .map_err(|e| format!("TCP bind failed: {e}"))?;

    info!("HTTP server listening on http://0.0.0.0:{}", cfg.port);
    info!("proxy: POST / with SecretProxyRequest JSON → SSE");
    info!("health: GET /health (TEEC + TA probe, no auth)");
    info!(
        "admin: GET /admin/keys/slots, POST /admin/keys/provision, POST /admin/keys/remove (requires {ADMIN_TOKEN_ENV})"
    );
    info!("admin: POST /admin/whitelist/add (requires {ADMIN_TOKEN_ENV})");

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                if let Err(e) = connection::handle_connection(&mut teec, client) {
                    error!("serve error: {e}");
                }
            }
            Err(e) => error!("accept error: {e}"),
        }
    }

    // `teec` drops here — closes session + finalizes context in the
    // close-session-before-finalize-context order the GP TEE spec requires.
    Ok(())
}
