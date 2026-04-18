//! secret_proxy_ca — Client Application for SecretProxyTA.
//!
//! Communicates with SecretProxyTA via the GP TEE Client API
//! (rust-libteec). The chain is:
//!
//! ```text
//! this binary → TEEC_InvokeCommand → virga (TLS/vsock)
//!             → teec_cc_bridge → Unix socket → secret_proxy_ta
//! ```
//!
//! For proxy requests, uses a TEEC relay protocol: the TA drives the
//! TLS state machine (rustls) inside the TEE, while this CA handles
//! TCP I/O to external API servers. No separate tls_forwarder needed.
//!
//! # Module layout
//!
//! ```text
//! main.rs          this file (env_logger init + cli::run)
//! cli/             argv dispatch, subcommand handlers, diagnostics
//! server/          HTTP serve mode (/health, /admin/*, proxy)
//! relay/           TEEC relay state machine + TCP adapter
//! teec/            Teec trait + RealTeec + MockTeec + ops wrappers
//! http/            pure HTTP parser/response helpers + chunked decoder
//! sse/             SSE response header + Anthropic event parser
//! wire.rs          CA↔TA JSON DTOs
//! constants.rs     TA_UUID + CMD_* + BIZ_* + env var names
//! error.rs         thiserror Error enum + From<Error> for String
//! clock.rs         Clock trait (unused by production, ready for timeouts)
//! ```
//!
//! `main()` below is deliberately tiny — all logic is in submodules.

mod cli;
mod clock;
mod constants;
mod error;
mod http;
mod relay;
mod server;
mod sse;
mod teec;
mod wire;

// Re-export crate-root names used by other modules. Prefer explicit
// paths (e.g. `crate::wire::ProxyResponse`) in new code; these
// re-exports are kept to avoid a mechanical renames pass across every
// module — they can be tightened incrementally.
#[allow(unused_imports)]
pub(crate) use constants::{
    ADMIN_ACTOR_HEADER, ADMIN_REQUEST_ID_HEADER, ADMIN_TOKEN_ENV, ADMIN_TOKEN_MIN_LEN,
    ADMIN_TOKEN_PREV_ENV, BIZ_ERR_BAD_JSON, BIZ_ERR_FORBIDDEN, BIZ_ERR_KEY_NOT_FOUND,
    BIZ_ERR_TRANSPORT, BIZ_RELAY_CONTINUE, BIZ_RELAY_DONE, BIZ_RELAY_START, BIZ_RELAY_STREAMING,
    BIZ_SUCCESS, CMD_ADD_WHITELIST, CMD_LIST_SLOTS, CMD_LIST_SLOTS_META, CMD_PROVISION_KEY,
    CMD_PROXY_REQUEST, CMD_RELAY_DATA, CMD_REMOVE_KEY, TA_UUID,
};
#[allow(unused_imports)]
pub(crate) use teec::ops::{
    check_teec_rc, ta_error_layer, teec_list_slots, teec_list_slots_meta, teec_provision_key,
    teec_remove_key,
};
#[allow(unused_imports)]
pub(crate) use wire::{
    HttpMethod, ProvisionKeyPayload, ProxyRequest, ProxyResponse, SlotEntry,
};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = cli::run() {
        log::error!("{e}");
        std::process::exit(1);
    }
}
