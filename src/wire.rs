//! Wire-format DTOs shared across the CA↔TA boundary.
//!
//! Every type here is `Serialize`+`Deserialize` and crosses the TEEC
//! MEMREF boundary as JSON. **Field names are part of the protocol** —
//! renaming `key_id` or `endpoint_url` silently breaks the TA without
//! any Rust-level error. The pairing TA definitions live in
//! `secret_proxy_ta::protocol`; update both sides together or don't
//! update either.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// HTTP method enum — serialized as JSON variant name ("Get", "Post",
/// ...). **Case-sensitive on both sides**: a wrapper sending `"post"`
/// gets rejected by the TA with 400 Bad Request. Regression-pinned by
/// `format/test_proxy_format.py::test_method_lowercase_rejected`.
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

/// Request payload sent to the TA via `CMD_PROXY_REQUEST`
/// (params[0] MemrefInput).
///
/// The TA uses `key_id` to look up the API key in its key store and
/// injects `Authorization: Bearer <key>` before encrypting with
/// rustls. The CA never sees the real API key.
///
/// `body` is a byte array (`Vec<u8>`) because JSON serializes it as
/// an integer array — this avoids encoding issues with non-UTF-8
/// data. For payloads >4 KiB, prefer `body_base64` to halve TEEC
/// transport size (a 61 KiB body is 220 KiB as JSON int array, 82
/// KiB as base64).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProxyRequest {
    /// Key slot index — the TA looks up the API key by this ID.
    pub key_id: u32,
    /// Target HTTPS URL (e.g. `https://api.minimax.chat/v1/text/chatcompletion_v2`).
    pub endpoint_url: String,
    /// HTTP method (`Get`, `Post`, `Put`, `Delete`, `Patch`).
    pub method: HttpMethod,
    /// HTTP headers to include. Do NOT include `Authorization` (TA
    /// injects it) or `Content-Length` (TA adds it automatically).
    pub headers: HashMap<String, String>,
    /// Request body as raw bytes (JSON integer array). Used by CLI mode.
    #[serde(default)]
    pub body: Vec<u8>,
    /// Request body as base64-encoded string (compact alternative).
    /// Used by serve mode for large payloads. If both `body` and
    /// `body_base64` are present, TA prefers `body_base64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

/// Response payload returned by the TA via `BIZ_RELAY_DONE` short-
/// response path (params[2] MemrefOutput).
///
/// Only used when the TA completes the whole HTTP round-trip in one
/// round (no streaming). In streaming mode the decrypted plaintext
/// flows through `BIZ_RELAY_STREAMING` and this struct is unused.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProxyResponse {
    /// HTTP status code (e.g. 200, 401, 502). Forwarded verbatim to
    /// the client — `openclaw` must see the real upstream status, not
    /// a normalized 200.
    pub status: u16,
    /// Response headers with lowercase keys (e.g. `content-type`).
    pub headers: HashMap<String, String>,
    /// Response body as raw bytes.
    pub body: Vec<u8>,
}

/// Non-secret slot row from the TA via `CMD_LIST_SLOTS_META`. Matches
/// the TA's `SlotMeta` JSON one-for-one. Never carries key material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SlotEntry {
    pub slot: u32,
    pub provider: String,
}

/// Payload for `CMD_PROVISION_KEY` (params[0] MemrefInput). The `key`
/// field is the sensitive one — never log it.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProvisionKeyPayload {
    /// Key slot index to store the key in.
    pub slot: u32,
    /// The API key string (e.g. `sk-api--xxxxx`).
    pub key: String,
    /// Provider name (e.g. `minimax`, `moonshot`).
    pub provider: String,
}

/// Payload for `CMD_ADD_WHITELIST` (params[0] MemrefInput).
///
/// The TA matches `endpoint_url.starts_with(pattern)` before allowing
/// an outgoing request — prefix match, not glob.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AddWhitelistPayload {
    pub pattern: String,
}
