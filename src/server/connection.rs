//! Per-connection HTTP handler for serve mode.
//!
//! One function [`handle_connection`] covers the full lifecycle of an
//! accepted TCP client: parse the HTTP request, route on method+path,
//! dispatch to `/health`, admin API, or the SSE proxy handler.
//!
//! Step 9 refactor: this used to be `serve.rs::handle_http_connection`
//! (plus its private helpers). It moved here verbatim — the only
//! renames are `handle_http_connection → handle_connection` and the
//! serve.rs doc-string was split between `server/mod.rs` (data-flow
//! overview) and this module (per-connection details).
//!
//! The accept loop + TEEC session lifecycle now live in
//! [`crate::server::run`] in `server/mod.rs`; config parsing is in
//! [`crate::server::config`].

use std::io::{BufReader, Write};
use std::mem;
use std::net::TcpStream;

use cc_teec::raw;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::{
    check_teec_rc,
    ta_error_layer, teec_list_slots, teec_list_slots_meta, teec_provision_key, teec_remove_key,
    ProvisionKeyPayload,
    SlotEntry,
    CMD_PROXY_REQUEST,
    BIZ_RELAY_START,
    HttpMethod, ProxyRequest,
    ADMIN_ACTOR_HEADER, ADMIN_REQUEST_ID_HEADER,
};
use crate::teec::Teec;

#[derive(Clone, Debug)]
struct AdminAuditContext {
    actor: String,
    request_id: String,
    source: String,
}

/// Fields extracted from the incoming HTTP POST body.
/// Uses `serde(default)` to tolerate extra fields from OpenClaw's `Object.assign`.
#[derive(Deserialize)]
struct IncomingProxyRequest {
    key_id: u32,
    endpoint_url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    body: Vec<u8>,
}

fn default_method() -> String {
    "Post".into()
}

// Pure header / token helpers moved to `crate::http::headers` in Step 2.
// `header_value` is still used by `admin_audit_context`.
use crate::http::headers::header_value;

fn admin_audit_context(headers_block: &str, client: &TcpStream) -> AdminAuditContext {
    let actor = header_value(headers_block, ADMIN_ACTOR_HEADER).unwrap_or_else(|| "unknown".into());
    let request_id =
        header_value(headers_block, ADMIN_REQUEST_ID_HEADER).unwrap_or_else(|| "none".into());
    let source = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    AdminAuditContext {
        actor,
        request_id,
        source,
    }
}

fn send_json_response(client: &mut TcpStream, status: u16, status_text: &str, json_body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {json_body}",
        json_body.len()
    );
    let _ = client.write_all(response.as_bytes());
}

// `check_admin_token` lives in the sibling module `server::admin` (Step 4).
use super::admin::check_admin_token;

#[derive(Deserialize)]
struct AdminProvisionBody {
    slot: u32,
    key: String,
    provider: String,
}

#[derive(Deserialize)]
struct AdminRemoveBody {
    slot: u32,
}

#[derive(Serialize)]
struct AdminOkProvision {
    ok: bool,
    slot: u32,
    /// True when post-provision list includes `slot` (automation signal).
    verified: bool,
    slots: Vec<u32>,
    slot_entries: Vec<SlotEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_warning: Option<String>,
}

#[derive(Serialize)]
struct AdminOkSlots {
    ok: bool,
    slots: Vec<u32>,
    /// Provider per occupied slot (no key material); may be empty if meta probe failed.
    slot_entries: Vec<SlotEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta_warning: Option<String>,
}

#[derive(Serialize)]
struct AdminOkRemove {
    ok: bool,
    slot: u32,
    slots: Vec<u32>,
    slot_entries: Vec<SlotEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_warning: Option<String>,
}

#[derive(Serialize)]
struct HealthBody {
    ok: bool,
    service: &'static str,
    teec_session: &'static str,
    ta: HealthTa,
}

#[derive(Serialize)]
struct HealthTa {
    reachable: bool,
    /// Primary probe: `CMD_LIST_SLOTS` (TA must respond).
    probe: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    slots: Option<Vec<u32>>,
    /// Secondary: `CMD_LIST_SLOTS_META`; empty if unsupported or failed (see `meta_warning`).
    #[serde(skip_serializing_if = "Option::is_none")]
    slot_entries: Option<Vec<SlotEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_layer: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Handle one HTTP connection: read request, optional admin API, or TEEC relay + SSE.
pub(crate) fn handle_connection(
    teec: &mut dyn Teec,
    mut client: TcpStream,
) -> Result<(), String> {
    // Step 3 refactor: inline request parsing (request line + headers +
    // body read) migrated to `crate::http::request::parse_request`. Local
    // bindings `http_method`, `path`, `headers_text`, `content_length`,
    // `body` are kept identically named so the downstream 350+ lines of
    // routing logic continue to work without churn.
    let mut reader = BufReader::new(&client);
    let req = crate::http::request::parse_request(&mut reader)?;
    let http_method = req.method;
    let path = req.path;
    let headers_text = req.headers_text;
    let content_length = req.content_length;
    let body = req.body;
    let audit_ctx = admin_audit_context(&headers_text, &client);

    // --- GET /health (no auth): TEEC session open + TA list probe ---
    if path == "/health" && http_method == "GET" {
        let health = match teec_list_slots(teec) {
            Ok(slots) => {
                let (slot_entries, meta_warning) = match teec_list_slots_meta(teec) {
                    Ok(e) => (Some(e), None),
                    Err(e) => (Some(Vec::new()), Some(e)),
                };
                HealthBody {
                    ok: true,
                    service: "secret_proxy_ca",
                    teec_session: "open",
                    ta: HealthTa {
                        reachable: true,
                        probe: "list_slots",
                        slots: Some(slots),
                        slot_entries,
                        meta_warning,
                        error_layer: None,
                        message: None,
                    },
                }
            }
            Err(e) => {
                let layer = ta_error_layer(&e);
                HealthBody {
                    ok: false,
                    service: "secret_proxy_ca",
                    teec_session: "open",
                    ta: HealthTa {
                        reachable: false,
                        probe: "list_slots",
                        slots: None,
                        slot_entries: None,
                        meta_warning: None,
                        error_layer: Some(layer),
                        message: Some(e),
                    },
                }
            }
        };
        let json = serde_json::to_string(&health).unwrap_or_else(|_| r#"{"ok":false}"#.into());
        send_json_response(&mut client, 200, "OK", &json);
        info!(
            "health: ta_reachable={} probe=list_slots",
            health.ta.reachable
        );
        return Ok(());
    }

    // Body was already read by parse_request; no additional I/O needed here.
    // (Previously this block did: vec![0u8; content_length]; reader.read_exact(&mut body))

    // --- Admin API (same TEEC session as proxy) ---
    if path == "/admin/keys/slots" && http_method == "GET" {
        if let Err(reason) = check_admin_token(&headers_text) {
            let status = if reason.contains("disabled") { 503 } else { 401 };
            let text = if status == 503 {
                "Service Unavailable"
            } else {
                "Unauthorized"
            };
            let msg = serde_json::json!({ "ok": false, "error": reason }).to_string();
            send_json_response(&mut client, status, text, &msg);
            warn!(
                "audit event=admin_list_slots result=deny actor={} request_id={} source={} reason={}",
                audit_ctx.actor, audit_ctx.request_id, audit_ctx.source, reason
            );
            return Err(reason.into());
        }
        match teec_list_slots(teec) {
            Ok(slots) => {
                let (slot_entries, meta_warning) = match teec_list_slots_meta(teec) {
                    Ok(e) => (e, None),
                    Err(e) => {
                        warn!("admin list_slots: slot metadata unavailable: {e}");
                        (Vec::new(), Some(e))
                    }
                };
                info!(
                    "audit event=admin_list_slots result=ok actor={} request_id={} source={} count={} entries={} meta_ok={}",
                    audit_ctx.actor,
                    audit_ctx.request_id,
                    audit_ctx.source,
                    slots.len(),
                    slot_entries.len(),
                    meta_warning.is_none()
                );
                let json = serde_json::to_string(&AdminOkSlots {
                    ok: true,
                    slots,
                    slot_entries,
                    meta_warning,
                })
                .unwrap_or_else(|_| r#"{"ok":false,"error":"serialize"}"#.into());
                send_json_response(&mut client, 200, "OK", &json);
                Ok(())
            }
            Err(e) => {
                let msg = serde_json::json!({ "ok": false, "error": e }).to_string();
                send_json_response(&mut client, 502, "Bad Gateway", &msg);
                warn!(
                    "audit event=admin_list_slots result=error actor={} request_id={} source={} error={}",
                    audit_ctx.actor, audit_ctx.request_id, audit_ctx.source, e
                );
                Err(e)
            }
        }
    } else if path == "/admin/keys/provision" && http_method == "POST" {
        if let Err(reason) = check_admin_token(&headers_text) {
            let status = if reason.contains("disabled") { 503 } else { 401 };
            let text = if status == 503 {
                "Service Unavailable"
            } else {
                "Unauthorized"
            };
            let msg = serde_json::json!({ "ok": false, "error": reason }).to_string();
            send_json_response(&mut client, status, text, &msg);
            warn!(
                "audit event=admin_provision result=deny actor={} request_id={} source={} reason={}",
                audit_ctx.actor, audit_ctx.request_id, audit_ctx.source, reason
            );
            return Err(reason.into());
        }
        let parsed: AdminProvisionBody = match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => {
                let msg = serde_json::json!({ "ok": false, "error": format!("invalid JSON: {e}") })
                    .to_string();
                send_json_response(&mut client, 400, "Bad Request", &msg);
                warn!(
                    "audit event=admin_provision result=error actor={} request_id={} source={} reason=bad_json",
                    audit_ctx.actor, audit_ctx.request_id, audit_ctx.source
                );
                return Err(format!("admin provision bad JSON: {e}"));
            }
        };
        info!(
            "audit event=admin_provision result=start actor={} request_id={} source={} slot={} provider={} key_len={}",
            audit_ctx.actor,
            audit_ctx.request_id,
            audit_ctx.source,
            parsed.slot,
            parsed.provider,
            parsed.key.len()
        );
        let payload = ProvisionKeyPayload {
            slot: parsed.slot,
            key: parsed.key,
            provider: parsed.provider,
        };
        match teec_provision_key(teec, &payload) {
            Ok(()) => {
                let slot_id = payload.slot;
                let (verified, slots, slot_entries, verification_warning) =
                    match (teec_list_slots(teec), teec_list_slots_meta(teec)) {
                        (Ok(s), Ok(e)) => {
                            let v = s.contains(&slot_id);
                            (v, s, e, None)
                        }
                        (Ok(s), Err(e)) => {
                            warn!("admin provision: post-verify meta failed: {e}");
                            (s.contains(&slot_id), s, Vec::new(), Some(e))
                        }
                        (Err(e), _) => {
                            warn!("admin provision: post-verify list failed: {e}");
                            (
                                false,
                                Vec::new(),
                                Vec::new(),
                                Some(format!("post-provision list_slots failed: {e}")),
                            )
                        }
                    };
                info!(
                    "audit event=admin_provision result=ok actor={} request_id={} source={} slot={} verified={} slots_count={}",
                    audit_ctx.actor,
                    audit_ctx.request_id,
                    audit_ctx.source,
                    slot_id,
                    verified,
                    slots.len(),
                );
                let json = serde_json::to_string(&AdminOkProvision {
                    ok: true,
                    slot: slot_id,
                    verified,
                    slots,
                    slot_entries,
                    verification_warning,
                })
                .unwrap_or_else(|_| r#"{"ok":false}"#.into());
                send_json_response(&mut client, 200, "OK", &json);
                Ok(())
            }
            Err(e) => {
                let msg = serde_json::json!({ "ok": false, "error": e }).to_string();
                send_json_response(&mut client, 502, "Bad Gateway", &msg);
                warn!(
                    "audit event=admin_provision result=error actor={} request_id={} source={} slot={} error={}",
                    audit_ctx.actor, audit_ctx.request_id, audit_ctx.source, payload.slot, e
                );
                Err(e)
            }
        }
    } else if path == "/admin/keys/remove" && http_method == "POST" {
        if let Err(reason) = check_admin_token(&headers_text) {
            let status = if reason.contains("disabled") { 503 } else { 401 };
            let text = if status == 503 {
                "Service Unavailable"
            } else {
                "Unauthorized"
            };
            let msg = serde_json::json!({ "ok": false, "error": reason }).to_string();
            send_json_response(&mut client, status, text, &msg);
            warn!(
                "audit event=admin_remove result=deny actor={} request_id={} source={} reason={}",
                audit_ctx.actor, audit_ctx.request_id, audit_ctx.source, reason
            );
            return Err(reason.into());
        }
        let parsed: AdminRemoveBody = match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => {
                let msg = serde_json::json!({ "ok": false, "error": format!("invalid JSON: {e}") })
                    .to_string();
                send_json_response(&mut client, 400, "Bad Request", &msg);
                warn!(
                    "audit event=admin_remove result=error actor={} request_id={} source={} reason=bad_json",
                    audit_ctx.actor, audit_ctx.request_id, audit_ctx.source
                );
                return Err(format!("admin remove bad JSON: {e}"));
            }
        };
        match teec_remove_key(teec, parsed.slot) {
            Ok(()) => {
                let (slots, slot_entries, verification_warning) =
                    match (teec_list_slots(teec), teec_list_slots_meta(teec)) {
                        (Ok(s), Ok(e)) => (s, e, None),
                        (Ok(s), Err(e)) => {
                            warn!("admin remove: post-verify meta failed: {e}");
                            (s, Vec::new(), Some(e))
                        }
                        (Err(e), _) => {
                            warn!("admin remove: post-verify list failed: {e}");
                            (
                                Vec::new(),
                                Vec::new(),
                                Some(format!("post-remove list_slots failed: {e}")),
                            )
                        }
                    };
                info!(
                    "audit event=admin_remove result=ok actor={} request_id={} source={} slot={} slots_count={}",
                    audit_ctx.actor,
                    audit_ctx.request_id,
                    audit_ctx.source,
                    parsed.slot,
                    slots.len()
                );
                let json = serde_json::to_string(&AdminOkRemove {
                    ok: true,
                    slot: parsed.slot,
                    slots,
                    slot_entries,
                    verification_warning,
                })
                .unwrap_or_else(|_| r#"{"ok":false}"#.into());
                send_json_response(&mut client, 200, "OK", &json);
                Ok(())
            }
            Err(e) => {
                let msg = serde_json::json!({ "ok": false, "error": e }).to_string();
                send_json_response(&mut client, 502, "Bad Gateway", &msg);
                warn!(
                    "audit event=admin_remove result=error actor={} request_id={} source={} slot={} error={}",
                    audit_ctx.actor, audit_ctx.request_id, audit_ctx.source, parsed.slot, e
                );
                Err(e)
            }
        }
    } else if http_method != "POST" {
        let msg = serde_json::json!({ "ok": false, "error": "method not allowed for this path" })
            .to_string();
        send_json_response(&mut client, 405, "Method Not Allowed", &msg);
        Err("bad HTTP method".into())
    } else {
        handle_proxy_post(teec, client, body)
    }
}

/// LLM proxy: parse `SecretProxyRequest` JSON and stream SSE (ignore extra fields from OpenClaw's `Object.assign`).
fn handle_proxy_post(
    teec: &mut dyn Teec,
    mut client: TcpStream,
    body: Vec<u8>,
) -> Result<(), String> {
    // Parse SecretProxyRequest
    let incoming: IncomingProxyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let error_body = format!("{{\"error\":{{\"message\":\"invalid JSON: {e}\",\"type\":\"proxy_error\"}}}}");
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                error_body.len(), error_body
            );
            let _ = client.write_all(response.as_bytes());
            return Err(format!("bad JSON: {e}"));
        }
    };

    let method = match incoming.method.as_str() {
        "Get" => HttpMethod::Get,
        "Post" => HttpMethod::Post,
        "Put" => HttpMethod::Put,
        "Delete" => HttpMethod::Delete,
        "Patch" => HttpMethod::Patch,
        other => {
            send_error(&mut client, 400, &format!("unknown method: {other}"));
            return Err(format!("unknown method: {other}"));
        }
    };

    info!(
        "serve → {} {} (key_id={}, body={} bytes)",
        incoming.method, incoming.endpoint_url, incoming.key_id, incoming.body.len()
    );

    // Log the request body (the actual prompt being sent to the LLM)
    if let Ok(body_str) = std::str::from_utf8(&incoming.body) {
        if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(body_str) {
            if let Some(model) = body_json.get("model") {
                info!("┌─ REQUEST ─────────────────────────────");
                info!("│ model: {model}");
            }
            if let Some(messages) = body_json.get("messages").and_then(|m| m.as_array()) {
                for msg in messages {
                    let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("?");
                    // Content can be a string or an array of content blocks
                    let content_text = if let Some(s) = msg.get("content").and_then(|c| c.as_str()) {
                        s.to_string()
                    } else if let Some(arr) = msg.get("content").and_then(|c| c.as_array()) {
                        // Anthropic format: [{"type":"text","text":"..."},{"type":"image",...}]
                        arr.iter()
                            .filter_map(|block| {
                                block.get("text").and_then(|t| t.as_str())
                            })
                            .collect::<Vec<_>>()
                            .join(" ")
                    } else {
                        String::new()
                    };
                    let preview: String = content_text.chars().take(200).collect();
                    let suffix = if content_text.chars().count() > 200 { "..." } else { "" };
                    info!("│ [{role}] {preview}{suffix}");
                }
            }
            info!("└───────────────────────────────────────");
        }
    }

    // 4. Build ProxyRequest and start TEEC relay.
    //    Ensure anthropic-version header is present — MiniMax's Anthropic endpoint
    //    requires it, but pi-ai adds it at the HTTP transport level (not in the
    //    onPayload callback), so it won't be in SecretProxyRequest.headers from
    //    the wrapper.  We inject it here if missing.
    let mut req_headers = incoming.headers;
    if !req_headers.keys().any(|k| k.to_lowercase() == "anthropic-version") {
        req_headers.insert("anthropic-version".into(), "2023-06-01".into());
    }
    if !req_headers.keys().any(|k| k.to_lowercase() == "content-type") {
        req_headers.insert("Content-Type".into(), "application/json".into());
    }

    // Encode body as base64 to reduce TEEC payload size.
    // 61KB raw → 82KB base64 (vs 220KB as JSON integer array).
    use base64::Engine;
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&incoming.body);
    debug!(
        "body encoding: {} raw → {} base64 (was ~{} as int array)",
        incoming.body.len(), body_b64.len(),
        incoming.body.len() * 4  // approximate JSON int array size
    );

    let req = ProxyRequest {
        key_id: incoming.key_id,
        endpoint_url: incoming.endpoint_url,
        method,
        headers: req_headers,
        body: Vec::new(),          // empty — TA will use body_base64
        body_base64: Some(body_b64),
    };

    let mut json = serde_json::to_vec(&req)
        .map_err(|e| format!("serialize ProxyRequest: {e}"))?;
    debug!("ProxyRequest JSON size: {} bytes", json.len());

    // CMD_PROXY_REQUEST
    let mut target_buf = vec![0u8; 1024];
    let mut tls_buf = vec![0u8; 16384];
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_TEMP_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_MEMREF_TEMP_OUTPUT,
        raw::TEEC_MEMREF_TEMP_OUTPUT,
    );
    op.params[0].tmpref.buffer = json.as_mut_ptr() as *mut _;
    op.params[0].tmpref.size = json.len();
    op.params[2].tmpref.buffer = target_buf.as_mut_ptr() as *mut _;
    op.params[2].tmpref.size = target_buf.len();
    op.params[3].tmpref.buffer = tls_buf.as_mut_ptr() as *mut _;
    op.params[3].tmpref.size = tls_buf.len();

    let (rc, origin) = teec.invoke(CMD_PROXY_REQUEST, &mut op);
    if let Err(e) = check_teec_rc(rc, origin) {
        send_error(&mut client, 502, &e);
        return Err(e);
    }

    let biz_code = unsafe { op.params[1].value.a };
    if biz_code != BIZ_RELAY_START {
        let msg = format!("TA rejected: biz_code=0x{biz_code:04x}");
        send_error(&mut client, 502, &msg);
        return Err(msg);
    }

    let target_len = unsafe { op.params[2].tmpref.size };
    let target = std::str::from_utf8(&target_buf[..target_len])
        .map_err(|e| format!("invalid target: {e}"))?;
    let tls_len = unsafe { op.params[3].tmpref.size };
    let initial_tls = &tls_buf[..tls_len];

    info!("serve relay → {target}");

    // 5. Run relay loop, streaming SSE to client
    relay_and_stream(teec, target, initial_tls, &mut client)
}

/// Run the TEEC relay loop and stream the response directly to the HTTP client.
///
/// # SSE streaming logic
/// - On first `BIZ_RELAY_STREAMING` chunk: the decrypted bytes contain the
///   HTTP response headers from the LLM API (e.g. `Content-Type: text/event-stream`).
///   We extract the status code and write our own HTTP response headers to the client.
///   Any body data after `\r\n\r\n` in the first chunk is the start of SSE events.
/// - On subsequent `BIZ_RELAY_STREAMING` chunks: write the decrypted body bytes
///   directly to the client.  These contain raw SSE events from the LLM API.
/// - The decrypted bytes may include `Transfer-Encoding: chunked` framing from
///   the LLM server (hex length prefixes like `19d\r\n`).  We strip these since
///   the CA→OpenClaw connection uses its own framing.
/// - On `BIZ_RELAY_DONE`: flush and close.
/// Step 7b refactor: the 265-line inline loop (TA invoke + dispatch +
/// client/upstream I/O) is now the `relay::session::run_relay_loop`
/// adapter driving the `relay::core` pure state machine. This wrapper
/// keeps the original signature and handles the two concerns that
/// stay here: disabling Nagle on the client socket (so SSE events
/// push without kernel batching) and establishing the upstream TCP
/// connection.
fn relay_and_stream(
    teec: &mut dyn Teec,
    target: &str,
    initial_tls: &[u8],
    client: &mut TcpStream,
) -> Result<(), String> {
    // TCP_NODELAY preserved from pre-refactor serve.rs:836. Load-
    // bearing for SSE UX — without it the kernel batches 40-byte
    // `data: ...\n\n` lines and openclaw's token-by-token rendering
    // stalls until the next full MTU worth of bytes accumulates.
    let _ = client.set_nodelay(true);

    // Upstream connect moved into TcpUpstream::connect (sets the same
    // 120s read timeout the pre-refactor code used).
    let mut upstream = crate::relay::upstream::TcpUpstream::connect(target)
        .map_err(|e| format!("TCP connect to {target}: {e}"))?;

    info!("serve relay → {target}");
    crate::relay::session::run_relay_loop(teec, &mut upstream, client, initial_tls)
}

// Step 7b refactor: `log_sse_content`, `parse_upstream_headers`, and the
// `strip_chunked_framing`/`ChunkedDecoder` helpers all moved into the
// relay subtree — `log_sse_content` became
// `crate::relay::session::log_decoded_events`, `parse_upstream_headers`
// became a private helper inside `crate::relay::core`, and
// `ChunkedDecoder` was already in `crate::http::chunked` and is now
// owned by `RelayState`.

/// Send an HTTP error response to the client.
fn send_error(client: &mut TcpStream, status: u16, message: &str) {
    let body = format!("{{\"error\":{{\"message\":\"{message}\",\"type\":\"proxy_error\"}}}}");
    let response = format!(
        "HTTP/1.1 {status} Error\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _ = client.write_all(response.as_bytes());
}
