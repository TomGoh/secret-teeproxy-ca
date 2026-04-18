//! Per-connection HTTP handler for serve mode.
//!
//! One function — [`handle_connection`] — covers the full lifecycle of
//! an accepted TCP client: parse the HTTP request, route on method+path,
//! dispatch to `/health`, admin API, or the SSE proxy handler. The
//! accept loop + TEEC session lifecycle live in [`crate::server::run`]
//! (see `server/mod.rs`); config parsing is in [`crate::server::config`].

use std::io::{BufReader, Write};
use std::mem;
use std::net::TcpStream;
use std::time::Duration;

use cc_teec::raw;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::teec::Teec;
use crate::{
    check_teec_rc, ta_error_layer, teec_list_slots, teec_list_slots_meta, teec_provision_key,
    teec_remove_key, HttpMethod, ProvisionKeyPayload, ProxyRequest, SlotEntry, ADMIN_ACTOR_HEADER,
    ADMIN_REQUEST_ID_HEADER, BIZ_RELAY_START, CMD_PROXY_REQUEST,
};

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
pub(crate) fn handle_connection(teec: &mut dyn Teec, mut client: TcpStream) -> Result<(), String> {
    // Per-connection read deadline: the accept loop is single-threaded, so a
    // stuck `read_line` inside `parse_request` would hang every subsequent
    // client (including `/health`). 3s is generous for normal request
    // assembly — openclaw sends a ~100KB JSON body serialized in-memory in
    // one go, well under 1s even on 3G — but short enough that
    // `test_slow_drip_doesnt_block_health`'s 5s /health deadline is
    // reachable once the slow-drip client times out. See
    // tests/chaos/test_adversarial.py.
    //
    // Intentionally no `set_write_timeout`: SSE responses are long-lived by
    // design (multi-turn streaming), and a short write timeout would cut
    // them off mid-stream.
    //
    // This bounds slow-drip DoS but does NOT fix the 100-idle case
    // (test_100_idle_connections_no_hang) — that requires concurrent accept
    // (Phase 2 session pool) because the sum of per-connection timeouts
    // across a queued backlog is unavoidable on a single-threaded loop.
    let _ = client.set_read_timeout(Some(Duration::from_secs(3)));

    let mut reader = BufReader::new(&client);
    let req = crate::http::request::parse_request(&mut reader)?;
    let http_method = req.method;
    let path = req.path;
    let headers_text = req.headers_text;
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

    // --- Admin API (same TEEC session as proxy) ---
    if path == "/admin/keys/slots" && http_method == "GET" {
        if let Err(reason) = check_admin_token(&headers_text) {
            let status = if reason.contains("disabled") {
                503
            } else {
                401
            };
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
            let status = if reason.contains("disabled") {
                503
            } else {
                401
            };
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
            let status = if reason.contains("disabled") {
                503
            } else {
                401
            };
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
            let error_body = format!(
                "{{\"error\":{{\"message\":\"invalid JSON: {e}\",\"type\":\"proxy_error\"}}}}"
            );
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
        incoming.method,
        incoming.endpoint_url,
        incoming.key_id,
        incoming.body.len()
    );

    // Summarize the request body for operators. openclaw replays the
    // full chat history each turn, so dumping every message at INFO
    // produces quadratic log growth; instead we log the model + a
    // count of messages + the most recent user turn's preview. Full
    // history at DEBUG for forensics.
    log_request_preview(&incoming.body);

    // MiniMax's Anthropic endpoint rejects requests without an
    // `anthropic-version` header. pi-ai sets it at the HTTP transport
    // layer (not via `onPayload`), so it's usually absent in
    // `SecretProxyRequest.headers`. Inject both headers if missing
    // so wrappers can omit them safely.
    let mut req_headers = incoming.headers;
    if !req_headers
        .keys()
        .any(|k| k.to_lowercase() == "anthropic-version")
    {
        req_headers.insert("anthropic-version".into(), "2023-06-01".into());
    }
    if !req_headers
        .keys()
        .any(|k| k.to_lowercase() == "content-type")
    {
        req_headers.insert("Content-Type".into(), "application/json".into());
    }

    // Base64-encode the body to roughly quarter the TEEC transport
    // size vs the JSON-int-array serialization (measured on a 61 KiB
    // sample: 220 KiB int-array → 82 KiB base64). The TA prefers
    // `body_base64` when both fields are present.
    use base64::Engine;
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&incoming.body);
    debug!(
        "body encoding: {} raw → {} base64",
        incoming.body.len(),
        body_b64.len(),
    );

    let req = ProxyRequest {
        key_id: incoming.key_id,
        endpoint_url: incoming.endpoint_url,
        method,
        headers: req_headers,
        body: Vec::new(),
        body_base64: Some(body_b64),
    };

    let mut json = serde_json::to_vec(&req).map_err(|e| format!("serialize ProxyRequest: {e}"))?;
    debug!("ProxyRequest JSON size: {} bytes", json.len());

    // CMD_PROXY_REQUEST: param[0] = JSON in, param[1] = biz out,
    //                    param[2] = target host:port out,
    //                    param[3] = initial TLS ClientHello out.
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

    // Note: `relay_and_stream` logs `serve relay → {target}` itself,
    // so we don't emit it here (that used to be a double-log).
    relay_and_stream(teec, target, initial_tls, &mut client)
}

/// Run the TEEC relay loop and stream the SSE response back to the HTTP
/// client. This wrapper owns the two concerns that don't belong in the
/// pure state machine: disabling Nagle on the client socket (so SSE
/// events push without kernel batching) and establishing the upstream
/// TCP connection. Everything else delegates to
/// [`crate::relay::session::run_relay_loop`] + [`crate::relay::core`].
fn relay_and_stream(
    teec: &mut dyn Teec,
    target: &str,
    initial_tls: &[u8],
    client: &mut TcpStream,
) -> Result<(), String> {
    // TCP_NODELAY is load-bearing for SSE UX — without it the kernel
    // batches 40-byte `data: ...\n\n` lines and openclaw's token-by-
    // token rendering stalls until the next full MTU accumulates.
    let _ = client.set_nodelay(true);

    let mut upstream = crate::relay::upstream::TcpUpstream::connect(target)
        .map_err(|e| format!("TCP connect to {target}: {e}"))?;

    info!("serve relay → {target}");
    crate::relay::session::run_relay_loop(teec, &mut upstream, client, initial_tls)
}

/// Send an HTTP error response to the client. Body shape
/// `{"error":{"message":"...","type":"proxy_error"}}` matches what
/// openclaw + the pytest format suite both expect; do not reword.
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

/// Summarize an Anthropic ProxyRequest body for the operator log.
///
/// Emits at INFO: `model`, number of messages, and a 200-char preview
/// of the *most recent* user message. Emits the full history at DEBUG
/// for forensics. This avoids the quadratic INFO-log growth that
/// happens when openclaw replays the whole chat each turn.
fn log_request_preview(body: &[u8]) {
    let Ok(body_str) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(body_json) = serde_json::from_str::<serde_json::Value>(body_str) else {
        return;
    };

    let model = body_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("?");
    let messages = body_json.get("messages").and_then(|m| m.as_array());
    let count = messages.map(|m| m.len()).unwrap_or(0);

    let last_user_preview = messages.and_then(|msgs| {
        msgs.iter()
            .rev()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
            .map(extract_message_text)
    });

    match last_user_preview {
        Some(text) => info!(
            "model={model} messages={count} last_user={:?}",
            truncate_chars(&text, 200),
        ),
        None => info!("model={model} messages={count}"),
    }

    // Full history at DEBUG — only rendered when RUST_LOG=debug.
    if log::log_enabled!(log::Level::Debug) {
        if let Some(msgs) = messages {
            for msg in msgs {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("?");
                let text = extract_message_text(msg);
                debug!("  [{role}] {}", truncate_chars(&text, 400));
            }
        }
    }
}

/// Pull a plain-text preview out of an Anthropic-format message.
/// Handles both the string form (`"content": "hi"`) and the block form
/// (`"content": [{"type":"text","text":"hi"}, {"type":"image",...}]`).
fn extract_message_text(msg: &serde_json::Value) -> String {
    if let Some(s) = msg.get("content").and_then(|c| c.as_str()) {
        return s.to_string();
    }
    if let Some(arr) = msg.get("content").and_then(|c| c.as_array()) {
        return arr
            .iter()
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(" ");
    }
    String::new()
}

fn truncate_chars(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}
