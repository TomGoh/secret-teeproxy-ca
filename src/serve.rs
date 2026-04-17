//! HTTP serve mode for secret_proxy_ca — SSE streaming support.
//!
//! Starts a persistent HTTP server that accepts `SecretProxyRequest` JSON
//! via POST and returns **SSE (Server-Sent Events)** responses streamed
//! from the LLM API through the TEEC relay.
//!
//! This bridges OpenClaw's `secret-proxy-wrapper.ts` (which uses `streamSimple`
//! expecting Anthropic-format SSE) with the TA's `BIZ_RELAY_STREAMING` protocol.
//!
//! Uses raw `TcpListener` instead of an HTTP framework because we need full
//! control over response streaming — writing SSE chunks as they arrive from
//! the TEEC relay, not buffering the entire response.
//!
//! # Data flow
//! ```text
//! OpenClaw (streamSimple)
//!   → HTTP POST to CA (localhost:18790)
//!   → CA parses SecretProxyRequest
//!   → CA calls TEEC CMD_PROXY_REQUEST → TA starts relay
//!   → CA TCP connects to LLM API target
//!   → relay loop: TA decrypts SSE → BIZ_RELAY_STREAMING → CA pipes to OpenClaw
//!   → OpenClaw receives Anthropic SSE events in real-time
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::mem;
use std::net::{TcpListener, TcpStream};

use cc_teec::{
    TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext, TEEC_InvokeCommand,
    TEEC_OpenSession, raw,
};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

use crate::{
    parse_arg_u32, parse_uuid, check_teec_rc,
    ta_error_layer, teec_list_slots, teec_list_slots_meta, teec_provision_key, teec_remove_key,
    ProvisionKeyPayload,
    SlotEntry,
    TA_UUID, CMD_PROXY_REQUEST, CMD_RELAY_DATA,
    BIZ_RELAY_START, BIZ_RELAY_CONTINUE, BIZ_RELAY_DONE, BIZ_RELAY_STREAMING,
    HttpMethod, ProxyRequest,
    // Admin-API constants (moved to crate::constants in Step 1 refactor,
    // re-exported at crate root — see main.rs top).
    // ADMIN_TOKEN_MIN_LEN migrated with `validate_admin_token_strength` to
    // `crate::http::headers` in Step 2, so no longer imported here.
    ADMIN_TOKEN_ENV, ADMIN_TOKEN_PREV_ENV,
    ADMIN_ACTOR_HEADER, ADMIN_REQUEST_ID_HEADER,
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

/// Start the HTTP serve mode with SSE streaming support.
///
/// # Logic
/// 1. Parse `--port` from args (default 18790).
/// 2. Initialize TEEC context and open a persistent session to the TA.
/// 3. Bind TCP listener on `0.0.0.0:{port}`.
/// 4. For each incoming connection:
///    a. Parse HTTP POST request (headers + body).
///    b. Extract `SecretProxyRequest` fields from JSON body.
///    c. Run TEEC relay, streaming the TA's decrypted SSE data directly
///       to the HTTP response.
/// 5. TEEC session remains open across requests.
pub fn cmd_serve(args: &[String]) -> Result<(), String> {
    let port = parse_arg_u32(args, "--port").unwrap_or(18790);

    info!("serve mode starting on port {port}");

    // Initialize TEEC (persistent, reused across all requests)
    let ta_uuid = parse_uuid(TA_UUID)?;
    let mut ctx: raw::TEEC_Context = unsafe { mem::zeroed() };
    let mut session: raw::TEEC_Session = unsafe { mem::zeroed() };
    let mut origin = 0u32;

    let rc = TEEC_InitializeContext(std::ptr::null(), &mut ctx);
    if rc != raw::TEEC_SUCCESS {
        return Err(format!("TEEC_InitializeContext failed: 0x{rc:08x}"));
    }

    let rc = TEEC_OpenSession(
        &mut ctx,
        &mut session,
        &ta_uuid,
        raw::TEEC_LOGIN_PUBLIC,
        std::ptr::null(),
        std::ptr::null_mut(),
        &mut origin,
    );
    if rc != raw::TEEC_SUCCESS {
        TEEC_FinalizeContext(&mut ctx);
        return Err(format!("TEEC_OpenSession failed: 0x{rc:08x}, origin={origin}"));
    }

    info!("TEEC session established (persistent)");

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

    // Bind HTTP server
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .map_err(|e| format!("TCP bind failed: {e}"))?;

    info!("HTTP server listening on http://0.0.0.0:{port}");
    info!("proxy: POST / with SecretProxyRequest JSON → SSE");
    info!("health: GET /health (TEEC + TA probe, no auth)");
    info!(
        "admin: GET /admin/keys/slots, POST /admin/keys/provision, POST /admin/keys/remove (requires {ADMIN_TOKEN_ENV})"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                if let Err(e) = handle_http_connection(&mut session, client) {
                    error!("serve error: {e}");
                }
            }
            Err(e) => error!("accept error: {e}"),
        }
    }

    TEEC_CloseSession(&mut session);
    TEEC_FinalizeContext(&mut ctx);
    Ok(())
}

// Pure header / token helpers moved to `crate::http::headers` in Step 2.
// `validate_admin_token_strength` now returns `Result<(), &'static str>` —
// the existing `.map_err(|e| format!("... {e}"))` call sites compose the same
// way since both `&str` and `String` implement `Display`.
use crate::http::headers::{
    constant_time_equal, header_value, normalize_http_path, validate_admin_token_strength,
};
use crate::http::chunked::ChunkedDecoder;

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

/// Validate `X-Admin-Token` against `SECRET_PROXY_CA_ADMIN_TOKEN`. If env is unset/empty, admin is disabled.
fn check_admin_token(headers_block: &str) -> Result<(), &'static str> {
    let expected = match std::env::var(ADMIN_TOKEN_ENV) {
        Ok(t) if !t.is_empty() => t,
        _ => return Err("admin API disabled (set SECRET_PROXY_CA_ADMIN_TOKEN)"),
    };
    let expected_prev = std::env::var(ADMIN_TOKEN_PREV_ENV)
        .ok()
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
fn handle_http_connection(
    session: &mut raw::TEEC_Session,
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
        let health = match teec_list_slots(session) {
            Ok(slots) => {
                let (slot_entries, meta_warning) = match teec_list_slots_meta(session) {
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
        match teec_list_slots(session) {
            Ok(slots) => {
                let (slot_entries, meta_warning) = match teec_list_slots_meta(session) {
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
        match teec_provision_key(session, &payload) {
            Ok(()) => {
                let slot_id = payload.slot;
                let (verified, slots, slot_entries, verification_warning) =
                    match (teec_list_slots(session), teec_list_slots_meta(session)) {
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
        match teec_remove_key(session, parsed.slot) {
            Ok(()) => {
                let (slots, slot_entries, verification_warning) =
                    match (teec_list_slots(session), teec_list_slots_meta(session)) {
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
        handle_proxy_post(session, client, body)
    }
}

/// LLM proxy: parse `SecretProxyRequest` JSON and stream SSE (ignore extra fields from OpenClaw's `Object.assign`).
fn handle_proxy_post(
    session: &mut raw::TEEC_Session,
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

    let mut origin = 0u32;
    let rc = TEEC_InvokeCommand(session, CMD_PROXY_REQUEST, &mut op, &mut origin);
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
    relay_and_stream(session, target, initial_tls, &mut client)
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
fn relay_and_stream(
    session: &mut raw::TEEC_Session,
    target: &str,
    initial_tls: &[u8],
    client: &mut TcpStream,
) -> Result<(), String> {
    // Disable Nagle on the client connection so SSE events are pushed
    // immediately instead of being batched by the kernel.
    let _ = client.set_nodelay(true);

    // TCP connect to LLM API server
    let mut tcp = TcpStream::connect(target)
        .map_err(|e| format!("TCP connect to {target}: {e}"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;

    debug!("sending {} bytes ClientHello to {target}", initial_tls.len());
    tcp.write_all(initial_tls)
        .map_err(|e| format!("TCP write ClientHello: {e}"))?;

    let mut read_buf = vec![0u8; 65536];
    let mut response_buf = vec![0u8; 1024 * 1024];
    let mut tls_extra_buf = vec![0u8; 4096];
    let mut saw_eof = false;
    let mut response_started = false;
    let mut round = 0u32;
    // Track whether upstream uses chunked encoding (detected from response headers)
    let mut is_chunked = false;
    // Chunked decoder (stateful across relay rounds — carries partial chunks
    // and partial size lines between TA roundtrips).
    // Step 2 refactor: replaced the prior pair of `chunk_remaining` / `chunk_pending`
    // locals with a single struct that encapsulates both. Behavior identical
    // (Lenient fallback: parse failure dumps pending buffer as raw).
    let mut chunked_decoder = ChunkedDecoder::new();

    loop {
        round += 1;
        debug!("relay round {round}, reading from TCP...");
        let n = match tcp.read(&mut read_buf) {
            Ok(n) => n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                send_error(client, 504, "upstream timeout");
                return Err("TCP read timed out".into());
            }
            Err(e) => {
                if !response_started {
                    send_error(client, 502, &format!("TCP read: {e}"));
                }
                return Err(format!("TCP read: {e}"));
            }
        };

        if n == 0 {
            if saw_eof {
                return Err("server closed before relay completed".into());
            }
            saw_eof = true;
        } else {
            saw_eof = false;
        }

        debug!("relay round {round}, server→ {n} bytes{}", if n == 0 { " (EOF)" } else { "" });

        // Send ciphertext to TA via CMD_RELAY_DATA
        let mut server_data = read_buf[..n].to_vec();
        let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_MEMREF_TEMP_INPUT,
            raw::TEEC_VALUE_INOUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
        );
        op.params[0].tmpref.buffer = server_data.as_mut_ptr() as *mut _;
        op.params[0].tmpref.size = server_data.len();
        // Param 1 input: a=1 only when upstream TCP read returned EOF (n==0).
        // Distinguishes that from empty ciphertext used to pump rustls (see below).
        op.params[1].value.a = if n == 0 { 1 } else { 0 };
        op.params[1].value.b = 0;
        op.params[2].tmpref.buffer = response_buf.as_mut_ptr() as *mut _;
        op.params[2].tmpref.size = response_buf.len();
        op.params[3].tmpref.buffer = tls_extra_buf.as_mut_ptr() as *mut _;
        op.params[3].tmpref.size = tls_extra_buf.len();

        let mut origin = 0u32;
        let rc = TEEC_InvokeCommand(session, CMD_RELAY_DATA, &mut op, &mut origin);
        if let Err(e) = check_teec_rc(rc, origin) {
            if !response_started {
                send_error(client, 502, &e);
            }
            return Err(e);
        }

        let (status, _detail) = unsafe { (op.params[1].value.a, op.params[1].value.b) };
        let filled = unsafe { op.params[2].tmpref.size };
        let tls_extra_filled = unsafe { op.params[3].tmpref.size };

        debug!("relay round {round}, TA status=0x{status:04x}, params[2]={filled} bytes, params[3]={tls_extra_filled} bytes");

        match status {
            BIZ_RELAY_CONTINUE => {
                if filled > 0 {
                    // TLS handshake — send outgoing bytes to server
                    debug!("relay round {round}, →server {filled} bytes (handshake)");
                    tcp.write_all(&response_buf[..filled])
                        .map_err(|e| format!("TCP write TLS: {e}"))?;
                } else {
                    // TA consumed data but produced no outgoing bytes yet.
                    // Pump the state machine with empty input — rustls may
                    // have pending write_tls data after processing multiple
                    // TLS records across separate process_relay calls.
                    debug!("relay round {round}, pumping TA (0 outgoing, calling relay with empty)");
                    let mut empty = Vec::new();
                    let mut op2: raw::TEEC_Operation = unsafe { mem::zeroed() };
                    op2.paramTypes = raw::TEEC_PARAM_TYPES(
                        raw::TEEC_MEMREF_TEMP_INPUT,
                        raw::TEEC_VALUE_INOUT,
                        raw::TEEC_MEMREF_TEMP_OUTPUT,
                        raw::TEEC_MEMREF_TEMP_OUTPUT,
                    );
                    op2.params[0].tmpref.buffer = empty.as_mut_ptr() as *mut _;
                    op2.params[0].tmpref.size = 0;
                    op2.params[1].value.a = 0;
                    op2.params[1].value.b = 0;
                    op2.params[2].tmpref.buffer = response_buf.as_mut_ptr() as *mut _;
                    op2.params[2].tmpref.size = response_buf.len();
                    op2.params[3].tmpref.buffer = tls_extra_buf.as_mut_ptr() as *mut _;
                    op2.params[3].tmpref.size = tls_extra_buf.len();

                    let mut origin2 = 0u32;
                    let rc2 = TEEC_InvokeCommand(session, CMD_RELAY_DATA, &mut op2, &mut origin2);
                    if let Err(e) = check_teec_rc(rc2, origin2) {
                        if !response_started { send_error(client, 502, &e); }
                        return Err(e);
                    }
                    let pump_filled = unsafe { op2.params[2].tmpref.size };
                    if pump_filled > 0 {
                        debug!("relay round {round}, pump produced {pump_filled} bytes, →server");
                        tcp.write_all(&response_buf[..pump_filled])
                            .map_err(|e| format!("TCP write TLS (pump): {e}"))?;
                    }
                }
            }

            BIZ_RELAY_STREAMING => {
                let decrypted = &response_buf[..filled];

                if !response_started {
                    // First streaming chunk: contains HTTP headers + initial body.
                    // Extract the LLM server's HTTP status and start our response.
                    let (http_status, body_start) = parse_upstream_headers(decrypted);

                    // Detect chunked transfer encoding from upstream headers
                    let header_bytes = &decrypted[..body_start.saturating_sub(4).min(decrypted.len())];
                    if let Ok(hdr) = std::str::from_utf8(header_bytes) {
                        info!("┌─ UPSTREAM RESPONSE ────────────────────");
                        for line in hdr.lines().take(10) {
                            info!("│ {line}");
                            if line.to_lowercase().contains("transfer-encoding")
                                && line.to_lowercase().contains("chunked")
                            {
                                is_chunked = true;
                            }
                        }
                        info!("└───────────────────────────────────────");
                    }
                    debug!("upstream chunked encoding: {is_chunked}");

                    // Write HTTP response headers to OpenClaw client
                    let response_headers = format!(
                        "HTTP/1.1 {} OK\r\n\
                         Content-Type: text/event-stream; charset=utf-8\r\n\
                         Cache-Control: no-cache\r\n\
                         Connection: close\r\n\
                         \r\n",
                        http_status
                    );
                    client.write_all(response_headers.as_bytes())
                        .map_err(|e| format!("client write headers: {e}"))?;
                    response_started = true;

                    // Write initial body data (SSE events after the upstream headers)
                    if body_start < decrypted.len() {
                        let body_data = &decrypted[body_start..];
                        let output = if is_chunked {
                            chunked_decoder.feed(body_data)
                        } else {
                            body_data.to_vec()
                        };
                        log_sse_content(&output);
                        client.write_all(&output)
                            .map_err(|e| format!("client write initial body: {e}"))?;
                        client.flush().map_err(|e| format!("client flush: {e}"))?;
                    }
                } else {
                    // Subsequent chunks: just SSE body data
                    let output = if is_chunked {
                        chunked_decoder.feed(decrypted)
                    } else {
                        decrypted.to_vec()
                    };
                    log_sse_content(&output);
                    client.write_all(&output)
                        .map_err(|e| format!("client write SSE: {e}"))?;
                    client.flush().map_err(|e| format!("client flush: {e}"))?;
                }

                // Send any TLS bytes back to server
                let tls_len = unsafe { op.params[3].tmpref.size };
                if tls_len > 0 {
                    tcp.write_all(&tls_extra_buf[..tls_len])
                        .map_err(|e| format!("TCP write TLS: {e}"))?;
                }
            }

            BIZ_RELAY_DONE => {
                // Send final TLS bytes (e.g. close_notify)
                let tls_len = unsafe { op.params[3].tmpref.size };
                if tls_len > 0 {
                    let _ = tcp.write_all(&tls_extra_buf[..tls_len]);
                }

                if !response_started && filled > 0 {
                    // The TA completed the relay in a single round — the
                    // decrypted data is a ProxyResponse JSON (not raw HTTP).
                    // Parse it and forward the body with the correct
                    // content-type so the Anthropic SDK's SSE parser works.
                    let decrypted = &response_buf[..filled];
                    let resp: crate::ProxyResponse = serde_json::from_slice(decrypted)
                        .map_err(|e| format!("parse ProxyResponse: {e}"))?;

                    let content_type = resp.headers.get("content-type")
                        .map(|s| s.as_str())
                        .unwrap_or("application/json");
                    let response_headers = format!(
                        "HTTP/1.1 {} OK\r\n\
                         Content-Type: {content_type}\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        resp.status, resp.body.len()
                    );
                    log_sse_content(&resp.body);
                    client.write_all(response_headers.as_bytes())
                        .map_err(|e| format!("client write headers: {e}"))?;
                    client.write_all(&resp.body)
                        .map_err(|e| format!("client write body: {e}"))?;
                }

                let _ = client.flush();
                info!("serve → stream complete");
                return Ok(());
            }

            _ => {
                let msg = format!("relay error: 0x{status:04x}");
                if !response_started {
                    send_error(client, 502, &msg);
                }
                return Err(msg);
            }
        }
    }
}

/// Log SSE event content, extracting the actual text from Anthropic-format events.
///
/// Parses `data: {...}` lines and prints the text deltas and thinking content
/// so the operator can see the LLM's real words in the log.
fn log_sse_content(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    for line in text.lines() {
        if !line.starts_with("data: ") {
            continue;
        }
        let json_str = &line["data: ".len()..];
        if json_str == "[DONE]" {
            info!("◄ [DONE]");
            continue;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(json_str) else { continue };
        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match event_type {
            "content_block_delta" => {
                if let Some(delta) = event.get("delta") {
                    let delta_type = delta.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match delta_type {
                        "text_delta" => {
                            if let Some(t) = delta.get("text").and_then(|t| t.as_str()) {
                                eprint!("{t}");
                            }
                        }
                        "thinking_delta" => {
                            if let Some(t) = delta.get("thinking").and_then(|t| t.as_str()) {
                                eprint!("{t}");
                            }
                        }
                        _ => {}
                    }
                }
            }
            "content_block_start" => {
                if let Some(cb) = event.get("content_block") {
                    let cb_type = cb.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match cb_type {
                        "thinking" => info!("\n◄ [thinking]"),
                        "text" => info!("\n◄ [text]"),
                        _ => info!("\n◄ [block:{cb_type}]"),
                    }
                }
            }
            "message_start" => {
                if let Some(msg) = event.get("message") {
                    let model = msg.get("model").and_then(|m| m.as_str()).unwrap_or("?");
                    let id = msg.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                    info!("◄ message_start (model={model}, id={id})");
                }
            }
            "message_delta" => {
                if let Some(usage) = event.get("usage") {
                    info!("\n◄ message_delta (usage: {usage})");
                }
            }
            "message_stop" => {
                info!("\n◄ message_stop");
            }
            _ => {}
        }
    }
}

/// Parse the HTTP status code and find the body start from upstream response headers.
///
/// The first `BIZ_RELAY_STREAMING` chunk contains the full HTTP response headers
/// from the LLM server followed by `\r\n\r\n` and the start of SSE body.
///
/// # Returns
/// `(http_status_code, byte_offset_of_body_start)`
fn parse_upstream_headers(data: &[u8]) -> (u16, usize) {
    // Find \r\n\r\n boundary
    let boundary = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(data.len());

    // Parse status from first line: "HTTP/1.1 200 OK"
    let header_str = String::from_utf8_lossy(&data[..boundary]);
    let status = header_str
        .lines()
        .next()
        .and_then(|line| {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                parts[1].parse::<u16>().ok()
            } else {
                None
            }
        })
        .unwrap_or(200);

    let body_start = if boundary + 4 <= data.len() {
        boundary + 4
    } else {
        data.len()
    };

    (status, body_start)
}

// `strip_chunked_framing` was moved to `crate::http::chunked::ChunkedDecoder` in
// Step 2 of the refactor. The stateful decoder is now a proper struct with
// unit-testable feed() method; behavior (including Lenient fallback on parse
// failure) is preserved exactly.

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
