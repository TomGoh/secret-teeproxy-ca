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
use log::{info, debug, warn, error};
use serde::Deserialize;

use crate::{
    parse_arg_u32, parse_uuid, check_teec_rc,
    TA_UUID, CMD_PROXY_REQUEST, CMD_RELAY_DATA,
    BIZ_RELAY_START, BIZ_RELAY_CONTINUE, BIZ_RELAY_DONE, BIZ_RELAY_STREAMING,
    HttpMethod, ProxyRequest,
};

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

    // Bind HTTP server
    let listener = TcpListener::bind(format!("0.0.0.0:{port}"))
        .map_err(|e| format!("TCP bind failed: {e}"))?;

    info!("HTTP server listening on http://0.0.0.0:{port}");
    info!("accepts POST with SecretProxyRequest JSON, returns SSE");

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

/// Handle one HTTP connection: read request, run TEEC relay, stream SSE response.
fn handle_http_connection(
    session: &mut raw::TEEC_Session,
    mut client: TcpStream,
) -> Result<(), String> {
    // 1. Read HTTP request headers
    let mut reader = BufReader::new(&client);
    let mut headers_text = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)
            .map_err(|e| format!("read header line: {e}"))?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        headers_text.push_str(&line);
    }

    // 2. Parse Content-Length and read body
    let content_length = headers_text
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("content-length:") {
                lower.trim_start_matches("content-length:").trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)
            .map_err(|e| format!("read body: {e}"))?;
    }

    // 3. Parse SecretProxyRequest (ignore extra fields from OpenClaw's Object.assign)
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
    // Chunked decoder state: bytes remaining in current chunk (carried across relay rounds)
    let mut chunk_remaining: usize = 0;
    // Buffer for incomplete chunked framing data across relay rounds.
    let mut chunk_pending = Vec::<u8>::new();

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
                            strip_chunked_framing(body_data, &mut chunk_remaining, &mut chunk_pending)
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
                        strip_chunked_framing(decrypted, &mut chunk_remaining, &mut chunk_pending)
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
                    // Non-streaming response (shouldn't happen with stream:true,
                    // but handle gracefully): return the ProxyResponse body as JSON.
                    let resp: crate::ProxyResponse = serde_json::from_slice(&response_buf[..filled])
                        .map_err(|e| format!("parse ProxyResponse: {e}"))?;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        resp.body.len()
                    );
                    client.write_all(response.as_bytes())
                        .map_err(|e| format!("client write: {e}"))?;
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

/// Decode `Transfer-Encoding: chunked` framing from raw bytes.
///
/// Uses a proper stateful chunked decoder that tracks expected chunk sizes,
/// instead of the old heuristic that stripped any all-hex line.  The old
/// approach would corrupt data when SSE content contained lines with only
/// hex characters (e.g. code snippets like "abcdef", "face", "0000").
///
/// `chunk_remaining` tracks how many bytes of chunk data are still expected
/// from a previous call (data may be split across relay rounds).
///
/// If parsing fails at any point, returns the raw data unchanged as a safe
/// fallback — better to pass through framing artifacts than to corrupt content.
fn strip_chunked_framing(
    data: &[u8],
    chunk_remaining: &mut usize,
    pending: &mut Vec<u8>,
) -> Vec<u8> {
    pending.extend_from_slice(data);

    let mut result = Vec::with_capacity(pending.len());
    let mut pos = 0;

    while pos < pending.len() {
        if *chunk_remaining > 0 {
            // We're in the middle of a chunk — consume up to chunk_remaining bytes
            let available = pending.len() - pos;
            let to_copy = available.min(*chunk_remaining);
            result.extend_from_slice(&pending[pos..pos + to_copy]);
            pos += to_copy;
            *chunk_remaining -= to_copy;

            // If we've consumed the full chunk, we must have trailing \r\n.
            // If not available yet, wait for more bytes in the next round.
            if *chunk_remaining == 0 {
                if pos + 2 > pending.len() {
                    break;
                }
                if &pending[pos..pos + 2] == b"\r\n" {
                    pos += 2;
                } else {
                    debug!("chunked decode: missing chunk CRLF, falling back to raw");
                    let raw = pending.split_off(0);
                    return raw;
                }
            }
            continue;
        }

        // Expecting a chunk size line: hex digits followed by \r\n
        let line_end = match pending[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => pos + p,
            None => {
                // No complete line — partial chunk-size line, keep in pending.
                break;
            }
        };

        let line = &pending[pos..line_end];

        // Parse hex chunk size (ignore chunk extensions after ';')
        let hex_str = match std::str::from_utf8(line) {
            Ok(s) => s.split(';').next().unwrap_or("").trim(),
            Err(_) => {
                // Not valid UTF-8 — not a chunk size line.  Fall back to raw passthrough.
                warn!("chunked decode: non-UTF8 at pos {pos}, falling back to raw");
                let raw = pending.split_off(0);
                return raw;
            }
        };

        if hex_str.is_empty() {
            // Empty line between chunks — skip
            pos = line_end + 2;
            continue;
        }

        let chunk_size = match usize::from_str_radix(hex_str, 16) {
            Ok(size) => size,
            Err(_) => {
                // Not a valid hex size — this data isn't actually chunked, or we've
                // lost sync.  Return raw data as fallback.
                debug!("chunked decode: invalid hex '{}' at pos {pos}, falling back to raw", hex_str);
                let raw = pending.split_off(0);
                return raw;
            }
        };

        // Skip past the chunk size line + \r\n
        pos = line_end + 2;

        if chunk_size == 0 {
            // Terminal chunk — skip optional trailers and final \r\n
            // Keep parser simple: stop consuming here; any trailers stay in pending.
            break;
        }

        // Read chunk data
        let available = pending.len() - pos;
        let to_copy = available.min(chunk_size);
        result.extend_from_slice(&pending[pos..pos + to_copy]);
        pos += to_copy;

        if to_copy < chunk_size {
            // Chunk spans into the next relay round
            *chunk_remaining = chunk_size - to_copy;
        } else {
            // Full chunk consumed — skip trailing \r\n
            if pos + 2 <= pending.len() && &pending[pos..pos + 2] == b"\r\n" {
                pos += 2;
            }
        }
    }

    if pos > 0 {
        pending.drain(0..pos);
    }
    result
}

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
