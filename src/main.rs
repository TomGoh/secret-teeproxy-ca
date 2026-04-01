//! secret_proxy_ca — Client Application for SecretProxyTA
//!
//! Communicates with SecretProxyTA via the GP TEE Client API (rust-libteec).
//! The chain is:
//!   this binary → TEEC_InvokeCommand → virga (TLS/vsock) → teec_cc_bridge
//!   → Unix socket /tmp/<UUID>.sock → secret_proxy_ta
//!
//! For proxy requests, uses a TEEC relay protocol: the TA drives the TLS
//! state machine (rustls) inside the TEE, while this CA handles TCP I/O
//! to external API servers.  No separate tls_forwarder process is needed.
//!
//! Usage:
//!   secret_proxy_ca list-slots
//!   secret_proxy_ca provision-key --slot <N> --key <sk-...> --provider <minimax|moonshot>
//!   secret_proxy_ca remove-key --slot <N>
//!   secret_proxy_ca add-whitelist --pattern <url-prefix>
//!   secret_proxy_ca proxy --slot <N> --url <https://...> --body <json>
//!   secret_proxy_ca serve [--port 18800]

mod serve;

use std::{collections::HashMap, mem};
use std::io::{Read, Write};
use std::net::TcpStream;

use cc_teec::{
    TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext, TEEC_InvokeCommand,
    TEEC_OpenSession, raw,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// TA UUID — must match `TA_UUID` in `secret_proxy_ta/src/main.rs`.
/// The `teec_cc_bridge` uses this to locate the TA's Unix socket at
/// `/tmp/{uuid}.sock`.
pub(crate) const TA_UUID: &str = "a3f79c15-72d0-4e3a-b8d1-9f2ca3e81054";

/// GP TEE command IDs — must match the constants in `secret_proxy_ta/src/main.rs`.
/// These are passed as `cmd_id` to `TEEC_InvokeCommand()`.

pub(crate) const CMD_PROXY_REQUEST:  u32 = 0x0001;
const CMD_PROVISION_KEY:  u32 = 0x0002;
const CMD_REMOVE_KEY:     u32 = 0x0003;
const CMD_LIST_SLOTS:     u32 = 0x0004;
const CMD_ADD_WHITELIST:  u32 = 0x0005;
pub(crate) const CMD_RELAY_DATA:     u32 = 0x0006;

/// Business result codes returned in `params[1].value.a` by the TA.
/// Must match the constants in `secret_proxy_ta/src/main.rs`.

const BIZ_SUCCESS:           u32 = 0x900D;
pub(crate) const BIZ_RELAY_START:       u32 = 0x9001;
pub(crate) const BIZ_RELAY_CONTINUE:    u32 = 0x9002;
pub(crate) const BIZ_RELAY_DONE:        u32 = 0x9003;
pub(crate) const BIZ_RELAY_STREAMING:   u32 = 0x9004;
const BIZ_ERR_BAD_JSON:      u32 = 0xE001;
const BIZ_ERR_KEY_NOT_FOUND: u32 = 0xE004;
const BIZ_ERR_FORBIDDEN:     u32 = 0xE005;
const BIZ_ERR_TRANSPORT:     u32 = 0xE006;

// ---------------------------------------------------------------------------
// Shared data types — must match protocol.rs in secret_proxy_ta.
// These structs are serialized to/from JSON and passed as MemrefInput/Output
// in TEEC parameters.
// ---------------------------------------------------------------------------

/// HTTP method enum — serialized as JSON variant name ("Get", "Post", etc.).
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

/// Request payload sent to the TA via CMD_PROXY_REQUEST (params[0] MemrefInput).
///
/// The TA uses `key_id` to look up the API key in its key store and injects
/// `Authorization: Bearer <key>` before encrypting with rustls.  The CA never
/// sees the real API key.
///
/// `body` is a byte array (Vec<u8>) because JSON serializes it as an integer
/// array — this avoids encoding issues with non-UTF-8 data.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProxyRequest {
    /// Key slot index — the TA looks up the API key by this ID.
    key_id: u32,
    /// Target HTTPS URL (e.g. "https://api.minimax.chat/v1/text/chatcompletion_v2").
    endpoint_url: String,
    /// HTTP method (Get, Post, Put, Delete, Patch).
    method: HttpMethod,
    /// HTTP headers to include.  Do NOT include Authorization (TA injects it)
    /// or Content-Length (TA adds it automatically).
    headers: HashMap<String, String>,
    /// Request body as raw bytes (JSON integer array).
    /// Used by CLI mode.
    #[serde(default)]
    body: Vec<u8>,
    /// Request body as base64-encoded string (compact alternative).
    /// Used by serve mode for large payloads to reduce TEEC transport overhead.
    /// If both `body` and `body_base64` are present, TA prefers `body_base64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body_base64: Option<String>,
}

/// Response payload returned by the TA via BIZ_RELAY_DONE (params[2] MemrefOutput).
///
/// Only used in non-streaming mode.  In streaming mode, decrypted plaintext
/// is returned progressively via BIZ_RELAY_STREAMING and this struct is not used.
#[derive(Debug, Serialize, Deserialize)]
struct ProxyResponse {
    /// HTTP status code (e.g. 200, 401, 502).
    status: u16,
    /// Response headers with lowercase keys (e.g. "content-type" → "application/json").
    headers: HashMap<String, String>,
    /// Response body as raw bytes.
    body: Vec<u8>,
}

/// Payload for CMD_PROVISION_KEY (params[0] MemrefInput).
#[derive(Debug, Serialize, Deserialize)]
struct ProvisionKeyPayload {
    /// Key slot index to store the key in.
    slot: u32,
    /// The API key string (e.g. "sk-api--xxxxx").
    key: String,
    /// Provider name (e.g. "minimax", "moonshot").
    provider: String,
}

/// Payload for CMD_ADD_WHITELIST (params[0] MemrefInput).
#[derive(Debug, Serialize, Deserialize)]
struct AddWhitelistPayload {
    /// URL prefix pattern (e.g. "https://api.minimax.chat/").
    /// The TA checks `endpoint_url.starts_with(pattern)` before allowing requests.
    pattern: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    if let Err(e) = run() {
        eprintln!("secret_proxy_ca: {e}");
        std::process::exit(1);
    }
}

/// Main entry point: open a TEEC session to the TA, dispatch the CLI subcommand,
/// and clean up.
///
/// # Logic
/// 1. Parse the UUID string into `TEEC_UUID`.
/// 2. `TEEC_InitializeContext` — connects to the TEE transport layer (virga).
/// 3. `TEEC_OpenSession` — establishes a session with the TA identified by UUID.
///    The `teec_cc_bridge` receives this via virga TLS + vsock:9999 and creates
///    a Unix socket connection to `/tmp/{uuid}.sock`.
/// 4. Dispatch the CLI subcommand (list-slots, provision-key, remove-key,
///    add-whitelist, or proxy).
/// 5. `TEEC_CloseSession` + `TEEC_FinalizeContext` — clean up regardless of
///    subcommand success/failure.
///
/// # Returns
/// `Ok(())` on success, `Err(String)` with human-readable error on failure.
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    // `serve` manages its own TEEC lifecycle (long-lived session)
    if args[1] == "serve" {
        return serve::cmd_serve(&args[2..]);
    }

    let ta_uuid = parse_uuid(TA_UUID)?;

    // Open TEE session
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

    let result = match args[1].as_str() {
        "list-slots"     => cmd_list_slots(&mut session),
        "provision-key"  => cmd_provision_key(&mut session, &args[2..]),
        "remove-key"     => cmd_remove_key(&mut session, &args[2..]),
        "add-whitelist"  => cmd_add_whitelist(&mut session, &args[2..]),
        "proxy"          => cmd_proxy(&mut session, &args[2..]),
        other => {
            eprintln!("unknown command: {other}");
            print_usage(&args[0]);
            Ok(())
        }
    };

    TEEC_CloseSession(&mut session);
    TEEC_FinalizeContext(&mut ctx);

    result
}

/// List all occupied key slot IDs in the TA via CMD_LIST_SLOTS (0x0004).
///
/// # TEEC Parameters
/// - `params[0]` MemrefOutput: JSON array of slot IDs (e.g. `[0, 1, 7]`)
/// - `params[1]` ValueOutput:  `{a: BIZ_SUCCESS, b: slot_count}`
///
/// # Logic
/// 1. Allocate a 4KB output buffer for the JSON array.
/// 2. `TEEC_InvokeCommand(CMD_LIST_SLOTS)`.
/// 3. Read `params[1].value.b` for the count and `params[0]` for the JSON.
/// 4. Deserialize and print: `Slots (N total): [0, 1, 7]`.
fn cmd_list_slots(session: &mut raw::TEEC_Session) -> Result<(), String> {
    // params[0] MemrefOutput: JSON Vec<u32>
    // params[1] ValueOutput:  {a: biz_code, b: count}
    let mut response_buf = vec![0u8; 4096];
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_TEMP_OUTPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].tmpref.buffer = response_buf.as_mut_ptr() as *mut _;
    op.params[0].tmpref.size = response_buf.len();

    let mut origin = 0u32;
    let rc = TEEC_InvokeCommand(session, CMD_LIST_SLOTS, &mut op, &mut origin);
    check_teec_rc(rc, origin)?;

    let (biz_code, count) = unsafe { (op.params[1].value.a, op.params[1].value.b) };
    check_biz_code(biz_code)?;

    let filled = unsafe { op.params[0].tmpref.size };
    let slots: Vec<u32> = serde_json::from_slice(&response_buf[..filled])
        .map_err(|e| format!("failed to parse slot list: {e}"))?;

    println!("Slots ({count} total): {slots:?}");
    Ok(())
}

/// Store an API key in the TA's key slot via CMD_PROVISION_KEY (0x0002).
///
/// # CLI Arguments
/// `--slot <N>` — slot index (u32), `--key <sk-...>` — API key string,
/// `--provider <name>` — provider name (e.g. "minimax").
///
/// # TEEC Parameters
/// - `params[0]` MemrefInput:  JSON `{"slot": N, "key": "sk-...", "provider": "minimax"}`
/// - `params[1]` ValueOutput:  `{a: BIZ_SUCCESS, b: 0}`
///
/// # Logic
/// 1. Parse `--slot`, `--key`, `--provider` from CLI args.
/// 2. Serialize `ProvisionKeyPayload` to JSON.
/// 3. `TEEC_InvokeCommand(CMD_PROVISION_KEY)` with JSON as MemrefInput.
/// 4. Check TEEC return code and business code.
fn cmd_provision_key(session: &mut raw::TEEC_Session, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;
    let key = parse_arg_str(args, "--key")?;
    let provider = parse_arg_str(args, "--provider")?;

    let payload = ProvisionKeyPayload { slot, key, provider };
    let mut json = serde_json::to_vec(&payload).map_err(|e| format!("serialize error: {e}"))?;

    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_TEMP_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].tmpref.buffer = json.as_mut_ptr() as *mut _;
    op.params[0].tmpref.size = json.len();

    let mut origin = 0u32;
    let rc = TEEC_InvokeCommand(session, CMD_PROVISION_KEY, &mut op, &mut origin);
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };
    check_biz_code(biz_code)?;

    println!("Key provisioned in slot {slot}");
    Ok(())
}

/// Remove an API key from a slot via CMD_REMOVE_KEY (0x0003).
///
/// # CLI Arguments
/// `--slot <N>` — slot index to remove.
///
/// # TEEC Parameters
/// - `params[0]` ValueInput:   `{a: slot_id, b: 0}` (no JSON needed for a single u32)
/// - `params[1]` ValueOutput:  `{a: BIZ_SUCCESS, b: 0}` or
///                             `{a: BIZ_ERR_KEY_NOT_FOUND, b: slot_id}`
fn cmd_remove_key(session: &mut raw::TEEC_Session, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;

    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_VALUE_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].value.a = slot;
    op.params[0].value.b = 0;

    let mut origin = 0u32;
    let rc = TEEC_InvokeCommand(session, CMD_REMOVE_KEY, &mut op, &mut origin);
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };
    check_biz_code(biz_code)?;

    println!("Slot {slot} removed");
    Ok(())
}

/// Add a URL prefix pattern to the TA's whitelist via CMD_ADD_WHITELIST (0x0005).
///
/// # CLI Arguments
/// `--pattern <url-prefix>` — URL prefix (e.g. "https://api.openai.com/").
///
/// # TEEC Parameters
/// - `params[0]` MemrefInput:  JSON `{"pattern": "https://..."}`
/// - `params[1]` ValueOutput:  `{a: BIZ_SUCCESS, b: 0}`
///
/// The TA uses prefix matching: a request to `endpoint_url` is allowed if
/// `endpoint_url.starts_with(pattern)` for any whitelisted pattern.
fn cmd_add_whitelist(session: &mut raw::TEEC_Session, args: &[String]) -> Result<(), String> {
    let pattern = parse_arg_str(args, "--pattern")?;

    let payload = AddWhitelistPayload { pattern: pattern.clone() };
    let mut json = serde_json::to_vec(&payload).map_err(|e| format!("serialize error: {e}"))?;

    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_TEMP_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].tmpref.buffer = json.as_mut_ptr() as *mut _;
    op.params[0].tmpref.size = json.len();

    let mut origin = 0u32;
    let rc = TEEC_InvokeCommand(session, CMD_ADD_WHITELIST, &mut op, &mut origin);
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };
    check_biz_code(biz_code)?;

    println!("Whitelist entry added: {pattern}");
    Ok(())
}

/// Execute an HTTP proxy request through the TEEC relay.
///
/// # Logic
/// 1. Parse CLI arguments: `--slot`, `--url`, `--body`, `--method`, `--stream`.
/// 2. Build a `ProxyRequest` JSON and send via `TEEC_InvokeCommand(CMD_PROXY_REQUEST)`.
/// 3. Check the response:
///    - `BIZ_RELAY_START`: TA created a relay session.  Extract the target
///      "host:port" from `params[2]` and initial TLS bytes from `params[3]`.
///      Enter [`relay_loop`] to drive the TCP + TEEC relay cycle.
///    - `BIZ_SUCCESS`: legacy mode (vsock-forwarder/direct-http).  The TA
///      returned the full ProxyResponse directly in `params[2]`.
///    - `BIZ_ERR_*`: validation failure (whitelist, key not found, bad JSON).
///
/// # Arguments
/// * `session` - open TEEC session to the TA
/// * `args` - CLI argument slice after the "proxy" subcommand
///
/// # Returns
/// `Ok(())` on success (response printed to stdout), `Err(String)` on failure.
fn cmd_proxy(session: &mut raw::TEEC_Session, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;
    let url = parse_arg_str(args, "--url")?;
    let body_str = parse_arg_str(args, "--body")?;
    let method_str = parse_arg_str(args, "--method").unwrap_or_else(|_| "Post".into());
    let stream_mode = args.iter().any(|a| a == "--stream");

    let method = match method_str.as_str() {
        "Get"    => HttpMethod::Get,
        "Post"   => HttpMethod::Post,
        "Put"    => HttpMethod::Put,
        "Delete" => HttpMethod::Delete,
        "Patch"  => HttpMethod::Patch,
        other    => return Err(format!("unknown method: {other}")),
    };

    let mut headers = HashMap::from([("Content-Type".into(), "application/json".into())]);
    // Anthropic-compatible endpoints require this version header
    if url.contains("/anthropic/") {
        headers.insert("anthropic-version".into(), "2023-06-01".into());
    }

    let req = ProxyRequest {
        key_id: slot,
        endpoint_url: url,
        method,
        headers,
        body: body_str.into_bytes(),
        body_base64: None,
    };
    let mut json = serde_json::to_vec(&req).map_err(|e| format!("serialize error: {e}"))?;

    // --- Step 1: CMD_PROXY_REQUEST → get relay start or legacy response ---
    // params[0] MemrefInput:  JSON ProxyRequest
    // params[1] ValueOutput:  {a: biz_code, b: detail}
    // params[2] MemrefOutput: target host:port (relay) or ProxyResponse JSON (legacy)
    // params[3] MemrefOutput: initial TLS bytes (relay only)
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
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };

    if biz_code == BIZ_RELAY_START {
        // --- Relay mode: CA handles TCP I/O ---
        let target_len = unsafe { op.params[2].tmpref.size };
        let target = std::str::from_utf8(&target_buf[..target_len])
            .map_err(|e| format!("invalid target UTF-8: {e}"))?
            .to_string();
        let tls_len = unsafe { op.params[3].tmpref.size };
        let initial_tls = &tls_buf[..tls_len];

        eprintln!("secret_proxy_ca: relay mode → TCP connect to {target}");

        return relay_loop(session, &target, initial_tls, stream_mode);
    }

    // --- Legacy mode: TA returned the final result directly ---
    check_biz_code(biz_code)?;

    let http_status = unsafe { op.params[1].value.b };
    let filled = unsafe { op.params[2].tmpref.size };
    let resp: ProxyResponse = serde_json::from_slice(&target_buf[..filled])
        .map_err(|e| format!("failed to parse ProxyResponse: {e}"))?;

    println!("HTTP {http_status}");
    if let Ok(s) = std::str::from_utf8(&resp.body) {
        println!("{s}");
    } else {
        println!("<{} bytes binary>", resp.body.len());
    }
    Ok(())
}

/// Relay loop: the CA drives TCP I/O while the TA drives the TLS state machine.
///
/// # Logic
/// 1. `TcpStream::connect(target)` to the API server (e.g. api.minimax.chat:443).
///    Set a 30-second read timeout.
/// 2. Send initial TLS bytes (ClientHello from CMD_PROXY_REQUEST) to the server.
/// 3. Enter the relay loop.  Each iteration:
///    a. Read ciphertext from the TCP socket (server → CA).
///    b. Send it to the TA via `TEEC_InvokeCommand(CMD_RELAY_DATA)`.
///    c. Process the TA's response based on the business status code:
///       - `BIZ_RELAY_CONTINUE`: send `params[2]` TLS bytes to the server.
///         (TLS handshake continuation or encrypted HTTP request.)
///       - `BIZ_RELAY_STREAMING`: TA has decrypted SSE plaintext.  If
///         `stream_mode`, write `params[2]` to stdout and flush immediately.
///         Send any `params[3]` TLS bytes to the server.
///       - `BIZ_RELAY_DONE`: relay complete.  In `stream_mode`, all data was
///         already written to stdout — just send final TLS bytes and return.
///         In non-stream mode, parse `params[2]` as ProxyResponse JSON and
///         print as `HTTP {status}\n{body}`.
///       - `BIZ_ERR_TRANSPORT`: TA reported a TLS/connection error.
/// 4. EOF detection: if `tcp.read()` returns 0 twice consecutively, the server
///    closed the connection before the TA completed — return an error to
///    prevent infinite looping.
///
/// # Arguments
/// * `session` - open TEEC session to the TA
/// * `target` - "host:port" string from CMD_PROXY_REQUEST response
/// * `initial_tls` - ClientHello bytes from CMD_PROXY_REQUEST response
/// * `stream_mode` - if true, write decrypted plaintext to stdout progressively
///
/// # Returns
/// `Ok(())` on success, `Err(String)` on TCP/TEEC failure.
fn relay_loop(
    session: &mut raw::TEEC_Session,
    target: &str,
    initial_tls: &[u8],
    stream_mode: bool,
) -> Result<(), String> {
    // 1. TCP connect to the target API server
    let mut tcp = TcpStream::connect(target)
        .map_err(|e| format!("TCP connect to {target} failed: {e}"))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;

    // 2. Send initial TLS bytes (ClientHello)
    tcp.write_all(initial_tls)
        .map_err(|e| format!("TCP write initial TLS failed: {e}"))?;

    // 3. Relay loop — reuse buffers across rounds to avoid repeated allocation
    let mut read_buf = vec![0u8; 65536];
    let mut response_buf = vec![0u8; 1024 * 1024]; // 1 MiB for TA output
    let mut tls_final_buf = vec![0u8; 4096]; // for final TLS bytes on DONE
    let mut round = 0u32;
    let mut saw_eof = false;

    loop {
        round += 1;

        // Read from TCP server
        let n = match tcp.read(&mut read_buf) {
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut
                       || e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err("TCP read timed out waiting for server".into());
            }
            Err(e) => return Err(format!("TCP read failed: {e}")),
        };

        if n == 0 {
            if saw_eof {
                // Second consecutive EOF → server closed, TA didn't finish
                return Err("server closed connection before TA completed relay".into());
            }
            saw_eof = true;
        } else {
            saw_eof = false;
        }

        eprintln!("secret_proxy_ca: relay round {round}, server→ {n} bytes{}", if n == 0 { " (EOF)" } else { "" });

        // Send server data to TA via CMD_RELAY_DATA
        let mut server_data = read_buf[..n].to_vec();
        let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_MEMREF_TEMP_INPUT,
            raw::TEEC_VALUE_OUTPUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
        );
        op.params[0].tmpref.buffer = server_data.as_mut_ptr() as *mut _;
        op.params[0].tmpref.size = server_data.len();
        op.params[2].tmpref.buffer = response_buf.as_mut_ptr() as *mut _;
        op.params[2].tmpref.size = response_buf.len();
        op.params[3].tmpref.buffer = tls_final_buf.as_mut_ptr() as *mut _;
        op.params[3].tmpref.size = tls_final_buf.len();

        let mut origin = 0u32;
        let rc = TEEC_InvokeCommand(session, CMD_RELAY_DATA, &mut op, &mut origin);
        check_teec_rc(rc, origin)?;

        let (status, detail) = unsafe { (op.params[1].value.a, op.params[1].value.b) };
        let filled = unsafe { op.params[2].tmpref.size };

        match status {
            BIZ_RELAY_CONTINUE => {
                // Send outgoing TLS bytes to server (if any)
                if filled > 0 {
                    tcp.write_all(&response_buf[..filled])
                        .map_err(|e| format!("TCP write TLS data failed: {e}"))?;
                    eprintln!("secret_proxy_ca: relay round {round}, →server {filled} bytes");
                }
            }
            BIZ_RELAY_STREAMING => {
                // Streaming mode: write decrypted plaintext to stdout immediately
                if filled > 0 && stream_mode {
                    std::io::stdout().write_all(&response_buf[..filled])
                        .map_err(|e| format!("stdout write: {e}"))?;
                    std::io::stdout().flush()
                        .map_err(|e| format!("stdout flush: {e}"))?;
                }

                // Send any TLS bytes back to server
                let tls_len = unsafe { op.params[3].tmpref.size };
                if tls_len > 0 {
                    tcp.write_all(&tls_final_buf[..tls_len])
                        .map_err(|e| format!("TCP write TLS data: {e}"))?;
                }
            }
            BIZ_RELAY_DONE => {
                // Send any final TLS bytes (e.g. close_notify) before closing
                let final_tls_len = unsafe { op.params[3].tmpref.size };
                if final_tls_len > 0 {
                    let _ = tcp.write_all(&tls_final_buf[..final_tls_len]);
                }

                if stream_mode {
                    // Streaming: all data already written to stdout
                    return Ok(());
                }

                let http_status = detail;
                let resp: ProxyResponse = serde_json::from_slice(&response_buf[..filled])
                    .map_err(|e| format!("failed to parse ProxyResponse: {e}"))?;

                println!("HTTP {http_status}");
                if let Ok(s) = std::str::from_utf8(&resp.body) {
                    println!("{s}");
                } else {
                    println!("<{} bytes binary>", resp.body.len());
                }
                return Ok(());
            }
            BIZ_ERR_TRANSPORT => {
                return Err(format!("TA relay error (transport): detail=0x{detail:04x}"));
            }
            _ => {
                return Err(format!("unexpected relay status: 0x{status:04x}"));
            }
        }
    }
}

/// Parse a UUID string (e.g. "a3f79c15-72d0-4e3a-b8d1-9f2ca3e81054") into the
/// `TEEC_UUID` struct required by rust-libteec.
///
/// # Arguments
/// * `s` - UUID string in standard 8-4-4-4-12 format
///
/// # Returns
/// `Ok(TEEC_UUID)` on success.  The struct fields (timeLow, timeMid, etc.)
/// are populated from the UUID's binary representation.
pub(crate) fn parse_uuid(s: &str) -> Result<raw::TEEC_UUID, String> {
    Uuid::parse_str(s)
        .map(|u| {
            let (time_low, time_mid, time_hi_and_version, clock_seq_and_node) = u.as_fields();
            raw::TEEC_UUID {
                timeLow: time_low,
                timeMid: time_mid,
                timeHiAndVersion: time_hi_and_version,
                clockSeqAndNode: *clock_seq_and_node,
            }
        })
        .map_err(|e| format!("UUID parse failed: {e}"))
}

/// Check the TEEC return code from `TEEC_InvokeCommand`.
///
/// # Arguments
/// * `rc` - return code from the TEEC call (0 = `TEEC_SUCCESS`)
/// * `origin` - error origin indicator (which layer produced the error:
///   TEE client API, communication, trusted app, or trusted OS)
///
/// # Returns
/// `Ok(())` if `rc == TEEC_SUCCESS`, otherwise `Err` with the hex error
/// code and origin for debugging.
pub(crate) fn check_teec_rc(rc: u32, origin: u32) -> Result<(), String> {
    if rc != raw::TEEC_SUCCESS {
        Err(format!("TEEC_InvokeCommand failed: 0x{rc:08x}, origin={origin}"))
    } else {
        Ok(())
    }
}

/// Check the TA business result code from `params[1].value.a`.
///
/// The TA always returns `TEE_SUCCESS` at the TEEC level; business-layer
/// errors are communicated via this code.
///
/// # Arguments
/// * `biz_code` - value from `params[1].value.a` in the TA's response
///
/// # Returns
/// `Ok(())` if `biz_code == BIZ_SUCCESS (0x900D)`.  Otherwise, returns
/// `Err` with a human-readable message mapping the code to its meaning
/// (e.g. 0xE005 → "endpoint blocked by whitelist").
fn check_biz_code(biz_code: u32) -> Result<(), String> {
    if biz_code == BIZ_SUCCESS {
        return Ok(());
    }
    let msg = match biz_code {
        BIZ_ERR_BAD_JSON      => "bad JSON payload",
        BIZ_ERR_KEY_NOT_FOUND => "key slot not found",
        BIZ_ERR_FORBIDDEN     => "endpoint blocked by whitelist",
        BIZ_ERR_TRANSPORT     => "upstream HTTP transport error",
        _                     => "unknown business error",
    };
    Err(format!("TA error 0x{biz_code:04x}: {msg}"))
}

/// Extract a string argument value following a flag (e.g. `--slot 0` → "0").
/// Scans `args` for a window `[flag, value]` and returns the value.
fn parse_arg_str(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .ok_or_else(|| format!("missing argument: {flag}"))
}

/// Extract a u32 argument value following a flag (e.g. `--slot 0` → 0u32).
pub(crate) fn parse_arg_u32(args: &[String], flag: &str) -> Result<u32, String> {
    let s = parse_arg_str(args, flag)?;
    s.parse::<u32>().map_err(|e| format!("{flag} parse error: {e}"))
}

fn print_usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {prog} list-slots");
    eprintln!("  {prog} provision-key --slot <N> --key <sk-...> --provider <name>");
    eprintln!("  {prog} remove-key --slot <N>");
    eprintln!("  {prog} add-whitelist --pattern <url-prefix>");
    eprintln!("  {prog} proxy --slot <N> --url <https://...> --body <json>");
    eprintln!("             [--method Post|Get|Put|Delete|Patch] [--stream]");
    eprintln!();
    eprintln!("The proxy command uses TEEC relay mode: the CA handles TCP I/O to");
    eprintln!("external APIs while the TA drives TLS encryption inside the TEE.");
    eprintln!("No separate tls_forwarder process is needed.");
}
