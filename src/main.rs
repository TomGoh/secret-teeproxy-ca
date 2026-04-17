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
//!   secret_proxy_ca serve [--port 18800]
//!
//! Note: the `proxy` CLI subcommand was removed in the Step 8 refactor
//! (verified no external callers — openclaw uses `serve` mode's HTTP API).

mod constants;
mod error;
mod http;
mod relay;
mod server;
mod sse;
mod teec;

// Re-export constants at the crate root so existing `crate::TA_UUID` imports
// (notably in serve.rs) keep compiling without churn during the refactor.
// When the refactor finishes, these re-exports should be removed and callers
// should import from `crate::constants::*` explicitly.
#[allow(unused_imports)]
pub(crate) use constants::{
    TA_UUID,
    CMD_PROXY_REQUEST, CMD_PROVISION_KEY, CMD_REMOVE_KEY, CMD_LIST_SLOTS,
    CMD_ADD_WHITELIST, CMD_RELAY_DATA, CMD_LIST_SLOTS_META,
    BIZ_SUCCESS, BIZ_RELAY_START, BIZ_RELAY_CONTINUE, BIZ_RELAY_DONE,
    BIZ_RELAY_STREAMING, BIZ_ERR_BAD_JSON, BIZ_ERR_KEY_NOT_FOUND,
    BIZ_ERR_FORBIDDEN, BIZ_ERR_TRANSPORT,
    ADMIN_TOKEN_ENV, ADMIN_TOKEN_PREV_ENV, ADMIN_TOKEN_MIN_LEN,
    ADMIN_ACTOR_HEADER, ADMIN_REQUEST_ID_HEADER,
};

use std::{collections::HashMap, mem};
// Step 8 refactor: `Read`, `Write`, `TcpStream`, `debug`, `info` were only
// used by the removed `cmd_proxy` + `relay_loop`; pruned here. The logging
// crate `log::error` macro is still needed by the main entry point.

// Step 5 refactor: raw `TEEC_InitializeContext / TEEC_OpenSession / TEEC_Close*`
// calls moved inside `teec::RealTeec`. Only `TEEC_Operation` plumbing +
// `TEEC_PARAM_TYPES` constants are still touched directly by the command
// helpers below. `TEEC_InvokeCommand` now goes through `Teec::invoke`.
use cc_teec::raw;
use log::error;
use serde::{Deserialize, Serialize};

use crate::teec::{RealTeec, Teec};

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

/// Non-secret slot row from TA (`CMD_LIST_SLOTS_META`) — matches TA `SlotMeta` JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SlotEntry {
    pub slot: u32,
    pub provider: String,
}

/// Payload for CMD_PROVISION_KEY (params[0] MemrefInput).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ProvisionKeyPayload {
    /// Key slot index to store the key in.
    pub slot: u32,
    /// The API key string (e.g. "sk-api--xxxxx").
    pub key: String,
    /// Provider name (e.g. "minimax", "moonshot").
    pub provider: String,
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
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    ).init();

    if let Err(e) = run() {
        error!("{e}");
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

    // `serve` manages its own TEEC lifecycle (long-lived session).
    // Step 9 refactor: the serve-mode entry moved from `serve::cmd_serve`
    // to `server::run` as part of the serve.rs teardown.
    if args[1] == "serve" {
        return server::run(&args[2..]);
    }

    // `dns-test` is a TEEC-free diagnostic: it just calls `to_socket_addrs`
    // and prints the result. Used to verify the platform's DNS resolver
    // (musl /etc/resolv.conf vs Bionic dnsproxyd) works for a target host
    // before exercising the full proxy path. Safe to run on any device,
    // including stock Android with no TEE backend.
    if args[1] == "dns-test" {
        use std::net::ToSocketAddrs;
        let host = args.get(2)
            .ok_or("dns-test requires <hostname>")?;
        let target = format!("{host}:443");
        match target.to_socket_addrs() {
            Ok(iter) => {
                let addrs: Vec<_> = iter.collect();
                if addrs.is_empty() {
                    println!("{host} -> (no addresses)");
                } else {
                    println!("{host} ->");
                    for a in addrs { println!("  {a}"); }
                }
                return Ok(());
            }
            Err(e) => return Err(format!("resolve {host} failed: {e}")),
        }
    }

    // `vsock-test` is a TEEC-free diagnostic that isolates the AF_VSOCK
    // socket + connect path from the rest of the CA pipeline (rust-libteec
    // → virga → mbedtls TLS-over-vsock). Errors are raw errno values from
    // the kernel, so failures are attributable to one of:
    //
    //   - EACCES         SELinux blocked socket(AF_VSOCK,...) or connect(2)
    //   - EAFNOSUPPORT   kernel has no vsock support at all
    //   - ENODEV         no host-side vsock peer at this CID (VM not running)
    //   - ECONNREFUSED   host is there but nothing is listening on that port
    //   - EPERM          uid/capability problem
    //
    // Use on Android device bring-up to answer "does vsock work on this
    // device for my app uid, and can I reach the TEE VM at the expected
    // CID?" in isolation, before stacking TEEC/mbedtls errors on top.
    //
    // Usage:  secret_proxy_ca vsock-test <cid> [port]
    // Examples:
    //   vsock-test 103 9999    # our design-time TEEC bridge target
    //   vsock-test 2 9999      # VMADDR_CID_HOST (host side), sanity check
    //   vsock-test 1 9999      # VMADDR_CID_LOCAL, loopback — tests kernel
    //                          # vsock support without any real peer
    if args[1] == "vsock-test" {
        let cid: u32 = args.get(2)
            .ok_or("vsock-test requires <cid> [port]")?
            .parse()
            .map_err(|e| format!("invalid cid: {e}"))?;
        let port: u32 = match args.get(3) {
            Some(s) => s.parse().map_err(|e| format!("invalid port: {e}"))?,
            None => 9999,
        };
        return vsock_test(cid, port);
    }

    // Step 5 refactor: TEEC context + session setup + teardown moved inside
    // `RealTeec::open`/`Drop`. Behavior is identical — same UUID parse, same
    // TEEC_InitializeContext + TEEC_OpenSession sequence, same close-session
    // -before-finalize-context cleanup ordering — but the command helpers now
    // take `&mut dyn Teec` so they are unit-testable with `MockTeec`.
    let mut teec = RealTeec::open(TA_UUID)?;

    // Step 8 refactor (2026-04-17): the `proxy` CLI subcommand and its
    // 185-LOC companion `relay_loop` were removed. Verified via grep that
    // nothing outside this crate invoked `secret_proxy_ca proxy` —
    // openclaw uses the HTTP `serve` mode directly, and no shell script
    // or deploy script referenced the CLI path.
    match args[1].as_str() {
        "list-slots"     => cmd_list_slots(&mut teec),
        "provision-key"  => cmd_provision_key(&mut teec, &args[2..]),
        "remove-key"     => cmd_remove_key(&mut teec, &args[2..]),
        "add-whitelist"  => cmd_add_whitelist(&mut teec, &args[2..]),
        other => {
            error!("unknown command: {other}");
            print_usage(&args[0]);
            Ok(())
        }
    }
    // `teec` is dropped here — closes session + finalizes context in the
    // same order as the pre-refactor manual cleanup.
}

/// List all occupied key slot IDs in the TA via CMD_LIST_SLOTS (0x0004).
/// Shared by CLI and HTTP admin API.
pub(crate) fn teec_list_slots(teec: &mut dyn Teec) -> Result<Vec<u32>, String> {
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

    let (rc, origin) = teec.invoke(CMD_LIST_SLOTS, &mut op);
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };
    check_biz_code(biz_code)?;

    let filled = unsafe { op.params[0].tmpref.size };
    let slots: Vec<u32> = serde_json::from_slice(&response_buf[..filled])
        .map_err(|e| format!("failed to parse slot list: {e}"))?;

    Ok(slots)
}

/// List occupied slots with provider names (no key material) via CMD_LIST_SLOTS_META (0x0007).
pub(crate) fn teec_list_slots_meta(teec: &mut dyn Teec) -> Result<Vec<SlotEntry>, String> {
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

    let (rc, origin) = teec.invoke(CMD_LIST_SLOTS_META, &mut op);
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };
    check_biz_code(biz_code)?;

    let filled = unsafe { op.params[0].tmpref.size };
    let entries: Vec<SlotEntry> = serde_json::from_slice(&response_buf[..filled])
        .map_err(|e| format!("failed to parse slot meta list: {e}"))?;

    Ok(entries)
}

/// Classify a TA/list probe error for `/health` and automation (`error_layer` field).
pub(crate) fn ta_error_layer(message: &str) -> &'static str {
    if message.contains("TEEC_InvokeCommand failed") {
        "teec_invoke"
    } else if message.contains("TA error") {
        "ta_business"
    } else if message.contains("failed to parse") {
        "ca_parse"
    } else {
        "unknown"
    }
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
fn cmd_list_slots(teec: &mut dyn Teec) -> Result<(), String> {
    let slots = teec_list_slots(teec)?;
    let count = slots.len();
    println!("Slots ({count} total): {slots:?}");
    Ok(())
}

/// Store an API key in the TA's key slot via CMD_PROVISION_KEY (0x0002).
/// Shared by CLI and HTTP admin API.
pub(crate) fn teec_provision_key(
    teec: &mut dyn Teec,
    payload: &ProvisionKeyPayload,
) -> Result<(), String> {
    let mut json = serde_json::to_vec(payload).map_err(|e| format!("serialize error: {e}"))?;

    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_TEMP_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].tmpref.buffer = json.as_mut_ptr() as *mut _;
    op.params[0].tmpref.size = json.len();

    let (rc, origin) = teec.invoke(CMD_PROVISION_KEY, &mut op);
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };
    check_biz_code(biz_code)?;

    Ok(())
}

/// Remove an API key from a TA slot via CMD_REMOVE_KEY.
pub(crate) fn teec_remove_key(teec: &mut dyn Teec, slot: u32) -> Result<(), String> {
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_VALUE_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_NONE,
        raw::TEEC_NONE,
    );
    op.params[0].value.a = slot;
    op.params[0].value.b = 0;

    let (rc, origin) = teec.invoke(CMD_REMOVE_KEY, &mut op);
    check_teec_rc(rc, origin)?;

    let biz_code = unsafe { op.params[1].value.a };
    check_biz_code(biz_code)?;
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
fn cmd_provision_key(teec: &mut dyn Teec, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;
    let key = parse_arg_str(args, "--key")?;
    let provider = parse_arg_str(args, "--provider")?;

    let payload = ProvisionKeyPayload { slot, key, provider };
    teec_provision_key(teec, &payload)?;

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
fn cmd_remove_key(teec: &mut dyn Teec, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;
    teec_remove_key(teec, slot)?;
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
fn cmd_add_whitelist(teec: &mut dyn Teec, args: &[String]) -> Result<(), String> {
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

    let (rc, origin) = teec.invoke(CMD_ADD_WHITELIST, &mut op);
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

// Step 5 refactor: `parse_uuid` moved to `crate::teec::real` (only used
// during TEE session open, now encapsulated in `RealTeec::open`).

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
    eprintln!("  {prog} serve [--port 19030]");
    eprintln!("  {prog} dns-test <hostname>");
    eprintln!("  {prog} vsock-test <cid> [port]");
    eprintln!();
    eprintln!("HTTP proxy requests are served only via `serve` mode (the `proxy`");
    eprintln!("CLI subcommand was removed in the Step 8 refactor — it had no");
    eprintln!("external callers). Clients should POST SecretProxyRequest JSON");
    eprintln!("to the port configured with --port.");
    eprintln!();
    eprintln!("dns-test is a TEEC-free diagnostic: resolves <hostname>:443 via the");
    eprintln!("platform's getaddrinfo and prints the result. Use it on Android to");
    eprintln!("verify Bionic/dnsproxyd works before exercising the full proxy.");
    eprintln!();
    eprintln!("vsock-test is a TEEC-free diagnostic that exercises the raw vsock");
    eprintln!("socket + connect path to a given (cid, port). Errors come back as");
    eprintln!("raw errno values from the kernel — useful on Android bring-up to");
    eprintln!("distinguish SELinux denials (EACCES) from missing VM peers (ENODEV)");
    eprintln!("or missing kernel support (EAFNOSUPPORT). Default port is 9999.");
    eprintln!();
    eprintln!("Logging: set RUST_LOG=debug for verbose relay details.");
    eprintln!();
    eprintln!("serve: GET /health (TEEC+TA probe, no auth); admin API: set SECRET_PROXY_CA_ADMIN_TOKEN");
    eprintln!("  X-Admin-Token for GET /admin/keys/slots and POST /admin/keys/provision");
}

/// Raw `sockaddr_vm` as defined in `<linux/vm_sockets.h>`.
///
/// Not re-exported by every `libc` version on every target, so we declare it
/// locally to keep this diagnostic self-contained. The layout matches the
/// kernel ABI exactly; do not reorder fields.
#[repr(C)]
#[derive(Default)]
#[allow(non_camel_case_types)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// TEEC-free diagnostic: attempt `socket(AF_VSOCK, SOCK_STREAM, 0)` +
/// `connect(&sockaddr_vm { cid, port })` and print exactly what the kernel
/// returned. See the call site in `run()` for the full intent.
fn vsock_test(cid: u32, port: u32) -> Result<(), String> {
    // Step 1: create the socket.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(format!(
            "socket(AF_VSOCK, SOCK_STREAM, 0) failed: {e}{}",
            errno_hint(e.raw_os_error().unwrap_or(0)),
        ));
    }
    println!("✓ socket(AF_VSOCK, SOCK_STREAM, 0) → fd={fd}");

    // Step 2: connect to (cid, port). On failure we still need to close the
    // socket — capture the error first, close, then report.
    let addr = SockaddrVm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_port: port,
        svm_cid: cid,
        ..SockaddrVm::default()
    };
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };
    let connect_err = if rc < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::close(fd) };

    match connect_err {
        None => {
            println!("✓ connect(cid={cid}, port={port}) → success");
            Ok(())
        }
        Some(e) => {
            let errno = e.raw_os_error().unwrap_or(0);
            Err(format!(
                "connect(cid={cid}, port={port}) failed: {e} (errno={errno}){}",
                errno_hint(errno),
            ))
        }
    }
}

/// Short human-readable hint for the most common errno values that the
/// vsock path can return. Keeps the error output actionable without
/// requiring the user to grep man pages.
fn errno_hint(errno: i32) -> &'static str {
    match errno {
        libc::EACCES       => "  (SELinux denial on vsock_socket; check `dmesg | grep avc` or `logcat | grep avc`)",
        libc::EAFNOSUPPORT => "  (kernel has no AF_VSOCK support; CONFIG_VSOCKETS is missing)",
        libc::ENODEV       => "  (no vsock peer at this CID; the host VM is probably not running)",
        libc::ECONNREFUSED => "  (peer is there but nothing is listening on that port)",
        libc::ECONNRESET   => "  (peer exists and reset the connection; on VMADDR_CID_LOCAL this means kernel vsock loopback is working but no one is listening on that port — a GOOD signal about kernel support)",
        libc::ETIMEDOUT    => "  (SYN dispatched to peer but no answer — peer vsock stack is probably up and CID is registered, but no socket is in LISTEN state on that port and the peer's vsock driver is not sending RSTs for unknown destinations; in our pipeline this is the expected error when the x-kernel VM is booted but no teec_cc_bridge is running inside it)",
        libc::EPERM        => "  (operation not permitted; check process uid/capabilities)",
        libc::ENETUNREACH  => "  (network unreachable; kernel vsock configuration may be incomplete)",
        _                  => "",
    }
}

// ---------------------------------------------------------------------------
// Step 5 param-layout validation tests
//
// These tests drive each TEEC helper with a `MockTeec` and assert that the
// cmd_id + paramTypes combination exactly matches what the TA expects.
// The TA checks `op.paramTypes` on entry and silently fails when the bit
// pattern is wrong — a bug that is nearly impossible to diagnose from the
// CA side. Locking the layout at unit-test time means any future reorder
// (e.g. dropping a VALUE_OUTPUT or flipping INPUT↔OUTPUT) trips the test
// locally, before the Android deploy.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod teec_layout_tests {
    use super::*;
    use crate::teec::mock::MockTeec;
    use cc_teec::raw;

    /// CMD_LIST_SLOTS (0x0004): params[0]=MEMREF_TEMP_OUTPUT (slot JSON),
    ///   params[1]=VALUE_OUTPUT (biz_code).
    #[test]
    fn list_slots_layout() {
        let mut mock = MockTeec::new();
        mock.queue_blob_and_biz(CMD_LIST_SLOTS, BIZ_SUCCESS, b"[0]".to_vec());
        let slots = teec_list_slots(&mut mock).expect("success path");
        assert_eq!(slots, vec![0u32]);
        assert_eq!(mock.calls.len(), 1);
        assert_eq!(mock.calls[0].cmd_id, CMD_LIST_SLOTS);
        assert_eq!(
            mock.calls[0].param_types,
            raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_TEMP_OUTPUT,
                raw::TEEC_VALUE_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
        );
    }

    /// CMD_LIST_SLOTS_META (0x0007): same layout as CMD_LIST_SLOTS but
    /// returns JSON array of `{slot, provider}` objects.
    #[test]
    fn list_slots_meta_layout() {
        let mut mock = MockTeec::new();
        mock.queue_blob_and_biz(
            CMD_LIST_SLOTS_META,
            BIZ_SUCCESS,
            br#"[{"slot":0,"provider":"minimax-anthropic"}]"#.to_vec(),
        );
        let entries = teec_list_slots_meta(&mut mock).expect("success path");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].slot, 0);
        assert_eq!(entries[0].provider, "minimax-anthropic");
        assert_eq!(
            mock.calls[0].param_types,
            raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_TEMP_OUTPUT,
                raw::TEEC_VALUE_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
        );
    }

    /// CMD_PROVISION_KEY (0x0002): params[0]=MEMREF_TEMP_INPUT (JSON
    /// key payload), params[1]=VALUE_OUTPUT (biz_code).
    #[test]
    fn provision_key_layout() {
        let mut mock = MockTeec::new();
        mock.queue_biz(CMD_PROVISION_KEY, BIZ_SUCCESS);
        let payload = ProvisionKeyPayload {
            slot: 0,
            key: "sk-test".into(),
            provider: "minimax".into(),
        };
        teec_provision_key(&mut mock, &payload).expect("success path");
        assert_eq!(
            mock.calls[0].param_types,
            raw::TEEC_PARAM_TYPES(
                raw::TEEC_MEMREF_TEMP_INPUT,
                raw::TEEC_VALUE_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
        );
    }

    /// CMD_REMOVE_KEY (0x0003): params[0]=VALUE_INPUT (slot_id in .a),
    /// params[1]=VALUE_OUTPUT. The slot id is passed by value, not JSON.
    #[test]
    fn remove_key_layout() {
        let mut mock = MockTeec::new();
        mock.queue_biz(CMD_REMOVE_KEY, BIZ_SUCCESS);
        teec_remove_key(&mut mock, 7).expect("success path");
        assert_eq!(
            mock.calls[0].param_types,
            raw::TEEC_PARAM_TYPES(
                raw::TEEC_VALUE_INPUT,
                raw::TEEC_VALUE_OUTPUT,
                raw::TEEC_NONE,
                raw::TEEC_NONE,
            ),
        );
    }

    /// Biz-code errors surface as `TA error 0x...: <msg>` strings so the
    /// admin API can distinguish them from TEEC_InvokeCommand failures.
    #[test]
    fn biz_error_surfaces_as_ta_error_string() {
        let mut mock = MockTeec::new();
        mock.queue_biz(CMD_REMOVE_KEY, BIZ_ERR_KEY_NOT_FOUND);
        let err = teec_remove_key(&mut mock, 99).unwrap_err();
        assert!(err.starts_with("TA error 0x"), "got: {err}");
        assert!(err.contains("key slot not found"), "got: {err}");
    }

    /// TEEC-level errors (bad session, bridge down, etc.) surface as
    /// `TEEC_InvokeCommand failed: ...` so `ta_error_layer` can tag
    /// them distinctly in `/health`.
    #[test]
    fn teec_rc_error_surfaces_as_invoke_failed_string() {
        let mut mock = MockTeec::new();
        // TEEC_ERROR_COMMUNICATION == 0xFFFF000E per GP spec.
        mock.queue_rc(CMD_LIST_SLOTS, 0xFFFF000E, 2);
        let err = teec_list_slots(&mut mock).unwrap_err();
        assert!(err.starts_with("TEEC_InvokeCommand failed:"), "got: {err}");
        assert!(err.contains("0xffff000e"), "got: {err}");
        assert!(err.contains("origin=2"), "got: {err}");
        // Regression: the health handler uses this tag to route errors.
        assert_eq!(ta_error_layer(&err), "teec_invoke");
    }
}
