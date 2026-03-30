//! secret_proxy_ca — Client Application for SecretProxyTA
//!
//! Communicates with SecretProxyTA via the GP TEE Client API (rust-libteec).
//! The chain is:
//!   this binary → TEEC_InvokeCommand → virga (TLS/vsock) → teec_cc_bridge
//!   → Unix socket /tmp/<UUID>.sock → secret_proxy_ta
//!
//! Usage:
//!   secret_proxy_ca list-slots
//!   secret_proxy_ca provision-key --slot <N> --key <sk-...> --provider <minimax|moonshot>
//!   secret_proxy_ca remove-key --slot <N>
//!   secret_proxy_ca add-whitelist --pattern <url-prefix>
//!   secret_proxy_ca proxy --slot <N> --url <https://...> --body <json>

use std::{collections::HashMap, mem};

use cc_teec::{
    TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext, TEEC_InvokeCommand,
    TEEC_OpenSession, raw,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// TA identity — must match secret_proxy_ta's TA_UUID
// ---------------------------------------------------------------------------

const TA_UUID: &str = "a3f79c15-72d0-4e3a-b8d1-9f2ca3e81054";

// ---------------------------------------------------------------------------
// GP TEE command IDs — must match secret_proxy_ta's constants
// ---------------------------------------------------------------------------

const CMD_PROXY_REQUEST:  u32 = 0x0001;
const CMD_PROVISION_KEY:  u32 = 0x0002;
const CMD_REMOVE_KEY:     u32 = 0x0003;
const CMD_LIST_SLOTS:     u32 = 0x0004;
const CMD_ADD_WHITELIST:  u32 = 0x0005;

// ---------------------------------------------------------------------------
// Business result codes — must match secret_proxy_ta's constants
// ---------------------------------------------------------------------------

const BIZ_SUCCESS:           u32 = 0x900D;
const BIZ_ERR_BAD_JSON:      u32 = 0xE001;
const BIZ_ERR_KEY_NOT_FOUND: u32 = 0xE004;
const BIZ_ERR_FORBIDDEN:     u32 = 0xE005;
const BIZ_ERR_TRANSPORT:     u32 = 0xE006;

// ---------------------------------------------------------------------------
// Shared data types (must match protocol.rs in secret_proxy_ta)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProxyRequest {
    key_id: u32,
    endpoint_url: String,
    method: HttpMethod,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProxyResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProvisionKeyPayload {
    slot: u32,
    key: String,
    provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AddWhitelistPayload {
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

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
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

// ---------------------------------------------------------------------------
// list-slots
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// provision-key --slot <N> --key <sk-...> --provider <name>
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// remove-key --slot <N>
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// add-whitelist --pattern <url-prefix>
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// proxy --slot <N> --url <https://...> --body <json-string>
//        [--method Post|Get|Put|Delete|Patch]  (default: Post)
// ---------------------------------------------------------------------------

fn cmd_proxy(session: &mut raw::TEEC_Session, args: &[String]) -> Result<(), String> {
    let slot = parse_arg_u32(args, "--slot")?;
    let url = parse_arg_str(args, "--url")?;
    let body_str = parse_arg_str(args, "--body")?;
    let method_str = parse_arg_str(args, "--method").unwrap_or_else(|_| "Post".into());

    let method = match method_str.as_str() {
        "Get"    => HttpMethod::Get,
        "Post"   => HttpMethod::Post,
        "Put"    => HttpMethod::Put,
        "Delete" => HttpMethod::Delete,
        "Patch"  => HttpMethod::Patch,
        other    => return Err(format!("unknown method: {other}")),
    };

    let req = ProxyRequest {
        key_id: slot,
        endpoint_url: url,
        method,
        headers: HashMap::from([("Content-Type".into(), "application/json".into())]),
        body: body_str.into_bytes(),
    };
    let mut json = serde_json::to_vec(&req).map_err(|e| format!("serialize error: {e}"))?;

    // params[0] MemrefInput:  JSON ProxyRequest
    // params[1] ValueOutput:  {a: biz_code, b: http_status}
    // params[2] MemrefOutput: JSON ProxyResponse
    let mut response_buf = vec![0u8; 1024 * 1024]; // 1 MiB
    let mut op: raw::TEEC_Operation = unsafe { mem::zeroed() };
    op.paramTypes = raw::TEEC_PARAM_TYPES(
        raw::TEEC_MEMREF_TEMP_INPUT,
        raw::TEEC_VALUE_OUTPUT,
        raw::TEEC_MEMREF_TEMP_OUTPUT,
        raw::TEEC_NONE,
    );
    op.params[0].tmpref.buffer = json.as_mut_ptr() as *mut _;
    op.params[0].tmpref.size = json.len();
    op.params[2].tmpref.buffer = response_buf.as_mut_ptr() as *mut _;
    op.params[2].tmpref.size = response_buf.len();

    let mut origin = 0u32;
    let rc = TEEC_InvokeCommand(session, CMD_PROXY_REQUEST, &mut op, &mut origin);
    check_teec_rc(rc, origin)?;

    let (biz_code, http_status) = unsafe { (op.params[1].value.a, op.params[1].value.b) };
    check_biz_code(biz_code)?;

    let filled = unsafe { op.params[2].tmpref.size };
    let resp: ProxyResponse = serde_json::from_slice(&response_buf[..filled])
        .map_err(|e| format!("failed to parse ProxyResponse: {e}"))?;

    println!("HTTP {http_status}");
    if let Ok(body_str) = std::str::from_utf8(&resp.body) {
        println!("{body_str}");
    } else {
        println!("<{} bytes binary>", resp.body.len());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_uuid(s: &str) -> Result<raw::TEEC_UUID, String> {
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

fn check_teec_rc(rc: u32, origin: u32) -> Result<(), String> {
    if rc != raw::TEEC_SUCCESS {
        Err(format!("TEEC_InvokeCommand failed: 0x{rc:08x}, origin={origin}"))
    } else {
        Ok(())
    }
}

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

fn parse_arg_str(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .ok_or_else(|| format!("missing argument: {flag}"))
}

fn parse_arg_u32(args: &[String], flag: &str) -> Result<u32, String> {
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
    eprintln!("             [--method Post|Get|Put|Delete|Patch]");
}
