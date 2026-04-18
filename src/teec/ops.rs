//! TA command wrappers — thin Rust helpers around each `CMD_*` invoke.
//!
//! Each function in this module:
//! 1. Constructs a `TEEC_Operation` with the exact `paramTypes`
//!    composition the TA expects for that command.
//! 2. Fills inputs from the Rust-side args.
//! 3. Calls `teec.invoke(cmd_id, &mut op)` via the [`Teec`] trait.
//! 4. Unpacks outputs (biz_code, MEMREF_TEMP_OUTPUT slices).
//! 5. Returns a Rust-typed `Result`.
//!
//! # Why every layout is unit-tested
//!
//! The TA silently fails (returns `0xFFFF0000` or garbage output) when
//! `paramTypes` doesn't match its expectation exactly — wrong order of
//! `MEMREF_*` vs `VALUE_*`, INPUT↔OUTPUT flipped, etc. These are the
//! hardest bugs to diagnose from the CA side. The `tests` submodule
//! pins each command's layout as a bit-exact constant so any future
//! reorder trips a local unit test, not a silent device regression.

use std::mem;

use cc_teec::raw;

use crate::constants::{
    BIZ_ERR_BAD_JSON, BIZ_ERR_FORBIDDEN, BIZ_ERR_KEY_NOT_FOUND, BIZ_ERR_TRANSPORT, BIZ_SUCCESS,
    CMD_ADD_WHITELIST, CMD_LIST_SLOTS, CMD_LIST_SLOTS_META, CMD_PROVISION_KEY, CMD_REMOVE_KEY,
};
use crate::teec::Teec;
use crate::wire::{AddWhitelistPayload, ProvisionKeyPayload, SlotEntry};

/// List all occupied key slot IDs in the TA via `CMD_LIST_SLOTS` (0x0004).
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

/// List occupied slots with provider names (no key material) via
/// `CMD_LIST_SLOTS_META` (0x0007).
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

/// Store an API key in the TA's key slot via `CMD_PROVISION_KEY` (0x0002).
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

/// Remove an API key from a TA slot via `CMD_REMOVE_KEY` (0x0003).
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

/// Add a URL prefix pattern to the TA's whitelist via
/// `CMD_ADD_WHITELIST` (0x0005). The TA matches
/// `endpoint_url.starts_with(pattern)` — prefix match, not glob.
pub(crate) fn teec_add_whitelist(
    teec: &mut dyn Teec,
    pattern: &str,
) -> Result<(), String> {
    let payload = AddWhitelistPayload {
        pattern: pattern.to_string(),
    };
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

    Ok(())
}

/// Map a `TEEC_InvokeCommand` return code to a `Result`.
///
/// Error format: `TEEC_InvokeCommand failed: 0x{rc:08x}, origin={origin}`.
/// `ta_error_layer` greps on this substring to classify `/health` output.
pub(crate) fn check_teec_rc(rc: u32, origin: u32) -> Result<(), String> {
    if rc != raw::TEEC_SUCCESS {
        Err(format!(
            "TEEC_InvokeCommand failed: 0x{rc:08x}, origin={origin}"
        ))
    } else {
        Ok(())
    }
}

/// Map the TA's business-layer status code (`params[1].value.a`) to a
/// `Result`. `BIZ_SUCCESS` is `Ok`, anything else is `Err` with a
/// human-readable suffix.
///
/// Error format: `TA error 0x{biz_code:04x}: {human}` — pytest greps
/// on it, don't reword.
pub(crate) fn check_biz_code(biz_code: u32) -> Result<(), String> {
    if biz_code == BIZ_SUCCESS {
        return Ok(());
    }
    let msg = match biz_code {
        BIZ_ERR_BAD_JSON => "bad JSON payload",
        BIZ_ERR_KEY_NOT_FOUND => "key slot not found",
        BIZ_ERR_FORBIDDEN => "endpoint blocked by whitelist",
        BIZ_ERR_TRANSPORT => "upstream HTTP transport error",
        _ => "unknown business error",
    };
    Err(format!("TA error 0x{biz_code:04x}: {msg}"))
}

/// Classify a TA/list probe error string for `/health`'s
/// `error_layer` field. Used by the health handler + `teec_rc_error_surfaces`
/// regression test. Kept here next to the two functions that *produce*
/// these error strings so all three move together.
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

// ---------------------------------------------------------------------------
// Param-layout validation tests.
//
// Each test drives one helper with `MockTeec` and asserts the cmd_id +
// `paramTypes` bit pattern matches what the TA expects. The TA silently
// fails on wrong paramTypes, so locking the layout at unit-test time
// catches any future reorder (dropping a VALUE_OUTPUT, flipping
// INPUT↔OUTPUT, etc.) without needing a real device.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::teec::mock::MockTeec;

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

    #[test]
    fn add_whitelist_layout() {
        let mut mock = MockTeec::new();
        mock.queue_biz(CMD_ADD_WHITELIST, BIZ_SUCCESS);
        teec_add_whitelist(&mut mock, "https://api.minimax.chat/").expect("success path");
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

    #[test]
    fn biz_error_surfaces_as_ta_error_string() {
        let mut mock = MockTeec::new();
        mock.queue_biz(CMD_REMOVE_KEY, BIZ_ERR_KEY_NOT_FOUND);
        let err = teec_remove_key(&mut mock, 99).unwrap_err();
        assert!(err.starts_with("TA error 0x"), "got: {err}");
        assert!(err.contains("key slot not found"), "got: {err}");
    }

    #[test]
    fn teec_rc_error_surfaces_as_invoke_failed_string() {
        let mut mock = MockTeec::new();
        // TEEC_ERROR_COMMUNICATION == 0xFFFF000E per GP spec.
        mock.queue_rc(CMD_LIST_SLOTS, 0xFFFF000E, 2);
        let err = teec_list_slots(&mut mock).unwrap_err();
        assert!(err.starts_with("TEEC_InvokeCommand failed:"), "got: {err}");
        assert!(err.contains("0xffff000e"), "got: {err}");
        assert!(err.contains("origin=2"), "got: {err}");
        // ta_error_layer classification — same string the /health handler
        // consumes to populate `error_layer`.
        assert_eq!(ta_error_layer(&err), "teec_invoke");
    }

    #[test]
    fn ta_error_layer_classifies_ta_business() {
        assert_eq!(
            ta_error_layer("TA error 0xE004: key slot not found"),
            "ta_business"
        );
    }

    #[test]
    fn ta_error_layer_classifies_ca_parse() {
        assert_eq!(
            ta_error_layer("failed to parse slot list: EOF"),
            "ca_parse"
        );
    }

    #[test]
    fn ta_error_layer_default_unknown() {
        assert_eq!(ta_error_layer("some unrelated error"), "unknown");
    }
}
