//! In-memory [`Teec`] for unit tests.
//!
//! Tests queue [`ScriptedResponse`]s; each `invoke()` pops the next one,
//! runs its `mutate` closure against the incoming `TEEC_Operation`, and
//! returns the scripted `(rc, origin)`. The mutator is where tests
//! simulate the TA: setting `params[1].value.a` to a `BIZ_*` code,
//! filling a `MEMREF_TEMP_OUTPUT` buffer with a canned JSON response,
//! and so on.
//!
//! Every call is also recorded in `calls: Vec<InvokeCall>` so tests can
//! assert the marshalling after the fact — especially the `paramTypes`
//! bit-pattern, which is the classic foot-gun.
//!
//! Only compiled under `#[cfg(test)]` or with the `test-support`
//! feature, so production binaries never link it.

use std::collections::VecDeque;

use cc_teec::raw;

use super::Teec;

/// One scripted response from the fake TA.
pub struct ScriptedResponse {
    /// If `Some`, [`MockTeec::invoke`] panics when the actual cmd_id
    /// does not match — catches tests that forgot to update the script
    /// after reordering call sites.
    pub expected_cmd_id: Option<u32>,
    /// TEEC-level return code to hand back.
    pub rc: u32,
    /// `TEEC_InvokeCommand` error-origin byte.
    pub origin: u32,
    /// Callback to mutate the op *before* `invoke` returns. Use this to
    /// fill `params[i].value` / `params[i].tmpref.size` so the caller's
    /// response-parsing code sees the "TA output" it expects.
    pub mutate: Box<dyn FnMut(&mut raw::TEEC_Operation) + Send>,
}

/// Snapshot of one past invoke() call. Tests inspect these to verify
/// parameter layout (the whole point of the trait).
#[derive(Debug, Clone, Copy)]
pub struct InvokeCall {
    pub cmd_id: u32,
    /// `op.paramTypes` as it was *before* the mutator ran. Tests assert
    /// bit-perfect equality against the expected `TEEC_PARAM_TYPES(...)`
    /// composition.
    pub param_types: u32,
}

/// Scripted [`Teec`] impl. Create with `MockTeec::new()`, queue responses
/// with `queue` / `queue_biz` / `queue_rc`, hand to the code under test.
#[derive(Default)]
pub struct MockTeec {
    pub calls: Vec<InvokeCall>,
    responses: VecDeque<ScriptedResponse>,
}

impl MockTeec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn queue(&mut self, resp: ScriptedResponse) -> &mut Self {
        self.responses.push_back(resp);
        self
    }

    /// Shorthand: success (rc = TEEC_SUCCESS, origin = 0) with a given
    /// business code written to `params[1].value.a`. Covers the common
    /// `VALUE_OUTPUT` biz-code pattern used by every TA command.
    pub fn queue_biz(&mut self, cmd_id: u32, biz_code: u32) -> &mut Self {
        // NB: writing to a union field is a safe operation on stable Rust
        // since Rust 1.19 (see RFC 1444). No `unsafe` needed for plain
        // assignment; only *reads* from the union require unsafe.
        self.queue(ScriptedResponse {
            expected_cmd_id: Some(cmd_id),
            rc: raw::TEEC_SUCCESS,
            origin: 0,
            mutate: Box::new(move |op| {
                op.params[1].value.a = biz_code;
                op.params[1].value.b = 0;
            }),
        })
    }

    /// Shorthand: TEEC-level failure (nonzero rc). No mutation.
    pub fn queue_rc(&mut self, cmd_id: u32, rc: u32, origin: u32) -> &mut Self {
        self.queue(ScriptedResponse {
            expected_cmd_id: Some(cmd_id),
            rc,
            origin,
            mutate: Box::new(|_| {}),
        })
    }

    /// Queue a response that fills `params[0].tmpref` with `bytes` (as
    /// if the TA wrote a JSON blob to `MEMREF_TEMP_OUTPUT`) and sets
    /// `params[1].value.a = biz_code`. The caller's buffer must be at
    /// least `bytes.len()` bytes — if the provided buffer is smaller,
    /// `mutate` writes only as many bytes as fit and updates
    /// `tmpref.size` accordingly (matches TA short-write semantics).
    pub fn queue_blob_and_biz(
        &mut self,
        cmd_id: u32,
        biz_code: u32,
        bytes: Vec<u8>,
    ) -> &mut Self {
        self.queue(ScriptedResponse {
            expected_cmd_id: Some(cmd_id),
            rc: raw::TEEC_SUCCESS,
            origin: 0,
            mutate: Box::new(move |op| unsafe {
                // Reads from the union (`tmpref.buffer`, `tmpref.size`) and
                // raw-pointer copy still require unsafe — only the
                // *writes* into the union field via assignment are safe.
                let dst = op.params[0].tmpref.buffer as *mut u8;
                let cap = op.params[0].tmpref.size;
                let n = bytes.len().min(cap);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, n);
                op.params[0].tmpref.size = n;
                op.params[1].value.a = biz_code;
                op.params[1].value.b = 0;
            }),
        })
    }
}

impl Teec for MockTeec {
    fn invoke(&mut self, cmd_id: u32, op: &mut raw::TEEC_Operation) -> (u32, u32) {
        self.calls.push(InvokeCall {
            cmd_id,
            param_types: op.paramTypes,
        });
        let mut resp = self
            .responses
            .pop_front()
            .unwrap_or_else(|| panic!("MockTeec: unexpected invoke for cmd_id=0x{cmd_id:04x}"));
        if let Some(expected) = resp.expected_cmd_id {
            assert_eq!(
                cmd_id, expected,
                "MockTeec: expected cmd_id=0x{expected:04x}, got 0x{cmd_id:04x}"
            );
        }
        (resp.mutate)(op);
        (resp.rc, resp.origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    fn zeroed_op() -> raw::TEEC_Operation {
        unsafe { mem::zeroed() }
    }

    #[test]
    fn records_cmd_ids_in_order() {
        let mut mock = MockTeec::new();
        mock.queue_biz(0x0004, 0x900D)
            .queue_biz(0x0007, 0x900D);

        let mut op = zeroed_op();
        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_MEMREF_TEMP_OUTPUT,
            raw::TEEC_VALUE_OUTPUT,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
        );
        assert_eq!(mock.invoke(0x0004, &mut op), (raw::TEEC_SUCCESS, 0));

        let mut op2 = zeroed_op();
        assert_eq!(mock.invoke(0x0007, &mut op2), (raw::TEEC_SUCCESS, 0));

        assert_eq!(mock.calls.len(), 2);
        assert_eq!(mock.calls[0].cmd_id, 0x0004);
        assert_eq!(mock.calls[1].cmd_id, 0x0007);
    }

    #[test]
    fn queue_biz_writes_biz_code_to_value_a() {
        let mut mock = MockTeec::new();
        mock.queue_biz(0x0002, 0x900D);
        let mut op = zeroed_op();
        let _ = mock.invoke(0x0002, &mut op);
        let biz = unsafe { op.params[1].value.a };
        assert_eq!(biz, 0x900D);
    }

    #[test]
    fn queue_blob_writes_bytes_and_biz() {
        let mut mock = MockTeec::new();
        let blob = b"[0,1,2]".to_vec();
        mock.queue_blob_and_biz(0x0004, 0x900D, blob.clone());

        let mut buf = vec![0u8; 4096];
        let mut op = zeroed_op();
        op.params[0].tmpref.buffer = buf.as_mut_ptr() as *mut _;
        op.params[0].tmpref.size = buf.len();
        let _ = mock.invoke(0x0004, &mut op);

        let filled = unsafe { op.params[0].tmpref.size };
        assert_eq!(filled, blob.len());
        assert_eq!(&buf[..filled], blob.as_slice());
        let biz = unsafe { op.params[1].value.a };
        assert_eq!(biz, 0x900D);
    }

    #[test]
    #[should_panic(expected = "expected cmd_id=0x0004")]
    fn cmd_id_mismatch_panics() {
        let mut mock = MockTeec::new();
        mock.queue_biz(0x0004, 0x900D);
        let mut op = zeroed_op();
        let _ = mock.invoke(0x0002, &mut op);
    }

    #[test]
    #[should_panic(expected = "unexpected invoke")]
    fn unexpected_invoke_panics() {
        let mut mock = MockTeec::new();
        let mut op = zeroed_op();
        let _ = mock.invoke(0x0004, &mut op);
    }

    #[test]
    fn queue_rc_passes_through_error_code() {
        let mut mock = MockTeec::new();
        mock.queue_rc(0x0001, 0xFFFF0001, 3);
        let mut op = zeroed_op();
        let (rc, origin) = mock.invoke(0x0001, &mut op);
        assert_eq!(rc, 0xFFFF0001);
        assert_eq!(origin, 3);
    }

    #[test]
    fn param_types_captured_before_mutate_runs() {
        let mut mock = MockTeec::new();
        mock.queue_biz(0x0003, 0x900D);

        let expected_types = raw::TEEC_PARAM_TYPES(
            raw::TEEC_VALUE_INPUT,
            raw::TEEC_VALUE_OUTPUT,
            raw::TEEC_NONE,
            raw::TEEC_NONE,
        );
        let mut op = zeroed_op();
        op.paramTypes = expected_types;
        let _ = mock.invoke(0x0003, &mut op);

        assert_eq!(mock.calls[0].param_types, expected_types);
    }
}
