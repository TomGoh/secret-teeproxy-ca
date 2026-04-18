//! TEEC invoke gateway trait + production/mock implementations.
//!
//! # Why a trait?
//!
//! Every call into the TA goes through
//! `TEEC_InvokeCommand(session, cmd_id, &mut op, &mut origin)`. The
//! trait gives each call-site an injectable seam so the marshalling
//! (wrong `params[i]` slot, wrong `paramTypes` bits, off-by-one in
//! output buffer size) can be unit-tested without a real TEE device.
//! A wrong layout on the real TA silently fails — the mock lets us
//! catch it bit-exactly.
//!
//! Implementations:
//! - [`RealTeec`] — holds a live `TEEC_Context + TEEC_Session`; `Drop`
//!   closes both handles in the close-session-before-finalize-context
//!   order the GP TEE spec requires.
//! - [`mock::MockTeec`] (test-only, gated on
//!   `#[cfg(any(test, feature="test-support"))]`) — records every
//!   invocation and runs a scripted mutator on the `TEEC_Operation`
//!   so tests can simulate the TA's responses.
//!
//! # What the trait does NOT do
//!
//! It is intentionally a thin wrapper over the C function. Callers
//! still build `TEEC_Operation` structs themselves (set `paramTypes`,
//! fill `params[i].tmpref` / `params[i].value`). Wrapping the
//! `TEEC_Parameter` union would force every call site through a typed
//! API with no real safety win — the C layout is already `#[repr(C)]`
//! and the marshalling is exactly what we want visible for review.
//!
//! Tests verify marshalling by inspecting `InvokeCall` records from
//! `MockTeec`. See [`ops::tests`](crate::teec::ops) for examples.

pub mod ops;
pub mod real;

#[cfg(any(test, feature = "test-support"))]
pub mod mock;

use cc_teec::raw;

pub use real::RealTeec;

/// Abstract gateway for `TEEC_InvokeCommand`.
///
/// Implementations own (or simulate owning) a TEE session. The caller
/// builds the `TEEC_Operation` in place and hands it in by `&mut`; the
/// impl may mutate `op.params[]` to reflect TA outputs.
///
/// Returns `(rc, origin)` matching the two outputs of `TEEC_InvokeCommand`:
/// the TEEC return code and the error-origin indicator.
pub trait Teec {
    fn invoke(&mut self, cmd_id: u32, op: &mut raw::TEEC_Operation) -> (u32, u32);
}
