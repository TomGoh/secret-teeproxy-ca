//! TEEC invoke gateway trait + production/mock implementations.
//!
//! # Why a trait?
//!
//! Every call into the TA goes through `TEEC_InvokeCommand(session, cmd_id,
//! &mut op, &mut origin)`. Before Step 5 these calls were scattered directly
//! across `main.rs` and `serve.rs`, making it impossible to unit-test the
//! parameter marshalling: a wrong `params[i]` slot or bad `paramTypes` would
//! only surface on a real TEE device as a silent TA failure.
//!
//! The trait gives each call-site a seam:
//!
//! - [`RealTeec`] holds a live `TEEC_Context + TEEC_Session` pair. `invoke()`
//!   forwards to `TEEC_InvokeCommand`; `Drop` closes both handles in the
//!   same order as the pre-refactor cleanup (session first, then context).
//! - [`mock::MockTeec`] (test-only, gated on `#[cfg(any(test,
//!   feature="test-support"))]`) records every invocation and runs a
//!   scripted mutator on the `TEEC_Operation` so tests can simulate the
//!   TA's responses.
//!
//! # What the trait does **not** do
//!
//! It is intentionally a thin wrapper over the C function. Callers still
//! build `TEEC_Operation` structs themselves (set `paramTypes`, fill
//! `params[i].tmpref` / `params[i].value`). That is on purpose — wrapping
//! the `TEEC_Parameter` union would force every call site through a new
//! typed API with no real safety win (the C layout is already `#[repr(C)]`
//! and the marshalling is exactly what we want to keep visible for review).
//!
//! Instead, tests verify the marshalling by inspecting `InvokeCall`
//! records produced by `MockTeec`. See `teec::mock::tests` and the
//! param-layout tests in `main.rs` for examples.

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
