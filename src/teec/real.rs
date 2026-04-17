//! Production [`Teec`] impl backed by a live GP TEE session.
//!
//! Replaces the ad-hoc `TEEC_InitializeContext + TEEC_OpenSession` dance
//! that previously ran in two places (`main.rs::run`, `serve::cmd_serve`).
//! After Step 5, both call sites construct one [`RealTeec`] and hand it
//! down by `&mut dyn Teec` to the command handlers.
//!
//! # Cleanup ordering
//!
//! The pre-refactor code at `main.rs:288-289` and `serve.rs:159-160` always
//! called `TEEC_CloseSession(&mut session)` **before**
//! `TEEC_FinalizeContext(&mut ctx)`. `Drop` preserves that exact order —
//! finalizing the context while a session is still open is an ABI error
//! on several TEE implementations.
//!
//! # Pointer stability (critical)
//!
//! `TEEC_OpenSession(ctx_ptr, session_ptr, ...)` stores `ctx_ptr` into
//! `session.imp.ctx` so subsequent `TEEC_InvokeCommand` calls can
//! re-locate the context via the session handle. If the storage backing
//! `ctx` ever moves after `TEEC_OpenSession` returns, that stored pointer
//! dangles and every invoke fails with `0xFFFF0000` (TEEC_ERROR_GENERIC,
//! origin TEEC_ORIGIN_API).
//!
//! In the pre-refactor code this was accidentally safe: `ctx` was a
//! stack local in the same function that ran the invoke calls, so its
//! address stayed fixed for the function's lifetime.
//!
//! After Step 5, `open()` returns `Self { ctx, session, .. }` by value;
//! the return move would relocate a stack-backed `ctx`, dangling the
//! pointer stored in `session.imp.ctx`. We store `ctx` in a `Box` so
//! its address is heap-allocated and stable across moves of `Self`.
//! The `Box` pointer is what we pass to TEEC_OpenSession, and any later
//! move of `Self` only shuffles the `Box`'s three-word envelope — the
//! heap storage stays put.

use std::mem;

use cc_teec::{
    TEEC_CloseSession, TEEC_FinalizeContext, TEEC_InitializeContext, TEEC_InvokeCommand,
    TEEC_OpenSession, raw,
};
use uuid::Uuid;

use super::Teec;

/// Owns a live `TEEC_Context` + `TEEC_Session`. Construct with
/// [`RealTeec::open`]; drop to release.
///
/// The struct is `!Send + !Sync` by virtue of containing raw pointers
/// inside `TEEC_Session__Imp.ctx`. That is fine for serve-mode (single
/// thread accepts connections and dispatches synchronously) and matches
/// the pre-refactor invariant that the TEEC session handle was never
/// shared across threads.
pub struct RealTeec {
    /// Heap-allocated so its address is stable across moves of `Self`.
    /// `TEEC_OpenSession` stores a raw pointer to this into
    /// `session.imp.ctx`; any move that invalidated that pointer would
    /// cascade into 0xFFFF0000 invoke failures.
    ctx: Box<raw::TEEC_Context>,
    session: raw::TEEC_Session,
}

impl RealTeec {
    /// Initialize a TEE context and open a session to the TA identified
    /// by `ta_uuid_str` (RFC 4122 form, e.g.
    /// `"a3f79c15-72d0-4e3a-b8d1-9f2ca3e81054"`).
    ///
    /// On open failure, the partially-initialized context is finalized
    /// before the error is returned — no resource leak.
    pub fn open(ta_uuid_str: &str) -> Result<Self, String> {
        let ta_uuid = parse_uuid(ta_uuid_str)?;

        // Box the context first so its heap address is pinned before
        // TEEC_OpenSession stores a pointer to it into session.imp.ctx.
        let mut ctx: Box<raw::TEEC_Context> = Box::new(unsafe { mem::zeroed() });
        let mut session: raw::TEEC_Session = unsafe { mem::zeroed() };

        let rc = TEEC_InitializeContext(std::ptr::null(), ctx.as_mut());
        if rc != raw::TEEC_SUCCESS {
            return Err(format!("TEEC_InitializeContext failed: 0x{rc:08x}"));
        }

        let mut origin = 0u32;
        let rc = TEEC_OpenSession(
            ctx.as_mut(),
            &mut session,
            &ta_uuid,
            raw::TEEC_LOGIN_PUBLIC,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut origin,
        );
        if rc != raw::TEEC_SUCCESS {
            TEEC_FinalizeContext(ctx.as_mut());
            return Err(format!(
                "TEEC_OpenSession failed: 0x{rc:08x}, origin={origin}"
            ));
        }

        Ok(Self { ctx, session })
    }
}

impl Teec for RealTeec {
    fn invoke(&mut self, cmd_id: u32, op: &mut raw::TEEC_Operation) -> (u32, u32) {
        let mut origin = 0u32;
        let rc = TEEC_InvokeCommand(&mut self.session, cmd_id, op, &mut origin);
        (rc, origin)
    }
}

impl Drop for RealTeec {
    fn drop(&mut self) {
        // Session first, context second — see module docs.
        TEEC_CloseSession(&mut self.session);
        TEEC_FinalizeContext(self.ctx.as_mut());
    }
}

/// Parse an RFC 4122 UUID string into the wire form expected by libteec.
///
/// Moved from `main.rs::parse_uuid` in Step 5. The previous function was
/// `pub(crate)` and called from two places (`main.rs::run`,
/// `serve::cmd_serve`), both of which now go through [`RealTeec::open`].
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_accepts_rfc4122_form() {
        let uuid = parse_uuid("a3f79c15-72d0-4e3a-b8d1-9f2ca3e81054")
            .expect("valid UUID must parse");
        assert_eq!(uuid.timeLow, 0xa3f79c15);
        assert_eq!(uuid.timeMid, 0x72d0);
        assert_eq!(uuid.timeHiAndVersion, 0x4e3a);
        assert_eq!(uuid.clockSeqAndNode, [0xb8, 0xd1, 0x9f, 0x2c, 0xa3, 0xe8, 0x10, 0x54]);
    }

    #[test]
    fn parse_uuid_rejects_malformed_string() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid("a3f79c15").is_err());
    }

    #[test]
    fn parse_uuid_matches_crate_constant() {
        // Regression test: the constant must stay in sync with the TA.
        let parsed = parse_uuid(crate::constants::TA_UUID).expect("TA_UUID must parse");
        assert_eq!(parsed.timeLow, 0xa3f79c15);
    }
}
