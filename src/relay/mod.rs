//! TEEC relay-loop core + adapters.
//!
//! The `relay_and_stream` function in `serve.rs` (269 LOC before this
//! step) is the most bug-prone part of the CA: it interleaves TA
//! invocations, upstream TCP I/O, client HTTP writes, and a stateful
//! dispatch on `BIZ_RELAY_*` codes. Step 7a extracts just the dispatch
//! as a pure state machine in [`core`]; Step 7b will wire the adapter
//! side (upstream TCP + client writes + TA invoke gateway) around it.
//!
//! After Step 7a the serve.rs loop is unchanged — the module exists
//! but is not yet called from production code. This is deliberate:
//! the pure core is large and its test matrix is the only thing
//! standing between Step 7b and a streaming regression, so it lands
//! as a reviewable unit first, with the inline loop as the reference
//! implementation to diff against.
//!
//! See the Step 7a section of `docs/…` and the per-step git commits
//! for the migration trajectory.

pub mod core;
