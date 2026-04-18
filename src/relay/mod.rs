//! TEEC relay loop — split into a pure state machine + I/O adapter.
//!
//! The relay path interleaves three independently-complicated
//! concerns: TA invocations, upstream TCP I/O, and client HTTP/SSE
//! writes, all driven by a stateful dispatch on `BIZ_RELAY_*` codes.
//! Historically this was one 265-line `loop { }` that was the single
//! most bug-prone piece of code in the CA. The module split here:
//!
//! - [`core`]    — pure state machine: given a TA `RelayTaOutput`,
//!                 emit a list of `RelayEvent`s and a `RelayNext`
//!                 action. No I/O, no `TcpStream`, no `TEEC_*`.
//! - [`session`] — adapter: upstream [`Upstream`] + [`Teec`] + HTTP
//!                 client writer glued to the state machine. All the
//!                 actual side effects live here.
//! - [`upstream`] — `trait Upstream` + `TcpUpstream` production impl
//!                  + `MockUpstream` (feature="test-support") for
//!                  scripting byte traces in tests.

pub mod core;
pub mod session;
pub mod upstream;
