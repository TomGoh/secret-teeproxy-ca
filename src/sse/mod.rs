//! Server-Sent Events (SSE) helpers — pure parser + response-header encoder.
//!
//! - [`parser`] — extract Anthropic-format events (`data: {...}` lines)
//!   from a byte buffer. Pure: no I/O, no logging. The relay adapter
//!   calls [`parser::parse_events`] + [`parser::log_event`] to surface
//!   the LLM's words in the daemon log.
//! - [`encoder`] — build the fixed SSE response preamble (status +
//!   `Content-Type: text/event-stream` + `Cache-Control: no-cache` +
//!   `Connection: close`). Called from `relay::session` on the first
//!   `BIZ_RELAY_STREAMING` chunk.
//!
//! # Deliberately NOT here: outgoing SSE event framing
//!
//! The CA forwards upstream SSE bytes to openclaw verbatim — no chunk
//! reframing, no `Transfer-Encoding: chunked` on the outgoing
//! response (the connection lives until TCP close marks the stream
//! end). `chunk_frame` / `finalizer_frame` helpers would be dead code.
//! Add them only if the relay state machine starts synthesizing SSE
//! events (e.g. wrapping a short `BIZ_RELAY_DONE` as a single frame).

pub mod encoder;
pub mod parser;
