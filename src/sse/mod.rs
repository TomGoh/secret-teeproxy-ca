//! Server-Sent Events (SSE) helpers — pure parser + response-header encoder.
//!
//! # Scope after Step 6
//!
//! - [`parser`] — extract Anthropic-format events (`data: {...}` lines)
//!   from a byte buffer. Pure: no I/O, no logging. `serve.rs::log_sse_content`
//!   is now a thin wrapper that calls [`parser::parse_events`] and logs
//!   each resulting [`parser::SseEvent`].
//! - [`encoder`] — build the fixed SSE response preamble (status + headers).
//!   Used at the one call site in `serve::relay_and_stream` where we
//!   transition from streaming-CMD to client HTTP response.
//!
//! # What this module deliberately does **not** do
//!
//! The pre-refactor CA forwards upstream SSE bytes to the openclaw client
//! verbatim — no chunk reframing, no Transfer-Encoding: chunked on the
//! outgoing response (connection lives until EOF marks the stream end).
//! The refactor plan mentioned `chunk_frame` / `finalizer_frame`
//! helpers, but the production path never composes its own SSE events —
//! they come pre-formatted from the TA's decrypted upstream stream.
//! Adding those helpers here would be dead code. They will reappear in
//! Step 7a if the pure state-machine design needs to synthesize events
//! (e.g. wrapping a short BIZ_RELAY_DONE response into a single SSE
//! event); until then the scope stays minimal.

pub mod encoder;
pub mod parser;
