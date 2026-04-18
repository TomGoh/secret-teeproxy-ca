//! Pure state machine for the TEEC relay loop.
//!
//! # Why pure
//!
//! The relay dispatch — "TA gave me a `BIZ_RELAY_*` response, what
//! bytes do I write where?" — used to live inside a 265-line `loop { }`
//! interleaved with TA invocations, upstream TCP I/O, and client HTTP
//! writes. Bugs historically clustered in the match arms: missed edge
//! cases, wrong flag ordering, off-by-one in chunked-decode integration.
//! Extracting the dispatch as a pure function lets each biz_code
//! transition be tested individually with hand-crafted
//! [`RelayTaOutput`] + [`RelayState`] pairs.
//!
//! # What this module is NOT
//!
//! - Not a TA client. `teec.invoke` lives in [`crate::relay::session`].
//! - Not a TCP server. Upstream + client I/O live in `relay::session`.
//! - Not responsible for the upstream-EOF double-detection
//!   (`saw_eof → return Err("server closed before relay completed")`).
//!   That is upstream-read loop state owned by `relay::session`.
//!
//! # Wire-behavior invariants (DO NOT break these without a pytest run)
//!
//! 1. **Pump semantics**: BIZ_RELAY_CONTINUE with empty `decrypted`
//!    triggers exactly ONE extra TA invoke with empty input. If that
//!    second invoke is also empty, fall through to the next upstream
//!    read — do **not** cascade pumps. Cascading deadlocks when
//!    rustls genuinely has nothing to send.
//! 2. **Streaming preamble exactly once**: `StartStreamingResponse`
//!    fires on the first `BIZ_RELAY_STREAMING`, not on subsequent ones.
//! 3. **BIZ_RELAY_DONE short-response path**: if the TA completes the
//!    whole request in one round (never emitted `BIZ_RELAY_STREAMING`)
//!    the decrypted bytes are a `ProxyResponse` JSON and the caller
//!    sends a plain HTTP response, not an SSE stream. `Content-Type`
//!    passes through from the upstream headers verbatim.
//! 4. **Unknown biz_code error string** is exactly
//!    `"relay error: 0x{biz:04x}"` — pytest greps on it; do not reword.
//! 5. **Chunked decoder state** is carried across `step()` calls via
//!    `RelayState`; partial chunks that span TA roundtrips must be
//!    buffered in the decoder, not in the caller.
//!
//! # Testing
//!
//! See the `tests` module at the bottom. Every biz_code branch + each
//! pump phase + each error path has at least one test, plus a handful
//! of "realistic trace" tests that drive a CONTINUE→PUMP→STREAMING→DONE
//! sequence representing a full relay round.

use crate::constants::{
    BIZ_RELAY_CONTINUE, BIZ_RELAY_DONE, BIZ_RELAY_STREAMING, BIZ_RELAY_START,
};
use crate::http::chunked::ChunkedDecoder;

/// One TA CMD_RELAY_DATA response, decoupled from the FFI-level
/// `TEEC_Operation`. The adapter constructs this from the op's
/// `params[1].value.a` (biz_code), `params[2].tmpref` (decrypted),
/// `params[3].tmpref` (tls_extra).
///
/// Borrows slices so the adapter doesn't have to copy buffers — the
/// state machine reads and, when it needs to keep a byte, copies to
/// a `Vec` in the emitted event.
#[derive(Debug, Clone, Copy)]
pub struct RelayTaOutput<'a> {
    pub biz_code: u32,
    pub decrypted: &'a [u8],
    pub tls_extra: &'a [u8],
}

/// One side-effect instruction for the adapter to perform. The ordering
/// of events within a `RelayOutcome.events` vec is significant —
/// adapters must execute them in sequence or the TLS handshake / SSE
/// flush semantics break.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayEvent {
    /// Write these bytes to the upstream TCP socket. Used for both TLS
    /// handshake continuation and post-streaming TLS acks / close_notify.
    ToUpstream(Vec<u8>),

    /// First streaming chunk from the TA arrived. Write the SSE
    /// response preamble (status line + fixed headers) to the client;
    /// subsequent `ClientBody` events follow.
    ///
    /// `upstream_status` is the HTTP status code the CA parsed from
    /// the upstream response's first line (e.g. 200, 429). It is NOT
    /// necessarily 200 — if the upstream returned an error status,
    /// we forward it so openclaw can react correctly.
    StartStreamingResponse { upstream_status: u16 },

    /// Write these decoded body bytes to the client. For non-chunked
    /// upstreams this is the raw decrypted body slice; for chunked
    /// upstreams this is the output of [`ChunkedDecoder::feed`].
    ClientBody(Vec<u8>),

    /// Flush the client TCP stream. Paired with every `ClientBody` emit
    /// so SSE events push without buffering. (TCP_NODELAY helps, but
    /// the adapter still wants to call `flush()` as a belt-and-braces
    /// measure.)
    FlushClient,

    /// BIZ_RELAY_DONE short-response path: the TA finished in one round
    /// and handed back a `ProxyResponse` JSON. Adapter writes a single
    /// non-streaming HTTP response with the given status + headers + body.
    ///
    /// `content_type` is taken from `ProxyResponse.headers["content-type"]`
    /// if present, else defaults to `"application/json"`.
    ClientFullResponse {
        status: u16,
        content_type: String,
        body: Vec<u8>,
    },
}

/// After processing this TA output, what should the adapter do next?
#[derive(Debug, PartialEq, Eq)]
pub enum RelayNext {
    /// Back to the top of the upstream-read loop.
    ReadUpstream,
    /// Call the TA again with empty input, feed the result back into
    /// `step()`. This is emitted at most once per upstream round — if
    /// the pump itself yields another empty CONTINUE, `step()` switches
    /// to `ReadUpstream` rather than cascading.
    PumpTa,
    /// Relay finished cleanly. Adapter flushes and returns Ok.
    Done,
    /// Relay failed. The `String` is the error message; adapter should
    /// `send_error(502, msg)` if `response_started == false`, and in
    /// any case propagate the error to its caller.
    Error(String),
}

/// What one `step()` call produced.
#[derive(Debug, PartialEq, Eq)]
pub struct RelayOutcome {
    pub events: Vec<RelayEvent>,
    pub next: RelayNext,
}

/// Carry-over state between `step()` calls within a single relay session.
///
/// Fields are `pub` (as opposed to encapsulated) because tests in this
/// module construct states with specific mid-stream configurations
/// (e.g. "we've already started the client response, now here comes
/// the next streaming chunk"); hiding the fields would force each test
/// through a dance of synthetic early `step()` calls.
///
/// Adapters should treat the fields as opaque and construct a fresh
/// state with `new()` per session.
pub struct RelayState {
    pub response_started: bool,
    pub upstream_is_chunked: bool,
    pub chunked_decoder: ChunkedDecoder,
    /// Set to `true` when the prior `step()` returned `PumpTa`. The
    /// next `step()` consumes this flag; if the pump response is still
    /// an empty CONTINUE, the state machine falls through to
    /// `ReadUpstream` (no double-pump).
    pub waiting_for_pump: bool,
}

impl Default for RelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayState {
    pub fn new() -> Self {
        Self {
            response_started: false,
            upstream_is_chunked: false,
            chunked_decoder: ChunkedDecoder::new(),
            waiting_for_pump: false,
        }
    }
}

/// Core state-machine step. Consumes one `RelayTaOutput`, mutates
/// `state`, returns the events the adapter should execute and the
/// next action. Deterministic: repeated calls with the same inputs
/// yield the same outputs modulo `ChunkedDecoder` internal state.
pub fn step(ta: RelayTaOutput<'_>, state: &mut RelayState) -> RelayOutcome {
    // Take and clear the pump flag atomically: if this step IS a pump
    // response, `was_pump_response == true`, and we must not re-emit
    // PumpTa on an empty CONTINUE.
    let was_pump_response = std::mem::take(&mut state.waiting_for_pump);

    match ta.biz_code {
        BIZ_RELAY_CONTINUE => step_continue(ta, state, was_pump_response),
        BIZ_RELAY_STREAMING => step_streaming(ta, state),
        BIZ_RELAY_DONE => step_done(ta, state),
        // BIZ_RELAY_START is handled before the relay loop begins (by
        // handle_proxy_post's CMD_PROXY_REQUEST dispatch); seeing it
        // here mid-stream is a protocol error.
        BIZ_RELAY_START => RelayOutcome {
            events: vec![],
            next: RelayNext::Error(format!("relay error: 0x{:04x}", ta.biz_code)),
        },
        _ => RelayOutcome {
            events: vec![],
            next: RelayNext::Error(format!("relay error: 0x{:04x}", ta.biz_code)),
        },
    }
}

fn step_continue(
    ta: RelayTaOutput<'_>,
    state: &mut RelayState,
    was_pump_response: bool,
) -> RelayOutcome {
    if !ta.decrypted.is_empty() {
        // TLS handshake bytes — send to upstream regardless of pump status.
        return RelayOutcome {
            events: vec![RelayEvent::ToUpstream(ta.decrypted.to_vec())],
            next: RelayNext::ReadUpstream,
        };
    }
    // `decrypted` is empty.
    if was_pump_response {
        // Pumped and still empty — give up pumping this round and
        // go read more upstream bytes.
        RelayOutcome {
            events: vec![],
            next: RelayNext::ReadUpstream,
        }
    } else {
        // First empty CONTINUE — pump the TA once with empty input.
        state.waiting_for_pump = true;
        RelayOutcome {
            events: vec![],
            next: RelayNext::PumpTa,
        }
    }
}

fn step_streaming(ta: RelayTaOutput<'_>, state: &mut RelayState) -> RelayOutcome {
    let mut events = Vec::new();
    if !state.response_started {
        // First streaming chunk: decrypted bytes contain the upstream
        // response's HTTP status line + headers + CRLF + start-of-body.
        // Parse the status and split the body off the headers.
        let (upstream_status, body_start) = parse_upstream_headers(ta.decrypted);

        // Detect `Transfer-Encoding: chunked` from the parsed headers.
        let header_slice_end = body_start.saturating_sub(4).min(ta.decrypted.len());
        let header_bytes = &ta.decrypted[..header_slice_end];
        if let Ok(hdr_str) = std::str::from_utf8(header_bytes) {
            for line in hdr_str.lines() {
                let lower = line.to_lowercase();
                if lower.contains("transfer-encoding") && lower.contains("chunked") {
                    state.upstream_is_chunked = true;
                    break;
                }
            }
        }

        events.push(RelayEvent::StartStreamingResponse { upstream_status });
        state.response_started = true;

        // Emit the initial body, if the first chunk already contains any.
        if body_start < ta.decrypted.len() {
            let body_slice = &ta.decrypted[body_start..];
            let decoded = if state.upstream_is_chunked {
                state.chunked_decoder.feed(body_slice)
            } else {
                body_slice.to_vec()
            };
            if !decoded.is_empty() {
                events.push(RelayEvent::ClientBody(decoded));
            }
            events.push(RelayEvent::FlushClient);
        }
    } else {
        // Subsequent streaming chunk: just SSE body bytes.
        let decoded = if state.upstream_is_chunked {
            state.chunked_decoder.feed(ta.decrypted)
        } else {
            ta.decrypted.to_vec()
        };
        if !decoded.is_empty() {
            events.push(RelayEvent::ClientBody(decoded));
        }
        events.push(RelayEvent::FlushClient);
    }

    // Any tls_extra (post-decrypt TLS ack, rekey, etc.) goes back upstream.
    if !ta.tls_extra.is_empty() {
        events.push(RelayEvent::ToUpstream(ta.tls_extra.to_vec()));
    }

    RelayOutcome {
        events,
        next: RelayNext::ReadUpstream,
    }
}

fn step_done(ta: RelayTaOutput<'_>, state: &mut RelayState) -> RelayOutcome {
    let mut events = Vec::new();

    // Final TLS bytes (close_notify, etc.) — best-effort; the upstream
    // may already have EOF'd but the adapter sends them anyway.
    if !ta.tls_extra.is_empty() {
        events.push(RelayEvent::ToUpstream(ta.tls_extra.to_vec()));
    }

    if !state.response_started && !ta.decrypted.is_empty() {
        // Short-response path: the TA completed the whole HTTP round
        // trip in one go and returned a ProxyResponse JSON.
        match serde_json::from_slice::<crate::ProxyResponse>(ta.decrypted) {
            Ok(resp) => {
                let content_type = resp
                    .headers
                    .get("content-type")
                    .cloned()
                    .unwrap_or_else(|| "application/json".to_string());
                events.push(RelayEvent::ClientFullResponse {
                    status: resp.status,
                    content_type,
                    body: resp.body,
                });
            }
            Err(e) => {
                return RelayOutcome {
                    events: vec![],
                    next: RelayNext::Error(format!("parse ProxyResponse: {e}")),
                };
            }
        }
    }

    events.push(RelayEvent::FlushClient);

    RelayOutcome {
        events,
        next: RelayNext::Done,
    }
}

/// Parse `HTTP/1.1 {status} {text}\r\n...\r\n\r\n{body}` from the
/// first streaming chunk. Returns `(status_code, byte_offset_of_body)`.
/// Falls back to 200 when the status line is malformed, and to
/// `data.len()` (empty body slice) when there's no `\r\n\r\n` yet —
/// both behaviors are pytest-pinned in `format/test_proxy_format.py`.
fn parse_upstream_headers(data: &[u8]) -> (u16, usize) {
    let boundary = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(data.len());

    let header_str = String::from_utf8_lossy(&data[..boundary]);
    let status = header_str
        .lines()
        .next()
        .and_then(|line| {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                parts[1].parse::<u16>().ok()
            } else {
                None
            }
        })
        .unwrap_or(200);

    let body_start = if boundary + 4 <= data.len() {
        boundary + 4
    } else {
        data.len()
    };

    (status, body_start)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Helpers ---------------------------------------------------
    fn ta<'a>(biz: u32, dec: &'a [u8], tls: &'a [u8]) -> RelayTaOutput<'a> {
        RelayTaOutput {
            biz_code: biz,
            decrypted: dec,
            tls_extra: tls,
        }
    }

    // ----- BIZ_RELAY_CONTINUE ----------------------------------------
    #[test]
    fn continue_with_handshake_bytes_emits_to_upstream() {
        let mut state = RelayState::new();
        let out = step(ta(BIZ_RELAY_CONTINUE, b"TLSHELLO", b""), &mut state);
        assert_eq!(
            out.events,
            vec![RelayEvent::ToUpstream(b"TLSHELLO".to_vec())]
        );
        assert_eq!(out.next, RelayNext::ReadUpstream);
        assert!(!state.waiting_for_pump);
    }

    #[test]
    fn continue_empty_first_time_emits_pump() {
        let mut state = RelayState::new();
        let out = step(ta(BIZ_RELAY_CONTINUE, b"", b""), &mut state);
        assert_eq!(out.events, vec![]);
        assert_eq!(out.next, RelayNext::PumpTa);
        assert!(
            state.waiting_for_pump,
            "state must remember we asked for a pump"
        );
    }

    #[test]
    fn continue_empty_after_pump_falls_through_to_read_upstream() {
        // Setup: pretend we just asked for a pump.
        let mut state = RelayState::new();
        state.waiting_for_pump = true;

        // Pump response is also empty CONTINUE — must NOT cascade.
        let out = step(ta(BIZ_RELAY_CONTINUE, b"", b""), &mut state);
        assert_eq!(out.events, vec![]);
        assert_eq!(out.next, RelayNext::ReadUpstream);
        assert!(
            !state.waiting_for_pump,
            "pump flag must clear after consumption"
        );
    }

    #[test]
    fn continue_pump_response_with_bytes_emits_to_upstream() {
        let mut state = RelayState::new();
        state.waiting_for_pump = true;
        let out = step(ta(BIZ_RELAY_CONTINUE, b"POSTPUMP", b""), &mut state);
        assert_eq!(
            out.events,
            vec![RelayEvent::ToUpstream(b"POSTPUMP".to_vec())]
        );
        assert_eq!(out.next, RelayNext::ReadUpstream);
        assert!(!state.waiting_for_pump);
    }

    // ----- BIZ_RELAY_STREAMING (first chunk) -------------------------
    #[test]
    fn streaming_first_chunk_parses_200_and_emits_preamble() {
        let payload = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: text/event-stream\r\n\
                        Cache-Control: no-cache\r\n\
                        \r\n\
                        data: {\"type\":\"message_start\"}\n\n";
        let mut state = RelayState::new();
        let out = step(ta(BIZ_RELAY_STREAMING, payload, b""), &mut state);

        // First event must be StartStreamingResponse{200}.
        assert_eq!(out.events[0], RelayEvent::StartStreamingResponse { upstream_status: 200 });
        // Then the initial body bytes (everything after \r\n\r\n).
        let body_start = payload.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(
            out.events[1],
            RelayEvent::ClientBody(payload[body_start..].to_vec())
        );
        // Finally a flush so the SSE first event reaches openclaw.
        assert_eq!(out.events[2], RelayEvent::FlushClient);
        assert_eq!(out.next, RelayNext::ReadUpstream);
        assert!(state.response_started);
        assert!(!state.upstream_is_chunked);
    }

    #[test]
    fn streaming_first_chunk_preserves_upstream_429_status() {
        // If the upstream rate-limits us, openclaw should see a 429,
        // not a falsified 200. Regression for the Anthropic SDK path.
        let payload = b"HTTP/1.1 429 Too Many Requests\r\n\r\n";
        let mut state = RelayState::new();
        let out = step(ta(BIZ_RELAY_STREAMING, payload, b""), &mut state);
        assert_eq!(
            out.events[0],
            RelayEvent::StartStreamingResponse { upstream_status: 429 }
        );
    }

    #[test]
    fn streaming_first_chunk_detects_transfer_encoding_chunked() {
        let payload = b"HTTP/1.1 200 OK\r\n\
                        Transfer-Encoding: chunked\r\n\
                        \r\n";
        let mut state = RelayState::new();
        step(ta(BIZ_RELAY_STREAMING, payload, b""), &mut state);
        assert!(
            state.upstream_is_chunked,
            "chunked upstream flag must flip on"
        );
    }

    #[test]
    fn streaming_first_chunk_case_insensitive_chunked_detection() {
        // Capital-T / capital-E variants still hit. Anthropic's edge
        // uses Title-Case; cloudfront sometimes lowercase. Both work.
        let payload = b"HTTP/1.1 200 OK\r\n\
                        transfer-encoding: Chunked\r\n\
                        \r\n";
        let mut state = RelayState::new();
        step(ta(BIZ_RELAY_STREAMING, payload, b""), &mut state);
        assert!(state.upstream_is_chunked);
    }

    #[test]
    fn streaming_first_chunk_without_te_chunked_stays_unchunked() {
        let payload = b"HTTP/1.1 200 OK\r\n\
                        Content-Type: text/event-stream\r\n\
                        \r\n";
        let mut state = RelayState::new();
        step(ta(BIZ_RELAY_STREAMING, payload, b""), &mut state);
        assert!(!state.upstream_is_chunked);
    }

    #[test]
    fn streaming_first_chunk_with_no_body_omits_clientbody_and_flush() {
        // Server sent only headers on the first round; body arrives later.
        let payload = b"HTTP/1.1 200 OK\r\n\r\n";
        let mut state = RelayState::new();
        let out = step(ta(BIZ_RELAY_STREAMING, payload, b""), &mut state);
        // Only the preamble — no body bytes to emit yet, and no flush.
        assert_eq!(out.events.len(), 1);
        assert!(matches!(
            out.events[0],
            RelayEvent::StartStreamingResponse { .. }
        ));
    }

    // ----- BIZ_RELAY_STREAMING (subsequent chunks) -------------------
    #[test]
    fn streaming_subsequent_chunk_emits_body_and_flush_only() {
        let mut state = RelayState::new();
        state.response_started = true;
        let out = step(ta(BIZ_RELAY_STREAMING, b"data: {\"x\":1}\n\n", b""), &mut state);
        assert_eq!(
            out.events[0],
            RelayEvent::ClientBody(b"data: {\"x\":1}\n\n".to_vec())
        );
        assert_eq!(out.events[1], RelayEvent::FlushClient);
        assert_eq!(out.next, RelayNext::ReadUpstream);
    }

    #[test]
    fn streaming_with_tls_extra_appends_to_upstream_event() {
        let mut state = RelayState::new();
        state.response_started = true;
        let out = step(
            ta(BIZ_RELAY_STREAMING, b"data: x\n\n", b"TLSACK"),
            &mut state,
        );
        // Body + flush + upstream ACK — in that order.
        assert_eq!(out.events.len(), 3);
        assert_eq!(out.events[0], RelayEvent::ClientBody(b"data: x\n\n".to_vec()));
        assert_eq!(out.events[1], RelayEvent::FlushClient);
        assert_eq!(out.events[2], RelayEvent::ToUpstream(b"TLSACK".to_vec()));
    }

    #[test]
    fn streaming_subsequent_with_chunked_decoder_decodes_across_calls() {
        // A chunk size line split across two TA rounds — exactly the
        // scenario the stateful `ChunkedDecoder` is designed for.
        let mut state = RelayState::new();
        state.response_started = true;
        state.upstream_is_chunked = true;

        // Round 1: "5\r\nHel" — size line + 3 of 5 body bytes.
        let out1 = step(ta(BIZ_RELAY_STREAMING, b"5\r\nHel", b""), &mut state);
        let round1_body = match &out1.events[0] {
            RelayEvent::ClientBody(b) => b.clone(),
            _ => panic!("expected ClientBody first"),
        };

        // Round 2: "lo\r\n0\r\n\r\n" — finish the chunk, then terminator.
        let out2 = step(ta(BIZ_RELAY_STREAMING, b"lo\r\n0\r\n\r\n", b""), &mut state);
        let round2_body = out2
            .events
            .iter()
            .filter_map(|e| {
                if let RelayEvent::ClientBody(b) = e {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_default();

        let combined: Vec<u8> = round1_body.iter().chain(round2_body.iter()).copied().collect();
        assert_eq!(
            combined,
            b"Hello".to_vec(),
            "chunked decoder must carry state across step() calls"
        );
    }

    // ----- BIZ_RELAY_DONE --------------------------------------------
    #[test]
    fn done_after_streaming_emits_flush_only() {
        let mut state = RelayState::new();
        state.response_started = true;
        let out = step(ta(BIZ_RELAY_DONE, b"", b""), &mut state);
        assert_eq!(out.events, vec![RelayEvent::FlushClient]);
        assert_eq!(out.next, RelayNext::Done);
    }

    #[test]
    fn done_with_final_tls_extra_emits_upstream_then_flush() {
        let mut state = RelayState::new();
        state.response_started = true;
        let out = step(ta(BIZ_RELAY_DONE, b"", b"CLOSE_NOTIFY"), &mut state);
        assert_eq!(
            out.events,
            vec![
                RelayEvent::ToUpstream(b"CLOSE_NOTIFY".to_vec()),
                RelayEvent::FlushClient,
            ]
        );
        assert_eq!(out.next, RelayNext::Done);
    }

    #[test]
    fn done_short_response_emits_full_http_response() {
        // Short-response path: no streaming happened, TA handed back
        // a ProxyResponse JSON. Should produce ONE ClientFullResponse.
        let body_bytes = b"{\"hello\":\"world\"}";
        let resp_json = format!(
            r#"{{"status":200,"headers":{{"content-type":"application/json"}},"body":{:?}}}"#,
            body_bytes.to_vec(),
        );
        let mut state = RelayState::new();
        let out = step(
            ta(BIZ_RELAY_DONE, resp_json.as_bytes(), b""),
            &mut state,
        );

        assert_eq!(out.next, RelayNext::Done);
        let full = out.events.iter().find_map(|e| {
            if let RelayEvent::ClientFullResponse { status, content_type, body } = e {
                Some((*status, content_type.clone(), body.clone()))
            } else {
                None
            }
        });
        let (status, ct, body) = full.expect("expected ClientFullResponse");
        assert_eq!(status, 200);
        assert_eq!(ct, "application/json");
        assert_eq!(body, body_bytes.to_vec());
    }

    #[test]
    fn done_short_response_missing_content_type_defaults_to_json() {
        let resp_json = r#"{"status":200,"headers":{},"body":[]}"#;
        let mut state = RelayState::new();
        let out = step(
            ta(BIZ_RELAY_DONE, resp_json.as_bytes(), b""),
            &mut state,
        );
        let ct = out.events.iter().find_map(|e| {
            if let RelayEvent::ClientFullResponse { content_type, .. } = e {
                Some(content_type.clone())
            } else {
                None
            }
        });
        assert_eq!(ct.as_deref(), Some("application/json"));
    }

    #[test]
    fn done_short_response_preserves_upstream_error_status() {
        // The TA might hand back a 401 unauthorized result in a single
        // round — openclaw must see 401, not a falsified 200.
        let resp_json = r#"{"status":401,"headers":{"content-type":"text/plain"},"body":[117,110,97,117,116,104]}"#;
        let mut state = RelayState::new();
        let out = step(
            ta(BIZ_RELAY_DONE, resp_json.as_bytes(), b""),
            &mut state,
        );
        let status = out.events.iter().find_map(|e| {
            if let RelayEvent::ClientFullResponse { status, .. } = e {
                Some(*status)
            } else {
                None
            }
        });
        assert_eq!(status, Some(401));
    }

    #[test]
    fn done_short_response_bad_json_emits_error() {
        let mut state = RelayState::new();
        let out = step(
            ta(BIZ_RELAY_DONE, b"not-json-at-all", b""),
            &mut state,
        );
        assert!(out.events.is_empty());
        match out.next {
            RelayNext::Error(msg) => assert!(msg.contains("parse ProxyResponse")),
            other => panic!("expected Error(parse ProxyResponse), got {other:?}"),
        }
    }

    #[test]
    fn done_after_streaming_ignores_decrypted_bytes() {
        // If the stream already started, we DO NOT re-parse decrypted
        // as a ProxyResponse — the short-response branch is guarded
        // by `!response_started`.
        let mut state = RelayState::new();
        state.response_started = true;
        let out = step(
            ta(BIZ_RELAY_DONE, b"{\"status\":200}", b""),
            &mut state,
        );
        // Only a flush; no ClientFullResponse, no Error.
        assert_eq!(out.events, vec![RelayEvent::FlushClient]);
        assert_eq!(out.next, RelayNext::Done);
    }

    // ----- Error paths -----------------------------------------------
    #[test]
    fn unknown_biz_code_yields_error_with_exact_pre_refactor_string() {
        // Pytest greps on this string; do not reword without updating tests.
        let mut state = RelayState::new();
        let out = step(ta(0xE006, b"", b""), &mut state);
        match out.next {
            RelayNext::Error(msg) => assert_eq!(msg, "relay error: 0xe006"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn mid_stream_relay_start_is_protocol_error() {
        // BIZ_RELAY_START should only appear from CMD_PROXY_REQUEST,
        // never from CMD_RELAY_DATA. If we see it here, it's a bug.
        let mut state = RelayState::new();
        let out = step(ta(BIZ_RELAY_START, b"", b""), &mut state);
        match out.next {
            RelayNext::Error(msg) => assert!(msg.starts_with("relay error: 0x")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    // ----- Realistic trace: streaming full relay ----------------------
    #[test]
    fn realistic_trace_streaming_sse() {
        // Simulates a typical Anthropic stream:
        //  1. CONTINUE with bytes (TLS handshake) → ToUpstream
        //  2. CONTINUE empty → PumpTa
        //  3. Pump CONTINUE with bytes → ToUpstream
        //  4. STREAMING first chunk → preamble + body + flush
        //  5. STREAMING next chunk → body + flush
        //  6. DONE → flush, Done
        let mut state = RelayState::new();

        // 1
        let o1 = step(ta(BIZ_RELAY_CONTINUE, b"HS1", b""), &mut state);
        assert_eq!(o1.next, RelayNext::ReadUpstream);
        assert_eq!(o1.events[0], RelayEvent::ToUpstream(b"HS1".to_vec()));

        // 2
        let o2 = step(ta(BIZ_RELAY_CONTINUE, b"", b""), &mut state);
        assert_eq!(o2.next, RelayNext::PumpTa);
        assert!(state.waiting_for_pump);

        // 3 (pump response)
        let o3 = step(ta(BIZ_RELAY_CONTINUE, b"HS2", b""), &mut state);
        assert_eq!(o3.next, RelayNext::ReadUpstream);
        assert_eq!(o3.events[0], RelayEvent::ToUpstream(b"HS2".to_vec()));
        assert!(!state.waiting_for_pump);

        // 4
        let first_chunk = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: a\n\n";
        let o4 = step(ta(BIZ_RELAY_STREAMING, first_chunk, b""), &mut state);
        assert_eq!(o4.next, RelayNext::ReadUpstream);
        assert!(matches!(
            o4.events[0],
            RelayEvent::StartStreamingResponse { upstream_status: 200 }
        ));

        // 5
        let o5 = step(
            ta(BIZ_RELAY_STREAMING, b"data: b\n\n", b""),
            &mut state,
        );
        assert_eq!(o5.next, RelayNext::ReadUpstream);
        assert_eq!(
            o5.events[0],
            RelayEvent::ClientBody(b"data: b\n\n".to_vec())
        );

        // 6
        let o6 = step(ta(BIZ_RELAY_DONE, b"", b""), &mut state);
        assert_eq!(o6.next, RelayNext::Done);
    }

    #[test]
    fn parse_upstream_headers_extracts_status_and_body_offset() {
        let data = b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nBODY";
        let (status, off) = parse_upstream_headers(data);
        assert_eq!(status, 200);
        assert_eq!(off, data.len() - 4);
        assert_eq!(&data[off..], b"BODY");
    }

    #[test]
    fn parse_upstream_headers_falls_back_to_200_when_malformed() {
        let data = b"GARBAGE\r\n\r\n";
        let (status, _) = parse_upstream_headers(data);
        assert_eq!(status, 200);
    }

    #[test]
    fn parse_upstream_headers_no_boundary_returns_end() {
        // No \r\n\r\n boundary yet → body_start = data.len()
        // (i.e. the caller gets an empty body slice and waits for
        // the next chunk to carry the rest of the headers).
        let data = b"HTTP/1.1 200 OK\r\n";
        let (_, off) = parse_upstream_headers(data);
        assert_eq!(off, data.len());
    }
}
