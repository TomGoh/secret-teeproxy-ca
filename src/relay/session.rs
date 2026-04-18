//! Relay loop adapter — drives the pure [`core`] state machine with
//! real I/O.
//!
//! [`core`]: crate::relay::core
//!
//! # What this module owns
//!
//! Everything the pure state machine deliberately doesn't:
//!
//! - Upstream TCP read (via [`Upstream`]) + upstream-EOF double-detect
//!   (`saw_eof` twice in a row ⇒ `"server closed before relay completed"`).
//! - TA invoke (via [`Teec`]) — builds the `TEEC_Operation` for
//!   `CMD_RELAY_DATA`, unpacks the result into `RelayTaOutput`.
//! - HTTP client writes — preamble + body streaming + flush + the
//!   short-response full HTTP response.
//! - Error → HTTP status mapping: TCP TimedOut → 504, TCP read failure
//!   → 502, TA invoke rc failure → 502, state-machine Error → 502.
//!   After the SSE preamble has been written, mid-stream errors
//!   **must not** call `send_error` (would corrupt the response).
//!
//! # Why a free function not a struct
//!
//! Per-session state is tiny (`RelayState` is two booleans + a decoder
//! + a pump flag) and integration tests read more naturally as
//! "call once, assert afterwards" than as `.step()`/`.step()`. A
//! struct with methods would buy nothing over a free fn taking
//! `&mut RelayState`.

use std::io::{self, Write};

use cc_teec::raw;
use log::{debug, error, info};

use crate::constants::CMD_RELAY_DATA;
use crate::relay::core::{self, RelayEvent, RelayNext, RelayOutcome, RelayState, RelayTaOutput};
use crate::relay::upstream::Upstream;
use crate::sse::encoder::sse_response_headers;
use crate::sse::parser::{log_event, parse_events};
use crate::teec::Teec;

/// Run the full TEEC ↔ upstream ↔ client relay loop.
///
/// Wire behavior is pytest-pinned — the smoke/format/recovery suite
/// in `tests/` is the acceptance gate for any change here.
///
/// Returns `Ok(())` on clean BIZ_RELAY_DONE. Any other exit — upstream
/// EOF before DONE, TCP error, TA error, state-machine error, client
/// write failure — returns `Err(msg)` and (when applicable) has already
/// written an HTTP error response to `client` via [`send_error`].
pub(crate) fn run_relay_loop<U, W>(
    teec: &mut dyn Teec,
    upstream: &mut U,
    client: &mut W,
    initial_tls: &[u8],
) -> Result<(), String>
where
    U: Upstream,
    W: Write,
{
    debug!("sending {} bytes ClientHello upstream", initial_tls.len());
    upstream
        .write_all(initial_tls)
        .map_err(|e| format!("TCP write ClientHello: {e}"))?;

    let mut state = RelayState::new();
    let mut read_buf = vec![0u8; 65536];
    // 1 MiB — covers the biggest Anthropic SSE chunk seen in
    // production. Larger upstreams would need CMD_RELAY_DATA to be
    // re-issued with a bigger output buffer, which is a TA-side change.
    let mut response_buf = vec![0u8; 1024 * 1024];
    let mut tls_extra_buf = vec![0u8; 4096];
    let mut saw_upstream_eof = false;
    let mut round = 0u32;
    // `next` seeds the first iteration: ReadUpstream pulls the first
    // server response bytes before we call the TA.
    let mut next = RelayNext::ReadUpstream;

    loop {
        round += 1;

        // --- Gather TA input: either upstream read or empty (pump) --
        let (input_bytes, eof_flag): (&[u8], bool) = match next {
            RelayNext::ReadUpstream => {
                debug!("relay round {round}, reading from upstream...");
                match upstream.read(&mut read_buf) {
                    Ok(n) => {
                        if n == 0 {
                            if saw_upstream_eof {
                                return Err("server closed before relay completed".into());
                            }
                            saw_upstream_eof = true;
                        } else {
                            saw_upstream_eof = false;
                        }
                        debug!(
                            "relay round {round}, server→ {n} bytes{}",
                            if n == 0 { " (EOF)" } else { "" }
                        );
                        (&read_buf[..n], n == 0)
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::TimedOut
                            || e.kind() == io::ErrorKind::WouldBlock =>
                    {
                        send_error(client, 504, "upstream timeout");
                        return Err("TCP read timed out".into());
                    }
                    Err(e) => {
                        if !state.response_started {
                            send_error(client, 502, &format!("TCP read: {e}"));
                        }
                        return Err(format!("TCP read: {e}"));
                    }
                }
            }
            RelayNext::PumpTa => {
                debug!("relay round {round}, pumping TA (empty input)");
                (&[] as &[u8], false)
            }
            RelayNext::Done | RelayNext::Error(_) => {
                // Already handled at end of previous iteration — we
                // should never loop back here.
                unreachable!("done/error should have returned");
            }
        };

        // --- Invoke TA CMD_RELAY_DATA --------------------------------
        //
        // Param layout (wire contract, do not reorder):
        //   params[0] MEMREF_TEMP_INPUT   ciphertext from upstream
        //   params[1] VALUE_INOUT         {in: a=eof_flag, out: a=biz, b=detail}
        //   params[2] MEMREF_TEMP_OUTPUT  decrypted response
        //   params[3] MEMREF_TEMP_OUTPUT  TLS bytes to send back upstream
        let mut server_data = input_bytes.to_vec();
        let mut op: raw::TEEC_Operation = unsafe { std::mem::zeroed() };
        op.paramTypes = raw::TEEC_PARAM_TYPES(
            raw::TEEC_MEMREF_TEMP_INPUT,
            raw::TEEC_VALUE_INOUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
            raw::TEEC_MEMREF_TEMP_OUTPUT,
        );
        op.params[0].tmpref.buffer = server_data.as_mut_ptr() as *mut _;
        op.params[0].tmpref.size = server_data.len();
        op.params[1].value.a = if eof_flag { 1 } else { 0 };
        op.params[1].value.b = 0;
        op.params[2].tmpref.buffer = response_buf.as_mut_ptr() as *mut _;
        op.params[2].tmpref.size = response_buf.len();
        op.params[3].tmpref.buffer = tls_extra_buf.as_mut_ptr() as *mut _;
        op.params[3].tmpref.size = tls_extra_buf.len();

        let (rc, origin) = teec.invoke(CMD_RELAY_DATA, &mut op);
        if let Err(e) = crate::check_teec_rc(rc, origin) {
            if !state.response_started {
                send_error(client, 502, &e);
            }
            return Err(e);
        }

        let biz_code = unsafe { op.params[1].value.a };
        let filled = unsafe { op.params[2].tmpref.size };
        let tls_extra_filled = unsafe { op.params[3].tmpref.size };
        debug!(
            "relay round {round}, TA biz=0x{biz_code:04x}, \
             decrypted={filled}B, tls_extra={tls_extra_filled}B"
        );

        // --- Drive the pure state machine with this TA output --------
        let ta_out = RelayTaOutput {
            biz_code,
            decrypted: &response_buf[..filled],
            tls_extra: &tls_extra_buf[..tls_extra_filled],
        };
        let RelayOutcome { events, next: next_action } = core::step(ta_out, &mut state);

        // --- Apply the events the state machine emitted --------------
        for ev in events {
            match ev {
                RelayEvent::ToUpstream(bytes) => {
                    debug!("relay round {round}, →upstream {} bytes", bytes.len());
                    upstream
                        .write_all(&bytes)
                        .map_err(|e| format!("TCP write TLS: {e}"))?;
                }
                RelayEvent::StartStreamingResponse { upstream_status } => {
                    let hdr = sse_response_headers(upstream_status);
                    client
                        .write_all(&hdr)
                        .map_err(|e| format!("client write headers: {e}"))?;
                }
                RelayEvent::ClientBody(bytes) => {
                    log_decoded_events(&bytes);
                    client
                        .write_all(&bytes)
                        .map_err(|e| format!("client write body: {e}"))?;
                }
                RelayEvent::FlushClient => {
                    client
                        .flush()
                        .map_err(|e| format!("client flush: {e}"))?;
                }
                RelayEvent::ClientFullResponse {
                    status,
                    content_type,
                    body,
                } => {
                    let hdr = format!(
                        "HTTP/1.1 {status} OK\r\n\
                         Content-Type: {content_type}\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n",
                        body.len()
                    );
                    log_decoded_events(&body);
                    client
                        .write_all(hdr.as_bytes())
                        .map_err(|e| format!("client write headers: {e}"))?;
                    client
                        .write_all(&body)
                        .map_err(|e| format!("client write body: {e}"))?;
                }
            }
        }

        // --- Decide what to do next ---------------------------------
        match next_action {
            RelayNext::ReadUpstream | RelayNext::PumpTa => {
                next = next_action;
                continue;
            }
            RelayNext::Done => {
                let _ = client.flush();
                info!("serve → stream complete");
                return Ok(());
            }
            RelayNext::Error(msg) => {
                if !state.response_started {
                    send_error(client, 502, &msg);
                }
                error!("relay state machine error: {msg}");
                return Err(msg);
            }
        }
    }
}

/// Emit an HTTP error response to the client. Mirrors
/// `serve::send_error` — kept local to avoid cross-module coupling,
/// trivial enough to duplicate.
fn send_error<W: Write>(client: &mut W, status: u16, message: &str) {
    let body = format!("{{\"error\":{{\"message\":\"{message}\",\"type\":\"proxy_error\"}}}}");
    let response = format!(
        "HTTP/1.1 {status} Error\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _ = client.write_all(response.as_bytes());
}

/// Parse SSE events from `bytes` and log them via the shared
/// sse::parser helpers. Used for both streaming body chunks and the
/// short-response full body so operators see Anthropic events in
/// daemon.log regardless of transport path.
fn log_decoded_events(bytes: &[u8]) {
    for ev in parse_events(bytes) {
        log_event(&ev);
    }
}

// --- Unit tests -----------------------------------------------------------
//
// These drive `run_relay_loop` with `MockTeec` + `MockUpstream` +
// `Vec<u8>` as the client writer. They cover the adapter-side decisions
// (error mapping, I/O orchestration) that the `relay::core` tests
// don't — core tests assume well-formed TA output, these assume the
// full TA + upstream contract.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        BIZ_RELAY_CONTINUE, BIZ_RELAY_DONE, BIZ_RELAY_STREAMING, BIZ_SUCCESS,
    };
    use crate::relay::upstream::MockUpstream;
    use crate::teec::mock::{MockTeec, ScriptedResponse};

    /// Build a scripted TA response that fills params[1]/params[2]/params[3]
    /// to simulate one CMD_RELAY_DATA round.
    fn queue_ta_round(
        mock: &mut MockTeec,
        biz_code: u32,
        decrypted: &'static [u8],
        tls_extra: &'static [u8],
    ) {
        mock.queue(ScriptedResponse {
            expected_cmd_id: Some(CMD_RELAY_DATA),
            rc: raw::TEEC_SUCCESS,
            origin: 0,
            mutate: Box::new(move |op| unsafe {
                op.params[1].value.a = biz_code;
                op.params[1].value.b = 0;
                let dst2 = op.params[2].tmpref.buffer as *mut u8;
                let cap2 = op.params[2].tmpref.size;
                let n2 = decrypted.len().min(cap2);
                std::ptr::copy_nonoverlapping(decrypted.as_ptr(), dst2, n2);
                op.params[2].tmpref.size = n2;
                let dst3 = op.params[3].tmpref.buffer as *mut u8;
                let cap3 = op.params[3].tmpref.size;
                let n3 = tls_extra.len().min(cap3);
                std::ptr::copy_nonoverlapping(tls_extra.as_ptr(), dst3, n3);
                op.params[3].tmpref.size = n3;
            }),
        });
    }

    /// Minimal streaming scenario: initial TLS handshake (CONTINUE
    /// with bytes), then STREAMING with a full HTTP response including
    /// one SSE event, then DONE.
    #[test]
    fn happy_path_streaming_sse_round_trip() {
        let mut teec = MockTeec::new();
        // Round 1: TA accepts upstream ciphertext, emits handshake bytes.
        queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"HS_TO_UPSTREAM", b"");
        // Round 2: STREAMING with HTTP headers + SSE body.
        queue_ta_round(
            &mut teec,
            BIZ_RELAY_STREAMING,
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: text/event-stream\r\n\
              \r\n\
              data: {\"type\":\"message_stop\"}\n\n",
            b"",
        );
        // Round 3: DONE clean.
        queue_ta_round(&mut teec, BIZ_RELAY_DONE, b"", b"");

        let mut upstream = MockUpstream::new();
        // Two upstream reads: one to trigger round 2, one to trigger round 3.
        upstream
            .queue_read(b"CIPHERTEXT_1".to_vec())
            .queue_read(b"CIPHERTEXT_2".to_vec())
            .queue_read(b"CIPHERTEXT_3".to_vec());

        let mut client = Vec::<u8>::new();
        let result = run_relay_loop(&mut teec, &mut upstream, &mut client, b"CLIENT_HELLO");

        assert!(result.is_ok(), "relay should succeed: {result:?}");

        // Upstream should have received: ClientHello + HS_TO_UPSTREAM.
        let up_total = upstream.total_written();
        assert!(up_total.starts_with(b"CLIENT_HELLO"));
        assert!(up_total.windows(14).any(|w| w == b"HS_TO_UPSTREAM"));

        // Client should have SSE preamble + the data line.
        let client_str = String::from_utf8_lossy(&client);
        assert!(client_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(client_str.contains("Content-Type: text/event-stream"));
        assert!(client_str.contains("data: {\"type\":\"message_stop\"}"));
    }

    #[test]
    fn short_response_emits_full_http_response_no_sse() {
        // Scenario: TA completes in one round with BIZ_RELAY_DONE and
        // a ProxyResponse JSON. Client should see `Content-Length: N`
        // and the raw body — not an SSE-style preamble.
        let body_bytes = b"{\"ok\":true}";
        let proxy_resp = format!(
            r#"{{"status":200,"headers":{{"content-type":"application/json"}},"body":{:?}}}"#,
            body_bytes.to_vec(),
        );
        // Leak to get 'static for MockTeec's FnMut closure.
        let leaked: &'static [u8] = Box::leak(proxy_resp.into_bytes().into_boxed_slice());

        let mut teec = MockTeec::new();
        queue_ta_round(&mut teec, BIZ_RELAY_DONE, leaked, b"");

        let mut upstream = MockUpstream::new();
        upstream.queue_read(b"CIPHERTEXT".to_vec());

        let mut client = Vec::<u8>::new();
        run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO").unwrap();

        let client_str = String::from_utf8_lossy(&client);
        assert!(client_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(client_str.contains("Content-Type: application/json"));
        assert!(
            client_str.contains(&format!("Content-Length: {}", body_bytes.len())),
            "got: {client_str}"
        );
        assert!(client.ends_with(body_bytes));
    }

    #[test]
    fn upstream_timeout_writes_504_and_errors() {
        let mut teec = MockTeec::new();
        // No TA rounds queued — upstream.read errors before we get there.

        let mut upstream = MockUpstream::new();
        upstream.queue_read_err(io::ErrorKind::TimedOut);

        let mut client = Vec::<u8>::new();
        let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
            .expect_err("should error on timeout");
        assert!(err.contains("TCP read timed out"), "got: {err}");

        let client_str = String::from_utf8_lossy(&client);
        assert!(client_str.starts_with("HTTP/1.1 504 Error\r\n"), "got: {client_str}");
        assert!(client_str.contains("upstream timeout"));
    }

    #[test]
    fn upstream_read_error_writes_502_before_response_started() {
        let mut teec = MockTeec::new();

        let mut upstream = MockUpstream::new();
        upstream.queue_read_err(io::ErrorKind::ConnectionReset);

        let mut client = Vec::<u8>::new();
        let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
            .expect_err("should error on reset");
        assert!(err.contains("TCP read"), "got: {err}");

        let client_str = String::from_utf8_lossy(&client);
        assert!(client_str.starts_with("HTTP/1.1 502 Error\r\n"));
    }

    #[test]
    fn double_eof_yields_server_closed_error() {
        // Script:
        //   Round 1: upstream EOF → TA returns CONTINUE+empty → PumpTa.
        //   Pump round (no upstream read) → TA again CONTINUE+empty →
        //   adapter falls through (no cascade) → ReadUpstream.
        //   Round 2: upstream EOF again → adapter's saw_eof flag is set
        //   from round 1 → `"server closed before relay completed"`.
        let mut teec = MockTeec::new();
        queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"", b""); // round 1 result
        queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"", b""); // pump result

        let mut upstream = MockUpstream::new();
        upstream.queue_read_eof().queue_read_eof();

        let mut client = Vec::<u8>::new();
        let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
            .expect_err("should error on double EOF");
        assert!(
            err.contains("server closed"),
            "expected server-closed error, got: {err}"
        );
    }

    #[test]
    fn teec_rc_failure_writes_502_before_response_started() {
        let mut teec = MockTeec::new();
        // TEEC_ERROR_COMMUNICATION
        teec.queue_rc(CMD_RELAY_DATA, 0xFFFF000E, 2);

        let mut upstream = MockUpstream::new();
        upstream.queue_read(b"CIPHERTEXT".to_vec());

        let mut client = Vec::<u8>::new();
        let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
            .expect_err("should error on TEEC rc");
        assert!(err.contains("TEEC_InvokeCommand failed"));

        let client_str = String::from_utf8_lossy(&client);
        assert!(client_str.starts_with("HTTP/1.1 502 Error\r\n"));
    }

    #[test]
    fn unknown_biz_code_writes_502_before_response_started() {
        let mut teec = MockTeec::new();
        // 0xE007 isn't a BIZ_RELAY_* — state machine → RelayNext::Error.
        queue_ta_round(&mut teec, 0xE007, b"", b"");

        let mut upstream = MockUpstream::new();
        upstream.queue_read(b"CIPHERTEXT".to_vec());

        let mut client = Vec::<u8>::new();
        let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
            .expect_err("should error on unknown biz");
        assert_eq!(err, "relay error: 0xe007");

        let client_str = String::from_utf8_lossy(&client);
        assert!(client_str.starts_with("HTTP/1.1 502 Error\r\n"));
        assert!(client_str.contains("relay error: 0xe007"));
    }

    #[test]
    fn unknown_biz_code_after_streaming_does_not_send_error() {
        // After preamble has been written, we can't retroactively send
        // a 502 (the HTTP response has already been started). The
        // function just returns Err; client is left truncated.
        let mut teec = MockTeec::new();
        queue_ta_round(
            &mut teec,
            BIZ_RELAY_STREAMING,
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"",
        );
        queue_ta_round(&mut teec, 0xE007, b"", b"");

        let mut upstream = MockUpstream::new();
        upstream
            .queue_read(b"C1".to_vec())
            .queue_read(b"C2".to_vec());

        let mut client = Vec::<u8>::new();
        let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
            .expect_err("should error on unknown biz mid-stream");
        assert_eq!(err, "relay error: 0xe007");

        let client_str = String::from_utf8_lossy(&client);
        // Only ONE HTTP status line should be present — the preamble.
        // If send_error fired we'd see a second one.
        assert_eq!(
            client_str.matches("HTTP/1.1 ").count(),
            1,
            "must not send_error after preamble; got: {client_str:?}"
        );
        assert!(client_str.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn pump_path_cascades_from_empty_continue() {
        let mut teec = MockTeec::new();
        // Round 1 (upstream read): CONTINUE empty → pump.
        queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"", b"");
        // Round 2 (pump, empty input): CONTINUE with bytes → write to upstream.
        queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"PUMPED_HS", b"");
        // Round 3 (upstream read): STREAMING.
        queue_ta_round(
            &mut teec,
            BIZ_RELAY_STREAMING,
            b"HTTP/1.1 200 OK\r\n\r\n",
            b"",
        );
        // Round 4: DONE.
        queue_ta_round(&mut teec, BIZ_RELAY_DONE, b"", b"");

        let mut upstream = MockUpstream::new();
        // Two upstream reads needed — round 2 is pump (no read).
        upstream
            .queue_read(b"CIPHERTEXT_1".to_vec())
            .queue_read(b"CIPHERTEXT_2".to_vec())
            .queue_read(b"CIPHERTEXT_3".to_vec());

        let mut client = Vec::<u8>::new();
        run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO").unwrap();

        // Upstream should have seen PUMPED_HS among the writes.
        let up_total = upstream.total_written();
        assert!(
            up_total.windows(9).any(|w| w == b"PUMPED_HS"),
            "pump output not written to upstream: {up_total:?}"
        );

        let client_str = String::from_utf8_lossy(&client);
        assert!(client_str.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn send_error_body_shape_matches_pre_refactor() {
        // Regression: pytest format/test_proxy_format.py asserts a
        // `"type":"proxy_error"` field in 502 body JSON.
        let mut buf = Vec::<u8>::new();
        send_error(&mut buf, 502, "some failure");
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("\"type\":\"proxy_error\""));
        assert!(s.contains("\"message\":\"some failure\""));
        assert!(s.contains("Content-Type: application/json"));
    }
}
