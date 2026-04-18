//! End-to-end integration tests for the proxy-relay path.
//!
//! Exercises [`secret_proxy_ca::relay::session::run_relay_loop`] with
//! scripted [`MockTeec`] + [`MockUpstream`] + a `Vec<u8>` client writer
//! — no real TEE device, no real TCP upstream, no openclaw. Every TA
//! and upstream response is deterministic.
//!
//! Run with:
//!   `cargo test --features test-support --test serve_proxy_sse`
//!
//! # Why these tests on top of the unit tests
//!
//! The unit tests inside `src/relay/core.rs` and `src/relay/session.rs`
//! cover dispatch correctness. These integration tests cover:
//!
//! 1. **Composition** — verify the `session → core → http::chunked →
//!    sse::encoder` wiring end-to-end at a module-external boundary.
//! 2. **Deterministic "flaky" scenarios** — script TA and upstream
//!    responses that are impossible or painful to reproduce on real
//!    hardware (mid-stream 401, malformed bytes, slow reads, cascaded
//!    pumps, etc.).
//! 3. **Byte-exact client output** — full buffers we can grep for the
//!    SSE preamble, HTTP status line, Content-Type, etc.
//!
//! All tests are hermetic: millisecond runtime, no external deps, can
//! run in CI on any box.

use std::io;

use secret_proxy_ca::constants::{
    BIZ_RELAY_CONTINUE, BIZ_RELAY_DONE, BIZ_RELAY_STREAMING, CMD_RELAY_DATA,
};
use secret_proxy_ca::relay::session::run_relay_loop;
use secret_proxy_ca::relay::upstream::MockUpstream;
use secret_proxy_ca::teec::mock::{MockTeec, ScriptedResponse};

// cc_teec::raw is re-exported by rust-libteec. Pull it in for the
// TEEC_SUCCESS constant and for the one Op-mutation helper we write below.
use cc_teec::raw;

// ----------------------------------------------------------------------
// Helpers for scripting TA responses. Mirrors the pattern in
// `src/relay/session.rs::tests` but reusable across test files.
// ----------------------------------------------------------------------

/// Push one scripted CMD_RELAY_DATA result onto the mock: sets the
/// biz_code in `params[1].value.a`, copies `decrypted` into
/// `params[2].tmpref`, copies `tls_extra` into `params[3].tmpref`.
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
            // params[2] = decrypted MEMREF_TEMP_OUTPUT
            let dst2 = op.params[2].tmpref.buffer as *mut u8;
            let cap2 = op.params[2].tmpref.size;
            let n2 = decrypted.len().min(cap2);
            std::ptr::copy_nonoverlapping(decrypted.as_ptr(), dst2, n2);
            op.params[2].tmpref.size = n2;
            // params[3] = tls_extra MEMREF_TEMP_OUTPUT
            let dst3 = op.params[3].tmpref.buffer as *mut u8;
            let cap3 = op.params[3].tmpref.size;
            let n3 = tls_extra.len().min(cap3);
            std::ptr::copy_nonoverlapping(tls_extra.as_ptr(), dst3, n3);
            op.params[3].tmpref.size = n3;
        }),
    });
}

// ----------------------------------------------------------------------
// Happy-path: realistic Anthropic SSE stream
// ----------------------------------------------------------------------

#[test]
fn streaming_anthropic_sse_happy_path() {
    // Script a three-round TA interaction that looks like a real
    // Anthropic message_start → content_block_delta → message_stop
    // flow. Assert the client buffer gets the SSE preamble + the
    // decrypted body verbatim.
    let mut teec = MockTeec::new();

    // Round 1: TA asks us to send the ClientHello handshake bytes.
    queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"TLS_HANDSHAKE_OUT", b"");

    // Round 2: STREAMING — first chunk has HTTP headers + initial SSE events.
    queue_ta_round(
        &mut teec,
        BIZ_RELAY_STREAMING,
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: text/event-stream; charset=utf-8\r\n\
          Cache-Control: no-cache\r\n\
          \r\n\
          event: message_start\n\
          data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"model\":\"claude-x\"}}\n\n",
        b"",
    );

    // Round 3: STREAMING — more SSE events (content_block_delta ×2).
    queue_ta_round(
        &mut teec,
        BIZ_RELAY_STREAMING,
        b"event: content_block_delta\n\
          data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n\
          event: content_block_delta\n\
          data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}\n\n",
        b"",
    );

    // Round 4: STREAMING — message_stop.
    queue_ta_round(
        &mut teec,
        BIZ_RELAY_STREAMING,
        b"event: message_stop\n\
          data: {\"type\":\"message_stop\"}\n\n",
        b"",
    );

    // Round 5: DONE with close_notify TLS bytes.
    queue_ta_round(&mut teec, BIZ_RELAY_DONE, b"", b"TLS_CLOSE_NOTIFY");

    let mut upstream = MockUpstream::new();
    upstream
        .queue_read(b"UPSTREAM_BYTES_1".to_vec())
        .queue_read(b"UPSTREAM_BYTES_2".to_vec())
        .queue_read(b"UPSTREAM_BYTES_3".to_vec())
        .queue_read(b"UPSTREAM_BYTES_4".to_vec())
        .queue_read(b"UPSTREAM_BYTES_5".to_vec());

    let mut client = Vec::<u8>::new();
    let result = run_relay_loop(&mut teec, &mut upstream, &mut client, b"CLIENT_HELLO");
    assert!(result.is_ok(), "relay should succeed: {:?}", result);

    // Client should have received: SSE preamble + all three streaming chunks concatenated.
    let client_str = String::from_utf8_lossy(&client);

    // SSE preamble comes from sse::encoder::sse_response_headers.
    assert!(
        client_str.starts_with("HTTP/1.1 200 OK\r\n"),
        "client output must start with status line, got: {client_str:?}"
    );
    assert!(
        client_str.contains("Content-Type: text/event-stream; charset=utf-8\r\n"),
        "missing SSE content-type"
    );
    assert!(
        client_str.contains("Cache-Control: no-cache\r\n"),
        "missing cache-control"
    );
    assert!(
        client_str.contains("Connection: close\r\n"),
        "missing Connection: close"
    );

    // Every event line must appear in the client buffer.
    for expected in [
        "\"type\":\"message_start\"",
        "\"type\":\"content_block_delta\"",
        "\"text\":\"Hi\"",
        "\"text\":\" there\"",
        "\"type\":\"message_stop\"",
    ] {
        assert!(
            client_str.contains(expected),
            "client missing expected SSE fragment {expected:?} in output:\n{client_str}"
        );
    }

    // Upstream should have seen: ClientHello + TLS_HANDSHAKE_OUT + TLS_CLOSE_NOTIFY.
    let up_total = upstream.total_written();
    assert!(up_total.starts_with(b"CLIENT_HELLO"));
    assert!(
        up_total.windows(17).any(|w| w == b"TLS_HANDSHAKE_OUT"),
        "handshake bytes not written to upstream"
    );
    assert!(
        up_total.windows(16).any(|w| w == b"TLS_CLOSE_NOTIFY"),
        "close_notify not written to upstream"
    );
}

// ----------------------------------------------------------------------
// Short-response path: TA returns a non-streaming ProxyResponse (e.g. 429)
// ----------------------------------------------------------------------

#[test]
fn short_response_429_rate_limit_passes_through_status() {
    // The TA completes the whole request in one round (no streaming
    // ever started) and hands us a ProxyResponse JSON representing an
    // upstream 429 rate-limit response. The CA must forward the
    // upstream status + content-type + body byte-for-byte — NOT
    // rewrite to 200. This is the scenario that's painful to reproduce
    // with a real MiniMax (you'd have to actually hit their rate limit)
    // but trivial to script here.
    let body_bytes = b"{\"error\":\"rate limit exceeded\"}";
    let proxy_resp = format!(
        r#"{{"status":429,"headers":{{"content-type":"application/json"}},"body":{:?}}}"#,
        body_bytes.to_vec(),
    );
    // Leak to 'static — MockTeec's FnMut closure needs a 'static capture.
    let leaked: &'static [u8] = Box::leak(proxy_resp.into_bytes().into_boxed_slice());

    let mut teec = MockTeec::new();
    queue_ta_round(&mut teec, BIZ_RELAY_DONE, leaked, b"");

    let mut upstream = MockUpstream::new();
    upstream.queue_read(b"CIPHERTEXT".to_vec());

    let mut client = Vec::<u8>::new();
    run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO").unwrap();

    let client_str = String::from_utf8_lossy(&client);
    assert!(
        client_str.starts_with("HTTP/1.1 429 OK\r\n"),
        "upstream 429 must be forwarded (reason-phrase 'OK' is by design), got: {client_str:?}"
    );
    assert!(
        client_str.contains("Content-Type: application/json\r\n"),
        "content-type must pass through from ProxyResponse.headers"
    );
    assert!(
        client_str.contains(&format!("Content-Length: {}", body_bytes.len())),
        "content-length must match body"
    );
    assert!(
        client.ends_with(body_bytes),
        "client body must match ProxyResponse.body byte-exactly"
    );
}

// ----------------------------------------------------------------------
// Error paths
// ----------------------------------------------------------------------

#[test]
fn upstream_timeout_emits_504() {
    let mut teec = MockTeec::new();
    // No TA rounds scripted — upstream errors before we ever invoke.

    let mut upstream = MockUpstream::new();
    upstream.queue_read_err(io::ErrorKind::TimedOut);

    let mut client = Vec::<u8>::new();
    let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
        .expect_err("timeout must propagate");
    assert!(err.contains("TCP read timed out"), "got: {err}");

    let client_str = String::from_utf8_lossy(&client);
    assert!(
        client_str.starts_with("HTTP/1.1 504 Error\r\n"),
        "client must receive 504 Gateway Timeout, got: {client_str:?}"
    );
    assert!(client_str.contains("upstream timeout"));
    assert!(client_str.contains("\"type\":\"proxy_error\""));
}

#[test]
fn unknown_biz_code_emits_502_with_exact_pytest_pinned_string() {
    // Pytest format suite greps on the exact string "relay error: 0x...".
    // If this assertion ever breaks, check the grep in tests/format/
    // before "fixing" the CA side.
    let mut teec = MockTeec::new();
    queue_ta_round(&mut teec, 0xE007, b"", b"");

    let mut upstream = MockUpstream::new();
    upstream.queue_read(b"CIPHERTEXT".to_vec());

    let mut client = Vec::<u8>::new();
    let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
        .expect_err("unknown biz must error");
    assert_eq!(err, "relay error: 0xe007");

    let client_str = String::from_utf8_lossy(&client);
    assert!(client_str.starts_with("HTTP/1.1 502 Error\r\n"));
    assert!(client_str.contains("relay error: 0xe007"));
    assert!(client_str.contains("\"type\":\"proxy_error\""));
}

#[test]
fn mid_stream_error_must_not_resend_headers() {
    // After SSE preamble is written, any error MUST NOT trigger
    // send_error — that would write a second HTTP status line on top
    // of an already-started response and corrupt the stream. Verify
    // by checking the client buffer contains exactly ONE
    // "HTTP/1.1 " prefix.
    let mut teec = MockTeec::new();
    queue_ta_round(
        &mut teec,
        BIZ_RELAY_STREAMING,
        b"HTTP/1.1 200 OK\r\n\r\nevent: ping\ndata: {}\n\n",
        b"",
    );
    // Second round: unknown biz — would normally emit 502, but stream has started.
    queue_ta_round(&mut teec, 0xE007, b"", b"");

    let mut upstream = MockUpstream::new();
    upstream
        .queue_read(b"CIPHERTEXT_1".to_vec())
        .queue_read(b"CIPHERTEXT_2".to_vec());

    let mut client = Vec::<u8>::new();
    let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
        .expect_err("mid-stream error must propagate");
    assert_eq!(err, "relay error: 0xe007");

    let client_str = String::from_utf8_lossy(&client);
    let status_line_count = client_str.matches("HTTP/1.1 ").count();
    assert_eq!(
        status_line_count, 1,
        "after preamble, send_error must NOT fire; got {status_line_count} status lines:\n{client_str}"
    );
    assert!(client_str.starts_with("HTTP/1.1 200 OK\r\n"));
}

// ----------------------------------------------------------------------
// Pump cascade — CONTINUE with empty decrypted triggers one (and only
// one) extra TA invoke with empty input.
// ----------------------------------------------------------------------

#[test]
fn pump_single_shot_then_advances() {
    let mut teec = MockTeec::new();

    // Round 1 (upstream read): CONTINUE empty → state machine emits PumpTa.
    queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"", b"");
    // Round 2 (pump, empty input): CONTINUE with bytes → ToUpstream.
    queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"POST_PUMP_HS", b"");
    // Round 3 (upstream read): STREAMING starts.
    queue_ta_round(&mut teec, BIZ_RELAY_STREAMING, b"HTTP/1.1 200 OK\r\n\r\n", b"");
    // Round 4: DONE.
    queue_ta_round(&mut teec, BIZ_RELAY_DONE, b"", b"");

    let mut upstream = MockUpstream::new();
    upstream
        .queue_read(b"C1".to_vec())
        .queue_read(b"C2".to_vec())
        .queue_read(b"C3".to_vec());

    let mut client = Vec::<u8>::new();
    run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO").unwrap();

    // Pumped handshake bytes must reach upstream.
    let up_total = upstream.total_written();
    assert!(
        up_total.windows(12).any(|w| w == b"POST_PUMP_HS"),
        "pumped bytes not forwarded upstream"
    );

    // Client got the preamble (stream started successfully).
    let client_str = String::from_utf8_lossy(&client);
    assert!(client_str.starts_with("HTTP/1.1 200 OK\r\n"));
}

#[test]
fn pump_empty_does_not_cascade_into_second_pump() {
    // CONTINUE empty → PumpTa. Pump response is ALSO CONTINUE empty.
    // State machine must fall through to ReadUpstream (not emit
    // another PumpTa) — otherwise rustls-stuck streams deadlock.
    let mut teec = MockTeec::new();
    queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"", b""); // round 1: empty → pump
    queue_ta_round(&mut teec, BIZ_RELAY_CONTINUE, b"", b""); // pump: also empty → fall through
    // After fallthrough, next upstream read is EOF → double-EOF error.

    let mut upstream = MockUpstream::new();
    upstream.queue_read_eof().queue_read_eof();

    let mut client = Vec::<u8>::new();
    let err = run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO")
        .expect_err("double EOF after non-progressing pump must error");
    assert!(
        err.contains("server closed"),
        "expected server-closed error after pump-then-EOF; got: {err}"
    );
}

// ----------------------------------------------------------------------
// Upstream chunked Transfer-Encoding — CA unwraps the hex framing
// before forwarding SSE to client. Regression test for the
// stateful-decoder-across-rounds behavior (Step 2 refactor).
// ----------------------------------------------------------------------

#[test]
fn upstream_chunked_encoding_unwrapped_across_rounds() {
    let mut teec = MockTeec::new();

    // First chunk: headers declare chunked, then initial body piece
    // "5\r\nHello" (5-byte chunk, 3 out of 5 bytes of payload arrived).
    queue_ta_round(
        &mut teec,
        BIZ_RELAY_STREAMING,
        b"HTTP/1.1 200 OK\r\n\
          Transfer-Encoding: chunked\r\n\
          \r\n\
          5\r\nHel",
        b"",
    );
    // Second chunk: rest of "Hello" + next chunk + terminator.
    queue_ta_round(&mut teec, BIZ_RELAY_STREAMING, b"lo\r\n0\r\n\r\n", b"");
    queue_ta_round(&mut teec, BIZ_RELAY_DONE, b"", b"");

    let mut upstream = MockUpstream::new();
    upstream
        .queue_read(b"C1".to_vec())
        .queue_read(b"C2".to_vec())
        .queue_read(b"C3".to_vec());

    let mut client = Vec::<u8>::new();
    run_relay_loop(&mut teec, &mut upstream, &mut client, b"HELLO").unwrap();

    let client_str = String::from_utf8_lossy(&client);
    // Client must see "Hello" decoded — NOT the raw "5\r\nHello\r\n0..." framing.
    assert!(
        client_str.contains("Hello"),
        "chunked decoder must decode body across rounds; client got:\n{client_str}"
    );
    assert!(
        !client_str.contains("5\r\nHel"),
        "chunked size line must not leak through to client"
    );
    assert!(
        !client_str.contains("0\r\n\r\n"),
        "chunked zero-terminator must not leak through to client"
    );
}
