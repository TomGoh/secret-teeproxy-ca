//! SSE response-header encoder.
//!
//! The CA's SSE response preamble is fixed in shape:
//!
//! ```text
//! HTTP/1.1 <upstream_status> OK
//! Content-Type: text/event-stream; charset=utf-8
//! Cache-Control: no-cache
//! Connection: close
//!
//! ```
//!
//! # Why these exact headers — preserve in Step 6 and beyond
//!
//! - `text/event-stream; charset=utf-8` is what the Anthropic SDK's SSE
//!   parser sniffs on. Any other media type makes it fall back to a
//!   plain HTTP client and the streaming UX breaks.
//! - `Cache-Control: no-cache` keeps Nginx/Cloudflare-style intermediaries
//!   (none in the current deploy, but a safe default) from buffering
//!   events. The Anthropic docs recommend it for SSE endpoints.
//! - `Connection: close` is *load-bearing*: the response is not
//!   Content-Length-delimited and does not use Transfer-Encoding:
//!   chunked, so the only EOF signal the client has is TCP close. This
//!   is a deliberate match for how `cmd_serve`'s relay loop drops the
//!   TcpStream when BIZ_RELAY_DONE lands — no keep-alive, no pooling.
//!
//! - Status text is a literal `OK` even when the upstream returned e.g.
//!   429. The reason-phrase is optional per RFC 7230 §3.1.2 and
//!   openclaw's Anthropic SDK reads only the numeric status; flipping
//!   the phrase per-status would be correct but different from the
//!   pre-refactor string and Step 6 is explicitly a characterization
//!   refactor (bytes unchanged). A future step can switch to
//!   `http::response::status_text_for(status)` once the openclaw side
//!   is confirmed to ignore it.

/// Compose the fixed SSE response preamble. Caller writes this to the
/// HTTP client before streaming any body bytes.
///
/// Preserves the exact byte form of the pre-refactor inline
/// `format!(...)` at `serve.rs:897-904`. Regression-tested in the
/// `preamble_exact_bytes` unit test below.
pub fn sse_response_headers(upstream_status: u16) -> Vec<u8> {
    format!(
        "HTTP/1.1 {upstream_status} OK\r\n\
         Content-Type: text/event-stream; charset=utf-8\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n\
         \r\n",
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_exact_bytes() {
        // Snapshot of the pre-refactor byte string. If this test breaks,
        // openclaw's SSE parser might too — check the Anthropic SDK
        // before adjusting the expected string.
        let got = sse_response_headers(200);
        let expected = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/event-stream; charset=utf-8\r\n\
                         Cache-Control: no-cache\r\n\
                         Connection: close\r\n\
                         \r\n";
        assert_eq!(got, expected);
    }

    #[test]
    fn preamble_forwards_upstream_status_numerically() {
        // Upstream 429 Too Many Requests still surfaces as "429 OK" in
        // the reason-phrase — the SDK ignores it and the status code
        // survives. See module docs for why we accept this quirk.
        let got = sse_response_headers(429);
        assert!(got.starts_with(b"HTTP/1.1 429 OK\r\n"));
    }

    #[test]
    fn preamble_ends_with_blank_line() {
        // The trailing `\r\n\r\n` is how HTTP clients know to stop
        // reading headers and start treating bytes as SSE body.
        let got = sse_response_headers(200);
        assert!(got.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn preamble_has_exact_four_header_lines() {
        // status line + 3 headers + terminator blank line.
        let got = sse_response_headers(200);
        let text = std::str::from_utf8(&got).unwrap();
        let lines: Vec<&str> = text.split("\r\n").collect();
        // Lines: [0] "HTTP/1.1 200 OK"
        //        [1] "Content-Type: text/event-stream; charset=utf-8"
        //        [2] "Cache-Control: no-cache"
        //        [3] "Connection: close"
        //        [4] ""  (blank line ending headers)
        //        [5] ""  (trailing empty split slot after final \r\n)
        assert_eq!(lines.len(), 6, "headers: {text:?}");
        assert_eq!(lines[0], "HTTP/1.1 200 OK");
        assert_eq!(lines[1], "Content-Type: text/event-stream; charset=utf-8");
        assert_eq!(lines[2], "Cache-Control: no-cache");
        assert_eq!(lines[3], "Connection: close");
        assert_eq!(lines[4], "");
        assert_eq!(lines[5], "");
    }
}
