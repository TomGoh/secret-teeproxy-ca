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
//! # Why these exact headers (all load-bearing)
//!
//! - `text/event-stream; charset=utf-8` — what the Anthropic SDK's SSE
//!   parser sniffs on. Any other media type makes it fall back to a
//!   plain HTTP client and the streaming UX breaks.
//! - `Cache-Control: no-cache` — keeps Nginx/Cloudflare-style
//!   intermediaries (none in the current deploy, but a safe default)
//!   from buffering events. Anthropic docs recommend it for SSE.
//! - `Connection: close` — the response is not Content-Length
//!   delimited and does not use `Transfer-Encoding: chunked`, so the
//!   only EOF signal the client has is TCP close. The relay loop
//!   drops the TcpStream on BIZ_RELAY_DONE; no keep-alive, no pooling.
//! - Status reason-phrase is literal `OK` even when the upstream
//!   status is 429/500/etc. The reason-phrase is optional per
//!   RFC 7230 §3.1.2 and openclaw's SDK reads only the numeric status.
//!   Changing it would be correct but unverified; leave as-is until
//!   the SDK behavior is confirmed.

/// Compose the fixed SSE response preamble. Caller writes this to the
/// HTTP client before streaming any body bytes. Byte-exact output is
/// pinned by the `preamble_exact_bytes` unit test.
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
        // Byte-exact snapshot. If this test breaks, openclaw's SSE
        // parser likely breaks too — check the Anthropic SDK
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
