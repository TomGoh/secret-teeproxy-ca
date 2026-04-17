//! Minimal HTTP/1.1 request parser for the serve-mode handlers.
//!
//! Scope: the CA accepts a handful of routes (`/health`, `/admin/keys/*`,
//! `/`, `/proxy`) from `openclaw-minimax-secret-proxy`. That's it. This
//! parser handles exactly that surface — no HTTP/2, no keep-alive,
//! no pipelining, no chunked request bodies. Anything fancier is expected
//! to 400.
//!
//! The parser is a straight byte-level lift of the code that used to live
//! inline at the top of `serve::handle_http_connection`. Behavior is
//! preserved exactly (same method uppercasing, same Content-Length lookup,
//! same body read-to-completion); the wire format is not touched.

use std::io::{BufRead, Read};

use super::headers::normalize_http_path;

/// A parsed HTTP request with body already read into memory.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Uppercase HTTP method (`GET`, `POST`, …). Normalized via
    /// `to_ascii_uppercase` so downstream routing can match case-sensitively.
    pub method: String,
    /// Query-stripped, trimmed path. `GET /health?foo=1 HTTP/1.1` →
    /// `path = "/health"`.
    pub path: String,
    /// Raw path as it appeared on the request line, including any query
    /// string. Retained so future handlers can inspect query parameters
    /// without re-parsing the raw line.
    pub raw_path: String,
    /// Raw header block (the lines between the request line and the blank
    /// terminator, joined with the original `\r\n`). Kept as a string to
    /// interop with the existing `header_value()` helper.
    pub headers_text: String,
    /// `Content-Length` as parsed from headers. `0` if header is absent
    /// or unparseable — consistent with pre-refactor behavior.
    pub content_length: usize,
    /// Body bytes exactly `content_length` long. Empty for requests
    /// without a body.
    pub body: Vec<u8>,
}

/// Parse a single HTTP/1.1 request off a buffered reader, consuming the
/// request line, headers, blank line terminator, and `Content-Length`
/// bytes of body.
///
/// Errors:
/// - Connection closed mid-request (I/O error surfaces verbatim)
/// - Body read short of `Content-Length` (socket closed early)
///
/// Does **not** check for oversize headers, oversize body, or slow clients.
/// Those hardening checks belong in Phase 2 (`docs/phase2-improvements.md`
/// §2 HTTP Connection Management); Step 3 preserves the pre-refactor
/// lenient behavior byte-for-byte so pytest Characterization Tests stay
/// green.
pub fn parse_request<R: BufRead>(reader: &mut R) -> Result<HttpRequest, String> {
    // --- Request line ----------------------------------------------------
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("read request line: {e}"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let raw_path = parts.next().unwrap_or("/").to_string();
    let path = normalize_http_path(&raw_path).to_string();

    // --- Headers until blank line ---------------------------------------
    let mut headers_text = String::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read header line: {e}"))?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        headers_text.push_str(&line);
    }

    // --- Content-Length (case-insensitive scan of the raw block) --------
    // We intentionally use the same all-lowercase heuristic as pre-refactor
    // code for byte-identical behavior. Duplicate `Content-Length` headers
    // or malformed values silently default to `0`, which is how the original
    // parser behaved.
    let content_length = headers_text
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("content-length:") {
                lower
                    .trim_start_matches("content-length:")
                    .trim()
                    .parse::<usize>()
                    .ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    // --- Body ------------------------------------------------------------
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("read body: {e}"))?;
    }

    Ok(HttpRequest {
        method,
        path,
        raw_path,
        headers_text,
        content_length,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(raw: &[u8]) -> Result<HttpRequest, String> {
        let mut reader = Cursor::new(raw);
        parse_request(&mut reader)
    }

    #[test]
    fn get_health_no_body() {
        let req = parse(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/health");
        assert_eq!(req.content_length, 0);
        assert!(req.body.is_empty());
    }

    #[test]
    fn method_is_uppercased() {
        // Lowercase on the wire → uppercase on the struct (matches
        // pre-refactor which called to_ascii_uppercase unconditionally).
        let req = parse(b"get /health HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(req.method, "GET");
    }

    #[test]
    fn query_string_stripped_from_path() {
        let req = parse(b"GET /health?probe=deep HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(req.path, "/health");
        assert_eq!(req.raw_path, "/health?probe=deep");
    }

    #[test]
    fn post_with_content_length_body() {
        let raw = b"POST /admin/keys/slots HTTP/1.1\r\n\
                    Content-Length: 13\r\n\
                    Content-Type: application/json\r\n\
                    \r\n\
                    {\"slot\":999}\n";
        let req = parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.content_length, 13);
        assert_eq!(req.body, b"{\"slot\":999}\n");
    }

    #[test]
    fn missing_content_length_defaults_to_zero() {
        // Pre-refactor behavior: no Content-Length → parse as 0, read
        // zero body bytes. Don't error (lenient).
        let req = parse(b"POST / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(req.content_length, 0);
        assert!(req.body.is_empty());
    }

    #[test]
    fn content_length_case_insensitive() {
        let req = parse(
            b"POST / HTTP/1.1\r\ncontent-length: 2\r\n\r\nok",
        )
        .unwrap();
        assert_eq!(req.content_length, 2);
        assert_eq!(req.body, b"ok");
    }

    #[test]
    fn malformed_content_length_silently_falls_to_zero() {
        // Pre-refactor: `parse::<usize>().ok()` swallows parse errors.
        // Preserve that. (Phase 2 hardening can tighten.)
        let req = parse(
            b"POST / HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\n",
        )
        .unwrap();
        assert_eq!(req.content_length, 0);
    }

    #[test]
    fn body_read_short_returns_error() {
        // Content-Length = 100 but only 5 body bytes available.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort";
        let err = parse(raw).unwrap_err();
        assert!(
            err.contains("read body"),
            "expected 'read body' in error, got: {err}"
        );
    }

    #[test]
    fn headers_text_preserves_raw_lines() {
        // Downstream consumers (admin audit, header_value lookup) depend
        // on `headers_text` retaining the original CRLF-separated form.
        let req = parse(
            b"GET / HTTP/1.1\r\n\
              X-Foo: 1\r\n\
              X-Bar: 2\r\n\
              \r\n",
        )
        .unwrap();
        assert!(req.headers_text.contains("X-Foo: 1"));
        assert!(req.headers_text.contains("X-Bar: 2"));
        // And does NOT include the blank-line terminator.
        assert!(!req.headers_text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn empty_path_defaults_to_slash() {
        // Pre-refactor: parts.next().unwrap_or("/") — an empty request
        // line should still yield "/" not panic.
        let req = parse(b"POST\r\n\r\n").unwrap();
        assert_eq!(req.path, "/");
    }
}
