//! Minimal HTTP/1.1 response builders for the serve-mode handlers.
//!
//! Covers the two response shapes the CA emits synchronously (non-SSE):
//! - JSON bodies: 200 / 400 / 401 / 404 / 502 with
//!   `Content-Type: application/json`.
//! - Error shapes: `{"error":{"message":"...","type":"proxy_error"}}`
//!   in JSON with a given status.
//!
//! **Not covered**: SSE streaming responses to `POST /` proxy requests
//! — those live in `crate::sse::encoder` + `crate::relay::session`.
//! SSE can't pre-compute `Content-Length`, so it doesn't fit this
//! buffered builder.
//!
//! **Not a full HTTP framework**. Always emits `Connection: close`,
//! never keep-alive — the serve loop is not designed for HTTP/1.1
//! pipelining.
//!
//! # NOTE: this module is not yet wired in
//!
//! The serve-mode handlers in `server::connection` still use inline
//! `format!(...)` + `client.write_all` calls; `HttpResponse::write_to`
//! is reserved for a future migration. It's kept here so a
//! sibling-but-untested API doesn't appear out of thin air the day we
//! need it.

use std::io::{self, Write};

/// A fully-buffered HTTP response. Not suitable for streaming —
/// [`body`] is held in memory and `Content-Length` is computed from it.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    status: u16,
    status_text: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    /// `200 OK` + `application/json`.
    pub fn json_ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            status_text: "OK",
            content_type: "application/json",
            body: body.into(),
        }
    }

    /// JSON response with an arbitrary non-2xx status and
    /// `{"error":{"message":"...","type":"proxy_error"}}` body shape.
    /// openclaw + pytest `format/test_proxy_format.py` both grep on
    /// this exact shape; do not reword.
    pub fn proxy_error(status: u16, message: &str) -> Self {
        // Naive double-quote formatting: a `message` containing `"`
        // would produce invalid JSON. Preserved deliberately — any
        // tightening is a wire-format change that would trip openclaw
        // and existing string matching. Revisit only with Phase 2's
        // HTTP framework migration.
        let body = format!(
            "{{\"error\":{{\"message\":\"{message}\",\"type\":\"proxy_error\"}}}}"
        );
        Self {
            status,
            status_text: status_text_for(status),
            content_type: "application/json",
            body: body.into_bytes(),
        }
    }

    /// JSON response with a custom status code and arbitrary body.
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            status_text: status_text_for(status),
            content_type: "application/json",
            body: body.into(),
        }
    }

    /// Write the full response (status line + headers + blank line + body)
    /// to the given writer. Does not flush — callers that need SSE-style
    /// immediacy should call `flush()` explicitly.
    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let header = format!(
            "HTTP/1.1 {status} {text}\r\n\
             Content-Type: {ct}\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n",
            status = self.status,
            text = self.status_text,
            ct = self.content_type,
            len = self.body.len(),
        );
        w.write_all(header.as_bytes())?;
        w.write_all(&self.body)?;
        Ok(())
    }

    /// Accessors for tests / introspection.
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Map common HTTP status codes to their reason-phrase. Not exhaustive —
/// only covers codes the CA emits in practice. Unknown codes fall back
/// to `"Error"`, which matches `send_error`'s generic phrasing.
fn status_text_for(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(resp: &HttpResponse) -> Vec<u8> {
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn json_ok_has_200_status_and_correct_length() {
        let r = HttpResponse::json_ok(r#"{"ok":true}"#);
        let wire = render(&r);
        let text = String::from_utf8(wire).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "wire:\n{text}");
        assert!(text.contains("Content-Type: application/json"));
        assert!(text.contains("Content-Length: 11"));
        assert!(text.ends_with(r#"{"ok":true}"#));
    }

    #[test]
    fn proxy_error_shape_matches_pre_refactor_format() {
        // The body shape is part of the openclaw-visible contract — any
        // change would break test_proxy_format.py. Lock it down here.
        let r = HttpResponse::proxy_error(400, "invalid JSON");
        let text = String::from_utf8(render(&r)).unwrap();
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(
            text.contains(r#"{"error":{"message":"invalid JSON","type":"proxy_error"}}"#),
            "wire:\n{text}"
        );
    }

    #[test]
    fn unknown_status_falls_back_to_error_reason() {
        let r = HttpResponse::proxy_error(599, "weird");
        let text = String::from_utf8(render(&r)).unwrap();
        assert!(text.starts_with("HTTP/1.1 599 Error\r\n"), "wire:\n{text}");
    }

    #[test]
    fn connection_close_is_always_set() {
        // The serve loop is single-request; keep-alive is unsupported.
        // Phase 2's HTTP framework migration can revisit.
        for r in [
            HttpResponse::json_ok(""),
            HttpResponse::proxy_error(502, "boom"),
            HttpResponse::json(401, ""),
        ] {
            let text = String::from_utf8(render(&r)).unwrap();
            assert!(text.contains("Connection: close"), "missing close:\n{text}");
        }
    }

    #[test]
    fn content_length_matches_body_bytes() {
        // Non-ASCII body — bytes count, not chars.
        let r = HttpResponse::json_ok("你好".as_bytes().to_vec());
        let text = String::from_utf8(render(&r)).unwrap();
        assert!(
            text.contains("Content-Length: 6"),
            "UTF-8 '你好' is 6 bytes; wire:\n{text}"
        );
    }

    #[test]
    fn header_block_terminator_is_crlf_crlf() {
        let r = HttpResponse::json_ok("x");
        let wire = render(&r);
        // The double-CRLF should appear exactly once, separating headers
        // from body.
        let count = wire
            .windows(4)
            .filter(|w| *w == b"\r\n\r\n")
            .count();
        assert_eq!(count, 1, "expected single header terminator");
    }
}
