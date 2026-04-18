//! Unified error type for `secret_proxy_ca`.
//!
//! This is the **target** error shape for the refactor. The rest of the crate
//! still returns `Result<T, String>` in many places; an `impl From<Error> for
//! String` bridge below lets migrated modules return `Error` while still
//! feeding into legacy signatures via the `?` operator.
//!
//! ```ignore
//! // refactored module returns Result<T>:
//! fn parse_body(s: &[u8]) -> Result<Body> { … }
//!
//! // legacy caller still signed Result<T, String>:
//! fn legacy() -> std::result::Result<Body, String> {
//!     let body = parse_body(&buf)?;   // Error -> String via bridge
//!     Ok(body)
//! }
//! ```

use thiserror::Error;

/// Crate-wide `Result` alias. Prefer this over `core::result::Result` in
/// new code so the error type stays uniform.
pub type Result<T> = core::result::Result<T, Error>;

/// Canonical error type. Variants partition failures by *layer* rather than
/// underlying source so handlers can pattern-match on what failed instead of
/// parsing strings.
#[derive(Debug, Error)]
pub enum Error {
    /// HTTP request parsing or framing failed (malformed request line,
    /// bad headers, unexpected EOF before body).
    #[error("http parse: {0}")]
    HttpParse(String),

    /// A `TEEC_InvokeCommand` call returned a non-zero return code.
    /// `rc` is the raw TEEC return value (e.g. `0xFFFF000E` =
    /// `TEEC_ERROR_COMMUNICATION`).
    #[error("teec invoke cmd={cmd_id:#x} rc={rc:#x}")]
    Teec { cmd_id: u32, rc: u32 },

    /// Upstream I/O (TCP to the LLM API, read/write/shutdown) failed.
    #[error("upstream io: {0}")]
    UpstreamIo(#[source] std::io::Error),

    /// The TA returned a non-success business code. `code` is one of
    /// `constants::BIZ_*`. `msg` carries the TA's diagnostic string.
    #[error("biz error: code={code:#x} msg={msg}")]
    Biz { code: u32, msg: String },

    /// Admin-API authentication rejected a request (missing env var,
    /// token too short, token mismatch).
    #[error("admin auth: {0}")]
    AdminAuth(&'static str),

    /// JSON serialize/deserialize of a wire-protocol struct failed.
    #[error("wire: {0}")]
    Wire(#[from] serde_json::Error),

    /// Configuration problem (missing required env var, invalid flag
    /// at startup). Distinct from `AdminAuth` because this happens before
    /// any request is served.
    #[error("config: {0}")]
    Config(String),

    /// Local I/O unrelated to upstream or TEEC — typically socket bind,
    /// file read, etc.
    #[error("io: {0}")]
    Io(#[source] std::io::Error),

    /// Catch-all for messages that don't yet fit a specific variant.
    /// Intentionally ergonomic during the refactor; should shrink as the
    /// rest of the code migrates to typed variants.
    #[error("{0}")]
    Other(String),
}

/// Migration bridge: legacy code throughout the crate still uses
/// `Result<T, String>`. Allowing `Error -> String` keeps refactored modules
/// returning `Result<T>` while legacy call sites compose via `?`.
///
/// This bridge is expected to disappear once all modules migrate — having
/// it explicit here (vs. relying on `Display`) makes the dependency visible
/// and greppable.
impl From<Error> for String {
    fn from(e: Error) -> String {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_teec_contains_cmd_id_and_rc() {
        // Display format is load-bearing: ops tooling greps for cmd_id + rc.
        let e = Error::Teec {
            cmd_id: 0x0006,
            rc: 0xFFFF000E,
        };
        let s = e.to_string();
        assert!(
            s.contains("0x6"),
            "display should include cmd_id in hex: {s}"
        );
        assert!(
            s.contains("0xffff000e"),
            "display should include rc in hex: {s}"
        );
    }

    #[test]
    fn from_serde_json_error_uses_wire_variant() {
        // The #[from] attribute should produce the Wire variant automatically.
        // If someone accidentally breaks that (e.g. drops #[from] during a
        // refactor), ? on serde_json::Error would stop compiling.
        let parse_res: std::result::Result<serde_json::Value, serde_json::Error> =
            serde_json::from_str("not-json");
        let e: Error = parse_res.unwrap_err().into();
        match e {
            Error::Wire(_) => {}
            other => panic!("expected Wire variant, got {other:?}"),
        }
    }

    #[test]
    fn to_string_bridge_preserves_message() {
        // The From<Error> for String bridge is load-bearing during migration:
        // legacy Result<_, String> signatures compose with Result<T> via ?.
        let e = Error::AdminAuth("missing token");
        let s: String = e.into();
        assert!(s.contains("admin auth"), "bridge lost display prefix: {s}");
        assert!(
            s.contains("missing token"),
            "bridge lost inner message: {s}"
        );
    }
}
