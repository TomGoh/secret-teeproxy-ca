//! HTTP byte-level helpers for the CA's serve mode.
//!
//! Scope: just the minimum this CA needs. Not a general HTTP library.
//! - [`headers`] — header lookup, path normalization, constant-time compare.
//! - [`chunked`] — RFC 7230 §4.1 chunked transfer decoder (stateful).
//! - [`request`] — parse a single HTTP/1.1 request from a `BufRead`.
//! - [`response`] — build and write a non-SSE response to a `Write`.
//!
//! All four are unit-testable with pure Rust (no Android target required)
//! and hold no global state. SSE streaming responses are handled
//! separately in `crate::sse` + `crate::relay::core` because they require
//! chunked Transfer-Encoding and cannot pre-compute `Content-Length`.

pub mod chunked;
pub mod headers;
pub mod request;
pub mod response;
