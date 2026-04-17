//! HTTP byte-level helpers — pure, zero-I/O, no TEEC, no sockets.
//!
//! Scope: just the minimum this CA needs. Not a general HTTP library.
//! - [`headers`] — header lookup, path normalization, constant-time compare.
//! - [`chunked`] — RFC 7230 §4.1 chunked transfer decoder for upstream responses.
//!
//! Everything here is unit-testable with pure Rust (no Android target required).

pub mod chunked;
pub mod headers;
