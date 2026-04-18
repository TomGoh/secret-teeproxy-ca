//! Upstream TCP socket abstraction for the relay loop.
//!
//! The relay's only I/O contract with the LLM API server is:
//! "connect once, read ciphertext bytes, write TLS bytes back,
//! tear down when done." `trait Upstream` makes that contract
//! injectable so integration tests can script a byte-level trace
//! without a real `TcpListener` and SSL peer.
//!
//! # Why not `impl Read + Write`?
//!
//! The standard-library traits let a caller do any of ~20 operations
//! (seeking, slices, line-buffered reads, etc.); the relay loop only
//! ever needs two of them. A narrow trait lets `MockUpstream` have a
//! small surface to uphold, and makes "did we write these bytes to
//! the upstream?" assertions read cleanly in tests (`mock.writes()`).
//!
//! # Timeouts
//!
//! `TcpUpstream::connect` sets a 120-second read timeout. The relay
//! loop surfaces a timeout as the 504 Gateway Timeout response (see
//! `relay::session`). Longer timeouts mask upstream deadlocks as
//! transient; shorter ones trip on slow-but-working LLM responses.
//! 120s is the empirically-settled middle ground.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Narrow IO trait the relay loop uses to talk to an upstream server.
/// Production impl: [`TcpUpstream`]. Test impl: [`MockUpstream`].
pub trait Upstream {
    /// Read up to `buf.len()` bytes. `Ok(0)` = EOF. The relay loop
    /// tracks a "saw_eof" flag separately so two consecutive EOFs
    /// without intervening TA progress become
    /// `"server closed before relay completed"`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write the whole buffer or return an error. Used for TLS
    /// handshake continuation and post-decrypt TLS acks / close_notify.
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
}

/// Production [`Upstream`] backed by a `TcpStream` with a 120s read
/// timeout (see module docs for rationale).
pub struct TcpUpstream {
    tcp: TcpStream,
}

impl TcpUpstream {
    /// Connect to `target` (`host:port` form) and configure the read
    /// timeout. Any `io::Error` from connect or `set_read_timeout`
    /// propagates — the relay adapter maps this to a 502 response to
    /// openclaw.
    pub fn connect(target: &str) -> io::Result<Self> {
        let tcp = TcpStream::connect(target)?;
        tcp.set_read_timeout(Some(Duration::from_secs(120)))?;
        Ok(Self { tcp })
    }
}

impl Upstream for TcpUpstream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.read(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.tcp.write_all(buf)
    }
}

// --- Mock, gated on test-support ------------------------------------------
//
// Needed both by unit tests inside this crate (`#[cfg(test)]`) and by
// the integration test at `tests/serve_proxy_sse.rs` which imports
// `secret_proxy_ca` as a library with `--features test-support`. The
// `cfg(any(...))` pair is the standard idiom for "test-only in unit
// tests, feature-gated for integration tests."

#[cfg(any(test, feature = "test-support"))]
mod mock {
    use super::{Read, Write, io};
    use std::collections::VecDeque;

    /// One scripted result for the next `read()` call. Variants:
    /// - `Ok(bytes)` — copy `bytes` into the caller's buffer (truncated
    ///   if the buffer is smaller).
    /// - `Err(kind)` — return an `io::Error` with the given `ErrorKind`
    ///   and an empty message. Useful for exercising the adapter's
    ///   `TimedOut` / `WouldBlock` / other branches.
    pub enum ScriptedRead {
        Ok(Vec<u8>),
        Err(io::ErrorKind),
    }

    /// Scripted [`Upstream`] impl for unit + integration tests.
    ///
    /// Feed it with `queue_read(data)` / `queue_read_eof()` /
    /// `queue_read_err(kind)`, run the code under test, inspect writes
    /// via `writes()` after the fact.
    ///
    /// `read()` pops the next script entry; if the script is empty it
    /// returns `Ok(0)` (EOF) — this matches the real-world "upstream
    /// closed after sending everything" state and means tests don't
    /// need to queue a trailing explicit EOF just to end the loop.
    pub struct MockUpstream {
        scripted: VecDeque<ScriptedRead>,
        writes: Vec<Vec<u8>>,
    }

    impl Default for MockUpstream {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockUpstream {
        pub fn new() -> Self {
            Self {
                scripted: VecDeque::new(),
                writes: Vec::new(),
            }
        }

        pub fn queue_read(&mut self, data: Vec<u8>) -> &mut Self {
            self.scripted.push_back(ScriptedRead::Ok(data));
            self
        }

        pub fn queue_read_eof(&mut self) -> &mut Self {
            self.scripted.push_back(ScriptedRead::Ok(Vec::new()));
            self
        }

        pub fn queue_read_err(&mut self, kind: io::ErrorKind) -> &mut Self {
            self.scripted.push_back(ScriptedRead::Err(kind));
            self
        }

        /// All bytes written via `write_all`, in order. Each element is
        /// one `write_all` call (not concatenated) so tests can assert
        /// "the first TLS handshake write was exactly these bytes".
        pub fn writes(&self) -> &[Vec<u8>] {
            &self.writes
        }

        /// Total bytes written across all calls, concatenated. Useful
        /// when the test doesn't care about per-call chunking.
        pub fn total_written(&self) -> Vec<u8> {
            self.writes.iter().flat_map(|v| v.iter().copied()).collect()
        }
    }

    impl super::Upstream for MockUpstream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.scripted.pop_front() {
                Some(ScriptedRead::Ok(data)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok(n)
                }
                Some(ScriptedRead::Err(kind)) => Err(io::Error::new(kind, "mock upstream")),
                None => Ok(0),
            }
        }

        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.writes.push(buf.to_vec());
            Ok(())
        }
    }

    // --- Unit tests live here so `Read`/`Write` stay imported ----------
    //
    // They test the mock itself. The adapter-side tests live in
    // `relay::session` (unit) and `tests/serve_proxy_sse.rs` (integration).
    #[cfg(test)]
    mod tests {
        use super::super::Upstream;
        use super::MockUpstream;
        use std::io;

        #[test]
        fn read_pops_scripted_bytes_in_order() {
            let mut m = MockUpstream::new();
            m.queue_read(b"abc".to_vec()).queue_read(b"de".to_vec());
            let mut buf = [0u8; 16];
            let n1 = m.read(&mut buf).unwrap();
            assert_eq!(&buf[..n1], b"abc");
            let n2 = m.read(&mut buf).unwrap();
            assert_eq!(&buf[..n2], b"de");
        }

        #[test]
        fn read_truncates_when_buffer_smaller() {
            let mut m = MockUpstream::new();
            m.queue_read(b"hello world".to_vec());
            let mut buf = [0u8; 5];
            let n = m.read(&mut buf).unwrap();
            assert_eq!(n, 5);
            assert_eq!(&buf, b"hello");
            // The un-delivered tail is dropped — not buffered for next call.
            // This matches TcpStream::read semantics (read once into buffer).
            let n2 = m.read(&mut buf).unwrap();
            assert_eq!(n2, 0, "no more scripted reads → EOF");
        }

        #[test]
        fn empty_script_returns_eof() {
            let mut m = MockUpstream::new();
            let mut buf = [0u8; 16];
            let n = m.read(&mut buf).unwrap();
            assert_eq!(n, 0);
        }

        #[test]
        fn queue_read_eof_is_immediate_zero() {
            let mut m = MockUpstream::new();
            m.queue_read_eof().queue_read(b"unreachable".to_vec());
            let mut buf = [0u8; 16];
            assert_eq!(m.read(&mut buf).unwrap(), 0);
            // Second read also returns 0 but reads the "unreachable" payload
            // since queue_read_eof only pushes an empty Ok.
            let n2 = m.read(&mut buf).unwrap();
            assert_eq!(&buf[..n2], b"unreachable");
        }

        #[test]
        fn queue_read_err_surfaces_as_io_error() {
            let mut m = MockUpstream::new();
            m.queue_read_err(io::ErrorKind::TimedOut);
            let mut buf = [0u8; 16];
            let err = m.read(&mut buf).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        }

        #[test]
        fn write_all_records_per_call() {
            let mut m = MockUpstream::new();
            m.write_all(b"first").unwrap();
            m.write_all(b"second").unwrap();
            assert_eq!(m.writes().len(), 2);
            assert_eq!(m.writes()[0], b"first".to_vec());
            assert_eq!(m.writes()[1], b"second".to_vec());
            assert_eq!(m.total_written(), b"firstsecond".to_vec());
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use mock::{MockUpstream, ScriptedRead};
