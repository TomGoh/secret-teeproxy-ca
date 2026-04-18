//! RFC 7230 §4.1 chunked transfer decoder.
//!
//! # Why this exists
//!
//! The CA relays decrypted SSE body bytes from the TA to the OpenClaw client.
//! Some upstream servers (notably MiniMax's Anthropic endpoint) emit
//! `Transfer-Encoding: chunked` inside the TLS session, which the TA dutifully
//! decrypts and hands to the CA still-framed. If the CA forwarded those raw
//! bytes to OpenClaw, its SSE parser would choke on the hex size lines.
//!
//! # Statefulness
//!
//! Framing can split across TEEC relay rounds:
//!
//! ```text
//! Round 1:  "10\r\nfirst-8-byte"
//! Round 2:  "s\r\n5\r\nhello\r\n0\r\n\r\n"
//! ```
//!
//! This decoder holds a [`Vec<u8>`] `pending` buffer to reassemble partial
//! size-lines, and a `chunk_remaining` counter to carry unfinished chunk
//! payloads across `feed()` calls.
//!
//! # Lenient fallback (load-bearing)
//!
//! **If framing parse fails for any reason, dump the whole pending
//! buffer as raw bytes.** This tolerance exists because the CA can't
//! always trust upstream's chunked signal, and "garbage in → garbage
//! out" is preferred over dropping data when openclaw is waiting for
//! an SSE frame.
//!
//! Any future move to a Strict mode (panic or `Err` on malformed
//! input) must be a new [`DecoderMode`] variant, not a silent
//! behavior change here.

use log::{debug, warn};

/// Decoder strictness. Currently only `Lenient` is implemented. A
/// `Strict` variant could be added later for test harnesses that want
/// errors on malformed input instead of silent raw fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderMode {
    /// On any parse failure (non-UTF-8 size line, bad hex, missing CRLF),
    /// dump the entire `pending` buffer as-is and continue.
    Lenient,
}

/// Stateful chunked transfer decoder.
///
/// Call [`feed`](Self::feed) with each new slice of upstream body bytes.
/// The returned `Vec<u8>` contains only fully-decoded chunk payload bytes.
/// Any unparseable remainder is retained internally for the next call
/// (or emitted as raw bytes in `Lenient` mode on parse failure).
pub struct ChunkedDecoder {
    /// Bytes still expected to complete the current chunk's payload.
    /// Non-zero when a chunk's size line has been consumed but not all of
    /// its payload has arrived yet.
    chunk_remaining: usize,
    /// Buffered bytes not yet decoded. Includes partial size lines or
    /// partial payload. Drained as decoding progresses.
    pending: Vec<u8>,
    mode: DecoderMode,
}

impl ChunkedDecoder {
    /// New decoder in `Lenient` mode (the only mode currently implemented).
    pub fn new() -> Self {
        Self::with_mode(DecoderMode::Lenient)
    }

    pub fn with_mode(mode: DecoderMode) -> Self {
        Self {
            chunk_remaining: 0,
            pending: Vec::new(),
            mode,
        }
    }

    /// True iff the decoder has buffered data waiting for more input.
    /// Exposed for tests; not needed by normal callers.
    #[cfg(test)]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty() || self.chunk_remaining > 0
    }

    /// Feed a slice of upstream body bytes and return any newly-decoded
    /// payload bytes. Safe to call with `&[]` (returns an empty `Vec`).
    ///
    /// In `Lenient` mode, if a parse error is encountered, the whole
    /// pending buffer (including the just-fed slice) is returned as-is.
    /// See module docs for why this fallback is load-bearing.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);

        let mut result = Vec::with_capacity(self.pending.len());
        let mut pos = 0;

        while pos < self.pending.len() {
            if self.chunk_remaining > 0 {
                // Mid-chunk: drain up to chunk_remaining bytes.
                let available = self.pending.len() - pos;
                let to_copy = available.min(self.chunk_remaining);
                result.extend_from_slice(&self.pending[pos..pos + to_copy]);
                pos += to_copy;
                self.chunk_remaining -= to_copy;

                // End of chunk → expect trailing \r\n.
                if self.chunk_remaining == 0 {
                    if pos + 2 > self.pending.len() {
                        break; // wait for next feed
                    }
                    if &self.pending[pos..pos + 2] == b"\r\n" {
                        pos += 2;
                    } else {
                        debug!("chunked decode: missing chunk CRLF, falling back to raw");
                        return self.fallback_to_raw();
                    }
                }
                continue;
            }

            // Looking for a chunk size line: hex digits followed by \r\n.
            let line_end = match self.pending[pos..]
                .windows(2)
                .position(|w| w == b"\r\n")
            {
                Some(p) => pos + p,
                None => break, // incomplete size line — wait for next feed
            };

            let line = &self.pending[pos..line_end];

            // Parse hex chunk size (ignoring chunk extensions after ';').
            let hex_str = match std::str::from_utf8(line) {
                Ok(s) => s.split(';').next().unwrap_or("").trim(),
                Err(_) => {
                    warn!("chunked decode: non-UTF8 at pos {pos}, falling back to raw");
                    return self.fallback_to_raw();
                }
            };

            if hex_str.is_empty() {
                // Empty line between chunks — skip.
                pos = line_end + 2;
                continue;
            }

            let chunk_size = match usize::from_str_radix(hex_str, 16) {
                Ok(size) => size,
                Err(_) => {
                    debug!(
                        "chunked decode: invalid hex '{hex_str}' at pos {pos}, \
                         falling back to raw"
                    );
                    return self.fallback_to_raw();
                }
            };

            // Skip past the size line + \r\n.
            pos = line_end + 2;

            if chunk_size == 0 {
                // Terminal chunk. Don't try to parse trailers — just stop;
                // anything after stays in pending (rare; typically empty).
                break;
            }

            // Copy chunk data (possibly partial if it spans this feed).
            let available = self.pending.len() - pos;
            let to_copy = available.min(chunk_size);
            result.extend_from_slice(&self.pending[pos..pos + to_copy]);
            pos += to_copy;

            if to_copy < chunk_size {
                // Chunk payload continues into next feed.
                self.chunk_remaining = chunk_size - to_copy;
            } else {
                // Full chunk consumed — skip the trailing \r\n if present.
                if pos + 2 <= self.pending.len() && &self.pending[pos..pos + 2] == b"\r\n" {
                    pos += 2;
                }
            }
        }

        if pos > 0 {
            self.pending.drain(0..pos);
        }
        result
    }

    /// `Lenient` fallback: dump everything buffered as raw bytes and reset
    /// the chunk counter. Do not touch `mode`; the caller's future feeds
    /// may still succeed (e.g. if the malformed bytes were a transient
    /// corruption that's now past).
    fn fallback_to_raw(&mut self) -> Vec<u8> {
        match self.mode {
            DecoderMode::Lenient => {
                self.chunk_remaining = 0;
                std::mem::take(&mut self.pending)
            }
        }
    }
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================
//
// Coverage targets:
// - Single chunk within one feed
// - Hex size line split across two feeds (critical — partial
//   size-lines must be carried in `pending`)
// - Zero terminator
// - Trailing CRLF
// - Oversize / invalid size line → raw fallback in Lenient mode
// - Hex upper + lowercase both parse
// - Chunk data that embeds CRLF bytes (must not be misinterpreted)
// - Chunk payload spans across feeds (chunk_remaining carry)
// - Empty feed is a no-op
// - Hand-rolled "random split points" property test (see
//   `prop_decoder_matches_reference`) against a naive reference oracle.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference oracle: encode a sequence of `payloads` into chunked form,
    /// ending with a zero-terminator. Not a re-implementation of `feed` —
    /// this is the *inverse* (encoder), used to generate valid fixtures
    /// for property tests.
    fn encode_chunked(payloads: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in payloads {
            out.extend_from_slice(format!("{:x}\r\n", p.len()).as_bytes());
            out.extend_from_slice(p);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    #[test]
    fn single_chunk_exact_boundary() {
        let mut d = ChunkedDecoder::new();
        let out = d.feed(b"5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(out, b"hello");
    }

    #[test]
    fn two_chunks_same_feed() {
        let mut d = ChunkedDecoder::new();
        let out = d.feed(b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n");
        assert_eq!(out, b"helloworld");
    }

    #[test]
    fn split_size_line_across_feeds() {
        let mut d = ChunkedDecoder::new();
        // Feed "5\r" — incomplete size line, no \r\n found yet.
        assert_eq!(d.feed(b"5\r"), b"");
        // Feed the "\n" and data — decoder should have buffered "5\r" and
        // finish parsing the size line.
        let out = d.feed(b"\nhello\r\n0\r\n\r\n");
        assert_eq!(out, b"hello");
    }

    #[test]
    fn chunk_payload_spans_across_feeds() {
        // The single most important test: `chunk_remaining` carrying across
        // feed() calls is the stateful heart of the decoder. Size = 0xb = 11
        // bytes payload "HELLO WORLD", split 4 + 7.
        let mut d = ChunkedDecoder::new();
        let out1 = d.feed(b"b\r\nHELL"); // chunk_size=11, only 4 payload bytes arrived
        assert_eq!(out1, b"HELL");
        assert!(d.chunk_remaining > 0, "decoder must carry state across feeds");
        let out2 = d.feed(b"O WORLD\r\n0\r\n\r\n");
        assert_eq!(out2, b"O WORLD");
    }

    #[test]
    fn zero_terminator_without_trailing_crlf() {
        // "0\r\n\r\n" is RFC-compliant. We also accept just "0\r\n" because
        // any trailer/terminator bytes beyond the zero-chunk are left in
        // `pending` but never consumed by relay consumers.
        let mut d = ChunkedDecoder::new();
        let out = d.feed(b"3\r\nfoo\r\n0\r\n");
        assert_eq!(out, b"foo");
    }

    #[test]
    fn empty_feed_is_noop() {
        let mut d = ChunkedDecoder::new();
        assert_eq!(d.feed(b""), b"");
    }

    #[test]
    fn hex_size_uppercase_and_lowercase() {
        let mut a = ChunkedDecoder::new();
        let mut b = ChunkedDecoder::new();
        assert_eq!(a.feed(b"A\r\n0123456789\r\n0\r\n\r\n"), b"0123456789");
        assert_eq!(b.feed(b"a\r\n0123456789\r\n0\r\n\r\n"), b"0123456789");
    }

    #[test]
    fn chunk_with_embedded_crlf_in_data() {
        // If chunk data contains \r\n, the decoder must NOT treat that as
        // a size boundary. This is why chunked encoding uses explicit
        // length prefixes rather than scanning for delimiters.
        let payload = b"foo\r\nbar";
        let mut d = ChunkedDecoder::new();
        let out = d.feed(b"8\r\nfoo\r\nbar\r\n0\r\n\r\n");
        assert_eq!(out, payload);
    }

    #[test]
    fn non_utf8_size_line_falls_back_to_raw() {
        let mut d = ChunkedDecoder::new();
        // Invalid UTF-8 byte 0xC3 0x28 as the "size" line.
        let raw = [0xC3u8, 0x28, b'\r', b'\n', b'x'];
        let out = d.feed(&raw);
        // Lenient: dump everything as raw.
        assert_eq!(out, raw);
    }

    #[test]
    fn invalid_hex_size_falls_back_to_raw() {
        let mut d = ChunkedDecoder::new();
        // "ZZZ" is not hex.
        let raw = b"ZZZ\r\ndata\r\n0\r\n\r\n";
        let out = d.feed(raw);
        assert_eq!(out, raw);
    }

    #[test]
    fn missing_trailing_crlf_falls_back_to_raw() {
        let mut d = ChunkedDecoder::new();
        // Chunk payload "hello" followed by "XY" instead of "\r\n".
        // Then "0\r\n\r\n" — but because of the bad CRLF, the decoder
        // re-enters the size-line branch at pos=8 with pending[8..]="XY0\r\n\r\n",
        // finds the first "\r\n" at offset 3, tries to parse "XY0" as hex,
        // fails, and falls back to raw.
        //
        // `fallback_to_raw` uses `mem::take(&mut pending)` which returns
        // the *entire* pending buffer — it does NOT fold in the partial
        // `result` already decoded. So the final output is the raw
        // original input bytes with any partially-decoded bytes
        // discarded. This is surprising but deliberate: "garbage in →
        // garbage out" beats dropping user-visible content.
        let raw = b"5\r\nhelloXY0\r\n\r\n";
        let out = d.feed(raw);
        assert_eq!(
            out, raw,
            "Lenient fallback must dump the whole raw pending buffer, not the partial result"
        );
    }

    #[test]
    fn proptest_lite_random_split_points() {
        // Lightweight property test (no `proptest` crate dep). Seed
        // a valid encoded stream and feed it at every single-byte
        // boundary to verify the decoder reassembles the original
        // payload byte-for-byte.
        let payloads: Vec<&[u8]> = vec![
            b"hello",
            b"a",
            b"",                        // zero-length data chunks are legal (but will terminate)
            b"a much longer payload string",
            b"foo\r\nbar",
            b"\x00\x01\x02\x03",        // binary content
        ];
        // Filter out the empty payload: a chunk with size=0 would be
        // interpreted as the terminator mid-stream, breaking reassembly.
        let payloads: Vec<&[u8]> = payloads.into_iter().filter(|p| !p.is_empty()).collect();
        let encoded = encode_chunked(&payloads);
        let expected: Vec<u8> = payloads.iter().flat_map(|p| p.iter().copied()).collect();

        for split in 1..encoded.len() {
            let mut d = ChunkedDecoder::new();
            let mut got = d.feed(&encoded[..split]);
            got.extend_from_slice(&d.feed(&encoded[split..]));
            assert_eq!(got, expected, "split point {split} broke reassembly");
        }
    }

    #[test]
    fn decoder_is_reusable_after_terminator() {
        // After reaching the zero-terminator, feeding more bytes is
        // undefined (should never happen in our protocol). Verify the
        // decoder doesn't panic — garbage-in → (mostly) empty-out is fine.
        let mut d = ChunkedDecoder::new();
        assert_eq!(d.feed(b"3\r\nabc\r\n0\r\n\r\n"), b"abc");
        // Further feed: should not panic.
        let _ = d.feed(b"extra garbage");
    }
}
