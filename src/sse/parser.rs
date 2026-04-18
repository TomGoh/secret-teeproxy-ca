//! Pure SSE event parser.
//!
//! Takes a byte buffer containing one or more SSE frames and returns a
//! `Vec<SseEvent>` — the Anthropic event types the CA's logger cares
//! about. Unknown event types land in [`SseEvent::Other`] so the caller
//! can log them for debugging without erroring.
//!
//! # Scope
//!
//! This parser exists for observability, not correctness — the CA
//! forwards the raw byte stream verbatim to openclaw; it just also
//! parses the bytes in-process so `RUST_LOG=info` shows the LLM's
//! actual words in the daemon log. Any parse failure is silently
//! skipped — observability is never allowed to break a request.
//!
//! # Why "data:" only
//!
//! Anthropic's SSE responses follow the shape:
//!
//! ```text
//! event: message_delta
//! data: {"type":"message_delta","usage":...}
//!
//! event: message_stop
//! data: {"type":"message_stop"}
//!
//! ```
//!
//! The `type` field inside the JSON mirrors the `event:` line, so
//! parsing only `data:` lines and reading `event["type"]` is
//! equivalent — the `event:` line is ignored.
//!
//! # `[DONE]` sentinel
//!
//! Anthropic doesn't emit `data: [DONE]`, but OpenAI-compatible
//! upstreams routed through this proxy do. See [`SseEvent::Done`].

use log::info;

/// One parsed Anthropic SSE event. Carries the minimal fields the
/// logger actually uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseEvent {
    /// `{"type":"message_start", "message": {"id":..., "model":...}}`
    MessageStart { model: String, id: String },
    /// `{"type":"message_delta", "usage":...}`. The raw usage object is
    /// kept as a JSON string so the logger can print it verbatim
    /// without re-walking the tree.
    MessageDelta { usage_json: String },
    /// `{"type":"message_stop"}`
    MessageStop,
    /// `{"type":"content_block_start", "content_block":{"type":"text"|"thinking"|...}}`
    ContentBlockStart { block_type: String },
    /// `{"type":"content_block_delta", "delta":{...}}`
    ContentBlockDelta(DeltaContent),
    /// The `data: [DONE]` sentinel. Not used by Anthropic but kept for
    /// OpenAI-compatible upstreams routed through the same proxy.
    Done,
    /// A parsed JSON event whose `type` was not one we specialize on.
    /// Carries the raw `type` string for the logger.
    Other(String),
}

/// Payload of a `content_block_delta` event. Anthropic uses
/// `text_delta` for visible text and `thinking_delta` for the
/// extended-thinking tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaContent {
    Text(String),
    Thinking(String),
    /// Any other delta type (e.g. `input_json_delta` for tool use). We
    /// don't log the payload for these — they are usually large and
    /// binary-ish.
    Other(String),
}

/// Parse all `data:` lines in `data` and return one [`SseEvent`] per
/// successfully-decoded event. Malformed lines and non-data lines are
/// silently skipped.
///
/// Input is treated as UTF-8; invalid UTF-8 makes the whole buffer
/// yield an empty `Vec` — observability never breaks a request.
pub fn parse_events(data: &[u8]) -> Vec<SseEvent> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(ev) = parse_one_line(line) {
            out.push(ev);
        }
    }
    out
}

fn parse_one_line(line: &str) -> Option<SseEvent> {
    let payload = line.strip_prefix("data: ")?;
    if payload == "[DONE]" {
        return Some(SseEvent::Done);
    }
    let event: serde_json::Value = serde_json::from_str(payload).ok()?;
    let event_type = event.get("type")?.as_str()?.to_string();
    match event_type.as_str() {
        "message_start" => {
            let msg = event.get("message")?;
            let model = msg
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let id = msg
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            Some(SseEvent::MessageStart { model, id })
        }
        "message_delta" => {
            // Preserve the exact JSON text of the `usage` object for
            // logging. If `usage` is missing, fall through to Other.
            let usage = event.get("usage")?;
            Some(SseEvent::MessageDelta {
                usage_json: usage.to_string(),
            })
        }
        "message_stop" => Some(SseEvent::MessageStop),
        "content_block_start" => {
            let cb = event.get("content_block")?;
            let block_type = cb
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            Some(SseEvent::ContentBlockStart { block_type })
        }
        "content_block_delta" => {
            let delta = event.get("delta")?;
            let delta_type = delta.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let content = match delta_type {
                "text_delta" => {
                    let t = delta
                        .get("text")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    DeltaContent::Text(t)
                }
                "thinking_delta" => {
                    let t = delta
                        .get("thinking")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    DeltaContent::Thinking(t)
                }
                other => DeltaContent::Other(other.to_string()),
            };
            Some(SseEvent::ContentBlockDelta(content))
        }
        other => Some(SseEvent::Other(other.to_string())),
    }
}

/// Log one parsed event at the appropriate level. Message shapes
/// (`◄ message_stop`, `◄ [thinking]`, etc.) are what operators grep
/// for in `daemon.log`; preserve them when editing.
pub fn log_event(ev: &SseEvent) {
    match ev {
        SseEvent::MessageStart { model, id } => {
            info!("◄ message_start (model={model}, id={id})");
        }
        SseEvent::MessageDelta { usage_json } => {
            info!("\n◄ message_delta (usage: {usage_json})");
        }
        SseEvent::MessageStop => {
            info!("\n◄ message_stop");
        }
        SseEvent::ContentBlockStart { block_type } => {
            // Preserve the `[thinking]` / `[text]` / `[block:<other>]`
            // shape from log_sse_content.
            match block_type.as_str() {
                "thinking" => info!("\n◄ [thinking]"),
                "text" => info!("\n◄ [text]"),
                other => info!("\n◄ [block:{other}]"),
            }
        }
        SseEvent::ContentBlockDelta(DeltaContent::Text(t)) => {
            // Per-token stdout print — matches the `eprint!("{t}")`
            // in log_sse_content. Using `eprint!` not `info!` because
            // the logger adds prefixes that break token-level flow.
            eprint!("{t}");
        }
        SseEvent::ContentBlockDelta(DeltaContent::Thinking(t)) => {
            eprint!("{t}");
        }
        SseEvent::ContentBlockDelta(DeltaContent::Other(_)) => {
            // Silent — tool_use / input_json deltas are too chatty.
        }
        SseEvent::Done => {
            info!("◄ [DONE]");
        }
        SseEvent::Other(_) => {
            // Unknown event types are noise; swallow. Operators can
            // RUST_LOG=debug to inspect raw bytes if needed.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_nothing() {
        assert_eq!(parse_events(b""), vec![]);
    }

    #[test]
    fn non_data_lines_are_ignored() {
        let input = b"event: message_start\n: a comment\nretry: 3000\n\n";
        assert_eq!(parse_events(input), vec![]);
    }

    #[test]
    fn malformed_json_in_data_line_is_skipped() {
        let input = b"data: {this is not json\n\n";
        assert_eq!(parse_events(input), vec![]);
    }

    #[test]
    fn non_utf8_input_yields_nothing() {
        // Invalid UTF-8: 0xFF is never a valid continuation byte on
        // its own, and the bytes before it form an incomplete seq.
        let input = &[b'd', b'a', b't', b'a', b':', b' ', 0xFF, 0xFE][..];
        assert_eq!(parse_events(input), vec![]);
    }

    #[test]
    fn message_start_parsed() {
        let input =
            b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"model\":\"claude-x\"}}\n\n";
        assert_eq!(
            parse_events(input),
            vec![SseEvent::MessageStart {
                model: "claude-x".into(),
                id: "msg_01".into(),
            }]
        );
    }

    #[test]
    fn message_start_missing_fields_defaults_to_question_mark() {
        // Anthropic always sets model+id, but we defensively parse.
        let input = b"data: {\"type\":\"message_start\",\"message\":{}}\n\n";
        assert_eq!(
            parse_events(input),
            vec![SseEvent::MessageStart {
                model: "?".into(),
                id: "?".into(),
            }]
        );
    }

    #[test]
    fn content_block_start_text_and_thinking() {
        let input = b"data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"text\"}}\n\
                     data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"thinking\"}}\n\
                     data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\"}}\n";
        assert_eq!(
            parse_events(input),
            vec![
                SseEvent::ContentBlockStart { block_type: "text".into() },
                SseEvent::ContentBlockStart { block_type: "thinking".into() },
                SseEvent::ContentBlockStart { block_type: "tool_use".into() },
            ]
        );
    }

    #[test]
    fn text_delta_extracted() {
        let input = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n";
        assert_eq!(
            parse_events(input),
            vec![SseEvent::ContentBlockDelta(DeltaContent::Text("Hello".into()))]
        );
    }

    #[test]
    fn thinking_delta_extracted() {
        let input = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}\n";
        assert_eq!(
            parse_events(input),
            vec![SseEvent::ContentBlockDelta(DeltaContent::Thinking("hmm".into()))]
        );
    }

    #[test]
    fn input_json_delta_is_other() {
        let input = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":\"}}\n";
        assert_eq!(
            parse_events(input),
            vec![SseEvent::ContentBlockDelta(DeltaContent::Other("input_json_delta".into()))]
        );
    }

    #[test]
    fn message_delta_preserves_usage_json() {
        let input = b"data: {\"type\":\"message_delta\",\"usage\":{\"input\":7,\"output\":19}}\n";
        let got = parse_events(input);
        assert_eq!(got.len(), 1);
        if let SseEvent::MessageDelta { usage_json } = &got[0] {
            // Normalize via re-parse so we don't pin on field order.
            let v: serde_json::Value = serde_json::from_str(usage_json).unwrap();
            assert_eq!(v["input"], 7);
            assert_eq!(v["output"], 19);
        } else {
            panic!("expected MessageDelta, got {:?}", got[0]);
        }
    }

    #[test]
    fn message_stop_parsed() {
        let input = b"data: {\"type\":\"message_stop\"}\n";
        assert_eq!(parse_events(input), vec![SseEvent::MessageStop]);
    }

    #[test]
    fn done_sentinel_parsed() {
        // Anthropic doesn't emit this, but OpenAI-compatible proxies do.
        let input = b"data: [DONE]\n\n";
        assert_eq!(parse_events(input), vec![SseEvent::Done]);
    }

    #[test]
    fn unknown_type_becomes_other() {
        let input = b"data: {\"type\":\"ping\"}\n";
        assert_eq!(parse_events(input), vec![SseEvent::Other("ping".into())]);
    }

    #[test]
    fn multiple_events_in_one_buffer() {
        // Real Anthropic stream: a message_start, a text delta, and a stop.
        let input = b"event: message_start\n\
                      data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_42\",\"model\":\"claude-x\"}}\n\
                      \n\
                      event: content_block_delta\n\
                      data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\
                      \n\
                      data: {\"type\":\"message_stop\"}\n";
        assert_eq!(
            parse_events(input),
            vec![
                SseEvent::MessageStart {
                    model: "claude-x".into(),
                    id: "msg_42".into(),
                },
                SseEvent::ContentBlockDelta(DeltaContent::Text("Hi".into())),
                SseEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn data_line_without_trailing_newline_still_parses() {
        // `str::lines()` yields the final line even without a terminator.
        let input = b"data: {\"type\":\"message_stop\"}";
        assert_eq!(parse_events(input), vec![SseEvent::MessageStop]);
    }

    #[test]
    fn event_type_missing_entirely_is_skipped() {
        // `{}` has no type field; should be skipped (no SseEvent).
        let input = b"data: {}\n";
        assert_eq!(parse_events(input), vec![]);
    }

    // ----- Lightweight round-trip test (no proptest crate) ------
    // Feed N hand-crafted SSE events through the parser and assert
    // the output matches. Not a property test proper, but exercises
    // the shape contract between "what we write" and "what we parse".
    #[test]
    fn round_trip_stop_and_done_and_ping() {
        let body = "data: {\"type\":\"message_stop\"}\n\
                    data: [DONE]\n\
                    data: {\"type\":\"ping\"}\n";
        assert_eq!(
            parse_events(body.as_bytes()),
            vec![
                SseEvent::MessageStop,
                SseEvent::Done,
                SseEvent::Other("ping".into()),
            ]
        );
    }
}
