//! Reads the usage the upstream reported from a copy of the relayed response body. Reading
//! never changes the bytes the caller receives: a parse failure or an exceeded bound only means
//! that no report is written.
//!
//! SGLang facts this relies on (`tests/fixtures/sglang-recorded/`, recorded 23 Nov 2026): a
//! non-streamed answer carries `usage` in its JSON body; a stream asked for `include_usage`
//! sends it in a final chunk with `"choices":[]` before `data: [DONE]`, also when `max_tokens`
//! cut the answer short. Reasoning arrives as a top-level `reasoning_tokens` and as
//! `completion_tokens_details.reasoning_tokens` (or `null`), and is already counted in
//! `completion_tokens`.
//!
//! Only a usage object in the stream's last data event before `[DONE]` counts: an earlier one
//! may be interim. Documents are read with the worker decoder's parser, which refuses duplicate
//! keys, and the envelope, `usage` and any `completion_tokens_details` must be JSON objects.
use crate::{
    provider_http::inference::{json, stream::Sse},
    telemetry::UsageGap,
};
use axum::http::HeaderValue;
use serde_json::{Map, Value};

/// Largest non-streamed body read for usage: the worker decoder's response bound. A larger body
/// is still relayed in full. Streamed events are bounded by the shared SSE framer (128 KiB per
/// line, 256 KiB per event).
pub(super) const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;

/// One upstream usage object with both required counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Usage {
    pub prompt: i64,
    pub completion: i64,
    /// Present when the upstream reported it. Already included in `completion`.
    pub reasoning: Option<i64>,
}

/// A count that is absent or `null` (`Some(None)`), or a non-negative integer that fits a
/// database `bigint`; `None` refuses anything else.
fn count(object: &Map<String, Value>, key: &str) -> Option<Option<i64>> {
    match object.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(n) => n.as_u64().and_then(|n| i64::try_from(n).ok()).map(Some),
    }
}

/// Both counts are required. The two reasoning fields must agree when both are present, and
/// reasoning cannot exceed the completion count that includes it.
fn usage(object: &Map<String, Value>) -> Option<Usage> {
    let detail = match object.get("completion_tokens_details") {
        None | Some(Value::Null) => None,
        Some(Value::Object(details)) => count(details, "reasoning_tokens")?,
        Some(_) => return None,
    };
    let reasoning = match (count(object, "reasoning_tokens")?, detail) {
        (Some(top), Some(detail)) if top != detail => return None,
        (top, detail) => top.or(detail),
    };
    let completion = count(object, "completion_tokens")??;
    if reasoning.is_some_and(|reasoning| reasoning > completion) {
        return None;
    }
    Some(Usage {
        prompt: count(object, "prompt_tokens")??,
        completion,
        reasoning,
    })
}

/// `usage` of one JSON document: `Ok(None)` when absent or `null`.
fn parse(bytes: &[u8]) -> Result<Option<Usage>, UsageGap> {
    let Ok(Value::Object(envelope)) = json::parse(bytes) else {
        return Err(UsageGap::Unparsable);
    };
    match envelope.get("usage") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => usage(object).map(Some).ok_or(UsageGap::Unparsable),
        Some(_) => Err(UsageGap::Unparsable),
    }
}

/// The reader for one 200 response, chosen by its media type.
pub(super) enum Extract {
    Json {
        body: Vec<u8>,
        over: bool,
    },
    Sse {
        framer: Sse,
        usage: Option<Usage>,
        done: bool,
        failed: bool,
    },
}

impl Extract {
    /// `text/event-stream` is read as a stream and anything else as one JSON document.
    pub fn new(content_type: Option<&HeaderValue>) -> Self {
        let streamed = content_type
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"));
        if streamed {
            Self::Sse {
                framer: Sse::default(),
                usage: None,
                done: false,
                failed: false,
            }
        } else {
            Self::Json {
                body: Vec::new(),
                over: false,
            }
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        match self {
            Self::Json { body, over } if !*over => {
                if data.len() > MAX_JSON_BYTES - body.len() {
                    *over = true;
                    *body = Vec::new();
                } else {
                    body.extend_from_slice(data);
                }
            }
            Self::Json { .. } => {}
            Self::Sse {
                framer,
                usage,
                done,
                failed,
            } => {
                for &b in data {
                    if *failed {
                        return;
                    }
                    match framer.byte(b) {
                        Ok(None) => {}
                        Ok(Some(event)) => match (*done, event.data.as_slice()) {
                            // Nothing may follow the terminator.
                            (true, _) => *failed = true,
                            (false, b"[DONE]") => *done = true,
                            // Only the last data event's usage counts.
                            (false, data) => match parse(data) {
                                Ok(found) => *usage = found,
                                Err(_) => *failed = true,
                            },
                        },
                        Err(_) => *failed = true,
                    }
                }
            }
        }
    }

    /// Whether the usage may already be in hand, so the rest of the upstream body is worth
    /// reading after the caller has left: a stream whose last event carried usage, or a JSON
    /// body within its bound (SGLang sends a JSON head only after generating the whole answer).
    pub fn worth_draining(&self) -> bool {
        match self {
            Self::Json { over, .. } => !over,
            Self::Sse { usage, failed, .. } => usage.is_some() && !failed,
        }
    }

    /// The usage of a body that ended cleanly.
    pub fn finish(self) -> Result<Usage, UsageGap> {
        match self {
            Self::Json { over: true, .. } => Err(UsageGap::Unparsable),
            Self::Json { body, .. } => parse(&body)?.ok_or(UsageGap::NoUsage),
            Self::Sse { failed: true, .. } => Err(UsageGap::Unparsable),
            Self::Sse {
                framer,
                usage,
                done,
                ..
            } => {
                if !done || !framer.ended() {
                    return Err(UsageGap::Incomplete);
                }
                usage.ok_or(UsageGap::NoUsage)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: &str = "text/event-stream; charset=utf-8";

    fn read(content_type: &str, pieces: &[&[u8]]) -> Result<Usage, UsageGap> {
        let mut extract = Extract::new(Some(&HeaderValue::from_str(content_type).unwrap()));
        for piece in pieces {
            extract.feed(piece);
        }
        extract.finish()
    }

    fn usage(prompt: i64, completion: i64, reasoning: Option<i64>) -> Usage {
        Usage {
            prompt,
            completion,
            reasoning,
        }
    }

    #[test]
    fn reads_both_reasoning_fields_and_requires_them_to_agree() {
        for (body, expected) in [
            (
                r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"reasoning_tokens":0,"completion_tokens_details":null}}"#,
                Ok(usage(3, 5, Some(0))),
            ),
            (
                r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"completion_tokens_details":{"reasoning_tokens":4}}}"#,
                Ok(usage(3, 5, Some(4))),
            ),
            (
                r#"{"usage":{"prompt_tokens":3,"completion_tokens":5}}"#,
                Ok(usage(3, 5, None)),
            ),
            (
                r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"reasoning_tokens":4,"completion_tokens_details":{"reasoning_tokens":2}}}"#,
                Err(UsageGap::Unparsable),
            ),
            (
                r#"{"usage":{"prompt_tokens":3}}"#,
                Err(UsageGap::Unparsable),
            ),
            (
                r#"{"usage":{"prompt_tokens":9223372036854775808,"completion_tokens":1}}"#,
                Err(UsageGap::Unparsable),
            ),
            (r#"{"usage":null}"#, Err(UsageGap::NoUsage)),
            (r#"{"choices":[]}"#, Err(UsageGap::NoUsage)),
            ("not json", Err(UsageGap::Unparsable)),
        ] {
            assert_eq!(
                read("application/json", &[body.as_bytes()]),
                expected,
                "{body}"
            );
        }
    }

    #[test]
    fn a_stream_counts_only_when_it_reaches_done() {
        let usage_event =
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\n";
        let content = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n";
        assert_eq!(
            read(STREAM, &[content, usage_event, b"data: [DONE]\n\n"]),
            Ok(usage(2, 1, None))
        );
        // Split anywhere, including inside the terminator.
        let whole = [&content[..], usage_event, b"data: [DONE]\n\n"].concat();
        let bytes: Vec<&[u8]> = whole.chunks(1).collect();
        assert_eq!(read(STREAM, &bytes), Ok(usage(2, 1, None)));
        assert_eq!(
            read(STREAM, &[content, usage_event]),
            Err(UsageGap::Incomplete)
        );
        assert_eq!(
            read(STREAM, &[content, usage_event, b"data: [DONE]\n"]),
            Err(UsageGap::Incomplete)
        );
        assert_eq!(
            read(STREAM, &[content, b"data: [DONE]\n\n"]),
            Err(UsageGap::NoUsage)
        );
        assert_eq!(
            read(STREAM, &[usage_event, b"data: [DONE]\n\n", content]),
            Err(UsageGap::Unparsable)
        );
        assert_eq!(
            read(
                STREAM,
                &[b"data: {oops}\n\n", usage_event, b"data: [DONE]\n\n"]
            ),
            Err(UsageGap::Unparsable)
        );
    }

    #[test]
    fn a_stream_counts_only_the_usage_of_its_last_event() {
        let interim =
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\n";
        let null_usage =
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}],\"usage\":null}\n\n";
        let no_usage = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n";
        let last =
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":9}}\n\n";
        let done = b"data: [DONE]\n\n";
        for later in [&null_usage[..], &no_usage[..]] {
            assert_eq!(
                read(STREAM, &[interim, later, done]),
                Err(UsageGap::NoUsage)
            );
            assert_eq!(
                read(STREAM, &[interim, later, last, done]),
                Ok(usage(2, 9, None))
            );
        }
    }

    #[test]
    fn usage_must_be_objects_with_reasoning_inside_completion() {
        for body in [
            r#"[{"usage":{"prompt_tokens":3,"completion_tokens":5}}]"#,
            r#"{"usage":[3,5,null,null]}"#,
            r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"completion_tokens_details":[4]}}"#,
            r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"completion_tokens_details":7}}"#,
            r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"reasoning_tokens":7}}"#,
            r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"completion_tokens_details":{"reasoning_tokens":6}}}"#,
            r#"{"usage":{"prompt_tokens":3.0,"completion_tokens":5}}"#,
            r#"{"usage":{"prompt_tokens":3,"prompt_tokens":4,"completion_tokens":5}}"#,
            r#"{"usage":{"prompt_tokens":3,"completion_tokens":5},"usage":null}"#,
        ] {
            assert_eq!(
                read("application/json", &[body.as_bytes()]),
                Err(UsageGap::Unparsable),
                "{body}"
            );
        }
        let edge = r#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"reasoning_tokens":5,"completion_tokens_details":{"reasoning_tokens":null}}}"#;
        assert_eq!(
            read("application/json", &[edge.as_bytes()]),
            Ok(usage(3, 5, Some(5)))
        );
    }

    #[test]
    fn exceeding_a_parse_bound_gives_up_on_usage_only() {
        let mut extract = Extract::new(None);
        extract.feed(&vec![b' '; MAX_JSON_BYTES]);
        assert!(extract.worth_draining());
        extract.feed(br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#);
        assert!(!extract.worth_draining());
        assert_eq!(extract.finish(), Err(UsageGap::Unparsable));

        // One SSE event longer than the framer's 256 KiB event bound.
        let mut extract = Extract::new(Some(&HeaderValue::from_static(STREAM)));
        let line = format!("data: {}\n", "x".repeat(64 * 1024));
        for _ in 0..5 {
            extract.feed(line.as_bytes());
        }
        extract.feed(b"\ndata: [DONE]\n\n");
        assert_eq!(extract.finish(), Err(UsageGap::Unparsable));
    }

    #[test]
    fn draining_after_the_caller_left_needs_usage_in_hand() {
        let mut extract = Extract::new(Some(&HeaderValue::from_static(STREAM)));
        extract.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n");
        assert!(!extract.worth_draining());
        extract.feed(
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\n",
        );
        assert!(extract.worth_draining());
    }
}
