//! Replays responses recorded from one real SGLang deployment on 23 Nov 2026 through the
//! production decoder (`Gateway::caller`) over the in-process TLS fixture. Provenance, the
//! request each case sent, substitutions and limits: `tests/fixtures/sglang-recorded/README.md`.
//! Tests named `known_gap_*` pin today's behaviour for gaps recorded on issue #9. A later
//! increment is expected to change each of them; update the assertion together with that fix.
use crate::authz::gateway::problem::{Cause, Problem};
use crate::{
    provider_http::{fixture::Reply, inference::*},
    sglang_recorded::*,
    support::*,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// Synthetic substitute for the deployment's served model name.
const MODEL: &str = "recorded-sglang-model";
const CASES: [&str; 12] = [
    "01-models",
    "02-chat-plain",
    "03-chat-stream-usage",
    "04-chat-stream-reasoning",
    "05-chat-stream-tools",
    "06-chat-tools-nonstream",
    "07-chat-stream-length",
    "08-chat-stream-abort",
    "09-responses-plain",
    "10-responses-stream",
    "11-chat-bad-model",
    "14-responses-list",
];
fn sent(case: &str) -> Value {
    serde_json::from_slice(&file(case, "request.json")).unwrap()
}
/// Each JSON document in the body: the whole body, or every SSE `data:` event except `[DONE]`.
fn documents(case: &str) -> Vec<Value> {
    let b = String::from_utf8(body(case)).unwrap();
    if !chunked(case) {
        return serde_json::from_str(&b).into_iter().collect();
    }
    b.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter(|d| *d != "[DONE]")
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}
fn recorded_finish(case: &str) -> Option<String> {
    documents(case)
        .iter()
        .flat_map(|d| d["choices"].as_array().cloned().unwrap_or_default())
        .filter_map(|c| c["finish_reason"].as_str().map(str::to_owned))
        .next_back()
}
fn recorded_usage(case: &str) -> Option<Value> {
    documents(case)
        .into_iter()
        .filter_map(|d| d.get("usage").filter(|u| !u.is_null()).cloned())
        .next_back()
}
fn recorded_content(case: &str) -> String {
    documents(case)
        .iter()
        .flat_map(|d| d["choices"].as_array().cloned().unwrap_or_default())
        .filter_map(|c| c["delta"]["content"].as_str().map(str::to_owned))
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Chunking {
    /// Content-Length body exactly as recorded.
    AsRecorded,
    /// One HTTP chunk per SSE event.
    PerEvent,
    /// One HTTP chunk per byte, splitting UTF-8, JSON tokens and LF event terminators.
    PerByte,
}
fn chunkings(case: &str) -> &'static [Chunking] {
    if chunked(case) {
        &[Chunking::PerEvent, Chunking::PerByte]
    } else {
        &[Chunking::AsRecorded]
    }
}
fn response(case: &str, chunking: Chunking) -> Vec<u8> {
    let body = body(case);
    let mut out = head(case).into_bytes();
    let pieces: Vec<&[u8]> = match chunking {
        Chunking::AsRecorded => {
            out.extend(body);
            return out;
        }
        Chunking::PerByte => body.chunks(1).collect(),
        Chunking::PerEvent => events(&body),
    };
    for piece in pieces {
        out.extend(chunk(piece));
    }
    // An aborted stream closes without the zero-length terminal chunk.
    if case != ABORTED {
        out.extend(b"0\r\n\r\n");
    }
    out
}
/// Rebuild the caller request from the recorded request: prompt, tools and streaming.
fn request(case: &str) -> (Protocol, Request) {
    let r = sent(case);
    let protocol = if r.get("messages").is_some() {
        Protocol::Chat
    } else {
        Protocol::Responses
    };
    let prompt = [
        &r["messages"][0]["content"],
        &r["input"],
        &r["input"][0]["content"],
    ]
    .into_iter()
    .find_map(Value::as_str)
    .unwrap();
    let tools = r["tools"].as_array().map(|tools| {
        tools
            .iter()
            .map(|t| Tool {
                name: t["function"]["name"].as_str().unwrap().into(),
                description: t["function"]["description"].as_str().unwrap().into(),
                parameters: t["function"]["parameters"].clone(),
            })
            .collect()
    });
    let request = Request {
        history: vec![History::User(prompt.into())],
        tools,
        parallel: None,
        stream: r["stream"] == true,
    };
    (protocol, request)
}

struct Replay {
    label: String,
    result: Result<Turn, Error>,
    /// Visible deltas forwarded before the turn ended, concatenated.
    visible: String,
    /// The request core sent to the fixture.
    sent: Value,
    family: bool,
}
impl Replay {
    fn turn(&self) -> &Turn {
        match &self.result {
            Ok(turn) => turn,
            Err(e) => panic!("{}: {e:?}", self.label),
        }
    }
    /// The recorded decoder error, and its ADR 0037 projection on a family-policy route.
    fn failed(&self, plain: Error) {
        let expected = if self.family {
            Error::Gateway(Problem::Failure(Cause::Protocol))
        } else {
            plain
        };
        assert_eq!(
            self.result.as_ref().err(),
            Some(&expected),
            "{}",
            self.label
        );
    }
}

/// Every applicable re-chunking, with and without the family policy.
async fn replays(case: &str, configure: impl Fn(&mut Qualification)) -> Vec<Replay> {
    let mut out = Vec::new();
    for &chunking in chunkings(case) {
        for family in [false, true] {
            let (protocol, request) = request(case);
            let c = catalog(protocol, true);
            let e = effective(&c, false);
            let bytes = response(case, chunking);
            let mock = Mock::new(protocol, move |_| Reply::Bytes(bytes.clone())).await;
            let mut gateway = mock.configured(&e, NORMAL, &configure);
            if family {
                gateway = gateway.with_family_policy_v1();
            }
            let seen = Arc::new(Mutex::new(String::new()));
            let sink = seen.clone();
            let result = gateway
                .caller(&c, &e, &request, Credential::Bearer(TOKEN), move |d| {
                    sink.lock().unwrap().push_str(&d.text);
                    async {}
                })
                .await;
            mock.assert_inference_only(1);
            let sent = mock.captured.lock().unwrap()[0].clone();
            let visible = seen.lock().unwrap().clone();
            out.push(Replay {
                label: format!("{case} {chunking:?} family_policy_v1={family}"),
                result,
                visible,
                sent,
                family,
            });
        }
    }
    out
}

struct Expect {
    finish: &'static str,
    parts: &'static [&'static str],
    reasoning: Option<&'static str>,
    calls: &'static [(&'static str, &'static str)],
    usage: (u64, u64),
}
async fn decodes(case: &str, expect: Expect) {
    assert_eq!(recorded_finish(case).as_deref(), Some(expect.finish));
    for r in replays(case, |_| {}).await {
        let turn = r.turn();
        assert_eq!(turn.answers.len(), 1, "{}", r.label);
        let a = &turn.answers[0];
        assert_eq!(a.choice, 0, "{}", r.label);
        assert_eq!(a.parts, expect.parts, "{}", r.label);
        // Only a streamed turn forwards visible deltas.
        let visible = if chunked(case) {
            expect.parts.concat()
        } else {
            String::new()
        };
        assert_eq!(r.visible, visible, "{}", r.label);
        let reasoning = a.reasoning.as_ref().map(|x| {
            assert_eq!(x.source.format, "reasoning_content", "{}", r.label);
            x.blocks.clone()
        });
        assert_eq!(
            reasoning,
            expect.reasoning.map(|t| vec![json!({"text": t})]),
            "{}",
            r.label
        );
        let CallGroup::Valid(calls) = &a.calls else {
            panic!("{}: invalid call group", r.label)
        };
        let calls: Vec<_> = calls
            .iter()
            .map(|c| (c.id.as_str(), c.name.as_str(), c.arguments.clone()))
            .collect();
        let expected: Vec<_> = expect
            .calls
            .iter()
            .map(|&(id, name)| (id, name, json!({"city":"Paris"})))
            .collect();
        assert_eq!(calls, expected, "{}", r.label);
        let u = turn.usage.as_ref().expect("usage");
        let (input, output) = expect.usage;
        assert_eq!(
            (u.input, u.output),
            (Some(input), Some(output)),
            "{}",
            r.label
        );
        assert_eq!((u.source, u.semantics.as_str()), ("gateway", "final_call"));
    }
}

#[test]
fn recorded_fixture_set_is_complete_and_uses_the_synthetic_model() {
    let mut expected = vec!["README.md".to_owned()];
    for case in CASES {
        expected.extend(["body", "headers"].map(|ext| format!("{case}.{ext}")));
        if case != "01-models" {
            expected.push(format!("{case}.request.json"));
        }
        let head = head(case);
        assert!(head.starts_with("HTTP/1.1 ") && head.ends_with("\r\n\r\n"));
        let length = head.lines().find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::to_owned)
        });
        assert_eq!(length.is_none(), chunked(case), "{case}");
        if let Some(n) = length {
            assert_eq!(n.parse::<usize>().unwrap(), body(case).len(), "{case}");
        }
        for doc in documents(case).iter().filter(|_| case != "01-models") {
            let model = doc["model"].as_str().unwrap();
            assert!(model == MODEL || case == "11-chat-bad-model", "{case}");
        }
    }
    let mut found: Vec<_> = std::fs::read_dir(DIR)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    found.sort();
    expected.sort();
    assert_eq!(found, expected);
    let models: Value = serde_json::from_slice(&body("01-models")).unwrap();
    assert_eq!(models["data"][0]["id"], MODEL);
}

#[tokio::test]
async fn recorded_chat_plain_decodes() {
    decodes(
        "02-chat-plain",
        Expect {
            finish: "stop",
            parts: &["ok"],
            reasoning: None,
            calls: &[],
            usage: (17, 2),
        },
    )
    .await;
}

/// LF-only SSE; usage arrives in a final `"choices":[]` chunk before `[DONE]`.
#[tokio::test]
async fn recorded_chat_stream_with_usage_decodes() {
    decodes(
        "03-chat-stream-usage",
        Expect {
            finish: "stop",
            parts: &["12345"],
            reasoning: None,
            calls: &[],
            usage: (23, 6),
        },
    )
    .await;
}

#[tokio::test]
async fn recorded_chat_stream_reasoning_decodes() {
    decodes(
        "04-chat-stream-reasoning",
        Expect {
            finish: "stop",
            parts: &["\n\n43"],
            reasoning: Some(
                "We need answer user's simple arithmetic: 17 + 26 = 43. User asks answer with the number. Final just number.\n",
            ),
            calls: &[],
            usage: (67, 37),
        },
    )
    .await;
}

/// Two parallel calls streamed with the fork's `"\n"` separator on the content lane, which the
/// `tool_separator_whitespace` qualification (on in the fixture) keeps out of visible text.
#[tokio::test]
async fn recorded_chat_stream_parallel_tool_calls_decode() {
    decodes(
        "05-chat-stream-tools",
        Expect {
            finish: "tool_calls",
            parts: &[],
            reasoning: None,
            calls: &[
                ("call_34ecef725cee46718265ef1a", "get_weather"),
                ("call_db80d6f4519142a3a89c2452", "get_time"),
            ],
            usage: (354, 52),
        },
    )
    .await;
}

#[tokio::test]
async fn recorded_chat_parallel_tool_calls_decode() {
    decodes(
        "06-chat-tools-nonstream",
        Expect {
            finish: "tool_calls",
            parts: &[],
            reasoning: None,
            calls: &[
                ("call_f59554f62f6a45daa936011e", "get_weather"),
                ("call_d69cae8333724ead850bb51a", "get_time"),
            ],
            usage: (354, 52),
        },
    )
    .await;
}

/// KNOWN GAP (issue #9): a stream cut by `max_tokens` fails the whole turn as `Incomplete`
/// after its text was already forwarded, and the usage chunk SGLang sends after the `length`
/// finish is never read. A later increment is expected to keep the partial output and usage.
#[tokio::test]
async fn known_gap_length_cutoff_is_incomplete_and_loses_usage() {
    let case = "07-chat-stream-length";
    assert_eq!(recorded_finish(case).as_deref(), Some("length"));
    assert_eq!(recorded_usage(case).unwrap()["completion_tokens"], 12);
    for r in replays(case, |_| {}).await {
        r.failed(Error::Incomplete);
        assert_eq!(r.visible, recorded_content(case), "{}", r.label);
    }
}

/// KNOWN GAP (issue #9): a stream that ends without a finish, `[DONE]` or usage is reported as
/// `Malformed`, indistinguishable from corrupt output, with no usage and no partial outcome.
/// A later increment is expected to report an interrupted stream distinctly.
#[tokio::test]
async fn known_gap_aborted_stream_is_malformed_without_usage() {
    assert_eq!(recorded_finish(ABORTED), None);
    assert_eq!(recorded_usage(ABORTED), None);
    for r in replays(ABORTED, |_| {}).await {
        r.failed(Error::Malformed);
        assert_eq!(r.visible, recorded_content(ABORTED), "{}", r.label);
    }
}

/// KNOWN GAP (issue #9): SGLang reports reasoning tokens (included in `completion_tokens` on
/// this deployment), but `Usage` carries only input and output. The exhaustive pattern below
/// stops compiling when a reasoning field is added; a later increment is expected to do so.
#[tokio::test]
async fn known_gap_reasoning_tokens_are_not_surfaced() {
    let case = "04-chat-stream-reasoning";
    let recorded = recorded_usage(case).unwrap();
    assert_eq!(recorded["reasoning_tokens"], 33);
    assert_eq!(
        recorded["completion_tokens_details"]["reasoning_tokens"],
        33
    );
    for r in replays(case, |_| {}).await {
        let Usage {
            input,
            output,
            source: _,
            semantics: _,
        } = r.turn().usage.as_ref().unwrap();
        assert_eq!((*input, *output), (Some(67), Some(37)), "{}", r.label);
    }
}

/// KNOWN GAP (issue #9): the response `model` field is never checked. Core accepts a body naming
/// another model. SGLang also answered a request for an unknown model with HTTP 200 from the
/// loaded model while echoing the requested name, so model enforcement has to happen in front
/// of SGLang. Here that turn fails only because it hit `max_tokens` (`length`).
#[tokio::test]
async fn known_gap_response_model_is_not_checked() {
    for r in replays("02-chat-plain", |_| {}).await {
        assert_ne!(r.sent["model"], MODEL, "{}", r.label);
        assert_eq!(r.turn().answers[0].parts, ["ok"], "{}", r.label);
    }
    let case = "11-chat-bad-model";
    assert_eq!(sent(case)["model"], "no-such-model");
    assert_eq!(documents(case)[0]["model"], "no-such-model");
    assert_eq!(recorded_finish(case).as_deref(), Some("length"));
    for r in replays(case, |_| {}).await {
        r.failed(Error::Incomplete);
    }
}

/// KNOWN GAP (issue #9): `/v1/responses` returned a plain-text HTTP 500 on this deployment, so
/// the Responses decoder is unverified against any real server. Core maps the 500 to a provider
/// failure. A later increment is expected to replace these with recorded Responses output.
#[tokio::test]
async fn known_gap_responses_http_500_is_a_provider_failure() {
    for case in [
        "09-responses-plain",
        "10-responses-stream",
        "14-responses-list",
    ] {
        assert!(head(case).starts_with("HTTP/1.1 500 "));
        assert_eq!(body(case), b"Internal Server Error");
        for r in replays(case, |_| {}).await {
            r.failed(Error::Provider);
            assert_eq!(r.visible, "", "{}", r.label);
        }
    }
}

/// KNOWN GAP (issue #9): the real server still emits the tool-call separator on the content
/// lane, so with `tool_separator_whitespace` off it becomes a visible text part. Any
/// tool-using route needs that qualification until the fork's fix is deployed and recorded.
#[tokio::test]
async fn known_gap_tool_separator_is_content_without_qualification() {
    let case = "05-chat-stream-tools";
    for r in replays(case, |q| q.tool_separator_whitespace = false).await {
        let a = &r.turn().answers[0];
        assert_eq!(a.parts, ["\n"], "{}", r.label);
        assert_eq!(r.visible, "\n", "{}", r.label);
        assert!(
            matches!(&a.calls, CallGroup::Valid(c) if c.len() == 2),
            "{}",
            r.label
        );
    }
}
