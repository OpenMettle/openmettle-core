use crate::{
    provider_http::{
        fixture::{self, Reply},
        inference::*,
    },
    support::*,
    timing::run_stop,
};
use serde_json::{Value, json};

use tokio::time::{Duration, Instant};

#[tokio::test]
async fn terminal_state_machines_fail_closed_in_json_and_sse() {
    for stream in [false, true] {
        for (reason, calls, error) in [
            (Value::Null, false, Error::Malformed),
            ("other".into(), false, Error::Malformed),
            ("length".into(), true, Error::Incomplete),
            ("content_filter".into(), true, Error::Filtered),
            ("stop".into(), true, Error::Malformed),
            ("tool_calls".into(), false, Error::Malformed),
        ] {
            let mut m = json!({"role":"assistant","content":"partial"});
            if calls {
                m["tool_calls"] = json!([{"type":"function","index":0,"id":"x","function":{"name":"left","arguments":"{"}}]);
            }
            let b = wire(Protocol::Chat, stream, m, reason, vec![]);
            assert_eq!(once(Protocol::Chat, stream, b).await.err(), Some(error));
        }
        for (status, error) in [
            ("failed", Error::Provider),
            ("cancelled", Error::Provider),
            ("incomplete", Error::Incomplete),
            ("unknown", Error::Malformed),
        ] {
            let v = json!({"status":status,"output":[message("partial")]});
            let b = if stream {
                sse(&event(
                    json!({"type":format!("response.{status}"),"response":v}),
                ))
            } else {
                fixture::json(v.to_string().as_bytes())
            };
            assert_eq!(
                once(Protocol::Responses, stream, b).await.err(),
                Some(error)
            );
        }
    }
    let p = Protocol::Chat;
    let open = delta(json!({"content":"unfinished"}), Value::Null);
    for data in [
        open.clone(),
        open.clone() + "data: [DONE]\n\n",
        delta(json!({"content":"ok"}), "stop".into()),
        delta(json!({}), "stop".into()) + &delta(json!({}), "stop".into()) + "data: [DONE]\n\n",
    ] {
        assert_eq!(
            once(p, true, sse(&data)).await.err(),
            Some(Error::Malformed)
        );
    }
    for p in [Protocol::Chat, Protocol::Responses] {
        let first = if p == Protocol::Chat {
            open.clone()
        } else {
            event(json!({"type":"response.created"}))
        };
        let err = if p == Protocol::Chat {
            event(json!({"error":{"message":ECHO}}))
        } else {
            event(json!({"type":"error","message":ECHO}))
        };
        assert_eq!(
            once(p, true, sse(&(first + &err))).await.err(),
            Some(Error::Provider)
        );
    }
}

#[tokio::test]
async fn json_duplicate_keys_truncation_framing_and_bounds() {
    for (p, stream) in MODES {
        let msg = json!({"role":"assistant","content":"ok"});
        let envelope = match (p, stream) {
            (Protocol::Chat, true) => {
                json!({"choices":[{"index":0,"delta":msg,"finish_reason":"stop"}]})
            }
            (Protocol::Chat, false) => chat_json(msg, "stop".into()),
            (Protocol::Responses, false) => completed(vec![message("ok")]),
            (Protocol::Responses, true) => {
                json!({"type":"response.completed","response":completed(vec![message("ok")])})
            }
        };
        let encode = |payload: &str| {
            if stream {
                let done = if p == Protocol::Chat {
                    "data: [DONE]\n\n"
                } else {
                    ""
                };
                sse(&format!("data: {payload}\n\n{done}"))
            } else {
                fixture::json(payload.as_bytes())
            }
        };
        let good = envelope.to_string();
        let distinct = good.replacen('{', r#"{"nested":{"a":1,"b":2},"#, 1);
        assert!(once(p, stream, encode(&distinct)).await.is_ok());
        let duplicate = distinct.replace(r#""b":2"#, r#""\u0061":2"#);
        for bad in [duplicate, good[..good.len() - 1].to_owned(), "[]".into()] {
            assert_eq!(
                once(p, stream, encode(&bad)).await.err(),
                Some(Error::Malformed)
            );
        }
        let media = if stream {
            "text/event-stream"
        } else {
            "application/json"
        };
        for raw in [
            format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: 200\r\n\r\n{{}}"),
            format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nContent-Length: 2097153\r\n\r\n"),
            format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\n\r\n{{}}"),
            format!(
                "HTTP/1.1 200 OK\r\nX-Pad: {}\r\nContent-Type: {media}\r\nContent-Length: 2\r\n\r\n{{}}",
                "a".repeat(8192)
            ),
        ] {
            assert_eq!(
                once(p, stream, raw.into_bytes()).await.err(),
                Some(Error::Malformed)
            );
        }
        let raw = fixture::response(200, &[("content-type", media)], b"data: \xff\n\n");
        assert_eq!(once(p, stream, raw).await.err(), Some(Error::Malformed));
    }
    for p in [Protocol::Chat, Protocol::Responses] {
        for payload in [
            format!(":{}\n\n", "x".repeat(128 * 1024)),
            format!(
                "data: {}\ndata: {}\ndata: {}\n\n",
                "x".repeat(90 * 1024),
                "y".repeat(90 * 1024),
                "z".repeat(90 * 1024)
            ),
        ] {
            assert_eq!(
                once(
                    p,
                    true,
                    fixture::response(
                        200,
                        &[("content-type", "text/event-stream")],
                        payload.as_bytes()
                    )
                )
                .await
                .err(),
                Some(Error::Malformed)
            );
        }
    }
}

fn group_wire(p: Protocol, stream: bool, calls: &[(&str, &str, &str)]) -> Vec<u8> {
    let chat=calls.iter().enumerate().map(|(i,(id,name,args))|json!({"index":i,"type":"function","id":id,"function":{"name":name,"arguments":args}})).collect::<Vec<_>>();
    let res = calls
        .iter()
        .map(|(id, name, args)| function(id, name, args))
        .collect();
    wire(
        p,
        stream,
        json!({"role":"assistant","tool_calls":chat}),
        "tool_calls".into(),
        res,
    )
}

#[tokio::test]
async fn validate_entire_group_before_returning_calls_or_fixed_server_errors() {
    for (p, stream) in MODES {
        for (id, name, args, recoverable) in [
            ("second", "right", r#"{"v":"x","extra":1}"#, true),
            ("second", "right", r#"{"v":false}"#, true),
            ("second", "right", r#"{"v":{"nested":1,"nested":2}}"#, true),
            ("second", "right", r#"{"v":"x","v":"y"}"#, true),
            ("second", "right", "[1]", true),
            ("second", "right", "{", true),
            ("second", "right", "{}", true),
            ("first", "right", "{}", false),
            ("", "right", "{}", false),
            ("second", "unoffered", "{}", false),
        ] {
            let data = group_wire(
                p,
                stream,
                &[("first", "left", r#"{"v":"valid"}"#), (id, name, args)],
            );
            let mock = Mock::new(p, move |_| Reply::Bytes(data.clone())).await;
            let c = catalog(p, true);
            let e = effective(&c, false);
            let g = mock.gateway(&e, NORMAL);
            let r = request(stream);
            assert_eq!(
                g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                    .await
                    .err(),
                Some(Error::Malformed)
            );
            let (_tx, run) = run_stop(Instant::now() + Duration::from_secs(5));
            let turn = g
                .server(&c, &e, &r, Credential::Bearer(TOKEN), run, |_| async {})
                .await;
            if recoverable {
                let CallGroup::InvalidArguments(errors) = turn.unwrap().answers.remove(0).calls
                else {
                    panic!("invalid group was executable")
                };
                assert_eq!(errors.len(), 2);
                assert_eq!(errors[0].call_id, "first");
                assert_eq!(errors[1].call_id, "second");
                assert!(errors.iter().all(
                    |e| e.model_output() == json!({"error":{"code":"invalid_tool_arguments"}})
                ));
            } else {
                assert_eq!(turn.err(), Some(Error::Malformed));
            }
            mock.assert_inference_only(2);
        }
    }
}

#[tokio::test]
async fn turn_storage_ceiling_counts_utf8_ordinals_and_postgres_jsonb_spaces() {
    for (p, stream) in MODES {
        // Use a single HTTP body for the large SSE fixtures; fragmentation is covered separately.
        let send = |chat: Value, items: Vec<Value>| {
            let v = if p == Protocol::Chat {
                if stream {
                    json!({"choices":[{"index":0,"delta":chat,"finish_reason":"stop"}]})
                } else {
                    chat_json(chat, "stop".into())
                }
            } else {
                completed(items)
            };
            if stream {
                let mut s = if p == Protocol::Chat {
                    event(v)
                } else {
                    event(json!({"type":"response.completed","response":v}))
                };
                if p == Protocol::Chat {
                    s += "data: [DONE]\n\n";
                }
                fixture::response(200, &[("content-type", "text/event-stream")], s.as_bytes())
            } else {
                fixture::json(v.to_string().as_bytes())
            }
        };
        for extra in ["", "x"] {
            let text = "é".repeat(32768) + extra;
            let res = once(
                p,
                stream,
                send(
                    json!({"role":"assistant","content":text}),
                    vec![message(&text)],
                ),
            )
            .await;
            if extra.is_empty() {
                let a = res.unwrap().answers.remove(0);
                assert_eq!(a.parts[0].len(), 65536);
                assert!(a.reasoning.is_none());
            } else {
                assert_eq!(res.err(), Some(Error::Malformed));
            }
        }
        let overhead = if p == Protocol::Chat {
            r#"[{"text": ""}]"#.len()
        } else {
            r#"[{"id": "why", "type": "reasoning", "summary": [{"text": "", "type": "summary_text"}]}]"#.len()
        };
        for extra in ["", "x"] {
            let text = "x".repeat(65536 - overhead - 2) + "\n" + extra;
            let res = once(
                p,
                stream,
                send(
                    json!({"role":"assistant","reasoning_content":text}),
                    vec![reasoning(&text)],
                ),
            )
            .await;
            if extra.is_empty() {
                let a = res.unwrap().answers.remove(0);
                assert!(a.parts.is_empty());
                assert_eq!(a.reasoning.unwrap().storage_bytes, 65536);
            } else {
                assert_eq!(res.err(), Some(Error::Malformed));
            }
        }
        if p == Protocol::Responses {
            for n in [128, 129] {
                let mut m = message("");
                m["content"] = vec![json!({"type":"output_text","text":"x"}); n].into();
                let res = once(p, stream, send(Value::Null, vec![m])).await;
                if n == 128 {
                    assert_eq!(res.unwrap().answers[0].parts.len(), 128);
                } else {
                    assert_eq!(res.err(), Some(Error::Malformed));
                }
                let items = (0..n)
                    .map(|i| {
                        let mut b = reasoning("x");
                        b["id"] = format!("why-{i}").into();
                        b
                    })
                    .collect();
                let res = once(p, stream, send(Value::Null, items)).await;
                if n == 128 {
                    assert_eq!(
                        res.unwrap()
                            .answers
                            .remove(0)
                            .reasoning
                            .unwrap()
                            .blocks
                            .len(),
                        128
                    );
                } else {
                    assert_eq!(res.err(), Some(Error::Malformed));
                }
            }
        }
    }
}

#[tokio::test]
async fn authoritative_partial_usage_and_absent_usage_are_distinct() {
    for (p, stream) in MODES {
        for measured in [true, false] {
            let mut reply = if p == Protocol::Chat {
                if stream {
                    json!({"choices":[{"index":0,"delta":{"content":"answer"},"finish_reason":"stop"}]})
                } else {
                    chat_json(
                        json!({"role":"assistant","content":"answer"}),
                        "stop".into(),
                    )
                }
            } else {
                completed(vec![message("answer")])
            };
            if measured {
                reply["usage"] = if p == Protocol::Chat {
                    json!({"prompt_tokens":27})
                } else {
                    json!({"input_tokens":27})
                };
            }
            let b = if stream {
                if p == Protocol::Chat {
                    sse(&(event(reply) + "data: [DONE]\r\n\r\n"))
                } else {
                    sse(&event(
                        json!({"type":"response.completed","response":reply}),
                    ))
                }
            } else {
                fixture::response(
                    200,
                    &[("content-type", "Application/JSON; Charset=\"UTF-8\"")],
                    reply.to_string().as_bytes(),
                )
            };
            let usage = once(p, stream, b).await.unwrap().usage;
            if measured {
                let u = usage.unwrap();
                assert_eq!(u.source, "gateway");
                assert_eq!(
                    (u.input, u.output, u.semantics.as_str()),
                    (Some(27), None, "final_call")
                );
            } else {
                assert!(usage.is_none());
            }
        }
    }
}

#[tokio::test]
async fn call_and_argument_limits_across_protocols() {
    for (p, stream) in MODES {
        let ids: Vec<_> = (0..129).map(|n| format!("call{n}")).collect();
        let calls: Vec<_> = ids
            .iter()
            .map(|id| (id.as_str(), "left", r#"{"v":"ok"}"#))
            .collect();
        for n in [128, 129] {
            let reply = group_wire(p, stream, &calls[..n]);
            let turn = once(p, stream, reply).await;
            if n == 128 {
                assert!(
                    matches!(&turn.unwrap().answers[0].calls,CallGroup::Valid(c) if c.len()==128)
                );
            } else {
                assert_eq!(turn.err(), Some(Error::Malformed));
            }
        }
        let args = json!({"v":"a".repeat(65536)}).to_string();
        assert_eq!(
            once(p, stream, group_wire(p, stream, &[("id", "left", &args)]))
                .await
                .err(),
            Some(Error::Malformed)
        );
    }
}

#[tokio::test]
async fn multiline_data_multiple_choices_and_inconsistent_response_lanes() {
    let v = json!({"choices":[{"index":1,"delta":{"content":"second"},"finish_reason":"stop"},
                             {"index":0,"delta":{"content":"first"},"finish_reason":"stop"}]});
    let multiline = format!(
        ": ping\r\ndata: {}\r\n\r\ndata: [DONE]\r\n\r\n",
        v.to_string().replace("[{", "[\r\ndata: {")
    );
    let turn = once(Protocol::Chat, true, sse(&multiline)).await.unwrap();
    assert_eq!(turn.answers[0].parts, ["first"]);
    assert_eq!(turn.answers[1].choice, 1);
    let base = event(
        json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"item","call_id":"call","name":"left","arguments":""}}),
    );
    for (item, call, index) in [
        ("other", "call", 0),
        ("item", "other", 0),
        ("item", "call", 1),
    ] {
        let data = base.clone()
            + &event(
                json!({"type":"response.function_call_arguments.delta","item_id":item,"call_id":call,"output_index":index,"delta":"{"}),
            );
        assert_eq!(
            once(Protocol::Responses, true, sse(&data)).await.err(),
            Some(Error::Malformed)
        );
    }
    let base = event(
        json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[],"id":"msg"}}),
    );
    let done = event(
        json!({"type":"response.output_text.done","item_id":"msg","content_index":0,"output_index":0,"text":"observed"}),
    );
    let data = base
        + &done
        + &event(
            json!({"type":"response.completed","response":completed(vec![message("changed")])}),
        );
    assert_eq!(
        once(Protocol::Responses, true, sse(&data)).await.err(),
        Some(Error::Malformed)
    );
}

#[tokio::test]
async fn rejected_group_can_be_replayed_only_as_correlated_server_errors() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for (p, stream) in MODES {
        let first = AtomicBool::new(true);
        let calls = group_wire(
            p,
            stream,
            &[("a", "left", "{"), ("b", "right", r#"{"v":"ok"}"#)],
        );
        let answer = wire(
            p,
            stream,
            json!({"role":"assistant","content":"recovered"}),
            "stop".into(),
            vec![message("recovered")],
        );
        let mock = Mock::new(p, move |_| {
            Reply::Bytes(if first.swap(false, Ordering::SeqCst) {
                calls.clone()
            } else {
                answer.clone()
            })
        })
        .await;
        let c = catalog(p, false);
        let e = effective(&c, false);
        let g = mock.gateway(&e, NORMAL);
        let mut r = request(stream);
        let (_tx, stop) = run_stop(Instant::now() + Duration::from_secs(5));
        let turn = g
            .server(&c, &e, &r, Credential::Bearer(TOKEN), stop, |_| async {})
            .await
            .unwrap();
        let CallGroup::InvalidArguments(group) = turn.answers.into_iter().next().unwrap().calls
        else {
            panic!("group must be rejected")
        };
        r.history.push(History::RejectedGroup(group));
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        let (_tx, stop) = run_stop(Instant::now() + Duration::from_secs(5));
        let turn = g
            .server(&c, &e, &r, Credential::Bearer(TOKEN), stop, |_| async {})
            .await
            .unwrap();
        assert_eq!(turn.answers[0].parts, ["recovered"]);
        mock.assert_inference_only(2);
        let captured = mock.captured.lock().unwrap();
        let (items, key, id) = if p == Protocol::Chat {
            ("messages", "content", "tool_call_id")
        } else {
            ("input", "output", "call_id")
        };
        let items = captured[1][items].as_array().unwrap();
        let results = &items[items.len() - 2..];
        for (result, expected) in results.iter().zip(["a", "b"]) {
            assert_eq!(result[id], expected);
            assert_eq!(
                serde_json::from_str::<Value>(result[key].as_str().unwrap()).unwrap(),
                json!({"error":{"code":"invalid_tool_arguments"}})
            );
        }
    }
}

#[tokio::test]
async fn nested_duplicates_in_otherwise_schema_valid_arguments_fail_every_mode() {
    for (p, stream) in MODES {
        for (args, valid) in [
            (r#"{"v":{"k":2}}"#, true),
            (r#"{"v":{"k":1,"\u006b":2}}"#, false),
        ] {
            let data = group_wire(p, stream, &[("id", "left", args)]);
            let mock = Mock::new(p, move |_| Reply::Bytes(data.clone())).await;
            let c = catalog(p, true);
            let e = effective(&c, false);
            let mut r = request(stream);
            r.tools.as_mut().unwrap()[0].parameters["properties"]["v"] = json!({
                "type":"object","properties":{"k":{"type":"integer"}},"required":["k"],"additionalProperties":false
            });
            let result = mock
                .gateway(&e, NORMAL)
                .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await;
            if valid {
                assert!(
                    matches!(&result.unwrap().answers[0].calls,CallGroup::Valid(c) if c[0].arguments["v"]["k"]==2)
                );
            } else {
                assert_eq!(result.err(), Some(Error::Malformed));
            }
            mock.assert_inference_only(1);
        }
    }
}

#[tokio::test]
async fn responses_reasoning_block_bounds_normalized_jsonb_bytes() {
    let overhead =
        r#"[{"id": "why", "type": "reasoning", "summary": [{"text": "", "type": "summary_text"}]}]"#
            .len();
    let sse_reply = |body: &str| {
        fixture::response(
            200,
            &[("content-type", "text/event-stream")],
            body.as_bytes(),
        )
    };
    let streamed_reasoning = |done_item: &Value, text: &str| {
        let mut added = json!({
            "type": "reasoning",
            "id": "why",
            "status": Value::Null,
            "summary": [],
            "upstream_seq": 7
        });
        if let Some(enc) = done_item.get("encrypted_content") {
            added["encrypted_content"] = enc.clone();
        }
        let body = event(json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": added
        })) + &event(json!({
            "type": "response.reasoning_summary_part.added",
            "output_index": 0,
            "item_id": "why",
            "summary_index": 0,
            "part": {
                "type": "summary_text",
                "text": "",
                "index": 0,
                "annotations": Value::Null,
                "cached": false
            }
        })) + &event(json!({
            "type": "response.reasoning_summary_text.delta",
            "output_index": 0,
            "item_id": "why",
            "summary_index": 0,
            "delta": text
        })) + &event(json!({
            "type": "response.reasoning_summary_part.done",
            "output_index": 0,
            "item_id": "why",
            "summary_index": 0,
            "part": done_item["summary"][0]
        })) + &event(json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": done_item
        })) + &event(json!({
            "type": "response.completed",
            "response": completed(vec![done_item.clone()])
        }));
        sse_reply(&body)
    };

    for stream in [false, true] {
        // Extra numeric/null/boolean and >64 KiB metadata fields on raw summary items must not
        // falsely reject a valid normalized reasoning block.
        let padded_short = json!({
            "type": "reasoning",
            "id": "why",
            "status": Value::Null,
            "summary": [{
                "type": "summary_text",
                "text": THINK,
                "index": 0,
                "annotations": Value::Null,
                "cached": false,
                "provider_metadata": "p".repeat(70_000)
            }]
        });
        let raw = if stream {
            streamed_reasoning(&padded_short, THINK)
        } else {
            fixture::json(completed(vec![padded_short.clone()]).to_string().as_bytes())
        };
        let reasoning = once(Protocol::Responses, stream, raw)
            .await
            .unwrap()
            .answers
            .remove(0)
            .reasoning
            .unwrap();
        assert_eq!(
            reasoning.blocks,
            vec![json!({
                "type": "reasoning",
                "id": "why",
                "summary": [{"type": "summary_text", "text": THINK}]
            })]
        );
        assert_eq!(reasoning.storage_bytes, overhead + THINK.len());

        // Exact 65,536-byte normalized block with extra raw metadata fits; +1 byte fails closed.
        for extra in ["", "x"] {
            let text = "x".repeat(65536 - overhead) + extra;
            let item = json!({
                "type": "reasoning",
                "id": "why",
                "summary": [{
                    "type": "summary_text",
                    "text": text,
                    "index": 0,
                    "annotations": Value::Null,
                    "provider_metadata": "m".repeat(1024)
                }]
            });
            let raw = if stream {
                streamed_reasoning(&item, &text)
            } else {
                fixture::json(completed(vec![item]).to_string().as_bytes())
            };
            let res = once(Protocol::Responses, stream, raw).await;
            if extra.is_empty() {
                assert_eq!(
                    res.unwrap().answers[0]
                        .reasoning
                        .as_ref()
                        .unwrap()
                        .storage_bytes,
                    65536
                );
            } else {
                assert_eq!(res.err(), Some(Error::Malformed));
            }
        }

        // Encrypted content pushing the normalized block over 65,536 pg_bytes fails closed
        // even when only attached at output_item.done / response.completed.
        let near_limit = "x".repeat(65536 - overhead - 4);
        let encrypted_overflow = json!({
            "type": "reasoning",
            "id": "why",
            "encrypted_content": "abc",
            "summary": [{"type": "summary_text", "text": near_limit}]
        });
        let raw = if stream {
            let body = event(json!({
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {"type": "reasoning", "id": "why", "summary": []}
            })) + &event(json!({
                "type": "response.reasoning_summary_text.delta",
                "output_index": 0,
                "item_id": "why",
                "summary_index": 0,
                "delta": near_limit
            })) + &event(json!({
                "type": "response.output_item.done",
                "output_index": 0,
                "item": encrypted_overflow
            })) + &event(json!({
                "type": "response.completed",
                "response": completed(vec![encrypted_overflow.clone()])
            }));
            sse_reply(&body)
        } else {
            fixture::json(completed(vec![encrypted_overflow]).to_string().as_bytes())
        };
        assert_eq!(
            once(Protocol::Responses, stream, raw).await.err(),
            Some(Error::Malformed)
        );
    }
}

#[tokio::test]
async fn responses_output_item_null_status_and_streamed_cancelled_parity() {
    use crate::{authz::leases::FailReason, worker::StepResult};

    for stream in [false, true] {
        let mut r_item = reasoning(THINK);
        r_item["status"] = Value::Null;
        let mut m_item = message("ok");
        m_item["status"] = Value::Null;
        let mut f_item = function("c1", "left", r#"{"v":"one"}"#);
        f_item["status"] = Value::Null;

        let raw = if stream {
            let body = event(json!({
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {"type": "reasoning", "id": "why", "status": Value::Null, "summary": []}
            })) + &event(json!({
                "type": "response.reasoning_summary_text.delta",
                "output_index": 0,
                "item_id": "why",
                "summary_index": 0,
                "delta": THINK
            })) + &event(json!({
                "type": "response.output_item.done",
                "output_index": 0,
                "item": r_item
            })) + &event(json!({
                "type": "response.output_item.added",
                "output_index": 1,
                "item": {"type": "message", "id": "msg", "role": "assistant", "status": Value::Null, "content": []}
            })) + &event(json!({
                "type": "response.output_text.delta",
                "output_index": 1,
                "item_id": "msg",
                "content_index": 0,
                "delta": "ok"
            })) + &event(json!({
                "type": "response.output_item.done",
                "output_index": 1,
                "item": m_item
            })) + &event(json!({
                "type": "response.output_item.added",
                "output_index": 2,
                "item": {"type": "function_call", "id": "item-c1", "call_id": "c1", "name": "left", "arguments": "", "status": Value::Null}
            })) + &event(json!({
                "type": "response.function_call_arguments.delta",
                "output_index": 2,
                "item_id": "item-c1",
                "delta": r#"{"v":"one"}"#
            })) + &event(json!({
                "type": "response.output_item.done",
                "output_index": 2,
                "item": f_item
            })) + &event(json!({
                "type": "response.completed",
                "response": completed(vec![r_item, m_item, f_item])
            }));
            sse(&body)
        } else {
            fixture::json(
                completed(vec![r_item, m_item, f_item])
                    .to_string()
                    .as_bytes(),
            )
        };
        let answer = once(Protocol::Responses, stream, raw)
            .await
            .unwrap()
            .answers
            .remove(0);
        assert_eq!(answer.parts, ["ok"]);
        assert!(answer.reasoning.is_some());
        assert!(matches!(answer.calls, CallGroup::Valid(ref c) if c.len() == 1));

        // Non-null non-completed output item statuses still fail closed.
        for (status, details, expected) in [
            ("incomplete".into(), None, Error::Incomplete),
            (
                "incomplete".into(),
                Some(json!({"reason": "content_filter"})),
                Error::Filtered,
            ),
            ("failed".into(), None, Error::Provider),
            ("cancelled".into(), None, Error::Provider),
            ("in_progress".into(), None, Error::Malformed),
            (json!(123), None, Error::Malformed),
            (json!(true), None, Error::Malformed),
        ] {
            let mut item = message("partial");
            item["status"] = status;
            if let Some(d) = details {
                item["incomplete_details"] = d;
            }
            let raw = wire(
                Protocol::Responses,
                stream,
                Value::Null,
                Value::Null,
                vec![item],
            );
            assert_eq!(
                once(Protocol::Responses, stream, raw).await.err(),
                Some(expected)
            );
        }

        // Top-level response status still cannot be null.
        let top_null = json!({"status": Value::Null, "output": [message("ok")]});
        let raw = if stream {
            sse(&event(json!({
                "type": "response.completed",
                "response": top_null
            })))
        } else {
            fixture::json(top_null.to_string().as_bytes())
        };
        assert_eq!(
            once(Protocol::Responses, stream, raw).await.err(),
            Some(Error::Malformed)
        );
    }

    // Streamed response.cancelled (including after partial text deltas and with SSE event name)
    // yields Error::Provider for both caller and server (never Error::Stopped when RunStop is clear).
    let partial_then_cancelled = event(json!({"type": "response.created"}))
        + &event(json!({
            "type": "response.output_item.added",
            "output_index": 0,
            "item": {"type": "message", "id": "msg", "role": "assistant", "content": []}
        }))
        + &event(json!({
            "type": "response.output_text.delta",
            "output_index": 0,
            "item_id": "msg",
            "content_index": 0,
            "delta": "partial"
        }))
        + "event: response.cancelled\r\n"
        + &event(json!({
            "type": "response.cancelled",
            "response": {"status": "cancelled", "output": [message("partial")]}
        }));
    let bytes = sse(&partial_then_cancelled);
    let mock = Mock::new(Protocol::Responses, move |_| Reply::Bytes(bytes.clone())).await;
    let c = catalog(Protocol::Responses, true);
    let e = effective(&c, false);
    let g = mock.gateway(&e, NORMAL);
    let r = request(true);
    assert_eq!(
        g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
            .await
            .err(),
        Some(Error::Provider)
    );
    let (_tx, stop) = run_stop(Instant::now() + Duration::from_secs(5));
    let server_err = g
        .server(&c, &e, &r, Credential::Bearer(TOKEN), stop, |_| async {})
        .await
        .err()
        .unwrap();
    assert_eq!(server_err, Error::Provider);
    assert!(matches!(
        server_err.step_result(),
        StepResult::Failed(FailReason::StepFailed)
    ));
    mock.assert_inference_only(2);
}

#[tokio::test]
async fn chat_non_streamed_tool_call_arguments_require_json_string() {
    let valid_msg = json!({
        "role": "assistant",
        "tool_calls": [{
            "id": "c1",
            "type": "function",
            "function": {"name": "left", "arguments": r#"{"v":"ok"}"#}
        }]
    });
    let turn = once(
        Protocol::Chat,
        false,
        fixture::json(
            chat_json(valid_msg, "tool_calls".into())
                .to_string()
                .as_bytes(),
        ),
    )
    .await
    .unwrap();
    assert!(
        matches!(&turn.answers[0].calls, CallGroup::Valid(c) if c.len() == 1 && c[0].arguments == json!({"v": "ok"}))
    );

    // Non-string wire shapes (object, null, omitted, array, number, boolean) must fail with
    // Error::Malformed in both caller and server modes rather than coercing or treating as empty.
    for raw_function in [
        json!({"name": "left", "arguments": {"v": "ok"}}),
        json!({"name": "left", "arguments": Value::Null}),
        json!({"name": "left"}),
        json!({"name": "left", "arguments": ["ok"]}),
        json!({"name": "left", "arguments": 123}),
        json!({"name": "left", "arguments": true}),
    ] {
        let body = chat_json(
            json!({
                "role": "assistant",
                "tool_calls": [{
                    "id": "c1",
                    "type": "function",
                    "function": raw_function
                }]
            }),
            "tool_calls".into(),
        );
        let bytes = fixture::json(body.to_string().as_bytes());
        let mock = Mock::new(Protocol::Chat, move |_| Reply::Bytes(bytes.clone())).await;
        let c = catalog(Protocol::Chat, true);
        let e = effective(&c, false);
        let g = mock.gateway(&e, NORMAL);
        let r = request(false);
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Malformed)
        );
        let (_tx, stop) = run_stop(Instant::now() + Duration::from_secs(5));
        assert_eq!(
            g.server(&c, &e, &r, Credential::Bearer(TOKEN), stop, |_| async {})
                .await
                .err(),
            Some(Error::Malformed)
        );
        mock.assert_inference_only(2);
    }

    // Invalid JSON strings on non-streamed Chat tool calls are rejected for caller.
    for bad_args in ["{", "[1]", r#"{"v":"a","v":"b"}"#] {
        let body = chat_json(
            json!({
                "role": "assistant",
                "tool_calls": [{
                    "id": "c1",
                    "type": "function",
                    "function": {"name": "left", "arguments": bad_args}
                }]
            }),
            "tool_calls".into(),
        );
        assert_eq!(
            once(
                Protocol::Chat,
                false,
                fixture::json(body.to_string().as_bytes())
            )
            .await
            .err(),
            Some(Error::Malformed)
        );
    }

    // Streamed Chat tool call deltas may omit or send null arguments before string fragments,
    // while still rejecting non-string non-null arguments.
    let streamed_ok = delta(
        json!({
            "role": "assistant",
            "tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {"name": "left", "arguments": Value::Null}}]
        }),
        Value::Null,
    ) + &delta(
        json!({
            "tool_calls": [{"index": 0, "function": {"arguments": r#"{"v":"ok"}"#}}]
        }),
        "tool_calls".into(),
    ) + "data: [DONE]\r\n\r\n";
    let streamed_turn = once(Protocol::Chat, true, sse(&streamed_ok)).await.unwrap();
    assert!(
        matches!(&streamed_turn.answers[0].calls, CallGroup::Valid(c) if c.len() == 1 && c[0].arguments == json!({"v": "ok"}))
    );

    let streamed_bad = delta(
        json!({
            "role": "assistant",
            "tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {"name": "left", "arguments": {"v": "ok"}}}]
        }),
        "tool_calls".into(),
    ) + "data: [DONE]\r\n\r\n";
    assert_eq!(
        once(Protocol::Chat, true, sse(&streamed_bad)).await.err(),
        Some(Error::Malformed)
    );
}
