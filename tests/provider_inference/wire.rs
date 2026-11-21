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
