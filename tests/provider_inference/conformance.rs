use crate::model_config::Source;
use crate::{
    provider_http::{
        fixture::{self, Reply},
        inference::*,
    },
    support::*,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn tool_call(index: usize, id: &str, name: &str, args: &str) -> Value {
    json!({"index":index,"id":id,"type":"function","function":{"name":name,"arguments":args}})
}
fn groups(p: Protocol, stream: bool, args: [&str; 2]) -> Vec<u8> {
    let chat_calls = vec![
        tool_call(0, "c1", "left", args[0]),
        tool_call(1, "c2", "right", args[1]),
    ];
    let res_calls = vec![
        function("c1", "left", args[0]),
        function("c2", "right", args[1]),
    ];
    if !stream {
        return wire(
            p,
            false,
            json!({"role":"assistant","content":"résultat","tool_calls":chat_calls}),
            "tool_calls".into(),
            [vec![message("résultat")], res_calls].concat(),
        );
    }
    let mut data = String::from(": heartbeat\r\n\r\n");
    if p == Protocol::Chat {
        data += &delta(
            json!({"role":"assistant","content":"résultat"}),
            Value::Null,
        );
        let mut start = chat_calls.clone();
        for c in &mut start {
            c["function"]["arguments"] = "{".into();
        }
        data += &delta(json!({"tool_calls":start}), Value::Null);
        for i in [1, 0] {
            data += &delta(
                json!({"tool_calls":[{"index":i,"function":{"arguments":&args[i][1..args[i].len()-1]}}]}),
                Value::Null,
            );
        }
        data += &delta(json!({"content":" \n"}), Value::Null);
        for i in [0, 1] {
            data += &delta(
                json!({"tool_calls":[{"index":i,"function":{"arguments":"}"}}]}),
                Value::Null,
            );
        }
        data += &delta(json!({"content":""}), "tool_calls".into());
        data += &event(json!({"choices":[],"usage":{"prompt_tokens":27,"completion_tokens":8}}));
        data += "data: [DONE]\r\n\r\n";
    } else {
        let msg = message("résultat");
        for (i, c) in res_calls.iter().enumerate() {
            let mut added = c.clone();
            added["arguments"] = "".into();
            data += &event(
                json!({"type":"response.output_item.added","output_index":i+1,"item":added}),
            );
        }
        for i in [1, 0] {
            data += &event(
                json!({"type":"response.function_call_arguments.delta","output_index":i+1,"item_id":res_calls[i]["id"],"delta":&args[i][..1]}),
            );
        }
        for i in [0, 1] {
            data += &event(
                json!({"type":"response.function_call_arguments.delta","output_index":i+1,"item_id":res_calls[i]["id"],"delta":&args[i][1..]}),
            );
            data += &event(
                json!({"type":"response.output_item.done","output_index":i+1,"item":res_calls[i]}),
            );
        }
        data += &event(
            json!({"type":"response.completed","response":completed([vec![msg],res_calls].concat())}),
        );
    }
    sse(&data)
}

#[tokio::test]
async fn caller_owns_two_rounds_and_exact_correlated_wire_history() {
    for (p, stream) in MODES {
        let args = [r#"{"v":"one"}"#, r#"{"v":"two"}"#];
        let reply = groups(p, stream, args);
        let round = AtomicUsize::new(0);
        let second = wire(
            p,
            stream,
            json!({
                "role":"assistant","tool_calls":[tool_call(0,"c3","left",args[0]),tool_call(1,"c4","right",args[1])]
            }),
            "tool_calls".into(),
            vec![
                function("c3", "left", args[0]),
                function("c4", "right", args[1]),
            ],
        );
        let final_answer = wire(
            p,
            stream,
            json!({"role":"assistant","content":"finished"}),
            "stop".into(),
            vec![message("finished")],
        );
        let mock = Mock::new(p, move |_| {
            let bytes = match round.fetch_add(1, Ordering::SeqCst) {
                0 => &reply,
                1 => &second,
                2 => &final_answer,
                _ => panic!("extra model round"),
            };
            Reply::Bytes(bytes.clone())
        })
        .await;
        let c = catalog(p, true);
        let e = effective(&c, false);
        let g = mock.gateway(&e, NORMAL);
        let mut r = request(stream);
        let visible = Arc::new(Mutex::new(String::new()));
        for pair in [["c1", "c2"], ["c3", "c4"]] {
            let text = visible.clone();
            let turn = g
                .caller(&c, &e, &r, Credential::Bearer(TOKEN), move |d| {
                    assert_eq!(d.choice, 0);
                    text.lock().unwrap().push_str(&d.text);
                    async {}
                })
                .await
                .unwrap();
            let a = turn.answers.into_iter().next().unwrap();
            if pair[0] == "c1" {
                assert_eq!(a.parts, ["résultat"]);
                if stream {
                    assert_eq!(visible.lock().unwrap().as_str(), "résultat");
                }
            }
            let CallGroup::Valid(calls) = a.calls else {
                panic!("caller received invalid group")
            };
            assert_eq!(
                calls.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
                pair
            );
            assert_eq!(
                calls.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
                ["left", "right"]
            );
            assert_eq!(
                calls
                    .iter()
                    .map(|c| c.arguments["v"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["one", "two"]
            );
            r.history.push(History::Assistant {
                parts: a.parts,
                reasoning: None,
                calls,
            });
            for id in pair.into_iter().rev() {
                r.history.push(History::ToolResult {
                    id: id.into(),
                    output: format!("result-{id}"),
                });
            }
        }
        let answer = g
            .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
            .await
            .unwrap();
        assert_eq!(answer.answers[0].parts, ["finished"]);
        mock.assert_inference_only(3);
        let captured = mock.captured.lock().unwrap();
        assert!(captured[2].to_string().contains("result-c4"));
        let tools = &captured[0]["tools"];
        for (i, t) in r.tools.as_ref().unwrap().iter().enumerate() {
            let f = if p == Protocol::Chat {
                &tools[i]["function"]
            } else {
                &tools[i]
            };
            assert_eq!(f["parameters"], t.parameters);
            assert_eq!(f["name"], t.name);
        }
        let items = captured[1][if p == Protocol::Chat {
            "messages"
        } else {
            "input"
        }]
        .as_array()
        .unwrap();
        let results = &items[items.len() - 2..];
        for (v, id) in results.iter().zip(["c2", "c1"]) {
            if p == Protocol::Chat {
                assert_eq!(
                    v,
                    &json!({"role":"tool","tool_call_id":id,"content":format!("result-{id}")})
                );
            } else {
                assert_eq!(
                    v,
                    &json!({"type":"function_call_output","call_id":id,"output":format!("result-{id}")})
                );
            }
        }
    }
}

#[tokio::test]
async fn omitted_empty_unsolicited_and_preflight_refusals() {
    for (p, stream) in MODES {
        let bytes = groups(p, stream, [r#"{"v":"x"}"#, r#"{"v":"y"}"#]);
        let mock = Mock::new(p, move |_| Reply::Bytes(bytes.clone())).await;
        let c = catalog(p, true);
        let e = effective(&c, false);
        let g = mock.gateway(&e, NORMAL);
        for offered in [None, Some(vec![])] {
            let mut r = request(stream);
            r.tools = offered;
            assert_eq!(
                g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                    .await
                    .err(),
                Some(Error::Malformed)
            );
            assert_eq!(
                mock.captured.lock().unwrap().last().unwrap().get("tools"),
                r.tools.is_some().then_some(&json!([]))
            );
        }
        let r = request(stream);
        for rejected in [
            mock.configured(&e, NORMAL, |q| {
                q.json = false;
                q.sse = false;
            }),
            mock.configured(&e, NORMAL, |q| q.functions = None),
        ] {
            assert_eq!(
                rejected
                    .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                    .await
                    .err(),
                Some(Error::Validation)
            );
        }
        let mut r = request(stream);
        r.parallel = Some(true);
        assert_eq!(
            mock.configured(&e, NORMAL, |q| q.parallel = false)
                .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        r.tools.as_mut().unwrap()[0].parameters["oneOf"] = json!([]);
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        let mut r = request(stream);
        r.history.push(History::ToolResult {
            id: "unpaired".into(),
            output: "private".into(),
        });
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        assert_eq!(mock.server.connections.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn reasoning_only_qualified_replay_and_control_provenance() {
    for (p, stream) in MODES {
        let bytes = wire(
            p,
            stream,
            json!({"role":"assistant","reasoning_content":THINK}),
            "stop".into(),
            vec![reasoning(THINK)],
        );
        let mock = Mock::new(p, move |_| Reply::Bytes(bytes.clone())).await;
        for (qualified, mismatch) in [
            (true, None),
            (true, Some("template")),
            (true, Some("format")),
            (false, None),
        ] {
            let c = catalog(p, qualified);
            let mut r = request(stream);
            for explicit in [false, true] {
                let e = effective(&c, explicit);
                let g = mock.gateway(&e, NORMAL);
                assert_eq!(
                    e.reasoning_effort.source,
                    if explicit {
                        Source::Request
                    } else {
                        Source::GatewayDefault
                    }
                );
                assert_eq!(
                    (
                        e.context_window.source,
                        e.context_window.value,
                        e.usable_input()
                    ),
                    (Source::Model, Some(8192), Some(7168))
                );
                let mut a = g
                    .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {
                        panic!("reasoning became visible")
                    })
                    .await
                    .unwrap()
                    .answers
                    .remove(0);
                assert!(a.parts.is_empty());
                let mut blocks = a.reasoning.take().unwrap();
                match mismatch {
                    Some("template") => blocks.source.profile.template = "other-template".into(),
                    Some("format") => blocks.source.format = "unqualified-format".into(),
                    _ => {}
                }
                r.history.push(History::Assistant {
                    parts: vec![],
                    reasoning: Some(blocks),
                    calls: vec![],
                });
                r.history.push(History::User("again".into()));
                let captured = mock.captured.lock().unwrap();
                let wire = captured.last().unwrap();
                let effort = if p == Protocol::Chat {
                    wire.get("reasoning_effort")
                } else {
                    wire.pointer("/reasoning/effort")
                };
                assert_eq!(effort.and_then(Value::as_str), explicit.then_some("medium"));
                assert_eq!(
                    wire.to_string().contains(THINK),
                    explicit && qualified && mismatch.is_none()
                );
                if explicit && (!qualified || mismatch.is_some()) {
                    let items = wire[if p == Protocol::Chat {
                        "messages"
                    } else {
                        "input"
                    }]
                    .as_array()
                    .unwrap();
                    assert!(
                        items
                            .iter()
                            .all(|v| v["role"] != "assistant" && v["type"] != "reasoning")
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn http_classification_status_charset_credentials_and_retry_after() {
    for (p, stream) in MODES {
        for (status, delay, expected) in [
            (400, vec![], Error::Provider),
            (401, vec![], Error::Provider),
            (403, vec![], Error::Provider),
            (404, vec![], Error::Provider),
            (422, vec![], Error::Provider),
            (502, vec![], Error::Provider),
            (503, vec![], Error::Unavailable),
            (504, vec![], Error::Timeout),
            (307, vec![], Error::Provider),
            (429, vec!["0"], Error::RateLimited(Some(0))),
            (429, vec!["86400"], Error::RateLimited(Some(86400))),
            (429, vec!["86401"], Error::RateLimited(None)),
            (429, vec!["-1"], Error::RateLimited(None)),
            (429, vec!["1", "2"], Error::RateLimited(None)),
            (429, vec![ECHO], Error::RateLimited(None)),
        ] {
            let h = delay
                .into_iter()
                .map(|s| ("Retry-After", s))
                .collect::<Vec<_>>();
            let error = once(p, stream, fixture::response(status, &h, ECHO.as_bytes()))
                .await
                .err()
                .unwrap();
            assert_eq!(error, expected);
            assert!(!format!("{error:?} {error}").contains(ECHO));
        }
        let media = if stream {
            "text/event-stream; charset=latin1"
        } else {
            "application/json; charset=latin1"
        };
        assert_eq!(
            once(
                p,
                stream,
                fixture::response(200, &[("content-type", media)], b"{}")
            )
            .await
            .err(),
            Some(Error::Malformed)
        );
        let c = catalog(p, true);
        let e = effective(&c, false);
        let mock = Mock::new(p, |_| panic!("unexpected request")).await;
        let g = mock.gateway(&e, NORMAL);
        let long = "x".repeat(1024);
        for (credential, err) in [
            (Credential::MissingEntitlement, Error::Provisioning),
            (Credential::Broken, Error::Credential),
            (Credential::Bearer(""), Error::Credential),
            (Credential::Bearer("bad token"), Error::Credential),
            (Credential::Bearer("bad\r\nheader"), Error::Credential),
            (Credential::Bearer(&long), Error::Credential),
        ] {
            assert_eq!(
                g.caller(&c, &e, &request(stream), credential, |_| async {})
                    .await
                    .err(),
                Some(err)
            );
        }
        assert_eq!(mock.server.connections.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn configuration_schema_controls_capacity_and_image_qualification() {
    use crate::model_config::{Catalog, Selection};
    for (p, stream) in MODES {
        let c = catalog(p, true);
        let mut doc: Value = serde_json::from_slice(&c.bytes()).unwrap();
        doc["models"]["a"]["context_window"] = Value::Null;
        let c = Catalog::load(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let e = effective(&c, false);
        assert!(e.context_window.value.is_none() && e.usable_input().is_none());
        let reply = wire(
            p,
            stream,
            json!({"role":"assistant","content":"ok"}),
            "stop".into(),
            vec![message("ok")],
        );
        let mock = Mock::new(p, move |_| Reply::Bytes(reply.clone())).await;
        let g = mock.gateway(&e, NORMAL);
        let mut r = request(stream);
        let mut bad_temperature = e.clone();
        bad_temperature.temperature.value = Some(2.0);
        let mut bad_effort = e.clone();
        bad_effort.reasoning_effort.value = Some("unknown".into());
        let mut stale = e.clone();
        stale.catalog_revision = "different-catalog-revision".into();
        for bad in [bad_temperature, bad_effort, stale] {
            assert_eq!(
                g.caller(&c, &bad, &r, Credential::Bearer(TOKEN), |_| async {})
                    .await
                    .err(),
                Some(Error::Validation)
            );
        }
        let request_layer = serde_json::from_value(
            json!({"model":"a","layer":{"controls":{"context_window":8192}}}),
        )
        .unwrap();
        assert!(
            c.resolve(&Selection::default(), &request_layer, None, |_, _| true)
                .is_err()
        );
        r.tools.as_mut().unwrap()[0].parameters = json!({"type":"object","properties":{"list":{"type":"array","items":{"type":"integer"}}}});
        let flat = mock.configured(&e, NORMAL, |q| q.functions = Some(SchemaSubset::Flat));
        assert_eq!(
            flat.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        r.history.push(History::UserImage {
            text: "image".into(),
            media: ImageType::Png,
            bytes: vec![1, 2, 3],
        });
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        mock.assert_inference_only(0);
        let qualified = mock.configured(&e, NORMAL, |q| q.images = true);
        qualified
            .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
            .await
            .unwrap();
        assert!(
            mock.captured.lock().unwrap()[0]
                .to_string()
                .contains("data:image/png;base64,AQID")
        );
        r.history.pop();
        r.tools = None;
        for empty in [false, true] {
            if empty {
                r.tools = Some(vec![]);
            }
            let turn = g
                .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .unwrap();
            assert!(matches!(&turn.answers[0].calls,CallGroup::Valid(c) if c.is_empty()));
            let wire = mock.captured.lock().unwrap();
            assert_eq!(
                wire.last().unwrap().get("tools"),
                empty.then_some(&json!([]))
            );
        }
        mock.assert_inference_only(3);
    }
}

#[tokio::test]
async fn omitted_reasoning_preserves_tool_and_result_pair_rejects_missing_or_duplicate_results() {
    for (p, stream) in MODES {
        let bytes = canary_turn(p, stream);
        let mock = Mock::new(p, move |_| Reply::Bytes(bytes.clone())).await;
        let c = catalog(p, false);
        let e = effective(&c, false);
        let g = mock.gateway(&e, NORMAL);
        let mut r = request(stream);
        let a = g
            .caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
            .await
            .unwrap()
            .answers
            .remove(0);
        let CallGroup::Valid(calls) = a.calls else {
            panic!("expected valid calls")
        };
        r.history.push(History::Assistant {
            parts: vec![],
            reasoning: a.reasoning,
            calls,
        });
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        r.history.push(History::ToolResult {
            id: "c".into(),
            output: "done".into(),
        });
        // The returned group reuses a historical ID. Check both the captured request and the rejection.
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Malformed)
        );
        r.history.push(r.history.last().unwrap().clone());
        assert_eq!(
            g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        mock.assert_inference_only(2);
        let req = &mock.captured.lock().unwrap()[1].to_string();
        assert!(!req.contains(THINK) && req.contains("done") && req.contains(ARG));
    }
}

#[tokio::test]
async fn prepared_request_decodes_tool_calls_against_bound_request_tools() {
    for (p, stream) in MODES {
        let bytes = canary_turn(p, stream);
        let mock = Mock::new(p, move |_| Reply::Bytes(bytes.clone())).await;
        let c = catalog(p, false);
        let e = effective(&c, false);
        let g = mock.gateway(&e, NORMAL);
        let r = request(stream);

        // caller_prepared decodes the tool call strictly against the prepared request's bound tools.
        let prepared_caller = g.prepare(&c, &e, &r, false).unwrap();
        assert!(std::ptr::eq(prepared_caller.gateway(), &g));
        assert_eq!(prepared_caller.model_name(), e.model);
        assert!(!prepared_caller.is_server());
        assert_eq!(
            prepared_caller.round_tokens(),
            e.ceiling.value.map(|v| v as i64)
        );
        assert_eq!(prepared_caller.round_cost(), None);
        assert!(!prepared_caller.requires_device_slot());
        g.validate_outbound_headers(Credential::Bearer(TOKEN), &prepared_caller)
            .unwrap();
        let oversized_bearer = "b".repeat(940);
        assert_eq!(
            g.validate_outbound_headers(Credential::Bearer(&oversized_bearer), &prepared_caller),
            Err(Error::Credential)
        );
        let caller_turn = g
            .caller_prepared(prepared_caller, Credential::Bearer(TOKEN), |_| async {})
            .await
            .unwrap();
        let CallGroup::Valid(caller_calls) = &caller_turn.answers[0].calls else {
            panic!("expected valid caller_prepared tool calls");
        };
        assert_eq!(caller_calls.len(), 1);
        assert_eq!(caller_calls[0].id, "c");

        // server_prepared decodes the tool call strictly against the prepared request's bound tools.
        let prepared_server = g.prepare(&c, &e, &r, true).unwrap();
        let (_tx, stop) = super::timing::run_stop(
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        let server_turn = g
            .server_prepared(
                prepared_server,
                Credential::Bearer(TOKEN),
                stop,
                |_| async {},
            )
            .await
            .unwrap();
        let CallGroup::Valid(server_calls) = &server_turn.answers[0].calls else {
            panic!("expected valid server_prepared tool calls");
        };
        assert_eq!(server_calls.len(), 1);
        assert_eq!(server_calls[0].id, "c");

        // Mismatched server flag between prepare() and *_prepared() is refused before HTTP.
        let wrong_for_caller = g.prepare(&c, &e, &r, true).unwrap();
        assert_eq!(
            g.caller_prepared(wrong_for_caller, Credential::Bearer(TOKEN), |_| async {})
                .await
                .err(),
            Some(Error::Validation)
        );
        let wrong_for_server = g.prepare(&c, &e, &r, false).unwrap();
        let (_tx2, stop2) = super::timing::run_stop(
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        assert_eq!(
            g.server_prepared(
                wrong_for_server,
                Credential::Bearer(TOKEN),
                stop2,
                |_| async {}
            )
            .await
            .err(),
            Some(Error::Validation)
        );
        mock.assert_inference_only(2);
    }
}

#[tokio::test]
async fn prepared_request_rejects_cross_gateway_same_pin_dispatch() {
    let chat_mock = Mock::new(Protocol::Chat, |_| Reply::Bytes(Vec::new())).await;
    let resp_mock = Mock::new(Protocol::Responses, |_| Reply::Bytes(Vec::new())).await;
    let c = catalog(Protocol::Chat, false);
    let e = effective(&c, false);
    let chat_gw = chat_mock.gateway(&e, NORMAL);
    let resp_gw = resp_mock.gateway(&e, NORMAL);
    let r = request(false);

    let chat_caller = chat_gw.prepare(&c, &e, &r, false).unwrap();
    assert_eq!(
        resp_gw.validate_outbound_headers(Credential::Bearer(TOKEN), &chat_caller),
        Err(Error::Validation)
    );
    assert_eq!(
        resp_gw
            .caller_prepared(chat_caller, Credential::Bearer(TOKEN), |_| async {})
            .await
            .err(),
        Some(Error::Validation)
    );

    let chat_server = chat_gw.prepare(&c, &e, &r, true).unwrap();
    assert_eq!(
        resp_gw.validate_outbound_headers(Credential::Bearer(TOKEN), &chat_server),
        Err(Error::Validation)
    );
    let (_tx, stop) =
        super::timing::run_stop(tokio::time::Instant::now() + std::time::Duration::from_secs(5));
    assert_eq!(
        resp_gw
            .server_prepared(chat_server, Credential::Bearer(TOKEN), stop, |_| async {})
            .await
            .err(),
        Some(Error::Validation)
    );

    chat_mock.assert_inference_only(0);
    resp_mock.assert_inference_only(0);
}
