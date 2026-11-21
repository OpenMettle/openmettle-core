use crate::{
    authz::{
        leases::{ExecState, FailReason},
        runs::ClaimedRun,
    },
    provider_http::{fixture::Reply, inference::*},
    support::*,
    worker::{ActiveRun, StepResult, Stop},
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    sync::{Notify, watch},
    time::{Instant, sleep, timeout},
};

const BOUND: Duration = Duration::from_secs(2);
const SHORT: Duration = Duration::from_millis(160);
pub(super) fn run_stop(deadline: Instant) -> (watch::Sender<Option<Stop>>, RunStop) {
    let (tx, rx) = watch::channel(None);
    let run = ActiveRun {
        claim: ClaimedRun {
            scope_id: "scope".into(),
            run_id: "run".into(),
            claim_token: "claim".into(),
            actor_approval_id: "actor".into(),
            round_limit: 4,
            lease_remaining: SHORT,
            execution_remaining: BOUND,
        },
        state: ExecState::Running,
        execution_deadline: deadline,
    };
    (tx, RunStop::from_worker(&run, rx))
}
fn prefix(p: Protocol) -> Vec<u8> {
    let data = if p == Protocol::Chat {
        delta(json!({"content":"hello"}), Value::Null)
    } else {
        event(
            json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"m","role":"assistant","content":[]}}),
        ) + &event(
            json!({"type":"response.output_text.delta","output_index":0,"item_id":"m","content_index":0,"delta":"hello"}),
        )
    };
    [sse_head(), chunk(data.as_bytes())].concat()
}
#[tokio::test]
async fn four_runner_stops_close_stalled_peer_and_never_retry() {
    for p in [Protocol::Chat, Protocol::Responses] {
        for cause in [
            Stop::Cancel,
            Stop::Deadline,
            Stop::LeaseLost,
            Stop::Shutdown,
        ] {
            let c = catalog(p, true);
            let e = effective(&c, false);
            let mock = Mock::new(p, move |_| Reply::Stall(prefix(p))).await;
            let g = mock.gateway(&e, NORMAL);
            let r = request(true);
            let (tx, run) = run_stop(Instant::now() + BOUND);
            let first = Notify::new();
            let call = g.server(&c, &e, &r, Credential::Bearer(TOKEN), run, |d| {
                assert_eq!(d.text, "hello");
                first.notify_one();
                async {}
            });
            let signal = async {
                first.notified().await;
                tx.send_replace(Some(cause));
            };
            let (result, ()) = timeout(BOUND, async { tokio::join!(call, signal) })
                .await
                .unwrap();
            let err = result.err().unwrap();
            assert_eq!(err, Error::Stopped(cause));
            assert!(matches!(err.step_result(), StepResult::Stopped));
            timeout(BOUND, mock.server.closed.notified()).await.unwrap();
            assert_eq!(mock.server.connections.load(Ordering::SeqCst), 1);
        }
    }
}
#[tokio::test]
async fn hard_deadline_drops_peer_before_waiting_for_runner() {
    for p in [Protocol::Chat, Protocol::Responses] {
        let c = catalog(p, true);
        let e = effective(&c, false);
        let mock = Mock::new(p, move |_| Reply::Stall(prefix(p))).await;
        let g = mock.gateway(&e, NORMAL);
        let r = request(true);
        let (tx, run) = run_stop(Instant::now() + SHORT);
        let call = g.server(&c, &e, &r, Credential::Bearer(TOKEN), run, |_| async {});
        let signal = async {
            mock.server.closed.notified().await;
            assert!(tx.borrow().is_none());
            tx.send_replace(Some(Stop::Deadline));
        };
        let (ret, ()) = timeout(BOUND, async { tokio::join!(call, signal) })
            .await
            .unwrap();
        assert_eq!(ret.err(), Some(Error::Stopped(Stop::Deadline)));
        mock.assert_inference_only(1);
    }
}
#[tokio::test]
async fn renewal_permits_completion_past_initial_lease_stop_point() {
    for p in [Protocol::Chat, Protocol::Responses] {
        let c = catalog(p, true);
        let e = effective(&c, false);
        let finish = if p == Protocol::Chat {
            delta(json!({}), "stop".into()) + "data: [DONE]\r\n\r\n"
        } else {
            let mut m = message("hello");
            m["id"] = "m".into();
            event(json!({"type":"response.completed","response":completed(vec![m])}))
        };
        let next = Arc::new(Notify::new());
        let gate = next.clone();
        let mock = Mock::new(p, move |_| {
            Reply::Split(
                prefix(p),
                gate.clone(),
                [chunk(finish.as_bytes()), b"0\r\n\r\n".to_vec()].concat(),
            )
        })
        .await;
        let g = mock.gateway(&e, NORMAL);
        let r = request(true);
        let first = Notify::new();
        let start = Instant::now();
        let initial = start + SHORT;
        let (tx, run) = run_stop(start + BOUND);
        let call = g.server(&c, &e, &r, Credential::Bearer(TOKEN), run, |_| {
            first.notify_one();
            async {}
        });
        // The runner renews its watched stop point. Without this update the monitor
        // would signal lease loss before the peer releases its terminal event.
        let (lease_updates, mut live_lease) = watch::channel(initial);
        let monitor = async {
            loop {
                let stop_at = *live_lease.borrow_and_update();
                tokio::select! {
                    biased;
                    _=tokio::time::sleep_until(stop_at)=>{ tx.send_replace(Some(Stop::LeaseLost));break; }
                    changed=live_lease.changed()=>{if changed.is_err(){break;}}
                }
            }
        };
        let renew = async {
            first.notified().await;
            lease_updates.send_replace(initial + BOUND);
            tokio::time::sleep_until(initial + Duration::from_millis(20)).await;
            next.notify_one();
        };
        let work = async {
            let (result, ()) = tokio::join!(call, renew);
            result
        };
        let ret = timeout(BOUND, async {
            tokio::select! {result=work=>result,()=monitor=>panic!("renewal missed")}
        })
        .await
        .unwrap();
        assert_eq!(ret.unwrap().answers[0].parts, ["hello"]);
        assert!(Instant::now() > initial);
    }
}
#[tokio::test]
async fn standalone_setup_first_and_next_idle_overall_and_downstream_backpressure() {
    for p in [Protocol::Chat, Protocol::Responses] {
        for mode in ["setup", "headers", "first", "next", "overall", "downstream"] {
            let c = catalog(p, true);
            let e = effective(&c, false);
            let mock = Mock::new(p, move |_| match mode {
                "headers" => Reply::Stall(vec![]),
                "first" => Reply::Stall(sse_head()),
                "overall" => Reply::Drip(prefix(p), chunk(b": heartbeat\n\n")),
                _ => Reply::Stall(prefix(p)),
            })
            .await;
            let mut t = NORMAL;
            match mode {
                "setup" => t.setup = SHORT,
                "headers" | "first" | "next" => t.idle = SHORT,
                _ => t.overall = SHORT,
            }
            let mut g = mock.gateway(&e, t);
            if mode == "setup" {
                g.fixture_lookup(Arc::new(|_, port| {
                    std::thread::sleep(SHORT * 2);
                    crate::provider_http::fixture::loopback("", port)
                }));
            }
            let (tx, run) = run_stop(Instant::now() + BOUND);
            let ret = timeout(
                BOUND,
                g.server(
                    &c,
                    &e,
                    &request(true),
                    Credential::Bearer(TOKEN),
                    run,
                    |_| async {
                        if mode == "downstream" {
                            std::future::pending::<()>().await;
                        }
                    },
                ),
            )
            .await
            .unwrap();
            assert!(tx.borrow().is_none());
            let err = ret.err().unwrap();
            assert_eq!(err, Error::Timeout);
            assert_eq!(err.problem().0, 504);
            assert!(matches!(
                err.step_result(),
                StepResult::Failed(FailReason::StepFailed)
            ));
            if mode != "setup" {
                timeout(BOUND, mock.server.closed.notified()).await.unwrap();
            }
            assert_eq!(
                mock.server.connections.load(Ordering::SeqCst),
                usize::from(mode != "setup")
            );
        }
    }
}
#[tokio::test]
async fn stopped_before_dispatch_or_dropped_caller_closes_its_own_request() {
    let p = Protocol::Chat;
    let c = catalog(p, true);
    let e = effective(&c, false);
    let mock = Mock::new(p, move |_| Reply::Stall(prefix(p))).await;
    let g = mock.gateway(&e, NORMAL);
    let r = request(true);
    let (tx, run) = run_stop(Instant::now() + BOUND);
    tx.send_replace(Some(Stop::Cancel));
    assert_eq!(
        g.server(&c, &e, &r, Credential::Bearer(TOKEN), run, |_| async {})
            .await
            .err(),
        Some(Error::Stopped(Stop::Cancel))
    );
    assert_eq!(mock.server.connections.load(Ordering::SeqCst), 0);
    let mut call = Box::pin(g.caller(&c, &e, &r, Credential::Bearer(TOKEN), |_| async {}));
    tokio::select! {_=mock.server.entered.notified()=>{},_=&mut call=>panic!("unexpected completion"),_=sleep(BOUND)=>panic!("no request")}
    drop(call);
    timeout(BOUND, mock.server.closed.notified()).await.unwrap();
    mock.assert_inference_only(1);
}

#[tokio::test]
async fn caller_timeout_before_headers_and_tls_setup_close_the_peer() {
    use tokio::io::AsyncReadExt;
    for (p, stream) in MODES {
        let c = catalog(p, true);
        let e = effective(&c, false);
        let gate = Arc::new(Notify::new());
        let barrier = gate.clone();
        let mock = Mock::new(p, move |_| Reply::Gate(barrier.clone(), vec![])).await;
        let mut t = NORMAL;
        t.idle = SHORT;
        let g = mock.gateway(&e, t);
        let err = g
            .caller(
                &c,
                &e,
                &request(stream),
                Credential::Bearer(TOKEN),
                |_| async {},
            )
            .await
            .err()
            .unwrap();
        assert_eq!(
            err.problem(),
            (504, "timeout", "Gateway request timed out.")
        );
        gate.notify_one();
        mock.assert_inference_only(1);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut no_tls = mock;
        no_tls.server.port = listener.local_addr().unwrap().port();
        let mut t = NORMAL;
        t.setup = SHORT;
        let g = no_tls.gateway(&e, t);
        let r = request(stream);
        let (_tx, run) = run_stop(Instant::now() + BOUND);
        let call = g.server(&c, &e, &r, Credential::Bearer(TOKEN), run, |_| async {});
        let peer = async {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut hello = Vec::new();
            tcp.read_to_end(&mut hello).await.unwrap();
            assert!(!hello.is_empty());
        };
        let (result, ()) = timeout(BOUND, async { tokio::join!(call, peer) })
            .await
            .unwrap();
        assert_eq!(result.err(), Some(Error::Timeout));
    }
}

#[tokio::test]
async fn premature_close_is_failure_without_retry() {
    for (p, stream) in MODES {
        let c = catalog(p, true);
        let e = effective(&c, false);
        let mock = Mock::new(p, |_| Reply::Close).await;
        let result = mock
            .gateway(&e, NORMAL)
            .caller(
                &c,
                &e,
                &request(stream),
                Credential::Bearer(TOKEN),
                |_| async {},
            )
            .await;
        assert_eq!(result.err(), Some(Error::Malformed));
        mock.assert_inference_only(1);
    }
}

#[tokio::test]
async fn caller_timeout_after_visible_delta_is_an_active_protocol_failure() {
    for p in [Protocol::Chat, Protocol::Responses] {
        let c = catalog(p, true);
        let e = effective(&c, false);
        let mock = Mock::new(p, move |_| Reply::Stall(prefix(p))).await;
        let mut time = NORMAL;
        time.idle = SHORT;
        let mut streamed = String::new();
        let err = mock
            .gateway(&e, time)
            .caller(&c, &e, &request(true), Credential::Bearer(TOKEN), |delta| {
                streamed.push_str(&delta.text);
                async {}
            })
            .await
            .err()
            .unwrap();
        assert_eq!(streamed, "hello");
        assert_eq!(err, Error::Timeout);
        let payload = err.stream_error(p);
        if p == Protocol::Chat {
            assert_eq!(payload["error"]["code"], "timeout");
        } else {
            assert_eq!(payload["type"], "error");
            assert_eq!(payload["code"], "timeout");
        }
        timeout(BOUND, mock.server.closed.notified()).await.unwrap();
        mock.assert_inference_only(1);
    }
}
