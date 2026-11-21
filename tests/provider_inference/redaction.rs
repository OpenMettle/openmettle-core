//! Runs with the library's cfg(test)-only TLS exporter seam. Isolate global telemetry and
//! its panic hook in a subprocess, capturing actual stderr and decoding both collector routes.
#[allow(
    dead_code,
    reason = "shared TLS matrix helpers also serve the integration target"
)]
#[path = "support.rs"]
mod support;
use crate::{
    auth_config::tests::support::Dir,
    provider_http::{
        fixture::{self, Reply, Server},
        inference::*,
    },
    telemetry::{self, Format, Process, Verbosity, otlp},
};
use axum::{Router, http::StatusCode, routing::get};
use opentelemetry_proto::tonic::collector::{
    metrics::v1::ExportMetricsServiceRequest, trace::v1::ExportTraceServiceRequest,
};
use prost::Message;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::*;

const CANARIES: [&str; 6] = [TOKEN, PROMPT, ANSWER, THINK, ARG, ECHO];
const CHILD: &str = "OPENMETTLE_INFERENCE_REDACTION_CHILD";
#[test]
fn captures_real_stderr_and_both_decoded_otlp_signals() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "provider_http::inference_redaction::redaction_child",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "redaction child failed: {}",
        String::from_utf8_lossy(&child.stdout)
    );
    let stderr = String::from_utf8(child.stderr).unwrap();
    assert!(
        stderr.contains("http.request.completed") || stderr.contains("request.completed"),
        "missing request logs"
    );
    for text in CANARIES {
        assert!(!stderr.contains(text), "canary reached stderr");
    }
}
#[tokio::test]
#[ignore = "subprocess with isolated global subscriber"]
async fn redaction_child() {
    if std::env::var(CHILD).as_deref() != Ok("1") {
        return;
    }
    let ca = fixture::Ca::new();
    let received = Arc::new(Mutex::new(Vec::new()));
    let capture = received.clone();
    let collector = Server::start(ca.leaf(fixture::HOST, false), move |r| {
        capture
            .lock()
            .unwrap()
            .push((r.head.starts_with("POST /v1/traces "), r.body.clone()));
        Reply::Bytes(fixture::response(200, &[], b""))
    })
    .await;
    let dir = Dir::new();
    let pem = dir.write("synthetic-ca.pem", &ca.pem());
    let settings = otlp::Settings::parse(|key| {
        Ok(match key {
            "OTLP_CA_FILE" => Some(pem.clone()),
            "OTLP_TRACES_ENDPOINT" => Some(format!(
                "https://{}:{}/v1/traces",
                fixture::HOST,
                collector.port
            )),
            "OTLP_METRICS_ENDPOINT" => Some(format!(
                "https://{}:{}/v1/metrics",
                fixture::HOST,
                collector.port
            )),
            _ => None,
        })
    })
    .unwrap()
    .unwrap();
    let dest = otlp::Destination::load(&settings)
        .unwrap()
        .with_lookup(fixture::loopback)
        .allow_loopback_fixture()
        .with_tuning(otlp::Tuning {
            queue: otlp::QUEUE_CAPACITY,
            batch: otlp::MAX_BATCH,
            interval: Duration::from_millis(20),
            deadline: Duration::from_secs(2),
            request_body: otlp::MAX_REQUEST_BYTES,
        });
    let installed = telemetry::install(
        telemetry::Settings {
            format: Format::Json,
            verbosity: Verbosity::Debug,
        },
        Process::Api,
        Some(dest),
    )
    .unwrap();
    for (p, stream) in MODES {
        let good = canary_turn(p, stream);
        let count = AtomicUsize::new(0);
        let mock = Mock::new(p, move |r| {
            assert!(
                r.head.contains(TOKEN) && std::str::from_utf8(&r.body).unwrap().contains(PROMPT)
            );
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                let gate = Arc::new(tokio::sync::Notify::new());
                gate.notify_one();
                let (first, last) = good.split_at(good.len() / 2);
                Reply::Split(first.into(), gate, last.into())
            } else {
                Reply::Bytes(fixture::response(
                    422,
                    &[("X-Echo", TOKEN)],
                    CANARIES.join(" ").as_bytes(),
                ))
            }
        })
        .await;
        let c = Arc::new(catalog(p, true));
        let e = Arc::new(effective(&c, false));
        let g = Arc::new(mock.gateway(&e, NORMAL));
        let app = telemetry::observe(Router::new().route(
            "/completion",
            get(move || {
                let (c, e, g) = (c.clone(), e.clone(), g.clone());
                async move {
                    match g
                        .caller(
                            &c,
                            &e,
                            &request(stream),
                            Credential::Bearer(TOKEN),
                            |_| async {},
                        )
                        .await
                    {
                        Ok(turn) => {
                            let a = &turn.answers[0];
                            assert_eq!(a.parts, [ANSWER]);
                            assert!(
                                a.reasoning.as_ref().unwrap().blocks[0]
                                    .to_string()
                                    .contains(THINK)
                            );
                            assert!(
                                matches!(&a.calls,CallGroup::Valid(c) if c[0].arguments["v"]==ARG)
                            );
                            StatusCode::OK
                        }
                        Err(err) => {
                            assert_eq!(err, Error::Provider);
                            for text in CANARIES {
                                assert!(
                                    !format!("{err:?} {err} {:?}", err.problem()).contains(text)
                                );
                            }
                            StatusCode::BAD_GATEWAY
                        }
                    }
                }
            }),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for status in [200, 502] {
            assert_eq!(
                telemetry::tests::exchange(
                    addr,
                    b"GET /completion HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                .await,
                status
            );
        }
        server.abort();
    }
    assert!(installed.stop(Duration::from_secs(5)).await);
    let mut statuses = Vec::new();
    let mut metric = false;
    for (trace, bytes) in received.lock().unwrap().iter() {
        let decoded = if *trace {
            let req = ExportTraceServiceRequest::decode(bytes.as_slice()).unwrap();
            for resource in &req.resource_spans {
                for scope in &resource.scope_spans {
                    for span in &scope.spans {
                        assert_eq!(span.name, "http.server.request");
                        statuses.extend(
                            span.attributes
                                .iter()
                                .filter(|a| a.key == "http.response.status_code")
                                .map(|a| format!("{:?}", a.value)),
                        );
                    }
                }
            }
            format!("{req:?}")
        } else {
            let req = ExportMetricsServiceRequest::decode(bytes.as_slice()).unwrap();
            metric |= req
                .resource_metrics
                .iter()
                .flat_map(|r| &r.scope_metrics)
                .flat_map(|s| &s.metrics)
                .any(|m| m.name.contains("http"));
            format!("{req:?}")
        };
        for text in CANARIES {
            assert!(
                !decoded.contains(text) && !bytes.windows(text.len()).any(|w| w == text.as_bytes())
            );
        }
    }
    assert!(metric);
    for code in ["200", "502"] {
        assert_eq!(statuses.iter().filter(|s| s.contains(code)).count(), 4);
    }
}
