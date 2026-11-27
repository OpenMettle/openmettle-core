//! OTLP/HTTP trace export (ADR 0026) against in-process collectors: a synthetic-CA TLS
//! collector that decodes what it receives, one that accepts TCP and never reads, and scripted
//! failures. No external network, cluster or PostgreSQL.
use super::{Capture, exchange};
use crate::{
    auth_config::tests::support::Dir,
    provider_http::fixture::{self, Ca, Reply, Server, loopback, response},
    telemetry::{
        Format, Method, Process, RequestId, Route, TARGET, Verbosity, metrics, observe,
        otlp::{self, Destination, Exporter, Tuning},
        request_span,
    },
};
use axum::{Router, routing::get};
use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest,
    common::v1::{AnyValue, KeyValue, any_value::Value},
    trace::v1::{Span, span::SpanKind},
};
use prost::Message;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

pub(crate) const COLLECTOR: &str = "collector.example.test";
const CANARY: &str = "CANARY-otlp-5c1e";
const TRACEPARENT_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT_SPAN: &str = "00f067aa0ba902b7";

/// Short cycles and deadlines so tests finish quickly; queue and batch bounds as in production.
const FAST: Tuning = Tuning {
    queue: otlp::QUEUE_CAPACITY,
    batch: otlp::MAX_BATCH,
    interval: Duration::from_millis(20),
    deadline: Duration::from_secs(2),
    request_body: otlp::MAX_REQUEST_BYTES,
};

fn settings(port: u16, ca_file: Option<&str>) -> otlp::Settings {
    let endpoint = format!("https://{COLLECTOR}:{port}/v1/traces");
    otlp::Settings::parse(|key| {
        Ok(match key {
            "OTLP_TRACES_ENDPOINT" => Some(endpoint.clone()),
            "OTLP_CA_FILE" => ca_file.map(str::to_owned),
            _ => None,
        })
    })
    .unwrap()
    .unwrap()
}

fn metrics_destination(port: u16, ca: &Ca, tuning: Tuning) -> otlp::Destination {
    let dir = Dir::new();
    let path = dir.write("collector-ca.pem", &ca.pem());
    let endpoint = format!("https://{COLLECTOR}:{port}/v1/metrics");
    let settings = otlp::Settings::parse(|key| {
        Ok(match key {
            "OTLP_METRICS_ENDPOINT" => Some(endpoint.clone()),
            "OTLP_CA_FILE" => Some(path.clone()),
            _ => None,
        })
    })
    .unwrap()
    .unwrap();
    otlp::Destination::load(&settings)
        .unwrap()
        .with_lookup(loopback)
        .with_tuning(tuning)
        .allow_loopback_fixture()
}

fn start_traces(
    destination: otlp::Destination,
    role: Process,
) -> (opentelemetry_sdk::trace::SdkTracer, otlp::Exporter) {
    let (tracer, exporter) = otlp::start(destination, role);
    (tracer.expect("traces endpoint configured"), exporter)
}

/// A destination for `port` trusting only `ca`, loaded through `OTLP_CA_FILE` as in
/// production, resolving to loopback.
fn destination(port: u16, ca: &Ca, tuning: Tuning) -> Destination {
    let dir = Dir::new();
    let path = dir.write("collector-ca.pem", &ca.pem());
    Destination::load(&settings(port, Some(&path)))
        .ok()
        .unwrap()
        .with_lookup(loopback)
        .allow_loopback_fixture()
        .with_tuning(tuning)
}

/// A TLS collector that records every request body and answers with `reply`.
pub(crate) struct Collector {
    pub(crate) server: Server,
    pub(crate) ca: Ca,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Collector {
    pub(crate) async fn start(reply: impl Fn() -> Reply + Send + Sync + 'static) -> Self {
        let ca = Ca::new();
        let bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let recorded = bodies.clone();
        let server = Server::start(ca.leaf(COLLECTOR, false), move |received| {
            recorded.lock().unwrap().push(received.body.clone());
            reply()
        })
        .await;
        Self { server, ca, bodies }
    }
    pub(crate) async fn accepting() -> Self {
        Self::start(|| Reply::Bytes(response(200, &[], b""))).await
    }
    pub(crate) fn destination(&self) -> Destination {
        destination(self.server.port, &self.ca, FAST)
    }
    pub(crate) fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().unwrap().clone()
    }
    pub(crate) fn requests(&self) -> Vec<ExportTraceServiceRequest> {
        let bodies = self.bodies().into_iter();
        bodies
            .map(|b| ExportTraceServiceRequest::decode(&b[..]).unwrap())
            .collect()
    }
    /// Every exported span.
    pub(crate) fn spans(&self) -> Vec<Span> {
        let mut spans = Vec::new();
        for request in self.requests() {
            for resource in request.resource_spans {
                for scope in resource.scope_spans {
                    spans.extend(scope.spans);
                }
            }
        }
        spans
    }
    /// Fails if any canary's bytes appear in any request body.
    pub(crate) fn assert_absent(&self, canaries: &[&[u8]]) {
        for body in self.bodies() {
            for canary in canaries {
                assert!(
                    !body.windows(canary.len()).any(|w| w == *canary),
                    "canary {:?} was exported",
                    String::from_utf8_lossy(canary)
                );
            }
        }
    }
}

/// Stops `exporter` with a generous deadline, so everything queued is sent.
pub(crate) async fn finish(exporter: Exporter) {
    exporter
        .stop(tokio::time::Instant::now() + Duration::from_secs(10))
        .await;
}

fn text(value: &Option<AnyValue>) -> Option<&str> {
    match value.as_ref()?.value.as_ref()? {
        Value::StringValue(s) => Some(s),
        _ => None,
    }
}

fn int(value: &Option<AnyValue>) -> Option<i64> {
    match value.as_ref()?.value.as_ref()? {
        Value::IntValue(i) => Some(*i),
        _ => None,
    }
}

fn attributes(list: &[KeyValue]) -> BTreeMap<&str, &Option<AnyValue>> {
    list.iter().map(|kv| (kv.key.as_str(), &kv.value)).collect()
}

/// Total `dropped_spans` across `telemetry.dropped` events.
fn dropped(capture: &Capture) -> u64 {
    let events = capture.events("telemetry.dropped").into_iter();
    events
        .filter_map(|e| e.get("dropped_spans").and_then(|v| v.as_u64()))
        .sum()
}

/// A lazy pool whose database address refuses connections, so readiness fails quickly.
fn refusing_pool() -> sqlx::PgPool {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(port)
                .username("fixture")
                .password(CANARY)
                .database("fixture")
                .ssl_mode(PgSslMode::Disable),
        )
}

/// Instrumentation a handler might trigger, none of which may be exported: third-party
/// spans and events, a span on our target with an unlisted field, our own spans below `info`,
/// and our own admitted events, which must not become span events.
fn foreign_instrumentation() {
    let query = tracing::info_span!(target: "sqlx::query", "query", db.statement = CANARY);
    query.in_scope(|| tracing::info!(target: "hyper::proto", role = CANARY));
    tracing::info_span!(target: "rustls::client", "handshake", request_id = CANARY).in_scope(|| {});
    tracing::info_span!(target: TARGET, "leak", password = CANARY).in_scope(|| {});
    tracing::debug_span!(target: TARGET, "verbose", request_id = CANARY).in_scope(|| {});
    tracing::trace_span!(target: TARGET, "chatty", request_id = CANARY).in_scope(|| {});
    tracing::error!(target: TARGET, event = "guard.span_event", role = "api");
}

/// The served health routes, a handler that triggers [`foreign_instrumentation`] and the
/// fallback, observed as in `serve`.
async fn serve_app() -> SocketAddr {
    let health = crate::routes(crate::Health {
        pool: refusing_pool(),
        timeout: Duration::from_millis(200),
    });
    let handler = Router::new().route(
        "/v1/thing",
        get(|| async {
            foreign_instrumentation();
            "ok\n"
        }),
    );
    let app = observe(health.merge(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    address
}

fn get_request(target: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nhost: localhost\r\ntraceparent: 00-{TRACEPARENT_ID}-{TRACEPARENT_SPAN}-01\r\n\
         tracestate: vendor={CANARY}\r\ncookie: session={CANARY}\r\nconnection: close\r\n\r\n"
    )
}

/// The happy path through the production stack: one root server span per non-probe request
/// with only the allowlisted attributes and `service.name`, sent as HTTP/1.1 protobuf over TLS
/// with exactly the core's headers.
#[tokio::test]
async fn export_carries_only_allowlisted_root_request_spans_over_tls_http1() {
    let collector = Collector::accepting().await;
    let (tracer, exporter) = start_traces(collector.destination(), Process::Api);
    let (capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Debug, tracer);
    let address = serve_app().await;
    let post = format!(
        "POST /healthz HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{CANARY}",
        CANARY.len()
    );
    let cases = [
        (get_request("/healthz"), 200),
        (get_request("/readyz"), 503),
        (post, 405),
        (get_request(&format!("/v1/thing?q={CANARY}")), 200),
        (get_request(&format!("/{CANARY}/x")), 404),
    ];
    for (request, status) in &cases {
        assert_eq!(exchange(address, request.as_bytes()).await, *status);
    }
    finish(exporter).await;

    // Only the two non-probe requests produced spans; nothing else was exported.
    let spans = collector.spans();
    assert_eq!(spans.len(), 2, "{spans:#?}");
    let mut routes = BTreeSet::new();
    let mut traces = BTreeSet::new();
    for span in &spans {
        assert_eq!(span.name, "http.server.request");
        assert_eq!(span.kind, SpanKind::Server as i32);
        // Root spans: the inbound traceparent and tracestate were ignored.
        assert!(span.parent_span_id.is_empty());
        assert!(span.trace_state.is_empty());
        assert_ne!(hex(&span.trace_id), TRACEPARENT_ID);
        assert!(traces.insert(span.trace_id.clone()));
        assert!(span.events.is_empty() && span.links.is_empty());
        let attributes = attributes(&span.attributes);
        let keys: BTreeSet<&str> = attributes.keys().copied().collect();
        assert_eq!(
            keys,
            [
                "request_id",
                "http.route",
                "http.request.method",
                "http.response.status_code"
            ]
            .into()
        );
        assert!(super::is_v4(text(attributes["request_id"]).unwrap()));
        assert_eq!(text(attributes["http.request.method"]), Some("GET"));
        let route = text(attributes["http.route"]).unwrap();
        let status = int(attributes["http.response.status_code"]).unwrap();
        routes.insert((route.to_owned(), status));
    }
    assert_eq!(
        routes,
        [("/v1/thing".to_owned(), 200), ("unmatched".to_owned(), 404)].into()
    );
    for request in collector.requests() {
        for resource in &request.resource_spans {
            let res_attrs = attributes(&resource.resource.as_ref().unwrap().attributes);
            assert_eq!(res_attrs.len(), 2);
            assert_eq!(text(res_attrs["service.name"]), Some("openmettle-api"));
            assert!(super::is_v4(
                text(res_attrs["service.instance.id"]).unwrap()
            ));
            for scope in &resource.scope_spans {
                assert_eq!(scope.scope.as_ref().unwrap().name, TARGET);
            }
        }
    }
    for head in collector.server.heads.lock().unwrap().iter() {
        let mut lines = head.trim_end().split("\r\n");
        assert_eq!(lines.next(), Some("POST /v1/traces HTTP/1.1"));
        let headers: BTreeMap<String, String> = lines
            .map(|l| {
                let (k, v) = l.split_once(':').unwrap();
                (k.to_ascii_lowercase(), v.trim().to_owned())
            })
            .collect();
        let names: BTreeSet<&str> = headers.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            ["connection", "content-length", "content-type", "host"].into()
        );
        assert_eq!(headers["connection"], "close");
        assert_eq!(headers["content-type"], "application/x-protobuf");
        let port = collector.server.port;
        assert_eq!(headers["host"], format!("{COLLECTOR}:{port}"));
    }
    collector.assert_absent(&[
        CANARY.as_bytes(),
        b"CANARY",
        b"sqlx",
        b"hyper",
        b"rustls",
        b"guard.span_event",
        b"leak",
        b"code.",
        b"thread.",
        TRACEPARENT_ID.as_bytes(),
    ]);
    // Stderr is unchanged by the span layer: one completion event per request and the
    // handler's admitted event, no span context and no canary.
    capture.assert_absent(&[CANARY.as_bytes(), b"http.server.request", b"spans"]);
    assert_eq!(capture.events("http.request.completed").len(), cases.len());
    assert_eq!(capture.events("guard.span_event").len(), 1);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A collector that accepts TCP connections and never reads from them, keeping each socket.
struct Stalled {
    port: u16,
    sockets: Arc<Mutex<Vec<tokio::net::TcpStream>>>,
}

impl Stalled {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let sockets: Arc<Mutex<Vec<tokio::net::TcpStream>>> = Arc::default();
        let kept = sockets.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                kept.lock().unwrap().push(socket);
            }
        });
        Self { port, sockets }
    }
    fn connections(&self) -> usize {
        self.sockets.lock().unwrap().len()
    }
}

/// Polls `done` on this runtime until it holds, for at most ten seconds.
async fn until(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "condition not reached");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A collector that never reads: emitting never waits, probes still answer promptly, every
/// span is accounted for exactly in rate-limited `telemetry.dropped` events, and shutdown
/// closes the stalled socket within its deadline.
#[tokio::test]
async fn a_stalled_collector_costs_spans_not_serving_or_shutdown() {
    let collector = Stalled::start().await;
    let ca = Ca::new();
    let tuning = Tuning {
        deadline: Duration::from_millis(200),
        ..FAST
    };
    let (tracer, exporter) = start_traces(destination(collector.port, &ca, tuning), Process::Api);
    let (capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Info, tracer);
    let address = serve_app().await;

    let began = Instant::now();
    for _ in 0..10_000 {
        drop(request_span(
            RequestId::generate(),
            &Route(None),
            Method::Get,
        ));
    }
    let emitting = began.elapsed();
    assert!(emitting < Duration::from_secs(5), "{emitting:?}");

    // While the exporter is held by the collector, the probes keep answering.
    for _ in 0..20 {
        let began = Instant::now();
        assert_eq!(
            exchange(address, get_request("/healthz").as_bytes()).await,
            200
        );
        assert!(began.elapsed() < Duration::from_secs(1));
    }
    until(|| dropped(&capture) >= 10_000).await;
    // The queue held 2048 of them: four full batches, each one connection and no retry.
    assert_eq!(dropped(&capture), 10_000);
    assert_eq!(
        collector.connections(),
        otlp::QUEUE_CAPACITY / otlp::MAX_BATCH
    );
    let reports = capture.events("telemetry.dropped");
    assert_eq!(reports.len(), 4, "{}", capture.text());
    for report in &reports {
        let keys: BTreeSet<&str> = report.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["timestamp", "level", "event", "dropped_spans"].into()
        );
        assert_eq!(report["level"], "ERROR");
    }

    // One more span is queued, so the stop tries to send it to the stalled collector.
    drop(request_span(
        RequestId::generate(),
        &Route(None),
        Method::Get,
    ));
    until(|| collector.connections() == 4).await;
    let began = Instant::now();
    exporter
        .stop(tokio::time::Instant::now() + Duration::from_millis(100))
        .await;
    let stopping = began.elapsed();
    assert!(stopping < Duration::from_millis(500), "{stopping:?}");
    // Cancelling the export dropped its connection: the collector sees end of stream.
    until(|| collector.connections() == 5).await;
    let mut last = collector.sockets.lock().unwrap().pop().unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buf = [0; 1024];
        while last.read(&mut buf).await.is_ok_and(|n| n > 0) {}
    })
    .await;
    assert!(closed.is_ok(), "the stalled export's socket stayed open");
    capture.assert_absent(&[CANARY.as_bytes()]);
}

/// How one failure case is set up and what the collector should see.
struct Case {
    name: &'static str,
    reply: fn(u16) -> Reply,
    leaf: &'static str,
    lookup: fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
    connections: usize,
    requests: usize,
    dropped: u64,
}

fn private_answer(_: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(vec![SocketAddr::from(([10, 0, 0, 1], port))])
}

/// Each failure drops exactly its batch with one attempt and no retry, and serving continues.
/// A redirect is never followed.
#[tokio::test]
async fn failed_exports_drop_their_batch_once_without_retry_or_redirect() {
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    static REDIRECT: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
    let _ = REDIRECT.set(target.local_addr().unwrap().port());
    let ok = |_: u16| Reply::Bytes(response(200, &[], b""));
    let cases = [
        Case {
            name: "accepted",
            reply: ok,
            leaf: COLLECTOR,
            lookup: loopback,
            connections: 1,
            requests: 1,
            dropped: 0,
        },
        Case {
            name: "redirect",
            reply: |_| {
                let location = format!("https://{COLLECTOR}:{}/v1/traces", REDIRECT.get().unwrap());
                Reply::Bytes(response(307, &[("location", &location)], b""))
            },
            leaf: COLLECTOR,
            lookup: loopback,
            connections: 1,
            requests: 1,
            dropped: 3,
        },
        Case {
            name: "server error",
            reply: |_| Reply::Bytes(response(500, &[], b"")),
            leaf: COLLECTOR,
            lookup: loopback,
            connections: 1,
            requests: 1,
            dropped: 3,
        },
        Case {
            name: "throttled",
            reply: |_| Reply::Bytes(response(429, &[("retry-after", "1")], b"")),
            leaf: COLLECTOR,
            lookup: loopback,
            connections: 1,
            requests: 1,
            dropped: 3,
        },
        Case {
            name: "oversized response",
            reply: |_| {
                let body = vec![b'x'; otlp::MAX_RESPONSE_BYTES + 1];
                Reply::Bytes(response(200, &[], &body))
            },
            leaf: COLLECTOR,
            lookup: loopback,
            connections: 1,
            requests: 1,
            dropped: 3,
        },
        Case {
            name: "certificate for another host",
            reply: ok,
            leaf: "other.example.test",
            lookup: loopback,
            connections: 1,
            requests: 0,
            dropped: 3,
        },
        Case {
            name: "private address without an allowlisted range",
            reply: ok,
            leaf: COLLECTOR,
            lookup: private_answer,
            connections: 0,
            requests: 0,
            dropped: 3,
        },
    ];
    let address = serve_app().await;
    for case in cases {
        let ca = Ca::new();
        let reply = case.reply;
        let server = Server::start(ca.leaf(case.leaf, false), move |_| reply(0)).await;
        let destination = destination(server.port, &ca, FAST).with_lookup(case.lookup);
        let (tracer, exporter) = start_traces(destination, Process::Worker);
        let (capture, guard) = Capture::install_traced(Format::Json, Verbosity::Info, tracer);
        for _ in 0..3 {
            drop(request_span(
                RequestId::generate(),
                &Route(None),
                Method::Post,
            ));
        }
        finish(exporter).await;
        assert_eq!(
            server.connections.load(Ordering::SeqCst),
            case.connections,
            "{}",
            case.name
        );
        assert_eq!(
            server.requests.load(Ordering::SeqCst),
            case.requests,
            "{}",
            case.name
        );
        assert_eq!(dropped(&capture), case.dropped, "{}", case.name);
        assert!(
            capture.events("telemetry.dropped").len() <= 1,
            "{}",
            case.name
        );
        drop(guard);
        assert_eq!(
            exchange(address, get_request("/healthz").as_bytes()).await,
            200
        );
    }
    assert!(target.accept().is_err(), "the redirect was followed");
}

/// A batch whose encoding exceeds the request bound is dropped before any DNS work.
#[tokio::test]
async fn an_oversized_batch_is_dropped_before_resolution() {
    let collector = Collector::accepting().await;
    let lookups = Arc::new(AtomicUsize::new(0));
    let counted = lookups.clone();
    let tuning = Tuning {
        request_body: 64,
        ..FAST
    };
    let destination =
        destination(collector.server.port, &collector.ca, tuning).with_lookup(move |host, port| {
            counted.fetch_add(1, Ordering::SeqCst);
            loopback(host, port)
        });
    let (tracer, exporter) = start_traces(destination, Process::Api);
    let (capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Info, tracer);
    for _ in 0..5 {
        drop(request_span(
            RequestId::generate(),
            &Route(None),
            Method::Get,
        ));
    }
    finish(exporter).await;
    assert_eq!(dropped(&capture), 5);
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert_eq!(collector.server.connections.load(Ordering::SeqCst), 0);
}

/// A gate that holds operating-system lookups until released.
#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);

impl Gate {
    fn wait(&self) {
        let (open, changed) = &*self.0;
        drop(changed.wait_while(open.lock().unwrap(), |o| !*o).unwrap());
    }
    fn release(&self) {
        let (open, changed) = &*self.0;
        *open.lock().unwrap() = true;
        changed.notify_all();
    }
}

/// The exporter's two DNS slots are its own: hung exporter lookups exhaust them without
/// touching the provider transports' process-wide pool, which keeps resolving.
#[tokio::test]
async fn exporter_dns_slots_are_isolated_from_provider_transports() {
    let gate = Gate::default();
    let held = gate.clone();
    let started = Arc::new(AtomicUsize::new(0));
    let counted = started.clone();
    let ca = Ca::new();
    let tuning = Tuning {
        batch: 1,
        deadline: Duration::from_millis(150),
        ..FAST
    };
    let destination = destination(1, &ca, tuning).with_lookup(move |host, port| {
        counted.fetch_add(1, Ordering::SeqCst);
        held.wait();
        loopback(host, port)
    });
    let slots = destination.slots.clone();
    assert_eq!(slots.available_permits(), otlp::DNS_LOOKUP_SLOTS);
    let (tracer, exporter) = start_traces(destination, Process::Api);
    let (capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Info, tracer);
    for _ in 0..3 {
        drop(request_span(
            RequestId::generate(),
            &Route(None),
            Method::Get,
        ));
    }
    // Three single-span batches: two hung lookups hold both slots, the third times out
    // waiting for one. All three batches are dropped.
    until(|| dropped(&capture) == 3).await;
    assert_eq!(slots.available_permits(), 0);
    assert_eq!(started.load(Ordering::SeqCst), otlp::DNS_LOOKUP_SLOTS);

    // A provider transport on the default process-wide pool still resolves and connects.
    let provider = Server::start(fixture::Ca::leaf(&ca, fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    let transport = fixture::transport(provider.port, &ca);
    let reply = openidconnect::AsyncHttpClient::call(
        &transport,
        fixture::token_request(&fixture::url(provider.port)),
    )
    .await
    .unwrap();
    assert_eq!(reply.status(), 200);

    gate.release();
    until(|| slots.available_permits() == otlp::DNS_LOOKUP_SLOTS).await;
    finish(exporter).await;
}

fn parse(pairs: &[(&str, &str)]) -> Result<Option<otlp::Settings>, &'static str> {
    otlp::Settings::parse(|key| {
        let found = pairs.iter().find(|(k, _)| *k == key);
        Ok(found.map(|(_, v)| v.to_string()))
    })
}

/// Unset is off; a set key is never ignored; only canonical HTTPS endpoints with a DNS host,
/// absolute CA paths and explicit private ranges are accepted; errors name the key only.
#[test]
fn settings_accept_only_https_endpoints_absolute_ca_files_and_private_ranges() {
    const ENDPOINT: &str = "https://alloy.monitoring.svc.cluster.local:4318/v1/traces";
    assert!(parse(&[]).unwrap().is_none());
    assert!(
        parse(&[("OTLP_TRACES_ENDPOINT", ENDPOINT)])
            .unwrap()
            .is_some()
    );
    let full = parse(&[
        ("OTLP_TRACES_ENDPOINT", ENDPOINT),
        ("OTLP_CA_FILE", "/etc/openmettle/collector-ca.pem"),
        ("OTLP_PRIVATE_RANGES", "10.43.0.0/16,fd00:10::/64"),
    ]);
    assert!(full.unwrap().is_some());
    for (pairs, error) in [
        (
            &[("OTLP_CA_FILE", "/etc/ca.pem")][..],
            "invalid OTLP_CA_FILE",
        ),
        (
            &[("OTLP_PRIVATE_RANGES", "10.0.0.0/8")][..],
            "invalid OTLP_PRIVATE_RANGES",
        ),
    ] {
        assert_eq!(parse(pairs).err(), Some(error), "{pairs:?}");
    }
    for endpoint in [
        "",
        "http://alloy.monitoring.svc:4318/v1/traces",
        "https://127.0.0.1:4318/v1/traces",
        "https://[::1]:4318/v1/traces",
        "https://localhost:4318/v1/traces",
        "https://Alloy.monitoring.svc:4318/v1/traces",
        "https://alloy.monitoring.svc:4318/v1/traces?x=1",
        "https://user@alloy.monitoring.svc:4318/v1/traces",
        "https://alloy.monitoring.svc:443/v1/traces",
        "https://alloy.monitoring.svc:4318/v1/%74races",
        "grpc://alloy.monitoring.svc:4317",
        CANARY,
    ] {
        assert_eq!(
            parse(&[("OTLP_TRACES_ENDPOINT", endpoint)]).err(),
            Some("invalid OTLP_TRACES_ENDPOINT"),
            "{endpoint:?}"
        );
    }
    for ca in ["", "ca.pem", "./ca.pem", "~/ca.pem"] {
        let pairs = [("OTLP_TRACES_ENDPOINT", ENDPOINT), ("OTLP_CA_FILE", ca)];
        assert_eq!(parse(&pairs).err(), Some("invalid OTLP_CA_FILE"), "{ca:?}");
    }
    let too_many = (0..=crate::provider_http::MAX_PRIVATE_RANGES)
        .map(|i| format!("10.{i}.0.0/16"))
        .collect::<Vec<_>>()
        .join(",");
    for ranges in [
        "",
        ",",
        "10.0.0.0/8,",
        "10.0.0.1/8",
        "8.8.8.0/24",
        "127.0.0.0/8",
        "0.0.0.0/0",
        "10.0.0.0/8, 192.168.0.0/16",
        "10.0.0.0/8,10.0.0.0/8",
        too_many.as_str(),
    ] {
        let pairs = [
            ("OTLP_TRACES_ENDPOINT", ENDPOINT),
            ("OTLP_PRIVATE_RANGES", ranges),
        ];
        assert_eq!(
            parse(&pairs).err(),
            Some("invalid OTLP_PRIVATE_RANGES"),
            "{ranges:?}"
        );
    }
}

/// Loading reads the CA file through the bounded reader: missing, oversized, non-PEM or a
/// directory each refuse with the fixed line.
#[test]
fn loading_refuses_unusable_ca_files_with_a_fixed_line() {
    let dir = Dir::new();
    let ca = Ca::new();
    let good = dir.write("ca.pem", &ca.pem());
    assert!(Destination::load(&settings(4318, Some(&good))).is_ok());
    let mut large = ca.pem();
    large.resize(crate::provider_http::MAX_TRUST_BUNDLE_BYTES + 1, b'\n');
    for path in [
        dir.path("missing.pem"),
        dir.write("large.pem", &large),
        dir.write("text.pem", CANARY.as_bytes()),
        dir.write("empty.pem", b""),
        dir.path(""),
    ] {
        assert_eq!(
            Destination::load(&settings(4318, Some(&path))).err(),
            Some("invalid OTLP_CA_FILE"),
            "{path}"
        );
    }
}

/// The serving processes read the OTLP keys after their existing keys and before
/// `ARTIFACTS_DIR` and `AUTH_CONFIG`; the worker and the gateway read them too.
#[test]
fn serving_configuration_reads_otlp_keys_after_logging_and_before_auth_config() {
    for role in [crate::Role::Api, crate::Role::Worker, crate::Role::Gateway] {
        let asked = std::cell::RefCell::new(Vec::new());
        let config = crate::Config::parse(role, |key| {
            asked.borrow_mut().push(key.to_owned());
            Ok(match key {
                "DATABASE_URL" => Some("postgres://localhost/test".to_owned()),
                "OTLP_TRACES_ENDPOINT" => {
                    Some("https://alloy.monitoring.svc:4318/v1/traces".to_owned())
                }
                _ => None,
            })
        });
        assert!(config.ok().unwrap().otlp.is_some());
        let asked = asked.into_inner();
        let position = |key: &str| asked.iter().position(|k| k == key);
        let level = position("LOG_LEVEL").unwrap();
        let endpoint = position("OTLP_TRACES_ENDPOINT").unwrap();
        assert_eq!(
            asked[endpoint..endpoint + 4],
            [
                "OTLP_TRACES_ENDPOINT",
                "OTLP_METRICS_ENDPOINT",
                "OTLP_CA_FILE",
                "OTLP_PRIVATE_RANGES"
            ]
        );
        assert!(level < endpoint);
        // ADR 0031: the API and the worker read `ARTIFACTS_DIR` next; the gateway never does.
        let (artifacts, auth) = match role {
            crate::Role::Api => (Some(endpoint + 4), Some(endpoint + 5)),
            crate::Role::Worker => (Some(endpoint + 4), None),
            crate::Role::Gateway => (None, None),
        };
        assert_eq!(position("ARTIFACTS_DIR"), artifacts);
        assert_eq!(position("AUTH_CONFIG"), auth);
        // A refused OTLP key precedes the AUTH_CONFIG check and follows LOG_* checks.
        let refused = crate::Config::parse(role, |key| {
            Ok(match key {
                "DATABASE_URL" => Some("postgres://localhost/test".to_owned()),
                "LOG_LEVEL" => Some("trace".to_owned()),
                "OTLP_TRACES_ENDPOINT" => Some("http://x.example.test/".to_owned()),
                _ => None,
            })
        });
        assert_eq!(refused.err(), Some("invalid LOG_LEVEL"));
        let refused = crate::Config::parse(role, |key| {
            Ok(match key {
                "DATABASE_URL" => Some("postgres://localhost/test".to_owned()),
                "OTLP_TRACES_ENDPOINT" => Some("http://x.example.test/".to_owned()),
                "AUTH_CONFIG" => Some("relative".to_owned()),
                _ => None,
            })
        });
        assert_eq!(refused.err(), Some("invalid OTLP_TRACES_ENDPOINT"));
    }
}

/// Without a tracer the stack is today's: the stderr guard refuses our request span, so it
/// neither prints nor adds span context to text lines. (With one global dispatcher, as in
/// production, the callsite's interest is `never` and the span is disabled outright; test
/// threads share callsite interest with other tests' dispatchers, so that is not asserted.)
#[test]
fn without_export_the_request_span_is_disabled() {
    for format in [Format::Json, Format::Text] {
        let (capture, _guard) = Capture::install(format, Verbosity::Debug);
        let span = request_span(RequestId::generate(), &Route(None), Method::Get);

        span.in_scope(|| tracing::warn!(target: TARGET, event = "inside", role = "api"));
        let text = capture.text();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(!text.contains("http.server.request") && !text.contains("request_id"));
    }
}

#[test]
fn metrics_endpoint_settings_parse_alone_and_with_traces() {
    const TRACES: &str = "https://alloy.monitoring.svc.cluster.local:4318/v1/traces";
    const METRICS: &str = "https://alloy.monitoring.svc.cluster.local:4318/v1/metrics";
    let parse = |pairs: &[(&str, &str)]| {
        otlp::Settings::parse(|key| {
            Ok(pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_owned()))
        })
    };
    assert!(
        parse(&[("OTLP_METRICS_ENDPOINT", METRICS)])
            .unwrap()
            .is_some()
    );
    assert!(
        parse(&[
            ("OTLP_METRICS_ENDPOINT", METRICS),
            ("OTLP_CA_FILE", "/etc/openmettle/collector-ca.pem"),
            ("OTLP_PRIVATE_RANGES", "10.43.0.0/16"),
        ])
        .unwrap()
        .is_some()
    );
    assert!(
        parse(&[
            ("OTLP_TRACES_ENDPOINT", TRACES),
            ("OTLP_METRICS_ENDPOINT", METRICS),
        ])
        .unwrap()
        .is_some()
    );
    for bad in [
        "",
        "http://alloy.monitoring.svc:4318/v1/metrics",
        "https://127.0.0.1:4318/v1/metrics",
        "https://alloy.monitoring.svc:4318/v1/metrics?token=secret",
    ] {
        assert_eq!(
            parse(&[("OTLP_METRICS_ENDPOINT", bad)]).err(),
            Some("invalid OTLP_METRICS_ENDPOINT"),
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn metrics_export_sends_valid_protobuf_over_tls_http1() {
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::metrics::v1::metric;

    let ca = Ca::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let recorded = captured.clone();
    let server = Server::start(ca.leaf(COLLECTOR, false), move |received| {
        recorded
            .lock()
            .unwrap()
            .push((received.head.clone(), received.body.clone()));
        Reply::Bytes(response(200, &[], b""))
    })
    .await;

    let store = Arc::new(metrics::Metrics::new());
    store.record_http(
        Method::Get,
        metrics::RouteClass::V1,
        metrics::StatusClass::S2xx,
        Duration::from_millis(15),
    );
    store.record_db_readiness(metrics::ReadinessOutcome::Ok, Duration::from_millis(2));
    store.record_provider_http(
        metrics::ProviderOperation::Jwks,
        metrics::ProviderOutcome::Ok,
        Duration::from_millis(40),
    );
    store.record_storage(
        metrics::StorageOperation::Reserve,
        metrics::StorageOutcome::QuotaRefused,
    );

    let dest = metrics_destination(server.port, &ca, FAST);
    let (tracer, exporter) = otlp::start_with_metrics(dest, Process::Api, store);
    assert!(
        tracer.is_none(),
        "metrics-only configuration must not install a tracer"
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    while captured.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for metrics export"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    exporter
        .stop(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;

    let requests = captured.lock().unwrap().clone();
    assert!(!requests.is_empty());
    let (head, body) = &requests[0];
    assert!(
        head.starts_with("POST /v1/metrics HTTP/1.1\r\n"),
        "unexpected request head: {head:?}"
    );
    let decoded = ExportMetricsServiceRequest::decode(body.as_slice())
        .expect("OTLP ExportMetricsServiceRequest protobuf");
    assert_eq!(decoded.resource_metrics.len(), 1);
    let res_attrs = attributes(
        &decoded.resource_metrics[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes,
    );
    assert_eq!(res_attrs.len(), 2);
    assert_eq!(text(res_attrs["service.name"]), Some("openmettle-api"));
    assert!(super::is_v4(
        text(res_attrs["service.instance.id"]).unwrap()
    ));
    let scope_metrics = &decoded.resource_metrics[0].scope_metrics[0];
    let names: Vec<&str> = scope_metrics
        .metrics
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(names.contains(&"openmettle.http.server.requests"));
    assert!(names.contains(&"openmettle.http.server.request.duration"));
    assert!(names.contains(&"openmettle.db.readiness.checks"));
    assert!(names.contains(&"openmettle.db.readiness.duration"));
    assert!(names.contains(&"openmettle.provider.http.requests"));
    assert!(names.contains(&"openmettle.provider.http.duration"));
    assert!(names.contains(&"openmettle.storage.operations"));

    let http_req = scope_metrics
        .metrics
        .iter()
        .find(|m| m.name == "openmettle.http.server.requests")
        .unwrap();
    let Some(metric::Data::Sum(sum)) = &http_req.data else {
        panic!("expected monotonic Sum");
    };
    assert!(sum.is_monotonic);
    assert_eq!(sum.data_points.len(), 1);
}

#[tokio::test]
async fn metrics_export_drops_on_collector_failure_and_reports_to_stderr() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(COLLECTOR, false), |_| {
        Reply::Bytes(response(503, &[], b""))
    })
    .await;
    let store = Arc::new(metrics::Metrics::new());
    store.record_db_readiness(metrics::ReadinessOutcome::Error, Duration::from_millis(5));

    let (capture, _guard) = Capture::install(Format::Json, Verbosity::Info);
    let dest = metrics_destination(server.port, &ca, FAST);
    let (_, exporter) = otlp::start_with_metrics(dest, Process::Worker, store.clone());

    let deadline = Instant::now() + Duration::from_secs(3);
    while store.dropped_count(metrics::DroppedSignal::MetricExports) == 0 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for dropped metric export report"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    exporter
        .stop(tokio::time::Instant::now() + Duration::from_secs(2))
        .await;

    let text = capture.text();
    let dropped_events: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|v: &serde_json::Value| v["event"] == "telemetry.dropped")
        .collect();
    assert!(
        !dropped_events.is_empty(),
        "expected telemetry.dropped in {text}"
    );
    assert!(
        dropped_events
            .iter()
            .all(|v| v["dropped_metric_exports"].as_u64().unwrap_or(0) >= 1),
        "{dropped_events:?}"
    );
}

/// A stalled metrics collector (accepts TCP and never reads) must not extend `Exporter::stop`
/// beyond its shutdown budget.
#[tokio::test]
async fn metrics_stalled_collector_does_not_extend_shutdown_deadline() {
    let collector = Stalled::start().await;
    let ca = Ca::new();
    let tuning = Tuning {
        deadline: Duration::from_secs(5),
        interval: Duration::from_millis(10),
        ..FAST
    };
    let store = Arc::new(metrics::Metrics::new());
    store.record_db_readiness(metrics::ReadinessOutcome::Ok, Duration::from_millis(1));
    let dest = metrics_destination(collector.port, &ca, tuning);
    let (_, exporter) = otlp::start_with_metrics(dest, Process::Api, store);

    until(|| collector.connections() >= 1).await;
    let budget = Duration::from_millis(125);
    let started = Instant::now();
    exporter.stop(tokio::time::Instant::now() + budget).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "stalled metrics collector held shutdown for {:?}",
        started.elapsed()
    );
}

/// When both `OTLP_TRACES_ENDPOINT` and `OTLP_METRICS_ENDPOINT` are configured, both tasks
/// export concurrently over the shared transport, carry the exact same `service.instance.id`,
/// and drain cleanly on `Exporter::stop`.
#[tokio::test]
async fn traces_and_metrics_export_concurrently_and_stop_cleanly() {
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;

    let ca = Ca::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let recorded = captured.clone();
    let server = Server::start(ca.leaf(COLLECTOR, false), move |received| {
        recorded
            .lock()
            .unwrap()
            .push((received.head.clone(), received.body.clone()));
        Reply::Bytes(response(200, &[], b""))
    })
    .await;

    let dir = Dir::new();
    let path = dir.write("collector-ca.pem", &ca.pem());
    let traces_url = format!("https://{COLLECTOR}:{}/v1/traces", server.port);
    let metrics_url = format!("https://{COLLECTOR}:{}/v1/metrics", server.port);
    let settings = otlp::Settings::parse(|key| {
        Ok(match key {
            "OTLP_TRACES_ENDPOINT" => Some(traces_url.clone()),
            "OTLP_METRICS_ENDPOINT" => Some(metrics_url.clone()),
            "OTLP_CA_FILE" => Some(path.clone()),
            _ => None,
        })
    })
    .unwrap()
    .unwrap();
    let dest = Destination::load(&settings)
        .unwrap()
        .with_lookup(loopback)
        .with_tuning(FAST)
        .allow_loopback_fixture();

    let store = Arc::new(metrics::Metrics::new());
    store.record_db_readiness(metrics::ReadinessOutcome::Ok, Duration::from_millis(2));
    let (tracer, exporter) = otlp::start_with_metrics(dest, Process::Api, store);
    let tracer = tracer.expect("traces endpoint configured");
    let (_capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Info, tracer);
    drop(request_span(
        RequestId::generate(),
        &Route(None),
        Method::Get,
    ));
    finish(exporter).await;

    let requests = captured.lock().unwrap().clone();
    let trace_body = requests
        .iter()
        .find(|(h, _)| h.starts_with("POST /v1/traces HTTP/1.1\r\n"))
        .map(|(_, b)| b)
        .expect("expected /v1/traces export");
    let metric_body = requests
        .iter()
        .find(|(h, _)| h.starts_with("POST /v1/metrics HTTP/1.1\r\n"))
        .map(|(_, b)| b)
        .expect("expected /v1/metrics export");

    let trace_req = ExportTraceServiceRequest::decode(trace_body.as_slice()).unwrap();
    let metric_req = ExportMetricsServiceRequest::decode(metric_body.as_slice()).unwrap();
    let trace_res = attributes(
        &trace_req.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes,
    );
    let metric_res = attributes(
        &metric_req.resource_metrics[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes,
    );
    let trace_instance = text(trace_res["service.instance.id"]).unwrap();
    let metric_instance = text(metric_res["service.instance.id"]).unwrap();
    assert!(super::is_v4(trace_instance));
    assert_eq!(trace_instance, metric_instance);
}

#[tokio::test]
async fn http_correlation_propagates_validated_ids_and_suppresses_on_401() {
    use crate::telemetry::record_request_run_id;
    use axum::http::{Extensions, StatusCode};

    const RUN_ID: &str = "11111111-1111-4111-8111-111111111111";
    const UNAUTH_RUN_ID: &str = "22222222-2222-4222-8222-222222222222";

    let collector = Collector::accepting().await;
    let (tracer, exporter) = start_traces(collector.destination(), Process::Api);
    let (capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Debug, tracer);

    let app = observe(
        Router::new()
            .route(
                "/v1/runs/{run_id}",
                get(move |ext: Extensions| async move {
                    record_request_run_id(&ext, RUN_ID);
                    "ok\n"
                }),
            )
            .route(
                "/v1/recheck-401/{run_id}",
                get(move |ext: Extensions| async move {
                    // Simulates recording run_id after initial session validation, followed by
                    // a post-auth DB principal/approval recheck returning 401 Unauthorized.
                    record_request_run_id(&ext, UNAUTH_RUN_ID);
                    StatusCode::UNAUTHORIZED
                }),
            )
            .route(
                "/v1/bad",
                get(|ext: Extensions| async move {
                    // Unvalidated canary strings must be silently ignored.
                    record_request_run_id(&ext, CANARY);
                    record_request_run_id(&ext, "not-a-uuid-canary");
                    "ok\n"
                }),
            ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    assert_eq!(
        exchange(
            address,
            get_request(&format!("/v1/runs/{RUN_ID}")).as_bytes()
        )
        .await,
        200
    );
    assert_eq!(
        exchange(
            address,
            get_request(&format!("/v1/recheck-401/{UNAUTH_RUN_ID}")).as_bytes()
        )
        .await,
        401
    );
    assert_eq!(
        exchange(address, get_request("/v1/bad").as_bytes()).await,
        200
    );
    server.abort();
    finish(exporter).await;

    let spans = collector.spans();
    assert_eq!(spans.len(), 3, "{spans:#?}");

    let run_span = spans
        .iter()
        .find(|s| text(attributes(&s.attributes)["http.route"]) == Some("/v1/runs/{run_id}"))
        .expect("correlated /v1/runs/{run_id} span");
    assert_eq!(run_span.name, "http.server.request");
    assert_eq!(run_span.kind, SpanKind::Server as i32);
    assert!(run_span.parent_span_id.is_empty());
    assert_eq!(run_span.dropped_attributes_count, 0);
    let run_attrs = attributes(&run_span.attributes);
    let run_keys: BTreeSet<&str> = run_attrs.keys().copied().collect();
    assert_eq!(
        run_keys,
        [
            "http.request.method",
            "http.response.status_code",
            "http.route",
            "request_id",
            "run_id",
        ]
        .into()
    );
    let run_req_id = text(run_attrs["request_id"]).unwrap();
    assert_eq!(text(run_attrs["run_id"]), Some(RUN_ID));

    // Post-auth 401 must centrally suppress `run_id` on both span and completion log.
    let unauth_span = spans
        .iter()
        .find(|s| text(attributes(&s.attributes)["http.route"]) == Some("/v1/recheck-401/{run_id}"))
        .expect("401 recheck span");
    assert_eq!(unauth_span.dropped_attributes_count, 0);
    let unauth_attrs = attributes(&unauth_span.attributes);
    assert_eq!(
        unauth_attrs.keys().copied().collect::<BTreeSet<_>>(),
        [
            "http.request.method",
            "http.response.status_code",
            "http.route",
            "request_id",
        ]
        .into()
    );
    let unauth_req_id = text(unauth_attrs["request_id"]).unwrap();
    assert_eq!(int(unauth_attrs["http.response.status_code"]), Some(401));

    let bad_span = spans
        .iter()
        .find(|s| text(attributes(&s.attributes)["http.route"]) == Some("/v1/bad"))
        .expect("/v1/bad span");
    assert_eq!(bad_span.dropped_attributes_count, 0);
    let bad_attrs = attributes(&bad_span.attributes);
    assert_eq!(
        bad_attrs.keys().copied().collect::<BTreeSet<_>>(),
        [
            "http.request.method",
            "http.response.status_code",
            "http.route",
            "request_id",
        ]
        .into()
    );

    let completed = capture.events("http.request.completed");
    assert_eq!(completed.len(), 3, "{}", capture.text());
    let run_log = completed
        .iter()
        .find(|e| e.get("http.route").and_then(|v| v.as_str()) == Some("/v1/runs/{run_id}"))
        .expect("correlated completion log");
    assert_eq!(run_log["request_id"].as_str(), Some(run_req_id));
    assert_eq!(run_log["run_id"].as_str(), Some(RUN_ID));

    let unauth_log = completed
        .iter()
        .find(|e| e.get("http.route").and_then(|v| v.as_str()) == Some("/v1/recheck-401/{run_id}"))
        .expect("401 recheck completion log");
    assert_eq!(unauth_log["request_id"].as_str(), Some(unauth_req_id));
    assert!(unauth_log.get("run_id").is_none());

    let bad_log = completed
        .iter()
        .find(|e| e.get("http.route").and_then(|v| v.as_str()) == Some("/v1/bad"))
        .expect("/v1/bad completion log");
    assert!(bad_log.get("run_id").is_none());

    collector.assert_absent(&[
        CANARY.as_bytes(),
        b"not-a-uuid-canary",
        UNAUTH_RUN_ID.as_bytes(),
    ]);
    capture.assert_absent(&[
        CANARY.as_bytes(),
        b"not-a-uuid-canary",
        UNAUTH_RUN_ID.as_bytes(),
    ]);
}

#[tokio::test]
async fn capacity_grant_lifecycle_emits_public_grant_id_as_lease_id_without_fence_secrets() {
    use crate::telemetry::{
        capacity_grant_completed, capacity_grant_span,
        metrics::{CapacityOperation, CapacityOutcome},
        record_capacity_span_grant_id,
    };
    use tracing::Instrument;

    const RUN_ID: &str = "77777777-7777-4777-8777-777777777777";
    const GRANT_ID: &str = "88888888-8888-4888-8888-888888888888";
    const FENCE_SECRET_CANARY: &str = "CANARY-controller-fence-secret-9999";

    let collector = Collector::accepting().await;
    let (tracer, exporter) = start_traces(collector.destination(), Process::Worker);
    let (capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Debug, tracer);

    // 1. Grant lifecycle: `grant_id` discovered mid-span and recorded as `lease_id`.
    let grant_span = capacity_grant_span(Some(RUN_ID), None, CapacityOperation::Grant);
    async {
        record_capacity_span_grant_id(FENCE_SECRET_CANARY); // rejected (not a UUID)
        record_capacity_span_grant_id(GRANT_ID);
        tracing::Span::current().record("operation.outcome", CapacityOutcome::Granted.as_str());
        capacity_grant_completed(
            Some(RUN_ID),
            Some(GRANT_ID),
            CapacityOperation::Grant,
            CapacityOutcome::Granted,
            Duration::from_millis(8),
        );
    }
    .instrument(grant_span)
    .await;

    // 2. Reconcile / release lifecycle with known `grant_id`.
    let rel_span = capacity_grant_span(None, Some(GRANT_ID), CapacityOperation::Reconcile);
    async {
        tracing::Span::current().record("operation.outcome", CapacityOutcome::Released.as_str());
        capacity_grant_completed(
            None,
            Some(GRANT_ID),
            CapacityOperation::Reconcile,
            CapacityOutcome::Released,
            Duration::from_millis(4),
        );
    }
    .instrument(rel_span)
    .await;

    finish(exporter).await;

    let spans = collector.spans();
    assert_eq!(spans.len(), 2, "{spans:#?}");
    for span in &spans {
        assert_eq!(span.name, "capacity.grant");
        assert_eq!(span.kind, SpanKind::Internal as i32);
        assert_eq!(span.dropped_attributes_count, 0);
        let attrs = attributes(&span.attributes);
        assert_eq!(text(attrs["lease_id"]), Some(GRANT_ID));
    }

    let events = capture.events("capacity.grant.completed");
    assert_eq!(events.len(), 2, "{}", capture.text());
    assert_eq!(events[0]["run_id"].as_str(), Some(RUN_ID));
    assert_eq!(events[0]["lease_id"].as_str(), Some(GRANT_ID));
    assert_eq!(events[0]["operation.kind"].as_str(), Some("grant"));
    assert_eq!(events[0]["operation.outcome"].as_str(), Some("granted"));
    assert_eq!(events[1]["lease_id"].as_str(), Some(GRANT_ID));
    assert_eq!(events[1]["operation.kind"].as_str(), Some("reconcile"));
    assert_eq!(events[1]["operation.outcome"].as_str(), Some("released"));

    collector.assert_absent(&[FENCE_SECRET_CANARY.as_bytes()]);
    capture.assert_absent(&[FENCE_SECRET_CANARY.as_bytes()]);
}

#[tokio::test]
async fn worker_run_and_child_operation_spans_and_logs_correlate_without_exposing_claim_token() {
    use crate::telemetry::{
        WorkerOperationKind, WorkerOperationOutcome, WorkerRunOutcome, derive_run_lease_id,
        worker_operation_completed, worker_operation_span, worker_run_claimed, worker_run_settled,
        worker_run_span,
    };
    use tracing::Instrument;

    const RUN_ID: &str = "44444444-4444-4444-8444-444444444444";
    const OP_ID: &str = "55555555-5555-4555-8555-555555555555";
    const RAW_CLAIM_TOKEN: &str = "66666666-6666-4666-8666-666666666666";

    let lease_id = derive_run_lease_id(RUN_ID, RAW_CLAIM_TOKEN);

    let collector = Collector::accepting().await;
    let (tracer, exporter) = start_traces(collector.destination(), Process::Worker);
    let (capture, _guard) = Capture::install_traced(Format::Json, Verbosity::Debug, tracer);

    let run_span = worker_run_span(RUN_ID, &lease_id);
    async {
        worker_run_claimed(RUN_ID, &lease_id);
        let op_span =
            worker_operation_span(RUN_ID, &lease_id, OP_ID, WorkerOperationKind::Inference);
        async {
            worker_operation_completed(
                RUN_ID,
                &lease_id,
                OP_ID,
                WorkerOperationKind::Inference,
                WorkerOperationOutcome::Ok,
                Duration::from_millis(12),
            );
            tracing::Span::current()
                .record("operation.outcome", WorkerOperationOutcome::Ok.as_str());
        }
        .instrument(op_span)
        .await;
        worker_run_settled(
            RUN_ID,
            &lease_id,
            WorkerRunOutcome::Succeeded,
            Duration::from_millis(25),
        );
        tracing::Span::current().record("run.outcome", WorkerRunOutcome::Succeeded.as_str());
    }
    .instrument(run_span)
    .await;

    finish(exporter).await;

    let spans = collector.spans();
    assert_eq!(spans.len(), 2, "{spans:#?}");
    let run_s = spans
        .iter()
        .find(|s| s.name == "worker.run")
        .expect("worker.run span");
    let op_s = spans
        .iter()
        .find(|s| s.name == "worker.operation")
        .expect("worker.operation span");

    assert!(run_s.parent_span_id.is_empty());
    assert_eq!(run_s.kind, SpanKind::Internal as i32);
    assert_eq!(run_s.dropped_attributes_count, 0);
    assert_eq!(op_s.trace_id, run_s.trace_id);
    assert_eq!(op_s.parent_span_id, run_s.span_id);
    assert_eq!(op_s.kind, SpanKind::Internal as i32);
    assert_eq!(op_s.dropped_attributes_count, 0);

    let run_attrs = attributes(&run_s.attributes);
    assert_eq!(
        run_attrs.keys().copied().collect::<BTreeSet<_>>(),
        ["lease_id", "run.outcome", "run_id"].into()
    );
    assert_eq!(text(run_attrs["run_id"]), Some(RUN_ID));
    assert_eq!(text(run_attrs["lease_id"]), Some(lease_id.as_str()));
    assert_eq!(text(run_attrs["run.outcome"]), Some("succeeded"));

    let op_attrs = attributes(&op_s.attributes);
    assert_eq!(
        op_attrs.keys().copied().collect::<BTreeSet<_>>(),
        [
            "lease_id",
            "operation.kind",
            "operation.outcome",
            "operation_id",
            "run_id",
        ]
        .into()
    );
    assert_eq!(text(op_attrs["run_id"]), Some(RUN_ID));
    assert_eq!(text(op_attrs["lease_id"]), Some(lease_id.as_str()));
    assert_eq!(text(op_attrs["operation_id"]), Some(OP_ID));
    assert_eq!(text(op_attrs["operation.kind"]), Some("inference"));
    assert_eq!(text(op_attrs["operation.outcome"]), Some("ok"));

    let claimed = capture.events("worker.run.claimed");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0]["run_id"].as_str(), Some(RUN_ID));
    assert_eq!(claimed[0]["lease_id"].as_str(), Some(lease_id.as_str()));

    let op_done = capture.events("worker.operation.completed");
    assert_eq!(op_done.len(), 1);
    assert_eq!(op_done[0]["run_id"].as_str(), Some(RUN_ID));
    assert_eq!(op_done[0]["lease_id"].as_str(), Some(lease_id.as_str()));
    assert_eq!(op_done[0]["operation_id"].as_str(), Some(OP_ID));
    assert_eq!(op_done[0]["operation.kind"].as_str(), Some("inference"));
    assert_eq!(op_done[0]["operation.outcome"].as_str(), Some("ok"));

    let settled = capture.events("worker.run.settled");
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0]["run_id"].as_str(), Some(RUN_ID));
    assert_eq!(settled[0]["lease_id"].as_str(), Some(lease_id.as_str()));
    assert_eq!(settled[0]["run.outcome"].as_str(), Some("succeeded"));

    collector.assert_absent(&[RAW_CLAIM_TOKEN.as_bytes()]);
    capture.assert_absent(&[RAW_CLAIM_TOKEN.as_bytes()]);
}
