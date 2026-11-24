//! The real metered path, end to end (ADR 0044 increment 2c). The packaged `openmettle-worker`
//! claims a queued run, reserves its round and hands it off, then sends it to the
//! `openmettle-gateway` binary. The gateway spends the round's one dispatch with the bearer the
//! worker made, forwards the request to the stand-in replaying a recorded SGLang answer, and
//! settles the usage that answer reports. No gateway binding, key or policy exists, and nothing
//! re-keys a request.
//!
//! The recorded answers used here carry no tool calls: the worker offers no tools and fails a
//! turn whose answer calls one (V1-14), parallel calls included.
use super::*;
use crate::gateway_proxy::{SETTLED, StandIn, header, launch_gateway};
use std::net::SocketAddr;

/// The model of the recorded answers, which the gateway under test serves.
const MODEL: &str = "recorded-sglang-model";
/// The installation every round is reserved and reported under.
const INSTALL: &str = "00000000-0000-4000-8000-0000000000e1";

/// How the worker reaches the gateway.
#[derive(Clone, Copy, PartialEq)]
enum Transport {
    /// `http://` straight to the gateway's listener on the private address.
    Plain,
    /// `https://` to a TLS terminator on the private address, which relays to the gateway's
    /// listener on loopback.
    Tls,
}

/// A chat whose catalog adds [`MODEL`], a copy of profile `a` under its own pin, and one queued
/// one-round run for it: the run and its input message.
async fn queued() -> (Chat, String, String) {
    let mut chat = Chat::new().await;
    let mut profile = chat.catalog["models"]["a"].clone();
    profile["pin"]["revision"] = json!("recorded/1");
    profile["replay"] = json!([]);
    chat.catalog["models"][MODEL] = profile;
    let (run, input) = chat.submit("end to end", MODEL, 1).await;
    (chat, run, input)
}

/// A port on `ip` that nothing listens on when this returns, for the gateway to bind.
fn free_port(ip: IpAddr) -> u16 {
    std::net::TcpListener::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A port on `ip` held by the returned socket, bound but never listening: while it lives, a
/// connection to the port is refused and nothing else can bind it.
fn reserved_port(ip: IpAddr) -> (tokio::net::TcpSocket, u16) {
    let socket = match ip {
        IpAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
        IpAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
    }
    .unwrap();
    socket.bind(SocketAddr::new(ip, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

/// Terminates TLS for `host` on `ip` and relays each connection's bytes to `backend` and back:
/// TLS in front of the gateway, which itself listens on plain HTTP. Returns the port and the CA
/// the worker must trust.
async fn terminator(host: &str, ip: IpAddr, backend: String) -> (u16, Ca) {
    let (acceptor, ca) = tls_acceptor(host);
    let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let (acceptor, backend) = (acceptor.clone(), backend.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let mut plain = tokio::net::TcpStream::connect(&backend).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
            });
        }
    });
    (port, ca)
}

/// The packaged worker routing every catalog model to `host:port` over `transport`, opted in to
/// the private address `ip` only. `ca` is the terminator's for [`Transport::Tls`].
fn start_worker(
    chat: &Chat,
    dir: &Dir,
    transport: Transport,
    (host, ip, port): (&str, IpAddr, u16),
    ca: Option<&Ca>,
    stream: bool,
) -> Packaged {
    let bundle = ca.map_or_else(|| Ca::new().pem(), Ca::pem);
    let authority = format!("{host}:{port}");
    let mut document =
        crate::auth_config_support::inference_document(dir, &chat.catalog, &bundle, &authority);
    document["installation"] = json!(INSTALL);
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    for route in document["routes"].as_object_mut().unwrap().values_mut() {
        route["private_cidrs"] = json!([format!("{ip}/{prefix}")]);
        route["stream"] = json!(stream);
        if transport == Transport::Plain {
            route["endpoint"] = json!(format!("http://{authority}/v1/chat/completions"));
            route.as_object_mut().unwrap().remove("trust");
        }
    }
    launch_packaged(&chat.f.db, dir, &document, &[])
}

/// Stops the gateway with SIGTERM, which drains running relays and their report writes, and
/// returns every `gateway.usage.*` event as (event, request ID, reason). The wait is bounded
/// like the worker's [`exited`]: past the deadline the panic drops the guard, which kills and
/// reaps the gateway, so a stuck gateway fails the case instead of hanging it.
async fn stop_gateway(
    mut gateway: Process,
    stderr: thread::JoinHandle<String>,
) -> Vec<(String, String, String)> {
    signal(&gateway.0, "-TERM");
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = gateway.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the gateway outlived its shutdown budget"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(status.success());
    tokio::task::block_in_place(|| stderr.join())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|e| e["event"].as_str().unwrap().starts_with("gateway.usage."))
        .map(|e| {
            let field = |name: &str| e[name].as_str().unwrap().to_owned();
            (
                field("event"),
                field("gateway.request_id"),
                field("error.type"),
            )
        })
        .collect()
}

/// The run's one gateway request: its ID, state, whether it was dispatched and whether it has
/// a binding.
async fn round(chat: &Chat, run: &str) -> (String, String, bool, bool) {
    let rounds: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT id::text, state, dispatched_at IS NOT NULL, binding_id IS NOT NULL
           FROM openmettle.gateway_requests WHERE run_id = $1::uuid",
    )
    .bind(run)
    .fetch_all(&mut connect(&chat.f.db.0, OWNER).await)
    .await
    .unwrap();
    let [round] = <[_; 1]>::try_from(rounds).expect("one gateway request");
    round
}

/// The token hold of request `id`: state, held units and settled units.
async fn hold(chat: &Chat, id: &str) -> (String, i64, String) {
    sqlx::query_as(
        "SELECT state, held_units, settled_units::text FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_tokens'",
    )
    .bind(id)
    .fetch_one(&mut connect(&chat.f.db.0, OWNER).await)
    .await
    .unwrap()
}

/// Every stored usage report of request `id`: source, revision, finality and token counts.
#[allow(clippy::type_complexity)]
async fn reports(
    chat: &Chat,
    id: &str,
) -> Vec<(
    String,
    i64,
    bool,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<bool>,
)> {
    sqlx::query_as(
        "SELECT source::text, revision, final, prompt_tokens, completion_tokens,
                reasoning_tokens, reasoning_included
           FROM openmettle.gateway_usage_reports WHERE request_id = $1::uuid",
    )
    .bind(id)
    .fetch_all(&mut connect(&chat.f.db.0, OWNER).await)
    .await
    .unwrap()
}

/// A queued run whose recorded answer `case` reaches the worker through the gateway over
/// `transport`, settled at the usage that answer reports.
async fn settles_through_the_gateway(transport: Transport, case: &'static str, content: &str) {
    let (_, prompt, completion, reasoning) = *SETTLED.iter().find(|(c, ..)| *c == case).unwrap();
    let stream = crate::sglang_recorded::chunked(case);
    let (chat, run, input) = queued().await;
    let upstream = StandIn::answering(case).await;
    let (host, ip) = gateway_host();
    let dir = Dir::new();
    let (gateway, logs, port, ca) = match transport {
        Transport::Plain => {
            let port = free_port(ip);
            let bind = SocketAddr::new(ip, port).to_string();
            let (gateway, logs) = launch_gateway(&chat.f.db, &bind, &upstream, MODEL, &[]);
            (gateway, logs, port, None)
        }
        Transport::Tls => {
            let bind = address();
            let (gateway, logs) = launch_gateway(&chat.f.db, &bind, &upstream, MODEL, &[]);
            let (port, ca) = terminator(&host, ip, bind).await;
            (gateway, logs, port, Some(ca))
        }
    };
    let packaged = start_worker(
        &chat,
        &dir,
        transport,
        (&host, ip, port),
        ca.as_ref(),
        stream,
    );
    chat.done(&run, "succeeded", None).await;
    // The gateway ends the worker's response before it writes the report, so stop it, which
    // drains that write, before reading what it stored.
    assert_eq!(stop_gateway(gateway, logs).await, []);

    // One round, handed off without a binding and dispatched once by the gateway.
    let (id, state, dispatched, bound) = round(&chat, &run).await;
    assert_eq!(
        (state.as_str(), dispatched, bound),
        ("handed_off", true, false)
    );
    // The upstream received the worker's request once, correlated, without the bearer.
    assert_eq!(upstream.count(), 1);
    let head = upstream.head(0);
    assert_eq!(header(&head, "x-request-id"), Some(id.as_str()));
    assert!(!head.contains("authorization"), "{head}");
    let body: Value = serde_json::from_slice(&upstream.body(0)).unwrap();
    assert_eq!(
        (&body["model"], &body["stream"]),
        (&json!(MODEL), &json!(stream))
    );
    // The stored usage is the recorded answer's, reported under the request's installation.
    assert_eq!(
        reports(&chat, &id).await,
        [(
            INSTALL.to_owned(),
            0,
            true,
            Some(prompt),
            Some(completion),
            Some(reasoning),
            Some(true)
        )]
    );
    let measured = (prompt + completion).to_string();
    assert_eq!(hold(&chat, &id).await, ("settled".to_owned(), 0, measured));
    // The run's turn holds the recorded content and counts.
    let (messages, turns, parts, head) = chat.graph().await;
    assert_eq!((messages, turns, parts), (2, 2, 2));
    assert_ne!(head.as_deref(), Some(input.as_str()));
    let mut owner = connect(&chat.f.db.0, OWNER).await;
    let answer: (String, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT p.text_value, t.input_count, t.output_count
           FROM openmettle.message_parts p JOIN openmettle.message_turns t USING (message_id)
          WHERE t.run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(answer, (content.to_owned(), Some(prompt), Some(completion)));
    // No ADR 0037 provisioning took part, and the accounting has no drift.
    let provisioned: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM openmettle.gateway_bindings)
              + (SELECT count(*) FROM openmettle.gateway_generations)
              + (SELECT count(*) FROM openmettle.gateway_policy)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(provisioned, 0);
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker(&chat.f.db).await)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));

    let (status, stderr) = terminate(packaged.process).await;
    assert!(status.success(), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn a_queued_run_settles_through_the_gateway_over_plain_http() {
    settles_through_the_gateway(Transport::Plain, "02-chat-plain", "ok").await;
}

/// The `https://` option: TLS terminated in front of the gateway, here with a streamed answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn a_queued_run_settles_through_the_gateway_behind_tls() {
    settles_through_the_gateway(Transport::Tls, "03-chat-stream-usage", "12345").await;
}

/// A gateway serving another model than the run's spends the dispatch, refuses the round with
/// `403 policy` and forwards nothing. The worker fails the turn, and the request keeps its hold
/// with no report, as the gateway page says for `model_not_served`, until increment 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn a_gateway_serving_another_model_refuses_the_round_and_keeps_its_hold() {
    let (chat, run, _) = queued().await;
    let upstream = StandIn::answering("02-chat-plain").await;
    let (host, ip) = gateway_host();
    let port = free_port(ip);
    let bind = SocketAddr::new(ip, port).to_string();
    let (gateway, logs) = launch_gateway(&chat.f.db, &bind, &upstream, "a", &[]);
    let dir = Dir::new();
    let worker = start_worker(
        &chat,
        &dir,
        Transport::Plain,
        (&host, ip, port),
        None,
        false,
    );
    chat.done(&run, "failed", Some("step_failed")).await;
    let events = stop_gateway(gateway, logs).await;

    let (id, state, dispatched, _) = round(&chat, &run).await;
    assert_eq!((state.as_str(), dispatched), ("handed_off", true));
    assert_eq!(upstream.count(), 0);
    assert_eq!(reports(&chat, &id).await, []);
    let (state, held, settled) = hold(&chat, &id).await;
    assert_eq!(
        (state.as_str(), settled.as_str()),
        ("handoff_committed", "0")
    );
    assert!(held > 0);
    let (status, stderr) = terminate(worker.process).await;
    assert!(status.success(), "{stderr}");
    assert_eq!(
        events,
        [(
            "gateway.usage.unrecorded".to_owned(),
            id,
            "model_not_served".to_owned()
        )]
    );
}

/// With nothing listening at the gateway's address, and its port held so that nothing else can
/// take it, the round was already handed off when the connection fails. The worker fails the turn without retrying it, and the request, never
/// dispatched, keeps its hold until increment 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn an_unreachable_gateway_fails_the_turn_and_keeps_the_handed_off_hold() {
    let (chat, run, _) = queued().await;
    let (host, ip) = gateway_host();
    let (_held, port) = reserved_port(ip);
    assert!(
        std::net::TcpListener::bind((ip, port)).is_err(),
        "nothing else can take the gateway's port during the case"
    );
    let dir = Dir::new();
    let worker = start_worker(
        &chat,
        &dir,
        Transport::Plain,
        (&host, ip, port),
        None,
        false,
    );
    chat.done(&run, "failed", Some("step_failed")).await;

    let (id, state, dispatched, _) = round(&chat, &run).await;
    assert_eq!((state.as_str(), dispatched), ("handed_off", false));
    assert_eq!(reports(&chat, &id).await, []);
    let (state, held, settled) = hold(&chat, &id).await;
    assert_eq!(
        (state.as_str(), settled.as_str()),
        ("handoff_committed", "0")
    );
    assert!(held > 0);
    let (status, stderr) = terminate(worker.process).await;
    assert!(status.success(), "{stderr}");
}
