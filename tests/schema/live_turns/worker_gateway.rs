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
    start_worker_with(chat, dir, transport, (host, ip, port), ca, stream, &[])
}

fn start_worker_with(
    chat: &Chat,
    dir: &Dir,
    transport: Transport,
    (host, ip, port): (&str, IpAddr, u16),
    ca: Option<&Ca>,
    stream: bool,
    settings: &[(&str, &str)],
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
    launch_packaged(&chat.f.db, dir, &document, settings)
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

/// Reads `GET /v1/conversations/{id}/branches/{branch_id}/messages` through a real `openmettle-api`
/// binary authenticated as the chat's actor, verifying the API's JSON wire projection.
async fn fetch_branch_messages(chat: &Chat) -> Value {
    use std::io::{BufRead, BufReader};
    let dir = Dir::new();
    let doc = crate::auth_config_support::document_v2_native(&dir, &Ca::new().pem());
    let auth_path = dir.write("auth.json", &serde_json::to_vec(&doc).unwrap());
    let bind = address();
    let mut api = Process(
        binary("api")
            .env("OPENMETTLE_API_AUTH_CONFIG", auth_path)
            .env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", chat.f.db.url(API))
            .env(
                "OPENMETTLE_API_ISSUANCE_DATABASE_URL",
                chat.f.db.url(ISSUANCE),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_ready(&mut api, &bind);
    let cookie = crate::authz_runs::seeded_session(&chat.f.db, &chat.f.actor, 77, None).await;
    let path = format!(
        "/v1/conversations/{}/branches/{}/messages",
        chat.root.conversation_id, chat.root.branch_id
    );
    let mut stream = TcpStream::connect(&bind).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: app.example.test\r\nCookie: __Host-openmettle-session={cookie}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    loop {
        let n = reader.read_line(&mut headers).unwrap();
        assert!(n > 0, "incomplete API response headers");
        if headers.ends_with("\r\n\r\n") {
            break;
        }
    }
    assert!(headers.starts_with("HTTP/1.1 200 "), "{headers}");
    let mut body = String::new();
    reader.read_to_string(&mut body).unwrap();
    signal(&api.0, "-TERM");
    assert!(api.0.wait().unwrap().success());
    serde_json::from_str(&body).unwrap()
}

/// A queued run whose recorded answer `case` reaches the worker through the gateway over
/// `transport`, settled at the usage that answer reports.
async fn settles_through_the_gateway(
    transport: Transport,
    case: &'static str,
    content: &str,
    expected_stop_reason: Option<&str>,
) {
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
            1,
            true,
            Some(prompt),
            Some(completion),
            Some(reasoning),
            Some(true)
        )]
    );
    let measured = (prompt + completion).to_string();
    assert_eq!(hold(&chat, &id).await, ("settled".to_owned(), 0, measured));
    // The run's turn holds the recorded content, counts and stop_reason.
    let (messages, turns, parts, head) = chat.graph().await;
    assert_eq!((messages, turns, parts), (2, 2, 2));
    assert_ne!(head.as_deref(), Some(input.as_str()));
    let mut owner = connect(&chat.f.db.0, OWNER).await;
    let answer: (String, Option<i64>, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT p.text_value, t.input_count, t.output_count, t.stop_reason
           FROM openmettle.message_parts p JOIN openmettle.message_turns t USING (message_id)
          WHERE t.run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        answer,
        (
            content.to_owned(),
            Some(prompt),
            Some(completion),
            expected_stop_reason.map(str::to_owned),
        )
    );
    // The mounted API exposes the assistant message's stop_reason (and null on user turns).
    let page = fetch_branch_messages(&chat).await;
    crate::consumer::decode_conversation_operation("listMessages", &page).unwrap();
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["role"], "assistant");
    assert_eq!(items[0]["parts"][0]["text"], content);
    assert_eq!(items[0]["input_count"], prompt.to_string());
    assert_eq!(items[0]["output_count"], completion.to_string());
    assert_eq!(items[0]["stop_reason"], json!(expected_stop_reason));
    assert_eq!(items[1]["role"], "user");
    assert_eq!(items[1]["stop_reason"], Value::Null);
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
    settles_through_the_gateway(Transport::Plain, "02-chat-plain", "ok", None).await;
}

/// The `https://` option: TLS terminated in front of the gateway, here with a streamed answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn a_queued_run_settles_through_the_gateway_behind_tls() {
    settles_through_the_gateway(Transport::Tls, "03-chat-stream-usage", "12345", None).await;
}

/// Recorded `07-chat-stream-length`: a streamed response stopped at its output token limit
/// settles through the gateway at actual usage (`21 + 12 = 33`), succeeds with partial text,
/// stores `stop_reason = 'limit'`, and exposes `"stop_reason": "limit"` over the API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn a_token_limit_stop_publishes_partial_output_and_settles_through_the_gateway() {
    settles_through_the_gateway(
        Transport::Plain,
        "07-chat-stream-length",
        "The lighthouse did not merely stand on the island of Oak",
        Some("limit"),
    )
    .await;
}

/// A gateway serving another model than the run's spends the dispatch, refuses the round with
/// `403 policy` and forwards nothing. The worker fails the turn. The gateway closes the request
/// with a final report that carries the reason `model_not_served` and no count: the hold is
/// released, nothing is charged and the accounting has no drift.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn a_gateway_serving_another_model_refuses_the_round_and_closes_its_hold() {
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
    assert_eq!(
        reports(&chat, &id).await,
        [(INSTALL.to_owned(), 1, true, None, None, None, None)]
    );
    let mut owner = connect(&chat.f.db.0, OWNER).await;
    let closed: (Option<String>, bool) = sqlx::query_as(
        "SELECT r.incomplete, q.settled_final FROM openmettle.gateway_usage_reports r
           JOIN openmettle.gateway_requests q ON q.id = r.request_id
          WHERE r.request_id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(closed, (Some("model_not_served".to_owned()), true));
    assert_eq!(
        hold(&chat, &id).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    let charged: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(active_used + reserved_held), 0)::bigint
           FROM openmettle.quota_budgets WHERE resource_kind = 'usage_tokens'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(charged, 0, "nothing is charged and nothing stays reserved");
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut self::worker(&chat.f.db).await)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
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
/// take it, the round was already handed off when the connection fails. The worker fails the
/// turn without retrying it, and the request is never dispatched. The packaged worker's own
/// maintenance sweep (increment 3b, migration 32) then closes the request with a revision-0
/// final report carrying `not_dispatched`, releases the hold with nothing charged, and leaves
/// zero accounting drift.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn an_unreachable_gateway_fails_the_turn_and_the_sweep_closes_its_hold() {
    let (chat, run, _) = queued().await;
    let (host, ip) = gateway_host();
    let (_held, port) = reserved_port(ip);
    assert!(
        std::net::TcpListener::bind((ip, port)).is_err(),
        "nothing else can take the gateway's port during the case"
    );
    let dir = Dir::new();
    let worker = start_worker_with(
        &chat,
        &dir,
        Transport::Plain,
        (&host, ip, port),
        None,
        false,
        &[("SWEEP_MS", "1000")],
    );
    chat.done(&run, "failed", Some("step_failed")).await;

    let (id, state, dispatched, _) = round(&chat, &run).await;
    assert_eq!((state.as_str(), dispatched), ("handed_off", false));
    let mut owner = connect(&chat.f.db.0, OWNER).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let settled: bool = sqlx::query_scalar(
            "SELECT settled_final FROM openmettle.gateway_requests WHERE id = $1::uuid",
        )
        .bind(&id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if settled {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "worker maintenance sweep did not close the undispatched request"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(
        reports(&chat, &id).await,
        [(INSTALL.to_owned(), 0, true, None, None, None, None)]
    );
    let closed: (Option<String>, bool, i64, bool, Option<String>, i64) = sqlx::query_as(
        "SELECT r.incomplete, q.settled_final, s.revision, s.final, s.measured::text, s.outstanding
           FROM openmettle.gateway_usage_reports r
           JOIN openmettle.gateway_requests q ON q.id = r.request_id
           JOIN openmettle.gateway_settlements s ON s.request_id = r.request_id
          WHERE r.request_id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        closed,
        (Some("not_dispatched".to_owned()), true, 0, true, None, 0)
    );
    assert_eq!(
        hold(&chat, &id).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    let charged: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(active_used + reserved_held), 0)::bigint
           FROM openmettle.quota_budgets WHERE resource_kind = 'usage_tokens'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(charged, 0, "nothing is charged and nothing stays reserved");
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut self::worker(&chat.f.db).await)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
    let (status, stderr) = terminate(worker.process).await;
    assert!(status.success(), "{stderr}");
    assert!(!stderr.contains("worker.sweep.failed"), "{stderr}");
}

/// Issue #166 (migration 34): end-to-end cost-metered turn through the packaged
/// `openmettle-worker` and `openmettle-gateway` binaries. Admission holds a 2-round
/// `usage_cost_micros` + `usage_tokens` parent budget, the worker hands off Round 1 recording
/// `Profile.cost_bound = { fixed_micros: 50, micros_per_token: 10 }` on `gateway_requests`, the
/// proxy settles `02-chat-plain` (`17 + 2 = 19` tokens -> `19 * 10 + 50 = 240` micros), and
/// terminal parent unwind releases the unused Round 2 holds leaving exact token and cost
/// `active_used`, `reserved_held = 0`, and zero accounting drift.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 and TEST_GATEWAY_HOST"]
async fn a_cost_metered_turn_settles_through_the_gateway_with_recorded_prices() {
    use openmettle_core::quotas::{self as budgets, RunBudgetReservation};

    let mut chat = Chat::new().await;
    let mut admin = chat.f.db.admin().await;
    admin
        .execute(
            "UPDATE openmettle.quota_defaults SET cost_denomination='usd_micros'
              WHERE scope_kind='instance' AND resource_kind='usage_cost_micros'",
        )
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
             VALUES ('personal','usage_cost_micros',1000000)",
        )
        .await
        .unwrap();

    let mut profile = chat.catalog["models"]["a"].clone();
    profile["pin"]["revision"] = json!("recorded/cost-1");
    profile["replay"] = json!([]);
    profile["cost_bound"] = json!({"fixed_micros": 50, "micros_per_token": 10});
    chat.catalog["models"][MODEL] = profile;

    // Admit a 2-round run with explicit admission-time token and cost parent holds.
    let f = &chat.f;
    let conv = Conversation {
        scope: &f.scope,
        id: &chat.root.conversation_id,
    };
    let branch = &chat.root.branch_id;
    let mut api_c = api(&f.db).await;
    let head: Option<String> = sqlx::query_scalar(
        "SELECT head_message_id::text FROM openmettle.branch_heads WHERE branch_id=$1::uuid",
    )
    .bind(branch)
    .fetch_one(&mut api_c)
    .await
    .unwrap();
    let input: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut api_c)
        .await
        .unwrap();
    let selection: Selection = serde_json::from_value(
        json!({"model": MODEL, "layer": {"controls": {"output_reserve": 256}}}),
    )
    .unwrap();
    let parts = [Part::Text("cost metered turn".into())];
    let op = Operation::Append(UserInput {
        id: &input,
        parts: &parts,
    });
    let intent = Intent {
        source_branch_id: branch,
        expected_head_message_id: head.as_deref(),
        operation: op,
        selection: &selection,
        requested_rounds: Some(2),
    };
    let catalog = Catalog::load(&serde_json::to_vec(&chat.catalog).unwrap()).unwrap();
    let effective = catalog
        .resolve(&Selection::default(), &selection, None, |_, _| true)
        .unwrap();
    let round_tokens = i64::try_from(effective.ceiling.value.unwrap()).unwrap();
    let per_round_cost = catalog.round_cost_ceiling(&effective).unwrap();
    assert_eq!(
        per_round_cost,
        Some(50 + u128::try_from(round_tokens).unwrap() * 10)
    );
    let config = ConfigSnapshot {
        effective,
        required_capabilities: catalog.model(MODEL).unwrap().required_capabilities.clone(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: catalog.model(MODEL).unwrap().cost_bound,
    };
    let actor = principal(&f.db, &f.actor).await;
    let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
    branches::prepare_turn(
        &mut tx,
        &ctx(&f.actor, "cost-turn"),
        conv,
        branch,
        head.as_deref(),
        op,
    )
    .await
    .unwrap();
    let history = branches::history(tx.connection().unwrap(), &actor, conv, branch, NOW)
        .await
        .unwrap()
        .unwrap();
    let pins = Snapshots::encode(&intent, &history, &catalog, &config).unwrap();
    let capabilities: Vec<_> = config
        .required_capabilities
        .iter()
        .map(|(name, gate)| queue::CapabilityUse { name, gate: *gate })
        .collect();
    let admission = queue::RunAdmission {
        input: RunInput {
            scope: &f.scope,
            actor: &f.actor.user,
            conversation: conv.id,
            branch,
            message: &input,
            key: "cost-turn",
            format: SNAPSHOT_FORMAT,
            version: SNAPSHOT_VERSION,
            input: &pins.input,
            config: &pins.config,
        },
        actor_approval_id: &f.actor.approval,
        capabilities: &capabilities,
        requested_rounds: Some(2),
        now_ms: NOW,
        cost_qualified: Some(true),
    };
    let limits = queue::AdmissionLimits {
        live_per_actor: 4,
        live_per_scope: 4,
        queued_in_instance: 4,
        round_cap: 4,
        queue_timeout: Duration::from_secs(60),
    };
    let queue::Admission::Admitted { run_id: run, .. } =
        queue::admit_run(&mut tx, &admission, &limits)
            .await
            .unwrap()
    else {
        panic!("expected admission");
    };
    let refused = budgets::reserve_admitted_run_budget(
        &mut tx,
        &RunBudgetReservation {
            scope_id: &f.scope,
            scope_kind: "personal",
            actor_user_id: &f.actor.user,
            actor_approval_id: &f.actor.approval,
            run_id: &run,
            token_units: round_tokens * 2,
            per_round_cost_micros: per_round_cost,
            round_limit: 2,
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    assert!(refused.is_none(), "{refused:?}");
    tx.commit().await.unwrap();

    let upstream = StandIn::answering("02-chat-plain").await;
    let (host, ip) = gateway_host();
    let port = free_port(ip);
    let bind = SocketAddr::new(ip, port).to_string();
    let (gateway, logs) = launch_gateway(&chat.f.db, &bind, &upstream, MODEL, &[]);
    let dir = Dir::new();
    let packaged = start_worker(
        &chat,
        &dir,
        Transport::Plain,
        (&host, ip, port),
        None,
        false,
    );

    chat.done(&run, "succeeded", None).await;
    assert_eq!(stop_gateway(gateway, logs).await, []);

    let (id, state, dispatched, bound) = round(&chat, &run).await;
    assert_eq!(
        (state.as_str(), dispatched, bound),
        ("handed_off", true, false)
    );
    assert_eq!(
        hold(&chat, &id).await,
        ("settled".to_owned(), 0, "19".to_owned())
    );
    let mut owner = connect(&chat.f.db.0, OWNER).await;
    let recorded_pricing: (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT cost_fixed_micros, cost_micros_per_token
           FROM openmettle.gateway_requests
          WHERE id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(recorded_pricing, (Some(50), Some(10)));
    let cost_hold: (String, i64, String) = sqlx::query_as(
        "SELECT state, held_units, settled_units::text FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(cost_hold, ("settled".to_owned(), 0, "240".to_owned()));

    let budgets: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT resource_kind, active_used::bigint, reserved_held::bigint
           FROM openmettle.quota_budgets
          WHERE scope_id = $1::uuid
          ORDER BY resource_kind",
    )
    .bind(&chat.f.scope)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        budgets,
        vec![
            ("usage_cost_micros".to_owned(), 240, 0),
            ("usage_tokens".to_owned(), 19, 0),
        ]
    );

    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut self::worker(&chat.f.db).await)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));

    let (status, stderr) = terminate(packaged.process).await;
    assert!(status.success(), "{stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn family_policy_denial_at_handoff_settles_run_as_revoked() {
    let chat = Chat::new().await;
    let _installation = chat.ensure_metered_gateway().await;
    let (run, _input) = chat.submit("family-handoff-revoked", "a", 1).await;

    // Hold account_admin_lock FOR UPDATE and stage a disabled-model family policy (uncommitted).
    // TurnExecutor passes recheck_claim and TurnExecutor::authority before blocking on
    // account_admin_lock inside reserve_turn_round / handoff_turn, then hits the committed policy
    // at handoff_turn and must recheck + settle as `cancelled` (`revoked`), not `failed` (`step_failed`).
    let mut owner = connect(&chat.f.db.0, OWNER).await;
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let mut tx = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.account_admin_lock FOR UPDATE")
        .execute(&mut *tx)
        .await
        .unwrap();
    let pid: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_user_id, active, zone)
         VALUES ('user', $1::uuid, true, 'UTC') RETURNING id::text",
    )
    .bind(&chat.f.actor.user)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
         VALUES ($1::uuid, 'disabled', 'a', true)",
    )
    .bind(&pid)
    .execute(&mut *tx)
    .await
    .unwrap();

    let provider = Provider::new().await;
    let _worker = chat.start(&provider).await;
    wait_for_blocked_peer(&chat.f.db, holder_pid).await;
    tx.commit().await.unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    let (state, cancel_reason): (String, Option<String>) = loop {
        let row: (String, Option<String>) =
            sqlx::query_as("SELECT state, cancel_reason FROM openmettle.runs WHERE id = $1::uuid")
                .bind(&run)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        if matches!(row.0.as_str(), "cancelled" | "failed" | "succeeded") {
            break row;
        }
        assert!(Instant::now() < deadline, "run did not settle: {row:?}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(state, "cancelled");
    assert_eq!(cancel_reason.as_deref(), Some("revoked"));
}
