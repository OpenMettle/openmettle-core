//! `openmettle-gateway`, increment 1 of the V1-06 proxy. The real binary, whose only database
//! login is `openmettle_gateway`, forwards requests to a stand-in upstream that replays the
//! responses recorded from a real SGLang deployment (`tests/fixtures/sglang-recorded/`), and
//! settles the usage they report. Every case uses its own handed-off gateway request.
use super::*;
use crate::{
    quotas::TurnHandoffFixture,
    sglang_recorded::{self as recorded, ABORTED},
};
use openmettle_core::{
    authz::gateway::{self, Authority, Call, Reservation},
    provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
};
use serde_json::Value;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{Mutex, atomic::AtomicUsize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};

const INSTALL: &str = "00000000-0000-4000-8000-0000000000a1";
const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000a2";
const BUDGET: &str = "00000000-0000-4000-8000-0000000000a3";
/// The report source of the gateway policy, stored on every handed-off request.
const SOURCE: &str = "00000000-0000-4000-8000-0000000000a4";
/// Token hold of each request: room for every recorded answer.
const UNITS: i64 = 1000;
/// Synthetic caller credentials that must reach neither the upstream nor the logs.
const CREDENTIAL: &str = "canary-caller-credential-gateway-proxy";
const COOKIE: &str = "canary-cookie-gateway-proxy";

/// Recorded 200 answers and the usage each reports: prompt, completion and reasoning tokens.
/// Reasoning is already inside the completion count on this server.
const SETTLED: [(&str, i64, i64, i64); 5] = [
    ("02-chat-plain", 17, 2, 0),
    ("03-chat-stream-usage", 23, 6, 0),
    ("04-chat-stream-reasoning", 67, 37, 33),
    ("05-chat-stream-tools", 354, 52, 0),
    ("07-chat-stream-length", 21, 12, 0),
];
/// A recorded `500 Internal Server Error`, replayed for its request body.
const UPSTREAM_500: &str = "09-responses-plain";

// --- database fixture -------------------------------------------------------------------------

fn pool(db: &TestDb, role: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(3)
        .connect_lazy_with(db.1.options(role))
}

fn keys() -> GatewayKeys {
    GatewayKeys::new(&[("fixture".into(), [42; 32])]).unwrap()
}

/// One account with a ready gateway binding whose session reserves and hands off requests.
struct Fixture {
    db: TestDb,
    api: PgPool,
    owner: PgPool,
    actor: authz_store::Account,
    scope: String,
    session: String,
    route: TurnHandoffFixture,
}

impl Fixture {
    async fn new() -> Self {
        let db = TestDb::migrated().await;
        db.admin()
            .await
            .execute(
                "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
                 VALUES ('personal','usage_tokens',1000000)",
            )
            .await
            .unwrap();
        let mut c = connect(&db.0, OWNER).await;
        authz_store::providers(&mut c).await;
        let actor =
            authz_store::account(&mut c, authz_store::PROVIDER, true, authz_store::FUTURE).await;
        let scope = authz_runs::personal_of(&db, &actor).await;
        let session = authz_runs::seeded_session(&db, &actor, 4, None).await;
        let api = pool(&db, API);
        let g = pool(&db, pg::GATEWAY);
        let binding: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid) RETURNING id::text",
        )
        .bind(INSTALL)
        .bind(&actor.user)
        .bind(PRINCIPAL)
        .bind(BUDGET)
        .fetch_one(&g)
        .await
        .unwrap();
        let context = Context {
            installation: INSTALL,
            user_id: &actor.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        };
        let (fingerprint, sealed) = GatewaySealer::new(keys(), g.clone())
            .seal(&context, &Bearer::generate().unwrap())
            .await
            .unwrap();
        sqlx::query("INSERT INTO openmettle.gateway_generations (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
            VALUES ($1::uuid,1,gen_random_uuid(),clock_timestamp()+interval '1 hour',$2,$3,$4,$5)")
            .bind(&binding).bind(&sealed.key_id).bind(fingerprint.as_slice()).bind(sealed.nonce.as_slice())
            .bind(sealed.ciphertext).execute(&g).await.unwrap();
        sqlx::query("INSERT INTO openmettle.gateway_policy (binding_id,revision,scope_id,approval_id,model,report_source,provider_generation,approval_generation,user_generation,capabilities)
            VALUES ($1::uuid,1,$2::uuid,$3::uuid,'a',$4::uuid,0,0,0,'{\"inference\":true}')")
            .bind(&binding).bind(&scope).bind(&actor.approval).bind(SOURCE).execute(&g).await.unwrap();
        sqlx::query("INSERT INTO openmettle.user_capability_grants (user_id,capability,granted,updated_by_user_id)
            VALUES ($1::uuid,'inference',true,$1::uuid)").bind(&actor.user).execute(&api).await.unwrap();
        g.execute("UPDATE openmettle.gateway_bindings SET active_generation=1,observed_revision=1,state='ready'")
            .await
            .unwrap();
        // From here on, every `openmettle_gateway` connection belongs to the binary.
        g.close().await;
        Self {
            owner: pool(&db, OWNER),
            route: TurnHandoffFixture::chat(INSTALL, "a", UNITS, None, false),
            db,
            api,
            actor,
            scope,
            session,
        }
    }

    /// A new caller request of `UNITS` tokens, handed off unless `reserved_only`.
    async fn request(&self, reserved_only: bool) -> String {
        let reservation: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&self.owner)
            .await
            .unwrap();
        let call = Call {
            installation: INSTALL,
            model: "a",
            units: UNITS,
            reservation: Reservation {
                id: &reservation,
                scope_id: &self.scope,
                actor: &self.actor.user,
                approval: &self.actor.approval,
            },
            authority: Authority::Session {
                credential: &self.session,
                native_audience: None,
            },
        };
        let pending = gateway::reserve(&self.api, call).await.unwrap();
        if !reserved_only {
            let handed_off = pending
                .handoff(
                    &self.api,
                    &keys(),
                    &self.route.billable(),
                    self.route.prepare_mode(false),
                )
                .await;
            assert!(handed_off.is_ok());
        }
        pending.id.clone()
    }

    /// Every stored report of `id`: report ID, source, revision, finality and token counts.
    #[allow(clippy::type_complexity)]
    async fn reports(
        &self,
        id: &str,
    ) -> Vec<(
        String,
        String,
        i64,
        bool,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<bool>,
    )> {
        sqlx::query_as(
            "SELECT report_id::text,source::text,revision,final,prompt_tokens,completion_tokens,
                    reasoning_tokens,reasoning_included
               FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid ORDER BY revision",
        )
        .bind(id)
        .fetch_all(&self.owner)
        .await
        .unwrap()
    }

    /// The settlement of `id`: revision, finality, measured tokens and outstanding hold.
    async fn settlement(&self, id: &str) -> Option<(i64, bool, Option<String>, i64)> {
        sqlx::query_as(
            "SELECT revision,final,measured::text,outstanding
               FROM openmettle.gateway_settlements WHERE request_id=$1::uuid",
        )
        .bind(id)
        .fetch_optional(&self.owner)
        .await
        .unwrap()
    }

    /// The token hold of `id`: state, held units and settled units.
    async fn hold(&self, id: &str) -> (String, i64, String) {
        sqlx::query_as(
            "SELECT state,held_units,settled_units::text FROM openmettle.quota_reservations
              WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'",
        )
        .bind(id)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }

    /// The account's token budget: used and held units.
    async fn budget(&self) -> (i64, i64) {
        sqlx::query_as(
            "SELECT active_used::bigint,reserved_held::bigint FROM openmettle.quota_budgets
              WHERE scope_id=$1::uuid AND resource_kind='usage_tokens'",
        )
        .bind(&self.scope)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }

    /// Open connections to this database as `openmettle_gateway`.
    async fn gateway_connections(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE datname=$1 AND usename='openmettle_gateway'",
        )
        .bind(&self.db.0)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }
}

// --- stand-in upstream ------------------------------------------------------------------------

/// What the stand-in received: the lowercased head and the exact body.
struct Received {
    head: String,
    body: Vec<u8>,
}

/// Holds a stream after its first event until the caller has read that event through the
/// proxy. A proxy that buffered the response would never deliver it, and the stand-in would
/// give up waiting and count a timeout. A proxy that closes the upstream connection meanwhile
/// is counted too.
#[derive(Default)]
struct Gate {
    first_event_relayed: Notify,
    timeouts: AtomicUsize,
    closed_by_proxy: AtomicUsize,
}

/// Replays the recorded response whose recorded request body equals the forwarded body, in
/// several TCP writes: a JSON body in two halves, a stream one HTTP chunk per SSE event.
struct StandIn {
    address: String,
    received: Arc<Mutex<Vec<Received>>>,
    gate: Arc<Gate>,
}

impl StandIn {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let received = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(Gate::default());
        let (log, held) = (received.clone(), gate.clone());
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(replay(socket, log.clone(), held.clone()));
            }
        });
        Self {
            address,
            received,
            gate,
        }
    }

    fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

async fn replay(
    mut socket: tokio::net::TcpStream,
    received: Arc<Mutex<Vec<Received>>>,
    gate: Arc<Gate>,
) {
    let Some((head, body)) = read_request(&mut socket).await else {
        return;
    };
    let case = SETTLED
        .iter()
        .map(|(case, ..)| *case)
        .chain([ABORTED, UPSTREAM_500])
        .find(|case| recorded::file(case, "request.json") == body);
    received.lock().unwrap().push(Received { head, body });
    let Some(case) = case else {
        // Any other request stalls before the head until the proxy closes the connection.
        let mut probe = [0; 1];
        let _ = socket.read(&mut probe).await;
        gate.closed_by_proxy.fetch_add(1, Ordering::SeqCst);
        return;
    };
    let response = recorded::body(case);
    let mut writes = vec![recorded::head(case).into_bytes()];
    if recorded::chunked(case) {
        for event in recorded::events(&response) {
            let mut chunk = format!("{:x}\r\n", event.len()).into_bytes();
            chunk.extend_from_slice(event);
            chunk.extend_from_slice(b"\r\n");
            writes.push(chunk);
        }
        // The aborted recording closes without the terminal chunk.
        if case != ABORTED {
            writes.push(b"0\r\n\r\n".to_vec());
        }
    } else {
        let (first, rest) = response.split_at(response.len() / 2);
        writes.extend([first.to_vec(), rest.to_vec()]);
    }
    for (n, write) in writes.iter().enumerate() {
        if socket.write_all(write).await.is_err() || socket.flush().await.is_err() {
            return;
        }
        if n == 1 && recorded::chunked(case) {
            let mut probe = [0; 1];
            tokio::select! {
                () = gate.first_event_relayed.notified() => {}
                // The proxy sends nothing more on this connection; a read ends only if it closes.
                _ = socket.read(&mut probe) => {
                    gate.closed_by_proxy.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                () = tokio::time::sleep(Duration::from_secs(5)) => {
                    gate.timeouts.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }
}

/// One request head and its `Content-Length` body.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut read = [0; 8192];
    let end = loop {
        if let Some(i) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = socket.read(&mut read).await.ok().filter(|n| *n > 0)?;
        buffer.extend_from_slice(&read[..n]);
    };
    let head = String::from_utf8(buffer[..end].to_vec())
        .unwrap()
        .to_ascii_lowercase();
    let length: usize = header(&head, "content-length").map_or(0, |v| v.parse().unwrap());
    let mut body = buffer.split_off(end);
    while body.len() < length {
        let n = socket.read(&mut read).await.ok().filter(|n| *n > 0)?;
        body.extend_from_slice(&read[..n]);
    }
    Some((head, body))
}

/// The first value of header `name` in a lowercased head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

// --- caller -----------------------------------------------------------------------------------

/// The caller's view of one response, read to the end of the connection.
struct Reply {
    status: u16,
    /// Lowercased status line and headers.
    head: String,
    body: Vec<u8>,
    /// Whether the framing completed: the terminal chunk or the full `Content-Length`.
    complete: bool,
}

fn parse(raw: &[u8]) -> Reply {
    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Reply {
            status: 0,
            head: String::new(),
            body: Vec::new(),
            complete: false,
        };
    };
    let head = String::from_utf8_lossy(&raw[..end + 4]).to_ascii_lowercase();
    let status = head[9..12].parse().unwrap();
    let rest = &raw[end + 4..];
    let (body, complete) = if header(&head, "transfer-encoding") == Some("chunked") {
        dechunk(rest)
    } else {
        let length: usize = header(&head, "content-length").unwrap().parse().unwrap();
        (
            rest[..length.min(rest.len())].to_vec(),
            rest.len() >= length,
        )
    };
    Reply {
        status,
        head,
        body,
        complete,
    }
}

/// The payload of a chunked body so far, and whether its terminal chunk arrived.
fn dechunk(mut raw: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let Some(line) = raw.windows(2).position(|w| w == b"\r\n") else {
            return (body, false);
        };
        let size = std::str::from_utf8(&raw[..line]).unwrap();
        let size = usize::from_str_radix(size.split(';').next().unwrap().trim(), 16).unwrap();
        raw = &raw[line + 2..];
        if size == 0 {
            return (body, true);
        }
        body.extend_from_slice(&raw[..size.min(raw.len())]);
        if raw.len() < size + 2 {
            return (body, false);
        }
        raw = &raw[size + 2..];
    }
}

/// The gateway binary serving the fixture's database through the stand-in.
struct Harness {
    fixture: Fixture,
    upstream: StandIn,
    gateway: Process,
    bind: String,
    stderr: thread::JoinHandle<String>,
}

impl Harness {
    async fn start() -> Self {
        let upstream = StandIn::start().await;
        let url = format!("http://{}", upstream.address);
        Self::start_with(upstream, &url).await
    }

    /// Serves through `url`, which is the stand-in unless a live check names another upstream.
    async fn start_with(upstream: StandIn, url: &str) -> Self {
        let fixture = Fixture::new().await;
        let bind = address();
        let mut child = binary("gateway")
            .env("OPENMETTLE_GATEWAY_BIND", &bind)
            .env(
                "OPENMETTLE_GATEWAY_DATABASE_URL",
                fixture.db.url(pg::GATEWAY),
            )
            .env("OPENMETTLE_GATEWAY_UPSTREAM_URL", url)
            .env("OPENMETTLE_GATEWAY_SHUTDOWN_TIMEOUT_MS", "10000")
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut pipe = child.stderr.take().unwrap();
        let stderr = thread::spawn(move || {
            let mut text = String::new();
            pipe.read_to_string(&mut text).unwrap();
            text
        });
        let mut gateway = Process(child);
        tokio::task::block_in_place(|| wait_ready(&mut gateway, &bind));
        Self {
            fixture,
            upstream,
            gateway,
            bind,
            stderr,
        }
    }

    /// Sends `body` with the synthetic credentials and reads the response to the end. With
    /// `first_event`, releases the stand-in once that event has arrived, or instead closes the
    /// connection then if `leave`.
    async fn send(
        &self,
        id: Option<&str>,
        body: &[u8],
        first_event: Option<&[u8]>,
        leave: bool,
    ) -> Reply {
        let mut socket = tokio::net::TcpStream::connect(&self.bind).await.unwrap();
        let accept = match first_event {
            Some(_) => "text/event-stream",
            None => "application/json",
        };
        let mut request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
             Content-Type: application/json\r\nAccept: {accept}\r\n\
             Authorization: Bearer {CREDENTIAL}\r\nCookie: session={COOKIE}\r\n\
             Content-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(id) = id {
            request.push_str(&format!("X-Request-Id: {id}\r\n"));
        }
        request.push_str("\r\n");
        socket.write_all(request.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
        let mut raw = Vec::new();
        let mut waiting = first_event;
        let mut read = [0; 8192];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(20), socket.read(&mut read))
                .await
                .expect("the proxy response stalled")
                .unwrap_or(0);
            if n == 0 {
                return parse(&raw);
            }
            raw.extend_from_slice(&read[..n]);
            let so_far = parse(&raw);
            if let Some(event) = waiting
                && so_far.body.starts_with(event)
            {
                if leave {
                    return so_far;
                }
                // A response that is already complete was not held: releasing now would leave a
                // stale permit for the next stream.
                if !so_far.complete {
                    self.upstream.gate.first_event_relayed.notify_one();
                }
                waiting = None;
            }
        }
    }

    /// Sends the recorded request of `case`, holding a stream until its first event arrives.
    async fn send_case(&self, case: &str, id: &str) -> Reply {
        self.send_recorded(case, id, false).await
    }

    async fn send_recorded(&self, case: &str, id: &str, leave: bool) -> Reply {
        let response = recorded::body(case);
        let events = recorded::events(&response);
        let first_event = recorded::chunked(case).then(|| events[0]);
        let request = recorded::file(case, "request.json");
        self.send(Some(id), &request, first_event, leave).await
    }

    /// Stops the binary with SIGTERM, which drains running relays and their reports, and
    /// returns every `gateway.usage.*` event as (event, request ID, reason).
    async fn stop(self) -> (Fixture, StandIn, Vec<(String, String, String)>) {
        let Self {
            fixture,
            upstream,
            mut gateway,
            stderr,
            ..
        } = self;
        signal(&gateway.0, "-TERM");
        let status = tokio::task::block_in_place(|| gateway.0.wait()).unwrap();
        assert!(status.success());
        let stderr = stderr.join().unwrap();
        for secret in [CREDENTIAL, COOKIE, "Count from 1 to 5"] {
            assert!(!stderr.contains(secret), "logged: {secret}");
        }
        let mut events: Vec<_> = stderr
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
            .collect();
        events.sort();
        (fixture, upstream, events)
    }
}

/// The content type of a lowercased response head.
fn content_type(head: &str) -> Option<String> {
    header(head, "content-type").map(str::to_owned)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn relays_recorded_answers_unchanged_and_settles_their_usage_as_the_gateway() {
    let h = Harness::start().await;
    let mut ids = Vec::new();
    for (n, (case, ..)) in SETTLED.into_iter().enumerate() {
        let id = h.fixture.request(false).await;
        let reply = h.send_case(case, &id).await;
        assert_eq!(reply.status, 200, "{case}");
        let recorded_head = recorded::head(case).to_ascii_lowercase();
        assert_eq!(
            content_type(&reply.head),
            content_type(&recorded_head),
            "{case}"
        );
        assert!(
            reply.body == recorded::body(case),
            "{case}: the caller receives the recorded bytes"
        );
        assert!(reply.complete, "{case}");
        {
            let log = h.upstream.received.lock().unwrap();
            let received = &log[n];
            assert!(
                received.body == recorded::file(case, "request.json"),
                "{case}: the upstream receives the caller's bytes"
            );
            assert_eq!(header(&received.head, "x-request-id"), Some(id.as_str()));
            assert_eq!(
                header(&received.head, "content-type"),
                Some("application/json")
            );
            for withheld in ["authorization", "cookie", CREDENTIAL, COOKIE] {
                assert!(!received.head.contains(withheld), "{case}: {withheld}");
            }
        }
        ids.push(id);
    }
    assert_eq!(
        h.upstream.gate.timeouts.load(Ordering::SeqCst),
        0,
        "every stream reached the caller while the upstream was still writing"
    );
    assert!(h.fixture.gateway_connections().await > 0);
    let (fixture, _, events) = h.stop().await;
    for ((case, prompt, completion, reasoning), id) in SETTLED.into_iter().zip(&ids) {
        assert_eq!(
            fixture.reports(id).await,
            [(
                id.clone(),
                SOURCE.to_owned(),
                0,
                true,
                Some(prompt),
                Some(completion),
                Some(reasoning),
                Some(true)
            )],
            "{case}"
        );
        let measured = (prompt + completion).to_string();
        assert_eq!(
            fixture.settlement(id).await,
            Some((0, true, Some(measured.clone()), 0)),
            "{case}"
        );
        assert_eq!(
            fixture.hold(id).await,
            ("settled".to_owned(), 0, measured),
            "{case}"
        );
    }
    assert_eq!(events, []);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn relays_but_leaves_the_hold_when_no_usage_was_observed() {
    let h = Harness::start().await;
    let aborted = h.fixture.request(false).await;
    let failed = h.fixture.request(false).await;
    let held = ("handoff_committed".to_owned(), UNITS, "0".to_owned());
    assert_eq!(h.fixture.hold(&aborted).await, held);
    assert_eq!(h.fixture.hold(&failed).await, held);

    let reply = h.send_case(ABORTED, &aborted).await;
    assert_eq!(reply.status, 200);
    assert!(reply.body == recorded::body(ABORTED));
    assert!(
        !reply.complete,
        "the caller's response is cut like the upstream's"
    );
    let reply = h.send_case(UPSTREAM_500, &failed).await;
    assert_eq!(
        (reply.status, content_type(&reply.head).as_deref()),
        (500, Some("text/plain; charset=utf-8"))
    );
    assert!(reply.body == recorded::body(UPSTREAM_500) && reply.complete);
    assert_eq!(h.upstream.count(), 2);

    let (fixture, _, events) = h.stop().await;
    for id in [&aborted, &failed] {
        assert_eq!(fixture.reports(id).await, []);
        assert_eq!(fixture.settlement(id).await, None);
        assert_eq!(fixture.hold(id).await, held);
    }
    let unrecorded = |id: &str, reason: &str| {
        (
            "gateway.usage.unrecorded".to_owned(),
            id.to_owned(),
            reason.to_owned(),
        )
    };
    let mut expected = vec![
        unrecorded(&aborted, "incomplete"),
        unrecorded(&failed, "upstream_status"),
    ];
    expected.sort();
    assert_eq!(events, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn refuses_unusable_or_unready_request_ids_before_forwarding() {
    let h = Harness::start().await;
    let reserved = h.fixture.request(true).await;
    let unknown: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&h.fixture.owner)
        .await
        .unwrap();
    let body = recorded::file("02-chat-plain", "request.json");
    for (id, status, code) in [
        (None, 400, "validation"),
        (Some("not-a-request-id".to_owned()), 400, "validation"),
        (Some(reserved.to_ascii_uppercase()), 400, "validation"),
        (Some(unknown), 404, "not_found"),
        // Reserved but not yet handed off.
        (Some(reserved.clone()), 404, "not_found"),
    ] {
        let reply = h.send(id.as_deref(), &body, None, false).await;
        assert_eq!(reply.status, status, "{id:?}");
        assert_eq!(
            content_type(&reply.head).as_deref(),
            Some("application/problem+json")
        );
        let problem: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(
            (problem["status"].as_u64(), problem["code"].as_str()),
            (Some(u64::from(status)), Some(code))
        );
    }
    assert_eq!(h.upstream.count(), 0, "nothing was forwarded");
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&reserved).await, []);
    assert_eq!(events, []);
}

/// Increment 2 makes a second dispatch of one request impossible. Until then the proxy
/// forwards it, and settlement accepts the identical report once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_repeated_dispatch_of_one_request_is_settled_once() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    for _ in 0..2 {
        let reply = h.send_case("03-chat-stream-usage", &id).await;
        assert_eq!(reply.status, 200);
        assert!(reply.body == recorded::body("03-chat-stream-usage") && reply.complete);
    }
    assert_eq!(h.upstream.count(), 2);
    let (fixture, _, events) = h.stop().await;
    let reports = fixture.reports(&id).await;
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(
        fixture.settlement(&id).await,
        Some((0, true, Some("29".to_owned()), 0))
    );
    assert_eq!(
        fixture.hold(&id).await,
        ("settled".to_owned(), 0, "29".to_owned())
    );
    assert_eq!(fixture.budget().await, (29, 0));
    assert_eq!(events, []);
}

/// A report write still retrying at SIGTERM finishes before the pool closes. The test holds the
/// request's settlement lock past settlement's 2 s lock timeout, so the first write fails
/// transiently and the relay retries while the process drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn shutdown_waits_for_a_report_write_that_is_retrying() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let mut lock = h.fixture.owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE")
        .bind(&id)
        .execute(&mut *lock)
        .await
        .unwrap();
    let reply = h.send_case("02-chat-plain", &id).await;
    assert_eq!(reply.status, 200);
    signal(&h.gateway.0, "-TERM");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    lock.commit().await.unwrap();
    // Draining ignores the second SIGTERM that `stop` sends.
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await.len(), 1);
    assert_eq!(
        fixture.settlement(&id).await,
        Some((0, true, Some("19".to_owned()), 0))
    );
    assert_eq!(events, []);
}

/// A caller that leaves before the usage arrived takes the upstream connection with it, so the
/// model server stops generating, and nothing is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_caller_leaving_mid_stream_drops_the_upstream_and_records_nothing() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let held = h.fixture.hold(&id).await;
    let reply = h.send_recorded("04-chat-stream-reasoning", &id, true).await;
    assert!(reply.status == 200 && !reply.complete);
    let deadline = Instant::now() + Duration::from_secs(5);
    while h.upstream.gate.closed_by_proxy.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the upstream connection stayed open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(h.upstream.gate.timeouts.load(Ordering::SeqCst), 0);
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await, []);
    assert_eq!(fixture.hold(&id).await, held);
    assert_eq!(
        events,
        [(
            "gateway.usage.unrecorded".to_owned(),
            id,
            "caller_disconnected".to_owned()
        )]
    );
}

/// The usage object in a relayed body: the JSON document's, or a stream's last one.
fn relayed_usage(body: &[u8]) -> Option<(i64, i64, Option<i64>)> {
    let text = String::from_utf8_lossy(body);
    let usage = match text.strip_prefix("data: ") {
        None => serde_json::from_str::<Value>(&text).ok()?["usage"].take(),
        Some(_) => text
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter(|data| *data != "[DONE]")
            .filter_map(|data| serde_json::from_str::<Value>(data).ok())
            .filter_map(|mut chunk| Some(chunk["usage"].take()).filter(|u| !u.is_null()))
            .next_back()?,
    };
    let reasoning = usage["reasoning_tokens"]
        .as_i64()
        .or(usage["completion_tokens_details"]["reasoning_tokens"].as_i64());
    Some((
        usage["prompt_tokens"].as_i64()?,
        usage["completion_tokens"].as_i64()?,
        reasoning,
    ))
}

/// Opt-in live check: with `TEST_GATEWAY_UPSTREAM_URL` set to a real SGLang `http://` origin,
/// sends the recorded requests through the binary and checks each stored report against the
/// usage in the bytes the caller received. Without it, returns at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn live_upstream_usage_matches_what_the_caller_received() {
    let Ok(url) = std::env::var("TEST_GATEWAY_UPSTREAM_URL") else {
        eprintln!("skipped: TEST_GATEWAY_UPSTREAM_URL is unset");
        return;
    };
    let h = Harness::start_with(StandIn::start().await, &url).await;
    let mut sent = Vec::new();
    for (case, ..) in SETTLED {
        let id = h.fixture.request(false).await;
        let reply = h
            .send(
                Some(&id),
                &recorded::file(case, "request.json"),
                None,
                false,
            )
            .await;
        assert!(
            reply.status == 200 && reply.complete,
            "{case}: {}",
            reply.status
        );
        let usage = relayed_usage(&reply.body).unwrap_or_else(|| panic!("{case}: no usage"));
        eprintln!("{case}: request {id}, relayed usage {usage:?}");
        sent.push((case, id, usage));
    }
    let (fixture, _, events) = h.stop().await;
    for (case, id, (prompt, completion, reasoning)) in sent {
        assert_eq!(
            fixture.reports(&id).await,
            [(
                id.clone(),
                SOURCE.to_owned(),
                0,
                true,
                Some(prompt),
                Some(completion),
                reasoning,
                reasoning.map(|_| true)
            )],
            "{case}"
        );
        let measured = prompt + completion.max(reasoning.unwrap_or(0));
        assert_eq!(
            fixture.settlement(&id).await,
            Some((0, true, Some(measured.to_string()), 0)),
            "{case}"
        );
    }
    assert_eq!(events, []);
}

/// A caller that leaves while the upstream has not answered yet also takes the upstream
/// connection with it, and the request is logged as unrecorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_caller_leaving_before_the_response_head_drops_the_upstream() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let held = h.fixture.hold(&id).await;
    let body = br#"{"stall":true}"#;
    let mut socket = tokio::net::TcpStream::connect(&h.bind).await.unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
         Content-Type: application/json\r\nX-Request-Id: {id}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    socket.write_all(body).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while h.upstream.count() == 0 {
        assert!(Instant::now() < deadline, "the request was not forwarded");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(socket);
    while h.upstream.gate.closed_by_proxy.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the upstream connection stayed open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await, []);
    assert_eq!(fixture.hold(&id).await, held);
    assert_eq!(
        events,
        [(
            "gateway.usage.unrecorded".to_owned(),
            id,
            "caller_disconnected".to_owned()
        )]
    );
}
