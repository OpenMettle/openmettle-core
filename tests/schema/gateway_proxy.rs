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
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize},
};
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

/// Coordinates the stand-in with the caller. A held answer pauses after its first body write
/// until the caller has read that write through the proxy and releases it. A proxy that
/// buffered the response would never deliver it, and the stand-in would give up waiting and
/// count a timeout.
#[derive(Default)]
struct Gate {
    released: Notify,
    timeouts: AtomicUsize,
    /// Answers the proxy cut off by closing the upstream connection.
    closed_by_proxy: AtomicUsize,
    /// Answers written to their end.
    finished: AtomicUsize,
}

/// One stand-in answer: the response head, then the body writes in order.
struct Script {
    writes: Box<dyn Iterator<Item = Vec<u8>> + Send>,
    held: bool,
    /// Pause before each body write after the first.
    pause: Duration,
    /// After the writes, keep the answer open, unfinished, until the proxy closes it.
    linger: bool,
}

fn chunk(data: &[u8]) -> Vec<u8> {
    let mut chunk = format!("{:x}\r\n", data.len()).into_bytes();
    chunk.extend_from_slice(data);
    chunk.extend_from_slice(b"\r\n");
    chunk
}

const SSE_HEAD: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream; charset=utf-8\r\n\
    transfer-encoding: chunked\r\n\r\n";

/// One SSE event carrying `content` and, like SGLang's `continuous_usage_stats`, the usage so
/// far.
fn continuous_event(content: &str, completion: usize) -> Vec<u8> {
    format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{content}\"}}}}],\
         \"usage\":{{\"prompt_tokens\":5,\"completion_tokens\":{completion}}}}}\n\n"
    )
    .into_bytes()
}

/// A recorded answer for its recorded request, a synthetic one for `{"synthetic":"…"}`, and
/// otherwise none.
fn script(body: &[u8]) -> Option<Script> {
    let recorded_case = SETTLED
        .iter()
        .map(|(case, ..)| *case)
        .chain([ABORTED, UPSTREAM_500])
        .find(|case| recorded::file(case, "request.json") == body);
    if let Some(case) = recorded_case {
        let response = recorded::body(case);
        let mut writes = vec![recorded::head(case).into_bytes()];
        let held = recorded::chunked(case);
        if held {
            writes.extend(recorded::events(&response).into_iter().map(chunk));
            // The aborted recording closes without the terminal chunk.
            if case != ABORTED {
                writes.push(b"0\r\n\r\n".to_vec());
            }
        } else {
            let (first, rest) = response.split_at(response.len() / 2);
            writes.extend([first.to_vec(), rest.to_vec()]);
        }
        return Some(Script {
            writes: Box::new(writes.into_iter()),
            held,
            pause: Duration::ZERO,
            linger: false,
        });
    }
    let name = serde_json::from_slice::<Value>(body).ok()?["synthetic"].take();
    let (writes, held, pause, linger): (Box<dyn Iterator<Item = Vec<u8>> + Send>, _, _, _) =
        match name.as_str()? {
            // An endless stream with usage in every event, one every 200 ms.
            "trickle" => {
                let head = std::iter::once(SSE_HEAD.as_bytes().to_vec());
                let events = (1..).map(|n| chunk(&continuous_event("x", n)));
                (
                    Box::new(head.chain(events)),
                    true,
                    Duration::from_millis(200),
                    false,
                )
            }
            // Compressed answers, left unfinished: the proxy must close them, not drain them.
            "gzip" => {
                let response = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                    content-encoding: gzip\r\ncontent-length: 8\r\n\r\n";
                let writes = vec![response.as_bytes().to_vec(), b"\x1f\x8b\x08\x00".to_vec()];
                (Box::new(writes.into_iter()), false, Duration::ZERO, true)
            }
            "gzip-te" => {
                let response = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                    transfer-encoding: gzip, chunked\r\n\r\n";
                let writes = vec![response.as_bytes().to_vec(), chunk(b"\x1f\x8b\x08\x00")];
                (Box::new(writes.into_iter()), false, Duration::ZERO, true)
            }
            // The recorded plain answer, with its `Content-Type` named hop-by-hop.
            "hop" => {
                let response = recorded::body("02-chat-plain");
                let head = format!(
                    "HTTP/1.1 200 OK\r\nconnection: content-type\r\n\
                     content-type: application/json\r\ncontent-length: {}\r\n\r\n",
                    response.len()
                );
                let writes = vec![head.into_bytes(), response];
                (Box::new(writes.into_iter()), false, Duration::ZERO, false)
            }
            _ => return None,
        };
    Some(Script {
        writes,
        held,
        pause,
        linger,
    })
}

/// Answers each request with its script, in separate TCP writes.
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

    /// The lowercased head of the `n`th request received.
    fn head(&self, n: usize) -> String {
        self.received.lock().unwrap()[n].head.clone()
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
    let script = script(&body);
    received.lock().unwrap().push(Received { head, body });
    let mut probe = [0; 1];
    let Some(script) = script else {
        // Any other request stalls before the head until the proxy closes the connection.
        let _ = socket.read(&mut probe).await;
        gate.closed_by_proxy.fetch_add(1, Ordering::SeqCst);
        return;
    };
    for (n, write) in script.writes.enumerate() {
        if n > 1 {
            tokio::time::sleep(script.pause).await;
        }
        if socket.write_all(&write).await.is_err() || socket.flush().await.is_err() {
            gate.closed_by_proxy.fetch_add(1, Ordering::SeqCst);
            return;
        }
        if n == 1 && script.held {
            tokio::select! {
                () = gate.released.notified() => {}
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
    if script.linger {
        let _ = socket.read(&mut probe).await;
        gate.closed_by_proxy.fetch_add(1, Ordering::SeqCst);
        return;
    }
    gate.finished.fetch_add(1, Ordering::SeqCst);
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

// --- faulty database connection ---------------------------------------------------------------

/// Text of the first statement settlement sends inside its transaction.
const SETTLEMENT_LOCK: &[u8] = b"quota_lock_gateway_request_for_settlement";
/// The simple query that opens every transaction.
const BEGIN: &[u8] = b"BEGIN\0";

/// What happens to the first connection that sends the trigger.
#[derive(Clone, Copy)]
enum Fault {
    /// Nothing more is forwarded either way; the sockets stay open until released.
    Silence,
    /// The trigger reaches the server, but every reply from then on is held back this long.
    Delay(Duration),
}

/// Forwards connections to the test PostgreSQL service, with one [`Fault`] on the first
/// connection that sends `trigger`.
struct FaultyPostgres {
    address: String,
    /// Times the trigger was seen; only the first was faulted.
    attempts: Arc<AtomicUsize>,
    /// Held-back replies delivered after a [`Fault::Delay`].
    late: Arc<AtomicUsize>,
    release: Arc<Notify>,
}

impl FaultyPostgres {
    async fn start(trigger: &'static [u8], fault: Fault) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let admin = pg::admin_options();
        let server = format!("{}:{}", admin.get_host(), admin.get_port());
        let attempts = Arc::new(AtomicUsize::new(0));
        let late = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let faults = Faults {
            trigger,
            fault,
            attempts: attempts.clone(),
            late: late.clone(),
            release: release.clone(),
        };
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let server = tokio::net::TcpStream::connect(&server).await.unwrap();
                tokio::spawn(forward(client, server, faults.clone()));
            }
        });
        Self {
            address,
            attempts,
            late,
            release,
        }
    }

    fn release(&self) {
        self.release.notify_waiters();
    }
}

#[derive(Clone)]
struct Faults {
    trigger: &'static [u8],
    fault: Fault,
    attempts: Arc<AtomicUsize>,
    late: Arc<AtomicUsize>,
    release: Arc<Notify>,
}

async fn forward(client: tokio::net::TcpStream, server: tokio::net::TcpStream, faults: Faults) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let silent = Arc::new(AtomicBool::new(false));
    let hold = Arc::new(Mutex::new(None::<tokio::time::Instant>));
    let (quiet, held, late) = (silent.clone(), hold.clone(), faults.late.clone());
    // Each direction ends when its source does; a silent connection's replies are discarded.
    let replies = async move {
        let mut buffer = [0; 8192];
        while let Ok(n @ 1..) = server_read.read(&mut buffer).await {
            if quiet.load(Ordering::SeqCst) {
                continue;
            }
            let until = held.lock().unwrap().take();
            if let Some(until) = until {
                tokio::time::sleep_until(until).await;
                late.fetch_add(1, Ordering::SeqCst);
            }
            if client_write.write_all(&buffer[..n]).await.is_err() {
                break;
            }
        }
    };
    let requests = async move {
        let mut buffer = [0; 8192];
        let mut seen = Vec::new();
        while let Ok(n @ 1..) = client_read.read(&mut buffer).await {
            seen.extend_from_slice(&buffer[..n]);
            if seen
                .windows(faults.trigger.len())
                .any(|w| w == faults.trigger)
                && faults.attempts.fetch_add(1, Ordering::SeqCst) == 0
            {
                match faults.fault {
                    Fault::Silence => {
                        // Hold both sockets open, unanswered, until the test lets them go;
                        // returning then closes the connection both ways.
                        silent.store(true, Ordering::SeqCst);
                        faults.release.notified().await;
                        return;
                    }
                    Fault::Delay(delay) => {
                        *hold.lock().unwrap() = Some(tokio::time::Instant::now() + delay);
                    }
                }
            }
            seen.drain(..seen.len().saturating_sub(faults.trigger.len()));
            if server_write.write_all(&buffer[..n]).await.is_err() {
                return;
            }
        }
    };
    tokio::join!(replies, requests);
}

// --- caller -----------------------------------------------------------------------------------

/// The caller's view of one response, read to the end of the connection.
struct Reply {
    status: u16,
    /// Lowercased status line and headers.
    head: String,
    body: Vec<u8>,
    /// Whether the framing completed: the terminal chunk and the end of its (empty) trailer
    /// section, or the full `Content-Length`.
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

/// The payload of a chunked body so far, and whether it ended: the zero-size chunk followed by
/// the blank line that closes its trailer section.
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
            let ended = raw.starts_with(b"\r\n") || raw.windows(4).any(|w| w == b"\r\n\r\n");
            return (body, ended);
        }
        body.extend_from_slice(&raw[..size.min(raw.len())]);
        if raw.len() < size + 2 {
            return (body, false);
        }
        raw = &raw[size + 2..];
    }
}

/// What the caller does once the given first bytes of the body have arrived.
#[derive(Clone, Copy)]
enum Then<'a> {
    /// Reads to the end; nothing is held.
    Read,
    /// Releases the held stand-in and reads to the end.
    Release(&'a [u8]),
    /// Closes the connection and leaves the stand-in held.
    Leave(&'a [u8]),
    /// Closes the connection, then releases the stand-in.
    LeaveAndRelease(&'a [u8]),
    /// Releases a held stand-in, if any, and reads nothing more until the stand-in has written
    /// its whole answer: meanwhile the proxy meets a caller that has stopped reading.
    Stall(Option<&'a [u8]>),
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
        Self::launch(Fixture::new().await, StandIn::start().await, &[]).await
    }

    /// Serves the fixture through the stand-in, with extra `OPENMETTLE_GATEWAY_` settings
    /// applied last.
    async fn launch(fixture: Fixture, upstream: StandIn, settings: &[(&str, String)]) -> Self {
        let bind = address();
        let mut command = binary("gateway");
        command
            .env("OPENMETTLE_GATEWAY_BIND", &bind)
            .env(
                "OPENMETTLE_GATEWAY_DATABASE_URL",
                fixture.db.url(pg::GATEWAY),
            )
            .env(
                "OPENMETTLE_GATEWAY_UPSTREAM_URL",
                format!("http://{}", upstream.address),
            )
            .env("OPENMETTLE_GATEWAY_SHUTDOWN_TIMEOUT_MS", "10000");
        for (key, value) in settings {
            command.env(format!("OPENMETTLE_GATEWAY_{key}"), value);
        }
        let mut child = command.stdout(Stdio::null()).spawn().unwrap();
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

    /// Sends `body` with the synthetic credentials and any `extra` header lines, then follows
    /// `then`. Without a `Connection` line in `extra`, the request asks to close.
    async fn send(&self, id: Option<&str>, body: &[u8], extra: &str, then: Then<'_>) -> Reply {
        let finished = self.upstream.gate.finished.load(Ordering::SeqCst);
        let mut socket = tokio::net::TcpStream::connect(&self.bind).await.unwrap();
        let mut request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
             Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
             Authorization: Bearer {CREDENTIAL}\r\nCookie: session={COOKIE}\r\n\
             Content-Length: {}\r\n{extra}",
            body.len()
        );
        if !extra.to_ascii_lowercase().contains("connection:") {
            request.push_str("Connection: close\r\n");
        }
        if let Some(id) = id {
            request.push_str(&format!("X-Request-Id: {id}\r\n"));
        }
        request.push_str("\r\n");
        socket.write_all(request.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
        let gate = &self.upstream.gate;
        let mut raw = Vec::new();
        let mut read = [0; 65536];
        let mut waiting = match then {
            Then::Read | Then::Stall(None) => None,
            Then::Release(first)
            | Then::Leave(first)
            | Then::LeaveAndRelease(first)
            | Then::Stall(Some(first)) => Some(first),
        };
        let mut stall = matches!(then, Then::Stall(None));
        loop {
            if stall {
                let deadline = Instant::now() + Duration::from_secs(30);
                while gate.finished.load(Ordering::SeqCst) == finished {
                    assert!(Instant::now() < deadline, "the stand-in never finished");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                stall = false;
            }
            let n = tokio::time::timeout(Duration::from_secs(20), socket.read(&mut read))
                .await
                .expect("the proxy response stalled")
                .unwrap_or(0);
            if n == 0 {
                return parse(&raw);
            }
            raw.extend_from_slice(&read[..n]);
            let so_far = parse(&raw);
            if let Some(first) = waiting
                && so_far.body.starts_with(first)
            {
                waiting = None;
                match then {
                    Then::Leave(_) => return so_far,
                    Then::LeaveAndRelease(_) => {
                        drop(socket);
                        gate.released.notify_one();
                        return so_far;
                    }
                    Then::Stall(_) => stall = true,
                    _ => {}
                }
                // A response that is already complete was not held: releasing now would leave a
                // stale permit for the next stream.
                if !so_far.complete {
                    gate.released.notify_one();
                }
            }
        }
    }

    /// Sends `request` as written and reads the response to the end of the connection.
    async fn raw(&self, request: &[u8]) -> Reply {
        let mut socket = tokio::net::TcpStream::connect(&self.bind).await.unwrap();
        socket.write_all(request).await.unwrap();
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), socket.read_to_end(&mut raw)).await;
        parse(&raw)
    }

    /// Sends the recorded request of `case`. A stream is released once its first event arrives
    /// unless `then` says otherwise.
    async fn send_case(&self, case: &str, id: &str) -> Reply {
        let response = recorded::body(case);
        let events = recorded::events(&response);
        let then = match recorded::chunked(case) {
            true => Then::Release(events[0]),
            false => Then::Read,
        };
        self.send_recorded(case, id, then).await
    }

    async fn send_recorded(&self, case: &str, id: &str, then: Then<'_>) -> Reply {
        let request = recorded::file(case, "request.json");
        self.send(Some(id), &request, "", then).await
    }

    async fn send_synthetic(&self, name: &str, id: &str, then: Then<'_>) -> Reply {
        let request = format!(r#"{{"synthetic":"{name}"}}"#);
        self.send(Some(id), request.as_bytes(), "", then).await
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

fn unrecorded(id: &str, reason: &str) -> (String, String, String) {
    (
        "gateway.usage.unrecorded".to_owned(),
        id.to_owned(),
        reason.to_owned(),
    )
}

/// Waits up to `limit` for `done`.
async fn eventually(limit: Duration, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
            for (name, value) in [
                ("x-request-id", id.as_str()),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("accept-encoding", "identity"),
            ] {
                assert_eq!(header(&received.head, name), Some(value), "{case}: {name}");
            }
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

/// A cut upstream stream reaches the caller as a prefix of its bytes with an unclean end, never
/// as a complete response. The caller reads nothing more after the first event until the
/// stand-in has written everything and closed, so the cut meets data still in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn relays_but_leaves_the_hold_when_no_usage_was_observed() {
    let h = Harness::start().await;
    let aborted = h.fixture.request(false).await;
    let failed = h.fixture.request(false).await;
    let held = ("handoff_committed".to_owned(), UNITS, "0".to_owned());
    assert_eq!(h.fixture.hold(&aborted).await, held);
    assert_eq!(h.fixture.hold(&failed).await, held);

    let recorded_body = recorded::body(ABORTED);
    let first = recorded::events(&recorded_body)[0];
    let reply = h
        .send_recorded(ABORTED, &aborted, Then::Stall(Some(first)))
        .await;
    assert_eq!(reply.status, 200);
    assert!(
        reply.body.len() >= first.len() && recorded_body.starts_with(&reply.body),
        "the caller receives a prefix of the upstream bytes"
    );
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
    let handed_off = h.fixture.request(false).await;
    let unknown: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&h.fixture.owner)
        .await
        .unwrap();
    let body = recorded::file("02-chat-plain", "request.json");
    let uppercase = "0F8FAD5B-D9CB-469F-A165-70867728950E".to_owned();
    for (id, extra, status, code) in [
        (None, "", 400, "validation"),
        (Some("not-a-request-id".to_owned()), "", 400, "validation"),
        (Some(uppercase), "", 400, "validation"),
        (Some(unknown), "", 404, "not_found"),
        // Reserved but not yet handed off.
        (Some(reserved.clone()), "", 404, "not_found"),
        // Only identity bodies are forwarded in this increment.
        (
            Some(handed_off.clone()),
            "Content-Encoding: gzip\r\n",
            415,
            "unsupported_media_type",
        ),
        // A request ID named as hop-by-hop counts as absent.
        (
            Some(handed_off.clone()),
            "Connection: close, X-Request-Id\r\n",
            400,
            "validation",
        ),
    ] {
        let reply = h.send(id.as_deref(), &body, extra, Then::Read).await;
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
    // HTTP/1.0 could not mark a cut stream, and only `chunked` may frame a request body.
    let mut chunked_body = chunk(&body);
    chunked_body.extend_from_slice(b"0\r\n\r\n");
    for (head, status, code) in [
        (
            format!(
                "POST /v1/chat/completions HTTP/1.0\r\nContent-Length: {}\r\n",
                body.len()
            ),
            505,
            "http_version_not_supported",
        ),
        (
            "POST /v1/chat/completions HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n".to_owned(),
            415,
            "unsupported_media_type",
        ),
    ] {
        let mut request = format!(
            "{head}Host: gateway.test\r\nContent-Type: application/json\r\n\
             X-Request-Id: {handed_off}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        request.extend_from_slice(if status == 505 { &body } else { &chunked_body });
        let reply = h.raw(&request).await;
        assert_eq!(reply.status, status, "{head}");
        let problem: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(problem["code"], code, "{head}");
    }
    assert_eq!(h.upstream.count(), 0, "nothing was forwarded");
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&reserved).await, []);
    assert_eq!(fixture.reports(&handed_off).await, []);
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

/// The transaction start of each settlement attempt by `openmettle_gateway` that is waiting for
/// a lock in the fixture's database. Read as the superuser: other roles' wait states are hidden.
async fn blocked_attempts(fixture: &Fixture) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT xact_start::text FROM pg_stat_activity
          WHERE datname=$1 AND usename='openmettle_gateway' AND wait_event_type='Lock'",
    )
    .bind(&fixture.db.0)
    .fetch_all(&mut fixture.db.admin().await)
    .await
    .unwrap()
}

/// A report write still retrying at SIGTERM finishes before the pool closes. The test holds the
/// request's settlement lock, sees the first attempt wait for it, signals, and releases the
/// lock only once a second, distinct attempt is waiting: the first has hit settlement's lock
/// timeout and the relay is retrying while the process drains.
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
    let deadline = Instant::now() + Duration::from_secs(10);
    let first = loop {
        if let [attempt] = &blocked_attempts(&h.fixture).await[..] {
            break attempt.clone();
        }
        assert!(Instant::now() < deadline, "no write attempt waited");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    signal(&h.gateway.0, "-TERM");
    loop {
        if blocked_attempts(&h.fixture)
            .await
            .iter()
            .any(|attempt| *attempt != first)
        {
            break;
        }
        assert!(Instant::now() < deadline, "the write was not retried");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    let case = "04-chat-stream-reasoning";
    let response = recorded::body(case);
    let reply = h
        .send_recorded(case, &id, Then::Leave(recorded::events(&response)[0]))
        .await;
    assert!(reply.status == 200 && !reply.complete);
    let gate = &h.upstream.gate;
    eventually(
        Duration::from_secs(5),
        "the upstream connection stayed open",
        || gate.closed_by_proxy.load(Ordering::SeqCst) > 0,
    )
    .await;
    assert_eq!(gate.timeouts.load(Ordering::SeqCst), 0);
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await, []);
    assert_eq!(fixture.hold(&id).await, held);
    assert_eq!(events, [unrecorded(&id, "caller_disconnected")]);
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
    let settings = [("UPSTREAM_URL", url)];
    let h = Harness::launch(Fixture::new().await, StandIn::start().await, &settings).await;
    let mut sent = Vec::new();
    for (case, ..) in SETTLED {
        let id = h.fixture.request(false).await;
        let reply = h.send_recorded(case, &id, Then::Read).await;
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
    eventually(
        Duration::from_secs(5),
        "the request was not forwarded",
        || h.upstream.count() > 0,
    )
    .await;
    drop(socket);
    eventually(
        Duration::from_secs(5),
        "the upstream connection stayed open",
        || h.upstream.gate.closed_by_proxy.load(Ordering::SeqCst) > 0,
    )
    .await;
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await, []);
    assert_eq!(fixture.hold(&id).await, held);
    assert_eq!(events, [unrecorded(&id, "caller_disconnected")]);
}

/// Only identity bodies are relayed in this increment: the upstream is asked for one, and an
/// answer with a content coding, or a transfer coding other than `chunked`, is refused with 502,
/// its connection closed without reading it, and recorded as nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_compressed_answer_is_refused_and_records_nothing() {
    let h = Harness::start().await;
    let mut ids = Vec::new();
    for (n, name) in ["gzip", "gzip-te"].into_iter().enumerate() {
        let id = h.fixture.request(false).await;
        let held = h.fixture.hold(&id).await;
        let reply = h.send_synthetic(name, &id, Then::Read).await;
        assert_eq!(reply.status, 502, "{name}");
        assert!(!reply.head.contains("encoding"), "{name}");
        let problem: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(problem["code"], "provider_failure");
        assert_eq!(
            header(&h.upstream.head(n), "accept-encoding"),
            Some("identity")
        );
        // The stand-in keeps its answer open: only the proxy can end it.
        let gate = &h.upstream.gate;
        eventually(
            Duration::from_secs(2),
            "the upstream connection stayed open",
            || gate.closed_by_proxy.load(Ordering::SeqCst) == n + 1,
        )
        .await;
        assert_eq!(gate.finished.load(Ordering::SeqCst), 0);
        assert_eq!(h.fixture.hold(&id).await, held, "{name}");
        ids.push(id);
    }
    let (fixture, _, events) = h.stop().await;
    let mut expected = Vec::new();
    for id in &ids {
        assert_eq!(fixture.reports(id).await, []);
        expected.push(unrecorded(id, "upstream_encoding"));
    }
    expected.sort();
    assert_eq!(events, expected);
}

/// After the caller has left, the upstream gets one idle timeout in total to finish, even if it
/// keeps sending within each idle interval.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_detached_relay_gives_the_upstream_one_idle_timeout_to_finish() {
    let settings = [("UPSTREAM_IDLE_TIMEOUT_MS", "1000".to_owned())];
    let h = Harness::launch(Fixture::new().await, StandIn::start().await, &settings).await;
    let id = h.fixture.request(false).await;
    let first = continuous_event("x", 1);
    let reply = h
        .send_synthetic("trickle", &id, Then::LeaveAndRelease(&first))
        .await;
    assert_eq!(reply.status, 200);
    eventually(
        Duration::from_secs(6),
        "the upstream connection stayed open",
        || h.upstream.gate.closed_by_proxy.load(Ordering::SeqCst) > 0,
    )
    .await;
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await, []);
    assert_eq!(events, [unrecorded(&id, "upstream_timeout")]);
}

/// A settlement attempt whose database connection goes silent is abandoned after its
/// client-side deadline (five `DB_TIMEOUT_MS`) and retried on another connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_report_write_on_a_silent_database_connection_is_retried() {
    let fixture = Fixture::new().await;
    let silencer = FaultyPostgres::start(SETTLEMENT_LOCK, Fault::Silence).await;
    let url = format!(
        "postgres://{}:{PASSWORD}@{}/{}?sslmode=disable",
        pg::GATEWAY,
        silencer.address,
        fixture.db.0
    );
    let settings = [("DATABASE_URL", url), ("DB_TIMEOUT_MS", "400".to_owned())];
    let h = Harness::launch(fixture, StandIn::start().await, &settings).await;
    let id = h.fixture.request(false).await;
    let reply = h.send_case("02-chat-plain", &id).await;
    assert_eq!(reply.status, 200);
    let deadline = Instant::now() + Duration::from_secs(15);
    while h.fixture.reports(&id).await.is_empty() {
        assert!(Instant::now() < deadline, "the report was never written");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The first attempt went silent and was abandoned; the second stored the report.
    assert_eq!(silencer.attempts.load(Ordering::SeqCst), 2);
    // Let the silent connection go, so the pool can close at shutdown.
    silencer.release();
    let (fixture, _, events) = h.stop().await;
    assert_eq!(
        fixture.settlement(&id).await,
        Some((0, true, Some("19".to_owned()), 0))
    );
    assert_eq!(events, []);
}

/// Fields the caller or the upstream names in `Connection` are hop-by-hop: they are not
/// forwarded even when they are otherwise allowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn connection_nominated_fields_are_not_forwarded() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let body = recorded::file("02-chat-plain", "request.json");
    let reply = h
        .send(
            Some(&id),
            &body,
            "Connection: close, Accept\r\n",
            Then::Read,
        )
        .await;
    assert_eq!(reply.status, 200);
    let head = h.upstream.head(0);
    assert_eq!(header(&head, "accept"), None, "{head}");
    assert_eq!(header(&head, "content-type"), Some("application/json"));
    let hop = h.fixture.request(false).await;
    let reply = h.send_synthetic("hop", &hop, Then::Read).await;
    assert_eq!(reply.status, 200);
    assert_eq!(content_type(&reply.head), None, "{}", reply.head);
    assert!(reply.body == recorded::body("02-chat-plain"));
    let (fixture, _, events) = h.stop().await;
    for id in [&id, &hop] {
        assert_eq!(fixture.reports(id).await.len(), 1);
    }
    assert_eq!(events, []);
}

/// A handed-off request whose body never arrives in full is refused and logged as unrecorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_unread_request_body_is_logged_as_unrecorded() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let mut socket = tokio::net::TcpStream::connect(&h.bind).await.unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
         Content-Type: application/json\r\nX-Request-Id: {id}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        2 * 1024 * 1024 + 1
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), socket.read_to_end(&mut raw)).await;
    let reply = parse(&raw);
    assert_eq!(reply.status, 400);
    assert_eq!(h.upstream.count(), 0);
    let (_, _, events) = h.stop().await;
    assert_eq!(events, [unrecorded(&id, "request_body")]);
}

/// The test's own chunked-body reader: a body ends only with the blank line after the
/// zero-size chunk, so a cut right after `0\r\n` is not mistaken for a complete response.
#[test]
fn dechunking_needs_the_end_of_the_trailer_section() {
    assert_eq!(dechunk(b"3\r\nabc\r\n0\r\n"), (b"abc".to_vec(), false));
    assert_eq!(dechunk(b"3\r\nabc\r\n0\r\n\r\n"), (b"abc".to_vec(), true));
    assert_eq!(
        dechunk(b"3\r\nabc\r\n0\r\nx: y\r\n\r\n"),
        (b"abc".to_vec(), true)
    );
    assert_eq!(dechunk(b"3\r\nab"), (b"ab".to_vec(), false));
}

/// The number of `openmettle_gateway` connections idle inside an open transaction. Read as the
/// superuser: other roles' session states are hidden.
async fn idle_in_transaction(fixture: &Fixture) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity
          WHERE datname=$1 AND usename='openmettle_gateway' AND state='idle in transaction'",
    )
    .bind(&fixture.db.0)
    .fetch_one(&mut fixture.db.admin().await)
    .await
    .unwrap()
}

/// A report write whose `BEGIN` is acknowledged only after the attempt's deadline is abandoned,
/// not cancelled: the retry stores the report, the abandoned attempt finishes on its own, and
/// no connection goes back to the pool inside a transaction for its next borrower.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_late_begin_never_leaves_a_pooled_connection_in_a_transaction() {
    let fixture = Fixture::new().await;
    // Two seconds per attempt (five `DB_TIMEOUT_MS`); the first `BEGIN` is answered after three.
    let postgres = FaultyPostgres::start(BEGIN, Fault::Delay(Duration::from_secs(3))).await;
    let url = format!(
        "postgres://{}:{PASSWORD}@{}/{}?sslmode=disable",
        pg::GATEWAY,
        postgres.address,
        fixture.db.0
    );
    let settings = [("DATABASE_URL", url), ("DB_TIMEOUT_MS", "400".to_owned())];
    let h = Harness::launch(fixture, StandIn::start().await, &settings).await;
    let id = h.fixture.request(false).await;
    assert_eq!(h.send_case("02-chat-plain", &id).await.status, 200);
    let late = &postgres.late;
    eventually(Duration::from_secs(10), "the late reply never came", || {
        late.load(Ordering::SeqCst) > 0
    })
    .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while idle_in_transaction(&h.fixture).await > 0 {
        assert!(
            Instant::now() < deadline,
            "a pooled connection stayed inside a transaction"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The delayed attempt and its retry each sent `BEGIN`.
    assert!(postgres.attempts.load(Ordering::SeqCst) >= 2);
    // The next borrowers of the pool serve another request as usual.
    let next = h.fixture.request(false).await;
    assert_eq!(h.send_case("02-chat-plain", &next).await.status, 200);
    let (fixture, _, events) = h.stop().await;
    for id in [&id, &next] {
        assert_eq!(fixture.reports(id).await.len(), 1);
        assert_eq!(
            fixture.settlement(id).await,
            Some((0, true, Some("19".to_owned()), 0))
        );
    }
    assert_eq!(fixture.budget().await, (38, 0));
    assert_eq!(events, []);
}
