//! `openmettle-gateway`, the V1-06 proxy (ADR 0044). The real binary, whose only database
//! login is `openmettle_gateway`, authenticates each caller by its request's round bearer,
//! forwards the request once to a stand-in upstream that replays the responses recorded from a
//! real SGLang deployment (`tests/fixtures/sglang-recorded/`), and settles the usage they
//! report. A request whose dispatch was spent and that ends without usage is closed by a final
//! report that names the reason (increment 3a, migration 31). Every case uses its own run
//! round, reserved and handed off through the library with its quota holds and without any
//! gateway binding, generation or policy row.
use super::*;
use crate::{
    quotas::{TurnHandoffFixture, snapshot_of},
    sglang_recorded::{self as recorded, ABORTED},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openmettle_core::{
    authz::{
        gateway::{
            self, Error as StoreError, TurnRound,
            settlement::{self, Outcome},
        },
        leases::LeaseSettings,
        runs::{self as queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
    },
    provider_http::gateway::UsageReport,
    quotas::{self as budgets, RunBudgetReservation},
    runs::{RunInput, WriteTransaction},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};

/// The installation of every request, which is also its report source.
const INSTALL: &str = "00000000-0000-4000-8000-0000000000a1";
/// The model the recorded requests name, which the gateway under test serves.
const MODEL: &str = "recorded-sglang-model";
/// A catalog model this gateway does not serve.
const OTHER_MODEL: &str = "a";
/// Token hold of each request: room for every recorded answer.
const UNITS: i64 = 1000;
/// A synthetic caller cookie that must reach neither the upstream nor the logs.
const COOKIE: &str = "canary-cookie-gateway-proxy";
const LIMITS: AdmissionLimits = AdmissionLimits {
    live_per_actor: 64,
    live_per_scope: 64,
    queued_in_instance: 64,
    queue_timeout: Duration::from_secs(300),
    round_cap: 4,
};
const CLAIMS: ClaimLimits = ClaimLimits {
    executing_per_actor: 64,
    executing_per_scope: 64,
};
const LEASES: LeaseSettings = LeaseSettings {
    lease: Duration::from_secs(120),
    execution_timeout: Duration::from_secs(600),
};

/// Recorded 200 answers and the usage each reports: prompt, completion and reasoning tokens.
/// Reasoning is already inside the completion count on this server.
pub(crate) const SETTLED: [(&str, i64, i64, i64); 5] = [
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

/// The round bearer the fixture gives request `id`. The library makes the bearer inside the
/// handoff, stores only its hash and keeps the bearer private to the worker's dispatch, and it
/// keeps the dispatch secret private too, so the fixture cannot choose the bearer through the
/// handoff. It replaces the stored `bearer_hash` of each handed-off request, as the database
/// owner, with the hash of a bearer the test can present. A request that is only reserved has
/// no bearer hash and gets none.
///
/// Every test in this file needs that known bearer: each presents a request the worker would
/// never send (a recorded or synthetic body, a missing, wrong or repeated credential, a
/// malformed header), or looks for the bearer in logs or database traffic. The bearer the
/// worker makes reaches the proxy unaltered in `worker_leases::live_turns::worker_gateway`,
/// where the packaged worker dispatches to this binary and nothing is re-keyed.
fn bearer_bytes(id: &str) -> [u8; 32] {
    Sha256::digest(format!("gateway-proxy-fixture:{id}")).into()
}

/// The credential of request `id`: its round bearer as unpadded base64url.
fn bearer(id: &str) -> String {
    URL_SAFE_NO_PAD.encode(bearer_bytes(id))
}

/// One account whose run rounds are reserved and handed off without any gateway binding.
struct Fixture {
    db: TestDb,
    owner: PgPool,
    worker: PgPool,
    actor: authz_store::Account,
    scope: String,
    /// The route of [`MODEL`] and of [`OTHER_MODEL`].
    route: TurnHandoffFixture,
    other_route: TurnHandoffFixture,
    runs: AtomicUsize,
    /// Every request issued, to check that no credential is logged.
    issued: Mutex<Vec<String>>,
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
        Self {
            owner: pool(&db, OWNER),
            worker: pool(&db, WORKER),
            route: TurnHandoffFixture::chat(INSTALL, MODEL, UNITS, None, false),
            other_route: TurnHandoffFixture::chat(INSTALL, OTHER_MODEL, UNITS, None, false),
            runs: AtomicUsize::new(0),
            issued: Mutex::default(),
            db,
            actor,
            scope,
        }
    }

    /// A new request of `UNITS` tokens for [`MODEL`], handed off unless `reserved_only`.
    async fn request(&self, reserved_only: bool) -> String {
        self.request_with_cost(MODEL, reserved_only, None).await
    }

    /// Round 1 of a new one-round run admitted for `model`, with its run and round holds,
    /// handed off unless `reserved_only`, and then given the bearer of [`bearer_bytes`].
    async fn request_for(&self, model: &str, reserved_only: bool) -> String {
        self.request_with_cost(model, reserved_only, None).await
    }

    /// Like [`Self::request_for`], optionally reserving a `usage_cost_micros` hold as well.
    async fn request_with_cost(
        &self,
        model: &str,
        reserved_only: bool,
        cost_micros: Option<u128>,
    ) -> String {
        let (actor, scope) = (&self.actor, self.scope.as_str());
        let chat = authz_runs::chat(&self.db, scope, "personal", actor).await;
        let mut api = connect(&self.db.0, API).await;
        let (branch, message) = quotas::branch_and_message(&mut api, scope, &chat).await;
        let key = format!("proxy-{}", self.runs.fetch_add(1, Ordering::SeqCst));
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let admitted = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope,
                    actor: &actor.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &message,
                    key: &key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snapshot_of(model, UNITS as u64),
                },
                actor_approval_id: &actor.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: cost_micros.map(|_| true),
            },
            &LIMITS,
        )
        .await
        .unwrap();
        let run = match admitted {
            Admission::Admitted { run_id, .. } => run_id,
            other => panic!("expected an admission, got {other:?}"),
        };
        let refused = budgets::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: scope,
                scope_kind: "personal",
                actor_user_id: &actor.user,
                actor_approval_id: &actor.approval,
                run_id: &run,
                token_units: UNITS,
                per_round_cost_micros: cost_micros,
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap();
        assert!(refused.is_none(), "{refused:?}");
        tx.commit().await.unwrap();
        let claim = queue::claim_next(&mut connect(&self.db.0, WORKER).await, &CLAIMS, &LEASES)
            .await
            .unwrap()
            .expect("a queued run");
        assert_eq!(claim.run_id, run);
        let pending = gateway::reserve_turn_round(
            &self.worker,
            TurnRound {
                scope_id: scope,
                actor: &actor.user,
                approval: &actor.approval,
                run_id: &run,
                round: 1,
                claim_token: &claim.claim_token,
                installation: INSTALL,
                model,
                round_tokens: UNITS,
                round_cost: cost_micros,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap();
        if !reserved_only {
            let cost_route = cost_micros
                .map(|c| TurnHandoffFixture::chat(INSTALL, model, UNITS, Some(c), false));
            let route = match (&cost_route, model) {
                (Some(r), _) => r,
                (None, MODEL) => &self.route,
                (None, _) => &self.other_route,
            };
            let handed_off = pending
                .handoff(
                    &self.worker,
                    None,
                    &route.billable(),
                    route.prepare_mode(true),
                )
                .await;
            assert!(handed_off.is_ok());
            let rekeyed = sqlx::query(
                "UPDATE openmettle.gateway_requests SET bearer_hash=sha256($2)
                  WHERE id=$1::uuid AND state='handed_off' AND bearer_hash IS NOT NULL",
            )
            .bind(&pending.id)
            .bind(bearer_bytes(&pending.id).as_slice())
            .execute(&self.owner)
            .await
            .unwrap();
            assert_eq!(rekeyed.rows_affected(), 1);
        }
        self.issued.lock().unwrap().push(pending.id.clone());
        pending.id.clone()
    }

    /// Replaces the dispatch secret of request `id` with `secret`, as the database owner: the
    /// library keeps the one it created private.
    async fn set_dispatch_secret(&self, id: &str, secret: &[u8; 32]) {
        let rekeyed = sqlx::query(
            "UPDATE openmettle.gateway_requests SET dispatch_hash=sha256($2) WHERE id=$1::uuid",
        )
        .bind(id)
        .bind(secret.as_slice())
        .execute(&self.owner)
        .await
        .unwrap();
        assert_eq!(rekeyed.rows_affected(), 1);
    }

    /// The run of request `id`.
    async fn run_of(&self, id: &str) -> String {
        sqlx::query_scalar("SELECT run_id::text FROM openmettle.gateway_requests WHERE id=$1::uuid")
            .bind(id)
            .fetch_one(&self.owner)
            .await
            .unwrap()
    }

    /// Whether the one dispatch of `id` is spent.
    async fn dispatched(&self, id: &str) -> bool {
        sqlx::query_scalar(
            "SELECT dispatched_at IS NOT NULL FROM openmettle.gateway_requests WHERE id=$1::uuid",
        )
        .bind(id)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }

    /// Spends the one dispatch of `id` as the gateway, with the fixture's bearer.
    async fn dispatch(&self, id: &str) {
        let spent = sqlx::query(
            "SELECT FROM openmettle.gateway_dispatch($1::uuid,sha256($2)) WHERE NOT replayed",
        )
        .bind(id)
        .bind(bearer_bytes(id).as_slice())
        .execute(&pool(&self.db, pg::GATEWAY))
        .await
        .unwrap();
        assert_eq!(spent.rows_affected(), 1);
    }

    /// A final report of `id` at `revision`, with the given prompt and completion counts.
    fn report(&self, id: &str, revision: i64, counts: Option<(i64, i64)>) -> UsageReport {
        UsageReport {
            request: id.to_owned(),
            installation: INSTALL.into(),
            principal: self.actor.user.clone(),
            scope: self.scope.clone(),
            source: INSTALL.into(),
            // One report identity per revision, as two writers would have.
            report_id: match revision {
                1 => id.to_owned(),
                n => format!("{}{n:012}", &id[..24]),
            },
            revision,
            r#final: true,
            prompt_tokens: counts.map(|(prompt, _)| prompt),
            completion_tokens: counts.map(|(_, completion)| completion),
            reasoning_tokens: None,
            reasoning_included: None,
            cost: None,
            unit: None,
        }
    }

    /// The kinds of the token hold's quota transitions, in order.
    async fn transitions(&self, id: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT c.kind FROM openmettle.quota_reconciliations c
               JOIN openmettle.quota_reservations h ON h.id=c.reservation_id
              WHERE h.gateway_request_id=$1::uuid AND h.resource_kind='usage_tokens'
              ORDER BY c.transition_revision",
        )
        .bind(id)
        .fetch_all(&self.owner)
        .await
        .unwrap()
    }

    /// Rows in the ADR 0037 provisioning tables: none is ever needed.
    async fn provisioned(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM openmettle.gateway_bindings)
                  + (SELECT count(*) FROM openmettle.gateway_generations)
                  + (SELECT count(*) FROM openmettle.gateway_policy)",
        )
        .fetch_one(&self.owner)
        .await
        .unwrap()
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

    /// Every stored report of `id` as an incomplete report shows it: report ID, revision,
    /// finality, the reason, and how many count, cost or unit fields it carries.
    async fn reasons(&self, id: &str) -> Vec<(String, i64, bool, Option<String>, i32)> {
        sqlx::query_as(
            "SELECT report_id::text,revision,final,incomplete,
                    num_nonnulls(prompt_tokens,completion_tokens,reasoning_tokens,
                                 reasoning_included,cost,unit)
               FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid ORDER BY revision",
        )
        .bind(id)
        .fetch_all(&self.owner)
        .await
        .unwrap()
    }

    /// Request `id` ended without usage for `reason`: its one report is final, carries the
    /// reason and no count, and has the proxy's revision; the settlement measured nothing and
    /// leaves nothing outstanding; the token hold is closed with nothing charged; and the
    /// request has left the scan of outstanding requests.
    async fn assert_closed(&self, id: &str, reason: &str) {
        assert_eq!(
            self.reasons(id).await,
            [(id.to_owned(), 1, true, Some(reason.to_owned()), 0)],
            "{reason}"
        );
        assert_eq!(
            self.settlement(id).await,
            Some((1, true, None, 0)),
            "{reason}"
        );
        assert_eq!(
            self.hold(id).await,
            ("settled".to_owned(), 0, "0".to_owned()),
            "{reason}"
        );
        let settled_final: bool = sqlx::query_scalar(
            "SELECT settled_final FROM openmettle.gateway_requests WHERE id=$1::uuid",
        )
        .bind(id)
        .fetch_one(&self.owner)
        .await
        .unwrap();
        assert!(settled_final, "{reason}");
    }

    /// Whether `id` is still in the scan of outstanding requests.
    async fn outstanding(&self, id: &str) -> bool {
        sqlx::query_scalar(
            "SELECT NOT settled_final FROM openmettle.gateway_requests WHERE id=$1::uuid",
        )
        .bind(id)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }

    /// What the worker's accounting verifier counts: storage, budget and settlement mismatches
    /// and accepted reports whose quota fold is still pending. All zero when the ledgers agree.
    async fn drift(&self) -> (i64, i64, i64, i64) {
        sqlx::query_as(
            "SELECT storage_mismatches,budget_mismatches,settlement_mismatches,
                    pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&self.worker)
        .await
        .unwrap()
    }

    /// The token units the account's requests still hold in reserve.
    async fn reserved(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT coalesce(sum(held_units),0)::bigint FROM openmettle.quota_reservations
              WHERE scope_id=$1::uuid AND resource_kind='usage_tokens'
                AND gateway_request_id IS NOT NULL",
        )
        .bind(&self.scope)
        .fetch_one(&self.owner)
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
        self.hold_of(id, "usage_tokens").await
    }

    /// The hold of `id` for `resource_kind`: state, held units and settled units.
    async fn hold_of(&self, id: &str, resource_kind: &str) -> (String, i64, String) {
        sqlx::query_as(
            "SELECT state,held_units,settled_units::text FROM openmettle.quota_reservations
              WHERE gateway_request_id=$1::uuid AND resource_kind=$2",
        )
        .bind(id)
        .bind(resource_kind)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }

    /// The token units the account's budget counts as used.
    async fn used(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT active_used::bigint FROM openmettle.quota_budgets
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

/// The recorded answer of `case`: a stream one event per chunk, and held after its first event
/// when `hold` is set; a JSON body in two writes.
fn recorded_script(case: &str, hold: bool) -> Script {
    let response = recorded::body(case);
    let mut writes = vec![recorded::head(case).into_bytes()];
    let chunked = recorded::chunked(case);
    if chunked {
        writes.extend(recorded::events(&response).into_iter().map(chunk));
        // The aborted recording closes without the terminal chunk.
        if case != ABORTED {
            writes.push(b"0\r\n\r\n".to_vec());
        }
    } else {
        let (first, rest) = response.split_at(response.len() / 2);
        writes.extend([first.to_vec(), rest.to_vec()]);
    }
    Script {
        writes: Box::new(writes.into_iter()),
        held: hold && chunked,
        pause: Duration::ZERO,
        linger: false,
    }
}

/// A recorded answer for its recorded request, a synthetic one for a body naming one in
/// `synthetic`, and otherwise none.
fn script(body: &[u8]) -> Option<Script> {
    let recorded_case = SETTLED
        .iter()
        .map(|(case, ..)| *case)
        .chain([ABORTED, UPSTREAM_500])
        .find(|case| recorded::file(case, "request.json") == body);
    if let Some(case) = recorded_case {
        return Some(recorded_script(case, true));
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
            // A complete stream that reports no usage, as when `include_usage` was not asked.
            "no-usage" => {
                let writes = vec![
                    SSE_HEAD.as_bytes().to_vec(),
                    chunk(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n"),
                    chunk(b"data: [DONE]\n\n"),
                    b"0\r\n\r\n".to_vec(),
                ];
                (Box::new(writes.into_iter()), false, Duration::ZERO, false)
            }
            // A complete stream whose usage is not a usage object.
            "garbled" => {
                let writes = vec![
                    SSE_HEAD.as_bytes().to_vec(),
                    chunk(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":\"many\"}}\n\n"),
                    chunk(b"data: [DONE]\n\n"),
                    b"0\r\n\r\n".to_vec(),
                ];
                (Box::new(writes.into_iter()), false, Duration::ZERO, false)
            }
            // The upstream reads the request and closes without answering.
            "hangup" => (Box::new(std::iter::empty()), false, Duration::ZERO, false),
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
pub(crate) struct StandIn {
    address: String,
    received: Arc<Mutex<Vec<Received>>>,
    gate: Arc<Gate>,
}

impl StandIn {
    async fn start() -> Self {
        Self::serve(None).await
    }

    /// A stand-in that answers every request, whatever its body, with the recorded answer of
    /// `case`, never held: for a caller such as the worker, whose requests are not the
    /// recorded ones.
    pub(crate) async fn answering(case: &'static str) -> Self {
        Self::serve(Some(case)).await
    }

    async fn serve(answer: Option<&'static str>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let received = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(Gate::default());
        let (log, held) = (received.clone(), gate.clone());
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(replay(socket, answer, log.clone(), held.clone()));
            }
        });
        Self {
            address,
            received,
            gate,
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }

    /// The lowercased head of the `n`th request received.
    pub(crate) fn head(&self, n: usize) -> String {
        self.received.lock().unwrap()[n].head.clone()
    }

    /// The body of the `n`th request received.
    pub(crate) fn body(&self, n: usize) -> Vec<u8> {
        self.received.lock().unwrap()[n].body.clone()
    }
}

async fn replay(
    mut socket: tokio::net::TcpStream,
    answer: Option<&'static str>,
    received: Arc<Mutex<Vec<Received>>>,
    gate: Arc<Gate>,
) {
    let Some((head, body)) = read_request(&mut socket).await else {
        return;
    };
    let script = match answer {
        Some(case) => Some(recorded_script(case, false)),
        None => script(&body),
    };
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
pub(crate) fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
}

// --- faulty database connection ---------------------------------------------------------------

/// Text of the first statement settlement sends inside its transaction.
const SETTLEMENT_LOCK: &[u8] = b"quota_lock_gateway_request_for_settlement";
/// The simple query that opens every transaction.
const BEGIN: &[u8] = b"BEGIN\0";

/// What happens to the connection that sends the faulted occurrence of the trigger.
#[derive(Clone, Copy)]
enum Fault {
    /// Nothing more is forwarded either way; the sockets stay open until released.
    Silence,
    /// The trigger reaches the server, but every reply from then on is held back this long.
    Delay(Duration),
    /// The trigger reaches the server, but the next reply is held back until released.
    Hold,
}

/// Forwards connections to the test PostgreSQL service, with one [`Fault`] on the connection
/// that sends `trigger` for the `skip + 1`th time.
pub(crate) struct FaultyPostgres {
    address: String,
    /// Times the trigger was seen; only one was faulted.
    attempts: Arc<AtomicUsize>,
    /// Held-back replies delivered after a [`Fault::Delay`] or a [`Fault::Hold`].
    late: Arc<AtomicUsize>,
    /// Every byte the client sent towards PostgreSQL, one stream per connection: a value
    /// split across two reads stays contiguous in its own stream.
    pub(crate) sent: Arc<Mutex<Vec<Vec<u8>>>>,
    release: Arc<Notify>,
}

impl FaultyPostgres {
    /// A forwarder that faults nothing and only records what the client sends.
    pub(crate) async fn recording() -> Self {
        Self::start(DISPATCH, usize::MAX, Fault::Silence).await
    }

    /// The address of `role` on `db` through this forwarder.
    pub(crate) fn url(&self, db: &TestDb, role: &str) -> String {
        let admin = pg::admin_options();
        let direct = format!("@{}:{}/", admin.get_host(), admin.get_port());
        let url = db.url(role);
        assert!(url.contains(&direct));
        url.replace(&direct, &format!("@{}/", self.address))
    }

    async fn start(trigger: &'static [u8], skip: usize, fault: Fault) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let admin = pg::admin_options();
        let server = format!("{}:{}", admin.get_host(), admin.get_port());
        let attempts = Arc::new(AtomicUsize::new(0));
        let late = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new(Notify::new());
        let faults = Faults {
            trigger,
            skip,
            fault,
            attempts: attempts.clone(),
            late: late.clone(),
            sent: sent.clone(),
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
            sent,
            release,
        }
    }

    /// Lets the one faulted connection go. The permit is kept, so a release that comes before
    /// the connection waits for it is not lost.
    fn release(&self) {
        self.release.notify_one();
    }
}

#[derive(Clone)]
struct Faults {
    trigger: &'static [u8],
    /// Earlier occurrences of the trigger that pass unfaulted.
    skip: usize,
    fault: Fault,
    attempts: Arc<AtomicUsize>,
    late: Arc<AtomicUsize>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    release: Arc<Notify>,
}

async fn forward(client: tokio::net::TcpStream, server: tokio::net::TcpStream, faults: Faults) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let stream = {
        let mut streams = faults.sent.lock().unwrap();
        streams.push(Vec::new());
        streams.len() - 1
    };
    let silent = Arc::new(AtomicBool::new(false));
    let hold = Arc::new(Mutex::new(None::<tokio::time::Instant>));
    let gate = Arc::new(AtomicBool::new(false));
    let (quiet, held, late) = (silent.clone(), hold.clone(), faults.late.clone());
    let (gated, released) = (gate.clone(), faults.release.clone());
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
            if gated.swap(false, Ordering::SeqCst) {
                released.notified().await;
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
            faults.sent.lock().unwrap()[stream].extend_from_slice(&buffer[..n]);
            seen.extend_from_slice(&buffer[..n]);
            if seen
                .windows(faults.trigger.len())
                .any(|w| w == faults.trigger)
                && faults.attempts.fetch_add(1, Ordering::SeqCst) == faults.skip
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
                    Fault::Hold => gate.store(true, Ordering::SeqCst),
                }
            }
            // Keep less than one trigger, so an occurrence is counted once.
            seen.drain(..seen.len().saturating_sub(faults.trigger.len() - 1));
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
        let (gateway, stderr) = launch_gateway(&fixture.db, &bind, &upstream, MODEL, settings);
        Self {
            fixture,
            upstream,
            gateway,
            bind,
            stderr,
        }
    }

    /// [`Self::send_with`] under the fixture's credential for `id`.
    async fn send(&self, id: Option<&str>, body: &[u8], extra: &str, then: Then<'_>) -> Reply {
        let credential = id.map_or_else(String::new, |id| {
            format!("Authorization: Bearer {}\r\n", bearer(id))
        });
        self.send_with(id, &credential, body, extra, then).await
    }

    /// Sends `body` with the `credential` header lines, the synthetic cookie and any `extra`
    /// header lines, then follows `then`. Without a `Connection` line in `extra`, the request
    /// asks to close.
    async fn send_with(
        &self,
        id: Option<&str>,
        credential: &str,
        body: &[u8],
        extra: &str,
        then: Then<'_>,
    ) -> Reply {
        let finished = self.upstream.gate.finished.load(Ordering::SeqCst);
        let mut socket = tokio::net::TcpStream::connect(&self.bind).await.unwrap();
        let mut request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
             Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
             {credential}Cookie: session={COOKIE}\r\nContent-Length: {}\r\n{extra}",
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
        let request = format!(r#"{{"model":"{MODEL}","synthetic":"{name}"}}"#);
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
        for secret in [COOKIE, "Count from 1 to 5"] {
            assert!(!stderr.contains(secret), "logged: {secret}");
        }
        for id in fixture.issued.lock().unwrap().iter() {
            assert!(
                !stderr.contains(&bearer(id)),
                "logged the credential of {id}"
            );
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

/// The gateway binary listening on `bind`, serving `db` as `openmettle_gateway` for `model`
/// through `upstream`, with extra `OPENMETTLE_GATEWAY_` settings applied last. It is ready when
/// this returns; the thread returns its complete stderr once it has exited.
pub(crate) fn launch_gateway(
    db: &TestDb,
    bind: &str,
    upstream: &StandIn,
    model: &str,
    settings: &[(&str, String)],
) -> (Process, thread::JoinHandle<String>) {
    let mut command = binary("gateway");
    command
        .env("OPENMETTLE_GATEWAY_BIND", bind)
        .env("OPENMETTLE_GATEWAY_DATABASE_URL", db.url(pg::GATEWAY))
        .env(
            "OPENMETTLE_GATEWAY_UPSTREAM_URL",
            format!("http://{}", upstream.address),
        )
        .env("OPENMETTLE_GATEWAY_MODEL", model)
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
    tokio::task::block_in_place(|| wait_ready(&mut gateway, bind));
    (gateway, stderr)
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
            let credential = bearer(&id).to_ascii_lowercase();
            for withheld in ["authorization", "cookie", &credential, COOKIE] {
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
    // Every request was authorized, dispatched and settled without a gateway binding.
    assert_eq!(fixture.provisioned().await, 0);
    for ((case, prompt, completion, reasoning), id) in SETTLED.into_iter().zip(&ids) {
        assert!(fixture.dispatched(id).await, "{case}");
        assert_eq!(
            fixture.reports(id).await,
            [(
                id.clone(),
                INSTALL.to_owned(),
                1,
                true,
                Some(prompt),
                Some(completion),
                Some(reasoning),
                Some(true)
            )],
            "{case}"
        );
        // A report with the upstream's usage carries no reason.
        assert_eq!(fixture.reasons(id).await[0].3, None, "{case}");
        let measured = (prompt + completion).to_string();
        assert_eq!(
            fixture.settlement(id).await,
            Some((1, true, Some(measured.clone()), 0)),
            "{case}"
        );
        assert_eq!(
            fixture.hold(id).await,
            ("settled".to_owned(), 0, measured),
            "{case}"
        );
    }
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
    assert_eq!(events, []);
}

/// A cut upstream stream reaches the caller as a prefix of its bytes with an unclean end, never
/// as a complete response. The caller reads nothing more after the first event until the
/// stand-in has written everything and closed, so the cut meets data still in flight.
///
/// The upstream was reached and reported no usage in each case here: the recorded aborted
/// stream, the recorded 500, a complete stream without a usage object and one whose usage is
/// not a usage object. Each closes its hold with the reason and charges nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn closes_the_hold_with_the_reason_when_the_upstream_reported_no_usage() {
    let h = Harness::start().await;
    let aborted = h.fixture.request(false).await;
    let failed = h.fixture.request(false).await;
    let silent = h.fixture.request(false).await;
    let garbled = h.fixture.request(false).await;
    let held = ("handoff_committed".to_owned(), UNITS, "0".to_owned());
    for id in [&aborted, &failed, &silent, &garbled] {
        assert_eq!(h.fixture.hold(id).await, held);
    }
    assert_eq!(h.fixture.reserved().await, 4 * UNITS);

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
    // Both streams reach the caller whole: only their accounting is incomplete.
    for (name, id) in [("no-usage", &silent), ("garbled", &garbled)] {
        let reply = h.send_synthetic(name, id, Then::Read).await;
        assert!(reply.status == 200 && reply.complete, "{name}");
        assert!(reply.body.ends_with(b"data: [DONE]\n\n"), "{name}");
    }
    assert_eq!(h.upstream.count(), 4);

    let (fixture, _, events) = h.stop().await;
    let ended = [
        (&aborted, "incomplete"),
        (&failed, "upstream_status"),
        (&silent, "no_usage"),
        (&garbled, "unparsable"),
    ];
    let mut expected = Vec::new();
    for (id, reason) in ended {
        fixture.assert_closed(id, reason).await;
        expected.push(unrecorded(id, reason));
    }
    // Nothing is charged and nothing stays reserved.
    assert_eq!((fixture.used().await, fixture.reserved().await), (0, 0));
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
    expected.sort();
    assert_eq!(events, expected);
}

/// An upstream that fails before its response head: one that closes without answering, and one
/// that does not answer within the idle timeout. The request was sent, so its usage is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_upstream_that_fails_before_its_head_closes_the_hold() {
    let settings = [("UPSTREAM_IDLE_TIMEOUT_MS", "1000".to_owned())];
    let h = Harness::launch(Fixture::new().await, StandIn::start().await, &settings).await;
    let hung_up = h.fixture.request(false).await;
    let reply = h.send_synthetic("hangup", &hung_up, Then::Read).await;
    assert_eq!(refusal(&reply), (502, "provider_failure".to_owned(), None));
    let stalled = h.fixture.request(false).await;
    // The stand-in has no script for this body: it waits for the proxy to give up.
    let reply = h.send_synthetic("stall", &stalled, Then::Read).await;
    assert_eq!(refusal(&reply), (504, "timeout".to_owned(), None));
    assert_eq!(h.upstream.count(), 2);
    let (fixture, _, events) = h.stop().await;
    fixture.assert_closed(&hung_up, "upstream_transport").await;
    fixture.assert_closed(&stalled, "upstream_timeout").await;
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
    let mut expected = vec![
        unrecorded(&hung_up, "upstream_transport"),
        unrecorded(&stalled, "upstream_timeout"),
    ];
    expected.sort();
    assert_eq!(events, expected);
}

/// An upstream that accepts no connection: the dispatch was spent and nothing was sent, which
/// the reason records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_unreachable_upstream_closes_the_hold_with_nothing_sent() {
    // A port held by a socket that is bound and never listens: for the whole case a connection
    // to it is refused and nothing else can take it.
    let held = tokio::net::TcpSocket::new_v4().unwrap();
    held.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let closed = held.local_addr().unwrap();
    assert!(
        std::net::TcpListener::bind(closed).is_err(),
        "nothing else can take the upstream's port during the case"
    );
    let settings = [("UPSTREAM_URL", format!("http://{closed}"))];
    let h = Harness::launch(Fixture::new().await, StandIn::start().await, &settings).await;
    let id = h.fixture.request(false).await;
    let reply = h.send_case("02-chat-plain", &id).await;
    assert_eq!(refusal(&reply), (502, "provider_failure".to_owned(), None));
    assert_eq!(h.upstream.count(), 0);
    let (fixture, _, events) = h.stop().await;
    assert!(fixture.dispatched(&id).await);
    fixture.assert_closed(&id, "upstream_connect").await;
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
    assert_eq!(events, [unrecorded(&id, "upstream_connect")]);
    drop(held);
}

/// The status, problem code and `WWW-Authenticate` value of a refusal.
fn refusal(reply: &Reply) -> (u16, String, Option<String>) {
    assert_eq!(
        content_type(&reply.head).as_deref(),
        Some("application/problem+json")
    );
    let problem: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(problem["status"].as_u64(), Some(u64::from(reply.status)));
    (
        reply.status,
        problem["code"].as_str().unwrap().to_owned(),
        header(&reply.head, "www-authenticate").map(str::to_owned),
    )
}

fn unauthenticated() -> (u16, String, Option<String>) {
    (401, "unauthenticated".to_owned(), Some("bearer".to_owned()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn refuses_unusable_requests_before_spending_or_forwarding_anything() {
    let h = Harness::start().await;
    let handed_off = h.fixture.request(false).await;
    let body = recorded::file("02-chat-plain", "request.json");
    let uppercase = "0F8FAD5B-D9CB-469F-A165-70867728950E".to_owned();
    for (id, extra, status, code) in [
        (None, "", 400, "validation"),
        (Some("not-a-request-id".to_owned()), "", 400, "validation"),
        (Some(uppercase), "", 400, "validation"),
        // Only identity bodies are forwarded.
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
        assert_eq!(
            refusal(&reply),
            (status, code.to_owned(), None),
            "{id:?} {extra}"
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
             X-Request-Id: {handed_off}\r\nAuthorization: Bearer {}\r\n\
             Connection: close\r\n\r\n",
            bearer(&handed_off)
        )
        .into_bytes();
        request.extend_from_slice(if status == 505 { &body } else { &chunked_body });
        let reply = h.raw(&request).await;
        assert_eq!(refusal(&reply), (status, code.to_owned(), None), "{head}");
    }
    // A `Connection` value that cannot be read could hide a nomination of the credential: the
    // request is refused whatever it names. The readable value lets the server close.
    let mut hidden = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
         Content-Type: application/json\r\nX-Request-Id: {handed_off}\r\n\
         Authorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\
         Connection: Authorization",
        bearer(&handed_off),
        body.len()
    )
    .into_bytes();
    hidden.extend_from_slice(b"\xff\r\n\r\n");
    hidden.extend_from_slice(&body);
    let reply = h.raw(&hidden).await;
    assert_eq!(refusal(&reply), (400, "validation".to_owned(), None));
    assert_eq!(h.upstream.count(), 0, "nothing was forwarded");
    assert!(!h.fixture.dispatched(&handed_off).await);
    // None of these refusals spent the dispatch.
    let reply = h.send(Some(&handed_off), &body, "", Then::Read).await;
    assert_eq!(reply.status, 200);
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&handed_off).await.len(), 1);
    assert_eq!(events, []);
}

/// A caller that cannot present the bearer of the request it names gets the same 401, whether
/// the credential is unusable, the bearer wrong, or the request unknown or not handed off:
/// nothing is sent upstream and nothing is spent. The request's dispatch secret is not its
/// bearer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn refuses_a_caller_without_the_bearer_of_its_request() {
    let h = Harness::start().await;
    let reserved = h.fixture.request(true).await;
    let handed_off = h.fixture.request(false).await;
    let other = h.fixture.request(false).await;
    // A handed-off request whose dispatch secret the test knows.
    let keyed = h.fixture.request(false).await;
    let dispatch_secret = [0x5a; 32];
    h.fixture
        .set_dispatch_secret(&keyed, &dispatch_secret)
        .await;
    let unknown: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&h.fixture.owner)
        .await
        .unwrap();
    let body = recorded::file("02-chat-plain", "request.json");
    let right = bearer(&handed_off);
    let header = |value: &str| format!("Authorization: {value}\r\n");
    for (id, credential, extra) in [
        // Missing, malformed and duplicated credentials.
        (&handed_off, String::new(), ""),
        (&handed_off, header(&right), ""),
        (&handed_off, header(&format!("Basic {right}")), ""),
        (&handed_off, header(&format!("bearer {right}")), ""),
        (&handed_off, header(&format!("Bearer {right}=")), ""),
        (&handed_off, header(&format!("Bearer {}", &right[..42])), ""),
        (&handed_off, header("Bearer not-a-round-bearer"), ""),
        (
            &handed_off,
            header(&format!("Bearer {right}")).repeat(2),
            "",
        ),
        // A credential named as hop-by-hop counts as absent.
        (
            &handed_off,
            header(&format!("Bearer {right}")),
            "Connection: close, Authorization\r\n",
        ),
        // Another request's bearer, and a well-formed bearer of no request.
        (
            &handed_off,
            header(&format!("Bearer {}", bearer(&other))),
            "",
        ),
        (
            &handed_off,
            header(&format!("Bearer {}", bearer(&unknown))),
            "",
        ),
        // The fixture's bearer for an unknown request, and for one reserved but not handed off,
        // which has no bearer yet.
        (
            &unknown,
            header(&format!("Bearer {}", bearer(&unknown))),
            "",
        ),
        (
            &reserved,
            header(&format!("Bearer {}", bearer(&reserved))),
            "",
        ),
        // The dispatch secret of a handed-off request: the worker's proof to the database, which
        // the proxy does not accept.
        (
            &keyed,
            header(&format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(dispatch_secret)
            )),
            "",
        ),
    ] {
        let reply = h
            .send_with(Some(id), &credential, &body, extra, Then::Read)
            .await;
        assert_eq!(refusal(&reply), unauthenticated(), "{id} {credential}");
    }
    assert_eq!(h.upstream.count(), 0, "nothing was forwarded");
    for id in [&reserved, &handed_off, &other, &keyed] {
        assert!(!h.fixture.dispatched(id).await);
    }
    // The holder of the bearer is still served.
    let reply = h.send(Some(&handed_off), &body, "", Then::Read).await;
    assert_eq!(reply.status, 200);
    assert_eq!(h.upstream.count(), 1);
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&reserved).await, []);
    assert_eq!(fixture.reports(&other).await, []);
    assert_eq!(fixture.reports(&handed_off).await.len(), 1);
    assert_eq!(events, []);
}

/// One request reaches the upstream once: a later dispatch with the right bearer is a
/// conflict, and of two concurrent ones at most one is forwarded. Here nothing else refuses
/// either of the two, so one is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn one_request_is_dispatched_and_settled_exactly_once() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let reply = h.send_case("03-chat-stream-usage", &id).await;
    assert_eq!(reply.status, 200);
    assert!(reply.body == recorded::body("03-chat-stream-usage") && reply.complete);
    let replayed = recorded::file("03-chat-stream-usage", "request.json");
    for _ in 0..2 {
        let reply = h.send(Some(&id), &replayed, "", Then::Read).await;
        assert_eq!(refusal(&reply), (409, "conflict".to_owned(), None));
    }
    // A replay is reported only to the holder of the bearer.
    let stranger = format!("Authorization: Bearer {}\r\n", bearer("another"));
    let reply = h
        .send_with(Some(&id), &stranger, &replayed, "", Then::Read)
        .await;
    assert_eq!(refusal(&reply), unauthenticated());
    assert_eq!(h.upstream.count(), 1);

    let raced = h.fixture.request(false).await;
    let plain = recorded::file("02-chat-plain", "request.json");
    let (first, second) = tokio::join!(
        h.send(Some(&raced), &plain, "", Then::Read),
        h.send(Some(&raced), &plain, "", Then::Read)
    );
    let mut statuses = [first.status, second.status];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    assert_eq!(h.upstream.count(), 2);

    let (fixture, _, events) = h.stop().await;
    let reports = fixture.reports(&id).await;
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(
        fixture.settlement(&id).await,
        Some((1, true, Some("29".to_owned()), 0))
    );
    assert_eq!(
        fixture.hold(&id).await,
        ("settled".to_owned(), 0, "29".to_owned())
    );
    assert_eq!(
        fixture.settlement(&raced).await,
        Some((1, true, Some("19".to_owned()), 0))
    );
    assert_eq!(fixture.used().await, 29 + 19);
    assert_eq!(events, []);
}

/// The upstream answers any model name from its loaded model (recorded case 11), so the proxy
/// is the only model check. A request reserved for a model this gateway does not serve, and a
/// body that does not name the reserved model exactly once, are refused with nothing sent
/// upstream. Each refusal comes after the dispatch was spent, is logged with its reason and
/// closes the request's hold with it: nothing was sent, so nothing is charged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn refuses_a_model_other_than_the_one_reserved_and_served() {
    let h = Harness::start().await;
    let served = recorded::file("02-chat-plain", "request.json");
    let not_served = h.fixture.request_for(OTHER_MODEL, false).await;
    let reply = h
        .send(
            Some(&not_served),
            br#"{"model":"a","messages":[]}"#,
            "",
            Then::Read,
        )
        .await;
    assert_eq!(refusal(&reply), (403, "policy".to_owned(), None));
    // Also when the body names the model this gateway serves.
    let also_not_served = h.fixture.request_for(OTHER_MODEL, false).await;
    let reply = h
        .send(Some(&also_not_served), &served, "", Then::Read)
        .await;
    assert_eq!(refusal(&reply), (403, "policy".to_owned(), None));

    let mut mismatched = Vec::new();
    let twice = format!(r#"{{"model":"{MODEL}","model":"no-such-model","messages":[]}}"#);
    for body in [
        recorded::file("11-chat-bad-model", "request.json"),
        twice.into_bytes(),
        br#"{"messages":[]}"#.to_vec(),
        b"not json".to_vec(),
    ] {
        let id = h.fixture.request(false).await;
        let reply = h.send(Some(&id), &body, "", Then::Read).await;
        assert_eq!(
            refusal(&reply),
            (400, "validation".to_owned(), None),
            "{}",
            String::from_utf8_lossy(&body)
        );
        mismatched.push(id);
    }
    assert_eq!(h.upstream.count(), 0, "nothing was forwarded");
    // The dispatch is spent: the corrected request is a replay.
    let reply = h.send(Some(&mismatched[0]), &served, "", Then::Read).await;
    assert_eq!(refusal(&reply), (409, "conflict".to_owned(), None));
    assert_eq!(h.upstream.count(), 0);

    let (fixture, _, events) = h.stop().await;
    let mut expected = Vec::new();
    for id in [&not_served, &also_not_served] {
        assert!(fixture.dispatched(id).await);
        fixture.assert_closed(id, "model_not_served").await;
        expected.push(unrecorded(id, "model_not_served"));
    }
    for id in &mismatched {
        assert!(fixture.dispatched(id).await);
        fixture.assert_closed(id, "model_mismatch").await;
        expected.push(unrecorded(id, "model_mismatch"));
    }
    assert_eq!((fixture.used().await, fixture.reserved().await), (0, 0));
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
    expected.sort();
    assert_eq!(events, expected);
}

/// A run cancelled after its round was handed off is not dispatched: the caller is refused
/// like one without the bearer, and the dispatch stays unspent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_cancelled_run_is_refused_without_forwarding() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let run = h.fixture.run_of(&id).await;
    let principal = authz_store::principal(&h.fixture.db, &h.fixture.actor).await;
    queue::cancel_run(
        &mut connect(&h.fixture.db.0, API).await,
        &principal,
        &h.fixture.scope,
        &run,
    )
    .await
    .unwrap();
    let body = recorded::file("02-chat-plain", "request.json");
    let reply = h.send(Some(&id), &body, "", Then::Read).await;
    assert_eq!(refusal(&reply), unauthenticated());
    assert_eq!(h.upstream.count(), 0);
    assert!(!h.fixture.dispatched(&id).await);
    let (_, _, events) = h.stop().await;
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
/// request's token hold, which settlement locks and the dispatch does not, sees the first
/// attempt wait for it, signals, and releases the lock only once a second, distinct attempt is
/// waiting: the first has hit settlement's lock timeout and the relay is retrying while the
/// process drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn shutdown_waits_for_a_report_write_that_is_retrying() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let mut lock = h.fixture.owner.begin().await.unwrap();
    let locked = sqlx::query(
        "SELECT FROM openmettle.quota_reservations WHERE gateway_request_id=$1::uuid
            FOR NO KEY UPDATE",
    )
    .bind(&id)
    .execute(&mut *lock)
    .await
    .unwrap();
    assert_eq!(locked.rows_affected(), 1);
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
        Some((1, true, Some("19".to_owned()), 0))
    );
    assert_eq!(events, []);
}

/// A caller that leaves before the usage arrived takes the upstream connection with it, so the
/// model server stops generating. How much it generated is unknown: the hold is closed with
/// that reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_caller_leaving_mid_stream_drops_the_upstream_and_closes_the_hold() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
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
    fixture.assert_closed(&id, "caller_disconnected").await;
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
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
/// sends the recorded requests through the binary, each under its request's credential, and
/// checks each stored report against the usage in the bytes the caller received. The gateway
/// serves the model name the recordings carry. Without the variable, returns at once.
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
                INSTALL.to_owned(),
                1,
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
            Some((1, true, Some(measured.to_string()), 0)),
            "{case}"
        );
    }
    assert_eq!(events, []);
}

/// A caller that leaves while the upstream has not answered yet also takes the upstream
/// connection with it. The handler is dropped with the caller, and the request is still closed:
/// the report is written by a task of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_caller_leaving_before_the_response_head_drops_the_upstream() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let body = format!(r#"{{"model":"{MODEL}","stall":true}}"#);
    let mut socket = tokio::net::TcpStream::connect(&h.bind).await.unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
         Content-Type: application/json\r\nX-Request-Id: {id}\r\n\
         Authorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
        bearer(&id),
        body.len()
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    socket.write_all(body.as_bytes()).await.unwrap();
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
    fixture.assert_closed(&id, "caller_disconnected").await;
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
    assert_eq!(events, [unrecorded(&id, "caller_disconnected")]);
}

/// Only identity bodies are relayed: the upstream is asked for one, and an
/// answer with a content coding, or a transfer coding other than `chunked`, is refused with 502,
/// its connection closed without reading it, and recorded without usage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_compressed_answer_is_refused_and_closes_the_hold() {
    let h = Harness::start().await;
    let mut ids = Vec::new();
    for (n, name) in ["gzip", "gzip-te"].into_iter().enumerate() {
        let id = h.fixture.request(false).await;
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
        ids.push(id);
    }
    let (fixture, _, events) = h.stop().await;
    let mut expected = Vec::new();
    for id in &ids {
        fixture.assert_closed(id, "upstream_encoding").await;
        expected.push(unrecorded(id, "upstream_encoding"));
    }
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
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
    fixture.assert_closed(&id, "upstream_timeout").await;
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
    assert_eq!(events, [unrecorded(&id, "upstream_timeout")]);
}

/// A settlement attempt whose database connection goes silent is abandoned after its
/// client-side deadline (five `DB_TIMEOUT_MS`) and retried on another connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_report_write_on_a_silent_database_connection_is_retried() {
    let fixture = Fixture::new().await;
    let silencer = FaultyPostgres::start(SETTLEMENT_LOCK, 0, Fault::Silence).await;
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
        Some((1, true, Some("19".to_owned()), 0))
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

/// A handed-off request whose body never arrives in full is refused, logged and closed: its
/// dispatch was spent before the body was read, and nothing was sent upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_unread_request_body_closes_the_hold() {
    let h = Harness::start().await;
    let id = h.fixture.request(false).await;
    let mut socket = tokio::net::TcpStream::connect(&h.bind).await.unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.test\r\n\
         Content-Type: application/json\r\nX-Request-Id: {id}\r\n\
         Authorization: Bearer {}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        bearer(&id),
        2 * 1024 * 1024 + 1
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), socket.read_to_end(&mut raw)).await;
    let reply = parse(&raw);
    assert_eq!(reply.status, 400);
    assert_eq!(h.upstream.count(), 0);
    let (fixture, _, events) = h.stop().await;
    assert!(fixture.dispatched(&id).await);
    fixture.assert_closed(&id, "request_body").await;
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
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
    // Two seconds per attempt (five `DB_TIMEOUT_MS`). The first `BEGIN` spends the dispatch;
    // the second, the first attempt to store the report, is answered after three seconds.
    let postgres = FaultyPostgres::start(BEGIN, 1, Fault::Delay(Duration::from_secs(3))).await;
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
    // The dispatch, the delayed attempt and its retry each sent `BEGIN`.
    assert!(postgres.attempts.load(Ordering::SeqCst) >= 3);
    // The next borrowers of the pool serve another request as usual.
    let next = h.fixture.request(false).await;
    assert_eq!(h.send_case("02-chat-plain", &next).await.status, 200);
    let (fixture, _, events) = h.stop().await;
    for id in [&id, &next] {
        assert_eq!(fixture.reports(id).await.len(), 1);
        assert_eq!(
            fixture.settlement(id).await,
            Some((1, true, Some("19".to_owned()), 0))
        );
    }
    assert_eq!(fixture.used().await, 38);
    assert_eq!(events, []);
}

/// Text of the statement that spends a dispatch.
const DISPATCH: &[u8] = b"gateway_dispatch";

/// A dispatch whose database exchange never answers is not forwarded: the caller gets 503
/// after the proxy stops waiting (five `DB_TIMEOUT_MS`), and the request is logged because its
/// dispatch may be spent. Here the statement never reached the server, so the caller's retry
/// is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_unanswered_dispatch_is_not_forwarded_and_is_logged() {
    let fixture = Fixture::new().await;
    let silencer = FaultyPostgres::start(DISPATCH, 0, Fault::Silence).await;
    let url = format!(
        "postgres://{}:{PASSWORD}@{}/{}?sslmode=disable",
        pg::GATEWAY,
        silencer.address,
        fixture.db.0
    );
    let settings = [("DATABASE_URL", url), ("DB_TIMEOUT_MS", "400".to_owned())];
    let h = Harness::launch(fixture, StandIn::start().await, &settings).await;
    let id = h.fixture.request(false).await;
    let body = recorded::file("02-chat-plain", "request.json");
    let reply = h.send(Some(&id), &body, "", Then::Read).await;
    assert_eq!(refusal(&reply), (503, "unavailable".to_owned(), None));
    assert_eq!(h.upstream.count(), 0);
    assert!(!h.fixture.dispatched(&id).await);
    let reply = h.send(Some(&id), &body, "", Then::Read).await;
    assert_eq!(reply.status, 200);
    assert_eq!(silencer.attempts.load(Ordering::SeqCst), 2);
    // Let the silent connection go, so the pool can close at shutdown.
    silencer.release();
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await.len(), 1);
    assert_eq!(events, [unrecorded(&id, "dispatch_unconfirmed")]);
}

/// Text of the statement that makes a transaction durable.
const COMMIT: &[u8] = b"COMMIT\0";

/// A dispatch whose commit reached the database, but whose acknowledgement came after the
/// proxy stopped waiting, is spent: the caller gets 503, nothing is forwarded, a retry is a
/// replay, and the request is logged once because nobody saw it succeed. The proxy cannot
/// close it, because it never learned that the dispatch was spent: the request keeps its hold
/// until the sweep of increment 3b closes it.
///
/// The order is not timed. The acknowledgement of the `COMMIT` is held in the forwarder until
/// the test releases it, and the test releases it only after it has read the 503 and the
/// retry's 409: neither can have followed the acknowledgement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_dispatch_committed_but_unacknowledged_is_spent_and_logged() {
    let fixture = Fixture::new().await;
    // The proxy waits two seconds for the dispatch (five `DB_TIMEOUT_MS`).
    let postgres = FaultyPostgres::start(COMMIT, 0, Fault::Hold).await;
    let url = format!(
        "postgres://{}:{PASSWORD}@{}/{}?sslmode=disable",
        pg::GATEWAY,
        postgres.address,
        fixture.db.0
    );
    let settings = [("DATABASE_URL", url), ("DB_TIMEOUT_MS", "400".to_owned())];
    let h = Harness::launch(fixture, StandIn::start().await, &settings).await;
    let id = h.fixture.request(false).await;
    let body = recorded::file("02-chat-plain", "request.json");
    let reply = h.send(Some(&id), &body, "", Then::Read).await;
    assert_eq!(refusal(&reply), (503, "unavailable".to_owned(), None));
    assert_eq!(h.upstream.count(), 0);
    // The 503 was read while the forwarder held the acknowledgement: the `COMMIT` had passed
    // it, and no held reply had been let through.
    let late = &postgres.late;
    assert_eq!(postgres.attempts.load(Ordering::SeqCst), 1);
    assert_eq!(late.load(Ordering::SeqCst), 0);
    // The commit itself was not held, only its acknowledgement.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !h.fixture.dispatched(&id).await {
        assert!(Instant::now() < deadline, "the dispatch never committed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let reply = h.send(Some(&id), &body, "", Then::Read).await;
    assert_eq!(refusal(&reply), (409, "conflict".to_owned(), None));
    assert_eq!(h.upstream.count(), 0);
    // Still held: the retry was refused on the committed row alone.
    assert_eq!(late.load(Ordering::SeqCst), 0);
    postgres.release();
    eventually(
        Duration::from_secs(10),
        "the late acknowledgement never came",
        || late.load(Ordering::SeqCst) > 0,
    )
    .await;
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await, []);
    assert_eq!(
        fixture.hold(&id).await,
        ("handoff_committed".to_owned(), UNITS, "0".to_owned())
    );
    assert_eq!(events, [unrecorded(&id, "dispatch_unconfirmed")]);

    // Inside its 15-minute grace window the sweep leaves the dispatch_unconfirmed hold open;
    // once 15 minutes pass after the run's execution deadline, the sweep closes it as
    // `unreported` at revision 0 with zero charged and zero drift.
    let mut pass = budgets::Pass::default();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&fixture.worker, &mut pass, 100)
            .await
            .unwrap(),
        0
    );
    let run = fixture.run_of(&id).await;
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                execution_expires_at=clock_timestamp()-interval '16 minutes'
          WHERE id=$1::uuid",
    )
    .bind(&run)
    .execute(&fixture.owner)
    .await
    .unwrap();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&fixture.worker, &mut pass, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        fixture.reasons(&id).await,
        [(id.clone(), 0, true, Some("unreported".to_owned()), 0)]
    );
    assert_eq!(fixture.settlement(&id).await, Some((0, true, None, 0)));
    assert_eq!(
        fixture.hold(&id).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!((fixture.used().await, fixture.reserved().await), (0, 0));
    assert_eq!(fixture.drift().await, (0, 0, 0, 0));
}

/// The proxy sends PostgreSQL the SHA-256 of the bearer and never the bearer: a server that
/// logs statement parameters then records nothing a caller could present. Every byte the
/// gateway sends to the database is recorded here, with nothing faulted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_bearer_never_reaches_the_database() {
    let fixture = Fixture::new().await;
    let postgres = FaultyPostgres::recording().await;
    let url = format!(
        "postgres://{}:{PASSWORD}@{}/{}?sslmode=disable",
        pg::GATEWAY,
        postgres.address,
        fixture.db.0
    );
    let h = Harness::launch(fixture, StandIn::start().await, &[("DATABASE_URL", url)]).await;
    let id = h.fixture.request(false).await;
    assert_eq!(h.send_case("02-chat-plain", &id).await.status, 200);
    let (fixture, _, events) = h.stop().await;
    assert_eq!(fixture.reports(&id).await.len(), 1);
    assert_eq!(events, []);
    let sent = postgres.sent.lock().unwrap().clone();
    let carried = |needle: &[u8]| {
        sent.iter()
            .any(|stream| stream.windows(needle.len()).any(|w| w == needle))
    };
    // The call that spent the dispatch went through this connection.
    assert!(carried(DISPATCH));
    let hex: String = bearer_bytes(&id)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for (form, spelled) in [
        ("raw", bearer_bytes(&id).to_vec()),
        ("hexadecimal", hex.into_bytes()),
        ("base64url", bearer(&id).into_bytes()),
    ] {
        assert!(
            !carried(&spelled),
            "the bearer reached the database, {form}"
        );
    }
    // What it carried is the hash.
    assert!(carried(&Sha256::digest(bearer_bytes(&id))));
}

/// The revisions settlement sees, without the binary: the proxy writes its one report at
/// revision 1 and leaves revision 0 to the sweep that closes a request nobody reported.
///   * A report of the proxy that arrives after the sweep's record corrects it, whether it
///     carries usage or a reason.
///   * Nothing reopens a request that a complete report closed: a second report under the same
///     identity conflicts, the sweep's revision is superseded, and a later incomplete report
///     keeps the charge.
///   * A report with a reason carries no usage of its own. What an earlier accepted report
///     measured is still charged: a running count in a report that is not final, then the
///     reason.
///   * A final report that does not close the hold is refused and leaves the hold and the
///     request as they were: accepted, it would hide the request and keep the hold for good.
///     That holds for no count at all, for one count, and for one count that covers the whole
///     reservation, which empties the hold without closing it.
///   * The operator's query lists a request by its current settlement, not by a record a later
///     report corrected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_later_report_corrects_an_incomplete_one_and_nothing_reopens_a_complete_one() {
    let f = Fixture::new().await;
    let gateway = pool(&f.db, pg::GATEWAY);
    let held = ("handoff_committed".to_owned(), UNITS, "0".to_owned());
    let usage = Some((7, 5));
    let charged = ("settled".to_owned(), 0, "12".to_owned());

    // An incomplete report first, then a higher revision with usage.
    let swept = f.request(false).await;
    f.dispatch(&swept).await;
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &f.report(&swept, 1, None), "upstream_timeout")
            .await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        f.hold(&swept).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!((f.used().await, f.reserved().await), (0, 0));
    assert_eq!(
        settlement::ingest(&gateway, &f.report(&swept, 2, usage)).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(f.hold(&swept).await, charged);
    assert_eq!(
        f.settlement(&swept).await,
        Some((2, true, Some("12".to_owned()), 0))
    );
    assert_eq!(
        f.transitions(&swept).await,
        ["final_settle", "final_correction"]
    );
    assert_eq!(f.used().await, 12);

    // An incomplete report first, then a higher revision with another reason: still nothing.
    let unknown = f.request(false).await;
    f.dispatch(&unknown).await;
    for (revision, reason) in [(1, "upstream_timeout"), (2, "caller_disconnected")] {
        assert_eq!(
            settlement::ingest_incomplete(&gateway, &f.report(&unknown, revision, None), reason)
                .await,
            Ok(Outcome::Applied)
        );
    }
    assert_eq!(
        f.reasons(&unknown)
            .await
            .iter()
            .map(|r| r.3.as_deref())
            .collect::<Vec<_>>(),
        [Some("upstream_timeout"), Some("caller_disconnected")]
    );
    assert_eq!(
        f.hold(&unknown).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!(f.transitions(&unknown).await, ["final_settle"]);

    // A complete report first: no later report without usage changes what it charged, and
    // revision 0 on an unbound request is reserved to the worker sweep.
    let complete = f.request(false).await;
    f.dispatch(&complete).await;
    assert_eq!(
        settlement::ingest(&gateway, &f.report(&complete, 2, usage)).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &f.report(&complete, 2, None), "incomplete").await,
        Err(StoreError::Conflict)
    );
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &f.report(&complete, 1, None), "incomplete").await,
        Ok(Outcome::Superseded)
    );
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &f.report(&complete, 0, None), "incomplete").await,
        Err(StoreError::Refused)
    );
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &f.report(&complete, 3, None), "incomplete").await,
        Ok(Outcome::Applied)
    );
    assert_eq!(f.hold(&complete).await, charged);
    assert_eq!(f.transitions(&complete).await, ["final_settle"]);
    assert_eq!((f.used().await, f.reserved().await), (24, 0));

    // A reason and usage, cost or unit in one report would contradict each other.
    let running = f.request(false).await;
    f.dispatch(&running).await;
    for mixed in [
        f.report(&running, 1, usage),
        UsageReport {
            reasoning_included: Some(true),
            ..f.report(&running, 1, None)
        },
        UsageReport {
            cost: Some("1".to_owned()),
            unit: Some("usd_micros".to_owned()),
            ..f.report(&running, 1, None)
        },
        UsageReport {
            unit: Some("usd_micros".to_owned()),
            ..f.report(&running, 1, None)
        },
    ] {
        assert_eq!(
            settlement::ingest_incomplete(&gateway, &mixed, "no_usage").await,
            Err(StoreError::Refused)
        );
    }
    assert_eq!(f.reports(&running).await, []);
    assert_eq!(f.hold(&running).await, held);
    // A running count arrives in a report that is not final; the reason then closes the hold at
    // that count.
    let mut interim = f.report(&running, 1, usage);
    interim.r#final = false;
    assert_eq!(
        settlement::ingest(&gateway, &interim).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        f.hold(&running).await,
        ("handoff_committed".to_owned(), UNITS - 12, "12".to_owned())
    );
    assert_eq!(
        settlement::ingest_incomplete(
            &gateway,
            &f.report(&running, 2, None),
            "caller_disconnected"
        )
        .await,
        Ok(Outcome::Applied)
    );
    assert_eq!(f.hold(&running).await, charged);
    assert_eq!(
        f.transitions(&running).await,
        ["partial_settle", "final_settle"]
    );
    assert_eq!((f.used().await, f.reserved().await), (36, 0));

    // The trap, on a metered request: no reason, and counts that do not close the hold.
    let trapped = f.request(false).await;
    f.dispatch(&trapped).await;
    for counts in [None, Some((4, 0)), Some((UNITS, 0))] {
        let mut bare = f.report(&trapped, 1, counts);
        bare.completion_tokens = None;
        assert_eq!(
            settlement::ingest(&gateway, &bare).await,
            Err(StoreError::Refused),
            "{counts:?}"
        );
    }
    assert_eq!(f.reports(&trapped).await, []);
    assert_eq!(f.settlement(&trapped).await, None);
    assert_eq!(f.hold(&trapped).await, held);
    assert!(f.outstanding(&trapped).await);
    assert_eq!((f.used().await, f.reserved().await), (36, UNITS));
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // The query the operator page gives, run as written: one row per request whose current
    // settlement is a report without usage. The request the sweep closed and the proxy then
    // reported with usage is not listed, and the one both closed is listed once, with the
    // proxy's reason.
    let page = include_str!("../../docs/operator/gateway-proxy.md");
    let (_, query) = page.split_once("```sql\n").unwrap();
    let (query, _) = query.split_once("```").unwrap();
    let query = query.trim().trim_end_matches(';');
    let mut listed: Vec<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT request_id::text,incomplete FROM ({query}) AS listed"
    )))
    .fetch_all(&f.owner)
    .await
    .unwrap();
    listed.sort();
    let mut expected = vec![
        (unknown.clone(), "caller_disconnected".to_owned()),
        (complete.clone(), "incomplete".to_owned()),
        (running.clone(), "caller_disconnected".to_owned()),
    ];
    expected.sort();
    assert_eq!(listed, expected);
}

/// One final report of `id` at revision 1 and its settlement, written directly in SQL as the
/// gateway role in one transaction. `columns` and `values` continue the report's column and
/// value lists, and `fold` says whether the quota fold is called. Returns the first error, the
/// commit's included.
async fn settle_in_sql(
    f: &Fixture,
    id: &str,
    (columns, values): (&str, &str),
    fold: bool,
    outstanding: i64,
) -> Result<(), sqlx::Error> {
    use sqlx::Connection;
    let mut c = connect(&f.db.0, pg::GATEWAY).await;
    let mut tx = c.begin().await?;
    let report = format!(
        "INSERT INTO openmettle.gateway_usage_reports
             (request_id,source,report_id,revision,final{columns})
         VALUES ($1::uuid,$2::uuid,$1::uuid,1,true{values})"
    );
    sqlx::query(sqlx::AssertSqlSafe(report))
        .bind(id)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding)
         VALUES ($1::uuid,1,true,NULL,$2)",
    )
    .bind(id)
    .bind(outstanding)
    .execute(&mut *tx)
    .await?;
    if fold {
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$1::uuid,1)")
            .bind(id)
            .bind(INSTALL)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

/// The rules of the settlement library hold in the database too, for a writer that has the
/// gateway role's grants and does not go through the library. A final settlement of a request
/// without a binding must leave zero outstanding and its token hold closed, or the transaction
/// is refused: no count and no reason; one count that covers the whole reservation; a reason
/// whose quota fold was never run; a reason that leaves a positive outstanding balance. A report
/// with a reason carries no count, cost or unit, and needs a request this proxy dispatched. A
/// report with a reason, folded with zero outstanding, is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_database_refuses_a_final_settlement_that_leaves_the_hold_open() {
    let f = Fixture::new().await;
    let held = ("handoff_committed".to_owned(), UNITS, "0".to_owned());
    let whole = format!(",{UNITS}");
    let reason = (",incomplete", ",'no_usage'");
    for (what, fields, fold, dispatched, outstanding) in [
        ("no count and no reason", ("", ""), true, true, 0),
        (
            "one count that covers the reservation",
            (",prompt_tokens", whole.as_str()),
            true,
            true,
            0,
        ),
        ("a reason without the quota fold", reason, false, true, 0),
        (
            "a reason with a positive outstanding balance",
            reason,
            true,
            true,
            UNITS,
        ),
        (
            "a reason for a request never dispatched",
            reason,
            true,
            false,
            0,
        ),
    ] {
        let id = f.request(false).await;
        if dispatched {
            f.dispatch(&id).await;
        }
        let Err(sqlx::Error::Database(error)) =
            settle_in_sql(&f, &id, fields, fold, outstanding).await
        else {
            panic!("{what}: the transaction committed");
        };
        assert_eq!(error.code().as_deref(), Some("23514"), "{what}");
        assert_eq!(f.reports(&id).await, [], "{what}");
        assert_eq!(f.settlement(&id).await, None, "{what}");
        assert_eq!(f.hold(&id).await, held, "{what}");
        assert!(f.outstanding(&id).await, "{what}");
    }

    let id = f.request(false).await;
    f.dispatch(&id).await;
    for fields in [
        (
            ",incomplete,prompt_tokens,completion_tokens",
            ",'no_usage',7,5",
        ),
        (
            ",incomplete,reasoning_tokens,reasoning_included",
            ",'no_usage',1,true",
        ),
        (",incomplete,reasoning_included", ",'no_usage',true"),
        (",incomplete,cost,unit", ",'no_usage',1,'unit'"),
    ] {
        let Err(sqlx::Error::Database(error)) = settle_in_sql(&f, &id, fields, true, 0).await
        else {
            panic!("{fields:?}: the transaction committed");
        };
        assert_eq!(
            (error.code().as_deref(), error.constraint()),
            (
                Some("23514"),
                Some("gateway_usage_reports_incomplete_check")
            ),
            "{fields:?}"
        );
    }
    assert_eq!(f.hold(&id).await, held);
    settle_in_sql(&f, &id, reason, true, 0).await.unwrap();
    f.assert_closed(&id, "no_usage").await;

    // An undispatched request cannot accept a reason even when a later revision in the same
    // transaction replaces it with usage before commit.
    let undispatched = f.request(false).await;
    {
        use sqlx::Connection;
        let mut c = connect(&f.db.0, pg::GATEWAY).await;
        let mut tx = c.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,incomplete)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true,'no_usage')",
        )
        .bind(&undispatched)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,true,NULL,0)",
        )
        .bind(&undispatched)
        .execute(&mut *tx)
        .await
        .unwrap();
        let rev2_report: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),2,true,7,5)
             RETURNING report_id::text",
        )
        .bind(&undispatched)
        .bind(INSTALL)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision=2,final=true,measured=12,outstanding=0
              WHERE request_id=$1::uuid",
        )
        .bind(&undispatched)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$3::uuid,2)")
            .bind(&undispatched)
            .bind(INSTALL)
            .bind(&rev2_report)
            .execute(&mut *tx)
            .await
            .unwrap();
        let Err(sqlx::Error::Database(error)) = tx.commit().await else {
            panic!("an undispatched request accepted a reason hidden behind a later revision");
        };
        assert_eq!(error.code().as_deref(), Some("23514"));
        assert!(
            error
                .message()
                .contains("an incomplete report needs a dispatched request without a binding"),
            "{}",
            error.message()
        );
        assert_eq!(f.reports(&undispatched).await, []);
        assert_eq!(f.settlement(&undispatched).await, None);
        assert_eq!(f.hold(&undispatched).await, held);
    }

    // With a cost hold present: a report with usage leaves the cost hold open (issue #166) and
    // commits, while a report with a reason must close the cost hold too — skipping the quota
    // fold on the reason is refused at commit.
    let mut admin = f.db.admin().await;
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
             VALUES ('personal','usage_cost_micros',100000)",
        )
        .await
        .unwrap();
    let costed = f.request_with_cost(MODEL, false, Some(250)).await;
    f.dispatch(&costed).await;
    let gateway = pool(&f.db, pg::GATEWAY);
    assert_eq!(
        settlement::ingest(&gateway, &f.report(&costed, 1, Some((7, 5)))).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        f.hold(&costed).await,
        ("settled".to_owned(), 0, "12".to_owned())
    );
    assert_eq!(
        f.hold_of(&costed, "usage_cost_micros").await,
        ("handoff_committed".to_owned(), 250, "0".to_owned())
    );
    {
        use sqlx::Connection;
        let mut c = connect(&f.db.0, pg::GATEWAY).await;
        let mut tx = c.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,incomplete)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),2,true,'incomplete')",
        )
        .bind(&costed)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision=2,final=true,measured=NULL,outstanding=0
              WHERE request_id=$1::uuid",
        )
        .bind(&costed)
        .execute(&mut *tx)
        .await
        .unwrap();
        let Err(sqlx::Error::Database(error)) = tx.commit().await else {
            panic!("a reason left the cost hold open without running the quota fold");
        };
        assert_eq!(error.code().as_deref(), Some("23514"));
        assert_eq!(
            f.hold_of(&costed, "usage_cost_micros").await,
            ("handoff_committed".to_owned(), 250, "0".to_owned())
        );
    }
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &f.report(&costed, 2, None), "incomplete").await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        f.hold_of(&costed, "usage_cost_micros").await,
        ("settled".to_owned(), 0, "0".to_owned())
    );

    assert_eq!((f.used().await, f.reserved().await), (12, 6 * UNITS));
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

/// ADR 0044, increment 3b (migration 32): the worker sweep settles both token and cost holds
/// at revision 0 for undispatched (`not_dispatched`) and past-grace dispatched (`unreported`)
/// requests. A late proxy report at revision 1 (with usage or with a proxy reason) cleanly
/// supersedes a revision-0 `unreported` sweep without collisions or drift, and once revision 1
/// is stored the sweep never touches the request again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_worker_sweep_settles_metered_holds_and_late_proxy_reports_correct_unreported() {
    let f = Fixture::new().await;
    let mut admin = f.db.admin().await;
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
             VALUES ('personal','usage_cost_micros',100000)",
        )
        .await
        .unwrap();
    let gateway = pool(&f.db, pg::GATEWAY);
    let mut pass = budgets::Pass::default();

    // 1. Undispatched request with both token and cost holds: untouched while live, then
    //    closed at revision 0 with `not_dispatched` once the run fails.
    let undisp = f.request_with_cost(MODEL, false, Some(250)).await;
    let undisp_run = f.run_of(&undisp).await;
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        f.hold(&undisp).await,
        ("handoff_committed".to_owned(), UNITS, "0".to_owned())
    );
    assert_eq!(
        f.hold_of(&undisp, "usage_cost_micros").await,
        ("handoff_committed".to_owned(), 250, "0".to_owned())
    );
    sqlx::query("UPDATE openmettle.runs SET state='failed' WHERE id=$1::uuid")
        .bind(&undisp_run)
        .execute(&f.owner)
        .await
        .unwrap();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        f.reasons(&undisp).await,
        [(
            undisp.clone(),
            0,
            true,
            Some("not_dispatched".to_owned()),
            0
        )]
    );
    assert_eq!(f.settlement(&undisp).await, Some((0, true, None, 0)));
    assert_eq!(
        f.hold(&undisp).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!(
        f.hold_of(&undisp, "usage_cost_micros").await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert!(!f.outstanding(&undisp).await);
    // Original bearer cannot dispatch it afterwards.
    let rejected: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.gateway_dispatch($1::uuid,sha256($2))")
            .bind(&undisp)
            .bind(bearer_bytes(&undisp).as_slice())
            .fetch_one(&gateway)
            .await
            .unwrap();
    assert_eq!(rejected, 0);

    // 2. Dispatched request swept as `unreported` at revision 0, then superseded by a late
    //    complete proxy report at revision 1 with the SAME report_id = request_id: charges
    //    actual tokens, updates gateway_settlements to revision 1, keeps cost hold settled at 0.
    let late_usage = f.request_with_cost(MODEL, false, Some(250)).await;
    f.dispatch(&late_usage).await;
    let late_usage_run = f.run_of(&late_usage).await;
    sqlx::query("UPDATE openmettle.runs SET state='failed' WHERE id=$1::uuid")
        .bind(&late_usage_run)
        .execute(&f.owner)
        .await
        .unwrap();
    // Not swept before execution_expires_at + 15 minutes.
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        0
    );
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                execution_expires_at=clock_timestamp()-interval '16 minutes'
          WHERE id=$1::uuid",
    )
    .bind(&late_usage_run)
    .execute(&f.owner)
    .await
    .unwrap();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        f.reasons(&late_usage).await,
        [(
            late_usage.clone(),
            0,
            true,
            Some("unreported".to_owned()),
            0
        )]
    );
    assert_eq!(
        f.hold(&late_usage).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!(
        f.hold_of(&late_usage, "usage_cost_micros").await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // Late proxy report arrives at revision 1 with report_id = request_id and complete counts.
    assert_eq!(
        settlement::ingest(&gateway, &f.report(&late_usage, 1, Some((17, 2)))).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        f.settlement(&late_usage).await,
        Some((1, true, Some("19".to_owned()), 0))
    );
    assert_eq!(
        f.hold(&late_usage).await,
        ("settled".to_owned(), 0, "19".to_owned())
    );
    assert_eq!(
        f.hold_of(&late_usage, "usage_cost_micros").await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!(
        f.transitions(&late_usage).await,
        ["final_settle", "final_correction"]
    );
    assert_eq!((f.used().await, f.reserved().await), (19, 0));
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // 3. Dispatched request swept as `unreported` at revision 0, then superseded by a late
    //    incomplete proxy report at revision 1 (`upstream_timeout`) with report_id = request_id.
    let late_reason = f.request_with_cost(MODEL, false, Some(250)).await;
    f.dispatch(&late_reason).await;
    let late_reason_run = f.run_of(&late_reason).await;
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                execution_expires_at=clock_timestamp()-interval '16 minutes'
          WHERE id=$1::uuid",
    )
    .bind(&late_reason_run)
    .execute(&f.owner)
    .await
    .unwrap();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        settlement::ingest_incomplete(
            &gateway,
            &f.report(&late_reason, 1, None),
            "upstream_timeout"
        )
        .await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        f.reasons(&late_reason).await,
        [
            (
                late_reason.clone(),
                0,
                true,
                Some("unreported".to_owned()),
                0
            ),
            (
                late_reason.clone(),
                1,
                true,
                Some("upstream_timeout".to_owned()),
                0
            ),
        ]
    );
    assert_eq!(f.settlement(&late_reason).await, Some((1, true, None, 0)));
    assert_eq!(
        f.hold(&late_reason).await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    assert_eq!(f.transitions(&late_reason).await, ["final_settle"]);

    // 4. Reverse order: proxy already settled revision 1 (complete and incomplete); even past
    //    the 15-minute grace window the sweep never overwrites or re-touches them.
    let rev1_complete = f.request_with_cost(MODEL, false, Some(250)).await;
    let rev1_incomplete = f.request_with_cost(MODEL, false, Some(250)).await;
    for id in [&rev1_complete, &rev1_incomplete] {
        f.dispatch(id).await;
    }
    assert_eq!(
        settlement::ingest(&gateway, &f.report(&rev1_complete, 1, Some((5, 6)))).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest_incomplete(
            &gateway,
            &f.report(&rev1_incomplete, 1, None),
            "caller_disconnected"
        )
        .await,
        Ok(Outcome::Applied)
    );
    for id in [&rev1_complete, &rev1_incomplete] {
        let run = f.run_of(id).await;
        sqlx::query(
            "UPDATE openmettle.runs
                SET lease_expires_at=clock_timestamp()-interval '20 minutes',
                    execution_expires_at=clock_timestamp()-interval '20 minutes'
              WHERE id=$1::uuid",
        )
        .bind(&run)
        .execute(&f.owner)
        .await
        .unwrap();
    }
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        0
    );
    assert_eq!(f.reasons(&rev1_complete).await.len(), 1);
    assert_eq!(f.reasons(&rev1_incomplete).await.len(), 1);
    assert_eq!((f.used().await, f.reserved().await), (30, 0));
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // Operator query shows each current incomplete settlement with its active reason, omitting
    // the request whose late complete proxy report corrected `unreported`.
    let page = include_str!("../../docs/operator/gateway-proxy.md");
    let (_, query) = page.split_once("```sql\n").unwrap();
    let (query, _) = query.split_once("```").unwrap();
    let query = query.trim().trim_end_matches(';');
    let mut listed: Vec<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT request_id::text,incomplete FROM ({query}) AS listed"
    )))
    .fetch_all(&f.owner)
    .await
    .unwrap();
    listed.sort();
    let mut expected = vec![
        (undisp.clone(), "not_dispatched".to_owned()),
        (late_reason.clone(), "upstream_timeout".to_owned()),
        (rev1_incomplete.clone(), "caller_disconnected".to_owned()),
    ];
    expected.sort();
    assert_eq!(listed, expected);
}

/// Older dispatched requests sitting inside their 15-minute grace window must never starve
/// newer eligible `not_dispatched` or past-grace `unreported` requests behind them when the
/// page limit is smaller than the number of in-grace rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn in_grace_dispatched_requests_do_not_starve_eligible_requests_behind_them() {
    let f = Fixture::new().await;
    let mut in_grace = Vec::new();
    for _ in 0..6 {
        let id = f.request(false).await;
        f.dispatch(&id).await;
        in_grace.push(id);
    }
    let mut eligible_undisp = Vec::new();
    for _ in 0..2 {
        let id = f.request(false).await;
        let run = f.run_of(&id).await;
        sqlx::query("UPDATE openmettle.runs SET state='failed' WHERE id=$1::uuid")
            .bind(&run)
            .execute(&f.owner)
            .await
            .unwrap();
        eligible_undisp.push(id);
    }
    let mut eligible_unrep = Vec::new();
    for _ in 0..2 {
        let id = f.request(false).await;
        f.dispatch(&id).await;
        let run = f.run_of(&id).await;
        sqlx::query(
            "UPDATE openmettle.runs
                SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                    execution_expires_at=clock_timestamp()-interval '16 minutes'
              WHERE id=$1::uuid",
        )
        .bind(&run)
        .execute(&f.owner)
        .await
        .unwrap();
        eligible_unrep.push(id);
    }

    // Limit 3 is smaller than the 6 older in-grace rows: the first two ticks scan 3 raw keys
    // each and return 0 while advancing `pass` past the all-ineligible prefix, then ticks 3 and
    // 4 close the 4 trailing eligible rows and reset `pass` once fewer than 3 raw keys remain.
    let mut pass = budgets::Pass::default();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 3)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 3)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 3)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 3)
            .await
            .unwrap(),
        1
    );
    for id in &eligible_undisp {
        assert_eq!(
            f.reasons(id).await,
            [(id.clone(), 0, true, Some("not_dispatched".to_owned()), 0)]
        );
    }
    for id in &eligible_unrep {
        assert_eq!(
            f.reasons(id).await,
            [(id.clone(), 0, true, Some("unreported".to_owned()), 0)]
        );
    }
    for id in &in_grace {
        assert!(f.outstanding(id).await);
        assert_eq!(f.reasons(id).await, []);
    }

    // Once the 6 in-grace rows age past 15 minutes, bounded pages of 3 drain all of them.
    for id in &in_grace {
        let run = f.run_of(id).await;
        sqlx::query(
            "UPDATE openmettle.runs
                SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                    execution_expires_at=clock_timestamp()-interval '16 minutes'
              WHERE id=$1::uuid",
        )
        .bind(&run)
        .execute(&f.owner)
        .await
        .unwrap();
    }
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 3)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 3)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 3)
            .await
            .unwrap(),
        0
    );
    assert_eq!((f.used().await, f.reserved().await), (0, 0));
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

/// After the worker sweep settles a dispatched request as `unreported` at revision 0, its holds
/// are already `settled`. A direct-SQL `openmettle_gateway` correction at revision 1 MUST still
/// fold those holds through `quota_settle_gateway_usage(..., 1)` so `accepted_source_revision`
/// matches `latest.revision`; skipping the fold is refused at commit with 23514.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_direct_sql_correction_after_unreported_must_fold_its_holds() {
    use sqlx::Connection;

    let f = Fixture::new().await;
    let mut admin = f.db.admin().await;
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
             VALUES ('personal','usage_cost_micros',100000)",
        )
        .await
        .unwrap();

    let id = f.request_with_cost(MODEL, false, Some(250)).await;
    f.dispatch(&id).await;
    let run = f.run_of(&id).await;
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                execution_expires_at=clock_timestamp()-interval '16 minutes'
          WHERE id=$1::uuid",
    )
    .bind(&run)
    .execute(&f.owner)
    .await
    .unwrap();
    let mut pass = budgets::Pass::default();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(f.hold(&id).await, ("settled".to_owned(), 0, "0".to_owned()));
    assert_eq!(
        f.hold_of(&id, "usage_cost_micros").await,
        ("settled".to_owned(), 0, "0".to_owned())
    );

    // Direct SQL as openmettle_gateway: write measured revision 1 + settlement WITHOUT folding.
    let mut direct = connect(&f.db.0, pg::GATEWAY).await;
    {
        let mut tx = direct.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,true,17,2)",
        )
        .bind(&id)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision=1,final=true,measured=19,outstanding=0
              WHERE request_id=$1::uuid",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await
        .unwrap();
        let Err(sqlx::Error::Database(error)) = tx.commit().await else {
            panic!("revision-1 correction committed without folding already-settled holds");
        };
        assert_eq!(error.code().as_deref(), Some("23514"));
    }
    assert_eq!(f.settlement(&id).await, Some((0, true, None, 0)));
    assert_eq!(f.used().await, 0);
    assert_eq!(f.drift().await, (0, 0, 0, 0));

    // Running `quota_settle_gateway_usage(..., 1)` in the same transaction folds both holds to
    // revision 1 and commits cleanly with zero drift.
    {
        let mut tx = direct.begin().await.unwrap();
        let report_id: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,true,17,2)
             RETURNING report_id::text",
        )
        .bind(&id)
        .bind(INSTALL)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision=1,final=true,measured=19,outstanding=0
              WHERE request_id=$1::uuid",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$3::uuid,1)")
            .bind(&id)
            .bind(INSTALL)
            .bind(&report_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(
        f.settlement(&id).await,
        Some((1, true, Some("19".to_owned()), 0))
    );
    assert_eq!(
        f.hold(&id).await,
        ("settled".to_owned(), 0, "19".to_owned())
    );
    assert_eq!(
        f.hold_of(&id, "usage_cost_micros").await,
        ("settled".to_owned(), 0, "0".to_owned())
    );
    let revs: Vec<(String, Option<i64>)> = sqlx::query_as(
        "SELECT resource_kind, accepted_source_revision
           FROM openmettle.quota_reservations
          WHERE gateway_request_id=$1::uuid
          ORDER BY resource_kind",
    )
    .bind(&id)
    .fetch_all(&f.owner)
    .await
    .unwrap();
    assert_eq!(
        revs,
        [
            ("usage_cost_micros".to_owned(), Some(1)),
            ("usage_tokens".to_owned(), Some(1)),
        ]
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}

/// After revision 0 (`unreported`) closes the fold, a bare or single-count final report at
/// revision 1 without an `incomplete` reason must be refused by both `settlement::ingest` and
/// PostgreSQL's deferred trigger, leaving `unreported` visible in the operator query.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_bare_or_partial_final_report_cannot_replace_unreported() {
    use sqlx::Connection;

    let f = Fixture::new().await;
    let gateway = pool(&f.db, pg::GATEWAY);
    let id = f.request(false).await;
    f.dispatch(&id).await;
    let run = f.run_of(&id).await;
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                execution_expires_at=clock_timestamp()-interval '16 minutes'
          WHERE id=$1::uuid",
    )
    .bind(&run)
    .execute(&f.owner)
    .await
    .unwrap();
    let mut pass = budgets::Pass::default();
    assert_eq!(
        budgets::sweep_unreported_gateway_requests(&f.worker, &mut pass, 100)
            .await
            .unwrap(),
        1
    );

    // Through `settlement::ingest`: bare, prompt-only, and completion-only final reports are
    // refused and leave no row at revision 1.
    for (prompt, completion) in [(None, None), (Some(10), None), (None, Some(5))] {
        let mut r = f.report(&id, 1, None);
        r.prompt_tokens = prompt;
        r.completion_tokens = completion;
        assert_eq!(
            settlement::ingest(&gateway, &r).await,
            Err(StoreError::Refused),
            "ingest accepted ({prompt:?}, {completion:?}) after unreported"
        );
    }
    assert_eq!(
        f.reasons(&id).await,
        [(id.clone(), 0, true, Some("unreported".to_owned()), 0)]
    );

    // Through direct SQL as `openmettle_gateway` even with `quota_settle_gateway_usage(..., 1)`:
    // bare and single-count final reports are refused at commit with 23514.
    let mut direct = connect(&f.db.0, pg::GATEWAY).await;
    for (what, cols, vals, measured) in [
        ("bare", "", "", None::<i64>),
        ("prompt_only", ",prompt_tokens", ",10", Some(10)),
        ("completion_only", ",completion_tokens", ",5", Some(5)),
    ] {
        let mut tx = direct.begin().await.unwrap();
        let report_id: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final{cols})
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,true{vals})
             RETURNING report_id::text"
        )))
        .bind(&id)
        .bind(INSTALL)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision=1,final=true,measured=$2,outstanding=0
              WHERE request_id=$1::uuid",
        )
        .bind(&id)
        .bind(measured)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$3::uuid,1)")
            .bind(&id)
            .bind(INSTALL)
            .bind(&report_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        let Err(sqlx::Error::Database(error)) = tx.commit().await else {
            panic!("direct SQL accepted {what} final report after unreported");
        };
        assert_eq!(error.code().as_deref(), Some("23514"), "{what}");
    }

    // Operator query still shows `unreported`, and a real complete revision-1 report succeeds.
    let page = include_str!("../../docs/operator/gateway-proxy.md");
    let (_, query) = page.split_once("```sql\n").unwrap();
    let (query, _) = query.split_once("```").unwrap();
    let query = query.trim().trim_end_matches(';');
    let listed: Vec<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT request_id::text,incomplete FROM ({query}) AS listed"
    )))
    .fetch_all(&f.owner)
    .await
    .unwrap();
    assert_eq!(listed, [(id.clone(), "unreported".to_owned())]);

    assert_eq!(
        settlement::ingest(&gateway, &f.report(&id, 1, Some((17, 2)))).await,
        Ok(Outcome::Applied)
    );
    let after: Vec<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT request_id::text,incomplete FROM ({query}) AS listed"
    )))
    .fetch_all(&f.owner)
    .await
    .unwrap();
    assert_eq!(after, []);
    assert_eq!(
        f.hold(&id).await,
        ("settled".to_owned(), 0, "19".to_owned())
    );
    assert_eq!(f.drift().await, (0, 0, 0, 0));
}
