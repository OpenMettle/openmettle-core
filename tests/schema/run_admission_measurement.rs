//! ADR 0032 (V1-10 PR3) measurement harness: admission contention on one hot project row
//! against separate scopes, concurrent `claim_next` serialization on `run_dispatch_lock`,
//! `pg_stat_activity` lock-wait sampling, and `EXPLAIN (ANALYZE, BUFFERS)` of the shipped
//! admission count and claim over a history-dominated `runs` table.
//!
//! One routine, two profiles. The bounded CI profile always runs in the hosted PostgreSQL 18
//! job and asserts that the report is complete, the invariants hold and the plans use the
//! partial indexes. The workstation profile runs only with `OPENMETTLE_QUEUE_BENCH=1`, because
//! CI runs every ignored `--test schema` case; its numbers are evidence only when the owner runs
//! it in the agreed window and records the report on #10. Every value is synthetic.
use super::*;
use openmettle_core::authz::Principal;
use serde_json::Value;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize},
};

/// Executing states: the ones that hold a worker (ADR 0032).
const EXECUTING: &str = "state IN ('running', 'cancelling', 'reconciling')";
/// The live predicate of the partial indexes, so the sampler's own reads stay off run history.
const LIVE: &str = "state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')";
/// The partial indexes over live rows; plans may also use `runs_pkey` for the claim's `UPDATE`.
const LIVE_INDEXES: [&str; 3] = [
    "runs_live_actor_idx",
    "runs_live_scope_idx",
    "runs_dispatch_idx",
];

struct Profile {
    name: &'static str,
    actors: usize,
    runs_per_actor: usize,
    claimers: usize,
    /// Terminal runs seeded before the load, spread over the actors.
    history: usize,
    /// Queued runs each actor leaves for the plan measurement.
    live_tail: usize,
    /// Every `cancel_every`-th admission is cancelled by its actor straight away.
    cancel_every: usize,
    /// How long a claimed run "executes" before the claimer finishes it.
    hold: Duration,
    /// Sleep after an empty claim, and between lock-wait samples.
    poll: Duration,
    claim: ClaimLimits,
    deadline: Duration,
}

impl Profile {
    fn ci() -> Self {
        Self {
            name: "ci",
            actors: 6,
            runs_per_actor: 12,
            claimers: 4,
            history: 900,
            live_tail: 6,
            cancel_every: 4,
            hold: Duration::from_millis(1),
            poll: Duration::from_millis(2),
            claim: ClaimLimits {
                executing_per_actor: 1,
                executing_per_scope: 2,
            },
            deadline: Duration::from_secs(60),
        }
    }

    /// Starting sizes for the owner's run; each can be overridden from the environment.
    fn workstation() -> Self {
        let size = |name: &str, default: usize| match std::env::var(name) {
            Err(_) => default,
            Ok(value) => match value.parse::<usize>() {
                Ok(n) if n > 0 => n,
                _ => panic!("{name} must be a positive integer"),
            },
        };
        let profile = Self {
            name: "workstation",
            actors: size("OPENMETTLE_QUEUE_BENCH_ACTORS", 48),
            runs_per_actor: size("OPENMETTLE_QUEUE_BENCH_RUNS_PER_ACTOR", 40),
            claimers: size("OPENMETTLE_QUEUE_BENCH_CLAIMERS", 16),
            history: size("OPENMETTLE_QUEUE_BENCH_HISTORY", 200_000),
            live_tail: 4,
            cancel_every: 4,
            hold: Duration::from_millis(5),
            poll: Duration::from_millis(5),
            claim: ClaimLimits {
                executing_per_actor: 2,
                executing_per_scope: 8,
            },
            deadline: Duration::from_secs(1800),
        };
        assert!(profile.actors >= 2, "a hot project and a separate scope");
        profile
    }

    /// Actors `0..hot` share one project; the rest each admit in their personal scope.
    fn hot(&self) -> usize {
        (self.actors / 2).max(1)
    }
}

/// One actor's admission template and authority.
struct Actor {
    template: Request,
    principal: Principal,
    hot: bool,
}

/// The SQL text of a `concat!` constant in `src/authz/runs.rs`, rebuilt from the source so the
/// harness explains exactly the statement the store ships.
fn shipped_sql(name: &str) -> String {
    const SOURCE: &str = include_str!("../../src/authz/runs.rs");
    let literal = |text: &str| -> (String, usize) {
        let body = &text[text.find('"').unwrap() + 1..];
        let end = body.find('"').unwrap();
        assert!(!body[..end].contains('\\'), "escape in {name}");
        (body[..end].to_owned(), text.len() - body.len() + end + 1)
    };
    let macro_at = SOURCE.find("macro_rules! non_terminal").unwrap();
    let (non_terminal, _) = literal(&SOURCE[macro_at..]);
    let start = SOURCE
        .find(&format!("const {name}: &str = concat!("))
        .unwrap_or_else(|| panic!("{name} not found"));
    let body = &SOURCE[start..];
    let mut rest = &body[body.find('(').unwrap() + 1..body.find("\n);").unwrap()];
    let mut sql = String::new();
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        if rest.is_empty() {
            return sql;
        }
        if let Some(after) = rest.strip_prefix("non_terminal!()") {
            sql.push_str(&non_terminal);
            rest = after;
        } else {
            assert!(rest.starts_with('"'), "unexpected token in {name}");
            let (text, used) = literal(rest);
            sql.push_str(&text);
            rest = &rest[used..];
        }
    }
}

/// count, p50, p95, p99, max and mean in microseconds (nearest rank).
fn latency(mut samples: Vec<Duration>) -> Value {
    samples.sort();
    let n = samples.len();
    if n == 0 {
        return json!({ "count": 0 });
    }
    let us = |d: &Duration| u64::try_from(d.as_micros()).unwrap();
    let at = |p: f64| us(&samples[((p * n as f64).ceil() as usize).clamp(1, n) - 1]);
    let total: u64 = samples.iter().map(us).sum();
    json!({
        "count": n,
        "p50_us": at(0.50),
        "p95_us": at(0.95),
        "p99_us": at(0.99),
        "max_us": us(&samples[n - 1]),
        "mean_us": total / n as u64,
    })
}

fn per_second(count: usize, elapsed: Duration) -> f64 {
    count as f64 / elapsed.as_secs_f64().max(1e-9)
}

/// Waiting backends of this database by the lock they wait for, classified by the statement
/// the store issued: [project row, user row, `run_dispatch_lock`, anything else].
async fn lock_waiters(admin: &mut PgConnection, database: &str) -> [usize; 4] {
    let queries: Vec<String> = sqlx::query_scalar(
        "SELECT query FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
    )
    .bind(database)
    .fetch_all(admin)
    .await
    .unwrap();
    let mut counts = [0; 4];
    for query in queries {
        let class = if query.contains("FROM openmettle.projects") {
            0
        } else if query.contains("FROM openmettle.users") {
            1
        } else if query.contains("openmettle.run_dispatch_lock") {
            2
        } else {
            3
        };
        counts[class] += 1;
    }
    counts
}

/// The largest executing count of any actor and of any scope, from one snapshot.
async fn executing_peaks(admin: &mut PgConnection) -> (i64, i64) {
    let peak = |column: &str| {
        format!(
            "coalesce((SELECT max(n) FROM (SELECT count(*) AS n FROM openmettle.runs
                WHERE {LIVE} AND {EXECUTING} GROUP BY {column}) p), 0)"
        )
    };
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {}, {}",
        peak("actor_user_id"),
        peak("scope_id")
    )))
    .fetch_one(admin)
    .await
    .unwrap()
}

/// The summary of one `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` document.
fn plan_summary(text: &str) -> Value {
    fn walk(node: &Value, indexes: &mut BTreeSet<String>, seq: &mut BTreeSet<String>) {
        if let Some(index) = node["Index Name"].as_str() {
            indexes.insert(index.to_owned());
        }
        if node["Node Type"] == "Seq Scan" {
            seq.insert(node["Relation Name"].as_str().unwrap_or("?").to_owned());
        }
        for child in node["Plans"].as_array().into_iter().flatten() {
            walk(child, indexes, seq);
        }
    }
    let document: Value = serde_json::from_str(text).unwrap();
    let top = &document[0];
    let plan = &top["Plan"];
    let (mut indexes, mut seq) = (BTreeSet::new(), BTreeSet::new());
    walk(plan, &mut indexes, &mut seq);
    json!({
        "execution_time_ms": top["Execution Time"],
        "planning_time_ms": top["Planning Time"],
        "shared_hit_blocks": plan["Shared Hit Blocks"],
        "shared_read_blocks": plan["Shared Read Blocks"],
        "index_names": indexes,
        "seq_scans": seq,
        "plan": plan,
    })
}

async fn explain(c: &mut PgConnection, sql: &str, binds: Vec<Bind>) -> Value {
    let explain = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}");
    let mut query = sqlx::query(AssertSqlSafe(explain));
    for bind in binds {
        query = match bind {
            Bind::Text(text) => query.bind(text),
            Bind::Int(n) => query.bind(n),
        };
    }
    let row = query.fetch_one(c).await.unwrap();
    // `json` is UTF-8 text on the wire; the driver has no JSON feature enabled.
    plan_summary(&row.try_get_unchecked::<String, _>(0).unwrap())
}

enum Bind {
    Text(String),
    Int(i64),
}

/// Terminal runs on the actor's template conversation, 512-byte snapshots, older than the load.
async fn seed_history(owner: &mut PgConnection, template: &Request, rows: usize) {
    sqlx::query(
        "INSERT INTO openmettle.runs (scope_id, actor_user_id, conversation_id, branch_id,
             input_message_id, idempotency_key, snapshot_format, snapshot_version, input_snapshot,
             config_snapshot, request_identity, request_digest, state, created_at)
         SELECT $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'history-' || g,
                'openmettle.synthetic-run', 1, convert_to(repeat('h', 512), 'UTF8'),
                convert_to('{}', 'UTF8'), convert_to('history-' || g, 'UTF8'),
                sha256(convert_to('history-' || g, 'UTF8')),
                (ARRAY['succeeded', 'failed', 'cancelled', 'interrupted'])[1 + g % 4],
                now() - make_interval(secs => g)
           FROM generate_series(1, $6::integer) g",
    )
    .bind(&template.scope)
    .bind(&template.actor.user)
    .bind(&template.conversation)
    .bind(&template.branch)
    .bind(&template.message)
    .bind(i32::try_from(rows).unwrap())
    .execute(owner)
    .await
    .unwrap();
}

/// Prove the sampler's classification on the shipped statements: hold the hot project row, a
/// separate actor's user row and the dispatch lock, start one blocked admission on each row and
/// one blocked claim, and sample them. The claim is released first and finds nothing to claim,
/// because both admissions are still blocked; the two admissions are then committed.
/// Returns the number of runs it admitted.
async fn calibrate(db: &TestDb, actors: &[Actor], hot_project: &str, limits: ClaimLimits) -> usize {
    let (hot, separate) = (&actors[0], actors.iter().find(|a| !a.hot).unwrap());
    let mut owner = connect(&db.0, OWNER).await;
    let mut held = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.projects WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(hot_project)
        .execute(&mut *held)
        .await
        .unwrap();
    sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&separate.template.actor.user)
        .execute(&mut *held)
        .await
        .unwrap();
    let mut dispatcher = worker(db).await;
    let mut dispatch = dispatcher.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE")
        .execute(&mut *dispatch)
        .await
        .unwrap();
    let admissions: Vec<_> = [hot, separate]
        .into_iter()
        .map(|actor| {
            let r = actor.template.keyed("calibrate");
            let options = role_options(&db.0, API);
            tokio::spawn(async move {
                let mut c = PgConnection::connect_with(&options).await.unwrap();
                admit_on(&mut c, &r, &LIMITS, None).await
            })
        })
        .collect();
    let options = role_options(&db.0, WORKER);
    let claim = tokio::spawn(async move {
        let mut c = PgConnection::connect_with(&options).await.unwrap();
        queue::claim_next(&mut c, &limits).await.unwrap()
    });
    wait_for_lock_waiters(db, 3).await;
    assert_eq!(
        lock_waiters(&mut db.admin().await, &db.0).await,
        [1, 1, 1, 0]
    );
    dispatch.rollback().await.unwrap();
    assert_eq!(claim.await.unwrap(), None);
    held.rollback().await.unwrap();
    let mut admitted = 0;
    for admission in admissions {
        let outcome = admission.await.unwrap();
        assert!(
            matches!(outcome, Ok(Admission::Admitted { .. })),
            "{outcome:?}"
        );
        admitted += 1;
    }
    admitted
}

#[derive(Default)]
struct Waits {
    samples: usize,
    with_waiters: usize,
    /// Waiting backends summed over samples, by class.
    observed: [usize; 4],
    /// Samples in which the class had at least one waiter.
    sampled: [usize; 4],
    max_waiters: usize,
    peak_actor: i64,
    peak_scope: i64,
    over_actor: usize,
    over_scope: usize,
}

/// Drive the profile against a migrated disposable database and return the JSON report.
async fn measure_queue_contention_and_plans(db: &TestDb, profile: &Profile) -> Value {
    let started = Instant::now();
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let server: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&mut owner)
        .await
        .unwrap();

    // Setup: one hot project shared by actors 0..hot; the others admit in personal scopes.
    let mut accounts = Vec::new();
    for _ in 0..profile.actors {
        accounts.push(account(&mut owner, PROVIDER, true, FUTURE).await);
    }
    let (hot_project, hot_scope) = new_project(db, &accounts[0], "bench").await;
    let mut actors = Vec::new();
    for (i, acct) in accounts.iter().enumerate() {
        let hot = i < profile.hot();
        if hot && i > 0 {
            editor(db, &accounts[0], &hot_project, acct).await;
        }
        let (scope, kind) = if hot {
            (hot_scope.clone(), "project")
        } else {
            (personal_of(db, acct).await, "personal")
        };
        actors.push(Actor {
            template: request(db, &scope, kind, acct, "template").await,
            principal: principal(db, acct).await,
            hot,
        });
    }
    let per_actor = profile.history.div_ceil(profile.actors);
    for actor in &actors {
        seed_history(&mut owner, &actor.template, per_actor).await;
    }
    let mut admitted = calibrate(db, &actors, &hot_project, profile.claim).await;
    let setup = started.elapsed();

    // Load: every actor admits its runs on its own API connection while the claimers drain
    // the queue and one superuser connection samples lock waits and the executing peaks.
    // Admitters, claimers, the sampler and this task start together.
    let parties = profile.actors + profile.claimers + 2;
    let barrier = Arc::new(tokio::sync::Barrier::new(parties));
    let admitting = Arc::new(AtomicUsize::new(profile.actors));
    let stop = Arc::new(AtomicBool::new(false));
    let mut admission_tasks = Vec::new();
    for actor in &actors {
        let (barrier, admitting) = (barrier.clone(), admitting.clone());
        let (template, principal, hot) =
            (actor.template.clone(), actor.principal.clone(), actor.hot);
        let options = role_options(&db.0, API);
        let (runs, cancel_every) = (profile.runs_per_actor, profile.cancel_every);
        admission_tasks.push(tokio::spawn(async move {
            let mut c = PgConnection::connect_with(&options).await.unwrap();
            let (mut times, mut outcomes) = (Vec::new(), [0usize; 4]);
            barrier.wait().await;
            for i in 0..runs {
                let r = template.keyed(&format!("bench-{i}"));
                let begun = Instant::now();
                let outcome = admit_on(&mut c, &r, &LIMITS, None).await;
                times.push(begun.elapsed());
                // [admitted, refused, cancelled, cancel found it executing or finished]
                match outcome {
                    Ok(Admission::Admitted { run_id, .. }) => {
                        outcomes[0] += 1;
                        if i % cancel_every == cancel_every - 1 {
                            let cancel =
                                queue::cancel_run(&mut c, &principal, &r.scope, &run_id).await;
                            match cancel.unwrap() {
                                CancelOutcome::Cancelled => outcomes[2] += 1,
                                _ => outcomes[3] += 1,
                            }
                        }
                    }
                    Ok(Admission::Refused(_)) => outcomes[1] += 1,
                    other => panic!("unexpected admission outcome {other:?}"),
                }
            }
            admitting.fetch_sub(1, Ordering::SeqCst);
            (hot, times, outcomes, Instant::now())
        }));
    }
    let claimed_ids = Arc::new(Mutex::new(Vec::new()));
    let mut claim_tasks = Vec::new();
    for _ in 0..profile.claimers {
        let (barrier, admitting, claimed_ids) =
            (barrier.clone(), admitting.clone(), claimed_ids.clone());
        let options = role_options(&db.0, WORKER);
        let (limits, hold, poll) = (profile.claim, profile.hold, profile.poll);
        claim_tasks.push(tokio::spawn(async move {
            let mut c = PgConnection::connect_with(&options).await.unwrap();
            let (mut times, mut empty, mut lost) = (Vec::new(), 0usize, 0usize);
            barrier.wait().await;
            loop {
                let begun = Instant::now();
                let claimed = queue::claim_next(&mut c, &limits).await.unwrap();
                let took = begun.elapsed();
                let Some(run) = claimed else {
                    empty += 1;
                    // Read before the queue: a finished admitter has committed every run.
                    let done = admitting.load(Ordering::SeqCst) == 0;
                    let queued: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT FROM openmettle.runs
                          WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
                            AND state = 'queued')",
                    )
                    .fetch_one(&mut c)
                    .await
                    .unwrap();
                    if done && !queued {
                        break;
                    }
                    tokio::time::sleep(poll).await;
                    continue;
                };
                times.push(took);
                claimed_ids.lock().unwrap().push(run.run_id.clone());
                tokio::time::sleep(hold).await;
                // Stands in for the V1-11 executor, which owns the real terminal transition.
                let finished = sqlx::query(
                    "UPDATE openmettle.runs SET state = 'succeeded'
                      WHERE id = $1::uuid AND claim_token = $2::uuid AND state = 'running'",
                )
                .bind(&run.run_id)
                .bind(&run.claim_token)
                .execute(&mut c)
                .await
                .unwrap();
                if finished.rows_affected() != 1 {
                    lost += 1;
                }
            }
            (times, empty, lost, Instant::now())
        }));
    }
    let sampler = {
        let (barrier, stop) = (barrier.clone(), stop.clone());
        let (database, poll, limits) = (db.0.clone(), profile.poll, profile.claim);
        let mut admin = db.admin().await;
        tokio::spawn(async move {
            let mut waits = Waits::default();
            barrier.wait().await;
            while !stop.load(Ordering::SeqCst) {
                let counts = lock_waiters(&mut admin, &database).await;
                let total: usize = counts.iter().sum();
                waits.samples += 1;
                waits.with_waiters += usize::from(total > 0);
                waits.max_waiters = waits.max_waiters.max(total);
                for (class, n) in counts.into_iter().enumerate() {
                    waits.observed[class] += n;
                    waits.sampled[class] += usize::from(n > 0);
                }
                let (actor, scope) = executing_peaks(&mut admin).await;
                waits.peak_actor = waits.peak_actor.max(actor);
                waits.peak_scope = waits.peak_scope.max(scope);
                waits.over_actor += usize::from(actor > i64::from(limits.executing_per_actor));
                waits.over_scope += usize::from(scope > i64::from(limits.executing_per_scope));
                tokio::time::sleep(poll).await;
            }
            waits
        })
    };

    let load = async {
        barrier.wait().await;
        let load_started = Instant::now();
        let mut admissions = Vec::new();
        for task in admission_tasks {
            admissions.push(task.await.unwrap());
        }
        let mut claims = Vec::new();
        for task in claim_tasks {
            claims.push(task.await.unwrap());
        }
        stop.store(true, Ordering::SeqCst);
        (load_started, admissions, claims, sampler.await.unwrap())
    };
    let (load_started, admissions, claims, waits) = tokio::time::timeout(profile.deadline, load)
        .await
        .expect("the load finished within the profile deadline");

    let (mut hot_times, mut separate_times, mut outcomes) = (Vec::new(), Vec::new(), [0usize; 4]);
    let mut admissions_end = load_started;
    for (hot, times, counts, end) in admissions {
        if hot {
            hot_times.extend(times);
        } else {
            separate_times.extend(times);
        }
        for (total, n) in outcomes.iter_mut().zip(counts) {
            *total += n;
        }
        admissions_end = admissions_end.max(end);
    }
    admitted += outcomes[0];
    let (mut claim_times, mut empty, mut lost, mut claims_end) = (Vec::new(), 0, 0, load_started);
    for (times, e, l, end) in claims {
        claim_times.extend(times);
        empty += e;
        lost += l;
        claims_end = claims_end.max(end);
    }
    let claimed: Vec<String> = claimed_ids.lock().unwrap().clone();
    let unique: BTreeSet<&String> = claimed.iter().collect();
    let duplicate_claims = claimed.len() - unique.len();
    let mut admin = db.admin().await;
    let still_live: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT count(*) FROM openmettle.runs WHERE {LIVE}"
    )))
    .fetch_one(&mut admin)
    .await
    .unwrap();
    let unaccounted = admitted.abs_diff(claimed.len() + outcomes[2]);
    let attempts = hot_times.len() + separate_times.len();
    let admission_elapsed = admissions_end - load_started;
    let claim_elapsed = claims_end - load_started;

    // Plans: leave a bounded live set (queued plus some running) on top of the history, refresh
    // the statistics, then explain the shipped statements as the roles that run them.
    for actor in &actors {
        let mut c = api(db).await;
        for i in 0..profile.live_tail {
            let r = actor.template.keyed(&format!("live-{i}"));
            let outcome = admit_on(&mut c, &r, &LIMITS, None).await;
            assert!(
                matches!(outcome, Ok(Admission::Admitted { .. })),
                "{outcome:?}"
            );
        }
    }
    let mut w = worker(db).await;
    for _ in 0..profile.claimers {
        if queue::claim_next(&mut w, &profile.claim)
            .await
            .unwrap()
            .is_none()
        {
            break;
        }
    }
    admin.execute("ANALYZE openmettle.runs").await.unwrap();
    let (rows, terminal, live, pages): (i64, i64, i64, i64) =
        sqlx::query_as(AssertSqlSafe(format!(
            "SELECT count(*), count(*) FILTER (WHERE NOT ({LIVE})), count(*) FILTER (WHERE {LIVE}),
                pg_relation_size('openmettle.runs') / current_setting('block_size')::bigint
           FROM openmettle.runs"
        )))
        .fetch_one(&mut admin)
        .await
        .unwrap();
    let hot_actor = &actors[0].template;
    let live_counts = explain(
        &mut api(db).await,
        &shipped_sql("LIVE_COUNTS"),
        vec![
            Bind::Text(hot_actor.actor.user.clone()),
            Bind::Text(hot_actor.scope.clone()),
            Bind::Int(LIMITS.live_per_actor.into()),
            Bind::Int(LIMITS.live_per_scope.into()),
            Bind::Int(LIMITS.queued_in_instance.into()),
        ],
    )
    .await;
    // The claim's UPDATE is measured inside a rolled-back transaction under the dispatch lock,
    // as `claim_next` takes it, so it changes nothing.
    let mut tx = w.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE")
        .execute(&mut *tx)
        .await
        .unwrap();
    let claim_plan = explain(
        &mut tx,
        &shipped_sql("CLAIM"),
        vec![
            Bind::Int(profile.claim.executing_per_actor.into()),
            Bind::Int(profile.claim.executing_per_scope.into()),
        ],
    )
    .await;
    tx.rollback().await.unwrap();

    json!({
        "profile": profile.name,
        "postgres_server_version": server,
        "parameters": {
            "actors": profile.actors,
            "hot_project_actors": profile.hot(),
            "runs_per_actor": profile.runs_per_actor,
            "claimers": profile.claimers,
            "history_rows": per_actor * profile.actors,
            "live_tail_per_actor": profile.live_tail,
            "cancel_every": profile.cancel_every,
            "hold_ms": profile.hold.as_millis() as u64,
            "poll_ms": profile.poll.as_millis() as u64,
            "executing_per_actor": profile.claim.executing_per_actor,
            "executing_per_scope": profile.claim.executing_per_scope,
            "admission_limits": {
                "live_per_actor": LIMITS.live_per_actor,
                "live_per_scope": LIMITS.live_per_scope,
                "queued_in_instance": LIMITS.queued_in_instance,
            },
        },
        "setup_ms": setup.as_millis() as u64,
        "admission": {
            "hot_project": latency(hot_times),
            "separate_scopes": latency(separate_times),
            "attempts": attempts,
            "admitted": outcomes[0],
            "refused": outcomes[1],
            "cancelled": outcomes[2],
            "cancel_after_claim": outcomes[3],
            "elapsed_ms": admission_elapsed.as_millis() as u64,
            "throughput_per_s": per_second(attempts, admission_elapsed),
        },
        "claim": {
            "latency": latency(claim_times),
            "claimed": claimed.len(),
            "empty_polls": empty,
            "elapsed_ms": claim_elapsed.as_millis() as u64,
            "throughput_per_s": per_second(claimed.len(), claim_elapsed),
        },
        "lock_waits": {
            "samples": waits.samples,
            "samples_with_waiters": waits.with_waiters,
            "max_concurrent_waiters": waits.max_waiters,
            "project": { "waiters": waits.observed[0], "samples": waits.sampled[0] },
            "user": { "waiters": waits.observed[1], "samples": waits.sampled[1] },
            "run_dispatch_lock": { "waiters": waits.observed[2], "samples": waits.sampled[2] },
            "other": { "waiters": waits.observed[3], "samples": waits.sampled[3] },
        },
        "invariants": {
            "peak_executing_per_actor": waits.peak_actor,
            "peak_executing_per_scope": waits.peak_scope,
            "actor_executing_over_limit": waits.over_actor,
            "scope_executing_over_limit": waits.over_scope,
            "duplicate_claims": duplicate_claims,
            "lost_completions": lost,
            "unaccounted_admissions": unaccounted,
            "live_after_drain": still_live,
        },
        "table": {
            "rows": rows,
            "terminal_rows": terminal,
            "live_rows": live,
            "heap_pages": pages,
        },
        "plans": { "live_counts": live_counts, "claim": claim_plan },
        "elapsed_ms": started.elapsed().as_millis() as u64,
    })
}

/// Print the report, and write it to `OPENMETTLE_QUEUE_BENCH_REPORT` when that is set.
fn publish(report: &Value) {
    let text = serde_json::to_string_pretty(report).unwrap();
    eprintln!("{text}");
    if let Ok(path) = std::env::var("OPENMETTLE_QUEUE_BENCH_REPORT") {
        std::fs::write(&path, format!("{text}\n")).unwrap();
        eprintln!("report written to {path}");
    }
}

/// Checks that hold for every profile: a complete report, no invariant violation and plans
/// that read live rows through the partial indexes, never the run history.
fn verify(report: &Value) {
    let admission = &report["admission"];
    for summary in [
        &admission["hot_project"],
        &admission["separate_scopes"],
        &report["claim"]["latency"],
    ] {
        let at = |key: &str| summary[key].as_u64().unwrap_or_else(|| panic!("{key}"));
        assert!(at("count") > 0);
        assert!(at("p50_us") <= at("p95_us") && at("p95_us") <= at("p99_us"));
        assert!(at("p99_us") <= at("max_us"));
    }
    for throughput in [
        &admission["throughput_per_s"],
        &report["claim"]["throughput_per_s"],
    ] {
        assert!(throughput.as_f64().unwrap() > 0.0);
    }
    let invariants = report["invariants"].as_object().unwrap();
    for key in [
        "actor_executing_over_limit",
        "scope_executing_over_limit",
        "duplicate_claims",
        "lost_completions",
        "unaccounted_admissions",
        "live_after_drain",
    ] {
        assert_eq!(invariants[key], 0, "{key}");
    }
    let waits = &report["lock_waits"];
    assert!(waits["samples"].as_u64().unwrap() > 0);
    for class in ["project", "user", "run_dispatch_lock", "other"] {
        assert!(waits[class]["waiters"].is_u64(), "{class}");
    }
    let table = &report["table"];
    let count = |key: &str| table[key].as_i64().unwrap();
    assert!(count("live_rows") > 0 && count("terminal_rows") > 10 * count("live_rows"));
    assert!(count("heap_pages") >= 20, "history spans several pages");
    let plans = &report["plans"];
    for (name, expected) in [
        ("live_counts", &LIVE_INDEXES[..2]),
        ("claim", &LIVE_INDEXES[2..]),
    ] {
        let plan = &plans[name];
        for key in ["execution_time_ms", "planning_time_ms"] {
            assert!(plan[key].is_f64(), "{name} {key}");
        }
        for key in ["shared_hit_blocks", "shared_read_blocks"] {
            assert!(plan[key].is_u64(), "{name} {key}");
        }
        assert_eq!(plan["seq_scans"], json!([]), "{name} scans no table");
        let used: BTreeSet<&str> = plan["index_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_str().unwrap())
            .collect();
        for index in expected {
            assert!(used.contains(index), "{name} uses {index}: {used:?}");
        }
        for index in &used {
            assert!(
                LIVE_INDEXES.contains(index) || *index == "runs_pkey",
                "{name} reads history through {index}"
            );
        }
    }
}

#[test]
fn shipped_statements_are_rebuilt_from_the_store_source() {
    let live_counts = shipped_sql("LIVE_COUNTS");
    assert_eq!(live_counts.matches(LIVE).count(), 3);
    assert!(live_counts.contains(" AND state = 'queued' LIMIT $5) q)"));
    let claim = shipped_sql("CLAIM");
    assert_eq!(claim.matches(LIVE).count(), 2);
    assert!(claim.starts_with("WITH executing AS ("));
    assert!(claim.contains("FOR NO KEY UPDATE OF r SKIP LOCKED"));
    assert!(
        claim
            .trim_end()
            .ends_with("r.actor_approval_id::text, r.round_limit")
    );
}

#[test]
fn latency_summary_uses_nearest_rank_percentiles() {
    let samples = (1..=200).map(Duration::from_micros).collect();
    assert_eq!(
        latency(samples),
        json!({
            "count": 200, "p50_us": 100, "p95_us": 190, "p99_us": 198, "max_us": 200,
            "mean_us": 100,
        })
    );
    assert_eq!(latency(Vec::new()), json!({ "count": 0 }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn bounded_queue_measurement_reports_contention_invariants_and_index_plans() {
    let db = TestDb::migrated().await;
    let profile = Profile::ci();
    let report = measure_queue_contention_and_plans(&db, &profile).await;
    publish(&report);
    verify(&report);
    // At CI scale every admission fits the limits and the drain accounts for each run.
    let admission = &report["admission"];
    let expected = profile.actors * profile.runs_per_actor;
    assert_eq!(admission["admitted"], expected);
    assert_eq!(admission["refused"], 0);
    let cancels = admission["cancelled"].as_u64().unwrap()
        + admission["cancel_after_claim"].as_u64().unwrap();
    assert_eq!(cancels, (expected / profile.cancel_every) as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "workstation contention measurement (20:00-07:00 window)"]
async fn workstation_queue_contention_profile() {
    // CI runs every ignored `--test schema` case, so the heavy profile needs an explicit opt-in.
    if std::env::var("OPENMETTLE_QUEUE_BENCH").as_deref() != Ok("1") {
        eprintln!("skipped: set OPENMETTLE_QUEUE_BENCH=1 to run the workstation profile");
        return;
    }
    let db = TestDb::migrated().await;
    let report = measure_queue_contention_and_plans(&db, &Profile::workstation()).await;
    publish(&report);
    verify(&report);
}
