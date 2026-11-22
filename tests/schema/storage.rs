//! Storage accounting tests (ADR 0005). Isolated PostgreSQL 18 with synthetic limits set by the
//! fixture owner; the values are test data, not deployment defaults.
use super::cancellation::{ResponseBarrier, cancel_at_response};
use super::*;
use openmettle_core::storage::{self, ReservationInput, ReservationState, Settlement};

fn sha(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn code(error: &Error) -> String {
    match error {
        Error::Database(sqlx::Error::Database(e)) => e.code().unwrap_or_default().into_owned(),
        other => panic!("expected a database error, got {other}"),
    }
}

/// Owner-only configuration, as an operator would apply it.
async fn configure(db: &TestDb, budget: Option<i64>, personal: Option<i64>, project: Option<i64>) {
    configure_limits(db, budget, personal, project).await;
    // Ledger-only tests use a synthetic owner-adopted volume. File tests initialize real sentinels.
    if db.exists("openmettle.storage_volume_control").await {
        db.admin()
            .await
            .execute(
                "UPDATE openmettle.storage_volume_control SET volume_id=gen_random_uuid(),
            bootstrap_auto_pin_allowed=false WHERE id AND volume_id IS NULL",
            )
            .await
            .unwrap();
    }
}
pub(super) async fn configure_limits(
    db: &TestDb,
    budget: Option<i64>,
    personal: Option<i64>,
    project: Option<i64>,
) {
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.storage_instance SET instance_budget_bytes=$1,personal_limit_bytes=$2,project_limit_bytes=$3")
        .bind(budget).bind(personal).bind(project).execute(&mut owner).await.unwrap();
}

/// Counters must equal the totals recomputed from reservation and revision rows.
pub(super) async fn assert_totals(db: &TestDb) {
    let mut admin = db.admin().await;
    let rows: Vec<(String, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT s.id::text,
           coalesce(a.active_bytes,0), coalesce(a.retained_bytes,0), coalesce(a.reserved_bytes,0),
           coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions v
                     WHERE v.scope_id=s.id AND v.state='active'),0)::bigint,
           coalesce((SELECT sum(size_bytes) FROM openmettle.artifact_revisions v
                     WHERE v.scope_id=s.id AND v.state IN ('retained','purging')),0)::bigint,
           coalesce((SELECT sum(max_bytes) FROM openmettle.storage_reservations x
                     WHERE x.scope_id=s.id AND x.state='reserved'),0)::bigint
         FROM openmettle.scopes s LEFT JOIN openmettle.storage_accounts a ON a.scope_id=s.id",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    let mut sums = (0, 0, 0);
    for (scope, a, r, x, ea, er, ex) in rows {
        assert_eq!((a, r, x), (ea, er, ex), "scope {scope} counters drifted");
        sums = (sums.0 + ea, sums.1 + er, sums.2 + ex);
    }
    let instance: (i64, i64, i64) = sqlx::query_as(
        "SELECT active_bytes,retained_bytes,reserved_bytes FROM openmettle.storage_instance",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(instance, sums, "instance counters drifted");
}

pub(super) async fn account(db: &TestDb, scope: &str) -> (i64, i64, i64) {
    sqlx::query_as("SELECT active_bytes,retained_bytes,reserved_bytes FROM openmettle.storage_accounts WHERE scope_id=$1::uuid")
        .bind(scope).fetch_one(&mut db.admin().await).await.unwrap()
}

pub(super) async fn new_uuid(db: &TestDb) -> String {
    sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

fn input<'a>(
    scope: &'a str,
    actor: &'a str,
    key: &'a str,
    artifact: &'a str,
    max: i64,
) -> ReservationInput<'a> {
    ReservationInput {
        scope,
        actor,
        key,
        artifact,
        max_bytes: max,
        run: None,
        operation: None,
    }
}

async fn reserve(
    db: &TestDb,
    role: &str,
    r: &ReservationInput<'_>,
) -> Result<storage::Reservation, Error> {
    let mut cn = connect(&db.0, role).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let result = storage::reserve(&mut tx, r).await;
    tx.commit().await.unwrap();
    result
}

async fn settle(
    db: &TestDb,
    scope: &str,
    reservation: &str,
    size: i64,
    body: &[u8],
    media: &str,
) -> Result<String, Error> {
    let mut cn = connect(&db.0, API).await;
    crate::mark_storage_payload_published(&mut cn, reservation).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let digest = sha(body);
    let result = storage::settle(
        &mut tx,
        &Settlement {
            scope,
            reservation,
            size_bytes: size,
            content_digest: &digest,
            media_type: media,
            display_name: None,
        },
    )
    .await;
    tx.commit().await.unwrap();
    result
}

async fn release(db: &TestDb, role: &str, scope: &str, reservation: &str) -> Result<(), Error> {
    let mut cn = connect(&db.0, role).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let result = storage::release(&mut tx, scope, reservation).await;
    tx.commit().await.unwrap();
    result
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn reserve_settle_release_replay_and_limits() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let doc = new_uuid(&db).await;
    // The migration installs an unconfigured singleton: new reservations fail closed.
    assert!(matches!(
        reserve(&db, API, &input(&c.scope, &c.actor, "a", &doc, 300)).await,
        Err(Error::LimitUnconfigured)
    ));
    configure(&db, Some(1000), Some(500), None).await;
    let a = reserve(&db, API, &input(&c.scope, &c.actor, "a", &doc, 300))
        .await
        .unwrap();
    assert_eq!(a.state, ReservationState::Reserved);
    let again = reserve(&db, WORKER, &input(&c.scope, &c.actor, "a", &doc, 300))
        .await
        .unwrap();
    assert_eq!(again.id, a.id);
    assert!(matches!(
        reserve(&db, API, &input(&c.scope, &c.actor, "a", &doc, 301)).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        reserve(&db, API, &input(&c.scope, &c.actor, "b", &doc, 201)).await,
        Err(Error::OwnerLimit)
    ));
    assert!(matches!(
        reserve(&db, API, &input(&c.scope, &c.actor, "b", &doc, 0)).await,
        Err(Error::Invalid)
    ));
    assert_eq!(account(&db, &c.scope).await, (0, 0, 300));
    // Settle charges the actual size once and releases the unused remainder.
    assert!(matches!(
        settle(&db, &c.scope, &a.id, 301, b"body", "text/plain").await,
        Err(Error::Invalid)
    ));
    let rev = settle(&db, &c.scope, &a.id, 120, b"body", "text/plain")
        .await
        .unwrap();
    assert_eq!(
        settle(&db, &c.scope, &a.id, 120, b"body", "text/plain")
            .await
            .unwrap(),
        rev
    );
    for (size, body, media) in [
        (121, b"body".as_slice(), "text/plain"),
        (120, b"other", "text/plain"),
        (120, b"body", "text/html"),
    ] {
        assert!(matches!(
            settle(&db, &c.scope, &a.id, size, body, media).await,
            Err(Error::Conflict)
        ));
    }
    assert_eq!(account(&db, &c.scope).await, (120, 0, 0));
    assert_eq!(
        reserve(&db, API, &input(&c.scope, &c.actor, "a", &doc, 300))
            .await
            .unwrap()
            .state,
        ReservationState::Settled
    );
    assert!(matches!(
        release(&db, API, &c.scope, &a.id).await,
        Err(Error::Conflict)
    ));
    // A second revision of the same artifact is its own payload and charge.
    let b = reserve(&db, API, &input(&c.scope, &c.actor, "b", &doc, 100))
        .await
        .unwrap();
    let rev2 = settle(&db, &c.scope, &b.id, 100, b"v2", "text/plain")
        .await
        .unwrap();
    let numbers: Vec<i64> = sqlx::query_scalar("SELECT revision FROM openmettle.artifact_revisions WHERE artifact_id=$1::uuid ORDER BY revision")
        .bind(&doc).fetch_all(&mut db.admin().await).await.unwrap();
    assert_eq!(numbers, [1, 2]);
    assert_ne!(rev, rev2);
    // Release once; repeats are no-ops and a released reservation cannot settle.
    let d = reserve(&db, WORKER, &input(&c.scope, &c.actor, "d", &doc, 50))
        .await
        .unwrap();
    release(&db, WORKER, &c.scope, &d.id).await.unwrap();
    release(&db, API, &c.scope, &d.id).await.unwrap();
    assert!(matches!(
        settle(&db, &c.scope, &d.id, 1, b"x", "text/plain").await,
        Err(Error::Conflict)
    ));
    assert_eq!(account(&db, &c.scope).await, (220, 0, 0));
    // A project scope uses the project limit; unconfigured project limits refuse.
    let mut api = connect(&db.0, API).await;
    let (_, ps) = project(&mut api, &c.actor).await;
    let pdoc = new_uuid(&db).await;
    assert!(matches!(
        reserve(&db, API, &input(&ps, &c.actor, "p", &pdoc, 10)).await,
        Err(Error::LimitUnconfigured)
    ));
    configure(&db, Some(1000), Some(500), Some(800)).await;
    reserve(&db, API, &input(&ps, &c.actor, "p", &pdoc, 700))
        .await
        .unwrap();
    // 220 + 700 + 100 > 1000 although the project limit (800) still has room.
    assert!(matches!(
        reserve(&db, API, &input(&ps, &c.actor, "q", &pdoc, 100)).await,
        Err(Error::InstanceLimit)
    ));
    // An artifact belongs to one scope; another scope cannot target it.
    assert!(matches!(
        reserve(&db, API, &input(&ps, &c.actor, "x", &doc, 1)).await,
        Err(Error::Conflict)
    ));
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn admission_composes_run_and_reservation_atomically() {
    let db = TestDb::migrated().await;
    configure(&db, Some(10_000), Some(10_000), Some(10_000)).await;
    let c = Context::new(&db).await;
    let out = new_uuid(&db).await;
    let admit = async |commit: bool| {
        let mut cn = connect(&db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        let run = runs::create_run(&mut tx, &c.input("admit")).await.unwrap();
        let mut r = input(&c.scope, &c.actor, "admit-output", &out, 400);
        r.run = Some(&run);
        let reservation = storage::reserve(&mut tx, &r).await.unwrap();
        if commit {
            tx.commit().await.unwrap()
        } else {
            tx.rollback().await.unwrap()
        }
        (run, reservation.id)
    };
    admit(false).await;
    assert_eq!(count(&db, "SELECT count(*) FROM openmettle.runs").await, 0);
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.storage_reservations").await,
        0
    );
    assert_totals(&db).await;
    let first = admit(true).await;
    // Replay after an uncertain acknowledgement returns the same pair and charges nothing new.
    assert_eq!(admit(true).await, first);
    assert_eq!(account(&db, &c.scope).await, (0, 0, 400));
    let (run, run_reservation) = first;
    // An operation-linked reservation stays reserved until the outcome is known.
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let op = runs::record_intent(&mut tx, &intent(&c, &run))
        .await
        .unwrap();
    let mut r = input(&c.scope, &c.actor, "op-output", &out, 100);
    r.run = Some(&run);
    r.operation = Some(&op);
    let op_reservation = storage::reserve(&mut tx, &r).await.unwrap().id;
    tx.commit().await.unwrap();
    for reservation in [&op_reservation, &run_reservation] {
        assert!(matches!(
            release(&db, WORKER, &c.scope, reservation).await,
            Err(Error::Unresolved)
        ));
    }
    let observe = async |key: &str, revision: i64, outcome: &str| {
        let mut cn = connect(&db.0, WORKER).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        runs::record_observation(
            &mut tx,
            &Observation {
                scope: &c.scope,
                run: &run,
                operation: &op,
                key,
                expected_revision: revision,
                outcome,
                handle: None,
                evidence: payload(b"evidence"),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    };
    observe("timeout", 0, "outcome_unknown").await;
    // A timeout is not evidence that the effect stopped: capacity is not freed.
    for reservation in [&op_reservation, &run_reservation] {
        assert!(matches!(
            release(&db, WORKER, &c.scope, reservation).await,
            Err(Error::Unresolved)
        ));
    }
    assert_eq!(account(&db, &c.scope).await, (0, 0, 500));
    observe("failed", 1, "failed").await;
    release(&db, WORKER, &c.scope, &op_reservation)
        .await
        .unwrap();
    release(&db, API, &c.scope, &run_reservation).await.unwrap();
    assert_eq!(account(&db, &c.scope).await, (0, 0, 0));
    // Operation links must be relationally consistent with the run.
    let other = c.run(&db, "other").await;
    let mut r = input(&c.scope, &c.actor, "mismatch", &out, 1);
    r.run = Some(&other);
    r.operation = Some(&op);
    assert_eq!(code(&reserve(&db, WORKER, &r).await.unwrap_err()), "23503");
    r.run = None;
    assert!(matches!(
        reserve(&db, WORKER, &r).await,
        Err(Error::Invalid)
    ));
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn concurrent_reservations_cannot_exceed_one_owner_limit() {
    let db = TestDb::migrated().await;
    // The instance can accommodate every request; only this owner's limit can bind.
    configure(&db, Some(10_000), Some(500), Some(500)).await;
    let owner = Context::new(&db).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for i in 0..8 {
        let c = owner.clone();
        let b = barrier.clone();
        let artifact = new_uuid(&db).await;
        let opts = role_options(&db.0, if i % 2 == 0 { API } else { WORKER });
        tasks.push(tokio::spawn(async move {
            let mut cn = PgConnection::connect_with(&opts).await.unwrap();
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            b.wait().await;
            let key = format!("owner-race-{i}");
            let result =
                storage::reserve(&mut tx, &input(&c.scope, &c.actor, &key, &artifact, 100)).await;
            // Refused attempts must leave no partial reservation or counter update, even
            // when the caller commits the otherwise valid transaction.
            tx.commit().await.unwrap();
            result
        }));
    }
    let (mut accepted, mut refused) = (0, 0);
    for task in tasks {
        match task.await.unwrap() {
            Ok(r) => {
                assert_eq!(r.state, ReservationState::Reserved);
                accepted += 1;
            }
            Err(Error::OwnerLimit) => refused += 1,
            Err(other) => panic!("unexpected owner-race result: {other}"),
        }
    }
    assert_eq!((accepted, refused), (5, 3));
    assert_eq!(account(&db, &owner.scope).await, (0, 0, 500));
    let rows: (i64, i64) = sqlx::query_as("SELECT count(*), coalesce(sum(max_bytes),0)::bigint FROM openmettle.storage_reservations WHERE scope_id=$1::uuid")
        .bind(&owner.scope).fetch_one(&mut db.admin().await).await.unwrap();
    assert_eq!(rows, (5, 500));
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn concurrent_owners_and_limit_reduction_never_oversubscribe() {
    let db = TestDb::migrated().await;
    // Ten owners with ample personal limits race for a 500-byte instance budget.
    configure(&db, Some(500), Some(1000), Some(1000)).await;
    let mut owners = Vec::new();
    for _ in 0..10 {
        owners.push(Context::new(&db).await);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(owners.len() + 3));
    let mut tasks = Vec::new();
    for (i, c) in owners.iter().cloned().enumerate().chain(
        std::iter::repeat_n(owners[0].clone(), 3)
            .enumerate()
            .map(|(i, c)| (i + 10, c)),
    ) {
        let opts = role_options(&db.0, if i % 2 == 0 { API } else { WORKER });
        let artifact = new_uuid(&db).await;
        let b = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let mut cn = PgConnection::connect_with(&opts).await.unwrap();
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            b.wait().await;
            let key = format!("race-{i}");
            let result =
                storage::reserve(&mut tx, &input(&c.scope, &c.actor, &key, &artifact, 100)).await;
            tx.commit().await.unwrap();
            result
        }));
    }
    let mut won = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => won += 1,
            Err(Error::InstanceLimit) => {}
            Err(other) => panic!("unexpected {other}"),
        }
    }
    assert_eq!(won, 5);
    assert_totals(&db).await;

    // A limit reduction waits for an in-flight reservation, then refuses new work only.
    let c = Context::new(&db).await;
    configure(&db, Some(100_000), Some(1000), Some(1000)).await;
    let doc = new_uuid(&db).await;
    let mut cn = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let held = storage::reserve(&mut tx, &input(&c.scope, &c.actor, "held", &doc, 600))
        .await
        .unwrap();
    let owner_opts = role_options(&db.0, OWNER);
    let reduce = tokio::spawn(async move {
        let mut owner = PgConnection::connect_with(&owner_opts).await.unwrap();
        sqlx::query("UPDATE openmettle.storage_instance SET personal_limit_bytes=100")
            .execute(&mut owner)
            .await
            .unwrap();
    });
    let mut admin = db.admin().await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname=$1 AND usename=$2 AND wait_event_type='Lock')")
        .bind(&db.0).bind(OWNER).fetch_one(&mut admin).await.unwrap()
    {
        assert!(Instant::now() < deadline, "limit update did not wait for the reservation lock");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tx.commit().await.unwrap();
    reduce.await.unwrap();
    // Existing usage is preserved, exact replay succeeds, new reservations are refused and the
    // existing allowance can still settle.
    assert_eq!(account(&db, &c.scope).await, (0, 0, 600));
    assert_eq!(
        reserve(&db, API, &input(&c.scope, &c.actor, "held", &doc, 600))
            .await
            .unwrap()
            .id,
        held.id
    );
    assert!(matches!(
        reserve(&db, API, &input(&c.scope, &c.actor, "new", &doc, 1)).await,
        Err(Error::OwnerLimit)
    ));
    settle(
        &db,
        &c.scope,
        &held.id,
        500,
        b"kept",
        "application/octet-stream",
    )
    .await
    .unwrap();
    assert_eq!(account(&db, &c.scope).await, (500, 0, 0));
    configure(&db, Some(100_000), None, Some(1000)).await;
    assert!(matches!(
        reserve(&db, API, &input(&c.scope, &c.actor, "new", &doc, 1)).await,
        Err(Error::LimitUnconfigured)
    ));
    assert_eq!(
        reserve(&db, API, &input(&c.scope, &c.actor, "held", &doc, 600))
            .await
            .unwrap()
            .state,
        ReservationState::Settled
    );
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn cross_owner_deadlock_is_retried_as_a_whole_transaction() {
    let db = TestDb::migrated().await;
    configure(&db, Some(10_000), Some(10_000), Some(10_000)).await;
    let a = Context::new(&db).await;
    let b = Context::new(&db).await;
    let (fa, fb) = (new_uuid(&db).await, new_uuid(&db).await);
    // Pre-create both accounts so each transaction waits on the other's owner row.
    reserve(&db, API, &input(&a.scope, &a.actor, "seed", &fa, 1))
        .await
        .unwrap();
    reserve(&db, API, &input(&b.scope, &b.actor, "seed", &fb, 1))
        .await
        .unwrap();
    // Acquire the instance lock before the peer starts; otherwise it can finish first.
    let cross_artifact = new_uuid(&db).await;
    let mut cn = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    storage::reserve(&mut tx, &input(&a.scope, &a.actor, "one", &fa, 10))
        .await
        .unwrap();
    let opts = role_options(&db.0, API);
    let (b2, fb2) = (b.clone(), fb.clone());
    let (pid_send, pid_recv) = tokio::sync::oneshot::channel();
    let second = tokio::spawn(async move {
        let mut cn = PgConnection::connect_with(&opts).await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut cn)
            .await
            .unwrap();
        pid_send.send(pid).unwrap();
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        match storage::reserve(&mut tx, &input(&b2.scope, &b2.actor, "two", &fb2, 10)).await {
            Ok(_) => {
                tx.commit().await.unwrap();
                None
            }
            Err(e) => {
                tx.rollback().await.unwrap();
                Some(code(&e))
            }
        }
    });
    let second_pid = pid_recv.await.unwrap();
    // `second` now holds b's owner row and waits for the instance row this transaction holds.
    let mut admin = db.admin().await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pg_stat_activity WHERE datname=$1 AND pid=$2 AND wait_event_type='Lock'",
    )
    .bind(&db.0)
    .bind(second_pid)
    .fetch_one(&mut admin)
    .await
    .unwrap()
        == 0
    {
        assert!(Instant::now() < deadline, "second transaction never waited");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mine = storage::reserve(
        &mut tx,
        &input(&b.scope, &a.actor, "cross", &cross_artifact, 10),
    )
    .await;
    let mine = match mine {
        Ok(_) => {
            tx.commit().await.unwrap();
            None
        }
        Err(e) => {
            // Abandon the whole transaction: its earlier locks would otherwise block the peer.
            tx.rollback().await.unwrap();
            Some(code(&e))
        }
    };
    let theirs = second.await.unwrap();
    assert!(
        matches!(
            (mine.as_deref(), theirs.as_deref()),
            (Some("40P01"), None) | (None, Some("40P01"))
        ),
        "{mine:?} {theirs:?}"
    );
    // Retrying the abandoned transaction with the same keys completes it exactly once.
    if mine.is_some() {
        let mut cn = connect(&db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        storage::reserve(&mut tx, &input(&a.scope, &a.actor, "one", &fa, 10))
            .await
            .unwrap();
        storage::reserve(
            &mut tx,
            &input(&b.scope, &a.actor, "cross", &cross_artifact, 10),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    } else {
        reserve(&db, API, &input(&b.scope, &b.actor, "two", &fb, 10))
            .await
            .unwrap();
    }
    reserve(&db, API, &input(&a.scope, &a.actor, "one", &fa, 10))
        .await
        .unwrap();
    reserve(&db, API, &input(&b.scope, &b.actor, "two", &fb, 10))
        .await
        .unwrap();
    assert_eq!(account(&db, &a.scope).await.2, 11);
    assert_eq!(account(&db, &b.scope).await.2, 21);
    let cross_count: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.storage_reservations WHERE scope_id=$1::uuid AND actor_user_id=$2::uuid AND idempotency_key='cross' AND artifact_id=$3::uuid AND max_bytes=10")
        .bind(&b.scope).bind(&a.actor).bind(&cross_artifact)
        .fetch_one(&mut admin).await.unwrap();
    assert_eq!(cross_count, 1);
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn retention_keeps_bytes_charged_until_confirmed_purge() {
    let db = TestDb::migrated().await;
    configure(&db, Some(10_000), Some(10_000), Some(10_000)).await;
    let c = Context::new(&db).await;
    let doc = new_uuid(&db).await;
    let r = reserve(&db, API, &input(&c.scope, &c.actor, "f", &doc, 64))
        .await
        .unwrap();
    let rev = settle(&db, &c.scope, &r.id, 40, b"retained", "text/plain")
        .await
        .unwrap();
    let step = async |role: &str, which: u8, grace: u32| -> Result<Option<String>, Error> {
        let mut cn = connect(&db.0, role).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        let result = match which {
            0 => storage::retain_revision(&mut tx, &c.scope, &rev, grace)
                .await
                .map(Some),
            1 => storage::restore_revision(&mut tx, &c.scope, &rev)
                .await
                .map(|_| None),
            2 => storage::begin_purge(&mut tx, &c.scope, &rev)
                .await
                .map(|_| None),
            _ => storage::confirm_purge(&mut tx, &c.scope, &rev)
                .await
                .map(|_| None),
        };
        tx.commit().await.unwrap();
        result
    };
    assert!(matches!(step(API, 0, 0).await, Err(Error::Invalid)));
    // Role split: the worker cannot retain or restore; the API cannot claim or confirm purge.
    assert_eq!(code(&step(WORKER, 0, 3600).await.unwrap_err()), "42501");
    let first = step(API, 0, 3600).await.unwrap().unwrap();
    assert_eq!(account(&db, &c.scope).await, (0, 40, 0));
    // Retries cannot move the stored deadline.
    assert_eq!(step(API, 0, 1).await.unwrap().unwrap(), first);
    assert!(matches!(step(WORKER, 2, 0).await, Err(Error::NotEligible)));
    assert!(matches!(step(WORKER, 3, 0).await, Err(Error::NotEligible)));
    assert_eq!(code(&step(WORKER, 1, 0).await.unwrap_err()), "42501");
    step(API, 1, 0).await.unwrap();
    assert_eq!(account(&db, &c.scope).await, (40, 0, 0));
    // A new removal starts a new grace period.
    step(API, 0, 1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(matches!(step(API, 1, 0).await, Err(Error::NotEligible)));
    assert_eq!(code(&step(API, 2, 0).await.unwrap_err()), "42501");
    // Claim and confirmation in one transaction is refused: deletion happens between them.
    let mut cn = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    storage::begin_purge(&mut tx, &c.scope, &rev).await.unwrap();
    assert!(matches!(
        storage::confirm_purge(&mut tx, &c.scope, &rev).await,
        Err(Error::NotEligible)
    ));
    tx.commit().await.unwrap();
    step(WORKER, 2, 0).await.unwrap();
    assert_eq!(account(&db, &c.scope).await, (0, 40, 0));
    assert!(matches!(step(API, 1, 0).await, Err(Error::NotEligible)));
    step(WORKER, 3, 0).await.unwrap();
    step(WORKER, 3, 0).await.unwrap();
    assert_eq!(account(&db, &c.scope).await, (0, 0, 0));
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn storage_roles_and_scoped_references_are_bounded() {
    let db = TestDb::migrated().await;
    configure(&db, Some(10_000), Some(10_000), Some(10_000)).await;
    let c = Context::new(&db).await;
    let other = Context::new(&db).await;
    let doc = new_uuid(&db).await;
    let r = reserve(&db, API, &input(&c.scope, &c.actor, "f", &doc, 10))
        .await
        .unwrap();
    let rev = settle(&db, &c.scope, &r.id, 5, b"x", "text/plain")
        .await
        .unwrap();
    let other_doc = new_uuid(&db).await;
    let o = reserve(
        &db,
        API,
        &input(&other.scope, &other.actor, "o", &other_doc, 10),
    )
    .await
    .unwrap();
    // Another actor cannot create a new artifact in someone's personal scope.
    let foreign = reserve(
        &db,
        API,
        &input(&c.scope, &other.actor, "foreign", &new_uuid(&db).await, 5),
    )
    .await
    .unwrap();
    assert_eq!(
        code(
            &settle(&db, &c.scope, &foreign.id, 1, b"y", "text/plain")
                .await
                .unwrap_err()
        ),
        "23503"
    );
    // A run from another scope is rejected relationally.
    let run = other.run(&db, "r").await;
    let mut cross = input(&c.scope, &c.actor, "cross", &doc, 1);
    cross.run = Some(&run);
    assert_eq!(code(&reserve(&db, API, &cross).await.unwrap_err()), "23503");
    for role in [API, WORKER] {
        let mut cn = connect(&db.0, role).await;
        for sql in [
            "UPDATE openmettle.storage_instance SET instance_budget_bytes=1",
            "UPDATE openmettle.storage_instance SET personal_limit_bytes=1",
            "INSERT INTO openmettle.storage_instance(id) VALUES (false)",
            "DELETE FROM openmettle.storage_instance",
            "TRUNCATE openmettle.storage_accounts",
            "DELETE FROM openmettle.storage_reservations",
            "DELETE FROM openmettle.artifact_revisions",
            "DELETE FROM openmettle.artifacts",
            "UPDATE openmettle.artifact_revisions SET size_bytes=0",
            "UPDATE openmettle.artifact_revisions SET content_digest=''::bytea",
            "UPDATE openmettle.storage_reservations SET max_bytes=1",
            "UPDATE openmettle.storage_reservations SET run_id=NULL",
            "UPDATE openmettle.artifacts SET scope_id=scope_id",
            "UPDATE openmettle.storage_accounts SET scope_id=scope_id",
            "SELECT * FROM openmettle._sqlx_migrations",
        ] {
            expect_state(&mut cn, sql, "42501").await;
        }
        let only = if role == API {
            "purging_at"
        } else {
            "purge_after"
        };
        expect_state(
            &mut cn,
            &format!("UPDATE openmettle.artifact_revisions SET {only}=NULL"),
            "42501",
        )
        .await;
        // Direct SQL must still satisfy scoped keys: a revision cannot attach another scope's
        // reservation, and an operation link needs its run.
        let result = sqlx::query("INSERT INTO openmettle.artifact_revisions(scope_id,artifact_id,revision,reservation_id,size_bytes,content_digest,media_type,created_by_user_id)
             VALUES($1::uuid,$2::uuid,9,$3::uuid,1,decode(repeat('00',32),'hex'),'x',$4::uuid)")
            .bind(&c.scope).bind(&doc).bind(&o.id).bind(&c.actor).execute(&mut cn).await;
        assert_eq!(sqlstate(result), "23503");
        let result = sqlx::query("INSERT INTO openmettle.storage_reservations(scope_id,actor_user_id,idempotency_key,artifact_id,max_bytes,operation_id,request_identity,request_digest)
             VALUES($1::uuid,$2::uuid,$3,$4::uuid,1,gen_random_uuid(),''::bytea,decode(repeat('00',32),'hex'))")
            .bind(&c.scope).bind(&c.actor).bind(role).bind(&doc).execute(&mut cn).await;
        assert_eq!(sqlstate(result), "23514");
        // A second revision for an already settled reservation violates its unique key.
        let result = sqlx::query("INSERT INTO openmettle.artifact_revisions(scope_id,artifact_id,revision,reservation_id,size_bytes,content_digest,media_type,created_by_user_id)
             VALUES($1::uuid,$2::uuid,9,$3::uuid,1,decode(repeat('00',32),'hex'),'x',$4::uuid)")
            .bind(&c.scope).bind(&doc).bind(&r.id).bind(&c.actor).execute(&mut cn).await;
        assert_eq!(sqlstate(result), "23505");
    }
    let mut cn = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    assert!(matches!(
        storage::retain_revision(&mut tx, &other.scope, &rev, 60).await,
        Err(Error::NotFound)
    ));
    tx.rollback().await.unwrap();
    assert_totals(&db).await;
    // Version-4 grants are refused before migration 4 has applied.
    let v3 = TestDb::new().await;
    migrate::apply(&v3.settings(Duration::from_secs(1)), &MIGRATIONS[..3])
        .await
        .unwrap();
    let mut owner = connect(&v3.0, OWNER).await;
    owner.execute("CREATE TABLE openmettle.artifacts(id int); GRANT SELECT ON openmettle.artifacts TO openmettle_worker").await.unwrap();
    assert!(matches!(
        migrate::apply(&v3.settings(Duration::from_secs(1)), MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
    assert_eq!(v3.history().await, [1, 2, 3]);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn cancellation_and_unknown_commit_never_double_charge() {
    let db = TestDb::migrated().await;
    configure(&db, Some(10_000), Some(1_000), Some(1_000)).await;
    let c = Context::new(&db).await;
    let doc = new_uuid(&db).await;
    let pending = reserve(&db, API, &input(&c.scope, &c.actor, "pending", &doc, 100))
        .await
        .unwrap();
    crate::mark_storage_payload_published(&mut db.admin().await, &pending.id).await;
    let to_release = reserve(&db, API, &input(&c.scope, &c.actor, "release", &doc, 100))
        .await
        .unwrap();
    for (which, command) in [
        (0, b"SAVEPOINT\0".as_slice()),
        (1, b"SAVEPOINT\0"),
        (2, b"SAVEPOINT\0"),
        (0, b"RELEASE\0"),
        (1, b"RELEASE\0"),
        (3, b"ROLLBACK\0"),
    ] {
        let mut barrier = ResponseBarrier::new(command);
        let options = role_options(&db.0, API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut connection = PgConnection::connect_with(&options).await.unwrap();
        let mut tx = WriteTransaction::begin(&mut connection).await.unwrap();
        let previous = message(
            tx.connection().unwrap(),
            &c.scope,
            &c.conversation,
            Some(&c.message),
        )
        .await
        .unwrap();
        let digest = sha(b"cancelled");
        let settlement = Settlement {
            scope: &c.scope,
            reservation: &pending.id,
            size_bytes: 10,
            content_digest: &digest,
            media_type: "text/plain",
            display_name: None,
        };
        match which {
            0 => {
                cancel_at_response(
                    &mut barrier,
                    storage::reserve(&mut tx, &input(&c.scope, &c.actor, "cancelled", &doc, 10)),
                )
                .await
            }
            1 => cancel_at_response(&mut barrier, storage::settle(&mut tx, &settlement)).await,
            2 => {
                cancel_at_response(
                    &mut barrier,
                    storage::release(&mut tx, &c.scope, &to_release.id),
                )
                .await
            }
            // Over the owner limit: cancelled while rolling back the helper savepoint.
            _ => {
                cancel_at_response(
                    &mut barrier,
                    storage::reserve(&mut tx, &input(&c.scope, &c.actor, "big", &doc, 5_000)),
                )
                .await
            }
        }
        assert!(
            matches!(tx.commit().await, Err(Error::TransactionUnavailable)),
            "{which}"
        );
        drop(connection);
        drop(barrier);
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM openmettle.messages WHERE parent_message_id IS NOT NULL"
            )
            .await,
            0,
            "{previous}"
        );
        assert_totals(&db).await;
    }
    assert_eq!(account(&db, &c.scope).await, (0, 0, 200));
    // A commit whose acknowledgement is lost is recovered by exact replay, not a second charge.
    let mut barrier = ResponseBarrier::new(b"COMMIT\0");
    let options = role_options(&db.0, API)
        .host("127.0.0.1")
        .port(barrier.port)
        .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut connection = PgConnection::connect_with(&options).await.unwrap();
    let mut tx = WriteTransaction::begin(&mut connection).await.unwrap();
    let uncertain = storage::reserve(&mut tx, &input(&c.scope, &c.actor, "uncertain", &doc, 300))
        .await
        .unwrap();
    cancel_at_response(&mut barrier, tx.commit()).await;
    drop(connection);
    drop(barrier);
    assert_eq!(
        reserve(&db, API, &input(&c.scope, &c.actor, "uncertain", &doc, 300))
            .await
            .unwrap()
            .id,
        uncertain.id
    );
    assert_eq!(account(&db, &c.scope).await, (0, 0, 500));
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn migration_four_failure_kill_timeout_and_concurrent_retry() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(1));
    migrate::apply(&settings, &MIGRATIONS[..3]).await.unwrap();
    let broken = Source {
        sql: concat!(
            include_str!("../../migrations/0004_artifacts_storage_accounting.sql"),
            "\nSELECT 1/0;"
        ),
        ..MIGRATIONS[3]
    };
    assert!(matches!(
        migrate::apply(
            &settings,
            &[MIGRATIONS[0], MIGRATIONS[1], MIGRATIONS[2], broken]
        )
        .await,
        Err(Failure::Migrate(_))
    ));
    assert_eq!(db.history().await, [1, 2, 3]);
    assert!(!db.exists("openmettle.storage_instance").await);
    // Migration 4's artifact foreign key waits on scopes after it has written the singleton.
    let mut blocker = db.admin().await;
    blocker.execute("BEGIN").await.unwrap();
    blocker
        .execute("LOCK TABLE openmettle.scopes IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut bounded = db.settings(Duration::from_secs(5));
    bounded.statement_timeout = Duration::from_millis(150);
    assert!(matches!(
        migrate::apply(&bounded, MIGRATIONS).await,
        Err(Failure::Migrate(_))
    ));
    db.wait_no_migration_session().await;
    assert_eq!(db.history().await, [1, 2, 3]);
    let mut admin = db.admin().await;
    for kill in ["-TERM", "-KILL"] {
        let mut child = migrate_command(
            &db.url(OWNER),
            &[
                ("LOCK_TIMEOUT_MS", "60000"),
                ("STATEMENT_TIMEOUT_MS", "60000"),
            ],
        )
        .spawn()
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let state: Option<(bool, bool)> = sqlx::query_as(
                "SELECT a.backend_xid IS NOT NULL,
                        EXISTS (SELECT FROM pg_locks AS l
                                WHERE l.pid = a.pid AND l.locktype = 'advisory' AND l.granted)
                 FROM pg_stat_activity AS a
                 WHERE a.datname = $1 AND a.application_name = $2 AND a.wait_event_type = 'Lock'",
            )
            .bind(&db.0)
            .bind(migrate::APPLICATION_NAME)
            .fetch_optional(&mut admin)
            .await
            .unwrap();
            if state == Some((true, true)) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "migrator never blocked inside migration 4: {state:?}"
            );
            assert!(child.try_wait().unwrap().is_none(), "migrator exited early");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        signal(&child, kill);
        let status = child.wait().unwrap();
        if kill == "-TERM" {
            assert_eq!(status.code(), Some(1));
        }
        db.wait_no_migration_session().await;
        assert!(!db.exists("openmettle.storage_instance").await, "{kill}");
        assert_eq!(db.history().await, [1, 2, 3], "{kill}");
    }
    blocker.execute("ROLLBACK").await.unwrap();
    let children: Vec<_> = (0..4)
        .map(|_| migrate_command(&db.url(OWNER), &[]).spawn().unwrap())
        .collect();
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
    }
    assert_eq!(db.history().await, all_versions());
    let singleton: (i64, Option<i64>) = sqlx::query_as(
        "SELECT count(*), max(instance_budget_bytes) FROM openmettle.storage_instance",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(singleton, (1, None));
    db.wait_no_migration_session().await;
}

fn old_command(dir: &std::path::Path, name: &str, template: &Command) -> Command {
    let mut cmd = Command::new(dir.join(name));
    for (k, v) in template.get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    cmd
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V3_BINARY_DIR required"]
async fn populated_v3_upgrade_and_authentic_v3_binaries() {
    let db = TestDb::new().await;
    let old = std::path::PathBuf::from(
        std::env::var("V3_BINARY_DIR").expect("build released 2f1be94 binaries first"),
    );
    let old_migrate = || {
        old_command(
            &old,
            "openmettle-migrate",
            &migrate_command(&db.url(OWNER), &[]),
        )
        .output()
        .unwrap()
    };
    let output = old_migrate();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(db.history().await, [1, 2, 3]);
    // Populate every v3 domain, including a project scope, events and an observed operation.
    let c = Context::new(&db).await;
    let run = c.run(&db, "before").await;
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let op = runs::record_intent(&mut tx, &intent(&c, &run))
        .await
        .unwrap();
    runs::record_observation(
        &mut tx,
        &Observation {
            scope: &c.scope,
            run: &run,
            operation: &op,
            key: "seen",
            expected_revision: 0,
            outcome: "outcome_unknown",
            handle: Some("handle"),
            evidence: payload(b"evidence"),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut api = connect(&db.0, API).await;
    let (_, ps) = project(&mut api, &c.actor).await;
    let tables = [
        "users",
        "user_identities",
        "scopes",
        "projects",
        "conversations",
        "messages",
        "conversation_branches",
        "runs",
        "operations",
    ];
    let events = "SELECT t::text FROM openmettle.run_events t ORDER BY run_id, sequence";
    let before = (
        snapshot(&mut api, &tables).await,
        sqlx::query_scalar::<_, String>(events)
            .fetch_all(&mut api)
            .await
            .unwrap(),
    );
    let history: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(db.history().await, all_versions());
    let after = (
        snapshot(&mut api, &tables).await,
        sqlx::query_scalar::<_, String>(events)
            .fetch_all(&mut api)
            .await
            .unwrap(),
    );
    assert_eq!(after, before);
    let kept: Vec<String> = sqlx::query_scalar(
        "SELECT t::text FROM openmettle._sqlx_migrations t WHERE version <= 3 ORDER BY version",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(kept, history);
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.storage_accounts").await,
        0
    );
    // The previous migrator refuses the newer database before changing anything.
    let full: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    let refused = old_migrate();
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("boundary check refused"),
        "{}",
        stderr(&refused)
    );
    let unchanged: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    assert_eq!(unchanged, full);
    // Previous runtime processes stay ready against the upgraded schema.
    for (name, role, prefix) in [
        ("openmettle-api", API, "OPENMETTLE_API"),
        ("openmettle-worker", WORKER, "OPENMETTLE_WORKER"),
    ] {
        let bind = address();
        let mut cmd = Command::new(old.join(name));
        scrub_env(&mut cmd);
        let child = cmd
            .env(format!("{prefix}_DATABASE_URL"), db.url(role))
            .env(format!("{prefix}_BIND"), &bind)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut process = Process(child);
        wait_ready(&mut process, &bind);
        signal(&process.0, "-TERM");
        assert!(process.0.wait().unwrap().success());
    }
    // Scopes written before the upgrade (and by a previous API afterwards) account lazily.
    configure(&db, Some(10_000), Some(1_000), Some(1_000)).await;
    let late = Context::new(&db).await;
    for (scope, actor, key) in [
        (&c.scope, &c.actor, "v3"),
        (&ps, &c.actor, "project"),
        (&late.scope, &late.actor, "late"),
    ] {
        let doc = new_uuid(&db).await;
        let mut r = input(scope, actor, key, &doc, 10);
        if key == "v3" {
            r.run = Some(&run);
        }
        let reservation = reserve(&db, API, &r).await.unwrap();
        if key == "v3" {
            assert!(matches!(
                release(&db, API, scope, &reservation.id).await,
                Err(Error::Unresolved)
            ));
        } else {
            settle(
                &db,
                scope,
                &reservation.id,
                10,
                key.as_bytes(),
                "text/plain",
            )
            .await
            .unwrap();
        }
    }
    assert_totals(&db).await;
    let chat = conversation(&mut api, &c.scope, "personal", &c.actor)
        .await
        .unwrap();
    message(&mut api, &c.scope, &chat, None).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn lifecycle_constraints_reject_missing_values() {
    let db = TestDb::migrated().await;
    configure(&db, Some(1000), Some(1000), Some(1000)).await;
    let c = Context::new(&db).await;
    let doc = new_uuid(&db).await;
    let r = reserve(
        &db,
        API,
        &input(&c.scope, &c.actor, "null-checks", &doc, 10),
    )
    .await
    .unwrap();
    let rev = settle(&db, &c.scope, &r.id, 5, b"x", "text/plain")
        .await
        .unwrap();
    let mut cn = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    storage::retain_revision(&mut tx, &c.scope, &rev, 60)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Both roles can change state, but neither may bypass mandatory lifecycle values.
    for role in [API, WORKER] {
        let mut cn = connect(&db.0, role).await;
        for state in ["purging", "purged"] {
            let result =
                sqlx::query("UPDATE openmettle.artifact_revisions SET state=$2 WHERE id=$1::uuid")
                    .bind(&rev)
                    .bind(state)
                    .execute(&mut cn)
                    .await;
            assert_eq!(sqlstate(result), "23514");
        }
        let result = sqlx::query(
            "UPDATE openmettle.storage_reservations SET settled_bytes=NULL WHERE id=$1::uuid",
        )
        .bind(&r.id)
        .execute(&mut cn)
        .await;
        assert_eq!(sqlstate(result), "23514");
    }
    // Use owner privileges to isolate CHECK enforcement from column grant enforcement.
    let mut owner = connect(&db.0, OWNER).await;
    for query in [
        "UPDATE openmettle.artifact_revisions SET state='retained', purge_after=NULL WHERE id=$1::uuid",
        "UPDATE openmettle.artifact_revisions SET state='retained', retained_at=NULL WHERE id=$1::uuid",
        "UPDATE openmettle.artifact_revisions SET state='purging', purging_at=NULL WHERE id=$1::uuid",
        "UPDATE openmettle.artifact_revisions SET state='purging', purging_at=purge_after, purge_after=NULL WHERE id=$1::uuid",
        "UPDATE openmettle.artifact_revisions SET state='purged', purging_at=purge_after, purged_at=NULL WHERE id=$1::uuid",
        "UPDATE openmettle.artifact_revisions SET state='purged', purging_at=NULL, purged_at=purge_after WHERE id=$1::uuid",
    ] {
        let result = sqlx::query(query).bind(&rev).execute(&mut owner).await;
        assert_eq!(sqlstate(result), "23514", "{query}");
    }
    assert_totals(&db).await;
}
