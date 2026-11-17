//! The pooled browser-auth service (ADR 0016) on a one-slot pool: connection ownership across
//! provider requests, reuse after acknowledged outcomes and replacement after uncertain ones.
//! Isolated CI PostgreSQL 18 only. The fixture administrator only observes other backends.
use super::sessions::{issue, seed, session_policy, statistics_observer, waiting};
use super::*;
use crate::browser_auth::{BrowserAuth, Error};
use crate::response_barrier::{ResponseBarrier, cancel_at_response};
use crate::sessions::{self as local, Error as SessionError};
use sqlx::{PgPool, postgres::PgPoolOptions};

/// One backend incarnation: a later backend that reused the process ID still differs.
type Backend = (i32, String);

// The acquire timeout is far above every deadline under test, so a deadline always fires first.
fn one_slot(options: PgConnectOptions) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(20))
        .connect_lazy_with(options)
}
fn service_over(f: &Flow, pool: &PgPool) -> BrowserAuth {
    service::browser_auth(
        &f.h,
        pool.clone(),
        Duration::from_secs(300),
        session_policy(),
    )
}
/// An unrelated query through the pool. It needs the only slot, so it also proves the slot
/// is available, and it reports which backend the pool currently owns.
async fn backend(pool: &PgPool) -> Backend {
    tokio::time::timeout(
        Duration::from_secs(10),
        sqlx::query_as(
            "SELECT pid, backend_start::text FROM pg_stat_activity WHERE pid = pg_backend_pid()",
        )
        .fetch_one(pool),
    )
    .await
    .expect("the single pool slot must be available")
    .unwrap()
}
// SQLx returns or closes a dropped checkout on its own task; wait for the pool's accounting.
async fn pool_state(pool: &PgPool, size: u32, idle: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while (pool.size(), pool.num_idle()) != (size, idle) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("pool accounting did not settle");
}
async fn gone(observer: &mut PgConnection, backend: &Backend) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND backend_start::text=$2)",
        )
        .bind(backend.0)
        .bind(&backend.1)
        .fetch_one(&mut *observer)
        .await
        .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("discarded backend did not exit");
}
fn posts(f: &Flow) -> usize {
    let heads = f.h.server.heads.lock().unwrap();
    heads.iter().filter(|head| head.starts_with("POST")).count()
}
async fn sessions(f: &mut Flow) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions")
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}
async fn session_issued(f: &mut Flow, started: &Started) -> bool {
    sqlx::query_scalar("SELECT session_issued FROM openmettle.login_transactions WHERE id=$1")
        .bind(locator(started))
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}
async fn reservations(f: &mut Flow) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM openmettle.login_nonce_reservations")
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}
// A separate owner session must take these locks at once: nothing idle may still hold them.
async fn unlocked(owner: &mut PgConnection, tables: &[&str]) {
    let mut tx = owner.begin().await.unwrap();
    tx.execute("SET LOCAL lock_timeout='500ms'").await.unwrap();
    for table in tables {
        tx.execute(AssertSqlSafe(format!(
            "SELECT 1 FROM openmettle.{table} FOR UPDATE"
        )))
        .await
        .expect("row lock still held");
    }
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn one_slot_pool_completes_a_login_and_reuses_after_replay_denial() {
    let mut f = Flow::new().await;
    let user = seed(&mut f, true, true).await;
    let pool = one_slot(f.db.options(API));
    let auth = service_over(&f, &pool);
    let first = backend(&pool).await;
    let started = auth.begin(signing::ID).await.unwrap();
    f.arm(&started);
    let credential = auth
        .complete(signing::ID, callback(&started))
        .await
        .unwrap();
    assert_eq!(posts(&f), 1);
    let context = auth.validate(credential.expose()).await.unwrap();
    assert_eq!(context.user_id(), user);
    // Replay is refused under the login row lock, after an awaited rollback, with no POST.
    assert_eq!(
        auth.complete(signing::ID, callback(&started))
            .await
            .unwrap_err(),
        Error::Login(login::Error::Rejected)
    );
    assert_eq!(posts(&f), 1);
    // That ordinary denial left no lock behind while the pooled connection sits idle, and
    // the pool still owns the backend it started with.
    pool_state(&pool, 1, 1).await;
    unlocked(
        &mut f.owner,
        &["login_transactions", "login_admission", "local_sessions"],
    )
    .await;
    assert_eq!(backend(&pool).await, first);
    // Validation and logout are local: a provider outage changes nothing and costs no request.
    f.h.script.lock().unwrap().mode = "failure";
    let requests = f.h.count();
    auth.validate(credential.expose()).await.unwrap();
    auth.logout(credential.expose()).await.unwrap();
    assert_eq!(
        auth.validate(credential.expose()).await.unwrap_err(),
        Error::Session(SessionError::Rejected)
    );
    assert_eq!(f.h.count(), requests);
    assert_eq!(backend(&pool).await, first);
    pool_state(&pool, 1, 1).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn blocked_provider_requests_hold_no_pooled_connection() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let pool = one_slot(f.db.options(API));
    let auth = service_over(&f, &pool);
    let gate = f.h.script.lock().unwrap().gate.clone();
    // Cold start: the key document request is held open during preflight. The pool has not
    // been asked for a connection, so unrelated work gets its only slot.
    f.h.script.lock().unwrap().mode = "gate-jwks";
    let control = async {
        f.h.entered(2).await;
        backend(&pool).await;
        f.h.script.lock().unwrap().mode = "ok";
        gate.notify_one();
    };
    let (started, ()) = tokio::join!(auth.begin(signing::ID), control);
    let started = started.unwrap();
    f.arm(&started);
    // The token request is held open after consumption committed. The consumption checkout
    // has already gone back, so unrelated work again gets the only slot.
    f.h.script.lock().unwrap().mode = "gate-post";
    let control = async {
        f.h.entered(3).await;
        assert!(f.consumed(&started).await);
        backend(&pool).await;
        gate.notify_one();
    };
    let (credential, ()) = tokio::join!(auth.complete(signing::ID, callback(&started)), control);
    f.h.script.lock().unwrap().mode = "ok";
    auth.validate(credential.unwrap().expose()).await.unwrap();
    assert_eq!(posts(&f), 1);
    pool_state(&pool, 1, 1).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn cancellation_timeout_and_database_errors_replace_the_connection() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let pool = one_slot(f.db.options(API));
    let auth = service_over(&f, &pool);
    let mut observer = statistics_observer(&f.db).await;

    // 1. Cancellation. Issuance holds the login row lock and waits for the user row.
    let (started, proof) = f.exchanged(&p).await;
    let cancelled = backend(&pool).await;
    let mut held = f.owner.begin().await.unwrap();
    held.execute("SELECT id FROM openmettle.users FOR UPDATE")
        .await
        .unwrap();
    {
        let attempt = Box::pin(auth.issue(&p, proof));
        tokio::select! {
            result = attempt => panic!("issuance finished while the user row was held: {result:?}"),
            () = waiting(&mut observer, cancelled.0) => {},
        }
    }
    // The slot comes back as soon as SQLx has closed the socket, with a different backend,
    // although the cancelled backend is still blocked in its statement.
    let replacement = backend(&pool).await;
    assert_ne!(replacement, cancelled);
    // That backend leaves when its lock wait ends, here at the transaction's own lock
    // timeout, because the blocker is never released. Its login row lock goes with it.
    gone(&mut observer, &cancelled).await;
    sqlx::query("SELECT id FROM openmettle.login_transactions WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(locator(&started))
        .fetch_one(&mut *held)
        .await
        .expect("cancelled issuance must not keep the login row locked");
    held.rollback().await.unwrap();
    assert_eq!(sessions(&mut f).await, 0);
    assert!(!session_issued(&mut f, &started).await);

    // 2. Timeout. Validation waits for an approval row past the session operation deadline.
    let credential = issue(&mut f).await;
    let brief = service::browser_auth(
        &f.h,
        pool.clone(),
        Duration::from_secs(300),
        local::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(1)).unwrap(),
    );
    let timed_out = backend(&pool).await;
    assert_eq!(
        timed_out, replacement,
        "an ordinary query keeps the backend"
    );
    let mut held = f.owner.begin().await.unwrap();
    held.execute("SELECT id FROM openmettle.local_identity_approvals FOR UPDATE")
        .await
        .unwrap();
    let (result, ()) = tokio::join!(
        brief.validate(credential.expose()),
        waiting(&mut observer, timed_out.0)
    );
    assert_eq!(result.unwrap_err(), Error::Session(SessionError::Timeout));
    let replacement = backend(&pool).await;
    assert_ne!(replacement, timed_out);
    gone(&mut observer, &timed_out).await;
    held.rollback().await.unwrap();
    unlocked(
        &mut f.owner,
        &[
            "login_providers",
            "local_identity_approvals",
            "users",
            "local_sessions",
        ],
    )
    .await;
    auth.validate(credential.expose()).await.unwrap();
    assert_eq!(backend(&pool).await, replacement);

    // 3. Database error. The insert fails after the admission lock. Its rollback succeeds,
    // but a database error is never trusted for reuse.
    f.owner
        .execute("ALTER TABLE openmettle.login_transactions ADD CONSTRAINT inject_failure CHECK (false) NOT VALID")
        .await
        .unwrap();
    assert_eq!(
        auth.begin(signing::ID).await.unwrap_err(),
        Error::Login(login::Error::Database)
    );
    f.owner
        .execute("ALTER TABLE openmettle.login_transactions DROP CONSTRAINT inject_failure")
        .await
        .unwrap();
    let after_error = backend(&pool).await;
    assert_ne!(after_error, replacement);
    gone(&mut observer, &replacement).await;
    unlocked(&mut f.owner, &["login_admission", "login_transactions"]).await;

    // 4. Lost connection. The backend is terminated while issuance waits, so the statement
    // and the ROLLBACK that follows both fail: the cleanup-failure case of ADR 0014.
    let (started, proof) = f.exchanged(&p).await;
    let mut held = f.owner.begin().await.unwrap();
    held.execute("SELECT id FROM openmettle.users FOR UPDATE")
        .await
        .unwrap();
    let control = async {
        waiting(&mut observer, after_error.0).await;
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(after_error.0)
            .execute(&mut observer)
            .await
            .unwrap();
    };
    let (result, ()) = tokio::join!(auth.issue(&p, proof), control);
    assert_eq!(result.unwrap_err(), SessionError::Database);
    held.rollback().await.unwrap();
    let after_loss = backend(&pool).await;
    assert_ne!(after_loss, after_error);
    assert!(!session_issued(&mut f, &started).await);

    // No capacity was lost: the single slot still serves a complete login.
    let started = auth.begin(signing::ID).await.unwrap();
    f.arm(&started);
    auth.complete(signing::ID, callback(&started))
        .await
        .unwrap();
    assert_eq!(backend(&pool).await, after_loss);
    pool_state(&pool, 1, 1).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn withheld_commit_acknowledgement_returns_nothing_and_is_never_retried() {
    for stage in ["consume", "issue"] {
        let mut f = Flow::new().await;
        seed(&mut f, true, true).await;
        let p = f.h.provider.clone();
        let mut barrier = ResponseBarrier::new(b"COMMIT\0");
        // The proxy carries exactly one connection: the pool's first. Replacements connect
        // directly, as a new connection would in a deployment.
        let pool = one_slot(
            f.db.options(API)
                .host("127.0.0.1")
                .port(barrier.port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable),
        );
        let auth = service_over(&f, &pool);
        let proxied = backend(&pool).await;
        pool_state(&pool, 1, 1).await;
        pool.set_connect_options(f.db.options(API));
        let started = if stage == "consume" {
            let started = f.begin(&p).await;
            f.arm(&started);
            cancel_at_response(&mut barrier, auth.complete(signing::ID, callback(&started))).await;
            started
        } else {
            let (started, proof) = f.exchanged(&p).await;
            cancel_at_response(&mut barrier, auth.issue(&p, proof)).await;
            started
        };
        // The dropped checkout is closed, not returned: wait for SQLx to finish before the
        // proxy is joined.
        pool_state(&pool, 0, 0).await;
        drop(barrier);
        // The commit happened, the caller received nothing, and the code is never sent again.
        let requested = usize::from(stage == "issue");
        assert!(f.consumed(&started).await, "{stage}");
        assert_eq!(posts(&f), requested, "{stage}");
        assert_eq!(
            sessions(&mut f).await,
            i64::from(stage == "issue"),
            "{stage}"
        );
        assert_eq!(
            session_issued(&mut f, &started).await,
            stage == "issue",
            "{stage}"
        );
        assert_eq!(
            auth.complete(signing::ID, callback(&started))
                .await
                .unwrap_err(),
            Error::Login(login::Error::Rejected),
            "{stage}"
        );
        assert_eq!(posts(&f), requested, "{stage}");
        assert_ne!(backend(&pool).await, proxied, "{stage}");
        pool_state(&pool, 1, 1).await;
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn pool_waits_stay_inside_the_original_deadlines() {
    // 1. The only slot stays busy past the deadline: nothing is issued or written.
    let mut brief = policy();
    brief.deadline = Duration::from_millis(1500);
    let mut f = Flow::with(Harness::with_policy(brief).await).await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let pool = one_slot(f.db.options(API));
    let auth = service_over(&f, &pool);
    let first = backend(&pool).await;
    let (started, proof) = f.exchanged(&p).await;
    let original = proof.deadline;
    let before = (f.rows().await, reservations(&mut f).await);
    let slot = pool.acquire().await.unwrap();
    // Issuance waits only until the proof's original exchange deadline. The session
    // operation deadline (10 s) would allow far longer if the wait opened a new window.
    assert_eq!(
        auth.issue(&p, proof).await.unwrap_err(),
        SessionError::Timeout
    );
    let now = Instant::now();
    assert!(now >= original && now < original + Duration::from_secs(3));
    // Initiation waits only until the manager phase deadline.
    assert_eq!(
        auth.begin(signing::ID).await.unwrap_err(),
        Error::Login(login::Error::Rejected)
    );
    drop(slot);
    pool_state(&pool, 1, 1).await;
    assert_eq!(sessions(&mut f).await, 0);
    assert!(!session_issued(&mut f, &started).await);
    assert_eq!((f.rows().await, reservations(&mut f).await), before);
    // Neither attempt was ever lent the connection, so nothing was discarded.
    assert_eq!(backend(&pool).await, first);

    // 2. The slot frees inside the deadline but after the login's original expiry: the
    // primary clock refuses issuance.
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    let pool = one_slot(f.db.options(API));
    let auth = service_over(&f, &pool);
    let first = backend(&pool).await;
    let started = p
        .begin(&mut f.api, &keys(), Duration::from_secs(1))
        .await
        .unwrap();
    f.arm(&started);
    let permit = f.consume(&p, &started).await.unwrap();
    let proof = permit
        .exchange_with_keys(&p, &auth::Policy::default())
        .await
        .unwrap();
    let slot = pool.acquire().await.unwrap();
    let control = async {
        sqlx::query("SELECT pg_sleep(GREATEST(0, (expires_ms - floor(extract(epoch FROM clock_timestamp())*1000))/1000.0 + 0.02)) FROM openmettle.login_transactions WHERE id=$1")
            .bind(locator(&started))
            .execute(&mut f.owner)
            .await
            .unwrap();
        drop(slot);
    };
    let (result, ()) = tokio::join!(auth.issue(&p, proof), control);
    assert_eq!(result.unwrap_err(), SessionError::Rejected);
    assert_eq!(sessions(&mut f).await, 0);
    assert!(!session_issued(&mut f, &started).await);

    // 3. Configuration retired during the wait: validity is rechecked after the wait and
    // before any write, and the untouched checkout goes back to the pool.
    let before = (f.rows().await, reservations(&mut f).await);
    let slot = pool.acquire().await.unwrap();
    let control = async {
        // `join!` polls initiation first, so it is already waiting for the slot here.
        f.h.manager.retire(&p).unwrap();
        drop(slot);
    };
    let (result, ()) = tokio::join!(auth.begin(signing::ID), control);
    assert_eq!(result.unwrap_err(), Error::Login(login::Error::Rejected));
    assert_eq!((f.rows().await, reservations(&mut f).await), before);
    assert_eq!(backend(&pool).await, first);
    pool_state(&pool, 1, 1).await;
}
