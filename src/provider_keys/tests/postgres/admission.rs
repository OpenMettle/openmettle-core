//! Outstanding-login admission (ADR 0014) through the managed path. Isolated CI PostgreSQL 18
//! only. The fixture administrator is used solely to observe other roles' lock waits.
use super::sessions::{issue, seed, statistics_observer, waiting};
use super::*;
use crate::response_barrier::{ResponseBarrier, cancel_at_response};

const LIMIT_ROW: &str =
    "SELECT outstanding_limit FROM openmettle.login_admission WHERE id FOR UPDATE";

async fn reservations(c: &mut PgConnection) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM openmettle.login_nonce_reservations")
        .fetch_one(c)
        .await
        .unwrap()
}
async fn outstanding(c: &mut PgConnection) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM openmettle.login_transactions WHERE NOT session_issued AND expires_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
        .fetch_one(c)
        .await
        .unwrap()
}
async fn pid(c: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(c)
        .await
        .unwrap()
}
// Sleeps on the caller's own connection until the primary clock passes this login's expiry.
async fn sleep_past_expiry(c: &mut PgConnection, started: &Started) {
    sqlx::query("SELECT pg_sleep(GREATEST(0, (expires_ms - floor(extract(epoch FROM clock_timestamp())*1000))/1000.0 + 0.02)) FROM openmettle.login_transactions WHERE id=$1")
        .bind(locator(started))
        .execute(c)
        .await
        .unwrap();
}
// Owner holds the singleton exclusively, optionally changing the limit in the same transaction.
async fn hold_limit(owner: &mut PgConnection, limit: Option<Option<i32>>) {
    owner.execute("BEGIN").await.unwrap();
    owner.execute(LIMIT_ROW).await.unwrap();
    if let Some(limit) = limit {
        sqlx::query("UPDATE openmettle.login_admission SET outstanding_limit=$1,changed_by='fixture-owner',change_reason='synthetic lowered limit',changed_at=clock_timestamp() WHERE id")
            .bind(limit)
            .execute(&mut *owner)
            .await
            .unwrap();
    }
}
// Proves no idle connection still holds the singleton: a short bounded lock must succeed.
async fn limit_row_is_free(owner: &mut PgConnection) {
    owner.execute("BEGIN").await.unwrap();
    owner
        .execute("SET LOCAL lock_timeout = '100ms'")
        .await
        .unwrap();
    owner.execute(LIMIT_ROW).await.unwrap();
    owner.execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn unconfigured_full_and_retired_prechecks_spend_no_reservation() {
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    admit(&mut f.owner, None).await;
    let refused = async |f: &mut Flow, expected: login::Error, why: &str| {
        let before = (reservations(&mut f.api).await, f.rows().await);
        let error = p
            .begin(&mut f.api, &keys(), Duration::from_secs(60))
            .await
            .unwrap_err();
        assert_eq!(error, expected, "{why}");
        assert_eq!(
            (reservations(&mut f.api).await, f.rows().await),
            before,
            "{why}: no reservation or login row"
        );
        assert!(!f.api.is_in_transaction(), "{why}");
    };
    refused(&mut f, login::Error::Unconfigured, "NULL limit").await;
    admit(&mut f.owner, Some(1)).await;
    let first = f.begin(&p).await;
    refused(&mut f, login::Error::Capacity, "unconsumed row").await;
    // A fake-code callback consumes the row and spends one provider POST; the slot stays held.
    let permit = f.consume(&p, &first).await.unwrap();
    f.h.script.lock().unwrap().mode = "failure";
    assert!(
        permit
            .exchange_with_keys(&p, &auth::Policy::default())
            .await
            .is_err()
    );
    f.h.script.lock().unwrap().mode = "ok";
    assert!(f.consumed(&first).await);
    refused(&mut f, login::Error::Capacity, "consumed without session").await;
    // Retired authority is refused before any reservation, even with free capacity.
    admit(&mut f.owner, Some(8)).await;
    write(&mut f.owner, None).await;
    refused(&mut f, login::Error::Rejected, "retired provider").await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn issued_and_expired_rows_free_capacity() {
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let p = f.h.provider.clone();
    admit(&mut f.owner, Some(1)).await;
    issue(&mut f).await;
    assert_eq!(
        outstanding(&mut f.api).await,
        0,
        "issued row frees its slot"
    );
    admit(&mut f.owner, Some(2)).await;
    let short = p
        .begin(&mut f.api, &keys(), Duration::from_secs(1))
        .await
        .unwrap();
    f.begin(&p).await;
    assert_eq!(
        p.begin(&mut f.api, &keys(), Duration::from_secs(60))
            .await
            .unwrap_err(),
        login::Error::Capacity
    );
    sleep_past_expiry(&mut f.api, &short).await;
    f.begin(&p).await;
    assert_eq!(outstanding(&mut f.api).await, 2);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn last_slot_has_one_winner_and_loser_releases_admission_lock() {
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    admit(&mut f.owner, Some(2)).await;
    f.begin(&p).await;
    let mut a = f.db.connect(API).await;
    let mut b = f.db.connect(API).await;
    let (pa, pb) = (pid(&mut a).await, pid(&mut b).await);
    let mut observer = statistics_observer(&f.db).await;
    let before = reservations(&mut f.api).await;
    // Both attempts pass the advisory precheck and spend a reservation, then wait.
    hold_limit(&mut f.owner, None).await;
    let control = async {
        waiting(&mut observer, pa).await;
        waiting(&mut observer, pb).await;
        f.owner.execute("COMMIT").await.unwrap();
    };
    let ring = keys();
    let (ra, rb, ()) = tokio::join!(
        p.begin(&mut a, &ring, Duration::from_secs(60)),
        p.begin(&mut b, &ring, Duration::from_secs(60)),
        control
    );
    let errors: Vec<_> = [&ra, &rb]
        .into_iter()
        .filter_map(|r| r.as_ref().err().copied())
        .collect();
    assert_eq!(errors, [login::Error::Capacity], "exactly one winner");
    assert_eq!(outstanding(&mut f.api).await, 2, "never oversubscribed");
    assert_eq!(
        reservations(&mut f.api).await,
        before + 2,
        "the loser's reservation is spent permanently"
    );
    // The loser's connection stays idle: its returned error already released the lock.
    assert!(!a.is_in_transaction() && !b.is_in_transaction());
    limit_row_is_free(&mut f.owner).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn waiting_begin_reads_limit_and_primary_clock_after_lock() {
    let ring = keys();
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    let mut observer = statistics_observer(&f.db).await;
    // Limit lowered while waiting, outstanding row still live: refused after the wait.
    admit(&mut f.owner, Some(2)).await;
    f.begin(&p).await;
    let mut x = f.db.connect(API).await;
    let px = pid(&mut x).await;
    hold_limit(&mut f.owner, Some(Some(1))).await;
    let control = async {
        waiting(&mut observer, px).await;
        f.owner.execute("COMMIT").await.unwrap();
    };
    let (result, ()) = tokio::join!(p.begin(&mut x, &ring, Duration::from_secs(60)), control);
    assert_eq!(result.unwrap_err(), login::Error::Capacity);
    // Same lowered limit, but the outstanding row expires during the wait: the clock is
    // sampled after the lock, so the expired row no longer counts.
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    let mut observer = statistics_observer(&f.db).await;
    admit(&mut f.owner, Some(2)).await;
    let short = p
        .begin(&mut f.api, &keys(), Duration::from_secs(1))
        .await
        .unwrap();
    let mut x = f.db.connect(API).await;
    let px = pid(&mut x).await;
    hold_limit(&mut f.owner, Some(Some(1))).await;
    let control = async {
        waiting(&mut observer, px).await;
        sleep_past_expiry(&mut f.owner, &short).await;
        f.owner.execute("COMMIT").await.unwrap();
    };
    let (result, ()) = tokio::join!(p.begin(&mut x, &ring, Duration::from_secs(60)), control);
    result.unwrap();
    assert_eq!(outstanding(&mut f.api).await, 1);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn returned_errors_release_admission_and_login_row_locks() {
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    // The insert fails after the admission lock: the idle caller must not keep it.
    f.owner
        .execute("ALTER TABLE openmettle.login_transactions ADD CONSTRAINT inject_failure CHECK (false) NOT VALID")
        .await
        .unwrap();
    let mut x = f.db.connect(API).await;
    assert_eq!(
        p.begin(&mut x, &keys(), Duration::from_secs(60))
            .await
            .unwrap_err(),
        login::Error::Database
    );
    assert!(!x.is_in_transaction());
    limit_row_is_free(&mut f.owner).await;
    f.owner
        .execute("ALTER TABLE openmettle.login_transactions DROP CONSTRAINT inject_failure")
        .await
        .unwrap();
    // A wrong caller binding is rejected under the row lock; the lock is released on return.
    let started = f.begin(&p).await;
    let other = f.begin(&p).await;
    let mut wrong = callback(&started);
    wrong.caller_binding = other.caller_binding.expose();
    assert_eq!(
        p.consume(&mut x, &keys(), wrong).await.unwrap_err(),
        login::Error::Rejected
    );
    assert!(!x.is_in_transaction());
    let mut probe = f.db.connect(API).await;
    probe.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT id FROM openmettle.login_transactions WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(locator(&started))
        .fetch_one(&mut probe)
        .await
        .unwrap();
    probe.execute("ROLLBACK").await.unwrap();
    assert!(!f.consumed(&started).await);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn cancellation_and_ambiguous_commit_admission() {
    // Cancelled while waiting for the singleton: no login row, the reservation is spent.
    let ring = keys();
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    admit(&mut f.owner, Some(1)).await;
    let mut observer = statistics_observer(&f.db).await;
    let mut x = f.db.connect(API).await;
    let px = pid(&mut x).await;
    let before = reservations(&mut f.api).await;
    hold_limit(&mut f.owner, None).await;
    {
        let attempt = Box::pin(p.begin(&mut x, &ring, Duration::from_secs(60)));
        tokio::select! {
            _ = attempt => panic!("begin finished while the singleton was held"),
            () = waiting(&mut observer, px) => {},
        }
    }
    drop(x); // Uncertain: discard the connection.
    f.owner.execute("COMMIT").await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(px)
        .fetch_one(&mut observer)
        .await
        .unwrap()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.rows().await, 0);
    assert_eq!(reservations(&mut f.api).await, before + 1);
    // Cancelled at the login INSERT response: rolled back, the slot is free. Cancelled at the
    // insert COMMIT response: committed, so the slot stays held until the original expiry even
    // though the caller received nothing. The first match of each tag is the reservation's.
    for (command, committed) in [
        (b"INSERT 0 1\0".as_slice(), false),
        (b"COMMIT\0".as_slice(), true),
    ] {
        let mut f = Flow::new().await;
        let p = f.h.provider.clone();
        admit(&mut f.owner, Some(1)).await;
        let mut barrier = ResponseBarrier::nth(command, 2);
        let options =
            f.db.options(API)
                .host("127.0.0.1")
                .port(barrier.port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut cn = PgConnection::connect_with(&options).await.unwrap();
        cancel_at_response(
            &mut barrier,
            p.begin(&mut cn, &keys(), Duration::from_secs(60)),
        )
        .await;
        drop(cn);
        drop(barrier);
        assert_eq!(reservations(&mut f.api).await, 1);
        let next = p.begin(&mut f.api, &keys(), Duration::from_secs(60)).await;
        if committed {
            assert_eq!(next.unwrap_err(), login::Error::Capacity);
            assert_eq!(f.rows().await, 1);
        } else {
            next.unwrap();
            assert_eq!(f.rows().await, 1);
        }
    }
}
