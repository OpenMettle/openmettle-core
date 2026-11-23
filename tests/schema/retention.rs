//! ADR 0041 PR2a: the audited retention policy, the purge reference recheck and the deletion
//! journal on PostgreSQL 18, including races between real concurrent sessions. Identities,
//! payloads and limits are synthetic fixture values.
use super::storage::{
    account, assert_totals, code, configure, input, new_uuid, reserve, retention_grace, settle,
};
use super::*;
use openmettle_core::storage;

#[derive(Clone, Copy, Debug)]
enum Step {
    Retain,
    Restore,
    Claim,
    Confirm,
}

impl Step {
    /// Only the API retains and restores; only the worker claims and confirms purges.
    fn role(self) -> &'static str {
        match self {
            Step::Retain | Step::Restore => API,
            Step::Claim | Step::Confirm => WORKER,
        }
    }

    async fn run(self, tx: &mut WriteTransaction<'_>, scope: &str, rev: &str) -> Result<(), Error> {
        match self {
            Step::Retain => storage::retain_revision(tx, scope, rev).await.map(drop),
            Step::Restore => storage::restore_revision(tx, scope, rev).await,
            Step::Claim => storage::begin_purge(tx, scope, rev).await,
            Step::Confirm => storage::confirm_purge(tx, scope, rev).await,
        }
    }
}

/// One step in its own transaction. The result includes the commit, where the journal appends.
async fn step(db: &str, scope: &str, rev: &str, step: Step) -> Result<(), Error> {
    let mut cn = connect(db, step.role()).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let result = step.run(&mut tx, scope, rev).await;
    let committed = tx.commit().await;
    result.and(committed)
}

async fn pid(c: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(c)
        .await
        .unwrap()
}

struct Fixture {
    db: TestDb,
    c: Context,
}

impl Fixture {
    /// Storage limits, a pinned volume and zero grace: a retained revision is due at once.
    async fn new() -> Self {
        let db = TestDb::migrated().await;
        configure(&db, Some(100_000), Some(100_000), Some(100_000)).await;
        retention_grace(&db, 0).await;
        let c = Context::new(&db).await;
        Self { db, c }
    }

    /// A settled revision of `size` bytes, written by `run` when given.
    async fn revision(&self, key: &str, size: i64, run: Option<&str>) -> String {
        let doc = new_uuid(&self.db).await;
        let mut r = input(&self.c.scope, &self.c.actor, key, &doc, size);
        r.run = run;
        let reservation = reserve(&self.db, API, &r).await.unwrap();
        settle(
            &self.db,
            &self.c.scope,
            &reservation.id,
            size,
            key.as_bytes(),
            "text/plain",
        )
        .await
        .unwrap()
    }

    async fn step(&self, rev: &str, s: Step) -> Result<(), Error> {
        step(&self.db.0, &self.c.scope, rev, s).await
    }

    async fn state(&self, rev: &str) -> String {
        sqlx::query_scalar("SELECT state FROM openmettle.artifact_revisions WHERE id=$1::uuid")
            .bind(rev)
            .fetch_one(&mut self.db.admin().await)
            .await
            .unwrap()
    }

    async fn hold(&self, c: &mut PgConnection, rev: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO openmettle.artifact_retention_holds (scope_id, artifact_revision_id)
             VALUES ($1::uuid, $2::uuid)",
        )
        .bind(&self.c.scope)
        .bind(rev)
        .execute(c)
        .await
        .map(drop)
    }
}

/// Publishes, in the caller's transaction, a new conversation whose first user turn attaches
/// `revision`, as the branch writer does.
async fn attach(
    c: &mut PgConnection,
    scope: &str,
    actor: &str,
    rev: &str,
) -> Result<(), sqlx::Error> {
    let chat = conversation(c, scope, "personal", actor).await?;
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(&chat)
    .fetch_one(&mut *c)
    .await?;
    sqlx::query(
        "INSERT INTO openmettle.branch_heads (scope_id, conversation_id, branch_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid)",
    )
    .bind(scope)
    .bind(&chat)
    .bind(&branch)
    .execute(&mut *c)
    .await?;
    let turn = message(c, scope, &chat, None).await?;
    sqlx::query(
        "INSERT INTO openmettle.message_turns (scope_id, conversation_id, message_id, author_user_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)",
    )
    .bind(scope)
    .bind(&chat)
    .bind(&turn)
    .bind(actor)
    .execute(&mut *c)
    .await?;
    sqlx::query(
        "INSERT INTO openmettle.message_parts
         (scope_id, conversation_id, message_id, ordinal, kind, artifact_revision_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 0, 'attachment', $4::uuid)",
    )
    .bind(scope)
    .bind(&chat)
    .bind(&turn)
    .bind(rev)
    .execute(&mut *c)
    .await?;
    sqlx::query(
        "UPDATE openmettle.branch_heads SET head_message_id=$2::uuid WHERE branch_id=$1::uuid",
    )
    .bind(&branch)
    .bind(&turn)
    .execute(c)
    .await
    .map(drop)
}

async fn journal(db: &TestDb) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT entity_id::text FROM openmettle.deletion_journal ORDER BY journal_seq",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap()
}

type JournalRow = (
    i64,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    Vec<u8>,
    Option<i64>,
    Vec<u8>,
);

/// Recomputes every chain digest from the encoding migration 28 documents, checks the sequence
/// is gapless and the head names the last record.
async fn assert_chain(db: &TestDb) {
    let mut admin = db.admin().await;
    let rows: Vec<JournalRow> = sqlx::query_as(
        "SELECT journal_seq, event_kind, entity_id::text, scope_id::text,
                (extract(epoch FROM recorded_at) * 1000000)::bigint,
                (extract(epoch FROM original_purge_after) * 1000000)::bigint,
                (extract(epoch FROM purged_at) * 1000000)::bigint,
                content_digest, policy_revision, chain_digest
           FROM openmettle.deletion_journal ORDER BY journal_seq",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    let mut previous = vec![0u8; 32];
    for (index, (seq, kind, entity, scope, at, after, purged, content, policy, chain)) in
        rows.iter().enumerate()
    {
        assert_eq!(*seq, index as i64 + 1);
        let hex: String = content.iter().map(|b| format!("{b:02x}")).collect();
        let policy = policy.map(|p| p.to_string()).unwrap_or_default();
        let text = format!(
            "openmettle.deletion_journal/1|{seq}|{kind}|{entity}|{scope}|{at}|{after}|{purged}|{hex}|{policy}"
        );
        let digest = Sha256::new()
            .chain_update(&previous)
            .chain_update(text.as_bytes())
            .finalize()
            .to_vec();
        assert_eq!(&digest, chain, "journal_seq {seq}");
        previous = digest;
    }
    let head: (i64, Vec<u8>) =
        sqlx::query_as("SELECT journal_seq, chain_digest FROM openmettle.deletion_journal_head")
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert_eq!(head, (rows.len() as i64, previous));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn retention_policy_changes_are_bounded_audited_and_stamped() {
    let db = TestDb::migrated().await;
    configure(&db, Some(1000), Some(1000), Some(1000)).await;
    let c = Context::new(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    let mut api = connect(&db.0, API).await;
    let policy = "SELECT revision, grace_seconds, min_grace_seconds, max_grace_seconds
        FROM openmettle.retention_policy";
    let read = async |c: &mut PgConnection| -> (i64, i32, i32, i32) {
        sqlx::query_as(policy).fetch_one(c).await.unwrap()
    };
    assert_eq!(read(&mut api).await, (1, 2_592_000, 2_592_000, 2_592_000));
    // Application roles change the policy only through the audited function.
    let direct = sqlx::query("UPDATE openmettle.retention_policy SET grace_seconds = 0")
        .execute(&mut api)
        .await;
    assert_eq!(sqlstate(direct), "42501");
    assert_eq!(
        sqlstate(
            sqlx::query(policy)
                .fetch_one(&mut connect(&db.0, WORKER).await)
                .await
        ),
        "42501"
    );
    let admin = new_user(&mut api).await;
    sqlx::query("INSERT INTO openmettle.account_admins (user_id, active) VALUES ($1::uuid, true)")
        .bind(&admin)
        .execute(&mut owner)
        .await
        .unwrap();
    let set = "SELECT openmettle.retention_set_grace($1::uuid, $2, 'synthetic reason', $3)";
    let change = async |actor: &str, grace: i32, key: &str| -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(set)
            .bind(actor)
            .bind(grace)
            .bind(key)
            .fetch_one(&mut connect(&db.0, API).await)
            .await
    };
    assert_eq!(
        sqlstate(change(&c.actor, 2_592_000, "not-admin").await),
        "42501"
    );
    // The default deployment bounds admit only 30 days.
    assert_eq!(sqlstate(change(&admin, 86_400, "narrow").await), "23514");
    sqlx::query("UPDATE openmettle.retention_policy SET min_grace_seconds = 0, max_grace_seconds = 31536000")
        .execute(&mut owner)
        .await
        .unwrap();
    assert_eq!(read(&mut api).await, (2, 2_592_000, 0, 31_536_000));
    assert_eq!(change(&admin, 3600, "hour").await.unwrap(), 3);
    let audit: (String, String, String, String, String) = sqlx::query_as(
        "SELECT action, target_kind, request_key, reason, details::text
           FROM openmettle.authorization_audit WHERE actor_user_id = $1::uuid",
    )
    .bind(&admin)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        (audit.0, audit.1, audit.2, audit.3),
        (
            "retention.policy_update".into(),
            "retention_policy".into(),
            "hour".into(),
            "synthetic reason".into()
        )
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&audit.4).unwrap(),
        serde_json::json!({"old_grace_seconds": 2_592_000, "new_grace_seconds": 3600, "revision": 3})
    );
    // A reused request key changes nothing.
    assert_eq!(sqlstate(change(&admin, 60, "hour").await), "23505");
    assert_eq!(read(&mut api).await, (3, 3600, 0, 31_536_000));

    // Disassociation applies and stamps the current revision; restore clears the stamp.
    let doc = new_uuid(&db).await;
    let r = reserve(&db, API, &input(&c.scope, &c.actor, "stamped", &doc, 10))
        .await
        .unwrap();
    let rev = settle(&db, &c.scope, &r.id, 10, b"stamped", "text/plain")
        .await
        .unwrap();
    step(&db.0, &c.scope, &rev, Step::Retain).await.unwrap();
    let stamp =
        "SELECT extract(epoch FROM purge_after - retained_at)::bigint, retention_policy_revision
        FROM openmettle.artifact_revisions WHERE id = $1::uuid";
    let stamped: (Option<i64>, Option<i64>) = sqlx::query_as(stamp)
        .bind(&rev)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(stamped, (Some(3600), Some(3)));
    step(&db.0, &c.scope, &rev, Step::Restore).await.unwrap();
    let cleared: (Option<i64>, Option<i64>) = sqlx::query_as(stamp)
        .bind(&rev)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(cleared, (None, None));
    assert_totals(&db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn expiry_boundaries_admit_zero_grace_and_the_exact_deadline() {
    let f = Fixture::new().await;
    let exact = f.revision("exact", 10, None).await;
    let early = f.revision("early", 10, None).await;
    // One owner transaction has one now(): grace 0 makes purge_after = retained_at = now(), and
    // a claim at now() == purge_after is due.
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut tx = WriteTransaction::begin(&mut owner).await.unwrap();
    storage::retain_revision(&mut tx, &f.c.scope, &exact)
        .await
        .unwrap();
    storage::begin_purge(&mut tx, &f.c.scope, &exact)
        .await
        .unwrap();
    let times: (bool, bool) = sqlx::query_as(
        "SELECT purge_after = retained_at, purging_at = purge_after
           FROM openmettle.artifact_revisions WHERE id = $1::uuid",
    )
    .bind(&exact)
    .fetch_one(tx.connection().unwrap())
    .await
    .unwrap();
    assert_eq!(times, (true, true));
    // One microsecond before its deadline a revision is not due.
    storage::retain_revision(&mut tx, &f.c.scope, &early)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.artifact_revisions SET purge_after = purge_after + interval '1 microsecond'
          WHERE id = $1::uuid",
    )
    .bind(&early)
    .execute(tx.connection().unwrap())
    .await
    .unwrap();
    assert!(matches!(
        storage::begin_purge(&mut tx, &f.c.scope, &early).await,
        Err(Error::NotEligible)
    ));
    tx.commit().await.unwrap();
    assert_eq!(f.state(&early).await, "retained");
    f.step(&exact, Step::Confirm).await.unwrap();
    // A zero-grace removal by the API is due to the worker's next transaction.
    f.step(&early, Step::Claim).await.unwrap();
    f.step(&early, Step::Confirm).await.unwrap();
    assert_eq!(journal(&f.db).await, [exact, early]);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 0));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn purge_recheck_defers_attachments_holds_and_unfinished_runs() {
    let f = Fixture::new().await;
    let mut api = connect(&f.db.0, API).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut worker = connect(&f.db.0, WORKER).await;

    // An attachment keeps a removed revision from purge, also against a direct claim.
    let attached = f.revision("attached", 10, None).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    attach(tx.connection().unwrap(), &f.c.scope, &f.c.actor, &attached)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    f.step(&attached, Step::Retain).await.unwrap();
    assert!(matches!(
        f.step(&attached, Step::Claim).await,
        Err(Error::NotEligible)
    ));
    let direct = sqlx::query(
        "UPDATE openmettle.artifact_revisions SET state = 'purging', purging_at = now() WHERE id = $1::uuid",
    )
    .bind(&attached)
    .execute(&mut worker)
    .await;
    assert_eq!(sqlstate(direct), "OMR01");
    // A retained revision accepts no new attachment.
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let refused = attach(tx.connection().unwrap(), &f.c.scope, &f.c.actor, &attached).await;
    assert_eq!(sqlstate(refused), "OMR01");
    tx.rollback().await.unwrap();

    // An operator hold defers the claim until released.
    let held = f.revision("held", 20, None).await;
    f.step(&held, Step::Retain).await.unwrap();
    f.hold(&mut owner, &held).await.unwrap();
    assert!(matches!(
        f.step(&held, Step::Claim).await,
        Err(Error::NotEligible)
    ));
    sqlx::query(
        "DELETE FROM openmettle.artifact_retention_holds WHERE artifact_revision_id = $1::uuid",
    )
    .bind(&held)
    .execute(&mut owner)
    .await
    .unwrap();
    f.step(&held, Step::Claim).await.unwrap();

    // The writing run defers the claim while unfinished, then while one of its operations has
    // no known outcome.
    let run = f.c.run(&f.db, "writer").await;
    let spilled = f.revision("spilled", 30, Some(&run)).await;
    f.step(&spilled, Step::Retain).await.unwrap();
    assert!(matches!(
        f.step(&spilled, Step::Claim).await,
        Err(Error::NotEligible)
    ));
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let op = runs::record_intent(&mut tx, &intent(&f.c, &run))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE openmettle.runs SET state = 'succeeded' WHERE id = $1::uuid")
        .bind(&run)
        .execute(&mut owner)
        .await
        .unwrap();
    assert!(matches!(
        f.step(&spilled, Step::Claim).await,
        Err(Error::NotEligible)
    ));
    sqlx::query(
        "UPDATE openmettle.operations SET outcome = 'failed', revision = 1,
             observation_format = 'fixture', observation_version = 1, evidence = '\\x01'
          WHERE id = $1::uuid",
    )
    .bind(&op)
    .execute(&mut owner)
    .await
    .unwrap();
    // The recheck needs READ COMMITTED to see other sessions' commits.
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(tx.connection().unwrap())
        .await
        .unwrap();
    let refused = storage::begin_purge(&mut tx, &f.c.scope, &spilled).await;
    assert_eq!(code(&refused.unwrap_err()), "25000");
    tx.rollback().await.unwrap();
    f.step(&spilled, Step::Claim).await.unwrap();

    assert_eq!(
        (
            f.state(&attached).await,
            f.state(&held).await,
            f.state(&spilled).await
        ),
        ("retained".into(), "purging".into(), "purging".into())
    );
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 60, 0));
    assert!(journal(&f.db).await.is_empty());
    // Break-glass erasure: the owner may claim a referenced revision; the purge is journaled.
    sqlx::query(
        "UPDATE openmettle.artifact_revisions SET state = 'purging', purging_at = now() WHERE id = $1::uuid",
    )
    .bind(&attached)
    .execute(&mut owner)
    .await
    .unwrap();
    f.step(&attached, Step::Confirm).await.unwrap();
    assert_eq!(journal(&f.db).await, [attached]);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 50, 0));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn concurrent_references_and_restores_collide_with_the_purge_claim() {
    let f = Fixture::new().await;
    let db = f.db.0.clone();
    let scope = f.c.scope.clone();

    // A hold in flight: the claim waits for it, then its recheck sees it.
    let rev = f.revision("hold-first", 10, None).await;
    f.step(&rev, Step::Retain).await.unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    let holder = pid(&mut owner).await;
    let mut tx = WriteTransaction::begin(&mut owner).await.unwrap();
    f.hold(tx.connection().unwrap(), &rev).await.unwrap();
    let claim = tokio::spawn({
        let (db, scope, rev) = (db.clone(), scope.clone(), rev.clone());
        async move { step(&db, &scope, &rev, Step::Claim).await }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    tx.commit().await.unwrap();
    assert!(matches!(claim.await.unwrap(), Err(Error::NotEligible)));
    assert_eq!(f.state(&rev).await, "retained");

    // A claim in flight: a hold (which a retained revision would accept) or an attachment waits
    // for it, then fails on 'purging' instead of acting on the state committed before it.
    let mut worker = connect(&f.db.0, WORKER).await;
    let claimer = pid(&mut worker).await;
    for attachment in [false, true] {
        let rev = f
            .revision(&format!("claim-first-{attachment}"), 10, None)
            .await;
        f.step(&rev, Step::Retain).await.unwrap();
        let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
        storage::begin_purge(&mut tx, &scope, &rev).await.unwrap();
        let reference = tokio::spawn({
            let (db, scope, actor, rev) =
                (db.clone(), scope.clone(), f.c.actor.clone(), rev.clone());
            async move {
                if attachment {
                    let mut api = connect(&db, API).await;
                    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
                    let attached = attach(tx.connection().unwrap(), &scope, &actor, &rev).await;
                    tx.rollback().await.unwrap();
                    attached
                } else {
                    sqlx::query(
                        "INSERT INTO openmettle.artifact_retention_holds
                         (scope_id, artifact_revision_id) VALUES ($1::uuid, $2::uuid)",
                    )
                    .bind(&scope)
                    .bind(&rev)
                    .execute(&mut connect(&db, OWNER).await)
                    .await
                    .map(drop)
                }
            }
        });
        wait_for_blocked_peer(&f.db, claimer).await;
        tx.commit().await.unwrap();
        assert_eq!(
            sqlstate(reference.await.unwrap()),
            "OMR01",
            "attachment {attachment}"
        );
        assert_eq!(f.state(&rev).await, "purging");
    }

    // An attachment in flight on a live revision: removal waits for it, so the claim sees it.
    let rev = f.revision("attach-first", 10, None).await;
    let mut api = connect(&f.db.0, API).await;
    let attacher = pid(&mut api).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    attach(tx.connection().unwrap(), &scope, &f.c.actor, &rev)
        .await
        .unwrap();
    let retain = tokio::spawn({
        let (db, scope, rev) = (db.clone(), scope.clone(), rev.clone());
        async move { step(&db, &scope, &rev, Step::Retain).await }
    });
    wait_for_blocked_peer(&f.db, attacher).await;
    tx.commit().await.unwrap();
    retain.await.unwrap().unwrap();
    assert!(matches!(
        f.step(&rev, Step::Claim).await,
        Err(Error::NotEligible)
    ));

    // Restore and claim at the deadline: the restore transaction started a microsecond before
    // purge_after and the claim after it, so each passes its own time check. Whichever locks
    // the revision first wins; the other sees the committed state and is refused.
    let deadline_after = async |rev: &str, now: String| {
        sqlx::query(
            "UPDATE openmettle.artifact_revisions
                SET purge_after = $2::timestamptz + interval '1 microsecond' WHERE id = $1::uuid",
        )
        .bind(rev)
        .bind(now)
        .execute(&mut f.db.admin().await)
        .await
        .unwrap();
    };
    let now = "SELECT now()::text";
    // The restore holds the revision: the claim waits, then sees it active.
    let rev = f.revision("restore-first", 10, None).await;
    f.step(&rev, Step::Retain).await.unwrap();
    let mut api = connect(&f.db.0, API).await;
    let restorer = pid(&mut api).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let started = sqlx::query_scalar(now)
        .fetch_one(tx.connection().unwrap())
        .await
        .unwrap();
    deadline_after(&rev, started).await;
    storage::restore_revision(&mut tx, &scope, &rev)
        .await
        .unwrap();
    let claim = tokio::spawn({
        let (db, scope, rev) = (db.clone(), scope.clone(), rev.clone());
        async move { step(&db, &scope, &rev, Step::Claim).await }
    });
    wait_for_blocked_peer(&f.db, restorer).await;
    tx.commit().await.unwrap();
    assert!(matches!(claim.await.unwrap(), Err(Error::NotEligible)));
    assert_eq!(f.state(&rev).await, "active");
    // The claim holds the revision: the restore, begun before the deadline, waits and is refused.
    let rev = f.revision("claim-before-restore", 10, None).await;
    f.step(&rev, Step::Retain).await.unwrap();
    let (started, start) = tokio::sync::oneshot::channel::<String>();
    let (go, proceed) = tokio::sync::oneshot::channel::<()>();
    let restore = tokio::spawn({
        let (db, scope, rev) = (db.clone(), scope.clone(), rev.clone());
        async move {
            let mut api = connect(&db, API).await;
            let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
            started
                .send(
                    sqlx::query_scalar(now)
                        .fetch_one(tx.connection().unwrap())
                        .await
                        .unwrap(),
                )
                .unwrap();
            proceed.await.unwrap();
            let result = storage::restore_revision(&mut tx, &scope, &rev).await;
            tx.commit().await.unwrap();
            result
        }
    });
    deadline_after(&rev, start.await.unwrap()).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::begin_purge(&mut tx, &scope, &rev).await.unwrap();
    go.send(()).unwrap();
    wait_for_blocked_peer(&f.db, claimer).await;
    tx.commit().await.unwrap();
    assert!(matches!(restore.await.unwrap(), Err(Error::NotEligible)));
    assert_eq!(f.state(&rev).await, "purging");
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn confirm_purge_journals_exactly_once_across_retries_duplicates_and_rollbacks() {
    let f = Fixture::new().await;
    let first = f.revision("first", 30, None).await;
    f.step(&first, Step::Retain).await.unwrap();
    f.step(&first, Step::Claim).await.unwrap();
    // A worker that dies before committing its confirmation leaves the purge and charge intact.
    let mut worker = connect(&f.db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::confirm_purge(&mut tx, &f.c.scope, &first)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(f.state(&first).await, "purging");
    assert!(journal(&f.db).await.is_empty());
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 30, 0));
    // Its replacement repeats the claim and confirms once; later retries change nothing.
    f.step(&first, Step::Claim).await.unwrap();
    f.step(&first, Step::Confirm).await.unwrap();
    for retry in [Step::Confirm, Step::Claim, Step::Confirm] {
        f.step(&first, retry).await.unwrap();
    }
    assert_eq!(journal(&f.db).await, std::slice::from_ref(&first));
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 0));

    // Two workers confirming the same revision concurrently release and journal it once.
    let second = f.revision("second", 20, None).await;
    f.step(&second, Step::Retain).await.unwrap();
    f.step(&second, Step::Claim).await.unwrap();
    let holder = pid(&mut worker).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::confirm_purge(&mut tx, &f.c.scope, &second)
        .await
        .unwrap();
    let duplicate = tokio::spawn({
        let (db, scope, rev) = (f.db.0.clone(), f.c.scope.clone(), second.clone());
        async move { step(&db, &scope, &rev, Step::Confirm).await }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    tx.commit().await.unwrap();
    duplicate.await.unwrap().unwrap();
    assert_eq!(journal(&f.db).await, [first.clone(), second.clone()]);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 0));
    let entry: (String, String, Option<i64>, bool, bool) = sqlx::query_as(
        "SELECT j.event_kind, j.scope_id::text, j.policy_revision,
                j.content_digest = r.content_digest,
                (j.original_purge_after, j.purged_at) = (r.purge_after, r.purged_at)
           FROM openmettle.deletion_journal j JOIN openmettle.artifact_revisions r ON r.id = j.entity_id
          WHERE j.entity_id = $1::uuid",
    )
    .bind(&second)
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    assert_eq!(
        entry,
        (
            "artifact_revision.purged".into(),
            f.c.scope.clone(),
            Some(2),
            true,
            true
        )
    );
    assert_chain(&f.db).await;

    // No application role can read, append, rewrite or remove journal records.
    for role in [API, WORKER, ISSUANCE, crate::pg::GATEWAY] {
        let mut c = connect(&f.db.0, role).await;
        for table in ["deletion_journal", "deletion_journal_head"] {
            for sql in [
                format!("SELECT FROM openmettle.{table}"),
                format!("UPDATE openmettle.{table} SET journal_seq = journal_seq"),
                format!("DELETE FROM openmettle.{table}"),
                format!("TRUNCATE openmettle.{table}"),
            ] {
                let result = sqlx::query(AssertSqlSafe(sql.clone()))
                    .execute(&mut c)
                    .await;
                assert_eq!(sqlstate(result), "42501", "{role}: {sql}");
            }
        }
        let insert = sqlx::query(
            "INSERT INTO openmettle.deletion_journal SELECT journal_seq + 1, recorded_at, event_kind,
                 gen_random_uuid(), scope_id, original_purge_after, purged_at, content_digest,
                 policy_revision, chain_digest FROM openmettle.deletion_journal",
        )
        .execute(&mut c)
        .await;
        assert_eq!(sqlstate(insert), "42501", "{role}");
    }
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn purge_fails_closed_while_the_volume_is_being_adopted() {
    let f = Fixture::new().await;
    let rev = f.revision("adoption", 40, None).await;
    f.step(&rev, Step::Retain).await.unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    let adopting = async |c: &mut PgConnection, on: bool| {
        sqlx::query(
            "UPDATE openmettle.storage_volume_control
                SET adoption_run_id = CASE WHEN $1 THEN gen_random_uuid() END WHERE id",
        )
        .bind(on)
        .execute(c)
        .await
        .unwrap();
    };
    adopting(&mut owner, true).await;
    assert_eq!(code(&f.step(&rev, Step::Claim).await.unwrap_err()), "OMQ03");
    assert_eq!(f.state(&rev).await, "retained");
    adopting(&mut owner, false).await;
    f.step(&rev, Step::Claim).await.unwrap();
    adopting(&mut owner, true).await;
    assert_eq!(
        code(&f.step(&rev, Step::Confirm).await.unwrap_err()),
        "OMQ03"
    );
    assert_eq!(f.state(&rev).await, "purging");
    assert!(journal(&f.db).await.is_empty());
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 40, 0));
    adopting(&mut owner, false).await;
    f.step(&rev, Step::Confirm).await.unwrap();
    assert_eq!(journal(&f.db).await, [rev]);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 0));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn schema_27_retained_revisions_purge_after_the_upgrade_with_a_journal_record() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..27]).await.unwrap();
    configure(&db, Some(1000), Some(1000), Some(1000)).await;
    let c = Context::new(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    let mut revisions = Vec::new();
    for key in ["legacy-free", "legacy-attached"] {
        let doc = new_uuid(&db).await;
        let r = reserve(&db, API, &input(&c.scope, &c.actor, key, &doc, 10))
            .await
            .unwrap();
        let rev = settle(&db, &c.scope, &r.id, 10, key.as_bytes(), "text/plain")
            .await
            .unwrap();
        if key == "legacy-attached" {
            let mut api = connect(&db.0, API).await;
            let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
            attach(tx.connection().unwrap(), &c.scope, &c.actor, &rev)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        // A removal by the previous release: no policy revision, an elapsed deadline.
        let mut tx = WriteTransaction::begin(&mut owner).await.unwrap();
        for sql in [
            "UPDATE openmettle.artifact_revisions SET state = 'retained',
                 retained_at = now() - interval '2 days', purge_after = now() - interval '1 day'
              WHERE id = $1::uuid",
            "UPDATE openmettle.storage_accounts a SET active_bytes = active_bytes - 10,
                 retained_bytes = retained_bytes + 10 FROM openmettle.artifact_revisions r
              WHERE r.id = $1::uuid AND a.scope_id = r.scope_id",
            "UPDATE openmettle.storage_instance SET active_bytes = active_bytes - 10,
                 retained_bytes = retained_bytes + 10 WHERE $1::uuid IS NOT NULL",
        ] {
            sqlx::query(sql)
                .bind(&rev)
                .execute(tx.connection().unwrap())
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        revisions.push(rev);
    }
    assert_totals(&db).await;

    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());
    let head: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT revision FROM openmettle.retention_policy),
                (SELECT journal_seq FROM openmettle.deletion_journal_head)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(head, (1, 0));
    let [free, attached] = &revisions[..] else {
        unreachable!()
    };
    // The upgrade adds no reference exemption for rows written before it.
    assert!(matches!(
        step(&db.0, &c.scope, attached, Step::Claim).await,
        Err(Error::NotEligible)
    ));
    step(&db.0, &c.scope, free, Step::Claim).await.unwrap();
    step(&db.0, &c.scope, free, Step::Confirm).await.unwrap();
    let recorded: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT entity_id::text, policy_revision FROM openmettle.deletion_journal")
            .fetch_all(&mut owner)
            .await
            .unwrap();
    assert_eq!(recorded, [(free.clone(), None)]);
    assert_chain(&db).await;
    assert_eq!(account(&db, &c.scope).await, (0, 10, 0));
    assert_totals(&db).await;
}
