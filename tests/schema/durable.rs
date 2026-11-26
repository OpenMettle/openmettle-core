//! Uses the existing isolated database/role fixture and the real persistence helpers.
use super::*;
use openmettle_core::runs::{
    self, Error, Intent, Observation, Payload, RunInput, WriteTransaction,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct Context {
    scope: String,
    actor: String,
    conversation: String,
    branch: String,
    message: String,
}
impl Context {
    async fn new(db: &TestDb) -> Self {
        let mut c = connect(&db.0, API).await;
        let actor = new_user(&mut c).await;
        let scope = personal_scope(&mut c, &actor).await;
        let conversation = conversation(&mut c, &scope, "personal", &actor)
            .await
            .unwrap();
        let message = message(&mut c, &scope, &conversation, None).await.unwrap();
        let branch = sqlx::query_scalar("INSERT INTO openmettle.conversation_branches(scope_id,conversation_id,fork_message_id) VALUES
             ($1::uuid,$2::uuid,$3::uuid) RETURNING id::text")
            .bind(&scope).bind(&conversation).bind(&message).fetch_one(&mut c).await.unwrap();
        Self {
            scope,
            actor,
            conversation,
            branch,
            message,
        }
    }
    fn input<'a>(&'a self, key: &'a str) -> RunInput<'a> {
        RunInput {
            scope: &self.scope,
            actor: &self.actor,
            conversation: &self.conversation,
            branch: &self.branch,
            message: &self.message,
            key,
            format: "fixture",
            version: 1,
            input: b"input",
            config: b"configuration",
        }
    }
    async fn run(&self, db: &TestDb, key: &str) -> String {
        let mut c = connect(&db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        let run = runs::create_run(&mut tx, &self.input(key)).await.unwrap();
        tx.commit().await.unwrap();
        run
    }
}
fn payload(bytes: &[u8]) -> Payload<'_> {
    Payload {
        format: "fixture",
        version: 1,
        bytes,
    }
}
fn intent<'a>(c: &'a Context, run: &'a str) -> Intent<'a> {
    Intent {
        scope: &c.scope,
        run,
        key: "step-1",
        target: "synthetic-backend",
        capability: "lookup",
        request: payload(b"request"),
    }
}
async fn count(db: &TestDb, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic OLD_BINARY_DIR required"]
async fn populated_v2_upgrade_and_authentic_old_binaries() {
    let db = TestDb::new().await;
    let old = std::path::PathBuf::from(
        std::env::var("OLD_BINARY_DIR").expect("build released 18f5246 binaries first"),
    );
    let old_migrate = || {
        let c = migrate_command(&db.url(OWNER), &[]); // retain sanitized environment
        let mut old_cmd = Command::new(old.join("openmettle-migrate"));
        for (k, v) in c.get_envs() {
            match v {
                Some(v) => {
                    old_cmd.env(k, v);
                }
                None => {
                    old_cmd.env_remove(k);
                }
            }
        }
        run_cli(&mut old_cmd, "old openmettle-migrate (v2)")
    };
    let output = old_migrate();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(db.history().await, [1, 2]);
    let mut api = connect(&db.0, API).await;
    let user = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &user).await;
    let (_, ps) = project(&mut api, &user).await;
    for (s, k) in [(&scope, "personal"), (&ps, "project")] {
        let chat = conversation(&mut api, s, k, &user).await.unwrap();
        let root = message(&mut api, s, &chat, None).await.unwrap();
        message(&mut api, s, &chat, Some(&root)).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO openmettle.user_identities(user_id,issuer,subject) VALUES
             ($1::uuid,'https://issuer.example.test','fixture')",
    )
    .bind(&user)
    .execute(&mut api)
    .await
    .unwrap();
    let tables = [
        "users",
        "user_identities",
        "scopes",
        "projects",
        "conversations",
        "messages",
    ];
    let before = snapshot(&mut api, &tables).await;
    let history: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(snapshot(&mut api, &tables).await, before);
    let old_history: Vec<String> = sqlx::query_scalar(
        "SELECT t::text FROM openmettle._sqlx_migrations t WHERE version <= 2 ORDER BY version",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(old_history, history);
    let full: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    let after_old = old_migrate();
    assert_eq!(after_old.status.code(), Some(1));
    assert!(stderr(&after_old).contains("boundary check refused"));
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let after: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    assert_eq!(full, after);
    // Prior runtime processes never invoke the newer validator or migrations.
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
        assert!(
            stop_process(&mut process, "-TERM", &format!("old {name} shutdown (v2)")).success()
        );
    }
    assert_eq!(snapshot(&mut api, &tables).await, before);
    // Existing v2 writes still work after the upgrade.
    let chat = conversation(&mut api, &scope, "personal", &user)
        .await
        .unwrap();
    message(&mut api, &scope, &chat, None).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn duplicate_run_identity_and_savepoint_failures() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(6));
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let c = c.clone();
        let b = barrier.clone();
        let opts = role_options(&db.0, API);
        tasks.push(tokio::spawn(async move {
            let mut cn = PgConnection::connect_with(&opts).await.unwrap();
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            b.wait().await;
            let id = runs::create_run(&mut tx, &c.input("same")).await.unwrap();
            tx.commit().await.unwrap();
            id
        }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    assert!(ids.iter().all(|id| id == &ids[0]));
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let mut changed = c.input("same");
    changed.config = b"changed";
    assert!(matches!(
        runs::create_run(&mut tx, &changed).await,
        Err(Error::Conflict)
    ));
    // Caller can commit after a recoverable error, without partial helper writes.
    tx.commit().await.unwrap();
    assert_eq!(count(&db, "SELECT count(*) FROM openmettle.runs").await, 1);
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.run_events").await,
        1
    );
    let other = Context::new(&db).await;
    assert_ne!(other.run(&db, "same").await, ids[0]);
    let mut input = c.input("same");
    input.actor = &other.actor;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    assert_ne!(runs::create_run(&mut tx, &input).await.unwrap(), ids[0]);
    tx.commit().await.unwrap();
    // Failure after run INSERT, while appending its initial event, rolls back the run.
    let mut admin = db.admin().await;
    admin.execute("ALTER TABLE openmettle.run_events ADD CONSTRAINT fixture_failure CHECK (append_key <> 'run-created') NOT VALID").await.unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    assert!(matches!(
        runs::create_run(&mut tx, &c.input("failed")).await,
        Err(Error::Database(_))
    ));
    tx.commit().await.unwrap();
    admin
        .execute("ALTER TABLE openmettle.run_events DROP CONSTRAINT fixture_failure")
        .await
        .unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM openmettle.runs WHERE idempotency_key='failed'"
        )
        .await,
        0
    );
    // Caller-owned message+run transaction: no orphan after explicit outer rollback.
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let msg = message(
        tx.connection().unwrap(),
        &c.scope,
        &c.conversation,
        Some(&c.message),
    )
    .await
    .unwrap();
    let mut input = c.input("rollback");
    input.message = &msg;
    runs::create_run(&mut tx, &input).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM openmettle.runs WHERE idempotency_key='rollback'"
        )
        .await,
        0
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.messages WHERE id=$1::uuid")
        .bind(msg)
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(n, 0);
    // Forged supplied digest cannot turn changed actual stored columns into a replay.
    sqlx::query("UPDATE openmettle.runs SET config_snapshot='forged'::bytea WHERE id=$1::uuid")
        .bind(&ids[0])
        .execute(&mut admin)
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    assert!(matches!(
        runs::create_run(&mut tx, &c.input("same")).await,
        Err(Error::Conflict)
    ));
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn event_commit_order_rollback_disconnect_and_replay() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "one").await;
    let other = c.run(&db, "other").await;
    let mut first = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut first).await.unwrap();
    assert_eq!(
        runs::append_event(&mut tx, &c.scope, &run, "a", payload(b"a"))
            .await
            .unwrap(),
        2
    );
    let mut second = connect(&db.0, WORKER).await;
    let mut later = WriteTransaction::begin(&mut second).await.unwrap();
    let mut pending = Box::pin(runs::append_event(
        &mut later,
        &c.scope,
        &run,
        "b",
        payload(b"b"),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut pending)
            .await
            .is_err()
    );
    assert_eq!(
        count(&db, "SELECT max(sequence) FROM openmettle.run_events").await,
        1
    );
    let mut independent = connect(&db.0, API).await;
    let mut separate = WriteTransaction::begin(&mut independent).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        runs::append_event(
            &mut separate,
            &c.scope,
            &other,
            "independent",
            payload(b"x"),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    separate.commit().await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(pending.await.unwrap(), 2);
    later.commit().await.unwrap();
    // Uncommitted connection loss also returns the counter to its committed value.
    let mut lost = connect(&db.0, WORKER).await;
    let mut lost_tx = WriteTransaction::begin(&mut lost).await.unwrap();
    assert_eq!(
        runs::append_event(&mut lost_tx, &c.scope, &run, "lost", payload(b"lost"))
            .await
            .unwrap(),
        3
    );
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(lost_tx.connection().unwrap())
        .await
        .unwrap();
    sqlx::query("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .execute(&mut db.admin().await)
        .await
        .unwrap();
    drop(lost_tx);
    drop(lost);
    let mut tx = WriteTransaction::begin(&mut second).await.unwrap();
    assert_eq!(
        runs::append_event(&mut tx, &c.scope, &run, "b", payload(b"b"))
            .await
            .unwrap(),
        2
    );
    assert!(matches!(
        runs::append_event(&mut tx, &c.scope, &run, "b", payload(b"different")).await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        runs::append_event(&mut tx, &c.scope, &run, "c", payload(b"c"))
            .await
            .unwrap(),
        3
    );
    tx.commit().await.unwrap();
    // Failed event INSERT rolls back the allocated sequence, even if caller commits.
    let mut admin = db.admin().await;
    admin.execute("ALTER TABLE openmettle.run_events ADD CONSTRAINT fixture_failure CHECK (append_key <> 'reject') NOT VALID").await.unwrap();
    let mut tx = WriteTransaction::begin(&mut second).await.unwrap();
    assert!(
        runs::append_event(&mut tx, &c.scope, &run, "reject", payload(b"x"))
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    admin
        .execute("ALTER TABLE openmettle.run_events DROP CONSTRAINT fixture_failure")
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(&mut second).await.unwrap();
    assert_eq!(
        runs::append_event(&mut tx, &c.scope, &run, "d", payload(b"d"))
            .await
            .unwrap(),
        4
    );
    tx.commit().await.unwrap();
    // Commit first writer before allowing second: ordered visibility, not only rollback.
    let mut tx = WriteTransaction::begin(&mut first).await.unwrap();
    runs::append_event(&mut tx, &c.scope, &run, "e", payload(b"e"))
        .await
        .unwrap();
    let mut later = WriteTransaction::begin(&mut second).await.unwrap();
    let mut pending = Box::pin(runs::append_event(
        &mut later,
        &c.scope,
        &run,
        "f",
        payload(b"f"),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut pending)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert_eq!(pending.await.unwrap(), 6);
    later.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn operations_replay_revision_evidence_and_atomic_failure() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "one").await;
    let mut tasks = Vec::new();
    let barrier = Arc::new(tokio::sync::Barrier::new(4));
    for _ in 0..4 {
        let c = c.clone();
        let run = run.clone();
        let b = barrier.clone();
        let opts = role_options(&db.0, WORKER);
        tasks.push(tokio::spawn(async move {
            let mut cn = PgConnection::connect_with(&opts).await.unwrap();
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            b.wait().await;
            let id = runs::record_intent(&mut tx, &intent(&c, &run))
                .await
                .unwrap();
            tx.commit().await.unwrap();
            id
        }));
    }
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    assert!(ids.iter().all(|id| id == &ids[0]));
    let op = &ids[0];
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let mut changed = intent(&c, &run);
    changed.target = "different";
    assert!(matches!(
        runs::record_intent(&mut tx, &changed).await,
        Err(Error::Conflict)
    ));
    tx.commit().await.unwrap();
    let mut observation = Observation {
        scope: &c.scope,
        run: &run,
        operation: op,
        key: "unknown",
        expected_revision: 0,
        outcome: "outcome_unknown",
        handle: Some("job-1"),
        evidence: payload(b"timeout is not failure"),
    };
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    assert_eq!(
        runs::record_observation(&mut tx, &observation)
            .await
            .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    drop(worker);
    // Reconnect after an acknowledgement is lost; recover same key, no duplicate event.
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    assert_eq!(
        runs::record_observation(&mut tx, &observation)
            .await
            .unwrap(),
        1
    );
    observation.key = "stale";
    assert!(matches!(
        runs::record_observation(&mut tx, &observation).await,
        Err(Error::StaleRevision)
    ));
    tx.commit().await.unwrap();
    observation.key = "settled";
    observation.expected_revision = 1;
    observation.outcome = "failed";
    observation.evidence = payload(b"");
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    assert!(matches!(
        runs::record_observation(&mut tx, &observation).await,
        Err(Error::Invalid)
    ));
    tx.commit().await.unwrap();
    observation.evidence = payload(b"authoritative failure");
    let mut admin = db.admin().await;
    admin.execute("ALTER TABLE openmettle.run_events ADD CONSTRAINT fixture_failure CHECK (append_key <> 'settled') NOT VALID").await.unwrap();
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    assert!(
        runs::record_observation(&mut tx, &observation)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert_eq!(
        count(&db, "SELECT revision FROM openmettle.operations").await,
        1
    );
    admin
        .execute("ALTER TABLE openmettle.run_events DROP CONSTRAINT fixture_failure")
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    assert_eq!(
        runs::record_observation(&mut tx, &observation)
            .await
            .unwrap(),
        2
    );
    tx.commit().await.unwrap();
    let outcome: String = sqlx::query_scalar("SELECT outcome FROM openmettle.operations")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(outcome, "failed");
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    assert_eq!(
        runs::record_observation(&mut tx, &observation)
            .await
            .unwrap(),
        2
    );
    observation.key = "overwrite";
    observation.expected_revision = 2;
    observation.outcome = "succeeded";
    assert!(matches!(
        runs::record_observation(&mut tx, &observation).await,
        Err(Error::Conflict)
    ));
    tx.commit().await.unwrap();
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.run_events").await,
        4
    );
    // Intent INSERT is rolled back when its event fails.
    admin.execute("ALTER TABLE openmettle.run_events ADD CONSTRAINT fixture_failure CHECK (format <> 'openmettle.operation-intent') NOT VALID").await.unwrap();
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let mut new = intent(&c, &run);
    new.key = "new";
    assert!(runs::record_intent(&mut tx, &new).await.is_err());
    tx.commit().await.unwrap();
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.operations").await,
        1
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn killed_migration_three_preserves_version_two() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..2])
        .await
        .unwrap();
    // Migration 3's foreign key to conversations waits behind this lock, after it has written catalog
    // rows in its transaction and while it holds the migration advisory lock.
    let mut blocker = db.admin().await;
    blocker.execute("BEGIN").await.unwrap();
    blocker
        .execute("LOCK TABLE openmettle.conversations IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut admin = db.admin().await;
    for kill in ["-TERM", "-KILL"] {
        let mut child = Process(
            migrate_command(
                &db.url(OWNER),
                &[
                    ("LOCK_TIMEOUT_MS", "60000"),
                    ("STATEMENT_TIMEOUT_MS", "60000"),
                ],
            )
            .spawn()
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let state: Option<(bool, bool)> = sqlx::query_as(
                "SELECT a.backend_xid IS NOT NULL,
                        EXISTS (SELECT FROM pg_locks AS l
                                WHERE l.pid = a.pid AND l.locktype = 'advisory' AND l.granted)
                 FROM pg_stat_activity AS a
                 WHERE a.datname = $1 AND a.application_name = $2
                   AND a.wait_event_type = 'Lock'",
            )
            .bind(&db.0)
            .bind(migrate::APPLICATION_NAME)
            .fetch_optional(&mut admin)
            .await
            .unwrap();
            // Uncommitted migration writes plus the held migration lock.
            if state == Some((true, true)) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "migrator never blocked inside migration 3 holding the lock: {state:?}"
            );
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "migrator exited early"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let status = stop_process(
            &mut child,
            kill,
            &format!("migrator mid-migration 3 ({kill})"),
        );
        if kill == "-TERM" {
            assert_eq!(status.code(), Some(1));
        }
        // PostgreSQL ends the session, rolls back migration 3 and releases the lock.
        db.wait_no_migration_session().await;
        assert!(
            !db.exists("openmettle.conversation_branches").await,
            "{kill}"
        );
        assert_eq!(db.history().await, [1, 2], "{kill}");
    }
    blocker.execute("ROLLBACK").await.unwrap();
    let mut cmd = migrate_command(&db.url(OWNER), &[("LOCK_TIMEOUT_MS", "1000")]);
    let output = run_cli(&mut cmd, "migrate after migration 3 rollback");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(db.history().await, all_versions());
    db.wait_no_migration_session().await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn version_three_failure_timeout_concurrent_upgrade() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(1));
    migrate::apply(&settings, &MIGRATIONS[..2]).await.unwrap();
    let broken = Source {
        sql: concat!(
            include_str!("../../migrations/0003_runs_events_operations.sql"),
            "\nSELECT 1/0;"
        ),
        ..MIGRATIONS[2]
    };
    assert!(matches!(
        migrate::apply(&settings, &[MIGRATIONS[0], MIGRATIONS[1], broken]).await,
        Err(Failure::Migrate(_))
    ));
    assert_eq!(db.history().await, [1, 2]);
    assert!(!db.exists("openmettle.conversation_branches").await);
    let mut blocker = db.admin().await;
    let mut tx = blocker.begin().await.unwrap();
    tx.execute("LOCK TABLE openmettle.conversations IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut bounded = db.settings(Duration::from_secs(5));
    bounded.statement_timeout = Duration::from_millis(150);
    assert!(matches!(
        migrate::apply(&bounded, MIGRATIONS).await,
        Err(Failure::Migrate(_))
    ));
    db.wait_no_migration_session().await;
    assert_eq!(db.history().await, [1, 2]);
    assert!(!db.exists("openmettle.conversation_branches").await);
    tx.rollback().await.unwrap();
    let children: Vec<Process> = (0..4)
        .map(|_| Process(migrate_command(&db.url(OWNER), &[]).spawn().unwrap()))
        .collect();
    for (index, child) in children.into_iter().enumerate() {
        let out = wait_output(
            child,
            &format!("concurrent migrator after migration 3 #{index}"),
        );
        assert!(out.status.success(), "{}", stderr(&out));
    }
    assert_eq!(db.history().await, all_versions());
    db.wait_no_migration_session().await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn durable_roles_and_ownership_are_bounded() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let other = Context::new(&db).await;
    let run = c.run(&db, "one").await;
    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    for (role, cn) in [(API, &mut api), (WORKER, &mut worker)] {
        for table in ["conversation_branches", "runs", "run_events", "operations"] {
            for privilege in [
                "SELECT",
                "INSERT",
                "UPDATE",
                "DELETE",
                "TRUNCATE",
                "REFERENCES",
                "TRIGGER",
                "MAINTAIN",
            ] {
                let expected = privilege == "SELECT"
                    || privilege == "INSERT"
                        && (table == "run_events"
                            || role == API && table == "conversation_branches");
                let actual: bool = sqlx::query_scalar("SELECT has_table_privilege($1,$2,$3)")
                    .bind(role)
                    .bind(format!("openmettle.{table}"))
                    .bind(privilege)
                    .fetch_one(&mut db.admin().await)
                    .await
                    .unwrap();
                assert_eq!(actual, expected, "{role} {table} {privilege}");
            }
        }
        for sql in [
            // Migration 15 grants UPDATE (state, wait_reason) for run invalidation only
            // (authorization.rs); no other run column may change alongside them.
            "UPDATE openmettle.runs SET state='running', actor_user_id=actor_user_id",
            "INSERT INTO openmettle.runs(state) VALUES ('succeeded')",
            "INSERT INTO openmettle.operations(outcome) VALUES ('succeeded')",
            "UPDATE openmettle.runs SET wait_reason='approval', conversation_id=conversation_id",
            "UPDATE openmettle.runs SET scope_id=scope_id",
            "UPDATE openmettle.runs SET input_snapshot='x'::bytea",
            "UPDATE openmettle.runs SET request_digest=request_digest",
            "UPDATE openmettle.run_events SET payload='x'::bytea",
            "UPDATE openmettle.operations SET request='x'::bytea",
            "UPDATE openmettle.conversation_branches SET fork_message_id=NULL",
            "DELETE FROM openmettle.run_events",
            "SELECT * FROM openmettle._sqlx_migrations",
            "CREATE TABLE openmettle.forbidden(id int)",
            "SET ROLE openmettle_owner",
        ] {
            expect_state(cn, sql, "42501").await;
        }
    }
    expect_state(
        &mut api,
        "UPDATE openmettle.operations SET outcome='failed'",
        "42501",
    )
    .await;
    expect_state(
        &mut worker,
        "INSERT INTO openmettle.conversation_branches DEFAULT VALUES",
        "42501",
    )
    .await;
    expect_state(
        &mut worker,
        "INSERT INTO openmettle.runs DEFAULT VALUES",
        "42501",
    )
    .await;
    let grants:i64=sqlx::query_scalar("SELECT count(*) FROM information_schema.role_table_grants WHERE table_schema='openmettle' AND
             grantee IN ('openmettle_api','openmettle_worker') AND is_grantable='YES'").fetch_one(&mut db.admin().await).await.unwrap();
    assert_eq!(grants, 0);
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let mut wrong = c.input("cross");
    wrong.branch = &other.branch;
    assert!(
        matches!(runs::create_run(&mut tx,&wrong).await,Err(Error::Database(ref e)) if e.as_database_error().unwrap().code().as_deref()==Some("23503"))
    );
    wrong = c.input("cross");
    wrong.message = &other.message;
    assert!(
        matches!(runs::create_run(&mut tx,&wrong).await,Err(Error::Database(ref e)) if e.as_database_error().unwrap().code().as_deref()==Some("23503"))
    );
    wrong = c.input("cross");
    wrong.scope = &other.scope;
    assert!(
        matches!(runs::create_run(&mut tx, &wrong).await, Err(Error::Database(ref e)) if e.as_database_error().unwrap().code().as_deref() == Some("23503"))
    );
    tx.commit().await.unwrap();
    let branch_error = sqlx::query(
        "INSERT INTO openmettle.conversation_branches(scope_id,conversation_id,fork_message_id)
             VALUES($1::uuid,$2::uuid,$3::uuid)",
    )
    .bind(&c.scope)
    .bind(&c.conversation)
    .bind(&other.message)
    .execute(&mut api)
    .await;
    assert_eq!(sqlstate(branch_error), "23503");
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let mut wrong = intent(&c, &run);
    wrong.scope = &other.scope;
    assert!(matches!(
        runs::record_intent(&mut tx, &wrong).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        runs::append_event(&mut tx, &other.scope, &run, "cross", payload(b"x")).await,
        Err(Error::NotFound)
    ));
    tx.commit().await.unwrap();
    // Direct relational checks are distinct from helper validation and application authorization.
    let result=sqlx::query("INSERT INTO
             openmettle.run_events(scope_id,run_id,sequence,append_key,format,format_version,payload,identity,digest)
             VALUES($1::uuid,$2::uuid,99,'cross','fixture',1,''::bytea,''::bytea,decode(repeat('00',32),'hex'))").bind(&other.scope).bind(&run).execute(&mut worker).await;
    assert_eq!(sqlstate(result), "23503");
    let result=sqlx::query("INSERT INTO
             openmettle.operations(scope_id,run_id,logical_key,target,capability,format,format_version,request,request_identity,request_digest)
             VALUES($1::uuid,$2::uuid,'cross','fixture','lookup','fixture',1,''::bytea,''::bytea,decode(repeat('00',32),'hex'))").bind(&other.scope).bind(&run).execute(&mut worker).await;
    assert_eq!(sqlstate(result), "23503");
    // Version-specific grants are rejected before v3, with no migration side effects.
    let v2 = TestDb::new().await;
    migrate::apply(&v2.settings(Duration::from_secs(1)), &MIGRATIONS[..2])
        .await
        .unwrap();
    let mut owner = connect(&v2.0, OWNER).await;
    owner.execute("CREATE TABLE openmettle.runs(id int); GRANT SELECT ON openmettle.runs TO openmettle_worker").await.unwrap();
    assert!(matches!(
        migrate::apply(&v2.settings(Duration::from_secs(1)), MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
    assert_eq!(v2.history().await, [1, 2]);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn concurrent_observations_have_one_revision_winner() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "race").await;
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let operation = runs::record_intent(&mut tx, &intent(&c, &run))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut tasks = Vec::new();
    for key in ["a", "b"] {
        let opts = role_options(&db.0, WORKER);
        let c = c.clone();
        let run = run.clone();
        let operation = operation.clone();
        let b = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let mut cn = PgConnection::connect_with(&opts).await.unwrap();
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            b.wait().await;
            let result = runs::record_observation(
                &mut tx,
                &Observation {
                    scope: &c.scope,
                    run: &run,
                    operation: &operation,
                    key,
                    expected_revision: 0,
                    outcome: "outcome_unknown",
                    handle: None,
                    evidence: payload(b"uncertain"),
                },
            )
            .await;
            tx.commit().await.unwrap();
            result
        }));
    }
    let a = tasks.remove(0).await.unwrap();
    let b = tasks.remove(0).await.unwrap();
    assert!(matches!(
        (&a, &b),
        (Ok(1), Err(Error::StaleRevision)) | (Err(Error::StaleRevision), Ok(1))
    ));
    assert_eq!(
        count(&db, "SELECT revision FROM openmettle.operations").await,
        1
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.run_events").await,
        3
    );
}

#[path = "artifact_fs.rs"]
mod artifact_fs;
#[path = "cancellation.rs"]
mod cancellation;
#[path = "restore.rs"]
mod restore;
#[path = "retention.rs"]
mod retention;
#[path = "storage.rs"]
mod storage;

#[path = "grants.rs"]
mod grants;

#[path = "login.rs"]
mod login;
