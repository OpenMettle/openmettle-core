//! Grant persistence uses synthetic vocabulary, never product permission meanings.
use super::cancellation::{ResponseBarrier, cancel_at_response};
use super::*;
use openmettle_core::grants::{
    self, Assignment, ChangeInput, Decision, GrantReceipt, MappingInput, Target,
};

const PROVIDER: &str = "00000000-0000-0000-0000-000000000001";
const RULE1: &str = "00000000-0000-0000-0000-000000000002";
const RULE2: &str = "00000000-0000-0000-0000-000000000003";
fn input<'a>(c: &'a Context, key: &'a str) -> ChangeInput<'a> {
    ChangeInput {
        assignment: Assignment {
            scope: &c.scope,
            target: Target::Conversation(&c.conversation),
            grantee: &c.actor,
            format: "test.assignment",
            version: 1,
            key: "synthetic",
            mapping_rule: None,
        },
        actor: &c.actor,
        key,
        expected_revision: 0,
        mapping_revision: None,
        decision: Decision::Grant,
    }
}
fn mapping<'a>(c: &'a Context, rule: &'a str, key: &'a str, expected: i64) -> MappingInput<'a> {
    MappingInput {
        rule,
        provider: PROVIDER,
        issuer: "https://issuer.example.test",
        actor: &c.actor,
        key,
        expected_revision: expected,
        enabled: true,
        selector_kind: "group",
        claim_name: "groups",
        claim_value: "synthetic-group",
        binding_format: "test.binding",
        binding_version: 1,
        binding: b"synthetic binding",
    }
}
async fn change(db: &TestDb, r: &ChangeInput<'_>) -> Result<GrantReceipt, Error> {
    let mut c = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let result = grants::change_grant(&mut tx, r).await;
    tx.commit().await.unwrap();
    result
}
async fn map(db: &TestDb, r: &MappingInput<'_>) -> Result<grants::MappingReceipt, Error> {
    let mut c = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let result = grants::record_mapping_revision(&mut tx, r).await;
    tx.commit().await.unwrap();
    result
}
async fn state(db: &TestDb, scope: &str, id: &str) -> grants::AssignmentSnapshot {
    grants::read_assignment(&mut connect(&db.0, WORKER).await, scope, id)
        .await
        .unwrap()
        .unwrap()
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn provenance_replay_revocation_and_fresh_cycles() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    map(&db, &mapping(&c, RULE1, "rule1", 0)).await.unwrap();
    let mut second = mapping(&c, RULE2, "rule2", 0);
    second.provider = RULE2;
    second.issuer = "https://other.example.test";
    map(&db, &second).await.unwrap();
    let direct = input(&c, "direct");
    let mut mapped1 = input(&c, "mapped1");
    mapped1.assignment.mapping_rule = Some(RULE1);
    mapped1.mapping_revision = Some(1);
    let mut mapped2 = input(&c, "mapped2");
    mapped2.assignment.mapping_rule = Some(RULE2);
    mapped2.mapping_revision = Some(1);
    let d = change(&db, &direct).await.unwrap();
    let m1 = change(&db, &mapped1).await.unwrap();
    let m2 = change(&db, &mapped2).await.unwrap();
    let mut disabled = mapping(&c, RULE1, "disable", 1);
    disabled.enabled = false;
    map(&db, &disabled).await.unwrap();
    let s = state(&db, &c.scope, &m1.assignment).await;
    assert!(s.recorded_active);
    assert!(!s.mapping_eligible);
    assert!(state(&db, &c.scope, &d.assignment).await.recorded_active);
    assert!(state(&db, &c.scope, &m2.assignment).await.mapping_eligible);
    assert_eq!(change(&db, &mapped1).await.unwrap(), m1);
    assert_eq!(
        map(&db, &mapping(&c, RULE1, "rule1", 0))
            .await
            .unwrap()
            .revision,
        1
    );
    let mut revoke = mapped1;
    revoke.key = "revoke1";
    revoke.expected_revision = 1;
    revoke.decision = Decision::Revoke(m1.cycle.as_deref());
    change(&db, &revoke).await.unwrap(); // Old mapping revision can revoke after disable.
    assert!(!state(&db, &c.scope, &m1.assignment).await.recorded_active);
    assert_eq!(change(&db, &mapped1).await.unwrap(), m1);
    let mut again = mapped1;
    again.key = "again";
    again.expected_revision = 2;
    assert!(matches!(
        change(&db, &again).await,
        Err(Error::StaleRevision)
    ));
    // Current revision alone is insufficient: a disabled rule cannot grant again.
    let before = count(&db, "SELECT count(*) FROM openmettle.grant_changes").await;
    let mut current_disabled = again;
    current_disabled.key = "current-disabled";
    current_disabled.mapping_revision = Some(2);
    assert!(matches!(
        change(&db, &current_disabled).await,
        Err(Error::StaleRevision)
    ));
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.grant_changes").await,
        before
    );
    assert!(!state(&db, &c.scope, &m1.assignment).await.recorded_active);
    map(&db, &mapping(&c, RULE1, "replace", 2)).await.unwrap();
    again.mapping_revision = Some(3);
    let new = change(&db, &again).await.unwrap();
    assert_ne!(new.cycle, m1.cycle);
    assert_eq!(change(&db, &revoke).await.unwrap().revision, 2); // Historical revoke cannot revoke new cycle.
    assert!(state(&db, &c.scope, &new.assignment).await.recorded_active);
    revoke.key = "stale-cycle";
    revoke.expected_revision = 3;
    assert!(matches!(
        change(&db, &revoke).await,
        Err(Error::StaleRevision)
    ));
    // A correct cycle still cannot be revoked using a different mapping revision.
    let before = count(&db, "SELECT count(*) FROM openmettle.grant_changes").await;
    let mut wrong_mapping = revoke;
    wrong_mapping.key = "wrong-mapping-revision";
    wrong_mapping.decision = Decision::Revoke(new.cycle.as_deref());
    assert_eq!(wrong_mapping.mapping_revision, Some(1));
    assert!(matches!(
        change(&db, &wrong_mapping).await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.grant_changes").await,
        before
    );
    assert!(state(&db, &c.scope, &new.assignment).await.recorded_active);
    assert_eq!(change(&db, &mapped1).await.unwrap(), m1);
    assert_eq!(state(&db, &c.scope, &new.assignment).await.revision, 3);
    let mut active = again;
    active.key = "already-active";
    active.expected_revision = 3;
    assert!(matches!(change(&db, &active).await, Err(Error::Conflict)));
    let mut rebind = mapping(&c, RULE1, "rebind", 3);
    rebind.provider = RULE2;
    assert!(matches!(map(&db, &rebind).await, Err(Error::Conflict)));
    rebind.provider = PROVIDER;
    rebind.issuer = "https://other.example.test";
    assert!(matches!(map(&db, &rebind).await, Err(Error::Conflict)));
    // Independently revoke other origins; the replacement remains recorded active.
    for (request, receipt, key) in [(direct, &d, "revoke-direct"), (mapped2, &m2, "revoke2")] {
        let mut r = request;
        r.key = key;
        r.expected_revision = 1;
        r.decision = Decision::Revoke(receipt.cycle.as_deref());
        change(&db, &r).await.unwrap();
        assert!(
            !state(&db, &c.scope, &receipt.assignment)
                .await
                .recorded_active
        );
    }
    assert!(state(&db, &c.scope, &new.assignment).await.recorded_active);
    let mut absent = input(&c, "absent-revoke");
    absent.assignment.key = "another";
    absent.decision = Decision::Revoke(None);
    let tombstone = change(&db, &absent).await.unwrap();
    assert!(!tombstone.granted);
    absent.key = "delayed-grant";
    absent.decision = Decision::Grant;
    assert!(matches!(
        change(&db, &absent).await,
        Err(Error::StaleRevision)
    ));
    absent.expected_revision = 1;
    change(&db, &absent).await.unwrap();
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn concurrent_replay_global_namespace_and_cas() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let r = input(&c, "equal");
    let (a, b) = tokio::join!(change(&db, &r), change(&db, &r));
    assert_eq!(a.unwrap(), b.unwrap());
    let mut a = input(&c, "global-key");
    a.assignment.key = "a";
    let mut b = a;
    b.assignment.key = "b";
    let (x, y) = tokio::join!(change(&db, &a), change(&db, &b));
    assert!(matches!(
        (&x, &y),
        (Ok(_), Err(Error::Conflict)) | (Err(Error::Conflict), Ok(_))
    ));
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.grant_assignments").await,
        2
    ); // Losing provisional row rolled back.
    let mut a = input(&c, "race-a");
    a.assignment.key = "cas";
    let mut b = a;
    b.key = "race-b";
    b.decision = Decision::Revoke(None);
    let (x, y) = tokio::join!(change(&db, &a), change(&db, &b));
    assert!(matches!(
        (&x, &y),
        (Ok(_), Err(Error::StaleRevision)) | (Err(Error::StaleRevision), Ok(_))
    ));
    let m = mapping(&c, RULE1, "equal", 0);
    let (x, y) = tokio::join!(map(&db, &m), map(&db, &m));
    assert_eq!(x.unwrap(), y.unwrap());
    let mut a = mapping(&c, RULE1, "mapping-race", 1);
    let mut b = a;
    b.enabled = false;
    let (x, y) = tokio::join!(map(&db, &a), map(&db, &b));
    assert!(matches!(
        (&x, &y),
        (Ok(_), Err(Error::Conflict)) | (Err(Error::Conflict), Ok(_))
    ));
    a.expected_revision = 2;
    a.key = "new-revision";
    a.enabled = false;
    map(&db, &a).await.unwrap();
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn ordinary_errors_and_outer_rollback_preserve_composition() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let r = input(&c, "original");
    change(&db, &r).await.unwrap();
    let mut cn = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    message(
        tx.connection().unwrap(),
        &c.scope,
        &c.conversation,
        Some(&c.message),
    )
    .await
    .unwrap();
    let mut bad = r;
    bad.assignment.key = "different";
    assert!(matches!(
        grants::change_grant(&mut tx, &bad).await,
        Err(Error::Conflict)
    ));
    bad.key = "fk-error";
    bad.assignment.target = Target::Artifact(PROVIDER);
    assert!(matches!(
        grants::change_grant(&mut tx, &bad).await,
        Err(Error::Database(_))
    ));
    tx.commit().await.unwrap();
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM openmettle.messages WHERE parent_message_id IS NOT NULL"
        )
        .await,
        1
    );
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let mut fresh = r;
    fresh.key = "rollback";
    fresh.assignment.key = "rollback";
    grants::change_grant(&mut tx, &fresh).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.grant_changes").await,
        1
    );
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn cancellation_and_unknown_commit_keep_grant_identity() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let original = input(&c, "original");
    change(&db, &original).await.unwrap();
    for mapping_helper in [false, true] {
        for command in [b"SAVEPOINT\0".as_slice(), b"RELEASE\0", b"ROLLBACK\0"] {
            let mut barrier = ResponseBarrier::new(command);
            let options = role_options(&db.0, API)
                .host("127.0.0.1")
                .port(barrier.port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable);
            let mut cn = PgConnection::connect_with(&options).await.unwrap();
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            message(
                tx.connection().unwrap(),
                &c.scope,
                &c.conversation,
                Some(&c.message),
            )
            .await
            .unwrap();
            if mapping_helper {
                let mut r = mapping(&c, RULE1, "cancel", 0);
                if command == b"ROLLBACK\0" {
                    r.expected_revision = 9;
                }
                cancel_at_response(&mut barrier, grants::record_mapping_revision(&mut tx, &r))
                    .await;
            } else {
                let mut r = input(&c, "cancel");
                r.assignment.key = "cancel";
                if command == b"ROLLBACK\0" {
                    r.key = "original";
                }
                cancel_at_response(&mut barrier, grants::change_grant(&mut tx, &r)).await;
            }
            assert!(matches!(
                tx.commit().await,
                Err(Error::TransactionUnavailable)
            ));
            drop(cn);
            drop(barrier);
            assert_eq!(
                count(
                    &db,
                    "SELECT count(*) FROM openmettle.messages WHERE parent_message_id IS NOT NULL"
                )
                .await,
                0
            );
            assert_eq!(
                count(&db, "SELECT count(*) FROM openmettle.grant_changes").await,
                1
            );
            assert_eq!(
                count(&db, "SELECT count(*) FROM openmettle.grant_mapping_rules").await,
                0
            );
        }
    }
    let mut barrier = ResponseBarrier::new(b"COMMIT\0");
    let options = role_options(&db.0, API)
        .host("127.0.0.1")
        .port(barrier.port)
        .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut cn = PgConnection::connect_with(&options).await.unwrap();
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let mut r = input(&c, "uncertain");
    r.assignment.key = "uncertain";
    let receipt = grants::change_grant(&mut tx, &r).await.unwrap();
    let mapping_receipt =
        grants::record_mapping_revision(&mut tx, &mapping(&c, RULE1, "uncertain", 0))
            .await
            .unwrap();
    cancel_at_response(&mut barrier, tx.commit()).await;
    drop(cn);
    drop(barrier);
    assert_eq!(change(&db, &r).await.unwrap(), receipt);
    assert_eq!(
        map(&db, &mapping(&c, RULE1, "uncertain", 0)).await.unwrap(),
        mapping_receipt
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.grant_changes").await,
        2
    );
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn sql_roles_scopes_null_checks_and_immutable_origin() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let other = Context::new(&db).await;
    map(&db, &mapping(&c, RULE1, "rule", 0)).await.unwrap();
    let direct = change(&db, &input(&c, "direct")).await.unwrap();
    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    for table in [
        "grant_mapping_rules",
        "grant_mapping_revisions",
        "grant_assignments",
        "grant_changes",
    ] {
        for statement in [
            format!("DELETE FROM openmettle.{table}"),
            format!("TRUNCATE openmettle.{table}"),
        ] {
            assert_eq!(
                sqlstate(api.execute(AssertSqlSafe(statement.clone())).await),
                "42501"
            );
            assert_eq!(
                sqlstate(worker.execute(AssertSqlSafe(statement)).await),
                "42501"
            );
        }
        assert_eq!(
            sqlstate(
                worker
                    .execute(AssertSqlSafe(format!(
                        "INSERT INTO openmettle.{table} DEFAULT VALUES"
                    )))
                    .await
            ),
            "42501"
        );
    }
    for statement in [
        "UPDATE openmettle.grant_mapping_rules SET issuer='https://changed.example.test'",
        "UPDATE openmettle.grant_mapping_rules SET provider_config_id=gen_random_uuid()",
        "UPDATE openmettle.grant_mapping_revisions SET enabled=false",
        "UPDATE openmettle.grant_assignments SET grantee_user_id=gen_random_uuid()",
        "UPDATE openmettle.grant_assignments SET mapping_rule_id=NULL",
        "UPDATE openmettle.grant_changes SET decision='revoke'",
    ] {
        expect_state(&mut api, statement, "42501").await;
    }
    expect_state(
        &mut worker,
        "UPDATE openmettle.grant_assignments SET last_revision=0",
        "42501",
    )
    .await;
    expect_state(
        &mut worker,
        "UPDATE openmettle.grant_mapping_rules SET last_revision=0",
        "42501",
    )
    .await;
    // Check typed targets and required fields through actual API SQL, independent of helpers.
    let insert = "INSERT INTO openmettle.grant_assignments(scope_id,target_kind,project_id,conversation_id,artifact_id,grantee_user_id,assignment_format,assignment_version,assignment_key,source_kind,mapping_rule_id,created_by_user_id) VALUES($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,$6::uuid,'test.assignment',1,'sql','direct',NULL,$6::uuid)";
    for (kind, p, chat, file, scope, code) in [
        ("conversation", None, None, None, c.scope.as_str(), "23514"),
        ("project", None, None, None, c.scope.as_str(), "23514"),
        ("artifact", None, None, None, c.scope.as_str(), "23514"),
        (
            "conversation",
            Some(PROVIDER),
            Some(c.conversation.as_str()),
            None,
            c.scope.as_str(),
            "23514",
        ),
        (
            "conversation",
            None,
            Some(other.conversation.as_str()),
            None,
            c.scope.as_str(),
            "23503",
        ),
        (
            "artifact",
            None,
            None,
            Some(PROVIDER),
            c.scope.as_str(),
            "23503",
        ),
    ] {
        assert_eq!(
            sqlstate(
                sqlx::query(insert)
                    .bind(scope)
                    .bind(kind)
                    .bind(p)
                    .bind(chat)
                    .bind(file)
                    .bind(&c.actor)
                    .execute(&mut api)
                    .await
            ),
            code
        );
    }
    let (project_id, ps) = project(&mut api, &c.actor).await;
    let mut r = input(&c, "project");
    r.assignment.scope = &ps;
    r.assignment.grantee = &other.actor;
    r.assignment.target = Target::Project(&project_id);
    let pr = change(&db, &r).await.unwrap();
    assert!(state(&db, &ps, &pr.assignment).await.recorded_active);
    assert!(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT FROM openmettle.grant_assignments WHERE scope_id=$1::uuid AND target_kind='conversation')").bind(&ps).fetch_one(&mut api).await.unwrap());
    // A real artifact target preserves its accounting and private ownership.
    let artifact: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut api)
        .await
        .unwrap();
    sqlx::query("INSERT INTO openmettle.artifacts(id,scope_id,scope_kind,owner_user_id) VALUES($1::uuid,$2::uuid,'project',$3::uuid)").bind(&artifact).bind(&ps).bind(&c.actor).execute(&mut api).await.unwrap();
    r.key = "artifact";
    r.assignment.target = Target::Artifact(&artifact);
    change(&db, &r).await.unwrap();
    r.key = "wrong-artifact-scope";
    r.assignment.scope = &c.scope;
    assert!(matches!(change(&db, &r).await, Err(Error::Database(_))));
    let mut owner = db.admin().await;
    for statement in [
        "UPDATE openmettle.grant_assignments SET source_kind='mapped',mapping_rule_id=NULL",
        "UPDATE openmettle.grant_changes SET source_kind='mapped',mapping_rule_id=NULL,mapping_revision=NULL",
        "UPDATE openmettle.grant_changes SET cycle_id=NULL WHERE decision='grant'",
    ] {
        expect_state(&mut owner, statement, "23514").await;
    }
    let mut another = input(&c, "another");
    another.assignment.key = "another";
    let other_grant = change(&db, &another).await.unwrap();
    assert_eq!(sqlstate(sqlx::query("INSERT INTO openmettle.grant_changes(scope_id,assignment_id,revision,source_kind,actor_user_id,request_key,decision,cycle_id,request_identity,request_digest) VALUES($1::uuid,$2::uuid,2,'direct',$3::uuid,'bad-cycle','revoke',$4::uuid,'x',decode(repeat('00',32),'hex'))")
        .bind(&c.scope).bind(&direct.assignment).bind(&c.actor).bind(&other_grant.change).execute(&mut api).await),"23503");
    // Version-5 permissions must not be accepted before migration 5 is recorded.
    let v4 = TestDb::new().await;
    migrate::apply(&v4.settings(Duration::from_secs(5)), &MIGRATIONS[..4])
        .await
        .unwrap();
    let mut owner = connect(&v4.0, OWNER).await;
    owner.execute("CREATE TABLE openmettle.grant_assignments(id uuid); GRANT SELECT ON openmettle.grant_assignments TO openmettle_api").await.unwrap();
    assert!(matches!(
        migrate::apply(&v4.settings(Duration::from_secs(5)), MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
    assert_eq!(v4.history().await, [1, 2, 3, 4]);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn migration_five_failure_kill_timeout_and_concurrent_retry() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(1));
    migrate::apply(&settings, &MIGRATIONS[..4]).await.unwrap();
    let broken = Source {
        sql: concat!(
            include_str!("../../migrations/0005_grant_persistence.sql"),
            "\nSELECT 1/0;"
        ),
        ..MIGRATIONS[4]
    };
    assert!(matches!(
        migrate::apply(
            &settings,
            &[
                MIGRATIONS[0],
                MIGRATIONS[1],
                MIGRATIONS[2],
                MIGRATIONS[3],
                broken
            ]
        )
        .await,
        Err(Failure::Migrate(_))
    ));
    assert_eq!(db.history().await, [1, 2, 3, 4]);
    assert!(!db.exists("openmettle.grant_mapping_rules").await);
    // Migration 5's first foreign key waits on users inside transactional DDL.
    let mut blocker = db.admin().await;
    blocker.execute("BEGIN").await.unwrap();
    blocker
        .execute("LOCK TABLE openmettle.users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut bounded = db.settings(Duration::from_secs(5));
    bounded.statement_timeout = Duration::from_millis(150);
    assert!(matches!(
        migrate::apply(&bounded, MIGRATIONS).await,
        Err(Failure::Migrate(_))
    ));
    db.wait_no_migration_session().await;
    assert_eq!(db.history().await, [1, 2, 3, 4]);
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
                "migrator never blocked inside migration 5: {state:?}"
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
        assert!(!db.exists("openmettle.grant_mapping_rules").await, "{kill}");
        assert_eq!(db.history().await, [1, 2, 3, 4], "{kill}");
    }
    blocker.execute("ROLLBACK").await.unwrap();
    let children: Vec<_> = (0..4)
        .map(|_| migrate_command(&db.url(OWNER), &[]).spawn().unwrap())
        .collect();
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
    }
    assert_eq!(db.history().await, [1, 2, 3, 4, 5, 6]);
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.grant_mapping_rules").await,
        0
    );
    db.wait_no_migration_session().await;
}
async fn old_domain_snapshot(db: &TestDb) -> Vec<String> {
    let mut c = db.admin().await;
    let mut result = Vec::new();
    for table in [
        "users",
        "user_identities",
        "scopes",
        "projects",
        "conversations",
        "messages",
        "conversation_branches",
        "runs",
        "run_events",
        "operations",
        "storage_instance",
        "storage_accounts",
        "artifacts",
        "storage_reservations",
        "artifact_revisions",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT t::text FROM openmettle.{table} t ORDER BY t::text"
        )))
        .fetch_all(&mut c)
        .await
        .unwrap();
        assert!(!rows.is_empty(), "upgrade fixture must populate {table}");
        result.push(table.into());
        result.extend(rows);
    }
    result
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V4_BINARY_DIR required"]
async fn populated_v4_upgrade_and_authentic_v4_binaries() {
    populated_upgrade("V4_BINARY_DIR", &[1, 2, 3, 4], false).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V5_BINARY_DIR required"]
async fn populated_v5_upgrade_and_authentic_v5_binaries() {
    populated_upgrade("V5_BINARY_DIR", &[1, 2, 3, 4, 5], true).await;
}
async fn populated_upgrade(binary_env: &str, versions: &[i64], with_grants: bool) {
    use openmettle_core::storage::{self as accounting, ReservationInput, Settlement};
    let db = TestDb::new().await;
    let old = std::path::PathBuf::from(
        std::env::var(binary_env).expect("build authentic released binaries first"),
    );
    let old_migrate = || {
        let template = migrate_command(&db.url(OWNER), &[]);
        let mut cmd = Command::new(old.join("openmettle-migrate"));
        for (k, v) in template.get_envs() {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
        }
        cmd.output().unwrap()
    };
    let output = old_migrate();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(db.history().await, versions);
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
            handle: Some("synthetic-handle"),
            evidence: payload(b"synthetic evidence"),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut api = connect(&db.0, API).await;
    sqlx::query("INSERT INTO openmettle.user_identities(user_id,issuer,subject) VALUES($1::uuid,'https://issuer.example.test','synthetic-subject')").bind(&c.actor).execute(&mut api).await.unwrap();
    let (_, ps) = project(&mut api, &c.actor).await;
    conversation(&mut api, &ps, "project", &c.actor)
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner.execute("UPDATE openmettle.storage_instance SET instance_budget_bytes=10000,personal_limit_bytes=1000,project_limit_bytes=1000").await.unwrap();
    for (scope, key, settle, retain) in [
        (&c.scope, "pending", false, false),
        (&c.scope, "active", true, false),
        (&ps, "retained", true, true),
    ] {
        let artifact: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut api)
            .await
            .unwrap();
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let reserved = accounting::reserve(
            &mut tx,
            &ReservationInput {
                scope,
                actor: &c.actor,
                key,
                artifact: &artifact,
                max_bytes: 100,
                run: None,
                operation: None,
            },
        )
        .await
        .unwrap();
        if settle {
            let revision = accounting::settle(
                &mut tx,
                &Settlement {
                    scope,
                    reservation: &reserved.id,
                    size_bytes: 10,
                    content_digest: &[0; 32],
                    media_type: "text/plain",
                },
            )
            .await
            .unwrap();
            if retain {
                accounting::retain_revision(&mut tx, scope, &revision, 3600)
                    .await
                    .unwrap();
            }
        }
        tx.commit().await.unwrap();
    }
    if with_grants {
        map(&db, &mapping(&c, RULE1, "upgrade-rule", 0))
            .await
            .unwrap();
        let mut grant = input(&c, "upgrade-grant");
        grant.assignment.mapping_rule = Some(RULE1);
        grant.mapping_revision = Some(1);
        change(&db, &grant).await.unwrap();
    }
    let grant_before = if with_grants {
        grant_snapshot(&db).await
    } else {
        vec![]
    };
    let before = old_domain_snapshot(&db).await;
    let history: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(db.history().await, [1, 2, 3, 4, 5, 6]);
    assert_eq!(old_domain_snapshot(&db).await, before);
    if with_grants {
        assert_eq!(grant_snapshot(&db).await, grant_before);
    }
    let kept: Vec<String> = sqlx::query_scalar(
        "SELECT t::text FROM openmettle._sqlx_migrations t WHERE version<=$1 ORDER BY version",
    )
    .bind(*versions.last().unwrap())
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(kept, history);
    let full: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    let refused = old_migrate();
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("boundary check refused"));
    let unchanged: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    assert_eq!(unchanged, full);
    for (name, role, prefix) in [
        ("openmettle-api", API, "OPENMETTLE_API"),
        ("openmettle-worker", WORKER, "OPENMETTLE_WORKER"),
    ] {
        let bind = address();
        let mut cmd = Command::new(old.join(name));
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("OPENMETTLE_")
                || k.to_string_lossy().starts_with("PG")
            {
                cmd.env_remove(k);
            }
        }
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
    change(&db, &input(&c, "after-upgrade")).await.unwrap();
    assert_eq!(old_domain_snapshot(&db).await, before); // Sharing changes no owner, charge or limit.
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(old_domain_snapshot(&db).await, before);
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn legal_bounds_and_distinct_provider_bindings() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let issuer = "x".repeat(2048);
    let payload = vec![1; 16384];
    let label = "x".repeat(128);
    let value = "y".repeat(1024);
    let mut m = mapping(&c, RULE1, &label, 0);
    m.issuer = &issuer;
    m.binding = &payload;
    m.claim_name = &label;
    m.claim_value = &value;
    m.binding_format = &label;
    map(&db, &m).await.unwrap();
    assert_eq!(map(&db, &m).await.unwrap().revision, 1);
    let mut other = m;
    other.rule = RULE2;
    other.provider = RULE2; // Identical issuer/group, different provider.
    map(&db, &other).await.unwrap();
    other.rule = PROVIDER;
    other.provider = PROVIDER;
    other.issuer = "https://other.example.test";
    map(&db, &other).await.unwrap(); // Same provider/group, different issuer on a new rule.
    let mut change_input = input(&c, &label);
    change_input.assignment.format = &label;
    change_input.assignment.key = &label;
    change(&db, &change_input).await.unwrap();
    let large = vec![1; 16385];
    let mut bad = m;
    bad.binding = &large;
    assert!(matches!(map(&db, &bad).await, Err(Error::Invalid)));
    bad = m;
    bad.claim_name = "bad\0name";
    assert!(matches!(map(&db, &bad).await, Err(Error::Invalid)));
    change_input.key = "bad\0key";
    assert!(matches!(
        change(&db, &change_input).await,
        Err(Error::Invalid)
    ));
    change_input.key = "overflow";
    change_input.expected_revision = i64::MAX;
    assert!(matches!(
        change(&db, &change_input).await,
        Err(Error::Invalid)
    ));
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM openmettle.grant_mapping_revisions"
        )
        .await,
        3
    );
}

#[test]
fn migration_five_contract_hash() {
    migrate::migrator(MIGRATIONS)
        .expect("all embedded migrations must pass the transactional scanner");
    assert_eq!(
        format!("{:x}", Sha256::digest(MIGRATIONS[4].sql.as_bytes())),
        "3130bf356a92c08f08d9ec65e49bd4ae04c41dd82ebab2ee4e313427fa423680"
    );
}

async fn grant_snapshot(db: &TestDb) -> Vec<String> {
    let mut result = Vec::new();
    for table in [
        "grant_mapping_rules",
        "grant_mapping_revisions",
        "grant_assignments",
        "grant_changes",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT t::text FROM openmettle.{table} t ORDER BY t::text"
        )))
        .fetch_all(&mut db.admin().await)
        .await
        .unwrap();
        assert!(!rows.is_empty());
        result.extend(rows);
    }
    result
}
