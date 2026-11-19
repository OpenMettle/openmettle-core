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
    // Migration 11 revokes the default PUBLIC USAGE on the evidence type, and no runtime role
    // is granted it. The owner keeps it as the type's owner.
    let usage: Vec<(String, bool)> = sqlx::query_as(
        "SELECT role, has_type_privilege(role, 'openmettle.membership_evidence', 'USAGE')
         FROM unnest(ARRAY['public','openmettle_api','openmettle_worker','openmettle_owner'])
           WITH ORDINALITY AS r(role, ord) ORDER BY ord",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(
        usage,
        [
            ("public".to_owned(), false),
            ("openmettle_api".to_owned(), false),
            ("openmettle_worker".to_owned(), false),
            ("openmettle_owner".to_owned(), true),
        ]
    );
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
    assert_eq!(
        db.history().await,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    );
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
            "SELECT (to_jsonb(t) - 'session_generation' - 'session_issued')::text FROM openmettle.{table} t ORDER BY 1"
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
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V6_BINARY_DIR required"]
async fn populated_v6_upgrade_and_authentic_v6_binaries() {
    populated_upgrade("V6_BINARY_DIR", &[1, 2, 3, 4, 5, 6], true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V7_BINARY_DIR required"]
async fn populated_v7_upgrade_and_authentic_v7_binaries() {
    populated_upgrade("V7_BINARY_DIR", &[1, 2, 3, 4, 5, 6, 7], true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V8_BINARY_DIR required"]
async fn populated_v8_upgrade_and_authentic_v8_binaries() {
    populated_upgrade("V8_BINARY_DIR", &[1, 2, 3, 4, 5, 6, 7, 8], true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V9_BINARY_DIR required"]
async fn populated_v9_upgrade_and_authentic_v9_binaries() {
    populated_upgrade("V9_BINARY_DIR", &[1, 2, 3, 4, 5, 6, 7, 8, 9], true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V10_BINARY_DIR required"]
async fn populated_v10_upgrade_and_authentic_v10_binaries() {
    populated_upgrade("V10_BINARY_DIR", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V11_BINARY_DIR required"]
async fn populated_v11_upgrade_and_authentic_v11_binaries() {
    populated_upgrade("V11_BINARY_DIR", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V12_BINARY_DIR required"]
async fn populated_v12_upgrade_and_authentic_v12_binaries() {
    populated_upgrade(
        "V12_BINARY_DIR",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        true,
    )
    .await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V13_BINARY_DIR required"]
async fn populated_v13_upgrade_and_authentic_v13_binaries() {
    populated_upgrade(
        "V13_BINARY_DIR",
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        true,
    )
    .await;
}
// Version-12 invitations as its commands left them, without a code: one redeemed by the
// fixture approval and login, one withdrawn in its window and one withdrawn after expiry.
// A pending one would block migration 13 (see home_invitations.rs).
async fn populate_invitations(db: &TestDb) {
    let mut owner = connect(&db.0, OWNER).await;
    for (id, subject, redeem_before_ms, redeemed) in [
        (
            "00000000-0000-0000-0000-0000000000b1",
            "synthetic-redeemed",
            4102444800000_i64,
            true,
        ),
        (
            "00000000-0000-0000-0000-0000000000b2",
            "synthetic-withdrawn",
            4102444800000,
            false,
        ),
        (
            "00000000-0000-0000-0000-0000000000b3",
            "synthetic-expired",
            1,
            false,
        ),
    ] {
        sqlx::query(
            "INSERT INTO openmettle.home_invitations
                (id,provider_id,provider_generation,provider_epoch,issuer,subject,redeem_before_ms,
                 approval_until_ms,created_by,withdrawn_by,withdrawn_at,approval_id,redeemed_at,login_id)
             SELECT $1::uuid,$2::uuid,0,max(epoch),'https://upgrade.example.test',$3,$4,4102444800001,
                    gen_random_uuid(),
                    CASE WHEN NOT $5 THEN gen_random_uuid() END,
                    CASE WHEN NOT $5 THEN clock_timestamp() END,
                    CASE WHEN $5 THEN $6::uuid END,
                    CASE WHEN $5 THEN clock_timestamp() END,
                    CASE WHEN $5 THEN repeat('b', 43) END
               FROM openmettle.login_provider_revisions WHERE provider_id=$2::uuid",
        )
        .bind(id)
        .bind(MEMBERSHIP_PROVIDER)
        .bind(subject)
        .bind(redeem_before_ms)
        .bind(redeemed)
        .bind(MEMBERSHIP_APPROVAL)
        .execute(&mut owner)
        .await
        .unwrap();
    }
}
// Every invitation column that schema 12 wrote. Migration 13 adds only code_hash. The filter
// reads code_hash through the row's JSON, so the snapshot also works on a schema-12 database,
// where the column does not exist yet.
async fn invitation_snapshot(db: &TestDb) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT (to_jsonb(t) - 'code_hash')::text FROM openmettle.home_invitations t
          WHERE to_jsonb(t) ->> 'code_hash' IS NULL ORDER BY 1",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap()
}
// Every invitation that holds a code hash, complete. Only schema 13 and later write one.
async fn coded_invitations(db: &TestDb) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT to_jsonb(t)::text FROM openmettle.home_invitations t
          WHERE code_hash IS NOT NULL ORDER BY 1",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap()
}
const MEMBERSHIP_PROVIDER: &str = "00000000-0000-0000-0000-000000000007";
const MEMBERSHIP_APPROVAL: &str = "00000000-0000-0000-0000-0000000000a8";
// Version-11 membership state written through its own grants: the owner records a mapping rule
// revision, an enrollment receipt and its missing observation (as the configuration script
// does). The API records the enrollment-derived grant and confirms the observation, as
// issuance reconciliation does.
async fn populate_membership(db: &TestDb, c: &Context, project: &str, scope: &str) {
    let rule = MappingInput {
        rule: RULE2,
        provider: MEMBERSHIP_PROVIDER,
        issuer: "https://issuer.example.test",
        actor: &c.actor,
        key: "membership-rule",
        expected_revision: 0,
        enabled: true,
        selector_kind: "group",
        claim_name: "groups",
        claim_value: "synthetic-team",
        binding_format: "openmettle.project-member",
        binding_version: 1,
        binding: project.as_bytes(),
    };
    map(db, &rule).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    let revision: i64 = sqlx::query_scalar(
        "INSERT INTO openmettle.membership_configuration_changes
            (request_id,approval_id,previous_revision,rule_id,rule_revision,project_id,scope_id,
             max_age_seconds,enabled,baseline_change,floor_ms,actor,reason)
         VALUES (gen_random_uuid(),$1::uuid,0,$2::uuid,1,$3::uuid,$4::uuid,180,true,NULL,NULL,
                 gen_random_uuid(),'upgrade fixture') RETURNING revision",
    )
    .bind(MEMBERSHIP_APPROVAL)
    .bind(RULE2)
    .bind(project)
    .bind(scope)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.membership_observations
            (approval_id,config_revision,enabled,floor_ms,rule_id,rule_revision,project_id,scope_id,
             max_age_seconds,observation)
         VALUES ($1::uuid,$2,true,NULL,$3::uuid,1,$4::uuid,$5::uuid,180,
                 ROW('missing',NULL)::openmettle.membership_evidence)",
    )
    .bind(MEMBERSHIP_APPROVAL)
    .bind(revision)
    .bind(RULE2)
    .bind(project)
    .bind(scope)
    .execute(&mut owner)
    .await
    .unwrap();
    let grant = change(
        db,
        &ChangeInput {
            assignment: Assignment {
                scope,
                target: Target::Project(project),
                grantee: &c.actor,
                format: "openmettle.project-member",
                version: 1,
                key: MEMBERSHIP_APPROVAL,
                mapping_rule: Some(RULE2),
            },
            actor: &c.actor,
            key: "membership-grant",
            expected_revision: 0,
            mapping_revision: Some(1),
            decision: Decision::Grant,
        },
    )
    .await
    .unwrap();
    let confirmed = sqlx::query(
        "UPDATE openmettle.membership_observations SET issued_ms=1000,expires_ms=4102444800000,
            observation=ROW('present',$2::uuid)::openmettle.membership_evidence,
            epoch=(SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id=$3::uuid),
            approval_generation=0,user_generation=1
         WHERE approval_id=$1::uuid",
    )
    .bind(MEMBERSHIP_APPROVAL)
    .bind(&grant.change)
    .bind(MEMBERSHIP_PROVIDER)
    .execute(&mut connect(&db.0, API).await)
    .await
    .unwrap();
    assert_eq!(confirmed.rows_affected(), 1);
}
async fn membership_snapshot(db: &TestDb) -> Vec<String> {
    let mut c = db.admin().await;
    let mut result = Vec::new();
    for table in [
        "membership_configuration_changes",
        "membership_observations",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT to_jsonb(t)::text FROM openmettle.{table} t ORDER BY 1"
        )))
        .fetch_all(&mut c)
        .await
        .unwrap();
        result.push(table.into());
        result.extend(rows);
    }
    result
}
// Synthetic protected-login rows written with the API role's version-6 column grants.
async fn login_snapshot(db: &TestDb) -> Vec<String> {
    let mut c = db.admin().await;
    let mut result = Vec::new();
    for table in ["login_nonce_reservations", "login_transactions"] {
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT (to_jsonb(t) - 'session_generation' - 'session_issued')::text FROM openmettle.{table} t ORDER BY 1"
        )))
        .fetch_all(&mut c)
        .await
        .unwrap();
        assert!(!rows.is_empty(), "upgrade fixture must populate {table}");
        result.extend(rows);
    }
    result
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
    let (pid, ps) = project(&mut api, &c.actor).await;
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
    let with_login = versions.contains(&6);
    if with_login {
        let mut api = connect(&db.0, API).await;
        api.execute("INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ('upgrade-key', decode(repeat('01', 12), 'hex'))").await.unwrap();
        api.execute("INSERT INTO openmettle.login_transactions (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext) VALUES (repeat('a', 43), 'synthetic-binding'::bytea, 1, decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'), decode(repeat('04', 32), 'hex'), 'upgrade-key', decode(repeat('01', 12), 'hex'), decode(repeat('05', 59), 'hex'))").await.unwrap();
    }
    // Version 8 removed the provider provenance defaults; its writers must supply them.
    let with_sessions = versions.contains(&8);
    if with_sessions {
        owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason) VALUES ('00000000-0000-0000-0000-000000000007','https://upgrade.example.test','synthetic','fixture-owner','synthetic provider'); INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ('00000000-0000-0000-0000-000000000007','v1')").await.unwrap();
    } else if versions.contains(&7) {
        owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id) VALUES ('00000000-0000-0000-0000-000000000007','https://upgrade.example.test','synthetic'); INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ('00000000-0000-0000-0000-000000000007','v1')").await.unwrap();
    }
    // Populate the v10-only domain before upgrading the authentic predecessor.
    let recovery_before = if versions.contains(&10) {
        let provider = "00000000-0000-0000-0000-000000000007";
        let source: i64 = sqlx::query_scalar(
            "SELECT epoch FROM openmettle.login_provider_revisions WHERE provider_id=$1::uuid",
        )
        .bind(provider)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let retired: i64 = sqlx::query_scalar("INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ($1::uuid,NULL) RETURNING epoch")
            .bind(provider).fetch_one(&mut owner).await.unwrap();
        let restored: i64 = sqlx::query_scalar("INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ($1::uuid,'v1') RETURNING epoch")
            .bind(provider).fetch_one(&mut owner).await.unwrap();
        Some(sqlx::query_scalar::<_,String>("INSERT INTO openmettle.provider_recoveries AS r
            (request_id,operator_id,provider_id,source_epoch,retired_epoch,restored_epoch,access_generation)
            VALUES (gen_random_uuid(),gen_random_uuid(),$1::uuid,$2,$3,$4,0) RETURNING to_jsonb(r)::text")
            .bind(provider).bind(source).bind(retired).bind(restored).fetch_one(&mut owner).await.unwrap())
    } else {
        None
    };
    let session_tables = [
        "login_providers",
        "local_identity_approvals",
        "local_sessions",
    ];
    if with_sessions {
        // An owner approval, an issued gate and its retained session, written through the
        // version-8 owner and API grants, plus an advanced user session generation.
        owner.execute("INSERT INTO openmettle.local_identity_approvals(id,provider_id,identity_id,active,expires_ms,changed_by,change_reason) SELECT '00000000-0000-0000-0000-0000000000a8','00000000-0000-0000-0000-000000000007',id,true,4102444800000,'fixture-owner','synthetic approval' FROM openmettle.user_identities WHERE subject='synthetic-subject'").await.unwrap();
        let mut api = connect(&db.0, API).await;
        api.execute("INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ('upgrade-key', decode(repeat('06', 12), 'hex'))").await.unwrap();
        api.execute("INSERT INTO openmettle.login_transactions (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext) VALUES (repeat('b', 43), 'synthetic-binding'::bytea, 4102444800000, decode(repeat('07', 32), 'hex'), decode(repeat('08', 32), 'hex'), decode(repeat('09', 32), 'hex'), 'upgrade-key', decode(repeat('06', 12), 'hex'), decode(repeat('05', 59), 'hex'))").await.unwrap();
        api.execute("UPDATE openmettle.login_transactions SET consumed=true,ciphertext=NULL,session_issued=true WHERE id=repeat('b', 43)").await.unwrap();
        api.execute("INSERT INTO openmettle.local_sessions(id,secret_hash,login_id,provider_id,identity_id,approval_id,user_id,issued_client,issued_epoch,issued_revision,provider_generation,approval_generation,user_generation,created_ms,expires_ms) SELECT repeat('s', 43),decode(repeat('0a', 32), 'hex'),repeat('b', 43),a.provider_id,a.identity_id,a.id,i.user_id,'synthetic',(SELECT max(epoch) FROM openmettle.login_provider_revisions),1,0,0,0,1,4102444800000 FROM openmettle.local_identity_approvals a JOIN openmettle.user_identities i ON i.id=a.identity_id").await.unwrap();
        api.execute("UPDATE openmettle.users SET session_generation=1 WHERE id IN (SELECT user_id FROM openmettle.user_identities WHERE subject='synthetic-subject')").await.unwrap();
    }
    // Populate the v11-only domain (enrollment, rule, grant and observation) for the approval
    // above before upgrading the authentic predecessor.
    let membership_before = if versions.contains(&11) {
        populate_membership(&db, &c, &pid, &ps).await;
        let rows = membership_snapshot(&db).await;
        assert_eq!(rows.len(), 4, "one receipt and one confirmed observation");
        rows
    } else {
        // Migration 11 creates both tables empty.
        vec![
            "membership_configuration_changes".into(),
            "membership_observations".into(),
        ]
    };
    // Populate the v12-only domain before upgrading the authentic predecessor.
    let invitations_before = if versions.contains(&12) {
        populate_invitations(&db).await;
        let rows = invitation_snapshot(&db).await;
        assert_eq!(rows.len(), 3, "redeemed, withdrawn and expired invitations");
        rows
    } else {
        // Migration 12 creates the table empty.
        vec![]
    };
    // Populate the v13-only domain: a pending invitation, which schema 13 requires to hold
    // its code hash. Migration 14 replaces the redemption function and must leave it pending.
    let coded_before = if versions.contains(&13) {
        sqlx::query(
            "INSERT INTO openmettle.home_invitations
                (id,provider_id,provider_generation,provider_epoch,issuer,subject,redeem_before_ms,
                 approval_until_ms,created_by,code_hash)
             SELECT '00000000-0000-0000-0000-0000000000b4',$1::uuid,0,max(epoch),
                    'https://upgrade.example.test','synthetic-pending',4102444800000,4102444800001,
                    gen_random_uuid(),decode(repeat('5c',32),'hex')
               FROM openmettle.login_provider_revisions WHERE provider_id=$1::uuid",
        )
        .bind(MEMBERSHIP_PROVIDER)
        .execute(&mut owner)
        .await
        .unwrap();
        let rows = coded_invitations(&db).await;
        assert_eq!(rows.len(), 1, "one pending invitation with a code hash");
        rows
    } else {
        vec![]
    };
    let session_snapshot = async || {
        let mut c = db.admin().await;
        let mut rows: Vec<String> = sqlx::query_scalar(
            "SELECT id::text || ':' || session_generation FROM openmettle.users ORDER BY 1",
        )
        .fetch_all(&mut c)
        .await
        .unwrap();
        for table in session_tables {
            let table_rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
                "SELECT to_jsonb(t)::text FROM openmettle.{table} t ORDER BY 1"
            )))
            .fetch_all(&mut c)
            .await
            .unwrap();
            assert!(
                !table_rows.is_empty(),
                "upgrade fixture must populate {table}"
            );
            rows.extend(table_rows);
        }
        rows
    };
    let sessions_before = if with_sessions {
        session_snapshot().await
    } else {
        vec![]
    };
    let authority_before: Vec<String> = if versions.contains(&7) {
        sqlx::query_scalar("SELECT row(id,issuer,client_id,created_at)::text FROM openmettle.login_providers ORDER BY id").fetch_all(&mut owner).await.unwrap()
    } else {
        vec![]
    };
    let login_before = if with_login {
        login_snapshot(&db).await
    } else {
        vec![]
    };
    let grant_before = if with_grants {
        grant_snapshot(&db).await
    } else {
        vec![]
    };
    let expected_admission = if versions.contains(&9) {
        owner.execute("UPDATE openmettle.login_admission SET outstanding_limit=37,changed_by='fixture-owner',change_reason='upgrade fixture',changed_at=clock_timestamp()").await.unwrap();
        (Some(37), "fixture-owner".into())
    } else {
        (None, "migration-9".into())
    };
    let before = old_domain_snapshot(&db).await;
    let history: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    if versions.last() == Some(&9) {
        migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..10])
            .await
            .unwrap();
        let refusal = old_migrate();
        assert_eq!(refusal.status.code(), Some(1));
        assert!(stderr(&refusal).contains("database has migration 10"));
    }
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(
        db.history().await,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    );
    assert_eq!(old_domain_snapshot(&db).await, before);
    if with_grants {
        assert_eq!(grant_snapshot(&db).await, grant_before);
    }
    if with_login {
        assert_eq!(login_snapshot(&db).await, login_before);
    }
    // Migration 9 installs only an unconfigured limit: initiation stays refused until the owner
    // configures it, and existing login, approval and session rows are untouched.
    let admission: (Option<i32>, String) =
        sqlx::query_as("SELECT outstanding_limit,changed_by FROM openmettle.login_admission")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(admission, expected_admission);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT to_jsonb(r)::text FROM openmettle.provider_recoveries r"
        )
        .fetch_all(&mut owner)
        .await
        .unwrap(),
        recovery_before.into_iter().collect::<Vec<_>>()
    );
    assert_eq!(membership_snapshot(&db).await, membership_before);
    // Migration 13 keeps every closed invitation exactly as schema 12 wrote it and gives none a
    // code. The code-less redemption function is gone, and no v11 role privilege is widened.
    // Migration 14 changes no invitation row: a pending schema-13 invitation keeps its hash.
    assert_eq!(invitation_snapshot(&db).await, invitations_before);
    assert_eq!(coded_invitations(&db).await, coded_before);
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM pg_proc WHERE proname = 'redeem_home_invitation'
              AND pronamespace = 'openmettle'::regnamespace AND pronargs <> 6"
        )
        .await,
        0
    );
    let roles: Vec<(String, bool, bool, bool, bool, bool)> = sqlx::query_as(
        "SELECT role,
            has_table_privilege(role,'openmettle.membership_observations','SELECT'),
            has_table_privilege(role,'openmettle.membership_observations','INSERT,DELETE,TRUNCATE'),
            has_table_privilege(role,'openmettle.membership_configuration_changes','SELECT,INSERT,UPDATE,DELETE'),
            has_table_privilege(role,'openmettle.home_invitations','SELECT,INSERT,UPDATE,DELETE')
              OR has_any_column_privilege(role,'openmettle.home_invitations','SELECT,INSERT,UPDATE'),
            has_function_privilege(role,'openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)','EXECUTE')
         FROM unnest(ARRAY['openmettle_api','openmettle_worker','public']) WITH ORDINALITY AS r(role, ord)
         ORDER BY ord",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        roles,
        [
            ("openmettle_api".into(), true, false, false, false, true),
            (
                "openmettle_worker".into(),
                false,
                false,
                false,
                false,
                false
            ),
            ("public".into(), false, false, false, false, false),
        ]
    );
    if with_sessions {
        assert_eq!(session_snapshot().await, sessions_before);
    }
    if versions.contains(&7) {
        let after: Vec<String> = sqlx::query_scalar("SELECT row(id,issuer,client_id,created_at)::text FROM openmettle.login_providers ORDER BY id").fetch_all(&mut owner).await.unwrap();
        assert_eq!(after, authority_before);
    }
    if versions.contains(&7) && !with_sessions {
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM openmettle.users WHERE session_generation <> 0"
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &db,
                "SELECT count(*) FROM openmettle.login_transactions WHERE session_issued"
            )
            .await,
            0
        );
    }
    // Migration 7 creates empty authority tables: no managed provider is active until the
    // operator records one, so an upgraded deployment fails closed for managed login.
    if !versions.contains(&7) {
        assert_eq!(
            count(&db, "SELECT count(*) FROM openmettle.login_providers").await
                + count(
                    &db,
                    "SELECT count(*) FROM openmettle.login_provider_revisions"
                )
                .await,
            0
        );
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
    // Membership (v11), invitation (v12, v13) and native delivery (v14) privileges are outside
    // every historical binary's contract, so each historical migrator stops at the boundary
    // check before the unknown-version check.
    assert!(stderr(&refused).contains("boundary check refused"));
    if versions.last() == Some(&13) {
        // The v13 contract admits the redemption grant, which migration 14 keeps. Only the
        // native delivery table's grants are outside it.
        for violation in [
            "openmettle_api has SELECT on openmettle.native_handoffs",
            "openmettle_api has UPDATE on openmettle.native_handoffs.sealed",
            "openmettle_api has INSERT on openmettle.native_handoffs.audience",
        ] {
            assert!(stderr(&refused).contains(violation), "{}", stderr(&refused));
        }
        for admitted in ["redeem_home_invitation", "membership"] {
            assert!(!stderr(&refused).contains(admitted), "{}", stderr(&refused));
        }
    } else if versions.last() >= Some(&11) {
        // The v11 and v12 contracts already admit every membership privilege. Only the v13
        // redemption EXECUTE grant is outside them: v11 knows no redemption function, and
        // v12 admits only the code-less signature that migration 13 dropped.
        assert!(
            stderr(&refused).contains("openmettle_api has EXECUTE on function openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)"),
            "{}",
            stderr(&refused)
        );
        assert!(
            !stderr(&refused).contains("membership"),
            "{}",
            stderr(&refused)
        );
    }
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
