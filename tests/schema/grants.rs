//! Grant persistence uses synthetic vocabulary, never product permission meanings.
use super::cancellation::{ResponseBarrier, cancel_at_response};
use super::*;
use openmettle_core::grants::{
    self, Assignment, ChangeInput, Decision, GrantReceipt, Grantee, MappingInput, Target,
};

const PROVIDER: &str = "00000000-0000-0000-0000-000000000001";
const RULE1: &str = "00000000-0000-0000-0000-000000000002";
const RULE2: &str = "00000000-0000-0000-0000-000000000003";
fn input<'a>(c: &'a Context, key: &'a str) -> ChangeInput<'a> {
    ChangeInput {
        assignment: Assignment {
            scope: &c.scope,
            target: Target::Conversation(&c.conversation),
            grantee: Grantee::User(&c.actor),
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
async fn gateway_usage_and_settlement_column_grants() {
    let db = TestDb::migrated().await;
    let mut c = db.admin().await;
    // After migration 37, `openmettle_gateway` has zero table or column privileges anywhere in
    // `openmettle`, and `openmettle_api` has zero privileges on `gateway_requests`.
    for (table, column) in [
        ("gateway_usage_reports", "reasoning_included"),
        ("gateway_usage_reports", "incomplete"),
        ("gateway_settlements", "final"),
        ("gateway_settlements", "updated_at"),
        ("gateway_requests", "settled_final"),
        ("gateway_requests", "dispatched_at"),
        ("gateway_requests", "bearer_hash"),
        ("gateway_requests", "claim_hash"),
        ("gateway_requests", "cost_fixed_micros"),
        ("gateway_requests", "cost_micros_per_token"),
    ] {
        for role in [pg::GATEWAY, API, WORKER, ISSUANCE, "public"] {
            let writes: (bool, bool) = sqlx::query_as(
                "SELECT has_column_privilege($1,$2,$3,'INSERT'), has_column_privilege($1,$2,$3,'UPDATE')",
            )
            .bind(role)
            .bind(format!("openmettle.{table}"))
            .bind(column)
            .fetch_one(&mut c)
            .await
            .unwrap();
            assert_eq!(writes, (false, false), "{role} {table}.{column}");
        }
    }
    // `openmettle_gateway` holds zero SELECT/INSERT/UPDATE/DELETE privileges on every table in `openmettle`.
    let gateway_table_privs: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM pg_class cl
           JOIN pg_namespace ns ON ns.oid = cl.relnamespace
          WHERE ns.nspname = 'openmettle'
            AND cl.relkind IN ('r', 'p')
            AND (has_table_privilege('openmettle_gateway', cl.oid, 'SELECT')
                 OR has_table_privilege('openmettle_gateway', cl.oid, 'INSERT')
                 OR has_table_privilege('openmettle_gateway', cl.oid, 'UPDATE')
                 OR has_table_privilege('openmettle_gateway', cl.oid, 'DELETE'))",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(gateway_table_privs, 0);

    // `openmettle_gateway` holds EXECUTE ONLY on `gateway_dispatch`, `gateway_dispatch_scoped`,
    // and `gateway_settle_report`.
    let gateway_exec_fns: Vec<String> = sqlx::query_scalar(
        "SELECT p.oid::regprocedure::text
           FROM pg_proc p
           JOIN pg_namespace ns ON ns.oid = p.pronamespace
          WHERE ns.nspname = 'openmettle'
            AND has_function_privilege('openmettle_gateway', p.oid, 'EXECUTE')
          ORDER BY p.oid::regprocedure::text COLLATE \"C\"",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    assert_eq!(
        gateway_exec_fns,
        vec![
            "openmettle.gateway_dispatch(uuid,bytea)",
            "openmettle.gateway_dispatch_scoped(uuid,bytea)",
            "openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text)",
        ]
    );

    for (function, allowed_role) in [
        (
            "openmettle.gateway_unreported_candidates(timestamptz,uuid,timestamptz,uuid,integer)",
            Some(WORKER),
        ),
        ("openmettle.gateway_close_unreported(uuid)", Some(WORKER)),
        ("openmettle.enforce_gateway_report_sweep_only()", None),
        (
            "openmettle.gateway_handoff_round(uuid,bytea,uuid,bytea,bigint,bigint)",
            Some(WORKER),
        ),
        ("openmettle.enforce_gateway_report_bound_cost()", None),
        ("openmettle.gateway_snapshot_cost_bound(text)", None),
        (
            "openmettle.gateway_backfill_legacy_request_cost_bound(uuid,bigint,bigint)",
            None,
        ),
        ("openmettle.gateway_release(uuid,bytea)", Some(WORKER)),
        (
            "openmettle.quota_recover_lost_handoff(uuid,bytea,uuid,uuid,uuid)",
            Some(WORKER),
        ),
        (
            "openmettle.quota_lock_gateway_request_for_settlement(uuid)",
            None,
        ),
        (
            "openmettle.quota_settle_gateway_usage(uuid,uuid,uuid,bigint)",
            None,
        ),
        (
            "openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text)",
            Some(pg::GATEWAY),
        ),
    ] {
        for role in [pg::GATEWAY, API, WORKER, ISSUANCE, "public"] {
            let can_exec: bool =
                sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                    .bind(role)
                    .bind(function)
                    .fetch_one(&mut c)
                    .await
                    .unwrap();
            assert_eq!(
                can_exec,
                allowed_role == Some(role),
                "{role} EXECUTE {function}"
            );
        }
    }
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
    r.assignment.grantee = Grantee::User(&other.actor);
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
    assert_eq!(v4.history().await, versions_through(4));
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
    assert_eq!(db.history().await, versions_through(4));
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
    assert_eq!(db.history().await, versions_through(4));
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
        assert_eq!(db.history().await, versions_through(4), "{kill}");
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
    assert_eq!(
        count(&db, "SELECT count(*) FROM openmettle.grant_mapping_rules").await,
        0
    );
    db.wait_no_migration_session().await;
}
async fn old_domain_snapshot(db: &TestDb, base_version: i64) -> Vec<String> {
    snapshot_nonempty_at(
        &mut db.admin().await,
        &[
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
        ],
        base_version,
    )
    .await
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V4_BINARY_DIR required"]
async fn populated_v4_upgrade_and_authentic_v4_binaries() {
    populated_upgrade("V4_BINARY_DIR", &versions_through(4), false).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V5_BINARY_DIR required"]
async fn populated_v5_upgrade_and_authentic_v5_binaries() {
    populated_upgrade("V5_BINARY_DIR", &versions_through(5), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V6_BINARY_DIR required"]
async fn populated_v6_upgrade_and_authentic_v6_binaries() {
    populated_upgrade("V6_BINARY_DIR", &versions_through(6), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V7_BINARY_DIR required"]
async fn populated_v7_upgrade_and_authentic_v7_binaries() {
    populated_upgrade("V7_BINARY_DIR", &versions_through(7), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V8_BINARY_DIR required"]
async fn populated_v8_upgrade_and_authentic_v8_binaries() {
    populated_upgrade("V8_BINARY_DIR", &versions_through(8), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V9_BINARY_DIR required"]
async fn populated_v9_upgrade_and_authentic_v9_binaries() {
    populated_upgrade("V9_BINARY_DIR", &versions_through(9), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V10_BINARY_DIR required"]
async fn populated_v10_upgrade_and_authentic_v10_binaries() {
    populated_upgrade("V10_BINARY_DIR", &versions_through(10), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V11_BINARY_DIR required"]
async fn populated_v11_upgrade_and_authentic_v11_binaries() {
    populated_upgrade("V11_BINARY_DIR", &versions_through(11), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V12_BINARY_DIR required"]
async fn populated_v12_upgrade_and_authentic_v12_binaries() {
    populated_upgrade("V12_BINARY_DIR", &versions_through(12), true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 and authentic V13_BINARY_DIR required"]
async fn populated_v13_upgrade_and_authentic_v13_binaries() {
    populated_upgrade("V13_BINARY_DIR", &versions_through(13), true).await;
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
// Every invitation column present at `base_version`. Migration 13 adds only `code_hash`
// (NULL on closed pre-13 rows); the filter reads it through JSON so it works on schema 12 too.
async fn invitation_snapshot(db: &TestDb, base_version: i64) -> Vec<String> {
    let raw: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(t)::text FROM openmettle.home_invitations t
          WHERE to_jsonb(t) ->> 'code_hash' IS NULL",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap();
    let mut rows: Vec<String> = raw
        .iter()
        .map(|row| {
            normalize_upgraded_row("home_invitations", base_version, row)
                .unwrap_or_else(|error| panic!("{error}"))
        })
        .collect();
    rows.sort();
    rows
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
/// Write a single version 5..15 user grant through the pre-16 API column grants so populated
/// upgrade fixtures can seed older databases before migration 16 adds the grantee columns.
async fn populate_v5_grant(db: &TestDb, r: &ChangeInput<'_>) -> String {
    let (kind, target) = match r.assignment.target {
        Target::Project(id) => ("project", id),
        Target::Conversation(id) => ("conversation", id),
        Target::Artifact(id) => ("artifact", id),
    };
    let Grantee::User(grantee_user) = r.assignment.grantee else {
        panic!("pre-16 grant fixture only supports user grantees");
    };
    let source = if r.assignment.mapping_rule.is_some() {
        "mapped"
    } else {
        "direct"
    };
    let identity = format!("synthetic-v5-grant/{}", r.key).into_bytes();
    let digest = [0x5au8; 32];
    let mut api = connect(&db.0, API).await;
    api.execute("BEGIN").await.unwrap();
    let assignment: String = sqlx::query_scalar(
        "INSERT INTO openmettle.grant_assignments
            (scope_id,target_kind,project_id,conversation_id,artifact_id,grantee_user_id,
             assignment_format,assignment_version,assignment_key,source_kind,mapping_rule_id,
             created_by_user_id)
         VALUES($1::uuid,$2,CASE WHEN $2='project' THEN $3::uuid END,
                CASE WHEN $2='conversation' THEN $3::uuid END,
                CASE WHEN $2='artifact' THEN $3::uuid END,
                $4::uuid,$5,$6,$7,$8,$9::uuid,$10::uuid)
         RETURNING id::text",
    )
    .bind(r.assignment.scope)
    .bind(kind)
    .bind(target)
    .bind(grantee_user)
    .bind(r.assignment.format)
    .bind(r.assignment.version)
    .bind(r.assignment.key)
    .bind(source)
    .bind(r.assignment.mapping_rule)
    .bind(r.actor)
    .fetch_one(&mut api)
    .await
    .unwrap();
    let change_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut api)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.grant_changes
            (id,scope_id,assignment_id,revision,source_kind,mapping_rule_id,mapping_revision,
             actor_user_id,request_key,decision,cycle_id,request_identity,request_digest)
         VALUES($1::uuid,$2::uuid,$3::uuid,1,$4,$5::uuid,$6,$7::uuid,$8,'grant',$1::uuid,$9,$10)",
    )
    .bind(&change_id)
    .bind(r.assignment.scope)
    .bind(&assignment)
    .bind(source)
    .bind(r.assignment.mapping_rule)
    .bind(r.mapping_revision)
    .bind(r.actor)
    .bind(r.key)
    .bind(&identity)
    .bind(&digest[..])
    .execute(&mut api)
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.grant_assignments SET last_revision=1 WHERE id=$1::uuid")
        .bind(&assignment)
        .execute(&mut api)
        .await
        .unwrap();
    api.execute("COMMIT").await.unwrap();
    change_id
}

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
    let grant_change = populate_v5_grant(
        db,
        &ChangeInput {
            assignment: Assignment {
                scope,
                target: Target::Project(project),
                grantee: Grantee::User(&c.actor),
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
    .await;
    let confirmed = sqlx::query(
        "UPDATE openmettle.membership_observations SET issued_ms=1000,expires_ms=4102444800000,
            observation=ROW('present',$2::uuid)::openmettle.membership_evidence,
            epoch=(SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id=$3::uuid),
            approval_generation=0,user_generation=1
         WHERE approval_id=$1::uuid",
    )
    .bind(MEMBERSHIP_APPROVAL)
    .bind(&grant_change)
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
async fn login_snapshot(db: &TestDb, base_version: i64) -> Vec<String> {
    snapshot_nonempty_at(
        &mut db.admin().await,
        &["login_nonce_reservations", "login_transactions"],
        base_version,
    )
    .await
}
async fn populated_upgrade(binary_env: &str, versions: &[i64], with_grants: bool) {
    let base_version = *versions.last().unwrap();
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
        // Seed the actual schema of the historical writer, including its storage counters.
        let mut tx = api.begin().await.unwrap();
        sqlx::query("INSERT INTO openmettle.storage_accounts(scope_id) VALUES($1::uuid) ON CONFLICT DO NOTHING")
            .bind(scope).execute(&mut *tx).await.unwrap();
        let id: String = sqlx::query_scalar("INSERT INTO openmettle.storage_reservations
            (scope_id,actor_user_id,idempotency_key,artifact_id,max_bytes,request_identity,request_digest)
            VALUES($1::uuid,$2::uuid,$3,$4::uuid,100,convert_to($3,'UTF8'),sha256(convert_to($3,'UTF8')))
            RETURNING id::text")
            .bind(scope).bind(&c.actor).bind(key).bind(&artifact).fetch_one(&mut *tx).await.unwrap();
        let (active, retained, reserved) = if retain {
            (0i64, 10i64, 0i64)
        } else if settle {
            (10, 0, 0)
        } else {
            (0, 0, 100)
        };
        sqlx::query("UPDATE openmettle.storage_accounts SET active_bytes=active_bytes+$2,
            retained_bytes=retained_bytes+$3,reserved_bytes=reserved_bytes+$4 WHERE scope_id=$1::uuid")
            .bind(scope).bind(active).bind(retained).bind(reserved).execute(&mut *tx).await.unwrap();
        sqlx::query(
            "UPDATE openmettle.storage_instance SET active_bytes=active_bytes+$1,
            retained_bytes=retained_bytes+$2,reserved_bytes=reserved_bytes+$3",
        )
        .bind(active)
        .bind(retained)
        .bind(reserved)
        .execute(&mut *tx)
        .await
        .unwrap();
        if settle {
            sqlx::query(
                "INSERT INTO openmettle.artifacts(id,scope_id,scope_kind,owner_user_id)
                SELECT $1::uuid,id,kind,$3::uuid FROM openmettle.scopes WHERE id=$2::uuid",
            )
            .bind(&artifact)
            .bind(scope)
            .bind(&c.actor)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query("UPDATE openmettle.artifacts SET last_revision=1 WHERE id=$1::uuid")
                .bind(&artifact)
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query("INSERT INTO openmettle.artifact_revisions(scope_id,artifact_id,revision,reservation_id,
                size_bytes,content_digest,media_type,created_by_user_id)
                VALUES($1::uuid,$2::uuid,1,$3::uuid,10,$4,'text/plain',$5::uuid)")
                .bind(scope).bind(&artifact).bind(&id).bind(&[0u8;32][..]).bind(&c.actor).execute(&mut *tx).await.unwrap();
            sqlx::query("UPDATE openmettle.storage_reservations SET state='settled',settled_bytes=10,closed_at=now()
                WHERE id=$1::uuid").bind(&id).execute(&mut *tx).await.unwrap();
            if retain {
                sqlx::query(
                    "UPDATE openmettle.artifact_revisions SET state='retained',retained_at=now(),
                    purge_after=now()+interval '1 hour' WHERE reservation_id=$1::uuid",
                )
                .bind(&id)
                .execute(&mut *tx)
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
        populate_v5_grant(&db, &grant).await;
    }
    let with_login = versions.contains(&6);
    if with_login {
        let mut api = connect(&db.0, API).await;
        api.execute("INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ('upgrade-key', decode(repeat('01', 12), 'hex'))").await.unwrap();
        api.execute("INSERT INTO openmettle.login_transactions (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext) VALUES (repeat('a', 43), 'synthetic-binding'::bytea, 1, decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'), decode(repeat('04', 32), 'hex'), 'upgrade-key', decode(repeat('01', 12), 'hex'), decode(repeat('05', 59), 'hex'))").await.unwrap();
    }
    // Version 8 removed the provider provenance defaults; its writers must supply them. The
    // provider issues the fixture identity, so the retained session below validates.
    let with_sessions = versions.contains(&8);
    if with_sessions {
        owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason) VALUES ('00000000-0000-0000-0000-000000000007','https://issuer.example.test','synthetic','fixture-owner','synthetic provider'); INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ('00000000-0000-0000-0000-000000000007','v1')").await.unwrap();
    } else if versions.contains(&7) {
        owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id) VALUES ('00000000-0000-0000-0000-000000000007','https://issuer.example.test','synthetic'); INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ('00000000-0000-0000-0000-000000000007','v1')").await.unwrap();
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
        // version-8 owner and API grants, plus an advanced user session generation. The
        // session's digest is the ADR 0013 browser digest of SESSION_SECRET (`sessions::digest`),
        // and it records the advanced generation, so it is valid before and after upgrading.
        owner.execute("INSERT INTO openmettle.local_identity_approvals(id,provider_id,identity_id,active,expires_ms,changed_by,change_reason) SELECT '00000000-0000-0000-0000-0000000000a8','00000000-0000-0000-0000-000000000007',id,true,4102444800000,'fixture-owner','synthetic approval' FROM openmettle.user_identities WHERE subject='synthetic-subject'").await.unwrap();
        let mut api = connect(&db.0, API).await;
        api.execute("INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ('upgrade-key', decode(repeat('06', 12), 'hex'))").await.unwrap();
        api.execute("INSERT INTO openmettle.login_transactions (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext) VALUES (repeat('b', 43), 'synthetic-binding'::bytea, 4102444800000, decode(repeat('07', 32), 'hex'), decode(repeat('08', 32), 'hex'), decode(repeat('09', 32), 'hex'), 'upgrade-key', decode(repeat('06', 12), 'hex'), decode(repeat('05', 59), 'hex'))").await.unwrap();
        api.execute("UPDATE openmettle.login_transactions SET consumed=true,ciphertext=NULL,session_issued=true WHERE id=repeat('b', 43)").await.unwrap();
        api.execute("INSERT INTO openmettle.local_sessions(id,secret_hash,login_id,provider_id,identity_id,approval_id,user_id,issued_client,issued_epoch,issued_revision,provider_generation,approval_generation,user_generation,created_ms,expires_ms) SELECT repeat('s', 43),sha256(convert_to('openmettle/session-secret/1','UTF8') || decode('00','hex') || int8send(43) || convert_to(repeat('s', 43),'UTF8') || int8send(32) || decode(repeat('0a', 32), 'hex')),repeat('b', 43),a.provider_id,a.identity_id,a.id,i.user_id,'synthetic',(SELECT max(epoch) FROM openmettle.login_provider_revisions),1,0,0,1,1,4102444800000 FROM openmettle.local_identity_approvals a JOIN openmettle.user_identities i ON i.id=a.identity_id").await.unwrap();
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
        let rows = invitation_snapshot(&db, base_version).await;
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
        login_snapshot(&db, base_version).await
    } else {
        vec![]
    };
    let grant_before = if with_grants {
        grant_snapshot(&db, base_version).await
    } else {
        vec![]
    };
    let expected_admission = if versions.contains(&9) {
        owner.execute("UPDATE openmettle.login_admission SET outstanding_limit=37,changed_by='fixture-owner',change_reason='upgrade fixture',changed_at=clock_timestamp()").await.unwrap();
        (Some(37), "fixture-owner".into())
    } else {
        (None, "migration-9".into())
    };
    let before = old_domain_snapshot(&db, base_version).await;
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
    // Upgrade to schema 14 first so the historical refusals below stay exact; schema 15 is
    // applied and checked after them.
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..14])
        .await
        .unwrap();
    assert_eq!(db.history().await, versions_through(14));
    assert_eq!(old_domain_snapshot(&db, base_version).await, before);
    if with_grants {
        assert_eq!(grant_snapshot(&db, base_version).await, grant_before);
    }
    if with_login {
        assert_eq!(login_snapshot(&db, base_version).await, login_before);
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
    assert_eq!(
        invitation_snapshot(&db, base_version).await,
        invitations_before
    );
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

    // Schema 15 keeps every row. Its V1-05 privileges are outside every historical contract
    // too, so the historical migrator still stops at the boundary check. From v11, each
    // reported violation is a v13 redemption, v14 native delivery or v15 privilege, and no
    // API membership privilege is ever reported.
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(db.history().await, all_versions());
    // Every column added after `base_version` (including migration 17's `display_name` and
    // migration 19's run admission/claim columns) is verified against its declared default here.
    assert_eq!(old_domain_snapshot(&db, base_version).await, before);
    if with_grants {
        assert_eq!(grant_snapshot(&db, base_version).await, grant_before);
    }
    if with_login {
        assert_eq!(login_snapshot(&db, base_version).await, login_before);
    }
    assert_eq!(membership_snapshot(&db).await, membership_before);
    assert_eq!(
        invitation_snapshot(&db, base_version).await,
        invitations_before
    );
    if with_sessions {
        // Migration 18 (ADR 0030) keeps every session row, and the one issued before the
        // upgrade still validates as the API role. Its secret is 32 bytes of 0x0a.
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use openmettle_core::sessions;
        assert_eq!(session_snapshot().await, sessions_before);
        let credential = format!("{}.{}", "s".repeat(43), URL_SAFE_NO_PAD.encode([0x0a; 32]));
        let policy =
            sessions::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(10)).unwrap();
        let context = sessions::validate(&mut connect(&db.0, API).await, &credential, &policy)
            .await
            .unwrap();
        assert_eq!(context.user_id(), c.actor);
    }
    let full: Vec<String> =
        sqlx::query_scalar("SELECT t::text FROM openmettle._sqlx_migrations t ORDER BY version")
            .fetch_all(&mut db.admin().await)
            .await
            .unwrap();
    let refused = old_migrate();
    assert_eq!(refused.status.code(), Some(1));
    let text = stderr(&refused);
    assert!(text.contains("boundary check refused"), "{text}");
    if versions.last() >= Some(&11) {
        // v11 to v13 report at most 20 sorted violations, joined by "; ", on one line.
        let (_, reported) = text
            .split_once("boundary check refused to migrate: ")
            .unwrap_or_else(|| panic!("{text}"));
        let reported: Vec<&str> = reported.lines().next().unwrap().split("; ").collect();
        assert!(!reported.is_empty(), "{text}");
        let later_objects: Vec<String> = expected_added_tables_since(14)
            .map(|entry| format!("openmettle.{}", entry.table))
            .chain(
                additive_columns_since(14)
                    .map(|entry| format!("openmettle.{}.{}", entry.table, entry.column)),
            )
            // Pre-existing `runs` columns that gained worker UPDATE grants in migration 15.
            .chain([
                "openmettle.runs.state".to_owned(),
                "openmettle.runs.wait_reason".to_owned(),
            ])
            .collect();
        let worker_reads = [
            "openmettle_worker has SELECT on openmettle.membership_observations",
            "openmettle_worker has SELECT on openmettle.local_identity_approvals",
            "openmettle_worker has SELECT on openmettle.login_providers",
            "openmettle_worker has SELECT on openmettle.login_provider_revisions",
            "openmettle_worker has SELECT on openmettle.user_identities",
        ];
        // Old binaries print PostgreSQL's canonical regprocedure spelling. Resolve the exact
        // role/signature pairs granted by migrations 0024+ that still exist in the final catalog
        // (skipping signatures superseded and dropped by later migrations such as 0026).
        let quota_sql: String = MIGRATIONS[23..]
            .iter()
            .map(|m| m.sql)
            .collect::<Vec<_>>()
            .join("\n");
        let quota_grants: Vec<String> = sqlx::query_scalar(r"SELECT DISTINCT trim(role) ||
            ' has EXECUTE on function ' || proc::text
            FROM regexp_matches($1, 'GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+(openmettle\.\w+\([^)]*\))\s+TO\s+([^;]+);','gi') parts,
            unnest(string_to_array(parts[2],',')) role,
            LATERAL (SELECT to_regprocedure(parts[1]) AS proc) p
            WHERE p.proc IS NOT NULL")
            .bind(&quota_sql).fetch_all(&mut owner).await.unwrap();
        for violation in &reported {
            let later = violation.contains("openmettle.native_handoffs")
                || violation.ends_with(" on function openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)")
                || **violation
                    == format!("{WORKER} has EXECUTE on function openmettle.gateway_release(uuid,bytea)")
                || quota_grants.iter().any(|grant| grant==violation)
                || worker_reads.contains(violation)
                || later_objects.iter().any(|object| {
                    violation.ends_with(&format!(" on {object}"))
                        || violation.contains(&format!(" on {object}."))
                });
            assert!(later, "{violation} in {text}");
            assert!(
                !(violation.starts_with("openmettle_api ")
                    && violation.contains("openmettle.membership_")),
                "{text}"
            );
            if versions.last() == Some(&13) {
                assert!(!violation.contains("redeem_home_invitation"), "{text}");
            }
        }
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
    change(&db, &input(&c, "after-upgrade")).await.unwrap();
    assert_eq!(old_domain_snapshot(&db, base_version).await, before); // Sharing changes no owner, charge or limit.
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(old_domain_snapshot(&db, base_version).await, before);
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

async fn grant_snapshot(db: &TestDb, base_version: i64) -> Vec<String> {
    snapshot_nonempty_at(
        &mut db.admin().await,
        &[
            "grant_mapping_rules",
            "grant_mapping_revisions",
            "grant_assignments",
            "grant_changes",
        ],
        base_version,
    )
    .await
}
