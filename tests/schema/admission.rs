//! Migration 9 outstanding-login admission and its exact operator scripts (ADR 0014).
//! PostgreSQL tests need an isolated CI PostgreSQL 18 service. The psql scripts run unchanged
//! with the pinned service image's psql through `POSTGRES_CONTAINER`, as in the image checks.
use super::*;
use std::collections::BTreeSet;
#[path = "../support/psql.rs"]
mod psql_transport;

const LIMIT_SCRIPT: &str = include_str!("../../docs/operator/login-admission-limit.psql");
const CLEANUP_SCRIPT: &str = include_str!("../../docs/operator/login-gate-cleanup.psql");
const ADR: &str = include_str!("../../docs/adr/0014-login-admission.md");

#[test]
fn adr_embeds_the_exact_executed_operator_scripts() {
    for script in [LIMIT_SCRIPT, CLEANUP_SCRIPT] {
        assert!(ADR.contains(&format!("```sql\n{script}```")));
    }
}

#[test]
fn released_migration_sources_match_their_pinned_hashes() {
    use sha2::{Digest, Sha256};
    let expected = [
        "1672dd9259a2c9670fef4fac324af8a4fdf9b35fd9eabd421bd9f023571137bd",
        "b1bf6e677a74226d258292dc6d987158a5d81fe2fa0ba00d4e3ed1afdd0a4e5c",
        "1744f1ca3e4ef146e151e2c622dd7d19d02b295281db1c819d747970807111c1",
        "6c4a1794d1c132739fdaf1b48706e8b2884ef51e903f0f2a979837919a8f53f3",
        "3130bf356a92c08f08d9ec65e49bd4ae04c41dd82ebab2ee4e313427fa423680",
        "6ebaec059411b63e6b787ca7bb72de9e152809174c462c48a2173bdf7b10e078",
        "42e5ef4abffbbd6023f6e65a954a6f6ebedbdbcf46439f28f64e61260280842d",
        "9a77a03a838fa058ad3919ed8db5e483619755cc4a96959240202d6c35b3939a",
        "f73f2f41d56136d90deb49aac87ef835b96f50dea416871ec86cab61dd0b3c76",
        "91b95d8146362a47c78ebf96de7b9f2e81f625b99ac880ddb1f427c3f5652f57",
        "887728e24ebf829d4644b6f47937c37149862ab7a7d8069c278827141f9d7a84",
        "b71bee740d4a71320f26f3392ce2be0962f599d8c032383cb14fc11bf32b1763",
        "58312aca4b72100dd460f5cccfca9688154e83f4662268358834f75f8f49e7bd",
        "e02d6df9824120c788991dd4ec84dc5f5bd1069d780549c25ac5f2cd7e6efc4a",
        "b4203f2bf76cf54ec21882c40a41a312233c9be37a4631949f28e566b32dd118",
    ];
    assert_eq!(MIGRATIONS.len(), expected.len());
    for (migration, hash) in MIGRATIONS.iter().zip(expected) {
        assert_eq!(
            format!("{:x}", Sha256::digest(migration.sql.as_bytes())),
            hash,
            "migration {}",
            migration.version
        );
    }
}

/// Runs an exact operator script with the service container's psql as openmettle_owner.
fn psql(db: &TestDb, script: &str, variables: &[(&str, &str)]) -> Output {
    psql_spawn(db, script, variables)
        .wait_with_output()
        .unwrap()
}
/// Starts the same psql run without waiting, for tests that hold a lock it must wait for.
/// The server-side session reports application_name `psql`.
fn psql_spawn(db: &TestDb, script: &str, variables: &[(&str, &str)]) -> Child {
    let mut child = psql_start(db, variables);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child
}
fn psql_start(db: &TestDb, variables: &[(&str, &str)]) -> Child {
    psql_transport::start(&db.0, OWNER, PASSWORD, variables)
}
async fn limit_row(db: &TestDb) -> (Option<i32>, String, String) {
    sqlx::query_as(
        "SELECT outstanding_limit,changed_by,change_reason FROM openmettle.login_admission",
    )
    .fetch_one(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}
async fn try_begin(db: &TestDb, lifetime: u64) -> Result<Started, Error> {
    login::begin(
        &mut connect(&db.0, API).await,
        &provider("v1", true),
        &keys(),
        Duration::from_secs(lifetime),
        None,
    )
    .await
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn exact_admission_privileges_constraints_and_unconfigured_default() {
    let db = TestDb::migrated().await;
    assert_eq!(
        limit_row(&db).await,
        (
            None,
            "migration-9".into(),
            "unconfigured; login initiation refused".into()
        )
    );
    // Fresh migration refuses initiation before spending a reservation.
    assert_eq!(try_begin(&db, 60).await.unwrap_err(), Error::Unconfigured);
    assert_eq!(counts(&db).await, (0, 0, 0));
    let mut api = connect(&db.0, API).await;
    api.execute("SELECT outstanding_limit FROM openmettle.login_admission FOR UPDATE")
        .await
        .unwrap();
    api.execute("UPDATE openmettle.login_admission SET lock_guard=false")
        .await
        .unwrap();
    expect_state(
        &mut api,
        "UPDATE openmettle.login_admission SET lock_guard=true",
        "23514",
    )
    .await;
    for sql in [
        "UPDATE openmettle.login_admission SET outstanding_limit=65536",
        "UPDATE openmettle.login_admission SET changed_by='api'",
        "INSERT INTO openmettle.login_admission(id,changed_at,changed_by,change_reason) VALUES (true,now(),'api','bypass')",
        "DELETE FROM openmettle.login_admission",
        "DELETE FROM openmettle.login_transactions",
        "DELETE FROM openmettle.login_nonce_reservations",
    ] {
        expect_state(&mut api, sql, "42501").await;
    }
    let mut worker = connect(&db.0, WORKER).await;
    expect_state(
        &mut worker,
        "SELECT * FROM openmettle.login_admission",
        "42501",
    )
    .await;
    let mut capped = connect(&db.0, CAPPED).await;
    capped
        .execute("SELECT id FROM openmettle.login_admission FOR UPDATE")
        .await
        .unwrap();
    expect_state(
        &mut capped,
        "UPDATE openmettle.login_admission SET outstanding_limit=1",
        "42501",
    )
    .await;
    let mut owner = connect(&db.0, OWNER).await;
    let public: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('public','openmettle.login_admission','SELECT')",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(!public);
    for (sql, state) in [
        (
            "UPDATE openmettle.login_admission SET outstanding_limit=0",
            "23514",
        ),
        (
            "UPDATE openmettle.login_admission SET outstanding_limit=65537",
            "23514",
        ),
        (
            "UPDATE openmettle.login_admission SET changed_by=''",
            "23514",
        ),
        (
            "INSERT INTO openmettle.login_admission(id,changed_at,changed_by,change_reason) VALUES (false,now(),'owner','second')",
            "23514",
        ),
        (
            "INSERT INTO openmettle.login_admission(id,changed_at,changed_by,change_reason) VALUES (true,now(),'owner','second')",
            "23505",
        ),
        (
            "INSERT INTO openmettle.login_admission(changed_by,change_reason) VALUES ('owner','no timestamp')",
            "23502",
        ),
    ] {
        expect_state(&mut owner, sql, state).await;
    }
    let indexed: bool = sqlx::query_scalar(
        "SELECT to_regclass('openmettle.login_transactions_outstanding_idx') IS NOT NULL",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(indexed);
    for (grant, revoke) in [
        (
            "GRANT UPDATE(outstanding_limit) ON openmettle.login_admission TO openmettle_api",
            "REVOKE UPDATE(outstanding_limit) ON openmettle.login_admission FROM openmettle_api",
        ),
        (
            "GRANT SELECT ON openmettle.login_admission TO openmettle_worker",
            "REVOKE SELECT ON openmettle.login_admission FROM openmettle_worker",
        ),
        (
            "GRANT DELETE ON openmettle.login_transactions TO openmettle_api",
            "REVOKE DELETE ON openmettle.login_transactions FROM openmettle_api",
        ),
    ] {
        owner.execute(grant).await.unwrap();
        assert!(matches!(
            migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS).await,
            Err(Failure::Refused(_))
        ));
        owner.execute(revoke).await.unwrap();
    }
    migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn migration_nine_rollback_and_version_gated_privileges() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..8])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute(
            "CREATE INDEX login_transactions_outstanding_idx ON openmettle.login_transactions (id)",
        )
        .await
        .unwrap();
    assert!(
        migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
            .await
            .is_err()
    );
    assert_eq!(db.history().await, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(
        !db.exists("openmettle.login_admission").await,
        "the preceding CREATE TABLE must roll back"
    );
    owner
        .execute("DROP INDEX openmettle.login_transactions_outstanding_idx")
        .await
        .unwrap();
    // Grants on the new relation are outside the contract until version 9 is recorded.
    owner
        .execute("CREATE TABLE openmettle.login_admission(lock_guard boolean); GRANT UPDATE(lock_guard) ON openmettle.login_admission TO openmettle_api")
        .await
        .unwrap();
    assert!(matches!(
        migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
    owner
        .execute("DROP TABLE openmettle.login_admission")
        .await
        .unwrap();
    migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(
        db.history().await,
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn limit_script_compare_and_set_lowering_and_refusals() {
    let db = TestDb::migrated().await;
    let set = |expected: &str, limit: &str| {
        psql(
            &db,
            LIMIT_SCRIPT,
            &[
                ("expected_limit", expected),
                ("limit", limit),
                ("actor", "fixture-operator"),
                ("reason", "synthetic limit change"),
            ],
        )
    };
    let unchanged = (
        None,
        "migration-9".to_owned(),
        "unconfigured; login initiation refused".to_owned(),
    );
    // Stale expectation, out-of-range and malformed values all exit non-zero, unchanged.
    let stale = set("5", "2");
    assert!(!stale.status.success());
    assert!(stderr(&stale).contains("operator change refused"));
    for bad in ["0", "65537", "-1", "99999", "x"] {
        assert!(!set("", bad).status.success(), "{bad}");
    }
    // A missing variable is never interpolated as a value.
    let missing = psql(
        &db,
        LIMIT_SCRIPT,
        &[
            ("expected_limit", ""),
            ("limit", "3"),
            ("reason", "no actor"),
        ],
    );
    assert!(!missing.status.success());
    assert_eq!(limit_row(&db).await, unchanged);
    let out = set("", "2");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        limit_row(&db).await,
        (
            Some(2),
            "fixture-operator".into(),
            "synthetic limit change".into()
        )
    );
    try_begin(&db, 60).await.unwrap();
    try_begin(&db, 60).await.unwrap();
    let before = counts(&db).await;
    assert_eq!(try_begin(&db, 60).await.unwrap_err(), Error::Capacity);
    assert_eq!(counts(&db).await, before, "precheck spent no reservation");
    // Lowering below the outstanding count preserves both rows and refuses new work.
    let out = set("2", "1");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(counts(&db).await, before);
    assert_eq!(try_begin(&db, 60).await.unwrap_err(), Error::Capacity);
    assert!(!set("2", "4").status.success());
    assert_eq!(limit_row(&db).await.0, Some(1));
    // Clearing restores fail-closed refusal.
    let out = set("1", "");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(limit_row(&db).await.0, None);
    assert_eq!(try_begin(&db, 60).await.unwrap_err(), Error::Unconfigured);
    assert_eq!(counts(&db).await, before);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn cleanup_script_removes_only_expired_unreferenced_gates() {
    let db = TestDb::migrated().await;
    db.admit(16).await;
    let p = provider("v1", true);
    let mut api = connect(&db.0, API).await;
    let id = |s: &Started| s.state.expose().split_once('.').unwrap().0.to_owned();
    // a: expired unconsumed. b: expired consumed. c: live. d: expired with a retained session.
    // e: expired but locked by a concurrent transaction.
    let a = try_begin(&db, 5).await.unwrap();
    let b = try_begin(&db, 5).await.unwrap();
    let c = try_begin(&db, 600).await.unwrap();
    let d = try_begin(&db, 5).await.unwrap();
    let e = try_begin(&db, 5).await.unwrap();
    for s in [&b, &d] {
        login::consume(&mut api, p.clone(), &keys(), callback(s, "code"))
            .await
            .unwrap();
    }
    let mut owner = connect(&db.0, OWNER).await;
    owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason) VALUES ('00000000-0000-0000-0000-000000000014','https://cleanup.example.test','synthetic','fixture-owner','synthetic provider'); INSERT INTO openmettle.login_provider_revisions(provider_id,revision) VALUES ('00000000-0000-0000-0000-000000000014','v1')").await.unwrap();
    let user = new_user(&mut api).await;
    let identity: String = sqlx::query_scalar("INSERT INTO openmettle.user_identities(user_id,issuer,subject) VALUES ($1::uuid,'https://cleanup.example.test','synthetic-subject') RETURNING id::text")
        .bind(&user).fetch_one(&mut api).await.unwrap();
    let approval: String = sqlx::query_scalar("INSERT INTO openmettle.local_identity_approvals(provider_id,identity_id,active,expires_ms,changed_by,change_reason) VALUES ('00000000-0000-0000-0000-000000000014',$1::uuid,true,4102444800000,'fixture-owner','synthetic approval') RETURNING id::text")
        .bind(&identity).fetch_one(&mut owner).await.unwrap();
    sqlx::query("UPDATE openmettle.login_transactions SET session_issued=true WHERE id=$1")
        .bind(id(&d))
        .execute(&mut api)
        .await
        .unwrap();
    sqlx::query("INSERT INTO openmettle.local_sessions(id,secret_hash,login_id,provider_id,identity_id,approval_id,user_id,issued_client,issued_epoch,issued_revision,provider_generation,approval_generation,user_generation,created_ms,expires_ms) VALUES (repeat('s',43),decode(repeat('0a',32),'hex'),$1,'00000000-0000-0000-0000-000000000014',$2::uuid,$3::uuid,$4::uuid,'synthetic',(SELECT max(epoch) FROM openmettle.login_provider_revisions),1,0,0,0,1,4102444800000)")
        .bind(id(&d)).bind(&identity).bind(&approval).bind(&user).execute(&mut api).await.unwrap();
    // Wait on the primary clock until every short gate has expired.
    api.execute("SELECT pg_sleep(GREATEST(0, (max(expires_ms) - floor(extract(epoch FROM clock_timestamp())*1000))/1000.0 + 0.02)) FROM openmettle.login_transactions WHERE expires_ms < floor(extract(epoch FROM clock_timestamp())*1000) + 10000")
        .await
        .unwrap();
    let mut holder = connect(&db.0, API).await;
    holder.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT id FROM openmettle.login_transactions WHERE id=$1 FOR UPDATE")
        .bind(id(&e))
        .fetch_one(&mut holder)
        .await
        .unwrap();
    // Compare gate membership independently of the database's collation.
    let remaining = async || -> BTreeSet<String> {
        sqlx::query_scalar::<_, String>("SELECT id FROM openmettle.login_transactions")
            .fetch_all(&mut connect(&db.0, OWNER).await)
            .await
            .unwrap()
            .into_iter()
            .collect()
    };
    let reservations = counts(&db).await.0;
    assert_eq!(reservations, 5);
    let cleanup = |batch: &str| psql(&db, CLEANUP_SCRIPT, &[("batch", batch)]);
    for bad in ["0", "1001", "x", ""] {
        let out = cleanup(bad);
        assert!(!out.status.success(), "{bad}");
        assert_eq!(remaining().await.len(), 5, "{bad}");
    }
    let out = cleanup("1");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        remaining().await.len(),
        4,
        "a batch of one deletes exactly one gate"
    );
    let out = cleanup("1000");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        remaining().await,
        BTreeSet::from([id(&c), id(&d), id(&e)]),
        "live, referenced and locked gates remain"
    );
    holder.execute("ROLLBACK").await.unwrap();
    let out = cleanup("1000");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(remaining().await, BTreeSet::from([id(&c), id(&d)]));
    assert_eq!(
        counts(&db).await.0,
        reservations,
        "nonce reservations are retained"
    );
    // Deleted gates can never be consumed again; replay is refused.
    for s in [&a, &b, &e] {
        assert_eq!(
            login::consume(&mut api, p.clone(), &keys(), callback(s, "code"))
                .await
                .unwrap_err(),
            Error::Rejected
        );
    }
    assert_eq!(counts(&db).await.0, reservations);
}

#[path = "approval_change.rs"]
mod approval_change;
#[path = "first_approval.rs"]
mod first_approval;
#[path = "session_cleanup.rs"]
mod session_cleanup;

#[path = "provider_recovery.rs"]
mod provider_recovery;

#[path = "home_invitations.rs"]
mod home_invitations;

#[path = "authorization.rs"]
mod authorization;
