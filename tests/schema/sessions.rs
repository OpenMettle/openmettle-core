//! Migration-8 and actual SQL privilege evidence; isolated CI PostgreSQL only.
use super::*;

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn exact_session_privileges_and_inert_lock_columns() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason) VALUES ('00000000-0000-0000-0000-000000000008','https://session.example.test','synthetic','fixture-owner','synthetic provider')").await.unwrap();
    let mut api = connect(&db.0, API).await;
    api.execute("SELECT id FROM openmettle.login_providers FOR SHARE")
        .await
        .unwrap();
    api.execute("UPDATE openmettle.login_providers SET lock_guard=false")
        .await
        .unwrap();
    expect_state(
        &mut api,
        "UPDATE openmettle.login_providers SET lock_guard=true",
        "23514",
    )
    .await;
    expect_state(
        &mut api,
        "UPDATE openmettle.login_providers SET lock_guard=NULL",
        "23502",
    )
    .await;
    for sql in [
        "UPDATE openmettle.login_providers SET access_generation=access_generation+1",
        "UPDATE openmettle.login_providers SET issuer='https://other.example.test'",
        "UPDATE openmettle.login_providers SET changed_by='api'",
        "INSERT INTO openmettle.local_identity_approvals(provider_id,identity_id,active,expires_ms,changed_by,change_reason) VALUES (gen_random_uuid(),gen_random_uuid(),true,1,'api','bypass')",
        "UPDATE openmettle.local_identity_approvals SET active=true",
        "UPDATE openmettle.local_identity_approvals SET access_generation=0",
        "UPDATE openmettle.local_identity_approvals SET revision=1",
        "UPDATE openmettle.local_sessions SET user_id=gen_random_uuid()",
        "UPDATE openmettle.local_sessions SET expires_ms=9223372036854775807",
        "UPDATE openmettle.local_sessions SET secret_hash=decode(repeat('00',32),'hex')",
        "UPDATE openmettle.local_sessions SET provider_generation=0",
        "DELETE FROM openmettle.local_sessions",
        "DELETE FROM openmettle.login_transactions",
        "SELECT nextval('openmettle.login_provider_revisions_epoch_seq')",
    ] {
        expect_state(&mut api, sql, "42501").await;
    }
    // Compatibility is explicit: the table INSERT grant includes the new user column.
    api.execute("INSERT INTO openmettle.users(session_generation) VALUES (7)")
        .await
        .unwrap();
    for role in [WORKER, CAPPED] {
        let mut c = connect(&db.0, role).await;
        if role == WORKER {
            expect_state(&mut c, "SELECT * FROM openmettle.local_sessions", "42501").await;
            // From migration 15 the worker reads approvals for its recheck (ADR 0027), but
            // cannot lock or change them.
            expect_state(
                &mut c,
                "SELECT id FROM openmettle.local_identity_approvals FOR SHARE",
                "42501",
            )
            .await;
            expect_state(
                &mut c,
                "UPDATE openmettle.local_identity_approvals SET lock_guard=false",
                "42501",
            )
            .await;
        } else {
            // Inherited API login can lock but cannot change authority.
            c.execute("SELECT id FROM openmettle.login_providers FOR SHARE")
                .await
                .unwrap();
            expect_state(
                &mut c,
                "UPDATE openmettle.login_providers SET access_generation=0",
                "42501",
            )
            .await;
        }
    }
    for table in ["local_sessions", "local_identity_approvals"] {
        let public: bool = sqlx::query_scalar("SELECT has_table_privilege('public',$1,'SELECT')")
            .bind(format!("openmettle.{table}"))
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert!(!public);
    }
    for (grant, revoke) in [
        (
            "GRANT UPDATE(access_generation) ON openmettle.login_providers TO openmettle_api",
            "REVOKE UPDATE(access_generation) ON openmettle.login_providers FROM openmettle_api",
        ),
        (
            "GRANT UPDATE(active) ON openmettle.local_identity_approvals TO openmettle_api",
            "REVOKE UPDATE(active) ON openmettle.local_identity_approvals FROM openmettle_api",
        ),
        (
            "GRANT DELETE ON openmettle.local_sessions TO openmettle_api",
            "REVOKE DELETE ON openmettle.local_sessions FROM openmettle_api",
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
async fn migration_eight_rollback_and_version_gated_privileges() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..7])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("CREATE TABLE openmettle.local_identity_approvals(conflict boolean)")
        .await
        .unwrap();
    assert!(
        migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
            .await
            .is_err()
    );
    assert_eq!(db.history().await, versions_through(7));
    let new_columns:i64=sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema='openmettle' AND column_name IN ('session_generation','session_issued','lock_guard')").fetch_one(&mut owner).await.unwrap();
    assert_eq!(new_columns, 0, "preceding ALTERs must roll back");
    owner.execute("DROP TABLE openmettle.local_identity_approvals; ALTER TABLE openmettle.login_providers ADD COLUMN lock_guard boolean; GRANT UPDATE(lock_guard) ON openmettle.login_providers TO openmettle_api").await.unwrap();
    assert!(matches!(
        migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
    owner.execute("REVOKE UPDATE(lock_guard) ON openmettle.login_providers FROM openmettle_api; ALTER TABLE openmettle.login_providers DROP COLUMN lock_guard").await.unwrap();
    migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(db.history().await, all_versions());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn provider_provenance_backfills_v7_but_requires_explicit_values_after_upgrade() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(5)), &MIGRATIONS[..7])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id) VALUES ('00000000-0000-0000-0000-000000000008','https://session.example.test','synthetic')").await.unwrap();
    migrate::apply(&db.settings(Duration::from_secs(5)), MIGRATIONS)
        .await
        .unwrap();
    let provenance: (String, String) =
        sqlx::query_as("SELECT changed_by,change_reason FROM openmettle.login_providers")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(
        provenance,
        ("migration-8".into(), "initial session authority".into())
    );
    let defaults: Vec<Option<String>> = sqlx::query_scalar("SELECT column_default FROM information_schema.columns WHERE table_schema='openmettle' AND table_name='login_providers' AND column_name IN ('changed_by','change_reason')")
        .fetch_all(&mut owner).await.unwrap();
    assert_eq!(defaults, vec![None, None]);
    for sql in [
        "INSERT INTO openmettle.login_providers(id,issuer,client_id) VALUES (gen_random_uuid(),'https://new.example.test','synthetic')",
        "INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by) VALUES (gen_random_uuid(),'https://new.example.test','synthetic','fixture-owner')",
        "INSERT INTO openmettle.login_providers(id,issuer,client_id,change_reason) VALUES (gen_random_uuid(),'https://new.example.test','synthetic','new provider')",
    ] {
        expect_state(&mut owner, sql, "23502").await;
    }
    owner.execute("INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason) VALUES (gen_random_uuid(),'https://new.example.test','synthetic','fixture-owner','new provider')").await.unwrap();
}
