use super::*;

// The candidate uses the real ten migrations on its private base. Release-binary
// qualification follows the actual merged predecessor at integration.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn upgrade_preserves_state_and_only_allows_exact_redemption_signature() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, &MIGRATIONS[..10]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("INSERT INTO openmettle.users DEFAULT VALUES")
        .await
        .unwrap();
    let previous = first_approval::everything(&db).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let current = first_approval::everything(&db).await;
    for (table, rows) in previous {
        if table != "_sqlx_migrations" {
            assert_eq!(rows, current[&table], "{table}");
        }
    }
    assert!(current["home_invitations"].is_empty());
    for role in [API, WORKER, CAPPED, "public"] {
        let privileges: (bool,bool,bool,bool) = sqlx::query_as("SELECT
            has_function_privilege($1, 'openmettle.redeem_home_invitation(uuid,text,text,text,bigint)', 'EXECUTE'),
            has_function_privilege($1, 'openmettle.check_home_redemption()', 'EXECUTE'),
            has_table_privilege($1, 'openmettle.home_invitations', 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
            OR has_any_column_privilege($1,'openmettle.home_invitations','SELECT,INSERT,UPDATE,REFERENCES'),
            has_any_column_privilege($1, 'openmettle.local_identity_approvals', 'INSERT')")
            .bind(role).fetch_one(&mut owner).await.unwrap();
        assert_eq!(
            privileges,
            (role == API || role == CAPPED, false, false, false),
            "{role}"
        );
    }
    for (grant, revoke) in [
        (
            "GRANT SELECT ON openmettle.home_invitations TO openmettle_api",
            "REVOKE SELECT ON openmettle.home_invitations FROM openmettle_api",
        ),
        (
            "GRANT EXECUTE ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint) TO openmettle_worker",
            "REVOKE EXECUTE ON FUNCTION openmettle.redeem_home_invitation(uuid,text,text,text,bigint) FROM openmettle_worker",
        ),
    ] {
        owner.execute(grant).await.unwrap();
        assert!(matches!(
            migrate::apply(&settings, MIGRATIONS).await,
            Err(Failure::Refused(_))
        ));
        owner.execute(revoke).await.unwrap();
    }
    owner.execute("CREATE FUNCTION openmettle.redeem_home_invitation(uuid) RETURNS int LANGUAGE sql AS 'SELECT 1'").await.unwrap();
    owner
        .execute(
            "GRANT EXECUTE ON FUNCTION openmettle.redeem_home_invitation(uuid) TO openmettle_api",
        )
        .await
        .unwrap();
    assert!(matches!(
        migrate::apply(&settings, MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
}
