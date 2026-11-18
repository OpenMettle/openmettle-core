use super::*;

const CREATE: &str = include_str!("../../docs/operator/home-invitation-create.psql");
/// The invitation migration's version on this base. Becomes 12 when stacked on membership.
const VERSION: i64 = 11;
const PROVIDER: &str = "00000000-0000-0000-0000-0000000000c1";
const INVITATION: &str = "00000000-0000-0000-0000-0000000000c2";
const OPERATOR: &str = "00000000-0000-0000-0000-0000000000c3";
const ISSUER: &str = "https://Invitation.example.test/Realm";
/// Deterministic absolute cutoffs (2100-01-01), independent of the test clock.
const FUTURE: &str = "4102444800000";
const LATER: &str = "4102444800001";
const SEARCH_PATH: &str = "search_path=pg_catalog, pg_temp";

async fn function_contract(
    owner: &mut PgConnection,
) -> Vec<(String, String, bool, Vec<String>, Vec<String>)> {
    sqlx::query_as(
        "SELECT p.oid::regprocedure::text, pg_get_userbyid(p.proowner)::text, p.prosecdef,
                coalesce(p.proconfig, '{}')::text[],
                ARRAY(SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END
                             || ' ' || a.privilege_type || ' by ' || pg_get_userbyid(a.grantor)
                             || CASE WHEN a.is_grantable THEN ' grantable' ELSE '' END
                        FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a ORDER BY 1)
           FROM pg_proc p
          WHERE p.pronamespace = 'openmettle'::regnamespace
            AND p.proname IN ('redeem_home_invitation', 'check_home_redemption')
          ORDER BY 1",
    )
    .fetch_all(owner)
    .await
    .unwrap()
}

// The candidate uses the real ten migrations on its private base. Release-binary
// qualification follows the actual merged predecessor at integration.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn upgrade_preserves_state_and_only_allows_exact_redemption_signature() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    let before = usize::try_from(VERSION - 1).unwrap();
    migrate::apply(&settings, &MIGRATIONS[..before])
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("INSERT INTO openmettle.users DEFAULT VALUES")
        .await
        .unwrap();
    let previous = first_approval::everything(&db).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(MIGRATIONS[before].version, VERSION);
    let current = first_approval::everything(&db).await;
    for (table, rows) in previous {
        if table != "_sqlx_migrations" {
            assert_eq!(rows, current[&table], "{table}");
        }
    }
    assert!(current["home_invitations"].is_empty());
    // Owner, security mode, pinned search path and the complete effective ACL.
    let owned = |name: &str, definer: bool, acl: &[&str]| {
        (
            name.to_owned(),
            OWNER.to_owned(),
            definer,
            vec![SEARCH_PATH.to_owned()],
            acl.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(),
        )
    };
    assert_eq!(
        function_contract(&mut owner).await,
        [
            owned(
                "openmettle.check_home_redemption()",
                false,
                &["openmettle_owner EXECUTE by openmettle_owner"],
            ),
            owned(
                "openmettle.redeem_home_invitation(uuid,text,text,text,bigint)",
                true,
                &[
                    "openmettle_api EXECUTE by openmettle_owner",
                    "openmettle_owner EXECUTE by openmettle_owner",
                ],
            ),
        ]
    );
    let trigger: (bool, bool, bool, String) = sqlx::query_as(
        "SELECT tgconstraint <> 0, tgdeferrable, tginitdeferred, tgfoid::regprocedure::text
           FROM pg_trigger WHERE tgrelid = 'openmettle.home_invitations'::regclass
            AND tgname = 'home_redemption_session'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        trigger,
        (
            true,
            true,
            true,
            "openmettle.check_home_redemption()".into()
        )
    );
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
        (
            "GRANT EXECUTE ON FUNCTION openmettle.check_home_redemption() TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION openmettle.check_home_redemption() FROM PUBLIC",
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

// The create command and the table constraint apply one byte predicate where the server does
// not validate client bytes.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn create_command_and_table_refuse_high_bit_subjects_on_sql_ascii() {
    let db = TestDb::create(
        "SELECT pg_advisory_lock_shared($1)",
        "TEMPLATE template0 ENCODING 'SQL_ASCII' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C'",
    )
    .await;
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query("INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason) VALUES ($1::uuid, $2, 'synthetic', 'fixture-owner', 'synthetic provider')")
        .bind(PROVIDER).bind(ISSUER).execute(&mut owner).await.unwrap();
    let epoch: i64 = sqlx::query_scalar("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, 'v1') RETURNING epoch")
        .bind(PROVIDER).fetch_one(&mut owner).await.unwrap();
    let vars = |subject: &'static str| {
        [
            ("invitation", INVITATION),
            ("operator", OPERATOR),
            ("provider", PROVIDER),
            ("issuer", ISSUER),
            ("subject", subject),
            ("expected_generation", "0"),
            ("redeem_before_ms", FUTURE),
            ("approval_until_ms", LATER),
        ]
    };
    let high = "Synthetic Subjéct";
    let out = psql(&db, CREATE, &vars(high));
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), stderr(&out));
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(text.contains("home invitation creation refused"), "{text}");
    for value in [
        INVITATION,
        OPERATOR,
        PROVIDER,
        ISSUER,
        "Synthetic Subj",
        FUTURE,
    ] {
        assert!(!text.contains(value), "output repeats an input value");
    }
    let insert = |subject: &'static str| {
        sqlx::query("INSERT INTO openmettle.home_invitations (id, provider_id, provider_generation, provider_epoch, issuer, subject, redeem_before_ms, approval_until_ms, created_by) VALUES ($1::uuid, $2::uuid, 0, $3, $4, $5, $6, $7, $8::uuid)")
            .bind(INVITATION).bind(PROVIDER).bind(epoch).bind(ISSUER).bind(subject)
            .bind(FUTURE.parse::<i64>().unwrap()).bind(LATER.parse::<i64>().unwrap()).bind(OPERATOR)
    };
    // A direct owner write meets the same byte predicate, in a transaction that is discarded.
    let mut tx = owner.begin().await.unwrap();
    let err = insert(high).execute(&mut *tx).await.unwrap_err();
    assert!(
        matches!(&err, sqlx::Error::Database(e) if e.code().as_deref() == Some("23514")),
        "{err:?}"
    );
    tx.rollback().await.unwrap();
    let mut tx = owner.begin().await.unwrap();
    insert("Synthetic Subject").execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();

    let out = psql(&db, CREATE, &vars("Synthetic Subject"));
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"home invitation created\n");
    let row: (String, i64, Vec<u8>) = sqlx::query_as(
        "SELECT id::text, provider_epoch, convert_to(subject, 'SQL_ASCII') FROM openmettle.home_invitations",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        row,
        (INVITATION.into(), epoch, b"Synthetic Subject".to_vec())
    );
}
