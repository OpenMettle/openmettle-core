//! ADR 0030 (AUTHSEC-01) evidence: from migration 18 only `openmettle_issuance` holds the
//! writes of session issuance, the boundary audit keeps that role narrow and disjoint, and
//! migration 18 refuses to run without it. Isolated CI PostgreSQL 18 only.
use super::*;
use std::collections::BTreeSet;

/// Moves the issuance role out of the way for one case; [`RESTORE`] undoes it.
const HIDE: &str = "ALTER ROLE openmettle_issuance RENAME TO openmettle_fixture_hidden";
/// Undoes every cluster role change these tests make. Each statement is idempotent or fails
/// harmlessly when its change is absent.
const RESTORE: &[&str] = &[
    "ALTER ROLE openmettle_fixture_hidden RENAME TO openmettle_issuance",
    "REVOKE openmettle_issuance FROM openmettle_fixture_capped",
    "REVOKE pg_read_all_data FROM openmettle_issuance",
    "ALTER ROLE openmettle_issuance NOCREATEDB",
    "DROP ROLE IF EXISTS openmettle_fixture_issuer",
];
async fn restore(admin: &mut PgConnection) {
    for statement in RESTORE {
        let _ = admin.execute(*statement).await;
    }
}

const PROVIDER: &str = "00000000-0000-0000-0000-000000000030";
const LOGIN: &str = "repeat('f', 43)";
const REDEEM: &str = "SELECT * FROM openmettle.redeem_home_invitation(
    '00000000-0000-0000-0000-000000000030'::uuid, 'https://forgery.example.test'::text,
    'synthetic-subject'::text, repeat('f', 43), 1::bigint, decode(repeat('5c', 16), 'hex'))";
/// Step 5 of the confirmed forgery path: a session for the existing approval, copying every
/// value validation compares from current rows and choosing the secret digest and expiry.
const FORGE_SESSION: &str = "INSERT INTO openmettle.local_sessions
    (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id, issued_client,
     issued_epoch, issued_revision, provider_generation, approval_generation, user_generation,
     created_ms, expires_ms)
    SELECT repeat('s', 43), decode(repeat('0a', 32), 'hex'), repeat('f', 43), a.provider_id,
           a.identity_id, a.id, i.user_id, p.client_id,
           (SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id = p.id),
           a.revision, p.access_generation, a.access_generation, u.session_generation, 1,
           9223372036854775807
      FROM openmettle.local_identity_approvals a
      JOIN openmettle.user_identities i ON i.id = a.identity_id
      JOIN openmettle.users u ON u.id = i.user_id
      JOIN openmettle.login_providers p ON p.id = a.provider_id";

/// An approved identity with its user, personal scope and provider, and a consumed login that
/// the API role fabricated with plain SQL (forgery steps 1 to 4, which stay within its grants).
async fn forgery_fixture(db: &TestDb) {
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute(AssertSqlSafe(format!(
            "INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason)
             VALUES ('{PROVIDER}', 'https://forgery.example.test', 'synthetic', 'fixture-owner',
                     'synthetic provider');
             INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
             VALUES ('{PROVIDER}', 'v1')"
        )))
        .await
        .unwrap();
    let user = new_user(&mut owner).await;
    personal_scope(&mut owner, &user).await;
    owner
        .execute(AssertSqlSafe(format!(
            "WITH identity AS (
                 INSERT INTO openmettle.user_identities (user_id, issuer, subject)
                 VALUES ('{user}', 'https://forgery.example.test', 'synthetic-subject')
                 RETURNING id)
             INSERT INTO openmettle.local_identity_approvals
                 (provider_id, identity_id, active, expires_ms, changed_by, change_reason)
             SELECT '{PROVIDER}', id, true, 4102444800000, 'fixture-owner', 'synthetic approval'
               FROM identity"
        )))
        .await
        .unwrap();
    let mut api = connect(&db.0, API).await;
    for statement in [
        "INSERT INTO openmettle.login_nonce_reservations (key_id, nonce)
         VALUES ('forged', decode(repeat('01', 12), 'hex'))",
        "INSERT INTO openmettle.login_transactions
             (id, binding, expires_ms, state_hash, nonce_hash, caller_hash, key_id, nonce,
              ciphertext)
         VALUES (repeat('f', 43), 'forged-binding'::bytea, 4102444800000,
                 decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'),
                 decode(repeat('04', 32), 'hex'), 'forged', decode(repeat('01', 12), 'hex'),
                 decode(repeat('00', 59), 'hex'))",
        "UPDATE openmettle.login_transactions SET consumed = true, ciphertext = NULL
          WHERE id = repeat('f', 43)",
    ] {
        api.execute(statement).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn api_sql_cannot_issue_and_the_issuance_role_holds_exactly_its_writes() {
    let db = TestDb::migrated().await;
    forgery_fixture(&db).await;

    // Every issuance-only write of the forgery path is refused to the API role, and so are the
    // membership evidence, native delivery and redemption writes and the issuance row locks.
    let mut api = connect(&db.0, API).await;
    for sql in [
        FORGE_SESSION.to_owned(),
        format!(
            "UPDATE openmettle.login_transactions SET session_issued = true WHERE id = {LOGIN}"
        ),
        "UPDATE openmettle.membership_observations SET issued_ms = issued_ms".to_owned(),
        "UPDATE openmettle.membership_observations SET observation.state = 'present'".to_owned(),
        "INSERT INTO openmettle.native_handoffs
             (session_id, code_hash, registration, audience, challenge, sealed, expires_ms)
         SELECT id, decode(repeat('0b', 32), 'hex'), decode(repeat('0c', 32), 'hex'),
                decode(repeat('0d', 32), 'hex'), decode(repeat('0e', 32), 'hex'), NULL,
                4102444800000
           FROM openmettle.local_sessions"
            .to_owned(),
        REDEEM.to_owned(),
        "UPDATE openmettle.users SET lock_guard = false".to_owned(),
        "UPDATE openmettle.grant_mapping_rules SET lock_guard = false".to_owned(),
        "SET ROLE openmettle_issuance".to_owned(),
    ] {
        expect_state(&mut api, &sql, "42501").await;
    }
    // The API role keeps login initiation, consumption, validation locks, logout, native token
    // exchange and account administration.
    for sql in [
        "SELECT id FROM openmettle.users FOR SHARE",
        "SELECT id FROM openmettle.login_transactions FOR UPDATE",
        "UPDATE openmettle.local_sessions SET revoked = revoked",
        "UPDATE openmettle.native_handoffs SET sealed = sealed",
        "UPDATE openmettle.users SET session_generation = session_generation",
        "SELECT count(*) FROM openmettle.membership_observations",
    ] {
        api.execute(sql).await.unwrap();
    }

    // The same session write succeeds as the issuance role: the boundary is the role.
    let mut issuance = connect(&db.0, ISSUANCE).await;
    let mut tx = issuance.begin().await.unwrap();
    let inserted = tx.execute(FORGE_SESSION).await.unwrap();
    assert_eq!(inserted.rows_affected(), 1);
    tx.execute(AssertSqlSafe(format!(
        "UPDATE openmettle.login_transactions SET session_issued = true WHERE id = {LOGIN}"
    )))
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    // It reaches nothing outside issuance: no logout, account administration, native token
    // exchange, login initiation or consumption, secrets, admission or product data.
    for sql in [
        "UPDATE openmettle.local_sessions SET revoked = false",
        "UPDATE openmettle.users SET disabled_at = NULL",
        "UPDATE openmettle.users SET session_generation = 0",
        "SELECT * FROM openmettle.native_handoffs",
        "UPDATE openmettle.native_handoffs SET sealed = NULL",
        "SELECT * FROM openmettle.login_nonce_reservations",
        "INSERT INTO openmettle.login_nonce_reservations (key_id, nonce)
         VALUES ('issuance', decode(repeat('01', 12), 'hex'))",
        "UPDATE openmettle.login_transactions SET consumed = false",
        "INSERT INTO openmettle.users DEFAULT VALUES",
        "INSERT INTO openmettle.user_identities (user_id, issuer, subject)
         SELECT id, 'https://forgery.example.test', 'other' FROM openmettle.users",
        "UPDATE openmettle.local_identity_approvals SET active = true",
        "UPDATE openmettle.grant_mapping_rules SET last_revision = last_revision",
        "SELECT * FROM openmettle.home_invitations",
        "SELECT * FROM openmettle.login_admission",
        "SELECT * FROM openmettle.projects",
        "SELECT * FROM openmettle.messages",
        "DELETE FROM openmettle.local_sessions",
        "SET ROLE openmettle_api",
    ] {
        expect_state(&mut issuance, sql, "42501").await;
    }

    // The issuance role's complete ACL in schema openmettle is the ADR 0030 contract.
    let observed: BTreeSet<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname::text, '', a.privilege_type::text
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,
                aclexplode(c.relacl) a
          WHERE n.nspname = 'openmettle' AND a.grantee = 'openmettle_issuance'::regrole
         UNION ALL
         SELECT c.relname::text, t.attname::text, a.privilege_type::text
           FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace,
                aclexplode(t.attacl) a
          WHERE n.nspname = 'openmettle' AND t.attnum > 0 AND NOT t.attisdropped
            AND a.grantee = 'openmettle_issuance'::regrole
         UNION ALL
         SELECT p.oid::regprocedure::text, '', a.privilege_type::text
           FROM pg_proc p, aclexplode(p.proacl) a
          WHERE p.pronamespace = 'openmettle'::regnamespace
            AND a.grantee = 'openmettle_issuance'::regrole",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let mut expected = BTreeSet::new();
    let mut add = |relation: &str, columns: &[&str], privilege: &str| {
        for column in columns {
            expected.insert((relation.into(), (*column).into(), privilege.into()));
        }
    };
    for relation in [
        "login_transactions",
        "login_providers",
        "login_provider_revisions",
        "user_identities",
        "users",
        "scopes",
        "local_identity_approvals",
        "local_sessions",
        "membership_observations",
        "grant_mapping_rules",
        "grant_mapping_revisions",
        "grant_assignments",
        "grant_changes",
    ] {
        add(relation, &[""], "SELECT");
    }
    add(
        "local_sessions",
        &[
            "id",
            "secret_hash",
            "login_id",
            "provider_id",
            "identity_id",
            "approval_id",
            "user_id",
            "issued_client",
            "issued_epoch",
            "issued_revision",
            "provider_generation",
            "approval_generation",
            "user_generation",
            "created_ms",
            "expires_ms",
        ],
        "INSERT",
    );
    add("login_transactions", &["session_issued"], "UPDATE");
    add(
        "membership_observations",
        &[
            "issued_ms",
            "expires_ms",
            "observation",
            "epoch",
            "approval_generation",
            "user_generation",
        ],
        "UPDATE",
    );
    add(
        "native_handoffs",
        &[
            "session_id",
            "code_hash",
            "registration",
            "audience",
            "challenge",
            "sealed",
            "expires_ms",
        ],
        "INSERT",
    );
    for relation in [
        "login_providers",
        "local_identity_approvals",
        "users",
        "grant_mapping_rules",
    ] {
        add(relation, &["lock_guard"], "UPDATE");
    }
    add(
        "grant_assignments",
        &[
            "scope_id",
            "target_kind",
            "project_id",
            "conversation_id",
            "artifact_id",
            "grantee_kind",
            "grantee_user_id",
            "grantee_local_group_id",
            "grantee_oidc_group_id",
            "assignment_format",
            "assignment_version",
            "assignment_key",
            "source_kind",
            "mapping_rule_id",
            "created_by_user_id",
        ],
        "INSERT",
    );
    add("grant_assignments", &["last_revision"], "UPDATE");
    add(
        "grant_changes",
        &[
            "id",
            "scope_id",
            "assignment_id",
            "revision",
            "source_kind",
            "mapping_rule_id",
            "mapping_revision",
            "actor_user_id",
            "request_key",
            "decision",
            "cycle_id",
            "request_identity",
            "request_digest",
        ],
        "INSERT",
    );
    add(
        "openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)",
        &[""],
        "EXECUTE",
    );
    assert_eq!(observed, expected);

    // Only the issuance role holds the moved privileges: not the API role, its login roles,
    // the worker or PUBLIC.
    for role in [API, CAPPED, WORKER, "public", ISSUANCE] {
        let moved: Vec<bool> = sqlx::query_scalar(
            "SELECT unnest(ARRAY[
                has_any_column_privilege($1, 'openmettle.local_sessions', 'INSERT'),
                has_column_privilege($1, 'openmettle.login_transactions', 'session_issued', 'UPDATE'),
                has_column_privilege($1, 'openmettle.membership_observations', 'issued_ms', 'UPDATE'),
                has_column_privilege($1, 'openmettle.membership_observations', 'observation', 'UPDATE'),
                has_any_column_privilege($1, 'openmettle.native_handoffs', 'INSERT'),
                has_function_privilege($1,
                    'openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)', 'EXECUTE'),
                has_column_privilege($1, 'openmettle.users', 'lock_guard', 'UPDATE'),
                has_column_privilege($1, 'openmettle.grant_mapping_rules', 'lock_guard', 'UPDATE')])",
        )
        .bind(role)
        .fetch_all(&mut db.admin().await)
        .await
        .unwrap();
        assert_eq!(moved, [role == ISSUANCE; 8], "{role}");
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn boundary_audit_refuses_unsafe_issuance_provisioning() {
    let db = TestDb::exclusive().await;
    let _restore = Restore(RESTORE);
    let mut admin = admin(None).await;
    restore(&mut admin).await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // Object privileges: a moved write back on the API role, any privilege outside the
    // issuance contract, and a delegable one.
    const REDEMPTION: &str = "openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)";
    let mut owner = connect(&db.0, OWNER).await;
    let cases: Vec<(String, String, String)> = vec![
        (
            "GRANT INSERT (id) ON openmettle.local_sessions TO openmettle_api".into(),
            "REVOKE INSERT (id) ON openmettle.local_sessions FROM openmettle_api".into(),
            "openmettle_api has INSERT on openmettle.local_sessions.id".into(),
        ),
        (
            "GRANT UPDATE (session_issued) ON openmettle.login_transactions TO openmettle_api"
                .into(),
            "REVOKE UPDATE (session_issued) ON openmettle.login_transactions FROM openmettle_api"
                .into(),
            "openmettle_api has UPDATE on openmettle.login_transactions.session_issued".into(),
        ),
        (
            "GRANT UPDATE (issued_ms) ON openmettle.membership_observations TO openmettle_api"
                .into(),
            "REVOKE UPDATE (issued_ms) ON openmettle.membership_observations FROM openmettle_api"
                .into(),
            "openmettle_api has UPDATE on openmettle.membership_observations.issued_ms".into(),
        ),
        (
            "GRANT INSERT (audience) ON openmettle.native_handoffs TO openmettle_api".into(),
            "REVOKE INSERT (audience) ON openmettle.native_handoffs FROM openmettle_api".into(),
            "openmettle_api has INSERT on openmettle.native_handoffs.audience".into(),
        ),
        (
            format!("GRANT EXECUTE ON FUNCTION {REDEMPTION} TO openmettle_api"),
            format!("REVOKE EXECUTE ON FUNCTION {REDEMPTION} FROM openmettle_api"),
            format!("openmettle_api has EXECUTE on function {REDEMPTION}"),
        ),
        (
            "GRANT UPDATE (lock_guard) ON openmettle.users TO openmettle_api".into(),
            "REVOKE UPDATE (lock_guard) ON openmettle.users FROM openmettle_api".into(),
            "openmettle_api has UPDATE on openmettle.users.lock_guard".into(),
        ),
        (
            "GRANT UPDATE (lock_guard) ON openmettle.grant_mapping_rules TO openmettle_worker"
                .into(),
            "REVOKE UPDATE (lock_guard) ON openmettle.grant_mapping_rules FROM openmettle_worker"
                .into(),
            "openmettle_worker has UPDATE on openmettle.grant_mapping_rules.lock_guard".into(),
        ),
        (
            "GRANT UPDATE (revoked) ON openmettle.local_sessions TO openmettle_issuance".into(),
            "REVOKE UPDATE (revoked) ON openmettle.local_sessions FROM openmettle_issuance".into(),
            "openmettle_issuance has UPDATE on openmettle.local_sessions.revoked".into(),
        ),
        (
            "GRANT DELETE ON openmettle.local_sessions TO openmettle_issuance".into(),
            "REVOKE DELETE ON openmettle.local_sessions FROM openmettle_issuance".into(),
            "openmettle_issuance has DELETE on openmettle.local_sessions".into(),
        ),
        (
            "GRANT SELECT ON openmettle.native_handoffs TO openmettle_issuance".into(),
            "REVOKE SELECT ON openmettle.native_handoffs FROM openmettle_issuance".into(),
            "openmettle_issuance has SELECT on openmettle.native_handoffs".into(),
        ),
        (
            "GRANT CREATE ON SCHEMA openmettle TO openmettle_issuance".into(),
            "REVOKE CREATE ON SCHEMA openmettle FROM openmettle_issuance".into(),
            "openmettle_issuance has CREATE on schema openmettle".into(),
        ),
        (
            "GRANT INSERT (id) ON openmettle.local_sessions TO openmettle_issuance WITH GRANT OPTION"
                .into(),
            "REVOKE GRANT OPTION FOR INSERT (id) ON openmettle.local_sessions FROM openmettle_issuance"
                .into(),
            "openmettle_issuance has grant option for INSERT on openmettle.local_sessions.id"
                .into(),
        ),
    ];
    for (grant, revoke, violation) in &cases {
        owner.execute(AssertSqlSafe(grant.clone())).await.unwrap();
        refused_with(&settings, MIGRATIONS, violation).await;
        owner.execute(AssertSqlSafe(revoke.clone())).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // Cluster roles: a login role in both the API and issuance roles, an issuance role with a
    // membership or privileged attribute, and a missing issuance role.
    let roles: &[(&str, &str)] = &[
        (
            "GRANT openmettle_issuance TO openmettle_fixture_capped",
            "role openmettle_fixture_capped reaches more than one of openmettle_api, openmettle_issuance, openmettle_worker and openmettle_gateway",
        ),
        (
            "GRANT pg_read_all_data TO openmettle_issuance",
            "role openmettle_issuance must not be a member of pg_read_all_data",
        ),
        (
            "ALTER ROLE openmettle_issuance CREATEDB",
            "role openmettle_issuance must not be superuser or hold CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS",
        ),
        (HIDE, "role openmettle_issuance is missing"),
    ];
    for (setup, violation) in roles {
        admin.execute(*setup).await.unwrap();
        refused_with(&settings, MIGRATIONS, violation).await;
        restore(&mut admin).await;
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // A separate login role that is a member of the issuance role alone is accepted, and
    // issues with exactly that role's privileges.
    admin
        .execute(AssertSqlSafe(format!(
            "CREATE ROLE openmettle_fixture_issuer LOGIN PASSWORD '{PASSWORD}';
             GRANT openmettle_issuance TO openmettle_fixture_issuer"
        )))
        .await
        .unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let mut issuer = connect(&db.0, "openmettle_fixture_issuer").await;
    issuer
        .execute("SELECT count(*) FROM openmettle.local_sessions")
        .await
        .unwrap();
    expect_state(
        &mut issuer,
        "UPDATE openmettle.local_sessions SET revoked = false",
        "42501",
    )
    .await;
    drop(issuer);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn migration_eighteen_requires_the_issuance_role_and_rolls_back_whole() {
    let db = TestDb::exclusive().await;
    let _restore = Restore(RESTORE);
    let mut admin = admin(None).await;
    restore(&mut admin).await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, &MIGRATIONS[..17]).await.unwrap();
    admin.execute(HIDE).await.unwrap();

    // Before version 18 the role is not required, so the audit passes and migration 18 itself
    // refuses. Its transaction rolls back whole, leaving schema 17.
    let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
    assert!(
        matches!(
            &failure,
            Failure::Migrate(MigrateError::ExecuteMigration(_, 18))
        ) && failure.to_string().contains("SQLSTATE P0001"),
        "{failure}"
    );
    let output = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("migration 18 failed (SQLSTATE P0001)"),
        "{}",
        stderr(&output)
    );
    assert_eq!(db.history().await, versions_through(17));
    let schema_17: (i64, bool, bool, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM pg_attribute WHERE attname = 'lock_guard' AND NOT attisdropped
                   AND attrelid IN ('openmettle.users'::regclass,
                                    'openmettle.grant_mapping_rules'::regclass)),
                has_column_privilege('openmettle_api', 'openmettle.local_sessions', 'id', 'INSERT'),
                has_function_privilege('openmettle_api',
                    'openmettle.redeem_home_invitation(uuid,text,text,text,bigint,bytea)', 'EXECUTE'),
                has_database_privilege('openmettle_fixture_hidden', current_database(), 'CONNECT')",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(schema_17, (0, true, true, false));
    db.wait_no_migration_session().await;

    // Once provisioned, the same release migrates.
    admin.execute(RESTORE[0]).await.unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());
}
