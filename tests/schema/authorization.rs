//! Migration 15 (ADR 0027): authorization schema constraints, the exact role boundary, a
//! populated version-14 upgrade and the exact account administrator operator script. The
//! PostgreSQL tests need the isolated CI PostgreSQL 18 service; the script tests also need
//! POSTGRES_CONTAINER for the pinned service psql. All values are synthetic.
use super::first_approval::{everything, wait_for_psql};
use super::*;
use std::collections::BTreeSet;

const SCRIPT: &str = include_str!("../../docs/operator/grant-account-admin.psql");
const GUIDE: &str = include_str!("../../docs/operator/account-admin-recovery.md");
const ADR_0027: &str = include_str!("../../docs/adr/0027-authorization-and-private-projects.md");
const README: &str = include_str!("../../README.md");

const OPERATOR: &str = "00000000-0000-0000-0000-0000000000f1";
const UNKNOWN_USER: &str = "00000000-0000-0000-0000-0000000000e9";
const REQUESTS: [&str; 5] = [
    "00000000-0000-0000-0000-0000000001a1",
    "00000000-0000-0000-0000-0000000001a2",
    "00000000-0000-0000-0000-0000000001a3",
    "00000000-0000-0000-0000-0000000001a4",
    "00000000-0000-0000-0000-0000000001a5",
];

/// Every relation migration 15 creates.
const NEW_TABLES: [&str; 9] = [
    "account_admin_lock",
    "account_admins",
    "authorization_audit",
    "local_group_memberships",
    "local_groups",
    "platform_capability_denies",
    "project_settings",
    "user_capability_denies",
    "user_capability_grants",
];
/// Existing non-secret authority and membership tables the worker reads from version 15.
const AUTHORITY_TABLES: [&str; 5] = [
    "membership_observations",
    "local_identity_approvals",
    "login_providers",
    "login_provider_revisions",
    "user_identities",
];
/// New tables the worker's execution-time recheck reads.
const WORKER_NEW_READS: [&str; 5] = [
    "local_groups",
    "local_group_memberships",
    "platform_capability_denies",
    "user_capability_denies",
    "user_capability_grants",
];
/// The API role's complete column grants on the new tables, as declared in migration 15.
const API_COLUMNS: &[(&str, &str, &[&str])] = &[
    (
        "project_settings",
        "INSERT",
        &[
            "project_id",
            "scope_id",
            "name",
            "instructions",
            "defaults",
            "updated_by_user_id",
        ],
    ),
    (
        "project_settings",
        "UPDATE",
        &[
            "name",
            "instructions",
            "defaults",
            "revision",
            "archived_at",
            "deleted_at",
            "updated_at",
            "updated_by_user_id",
        ],
    ),
    (
        "local_groups",
        "INSERT",
        &["id", "name", "created_by_user_id", "updated_by_user_id"],
    ),
    (
        "local_groups",
        "UPDATE",
        &[
            "name",
            "revision",
            "disabled_at",
            "updated_at",
            "updated_by_user_id",
        ],
    ),
    (
        "local_group_memberships",
        "INSERT",
        &["group_id", "user_id", "active", "updated_by_user_id"],
    ),
    (
        "local_group_memberships",
        "UPDATE",
        &["active", "revision", "updated_at", "updated_by_user_id"],
    ),
    ("account_admin_lock", "UPDATE", &["lock_guard"]),
    (
        "account_admins",
        "INSERT",
        &["user_id", "active", "updated_by_user_id"],
    ),
    (
        "account_admins",
        "UPDATE",
        &["active", "revision", "updated_at", "updated_by_user_id"],
    ),
    (
        "platform_capability_denies",
        "INSERT",
        &["capability", "denied", "updated_by_user_id"],
    ),
    (
        "platform_capability_denies",
        "UPDATE",
        &["denied", "revision", "updated_at", "updated_by_user_id"],
    ),
    (
        "user_capability_denies",
        "INSERT",
        &["user_id", "capability", "denied", "updated_by_user_id"],
    ),
    (
        "user_capability_denies",
        "UPDATE",
        &["denied", "revision", "updated_at", "updated_by_user_id"],
    ),
    (
        "user_capability_grants",
        "INSERT",
        &["user_id", "capability", "granted", "updated_by_user_id"],
    ),
    (
        "user_capability_grants",
        "UPDATE",
        &["granted", "revision", "updated_at", "updated_by_user_id"],
    ),
    (
        "authorization_audit",
        "INSERT",
        &[
            "actor_user_id",
            "action",
            "target_kind",
            "target_id",
            "request_key",
            "reason",
            "details",
        ],
    ),
];

/// Executes one statement with text parameters and returns the affected row count.
async fn exec(
    connection: &mut PgConnection,
    sql: &'static str,
    binds: &[&str],
) -> Result<u64, sqlx::Error> {
    let mut query = sqlx::query(sql);
    for value in binds {
        query = query.bind(*value);
    }
    query.execute(connection).await.map(|r| r.rows_affected())
}

#[test]
fn migration_15_is_registered_and_the_admin_script_is_canonical() {
    let v15 = &MIGRATIONS[14];
    assert_eq!(
        (v15.version, v15.description),
        (15, "authorization and private projects")
    );
    assert!(GUIDE.contains("](grant-account-admin.psql)"));
    assert!(README.contains("](docs/operator/account-admin-recovery.md)"));
    assert!(ADR_0027.contains("docs/operator/grant-account-admin.psql"));
    // The executable file is the only account_admin recipe. It never edits users or deletes.
    let insert = "INSERT INTO openmettle.account_admins";
    assert_eq!(SCRIPT.matches(insert).count(), 1);
    for doc in [README, ADR_0027, GUIDE] {
        assert!(!doc.contains(insert));
        assert!(!doc.contains("UPDATE openmettle.account_admins"));
    }
    for forbidden in [
        "DELETE ",
        "TRUNCATE",
        "UPDATE openmettle.users",
        "INSERT INTO openmettle.users",
        "disabled_at = NULL",
    ] {
        assert!(!SCRIPT.contains(forbidden), "{forbidden}");
    }
    // SQL text uses only quoted :'name' variables. Unquoted references appear only in psql
    // meta-commands and name script-owned booleans.
    let owned = ["valid", "replayed", "same", "eligible", "granted"];
    for line in SCRIPT.lines().map(str::trim_start) {
        if line.starts_with("--") {
            continue;
        }
        let bytes = line.as_bytes();
        for (i, _) in line.match_indices(':') {
            let next = bytes.get(i + 1).copied().unwrap_or(b' ');
            if (i > 0 && bytes[i - 1] == b':') || next == b':' || next == b'\'' || next == b' ' {
                continue;
            }
            assert!(line.starts_with('\\'), "unquoted variable in SQL: {line}");
            let name: String = line[i + 1..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            assert!(owned.contains(&name.as_str()), "{line}");
        }
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn migration_15_grants_exactly_the_contract() {
    let db = TestDb::migrated().await;
    assert_eq!(db.history().await, all_versions());
    let mut admin = db.admin().await;
    let privileges = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
        "MAINTAIN",
    ];
    let table_privilege = "SELECT has_table_privilege($1, $2, $3)";
    // Table level: the API reads every new table, the worker only its recheck tables, and
    // nobody holds any other table-wide privilege. Writes are column grants only.
    for table in NEW_TABLES {
        for role in [API, WORKER, "public"] {
            for privilege in privileges {
                let expected = privilege == "SELECT"
                    && (role == API || role == WORKER && WORKER_NEW_READS.contains(&table));
                let granted: bool = sqlx::query_scalar(table_privilege)
                    .bind(role)
                    .bind(format!("openmettle.{table}"))
                    .bind(privilege)
                    .fetch_one(&mut admin)
                    .await
                    .unwrap();
                assert_eq!(granted, expected, "{role} {privilege} {table}");
            }
        }
    }
    for table in AUTHORITY_TABLES {
        for privilege in privileges {
            let granted: bool = sqlx::query_scalar(table_privilege)
                .bind(WORKER)
                .bind(format!("openmettle.{table}"))
                .bind(privilege)
                .fetch_one(&mut admin)
                .await
                .unwrap();
            assert_eq!(granted, privilege == "SELECT", "worker {privilege} {table}");
        }
        let column_writes: bool = sqlx::query_scalar(
            "SELECT has_any_column_privilege($1, $2, 'INSERT,UPDATE,REFERENCES')",
        )
        .bind(WORKER)
        .bind(format!("openmettle.{table}"))
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert!(!column_writes, "worker writes {table}");
    }
    // Column level: exactly the declared API grants on the new tables, nothing for the worker.
    let observed: BTreeSet<(String, String, String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text, pg_get_userbyid(x.grantee)::text,
                x.privilege_type::text
           FROM pg_attribute AS a
           JOIN pg_class AS c ON c.oid = a.attrelid
           JOIN pg_namespace AS n ON n.oid = c.relnamespace,
                aclexplode(a.attacl) AS x
          WHERE n.nspname = 'openmettle' AND c.relname::text = ANY ($1::text[])
            AND a.attnum > 0 AND NOT a.attisdropped AND x.grantee <> c.relowner",
    )
    .bind(NEW_TABLES.to_vec())
    .fetch_all(&mut admin)
    .await
    .unwrap()
    .into_iter()
    .collect();
    let expected: BTreeSet<(String, String, String, String)> = API_COLUMNS
        .iter()
        .flat_map(|(table, privilege, columns)| {
            columns.iter().map(move |column| {
                (
                    table.to_string(),
                    column.to_string(),
                    API.to_owned(),
                    privilege.to_string(),
                )
            })
        })
        .collect();
    assert_eq!(observed, expected);
    // Both roles may change only a run's lifecycle columns, never ownership or input.
    let run_columns = [
        ("state", true),
        ("wait_reason", true),
        ("last_event_sequence", true),
        ("id", false),
        ("scope_id", false),
        ("actor_user_id", false),
        ("conversation_id", false),
        ("branch_id", false),
        ("input_message_id", false),
        ("idempotency_key", false),
        ("snapshot_format", false),
        ("snapshot_version", false),
        ("input_snapshot", false),
        ("config_snapshot", false),
        ("request_identity", false),
        ("request_digest", false),
        ("created_at", false),
    ];
    for role in [API, WORKER] {
        for (column, expected) in run_columns {
            let granted: bool = sqlx::query_scalar(
                "SELECT has_column_privilege($1, 'openmettle.runs', $2, 'UPDATE')",
            )
            .bind(role)
            .bind(column)
            .fetch_one(&mut admin)
            .await
            .unwrap();
            assert_eq!(granted, expected, "{role} UPDATE runs.{column}");
        }
    }
    // ADR 0035 grants the worker only these session columns for effect authorization.
    let readable: Vec<String> = sqlx::query_scalar(
        "SELECT attname::text FROM pg_attribute WHERE attrelid = 'openmettle.local_sessions'::regclass
         AND attnum > 0 AND NOT attisdropped AND has_column_privilege($1, attrelid, attnum, 'SELECT')
         ORDER BY attname",
    ).bind(WORKER).fetch_all(&mut admin).await.unwrap();
    assert_eq!(
        readable,
        [
            "approval_generation",
            "approval_id",
            "created_ms",
            "expires_ms",
            "id",
            "identity_id",
            "issued_client",
            "issued_epoch",
            "provider_generation",
            "provider_id",
            "revoked",
            "user_generation",
            "user_id"
        ]
    );
    // Other private authority, receipt, and administration tables remain inaccessible.
    for table in [
        "login_transactions",
        "login_nonce_reservations",
        "native_handoffs",
        "provider_recoveries",
        "home_invitations",
        "membership_configuration_changes",
        "login_admission",
        "account_admins",
        "account_admin_lock",
        "authorization_audit",
        "project_settings",
        "_sqlx_migrations",
    ] {
        let any: bool = sqlx::query_scalar(
            "SELECT has_table_privilege($1, $2,
                      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                 OR has_any_column_privilege($1, $2, 'SELECT,INSERT,UPDATE,REFERENCES')",
        )
        .bind(WORKER)
        .bind(format!("openmettle.{table}"))
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert!(!any, "worker reaches {table}");
    }

    // Any privilege beyond the contract is the one reported violation.
    let settings = db.settings(Duration::from_secs(5));
    let mut owner = connect(&db.0, OWNER).await;
    for (grant, revoke, violation) in [
        (
            "GRANT UPDATE ON openmettle.authorization_audit TO openmettle_api",
            "REVOKE UPDATE ON openmettle.authorization_audit FROM openmettle_api",
            "openmettle_api has UPDATE on openmettle.authorization_audit",
        ),
        (
            "GRANT TRUNCATE ON openmettle.authorization_audit TO openmettle_api",
            "REVOKE TRUNCATE ON openmettle.authorization_audit FROM openmettle_api",
            "openmettle_api has TRUNCATE on openmettle.authorization_audit",
        ),
        (
            "GRANT INSERT (operator_id) ON openmettle.authorization_audit TO openmettle_api",
            "REVOKE INSERT (operator_id) ON openmettle.authorization_audit FROM openmettle_api",
            "openmettle_api has INSERT on openmettle.authorization_audit.operator_id",
        ),
        (
            "GRANT DELETE ON openmettle.local_group_memberships TO openmettle_api",
            "REVOKE DELETE ON openmettle.local_group_memberships FROM openmettle_api",
            "openmettle_api has DELETE on openmettle.local_group_memberships",
        ),
        (
            "GRANT UPDATE (user_id) ON openmettle.account_admins TO openmettle_api",
            "REVOKE UPDATE (user_id) ON openmettle.account_admins FROM openmettle_api",
            "openmettle_api has UPDATE on openmettle.account_admins.user_id",
        ),
        (
            "GRANT INSERT ON openmettle.local_groups TO openmettle_worker",
            "REVOKE INSERT ON openmettle.local_groups FROM openmettle_worker",
            "openmettle_worker has INSERT on openmettle.local_groups",
        ),
        (
            "GRANT SELECT ON openmettle.account_admins TO openmettle_worker",
            "REVOKE SELECT ON openmettle.account_admins FROM openmettle_worker",
            "openmettle_worker has SELECT on openmettle.account_admins",
        ),
        (
            "GRANT SELECT ON openmettle.local_sessions TO openmettle_worker",
            "REVOKE SELECT ON openmettle.local_sessions FROM openmettle_worker",
            "openmettle_worker has SELECT on openmettle.local_sessions",
        ),
        (
            "GRANT UPDATE (scope_id) ON openmettle.runs TO openmettle_worker",
            "REVOKE UPDATE (scope_id) ON openmettle.runs FROM openmettle_worker",
            "openmettle_worker has UPDATE on openmettle.runs.scope_id",
        ),
    ] {
        owner.execute(grant).await.unwrap();
        refused_with(&settings, MIGRATIONS, violation).await;
        owner.execute(revoke).await.unwrap();
        if revoke == "REVOKE SELECT ON openmettle.local_sessions FROM openmettle_worker" {
            // Revoking a table grant also revokes its existing column grants.
            owner
                .execute(AssertSqlSafe(format!(
                    "GRANT SELECT ({}) ON openmettle.local_sessions TO openmettle_worker",
                    readable.join(", ")
                )))
                .await
                .unwrap();
        }
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // Version-15 privileges are outside the contract until version 15 is recorded.
    let early = TestDb::new().await;
    let early_settings = early.settings(Duration::from_secs(5));
    let v14 = &MIGRATIONS[..14];
    migrate::apply(&early_settings, v14).await.unwrap();
    let mut early_owner = connect(&early.0, OWNER).await;
    for (grant, revoke, violation) in [
        (
            "GRANT SELECT ON openmettle.user_identities TO openmettle_worker",
            "REVOKE SELECT ON openmettle.user_identities FROM openmettle_worker",
            "openmettle_worker has SELECT on openmettle.user_identities",
        ),
        (
            "GRANT UPDATE (state) ON openmettle.runs TO openmettle_api",
            "REVOKE UPDATE (state) ON openmettle.runs FROM openmettle_api",
            "openmettle_api has UPDATE on openmettle.runs.state",
        ),
    ] {
        early_owner.execute(grant).await.unwrap();
        refused_with(&early_settings, v14, violation).await;
        early_owner.execute(revoke).await.unwrap();
    }
    migrate::apply(&early_settings, MIGRATIONS).await.unwrap();
    assert_eq!(early.history().await, all_versions());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn application_roles_meet_the_v15_boundary_in_sql() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "authorization").await;
    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let alice = c.actor.clone();
    let bob = new_user(&mut api).await;
    let (project_id, project_scope) = project(&mut api, &alice).await;

    // API writes whole current-state rows and updates only lifecycle columns.
    exec(
        &mut api,
        "INSERT INTO openmettle.project_settings
           (project_id, scope_id, name, instructions, defaults, updated_by_user_id)
         VALUES ($1::uuid, $2::uuid, 'Synthetic project', 'Be brief.', '{\"model\": \"x\"}', $3::uuid)",
        &[&project_id, &project_scope, &alice],
    )
    .await
    .unwrap();
    exec(
        &mut api,
        "UPDATE openmettle.project_settings
            SET name = 'Renamed', revision = revision + 1, archived_at = clock_timestamp(),
                updated_at = clock_timestamp(), updated_by_user_id = $2::uuid
          WHERE project_id = $1::uuid",
        &[&project_id, &bob],
    )
    .await
    .unwrap();
    let group: String = sqlx::query_scalar(
        "INSERT INTO openmettle.local_groups (name, created_by_user_id, updated_by_user_id)
         VALUES ('Family', $1::uuid, $1::uuid) RETURNING id::text",
    )
    .bind(&alice)
    .fetch_one(&mut api)
    .await
    .unwrap();
    // Remove and re-add without DELETE: the same row changes state at each revision.
    exec(
        &mut api,
        "INSERT INTO openmettle.local_group_memberships (group_id, user_id, active, updated_by_user_id)
         VALUES ($1::uuid, $2::uuid, true, $3::uuid)",
        &[&group, &bob, &alice],
    )
    .await
    .unwrap();
    for active in ["false", "true"] {
        let changed = exec(
            &mut api,
            "UPDATE openmettle.local_group_memberships
                SET active = $3::boolean, revision = revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $2::uuid
              WHERE group_id = $1::uuid AND user_id = $2::uuid",
            &[&group, &bob, active],
        )
        .await
        .unwrap();
        assert_eq!(changed, 1);
    }
    let membership: (bool, i64) = sqlx::query_as(
        "SELECT active, revision FROM openmettle.local_group_memberships
          WHERE group_id = $1::uuid AND user_id = $2::uuid",
    )
    .bind(&group)
    .bind(&bob)
    .fetch_one(&mut api)
    .await
    .unwrap();
    assert_eq!(membership, (true, 3));
    for (sql, binds) in [
        (
            "INSERT INTO openmettle.account_admins (user_id, active, updated_by_user_id)
             VALUES ($1::uuid, true, $1::uuid)",
            vec![alice.as_str()],
        ),
        (
            "INSERT INTO openmettle.platform_capability_denies (capability, denied, updated_by_user_id)
             VALUES ('web_search', true, $1::uuid)",
            vec![alice.as_str()],
        ),
        (
            "INSERT INTO openmettle.user_capability_denies (user_id, capability, denied, updated_by_user_id)
             VALUES ($1::uuid, 'web_search', true, $2::uuid)",
            vec![bob.as_str(), alice.as_str()],
        ),
        (
            "INSERT INTO openmettle.user_capability_grants (user_id, capability, granted, updated_by_user_id)
             VALUES ($1::uuid, 'runs.use_yolo', true, $2::uuid)",
            vec![bob.as_str(), alice.as_str()],
        ),
        (
            "UPDATE openmettle.user_capability_grants
                SET granted = false, revision = revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $2::uuid
              WHERE user_id = $1::uuid AND capability = 'runs.use_yolo'",
            vec![bob.as_str(), alice.as_str()],
        ),
        (
            "INSERT INTO openmettle.authorization_audit
               (actor_user_id, action, target_kind, target_id, request_key, reason, details)
             VALUES ($1::uuid, 'local_group.member_add', 'local_group', $2, 'request-1',
                     'synthetic reason', '{\"user\": \"x\"}')",
            vec![alice.as_str(), group.as_str()],
        ),
    ] {
        assert_eq!(exec(&mut api, sql, &binds).await.unwrap(), 1, "{sql}");
    }
    // The API records only user actors, at the server's time and with a server ID.
    let audit: (String, Option<String>, bool) = sqlx::query_as(
        "SELECT actor_kind, operator_id::text, occurred_at <= clock_timestamp()
           FROM openmettle.authorization_audit",
    )
    .fetch_one(&mut api)
    .await
    .unwrap();
    assert_eq!(audit, ("user".into(), None, true));
    // A replayed request key is refused for the same actor and allowed for another.
    let duplicate = "INSERT INTO openmettle.authorization_audit
          (actor_user_id, action, target_kind, target_id, request_key, reason)
        VALUES ($1::uuid, 'local_group.member_remove', 'local_group', $2, 'request-1', 'again')";
    assert_eq!(
        sqlstate(exec(&mut api, duplicate, &[&alice, &group]).await),
        "23505"
    );
    exec(&mut api, duplicate, &[&bob, &group]).await.unwrap();
    // The singleton admin lock: lockable, never changeable, never a second row.
    api.execute("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
        .await
        .unwrap();
    expect_state(
        &mut api,
        "UPDATE openmettle.account_admin_lock SET lock_guard = true",
        "23514",
    )
    .await;
    for sql in [
        "INSERT INTO openmettle.account_admin_lock (id) VALUES (true)",
        "INSERT INTO openmettle.authorization_audit (actor_kind, actor_user_id, action, target_kind, target_id, request_key, reason)
         SELECT 'user', id, 'user.disable', 'user', id::text, 'forged-kind', 'x' FROM openmettle.users LIMIT 1",
        "INSERT INTO openmettle.authorization_audit (operator_id, action, target_kind, target_id, request_key, reason)
         VALUES (gen_random_uuid(), 'user.disable', 'user', 'x', 'forged-operator', 'x')",
        "INSERT INTO openmettle.authorization_audit (id, actor_user_id, action, target_kind, target_id, request_key, reason)
         SELECT gen_random_uuid(), id, 'user.disable', 'user', 'x', 'forged-id', 'x' FROM openmettle.users LIMIT 1",
        "INSERT INTO openmettle.authorization_audit (occurred_at, actor_user_id, action, target_kind, target_id, request_key, reason)
         SELECT now() - interval '1 day', id, 'user.disable', 'user', 'x', 'backdated', 'x' FROM openmettle.users LIMIT 1",
        "UPDATE openmettle.authorization_audit SET reason = 'rewritten'",
        "UPDATE openmettle.authorization_audit SET details = '{}'",
        "DELETE FROM openmettle.authorization_audit",
        "TRUNCATE openmettle.authorization_audit",
        "UPDATE openmettle.project_settings SET project_id = project_id",
        "UPDATE openmettle.project_settings SET scope_id = scope_id",
        "UPDATE openmettle.project_settings SET created_at = now()",
        "UPDATE openmettle.local_groups SET id = id",
        "UPDATE openmettle.local_groups SET created_by_user_id = created_by_user_id",
        "UPDATE openmettle.local_group_memberships SET user_id = user_id",
        "UPDATE openmettle.local_group_memberships SET group_id = group_id",
        "UPDATE openmettle.account_admins SET user_id = user_id",
        "UPDATE openmettle.platform_capability_denies SET capability = 'other'",
        "UPDATE openmettle.user_capability_denies SET user_id = user_id",
        "UPDATE openmettle.user_capability_grants SET capability = 'other'",
        "DELETE FROM openmettle.project_settings",
        "DELETE FROM openmettle.local_groups",
        "DELETE FROM openmettle.local_group_memberships",
        "DELETE FROM openmettle.account_admins",
        "DELETE FROM openmettle.account_admin_lock",
        "DELETE FROM openmettle.platform_capability_denies",
        "DELETE FROM openmettle.user_capability_denies",
        "DELETE FROM openmettle.user_capability_grants",
        "TRUNCATE openmettle.local_group_memberships",
        "TRUNCATE openmettle.account_admins",
        "UPDATE openmettle.runs SET scope_id = scope_id",
        "UPDATE openmettle.runs SET actor_user_id = actor_user_id",
        "UPDATE openmettle.runs SET input_snapshot = input_snapshot",
        "UPDATE openmettle.runs SET state = 'cancelled', config_snapshot = config_snapshot",
    ] {
        expect_state(&mut api, sql, "42501").await;
    }
    // A share, revoke or disable transaction can stop queued work in place.
    let cancelled = exec(
        &mut api,
        "UPDATE openmettle.runs SET state = 'cancelled', wait_reason = NULL WHERE id = $1::uuid",
        &[&run],
    )
    .await
    .unwrap();
    assert_eq!(cancelled, 1);

    // The worker reads authority, membership, group and capability rows, and nothing else new.
    for sql in [
        "SELECT count(*) FROM openmettle.user_identities",
        "SELECT count(*) FROM openmettle.login_providers",
        "SELECT count(*) FROM openmettle.login_provider_revisions",
        "SELECT count(*) FROM openmettle.local_identity_approvals",
        "SELECT count((observation).state) FROM openmettle.membership_observations",
        "SELECT count(*) FROM openmettle.local_groups WHERE disabled_at IS NULL",
        "SELECT count(*) FROM openmettle.local_group_memberships WHERE active",
        "SELECT count(*) FROM openmettle.platform_capability_denies WHERE denied",
        "SELECT count(*) FROM openmettle.user_capability_denies WHERE denied",
        "SELECT count(*) FROM openmettle.user_capability_grants WHERE granted",
    ] {
        worker.execute(sql).await.unwrap();
    }
    let worker_failed = exec(
        &mut worker,
        "UPDATE openmettle.runs SET state = 'failed', wait_reason = 'authorization revoked'
          WHERE id = $1::uuid",
        &[&run],
    )
    .await
    .unwrap();
    assert_eq!(worker_failed, 1);
    for sql in [
        "SELECT id FROM openmettle.local_identity_approvals FOR SHARE",
        "SELECT id FROM openmettle.login_providers FOR UPDATE",
        "UPDATE openmettle.user_identities SET subject = subject",
        "UPDATE openmettle.login_providers SET client_id = client_id",
        "UPDATE openmettle.local_identity_approvals SET active = active",
        "UPDATE openmettle.membership_observations SET issued_ms = issued_ms",
        "INSERT INTO openmettle.local_groups (name, created_by_user_id, updated_by_user_id)
         SELECT 'worker', id, id FROM openmettle.users LIMIT 1",
        "INSERT INTO openmettle.platform_capability_denies (capability, denied, updated_by_user_id)
         SELECT 'worker', true, id FROM openmettle.users LIMIT 1",
        "UPDATE openmettle.local_group_memberships SET active = false",
        "UPDATE openmettle.user_capability_denies SET denied = false",
        "UPDATE openmettle.user_capability_grants SET granted = true",
        "DELETE FROM openmettle.local_groups",
        "DELETE FROM openmettle.user_capability_denies",
        "TRUNCATE openmettle.platform_capability_denies",
        "SELECT * FROM openmettle.account_admins",
        "SELECT * FROM openmettle.account_admin_lock",
        "SELECT * FROM openmettle.authorization_audit",
        "SELECT * FROM openmettle.project_settings",
        "SELECT * FROM openmettle.login_transactions",
        "SELECT * FROM openmettle.login_nonce_reservations",
        "SELECT * FROM openmettle.local_sessions",
        "SELECT * FROM openmettle.native_handoffs",
        "SELECT * FROM openmettle.provider_recoveries",
        "SELECT * FROM openmettle.home_invitations",
        "SELECT * FROM openmettle.membership_configuration_changes",
        "UPDATE openmettle.runs SET scope_id = scope_id",
        "UPDATE openmettle.runs SET actor_user_id = actor_user_id",
        "UPDATE openmettle.runs SET input_snapshot = input_snapshot",
        "UPDATE openmettle.runs SET idempotency_key = idempotency_key",
    ] {
        expect_state(&mut worker, sql, "42501").await;
    }
    let state: (String, Option<String>) =
        sqlx::query_as("SELECT state, wait_reason FROM openmettle.runs WHERE id = $1::uuid")
            .bind(&run)
            .fetch_one(&mut worker)
            .await
            .unwrap();
    assert_eq!(
        state,
        ("failed".into(), Some("authorization revoked".into()))
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn v15_constraints_bound_every_stored_value() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let mut owner = connect(&db.0, OWNER).await;
    let alice = new_user(&mut api).await;
    let (project_id, project_scope) = project(&mut api, &alice).await;
    let (_, other_scope) = project(&mut api, &alice).await;

    // Capability names mirror src/authz.rs: lowercase ASCII, digits, '.', '_', '-', 1-128 bytes.
    let platform =
        "INSERT INTO openmettle.platform_capability_denies (capability, denied, updated_by_user_id)
                    VALUES ($1, true, $2::uuid)";
    let user_deny = "INSERT INTO openmettle.user_capability_denies (user_id, capability, denied, updated_by_user_id)
                     VALUES ($2::uuid, $1, true, $2::uuid)";
    let user_grant = "INSERT INTO openmettle.user_capability_grants (user_id, capability, granted, updated_by_user_id)
                      VALUES ($2::uuid, $1, true, $2::uuid)";
    let longest = "a".repeat(128);
    let too_long = "a".repeat(129);
    for sql in [platform, user_deny, user_grant] {
        for name in ["web_search", "runs.use_yolo", "-x.1_", longest.as_str()] {
            assert_eq!(
                exec(&mut api, sql, &[name, &alice]).await.unwrap(),
                1,
                "{name}"
            );
        }
        for name in [
            "",
            "Web_search",
            "web search",
            "web\tsearch",
            "wéb",
            "web/search",
            too_long.as_str(),
        ] {
            assert_eq!(
                sqlstate(exec(&mut api, sql, &[name, &alice]).await),
                "23514",
                "{name:?}"
            );
        }
        // PostgreSQL text cannot hold NUL: the value is refused before any constraint.
        assert_eq!(
            sqlstate(exec(&mut api, sql, &["web\0search", &alice]).await),
            "22021"
        );
        assert_eq!(
            sqlstate(exec(&mut api, sql, &["web_search", &alice]).await),
            "23505"
        );
    }

    // Group names: 1-128 bytes, no padding or control characters, unique.
    let group = "INSERT INTO openmettle.local_groups (name, created_by_user_id, updated_by_user_id)
                 VALUES ($1, $2::uuid, $2::uuid)";
    let longest_group = "g".repeat(128);
    for name in ["Family", "Équipe", longest_group.as_str()] {
        exec(&mut api, group, &[name, &alice]).await.unwrap();
    }
    let too_long_group = "g".repeat(129);
    for name in [
        "",
        " Family",
        "Family ",
        "tab\tname",
        "line\nname",
        too_long_group.as_str(),
    ] {
        assert_eq!(
            sqlstate(exec(&mut api, group, &[name, &alice]).await),
            "23514",
            "{name:?}"
        );
    }
    assert_eq!(
        sqlstate(exec(&mut api, group, &["Family", &alice]).await),
        "23505"
    );
    // Memberships reference an existing group and user, once per pair.
    let member = "INSERT INTO openmettle.local_group_memberships (group_id, user_id, active, updated_by_user_id)
                  VALUES ($1::uuid, $2::uuid, true, $2::uuid)";
    assert_eq!(
        sqlstate(exec(&mut api, member, &[UNKNOWN_USER, &alice]).await),
        "23503"
    );
    let family: String =
        sqlx::query_scalar("SELECT id::text FROM openmettle.local_groups WHERE name = 'Family'")
            .fetch_one(&mut api)
            .await
            .unwrap();
    exec(&mut api, member, &[&family, &alice]).await.unwrap();
    assert_eq!(
        sqlstate(exec(&mut api, member, &[&family, &alice]).await),
        "23505"
    );

    // Project settings: bounded name and instructions; defaults are a bounded JSON object
    // without legacy folder or collection identifiers; bound to the project's own scope.
    let settings = "INSERT INTO openmettle.project_settings
                      (project_id, scope_id, name, instructions, defaults, updated_by_user_id)
                    VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6::uuid)";
    let long_instructions = "i".repeat(32769);
    let large_defaults = format!("{{\"x\": \"{}\"}}", "d".repeat(16384));
    for (scope, name, instructions, defaults, code) in [
        (&project_scope, "", "", "{}", "23514"),
        (&project_scope, " padded", "", "{}", "23514"),
        (&project_scope, "line\nbreak", "", "{}", "23514"),
        (
            &project_scope,
            "Project",
            long_instructions.as_str(),
            "{}",
            "23514",
        ),
        (&project_scope, "Project", "", "[]", "23514"),
        (&project_scope, "Project", "", "\"text\"", "23514"),
        (
            &project_scope,
            "Project",
            "",
            "{\"folder_id\": \"f\"}",
            "23514",
        ),
        (
            &project_scope,
            "Project",
            "",
            "{\"collection_ids\": []}",
            "23514",
        ),
        (
            &project_scope,
            "Project",
            "",
            large_defaults.as_str(),
            "23514",
        ),
        (&other_scope, "Project", "", "{}", "23503"),
    ] {
        assert_eq!(
            sqlstate(
                exec(
                    &mut api,
                    settings,
                    &[&project_id, scope, name, instructions, defaults, &alice]
                )
                .await
            ),
            code,
            "{name:?} {defaults}"
        );
    }
    exec(
        &mut api,
        settings,
        &[
            &project_id,
            &project_scope,
            "Project",
            "Multi-line\ninstructions.",
            "{\"model\": \"m\", \"nested\": {\"folder_id\": \"kept\"}}",
            &alice,
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        sqlstate(
            exec(
                &mut api,
                settings,
                &[&project_id, &project_scope, "Again", "", "{}", &alice]
            )
            .await
        ),
        "23505"
    );

    // Audit rows: one actor kind with exactly its own actor column, allowlisted action and
    // target kinds, bounded identifiers, reason and details, and one request key per actor.
    let operator_row = |actor_kind: &str,
                        actor_user: &str,
                        operator: &str,
                        action: &str,
                        target_kind: &str,
                        target_id: &str,
                        request_key: &str,
                        reason: &str,
                        details: &str| {
        format!(
            "INSERT INTO openmettle.authorization_audit
               (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
                request_key, reason, details)
             VALUES ('{actor_kind}', {actor_user}, {operator}, '{action}', '{target_kind}',
                     '{target_id}', '{request_key}', '{reason}', '{details}')"
        )
    };
    let user = format!("'{alice}'::uuid");
    let op = format!("'{OPERATOR}'::uuid");
    let long_key = "k".repeat(129);
    let long_reason = "r".repeat(513);
    let long_target = "t".repeat(257);
    let large_details = format!("{{\"x\": \"{}\"}}", "d".repeat(4096));
    let action = "account_admin.grant";
    for (sql, code) in [
        (
            operator_row("operator", &user, &op, action, "user", "u", "k1", "r", "{}"),
            "23514",
        ),
        (
            operator_row(
                "operator", "NULL", "NULL", action, "user", "u", "k1", "r", "{}",
            ),
            "23514",
        ),
        (
            operator_row("user", &user, &op, action, "user", "u", "k1", "r", "{}"),
            "23514",
        ),
        (
            operator_row("user", "NULL", "NULL", action, "user", "u", "k1", "r", "{}"),
            "23514",
        ),
        (
            operator_row("admin", "NULL", &op, action, "user", "u", "k1", "r", "{}"),
            "23514",
        ),
        (
            operator_row(
                "operator",
                "NULL",
                &op,
                "user.delete",
                "user",
                "u",
                "k1",
                "r",
                "{}",
            ),
            "23514",
        ),
        (
            operator_row(
                "operator", "NULL", &op, action, "memory", "u", "k1", "r", "{}",
            ),
            "23514",
        ),
        (
            operator_row("operator", "NULL", &op, action, "user", "", "k1", "r", "{}"),
            "23514",
        ),
        (
            operator_row(
                "operator",
                "NULL",
                &op,
                action,
                "user",
                &long_target,
                "k1",
                "r",
                "{}",
            ),
            "23514",
        ),
        (
            operator_row("operator", "NULL", &op, action, "user", "u", "", "r", "{}"),
            "23514",
        ),
        (
            operator_row(
                "operator", "NULL", &op, action, "user", "u", &long_key, "r", "{}",
            ),
            "23514",
        ),
        (
            operator_row("operator", "NULL", &op, action, "user", "u", "k1", "", "{}"),
            "23514",
        ),
        (
            operator_row(
                "operator",
                "NULL",
                &op,
                action,
                "user",
                "u",
                "k1",
                &long_reason,
                "{}",
            ),
            "23514",
        ),
        (
            operator_row(
                "operator", "NULL", &op, action, "user", "u", "k1", "r", "[]",
            ),
            "23514",
        ),
        (
            operator_row(
                "operator",
                "NULL",
                &op,
                action,
                "user",
                "u",
                "k1",
                "r",
                &large_details,
            ),
            "23514",
        ),
        (
            operator_row(
                "user",
                &format!("'{UNKNOWN_USER}'::uuid"),
                "NULL",
                action,
                "user",
                "u",
                "k1",
                "r",
                "{}",
            ),
            "23503",
        ),
    ] {
        expect_state(&mut owner, &sql, code).await;
    }
    let other_operator = "'00000000-0000-0000-0000-0000000000f2'::uuid";
    for sql in [
        operator_row(
            "operator", "NULL", &op, action, "user", "u", "same-key", "r", "{}",
        ),
        operator_row(
            "operator",
            "NULL",
            other_operator,
            action,
            "user",
            "u",
            "same-key",
            "r",
            "{}",
        ),
        operator_row(
            "user", &user, "NULL", action, "user", "u", "same-key", "r", "{}",
        ),
    ] {
        owner.execute(AssertSqlSafe(sql)).await.unwrap();
    }
    expect_state(
        &mut owner,
        &operator_row(
            "operator",
            "NULL",
            &op,
            "account_admin.revoke",
            "user",
            "v",
            "same-key",
            "r",
            "{}",
        ),
        "23505",
    )
    .await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn populated_v14_upgrade_keeps_rows_and_adds_empty_authorization_state() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..14]).await.unwrap();
    assert_eq!(db.history().await, versions_through(14));
    // Version-14 rows written through the version-14 grants: account, identity, approval,
    // personal scope, conversation, branch, run and project.
    let c = Context::new(&db).await;
    let run = c.run(&db, "before-15").await;
    let mut api = connect(&db.0, API).await;
    let mut owner = connect(&db.0, OWNER).await;
    let provider = "00000000-0000-0000-0000-000000000015";
    exec(
        &mut owner,
        "INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason)
         VALUES ($1::uuid, 'https://authz.example.test', 'synthetic', 'fixture-owner', 'synthetic provider')",
        &[provider],
    )
    .await
    .unwrap();
    exec(
        &mut owner,
        "INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, 'v1')",
        &[provider],
    )
    .await
    .unwrap();
    let identity: String = sqlx::query_scalar(
        "INSERT INTO openmettle.user_identities (user_id, issuer, subject)
         VALUES ($1::uuid, 'https://authz.example.test', 'synthetic-subject') RETURNING id::text",
    )
    .bind(&c.actor)
    .fetch_one(&mut api)
    .await
    .unwrap();
    exec(
        &mut owner,
        "INSERT INTO openmettle.local_identity_approvals
           (provider_id, identity_id, active, expires_ms, changed_by, change_reason)
         VALUES ($1::uuid, $2::uuid, true, 4102444800000, 'fixture-owner', 'synthetic approval')",
        &[provider, &identity],
    )
    .await
    .unwrap();
    let (project_id, project_scope) = project(&mut api, &c.actor).await;
    // Before version 15 the worker can neither read identities nor change a run's state.
    let mut worker = connect(&db.0, WORKER).await;
    expect_state(
        &mut worker,
        "SELECT * FROM openmettle.user_identities",
        "42501",
    )
    .await;
    expect_state(
        &mut worker,
        "UPDATE openmettle.runs SET state = 'failed'",
        "42501",
    )
    .await;
    drop(worker);
    let before = everything(&db).await;

    let output = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(db.history().await, all_versions());
    let after = everything(&db).await;
    // Every pre-existing row is unchanged; history gains version 15 and later. Every column
    // added after migration 14 keeps its declared default on pre-existing rows.
    for (table, rows) in &before {
        if table == "_sqlx_migrations" {
            assert!(rows.is_subset(&after[table]));
            assert_eq!(after[table].len(), rows.len() + MIGRATIONS.len() - 14);
        } else {
            assert_eq!(
                normalize_upgraded_rows(table, 14, &after[table]),
                normalize_upgraded_rows(table, 14, rows),
                "{table}"
            );
        }
    }
    // Every table added after migration 14 starts empty apart from its declared singleton seed.
    let added: BTreeSet<&str> = after
        .keys()
        .filter(|t| !before.contains_key(*t))
        .map(String::as_str)
        .collect();
    let expected_added: BTreeSet<&str> = expected_added_tables_since(14)
        .map(|entry| entry.table)
        .collect();
    assert_eq!(added, expected_added);
    for entry in expected_added_tables_since(14) {
        let actual: BTreeSet<String> = after[entry.table]
            .iter()
            .map(|row| canonical_json(row))
            .collect();
        let expected: BTreeSet<String> = entry.seed_row.into_iter().map(canonical_json).collect();
        assert_eq!(actual, expected, "{}", entry.table);
    }
    // A pre-15 project has no settings row and stays valid; its owner can add one later.
    let unsettled: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.projects p
          WHERE NOT EXISTS (SELECT FROM openmettle.project_settings s WHERE s.project_id = p.id)",
    )
    .fetch_one(&mut api)
    .await
    .unwrap();
    assert_eq!(unsettled, 1);
    exec(
        &mut api,
        "INSERT INTO openmettle.project_settings (project_id, scope_id, name, updated_by_user_id)
         VALUES ($1::uuid, $2::uuid, 'Upgraded project', $3::uuid)",
        &[&project_id, &project_scope, &c.actor],
    )
    .await
    .unwrap();
    // The worker now reads the identity and can invalidate the pre-existing run.
    let mut worker = connect(&db.0, WORKER).await;
    let identities: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.user_identities")
        .fetch_one(&mut worker)
        .await
        .unwrap();
    assert_eq!(identities, 1);
    let invalidated = exec(
        &mut worker,
        "UPDATE openmettle.runs SET state = 'failed', wait_reason = 'authorization revoked'
          WHERE id = $1::uuid",
        &[&run],
    )
    .await
    .unwrap();
    assert_eq!(invalidated, 1);
    // Rerunning the migrator changes nothing.
    let rerun = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(rerun.status.code(), Some(0), "{}", stderr(&rerun));
    assert_eq!(db.history().await, all_versions());
}

// --- exact operator script -----------------------------------------------------------------

fn grant<'a>(
    user: &'a str,
    request: &'a str,
    operator: &'a str,
    reason: &'a str,
) -> [(&'a str, &'a str); 4] {
    [
        ("user_id", user),
        ("request", request),
        ("operator", operator),
        ("reason", reason),
    ]
}

type AuditRow = (
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
    String,
);
async fn audit_rows(db: &TestDb) -> Vec<AuditRow> {
    sqlx::query_as(
        "SELECT actor_kind, actor_user_id::text, operator_id::text, action, target_kind,
                target_id, request_key, reason, details::text
           FROM openmettle.authorization_audit ORDER BY occurred_at, id",
    )
    .fetch_all(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}
async fn admin_row(db: &TestDb, user: &str) -> Option<(bool, i64, Option<String>)> {
    sqlx::query_as(
        "SELECT active, revision, updated_by_user_id::text FROM openmettle.account_admins
          WHERE user_id = $1::uuid",
    )
    .bind(user)
    .fetch_optional(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}
fn audit(user: &str, request: &str, reason: &str, revision: i64, before: i64) -> AuditRow {
    (
        "operator".into(),
        None,
        Some(OPERATOR.into()),
        "account_admin.grant".into(),
        "user".into(),
        user.into(),
        request.into(),
        reason.into(),
        format!("{{\"revision\": {revision}, \"enabled_admins_before\": {before}}}"),
    )
}
fn refused(output: &Output, message: &str) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let text = stderr(output);
    assert!(text.contains("account admin grant refused"), "{text}");
    assert!(text.contains(message), "{text}");
    assert!(!text.contains("private-marker"), "{text}");
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn account_admin_script_bootstraps_replays_and_recovers() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let alice = new_user(&mut api).await;
    let bob = new_user(&mut api).await;
    let carol = new_user(&mut api).await;
    exec(
        &mut api,
        "UPDATE openmettle.users SET disabled_at = now() WHERE id = $1::uuid",
        &[&carol],
    )
    .await
    .unwrap();
    let marker = "private-marker reason";
    let initial = everything(&db).await;

    // Other roles, invalid input and missing variables change nothing and echo nothing.
    for role in [API, WORKER] {
        let vars = grant(&alice, REQUESTS[0], OPERATOR, marker);
        let mut child = psql_transport::start(&db.0, role, PASSWORD, &vars);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(SCRIPT.as_bytes())
            .unwrap();
        refused(&child.wait_with_output().unwrap(), "wrong role");
    }
    let upper = alice.to_uppercase();
    let long_reason = "r".repeat(513);
    for vars in [
        grant(&upper, REQUESTS[0], OPERATOR, marker),
        grant(&alice, "not-a-uuid", OPERATOR, marker),
        grant(
            &alice,
            REQUESTS[0],
            "{00000000-0000-0000-0000-0000000000f1}",
            marker,
        ),
        grant(&alice, REQUESTS[0], OPERATOR, ""),
        grant(&alice, REQUESTS[0], OPERATOR, &long_reason),
    ] {
        refused(&psql(&db, SCRIPT, &vars), "invalid input");
    }
    let missing = psql(
        &db,
        SCRIPT,
        &[
            ("user_id", alice.as_str()),
            ("request", REQUESTS[0]),
            ("operator", OPERATOR),
        ],
    );
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    // An unknown or disabled account is never made an administrator.
    for user in [UNKNOWN_USER, carol.as_str()] {
        refused(
            &psql(&db, SCRIPT, &grant(user, REQUESTS[0], OPERATOR, marker)),
            "no enabled user",
        );
    }
    assert_eq!(everything(&db).await, initial);

    // Bootstrap: the first administrator and its operator audit row commit together.
    let first = psql(
        &db,
        SCRIPT,
        &grant(&alice, REQUESTS[0], OPERATOR, "bootstrap"),
    );
    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(first.stdout, b"account admin grant committed\n");
    assert_eq!(admin_row(&db, &alice).await, Some((true, 1, None)));
    let mut expected = vec![audit(&alice, REQUESTS[0], "bootstrap", 1, 0)];
    assert_eq!(audit_rows(&db).await, expected);

    // Replaying the committed request changes nothing; reusing it for another user is refused.
    let committed = everything(&db).await;
    let replay = psql(
        &db,
        SCRIPT,
        &grant(&alice, REQUESTS[0], OPERATOR, "bootstrap"),
    );
    assert!(replay.status.success(), "{}", stderr(&replay));
    assert_eq!(replay.stdout, b"account admin grant already committed\n");
    refused(
        &psql(&db, SCRIPT, &grant(&bob, REQUESTS[0], OPERATOR, marker)),
        "request already used",
    );
    // An active administrator is not granted again under a new request.
    refused(
        &psql(&db, SCRIPT, &grant(&alice, REQUESTS[1], OPERATOR, marker)),
        "already an active administrator",
    );
    assert_eq!(everything(&db).await, committed);

    // Break-glass: after the application demotes the last administrator, the owner restores
    // the inactive row at its next revision.
    exec(
        &mut api,
        "UPDATE openmettle.account_admins
            SET active = false, revision = revision + 1, updated_at = clock_timestamp(),
                updated_by_user_id = $1::uuid
          WHERE user_id = $1::uuid",
        &[&alice],
    )
    .await
    .unwrap();
    let recovered = psql(
        &db,
        SCRIPT,
        &grant(&alice, REQUESTS[2], OPERATOR, "break-glass"),
    );
    assert!(recovered.status.success(), "{}", stderr(&recovered));
    assert_eq!(recovered.stdout, b"account admin grant committed\n");
    assert_eq!(admin_row(&db, &alice).await, Some((true, 3, None)));
    expected.push(audit(&alice, REQUESTS[2], "break-glass", 3, 0));
    assert_eq!(audit_rows(&db).await, expected);

    // Two requests for the same user wait on the administrator lock; exactly one commits.
    let mut holder = connect(&db.0, OWNER).await;
    holder.execute("BEGIN").await.unwrap();
    holder
        .execute("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
        .await
        .unwrap();
    let mut racing = psql_spawn(&db, SCRIPT, &grant(&bob, REQUESTS[3], OPERATOR, "race"));
    wait_for_psql(&db, &mut racing, "Lock", "account_admin_lock").await;
    let other = psql_spawn(&db, SCRIPT, &grant(&bob, REQUESTS[4], OPERATOR, "race"));
    holder.execute("COMMIT").await.unwrap();
    let mut winners = vec![];
    for (request, child) in [(REQUESTS[3], racing), (REQUESTS[4], other)] {
        let out = child.wait_with_output().unwrap();
        if out.status.success() {
            assert_eq!(out.stdout, b"account admin grant committed\n");
            winners.push(request);
        } else {
            refused(&out, "already an active administrator");
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(admin_row(&db, &bob).await, Some((true, 1, None)));
    expected.push(audit(&bob, winners[0], "race", 1, 1));
    assert_eq!(audit_rows(&db).await, expected);
}
