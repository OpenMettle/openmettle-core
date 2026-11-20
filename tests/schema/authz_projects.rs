//! ADR 0027 PR4a: migration 16 group and project grantees, and the project, membership and
//! share store. Hydration runs as both application roles; writes run as `openmettle_api`. The
//! owner role seeds fixtures and reads results. Every value is synthetic.
use super::authz_store::{
    Account, Audit, FUTURE, NOW, PROVIDER, UNCHANGED, UNKNOWN, account, applied, audit, conflict,
    ctx, denied, hydrate, make_admin, present_membership, principal, providers,
    wait_for_lock_waiters,
};
use super::*;
use openmettle_core::{
    authz::{
        self, Action, Decision, DenialReason, Grantee, PolicyReason, Project, ProjectRole,
        Resource, ResourceAccess, ResourceKind,
        projects::{self, ProjectSettingsInput},
        store::{self, StoreError, WriteOutcome},
    },
    grants::{self, Assignment, ChangeInput, Target},
    runs::WriteTransaction,
};
use serde_json::{Value, json};

const HIDDEN: Decision = Decision::Deny(DenialReason::NotFound);
const CONVERSATION: ResourceKind = ResourceKind::Conversation;
const ARTIFACT: ResourceKind = ResourceKind::Artifact;
const OIDC_TEAM: &str = "synthetic-team";

fn refused(reason: PolicyReason) -> Decision {
    Decision::Deny(DenialReason::Policy(reason))
}

fn policy(reason: PolicyReason) -> DenialReason {
    DenialReason::Policy(reason)
}

fn user(account: &Account) -> Grantee {
    Grantee::User(account.user.clone())
}

fn input<'a>(name: &'a str, defaults: &'a Value) -> ProjectSettingsInput<'a> {
    ProjectSettingsInput {
        name,
        instructions: "Synthetic instructions.",
        defaults,
    }
}

async fn api(db: &TestDb) -> PgConnection {
    connect(&db.0, API).await
}

async fn create(db: &TestDb, owner: &Account, key: &str) -> String {
    let defaults = json!({});
    applied(
        projects::create_project(&mut api(db).await, &ctx(owner, key), &input("P", &defaults))
            .await,
    )
}

async fn hydrated(db: &TestDb, role: &str, project: &str, now: i64) -> Project {
    let mut c = connect(&db.0, role).await;
    projects::hydrate_project(&mut c, project, now)
        .await
        .unwrap()
        .unwrap()
}

async fn role_of(db: &TestDb, account: &Account, project: &str) -> Option<ProjectRole> {
    let principal = principal(db, account).await;
    hydrated(db, API, project, NOW).await.role_of(&principal)
}

async fn item(db: &TestDb, kind: ResourceKind, id: &str) -> Resource {
    projects::hydrate_resource(&mut api(db).await, kind, id, NOW)
        .await
        .unwrap()
        .unwrap()
}

async fn decide(
    db: &TestDb,
    account: &Account,
    kind: ResourceKind,
    id: &str,
    action: Action,
) -> Decision {
    let principal = principal(db, account).await;
    authz::authorize_resource(&principal, &item(db, kind, id).await, action)
}

/// (read, write) decisions for one caller on one resource.
async fn reach(
    db: &TestDb,
    account: &Account,
    kind: ResourceKind,
    id: &str,
) -> (Decision, Decision) {
    (
        decide(db, account, kind, id, Action::Read).await,
        decide(db, account, kind, id, Action::Write).await,
    )
}

async fn set_role(
    db: &TestDb,
    actor: &Account,
    key: &str,
    project: &str,
    grantee: &Grantee,
    role: ProjectRole,
) -> Result<WriteOutcome, StoreError> {
    projects::set_project_member_role(&mut api(db).await, &ctx(actor, key), project, grantee, role)
        .await
}

async fn revoke(
    db: &TestDb,
    actor: &Account,
    key: &str,
    project: &str,
    grantee: &Grantee,
) -> Result<WriteOutcome, StoreError> {
    projects::revoke_project_member(&mut api(db).await, &ctx(actor, key), project, grantee).await
}

async fn share(
    db: &TestDb,
    actor: &Account,
    key: &str,
    (kind, id): (ResourceKind, &str),
    grantee: &Grantee,
    access: ResourceAccess,
) -> Result<WriteOutcome, StoreError> {
    projects::share_resource(
        &mut api(db).await,
        &ctx(actor, key),
        kind,
        id,
        grantee,
        access,
    )
    .await
}

async fn unshare(
    db: &TestDb,
    actor: &Account,
    key: &str,
    (kind, id): (ResourceKind, &str),
    grantee: &Grantee,
) -> Result<WriteOutcome, StoreError> {
    projects::unshare_resource(&mut api(db).await, &ctx(actor, key), kind, id, grantee).await
}

async fn scope_of(db: &TestDb, project: &str) -> String {
    sqlx::query_scalar("SELECT scope_id::text FROM openmettle.projects WHERE id = $1::uuid")
        .bind(project)
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

async fn chat(db: &TestDb, scope: &str, kind: &str, owner: &Account) -> String {
    conversation(&mut api(db).await, scope, kind, &owner.user)
        .await
        .unwrap()
}

/// Active direct `openmettle.project-role` keys of one user grantee.
async fn direct_roles(db: &TestDb, project: &str, account: &Account) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT a.assignment_key FROM openmettle.grant_assignments a
           JOIN openmettle.grant_changes h ON h.assignment_id = a.id AND h.revision = a.last_revision
          WHERE a.project_id = $1::uuid AND a.grantee_user_id = $2::uuid AND a.source_kind = 'direct'
            AND a.assignment_format = 'openmettle.project-role' AND h.decision = 'grant'
          ORDER BY 1",
    )
    .bind(project)
    .bind(&account.user)
    .fetch_all(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}

/// (action, target_kind, target_id) of every audit row, in order.
fn actions(rows: Vec<Audit>) -> Vec<(String, String, String)> {
    rows.into_iter().map(|r| (r.2, r.3, r.4)).collect()
}

fn row(action: &str, kind: &str, target: &str) -> (String, String, String) {
    (action.into(), kind.into(), target.into())
}

// --- pure validation ---------------------------------------------------------------------------

#[test]
fn project_settings_input_is_at_least_as_strict_as_migration_15() {
    let empty = json!({});
    let longest = "n".repeat(256);
    let ok = [
        input("A", &empty),
        input(&longest, &empty),
        input("Inner  space Ä", &empty),
    ];
    for settings in ok {
        assert!(settings.validate().is_ok(), "{}", settings.name);
    }
    let nested = json!({"model": "m", "nested": {"folder_id": "allowed below the top level"}});
    assert!(input("A", &nested).validate().is_ok());
    let long_name = "é".repeat(129); // 258 bytes
    for (name, field) in [
        ("", "name"),
        (" lead", "name"),
        ("trail ", "name"),
        ("tab\t", "name"),
        ("nul\0", "name"),
        ("c1\u{85}", "name"),
        (&long_name as &str, "name"),
        (&"n".repeat(257) as &str, "name"),
    ] {
        assert!(
            matches!(input(name, &empty).validate(), Err(StoreError::InvalidInput(f)) if f == field),
            "{name:?}"
        );
    }
    let instructions = |text: &str| {
        ProjectSettingsInput {
            instructions: text,
            ..input("A", &empty)
        }
        .validate()
    };
    assert!(instructions(&"i".repeat(32768)).is_ok());
    assert!(instructions("line\nbreak").is_ok());
    for bad in [&"i".repeat(32769) as &str, "nul\0"] {
        assert!(matches!(
            instructions(bad),
            Err(StoreError::InvalidInput("instructions"))
        ));
    }
    let big = json!({ "k": "v".repeat(16400) });
    for defaults in [
        json!([]),
        json!("text"),
        json!(null),
        json!({"folder_id": "x"}),
        json!({"folder_ids": []}),
        json!({"collection_id": "x"}),
        json!({"collection_ids": [], "model": "m"}),
        json!({"nul": "\u{0}"}),
        big,
    ] {
        assert!(
            matches!(
                input("A", &defaults).validate(),
                Err(StoreError::InvalidInput("defaults"))
            ),
            "{defaults}"
        );
    }
}

// --- migration 16 ------------------------------------------------------------------------------

/// The ADR 0006 version 1 request identity of a direct grant, encoded independently of
/// `src/grants.rs`: domain, then each field as a u64 big-endian length and its bytes.
fn v1_grant_identity(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = b"openmettle/grant-change/1\0".to_vec();
    for field in fields {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn migration_16_keeps_user_grants_and_constrains_every_grantee_kind() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..15]).await.unwrap();
    let mut api = connect(&db.0, API).await;
    let actor = new_user(&mut api).await;
    let other = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &actor).await;
    let chat = conversation(&mut api, &scope, "personal", &actor)
        .await
        .unwrap();
    // A version-15 ADR 0006 share written with the version-5 column grants and the exact
    // version-1 request identity, as a released binary or operator script writes it.
    let assignment: String = sqlx::query_scalar(
        "INSERT INTO openmettle.grant_assignments (scope_id, target_kind, conversation_id,
             grantee_user_id, assignment_format, assignment_version, assignment_key, source_kind,
             created_by_user_id)
         VALUES ($1::uuid, 'conversation', $2::uuid, $3::uuid, 'openmettle.resource-grant', 1,
                 'read', 'direct', $4::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&chat)
    .bind(&other)
    .bind(&actor)
    .fetch_one(&mut api)
    .await
    .unwrap();
    let change: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut api)
        .await
        .unwrap();
    let request = v1_grant_identity(&[
        scope.as_bytes(),
        b"conversation",
        chat.as_bytes(),
        other.as_bytes(),
        b"openmettle.resource-grant",
        &1i32.to_be_bytes(),
        b"read",
        b"",
        &0i64.to_be_bytes(),
        actor.as_bytes(),
        b"v15-share",
        &0i64.to_be_bytes(),
        b"grant",
        b"",
    ]);
    sqlx::query(
        "INSERT INTO openmettle.grant_changes (id, scope_id, assignment_id, revision, source_kind,
             actor_user_id, request_key, decision, cycle_id, request_identity, request_digest)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 'direct', $4::uuid, 'v15-share', 'grant',
                 $1::uuid, $5, sha256($5))",
    )
    .bind(&change)
    .bind(&scope)
    .bind(&assignment)
    .bind(&actor)
    .bind(&request)
    .execute(&mut api)
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.grant_assignments SET last_revision = 1 WHERE id = $1::uuid")
        .bind(&assignment)
        .execute(&mut api)
        .await
        .unwrap();
    let rows = "SELECT to_jsonb(t)::text FROM openmettle.grant_assignments t";
    let before: Vec<String> = sqlx::query_scalar(rows)
        .fetch_all(&mut db.admin().await)
        .await
        .unwrap();
    drop(api);

    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());
    let mut admin = db.admin().await;
    let after: Vec<String> = sqlx::query_scalar(rows)
        .fetch_all(&mut admin)
        .await
        .unwrap();
    let mut upgraded: Value = serde_json::from_str(&after[0]).unwrap();
    let object = upgraded.as_object_mut().unwrap();
    assert_eq!(object.remove("grantee_kind"), Some(json!("user")));
    assert_eq!(object.remove("grantee_local_group_id"), Some(Value::Null));
    assert_eq!(object.remove("grantee_oidc_group_id"), Some(Value::Null));
    let original: Value = serde_json::from_str(&before[0]).unwrap();
    assert_eq!(upgraded, original);

    // The current writer replays the version-15 request byte for byte.
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let replay = grants::change_grant(
        &mut tx,
        &ChangeInput {
            assignment: Assignment {
                scope: &scope,
                target: Target::Conversation(&chat),
                grantee: grants::Grantee::User(&other),
                format: "openmettle.resource-grant",
                version: 1,
                key: "read",
                mapping_rule: None,
            },
            actor: &actor,
            key: "v15-share",
            expected_revision: 0,
            mapping_revision: None,
            decision: grants::Decision::Grant,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        (
            replay.change.as_str(),
            replay.assignment.as_str(),
            replay.revision
        ),
        (change.as_str(), assignment.as_str(), 1)
    );
    for role in [API, WORKER] {
        let mut c = connect(&db.0, role).await;
        let shared = projects::hydrate_resource(&mut c, CONVERSATION, &chat, NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(shared.shares.len(), 1, "{role}");
        assert_eq!(
            shared.shares[0].grantee,
            Grantee::User(other.clone()),
            "{role}"
        );
        assert_eq!(shared.shares[0].permission, ResourceAccess::Read, "{role}");
    }

    // The natural key is the one named migration 16 constraint; migration 5's is gone.
    let unique: Vec<String> = sqlx::query_scalar(
        "SELECT conname::text FROM pg_constraint
          WHERE conrelid = 'openmettle.grant_assignments'::regclass AND contype = 'u'
            AND array_length(conkey, 1) > 3",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    assert_eq!(unique, ["grant_assignments_unique_key"]);

    // Every grantee kind, through the API's column grants.
    let (project_id, project_scope) = project(&mut api, &actor).await;
    let group: String = sqlx::query_scalar(
        "INSERT INTO openmettle.local_groups (name, created_by_user_id, updated_by_user_id)
         VALUES ('Synthetic', $1::uuid, $1::uuid) RETURNING id::text",
    )
    .bind(&actor)
    .fetch_one(&mut api)
    .await
    .unwrap();
    let insert = |target: &str, kind: &str, user: &str, group: &str, oidc: &str| {
        format!(
            "INSERT INTO openmettle.grant_assignments (scope_id, target_kind, project_id,
                 conversation_id, grantee_kind, grantee_user_id, grantee_local_group_id,
                 grantee_oidc_group_id, assignment_format, assignment_version, assignment_key,
                 source_kind, created_by_user_id)
             VALUES ('{s}', '{target}', {p}, {c}, '{kind}', {user}, {group}, {oidc},
                     'test.assignment', 1, 'sql', 'direct', '{actor}')",
            s = if target == "project" {
                &project_scope
            } else {
                &scope
            },
            p = if target == "project" {
                format!("'{project_id}'")
            } else {
                "NULL".into()
            },
            c = if target == "project" {
                "NULL".into()
            } else {
                format!("'{chat}'")
            },
        )
    };
    let u = format!("'{other}'");
    let g = format!("'{group}'");
    for (sql, code) in [
        (insert("project", "local_group", "NULL", &g, "NULL"), None),
        (
            insert("project", "oidc_group", "NULL", "NULL", "'team'"),
            None,
        ),
        (
            insert("conversation", "project", "NULL", "NULL", "NULL"),
            None,
        ),
        (insert("project", "user", &u, "NULL", "NULL"), None),
        // Duplicates of each kind: NULLs are not distinct in the natural key.
        (
            insert("project", "local_group", "NULL", &g, "NULL"),
            Some("23505"),
        ),
        (
            insert("project", "oidc_group", "NULL", "NULL", "'team'"),
            Some("23505"),
        ),
        (
            insert("conversation", "project", "NULL", "NULL", "NULL"),
            Some("23505"),
        ),
        // A project-wide grantee never targets a project.
        (
            insert("project", "project", "NULL", "NULL", "NULL"),
            Some("23514"),
        ),
        // Exactly the kind's column, and only it.
        (
            insert("project", "user", "NULL", "NULL", "NULL"),
            Some("23514"),
        ),
        (
            insert("project", "local_group", &u, &g, "NULL"),
            Some("23514"),
        ),
        (
            insert("project", "oidc_group", "NULL", &g, "'team2'"),
            Some("23514"),
        ),
        (
            insert("conversation", "project", &u, "NULL", "NULL"),
            Some("23514"),
        ),
        (
            insert("project", "group", "NULL", &g, "NULL"),
            Some("23514"),
        ),
        (
            insert("project", "oidc_group", "NULL", "NULL", "''"),
            Some("23514"),
        ),
        (
            insert("project", "oidc_group", "NULL", "NULL", "E'a\\nb'"),
            Some("23514"),
        ),
        (
            insert(
                "project",
                "oidc_group",
                "NULL",
                "NULL",
                &format!("'{}'", "x".repeat(1025)),
            ),
            Some("23514"),
        ),
        (
            insert(
                "project",
                "local_group",
                "NULL",
                &format!("'{UNKNOWN}'"),
                "NULL",
            ),
            Some("23503"),
        ),
    ] {
        match code {
            None => {
                api.execute(AssertSqlSafe(sql.clone())).await.unwrap();
            }
            Some(code) => expect_state(&mut api, &sql, code).await,
        }
    }
    // The API takes the inert project lock but can never set it; the worker can do neither.
    let mut tx_api = connect(&db.0, API).await;
    tx_api.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT id FROM openmettle.projects WHERE id = $1::uuid FOR UPDATE")
        .bind(&project_id)
        .execute(&mut tx_api)
        .await
        .unwrap();
    tx_api.execute("ROLLBACK").await.unwrap();
    expect_state(
        &mut api,
        "UPDATE openmettle.projects SET lock_guard = true",
        "23514",
    )
    .await;
    let mut worker = connect(&db.0, WORKER).await;
    for sql in [
        "SELECT id FROM openmettle.projects FOR UPDATE",
        "UPDATE openmettle.projects SET lock_guard = false",
        "INSERT INTO openmettle.grant_assignments (grantee_kind) VALUES ('project')",
        "UPDATE openmettle.grant_assignments SET grantee_kind = 'project'",
    ] {
        expect_state(&mut worker, sql, "42501").await;
    }
    expect_state(
        &mut api,
        "UPDATE openmettle.grant_assignments SET grantee_kind = 'project'",
        "42501",
    )
    .await;
    // The boundary check reports any privilege beyond the version-16 contract.
    let mut owner = connect(&db.0, OWNER).await;
    for (grant, revoke, violation) in [
        (
            "GRANT UPDATE (grantee_kind) ON openmettle.grant_assignments TO openmettle_api",
            "REVOKE UPDATE (grantee_kind) ON openmettle.grant_assignments FROM openmettle_api",
            "openmettle_api has UPDATE on openmettle.grant_assignments.grantee_kind",
        ),
        (
            "GRANT UPDATE (lock_guard) ON openmettle.projects TO openmettle_worker",
            "REVOKE UPDATE (lock_guard) ON openmettle.projects FROM openmettle_worker",
            "openmettle_worker has UPDATE on openmettle.projects.lock_guard",
        ),
    ] {
        owner.execute(grant).await.unwrap();
        refused_with(&settings, MIGRATIONS, violation).await;
        owner.execute(revoke).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
}

// --- projects ----------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn project_settings_and_lifecycle_are_owner_only_audited_and_idempotent() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let editor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let outsider = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let withdrawn = account(&mut owner, PROVIDER, false, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let mut c = api(&db).await;
    let defaults = json!({"model": "synthetic"});
    let alpha = input("Alpha", &defaults);

    let p = applied(projects::create_project(&mut c, &ctx(&alice, "create"), &alpha).await);
    let replay = projects::create_project(&mut c, &ctx(&alice, "create"), &alpha).await;
    assert_eq!(
        replay.unwrap(),
        WriteOutcome::Replayed {
            target_id: p.clone()
        }
    );
    assert_eq!(
        conflict(
            projects::create_project(&mut c, &ctx(&alice, "create"), &input("Beta", &defaults))
                .await
        ),
        "request_key already recorded another change"
    );
    assert_eq!(
        denied(projects::create_project(&mut c, &ctx(&withdrawn, "w"), &alpha).await),
        DenialReason::InactivePrincipal
    );
    assert_eq!(role_of(&db, &alice, &p).await, Some(ProjectRole::Owner));
    assert_eq!(direct_roles(&db, &p, &alice).await, ["owner"]);
    let loaded = projects::load_project_settings(&mut c, &p)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            loaded.name.as_str(),
            loaded.defaults.clone(),
            loaded.revision,
            loaded.archived,
            loaded.deleted
        ),
        ("Alpha", defaults.clone(), 1, false, false)
    );
    assert_eq!(loaded.scope_id, scope_of(&db, &p).await);

    applied(
        set_role(
            &db,
            &alice,
            "add-editor",
            &p,
            &user(&editor),
            ProjectRole::Editor,
        )
        .await,
    );
    let renamed = json!({"model": "other", "temperature": 1});
    let gamma = input("Gamma", &renamed);
    applied(projects::update_project_settings(&mut c, &ctx(&alice, "update"), &p, &gamma).await);
    assert_eq!(
        conflict(
            projects::update_project_settings(&mut c, &ctx(&alice, "update-2"), &p, &gamma).await
        ),
        UNCHANGED
    );
    let legacy = json!({"collection_ids": ["x"]});
    assert!(matches!(
        projects::update_project_settings(&mut c, &ctx(&alice, "legacy"), &p, &input("G", &legacy))
            .await,
        Err(StoreError::InvalidInput("defaults"))
    ));
    // Members below owner see a visible refusal; non-members, the administrator included, a
    // concealed one.
    for (actor, expected) in [
        (&editor, policy(PolicyReason::InsufficientRole)),
        (&outsider, DenialReason::NotFound),
        (&admin, DenialReason::NotFound),
    ] {
        assert_eq!(
            denied(projects::update_project_settings(&mut c, &ctx(actor, "x"), &p, &alpha).await),
            expected
        );
        assert_eq!(
            denied(projects::archive_project(&mut c, &ctx(actor, "y"), &p).await),
            expected
        );
        assert_eq!(
            denied(projects::delete_project(&mut c, &ctx(actor, "z"), &p).await),
            expected
        );
    }
    let settings = projects::load_project_settings(&mut c, &p)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (settings.name.as_str(), settings.defaults, settings.revision),
        ("Gamma", renamed, 2)
    );

    applied(projects::archive_project(&mut c, &ctx(&alice, "archive"), &p).await);
    assert!(
        projects::load_project_settings(&mut c, &p)
            .await
            .unwrap()
            .unwrap()
            .archived
    );
    assert_eq!(
        conflict(projects::archive_project(&mut c, &ctx(&alice, "archive-2"), &p).await),
        UNCHANGED
    );
    applied(projects::restore_project(&mut c, &ctx(&alice, "restore"), &p).await);
    assert_eq!(
        conflict(projects::restore_project(&mut c, &ctx(&alice, "restore-2"), &p).await),
        UNCHANGED
    );
    applied(projects::delete_project(&mut c, &ctx(&alice, "delete"), &p).await);
    let deleted = projects::load_project_settings(&mut c, &p)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (deleted.archived, deleted.deleted, deleted.revision),
        (false, true, 5)
    );
    // A deleted project is concealed from every later change, even from its owner.
    assert_eq!(
        denied(projects::delete_project(&mut c, &ctx(&alice, "delete-2"), &p).await),
        DenialReason::NotFound
    );
    assert_eq!(
        denied(
            set_role(
                &db,
                &alice,
                "late",
                &p,
                &user(&outsider),
                ProjectRole::Viewer
            )
            .await
        ),
        DenialReason::NotFound
    );

    // A pre-15 project has default settings until its owner writes the first row.
    let (legacy_project, legacy_scope) = project(&mut owner, &alice.user).await;
    let defaults_only = projects::load_project_settings(&mut c, &legacy_project)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            defaults_only.name.as_str(),
            defaults_only.instructions.as_str(),
            defaults_only.defaults,
            defaults_only.revision
        ),
        ("", "", json!({}), 0)
    );
    assert_eq!(defaults_only.scope_id, legacy_scope);
    assert_eq!(
        projects::load_project_settings(&mut c, UNKNOWN)
            .await
            .unwrap(),
        None
    );
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    grants::change_grant(
        &mut tx,
        &ChangeInput {
            assignment: Assignment {
                scope: &legacy_scope,
                target: Target::Project(&legacy_project),
                grantee: grants::Grantee::User(&alice.user),
                format: authz::PROJECT_ROLE,
                version: 1,
                key: "owner",
                mapping_rule: None,
            },
            actor: &alice.user,
            key: "legacy-owner",
            expected_revision: 0,
            mapping_revision: None,
            decision: grants::Decision::Grant,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        conflict(
            projects::archive_project(&mut c, &ctx(&alice, "legacy-archive"), &legacy_project)
                .await
        ),
        "project settings are not initialised"
    );
    applied(
        projects::update_project_settings(
            &mut c,
            &ctx(&alice, "legacy-set"),
            &legacy_project,
            &alpha,
        )
        .await,
    );
    let first = projects::load_project_settings(&mut c, &legacy_project)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((first.name.as_str(), first.revision), ("Alpha", 1));

    let digest = |r: &Audit| -> bool { r.5.contains("settings_digest") && !r.5.contains("Alpha") };
    let rows = audit(&db).await;
    assert!(rows.iter().filter(|r| r.2 == "project.create").all(digest));
    assert_eq!(
        actions(rows),
        [
            row("project.create", "project", &p),
            row("project.member_grant", "project", &p),
            row("project.settings_update", "project", &p),
            row("project.archive", "project", &p),
            row("project.restore", "project", &p),
            row("project.delete", "project", &p),
            row("project.settings_update", "project", &legacy_project),
        ]
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn membership_takes_the_highest_role_across_direct_group_and_oidc_grants() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let grouped = account(&mut owner, PROVIDER, true, FUTURE).await;
    let oidc = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    // `oidc` has current present evidence of OIDC group `synthetic-team` and a mapped ADR 0021
    // viewer grant on the fixture's own project.
    let mut owner = present_membership(&db, &oidc).await;
    let mapped: String =
        sqlx::query_scalar("SELECT project_id::text FROM openmettle.membership_observations")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let mut c = api(&db).await;
    let group = applied(store::create_local_group(&mut c, &ctx(&admin, "group"), "Readers").await);
    applied(
        store::add_local_group_member(&mut c, &ctx(&admin, "member"), &group, &grouped.user).await,
    );
    let p = create(&db, &alice, "create").await;

    // Highest active role wins across a direct viewer grant and a local-group editor grant.
    applied(
        set_role(
            &db,
            &alice,
            "g-view",
            &p,
            &user(&grouped),
            ProjectRole::Viewer,
        )
        .await,
    );
    applied(
        set_role(
            &db,
            &alice,
            "g-edit",
            &p,
            &Grantee::LocalGroup(group.clone()),
            ProjectRole::Editor,
        )
        .await,
    );
    assert_eq!(role_of(&db, &grouped, &p).await, Some(ProjectRole::Editor));
    // Namespaces are separate: an OIDC group named like the local group grants its members
    // nothing.
    applied(
        set_role(
            &db,
            &alice,
            "ns-oidc",
            &p,
            &Grantee::OidcGroup(group.clone()),
            ProjectRole::Owner,
        )
        .await,
    );
    assert_eq!(role_of(&db, &grouped, &p).await, Some(ProjectRole::Editor));
    // Removing the direct grant leaves the group role; removing the member leaves nothing.
    applied(revoke(&db, &alice, "g-unview", &p, &user(&grouped)).await);
    assert_eq!(role_of(&db, &grouped, &p).await, Some(ProjectRole::Editor));
    applied(
        store::remove_local_group_member(&mut c, &ctx(&admin, "unmember"), &group, &grouped.user)
            .await,
    );
    assert_eq!(role_of(&db, &grouped, &p).await, None);
    applied(
        store::add_local_group_member(&mut c, &ctx(&admin, "remember"), &group, &grouped.user)
            .await,
    );
    // A disabled group's grant is omitted from hydration.
    applied(store::disable_local_group(&mut c, &ctx(&admin, "group-off"), &group).await);
    assert!(
        !hydrated(&db, API, &p, NOW)
            .await
            .grants
            .iter()
            .any(|g| g.grantee == Grantee::LocalGroup(group.clone()))
    );
    assert_eq!(role_of(&db, &grouped, &p).await, None);
    assert_eq!(
        conflict(
            set_role(
                &db,
                &alice,
                "g-off",
                &p,
                &Grantee::LocalGroup(group.clone()),
                ProjectRole::Viewer
            )
            .await
        ),
        "local group is disabled"
    );
    applied(store::enable_local_group(&mut c, &ctx(&admin, "group-on"), &group).await);

    // An OIDC group grant needs current present evidence; the mapped ADR 0021 viewer too.
    applied(
        set_role(
            &db,
            &alice,
            "oidc",
            &p,
            &Grantee::OidcGroup(OIDC_TEAM.into()),
            ProjectRole::Owner,
        )
        .await,
    );
    assert_eq!(role_of(&db, &oidc, &p).await, Some(ProjectRole::Owner));
    assert_eq!(
        role_of(&db, &oidc, &mapped).await,
        Some(ProjectRole::Viewer)
    );
    let later = NOW + 60_000;
    let stale = hydrate(&db, API, &oidc, later).await.unwrap();
    assert!(stale.oidc_groups.is_empty());
    assert_eq!(hydrated(&db, API, &p, later).await.role_of(&stale), None);
    assert_eq!(
        hydrated(&db, API, &mapped, later).await.role_of(&stale),
        None
    );
    // OIDC group owners never count toward the last direct owner.
    assert_eq!(
        denied(revoke(&db, &alice, "alone", &p, &user(&alice)).await),
        policy(PolicyReason::LastProjectOwner)
    );

    // Changing a role replaces the old direct grant: the demoted owner keeps no owner key.
    applied(
        set_role(
            &db,
            &alice,
            "bob-owner",
            &p,
            &user(&bob),
            ProjectRole::Owner,
        )
        .await,
    );
    assert_eq!(direct_roles(&db, &p, &bob).await, ["owner"]);
    applied(
        set_role(
            &db,
            &alice,
            "bob-editor",
            &p,
            &user(&bob),
            ProjectRole::Editor,
        )
        .await,
    );
    assert_eq!(direct_roles(&db, &p, &bob).await, ["editor"]);
    assert_eq!(role_of(&db, &bob, &p).await, Some(ProjectRole::Editor));
    assert_eq!(
        conflict(
            set_role(
                &db,
                &alice,
                "bob-editor-2",
                &p,
                &user(&bob),
                ProjectRole::Editor
            )
            .await
        ),
        UNCHANGED
    );
    assert!(matches!(
        set_role(
            &db,
            &alice,
            "bob-editor",
            &p,
            &user(&bob),
            ProjectRole::Editor
        )
        .await,
        Ok(WriteOutcome::Replayed { .. })
    ));
    // Below owner, outside the project or as a mere administrator, changes are refused.
    for (actor, expected) in [
        (&bob, policy(PolicyReason::InsufficientRole)),
        (&grouped, policy(PolicyReason::InsufficientRole)),
        (&admin, DenialReason::NotFound),
    ] {
        assert_eq!(
            denied(set_role(&db, actor, "nope", &p, &user(actor), ProjectRole::Owner).await),
            expected
        );
    }
    assert_eq!(
        denied(
            set_role(
                &db,
                &alice,
                "whole",
                &p,
                &Grantee::Project,
                ProjectRole::Viewer
            )
            .await
        ),
        policy(PolicyReason::InvalidGrantee)
    );
    assert!(matches!(
        set_role(
            &db,
            &alice,
            "unknown",
            &p,
            &Grantee::User(UNKNOWN.into()),
            ProjectRole::Viewer
        )
        .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        set_role(
            &db,
            &alice,
            "bad",
            &p,
            &Grantee::OidcGroup("a\nb".into()),
            ProjectRole::Viewer
        )
        .await,
        Err(StoreError::InvalidInput("grantee"))
    ));
    assert_eq!(
        conflict(revoke(&db, &alice, "never", &p, &user(&admin)).await),
        UNCHANGED
    );

    // A disabled direct owner neither holds a role nor satisfies the last-owner invariant, and
    // a disabled user cannot be granted one.
    applied(
        set_role(
            &db,
            &alice,
            "bob-owner-2",
            &p,
            &user(&bob),
            ProjectRole::Owner,
        )
        .await,
    );
    applied(store::disable_user(&mut c, &ctx(&admin, "bob-off"), &bob.user).await);
    let project = hydrated(&db, API, &p, NOW).await;
    assert!(!project.grants.iter().any(|g| g.grantee == user(&bob)));
    assert_eq!(
        denied(
            set_role(
                &db,
                &alice,
                "step-down",
                &p,
                &user(&alice),
                ProjectRole::Editor
            )
            .await
        ),
        policy(PolicyReason::LastProjectOwner)
    );
    assert_eq!(
        conflict(
            set_role(
                &db,
                &alice,
                "bob-viewer",
                &p,
                &user(&bob),
                ProjectRole::Viewer
            )
            .await
        ),
        "target user is disabled"
    );
    // The disabled user's stale owner row can still be retired.
    applied(revoke(&db, &alice, "bob-gone", &p, &user(&bob)).await);
    assert!(direct_roles(&db, &p, &bob).await.is_empty());
    // The same hydration as the worker.
    assert_eq!(
        hydrated(&db, WORKER, &p, NOW).await,
        hydrated(&db, API, &p, NOW).await
    );
    let members: Vec<Audit> = audit(&db).await.into_iter().filter(|r| r.4 == p).collect();
    let details = &members
        .iter()
        .find(|r| r.2 == "project.member_grant")
        .unwrap()
        .5;
    let expected: Value =
        json!({"grantee_kind": "user", "grantee_id": grouped.user, "role": "viewer"});
    assert_eq!(serde_json::from_str::<Value>(details).unwrap(), expected);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn project_row_lock_serializes_the_last_two_direct_owners_stepping_down() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let a = account(&mut owner, PROVIDER, true, FUTURE).await;
    let b = account(&mut owner, PROVIDER, true, FUTURE).await;
    let p = create(&db, &a, "create").await;
    applied(set_role(&db, &a, "b-owner", &p, &user(&b), ProjectRole::Owner).await);
    let owners = async || {
        let project = hydrated(&db, API, &p, NOW).await;
        let mut owners = Vec::new();
        for account in [&a, &b] {
            if project.role_of(&principal(&db, account).await) == Some(ProjectRole::Owner) {
                owners.push(account.user.clone());
            }
        }
        owners
    };

    // Each round both direct owners step down at once, by two revocations and then by a
    // revocation racing a demotion. A held project lock makes both wait first.
    for round in ["revoke-revoke", "revoke-demote"] {
        assert_eq!(owners().await.len(), 2, "{round}");
        let mut holder = connect(&db.0, API).await;
        holder.execute("BEGIN").await.unwrap();
        sqlx::query("SELECT id FROM openmettle.projects WHERE id = $1::uuid FOR UPDATE")
            .bind(&p)
            .execute(&mut holder)
            .await
            .unwrap();
        let spawn = |actor: Account, demote: bool| {
            let (name, project) = (db.0.clone(), p.clone());
            let key = format!("{round}-{}", actor.user);
            tokio::spawn(async move {
                let mut c = connect(&name, API).await;
                let me = Grantee::User(actor.user.clone());
                if demote {
                    projects::set_project_member_role(
                        &mut c,
                        &ctx(&actor, &key),
                        &project,
                        &me,
                        ProjectRole::Viewer,
                    )
                    .await
                } else {
                    projects::revoke_project_member(&mut c, &ctx(&actor, &key), &project, &me).await
                }
            })
        };
        let first = spawn(a.clone(), false);
        let second = spawn(b.clone(), round == "revoke-demote");
        wait_for_lock_waiters(&db, 2).await;
        holder.execute("ROLLBACK").await.unwrap();
        let results = [first.await.unwrap(), second.await.unwrap()];
        let won = results
            .iter()
            .filter(|r| matches!(r, Ok(WriteOutcome::Applied { .. })))
            .count();
        let lost = results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::Denied(reason)) if *reason == policy(PolicyReason::LastProjectOwner)))
            .count();
        assert_eq!((won, lost), (1, 1), "{round}: {results:?}");
        let remaining = owners().await;
        assert_eq!(remaining.len(), 1, "{round}");
        let (winner, loser) = if remaining[0] == a.user {
            (&b, &a)
        } else {
            (&a, &b)
        };
        applied(
            set_role(
                &db,
                loser,
                &format!("{round}-restore"),
                &p,
                &user(winner),
                ProjectRole::Owner,
            )
            .await,
        );
    }
}

// --- resource shares ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn shares_keep_items_private_by_default_and_follow_project_roles() {
    use PolicyReason::*;
    use ResourceAccess::{Read, Write};
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let o = account(&mut owner, PROVIDER, true, FUTURE).await; // project owner
    let e = account(&mut owner, PROVIDER, true, FUTURE).await; // editor
    let v = account(&mut owner, PROVIDER, true, FUTURE).await; // viewer
    let gm = account(&mut owner, PROVIDER, true, FUTURE).await; // member through a group only
    let x = account(&mut owner, PROVIDER, true, FUTURE).await; // outsider
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await; // account_admin, not a member
    make_admin(&mut owner, &admin).await;
    let mut c = api(&db).await;
    let group = applied(store::create_local_group(&mut c, &ctx(&admin, "group"), "Members").await);
    applied(store::add_local_group_member(&mut c, &ctx(&admin, "gm"), &group, &gm.user).await);
    let p = create(&db, &o, "create").await;
    let scope = scope_of(&db, &p).await;
    applied(set_role(&db, &o, "e", &p, &user(&e), ProjectRole::Editor).await);
    applied(set_role(&db, &o, "v", &p, &user(&v), ProjectRole::Viewer).await);
    applied(
        set_role(
            &db,
            &o,
            "g",
            &p,
            &Grantee::LocalGroup(group.clone()),
            ProjectRole::Viewer,
        )
        .await,
    );
    let ce = chat(&db, &scope, "project", &e).await;
    let cv = chat(&db, &scope, "project", &v).await;
    let co = chat(&db, &scope, "project", &o).await;
    let ae: String = sqlx::query_scalar(
        "INSERT INTO openmettle.artifacts (id, scope_id, scope_kind, owner_user_id)
         VALUES (gen_random_uuid(), $1::uuid, 'project', $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&e.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let personal: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.scopes WHERE personal_user_id = $1::uuid",
    )
    .bind(&o.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let po = chat(&db, &personal, "personal", &o).await;
    let (ce_, ae_, co_, cv_, po_) = (
        (CONVERSATION, ce.as_str()),
        (ARTIFACT, ae.as_str()),
        (CONVERSATION, co.as_str()),
        (CONVERSATION, cv.as_str()),
        (CONVERSATION, po.as_str()),
    );
    let allow = Decision::Allow;
    let read_only = (allow, refused(InsufficientAccess));

    // Private by default: only the creator reaches an unshared item, never the project owner,
    // an outsider or an account administrator.
    assert_eq!(reach(&db, &e, CONVERSATION, &ce).await, (allow, allow));
    for account in [&o, &v, &gm, &x, &admin] {
        assert_eq!(
            reach(&db, account, CONVERSATION, &ce).await,
            (HIDDEN, HIDDEN)
        );
        assert_eq!(reach(&db, account, ARTIFACT, &ae).await, (HIDDEN, HIDDEN));
    }
    let admin_principal = principal(&db, &admin).await;
    let scope_view = authz::authorize_scope(
        &admin_principal,
        &authz::Scope::Project(hydrated(&db, API, &p, NOW).await),
        Action::Read,
    );
    assert_eq!(scope_view, HIDDEN);
    // Share managers: the creator with editor or owner, and the project owner on visible items.
    // An invisible item is concealed from a would-be manager.
    for (actor, item, expected) in [
        (&o, ce_, DenialReason::NotFound),
        (&admin, ce_, DenialReason::NotFound),
        (&x, ce_, DenialReason::NotFound),
        (&v, cv_, policy(NotShareManager)),
    ] {
        assert_eq!(
            denied(share(&db, actor, "deny", item, &user(&e), Read).await),
            expected
        );
    }

    // The editor shares with the viewer for writing: the viewer's role caps it at read.
    applied(share(&db, &e, "s1", ce_, &user(&v), Write).await);
    assert_eq!(reach(&db, &v, CONVERSATION, &ce).await, read_only);
    assert_eq!(
        conflict(share(&db, &e, "s1-again", ce_, &user(&v), Write).await),
        UNCHANGED
    );
    assert!(matches!(
        share(&db, &e, "s1", ce_, &user(&v), Write).await,
        Ok(WriteOutcome::Replayed { .. })
    ));
    // Changing the access replaces the share: one active key.
    applied(share(&db, &e, "s1-read", ce_, &user(&v), Read).await);
    let shares = item(&db, CONVERSATION, &ce).await.shares;
    let active: Vec<_> = shares
        .iter()
        .filter(|s| s.recorded_active)
        .map(|s| s.permission)
        .collect();
    assert_eq!(active, [Read]);
    // The grantee must be a member: a user, a member group or the whole project.
    assert_eq!(
        denied(share(&db, &e, "s-x", ce_, &user(&x), Read).await),
        policy(GranteeNotMember)
    );
    assert_eq!(
        denied(share(&db, &e, "s-admin", ce_, &user(&admin), Read).await),
        policy(GranteeNotMember)
    );
    assert_eq!(
        denied(
            share(
                &db,
                &e,
                "s-oidc",
                ce_,
                &Grantee::OidcGroup("absent".into()),
                Read
            )
            .await
        ),
        policy(GranteeNotMember)
    );
    assert_eq!(
        denied(share(&db, &e, "s-self", ce_, &user(&e), Read).await),
        policy(InvalidGrantee)
    );
    assert!(matches!(
        share(
            &db,
            &e,
            "s-unknown",
            ce_,
            &Grantee::User(UNKNOWN.into()),
            Read
        )
        .await,
        Err(StoreError::NotFound)
    ));
    applied(
        share(
            &db,
            &e,
            "s-group",
            ce_,
            &Grantee::LocalGroup(group.clone()),
            Write,
        )
        .await,
    );
    assert_eq!(reach(&db, &gm, CONVERSATION, &ce).await, read_only);
    applied(share(&db, &e, "s-project", ae_, &Grantee::Project, Read).await);
    for member in [&o, &v, &gm] {
        assert_eq!(reach(&db, member, ARTIFACT, &ae).await, read_only);
    }
    assert_eq!(reach(&db, &x, ARTIFACT, &ae).await, (HIDDEN, HIDDEN));
    // The project owner now sees the artifact, so it may revoke there; an editor cannot reshare
    // someone else's item; a viewer never shares.
    applied(unshare(&db, &o, "o-unshare", ae_, &Grantee::Project).await);
    assert_eq!(reach(&db, &v, ARTIFACT, &ae).await, (HIDDEN, HIDDEN));
    applied(share(&db, &o, "o-share", co_, &user(&e), Write).await);
    assert_eq!(reach(&db, &e, CONVERSATION, &co).await, (allow, allow));
    assert_eq!(
        denied(share(&db, &e, "e-reshare", co_, &user(&v), Read).await),
        policy(NotShareManager)
    );
    assert_eq!(
        denied(unshare(&db, &v, "v-unshare", ce_, &user(&v)).await),
        policy(NotShareManager)
    );

    // Lapsed membership conceals every item in the project, the caller's own included, and a
    // stale share row can still be retired.
    applied(revoke(&db, &o, "v-out", &p, &user(&v)).await);
    assert_eq!(reach(&db, &v, CONVERSATION, &cv).await, (HIDDEN, HIDDEN));
    assert_eq!(reach(&db, &v, CONVERSATION, &ce).await, (HIDDEN, HIDDEN));
    applied(unshare(&db, &e, "stale", ce_, &user(&v)).await);
    assert_eq!(
        conflict(unshare(&db, &e, "stale-2", ce_, &user(&v)).await),
        UNCHANGED
    );
    // A group share applies only while the group is a member, even to a direct member.
    applied(set_role(&db, &o, "gm-direct", &p, &user(&gm), ProjectRole::Viewer).await);
    applied(revoke(&db, &o, "g-out", &p, &Grantee::LocalGroup(group.clone())).await);
    assert_eq!(reach(&db, &gm, CONVERSATION, &ce).await, (HIDDEN, HIDDEN));
    // Demoted to viewer, the creator keeps read access to their own item and loses sharing.
    applied(set_role(&db, &o, "e-viewer", &p, &user(&e), ProjectRole::Viewer).await);
    assert_eq!(reach(&db, &e, CONVERSATION, &ce).await, read_only);
    assert_eq!(
        denied(share(&db, &e, "e-demoted", ce_, &user(&gm), Read).await),
        policy(NotShareManager)
    );

    // Personal scope: the owner shares with a user or a group, never the whole project. A
    // write share never lets a non-owner run in the owner's accounting scope.
    assert_eq!(reach(&db, &x, CONVERSATION, &po).await, (HIDDEN, HIDDEN));
    applied(share(&db, &o, "p-x", po_, &user(&x), Write).await);
    assert_eq!(reach(&db, &x, CONVERSATION, &po).await, (allow, allow));
    assert_eq!(
        decide(&db, &x, CONVERSATION, &po, Action::RunExecute).await,
        refused(InsufficientAccess)
    );
    assert_eq!(
        denied(share(&db, &o, "p-all", po_, &Grantee::Project, Read).await),
        policy(InvalidGrantee)
    );
    assert_eq!(
        denied(share(&db, &x, "p-x-reshare", po_, &user(&admin), Read).await),
        policy(NotShareManager)
    );
    applied(
        share(
            &db,
            &o,
            "p-group",
            po_,
            &Grantee::LocalGroup(group.clone()),
            Read,
        )
        .await,
    );
    assert_eq!(reach(&db, &gm, CONVERSATION, &po).await, read_only);
    assert_eq!(
        reach(&db, &admin, CONVERSATION, &po).await,
        (HIDDEN, HIDDEN)
    );
    applied(unshare(&db, &o, "p-x-off", po_, &user(&x)).await);
    assert_eq!(reach(&db, &x, CONVERSATION, &po).await, (HIDDEN, HIDDEN));
    // Unknown items and unshareable kinds.
    assert_eq!(
        denied(share(&db, &o, "nothing", (CONVERSATION, UNKNOWN), &user(&x), Read).await),
        DenialReason::NotFound
    );
    assert!(matches!(
        share(
            &db,
            &o,
            "memory",
            (ResourceKind::Memory, &po),
            &user(&x),
            Read
        )
        .await,
        Err(StoreError::InvalidInput("resource kind"))
    ));
    let shares: Vec<_> = audit(&db)
        .await
        .into_iter()
        .filter(|r| r.2.starts_with("resource."))
        .map(|r| (r.2, r.3, r.4))
        .collect();
    assert_eq!(
        shares.first(),
        Some(&row("resource.share", "conversation", &ce))
    );
    assert_eq!(
        shares.last(),
        Some(&row("resource.unshare", "conversation", &po))
    );
    assert_eq!(shares.len(), 10);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn worker_hydrates_projects_and_resources_without_admin_or_settings_reads() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let oidc = account(&mut owner, PROVIDER, true, FUTURE).await;
    let mut owner = present_membership(&db, &oidc).await;
    let mapped: String =
        sqlx::query_scalar("SELECT project_id::text FROM openmettle.membership_observations")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let p = create(&db, &alice, "create").await;
    applied(
        set_role(
            &db,
            &alice,
            "team",
            &p,
            &Grantee::OidcGroup(OIDC_TEAM.into()),
            ProjectRole::Editor,
        )
        .await,
    );
    let scope = scope_of(&db, &p).await;
    let item_id = chat(&db, &scope, "project", &alice).await;
    applied(
        share(
            &db,
            &alice,
            "share",
            (CONVERSATION, &item_id),
            &Grantee::Project,
            ResourceAccess::Write,
        )
        .await,
    );

    let mut worker = connect(&db.0, WORKER).await;
    let run_owner = store::hydrate_worker_principal(&mut worker, &oidc.user, &oidc.approval, NOW)
        .await
        .unwrap()
        .unwrap();
    for project in [&p, &mapped] {
        let as_worker = projects::hydrate_project(&mut worker, project, NOW)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(as_worker, hydrated(&db, API, project, NOW).await);
    }
    assert_eq!(
        hydrated(&db, WORKER, &p, NOW).await.role_of(&run_owner),
        Some(ProjectRole::Editor)
    );
    assert_eq!(
        hydrated(&db, WORKER, &mapped, NOW)
            .await
            .role_of(&run_owner),
        Some(ProjectRole::Viewer)
    );
    let resource = projects::hydrate_resource(&mut worker, CONVERSATION, &item_id, NOW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resource, item(&db, CONVERSATION, &item_id).await);
    assert_eq!(
        authz::authorize_resource(&run_owner, &resource, Action::RunExecute),
        Decision::Allow
    );
    for missing in [
        projects::hydrate_project(&mut worker, UNKNOWN, NOW)
            .await
            .unwrap()
            .map(drop),
        projects::hydrate_resource(&mut worker, ARTIFACT, UNKNOWN, NOW)
            .await
            .unwrap()
            .map(drop),
    ] {
        assert_eq!(missing, None);
    }
    // The worker reads neither administrators nor project settings, and hydration never needs to.
    assert!(matches!(
        projects::load_project_settings(&mut worker, &p).await,
        Err(StoreError::Database(_))
    ));
    let mut worker = connect(&db.0, WORKER).await;
    for table in ["account_admins", "project_settings", "authorization_audit"] {
        expect_state(
            &mut worker,
            &format!("SELECT * FROM openmettle.{table}"),
            "42501",
        )
        .await;
    }
}
