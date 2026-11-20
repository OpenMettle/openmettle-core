//! ADR 0027 PR3: primary-database principal hydration and the transactional administration
//! store. Hydration runs as both application roles; every write runs as `openmettle_api`
//! only. The owner role seeds fixtures and reads results. All values are synthetic.
use super::*;
use openmettle_core::{
    authz::{
        DenialReason, PolicyReason, Principal,
        store::{self, AuditContext, StoreError, WriteOutcome},
    },
    grants::{self, Assignment, ChangeInput, Decision, MappingInput, Target},
    runs::WriteTransaction,
};
use std::collections::BTreeSet;

const ISSUER: &str = "https://authz-store.example.test";
const PROVIDER: &str = "00000000-0000-0000-0000-0000000005a1";
const RETIRED: &str = "00000000-0000-0000-0000-0000000005a2";
const RULE: &str = "00000000-0000-0000-0000-0000000005a3";
const UNKNOWN: &str = "00000000-0000-0000-0000-0000000005ff";
const NOW: i64 = 1_800_000_000_000;
const FUTURE: i64 = 4_102_444_800_000;
const LAST_ADMIN: DenialReason = DenialReason::Policy(PolicyReason::LastAccountAdmin);
const NOT_ADMIN: DenialReason = DenialReason::Policy(PolicyReason::NotAccountAdmin);

#[derive(Clone)]
struct Account {
    user: String,
    approval: String,
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// An active provider and a retired one, both for `ISSUER`.
async fn providers(owner: &mut PgConnection) {
    for (id, revisions) in [
        (PROVIDER, &[Some("v1")][..]),
        (RETIRED, &[Some("v1"), None][..]),
    ] {
        sqlx::query("INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason) VALUES ($1::uuid, $2, 'synthetic', 'fixture-owner', 'synthetic provider')")
            .bind(id).bind(ISSUER).execute(&mut *owner).await.unwrap();
        for revision in revisions {
            sqlx::query("INSERT INTO openmettle.login_provider_revisions (provider_id, revision) VALUES ($1::uuid, $2)")
                .bind(id).bind(revision).execute(&mut *owner).await.unwrap();
        }
    }
}

/// An enabled user with a personal scope, one identity and its approval.
async fn account(owner: &mut PgConnection, provider: &str, active: bool, expires: i64) -> Account {
    let user = new_user(owner).await;
    personal_scope(owner, &user).await;
    let approval = sqlx::query_scalar(
        "WITH i AS (INSERT INTO openmettle.user_identities (user_id, issuer, subject)
                    VALUES ($1::uuid, $2, $3) RETURNING id)
         INSERT INTO openmettle.local_identity_approvals
             (provider_id, identity_id, active, expires_ms, changed_by, change_reason)
         SELECT $4::uuid, i.id, $5, $6, 'fixture-owner', 'synthetic approval' FROM i
         RETURNING id::text",
    )
    .bind(&user)
    .bind(ISSUER)
    .bind(format!("synthetic-{user}"))
    .bind(provider)
    .bind(active)
    .bind(expires)
    .fetch_one(owner)
    .await
    .unwrap();
    Account { user, approval }
}

async fn make_admin(owner: &mut PgConnection, account: &Account) {
    sqlx::query("INSERT INTO openmettle.account_admins (user_id, active) VALUES ($1::uuid, true)")
        .bind(&account.user)
        .execute(owner)
        .await
        .unwrap();
}

async fn hydrate(db: &TestDb, role: &str, account: &Account, now: i64) -> Option<Principal> {
    let mut c = connect(&db.0, role).await;
    let result = if role == API {
        store::hydrate_api_principal(&mut c, &account.user, &account.approval, now).await
    } else {
        store::hydrate_worker_principal(&mut c, &account.user, &account.approval, now).await
    };
    result.unwrap()
}

async fn principal(db: &TestDb, account: &Account) -> Principal {
    hydrate(db, API, account, NOW).await.unwrap()
}

fn ctx<'a>(actor: &'a Account, request_key: &'a str) -> AuditContext<'a> {
    AuditContext {
        actor_user_id: &actor.user,
        actor_approval_id: &actor.approval,
        now_ms: NOW,
        request_key,
        reason: "synthetic administration change",
    }
}

fn denied<T: std::fmt::Debug>(result: Result<T, StoreError>) -> DenialReason {
    match result {
        Err(StoreError::Denied(reason)) => reason,
        other => panic!("expected a denial, got {other:?}"),
    }
}

fn applied(result: Result<WriteOutcome, StoreError>) -> String {
    match result {
        Ok(WriteOutcome::Applied { target_id }) => target_id,
        other => panic!("expected an applied change, got {other:?}"),
    }
}

fn conflict<T: std::fmt::Debug>(result: Result<T, StoreError>) -> &'static str {
    match result {
        Err(StoreError::Conflict(what)) => what,
        other => panic!("expected a conflict, got {other:?}"),
    }
}

const UNCHANGED: &str = "target is already in the requested state";

/// (actor_kind, operator is NULL, action, target_kind, target_id, details) in insertion order.
type Audit = (String, bool, String, String, String, String);
async fn audit(db: &TestDb) -> Vec<Audit> {
    sqlx::query_as(
        "SELECT actor_kind, operator_id IS NULL, action, target_kind, target_id, details::text
           FROM openmettle.authorization_audit ORDER BY occurred_at, id",
    )
    .fetch_all(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}

fn audited(action: &str, kind: &str, target: &str, details: &str) -> Audit {
    (
        "user".into(),
        true,
        action.into(),
        kind.into(),
        target.into(),
        details.into(),
    )
}

async fn scalar(db: &TestDb, sql: &str, binds: &[&str]) -> i64 {
    let mut query = sqlx::query_scalar(AssertSqlSafe(sql.to_owned()));
    for bind in binds {
        query = query.bind(*bind);
    }
    query
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

async fn enabled_admins(db: &TestDb) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.account_admins a JOIN openmettle.users u ON u.id = a.user_id
          WHERE a.active AND u.disabled_at IS NULL",
    )
    .fetch_one(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn hydration_reads_current_primary_state_for_both_roles() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let active = account(&mut owner, PROVIDER, true, FUTURE).await;
    let withdrawn = account(&mut owner, PROVIDER, false, FUTURE).await;
    let expired = account(&mut owner, PROVIDER, true, NOW).await;
    let retired = account(&mut owner, RETIRED, true, FUTURE).await;
    let disabled = account(&mut owner, PROVIDER, true, FUTURE).await;
    sqlx::query("UPDATE openmettle.users SET disabled_at = clock_timestamp() WHERE id = $1::uuid")
        .bind(&disabled.user)
        .execute(&mut owner)
        .await
        .unwrap();
    make_admin(&mut owner, &active).await;
    let scopeless = new_user(&mut owner).await;

    // Enabled group with an active membership counts; a disabled group or an inactive
    // membership does not.
    let groups: Vec<String> = sqlx::query_scalar(
        "INSERT INTO openmettle.local_groups (name, created_by_user_id, updated_by_user_id, disabled_at)
         VALUES ('enabled', $1::uuid, $1::uuid, NULL), ('disabled', $1::uuid, $1::uuid, clock_timestamp()),
                ('inactive', $1::uuid, $1::uuid, NULL)
         RETURNING id::text",
    )
    .bind(&active.user)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    for (group, member) in groups.iter().zip([true, true, false]) {
        sqlx::query("INSERT INTO openmettle.local_group_memberships (group_id, user_id, active, updated_by_user_id) VALUES ($1::uuid, $2::uuid, $3, $2::uuid)")
            .bind(group).bind(&active.user).bind(member).execute(&mut owner).await.unwrap();
    }
    for (table, flag, capability, value) in [
        ("user_capability_grants", "granted", "runs.use_yolo", true),
        ("user_capability_grants", "granted", "withdrawn.cap", false),
        ("user_capability_denies", "denied", "web_search", true),
        ("user_capability_denies", "denied", "lifted.cap", false),
    ] {
        sqlx::query(AssertSqlSafe(format!("INSERT INTO openmettle.{table} (user_id, capability, {flag}, updated_by_user_id) VALUES ($1::uuid, $2, $3, $1::uuid)")))
            .bind(&active.user).bind(capability).bind(value).execute(&mut owner).await.unwrap();
    }
    for (capability, denied) in [("web_search", true), ("lifted.cap", false)] {
        sqlx::query("INSERT INTO openmettle.platform_capability_denies (capability, denied, updated_by_user_id) VALUES ($1, $2, $3::uuid)")
            .bind(capability).bind(denied).bind(&active.user).execute(&mut owner).await.unwrap();
    }

    let scope: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.scopes WHERE personal_user_id = $1::uuid",
    )
    .bind(&active.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    for role in [API, WORKER] {
        let expected = Principal {
            user_id: active.user.clone(),
            personal_scope_id: scope.clone(),
            account_active: true,
            approval_active: true,
            provider_active: true,
            // The worker never reads account_admins and never fails on it.
            account_admin: role == API,
            local_groups: set(&[groups[0].as_str()]),
            oidc_groups: BTreeSet::new(),
            granted_capabilities: set(&["runs.use_yolo"]),
            denied_capabilities: set(&["web_search"]),
        };
        assert_eq!(
            hydrate(&db, role, &active, NOW).await,
            Some(expected),
            "{role}"
        );

        let flags = async |account: &Account, now| {
            let p = hydrate(&db, role, account, now).await.unwrap();
            (
                p.account_active,
                p.approval_active,
                p.provider_active,
                p.is_active(),
            )
        };
        assert_eq!(
            flags(&withdrawn, NOW).await,
            (true, false, true, false),
            "{role}"
        );
        assert_eq!(
            flags(&expired, NOW).await,
            (true, false, true, false),
            "{role}"
        );
        assert_eq!(
            flags(&expired, NOW - 1).await,
            (true, true, true, true),
            "{role}"
        );
        assert_eq!(
            flags(&retired, NOW).await,
            (true, true, false, false),
            "{role}"
        );
        assert_eq!(
            flags(&disabled, NOW).await,
            (false, true, true, false),
            "{role}"
        );
        // Another user's approval never activates this principal.
        for approval in [&withdrawn.approval, &disabled.approval] {
            let borrowed = Account {
                user: active.user.clone(),
                approval: approval.clone(),
            };
            assert_eq!(
                flags(&borrowed, NOW).await,
                (true, false, false, false),
                "{role}"
            );
        }

        for missing in [
            Account {
                user: UNKNOWN.into(),
                approval: active.approval.clone(),
            },
            Account {
                user: scopeless.clone(),
                approval: active.approval.clone(),
            },
        ] {
            assert_eq!(hydrate(&db, role, &missing, NOW).await, None, "{role}");
        }
        let mut c = connect(&db.0, role).await;
        assert!(matches!(
            store::hydrate_worker_principal(&mut c, "not-a-uuid", &active.approval, NOW).await,
            Err(StoreError::InvalidInput("user_id"))
        ));
        let platform = store::load_platform_capabilities(&mut c).await.unwrap();
        assert_eq!(platform.denied_capabilities, set(&["web_search"]), "{role}");
    }
    // The worker role can still never read account_admins directly.
    expect_state(
        &mut connect(&db.0, WORKER).await,
        "SELECT * FROM openmettle.account_admins",
        "42501",
    )
    .await;
}

/// An ADR 0021 enrollment for `account` with a current `present` observation of
/// `synthetic-team`, written through the same grants the configuration script and session
/// issuance use. Returns the owner connection for later state changes.
async fn present_membership(db: &TestDb, account: &Account) -> PgConnection {
    let mut owner = connect(&db.0, OWNER).await;
    let (project, scope) = project(&mut owner, &account.user).await;
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    grants::record_mapping_revision(
        &mut tx,
        &MappingInput {
            rule: RULE,
            provider: PROVIDER,
            issuer: ISSUER,
            actor: &account.user,
            key: "membership-rule",
            expected_revision: 0,
            enabled: true,
            selector_kind: "group",
            claim_name: "groups",
            claim_value: "synthetic-team",
            binding_format: "openmettle.project-member",
            binding_version: 1,
            binding: project.as_bytes(),
        },
    )
    .await
    .unwrap();
    let grant = grants::change_grant(
        &mut tx,
        &ChangeInput {
            assignment: Assignment {
                scope: &scope,
                target: Target::Project(&project),
                grantee: &account.user,
                format: "openmettle.project-member",
                version: 1,
                key: &account.approval,
                mapping_rule: Some(RULE),
            },
            actor: &account.user,
            key: "membership-grant",
            expected_revision: 0,
            mapping_revision: Some(1),
            decision: Decision::Grant,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query(
        "WITH c AS (
           INSERT INTO openmettle.membership_configuration_changes
               (request_id, approval_id, previous_revision, rule_id, rule_revision, project_id,
                scope_id, max_age_seconds, enabled, baseline_change, floor_ms, actor, reason)
           VALUES (gen_random_uuid(), $1::uuid, 0, $2::uuid, 1, $3::uuid, $4::uuid, 180, true,
                   NULL, NULL, gen_random_uuid(), 'synthetic enrollment')
           RETURNING revision)
         INSERT INTO openmettle.membership_observations
             (approval_id, config_revision, enabled, floor_ms, rule_id, rule_revision, project_id,
              scope_id, max_age_seconds, issued_ms, expires_ms, observation, epoch,
              approval_generation, user_generation)
         SELECT $1::uuid, c.revision, true, NULL, $2::uuid, 1, $3::uuid, $4::uuid, 180,
                $6 - 1000, $6 + 60000, ROW('present', $5::uuid)::openmettle.membership_evidence,
                (SELECT max(epoch) FROM openmettle.login_provider_revisions
                  WHERE provider_id = $7::uuid), 0, 0
           FROM c",
    )
    .bind(&account.approval)
    .bind(RULE)
    .bind(&project)
    .bind(&scope)
    .bind(&grant.change)
    .bind(NOW)
    .bind(PROVIDER)
    .execute(&mut owner)
    .await
    .unwrap();
    owner
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn oidc_groups_need_current_present_evidence() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let member = account(&mut owner, PROVIDER, true, FUTURE).await;
    let mut owner = present_membership(&db, &member).await;
    let team = set(&["synthetic-team"]);
    for role in [API, WORKER] {
        let groups = async |now| hydrate(&db, role, &member, now).await.unwrap().oidc_groups;
        assert_eq!(groups(NOW).await, team, "{role}");
        // Past the observation expiry, or before its issue time, the evidence is stale.
        assert!(groups(NOW + 60_000).await.is_empty(), "{role}");
        assert!(groups(NOW - 1001).await.is_empty(), "{role}");
    }
    for (state, sql) in [
        (
            "absent",
            "UPDATE openmettle.membership_observations SET observation.state = 'absent'",
        ),
        (
            "stale",
            "UPDATE openmettle.membership_observations SET observation.state = 'stale'",
        ),
        // A newer session generation invalidates evidence recorded for the old one.
        (
            "generation",
            "UPDATE openmettle.users SET session_generation = 1",
        ),
    ] {
        let reset = "UPDATE openmettle.membership_observations SET observation.state = 'present'";
        owner.execute(reset).await.unwrap();
        owner
            .execute("UPDATE openmettle.users SET session_generation = 0")
            .await
            .unwrap();
        assert_eq!(principal(&db, &member).await.oidc_groups, team, "{state}");
        owner.execute(AssertSqlSafe(sql.to_owned())).await.unwrap();
        for role in [API, WORKER] {
            let p = hydrate(&db, role, &member, NOW).await.unwrap();
            assert!(p.oidc_groups.is_empty(), "{state} {role}");
        }
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn account_admin_and_lifecycle_writes_are_authorized_audited_and_idempotent() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let member = account(&mut owner, PROVIDER, true, FUTURE).await;
    let outsider = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let mut api = connect(&db.0, API).await;
    let c = &mut api;
    let admin_revision = "SELECT revision FROM openmettle.account_admins WHERE user_id = $1::uuid";

    // Grant: applied, visible on the very next hydration, then replayed without a new row.
    let grant = store::grant_account_admin(c, &ctx(&admin, "grant-1"), &member.user).await;
    assert_eq!(applied(grant), member.user);
    assert!(principal(&db, &member).await.account_admin);
    let replay = store::grant_account_admin(c, &ctx(&admin, "grant-1"), &member.user).await;
    assert_eq!(
        replay.unwrap(),
        WriteOutcome::Replayed {
            target_id: member.user.clone()
        }
    );
    assert_eq!(scalar(&db, admin_revision, &[&member.user]).await, 1);
    // The same key for another action or target is refused and changes nothing.
    for result in [
        store::revoke_account_admin(c, &ctx(&admin, "grant-1"), &member.user).await,
        store::grant_account_admin(c, &ctx(&admin, "grant-1"), &outsider.user).await,
    ] {
        assert_eq!(
            conflict(result),
            "request_key already recorded another change"
        );
    }
    assert!(principal(&db, &member).await.account_admin);
    assert!(!principal(&db, &outsider).await.account_admin);
    assert_eq!(
        conflict(store::grant_account_admin(c, &ctx(&admin, "grant-2"), &member.user).await),
        UNCHANGED
    );

    // Revoke and re-grant advance the one current-state row.
    applied(store::revoke_account_admin(c, &ctx(&admin, "revoke-1"), &member.user).await);
    assert!(!principal(&db, &member).await.account_admin);
    applied(store::grant_account_admin(c, &ctx(&admin, "grant-3"), &member.user).await);
    assert_eq!(scalar(&db, admin_revision, &[&member.user]).await, 3);

    // Disable and enable. Disabling advances the session generation.
    applied(store::disable_user(c, &ctx(&admin, "disable-1"), &member.user).await);
    let disabled = principal(&db, &member).await;
    assert!(!disabled.account_active && disabled.account_admin);
    assert_eq!(
        denied(store::grant_account_admin(c, &ctx(&member, "as-disabled"), &outsider.user).await)
            .status(),
        401
    );
    assert_eq!(
        conflict(store::disable_user(c, &ctx(&admin, "disable-2"), &member.user).await),
        UNCHANGED
    );
    let generation = "SELECT session_generation FROM openmettle.users WHERE id = $1::uuid";
    assert_eq!(scalar(&db, generation, &[&member.user]).await, 1);
    applied(store::enable_user(c, &ctx(&admin, "enable-1"), &member.user).await);
    assert!(principal(&db, &member).await.is_active());
    assert_eq!(
        conflict(store::enable_user(c, &ctx(&admin, "enable-2"), &member.user).await),
        UNCHANGED
    );

    // A disabled user cannot be promoted.
    applied(store::disable_user(c, &ctx(&admin, "disable-3"), &outsider.user).await);
    assert_eq!(
        conflict(store::grant_account_admin(c, &ctx(&admin, "grant-4"), &outsider.user).await),
        "target user is disabled"
    );
    applied(store::enable_user(c, &ctx(&admin, "enable-3"), &outsider.user).await);

    // Unknown targets, invalid input and non-administrators.
    assert!(matches!(
        store::grant_account_admin(c, &ctx(&admin, "unknown"), UNKNOWN).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store::disable_user(c, &ctx(&admin, "invalid"), "NOT-A-UUID").await,
        Err(StoreError::InvalidInput("user_id"))
    ));
    let refused =
        denied(store::grant_account_admin(c, &ctx(&outsider, "self"), &outsider.user).await);
    assert_eq!(
        (refused, refused.status(), refused.code()),
        (NOT_ADMIN, 403, "policy")
    );
    assert_eq!(
        denied(store::disable_user(c, &ctx(&outsider, "other"), UNKNOWN).await),
        NOT_ADMIN
    );

    // The last enabled administrator can be neither demoted nor disabled.
    applied(store::revoke_account_admin(c, &ctx(&admin, "revoke-2"), &member.user).await);
    assert_eq!(enabled_admins(&db).await, 1);
    for result in [
        store::revoke_account_admin(c, &ctx(&admin, "revoke-self"), &admin.user).await,
        store::disable_user(c, &ctx(&admin, "disable-self"), &admin.user).await,
    ] {
        assert_eq!(denied(result), LAST_ADMIN);
    }
    assert!(principal(&db, &admin).await.is_active());

    // An administrator whose approval is withdrawn or whose provider is retired is inactive,
    // even though both still count as enabled administrators.
    let withdrawn = account(&mut owner, PROVIDER, false, FUTURE).await;
    let retired = account(&mut owner, RETIRED, true, FUTURE).await;
    for actor in [&withdrawn, &retired] {
        make_admin(&mut owner, actor).await;
        let reason = denied(store::disable_user(c, &ctx(actor, "inactive"), &member.user).await);
        assert_eq!(
            (reason, reason.code()),
            (DenialReason::InactivePrincipal, "unauthenticated")
        );
    }

    let user = |id: &str, action| audited(action, "user", id, "{}");
    assert_eq!(
        audit(&db).await,
        [
            user(&member.user, "account_admin.grant"),
            user(&member.user, "account_admin.revoke"),
            user(&member.user, "account_admin.grant"),
            user(&member.user, "user.disable"),
            user(&member.user, "user.enable"),
            user(&outsider.user, "user.disable"),
            user(&outsider.user, "user.enable"),
            user(&member.user, "account_admin.revoke"),
        ]
    );
    // The audit stays append-only for the API.
    expect_state(
        c,
        "UPDATE openmettle.authorization_audit SET reason = 'x'",
        "42501",
    )
    .await;
    expect_state(c, "DELETE FROM openmettle.authorization_audit", "42501").await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn local_group_and_capability_writes_apply_on_the_next_hydration() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let member = account(&mut owner, PROVIDER, true, FUTURE).await;
    let other = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let mut api = connect(&db.0, API).await;
    let c = &mut api;
    let groups = async || principal(&db, &member).await.local_groups;

    // Create, replay and duplicate names.
    let group = applied(store::create_local_group(c, &ctx(&admin, "g-create"), "Team One").await);
    let replay = store::create_local_group(c, &ctx(&admin, "g-create"), "Team One").await;
    assert_eq!(
        replay.unwrap(),
        WriteOutcome::Replayed {
            target_id: group.clone()
        }
    );
    assert_eq!(
        conflict(store::create_local_group(c, &ctx(&admin, "g-dup"), "Team One").await),
        "a local group already has this name"
    );
    for bad in ["", " Team", "Team\n", &"x".repeat(129)] {
        assert!(matches!(
            store::create_local_group(c, &ctx(&admin, "g-bad"), bad).await,
            Err(StoreError::InvalidInput("group name"))
        ));
    }

    // Membership is visible to the next hydration and is never deleted.
    let membership =
        "SELECT revision FROM openmettle.local_group_memberships WHERE group_id = $1::uuid";
    applied(store::add_local_group_member(c, &ctx(&admin, "m-add"), &group, &member.user).await);
    assert_eq!(groups().await, set(&[group.as_str()]));
    assert!(matches!(
        store::add_local_group_member(c, &ctx(&admin, "m-add"), &group, &member.user).await,
        Ok(WriteOutcome::Replayed { .. })
    ));
    assert_eq!(
        conflict(
            store::add_local_group_member(c, &ctx(&admin, "m-add2"), &group, &member.user).await
        ),
        UNCHANGED
    );
    applied(store::remove_local_group_member(c, &ctx(&admin, "m-rm"), &group, &member.user).await);
    assert!(groups().await.is_empty());
    assert_eq!(
        conflict(
            store::remove_local_group_member(c, &ctx(&admin, "m-rm2"), &group, &member.user).await
        ),
        UNCHANGED
    );
    applied(store::add_local_group_member(c, &ctx(&admin, "m-readd"), &group, &member.user).await);
    assert_eq!(scalar(&db, membership, &[&group]).await, 3);

    // A disabled group grants nothing, accepts no member and still allows cleanup.
    applied(store::disable_local_group(c, &ctx(&admin, "g-off"), &group).await);
    assert!(groups().await.is_empty());
    assert_eq!(
        conflict(
            store::add_local_group_member(c, &ctx(&admin, "m-off"), &group, &other.user).await
        ),
        "local group is disabled"
    );
    assert_eq!(
        conflict(store::disable_local_group(c, &ctx(&admin, "g-off2"), &group).await),
        UNCHANGED
    );
    applied(store::enable_local_group(c, &ctx(&admin, "g-on"), &group).await);
    assert_eq!(groups().await, set(&[group.as_str()]));

    // Rename; a taken name is refused.
    applied(store::rename_local_group(c, &ctx(&admin, "g-rename"), &group, "Team Two").await);
    let second = applied(store::create_local_group(c, &ctx(&admin, "g-second"), "Team One").await);
    assert_eq!(
        conflict(store::rename_local_group(c, &ctx(&admin, "g-taken"), &second, "Team Two").await),
        "a local group already has this name"
    );
    assert_eq!(
        conflict(store::rename_local_group(c, &ctx(&admin, "g-same"), &group, "Team Two").await),
        UNCHANGED
    );
    let group_revision = "SELECT revision FROM openmettle.local_groups WHERE id = $1::uuid";
    assert_eq!(scalar(&db, group_revision, &[&group]).await, 4);
    assert!(matches!(
        store::add_local_group_member(c, &ctx(&admin, "m-unknown"), UNKNOWN, &member.user).await,
        Err(StoreError::NotFound)
    ));

    // A disabled user cannot be added but can be removed.
    applied(store::add_local_group_member(c, &ctx(&admin, "m-other"), &second, &other.user).await);
    applied(store::disable_user(c, &ctx(&admin, "u-off"), &other.user).await);
    assert_eq!(
        conflict(
            store::add_local_group_member(c, &ctx(&admin, "m-dis"), &group, &other.user).await
        ),
        "target user is disabled"
    );
    applied(
        store::remove_local_group_member(c, &ctx(&admin, "m-dis-rm"), &second, &other.user).await,
    );

    // Capabilities: platform and user denies, opt-in grants.
    applied(
        store::set_platform_capability_deny(c, &ctx(&admin, "p-deny"), "web_search", true).await,
    );
    let platform = store::load_platform_capabilities(c).await.unwrap();
    assert_eq!(platform.denied_capabilities, set(&["web_search"]));
    applied(
        store::set_platform_capability_deny(c, &ctx(&admin, "p-allow"), "web_search", false).await,
    );
    assert!(
        store::load_platform_capabilities(c)
            .await
            .unwrap()
            .denied_capabilities
            .is_empty()
    );
    assert_eq!(
        conflict(
            store::set_platform_capability_deny(c, &ctx(&admin, "p-allow2"), "web_search", false)
                .await
        ),
        UNCHANGED
    );
    assert_eq!(
        conflict(
            store::set_platform_capability_deny(c, &ctx(&admin, "p-never"), "never.denied", false)
                .await
        ),
        UNCHANGED
    );
    applied(
        store::set_user_capability_deny(
            c,
            &ctx(&admin, "u-deny"),
            &member.user,
            "web_search",
            true,
        )
        .await,
    );
    applied(
        store::set_user_capability_grant(
            c,
            &ctx(&admin, "u-grant"),
            &member.user,
            "runs.use_yolo",
            true,
        )
        .await,
    );
    let p = principal(&db, &member).await;
    assert_eq!(
        (p.denied_capabilities, p.granted_capabilities),
        (set(&["web_search"]), set(&["runs.use_yolo"]))
    );
    applied(
        store::set_user_capability_grant(
            c,
            &ctx(&admin, "u-revoke"),
            &member.user,
            "runs.use_yolo",
            false,
        )
        .await,
    );
    assert!(
        principal(&db, &member)
            .await
            .granted_capabilities
            .is_empty()
    );
    let grant_revision =
        "SELECT revision FROM openmettle.user_capability_grants WHERE user_id = $1::uuid";
    assert_eq!(scalar(&db, grant_revision, &[&member.user]).await, 2);
    for bad in ["Web", "", "web search"] {
        assert!(matches!(
            store::set_user_capability_deny(c, &ctx(&admin, "u-bad"), &member.user, bad, true)
                .await,
            Err(StoreError::InvalidInput("capability"))
        ));
    }
    assert!(matches!(
        store::set_user_capability_deny(c, &ctx(&admin, "u-unknown"), UNKNOWN, "web_search", true)
            .await,
        Err(StoreError::NotFound)
    ));

    // A non-administrator is refused before any target is read.
    for result in [
        store::create_local_group(c, &ctx(&member, "n-1"), "Mine").await,
        store::add_local_group_member(c, &ctx(&member, "n-2"), UNKNOWN, &member.user).await,
        store::set_platform_capability_deny(c, &ctx(&member, "n-3"), "web_search", true).await,
        store::set_user_capability_grant(
            c,
            &ctx(&member, "n-4"),
            &member.user,
            "runs.use_yolo",
            true,
        )
        .await,
    ] {
        assert_eq!(denied(result), NOT_ADMIN);
    }

    let g = |action, details: &str| audited(action, "local_group", &group, details);
    let added = format!(r#"{{"user_id": "{}"}}"#, member.user);
    let other_added = format!(r#"{{"user_id": "{}"}}"#, other.user);
    let user_cap = |action, name: &str| audited(action, "capability", name, &added);
    assert_eq!(
        audit(&db).await,
        [
            g("local_group.create", r#"{"name": "Team One"}"#),
            g("local_group.member_add", &added),
            g("local_group.member_remove", &added),
            g("local_group.member_add", &added),
            g("local_group.disable", "{}"),
            g("local_group.enable", "{}"),
            g("local_group.rename", r#"{"name": "Team Two"}"#),
            audited(
                "local_group.create",
                "local_group",
                &second,
                r#"{"name": "Team One"}"#
            ),
            audited(
                "local_group.member_add",
                "local_group",
                &second,
                &other_added
            ),
            audited("user.disable", "user", &other.user, "{}"),
            audited(
                "local_group.member_remove",
                "local_group",
                &second,
                &other_added
            ),
            audited("capability.platform_deny", "capability", "web_search", "{}"),
            audited(
                "capability.platform_allow",
                "capability",
                "web_search",
                "{}"
            ),
            user_cap("capability.user_deny", "web_search"),
            user_cap("capability.user_grant", "runs.use_yolo"),
            user_cap("capability.user_revoke", "runs.use_yolo"),
        ]
    );
}

/// Waits until `n` sessions in this database are blocked on a lock.
async fn wait_for_lock_waiters(db: &TestDb, n: i64) {
    let mut admin = db.admin().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
        )
        .bind(&db.0)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        if waiting >= n {
            return;
        }
        assert!(Instant::now() < deadline, "only {waiting} lock waiters");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn account_admin_lock_serializes_removal_of_the_last_two_admins() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let a = account(&mut owner, PROVIDER, true, FUTURE).await;
    let b = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &a).await;
    make_admin(&mut owner, &b).await;

    // Each round: both administrators remove themselves concurrently, once by two demotions
    // and once by a demotion racing a disablement. A held lock makes both wait first.
    for round in ["revoke-revoke", "revoke-disable"] {
        assert_eq!(enabled_admins(&db).await, 2, "{round}");
        let mut holder = connect(&db.0, API).await;
        holder.execute("BEGIN").await.unwrap();
        holder
            .execute("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
            .await
            .unwrap();
        let spawn = |actor: Account, disable: bool| {
            let name = db.0.clone();
            let key = format!("{round}-{}", actor.user);
            tokio::spawn(async move {
                let mut c = connect(&name, API).await;
                let audit_ctx = ctx(&actor, &key);
                if disable {
                    store::disable_user(&mut c, &audit_ctx, &actor.user).await
                } else {
                    store::revoke_account_admin(&mut c, &audit_ctx, &actor.user).await
                }
            })
        };
        let first = spawn(a.clone(), false);
        let second = spawn(b.clone(), round == "revoke-disable");
        wait_for_lock_waiters(&db, 2).await;
        holder.execute("ROLLBACK").await.unwrap();
        let results = [first.await.unwrap(), second.await.unwrap()];
        let won = results
            .iter()
            .filter(|r| matches!(r, Ok(WriteOutcome::Applied { .. })))
            .count();
        let lost = results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::Denied(reason)) if *reason == LAST_ADMIN))
            .count();
        assert_eq!((won, lost), (1, 1), "{round}: {results:?}");
        assert_eq!(enabled_admins(&db).await, 1, "{round}");
        // One audit row per applied change: the winner here, plus the earlier restore.
        assert_eq!(
            audit(&db).await.len(),
            if round == "revoke-revoke" { 1 } else { 3 }
        );

        // Restore two enabled administrators through the store for the next round.
        let (winner, loser) = if results[0].is_ok() {
            (&a, &b)
        } else {
            (&b, &a)
        };
        let mut c = connect(&db.0, API).await;
        let restore = format!("{round}-restore");
        if round == "revoke-revoke" {
            applied(store::grant_account_admin(&mut c, &ctx(loser, &restore), &winner.user).await);
        }
    }
}
