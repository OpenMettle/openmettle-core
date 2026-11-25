//! ADR 0027 PR3: primary-database principal hydration and the transactional administration
//! store. Hydration runs as both application roles; every write runs as `openmettle_api`
//! only. The owner role seeds fixtures and reads results. All values are synthetic.
use super::*;
use openmettle_core::{
    authz::{
        DenialReason, PolicyReason, Principal,
        store::{self, AuditContext, StoreError, WriteOutcome},
    },
    grants::{self, Assignment, ChangeInput, Decision, Grantee, MappingInput, Target},
    runs::WriteTransaction,
};
use std::collections::BTreeSet;

const ISSUER: &str = "https://authz-store.example.test";
pub(super) const PROVIDER: &str = "00000000-0000-0000-0000-0000000005a1";
const RETIRED: &str = "00000000-0000-0000-0000-0000000005a2";
const RULE: &str = "00000000-0000-0000-0000-0000000005a3";
pub(super) const UNKNOWN: &str = "00000000-0000-0000-0000-0000000005ff";
pub(super) const NOW: i64 = 1_800_000_000_000;
pub(super) const FUTURE: i64 = 4_102_444_800_000;
const LAST_ADMIN: DenialReason = DenialReason::Policy(PolicyReason::LastAccountAdmin);
const NOT_ADMIN: DenialReason = DenialReason::Policy(PolicyReason::NotAccountAdmin);

#[derive(Clone)]
pub(super) struct Account {
    pub(super) user: String,
    pub(super) approval: String,
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// An active provider and a retired one, both for `ISSUER`.
pub(super) async fn providers(owner: &mut PgConnection) {
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
pub(super) async fn account(
    owner: &mut PgConnection,
    provider: &str,
    active: bool,
    expires: i64,
) -> Account {
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

pub(super) async fn make_admin(owner: &mut PgConnection, account: &Account) {
    sqlx::query("INSERT INTO openmettle.account_admins (user_id, active) VALUES ($1::uuid, true)")
        .bind(&account.user)
        .execute(owner)
        .await
        .unwrap();
}

pub(super) async fn hydrate(
    db: &TestDb,
    role: &str,
    account: &Account,
    now: i64,
) -> Option<Principal> {
    let mut c = connect(&db.0, role).await;
    let result = if role == API {
        store::hydrate_api_principal(&mut c, &account.user, &account.approval, now).await
    } else {
        store::hydrate_worker_principal(&mut c, &account.user, &account.approval, now).await
    };
    result.unwrap()
}

pub(super) async fn principal(db: &TestDb, account: &Account) -> Principal {
    hydrate(db, API, account, NOW).await.unwrap()
}

pub(super) fn ctx<'a>(actor: &'a Account, request_key: &'a str) -> AuditContext<'a> {
    AuditContext {
        actor_user_id: &actor.user,
        actor_approval_id: &actor.approval,
        now_ms: NOW,
        request_key,
        reason: "synthetic administration change",
    }
}

pub(super) fn denied<T: std::fmt::Debug>(result: Result<T, StoreError>) -> DenialReason {
    match result {
        Err(StoreError::Denied(reason)) => reason,
        other => panic!("expected a denial, got {other:?}"),
    }
}

pub(super) fn applied<T: std::fmt::Debug>(result: Result<WriteOutcome<T>, StoreError>) -> T {
    match result {
        Ok(WriteOutcome::Applied { target_id }) => target_id,
        other => panic!("expected an applied change, got {other:?}"),
    }
}

pub(super) fn conflict<T: std::fmt::Debug>(result: Result<T, StoreError>) -> &'static str {
    match result {
        Err(StoreError::Conflict(what)) => what,
        other => panic!("expected a conflict, got {other:?}"),
    }
}

pub(super) const UNCHANGED: &str = "target is already in the requested state";

/// (actor_kind, operator is NULL, action, target_kind, target_id, details) in insertion order.
pub(super) type Audit = (String, bool, String, String, String, String);
pub(super) async fn audit(db: &TestDb) -> Vec<Audit> {
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
pub(super) async fn present_membership(db: &TestDb, account: &Account) -> PgConnection {
    present_membership_at(db, account, NOW).await
}

/// [`present_membership`] observed at `now_ms` and current for one minute after it.
pub(super) async fn present_membership_at(
    db: &TestDb,
    account: &Account,
    now_ms: i64,
) -> PgConnection {
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
                grantee: Grantee::User(&account.user),
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
    .bind(now_ms)
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
pub(super) async fn wait_for_lock_waiters(db: &TestDb, n: i64) {
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

async fn reenable(owner: &mut PgConnection, account: &Account) {
    sqlx::query("UPDATE openmettle.users SET disabled_at = NULL WHERE id = $1::uuid")
        .bind(&account.user)
        .execute(owner)
        .await
        .unwrap();
}

async fn session_generation(owner: &mut PgConnection, account: &Account) -> i64 {
    sqlx::query_scalar("SELECT session_generation FROM openmettle.users WHERE id = $1::uuid")
        .bind(&account.user)
        .fetch_one(owner)
        .await
        .unwrap()
}

async fn group_name(owner: &mut PgConnection, group: &str) -> String {
    sqlx::query_scalar("SELECT name FROM openmettle.local_groups WHERE id = $1::uuid")
        .bind(group)
        .fetch_one(owner)
        .await
        .unwrap()
}

/// `sessions::disable_user` locks only the user row, not `account_admin_lock`. A write that
/// re-hydrates its actor while that disable is in flight waits for it and is then refused, both
/// on a path that holds `account_admin_lock` and on one that does not.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn an_administrative_write_waits_for_a_disable_in_flight_and_is_refused() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let member = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let group = applied(
        store::create_local_group(&mut connect(&db.0, API).await, &ctx(&admin, "g"), "Before")
            .await,
    );
    let audited = audit(&db).await.len();

    for write in ["account_admin.grant", "local_group.rename"] {
        // The statements of sessions::disable_user, held uncommitted.
        let mut disabler = connect(&db.0, API).await;
        let disabler_pid = backend_pid(&mut disabler).await;
        let mut tx = WriteTransaction::begin(&mut disabler).await.unwrap();
        for sql in [
            "SELECT session_generation FROM openmettle.users WHERE id = $1::uuid FOR UPDATE",
            "UPDATE openmettle.users SET disabled_at = GREATEST(created_at, clock_timestamp()),
                 session_generation = session_generation + 1 WHERE id = $1::uuid",
        ] {
            sqlx::query(sql)
                .bind(&admin.user)
                .execute(tx.connection().unwrap())
                .await
                .unwrap();
        }
        let writer = tokio::spawn({
            let (name, admin, member, group) =
                (db.0.clone(), admin.clone(), member.clone(), group.clone());
            async move {
                let mut c = connect(&name, API).await;
                let audit_ctx = ctx(&admin, write);
                if write == "account_admin.grant" {
                    store::grant_account_admin(&mut c, &audit_ctx, &member.user).await
                } else {
                    store::rename_local_group(&mut c, &audit_ctx, &group, "After").await
                }
            }
        });
        wait_for_blocked_peer(&db, disabler_pid).await;
        tx.commit().await.unwrap();
        assert_eq!(
            denied(writer.await.unwrap()),
            DenialReason::InactivePrincipal,
            "{write}"
        );
        assert!(!principal(&db, &member).await.account_admin, "{write}");
        assert_eq!(group_name(&mut owner, &group).await, "Before", "{write}");
        assert_eq!(audit(&db).await.len(), audited, "{write}");
        reenable(&mut owner, &admin).await;
    }
}

/// The mirror ordering: a write that has decided waits for no disable. Either disable path
/// waits for the write to commit, then disables the actor, advances the session generation and
/// refuses the actor's next write.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn a_disable_waits_for_an_administrative_write_that_has_decided() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    // Sort three accounts by UUID so `member_low < admin < member_high` is deterministic:
    // - when `admin < member_high`, `lock_users_ordered` locks `admin` first, then blocks on
    //   `member_high`, so `sessions::disable_user(admin)` waits on `writer_pid`.
    // - when `member_low < admin`, `lock_users_ordered` blocks on `member_low` before reaching
    //   `admin`, so `sessions::disable_user(admin)` commits first and `grant_account_admin` fails
    //   closed with InactivePrincipal after waking up.
    let mut ordered = vec![
        account(&mut owner, PROVIDER, true, FUTURE).await,
        account(&mut owner, PROVIDER, true, FUTURE).await,
        account(&mut owner, PROVIDER, true, FUTURE).await,
    ];
    ordered.sort_by(|a, b| a.user.cmp(&b.user));
    let member_high = ordered.pop().unwrap();
    let admin = ordered.pop().unwrap();
    let member_low = ordered.pop().unwrap();
    let boss = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    make_admin(&mut owner, &boss).await;
    let group = applied(
        store::create_local_group(&mut connect(&db.0, API).await, &ctx(&admin, "g"), "Before")
            .await,
    );
    let policy = openmettle_core::sessions::Policy::new(
        Duration::from_secs(60),
        10,
        Duration::from_secs(30),
    )
    .unwrap();

    // (write, disable path): account_admin.grant holds account_admin_lock, which store's
    // disable also takes, so it is raced with the session disable only.
    for (round, (write, by_store)) in [
        ("account_admin.grant", false),
        ("local_group.rename", false),
        ("local_group.rename", true),
    ]
    .into_iter()
    .enumerate()
    {
        let generation = session_generation(&mut owner, &admin).await;
        // The fixture holds the write's target, so the write stops after locking `admin`.
        let mut fixture = connect(&db.0, OWNER).await;
        let fixture_pid = backend_pid(&mut fixture).await;
        fixture.execute("BEGIN").await.unwrap();
        let (sql, target) = if write == "account_admin.grant" {
            (
                "SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE",
                &member_high.user,
            )
        } else {
            (
                "SELECT FROM openmettle.local_groups WHERE id = $1::uuid FOR UPDATE",
                &group,
            )
        };
        sqlx::query(sql)
            .bind(target)
            .execute(&mut fixture)
            .await
            .unwrap();
        let name = format!("After {round}");
        let writer = tokio::spawn({
            let (db_name, admin, member, group, name) = (
                db.0.clone(),
                admin.clone(),
                member_high.clone(),
                group.clone(),
                name.clone(),
            );
            async move {
                let mut c = connect(&db_name, API).await;
                let key = format!("write-{round}");
                let audit_ctx = ctx(&admin, &key);
                if write == "account_admin.grant" {
                    store::grant_account_admin(&mut c, &audit_ctx, &member.user).await
                } else {
                    store::rename_local_group(&mut c, &audit_ctx, &group, &name).await
                }
            }
        });
        let writer_pid = waiter_on(&db, fixture_pid).await;
        let disabler = tokio::spawn({
            let (db_name, admin, boss) = (db.0.clone(), admin.clone(), boss.clone());
            async move {
                let mut c = connect(&db_name, API).await;
                if by_store {
                    let key = format!("disable-{round}");
                    store::disable_user(&mut c, &ctx(&boss, &key), &admin.user)
                        .await
                        .map(drop)
                        .map_err(|e| format!("{e:?}"))
                } else {
                    openmettle_core::sessions::disable_user(
                        &mut c,
                        &admin.user,
                        generation,
                        &policy,
                    )
                    .await
                    .map_err(|e| format!("{e:?}"))
                }
            }
        });
        wait_for_blocked_peer(&db, writer_pid).await;
        fixture.execute("ROLLBACK").await.unwrap();
        applied(writer.await.unwrap());
        disabler.await.unwrap().unwrap();
        assert_eq!(
            session_generation(&mut owner, &admin).await,
            generation + 1,
            "{write}"
        );
        assert!(!hydrate(&db, API, &admin, NOW).await.unwrap().is_active());
        if write == "account_admin.grant" {
            assert!(principal(&db, &member_high).await.account_admin);
        } else {
            assert_eq!(group_name(&mut owner, &group).await, name);
        }
        let next = format!("next-{round}");
        assert_eq!(
            denied(
                store::rename_local_group(
                    &mut connect(&db.0, API).await,
                    &ctx(&admin, &next),
                    &group,
                    "Refused",
                )
                .await
            ),
            DenialReason::InactivePrincipal
        );
        reenable(&mut owner, &admin).await;
    }

    // Opposite UUID ordering (`member_low < admin`): `lock_users_ordered` blocks on `member_low`
    // before reaching `admin`, so `sessions::disable_user(admin)` commits immediately and the
    // waiting `grant_account_admin` fails closed with InactivePrincipal once released.
    let generation = session_generation(&mut owner, &admin).await;
    let mut fixture = connect(&db.0, OWNER).await;
    let fixture_pid = backend_pid(&mut fixture).await;
    fixture.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&member_low.user)
        .execute(&mut fixture)
        .await
        .unwrap();
    let writer = tokio::spawn({
        let (db_name, admin, member_low) = (db.0.clone(), admin.clone(), member_low.clone());
        async move {
            let mut c = connect(&db_name, API).await;
            store::grant_account_admin(&mut c, &ctx(&admin, "write-low-target"), &member_low.user)
                .await
        }
    });
    wait_for_blocked_peer(&db, fixture_pid).await;
    openmettle_core::sessions::disable_user(
        &mut connect(&db.0, API).await,
        &admin.user,
        generation,
        &policy,
    )
    .await
    .unwrap();
    fixture.execute("ROLLBACK").await.unwrap();
    assert_eq!(
        denied(writer.await.unwrap()),
        DenialReason::InactivePrincipal
    );
    assert!(!principal(&db, &member_low).await.account_admin);
}

/// Review #1: a self-disable needs its actor's row `FOR UPDATE`. Taking `FOR SHARE` first let
/// another write by the same actor with the same request key share that row and then wait on
/// the self-disable's audit key, while the self-disable waited for that share: a deadlock. The
/// fixture's `FOR SHARE` holds the self-disable at its `FOR UPDATE` until the other write has
/// reached its wait.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn a_self_disable_and_a_same_key_write_by_the_same_actor_do_not_deadlock() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let other = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    make_admin(&mut owner, &other).await;
    let group = applied(
        store::create_local_group(&mut connect(&db.0, API).await, &ctx(&admin, "g"), "Before")
            .await,
    );

    let mut fixture = connect(&db.0, OWNER).await;
    let fixture_pid = backend_pid(&mut fixture).await;
    fixture.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR SHARE")
        .bind(&admin.user)
        .execute(&mut fixture)
        .await
        .unwrap();
    let disable = tokio::spawn({
        let (name, admin) = (db.0.clone(), admin.clone());
        async move {
            let mut c = connect(&name, API).await;
            store::disable_user(&mut c, &ctx(&admin, "same-key"), &admin.user).await
        }
    });
    let disable_pid = waiter_on(&db, fixture_pid).await;
    let rename = tokio::spawn({
        let (name, admin, group) = (db.0.clone(), admin.clone(), group.clone());
        async move {
            let mut c = connect(&name, API).await;
            store::rename_local_group(&mut c, &ctx(&admin, "same-key"), &group, "After").await
        }
    });
    // The rename either completes or waits behind the self-disable.
    let mut observer = db.admin().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !rename.is_finished() {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname = current_database()
                    AND $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(disable_pid)
            .fetch_one(&mut observer)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the rename neither completed nor waited on the self-disable");
    fixture.execute("ROLLBACK").await.unwrap();

    let results = [disable.await.unwrap(), rename.await.unwrap()];
    // One applies; the other is refused as a reused key, or as inactive once the disable
    // committed. Neither is a deadlock.
    let applied = results
        .iter()
        .filter(|r| matches!(r, Ok(WriteOutcome::Applied { .. })))
        .count();
    let refused = results
        .iter()
        .filter(|r| {
            matches!(r, Err(StoreError::Conflict(store::KEY_REUSED)))
                || matches!(r, Err(StoreError::Denied(DenialReason::InactivePrincipal)))
        })
        .count();
    assert_eq!((applied, refused), (1, 1), "{results:?}");
}

/// Issue #160 gap 1: local-group and capability administrative writes acquire
/// `account_admin_lock FOR UPDATE`, so they serialize in both directions with a concurrent
/// demotion of the acting administrator.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn local_group_and_capability_writes_serialize_with_concurrent_demotion() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let boss = account(&mut owner, PROVIDER, true, FUTURE).await;
    let member = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    make_admin(&mut owner, &boss).await;
    let group = applied(
        store::create_local_group(&mut connect(&db.0, API).await, &ctx(&admin, "g0"), "Before")
            .await,
    );

    // 1. Demotion in flight (holding account_admin_lock FOR UPDATE) blocks every local-group and
    //    capability write; once the demotion commits, every write is refused with NotAccountAdmin.
    for write in [
        "local_group.create",
        "local_group.rename",
        "capability.platform_deny",
        "capability.user_deny",
        "capability.user_grant",
    ] {
        let audited = audit(&db).await.len();
        let mut demoter = connect(&db.0, OWNER).await;
        let demoter_pid = backend_pid(&mut demoter).await;
        let mut tx = WriteTransaction::begin(&mut demoter).await.unwrap();
        sqlx::query("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
            .execute(tx.connection().unwrap())
            .await
            .unwrap();
        sqlx::query(
            "UPDATE openmettle.account_admins
                SET active = false, revision = revision + 1, updated_at = clock_timestamp()
              WHERE user_id = $1::uuid",
        )
        .bind(&admin.user)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();

        let writer = tokio::spawn({
            let (name, admin, member, group) =
                (db.0.clone(), admin.clone(), member.clone(), group.clone());
            async move {
                let mut c = connect(&name, API).await;
                let audit_ctx = ctx(&admin, write);
                match write {
                    "local_group.create" => {
                        store::create_local_group(&mut c, &audit_ctx, "CreatedAfterDemote").await
                    }
                    "local_group.rename" => {
                        store::rename_local_group(&mut c, &audit_ctx, &group, "RenamedAfterDemote")
                            .await
                    }
                    "capability.platform_deny" => {
                        store::set_platform_capability_deny(&mut c, &audit_ctx, "web_search", true)
                            .await
                    }
                    "capability.user_deny" => {
                        store::set_user_capability_deny(
                            &mut c,
                            &audit_ctx,
                            &member.user,
                            "web_search",
                            true,
                        )
                        .await
                    }
                    _ => {
                        store::set_user_capability_grant(
                            &mut c,
                            &audit_ctx,
                            &member.user,
                            "runs.use_yolo",
                            true,
                        )
                        .await
                    }
                }
            }
        });
        wait_for_blocked_peer(&db, demoter_pid).await;
        tx.commit().await.unwrap();
        assert_eq!(denied(writer.await.unwrap()), NOT_ADMIN, "{write}");
        assert_eq!(group_name(&mut owner, &group).await, "Before", "{write}");
        assert!(
            store::load_platform_capabilities(&mut connect(&db.0, API).await)
                .await
                .unwrap()
                .denied_capabilities
                .is_empty(),
            "{write}"
        );
        assert!(
            principal(&db, &member).await.denied_capabilities.is_empty()
                && principal(&db, &member)
                    .await
                    .granted_capabilities
                    .is_empty(),
            "{write}"
        );
        assert_eq!(audit(&db).await.len(), audited, "{write}");

        // Restore admin for the next case.
        sqlx::query(
            "UPDATE openmettle.account_admins SET active = true, revision = revision + 1
              WHERE user_id = $1::uuid",
        )
        .bind(&admin.user)
        .execute(&mut owner)
        .await
        .unwrap();
    }

    // 2. Mirror order: a capability write that has already taken account_admin_lock and pauses on
    //    its target user row blocks a concurrent revoke_account_admin until the write commits.
    let mut fixture = connect(&db.0, OWNER).await;
    let fixture_pid = backend_pid(&mut fixture).await;
    fixture.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR UPDATE")
        .bind(&member.user)
        .execute(&mut fixture)
        .await
        .unwrap();
    let writer = tokio::spawn({
        let (name, admin, member) = (db.0.clone(), admin.clone(), member.clone());
        async move {
            let mut c = connect(&name, API).await;
            store::set_user_capability_grant(
                &mut c,
                &ctx(&admin, "mirror-cap-grant"),
                &member.user,
                "runs.use_yolo",
                true,
            )
            .await
        }
    });
    let writer_pid = waiter_on(&db, fixture_pid).await;
    let demoter = tokio::spawn({
        let (name, boss, admin) = (db.0.clone(), boss.clone(), admin.clone());
        async move {
            let mut c = connect(&name, API).await;
            store::revoke_account_admin(&mut c, &ctx(&boss, "mirror-demote"), &admin.user).await
        }
    });
    wait_for_blocked_peer(&db, writer_pid).await;
    fixture.execute("ROLLBACK").await.unwrap();
    applied(writer.await.unwrap());
    applied(demoter.await.unwrap());
    assert!(
        principal(&db, &member)
            .await
            .granted_capabilities
            .contains("runs.use_yolo")
    );
    assert_eq!(
        denied(
            store::set_platform_capability_deny(
                &mut connect(&db.0, API).await,
                &ctx(&admin, "post-demote-cap"),
                "web_search",
                true,
            )
            .await
        ),
        NOT_ADMIN
    );
}

/// Issue #160 gap 2: every administrative write locks the actor's login provider and local
/// identity approval `FOR SHARE` (`login_providers -> local_identity_approvals -> users`),
/// serializing in both directions with operator approval withdrawal and provider retirement.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn administrative_writes_serialize_with_approval_withdrawal_and_provider_retirement() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let member = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let group = applied(
        store::create_local_group(&mut connect(&db.0, API).await, &ctx(&admin, "g0"), "Before")
            .await,
    );

    for transition in ["withdraw", "retire"] {
        // 1. Transition in flight (exclusive lock on approval or provider): admin writes block,
        //    then see the committed withdrawal/retirement and fail with InactivePrincipal.
        for write in [
            "account_admin.grant",
            "local_group.rename",
            "capability.platform_deny",
        ] {
            let audited = audit(&db).await.len();
            let before_name = group_name(&mut owner, &group).await;
            let mut op = connect(&db.0, OWNER).await;
            let op_pid = backend_pid(&mut op).await;
            let mut tx = WriteTransaction::begin(&mut op).await.unwrap();
            if transition == "withdraw" {
                sqlx::query(
                    "SELECT id FROM openmettle.local_identity_approvals WHERE id = $1::uuid FOR UPDATE",
                )
                .bind(&admin.approval)
                .execute(tx.connection().unwrap())
                .await
                .unwrap();
                sqlx::query(
                    "UPDATE openmettle.local_identity_approvals
                        SET active = false, revision = revision + 1,
                            access_generation = access_generation + 1, changed_at = clock_timestamp()
                      WHERE id = $1::uuid",
                )
                .bind(&admin.approval)
                .execute(tx.connection().unwrap())
                .await
                .unwrap();
            } else {
                sqlx::query(
                    "SELECT id FROM openmettle.login_providers WHERE id = $1::uuid FOR UPDATE",
                )
                .bind(PROVIDER)
                .execute(tx.connection().unwrap())
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
                     VALUES ($1::uuid, NULL)",
                )
                .bind(PROVIDER)
                .execute(tx.connection().unwrap())
                .await
                .unwrap();
                sqlx::query(
                    "UPDATE openmettle.login_providers
                        SET access_generation = access_generation + 1, changed_at = clock_timestamp()
                      WHERE id = $1::uuid",
                )
                .bind(PROVIDER)
                .execute(tx.connection().unwrap())
                .await
                .unwrap();
            }
            let key = format!("{transition}-{write}");
            let writer = tokio::spawn({
                let (name, admin, member, group, key) = (
                    db.0.clone(),
                    admin.clone(),
                    member.clone(),
                    group.clone(),
                    key.clone(),
                );
                async move {
                    let mut c = connect(&name, API).await;
                    let audit_ctx = ctx(&admin, &key);
                    match write {
                        "account_admin.grant" => {
                            store::grant_account_admin(&mut c, &audit_ctx, &member.user).await
                        }
                        "local_group.rename" => {
                            store::rename_local_group(&mut c, &audit_ctx, &group, "After").await
                        }
                        _ => {
                            store::set_platform_capability_deny(
                                &mut c,
                                &audit_ctx,
                                "web_search",
                                true,
                            )
                            .await
                        }
                    }
                }
            });
            wait_for_blocked_peer(&db, op_pid).await;
            tx.commit().await.unwrap();
            assert_eq!(
                denied(writer.await.unwrap()),
                DenialReason::InactivePrincipal,
                "{transition}/{write}"
            );
            assert!(!principal(&db, &member).await.account_admin);
            assert_eq!(group_name(&mut owner, &group).await, before_name);
            assert!(
                store::load_platform_capabilities(&mut connect(&db.0, API).await)
                    .await
                    .unwrap()
                    .denied_capabilities
                    .is_empty()
            );
            assert_eq!(audit(&db).await.len(), audited, "{transition}/{write}");

            // Restore active approval or provider for the next iteration.
            if transition == "withdraw" {
                sqlx::query(
                    "UPDATE openmettle.local_identity_approvals
                        SET active = true, revision = revision + 1
                      WHERE id = $1::uuid",
                )
                .bind(&admin.approval)
                .execute(&mut owner)
                .await
                .unwrap();
            } else {
                sqlx::query(
                    "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
                     VALUES ($1::uuid, 'v-restored')",
                )
                .bind(PROVIDER)
                .execute(&mut owner)
                .await
                .unwrap();
            }
        }

        // 2. Mirror order: write has decided and pauses on its target lock while holding FOR SHARE
        //    on provider and approval; operator withdrawal/retirement waits for commit, then
        //    commits and blocks the actor's next write.
        let mut fixture = connect(&db.0, OWNER).await;
        let fixture_pid = backend_pid(&mut fixture).await;
        fixture.execute("BEGIN").await.unwrap();
        sqlx::query("SELECT FROM openmettle.local_groups WHERE id = $1::uuid FOR UPDATE")
            .bind(&group)
            .execute(&mut fixture)
            .await
            .unwrap();
        let renamed = format!("After-{transition}");
        let writer = tokio::spawn({
            let (name, admin, group, renamed) =
                (db.0.clone(), admin.clone(), group.clone(), renamed.clone());
            async move {
                let mut c = connect(&name, API).await;
                let key = format!("mirror-{transition}");
                store::rename_local_group(&mut c, &ctx(&admin, &key), &group, &renamed).await
            }
        });
        let writer_pid = waiter_on(&db, fixture_pid).await;
        let op = tokio::spawn({
            let (name, approval) = (db.0.clone(), admin.approval.clone());
            async move {
                let mut c = connect(&name, OWNER).await;
                let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
                if transition == "withdraw" {
                    sqlx::query(
                        "UPDATE openmettle.local_identity_approvals
                            SET active = false, revision = revision + 1,
                                access_generation = access_generation + 1
                          WHERE id = $1::uuid",
                    )
                    .bind(&approval)
                    .execute(tx.connection().unwrap())
                    .await
                    .unwrap();
                } else {
                    sqlx::query(
                        "SELECT id FROM openmettle.login_providers WHERE id = $1::uuid FOR UPDATE",
                    )
                    .bind(PROVIDER)
                    .execute(tx.connection().unwrap())
                    .await
                    .unwrap();
                    sqlx::query(
                        "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
                         VALUES ($1::uuid, NULL)",
                    )
                    .bind(PROVIDER)
                    .execute(tx.connection().unwrap())
                    .await
                    .unwrap();
                }
                tx.commit().await.unwrap();
            }
        });
        wait_for_blocked_peer(&db, writer_pid).await;
        fixture.execute("ROLLBACK").await.unwrap();
        applied(writer.await.unwrap());
        op.await.unwrap();
        assert_eq!(group_name(&mut owner, &group).await, renamed);
        assert_eq!(
            denied(
                store::rename_local_group(
                    &mut connect(&db.0, API).await,
                    &ctx(&admin, &format!("after-mirror-{transition}")),
                    &group,
                    "Refused",
                )
                .await
            ),
            DenialReason::InactivePrincipal,
            "{transition}"
        );
        if transition == "withdraw" {
            sqlx::query(
                "UPDATE openmettle.local_identity_approvals
                    SET active = true, revision = revision + 1
                  WHERE id = $1::uuid",
            )
            .bind(&admin.approval)
            .execute(&mut owner)
            .await
            .unwrap();
        } else {
            sqlx::query(
                "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
                 VALUES ($1::uuid, 'v-restored-2')",
            )
            .bind(PROVIDER)
            .execute(&mut owner)
            .await
            .unwrap();
        }
    }
}

/// Issue #160 gap 3: decision time advances to the primary's post-lock `clock_timestamp()`,
/// rejecting an approval that expires either while waiting on `account_admin_lock` or while
/// waiting on a target row lock (`local_groups`).
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn administrative_write_rejects_approval_expired_during_lock_wait() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let setup_admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &setup_admin).await;
    let group = applied(
        store::create_local_group(
            &mut connect(&db.0, API).await,
            &ctx(&setup_admin, "g0"),
            "Before",
        )
        .await,
    );

    for wait_on in ["account_admin_lock", "local_groups"] {
        // Open and warm connections before computing the short DB-clock TTL so connection setup
        // never consumes the approval window before the intended lock wait.
        let mut holder = connect(&db.0, OWNER).await;
        let holder_pid = backend_pid(&mut holder).await;
        let mut writer_conn = connect(&db.0, API).await;
        let db_now_ms: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let expires_ms = db_now_ms + 500;
        let expiring = account(&mut owner, PROVIDER, true, expires_ms).await;
        make_admin(&mut owner, &expiring).await;
        let audited = audit(&db).await.len();

        holder.execute("BEGIN").await.unwrap();
        if wait_on == "account_admin_lock" {
            holder
                .execute("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
                .await
                .unwrap();
        } else {
            sqlx::query("SELECT FROM openmettle.local_groups WHERE id = $1::uuid FOR UPDATE")
                .bind(&group)
                .execute(&mut holder)
                .await
                .unwrap();
        }

        let writer = tokio::spawn({
            let (expiring, group) = (expiring.clone(), group.clone());
            async move {
                let audit_ctx = AuditContext {
                    actor_user_id: &expiring.user,
                    actor_approval_id: &expiring.approval,
                    now_ms: db_now_ms,
                    request_key: wait_on,
                    reason: "approval expires during lock wait",
                };
                store::rename_local_group(&mut writer_conn, &audit_ctx, &group, "Expired").await
            }
        });

        wait_for_blocked_peer(&db, holder_pid).await;
        wait_past_db_ms(&mut owner, expires_ms).await;
        holder.execute("ROLLBACK").await.unwrap();

        assert_eq!(
            denied(writer.await.unwrap()),
            DenialReason::InactivePrincipal,
            "{wait_on}"
        );
        assert_eq!(group_name(&mut owner, &group).await, "Before", "{wait_on}");
        assert_eq!(audit(&db).await.len(), audited, "{wait_on}");
    }
}

/// Issue #160 (P2 #1): `store::disable_user` locks `openmettle.users` `FOR NO KEY UPDATE` (not
/// `FOR UPDATE`), so a fenced worker spill holding a `runs` row can insert a
/// `storage_reservations` row referencing `users(id)` (`FOR KEY SHARE`) while `disable_user`
/// waits on that same run row, without deadlocking.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn disable_user_does_not_deadlock_with_worker_spill_storage_reservation_fk() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let target = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;

    let scope: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.scopes WHERE personal_user_id = $1::uuid AND kind = 'personal'",
    )
    .bind(&target.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let conversation: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversations (scope_id, scope_kind, owner_user_id)
         VALUES ($1::uuid, 'personal', $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&target.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let branch_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&conversation)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let message_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.messages (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&conversation)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let run_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.runs
             (scope_id, actor_user_id, actor_approval_id, conversation_id, branch_id,
              input_message_id, idempotency_key, state, snapshot_format, snapshot_version,
              input_snapshot, config_snapshot, request_identity, request_digest,
              round_limit, queue_expires_at)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,
                 $6::uuid, 'spill-run', 'queued', 'openmettle.turn', 1,
                 '{}'::bytea, '{}'::bytea, 'spill-run'::bytea, sha256('spill-run'::bytea),
                 1, clock_timestamp() + interval '1 hour')
         RETURNING id::text",
    )
    .bind(&scope)
    .bind(&target.user)
    .bind(&target.approval)
    .bind(&conversation)
    .bind(&branch_id)
    .bind(&message_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let artifact_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.artifacts (id, scope_id, scope_kind, owner_user_id)
         VALUES (gen_random_uuid(), $1::uuid, 'personal', $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&target.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.storage_accounts (scope_id) VALUES ($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();

    // Session B simulates a fenced worker tool spill holding the run row FOR NO KEY UPDATE.
    let mut worker = connect(&db.0, OWNER).await;
    let worker_pid = backend_pid(&mut worker).await;
    worker.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT FROM openmettle.runs WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&run_id)
        .execute(&mut worker)
        .await
        .unwrap();

    // Session A runs store::disable_user(target): locks users(target) FOR NO KEY UPDATE, updates
    // users, then waits on runs(run_id) inside cancel_user_runs.
    let mut api_conn = connect(&db.0, API).await;
    let disabler = tokio::spawn({
        let (admin, target) = (admin.clone(), target.clone());
        async move { store::disable_user(&mut api_conn, &ctx(&admin, "dis-spill"), &target.user).await }
    });
    wait_for_blocked_peer(&db, worker_pid).await;

    // While disable_user holds users(target) FOR NO KEY UPDATE and waits on runs(run_id), the
    // worker inserts storage_reservations referencing users(target) (FOR KEY SHARE): must succeed
    // immediately with no 40P01 deadlock.
    sqlx::query(
        "INSERT INTO openmettle.storage_reservations
             (scope_id, actor_user_id, idempotency_key, artifact_id, max_bytes, run_id,
              request_identity, request_digest, lease_expires_at)
         VALUES ($1::uuid, $2::uuid, 'spill-res', $3::uuid, 64, $4::uuid,
                 'spill-res'::bytea, sha256('spill-res'::bytea),
                 clock_timestamp() + interval '5 minutes')",
    )
    .bind(&scope)
    .bind(&target.user)
    .bind(&artifact_id)
    .bind(&run_id)
    .execute(&mut worker)
    .await
    .expect(
        "FOR NO KEY UPDATE on users must admit storage_reservations FOR KEY SHARE without deadlock",
    );
    worker.execute("COMMIT").await.unwrap();

    applied(disabler.await.unwrap());
    let run_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(run_state, "cancelled");
}
