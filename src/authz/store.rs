//! Primary-database hydration of the policy inputs and the transactional administration store
//! (ADR 0027 PR3). Nothing is cached: every call reads the primary, so a revocation applies to
//! the next request or worker recheck. Writes run only as `openmettle_api`, re-hydrate and
//! authorize the actor inside their own transaction and append one `authorization_audit` row.
use super::{Action, AdminChange, Decision, DenialReason, PlatformPolicy, Principal};
use crate::{membership::membership_state, runs::WriteTransaction};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use std::{collections::BTreeSet, fmt};

/// A store refusal or failure. `Display` never includes input values or database detail.
#[derive(Debug)]
pub enum StoreError {
    /// Map with [`DenialReason::status`] and [`DenialReason::code`] (ADR 0007).
    Denied(DenialReason),
    InvalidInput(&'static str),
    /// A reused request key, a duplicate name, an ineligible target or an unchanged state.
    Conflict(&'static str),
    /// The target does not exist. Only reported after the actor is authorized.
    NotFound,
    /// Discard the connection: the outcome of an in-flight statement or commit is uncertain.
    Database(sqlx::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "authorization denied: {}", reason.code()),
            Self::InvalidInput(what) => write!(f, "invalid input: {what}"),
            Self::Conflict(what) => write!(f, "conflict: {what}"),
            Self::NotFound => f.write_str("target not found"),
            Self::Database(_) => f.write_str("authorization persistence failed"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
impl From<crate::runs::Error> for StoreError {
    fn from(error: crate::runs::Error) -> Self {
        use crate::runs::Error as E;
        match error {
            E::Database(error) => Self::Database(error),
            // A concurrent ADR 0006 change won the assignment's revision; nothing was written.
            E::Conflict | E::StaleRevision => Self::Conflict("concurrent grant change"),
            E::Invalid => Self::InvalidInput("grant"),
            E::NotFound => Self::NotFound,
            _ => Self::Database(sqlx::Error::Protocol("transaction unavailable".into())),
        }
    }
}

pub(crate) fn uuid(value: &str, what: &'static str) -> Result<(), StoreError> {
    crate::runs::uuid(value).map_err(|_| StoreError::InvalidInput(what))
}

pub(crate) fn check(decision: Decision) -> Result<(), StoreError> {
    match decision {
        Decision::Allow => Ok(()),
        Decision::Deny(reason) => Err(StoreError::Denied(reason)),
    }
}

// --- hydration ---------------------------------------------------------------------------------

/// Hydrate a request principal as `openmettle_api`, including `account_admin`.
pub async fn hydrate_api_principal(
    c: &mut PgConnection,
    user_id: &str,
    approval_id: &str,
    now_ms: i64,
) -> Result<Option<Principal>, StoreError> {
    hydrate(c, user_id, approval_id, now_ms, true).await
}

/// Hydrate a run owner as `openmettle_worker`. Never reads `account_admins`, which the worker
/// cannot select and which never affects content or run access; `account_admin` is `false`.
pub async fn hydrate_worker_principal(
    c: &mut PgConnection,
    user_id: &str,
    approval_id: &str,
    now_ms: i64,
) -> Result<Option<Principal>, StoreError> {
    hydrate(c, user_id, approval_id, now_ms, false).await
}

// Approval and provider semantics match session validation (ADR 0013): the exact approval of
// one of the user's identities, active and unexpired, and a provider with the identity's
// issuer whose latest authority revision is not a retirement.
const PRINCIPAL: &str = "SELECT sc.id::text, u.disabled_at IS NULL,
       coalesce(ap.approval_active, false), coalesce(ap.provider_active, false),
       ARRAY(SELECT g.id::text FROM openmettle.local_group_memberships m
               JOIN openmettle.local_groups g ON g.id = m.group_id
              WHERE m.user_id = u.id AND m.active AND g.disabled_at IS NULL),
       ARRAY(SELECT capability FROM openmettle.user_capability_grants
              WHERE user_id = u.id AND granted),
       ARRAY(SELECT capability FROM openmettle.user_capability_denies
              WHERE user_id = u.id AND denied)
  FROM openmettle.users u
  JOIN openmettle.scopes sc ON sc.personal_user_id = u.id AND sc.kind = 'personal'
  LEFT JOIN LATERAL (
       SELECT a.active AND a.expires_ms > $3 AS approval_active,
              e.revision IS NOT NULL AND p.issuer = i.issuer AS provider_active
         FROM openmettle.local_identity_approvals a
         JOIN openmettle.user_identities i ON i.id = a.identity_id
         JOIN openmettle.login_providers p ON p.id = a.provider_id
         LEFT JOIN LATERAL (SELECT revision FROM openmettle.login_provider_revisions
                             WHERE provider_id = p.id ORDER BY epoch DESC LIMIT 1) e ON true
        WHERE a.id = $2::uuid AND i.user_id = u.id) ap ON true
 WHERE u.id = $1::uuid";

pub(super) async fn hydrate(
    c: &mut PgConnection,
    user_id: &str,
    approval_id: &str,
    now_ms: i64,
    include_account_admin: bool,
) -> Result<Option<Principal>, StoreError> {
    uuid(user_id, "user_id")?;
    uuid(approval_id, "approval_id")?;
    let Some(row) = sqlx::query(PRINCIPAL)
        .bind(user_id)
        .bind(approval_id)
        .bind(now_ms)
        .fetch_optional(&mut *c)
        .await?
    else {
        return Ok(None);
    };
    let set = |i| -> Result<BTreeSet<String>, sqlx::Error> {
        Ok(row.try_get::<Vec<String>, _>(i)?.into_iter().collect())
    };
    let account_admin = include_account_admin
        && sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM openmettle.account_admins WHERE user_id = $1::uuid AND active)",
        )
        .bind(user_id)
        .fetch_one(&mut *c)
        .await?;
    // ADR 0021: only current `present` evidence for a group selector names an OIDC group.
    let oidc_groups: Vec<String> = sqlx::query_scalar(concat!(
        "SELECT s.claim_value FROM (",
        membership_state!(),
        " WHERE a.id = $2::uuid AND u.id = $3::uuid) s
         WHERE s.state = 'present' AND s.selector_kind = 'group'"
    ))
    .bind(now_ms)
    .bind(approval_id)
    .bind(user_id)
    .fetch_all(&mut *c)
    .await?;
    Ok(Some(Principal {
        user_id: user_id.to_owned(),
        personal_scope_id: row.try_get(0)?,
        account_active: row.try_get(1)?,
        approval_active: row.try_get(2)?,
        provider_active: row.try_get(3)?,
        account_admin,
        local_groups: set(4)?,
        oidc_groups: oidc_groups.into_iter().collect(),
        granted_capabilities: set(5)?,
        denied_capabilities: set(6)?,
    }))
}

/// Current platform capability denies. Works as `openmettle_api` and `openmettle_worker`.
pub async fn load_platform_capabilities(
    c: &mut PgConnection,
) -> Result<PlatformPolicy, StoreError> {
    let denied: Vec<String> = sqlx::query_scalar(
        "SELECT capability FROM openmettle.platform_capability_denies WHERE denied",
    )
    .fetch_all(c)
    .await?;
    Ok(PlatformPolicy {
        denied_capabilities: denied.into_iter().collect(),
    })
}

// --- administration writes ---------------------------------------------------------------------

/// Who is writing, and why. `request_key` is unique per actor: a retry with the same key and
/// the same change is a replay; the same key for another change is a conflict.
#[derive(Clone, Copy, Debug)]
pub struct AuditContext<'a> {
    pub actor_user_id: &'a str,
    pub actor_approval_id: &'a str,
    pub now_ms: i64,
    /// 1 to 128 bytes.
    pub request_key: &'a str,
    /// 1 to 512 bytes, recorded in the audit row.
    pub reason: &'a str,
}

impl AuditContext<'_> {
    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        uuid(self.actor_user_id, "actor_user_id")?;
        uuid(self.actor_approval_id, "actor_approval_id")?;
        // PostgreSQL text cannot hold NUL, so it is refused here rather than by the database.
        if !crate::runs::bounded(self.request_key, 128) {
            return Err(StoreError::InvalidInput("request_key"));
        }
        if !crate::runs::bounded(self.reason, 512) {
            return Err(StoreError::InvalidInput("reason"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOutcome<T = String> {
    /// The change was applied and audited in one committed transaction.
    Applied { target_id: T },
    /// The request key already recorded this exact change; nothing was written.
    Replayed { target_id: T },
}

impl<T> WriteOutcome<T> {
    pub(super) fn map<U>(self, f: impl FnOnce(T) -> U) -> WriteOutcome<U> {
        match self {
            Self::Applied { target_id } => WriteOutcome::Applied {
                target_id: f(target_id),
            },
            Self::Replayed { target_id } => WriteOutcome::Replayed {
                target_id: f(target_id),
            },
        }
    }
}

impl WriteOutcome {
    pub fn target_id(&self) -> &str {
        match self {
            Self::Applied { target_id } | Self::Replayed { target_id } => target_id,
        }
    }
}

/// One audited change. `target_id: None` asks the store to assign a new UUID (group or project
/// creation); a replay then matches whatever target the original request recorded.
pub(super) struct Change {
    pub(super) action: &'static str,
    pub(super) target_kind: &'static str,
    pub(super) target_id: Option<String>,
    pub(super) details: Value,
}

pub(crate) const UNCHANGED: StoreError =
    StoreError::Conflict("target is already in the requested state");

/// The [`StoreError::Conflict`] of a request key that already recorded another change. The API
/// reports it as `idempotency_conflict` and every other conflict as `conflict` (ADR 0007).
pub const KEY_REUSED: &str = "request_key already recorded another change";

/// A flat local group name, at least as strict as the migration 15 `CHECK`.
pub fn valid_group_name(name: &str) -> bool {
    valid_name(name, 128)
}

/// 1 to `max` bytes, no surrounding whitespace and no control character: at least as strict as
/// the migration 15 name `CHECK`s.
pub(super) fn valid_name(name: &str, max: usize) -> bool {
    (1..=max).contains(&name.len()) && name.trim() == name && !name.chars().any(char::is_control)
}

fn capability(name: &str) -> Result<(), StoreError> {
    if super::valid_capability(name) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("capability"))
    }
}

pub(super) fn unique(error: sqlx::Error, constraint: &str, conflict: &'static str) -> StoreError {
    match &error {
        sqlx::Error::Database(e) if e.constraint() == Some(constraint) => {
            StoreError::Conflict(conflict)
        }
        _ => StoreError::Database(error),
    }
}

/// One bounded READ COMMITTED transaction, shared by the writers and the run recheck.
pub(crate) async fn begin(c: &mut PgConnection) -> Result<WriteTransaction<'_>, StoreError> {
    Ok(WriteTransaction::begin_bounded(c, false).await?)
}

/// Run `body` in one READ COMMITTED write transaction: commit on success, roll back otherwise.
/// The audit context is validated before the transaction starts.
pub(crate) async fn transact<T>(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    body: impl AsyncFnOnce(&mut WriteTransaction<'_>) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    ctx.validate()?;
    let mut tx = begin(c).await?;
    match body(&mut tx).await {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

/// The actor re-hydrated from the primary inside the write transaction; it must be active.
pub(crate) async fn acting(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
) -> Result<Principal, StoreError> {
    let actor =
        hydrate_api_principal(c, ctx.actor_user_id, ctx.actor_approval_id, ctx.now_ms).await?;
    super::require(actor.as_ref())
        .cloned()
        .map_err(StoreError::Denied)
}

/// Insert the audit row first, so a reused request key is detected before any change. `Applied`
/// carries the new (or given) target ID: apply the change next. `Replayed` means this exact
/// change is already recorded: write nothing. A different recorded change is a `Conflict`.
pub(super) async fn record(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    change: &Change,
) -> Result<WriteOutcome, StoreError> {
    let target = match &change.target_id {
        Some(id) => id.clone(),
        None => {
            sqlx::query_scalar("SELECT gen_random_uuid()::text")
                .fetch_one(&mut *c)
                .await?
        }
    };
    let details = change.details.to_string();
    let inserted = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
             (actor_user_id, action, target_kind, target_id, request_key, reason, details)
         VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb)
         ON CONFLICT (actor_user_id, request_key) DO NOTHING",
    )
    .bind(ctx.actor_user_id)
    .bind(change.action)
    .bind(change.target_kind)
    .bind(&target)
    .bind(ctx.request_key)
    .bind(ctx.reason)
    .bind(&details)
    .execute(&mut *c)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(WriteOutcome::Applied { target_id: target });
    }
    let row = sqlx::query(
        "SELECT action, target_kind, target_id, details = $3::jsonb
           FROM openmettle.authorization_audit
          WHERE actor_user_id = $1::uuid AND request_key = $2",
    )
    .bind(ctx.actor_user_id)
    .bind(ctx.request_key)
    .bind(&details)
    .fetch_one(&mut *c)
    .await?;
    let recorded: String = row.try_get(2)?;
    let same = row.try_get::<&str, _>(0)? == change.action
        && row.try_get::<&str, _>(1)? == change.target_kind
        && change.target_id.as_ref().is_none_or(|id| *id == recorded)
        && row.try_get::<bool, _>(3)?;
    if same {
        Ok(WriteOutcome::Replayed {
            target_id: recorded,
        })
    } else {
        Err(StoreError::Conflict(KEY_REUSED))
    }
}

/// The administration write protocol, in one transaction:
/// 1. account administration and user lifecycle lock `account_admin_lock` before anything else;
/// 2. the actor's user row is locked `FOR SHARE` (`FOR UPDATE` when a user disable or enable
///    targets the actor), then the actor is re-hydrated from the primary and must be an active
///    `account_admin`;
/// 3. the audit row is inserted first, so a reused request key is detected before any change;
/// 4. `apply` checks the target and changes current state, or the whole transaction rolls back.
async fn write(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    action: Action,
    change: Change,
    apply: impl AsyncFnOnce(&mut PgConnection, &Principal, &str) -> Result<(), StoreError>,
) -> Result<WriteOutcome, StoreError> {
    let self_lifecycle =
        action == Action::ManageAccounts && change.target_id.as_deref() == Some(ctx.actor_user_id);
    transact(c, ctx, async move |tx| {
        let c = tx.connection()?;
        if matches!(
            action,
            Action::ManageAccountAdmin | Action::ManageAccounts | Action::ManageFamilyPolicies
        ) {
            sqlx::query("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
                .fetch_one(&mut *c)
                .await?;
        }
        // sessions::disable_user locks only the user row: hold the actor's row so a disable in
        // flight is waited for and seen, and a later one waits for this commit. User disable and
        // enable lock their target FOR UPDATE: on their own actor they take it here, never
        // upgrading from FOR SHARE while another write by the actor waits on their audit key.
        let sql = if self_lifecycle {
            "SELECT FROM openmettle.users WHERE id = $1::uuid FOR UPDATE"
        } else {
            "SELECT FROM openmettle.users WHERE id = $1::uuid FOR SHARE"
        };
        sqlx::query(sql)
            .bind(ctx.actor_user_id)
            .execute(&mut *c)
            .await?;
        let actor = acting(c, ctx).await?;
        check(super::authorize_admin(
            &actor,
            AdminChange {
                action,
                removes_enabled_admin: false,
                enabled_account_admins: 0,
            },
        ))?;
        let outcome = record(c, ctx, &change).await?;
        if let WriteOutcome::Applied { target_id } = &outcome {
            apply(c, &actor, target_id).await?;
        }
        Ok(outcome)
    })
    .await
}

fn user_change(action: &'static str, user_id: &str) -> Result<Change, StoreError> {
    uuid(user_id, "user_id")?;
    Ok(Change {
        action,
        target_kind: "user",
        target_id: Some(user_id.to_owned()),
        details: json!({}),
    })
}

/// Enabled account administrators, counted under `account_admin_lock`.
async fn enabled_admins(c: &mut PgConnection) -> Result<u32, StoreError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.account_admins a
           JOIN openmettle.users u ON u.id = a.user_id
          WHERE a.active AND u.disabled_at IS NULL",
    )
    .fetch_one(c)
    .await?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Re-decide with the transactional count when the change removes an enabled administrator.
async fn keep_last_admin(
    c: &mut PgConnection,
    actor: &Principal,
    action: Action,
    removes_enabled_admin: bool,
) -> Result<(), StoreError> {
    if !removes_enabled_admin {
        return Ok(());
    }
    let enabled_account_admins = enabled_admins(c).await?;
    check(super::authorize_admin(
        actor,
        AdminChange {
            action,
            removes_enabled_admin,
            enabled_account_admins,
        },
    ))
}

/// Whether the user exists and is enabled, holding the row lock for the rest of the transaction.
pub(crate) async fn lock_user(
    c: &mut PgConnection,
    user_id: &str,
    exclusive: bool,
) -> Result<bool, StoreError> {
    let sql = if exclusive {
        "SELECT disabled_at IS NULL FROM openmettle.users WHERE id = $1::uuid FOR UPDATE"
    } else {
        "SELECT disabled_at IS NULL FROM openmettle.users WHERE id = $1::uuid FOR SHARE"
    };
    sqlx::query_scalar(sql)
        .bind(user_id)
        .fetch_optional(c)
        .await?
        .ok_or(StoreError::NotFound)
}

async fn is_active_admin(c: &mut PgConnection, user_id: &str) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM openmettle.account_admins WHERE user_id = $1::uuid AND active)",
    )
    .bind(user_id)
    .fetch_one(c)
    .await?)
}

/// Make an enabled user an active `account_admin`.
pub async fn grant_account_admin(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    user_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let change = user_change("account_admin.grant", user_id)?;
    write(
        c,
        ctx,
        Action::ManageAccountAdmin,
        change,
        async |c, _, user| {
            if !lock_user(c, user, false).await? {
                return Err(StoreError::Conflict("target user is disabled"));
            }
            sqlx::query_scalar::<_, i64>(
                "INSERT INTO openmettle.account_admins AS a (user_id, active, updated_by_user_id)
             VALUES ($1::uuid, true, $2::uuid)
             ON CONFLICT (user_id) DO UPDATE
                SET active = true, revision = a.revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $2::uuid
              WHERE NOT a.active
             RETURNING a.revision",
            )
            .bind(user)
            .bind(ctx.actor_user_id)
            .fetch_optional(c)
            .await?
            .ok_or(UNCHANGED)
            .map(drop)
        },
    )
    .await
}

/// Demote an `account_admin`, refusing to remove the last enabled one.
pub async fn revoke_account_admin(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    user_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let change = user_change("account_admin.revoke", user_id)?;
    write(
        c,
        ctx,
        Action::ManageAccountAdmin,
        change,
        async |c, actor, user| {
            let enabled = lock_user(c, user, false).await?;
            if !is_active_admin(c, user).await? {
                return Err(UNCHANGED);
            }
            keep_last_admin(c, actor, Action::ManageAccountAdmin, enabled).await?;
            sqlx::query(
                "UPDATE openmettle.account_admins
                SET active = false, revision = revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $2::uuid
              WHERE user_id = $1::uuid",
            )
            .bind(user)
            .bind(ctx.actor_user_id)
            .execute(c)
            .await?;
            Ok(())
        },
    )
    .await
}

/// Disable an account, refusing to disable the last enabled `account_admin`. The session
/// generation advances so re-enabling never revives an earlier session (ADR 0013). Every
/// non-terminal run the user owns is cancelled in the same transaction (ADR 0027 PR5);
/// re-enabling does not revive them.
pub async fn disable_user(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    user_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let change = user_change("user.disable", user_id)?;
    write(
        c,
        ctx,
        Action::ManageAccounts,
        change,
        async |c, actor, user| {
            if !lock_user(c, user, true).await? {
                return Err(UNCHANGED);
            }
            let admin = is_active_admin(c, user).await?;
            keep_last_admin(c, actor, Action::ManageAccounts, admin).await?;
            sqlx::query(
                "UPDATE openmettle.users
                SET disabled_at = GREATEST(created_at, clock_timestamp()),
                    session_generation = session_generation + 1
              WHERE id = $1::uuid",
            )
            .bind(user)
            .execute(&mut *c)
            .await?;
            // Last statement: run rows are locked after every other lock (see `authz::runs`).
            super::runs::cancel_user_runs(c, user).await?;
            Ok(())
        },
    )
    .await
}

/// Re-enable a disabled account. Earlier sessions stay invalid; the user signs in again.
pub async fn enable_user(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    user_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let change = user_change("user.enable", user_id)?;
    write(
        c,
        ctx,
        Action::ManageAccounts,
        change,
        async |c, _, user| {
            if lock_user(c, user, true).await? {
                return Err(UNCHANGED);
            }
            sqlx::query("UPDATE openmettle.users SET disabled_at = NULL WHERE id = $1::uuid")
                .bind(user)
                .execute(c)
                .await?;
            Ok(())
        },
    )
    .await
}

fn group_change(
    action: &'static str,
    group_id: Option<&str>,
    details: Value,
) -> Result<Change, StoreError> {
    if let Some(id) = group_id {
        uuid(id, "group_id")?;
    }
    Ok(Change {
        action,
        target_kind: "local_group",
        target_id: group_id.map(str::to_owned),
        details,
    })
}

fn group_name(name: &str) -> Result<(), StoreError> {
    if valid_group_name(name) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("group name"))
    }
}

const DUPLICATE_GROUP: &str = "a local group already has this name";

/// (name, enabled) of a group, locked for the rest of the transaction.
pub(crate) async fn lock_group(
    c: &mut PgConnection,
    group_id: &str,
    exclusive: bool,
) -> Result<(String, bool), StoreError> {
    let sql = if exclusive {
        "SELECT name, disabled_at IS NULL FROM openmettle.local_groups WHERE id = $1::uuid FOR UPDATE"
    } else {
        "SELECT name, disabled_at IS NULL FROM openmettle.local_groups WHERE id = $1::uuid FOR SHARE"
    };
    sqlx::query_as(sql)
        .bind(group_id)
        .fetch_optional(c)
        .await?
        .ok_or(StoreError::NotFound)
}

/// Create an enabled local group. The outcome carries the new group ID.
pub async fn create_local_group(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    name: &str,
) -> Result<WriteOutcome, StoreError> {
    group_name(name)?;
    let change = group_change("local_group.create", None, json!({ "name": name }))?;
    write(
        c,
        ctx,
        Action::ManageLocalGroups,
        change,
        async |c, _, group| {
            sqlx::query(
            "INSERT INTO openmettle.local_groups (id, name, created_by_user_id, updated_by_user_id)
             VALUES ($1::uuid, $2, $3::uuid, $3::uuid)",
        )
        .bind(group)
        .bind(name)
        .bind(ctx.actor_user_id)
        .execute(c)
        .await
        .map_err(|e| unique(e, "local_groups_name_key", DUPLICATE_GROUP))?;
            Ok(())
        },
    )
    .await
}

pub async fn rename_local_group(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    group_id: &str,
    name: &str,
) -> Result<WriteOutcome, StoreError> {
    group_name(name)?;
    let change = group_change(
        "local_group.rename",
        Some(group_id),
        json!({ "name": name }),
    )?;
    write(
        c,
        ctx,
        Action::ManageLocalGroups,
        change,
        async |c, _, group| {
            if lock_group(c, group, true).await?.0 == name {
                return Err(UNCHANGED);
            }
            sqlx::query(
                "UPDATE openmettle.local_groups
                SET name = $2, revision = revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $3::uuid
              WHERE id = $1::uuid",
            )
            .bind(group)
            .bind(name)
            .bind(ctx.actor_user_id)
            .execute(c)
            .await
            .map_err(|e| unique(e, "local_groups_name_key", DUPLICATE_GROUP))?;
            Ok(())
        },
    )
    .await
}

/// Disable or re-enable a group. A disabled group grants nothing but keeps its memberships.
async fn set_group_enabled(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    group_id: &str,
    enabled: bool,
) -> Result<WriteOutcome, StoreError> {
    let action = if enabled {
        "local_group.enable"
    } else {
        "local_group.disable"
    };
    let change = group_change(action, Some(group_id), json!({}))?;
    write(
        c,
        ctx,
        Action::ManageLocalGroups,
        change,
        async |c, _, group| {
            if lock_group(c, group, true).await?.1 == enabled {
                return Err(UNCHANGED);
            }
            sqlx::query(
                "UPDATE openmettle.local_groups
                SET disabled_at = CASE WHEN $2 THEN NULL
                                       ELSE GREATEST(created_at, clock_timestamp()) END,
                    revision = revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $3::uuid
              WHERE id = $1::uuid",
            )
            .bind(group)
            .bind(enabled)
            .bind(ctx.actor_user_id)
            .execute(c)
            .await?;
            Ok(())
        },
    )
    .await
}

pub async fn disable_local_group(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    group_id: &str,
) -> Result<WriteOutcome, StoreError> {
    set_group_enabled(c, ctx, group_id, false).await
}

pub async fn enable_local_group(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    group_id: &str,
) -> Result<WriteOutcome, StoreError> {
    set_group_enabled(c, ctx, group_id, true).await
}

/// Add an enabled user to an enabled group.
pub async fn add_local_group_member(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    group_id: &str,
    user_id: &str,
) -> Result<WriteOutcome, StoreError> {
    uuid(user_id, "user_id")?;
    let change = group_change(
        "local_group.member_add",
        Some(group_id),
        json!({ "user_id": user_id }),
    )?;
    write(
        c,
        ctx,
        Action::ManageLocalGroups,
        change,
        async |c, _, group| {
            if !lock_group(c, group, false).await?.1 {
                return Err(StoreError::Conflict("local group is disabled"));
            }
            if !lock_user(c, user_id, false).await? {
                return Err(StoreError::Conflict("target user is disabled"));
            }
            sqlx::query_scalar::<_, i64>(
                "INSERT INTO openmettle.local_group_memberships AS m
                 (group_id, user_id, active, updated_by_user_id)
             VALUES ($1::uuid, $2::uuid, true, $3::uuid)
             ON CONFLICT (group_id, user_id) DO UPDATE
                SET active = true, revision = m.revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $3::uuid
              WHERE NOT m.active
             RETURNING m.revision",
            )
            .bind(group)
            .bind(user_id)
            .bind(ctx.actor_user_id)
            .fetch_optional(c)
            .await?
            .ok_or(UNCHANGED)
            .map(drop)
        },
    )
    .await
}

/// Remove a member from a group, including a disabled user or from a disabled group.
pub async fn remove_local_group_member(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    group_id: &str,
    user_id: &str,
) -> Result<WriteOutcome, StoreError> {
    uuid(user_id, "user_id")?;
    let change = group_change(
        "local_group.member_remove",
        Some(group_id),
        json!({ "user_id": user_id }),
    )?;
    write(
        c,
        ctx,
        Action::ManageLocalGroups,
        change,
        async |c, _, group| {
            lock_group(c, group, false).await?;
            let changed = sqlx::query(
                "UPDATE openmettle.local_group_memberships
                SET active = false, revision = revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $3::uuid
              WHERE group_id = $1::uuid AND user_id = $2::uuid AND active",
            )
            .bind(group)
            .bind(user_id)
            .bind(ctx.actor_user_id)
            .execute(c)
            .await?
            .rows_affected();
            if changed == 0 {
                return Err(UNCHANGED);
            }
            Ok(())
        },
    )
    .await
}

/// The three capability tables share one current-state shape: a boolean flag whose absent row
/// means `false`. `current` binds `$1` capability and `$2` user (NULL for the platform);
/// `upsert` binds `$1` capability, `$2` flag, `$3` actor and `$4` user.
struct FlagTable {
    current: &'static str,
    upsert: &'static str,
}

const PLATFORM_DENIES: FlagTable = FlagTable {
    current: "SELECT denied FROM openmettle.platform_capability_denies
               WHERE capability = $1 AND $2::uuid IS NULL",
    upsert: "INSERT INTO openmettle.platform_capability_denies AS t
                 (capability, denied, updated_by_user_id)
             SELECT $1, $2, $3::uuid WHERE $4::uuid IS NULL
             ON CONFLICT (capability) DO UPDATE
                SET denied = $2, revision = t.revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $3::uuid
              WHERE t.denied <> $2
             RETURNING t.revision",
};
const USER_DENIES: FlagTable = FlagTable {
    current: "SELECT denied FROM openmettle.user_capability_denies
               WHERE capability = $1 AND user_id = $2::uuid",
    upsert: "INSERT INTO openmettle.user_capability_denies AS t
                 (user_id, capability, denied, updated_by_user_id)
             VALUES ($4::uuid, $1, $2, $3::uuid)
             ON CONFLICT (user_id, capability) DO UPDATE
                SET denied = $2, revision = t.revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $3::uuid
              WHERE t.denied <> $2
             RETURNING t.revision",
};
const USER_GRANTS: FlagTable = FlagTable {
    current: "SELECT granted FROM openmettle.user_capability_grants
               WHERE capability = $1 AND user_id = $2::uuid",
    upsert: "INSERT INTO openmettle.user_capability_grants AS t
                 (user_id, capability, granted, updated_by_user_id)
             VALUES ($4::uuid, $1, $2, $3::uuid)
             ON CONFLICT (user_id, capability) DO UPDATE
                SET granted = $2, revision = t.revision + 1, updated_at = clock_timestamp(),
                    updated_by_user_id = $3::uuid
              WHERE t.granted <> $2
             RETURNING t.revision",
};

async fn set_flag(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    table: FlagTable,
    action: &'static str,
    name: &str,
    user_id: Option<&str>,
    value: bool,
) -> Result<WriteOutcome, StoreError> {
    capability(name)?;
    if let Some(user) = user_id {
        uuid(user, "user_id")?;
    }
    let change = Change {
        action,
        target_kind: "capability",
        target_id: Some(name.to_owned()),
        details: user_id.map_or_else(|| json!({}), |user| json!({ "user_id": user })),
    };
    write(
        c,
        ctx,
        Action::ManageUserCapabilityDenies,
        change,
        async |c, _, _| {
            if let Some(user) = user_id {
                lock_user(c, user, false).await?;
            }
            let current: Option<bool> = sqlx::query_scalar(table.current)
                .bind(name)
                .bind(user_id)
                .fetch_optional(&mut *c)
                .await?;
            if current.unwrap_or(false) == value {
                return Err(UNCHANGED);
            }
            sqlx::query_scalar::<_, i64>(table.upsert)
                .bind(name)
                .bind(value)
                .bind(ctx.actor_user_id)
                .bind(user_id)
                .fetch_optional(c)
                .await?
                .ok_or(UNCHANGED)
                .map(drop)
        },
    )
    .await
}

/// Deny (`true`) or allow (`false`) a capability for the whole installation.
pub async fn set_platform_capability_deny(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    name: &str,
    denied: bool,
) -> Result<WriteOutcome, StoreError> {
    let action = if denied {
        "capability.platform_deny"
    } else {
        "capability.platform_allow"
    };
    set_flag(c, ctx, PLATFORM_DENIES, action, name, None, denied).await
}

/// Deny (`true`) or allow (`false`) a capability for one user.
pub async fn set_user_capability_deny(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    user_id: &str,
    name: &str,
    denied: bool,
) -> Result<WriteOutcome, StoreError> {
    let action = if denied {
        "capability.user_deny"
    } else {
        "capability.user_allow"
    };
    set_flag(c, ctx, USER_DENIES, action, name, Some(user_id), denied).await
}

/// Assign (`true`) or withdraw (`false`) an opt-in capability for one user.
pub async fn set_user_capability_grant(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    user_id: &str,
    name: &str,
    granted: bool,
) -> Result<WriteOutcome, StoreError> {
    let action = if granted {
        "capability.user_grant"
    } else {
        "capability.user_revoke"
    };
    set_flag(c, ctx, USER_GRANTS, action, name, Some(user_id), granted).await
}

// --- family policy administration (ADR 0044, increment 4) --------------------------------------

async fn write_family_policy(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    grantee: &super::gateway::family::FamilyGrantee,
    action: &'static str,
    details: Value,
    apply: impl AsyncFnOnce(&mut PgConnection, &str) -> Result<(), StoreError>,
) -> Result<WriteOutcome, StoreError> {
    grantee.validate()?;
    transact(c, ctx, async move |tx| {
        let c = tx.connection()?;
        sqlx::query("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
            .fetch_one(&mut *c)
            .await?;
        // Serialize with sessions::disable_user so a concurrently disabled admin cannot commit.
        sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR SHARE")
            .bind(ctx.actor_user_id)
            .execute(&mut *c)
            .await?;
        let actor = acting(c, ctx).await?;
        check(super::authorize_admin(
            &actor,
            AdminChange {
                action: Action::ManageFamilyPolicies,
                removes_enabled_admin: false,
                enabled_account_admins: 0,
            },
        ))?;
        let existing = super::gateway::family::existing_policy_id(c, grantee).await?;
        let change = Change {
            action,
            target_kind: "family_policy",
            target_id: existing,
            details,
        };
        let outcome = record(c, ctx, &change).await?;
        if let WriteOutcome::Applied { target_id } = &outcome {
            apply(c, target_id).await?;
        }
        Ok(outcome)
    })
    .await
}

/// Create or update a family schedule/override policy for a user, local group or OIDC group.
/// Serialized under `account_admin_lock` and audited as `actor_kind = 'user'`.
pub async fn set_family_policy(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    grantee: &super::gateway::family::FamilyGrantee,
    input: &super::gateway::family::FamilyPolicyInput,
) -> Result<WriteOutcome, StoreError> {
    input.validate(grantee)?;
    let details = super::gateway::family::set_policy_details(grantee, input);
    write_family_policy(
        c,
        ctx,
        grantee,
        "family_policy.set",
        details,
        async |c, id| {
            super::gateway::family::apply_set_policy(c, id, grantee, input, Some(ctx.actor_user_id))
                .await
        },
    )
    .await
}

/// Deactivate (`active = false`) an active family policy row without deleting history.
pub async fn clear_family_policy(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    grantee: &super::gateway::family::FamilyGrantee,
) -> Result<WriteOutcome, StoreError> {
    let details = super::gateway::family::clear_policy_details(grantee);
    write_family_policy(
        c,
        ctx,
        grantee,
        "family_policy.clear",
        details,
        async |c, id| {
            super::gateway::family::apply_clear_policy(c, id, grantee, Some(ctx.actor_user_id))
                .await
        },
    )
    .await
}

/// Activate (`true`) or deactivate (`false`) a `study_allow` or `disabled` model rule on an
/// existing family policy row.
pub async fn set_family_policy_model(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    grantee: &super::gateway::family::FamilyGrantee,
    kind: super::gateway::family::FamilyPolicyRuleKind,
    model: &str,
    active: bool,
) -> Result<WriteOutcome, StoreError> {
    if !super::gateway::family::valid_model(model) {
        return Err(StoreError::InvalidInput("model"));
    }
    let action = kind.audit_action(active);
    let details = super::gateway::family::set_model_details(grantee, kind, model, active);
    write_family_policy(c, ctx, grantee, action, details, async |c, id| {
        super::gateway::family::apply_set_model(
            c,
            id,
            grantee,
            kind,
            model,
            active,
            Some(ctx.actor_user_id),
        )
        .await
    })
    .await
}

/// Read the current-state family policy record and active model rules for `grantee`.
pub async fn load_family_policy(
    c: &mut PgConnection,
    grantee: &super::gateway::family::FamilyGrantee,
) -> Result<Option<super::gateway::family::FamilyPolicyRecord>, StoreError> {
    super::gateway::family::load_family_policy(c, grantee).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(request_key: &'a str, reason: &'a str) -> AuditContext<'a> {
        AuditContext {
            actor_user_id: "00000000-0000-0000-0000-000000000001",
            actor_approval_id: "00000000-0000-0000-0000-000000000002",
            now_ms: 1,
            request_key,
            reason,
        }
    }

    #[test]
    fn group_names_follow_the_flat_name_rule() {
        for ok in ["a", "Team Ä", &"x".repeat(128), "inner  space", "名前"] {
            assert!(valid_group_name(ok), "{ok:?}");
        }
        let long = "é".repeat(65); // 130 bytes
        for bad in [
            "",
            " lead",
            "trail ",
            "\ttab",
            "new\nline",
            "nul\0",
            "del\u{7f}",
            "c1\u{85}x",
            "nbsp\u{a0}",
            &"x".repeat(129),
            &long,
        ] {
            assert!(!valid_group_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn audit_context_bounds_and_identifiers() {
        assert!(ctx("k", "r").validate().is_ok());
        assert!(ctx(&"k".repeat(128), &"r".repeat(512)).validate().is_ok());
        for (key, reason, field) in [
            ("", "r", "request_key"),
            (&"k".repeat(129) as &str, "r", "request_key"),
            ("k", "", "reason"),
            ("k", &"r".repeat(513) as &str, "reason"),
            ("k\0", "r", "request_key"),
            ("k", "r\0", "reason"),
        ] {
            assert!(matches!(
                ctx(key, reason).validate(),
                Err(StoreError::InvalidInput(f)) if f == field
            ));
        }
        for actor in ["", "00000000-0000-0000-0000-00000000000A", "not-a-uuid"] {
            let bad = AuditContext {
                actor_user_id: actor,
                ..ctx("k", "r")
            };
            assert!(matches!(
                bad.validate(),
                Err(StoreError::InvalidInput("actor_user_id"))
            ));
        }
    }

    #[test]
    fn capability_names_reuse_the_policy_rule() {
        assert!(capability("runs.use_yolo").is_ok());
        assert!(capability(&"a".repeat(128)).is_ok());
        for bad in ["", "Web_search", "web search", "ü", &"a".repeat(129)] {
            assert!(matches!(
                capability(bad),
                Err(StoreError::InvalidInput("capability"))
            ));
        }
    }

    #[test]
    fn errors_map_to_adr_0007_and_never_display_detail() {
        let denied = StoreError::Denied(DenialReason::InactivePrincipal);
        assert_eq!(denied.to_string(), "authorization denied: unauthenticated");
        let db = StoreError::Database(sqlx::Error::Protocol("secret-detail".into()));
        assert_eq!(db.to_string(), "authorization persistence failed");
        assert_eq!(
            UNCHANGED.to_string(),
            "conflict: target is already in the requested state"
        );
    }
}
