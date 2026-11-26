//! Project settings, membership and resource shares (ADR 0027 PR4a), and the project lifecycle
//! rules the `/v1` routes enforce (PR4b). Hydration reads the primary on every call, never
//! caches and works as `openmettle_api` and `openmettle_worker`. It never reads
//! `account_admins`. Writers run only as `openmettle_api` and follow the PR3 protocol in one
//! READ COMMITTED transaction: lock, re-hydrate the actor, authorize with `src/authz.rs`, insert
//! or replay the `authorization_audit` row, then apply. A change that would not alter current
//! state returns `Conflict` and leaves no audit row.
//!
//! Lifecycle: a deleted project is concealed from every read and write except the exact replay
//! of the delete that recorded it. An archived project stays readable, and its revocations,
//! restore and delete stay available, but settings, role grants and new shares are refused
//! with [`ARCHIVED`] once the caller is authorized.
use super::{
    Action, Decision, DenialReason, Grant, GrantPermission, GrantVocabulary, Grantee, MemberChange,
    Origin, PROJECT_ROLE, Principal, Project, ProjectRole, RESOURCE_GRANT, Resource,
    ResourceAccess, ResourceKind, Scope, ShareRecipient,
    store::{
        self, AuditContext, Change, StoreError, UNCHANGED, UserLock, WriteOutcome, check,
        lock_actor_approval, lock_actor_authority, lock_actor_authority_with, post_lock_acting,
        record, transact, uuid,
    },
};
use crate::{
    grants::{self, Assignment, ChangeInput, Target},
    membership::{Observation, membership_state},
    runs::{WriteTransaction, bounded, digest, identity},
};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};

const ROLE_KEYS: [&str; 3] = ["viewer", "editor", "owner"];
const ACCESS_KEYS: [&str; 2] = ["read", "write"];
const LEGACY_DEFAULTS: [&str; 4] = ["folder_id", "folder_ids", "collection_id", "collection_ids"];

/// The vocabulary key of a project role, which is also its API wire value.
pub fn role_key(role: ProjectRole) -> &'static str {
    ROLE_KEYS[role as usize]
}

/// The vocabulary key of a resource access, which is also its API wire value.
pub fn access_key(access: ResourceAccess) -> &'static str {
    ACCESS_KEYS[access as usize]
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const CONCEALED: StoreError = StoreError::Denied(DenialReason::NotFound);

/// Settings, role grants and new shares in an archived project, refused after authorization.
pub const ARCHIVED: StoreError = StoreError::Conflict("project is archived");

/// The audited action whose exact replay a deleted project still answers.
const DELETE: &str = "project.delete";

// --- settings ----------------------------------------------------------------------------------

/// Requested project name, instructions and defaults, at least as strict as migration 15.
#[derive(Clone, Copy, Debug)]
pub struct ProjectSettingsInput<'a> {
    /// 1 to 256 bytes, no surrounding whitespace or control character.
    pub name: &'a str,
    /// At most 32 KiB, no NUL.
    pub instructions: &'a str,
    /// A JSON object of at most 16 KiB without top-level `folder_id`, `folder_ids`,
    /// `collection_id` or `collection_ids`.
    pub defaults: &'a Value,
}

fn contains_nul(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains('\0'),
        Value::Array(items) => items.iter().any(contains_nul),
        Value::Object(map) => map.iter().any(|(k, v)| k.contains('\0') || contains_nul(v)),
        _ => false,
    }
}

impl ProjectSettingsInput<'_> {
    pub fn validate(&self) -> Result<(), StoreError> {
        if !store::valid_name(self.name, 256) {
            return Err(StoreError::InvalidInput("name"));
        }
        if self.instructions.len() > 32768 || self.instructions.contains('\0') {
            return Err(StoreError::InvalidInput("instructions"));
        }
        let Some(object) = self.defaults.as_object() else {
            return Err(StoreError::InvalidInput("defaults"));
        };
        // The compact form is never longer than PostgreSQL's jsonb text, so this is a necessary
        // bound; the CHECK decides the exact one. jsonb refuses embedded NUL characters outright.
        let text = self.defaults.to_string();
        if LEGACY_DEFAULTS.iter().any(|key| object.contains_key(*key))
            || text.len() > 16384
            || contains_nul(self.defaults)
        {
            return Err(StoreError::InvalidInput("defaults"));
        }
        Ok(())
    }

    /// Audit details hold a digest of the request, never the project content itself.
    fn details(&self) -> Value {
        let defaults = self.defaults.to_string();
        let request = identity(
            b"openmettle/project-settings/1\0",
            &[
                self.name.as_bytes(),
                self.instructions.as_bytes(),
                defaults.as_bytes(),
            ],
        );
        json!({ "settings_digest": hex(&digest(&request)) })
    }
}

/// Current project settings. A project without a row (every pre-15 project) has an empty name,
/// empty instructions, `{}` defaults and revision 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectSettings {
    pub project_id: String,
    pub scope_id: String,
    pub name: String,
    pub instructions: String,
    pub defaults: Value,
    pub revision: i64,
    pub archived: bool,
    pub deleted: bool,
}

/// Settings of an existing project, or `None`. `openmettle_api` only: the worker never reads
/// project settings. This is a read, not an authorization decision.
pub async fn load_project_settings(
    c: &mut PgConnection,
    project_id: &str,
) -> Result<Option<ProjectSettings>, StoreError> {
    uuid(project_id, "project_id")?;
    let Some(row) = sqlx::query(
        "SELECT p.scope_id::text, coalesce(s.name, ''), coalesce(s.instructions, ''),
                coalesce(s.defaults, '{}'::jsonb)::text, coalesce(s.revision, 0),
                s.archived_at IS NOT NULL, s.deleted_at IS NOT NULL
           FROM openmettle.projects p
           LEFT JOIN openmettle.project_settings s ON s.project_id = p.id
          WHERE p.id = $1::uuid",
    )
    .bind(project_id)
    .fetch_optional(c)
    .await?
    else {
        return Ok(None);
    };
    let defaults: String = row.try_get(3)?;
    Ok(Some(ProjectSettings {
        project_id: project_id.to_owned(),
        scope_id: row.try_get(0)?,
        name: row.try_get(1)?,
        instructions: row.try_get(2)?,
        defaults: serde_json::from_str(&defaults)
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(e.into())))?,
        revision: row.try_get(4)?,
        archived: row.try_get(5)?,
        deleted: row.try_get(6)?,
    }))
}

// --- hydration ---------------------------------------------------------------------------------

/// Every assignment on one target whose vocabulary parses, with its recorded head and, for a
/// mapped origin, its ADR 0021 evidence at `$1`. Rows naming a disabled user or a disabled local
/// group are omitted, so they never satisfy a membership or last-owner check.
async fn grants_on(
    c: &mut PgConnection,
    scope_id: &str,
    target_kind: &str,
    target_id: &str,
    now_ms: i64,
) -> Result<Vec<Grant<GrantPermission>>, StoreError> {
    let rows = sqlx::query(concat!(
        "SELECT ga.grantee_kind, coalesce(ga.grantee_user_id::text,
                    ga.grantee_local_group_id::text, ga.grantee_oidc_group_id),
                ga.assignment_format, ga.assignment_version, ga.assignment_key,
                ga.source_kind = 'direct', coalesce(gh.decision = 'grant', false), evidence.state
           FROM openmettle.grant_assignments ga
           LEFT JOIN openmettle.grant_changes gh
             ON gh.assignment_id = ga.id AND gh.revision = ga.last_revision
           LEFT JOIN openmettle.users gu ON gu.id = ga.grantee_user_id
           LEFT JOIN openmettle.local_groups gg ON gg.id = ga.grantee_local_group_id
           LEFT JOIN LATERAL (SELECT s.state FROM (",
        membership_state!(),
        " WHERE g.id = ga.id) s) evidence ON ga.source_kind = 'mapped'
          WHERE ga.scope_id = $2::uuid AND ga.target_kind = $3 AND ga.target_id = $4::uuid
            AND gu.disabled_at IS NULL AND gg.disabled_at IS NULL
          ORDER BY ga.id"
    ))
    .bind(now_ms)
    .bind(scope_id)
    .bind(target_kind)
    .bind(target_id)
    .fetch_all(c)
    .await?;
    let mut grants = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(permission) =
            GrantVocabulary::parse(row.try_get(2)?, row.try_get(3)?, row.try_get(4)?)
        else {
            continue;
        };
        let id: Option<String> = row.try_get(1)?;
        let grantee = match (row.try_get::<&str, _>(0)?, id) {
            ("user", Some(id)) => Grantee::User(id),
            ("local_group", Some(id)) => Grantee::LocalGroup(id),
            ("oidc_group", Some(id)) => Grantee::OidcGroup(id),
            ("project", None) => Grantee::Project,
            _ => continue,
        };
        let origin = if row.try_get(5)? {
            Origin::Direct
        } else {
            Origin::Mapped(Observation::parse(row.try_get(7)?))
        };
        grants.push(Grant {
            grantee,
            permission,
            origin,
            recorded_active: row.try_get(6)?,
        });
    }
    Ok(grants)
}

/// Keep the grants whose permission applies to this target kind; the others are `WrongTarget`.
fn narrow<P, E>(
    grants: Vec<Grant<GrantPermission>>,
    applies: impl Fn(GrantPermission) -> Result<P, E>,
) -> Vec<Grant<P>> {
    grants
        .into_iter()
        .filter_map(|g| {
            Some(Grant {
                permission: applies(g.permission).ok()?,
                grantee: g.grantee,
                origin: g.origin,
                recorded_active: g.recorded_active,
            })
        })
        .collect()
}

async fn project_in(
    c: &mut PgConnection,
    project_id: &str,
    scope_id: &str,
    now_ms: i64,
) -> Result<Project, StoreError> {
    let grants = grants_on(c, scope_id, "project", project_id, now_ms).await?;
    Ok(Project {
        id: project_id.to_owned(),
        grants: narrow(grants, GrantPermission::project_role),
    })
}

/// The project's current grants, or `None` if it does not exist. Lifecycle (archive, delete) is
/// a settings attribute that the API reads with [`load_project_settings`].
pub async fn hydrate_project(
    c: &mut PgConnection,
    project_id: &str,
    now_ms: i64,
) -> Result<Option<Project>, StoreError> {
    uuid(project_id, "project_id")?;
    let scope: Option<String> =
        sqlx::query_scalar("SELECT scope_id::text FROM openmettle.projects WHERE id = $1::uuid")
            .bind(project_id)
            .fetch_optional(&mut *c)
            .await?;
    match scope {
        Some(scope) => project_in(c, project_id, &scope, now_ms).await.map(Some),
        None => Ok(None),
    }
}

pub(crate) fn resource_kind(kind: ResourceKind) -> Result<&'static str, StoreError> {
    match kind {
        ResourceKind::Conversation => Ok("conversation"),
        ResourceKind::Artifact => Ok("artifact"),
        _ => Err(StoreError::InvalidInput("resource kind")),
    }
}

/// Where a conversation or artifact lives, without its grants.
#[derive(Clone)]
struct Located {
    scope_id: String,
    creator_user_id: String,
    personal_owner: Option<String>,
    project_id: Option<String>,
    /// Creation time in Unix microseconds.
    created_us: i64,
    /// An artifact's last revision; `None` for a conversation.
    last_revision: Option<i64>,
}

async fn locate(
    c: &mut PgConnection,
    kind: ResourceKind,
    resource_id: &str,
) -> Result<Option<Located>, StoreError> {
    let sql = match resource_kind(kind)? {
        "conversation" => {
            "SELECT r.scope_id::text, r.owner_user_id::text, s.personal_user_id::text,
                    s.project_id::text, (extract(epoch FROM r.created_at) * 1000000)::bigint,
                    NULL::bigint
               FROM openmettle.conversations r JOIN openmettle.scopes s ON s.id = r.scope_id
              WHERE r.id = $1::uuid"
        }
        _ => {
            "SELECT r.scope_id::text, r.owner_user_id::text, s.personal_user_id::text,
                    s.project_id::text, (extract(epoch FROM r.created_at) * 1000000)::bigint,
                    r.last_revision
               FROM openmettle.artifacts r JOIN openmettle.scopes s ON s.id = r.scope_id
              WHERE r.id = $1::uuid"
        }
    };
    let row = sqlx::query(sql).bind(resource_id).fetch_optional(c).await?;
    row.map(|row| {
        Ok(Located {
            scope_id: row.try_get(0)?,
            creator_user_id: row.try_get(1)?,
            personal_owner: row.try_get(2)?,
            project_id: row.try_get(3)?,
            created_us: row.try_get(4)?,
            last_revision: row.try_get(5)?,
        })
    })
    .transpose()
}

async fn hydrate_located(
    c: &mut PgConnection,
    kind: ResourceKind,
    resource_id: &str,
    located: Located,
    now_ms: i64,
) -> Result<Resource, StoreError> {
    let scope = match (located.personal_owner, located.project_id) {
        (Some(owner_user_id), _) => Scope::Personal {
            scope_id: located.scope_id.clone(),
            owner_user_id,
        },
        (None, Some(project)) => {
            Scope::Project(project_in(c, &project, &located.scope_id, now_ms).await?)
        }
        (None, None) => return Err(StoreError::NotFound),
    };
    let shares = grants_on(
        c,
        &located.scope_id,
        resource_kind(kind)?,
        resource_id,
        now_ms,
    )
    .await?;
    Ok(Resource {
        kind,
        id: resource_id.to_owned(),
        creator_user_id: located.creator_user_id,
        scope,
        shares: narrow(shares, GrantPermission::resource_access),
    })
}

/// A conversation or artifact with its scope (a project hydrated as in [`hydrate_project`]) and
/// its parsed shares, or `None` if it does not exist. Other kinds are refused as input.
pub async fn hydrate_resource(
    c: &mut PgConnection,
    kind: ResourceKind,
    resource_id: &str,
    now_ms: i64,
) -> Result<Option<Resource>, StoreError> {
    resource_kind(kind)?;
    uuid(resource_id, "resource_id")?;
    match locate(c, kind, resource_id).await? {
        Some(located) => hydrate_located(c, kind, resource_id, located, now_ms)
            .await
            .map(Some),
        None => Ok(None),
    }
}

// --- shared write steps ------------------------------------------------------------------------

/// A locked project row: its scope and its lifecycle as read under the lock.
struct Locked {
    scope: String,
    archived: bool,
    deleted: bool,
}

/// Lock the project row FOR NO KEY UPDATE through its inert guard column (migration 16).
/// Membership, share, settings and lifecycle changes on one project serialize here while
/// admitting concurrent foreign-key `FOR KEY SHARE` locks. Lifecycle is read by a second
/// statement, whose READ COMMITTED snapshot is taken after the lock is granted, so a change
/// committed by the writer this one waited for is seen. Returns `None` when the project is
/// missing so callers can verify the actor is active before concealing it.
async fn lock_project(
    c: &mut PgConnection,
    project_id: &str,
) -> Result<Option<Locked>, StoreError> {
    let scope: Option<String> = sqlx::query_scalar(
        "SELECT scope_id::text FROM openmettle.projects WHERE id = $1::uuid FOR NO KEY UPDATE",
    )
    .bind(project_id)
    .fetch_optional(&mut *c)
    .await?;
    let Some(scope) = scope else {
        return Ok(None);
    };
    let (archived, deleted): (bool, bool) = sqlx::query_as(
        "SELECT coalesce(bool_or(archived_at IS NOT NULL), false),
                coalesce(bool_or(deleted_at IS NOT NULL), false)
           FROM openmettle.project_settings WHERE project_id = $1::uuid",
    )
    .bind(project_id)
    .fetch_one(c)
    .await?;
    Ok(Some(Locked {
        scope,
        archived,
        deleted,
    }))
}

fn grantee_input(grantee: &Grantee) -> Result<(), StoreError> {
    match grantee {
        Grantee::User(id) | Grantee::LocalGroup(id) => uuid(id, "grantee"),
        Grantee::OidcGroup(id) if !bounded(id, 1024) || id.chars().any(char::is_control) => {
            Err(StoreError::InvalidInput("grantee"))
        }
        _ => Ok(()),
    }
}

/// Audit details: the grantee's kind and identifier and the requested role or access.
fn grantee_details(grantee: &Grantee, field: &str, value: Option<&str>) -> Value {
    let (kind, user, local_group, oidc_group) = grants::Grantee::from(grantee).columns();
    let mut details = json!({ "grantee_kind": kind });
    if let Some(id) = user.or(local_group).or(oidc_group) {
        details["grantee_id"] = id.into();
    }
    if let Some(value) = value {
        details[field] = value.into();
    }
    details
}

/// A grant change key unique to this audited request and assignment key, within 128 bytes.
fn grant_key(ctx: &AuditContext<'_>, format: &str, key: &str) -> String {
    let request = identity(
        b"openmettle/authz-grant/1\0",
        &[
            ctx.request_key.as_bytes(),
            format.as_bytes(),
            key.as_bytes(),
        ],
    );
    format!("authz/{}", hex(&digest(&request)))
}

/// A direct version-1 assignment of `grantee` on `target`; `set_direct` fills in each key.
fn direct<'a>(
    scope: &'a str,
    target: Target<'a>,
    grantee: &'a Grantee,
    format: &'a str,
) -> Assignment<'a> {
    Assignment {
        scope,
        target,
        grantee: grantee.into(),
        format,
        version: 1,
        key: "",
        mapping_rule: None,
    }
}

/// Make `want` the only active key of the direct assignment among `keys`, revoking every
/// superseded key; `None` revokes all of them. No change is [`UNCHANGED`].
async fn set_direct(
    tx: &mut WriteTransaction<'_>,
    ctx: &AuditContext<'_>,
    assignment: Assignment<'_>,
    keys: &[&str],
    want: Option<&str>,
) -> Result<(), StoreError> {
    let mut changed = false;
    for key in keys {
        let assignment = Assignment { key, ..assignment };
        let current = grants::find_assignment(tx.connection()?, &assignment).await?;
        let active = current.as_ref().is_some_and(|s| s.recorded_active);
        if active == (want == Some(*key)) {
            continue;
        }
        grants::change_grant(
            tx,
            &ChangeInput {
                assignment,
                actor: ctx.actor_user_id,
                key: &grant_key(ctx, assignment.format, key),
                expected_revision: current.as_ref().map_or(0, |s| s.revision),
                mapping_revision: None,
                decision: if active {
                    grants::Decision::Revoke(current.as_ref().and_then(|s| s.cycle.as_deref()))
                } else {
                    grants::Decision::Grant
                },
            },
        )
        .await?;
        changed = true;
    }
    if changed { Ok(()) } else { Err(UNCHANGED) }
}

/// Settings writes map a migration 15 `CHECK` or jsonb refusal to invalid input.
fn settings_error(error: sqlx::Error) -> StoreError {
    match &error {
        sqlx::Error::Database(e) if matches!(e.code().as_deref(), Some("23514" | "22P05")) => {
            StoreError::InvalidInput("project settings")
        }
        _ => StoreError::Database(error),
    }
}

// --- project writes ----------------------------------------------------------------------------

/// Create a project owned by the actor: its scope, settings and a direct `Owner` grant. The
/// outcome carries the new project ID. Any active principal may create a project.
pub async fn create_project(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    settings: &ProjectSettingsInput<'_>,
) -> Result<WriteOutcome, StoreError> {
    create_project_checked(c, ctx, settings, async |_, _| Ok(())).await
}

pub(crate) async fn create_project_checked(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    settings: &ProjectSettingsInput<'_>,
    check_defaults: impl AsyncFnOnce(&mut PgConnection, &Principal) -> Result<(), StoreError>,
) -> Result<WriteOutcome, StoreError> {
    settings.validate()?;
    let change = Change {
        action: "project.create",
        target_kind: "project",
        target_id: None,
        details: settings.details(),
    };
    transact(c, ctx, async |tx| {
        let c = tx.connection()?;
        lock_actor_authority(c, ctx).await?;
        let (_, post_lock_ctx) = post_lock_acting(c, ctx).await?;
        let outcome = record(c, &post_lock_ctx, &change).await?;
        if let WriteOutcome::Applied { target_id: project } = &outcome {
            // The project and scope reference each other through deferred foreign keys.
            let scope: String = sqlx::query_scalar(
                "WITH s AS (INSERT INTO openmettle.scopes (id, kind, project_id)
                            VALUES (gen_random_uuid(), 'project', $1::uuid) RETURNING id)
                 INSERT INTO openmettle.projects (id, scope_id, created_by_user_id)
                 SELECT $1::uuid, s.id, $2::uuid FROM s RETURNING scope_id::text",
            )
            .bind(project)
            .bind(ctx.actor_user_id)
            .fetch_one(&mut *c)
            .await?;
            sqlx::query(
                "INSERT INTO openmettle.project_settings
                     (project_id, scope_id, name, instructions, defaults, updated_by_user_id)
                 VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6::uuid)",
            )
            .bind(project)
            .bind(&scope)
            .bind(settings.name)
            .bind(settings.instructions)
            .bind(settings.defaults.to_string())
            .bind(ctx.actor_user_id)
            .execute(&mut *c)
            .await
            .map_err(settings_error)?;
            let owner = Grantee::User(ctx.actor_user_id.to_owned());
            let assignment = direct(&scope, Target::Project(project), &owner, PROJECT_ROLE);
            set_direct(tx, &post_lock_ctx, assignment, &ROLE_KEYS, Some("owner")).await?;
        }
        let c = tx.connection()?;
        let (fresh_actor, _) = post_lock_acting(c, &post_lock_ctx).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            check_defaults(c, &fresh_actor).await?;
        }
        Ok(outcome)
    })
    .await
}

/// Restore only the direct grants for `grantee` from `pre_apply` into `fresh`, keeping all
/// post-write mapped grants and every other grantee's live state untouched.
fn restore_direct_grantee<P>(
    mut fresh: Vec<Grant<P>>,
    pre_apply: Vec<Grant<P>>,
    grantee: &Grantee,
) -> Vec<Grant<P>> {
    fresh.retain(|g| !(g.origin == Origin::Direct && &g.grantee == grantee));
    fresh.extend(
        pre_apply
            .into_iter()
            .filter(|g| g.origin == Origin::Direct && &g.grantee == grantee),
    );
    fresh
}

/// The project write protocol: lock the project (taking `account_admin_lock FOR SHARE` first on
/// distinct two-user writes for rolling-upgrade safety), lock and re-hydrate the actor at
/// post-lock time, hydrate the project, decide with `authorize`, record the audit row, `apply`
/// with the project's scope ID, and re-verify the complete live authorization predicate (including
/// OIDC `membership_observations`, local groups, approval/provider/user liveness, and any
/// post-write check) immediately before commit. A `frozen` change is refused with [`ARCHIVED`]
/// while the project is archived.
#[allow(clippy::too_many_arguments)]
async fn project_write(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    (change, frozen): (Change, bool),
    target_user: Option<(&str, UserLock)>,
    changed_grantee: Option<&Grantee>,
    authorize: impl Fn(&Principal, Project) -> Decision,
    apply: impl AsyncFnOnce(&mut WriteTransaction<'_>, &str, &Principal) -> Result<(), StoreError>,
    post_check: impl AsyncFnOnce(&mut PgConnection, &Principal) -> Result<(), StoreError>,
) -> Result<WriteOutcome, StoreError> {
    uuid(project_id, "project_id")?;
    transact(c, ctx, async move |tx| {
        let c = tx.connection()?;
        if target_user.is_some_and(|(id, _)| id != ctx.actor_user_id) {
            sqlx::query("SELECT id FROM openmettle.account_admin_lock WHERE id FOR SHARE")
                .fetch_one(&mut *c)
                .await?;
        }
        let Some(locked) = lock_project(c, project_id).await? else {
            lock_actor_authority(c, ctx).await?;
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        lock_actor_authority_with(c, ctx, UserLock::Share, target_user).await?;
        let (actor, post_lock_ctx) = post_lock_acting(c, ctx).await?;
        let project = project_in(c, project_id, &locked.scope, post_lock_ctx.now_ms).await?;
        let pre_apply_project = changed_grantee.is_some().then(|| project.clone());
        let decision = authorize(&actor, project);
        if locked.deleted {
            return deleted_replay(c, &post_lock_ctx, &change, decision).await;
        }
        check(decision)?;
        if frozen && locked.archived {
            return Err(ARCHIVED);
        }
        let outcome = record(c, &post_lock_ctx, &change).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            apply(tx, &locked.scope, &actor).await?;
        }
        let c = tx.connection()?;
        let (fresh_actor, fresh_ctx) = post_lock_acting(c, &post_lock_ctx).await?;
        let fresh_project = project_in(c, project_id, &locked.scope, fresh_ctx.now_ms).await?;
        let check_project = if let (Some(grantee), Some(pre_apply), true) = (
            changed_grantee,
            pre_apply_project,
            matches!(outcome, WriteOutcome::Applied { .. }),
        ) {
            // Restore only the direct role grant of the grantee this transaction just mutated
            // under the locked project row:
            // - A newly written direct role (for the actor or a group the actor belongs to) cannot
            //   self-authorize the write if the actor's pre-write role expired during apply.
            // - A still-authorized actor may self-demote or demote/revoke a group that granted
            //   their own role when another direct owner remains.
            // - Fresh approval/user/provider, local-group memberships, OIDC observations, mapped
            //   grants, and every other grantee's live grants are still re-evaluated at post-write
            //   clock_timestamp().
            Project {
                id: fresh_project.id,
                grants: restore_direct_grantee(fresh_project.grants, pre_apply.grants, grantee),
            }
        } else {
            fresh_project
        };
        check(authorize(&fresh_actor, check_project))?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            post_check(c, &fresh_actor).await?;
        }
        Ok(outcome)
    })
    .await
}

/// A deleted project stays concealed from every write. The one exception is the exact replay
/// of the delete that recorded it, by an actor still allowed to delete it, which answers
/// `Replayed` without writing. Any other request key is concealed.
async fn deleted_replay(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    change: &Change,
    decision: Decision,
) -> Result<WriteOutcome, StoreError> {
    let Some(project_id) = change.target_id.as_deref() else {
        return Err(CONCEALED);
    };
    if change.action != DELETE || !decision.is_allowed() {
        return Err(CONCEALED);
    }
    let target_id: Option<String> = sqlx::query_scalar(
        "SELECT target_id
           FROM openmettle.authorization_audit
          WHERE actor_user_id = $1::uuid
            AND request_key = $2
            AND action = $3
            AND target_kind = $4
            AND target_id = $5
            AND details = $6::jsonb",
    )
    .bind(ctx.actor_user_id)
    .bind(ctx.request_key)
    .bind(change.action)
    .bind(change.target_kind)
    .bind(project_id)
    .bind(change.details.to_string())
    .fetch_optional(&mut *c)
    .await?;
    target_id
        .map(|target_id| WriteOutcome::Replayed { target_id })
        .ok_or(CONCEALED)
}

fn project_change(action: &'static str, project_id: &str, details: Value) -> Change {
    Change {
        action,
        target_kind: "project",
        target_id: Some(project_id.to_owned()),
        details,
    }
}

fn manages(action: Action) -> impl Fn(&Principal, Project) -> Decision {
    move |actor, project| super::authorize_scope(actor, &Scope::Project(project), action)
}

/// Replace the name, instructions and defaults. A pre-15 project gains its first settings row.
/// Refused with [`ARCHIVED`] in an archived project.
pub async fn update_project_settings(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    settings: &ProjectSettingsInput<'_>,
) -> Result<WriteOutcome, StoreError> {
    update_project_settings_checked(
        c,
        ctx,
        project_id,
        settings,
        async |_, _| Ok(()),
        async |_, _| Ok(()),
    )
    .await
}

pub(crate) async fn update_project_settings_checked(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    settings: &ProjectSettingsInput<'_>,
    check_defaults: impl AsyncFnOnce(&mut PgConnection, &Principal) -> Result<(), StoreError>,
    recheck_defaults: impl AsyncFnOnce(&mut PgConnection, &Principal) -> Result<(), StoreError>,
) -> Result<WriteOutcome, StoreError> {
    settings.validate()?;
    let change = project_change("project.settings_update", project_id, settings.details());
    let apply = async |tx: &mut WriteTransaction<'_>, scope: &str, actor: &Principal| {
        let c = tx.connection()?;
        check_defaults(c, actor).await?;
        let defaults = settings.defaults.to_string();
        let updated = sqlx::query(
            "UPDATE openmettle.project_settings
                SET name = $2, instructions = $3, defaults = $4::jsonb, revision = revision + 1,
                    updated_at = clock_timestamp(), updated_by_user_id = $5::uuid
              WHERE project_id = $1::uuid
                AND (name, instructions, defaults) IS DISTINCT FROM ($2, $3, $4::jsonb)",
        )
        .bind(project_id)
        .bind(settings.name)
        .bind(settings.instructions)
        .bind(&defaults)
        .bind(ctx.actor_user_id)
        .execute(&mut *c)
        .await
        .map_err(settings_error)?
        .rows_affected();
        if updated == 1 {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO openmettle.project_settings
                 (project_id, scope_id, name, instructions, defaults, updated_by_user_id)
             VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6::uuid)
             ON CONFLICT (project_id) DO NOTHING",
        )
        .bind(project_id)
        .bind(scope)
        .bind(settings.name)
        .bind(settings.instructions)
        .bind(&defaults)
        .bind(ctx.actor_user_id)
        .execute(c)
        .await
        .map_err(settings_error)?
        .rows_affected()
        .eq(&1)
        .then_some(())
        .ok_or(UNCHANGED)
    };
    let authorize = manages(Action::ManageProjectSettings);
    project_write(
        c,
        ctx,
        project_id,
        (change, true),
        None,
        None,
        authorize,
        apply,
        recheck_defaults,
    )
    .await
}

/// One `archived_at` or `deleted_at` transition of an existing settings row. Archive and delete
/// also cancel every non-terminal run in the project's scope in the same transaction, because
/// the worker cannot read `project_settings` (ADR 0027 PR5). Restore revives no run.
async fn lifecycle(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    (action, required, sql): (&'static str, Action, &'static str),
    cancel_runs: bool,
) -> Result<WriteOutcome, StoreError> {
    let change = project_change(action, project_id, json!({}));
    let apply = async |tx: &mut WriteTransaction<'_>, scope: &str, _: &Principal| {
        let c = tx.connection()?;
        let changed = sqlx::query(sql)
            .bind(project_id)
            .bind(ctx.actor_user_id)
            .execute(&mut *c)
            .await?
            .rows_affected();
        if changed == 1 {
            if cancel_runs {
                // Last statement: run rows are locked after the project row (`authz::runs`).
                super::runs::cancel_scope_runs(c, scope).await?;
            }
            return Ok(());
        }
        let settled: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM openmettle.project_settings WHERE project_id = $1::uuid)",
        )
        .bind(project_id)
        .fetch_one(c)
        .await?;
        Err(if settled {
            UNCHANGED
        } else {
            StoreError::Conflict("project settings are not initialised")
        })
    };
    let authorize = manages(required);
    project_write(
        c,
        ctx,
        project_id,
        (change, false),
        None,
        None,
        authorize,
        apply,
        async |_, _| Ok(()),
    )
    .await
}

pub async fn archive_project(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let sql = "UPDATE openmettle.project_settings
                  SET archived_at = GREATEST(created_at, clock_timestamp()), revision = revision + 1,
                      updated_at = clock_timestamp(), updated_by_user_id = $2::uuid
                WHERE project_id = $1::uuid AND archived_at IS NULL";
    let step = ("project.archive", Action::ManageProjectSettings, sql);
    lifecycle(c, ctx, project_id, step, true).await
}

pub async fn restore_project(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let sql = "UPDATE openmettle.project_settings
                  SET archived_at = NULL, revision = revision + 1,
                      updated_at = clock_timestamp(), updated_by_user_id = $2::uuid
                WHERE project_id = $1::uuid AND archived_at IS NOT NULL";
    let step = ("project.restore", Action::ManageProjectSettings, sql);
    lifecycle(c, ctx, project_id, step, false).await
}

/// Soft delete. A deleted project is concealed from every later read and write, except an
/// exact replay of this delete; nothing is removed. Available in an archived project.
pub async fn delete_project(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let sql = "UPDATE openmettle.project_settings
                  SET deleted_at = GREATEST(created_at, clock_timestamp()), revision = revision + 1,
                      updated_at = clock_timestamp(), updated_by_user_id = $2::uuid
                WHERE project_id = $1::uuid AND deleted_at IS NULL";
    let step = ("project.delete", Action::DeleteProject, sql);
    lifecycle(c, ctx, project_id, step, true).await
}

/// Give `grantee` exactly one direct project role, revoking any other direct role it holds, so
/// demoting an owner removes the `owner` grant. A user must be enabled and a local group enabled.
/// Refused with [`ARCHIVED`] in an archived project.
pub async fn set_project_member_role(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    grantee: &Grantee,
    role: ProjectRole,
) -> Result<WriteOutcome, StoreError> {
    member_change(c, ctx, project_id, grantee, Some(role)).await
}

/// Revoke every direct project role of `grantee`. Mapped ADR 0021 membership is not changed.
/// Available in an archived project.
pub async fn revoke_project_member(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    grantee: &Grantee,
) -> Result<WriteOutcome, StoreError> {
    member_change(c, ctx, project_id, grantee, None).await
}

async fn member_change(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    grantee: &Grantee,
    role: Option<ProjectRole>,
) -> Result<WriteOutcome, StoreError> {
    grantee_input(grantee)?;
    let action = if role.is_some() {
        "project.member_grant"
    } else {
        "project.member_revoke"
    };
    let details = grantee_details(grantee, "role", role.map(role_key));
    let change = project_change(action, project_id, details);
    let member = MemberChange {
        grantee: grantee.clone(),
        role,
    };
    let authorize = |actor: &Principal, project: Project| {
        super::authorize_member_change(actor, &project, &member)
    };
    let apply = async |tx: &mut WriteTransaction<'_>, scope: &str, _: &Principal| {
        if role.is_some() {
            recipient_enabled(tx.connection()?, grantee).await?;
        }
        let assignment = direct(scope, Target::Project(project_id), grantee, PROJECT_ROLE);
        set_direct(tx, ctx, assignment, &ROLE_KEYS, role.map(role_key)).await
    };
    // Revocation stays available in an archived project; a new role does not.
    let frozen = role.is_some();
    let target_user = match (role.is_some(), grantee) {
        (true, Grantee::User(id)) => Some((id.as_str(), UserLock::Share)),
        _ => None,
    };
    project_write(
        c,
        ctx,
        project_id,
        (change, frozen),
        target_user,
        Some(grantee),
        authorize,
        apply,
        async |_, _| Ok(()),
    )
    .await
}

/// A user or local group recipient must exist and be enabled; it stays locked FOR SHARE.
async fn recipient_enabled(c: &mut PgConnection, grantee: &Grantee) -> Result<(), StoreError> {
    let (enabled, what) = match grantee {
        Grantee::User(id) => (
            store::lock_user(c, id, false).await?,
            "target user is disabled",
        ),
        Grantee::LocalGroup(id) => (
            store::lock_group(c, id, false).await?.1,
            "local group is disabled",
        ),
        _ => return Ok(()),
    };
    if enabled {
        Ok(())
    } else {
        Err(StoreError::Conflict(what))
    }
}

// --- resource shares ---------------------------------------------------------------------------

/// Share a conversation or artifact with `grantee` at exactly `access`, replacing another access
/// it holds. Inside a project the grantee must hold active project membership. Refused with
/// [`ARCHIVED`] in an archived project.
pub async fn share_resource(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    kind: ResourceKind,
    resource_id: &str,
    grantee: &Grantee,
    access: ResourceAccess,
) -> Result<WriteOutcome, StoreError> {
    share_change(c, ctx, kind, resource_id, grantee, Some(access)).await
}

/// Revoke `grantee`'s share. The grantee need not remain a member, so stale rows can be retired.
/// Available in an archived project.
pub async fn unshare_resource(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    kind: ResourceKind,
    resource_id: &str,
    grantee: &Grantee,
) -> Result<WriteOutcome, StoreError> {
    share_change(c, ctx, kind, resource_id, grantee, None).await
}

async fn check_share_recipient(
    c: &mut PgConnection,
    actor: &Principal,
    resource: &Resource,
    grantee: &Grantee,
    now_ms: i64,
) -> Result<(), StoreError> {
    let project = match &resource.scope {
        Scope::Project(project) => Some(project),
        Scope::Personal { .. } => None,
    };
    let decision = match grantee {
        Grantee::User(id) => {
            let recipient = recipient_principal(c, id, project, now_ms).await?;
            super::authorize_share(actor, resource, ShareRecipient::User(&recipient))
        }
        Grantee::LocalGroup(id) => {
            recipient_enabled(c, grantee).await?;
            super::authorize_share(actor, resource, ShareRecipient::LocalGroup(id))
        }
        Grantee::OidcGroup(id) => {
            super::authorize_share(actor, resource, ShareRecipient::OidcGroup(id))
        }
        Grantee::Project => super::authorize_share(actor, resource, ShareRecipient::Project),
    };
    check(decision)
}

async fn share_change(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    kind: ResourceKind,
    resource_id: &str,
    grantee: &Grantee,
    access: Option<ResourceAccess>,
) -> Result<WriteOutcome, StoreError> {
    let target_kind = resource_kind(kind)?;
    uuid(resource_id, "resource_id")?;
    grantee_input(grantee)?;
    let change = Change {
        action: if access.is_some() {
            "resource.share"
        } else {
            "resource.unshare"
        },
        target_kind,
        target_id: Some(resource_id.to_owned()),
        details: grantee_details(grantee, "access", access.map(access_key)),
    };
    transact(c, ctx, async |tx| {
        let c = tx.connection()?;
        let Some(located) = locate(c, kind, resource_id).await? else {
            lock_actor_authority(c, ctx).await?;
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        // Share changes on one scope serialize in canonical order:
        // projects -> login_providers -> local_identity_approvals -> users.
        // Personal shares lock at most one user row (the owner when actor == owner, else only the
        // actor FOR SHARE since non-owners cannot manage personal shares).
        let archived = match (&located.personal_owner, &located.project_id) {
            (_, Some(project)) => match lock_project(c, project).await? {
                Some(locked) if !locked.deleted => {
                    lock_actor_authority(c, ctx).await?;
                    locked.archived
                }
                _ => {
                    lock_actor_authority(c, ctx).await?;
                    post_lock_acting(c, ctx).await?;
                    return Err(CONCEALED);
                }
            },
            (Some(owner), _) => {
                lock_actor_approval(c, ctx.actor_approval_id).await?;
                if owner == ctx.actor_user_id {
                    sqlx::query(
                        "SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE",
                    )
                    .bind(owner)
                    .fetch_one(&mut *c)
                    .await?;
                } else {
                    sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR SHARE")
                        .bind(ctx.actor_user_id)
                        .execute(&mut *c)
                        .await?;
                }
                false
            }
            (None, None) => {
                lock_actor_authority(c, ctx).await?;
                post_lock_acting(c, ctx).await?;
                return Err(CONCEALED);
            }
        };
        let (actor, post_lock_ctx) = post_lock_acting(c, ctx).await?;
        let scope = located.scope_id.clone();
        let located_for_recheck = located.clone();
        let resource = hydrate_located(c, kind, resource_id, located, post_lock_ctx.now_ms).await?;
        let pre_apply_shares = resource.shares.clone();
        check(super::authorize_revoke(&actor, &resource))?;
        if access.is_some() {
            if archived {
                return Err(ARCHIVED);
            }
            check_share_recipient(c, &actor, &resource, grantee, post_lock_ctx.now_ms).await?;
        }
        let outcome = record(c, &post_lock_ctx, &change).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            let target = match kind {
                ResourceKind::Conversation => Target::Conversation(resource_id),
                _ => Target::Artifact(resource_id),
            };
            let assignment = direct(&scope, target, grantee, RESOURCE_GRANT);
            set_direct(
                tx,
                &post_lock_ctx,
                assignment,
                &ACCESS_KEYS,
                access.map(access_key),
            )
            .await?;
        }
        let c = tx.connection()?;
        let (fresh_actor, fresh_ctx) = post_lock_acting(c, &post_lock_ctx).await?;
        let mut fresh_resource =
            hydrate_located(c, kind, resource_id, located_for_recheck, fresh_ctx.now_ms).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            // Restore only the specific direct share assignment this transaction changed:
            // - On `share`, a newly written share (e.g. `Grantee::Project` or a local group the
            //   actor belongs to) cannot supply the actor's own visibility if their pre-write
            //   visibility (such as an OIDC-group share) expired during the write.
            // - On `unshare`, a still-authorized project owner may retire a share that supplied
            //   their own visibility while fresh_actor, fresh_resource.scope, and every other
            //   live share are still re-verified at post-write clock_timestamp().
            fresh_resource.shares =
                restore_direct_grantee(fresh_resource.shares, pre_apply_shares, grantee);
        }
        check(super::authorize_revoke(&fresh_actor, &fresh_resource))?;
        if access.is_some() {
            check_share_recipient(c, &fresh_actor, &fresh_resource, grantee, fresh_ctx.now_ms)
                .await?;
        }
        Ok(outcome)
    })
    .await
}

/// The share recipient's own principal, hydrated through each of its approvals as in PR3: the
/// first that is active (and, inside a project, holds a project role) wins. Without one the
/// recipient is inactive, which the policy refuses. An unknown user is `NotFound`. The user row
/// is not locked: a personal share already locks its owner's row, and locking a second user
/// could deadlock two owners sharing with each other. A later disablement grants nothing.
async fn recipient_principal(
    c: &mut PgConnection,
    user_id: &str,
    project: Option<&Project>,
    now_ms: i64,
) -> Result<Principal, StoreError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT FROM openmettle.users WHERE id = $1::uuid)")
            .bind(user_id)
            .fetch_one(&mut *c)
            .await?;
    if !exists {
        return Err(StoreError::NotFound);
    }
    let approvals: Vec<String> = sqlx::query_scalar(
        "SELECT a.id::text FROM openmettle.local_identity_approvals a
           JOIN openmettle.user_identities i ON i.id = a.identity_id
          WHERE i.user_id = $1::uuid ORDER BY a.id",
    )
    .bind(user_id)
    .fetch_all(&mut *c)
    .await?;
    for approval in approvals {
        let Some(principal) = store::hydrate(c, user_id, &approval, now_ms, false).await? else {
            continue;
        };
        if principal.is_active() && project.is_none_or(|p| p.role_of(&principal).is_some()) {
            return Ok(principal);
        }
    }
    Ok(Principal {
        user_id: user_id.to_owned(),
        ..Principal::default()
    })
}

// --- reads (PR4b) -------------------------------------------------------------------------------

/// A project as one caller may read it: its current settings and the caller's effective role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectView {
    pub settings: ProjectSettings,
    pub role: ProjectRole,
}

/// A conversation or artifact as one caller may read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceView {
    pub scope_id: String,
    /// The containing project, or `None` in a personal scope.
    pub project_id: Option<String>,
    /// Creation time in Unix microseconds.
    pub created_us: i64,
    /// An artifact's last revision; `None` for a conversation.
    pub last_revision: Option<i64>,
    /// Effective access: never more than `Read` in an archived project.
    pub access: ResourceAccess,
    /// [`super::authorize_revoke`]: the caller may change this item's shares.
    pub can_manage_shares: bool,
}

fn active(principal: &Principal) -> Result<(), StoreError> {
    super::require(Some(principal))
        .map(drop)
        .map_err(StoreError::Denied)
}

/// Read one project for `principal`, hydrated by the caller for this request. An inactive
/// principal is refused before anything is read. A missing, deleted or invisible project is
/// concealed; an archived one stays readable. `openmettle_api` only.
pub async fn read_project(
    c: &mut PgConnection,
    principal: &Principal,
    project_id: &str,
    now_ms: i64,
) -> Result<ProjectView, StoreError> {
    active(principal)?;
    let Some(settings) = load_project_settings(c, project_id).await? else {
        return Err(CONCEALED);
    };
    let project = project_in(c, project_id, &settings.scope_id, now_ms).await?;
    let role = project.role_of(principal);
    check(super::authorize_scope(
        principal,
        &Scope::Project(project),
        Action::Read,
    ))?;
    match role {
        Some(role) if !settings.deleted => Ok(ProjectView { settings, role }),
        _ => Err(CONCEALED),
    }
}

/// Decide whether `principal`, hydrated by the caller for this request, may create a
/// conversation or artifact in `scope_id` ([`Action::CreateInScope`]). A personal scope admits
/// its owner only; a project scope needs at least the editor role. A missing scope, or a
/// deleted or invisible project, is concealed. An archived project is refused with
/// [`ARCHIVED`] once the caller is authorized. `openmettle_api` only.
pub async fn authorize_create_in_scope(
    c: &mut PgConnection,
    principal: &Principal,
    scope_id: &str,
    now_ms: i64,
) -> Result<(), StoreError> {
    if authorized_create_scope_is_archived(c, principal, scope_id, now_ms).await? {
        return Err(ARCHIVED);
    }
    Ok(())
}

/// Check current create authority before an audit replay. A caller may return a recorded
/// target in an archived project, but must roll back a new write there.
pub(super) async fn authorized_create_scope_is_archived(
    c: &mut PgConnection,
    principal: &Principal,
    scope_id: &str,
    now_ms: i64,
) -> Result<bool, StoreError> {
    active(principal)?;
    uuid(scope_id, "scope_id")?;
    let owner: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT personal_user_id::text, project_id::text FROM openmettle.scopes
          WHERE id = $1::uuid",
    )
    .bind(scope_id)
    .fetch_optional(&mut *c)
    .await?;
    let (scope, archived) = match owner {
        Some((Some(owner_user_id), None)) => (
            Scope::Personal {
                scope_id: scope_id.to_owned(),
                owner_user_id,
            },
            false,
        ),
        Some((None, Some(project_id))) => match load_project_settings(c, &project_id).await? {
            Some(settings) if !settings.deleted => (
                Scope::Project(project_in(c, &project_id, scope_id, now_ms).await?),
                settings.archived,
            ),
            _ => return Err(CONCEALED),
        },
        _ => return Err(CONCEALED),
    };
    check(super::authorize_scope(
        principal,
        &scope,
        Action::CreateInScope,
    ))?;
    Ok(archived)
}

/// Read one conversation or artifact for `principal` with [`super::authorize_resource`]. An
/// item in a deleted project is concealed. In an archived project the item stays readable, its
/// effective access is `Read` and shares can still be revoked. `openmettle_api` only.
pub async fn read_resource(
    c: &mut PgConnection,
    principal: &Principal,
    kind: ResourceKind,
    resource_id: &str,
    now_ms: i64,
) -> Result<ResourceView, StoreError> {
    resource_view(c, principal, kind, resource_id, now_ms, Action::Read).await
}

/// Under the admission scope lock, authorize the resource and its accounting scope
/// before looking up a replay. Archive caps the projection but permits exact retries.
pub(crate) async fn resource_view(
    c: &mut PgConnection,
    principal: &Principal,
    kind: ResourceKind,
    resource_id: &str,
    now_ms: i64,
    action: Action,
) -> Result<ResourceView, StoreError> {
    active(principal)?;
    resource_kind(kind)?;
    uuid(resource_id, "resource_id")?;
    let Some(located) = locate(c, kind, resource_id).await? else {
        return Err(CONCEALED);
    };
    let archived = archived(c, &located).await?;
    let scope_id = located.scope_id.clone();
    let project_id = located.project_id.clone();
    let (created_us, last_revision) = (located.created_us, located.last_revision);
    let resource = hydrate_located(c, kind, resource_id, located, now_ms).await?;
    check(super::authorize_resource(principal, &resource, action))?;
    if action == Action::RunExecute {
        check(super::authorize_scope(principal, &resource.scope, action))?;
    }
    let writable =
        !archived && super::authorize_resource(principal, &resource, Action::Write).is_allowed();
    Ok(ResourceView {
        scope_id,
        project_id,
        created_us,
        last_revision,
        access: if writable {
            ResourceAccess::Write
        } else {
            ResourceAccess::Read
        },
        can_manage_shares: super::authorize_revoke(principal, &resource).is_allowed(),
    })
}

/// Whether a located item's project is archived. An item in a deleted project is concealed.
async fn archived(c: &mut PgConnection, located: &Located) -> Result<bool, StoreError> {
    match &located.project_id {
        Some(project) => match load_project_settings(c, project).await? {
            Some(settings) if !settings.deleted => Ok(settings.archived),
            _ => Err(CONCEALED),
        },
        None => Ok(false),
    }
}

/// Where an artifact lives, for a caller authorized to act on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactScope {
    pub scope_id: String,
    /// The containing project, or `None` in a personal scope.
    pub project_id: Option<String>,
}

/// Decide `action` (`Read`, `Download`, `Write` or `Delete`) on one artifact for `principal`, hydrated by
/// the caller for this request, with [`super::authorize_resource`] (ADR 0031, ADR 0041). A missing
/// artifact, one in a deleted project and one the caller may not read are concealed; a caller
/// who may read but not write is refused with `Policy`. Reads stay available in an archived
/// project; a write or delete there is refused with [`ARCHIVED`] once the caller is authorized.
/// `openmettle_api` only.
pub async fn authorize_artifact(
    c: &mut PgConnection,
    principal: &Principal,
    artifact_id: &str,
    action: Action,
    now_ms: i64,
) -> Result<ArtifactScope, StoreError> {
    active(principal)?;
    uuid(artifact_id, "artifact_id")?;
    let Some(located) = locate(c, ResourceKind::Artifact, artifact_id).await? else {
        return Err(CONCEALED);
    };
    let archived = archived(c, &located).await?;
    let scope = ArtifactScope {
        scope_id: located.scope_id.clone(),
        project_id: located.project_id.clone(),
    };
    let resource = hydrate_located(c, ResourceKind::Artifact, artifact_id, located, now_ms).await?;
    check(super::authorize_resource(principal, &resource, action))?;
    if archived && matches!(action, Action::Write | Action::Delete) {
        return Err(ARCHIVED);
    }
    Ok(scope)
}

/// Shared transactional protocol for artifact disassociation and pre-expiry restore (ADR 0041):
/// locks project (if project-scoped), actor approval and actor user in canonical order, re-hydrates
/// the actor and artifact at post-lock `clock_timestamp()`, authorizes `action` (refusing deleted
/// projects with `NotFound` and archived projects with `ARCHIVED`), executes `work`, and re-verifies
/// live authorization immediately before commit. `openmettle_api` only.
async fn artifact_write<T>(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    artifact_id: &str,
    action: Action,
    work: impl AsyncFnOnce(&mut WriteTransaction<'_>, &AuditContext<'_>, &str) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    uuid(artifact_id, "artifact_id")?;
    transact(c, ctx, async |tx| {
        let c = tx.connection()?;
        let Some(located) = locate(c, ResourceKind::Artifact, artifact_id).await? else {
            lock_actor_authority(c, ctx).await?;
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        let archived = match (&located.personal_owner, &located.project_id) {
            (_, Some(project)) => match lock_project(c, project).await? {
                Some(locked) if !locked.deleted => {
                    lock_actor_authority(c, ctx).await?;
                    locked.archived
                }
                _ => {
                    lock_actor_authority(c, ctx).await?;
                    post_lock_acting(c, ctx).await?;
                    return Err(CONCEALED);
                }
            },
            (Some(_), None) => {
                lock_actor_authority(c, ctx).await?;
                false
            }
            (None, None) => {
                lock_actor_authority(c, ctx).await?;
                post_lock_acting(c, ctx).await?;
                return Err(CONCEALED);
            }
        };
        let (actor, post_lock_ctx) = post_lock_acting(c, ctx).await?;
        let scope = located.scope_id.clone();
        let located_for_recheck = located.clone();
        let resource = hydrate_located(
            c,
            ResourceKind::Artifact,
            artifact_id,
            located,
            post_lock_ctx.now_ms,
        )
        .await?;
        check(super::authorize_resource(&actor, &resource, action))?;
        if archived {
            return Err(ARCHIVED);
        }
        let result = work(tx, &post_lock_ctx, &scope).await?;
        let c = tx.connection()?;
        let (fresh_actor, fresh_ctx) = post_lock_acting(c, &post_lock_ctx).await?;
        let fresh_resource = hydrate_located(
            c,
            ResourceKind::Artifact,
            artifact_id,
            located_for_recheck,
            fresh_ctx.now_ms,
        )
        .await?;
        check(super::authorize_resource(
            &fresh_actor,
            &fresh_resource,
            action,
        ))?;
        Ok(result)
    })
    .await
}

/// Disassociate all currently `active` revisions of `artifact_id` (`active -> retained`, locked
/// in ascending revision ID order), preserving charged storage bytes until purge and recording
/// one `artifact.delete` audit row with exact idempotency. `openmettle_api` only.
pub async fn delete_artifact(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    artifact_id: &str,
) -> Result<WriteOutcome, StoreError> {
    let change = Change {
        action: "artifact.delete",
        target_kind: "artifact",
        target_id: Some(artifact_id.to_owned()),
        details: json!({}),
    };
    artifact_write(
        c,
        ctx,
        artifact_id,
        Action::Delete,
        async |tx, post_lock_ctx, scope| {
            let outcome = record(tx.connection()?, post_lock_ctx, &change).await?;
            if matches!(outcome, WriteOutcome::Applied { .. }) {
                let active_revisions: Vec<String> = sqlx::query_scalar(
                    "SELECT id::text
                   FROM openmettle.artifact_revisions
                  WHERE scope_id = $1::uuid
                    AND artifact_id = $2::uuid
                    AND state = 'active'
                  ORDER BY id ASC
                    FOR UPDATE",
                )
                .bind(scope)
                .bind(artifact_id)
                .fetch_all(tx.connection()?)
                .await?;
                for rev_id in active_revisions {
                    crate::storage::retain_revision(tx, scope, &rev_id).await?;
                }
            }
            Ok(outcome)
        },
    )
    .await
}

/// Disassociate one revision of `artifact_id` (`active -> retained`), returning the updated
/// revision metadata. Exact retry replays the recorded audit row; a non-replayed call on an
/// already `purging` or `purged` revision fails with `Conflict`. `openmettle_api` only.
pub async fn delete_artifact_revision(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    artifact_id: &str,
    revision_id: &str,
) -> Result<crate::storage::Revision, StoreError> {
    uuid(revision_id, "revision_id")?;
    let change = Change {
        action: "artifact_revision.delete",
        target_kind: "artifact",
        target_id: Some(artifact_id.to_owned()),
        details: json!({ "revision_id": revision_id }),
    };
    artifact_write(
        c,
        ctx,
        artifact_id,
        Action::Delete,
        async |tx, post_lock_ctx, scope| {
            let state: Option<String> = sqlx::query_scalar(
                "SELECT state
               FROM openmettle.artifact_revisions
              WHERE scope_id = $1::uuid
                AND artifact_id = $2::uuid
                AND id = $3::uuid
                FOR UPDATE",
            )
            .bind(scope)
            .bind(artifact_id)
            .bind(revision_id)
            .fetch_optional(tx.connection()?)
            .await?;
            let Some(state) = state else {
                return Err(CONCEALED);
            };
            let outcome = record(tx.connection()?, post_lock_ctx, &change).await?;
            if matches!(outcome, WriteOutcome::Applied { .. }) {
                match state.as_str() {
                    "active" => {
                        crate::storage::retain_revision(tx, scope, revision_id).await?;
                    }
                    "retained" => {}
                    _ => {
                        return Err(StoreError::Conflict(
                            "artifact revision cannot be disassociated in its current state",
                        ));
                    }
                }
            }
            crate::storage::read_revision(tx.connection()?, artifact_id, revision_id)
                .await?
                .ok_or(CONCEALED)
        },
    )
    .await
}

/// Restore a retained revision of `artifact_id` back to `active` strictly before its
/// `purge_after` deadline without reinstating any revoked shares. Fails with `Conflict` if
/// already active (on a new key), expired, `purging` or `purged`. `openmettle_api` only.
pub async fn restore_artifact_revision(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    artifact_id: &str,
    revision_id: &str,
) -> Result<crate::storage::Revision, StoreError> {
    uuid(revision_id, "revision_id")?;
    let change = Change {
        action: "artifact_revision.restore",
        target_kind: "artifact",
        target_id: Some(artifact_id.to_owned()),
        details: json!({ "revision_id": revision_id }),
    };
    artifact_write(
        c,
        ctx,
        artifact_id,
        Action::Write,
        async |tx, post_lock_ctx, scope| {
            let state: Option<String> = sqlx::query_scalar(
                "SELECT state
               FROM openmettle.artifact_revisions
              WHERE scope_id = $1::uuid
                AND artifact_id = $2::uuid
                AND id = $3::uuid
                FOR UPDATE",
            )
            .bind(scope)
            .bind(artifact_id)
            .bind(revision_id)
            .fetch_optional(tx.connection()?)
            .await?;
            let Some(state) = state else {
                return Err(CONCEALED);
            };
            let outcome = record(tx.connection()?, post_lock_ctx, &change).await?;
            if matches!(outcome, WriteOutcome::Applied { .. }) {
                if state != "retained" {
                    return Err(StoreError::Conflict(
                        "artifact revision is not restorable in its current state",
                    ));
                }
                crate::storage::restore_revision(tx, scope, revision_id)
                    .await
                    .map_err(|err| match err {
                        crate::runs::Error::NotEligible => {
                            StoreError::Conflict("artifact revision retention deadline has elapsed")
                        }
                        other => StoreError::from(other),
                    })?;
            }
            crate::storage::read_revision(tx.connection()?, artifact_id, revision_id)
                .await?
                .ok_or(CONCEALED)
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_and_access_keys_match_the_vocabulary() {
        for role in [ProjectRole::Viewer, ProjectRole::Editor, ProjectRole::Owner] {
            assert_eq!(
                GrantVocabulary::parse(PROJECT_ROLE, 1, role_key(role)),
                Ok(GrantPermission::ProjectRole(role))
            );
        }
        for access in [ResourceAccess::Read, ResourceAccess::Write] {
            assert_eq!(
                GrantVocabulary::parse(RESOURCE_GRANT, 1, access_key(access)),
                Ok(GrantPermission::Resource(access))
            );
        }
    }

    #[test]
    fn grant_keys_are_bounded_and_distinct_per_request_and_key() {
        let ctx = |request_key| AuditContext {
            actor_user_id: "00000000-0000-0000-0000-000000000001",
            actor_approval_id: "00000000-0000-0000-0000-000000000002",
            now_ms: 1,
            request_key,
            reason: "r",
        };
        let long = "k".repeat(128);
        let a = grant_key(&ctx(&long), PROJECT_ROLE, "owner");
        assert_eq!(a.len(), 70);
        assert_ne!(a, grant_key(&ctx(&long), PROJECT_ROLE, "editor"));
        assert_ne!(a, grant_key(&ctx("k"), PROJECT_ROLE, "owner"));
        assert_eq!(a, grant_key(&ctx(&long), PROJECT_ROLE, "owner"));
    }

    #[test]
    fn audit_details_name_only_identifiers() {
        let user = Grantee::User("00000000-0000-0000-0000-000000000003".into());
        assert_eq!(
            grantee_details(&user, "role", Some("owner")),
            json!({"grantee_kind": "user",
                   "grantee_id": "00000000-0000-0000-0000-000000000003", "role": "owner"})
        );
        assert_eq!(
            grantee_details(&Grantee::Project, "access", None),
            json!({"grantee_kind": "project"})
        );
        let defaults = json!({"model": "x"});
        let input = ProjectSettingsInput {
            name: "Secret plan",
            instructions: "private",
            defaults: &defaults,
        };
        let details = input.details().to_string();
        assert!(!details.contains("Secret") && !details.contains("private"));
        assert_eq!(
            input.details()["settings_digest"].as_str().unwrap().len(),
            64
        );
    }

    #[test]
    fn defaults_validation_rejects_embedded_nul_without_rejecting_literal_escape() {
        let literal = json!({ "note": "\\u0000", "nested": ["\\u0000"] });
        let ok = ProjectSettingsInput {
            name: "Alpha",
            instructions: "",
            defaults: &literal,
        };
        assert!(ok.validate().is_ok());

        for bad in [
            json!({ "note": "a\0b" }),
            json!({ "k\0": "v" }),
            json!({ "nested": [{ "deep": "x\0y" }] }),
        ] {
            let input = ProjectSettingsInput {
                name: "Alpha",
                instructions: "",
                defaults: &bad,
            };
            assert!(matches!(
                input.validate(),
                Err(StoreError::InvalidInput("defaults"))
            ));
        }
    }
}
