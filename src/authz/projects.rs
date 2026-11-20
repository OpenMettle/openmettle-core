//! Project settings, membership and resource shares (ADR 0027 PR4a). Hydration reads the
//! primary on every call, never caches and works as `openmettle_api` and `openmettle_worker`.
//! It never reads `account_admins`. Writers run only as `openmettle_api` and follow the PR3
//! protocol in one READ COMMITTED transaction: lock, re-hydrate the actor, authorize with
//! `src/authz.rs`, insert or replay the `authorization_audit` row, then apply. A change that
//! would not alter current state returns `Conflict` and leaves no audit row.
use super::{
    Action, Decision, DenialReason, Grant, GrantPermission, GrantVocabulary, Grantee, MemberChange,
    Origin, PROJECT_ROLE, Principal, Project, ProjectRole, RESOURCE_GRANT, Resource,
    ResourceAccess, ResourceKind, Scope, ShareRecipient,
    store::{
        self, AuditContext, Change, StoreError, UNCHANGED, WriteOutcome, acting, check, record,
        transact, uuid,
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

fn role_key(role: ProjectRole) -> &'static str {
    ROLE_KEYS[role as usize]
}

fn access_key(access: ResourceAccess) -> &'static str {
    ACCESS_KEYS[access as usize]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const CONCEALED: StoreError = StoreError::Denied(DenialReason::NotFound);

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

fn resource_kind(kind: ResourceKind) -> Result<&'static str, StoreError> {
    match kind {
        ResourceKind::Conversation => Ok("conversation"),
        ResourceKind::Artifact => Ok("artifact"),
        _ => Err(StoreError::InvalidInput("resource kind")),
    }
}

/// Where a conversation or artifact lives, without its grants.
struct Located {
    scope_id: String,
    creator_user_id: String,
    personal_owner: Option<String>,
    project_id: Option<String>,
}

async fn locate(
    c: &mut PgConnection,
    kind: ResourceKind,
    resource_id: &str,
) -> Result<Option<Located>, StoreError> {
    let sql = match resource_kind(kind)? {
        "conversation" => {
            "SELECT r.scope_id::text, r.owner_user_id::text, s.personal_user_id::text,
                    s.project_id::text
               FROM openmettle.conversations r JOIN openmettle.scopes s ON s.id = r.scope_id
              WHERE r.id = $1::uuid"
        }
        _ => {
            "SELECT r.scope_id::text, r.owner_user_id::text, s.personal_user_id::text,
                    s.project_id::text
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

/// Lock the project row FOR NO KEY UPDATE through its inert guard column (migration 16).
/// Membership, share and settings changes on one project serialize here while admitting
/// concurrent foreign-key `FOR KEY SHARE` locks. Returns `None` when the project is missing or
/// deleted so callers can verify the actor is active before concealing it.
async fn lock_project(
    c: &mut PgConnection,
    project_id: &str,
) -> Result<Option<String>, StoreError> {
    let row: Option<(String, bool)> = sqlx::query_as(
        "SELECT p.scope_id::text, EXISTS (SELECT FROM openmettle.project_settings s
                                           WHERE s.project_id = p.id AND s.deleted_at IS NOT NULL)
           FROM openmettle.projects p WHERE p.id = $1::uuid FOR NO KEY UPDATE OF p",
    )
    .bind(project_id)
    .fetch_optional(c)
    .await?;
    Ok(match row {
        Some((scope, false)) => Some(scope),
        _ => None,
    })
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
    settings.validate()?;
    let change = Change {
        action: "project.create",
        target_kind: "project",
        target_id: None,
        details: settings.details(),
    };
    transact(c, ctx, async |tx| {
        let c = tx.connection()?;
        acting(c, ctx).await?;
        let outcome = record(c, ctx, &change).await?;
        let WriteOutcome::Applied { target_id: project } = &outcome else {
            return Ok(outcome);
        };
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
        set_direct(tx, ctx, assignment, &ROLE_KEYS, Some("owner")).await?;
        Ok(outcome)
    })
    .await
}

/// The project write protocol: lock the project, re-hydrate the actor and the project, decide
/// with `authorize`, record the audit row, then `apply` with the project's scope ID.
async fn project_write(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    change: Change,
    authorize: impl FnOnce(&Principal, Project) -> Decision,
    apply: impl AsyncFnOnce(&mut WriteTransaction<'_>, &str) -> Result<(), StoreError>,
) -> Result<WriteOutcome, StoreError> {
    uuid(project_id, "project_id")?;
    transact(c, ctx, async move |tx| {
        let c = tx.connection()?;
        let Some(scope) = lock_project(c, project_id).await? else {
            acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        let actor = acting(c, ctx).await?;
        let project = project_in(c, project_id, &scope, ctx.now_ms).await?;
        check(authorize(&actor, project))?;
        let outcome = record(c, ctx, &change).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            apply(tx, &scope).await?;
        }
        Ok(outcome)
    })
    .await
}

fn project_change(action: &'static str, project_id: &str, details: Value) -> Change {
    Change {
        action,
        target_kind: "project",
        target_id: Some(project_id.to_owned()),
        details,
    }
}

fn manages(action: Action) -> impl FnOnce(&Principal, Project) -> Decision {
    move |actor, project| super::authorize_scope(actor, &Scope::Project(project), action)
}

/// Replace the name, instructions and defaults. A pre-15 project gains its first settings row.
pub async fn update_project_settings(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    settings: &ProjectSettingsInput<'_>,
) -> Result<WriteOutcome, StoreError> {
    settings.validate()?;
    let change = project_change("project.settings_update", project_id, settings.details());
    let apply = async |tx: &mut WriteTransaction<'_>, scope: &str| {
        let c = tx.connection()?;
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
    project_write(c, ctx, project_id, change, authorize, apply).await
}

/// One `archived_at` or `deleted_at` transition of an existing settings row.
async fn lifecycle(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    project_id: &str,
    (action, required, sql): (&'static str, Action, &'static str),
) -> Result<WriteOutcome, StoreError> {
    let change = project_change(action, project_id, json!({}));
    let apply = async |tx: &mut WriteTransaction<'_>, _: &str| {
        let c = tx.connection()?;
        let changed = sqlx::query(sql)
            .bind(project_id)
            .bind(ctx.actor_user_id)
            .execute(&mut *c)
            .await?
            .rows_affected();
        if changed == 1 {
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
    project_write(c, ctx, project_id, change, manages(required), apply).await
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
    lifecycle(c, ctx, project_id, step).await
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
    lifecycle(c, ctx, project_id, step).await
}

/// Soft delete. A deleted project is concealed from every later write; nothing is removed.
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
    lifecycle(c, ctx, project_id, step).await
}

/// Give `grantee` exactly one direct project role, revoking any other direct role it holds, so
/// demoting an owner removes the `owner` grant. A user must be enabled and a local group enabled.
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
    let apply = async |tx: &mut WriteTransaction<'_>, scope: &str| {
        if role.is_some() {
            recipient_enabled(tx.connection()?, grantee).await?;
        }
        let assignment = direct(scope, Target::Project(project_id), grantee, PROJECT_ROLE);
        set_direct(tx, ctx, assignment, &ROLE_KEYS, role.map(role_key)).await
    };
    project_write(c, ctx, project_id, change, authorize, apply).await
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
/// it holds. Inside a project the grantee must hold active project membership.
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
pub async fn unshare_resource(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    kind: ResourceKind,
    resource_id: &str,
    grantee: &Grantee,
) -> Result<WriteOutcome, StoreError> {
    share_change(c, ctx, kind, resource_id, grantee, None).await
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
            acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        // Share changes on one scope serialize: on the project row, or on the personal owner.
        match (&located.personal_owner, &located.project_id) {
            (_, Some(project)) => {
                if lock_project(c, project).await?.is_none() {
                    acting(c, ctx).await?;
                    return Err(CONCEALED);
                }
            }
            (Some(owner), _) => {
                sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE")
                    .bind(owner)
                    .fetch_one(&mut *c)
                    .await?;
            }
            (None, None) => {
                acting(c, ctx).await?;
                return Err(CONCEALED);
            }
        }
        let actor = acting(c, ctx).await?;
        let scope = located.scope_id.clone();
        let resource = hydrate_located(c, kind, resource_id, located, ctx.now_ms).await?;
        check(super::authorize_revoke(&actor, &resource))?;
        if access.is_some() {
            let project = match &resource.scope {
                Scope::Project(project) => Some(project),
                Scope::Personal { .. } => None,
            };
            let decision = match grantee {
                Grantee::User(id) => {
                    let recipient = recipient_principal(c, id, project, ctx.now_ms).await?;
                    super::authorize_share(&actor, &resource, ShareRecipient::User(&recipient))
                }
                Grantee::LocalGroup(id) => {
                    recipient_enabled(c, grantee).await?;
                    super::authorize_share(&actor, &resource, ShareRecipient::LocalGroup(id))
                }
                Grantee::OidcGroup(id) => {
                    super::authorize_share(&actor, &resource, ShareRecipient::OidcGroup(id))
                }
                Grantee::Project => {
                    super::authorize_share(&actor, &resource, ShareRecipient::Project)
                }
            };
            check(decision)?;
        }
        let outcome = record(c, ctx, &change).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            let target = match kind {
                ResourceKind::Conversation => Target::Conversation(resource_id),
                _ => Target::Artifact(resource_id),
            };
            let assignment = direct(&scope, target, grantee, RESOURCE_GRANT);
            set_direct(tx, ctx, assignment, &ACCESS_KEYS, access.map(access_key)).await?;
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
