//! Managed conversation graph (ADR 0036). Standalone creates own their audit transaction.
//! User turns compose with run admission. All graph locks follow the scope and actor locks.
pub mod snapshot;

use super::{
    Action, DenialReason, Principal, ResourceKind, Scope, authorize_resource, projects, runs,
    store::{self, AuditContext, Change, StoreError, WriteOutcome},
};
use crate::model_config::{ConfigSnapshot, SNAPSHOT_FORMAT, SNAPSHOT_VERSION};
use crate::runs::{WriteTransaction, digest, identity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgConnection, Row};

const HIDDEN: StoreError = StoreError::Denied(DenialReason::NotFound);
pub const HEAD_MISMATCH: &str = "branch head changed";

#[derive(Clone, Copy)]
pub struct Conversation<'a> {
    pub scope: &'a str,
    pub id: &'a str,
}

async fn verify_write_access<'a>(
    c: &mut PgConnection,
    ctx: &AuditContext<'a>,
    chat: Conversation<'_>,
    project: Option<&str>,
    action: Action,
) -> Result<(Principal, bool, AuditContext<'a>), StoreError> {
    let (actor, post_lock_ctx) = store::post_lock_acting(c, ctx).await?;
    let resource =
        projects::hydrate_resource(c, ResourceKind::Conversation, chat.id, post_lock_ctx.now_ms)
            .await?
            .ok_or(HIDDEN)?;
    let in_scope = match &resource.scope {
        Scope::Personal { scope_id, .. } => scope_id == chat.scope,
        Scope::Project(p) => project == Some(p.id.as_str()),
    };
    if !in_scope {
        return Err(HIDDEN);
    }
    let archived = if let Some(id) = project {
        let settings = projects::load_project_settings(c, id)
            .await?
            .ok_or(HIDDEN)?;
        if settings.deleted {
            return Err(HIDDEN);
        }
        settings.archived
    } else {
        false
    };
    store::check(authorize_resource(&actor, &resource, action))?;
    Ok((actor, archived, post_lock_ctx))
}

async fn write_access<'a>(
    c: &mut PgConnection,
    ctx: &AuditContext<'a>,
    chat: Conversation<'_>,
    action: Action,
) -> Result<(Principal, bool, AuditContext<'a>, Option<String>), StoreError> {
    store::uuid(chat.scope, "scope_id")?;
    let (_, project) =
        runs::lock_scope_actor(c, chat.scope, ctx.actor_user_id, ctx.actor_approval_id).await?;
    let (actor, archived, post_lock_ctx) =
        verify_write_access(c, ctx, chat, project.as_deref(), action).await?;
    Ok((actor, archived, post_lock_ctx, project))
}

async fn insert_branch(
    c: &mut PgConnection,
    chat: Conversation<'_>,
    id: Option<&str>,
    source: Option<&str>,
    fork: Option<&str>,
) -> Result<String, StoreError> {
    let id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches
        (id, scope_id, conversation_id, fork_message_id) VALUES
        (coalesce($1::uuid, gen_random_uuid()), $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(id)
    .bind(chat.scope)
    .bind(chat.id)
    .bind(fork)
    .fetch_one(&mut *c)
    .await?;
    sqlx::query(
        "INSERT INTO openmettle.branch_heads
        (scope_id, conversation_id, branch_id, parent_branch_id, head_message_id)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid)",
    )
    .bind(chat.scope)
    .bind(chat.id)
    .bind(&id)
    .bind(source)
    .bind(fork)
    .execute(c)
    .await
    .map_err(|e| store::unique(e, "branch_heads_root_idx", "root already exists"))?;
    Ok(id)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Root {
    pub conversation_id: String,
    pub branch_id: String,
}

pub async fn create_conversation(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    scope: &str,
) -> Result<WriteOutcome<Root>, StoreError> {
    let ctx = AuditContext {
        reason: "create conversation",
        ..*ctx
    };
    store::uuid(scope, "scope_id")?;
    store::transact(c, &ctx, async |tx| {
        let c = tx.connection()?;
        let (personal_owner, project_id): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT personal_user_id::text, project_id::text FROM openmettle.scopes
              WHERE id = $1::uuid",
        )
        .bind(scope)
        .fetch_optional(&mut *c)
        .await?
        .unwrap_or_default();
        if let Some(project) = &project_id {
            sqlx::query("SELECT FROM openmettle.projects WHERE id = $1::uuid FOR NO KEY UPDATE")
                .bind(project)
                .execute(&mut *c)
                .await?;
        }
        store::lock_actor_approval(c, ctx.actor_approval_id).await?;
        if personal_owner.as_deref() == Some(ctx.actor_user_id) || project_id.is_some() {
            sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE")
                .bind(ctx.actor_user_id)
                .execute(&mut *c)
                .await?;
        } else {
            sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR SHARE")
                .bind(ctx.actor_user_id)
                .execute(&mut *c)
                .await?;
        }
        let (actor, post_lock_ctx) = store::post_lock_acting(c, &ctx).await?;
        let archived = projects::authorized_create_scope_is_archived(
            c,
            &actor,
            scope,
            post_lock_ctx.now_ms,
        )
        .await?;
        let change = Change {
            action: "conversation.create",
            target_kind: "conversation",
            target_id: None,
            details: json!({"scope_id": scope, "request_digest": projects::hex(&digest(scope.as_bytes()))}),
        };
        let outcome = store::record(c, &post_lock_ctx, &change).await?;
        let id = outcome.target_id();
        let branch_id = if matches!(outcome, WriteOutcome::Applied { .. }) {
            if archived { return Err(projects::ARCHIVED); }
            sqlx::query("INSERT INTO openmettle.conversations (scope_id, scope_kind, owner_user_id, id)
                SELECT id, kind, $2::uuid, $3::uuid FROM openmettle.scopes WHERE id=$1::uuid")
                .bind(scope).bind(ctx.actor_user_id).bind(id).execute(&mut *c).await?;
            insert_branch(c, Conversation {scope,id}, None, None, None).await?
        } else {
            sqlx::query_scalar("SELECT branch_id::text FROM openmettle.branch_heads
                WHERE conversation_id=$1::uuid AND parent_branch_id IS NULL")
                .bind(id).fetch_one(&mut *c).await?
        };
        let (fresh_actor, fresh_ctx) = store::post_lock_acting(c, &post_lock_ctx).await?;
        projects::authorized_create_scope_is_archived(c, &fresh_actor, scope, fresh_ctx.now_ms)
            .await?;
        Ok(outcome.map(|conversation_id| Root { conversation_id, branch_id }))
    }).await
}

async fn lock_head(
    c: &mut PgConnection,
    chat: Conversation<'_>,
    branch: &str,
) -> Result<Option<String>, StoreError> {
    store::uuid(branch, "branch_id")?;
    sqlx::query_scalar("SELECT head_message_id::text FROM openmettle.branch_heads
        WHERE scope_id=$1::uuid AND conversation_id=$2::uuid AND branch_id=$3::uuid FOR NO KEY UPDATE")
        .bind(chat.scope).bind(chat.id).bind(branch).fetch_optional(c).await?.ok_or(HIDDEN)
}

// Follow immutable parent edges only. A legacy branch has no managed head to start from.
macro_rules! path {
    () => { path!("") };
    ($bound:literal) => { concat!("WITH RECURSIVE path(id,parent_message_id,depth) AS (
        SELECT id,parent_message_id,0 FROM openmettle.messages WHERE conversation_id=$1::uuid AND id=$2::uuid
        UNION ALL SELECT m.id,m.parent_message_id,p.depth+1 FROM path p JOIN openmettle.messages m
        ON m.id=p.parent_message_id AND m.conversation_id=$1::uuid ", $bound, ") ") }
}
async fn ancestor(
    c: &mut PgConnection,
    chat: Conversation<'_>,
    head: Option<&str>,
    target: &str,
) -> Result<(Option<String>, bool), StoreError> {
    store::uuid(target, "target_message_id")?;
    sqlx::query_as(concat!(
        path!(),
        "SELECT p.parent_message_id::text,t.author_user_id IS NOT NULL
        FROM path p JOIN openmettle.message_turns t ON t.message_id=p.id WHERE p.id=$3::uuid"
    ))
    .bind(chat.id)
    .bind(head)
    .bind(target)
    .fetch_optional(c)
    .await?
    .ok_or(HIDDEN)
}

#[derive(Clone, Copy)]
pub struct Fork<'a> {
    pub branch: &'a str,
    pub ancestor: &'a str,
}

/// With no source, create the first empty managed root of an older conversation.
pub async fn create_branch(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    chat: Conversation<'_>,
    source: Option<Fork<'_>>,
) -> Result<WriteOutcome, StoreError> {
    let ctx = AuditContext {
        reason: "create branch",
        ..*ctx
    };
    if let Some(fork) = source {
        store::uuid(fork.branch, "branch_id")?;
        store::uuid(fork.ancestor, "fork_message_id")?;
    }
    let (branch, fork) = source.map(|s| (s.branch, s.ancestor)).unzip();
    let normalized = identity(
        b"branch.create",
        &[
            chat.id.as_bytes(),
            branch.unwrap_or("").as_bytes(),
            fork.unwrap_or("").as_bytes(),
        ],
    );
    store::transact(c, &ctx, async |tx| {
        let c = tx.connection()?;
        let (_, archived, post_lock_ctx, project) =
            write_access(c, &ctx, chat, Action::Write).await?;
        let change = Change {
            action: "branch.create",
            target_kind: "branch",
            target_id: None,
            details: json!({"conversation_id": chat.id, "request_digest": projects::hex(&digest(&normalized))}),
        };
        let result = store::record(c, &post_lock_ctx, &change).await?;
        if matches!(result, WriteOutcome::Applied { .. }) {
            if archived { return Err(projects::ARCHIVED); }
            if let Some(source) = source {
                let head = lock_head(c, chat, source.branch).await?;
                ancestor(c, chat, head.as_deref(), source.ancestor).await?;
            }
            insert_branch(c, chat, Some(result.target_id()), branch, fork).await?;
        }
        verify_write_access(c, &post_lock_ctx, chat, project.as_deref(), Action::Write).await?;
        Ok(result)
    }).await
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    Text(String),
    Attachment(String),
}

#[derive(Clone, Copy, Serialize)]
pub struct UserInput<'a> {
    pub id: &'a str,
    pub parts: &'a [Part],
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation<'a> {
    Append(UserInput<'a>),
    Edit {
        target: &'a str,
        replacement: UserInput<'a>,
    },
    Retry {
        target: &'a str,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct RunTarget {
    pub branch_id: String,
    pub input_message_id: String,
    pub attachment_revisions: Vec<String>,
}

/// Only visible active or retained revisions reach the caller. Only active ones supply bytes.
async fn revision_is_active(
    c: &mut PgConnection,
    actor: &Principal,
    scope: &str,
    id: &str,
    now: i64,
) -> Result<bool, StoreError> {
    store::uuid(id, "artifact_revision_id")?;
    let (artifact, active): (String, bool) = sqlx::query_as(
        "SELECT artifact_id::text, state='active' FROM openmettle.artifact_revisions
        WHERE scope_id=$1::uuid AND id=$2::uuid AND state IN ('active','retained')",
    )
    .bind(scope)
    .bind(id)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(HIDDEN)?;
    // The conversation check already established this exact scope. This resource check
    // also works for a worker, which cannot read project_settings.
    let resource = projects::hydrate_resource(c, ResourceKind::Artifact, &artifact, now)
        .await?
        .ok_or(HIDDEN)?;
    store::check(authorize_resource(actor, &resource, Action::Read))?;
    Ok(active)
}

pub(crate) async fn readable_revision(
    c: &mut PgConnection,
    actor: &Principal,
    scope: &str,
    id: &str,
    now: i64,
) -> Result<(), StoreError> {
    if revision_is_active(c, actor, scope, id, now).await? {
        Ok(())
    } else {
        Err(StoreError::Conflict("artifact revision is retained"))
    }
}

pub(crate) fn validate_parts(parts: &[Part], user: bool) -> Result<(), StoreError> {
    let mut bytes = 0;
    let mut attachment = false;
    if parts.len() > 128 {
        return Err(StoreError::InvalidInput("message parts"));
    }
    for part in parts {
        match part {
            Part::Text(s) if !s.contains('\0') => bytes += s.len(),
            Part::Text(_) => return Err(StoreError::InvalidInput("message text")),
            Part::Attachment(id) => {
                store::uuid(id, "artifact_revision_id")?;
                attachment = true;
            }
        }
    }
    if bytes > 65536 || (user && bytes == 0 && !attachment) {
        return Err(StoreError::InvalidInput("message text"));
    }
    Ok(())
}

async fn insert_message(
    c: &mut PgConnection,
    chat: Conversation<'_>,
    input: &str,
    parent: Option<&str>,
) -> Result<(), StoreError> {
    store::uuid(input, "message_id")?;
    if Some(input) == parent {
        return Err(StoreError::Conflict("message already exists"));
    }
    sqlx::query(
        "INSERT INTO openmettle.messages (scope_id,conversation_id,id,parent_message_id)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid)",
    )
    .bind(chat.scope)
    .bind(chat.id)
    .bind(input)
    .bind(parent)
    .execute(c)
    .await
    .map_err(|e| store::unique(e, "messages_pkey", "message already exists"))?;
    Ok(())
}

async fn publish(
    c: &mut PgConnection,
    chat: Conversation<'_>,
    branch: &str,
    parent: Option<&str>,
    id: &str,
    parts: &[Part],
) -> Result<(), StoreError> {
    for (i, p) in parts.iter().enumerate() {
        let (kind, text, revision) = match p {
            Part::Text(s) => ("text", Some(s), None),
            Part::Attachment(r) => ("attachment", None, Some(r)),
        };
        sqlx::query(
            "INSERT INTO openmettle.message_parts
            (scope_id,conversation_id,message_id,ordinal,kind,text_value,artifact_revision_id)
            VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7::uuid)",
        )
        .bind(chat.scope)
        .bind(chat.id)
        .bind(id)
        .bind(i as i32)
        .bind(kind)
        .bind(text)
        .bind(revision)
        .execute(&mut *c)
        .await?;
    }
    let n = sqlx::query(
        "UPDATE openmettle.branch_heads SET head_message_id=$2::uuid
        WHERE branch_id=$1::uuid AND head_message_id IS NOT DISTINCT FROM $3::uuid",
    )
    .bind(branch)
    .bind(id)
    .bind(parent)
    .execute(c)
    .await?
    .rows_affected();
    if n != 1 {
        return Err(StoreError::Conflict(HEAD_MISMATCH));
    }
    Ok(())
}

/// Apply the graph half of a submission in the caller's admission transaction.
/// Commit only after successful admission. On any error or replay roll back the transaction.
pub async fn prepare_turn(
    tx: &mut WriteTransaction<'_>,
    ctx: &AuditContext<'_>,
    chat: Conversation<'_>,
    branch: &str,
    expected_head: Option<&str>,
    op: Operation<'_>,
) -> Result<RunTarget, StoreError> {
    ctx.validate()?;
    if let Some(id) = expected_head {
        store::uuid(id, "expected_head_message_id")?;
    }
    let c = tx.connection()?;
    let (_, archived, post_lock_ctx, project) =
        write_access(c, ctx, chat, Action::RunExecute).await?;
    if archived {
        return Err(projects::ARCHIVED);
    }
    let head = lock_head(c, chat, branch).await?;
    let (actor, _, post_lock_ctx) = verify_write_access(
        c,
        &post_lock_ctx,
        chat,
        project.as_deref(),
        Action::RunExecute,
    )
    .await?;
    if head.as_deref() != expected_head {
        return Err(StoreError::Conflict(HEAD_MISMATCH));
    }
    let (destination, parent, input) = match op {
        Operation::Append(input) => {
            // Never wait on a run lock after taking the branch lock.
            let live: bool = sqlx::query_scalar("SELECT EXISTS (SELECT FROM openmettle.runs
                WHERE branch_id=$1::uuid AND state NOT IN ('succeeded','failed','cancelled','interrupted'))")
                .bind(branch).fetch_one(&mut *c).await?;
            if live {
                return Err(StoreError::Conflict("branch has live run"));
            }
            (branch.to_owned(), head, input)
        }
        Operation::Edit {
            target,
            replacement,
        } => {
            let (parent, user) = ancestor(c, chat, head.as_deref(), target).await?;
            if !user {
                return Err(StoreError::InvalidInput("edit target"));
            }
            (
                insert_branch(c, chat, None, Some(branch), parent.as_deref()).await?,
                parent,
                replacement,
            )
        }
        Operation::Retry { target } => {
            let (parent, user) = ancestor(c, chat, head.as_deref(), target).await?;
            let id = parent
                .filter(|_| !user)
                .ok_or(StoreError::InvalidInput("retry target"))?;
            let revisions: Vec<String> = sqlx::query_scalar("SELECT artifact_revision_id::text FROM
                openmettle.message_parts WHERE message_id=$1::uuid AND kind='attachment' ORDER BY ordinal")
                .bind(&id).fetch_all(&mut *c).await?;
            for revision in &revisions {
                readable_revision(c, &actor, chat.scope, revision, post_lock_ctx.now_ms).await?;
            }
            let branch_id = insert_branch(c, chat, None, Some(branch), Some(&id)).await?;
            let (fresh_actor, _, fresh_ctx) = verify_write_access(
                c,
                &post_lock_ctx,
                chat,
                project.as_deref(),
                Action::RunExecute,
            )
            .await?;
            for revision in &revisions {
                readable_revision(c, &fresh_actor, chat.scope, revision, fresh_ctx.now_ms).await?;
            }
            return Ok(RunTarget {
                branch_id,
                input_message_id: id,
                attachment_revisions: revisions,
            });
        }
    };
    validate_parts(input.parts, true)?;
    let attachment_revisions: Vec<String> = input
        .parts
        .iter()
        .filter_map(|p| match p {
            Part::Attachment(id) => Some(id.clone()),
            Part::Text(_) => None,
        })
        .collect();
    for revision in &attachment_revisions {
        readable_revision(c, &actor, chat.scope, revision, post_lock_ctx.now_ms).await?;
    }
    insert_message(c, chat, input.id, parent.as_deref()).await?;
    sqlx::query(
        "INSERT INTO openmettle.message_turns (scope_id,conversation_id,message_id,author_user_id)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid)",
    )
    .bind(chat.scope)
    .bind(chat.id)
    .bind(input.id)
    .bind(ctx.actor_user_id)
    .execute(&mut *c)
    .await?;
    publish(
        c,
        chat,
        &destination,
        parent.as_deref(),
        input.id,
        input.parts,
    )
    .await?;
    let (fresh_actor, _, fresh_ctx) = verify_write_access(
        c,
        &post_lock_ctx,
        chat,
        project.as_deref(),
        Action::RunExecute,
    )
    .await?;
    for revision in &attachment_revisions {
        readable_revision(c, &fresh_actor, chat.scope, revision, fresh_ctx.now_ms).await?;
    }
    Ok(RunTarget {
        branch_id: destination,
        input_message_id: input.id.to_owned(),
        attachment_revisions,
    })
}

/// Worker primitive for the fenced settlement transaction. Derive the graph edges from the
/// locked run. PostgreSQL computes the byte count after canonicalizing JSONB.
pub struct Answer<'a> {
    pub id: &'a str,
    pub parts: &'a [Part],
    pub reasoning: Option<&'a [serde_json::Map<String, serde_json::Value>]>,
    pub input_count: Option<i64>,
    pub output_count: Option<i64>,
    pub stop_reason: Option<&'a str>,
}

pub async fn publish_answer(
    tx: &mut WriteTransaction<'_>,
    lease: &super::leases::Lease<'_>,
    answer: &Answer<'_>,
) -> Result<(), super::leases::LeaseError> {
    use super::leases::{self, Fence};
    let c = tx.connection().map_err(StoreError::from)?;
    leases::lock(c, lease, Fence::Step).await?;
    publish_locked_answer(c, lease.scope_id, lease.run_id, answer).await?;
    Ok(())
}

async fn has_stop_reason(c: &mut PgConnection) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
               FROM pg_catalog.pg_attribute
              WHERE attrelid = to_regclass('openmettle.message_turns')
                AND attname = 'stop_reason'
                AND NOT attisdropped
         )",
    )
    .fetch_one(c)
    .await?)
}

pub(super) async fn publish_locked_answer(
    c: &mut PgConnection,
    scope: &str,
    run: &str,
    answer: &Answer<'_>,
) -> Result<(), StoreError> {
    validate_parts(answer.parts, false)?;
    if answer.reasoning.is_some_and(|r| r.len() > 128)
        || answer.stop_reason.is_some_and(|r| r != "limit")
        || [answer.input_count, answer.output_count]
            .into_iter()
            .flatten()
            .any(|n| n < 0)
    {
        return Err(StoreError::InvalidInput("assistant turn"));
    }
    let has_stop_reason = has_stop_reason(c).await?;
    if !has_stop_reason && answer.stop_reason.is_some() {
        return Err(StoreError::InvalidInput("assistant turn"));
    }
    let row = sqlx::query(
        "SELECT conversation_id::text, branch_id::text, input_message_id::text, actor_user_id::text,
                actor_approval_id::text, floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
         FROM openmettle.runs
         WHERE scope_id=$1::uuid AND id=$2::uuid",
    )
    .bind(scope)
    .bind(run)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(HIDDEN)?;
    let chat = Conversation {
        scope,
        id: row.try_get("conversation_id")?,
    };
    let branch: &str = row.try_get("branch_id")?;
    let input: &str = row.try_get("input_message_id")?;
    if lock_head(c, chat, branch).await?.as_deref() != Some(input) {
        return Err(StoreError::Conflict(HEAD_MISMATCH));
    }
    if answer
        .parts
        .iter()
        .any(|part| matches!(part, Part::Attachment(_)))
    {
        let now = row.try_get("now_ms")?;
        let actor = store::hydrate_worker_principal(
            c,
            row.try_get("actor_user_id")?,
            row.try_get("actor_approval_id")?,
            now,
        )
        .await?;
        let actor = super::require(actor.as_ref()).map_err(StoreError::Denied)?;
        for part in answer.parts {
            if let Part::Attachment(id) = part {
                readable_revision(c, actor, scope, id, now).await?;
            }
        }
    }
    insert_message(c, chat, answer.id, Some(input)).await?;
    let blocks = answer
        .reasoning
        .filter(|blocks| !blocks.is_empty())
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| StoreError::InvalidInput("reasoning blocks"))?;
    let inserted = if has_stop_reason {
        sqlx::query(
            "INSERT INTO openmettle.message_turns
            (scope_id,conversation_id,message_id,run_id,reasoning_blocks,reasoning_bytes,input_count,output_count,stop_reason)
            SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::jsonb,coalesce(octet_length($5::jsonb::text),0),$6,$7,$8
            WHERE coalesce(octet_length($5::jsonb::text),0)<=65536",
        )
        .bind(scope)
        .bind(chat.id)
        .bind(answer.id)
        .bind(run)
        .bind(blocks)
        .bind(answer.input_count)
        .bind(answer.output_count)
        .bind(answer.stop_reason)
        .execute(&mut *c)
        .await?
        .rows_affected()
    } else {
        sqlx::query(
            "INSERT INTO openmettle.message_turns
            (scope_id,conversation_id,message_id,run_id,reasoning_blocks,reasoning_bytes,input_count,output_count)
            SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::jsonb,coalesce(octet_length($5::jsonb::text),0),$6,$7
            WHERE coalesce(octet_length($5::jsonb::text),0)<=65536",
        )
        .bind(scope)
        .bind(chat.id)
        .bind(answer.id)
        .bind(run)
        .bind(blocks)
        .bind(answer.input_count)
        .bind(answer.output_count)
        .execute(&mut *c)
        .await?
        .rows_affected()
    };
    if inserted != 1 {
        return Err(StoreError::InvalidInput("reasoning blocks"));
    }
    publish(c, chat, branch, Some(input), answer.id, answer.parts).await
}

#[derive(PartialEq, Eq)]
pub enum PartContent {
    Available(Part),
    RetainedAttachment(String),
    UnavailableAttachment,
}

pub struct VisiblePart {
    pub id: String,
    pub ordinal: i32,
    pub value: PartContent,
}
pub struct HistoryTurn {
    pub parent_message_id: Option<String>,
    pub author_user_id: Option<String>,
    pub stop_reason: Option<String>,
    pub metadata: crate::model_config::PathTurn,
    pub parts: Vec<VisiblePart>,
}
pub struct History {
    pub head: Option<String>,
    /// Newest first, with visible parts in ordinal order within each turn.
    pub turns: Vec<HistoryTurn>,
}

/// Read the immutable path selected by one observation of the head. A legacy branch
/// returns None. An empty managed root returns Some with an empty path.
pub async fn history(
    c: &mut PgConnection,
    actor: &Principal,
    chat: Conversation<'_>,
    branch: &str,
    now: i64,
) -> Result<Option<History>, StoreError> {
    let Some(head) = history_head(c, actor, chat, branch, now).await? else {
        return Ok(None);
    };
    let turns = path_turns(c, actor, chat, head.as_deref(), i32::MAX, now).await?;
    Ok(Some(History { head, turns }))
}

/// Outer None denotes a legacy branch. An inner None is an empty managed head.
pub(crate) async fn history_head(
    c: &mut PgConnection,
    actor: &Principal,
    chat: Conversation<'_>,
    branch: &str,
    now: i64,
) -> Result<Option<Option<String>>, StoreError> {
    let resource =
        projects::read_resource(c, actor, ResourceKind::Conversation, chat.id, now).await?;
    if resource.scope_id != chat.scope {
        return Err(HIDDEN);
    }
    store::uuid(branch, "branch_id")?;
    let (managed, head): (bool, Option<String>) = sqlx::query_as(
        "SELECT h.branch_id IS NOT NULL,h.head_message_id::text
        FROM openmettle.conversation_branches b LEFT JOIN openmettle.branch_heads h ON h.branch_id=b.id
        WHERE b.scope_id=$1::uuid AND b.conversation_id=$2::uuid AND b.id=$3::uuid",
    )
        .bind(chat.scope).bind(chat.id).bind(branch).fetch_optional(&mut *c).await?.ok_or(HIDDEN)?;
    Ok(managed.then_some(head))
}

// The caller authorizes the branch and supplies its head or a MAC-authenticated ancestor.
pub(crate) async fn path_turns(
    c: &mut PgConnection,
    actor: &Principal,
    chat: Conversation<'_>,
    start: Option<&str>,
    limit: i32,
    now: i64,
) -> Result<Vec<HistoryTurn>, StoreError> {
    use crate::model_config::PathTurn;
    let has_stop_reason = has_stop_reason(c).await?;
    let rows = sqlx::query(if has_stop_reason {
        concat!(
            path!("WHERE p.depth+1 < $3"),
            "SELECT p.id::text,p.parent_message_id::text,t.author_user_id::text,t.run_id::text,t.reasoning_bytes,t.input_count,
            t.output_count,t.stop_reason,r.snapshot_format,r.snapshot_version,r.config_snapshot FROM path p
            JOIN openmettle.message_turns t ON t.message_id=p.id LEFT JOIN openmettle.runs r ON r.id=t.run_id
            ORDER BY p.depth"
        )
    } else {
        concat!(
            path!("WHERE p.depth+1 < $3"),
            "SELECT p.id::text,p.parent_message_id::text,t.author_user_id::text,t.run_id::text,t.reasoning_bytes,t.input_count,
            t.output_count,NULL::text AS stop_reason,r.snapshot_format,r.snapshot_version,r.config_snapshot FROM path p
            JOIN openmettle.message_turns t ON t.message_id=p.id LEFT JOIN openmettle.runs r ON r.id=t.run_id
            ORDER BY p.depth"
        )
    })
        .bind(chat.id).bind(start).bind(limit).fetch_all(&mut *c).await?;
    let mut turns = Vec::with_capacity(rows.len());
    for r in rows {
        let config = if r.try_get::<Option<&str>, _>("snapshot_format")? == Some(SNAPSHOT_FORMAT)
            && r.try_get::<Option<i32>, _>("snapshot_version")? == Some(SNAPSHOT_VERSION)
        {
            Some(
                serde_json::from_slice::<ConfigSnapshot>(r.try_get("config_snapshot")?)
                    .map_err(|_| StoreError::InvalidInput("stored configuration snapshot"))?
                    .effective,
            )
        } else {
            None
        };
        turns.push(HistoryTurn {
            parent_message_id: r.try_get("parent_message_id")?,
            author_user_id: r.try_get("author_user_id")?,
            stop_reason: r.try_get("stop_reason")?,
            metadata: PathTurn {
                message_id: r.try_get("id")?,
                run_id: r.try_get("run_id")?,
                reasoning_bytes: r.try_get::<i32, _>("reasoning_bytes")? as u32,
                input_count: r
                    .try_get::<Option<i64>, _>("input_count")?
                    .map(|v| v as u64),
                output_count: r
                    .try_get::<Option<i64>, _>("output_count")?
                    .map(|v| v as u64),
                reasoning_format: config.as_ref().and_then(|e| e.reasoning_format.clone()),
                profile: config.map(|e| e.profile),
            },
            parts: Vec::new(),
        });
    }
    let rows = sqlx::query(concat!(
        path!("WHERE p.depth+1 < $3"),
        "SELECT p.depth,v.id::text,v.ordinal,v.text_value,
        v.artifact_revision_id::text FROM path p JOIN openmettle.message_parts v ON v.message_id=p.id
        ORDER BY p.depth,v.ordinal"
    ))
    .bind(chat.id).bind(start).bind(limit).fetch_all(&mut *c).await?;
    for r in rows {
        let value = match r.try_get::<Option<String>, _>("artifact_revision_id")? {
            None => PartContent::Available(Part::Text(r.try_get("text_value")?)),
            Some(id) => match revision_is_active(c, actor, chat.scope, &id, now).await {
                Ok(true) => PartContent::Available(Part::Attachment(id)),
                Ok(false) => PartContent::RetainedAttachment(id),
                Err(StoreError::Denied(DenialReason::NotFound)) => {
                    PartContent::UnavailableAttachment
                }
                Err(error) => return Err(error),
            },
        };
        let depth = r.try_get::<i32, _>("depth")? as usize;
        let turn = turns
            .get_mut(depth)
            .ok_or(StoreError::InvalidInput("stored message path"))?;
        turn.parts.push(VisiblePart {
            id: r.try_get("id")?,
            ordinal: r.try_get("ordinal")?,
            value,
        });
    }
    Ok(turns)
}

/// The run's immutable capability requirements can be read before touching conversation data.
pub(crate) async fn worker_config(
    c: &mut PgConnection,
    claim: &runs::ClaimedRun,
) -> Result<ConfigSnapshot, StoreError> {
    let invalid = || StoreError::InvalidInput("stored configuration snapshot");
    let bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT config_snapshot FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid
         AND claim_token=$3::uuid AND snapshot_format=$4 AND snapshot_version=$5",
    )
    .bind(&claim.scope_id)
    .bind(&claim.run_id)
    .bind(&claim.claim_token)
    .bind(SNAPSHOT_FORMAT)
    .bind(SNAPSHOT_VERSION)
    .fetch_optional(c)
    .await?
    .ok_or_else(invalid)?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

pub(crate) struct WorkerPrompt {
    pub actor: String,
    pub history: Vec<crate::provider_http::inference::History>,
}

/// After the leased authority check, read only the path anchored by the admitted input.
pub(crate) async fn worker_prompt(
    c: &mut PgConnection,
    claim: &runs::ClaimedRun,
    config: &ConfigSnapshot,
    catalog: &crate::model_config::Catalog,
    artifacts: Option<&crate::artifact_fs::Store>,
) -> Result<WorkerPrompt, StoreError> {
    use crate::provider_http::inference::{History, Reasoning};
    let invalid = || StoreError::InvalidInput("stored conversation snapshot");
    let r = sqlx::query("SELECT r.actor_user_id::text,r.conversation_id::text,r.input_message_id::text,
          r.input_snapshot,
          floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now_ms
        FROM openmettle.runs r JOIN openmettle.branch_heads h USING (scope_id, conversation_id, branch_id)
        WHERE r.id=$1::uuid AND r.scope_id=$2::uuid AND r.claim_token=$3::uuid
          AND h.head_message_id=r.input_message_id")
        .bind(&claim.run_id).bind(&claim.scope_id).bind(&claim.claim_token)
        .fetch_optional(&mut *c).await?.ok_or_else(invalid)?;
    let input: snapshot::InputSnapshot =
        serde_json::from_slice(r.try_get("input_snapshot")?).map_err(|_| invalid())?;
    let target = catalog.target(&config.effective).map_err(|_| invalid())?;
    if config.effective.reasoning_format != target.reasoning_format
        || config.effective.usable_input().is_none()
    {
        return Err(invalid());
    }
    let now = r.try_get("now_ms")?;
    let actor_id: String = r.try_get("actor_user_id")?;
    let actor = store::hydrate_worker_principal(c, &actor_id, &claim.actor_approval_id, now)
        .await?
        .ok_or(HIDDEN)?;
    let chat = Conversation {
        scope: &claim.scope_id,
        id: r.try_get("conversation_id")?,
    };
    let conversation = projects::hydrate_resource(c, ResourceKind::Conversation, chat.id, now)
        .await?
        .ok_or(HIDDEN)?;
    store::check(authorize_resource(
        &actor,
        &conversation,
        Action::RunExecute,
    ))?;
    let start: &str = r.try_get("input_message_id")?;
    // One extra ancestor detects an incomplete pin without reading an unbounded legacy path.
    let turns = path_turns(
        c,
        &actor,
        chat,
        Some(start),
        input.path.len() as i32 + 1,
        now,
    )
    .await?;
    if input.path.len() != turns.len()
        || turns.first().is_none_or(|t| t.author_user_id.is_none())
        || turns.last().is_some_and(|t| t.parent_message_id.is_some())
    {
        return Err(invalid());
    }
    let mut history = Vec::with_capacity(turns.len());
    let mut remaining_image_bytes = 1536 * 1024;
    for (turn, pin) in turns.into_iter().zip(input.path).rev() {
        let meta = turn.metadata;
        if meta.message_id != pin.message_id {
            return Err(invalid());
        }
        let mut text = Vec::new();
        let mut pins = pin.attachments.iter();
        let mut image = None;
        for part in turn.parts {
            if let PartContent::Available(Part::Text(s)) = part.value {
                // The qualified image adapter encodes text followed by one image.
                if image.is_some() && !s.is_empty() {
                    return Err(StoreError::InvalidInput("attachment order"));
                }
                text.push(s);
                continue;
            }
            let attachment = pins
                .next()
                .filter(|a| a.ordinal == part.ordinal)
                .ok_or_else(invalid)?;
            match (attachment.revision_id.as_deref(), part.value) {
                (Some(id), PartContent::Available(Part::Attachment(current))) => {
                    if id != current || image.is_some() || turn.author_user_id.is_none() {
                        return Err(invalid());
                    }
                    image = Some(
                        worker_image(
                            c,
                            chat.scope,
                            id,
                            artifacts.ok_or_else(invalid)?,
                            &mut remaining_image_bytes,
                        )
                        .await?,
                    );
                }
                // Historical revisions may have lost access since admission. Never send their ID.
                _ if meta.message_id != start => (),
                _ => return Err(HIDDEN),
            }
        }
        if pins.next().is_some() {
            return Err(invalid());
        }
        if turn.author_user_id.is_some() {
            let text = text.concat();
            if let Some((media, bytes)) = image {
                history.push(History::UserImage { text, media, bytes });
            } else if !text.is_empty() {
                history.push(History::User(text));
            }
        } else {
            let reasoning = if let Some(rule) = meta
                .replay_rule(target)
                .filter(|_| pin.replay_reasoning && meta.reasoning_bytes > 0)
            {
                let json: String = sqlx::query_scalar(
                    "SELECT reasoning_blocks::text FROM openmettle.message_turns
                    WHERE scope_id=$1::uuid AND conversation_id=$2::uuid AND message_id=$3::uuid",
                )
                .bind(chat.scope)
                .bind(chat.id)
                .bind(&meta.message_id)
                .fetch_one(&mut *c)
                .await?;
                Some(Reasoning {
                    source: Box::new(rule.source.clone()),
                    blocks: serde_json::from_str(&json).map_err(|_| invalid())?,
                    storage_bytes: meta.reasoning_bytes as usize,
                })
            } else {
                None
            };
            if !text.is_empty() || reasoning.is_some() {
                history.push(History::Assistant {
                    parts: text,
                    reasoning,
                    calls: vec![],
                });
            }
        }
    }
    Ok(WorkerPrompt {
        actor: actor_id,
        history,
    })
}

async fn worker_image(
    c: &mut PgConnection,
    scope: &str,
    id: &str,
    store: &crate::artifact_fs::Store,
    remaining: &mut i64,
) -> Result<(crate::provider_http::inference::ImageType, Vec<u8>), StoreError> {
    use crate::provider_http::inference::ImageType;
    use http_body_util::BodyExt;
    let (reservation, size, media): (String, i64, String) = sqlx::query_as(
        "SELECT reservation_id::text,size_bytes,media_type FROM openmettle.artifact_revisions
         WHERE scope_id=$1::uuid AND id=$2::uuid AND state='active'",
    )
    .bind(scope)
    .bind(id)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(HIDDEN)?;
    let media = match media.as_str() {
        "image/jpeg" => ImageType::Jpeg,
        "image/png" => ImageType::Png,
        _ => return Err(StoreError::InvalidInput("unsupported attachment")),
    };
    // The inference transport bounds the whole request to 2 MiB after base64 encoding.
    if !(1..=*remaining).contains(&size) {
        return Err(StoreError::InvalidInput("attachment size"));
    }
    *remaining -= size;
    // The caller's connection, never a second one from the same pool (ADR 0043).
    let body = store
        .read_on(c, &reservation, size, 0, size as u64)
        .await
        .map_err(|_| HIDDEN)?;
    Ok((
        media,
        body.collect()
            .await
            .map_err(|_| HIDDEN)?
            .to_bytes()
            .to_vec(),
    ))
}
