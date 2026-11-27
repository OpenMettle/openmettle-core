//! ADR 0036 conversation and branch operations.
use super::{pagination::Page, *};
use crate::{
    auth_config::CursorKeys,
    authz::{
        branches::{self, Conversation, Fork, HistoryTurn, Part, PartContent},
        store::WriteOutcome,
    },
    model_config::Catalog,
};
use axum::extract::{FromRequestParts, Path};
use sqlx::Row;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    scope_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRoot {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Child {
    source_branch_id: String,
    fork_message_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BranchCreate {
    Child(Child),
    Root(EmptyRoot),
}

enum Content {
    Empty,
    Create(Create),
    Branch(BranchCreate),
    Preview(submission::Proposal),
    Run(submission::Request),
}
fn outcome<T>(write: WriteOutcome<T>) -> (StatusCode, T) {
    match write {
        WriteOutcome::Applied { target_id } => (StatusCode::CREATED, target_id),
        WriteOutcome::Replayed { target_id } => (StatusCode::OK, target_id),
    }
}

impl Api {
    pub(super) async fn conversation_operation(
        &self,
        op: Op,
        parts: &mut Parts,
        session: Session,
        key: Option<&str>,
        body: &[u8],
    ) -> Result<Response, Problem> {
        let list = matches!(
            op,
            Op::ListBranches
                | Op::ListMessages
                | Op::ListConversations
                | Op::ListModels
                | Op::ListPresets
        );
        if !list && parts.uri.query().is_some() {
            return Err(INVALID);
        }
        let preset = if op == Op::GetPreset {
            let Path(id) = Path::<String>::from_request_parts(parts, &())
                .await
                .map_err(|_| INVALID)?;
            if !crate::model_config::name(&id) {
                return Err(INVALID);
            }
            Some(id)
        } else {
            None
        };
        let target = if op.targeted() {
            path_id(parts, 3)?
        } else {
            ""
        };
        let branch = if matches!(
            op,
            Op::GetBranch | Op::ListMessages | Op::PreviewConfiguration
        ) {
            path_id(parts, 5)?
        } else {
            ""
        };
        let content = match op {
            Op::CreateRun => Content::Run(submission::Request::read(body)?),
            Op::CreateConversation => Content::Create(parse_unique(body)?),
            Op::CreateBranch => Content::Branch(parse_unique(body)?),
            Op::PreviewConfiguration => Content::Preview(submission::Proposal::read(body)?),
            _ => Content::Empty,
        };
        let catalog = parts.extensions.get::<Arc<Catalog>>().map(Arc::as_ref);
        let limits = parts.extensions.get::<authz::runs::AdmissionLimits>();
        let keys = parts.extensions.get::<Arc<CursorKeys>>();
        if (op == Op::CreateRun && limits.is_none())
            || (matches!(op, Op::CancelRun | Op::CreateRun) && keys.is_none())
        {
            return Err(PROVISIONING);
        }
        let context = self.authenticate(&session).await?;
        if op == Op::CancelRun {
            crate::telemetry::record_request_run_id(&parts.extensions, target);
        }
        let call = Call {
            op,
            context: &context,
            target,
            key: key.unwrap_or_default(),
            reason: None,
        };
        if matches!(op, Op::CancelRun | Op::CreateRun) {
            let (status, run, verified_now_ms) = match &content {
                Content::Run(request) => {
                    let limits = limits.ok_or(PROVISIONING)?;
                    self.with_connection(async |c| {
                        submission::submit(c, call, request, limits, catalog).await
                    })
                    .await?
                }
                _ => {
                    self.with_connection(async |c| submission::cancel(c, call).await)
                        .await?
                }
            };
            crate::telemetry::record_request_run_id(&parts.extensions, &run);
            return self
                .run_response(
                    &context,
                    keys.ok_or(PROVISIONING)?,
                    &run,
                    status,
                    verified_now_ms,
                )
                .await;
        }

        let page = list
            .then(|| Page::new(parts, context.user_id(), op))
            .transpose()?;
        self.with_connection(async |c| {
            let actor = principal(c, &context).await?;
            let now = context.observed_ms();
            match (op, content) {
                (Op::ListModels | Op::ListPresets | Op::GetPreset, _) => {
                    catalog::describe(c, &actor, op, preset.as_deref(), catalog, page.as_ref()).await
                }
                (_, Content::Create(new)) => {
                    let scope = new.scope_id.as_deref().unwrap_or(&actor.personal_scope_id);
                    let key = request_key(op, scope, call.key);
                    let audit = AuditContext { request_key: &key, ..call.audit() };
                    let (status, root) = outcome(branches::create_conversation(c, &audit, scope).await?);
                    Ok(reply(status, json!({
                        "conversation_id": root.conversation_id, "branch_id": root.branch_id, "scope_id": scope
                    })))
                }
                (Op::ListConversations, _) => conversations(c, &actor, page.as_ref().ok_or(INTERNAL)?, now).await,
                (Op::ListMessages, _) => {
                    let page = page.as_ref().ok_or(INTERNAL)?;
                    let mut tx = crate::authz::store::begin(c).await?;
                    let result = async {
                        let conn = tx.connection()?;
                        crate::restore::require_open_gate(conn).await?;
                        let view = projects::read_resource(conn, &actor, ResourceKind::Conversation, target, now).await?;
                        let chat = Conversation { id: target, scope: &view.scope_id };
                        messages(conn, &actor, chat, branch, page, now).await
                    }
                    .await;
                    let _ = tx.rollback().await;
                    result
                }
                (_, content) => {
                    let view = projects::read_resource(c, &actor, ResourceKind::Conversation, target, now).await?;
                    let chat = Conversation { id: target, scope: &view.scope_id };
                    match (op,content) {
                        (_, Content::Branch(new)) => {
                            let source = match &new {
                                BranchCreate::Child(child) => Some(Fork {
                                    branch: &child.source_branch_id, ancestor: &child.fork_message_id,
                                }),
                                BranchCreate::Root(_) => None,
                            };
                            let key = request_key(op, target, call.key);
                            let audit = AuditContext { request_key: &key, ..call.audit() };
                            let (status, id) = outcome(branches::create_branch(c, &audit, chat, source).await?);
                            Ok(reply(status, select_branch(c, chat, &id).await?))
                        }
                        (Op::GetBranch, _) => Ok(reply(StatusCode::OK, select_branch(c, chat, branch).await?)),
                        (Op::ListBranches, _) => branch_page(c, chat, page.as_ref().ok_or(INTERNAL)?).await,
                        (_, Content::Preview(proposal)) => submission::preview(c, call, &actor, &view, branch, catalog, &proposal).await,
                        _ => Err(INTERNAL),
                    }
                }
            }
        }).await
    }
}

type Position = (String, String);
async fn conversations(
    c: &mut PgConnection,
    actor: &Principal,
    page: &Page<'_>,
    now: i64,
) -> Result<Response, Problem> {
    let scope = page.scope.unwrap_or(&actor.personal_scope_id);
    let mut after: Option<Position> = page.position(scope)?;
    let mut items = Vec::new();
    let mut last = None;
    // Scan bounded keyset batches. A private row must never consume a visible page slot.
    loop {
        let rows: Vec<(String,String)> = sqlx::query_as(
            "SELECT c.id::text, to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
             FROM openmettle.conversations c WHERE c.scope_id=$1::uuid
               AND ($2::timestamptz IS NULL OR (c.created_at,c.id)>($2::timestamptz,$3::uuid))
               AND (c.owner_user_id=$4::uuid OR EXISTS (
                   SELECT FROM openmettle.grant_assignments g
                   WHERE g.scope_id=c.scope_id AND g.target_kind='conversation' AND g.target_id=c.id))
             ORDER BY c.created_at,c.id LIMIT $5",
        )
        .bind(scope)
        .bind(after.as_ref().map(|p| &p.0))
        .bind(after.as_ref().map(|p| &p.1))
        .bind(&actor.user_id)
        .bind((page.limit+1) as i64)
        .fetch_all(&mut *c).await?;
        let end = rows.len() <= page.limit;
        for (id, time) in rows {
            after = Some((time, id.clone()));
            match projects::read_resource(c, actor, ResourceKind::Conversation, &id, now).await {
                Ok(view) => {
                    if items.len() == page.limit {
                        return page.finish(items, scope, last);
                    }
                    items.push(resource_json(ResourceKind::Conversation, &id, &view)?);
                    last = after.clone();
                }
                Err(StoreError::Denied(authz::DenialReason::NotFound) | StoreError::NotFound) => (),
                Err(e) => return Err(e.into()),
            }
        }
        if end {
            return page.finish(items, scope, None::<Position>);
        }
    }
}

macro_rules! branch_select {
    () => {
        "SELECT b.id::text,b.conversation_id::text,b.fork_message_id::text,
                h.parent_branch_id::text,h.head_message_id::text,h.branch_id IS NOT NULL AS managed,
                (extract(epoch FROM b.created_at)*1000000)::bigint AS created_us
         FROM openmettle.conversation_branches b LEFT JOIN openmettle.branch_heads h ON h.branch_id=b.id
         WHERE b.scope_id=$1::uuid AND b.conversation_id=$2::uuid "
    };
}
fn branch_json(row: &sqlx::postgres::PgRow) -> Result<Value, Problem> {
    Ok(json!({
        "branch_id": row.get::<&str,_>("id"),
        "conversation_id": row.get::<&str,_>("conversation_id"),
        "history_available": row.get::<bool,_>("managed"),
        "fork_message_id": row.get::<Option<&str>,_>("fork_message_id"),
        "parent_branch_id": row.get::<Option<&str>,_>("parent_branch_id"),
        "head_message_id": row.get::<Option<&str>,_>("head_message_id"),
        "created_at": timestamp(row.get("created_us"))?,
    }))
}
async fn select_branch(
    c: &mut PgConnection,
    chat: Conversation<'_>,
    id: &str,
) -> Result<Value, Problem> {
    let row = sqlx::query(concat!(branch_select!(), "AND b.id=$3::uuid"))
        .bind(chat.scope)
        .bind(chat.id)
        .bind(id)
        .fetch_optional(c)
        .await?
        .ok_or(NOT_FOUND)?;
    branch_json(&row)
}
async fn branch_page(
    c: &mut PgConnection,
    chat: Conversation<'_>,
    page: &Page<'_>,
) -> Result<Response, Problem> {
    let after: Option<Position> = page.position(chat.scope)?;
    let rows = sqlx::query(concat!(
        branch_select!(),
        "AND ($3::timestamptz IS NULL OR (b.created_at,b.id)>($3::timestamptz,$4::uuid))
         ORDER BY b.created_at,b.id LIMIT $5"
    ))
    .bind(chat.scope)
    .bind(chat.id)
    .bind(after.as_ref().map(|p| &p.0))
    .bind(after.as_ref().map(|p| &p.1))
    .bind((page.limit + 1) as i64)
    .fetch_all(c)
    .await?;
    let items = rows
        .iter()
        .take(page.limit)
        .map(branch_json)
        .collect::<Result<Vec<_>, _>>()?;
    let next = if rows.len() > page.limit {
        let last = &rows[page.limit - 1];
        Some((
            timestamp(last.get("created_us"))?,
            last.get::<String, _>("id"),
        ))
    } else {
        None
    };
    page.finish(items, chat.scope, next)
}

async fn messages(
    c: &mut PgConnection,
    actor: &Principal,
    chat: Conversation<'_>,
    branch: &str,
    page: &Page<'_>,
    now: i64,
) -> Result<Response, Problem> {
    let head = branches::history_head(c, actor, chat, branch, now).await?;
    let after: Option<(String, String)> = page.position(chat.scope)?;
    let current = head.as_ref().and_then(Option::as_deref);
    if after
        .as_ref()
        .is_some_and(|(p, _)| Some(p.as_str()) != current)
    {
        return Err(pagination::INVALID_CURSOR);
    }
    let start = after.as_ref().map(|(_, next)| next.as_str()).or(current);
    let turns = branches::path_turns(c, actor, chat, start, page.limit as i32, now).await?;
    let next = turns
        .last()
        .and_then(|t| t.parent_message_id.as_deref())
        .zip(current)
        .map(|(next, pinned)| (pinned, next));
    let items = turns.iter().map(turn_json).collect();
    let mut response = page.finish(items, chat.scope, next)?;
    // Branch selection and the collection distinguish the legacy and empty cases.
    if head.is_none() {
        response.headers_mut().insert(
            "openmettle-history-available",
            HeaderValue::from_static("false"),
        );
    }
    Ok(response)
}
pub(super) fn decimal(n: Option<u64>) -> Option<String> {
    n.map(|n| n.to_string())
}
fn turn_json(t: &HistoryTurn) -> Value {
    let parts = t
        .parts
        .iter()
        .filter_map(|p| {
            let mut v = match &p.value {
                PartContent::Available(Part::Text(text)) => json!({"kind":"text","text":text}),
                PartContent::Available(Part::Attachment(id)) => {
                    json!({"kind":"attachment","revision_id":id,"state":"active"})
                }
                PartContent::RetainedAttachment(id) => {
                    json!({"kind":"attachment","revision_id":id,"state":"retained"})
                }
                PartContent::UnavailableAttachment => return None,
            };
            v["part_id"] = json!(p.id);
            Some(v)
        })
        .collect::<Vec<_>>();
    json!({"message_id":t.metadata.message_id,"parent_message_id":t.parent_message_id,"role":if t.author_user_id.is_some(){"user"}else{"assistant"},
        "parts":parts,"run_id":t.metadata.run_id,"input_count":decimal(t.metadata.input_count),"output_count":decimal(t.metadata.output_count),"stop_reason":t.stop_reason})
}
