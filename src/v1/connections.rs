//! Authenticated `/v1/connections*` routes for external connection lifecycle (ADR 0045).
//!
//! Never returns access tokens, refresh tokens, ciphertexts, or encryption key identifiers on any
//! response. `POST /v1/connections/{connection_id}/authorize` is write-only and requires a mounted
//! [`VaultKeyRing`] (`503 provisioning` when unconfigured).

use super::{
    BODY, GranteeBody, INTERNAL, INVALID, Op, PROVISIONING, Problem, Session, grantee_json,
    no_content, pagination::Page, parse, parse_unique, principal,
    quotas::parse_canonical_timestamp, reply, request_key, store_problem, timestamp,
};
use crate::{
    authz::store::{AuditContext, StoreError, WriteOutcome},
    vault::{
        self, AuthorizeConnectionInput, ConnectionView, CreateConnectionInput, VaultError,
        VaultKeyRing,
    },
};
use axum::{
    http::{StatusCode, request::Parts},
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateConnectionBody {
    scope_id: Option<String>,
    provider_kind: String,
    account_id: String,
    origin: String,
    allowed_scopes: Vec<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeConnectionBody {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    granted_scopes: Vec<String>,
    #[serde(default)]
    expires_at: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionShareBody {
    grantee: GranteeBody,
    access: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeConnectionShareBody {
    grantee: GranteeBody,
    reason: Option<String>,
}

fn validate_optional_reason(reason: Option<&str>) -> Result<(), Problem> {
    if reason.is_some_and(|r| !crate::runs::bounded(r, 512)) {
        return Err(BODY);
    }
    Ok(())
}

fn vault_problem(error: VaultError) -> Problem {
    match error {
        VaultError::Store(e) => store_problem(e),
        VaultError::InvalidSecret | VaultError::ScopeWidening => INVALID,
        VaultError::Configuration(_) | VaultError::UnknownKey => PROVISIONING,
        VaultError::Random
        | VaultError::Crypto
        | VaultError::RefreshRefused
        | VaultError::RefreshTransient => super::UNAVAILABLE,
    }
}

fn connection_json(view: &ConnectionView) -> Result<Value, Problem> {
    Ok(json!({
        "connection_id": view.connection_id,
        "scope_kind": view.scope_kind,
        "scope_id": view.scope_id,
        "project_id": view.project_id,
        "provider_kind": view.provider_kind,
        "account_id": view.account_id,
        "origin": view.origin,
        "allowed_scopes": view.allowed_scopes,
        "granted_scopes": view.granted_scopes,
        "state": view.state.as_str(),
        "expires_at": view.expires_at_us.map(timestamp).transpose()?,
        "has_refresh": view.has_refresh,
        "generation": view.credential_generation.to_string(),
        "revocation_generation": view.revocation_generation.to_string(),
        "share_revision": view.share_revision.to_string(),
        "created_at": timestamp(view.created_at_us)?,
        "updated_at": timestamp(view.updated_at_us)?,
        "disconnected_at": view.disconnected_at_us.map(timestamp).transpose()?,
        "can_manage": view.can_manage,
    }))
}

type Position = (String, String);

async fn list_connections(
    c: &mut PgConnection,
    actor: &crate::authz::Principal,
    page: &Page<'_>,
    now_ms: i64,
) -> Result<Response, Problem> {
    let scope = page.scope.unwrap_or(&actor.personal_scope_id);
    let mut after: Option<Position> = page.position(scope)?;
    let mut items = Vec::new();
    let mut last = None;
    loop {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT c.id::text,
                    to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
               FROM openmettle.external_connections c
              WHERE c.scope_id = $1::uuid
                AND ($2::timestamptz IS NULL OR (c.created_at, c.id) > ($2::timestamptz, $3::uuid))
              ORDER BY c.created_at, c.id
              LIMIT $4",
        )
        .bind(scope)
        .bind(after.as_ref().map(|p| &p.0))
        .bind(after.as_ref().map(|p| &p.1))
        .bind((page.limit + 1) as i64)
        .fetch_all(&mut *c)
        .await?;
        let end = rows.len() <= page.limit;
        for (id, created_at) in rows {
            after = Some((created_at, id.clone()));
            match vault::read_connection(c, actor, &id, now_ms).await {
                Ok(view) => {
                    if items.len() == page.limit {
                        return page.finish(items, scope, last);
                    }
                    items.push(connection_json(&view)?);
                    last = after.clone();
                }
                Err(
                    StoreError::Denied(crate::authz::DenialReason::NotFound) | StoreError::NotFound,
                ) => (),
                Err(e) => return Err(e.into()),
            }
        }
        if end {
            return page.finish(items, scope, None::<Position>);
        }
    }
}

impl super::Api {
    pub(super) async fn connection_operation(
        &self,
        op: Op,
        parts: &Parts,
        session: Session,
        target: &str,
        client_key: Option<&str>,
        body: &[u8],
    ) -> Result<Response, Problem> {
        if op != Op::ListConnections && parts.uri.query().is_some() {
            return Err(INVALID);
        }
        // Validate request body shape before touching the database.
        enum Parsed {
            None,
            Create(CreateConnectionBody),
            Authorize(AuthorizeConnectionBody, Option<String>),
            Share(crate::authz::Grantee, Option<String>),
            RevokeShare(crate::authz::Grantee, Option<String>),
        }
        let parsed = match op {
            Op::CreateConnection => {
                let req: CreateConnectionBody = parse_unique(body)?;
                validate_optional_reason(req.reason.as_deref())?;
                if let Some(scope) = req.scope_id.as_deref()
                    && crate::runs::uuid(scope).is_err()
                {
                    return Err(BODY);
                }
                vault::validate_provider_kind(&req.provider_kind).map_err(|_| BODY)?;
                vault::validate_account_id(&req.account_id).map_err(|_| BODY)?;
                vault::validate_endpoint_origin(&req.origin).map_err(|_| BODY)?;
                vault::normalize_scopes(&req.allowed_scopes, false).map_err(|_| BODY)?;
                Parsed::Create(req)
            }
            Op::AuthorizeConnection => {
                let req: AuthorizeConnectionBody = parse_unique(body)?;
                validate_optional_reason(req.reason.as_deref())?;
                vault::SecretText::new_access(&req.access_token).map_err(|_| BODY)?;
                if let Some(refresh) = req.refresh_token.as_deref() {
                    vault::SecretText::new_refresh(refresh).map_err(|_| BODY)?;
                }
                vault::normalize_scopes(&req.granted_scopes, false).map_err(|_| BODY)?;
                let expires_at = req
                    .expires_at
                    .as_deref()
                    .map(parse_canonical_timestamp)
                    .transpose()?;
                Parsed::Authorize(req, expires_at)
            }
            Op::ShareConnection => {
                let req: ConnectionShareBody = parse(body)?;
                validate_optional_reason(req.reason.as_deref())?;
                if req.access != "use" {
                    return Err(BODY);
                }
                let grantee = req.grantee.grantee(true)?;
                crate::authz::projects::grantee_input(&grantee).map_err(|_| BODY)?;
                Parsed::Share(grantee, req.reason)
            }
            Op::RevokeConnectionShare => {
                let req: RevokeConnectionShareBody = parse(body)?;
                validate_optional_reason(req.reason.as_deref())?;
                let grantee = req.grantee.grantee(true)?;
                crate::authz::projects::grantee_input(&grantee).map_err(|_| BODY)?;
                Parsed::RevokeShare(grantee, req.reason)
            }
            Op::ListConnections | Op::GetConnection | Op::DisconnectConnection => Parsed::None,
            _ => return Err(INTERNAL),
        };

        let vault_keys = parts.extensions.get::<Arc<VaultKeyRing>>().cloned();
        if op == Op::AuthorizeConnection && vault_keys.is_none() {
            return Err(PROVISIONING);
        }

        let context = self.authenticate(&session).await?;
        let now_ms = context.observed_ms();
        let page = (op == Op::ListConnections)
            .then(|| Page::new(parts, context.user_id(), op))
            .transpose()?;

        match (op, parsed) {
            (Op::ListConnections, _) => {
                let page = page.ok_or(INTERNAL)?;
                self.with_connection(async |c| {
                    let actor = principal(c, &context).await?;
                    list_connections(c, &actor, &page, now_ms).await
                })
                .await
            }
            (Op::GetConnection, _) => {
                let view = self
                    .database(async |c| {
                        let actor = principal(c, &context).await?;
                        vault::read_connection(c, &actor, target, now_ms).await
                    })
                    .await?;
                Ok(reply(StatusCode::OK, connection_json(&view)?))
            }
            (Op::CreateConnection, Parsed::Create(req)) => {
                let client_key = client_key.ok_or(INTERNAL)?;
                let (status, view) = self
                    .database(async |c| {
                        let actor = principal(c, &context).await?;
                        let scope_id = req.scope_id.as_deref().unwrap_or(&actor.personal_scope_id);
                        let derived_key = request_key(op, scope_id, client_key);
                        let audit = AuditContext {
                            actor_user_id: context.user_id(),
                            actor_approval_id: context.approval_id(),
                            now_ms,
                            request_key: &derived_key,
                            reason: req.reason.as_deref().unwrap_or(op.id()),
                        };
                        let outcome = vault::create_connection(
                            c,
                            &audit,
                            &CreateConnectionInput {
                                scope_id,
                                provider_kind: &req.provider_kind,
                                account_id: &req.account_id,
                                origin: &req.origin,
                                allowed_scopes: &req.allowed_scopes,
                            },
                        )
                        .await?;
                        let (status, id) = match outcome {
                            WriteOutcome::Applied { target_id } => (StatusCode::CREATED, target_id),
                            WriteOutcome::Replayed { target_id } => (StatusCode::OK, target_id),
                        };
                        let view = vault::read_connection(c, &actor, &id, now_ms).await?;
                        Ok((status, view))
                    })
                    .await?;
                Ok(reply(status, connection_json(&view)?))
            }
            (Op::AuthorizeConnection, Parsed::Authorize(req, expires_at)) => {
                let keyring = vault_keys.ok_or(PROVISIONING)?;
                let derived_key = request_key(op, target, client_key.ok_or(INTERNAL)?);
                let audit = AuditContext {
                    actor_user_id: context.user_id(),
                    actor_approval_id: context.approval_id(),
                    now_ms,
                    request_key: &derived_key,
                    reason: req.reason.as_deref().unwrap_or(op.id()),
                };
                let view = self
                    .with_connection(async |c| {
                        vault::authorize_connection(
                            c,
                            &audit,
                            &keyring,
                            target,
                            &AuthorizeConnectionInput {
                                access_token: &req.access_token,
                                refresh_token: req.refresh_token.as_deref(),
                                granted_scopes: &req.granted_scopes,
                                expires_at: expires_at.as_deref(),
                            },
                        )
                        .await
                        .map_err(vault_problem)?;
                        let actor = principal(c, &context).await?;
                        Ok(vault::read_connection(c, &actor, target, now_ms).await?)
                    })
                    .await?;
                Ok(reply(StatusCode::OK, connection_json(&view)?))
            }
            (Op::DisconnectConnection, _) => {
                let derived_key = request_key(op, target, client_key.ok_or(INTERNAL)?);
                let audit = AuditContext {
                    actor_user_id: context.user_id(),
                    actor_approval_id: context.approval_id(),
                    now_ms,
                    request_key: &derived_key,
                    reason: op.id(),
                };
                let view = self
                    .database(async |c| {
                        vault::disconnect_connection(c, &audit, target).await?;
                        let actor = principal(c, &context).await?;
                        vault::read_connection(c, &actor, target, now_ms).await
                    })
                    .await?;
                Ok(reply(StatusCode::OK, connection_json(&view)?))
            }
            (Op::ShareConnection, Parsed::Share(grantee, reason)) => {
                let derived_key = request_key(op, target, client_key.ok_or(INTERNAL)?);
                let audit = AuditContext {
                    actor_user_id: context.user_id(),
                    actor_approval_id: context.approval_id(),
                    now_ms,
                    request_key: &derived_key,
                    reason: reason.as_deref().unwrap_or(op.id()),
                };
                self.database(async |c| vault::share_connection(c, &audit, target, &grantee).await)
                    .await?;
                Ok(reply(
                    StatusCode::OK,
                    json!({
                        "connection_id": target,
                        "grantee": grantee_json(&grantee),
                        "access": "use",
                    }),
                ))
            }
            (Op::RevokeConnectionShare, Parsed::RevokeShare(grantee, reason)) => {
                let derived_key = request_key(op, target, client_key.ok_or(INTERNAL)?);
                let audit = AuditContext {
                    actor_user_id: context.user_id(),
                    actor_approval_id: context.approval_id(),
                    now_ms,
                    request_key: &derived_key,
                    reason: reason.as_deref().unwrap_or(op.id()),
                };
                self.database(async |c| {
                    vault::revoke_connection_share(c, &audit, target, &grantee).await
                })
                .await?;
                Ok(no_content())
            }
            _ => Err(INTERNAL),
        }
    }
}
