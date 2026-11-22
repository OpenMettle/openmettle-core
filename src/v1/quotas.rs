//! Authenticated `/v1` quota summary reads and `ManageQuotas` scope overrides (ADR 0040 PR3).
use super::{
    Api, BODY, INTERNAL, INVALID, Op, PROVISIONING, Problem, Session, UNAVAILABLE, parse_unique,
    path_id, principal, quota_problem, reply, request_key, store_problem,
};
use crate::{
    authz::{self, projects, store::AuditContext},
    quotas::{self, QuotaError, QuotaResourceKind},
};
use axum::{
    http::{StatusCode, request::Parts},
    response::Response,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetOverrideBody {
    hard_limit: String,
    #[serde(default)]
    expires_at: Option<String>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeOverrideBody {
    reason: String,
}

/// Canonical `NonNegativeDecimal`: `0..=i64::MAX`, base-10 ASCII digits, no sign or leading zeros.
pub(super) fn parse_non_negative_decimal(text: &str) -> Result<i64, Problem> {
    if text.is_empty()
        || text.len() > 19
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(BODY);
    }
    text.parse::<i64>().map_err(|_| BODY)
}

/// Canonical ADR 0007 `Timestamp`: `YYYY-MM-DDTHH:MM:SS.ffffffZ` (exactly 27 ASCII bytes in UTC).
pub(super) fn parse_canonical_timestamp(text: &str) -> Result<String, Problem> {
    if text.len() != 27 || !text.is_ascii() || !text.ends_with('Z') {
        return Err(BODY);
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(text).map_err(|_| BODY)?;
    let formatted = parsed
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string();
    if formatted != text {
        return Err(BODY);
    }
    Ok(formatted)
}

pub(super) fn parse_set_override(
    resource: QuotaResourceKind,
    body: &[u8],
) -> Result<(i64, Option<String>, String), Problem> {
    let parsed: SetOverrideBody = parse_unique(body)?;
    let hard_limit = parse_non_negative_decimal(&parsed.hard_limit)?;
    if resource.is_round_cap() && !(1..=1000).contains(&hard_limit) {
        return Err(INVALID);
    }
    let expires_at = parsed
        .expires_at
        .as_deref()
        .map(parse_canonical_timestamp)
        .transpose()?;
    if !crate::runs::bounded(&parsed.reason, 256) {
        return Err(BODY);
    }
    Ok((hard_limit, expires_at, parsed.reason))
}

pub(super) fn parse_revoke_override(body: &[u8]) -> Result<String, Problem> {
    let parsed: RevokeOverrideBody = parse_unique(body)?;
    if !crate::runs::bounded(&parsed.reason, 256) {
        return Err(BODY);
    }
    Ok(parsed.reason)
}

fn quota_error(error: QuotaError) -> Problem {
    match error {
        QuotaError::Store(e) => store_problem(e),
        QuotaError::UpgradeNotEnforced => PROVISIONING,
        QuotaError::AdoptionInProgress => UNAVAILABLE,
        QuotaError::CostDenominationUnconfigured => quota_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "provisioning",
            "Quota limits are not configured for this resource.",
            "usage_cost_micros",
            "instance",
        ),
    }
}

fn path_resource(parts: &Parts) -> Result<QuotaResourceKind, Problem> {
    parts
        .uri
        .path()
        .split('/')
        .nth(6)
        .and_then(QuotaResourceKind::parse)
        .ok_or(INVALID)
}

impl Api {
    pub(super) async fn quota_operation(
        &self,
        op: Op,
        parts: &Parts,
        session: Session,
        target: &str,
        client_key: Option<&str>,
        body: &[u8],
    ) -> Result<Response, Problem> {
        if parts.uri.query().is_some() {
            return Err(INVALID);
        }
        let limits = parts
            .extensions
            .get::<authz::runs::AdmissionLimits>()
            .copied();
        match op {
            Op::GetPersonalQuotas => {
                let context = self.authenticate(&session).await?;
                let summary = self
                    .with_connection(async |c| {
                        let p = principal(c, &context).await?;
                        quotas::read_summary(c, &p.personal_scope_id, Some(&p.user_id), limits)
                            .await
                            .map_err(quota_error)
                    })
                    .await?;
                let value = serde_json::to_value(summary).map_err(|_| INTERNAL)?;
                Ok(reply(StatusCode::OK, value))
            }
            Op::GetProjectQuotas => {
                let context = self.authenticate(&session).await?;
                let summary = self
                    .with_connection(async |c| {
                        let p = principal(c, &context).await?;
                        let view =
                            projects::read_project(c, &p, target, context.observed_ms()).await?;
                        quotas::read_summary(c, &view.settings.scope_id, None, limits)
                            .await
                            .map_err(quota_error)
                    })
                    .await?;
                let value = serde_json::to_value(summary).map_err(|_| INTERNAL)?;
                Ok(reply(StatusCode::OK, value))
            }
            Op::SetQuotaOverride => {
                let scope_id = path_id(parts, 4)?;
                let resource = path_resource(parts)?;
                let (hard_limit, expires_at, reason) = parse_set_override(resource, body)?;
                let key = request_key(
                    op,
                    &format!("{scope_id}/{}", resource.as_str()),
                    client_key.ok_or(INTERNAL)?,
                );
                let context = self.authenticate(&session).await?;
                let audit = AuditContext {
                    actor_user_id: context.user_id(),
                    actor_approval_id: context.approval_id(),
                    now_ms: context.observed_ms(),
                    request_key: &key,
                    reason: &reason,
                };
                let record = self
                    .with_connection(async |c| {
                        quotas::set_scope_override(
                            c,
                            &audit,
                            scope_id,
                            resource,
                            hard_limit,
                            expires_at.as_deref(),
                        )
                        .await
                        .map_err(quota_error)
                    })
                    .await?;
                let value = serde_json::to_value(record).map_err(|_| INTERNAL)?;
                Ok(reply(StatusCode::OK, value))
            }
            Op::RevokeQuotaOverride => {
                let scope_id = path_id(parts, 4)?;
                let resource = path_resource(parts)?;
                let reason = parse_revoke_override(body)?;
                let key = request_key(
                    op,
                    &format!("{scope_id}/{}", resource.as_str()),
                    client_key.ok_or(INTERNAL)?,
                );
                let context = self.authenticate(&session).await?;
                let audit = AuditContext {
                    actor_user_id: context.user_id(),
                    actor_approval_id: context.approval_id(),
                    now_ms: context.observed_ms(),
                    request_key: &key,
                    reason: &reason,
                };
                let record = self
                    .with_connection(async |c| {
                        quotas::revoke_scope_override(c, &audit, scope_id, resource)
                            .await
                            .map_err(quota_error)
                    })
                    .await?;
                let value = serde_json::to_value(record).map_err(|_| INTERNAL)?;
                Ok(reply(StatusCode::OK, value))
            }
            _ => Err(INTERNAL),
        }
    }
}
