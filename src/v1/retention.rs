//! Audited `account_admin` retention policy, deadline adjustment preview/apply and restore-gate
//! health routes under `/v1/admin/retention/*` (ADR 0041 PR3).
use super::{
    Api, BODY, CONFLICT, INTERNAL, INVALID, KEY_CONFLICT, NOT_FOUND, Op, POLICY, Problem, Session,
    UNAUTHENTICATED, UNAVAILABLE, denied, parse_unique, principal,
    quotas::parse_non_negative_decimal, reply, request_key, timestamp,
};
use crate::{
    authz::{self, Action, AdminChange, store},
    runs,
};
use axum::{
    http::{StatusCode, request::Parts},
    response::Response,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgConnection;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdatePolicyBody {
    grace_seconds: i32,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewDeadlinesBody {
    target_grace_seconds: i32,
    #[serde(default)]
    scope_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyDeadlinesBody {
    expected_policy_revision: String,
    target_grace_seconds: i32,
    #[serde(default)]
    scope_id: Option<String>,
    reason: String,
}

fn parse_reason(reason: &str) -> Result<(), Problem> {
    if !runs::bounded(reason, 256)
        || reason.trim() != reason
        || reason.chars().any(char::is_control)
    {
        return Err(BODY);
    }
    Ok(())
}

fn parse_scope_id(scope_id: Option<&str>) -> Result<(), Problem> {
    if let Some(id) = scope_id
        && runs::uuid(id).is_err()
    {
        return Err(BODY);
    }
    Ok(())
}

fn parse_update_policy(body: &[u8]) -> Result<(i32, String), Problem> {
    let parsed: UpdatePolicyBody = parse_unique(body)?;
    if parsed.grace_seconds < 0 {
        return Err(BODY);
    }
    parse_reason(&parsed.reason)?;
    Ok((parsed.grace_seconds, parsed.reason))
}

fn parse_preview_deadlines(body: &[u8]) -> Result<(i32, Option<String>), Problem> {
    let parsed: PreviewDeadlinesBody = parse_unique(body)?;
    if parsed.target_grace_seconds < 0 {
        return Err(BODY);
    }
    parse_scope_id(parsed.scope_id.as_deref())?;
    Ok((parsed.target_grace_seconds, parsed.scope_id))
}

fn parse_apply_deadlines(body: &[u8]) -> Result<(i64, i32, Option<String>, String), Problem> {
    let parsed: ApplyDeadlinesBody = parse_unique(body)?;
    let expected_revision = parse_non_negative_decimal(&parsed.expected_policy_revision)?;
    if expected_revision <= 0 || parsed.target_grace_seconds < 0 {
        return Err(BODY);
    }
    parse_scope_id(parsed.scope_id.as_deref())?;
    parse_reason(&parsed.reason)?;
    Ok((
        expected_revision,
        parsed.target_grace_seconds,
        parsed.scope_id,
        parsed.reason,
    ))
}

fn check_manage_retention(principal: &authz::Principal) -> Result<(), Problem> {
    match authz::authorize_admin(
        principal,
        AdminChange {
            action: Action::ManageRetention,
            removes_enabled_admin: false,
            enabled_account_admins: 0,
        },
    ) {
        authz::Decision::Allow => Ok(()),
        authz::Decision::Deny(reason) => Err(denied(reason)),
    }
}

fn map_retention_sql_error(err: sqlx::Error) -> Problem {
    if let sqlx::Error::Database(ref db) = err {
        let detail = db
            .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .and_then(|pg| pg.detail());
        match db.code().as_deref() {
            Some("42501") if detail == Some("inactive_principal") => return UNAUTHENTICATED,
            Some("42501") => return POLICY,
            Some("23514" | "22023") => return INVALID,
            Some("P0002") => return NOT_FOUND,
            Some("OMR06") => return CONFLICT,
            Some("23505") => return KEY_CONFLICT,
            Some("OMR02") => return UNAVAILABLE,
            _ => {}
        }
    }
    UNAVAILABLE
}

type StatusRow = (
    i64,
    i32,
    i32,
    i32,
    bool,
    Option<i64>,
    Option<i64>,
    bool,
    i64,
    i64,
);

async fn with_retention_tx<T>(
    c: &mut PgConnection,
    work: impl AsyncFnOnce(&mut PgConnection) -> Result<T, Problem>,
) -> Result<T, Problem> {
    let mut tx = store::begin(c).await?;
    let outcome = match tx.connection() {
        Ok(conn) => work(conn).await,
        Err(err) => Err(Problem::from(store::StoreError::from(err))),
    };
    match outcome {
        Ok(val) => {
            tx.commit().await?;
            Ok(val)
        }
        Err(err) => {
            let _ = tx.rollback().await;
            Err(err)
        }
    }
}

impl Api {
    pub(super) async fn retention_operation(
        &self,
        op: Op,
        parts: &Parts,
        session: Session,
        client_key: Option<&str>,
        body: &[u8],
    ) -> Result<Response, Problem> {
        if parts.uri.query().is_some() {
            return Err(INVALID);
        }
        match op {
            Op::GetAdminRetentionStatus => {
                let context = self.authenticate(&session).await?;
                let row: StatusRow = self
                    .with_connection(async |c| {
                        with_retention_tx(c, async |conn| {
                            let p = principal(conn, &context).await?;
                            check_manage_retention(&p)?;
                            sqlx::query_as(
                                "SELECT policy_revision, grace_seconds, min_grace_seconds,
                                        max_grace_seconds, gate_open, snapshot_journal_seq,
                                        required_journal_seq, coverage_complete, journal_seq,
                                        coverage_started_at_us
                                   FROM openmettle.admin_retention_status($1::uuid, $2::uuid, $3)",
                            )
                            .bind(context.user_id())
                            .bind(context.approval_id())
                            .bind(context.observed_ms())
                            .fetch_one(conn)
                            .await
                            .map_err(map_retention_sql_error)
                        })
                        .await
                    })
                    .await?;
                Ok(reply(
                    StatusCode::OK,
                    json!({
                        "policy": {
                            "revision": row.0.to_string(),
                            "grace_seconds": row.1,
                            "min_grace_seconds": row.2,
                            "max_grace_seconds": row.3,
                        },
                        "restore_gate": {
                            "open": row.4,
                            "snapshot_journal_seq": row.5.map(|v| v.to_string()),
                            "required_journal_seq": row.6.map(|v| v.to_string()),
                            "coverage_complete": row.7,
                        },
                        "deletion_journal": {
                            "journal_seq": row.8.to_string(),
                            "coverage_started_at": timestamp(row.9)?,
                        },
                    }),
                ))
            }
            Op::UpdateAdminRetentionPolicy => {
                let (grace_seconds, reason) = parse_update_policy(body)?;
                let key = request_key(op, "instance", client_key.ok_or(INTERNAL)?);
                let context = self.authenticate(&session).await?;
                let (revision, min_grace, max_grace): (i64, i32, i32) = self
                    .with_connection(async |c| {
                        with_retention_tx(c, async |conn| {
                            let p = principal(conn, &context).await?;
                            check_manage_retention(&p)?;
                            let rev: i64 = sqlx::query_scalar(
                                "SELECT openmettle.retention_set_grace($1::uuid, $2::uuid, $3, $4, $5)",
                            )
                            .bind(context.user_id())
                            .bind(context.approval_id())
                            .bind(grace_seconds)
                            .bind(&reason)
                            .bind(&key)
                            .fetch_one(&mut *conn)
                            .await
                            .map_err(map_retention_sql_error)?;
                            let (min_grace, max_grace): (i32, i32) = sqlx::query_as(
                                "SELECT min_grace_seconds, max_grace_seconds
                                   FROM openmettle.retention_policy
                                  WHERE id",
                            )
                            .fetch_one(&mut *conn)
                            .await?;
                            Ok((rev, min_grace, max_grace))
                        })
                        .await
                    })
                    .await?;
                Ok(reply(
                    StatusCode::OK,
                    json!({
                        "revision": revision.to_string(),
                        "grace_seconds": grace_seconds,
                        "min_grace_seconds": min_grace,
                        "max_grace_seconds": max_grace,
                    }),
                ))
            }
            Op::PreviewAdminRetentionDeadlines => {
                let (target_grace_seconds, scope_id) = parse_preview_deadlines(body)?;
                let context = self.authenticate(&session).await?;
                let (affected_revisions, affected_bytes, current_policy_revision, grace): (
                    i64,
                    i64,
                    i64,
                    i32,
                ) = self
                    .with_connection(async |c| {
                        with_retention_tx(c, async |conn| {
                            let p = principal(conn, &context).await?;
                            check_manage_retention(&p)?;
                            sqlx::query_as(
                                "SELECT affected_revisions, affected_bytes,
                                        current_policy_revision, target_grace_seconds
                                   FROM openmettle.retention_preview_deadlines(
                                       $1::uuid, $2::uuid, $3, $4, $5::uuid
                                   )",
                            )
                            .bind(context.user_id())
                            .bind(context.approval_id())
                            .bind(context.observed_ms())
                            .bind(target_grace_seconds)
                            .bind(scope_id.as_deref())
                            .fetch_one(conn)
                            .await
                            .map_err(map_retention_sql_error)
                        })
                        .await
                    })
                    .await?;
                Ok(reply(
                    StatusCode::OK,
                    json!({
                        "current_policy_revision": current_policy_revision.to_string(),
                        "target_grace_seconds": grace,
                        "scope_id": scope_id,
                        "affected_revisions": affected_revisions.to_string(),
                        "affected_bytes": affected_bytes.to_string(),
                    }),
                ))
            }
            Op::ApplyAdminRetentionDeadlines => {
                let (expected_policy_revision, target_grace_seconds, scope_id, reason) =
                    parse_apply_deadlines(body)?;
                // Scope the idempotency key to the endpoint ("instance"), never the body's
                // scope_id, so reusing a key with a different scope_id returns 409 idempotency_conflict.
                let key = request_key(op, "instance", client_key.ok_or(INTERNAL)?);
                let context = self.authenticate(&session).await?;
                let (affected_revisions, affected_bytes, policy_revision): (i64, i64, i64) = self
                    .with_connection(async |c| {
                        with_retention_tx(c, async |conn| {
                            let p = principal(conn, &context).await?;
                            check_manage_retention(&p)?;
                            sqlx::query_as(
                                "SELECT affected_revisions, affected_bytes, policy_revision
                                   FROM openmettle.retention_apply_deadlines(
                                       $1::uuid, $2::uuid, $3, $4, $5::uuid, $6, $7
                                   )",
                            )
                            .bind(context.user_id())
                            .bind(context.approval_id())
                            .bind(expected_policy_revision)
                            .bind(target_grace_seconds)
                            .bind(scope_id.as_deref())
                            .bind(&reason)
                            .bind(&key)
                            .fetch_one(conn)
                            .await
                            .map_err(map_retention_sql_error)
                        })
                        .await
                    })
                    .await?;
                Ok(reply(
                    StatusCode::OK,
                    json!({
                        "policy_revision": policy_revision.to_string(),
                        "target_grace_seconds": target_grace_seconds,
                        "scope_id": scope_id,
                        "affected_revisions": affected_revisions.to_string(),
                        "affected_bytes": affected_bytes.to_string(),
                    }),
                ))
            }
            _ => Err(INTERNAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_request_parsers_reject_invalid_fields_and_duplicates() {
        assert_eq!(
            parse_update_policy(br#"{"grace_seconds":0,"reason":"immediate"}"#),
            Ok((0, "immediate".into()))
        );
        for bad in [
            br#"{"grace_seconds":-1,"reason":"ok"}"#.as_slice(),
            br#"{"grace_seconds":60,"reason":""}"#,
            br#"{"grace_seconds":60,"reason":" padded "}"#,
            br#"{"grace_seconds":60,"reason":"bad\nline"}"#,
            br#"{"grace_seconds":60,"reason":"ok","extra":true}"#,
            br#"{"grace_seconds":60,"grace_seconds":60,"reason":"ok"}"#,
        ] {
            assert_eq!(parse_update_policy(bad), Err(BODY));
        }

        assert_eq!(
            parse_preview_deadlines(br#"{"target_grace_seconds":3600}"#),
            Ok((3600, None))
        );
        assert_eq!(
            parse_preview_deadlines(
                br#"{"target_grace_seconds":3600,"scope_id":"00000000-0000-4000-8000-000000000001"}"#
            ),
            Ok((3600, Some("00000000-0000-4000-8000-000000000001".into())))
        );
        assert_eq!(
            parse_preview_deadlines(br#"{"target_grace_seconds":-1}"#),
            Err(BODY)
        );
        assert_eq!(
            parse_preview_deadlines(br#"{"target_grace_seconds":1,"scope_id":"not-a-uuid"}"#),
            Err(BODY)
        );

        assert_eq!(
            parse_apply_deadlines(
                br#"{"expected_policy_revision":"2","target_grace_seconds":600,"reason":"adjust"}"#
            ),
            Ok((2, 600, None, "adjust".into()))
        );
        for bad in [
            br#"{"expected_policy_revision":"0","target_grace_seconds":600,"reason":"adjust"}"#
                .as_slice(),
            br#"{"expected_policy_revision":"02","target_grace_seconds":600,"reason":"adjust"}"#,
            br#"{"expected_policy_revision":"2","target_grace_seconds":-5,"reason":"adjust"}"#,
            br#"{"expected_policy_revision":"2","target_grace_seconds":600,"reason":""}"#,
        ] {
            assert_eq!(parse_apply_deadlines(bad), Err(BODY));
        }
    }
}
