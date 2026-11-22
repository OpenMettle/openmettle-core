//! Apply evidence to the original handoff, independently of the current run, key or policy.
use super::Error;
use crate::{
    provider_http::gateway::{Admin, UsageReport},
    runs::WriteTransaction,
};
use sqlx::{PgConnection, PgPool, Row};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Duplicate,
    Superseded,
}

const INSERT_REPORT: &str = "INSERT INTO openmettle.gateway_usage_reports
    (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included,cost,unit)
    VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10::text::numeric,$11) ON CONFLICT DO NOTHING";

const EXACT_REPORT: &str = "SELECT EXISTS (SELECT FROM openmettle.gateway_usage_reports
    WHERE (request_id,source,report_id,revision) = ($1::uuid,$2::uuid,$3::uuid,$4)
    AND (final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included,cost,unit)
    IS NOT DISTINCT FROM ($5::boolean,$6::bigint,$7::bigint,$8::bigint,$9::boolean,$10::text::numeric,$11::text))";

fn evidence<'a>(
    sql: &'static str,
    r: &'a UsageReport,
) -> sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(sql)
        .bind(&r.request)
        .bind(&r.source)
        .bind(&r.report_id)
        .bind(r.revision)
        .bind(r.r#final)
        .bind(r.prompt_tokens)
        .bind(r.completion_tokens)
        .bind(r.reasoning_tokens)
        .bind(r.reasoning_included)
        .bind(&r.cost)
        .bind(&r.unit)
}

async fn apply(
    c: &mut PgConnection,
    r: &UsageReport,
    measured: Option<String>,
    held: i64,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding)
        VALUES ($1::uuid,$2,$3,$4::text::numeric,$5) ON CONFLICT (request_id) DO UPDATE
        SET revision=excluded.revision,final=excluded.final,measured=excluded.measured,outstanding=excluded.outstanding")
        .bind(&r.request).bind(r.revision).bind(r.r#final).bind(measured).bind(held).execute(&mut *c).await?;
    settle_quota(c, r).await
}

async fn settle_quota(c: &mut PgConnection, r: &UsageReport) -> Result<(), Error> {
    sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$3::uuid,$4)")
        .bind(&r.request)
        .bind(&r.source)
        .bind(&r.report_id)
        .bind(r.revision)
        .execute(c)
        .await?;
    Ok(())
}

/// The caller supplies evidence from the authenticated reporting profile. Verify all routing
/// fields against the immutable request, including after key rotation and account withdrawal.
pub async fn ingest(pool: &PgPool, r: &UsageReport) -> Result<Outcome, Error> {
    if !r.valid() {
        return Err(Error::Refused);
    }
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let c = tx.connection()?;
    sqlx::query("SELECT openmettle.quota_lock_gateway_request_for_settlement($1::uuid)")
        .bind(&r.request)
        .execute(&mut *c)
        .await?;
    let row = sqlx::query(
        "SELECT q.units,s.revision,s.final,s.outstanding FROM openmettle.gateway_requests q
        JOIN openmettle.gateway_bindings b ON b.id=q.binding_id
        LEFT JOIN openmettle.gateway_settlements s ON s.request_id=q.id
        WHERE q.id=$1::uuid AND q.state='handed_off' AND q.report_source=$2::uuid
        AND q.installation=$3::uuid AND b.principal=$4::uuid AND q.scope_id=$5::uuid",
    )
    .bind(&r.request)
    .bind(&r.source)
    .bind(&r.installation)
    .bind(&r.principal)
    .bind(&r.scope)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::Refused)?;
    let inserted = evidence(INSERT_REPORT, r)
        .execute(&mut *c)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|d| d.is_check_violation())
            {
                Error::Refused
            } else {
                e.into()
            }
        })?
        .rows_affected();
    if inserted == 0
        && !evidence(EXACT_REPORT, r)
            .fetch_one(&mut *c)
            .await?
            .try_get::<bool, _>(0)?
    {
        return Err(Error::Conflict);
    }
    let previous_revision = row.try_get::<Option<i64>, _>("revision")?;
    let outcome = if previous_revision == Some(r.revision) {
        // Repair a previous writer's accepted report whose quota consumption was interrupted.
        settle_quota(c, r).await?;
        Outcome::Duplicate
    } else if previous_revision.is_some_and(|rev| rev > r.revision)
        || row.try_get::<Option<bool>, _>("final")? == Some(true) && !r.r#final
    {
        if inserted == 0 {
            Outcome::Duplicate
        } else {
            Outcome::Superseded
        }
    } else {
        let units = row.try_get::<i64, _>("units")?;
        let measured = r.measured();
        let previous = row
            .try_get::<Option<i64>, _>("outstanding")?
            .unwrap_or(units);
        let estimate = match measured {
            Some(_) if r.r#final && r.prompt_tokens.is_some() && r.completion_tokens.is_some() => 0,
            Some(n) => previous.min((i128::from(units) - n).max(0) as i64),
            None => previous,
        };
        // The quota fold is privileged and accepts only revisions already referenced by the
        // settlement trigger. Its held result can differ when a report omits components or
        // corrects an earlier cumulative total. Republish inside this transaction in that case.
        sqlx::query("SAVEPOINT gateway_fold")
            .execute(&mut *c)
            .await?;
        let amount = measured.map(|n| n.to_string());
        apply(c, r, amount.clone(), estimate).await?;
        let actual: Option<i64> = sqlx::query_scalar(
            "SELECT held_units FROM openmettle.quota_reservations
            WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'",
        )
        .bind(&r.request)
        .fetch_optional(&mut *c)
        .await?;
        if let Some(held) = actual.filter(|v| *v != estimate) {
            sqlx::query("ROLLBACK TO SAVEPOINT gateway_fold")
                .execute(&mut *c)
                .await?;
            apply(c, r, amount, held).await?;
        }
        sqlx::query("INSERT INTO openmettle.gateway_audit
            (binding_id,desired_revision,operation_id,step,outcome,remote_handle,remote_revision)
            SELECT i.binding_id,i.desired_revision,i.operation_id,'usage','confirmed',$2::uuid,$3
            FROM openmettle.gateway_requests q JOIN openmettle.gateway_intents i ON i.binding_id=q.binding_id AND i.desired_revision=q.policy_revision
            WHERE q.id=$1::uuid AND i.action='policy' LIMIT 1")
            .bind(&r.request).bind(&r.report_id).bind(r.revision).execute(&mut *c).await?;
        Outcome::Applied
    };
    tx.commit().await?;
    Ok(outcome)
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Backfill {
    // Keyset position is exclusive, and restarts deliberately overlap committed work.
    after: Option<(String, String)>,
}

impl Backfill {
    /// One bounded page. An authoritative absence holds the reservation for the next pass.
    pub async fn page(
        &mut self,
        pool: &PgPool,
        admin: &Admin,
        installation: &str,
        limit: u16,
        deadline: Instant,
    ) -> Result<usize, Error> {
        if !(1..=64).contains(&limit) {
            return Err(Error::Refused);
        }
        let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        let work = async {
            // Final evidence can settle just one resource. Its token or cost hold may
            // still require lookup after the normal outstanding index stops listing it.
            let rows: Vec<(String,String,i64)> = sqlx::query_as("WITH cursor AS (
                SELECT coalesce($2::text::timestamptz,'-infinity') AS at, coalesce($3::uuid,'00000000-0000-0000-0000-000000000000') AS id
            ), candidates AS (
                (SELECT q.created_at AS position,q.id,q.created_at FROM openmettle.gateway_requests q,cursor c
                 WHERE q.installation=$1::uuid AND q.state='handed_off' AND NOT q.settled_final
                   AND (q.created_at,q.id)>(c.at,c.id)
                   AND NOT EXISTS (SELECT FROM openmettle.gateway_settlements s WHERE s.request_id=q.id)
                 ORDER BY q.created_at,q.id LIMIT $4)
                UNION ALL
                (SELECT s.updated_at,q.id,q.created_at FROM openmettle.gateway_settlements s
                 JOIN openmettle.gateway_requests q ON q.id=s.request_id CROSS JOIN cursor c
                 WHERE NOT s.final AND q.installation=$1::uuid AND (s.updated_at,s.request_id)>(c.at,c.id)
                 ORDER BY s.updated_at,s.request_id LIMIT $4)
                UNION ALL
                (SELECT q.created_at,q.id,q.created_at FROM openmettle.gateway_requests q
                 JOIN openmettle.gateway_settlements s ON s.request_id=q.id CROSS JOIN cursor c
                 WHERE q.installation=$1::uuid AND q.settled_final AND (s.outstanding>0 OR EXISTS
                     (SELECT FROM openmettle.quota_reservations h WHERE h.gateway_request_id=q.id AND h.state='handoff_committed'))
                   AND (q.created_at,q.id)>(c.at,c.id)
                 ORDER BY q.created_at,q.id LIMIT $4))
                SELECT position::text,id::text,greatest(0,extract(epoch FROM clock_timestamp()-created_at))::bigint
                FROM candidates ORDER BY candidates.position,candidates.id LIMIT $4")
                .bind(installation)
                .bind(self.after.as_ref().map(|v| &v.0))
                .bind(self.after.as_ref().map(|v| &v.1))
                .bind(i64::from(limit)).fetch_all(pool).await?;
            let count = rows.len();
            for (position, request, age) in rows {
                use crate::telemetry::{
                    gateway_failure,
                    metrics::{GatewayCause, GatewayStep},
                };
                crate::telemetry::metrics::global().record_gateway_lag(age);
                let outcome = match admin.usage(&request, deadline).await {
                    Ok(Some(r)) if r.installation == installation && r.request == request => {
                        match ingest(pool, &r).await {
                            Ok(_) => None,
                            Err(Error::Refused | Error::Conflict) => {
                                Some(("refused", Some(GatewayCause::Protocol)))
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(Some(_)) => Some(("refused", Some(GatewayCause::Protocol))),
                    Ok(None) => Some(("deferred", None)),
                    Err(e) => {
                        gateway_failure(GatewayStep::Usage, e.cause());
                        if matches!(e, crate::provider_http::gateway::Error::Protocol) {
                            Some(("refused", None))
                        } else {
                            return Err(Error::Database);
                        }
                    }
                };
                if let Some((outcome, cause)) = outcome {
                    if let Some(c) = cause {
                        gateway_failure(GatewayStep::Usage, c);
                    }
                    // Old PR2 bindings may predate policy intents. Their original request
                    // remains in the outstanding scan even without an audit parent.
                    sqlx::query("INSERT INTO openmettle.gateway_audit(binding_id,desired_revision,operation_id,step,outcome,remote_handle)
                        SELECT i.binding_id,i.desired_revision,i.operation_id,'usage',$2,q.id
                        FROM openmettle.gateway_requests q JOIN openmettle.gateway_intents i ON i.binding_id=q.binding_id
                         AND i.desired_revision=q.policy_revision AND i.action='policy' WHERE q.id=$1::uuid LIMIT 1")
                        .bind(&request).bind(outcome).execute(pool).await?;
                }
                self.after = Some((position, request));
            }
            if count < usize::from(limit) {
                self.after = None;
            }
            Ok(count)
        };
        tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| Error::Database)?
    }
}
