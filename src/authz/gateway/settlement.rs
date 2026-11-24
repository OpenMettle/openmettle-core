//! Apply evidence to the original handoff, independently of the current run, key or policy.
use super::Error;
use crate::{
    provider_http::gateway::{Admin, Error as AdminError, UsageReport},
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
    (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included,cost,unit,incomplete)
    VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10::text::numeric,$11,$12) ON CONFLICT DO NOTHING";

const EXACT_REPORT: &str = "SELECT EXISTS (SELECT FROM openmettle.gateway_usage_reports
    WHERE (request_id,source,report_id,revision) = ($1::uuid,$2::uuid,$3::uuid,$4)
    AND (final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included,cost,unit,incomplete)
    IS NOT DISTINCT FROM ($5::boolean,$6::bigint,$7::bigint,$8::bigint,$9::boolean,$10::text::numeric,$11::text,$12::text))";

fn evidence<'a>(
    sql: &'static str,
    r: &'a UsageReport,
    incomplete: Option<&'a str>,
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
        .bind(incomplete)
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

/// Replay accepted token components for pre-metering handoffs. PostgreSQL's drift
/// verifier checks the settlement's measured column against the latest raw report;
/// the cumulative measurement drives outstanding, just as it drives held_units.
#[derive(Default)]
struct TokenFold {
    prompt: i128,
    completion: i128,
    reasoning: i128,
    separate: bool,
    separate_seen: bool,
    reasoning_current: bool,
    settled: i128,
    closed: bool,
}

impl TokenFold {
    fn observe(&mut self, row: &sqlx::postgres::PgRow) -> Result<(), Error> {
        let prompt_tokens: Option<i64> = row.try_get("prompt_tokens")?;
        let completion_tokens: Option<i64> = row.try_get("completion_tokens")?;
        let reasoning_tokens: Option<i64> = row.try_get("reasoning_tokens")?;
        let reasoning_included: Option<bool> = row.try_get("reasoning_included")?;
        // A report that says why the request has no usage ends it (migration 31's fold rule).
        self.closed |= row.try_get::<Option<String>, _>("incomplete")?.is_some();
        if let Some(prompt) = prompt_tokens {
            self.prompt = prompt.into();
        }
        if let Some(completion) = completion_tokens {
            self.completion = completion.into();
            self.reasoning_current = false;
        }
        if let Some(reasoning) = reasoning_tokens {
            self.reasoning = reasoning.into();
            self.separate = reasoning_included == Some(false);
            self.separate_seen |= self.separate;
            self.reasoning_current = true;
        }
        if prompt_tokens.is_none() && completion_tokens.is_none() && reasoning_tokens.is_none() {
            return Ok(());
        }
        let measured = self.prompt
            + if self.separate {
                self.completion + self.reasoning
            } else if self.reasoning_current {
                self.completion.max(self.reasoning)
            } else {
                self.completion
            };
        let complete = prompt_tokens.is_some()
            && completion_tokens.is_some()
            && (reasoning_tokens.is_some() || !self.separate_seen);
        self.settled = if complete {
            measured
        } else {
            self.settled.max(measured)
        };
        self.closed |= complete && row.try_get::<bool, _>("final")?;
        Ok(())
    }
}

async fn legacy_outstanding(
    c: &mut PgConnection,
    r: &UsageReport,
    units: i64,
) -> Result<i64, Error> {
    let mut fold = TokenFold::default();
    let mut after = -1_i64;
    loop {
        let rows = sqlx::query("SELECT revision,report_id::text,final,
            prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included,incomplete FROM openmettle.gateway_usage_reports
            WHERE request_id=$1::uuid AND revision>$2 AND revision<=$3 ORDER BY revision LIMIT 64")
            .bind(&r.request).bind(after).bind(r.revision).fetch_all(&mut *c).await?;
        let count = rows.len();
        for row in rows {
            after = row.try_get("revision")?;
            if after != r.revision {
                // The gateway login can replay accepted reports but cannot read the
                // private acceptance ledger. A superseded raw report fails this check.
                sqlx::query("SAVEPOINT accepted_report")
                    .execute(&mut *c)
                    .await?;
                let check = sqlx::query(
                    "SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$3::uuid,$4)",
                )
                .bind(&r.request)
                .bind(&r.source)
                .bind(row.try_get::<&str, _>("report_id")?)
                .bind(after)
                .execute(&mut *c)
                .await;
                if let Err(error) = check {
                    if !error.as_database_error().is_some_and(|e| {
                        e.is_check_violation() && e.message() == "unknown accepted report"
                    }) {
                        return Err(error.into());
                    }
                    sqlx::query("ROLLBACK TO SAVEPOINT accepted_report")
                        .execute(&mut *c)
                        .await?;
                    sqlx::query("RELEASE SAVEPOINT accepted_report")
                        .execute(&mut *c)
                        .await?;
                    continue;
                }
                sqlx::query("RELEASE SAVEPOINT accepted_report")
                    .execute(&mut *c)
                    .await?;
            }
            fold.observe(&row)?;
        }
        if count < 64 {
            break;
        }
    }
    Ok(if fold.closed {
        0
    } else {
        (i128::from(units) - fold.settled).max(0) as i64
    })
}

/// The caller supplies evidence from the authenticated reporting profile. Verify all routing
/// fields against the immutable request, including after key rotation and account withdrawal.
/// A request handed off without a binding (ADR 0044) reports under its actor as the principal,
/// the same rule as `openmettle.gateway_dispatch`, and only once it was dispatched: the proxy is
/// the only reporter and reports after it spent the dispatch.
pub async fn ingest(pool: &PgPool, r: &UsageReport) -> Result<Outcome, Error> {
    store(pool, r, None).await
}

/// [`ingest`] for a request that ended without usage (ADR 0044, amendment of 24 November
/// 2026): the final report `r` carries `reason`, one of the values the
/// `gateway_usage_reports.incomplete` CHECK lists, and closes the request's holds at what was
/// measured so far. An unknown reason or a report that is not final is refused.
pub async fn ingest_incomplete(
    pool: &PgPool,
    r: &UsageReport,
    reason: &str,
) -> Result<Outcome, Error> {
    store(pool, r, Some(reason)).await
}

async fn store(pool: &PgPool, r: &UsageReport, incomplete: Option<&str>) -> Result<Outcome, Error> {
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
        "SELECT q.units,s.revision,s.final,s.outstanding,q.binding_id IS NULL AS unbound
        FROM openmettle.gateway_requests q
        LEFT JOIN openmettle.gateway_bindings b ON b.id=q.binding_id
        LEFT JOIN openmettle.gateway_settlements s ON s.request_id=q.id
        WHERE q.id=$1::uuid AND q.state='handed_off' AND q.report_source=$2::uuid
        AND q.installation=$3::uuid AND coalesce(b.principal,q.actor_user_id)=$4::uuid
        AND q.scope_id=$5::uuid AND (q.binding_id IS NOT NULL OR q.dispatched_at IS NOT NULL)",
    )
    .bind(&r.request)
    .bind(&r.source)
    .bind(&r.installation)
    .bind(&r.principal)
    .bind(&r.scope)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::Refused)?;
    let inserted = evidence(INSERT_REPORT, r, incomplete)
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
        && !evidence(EXACT_REPORT, r, incomplete)
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
        let amount = r.measured().map(|n| n.to_string());
        // Acceptance by the settlement trigger precedes the privileged quota fold.
        // Stage a projection, then republish atomically if the folded hold differs.
        let previous = row
            .try_get::<Option<i64>, _>("outstanding")?
            .unwrap_or(units);
        sqlx::query("SAVEPOINT gateway_fold")
            .execute(&mut *c)
            .await?;
        apply(c, r, amount.clone(), previous).await?;
        let actual: Option<i64> = sqlx::query_scalar(
            "SELECT held_units FROM openmettle.quota_reservations
            WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'",
        )
        .bind(&r.request)
        .fetch_optional(&mut *c)
        .await?;
        let held = match actual {
            Some(held) => held,
            None => legacy_outstanding(c, r, units).await?,
        };
        // A final report that leaves the token hold open would mark the request settled, hide
        // it from every scan of outstanding requests and keep the hold for good. The proxy's
        // reports never do: one with both counts and one with a reason both close the hold.
        // Requests handed off under ADR 0037 keep their earlier behaviour.
        if r.r#final && held != 0 && row.try_get("unbound")? {
            return Err(Error::Refused);
        }
        if held != previous {
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
    // PR2 requests can have a final report with unknown components and no metered hold.
    #[serde(default)]
    legacy_after: Option<String>,
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
            let rows: Vec<(String, String, i64)> = sqlx::query_as(include_str!("backfill.sql"))
                .bind(installation)
                .bind(self.after.as_ref().map(|v| &v.0))
                .bind(self.after.as_ref().map(|v| &v.1))
                .bind(i64::from(limit))
                .fetch_all(pool)
                .await?;
            let count = rows.len();
            for (position, request, age) in rows {
                lookup(pool, admin, installation, &request, age, deadline).await?;
                self.after = Some((position, request));
            }
            if count == usize::from(limit) {
                return Ok(count);
            }
            self.after = None;
            // The normal work queue has room. Legacy incomplete finals have neither
            // a nonfinal index entry nor a quota hold. Limit the primary-key walk
            // *before* checking eligibility and resume after every inspected key.
            let room = usize::from(limit) - count;
            let legacy: Vec<(String, Option<i64>)> =
                sqlx::query_as(include_str!("legacy_backfill.sql"))
                    .bind(&self.legacy_after)
                    .bind(room as i64)
                    .bind(installation)
                    .fetch_all(pool)
                    .await?;
            let wrap = legacy.len() < room;
            let mut looked_up = count;
            for (request, age) in legacy {
                if let Some(age) = age {
                    lookup(pool, admin, installation, &request, age, deadline).await?;
                    looked_up += 1;
                }
                self.legacy_after = Some(request);
            }
            if wrap {
                self.legacy_after = None;
            }
            Ok(looked_up)
        };
        tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| Error::Database)?
    }
}

async fn lookup(
    pool: &PgPool,
    admin: &Admin,
    installation: &str,
    request: &str,
    age: i64,
    deadline: Instant,
) -> Result<(), Error> {
    use crate::telemetry::{
        gateway_failure,
        metrics::{GatewayCause, GatewayStep},
    };
    crate::telemetry::metrics::global().record_gateway_lag(age);
    let outcome = match admin.usage(request, deadline).await {
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
        Err(
            e @ (AdminError::Refused(401 | 403)
            | AdminError::Deferred(_)
            | AdminError::Transport(_)),
        ) => {
            gateway_failure(GatewayStep::Usage, e.cause());
            return Err(Error::Database);
        }
        Err(e) => Some(("refused", Some(e.cause()))),
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
            .bind(request).bind(outcome).execute(pool).await?;
    }
    Ok(())
}
