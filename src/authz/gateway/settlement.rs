//! Apply evidence to the original handoff, independently of the current run, key or policy.
use super::Error;
use crate::{provider_http::gateway::UsageReport, runs::WriteTransaction};
use sqlx::{PgConnection, PgPool, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Duplicate,
    Superseded,
}

const SETTLE_REPORT_PROC: &str = "openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text)";

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
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|d| d.is_check_violation())
            {
                Error::Refused
            } else {
                e.into()
            }
        })?;
    Ok(())
}

/// Replay accepted token components for pre-metering handoffs on pre-37 schemas.
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
        // A report that says why the request has no usage ends it without changing what earlier
        // accepted reports measured (migration 31's fold rule).
        if row.try_get::<Option<String>, _>("incomplete")?.is_some() {
            self.closed = true;
            return Ok(());
        }
        let prompt_tokens: Option<i64> = row.try_get("prompt_tokens")?;
        let completion_tokens: Option<i64> = row.try_get("completion_tokens")?;
        let reasoning_tokens: Option<i64> = row.try_get("reasoning_tokens")?;
        let reasoning_included: Option<bool> = row.try_get("reasoning_included")?;
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

async fn is_accepted_report(
    c: &mut PgConnection,
    request: &str,
    source: &str,
    report_id: &str,
    revision: i64,
) -> Result<bool, Error> {
    sqlx::query("SAVEPOINT accepted_report")
        .execute(&mut *c)
        .await?;
    let check =
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$3::uuid,$4)")
            .bind(request)
            .bind(source)
            .bind(report_id)
            .bind(revision)
            .execute(&mut *c)
            .await;
    match check {
        Ok(_) => {
            sqlx::query("RELEASE SAVEPOINT accepted_report")
                .execute(&mut *c)
                .await?;
            Ok(true)
        }
        Err(error) => {
            if !error
                .as_database_error()
                .is_some_and(|e| e.is_check_violation() && e.message() == "unknown accepted report")
            {
                return Err(error.into());
            }
            sqlx::query("ROLLBACK TO SAVEPOINT accepted_report")
                .execute(&mut *c)
                .await?;
            sqlx::query("RELEASE SAVEPOINT accepted_report")
                .execute(&mut *c)
                .await?;
            Ok(false)
        }
    }
}

/// The units still outstanding for a request without a metered hold on pre-37 schemas, and whether
/// the accepted reports closed it.
async fn legacy_outstanding(
    c: &mut PgConnection,
    r: &UsageReport,
    units: i64,
) -> Result<(i64, bool), Error> {
    let mut fold = TokenFold::default();
    let mut after = -1_i64;
    loop {
        let rows = sqlx::query(
            "SELECT revision,report_id::text,final,
                    prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included,incomplete
               FROM openmettle.gateway_usage_reports
              WHERE request_id=$1::uuid AND revision>$2 AND revision<=$3
              ORDER BY revision LIMIT 64",
        )
        .bind(&r.request)
        .bind(after)
        .bind(r.revision)
        .fetch_all(&mut *c)
        .await?;
        let count = rows.len();
        for row in rows {
            after = row.try_get("revision")?;
            if after != r.revision
                && !is_accepted_report(
                    c,
                    &r.request,
                    &r.source,
                    row.try_get::<&str, _>("report_id")?,
                    after,
                )
                .await?
            {
                continue;
            }
            fold.observe(&row)?;
        }
        if count < 64 {
            break;
        }
    }
    let outstanding = if fold.closed {
        0
    } else {
        (i128::from(units) - fold.settled).max(0) as i64
    };
    Ok((outstanding, fold.closed))
}

/// Record usage evidence from the inference proxy against the dispatched request (ADR 0044).
/// On schema `>= 37`, delegates to `openmettle.gateway_settle_report(...)` inside one
/// `WriteTransaction` so `openmettle_gateway` holds zero table or column privileges; on pre-37
/// schemas falls back to the unbound SQL path for rolling-upgrade compatibility.
pub async fn ingest(pool: &PgPool, r: &UsageReport) -> Result<Outcome, Error> {
    store(pool, r, None).await
}

/// [`ingest`] for a request that ended without usage (ADR 0044): the final report `r` carries
/// `reason`, one of the proxy values `gateway_usage_reports.incomplete` allows, and closes the
/// request's holds at what earlier accepted reports measured.
pub async fn ingest_incomplete(
    pool: &PgPool,
    r: &UsageReport,
    reason: &str,
) -> Result<Outcome, Error> {
    store(pool, r, Some(reason)).await
}

async fn store(pool: &PgPool, r: &UsageReport, incomplete: Option<&str>) -> Result<Outcome, Error> {
    let carries_usage = r.prompt_tokens.is_some()
        || r.completion_tokens.is_some()
        || r.reasoning_tokens.is_some()
        || r.reasoning_included.is_some()
        || r.cost.is_some()
        || r.unit.is_some();
    if !r.valid()
        || incomplete.is_some_and(|reason| {
            carries_usage || matches!(reason, "not_dispatched" | "unreported")
        })
    {
        return Err(Error::Refused);
    }
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let c = tx.connection()?;
    let has_settle_fn: bool = sqlx::query_scalar("SELECT to_regprocedure($1) IS NOT NULL")
        .bind(SETTLE_REPORT_PROC)
        .fetch_one(&mut *c)
        .await?;
    let outcome = if has_settle_fn {
        let verdict: String = sqlx::query_scalar(
            "SELECT openmettle.gateway_settle_report($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7,$8,$9,$10,$11,$12,$13::text::numeric,$14,$15)",
        )
        .bind(&r.request)
        .bind(&r.installation)
        .bind(&r.principal)
        .bind(&r.scope)
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
        .fetch_one(&mut *c)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|d| d.is_check_violation())
            {
                Error::Refused
            } else {
                e.into()
            }
        })?;
        match verdict.as_str() {
            "applied" => Outcome::Applied,
            "duplicate" => Outcome::Duplicate,
            "superseded" => Outcome::Superseded,
            "conflict" => return Err(Error::Conflict),
            _ => return Err(Error::Database),
        }
    } else {
        store_pre37(c, r, incomplete).await?
    };
    tx.commit().await.map_err(|e| match e {
        crate::runs::Error::Database(ref db)
            if db
                .as_database_error()
                .is_some_and(|d| d.is_check_violation()) =>
        {
            Error::Refused
        }
        other => other.into(),
    })?;
    Ok(outcome)
}

async fn store_pre37(
    c: &mut PgConnection,
    r: &UsageReport,
    incomplete: Option<&str>,
) -> Result<Outcome, Error> {
    sqlx::query("SELECT openmettle.quota_lock_gateway_request_for_settlement($1::uuid)")
        .bind(&r.request)
        .execute(&mut *c)
        .await?;
    let row = sqlx::query(
        "SELECT q.units,s.revision,s.final,s.outstanding
           FROM openmettle.gateway_requests q
           LEFT JOIN openmettle.gateway_settlements s ON s.request_id=q.id
          WHERE q.id=$1::uuid AND q.state='handed_off' AND q.dispatched_at IS NOT NULL
            AND q.report_source=$2::uuid AND q.installation=$3::uuid
            AND q.actor_user_id=$4::uuid AND q.scope_id=$5::uuid",
    )
    .bind(&r.request)
    .bind(&r.source)
    .bind(&r.installation)
    .bind(&r.principal)
    .bind(&r.scope)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Error::Refused)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM openmettle.gateway_usage_reports
          WHERE (source,report_id,revision)=($2::uuid,$3::uuid,$4)
             OR (request_id,revision)=($1::uuid,$4))",
    )
    .bind(&r.request)
    .bind(&r.source)
    .bind(&r.report_id)
    .bind(r.revision)
    .fetch_one(&mut *c)
    .await?;
    let reject_shape = r.revision == 0
        || r.cost.is_some()
        || r.unit.is_some()
        || (r.r#final
            && incomplete.is_none()
            && (r.prompt_tokens.is_none() || r.completion_tokens.is_none()));
    let inserted = if exists {
        if !evidence(EXACT_REPORT, r, incomplete)
            .fetch_one(&mut *c)
            .await?
            .try_get::<bool, _>(0)?
        {
            return Err(Error::Conflict);
        }
        if is_accepted_report(c, &r.request, &r.source, &r.report_id, r.revision).await? {
            return Ok(Outcome::Duplicate);
        }
        if reject_shape {
            return Err(Error::Refused);
        }
        0
    } else {
        if reject_shape {
            return Err(Error::Refused);
        }
        let rows = evidence(INSERT_REPORT, r, incomplete)
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
        if rows == 0
            && !evidence(EXACT_REPORT, r, incomplete)
                .fetch_one(&mut *c)
                .await?
                .try_get::<bool, _>(0)?
        {
            return Err(Error::Conflict);
        }
        rows
    };
    let previous_revision = row.try_get::<Option<i64>, _>("revision")?;
    if previous_revision == Some(r.revision) {
        settle_quota(c, r).await?;
        Ok(Outcome::Duplicate)
    } else if previous_revision.is_some_and(|rev| rev > r.revision)
        || row.try_get::<Option<bool>, _>("final")? == Some(true) && !r.r#final
    {
        Ok(if inserted == 0 {
            Outcome::Duplicate
        } else {
            Outcome::Superseded
        })
    } else {
        let units = row.try_get::<i64, _>("units")?;
        let amount = r.measured().map(|n| n.to_string());
        let previous = row
            .try_get::<Option<i64>, _>("outstanding")?
            .unwrap_or(units);
        sqlx::query("SAVEPOINT gateway_fold")
            .execute(&mut *c)
            .await?;
        apply(c, r, amount.clone(), previous).await?;
        let actual: Option<(i64, bool)> = sqlx::query_as(
            "SELECT held_units,state='settled' FROM openmettle.quota_reservations
              WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'",
        )
        .bind(&r.request)
        .fetch_optional(&mut *c)
        .await?;
        let (held, closed) = match actual {
            Some(folded) => folded,
            None => legacy_outstanding(c, r, units).await?,
        };
        if r.r#final && !closed {
            return Err(Error::Refused);
        }
        if held != previous {
            sqlx::query("ROLLBACK TO SAVEPOINT gateway_fold")
                .execute(&mut *c)
                .await?;
            apply(c, r, amount, held).await?;
        }
        Ok(Outcome::Applied)
    }
}
