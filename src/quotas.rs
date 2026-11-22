//! Transactional quota operations paired with gateway allocation and dispatch.
use crate::{
    authz::gateway::{Authority, Call, Error, Reservation},
    runs::WriteTransaction,
};

pub(crate) async fn prepare_round(
    tx: &mut WriteTransaction<'_>,
    call: &Call<'_>,
) -> Result<(), Error> {
    if let Authority::Lease { run, round, token } = call.authority {
        sqlx::query(
            "SELECT openmettle.quota_unwind_superseded_round($1::uuid,$2::uuid,$3::uuid,$4)",
        )
        .bind(call.reservation.scope_id)
        .bind(run)
        .bind(token)
        .bind(round)
        .execute(tx.connection()?)
        .await?;
        sqlx::query("SELECT openmettle.quota_ensure_legacy_run_holds($1::uuid,$2::uuid,$3::uuid)")
            .bind(call.reservation.scope_id)
            .bind(run)
            .bind(token)
            .execute(tx.connection()?)
            .await?;
    }
    Ok(())
}

pub(crate) async fn cost_ceiling(
    tx: &mut WriteTransaction<'_>,
    owner: &Reservation<'_>,
    supplied: Option<i64>,
) -> Result<Option<i64>, Error> {
    let configured: Option<i64> =
        sqlx::query_scalar("SELECT openmettle.quota_cost_ceiling($1::uuid,$2::uuid)")
            .bind(owner.scope_id)
            .bind(owner.actor)
            .fetch_one(tx.connection()?)
            .await?;
    match (configured, supplied) {
        (None, None) => Ok(None),
        (Some(limit), Some(n)) if n > 0 && n <= limit => Ok(Some(n)),
        (Some(n), None) if n > 0 => Ok(Some(n)),
        _ => Err(Error::Refused),
    }
}

pub(crate) async fn bind_request(
    tx: &mut WriteTransaction<'_>,
    call: &Call<'_>,
    id: &str,
    secret: &[u8],
    supplied: Option<i64>,
) -> Result<(), Error> {
    let cost = cost_ceiling(tx, &call.reservation, supplied).await?;
    for (resource, amount) in [
        ("usage_cost_micros", cost),
        ("usage_tokens", Some(call.units)),
    ] {
        let Some(amount) = amount else { continue };
        match call.authority {
            Authority::Session { .. } => {
                sqlx::query(
                    "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,$3,$4,$5,NULL,$6::uuid,$7,
                    clock_timestamp()+interval '15 minutes')",
                )
                .bind(call.reservation.scope_id)
                .bind(call.reservation.actor)
                .bind(resource)
                .bind(amount)
                .bind(format!("request:{id}"))
                .bind(id)
                .bind(secret)
                .execute(tx.connection()?)
                .await?;
            }
            Authority::Lease { token, .. } => {
                sqlx::query("SELECT openmettle.quota_allocate_round($1::uuid,$2,$3::uuid,$4,$5)")
                    .bind(id)
                    .bind(secret)
                    .bind(token)
                    .bind(resource)
                    .bind(amount)
                    .execute(tx.connection()?)
                    .await?;
            }
        }
    }
    Ok(())
}

use sqlx::PgPool;

const NIL: &str = "00000000-0000-0000-0000-000000000000";
const MAX: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";

/// One fixed upper bound per pass. Timestamps travel as PostgreSQL text to preserve precision.
#[derive(Default)]
pub(crate) struct Pass {
    upper: Option<String>,
    after: Option<(String, String)>,
}
impl Pass {
    fn cursor(&self) -> (&str, &str) {
        self.after
            .as_ref()
            .map_or(("-infinity", NIL), |(at, id)| (at, id))
    }
}

pub(crate) async fn reconcile_stale_quotas(
    pool: &PgPool,
    pass: &mut Pass,
    limit: i32,
) -> Result<(), crate::runs::Error> {
    if !(1..=1000).contains(&limit) {
        return Err(crate::runs::Error::Invalid);
    }
    if pass.upper.is_none() {
        pass.upper = Some(
            sqlx::query_scalar("SELECT clock_timestamp()::text")
                .fetch_one(pool)
                .await?,
        );
    }
    let (at, id) = pass.cursor();
    let page=sqlx::query_as::<_,(String,String,bool)>("WITH page AS MATERIALIZED (
        SELECT lease_expires_at,id,run_id FROM openmettle.quota_reservations WHERE state='held'
        AND (lease_expires_at,id)>($1::text::timestamptz,$2::uuid)
        AND (lease_expires_at,id)<=($3::text::timestamptz,$4::uuid) ORDER BY lease_expires_at,id LIMIT $5)
        SELECT p.lease_expires_at::text,p.id::text,(p.run_id IS NULL OR EXISTS (SELECT FROM openmettle.runs r
        WHERE r.id=p.run_id AND r.state IN ('succeeded','failed','cancelled','interrupted')
        AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id=r.id AND o.outcome IN ('intent','outcome_unknown'))))
        FROM page p ORDER BY p.lease_expires_at,p.id")
        .bind(at).bind(id).bind(&pass.upper).bind(MAX).bind(limit).fetch_all(pool).await?;
    let count = page.len();
    for (at, id, eligible) in page {
        pass.after = Some((at, id.clone()));
        if eligible {
            let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
            sqlx::query("SELECT openmettle.quota_release_unsent($1::uuid,NULL,true)")
                .bind(&id)
                .execute(tx.connection()?)
                .await?;
            tx.commit().await?;
        }
    }
    if count < limit as usize {
        *pass = Pass::default();
    }
    Ok(())
}

/// One short transaction can unwind at most one orphan. An early return after a release
/// advances the cursor without mistaking the partially inspected page for the end of a pass.
pub(crate) async fn orphan_page(
    pool: &PgPool,
    pass: &mut Pass,
    limit: i32,
) -> Result<(bool, i32), crate::runs::Error> {
    if !(1..=1000).contains(&limit) {
        return Err(crate::runs::Error::Invalid);
    }
    if pass.upper.is_none() {
        pass.upper = Some(
            sqlx::query_scalar("SELECT (clock_timestamp()-interval '15 minutes')::text")
                .fetch_one(pool)
                .await?,
        );
    }
    let (at, id) = pass.cursor();
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let (at,id,scanned,released):(String,String,i32,i32)=sqlx::query_as("SELECT next_created_at::text,next_id::text,
        raw_keys_scanned,released_count FROM openmettle.quota_release_orphan_gateway_requests(interval '15 minutes',
        $1::text::timestamptz,$2::uuid,$3::text::timestamptz,$4::uuid,$5)")
        .bind(at).bind(id).bind(&pass.upper).bind(MAX).bind(limit).fetch_one(tx.connection()?).await?;
    tx.commit().await?;
    let done = released == 0 && scanned < limit;
    if done {
        *pass = Pass::default();
    } else {
        pass.after = Some((at, id));
    }
    Ok((done, released))
}

/// Perform a complete bounded-key pass after old writers have drained. Each release commits separately.
pub async fn drain_gateway_orphans(pool: &PgPool) -> Result<u64, crate::runs::Error> {
    let mut pass = Pass::default();
    let mut total = 0;
    loop {
        let (done, released) = orphan_page(pool, &mut pass, 100).await?;
        total += released as u64;
        if done {
            return Ok(total);
        }
    }
}

pub(crate) async fn emit_warnings(pool: &PgPool) -> Result<(), sqlx::Error> {
    let warnings = sqlx::query_as::<_, (String, String, String, i16, i64)>(
        "SELECT * FROM openmettle.quota_take_warnings(100)",
    )
    .fetch_all(pool)
    .await?;
    for (target, scope, resource, threshold, bucket) in warnings {
        crate::telemetry::quota_warning(&target, &scope, &resource, threshold, bucket);
    }
    Ok(())
}

/// Count a bounded index page without taking row locks or changing the underlying holds.
pub(crate) async fn observe_overdue_handoffs(pool: &PgPool, limit: i32) -> Result<(), sqlx::Error> {
    let observed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT id FROM openmettle.quota_reservations
         WHERE state='handoff_committed' AND lease_expires_at <= statement_timestamp()
         ORDER BY lease_expires_at,id LIMIT $1) AS overdue",
    )
    .bind(limit)
    .fetch_one(pool)
    .await?;
    crate::telemetry::metrics::global().record_overdue_handoffs(observed as u64);
    Ok(())
}
