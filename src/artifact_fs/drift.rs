//! Read-only verification of the SQL ledgers and their current directory entries.
use super::*;
use rustix::fs::Dir;
use std::time::Instant;

#[derive(Debug, Default)]
pub struct Drift {
    pub storage_accounts: i64,
    pub budgets: i64,
    pub settlements: i64,
    pub pending_gateway: i64,
    pub files: u64,
    pub quarantined: u64,
    pub unsettled_payloads: u64,
}
impl Drift {
    pub fn healthy(&self) -> bool {
        self.storage_accounts == 0
            && self.budgets == 0
            && self.settlements == 0
            && self.files == 0
            && self.quarantined == 0
    }
}

const INVENTORY:&str="SELECT s.id::text,s.state,s.adoption_unverified,s.payload_ino::text,s.reclaim_state,s.publish_pending,
    r.state AS revision_state,r.purge_stage,r.size_bytes
    FROM openmettle.storage_reservations s LEFT JOIN openmettle.artifact_revisions r
    ON r.scope_id=s.scope_id AND r.reservation_id=s.id";

fn check(v: &Volume, row: &sqlx::postgres::PgRow) -> Result<bool, Error> {
    let id: &str = row.get("id");
    let bound = row
        .get::<Option<&str>, _>("payload_ino")
        .map(|s| s.parse::<u64>())
        .transpose()
        .map_err(|_| Error::Io)?;
    let reclaim: &str = row.get("reclaim_state");
    let state: &str = row.get("state");
    let rev: Option<&str> = row.get("revision_state");
    let purge: Option<&str> = row.get("purge_stage");
    let s = v.inode(&v.staging, id)?;
    let r = v.inode(&v.revisions, id)?;
    let a = format!(".reclaim.{id}");
    let p = format!(".purge.{id}");
    let reclaim_anchor = v.inode(&v.staging, &a)?;
    let purge_anchor = v.inode(&v.revisions, &p)?;
    for (anchor, dir, name, valid) in [
        (
            reclaim_anchor,
            &v.staging,
            &a,
            matches!(
                (state, reclaim),
                ("reserved", "claiming" | "truncated") | ("released", "anchor_pending_unlink")
            ),
        ),
        (
            purge_anchor,
            &v.revisions,
            &p,
            rev == Some("purging")
                || (rev == Some("purged") && purge == Some("anchor_pending_unlink")),
        ),
    ] {
        if anchor.is_some()
            && (!valid || anchor != bound || v.regular(dir, name, false)?.metadata()?.len() != 0)
        {
            return Err(Error::Io);
        }
    }
    match state {
        "released" if r.is_none() && s.is_none() => Ok(false),
        "reserved" => {
            if bound.is_none() && r.is_some() {
                return Err(Error::Io);
            }
            if bound.is_some()
                && (s.into_iter().chain(r).any(|ino| Some(ino) != bound)
                    || (s.is_none() && r.is_none() && reclaim_anchor.is_none()))
            {
                return Err(Error::Io);
            }
            if reclaim == "truncated" && (s.is_some() || r.is_some() || reclaim_anchor.is_none()) {
                return Err(Error::Io);
            }
            Ok(r.is_some())
        }
        "settled" => {
            let size = row.get::<i64, _>("size_bytes") as u64;
            if rev == Some("purged") {
                return if s.is_none() && r.is_none() {
                    Ok(false)
                } else {
                    Err(Error::Io)
                };
            }
            if rev == Some("lost") {
                return if bound.is_none()
                    && s.is_none()
                    && r.is_none()
                    && reclaim_anchor.is_none()
                    && purge_anchor.is_none()
                {
                    Ok(false)
                } else {
                    Err(Error::Io)
                };
            }
            if bound.is_none()
                || s.is_some_and(|i| Some(i) != bound)
                || r.is_some_and(|i| Some(i) != bound)
            {
                return Err(Error::Io);
            }
            if let Some(ino) = r {
                let f = v.regular(&v.revisions, id, false)?;
                v.matches(&f, &v.revisions, id, ino)?;
                let len = f.metadata()?.len();
                if matches!(rev, Some("active" | "retained")) && len == size
                    || rev == Some("purging") && (len == 0 || len == size && purge_anchor.is_none())
                {
                    return Ok(false);
                }
            } else if rev == Some("purging") && purge_anchor.is_some() {
                return Ok(false);
            }
            Err(Error::Io)
        }
        _ => Err(Error::Io),
    }
}

async fn ledgers(c: &mut PgConnection) -> Result<Drift, Error> {
    let (storage_accounts,budgets,settlements,pending_gateway):(i64,i64,i64,i64)=sqlx::query_as(
        "SELECT storage_mismatches,budget_mismatches,settlement_mismatches,pending_gateway_reconciliations
        FROM openmettle.quota_verify_accounting_drift()").fetch_one(c).await?;
    Ok(Drift {
        storage_accounts,
        budgets,
        settlements,
        pending_gateway,
        ..Drift::default()
    })
}

pub(crate) async fn verify_ledgers_on(c: &mut PgConnection) -> Result<Drift, Error> {
    ledgers(c).await
}

pub async fn verify_accounting_drift(pool: &PgPool, store: Option<&Store>) -> Result<Drift, Error> {
    let Some(store) = store else {
        let mut c = pool.acquire().await?;
        let report = ledgers(&mut c).await?;
        let disabled:bool=sqlx::query_scalar("SELECT volume_id IS NULL AND adoption_run_id IS NULL
            AND NOT EXISTS (SELECT FROM openmettle.storage_reservations) AND NOT EXISTS (SELECT FROM openmettle.artifact_revisions)
            FROM openmettle.storage_volume_control WHERE id").fetch_one(&mut *c).await?;
        return if disabled { Ok(report) } else { Err(Error::Io) };
    };
    let pin = store.prepare(pool, false).await?.ok_or(Error::Io)?;
    verify_volume(&mut *pool.acquire().await?, &store.volume, &pin).await
}

/// The ledgers and every directory entry of the pinned volume, on a connection the caller
/// holds. Rebind runs it inside its own transaction, under the adoption barrier.
pub(super) async fn verify_volume(
    c: &mut PgConnection,
    v: &Volume,
    pin: &str,
) -> Result<Drift, Error> {
    verify_volume_inner(c, v, pin, None, None).await
}

/// Restore-phase volume and ledger drift verification on a connection holding
/// `storage_volume_control FOR SHARE`. At elapsed-time `yield_interval` checkpoints during
/// synchronous per-row or directory-entry checks, runs a lightweight `SELECT 1` on `c` (keeping
/// `tx_pin` non-idle against `idle_in_transaction_session_timeout`) and yields cooperatively so
/// the concurrent lease-renewal heartbeat on Connection 2 can extend the volume-phase lease.
pub(crate) async fn verify_volume_on(
    c: &mut PgConnection,
    store: &Store,
    pin: &str,
    yield_interval: Duration,
) -> Result<Drift, Error> {
    verify_volume_inner(c, &store.volume, pin, Some(yield_interval), None).await
}

/// Test hook exercising `verify_volume_inner` with a controlled synchronous per-item filesystem
/// delay to verify `SELECT 1` idle-in-transaction keepalive behavior on PostgreSQL 18.
#[doc(hidden)]
pub async fn verify_volume_for_test(
    c: &mut PgConnection,
    store: &Store,
    pin: &str,
    yield_interval: Option<Duration>,
    per_item_delay: Option<Duration>,
) -> Result<Drift, Error> {
    verify_volume_inner(c, &store.volume, pin, yield_interval, per_item_delay).await
}

async fn verify_volume_inner(
    c: &mut PgConnection,
    v: &Volume,
    pin: &str,
    yield_interval: Option<Duration>,
    per_item_delay: Option<Duration>,
) -> Result<Drift, Error> {
    let mut report = ledgers(c).await?;
    let mut last_yield;
    let by_id = sqlx::AssertSqlSafe(format!("{INVENTORY} WHERE s.id=$1::uuid"));
    let paged = sqlx::AssertSqlSafe(format!(
        "{INVENTORY} WHERE ($1::uuid IS NULL OR s.id>$1::uuid) ORDER BY s.id LIMIT 100"
    ));
    let mut cursor: Option<String> = None;
    loop {
        let page = sqlx::query(sqlx::AssertSqlSafe(paged.0.as_str()))
            .bind(&cursor)
            .fetch_all(&mut *c)
            .await?;
        last_yield = Instant::now();
        if page.is_empty() {
            break;
        }
        for row in page {
            if let Some(interval) = yield_interval
                && last_yield.elapsed() >= interval
            {
                sqlx::query("SELECT 1").execute(&mut *c).await?;
                tokio::task::yield_now().await;
                last_yield = Instant::now();
            }
            let id: String = row.get("id");
            cursor = Some(id.clone());
            if row.get::<bool, _>("adoption_unverified") {
                report.quarantined += 1;
                continue;
            }
            let mut result = check(v, &row);
            if let Some(delay) = per_item_delay {
                std::thread::sleep(delay);
            }
            if result.is_err() {
                // A retained row may have finished purging since the original inventory snapshot.
                let updated = sqlx::query(sqlx::AssertSqlSafe(by_id.0.as_str()))
                    .bind(&id)
                    .fetch_one(&mut *c)
                    .await?;
                last_yield = Instant::now();
                if updated.get::<bool, _>("adoption_unverified") {
                    report.quarantined += 1;
                    continue;
                }
                result = check(v, &updated);
            }
            match result {
                Ok(true) => report.unsettled_payloads += 1,
                Ok(false) => {}
                Err(_) => report.files += 1,
            }
        }
    }
    for (dir, anchor) in [(&v.revisions, ".purge."), (&v.staging, ".reclaim.")] {
        for entry in Dir::read_from(dir)? {
            if let Some(interval) = yield_interval
                && last_yield.elapsed() >= interval
            {
                sqlx::query("SELECT 1").execute(&mut *c).await?;
                tokio::task::yield_now().await;
                last_yield = Instant::now();
            }
            let entry = entry?;
            if let Some(delay) = per_item_delay {
                std::thread::sleep(delay);
            }
            let Ok(name) = entry.file_name().to_str() else {
                report.files += 1;
                continue;
            };
            if matches!(name, "." | ".." | ".openmettle-volume-id")
                || name.starts_with(".openmettle-volume-id.tmp.")
            {
                continue;
            }
            let id = name.strip_prefix(anchor).unwrap_or(name);
            if !runs::is_canonical_uuid(id) {
                report.files += 1;
                continue;
            }
            let row = sqlx::query(sqlx::AssertSqlSafe(by_id.0.as_str()))
                .bind(id)
                .fetch_optional(&mut *c)
                .await?;
            last_yield = Instant::now();
            if row.is_none() && !matches!(v.inode(dir, name), Ok(None)) {
                report.files += 1;
            }
        }
    }
    v.verify(pin)?;
    Ok(report)
}
