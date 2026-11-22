//! Read-only verification of the SQL ledgers and their current directory entries.
use super::*;
use rustix::fs::Dir;

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

pub async fn verify_accounting_drift(pool: &PgPool, store: Option<&Store>) -> Result<Drift, Error> {
    let (storage_accounts,budgets,settlements,pending_gateway):(i64,i64,i64,i64)=sqlx::query_as(
        "SELECT storage_mismatches,budget_mismatches,settlement_mismatches,pending_gateway_reconciliations
        FROM openmettle.quota_verify_accounting_drift()").fetch_one(pool).await?;
    let mut report = Drift {
        storage_accounts,
        budgets,
        settlements,
        pending_gateway,
        ..Drift::default()
    };
    let Some(store) = store else {
        let disabled:bool=sqlx::query_scalar("SELECT volume_id IS NULL AND adoption_run_id IS NULL
            AND NOT EXISTS (SELECT FROM openmettle.storage_reservations) AND NOT EXISTS (SELECT FROM openmettle.artifact_revisions)
            FROM openmettle.storage_volume_control WHERE id").fetch_one(pool).await?;
        return if disabled { Ok(report) } else { Err(Error::Io) };
    };
    let pin = store.prepare(pool, false).await?.ok_or(Error::Io)?;
    let v = &store.volume;
    let by_id = sqlx::AssertSqlSafe(format!("{INVENTORY} WHERE s.id=$1::uuid"));
    let paged = sqlx::AssertSqlSafe(format!(
        "{INVENTORY} WHERE s.id>$1::uuid ORDER BY s.id LIMIT 100"
    ));
    let mut cursor = "00000000-0000-0000-0000-000000000000".to_owned();
    loop {
        let page = sqlx::query(sqlx::AssertSqlSafe(paged.0.as_str()))
            .bind(&cursor)
            .fetch_all(pool)
            .await?;
        if page.is_empty() {
            break;
        }
        for row in page {
            cursor = row.get("id");
            if row.get::<bool, _>("adoption_unverified") {
                report.quarantined += 1;
                continue;
            }
            let mut result = check(v, &row);
            if result.is_err() {
                // A retained row may have finished purging since the original inventory snapshot.
                let updated = sqlx::query(sqlx::AssertSqlSafe(by_id.0.as_str()))
                    .bind(&cursor)
                    .fetch_one(pool)
                    .await?;
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
            let entry = entry?;
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
                .fetch_optional(pool)
                .await?;
            if row.is_none() && v.inode(dir, name)?.is_some() {
                report.files += 1;
            }
        }
    }
    v.verify(&pin)?;
    Ok(report)
}
