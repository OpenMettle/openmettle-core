//! Restore reconciliation (ADR 0041): deletion journal export, the owner's verification and
//! replay of an export into a restored database, unsettled-upload scrub, audited break-glass
//! coverage-gap acceptance, and the gate the worker reads before claiming runs or purging.
//! Migration 41 makes every database decision: origin, watermark, chain and record checks, lag
//! against the restored snapshot and locked requirement, coverage completeness, and whether the
//! gate may open. This module moves the records and drives the volume-pinned purge and scrub.
//!
//! Export format, one line each, `\n` terminated:
//! - header `openmettle.deletion_journal.export/1`
//! - `origin <coverage_started_us>` (Unix microseconds of `deletion_journal_head.coverage_started_at`)
//! - zero or more record lines:
//!   `seq recorded_us event_kind entity_id scope_id original_purge_after_us purged_us content_digest policy_revision chain_digest`
//!   (times in Unix microseconds, digests in 64-character lowercase hex, canonical UUIDs, `-` for NULL policy revision)
//! - `watermark <seq> <chain_digest> <exported_us>`
//! - `sha256 <hex>` over every preceding byte.
//!
//! The checksum detects damage, not forgery: the chain and origin are verified against the
//! restored database and the independently recorded `(required_seq, required_digest)` watermark.
use crate::{
    artifact_fs::{self, Store},
    authz::projects::hex,
    runs::{self, digest},
};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::fmt::Write;

const HEADER: &str = "openmettle.deletion_journal.export/1";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Strict 64-character lowercase hexadecimal SHA-256 digest check.
pub fn is_valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_trimmed_text(s: &str, max_bytes: usize) -> bool {
    !s.is_empty() && s.len() <= max_bytes && s.trim() == s && !s.chars().any(char::is_control)
}

#[derive(Debug)]
pub enum Error {
    /// The export is truncated, fails its checksum, is malformed or out of sequence.
    Export(&'static str),
    /// A caller-supplied argument (digest, sequence, operator ID, request key or reason) is invalid.
    Invalid(&'static str),
    /// A migration 41 check refused (OMR02 to OMR05, OMQ03, 25000, 22023, 23505) or the database
    /// failed. Every refusal rolled its transaction back.
    Database(sqlx::Error),
    /// Purging a resurrected payload, scrubbing an unsettled upload, or reading the volume failed.
    Storage(artifact_fs::Error),
    /// The volume and the ledgers disagree after replay and scrub, or unsettled payloads remain.
    Drift,
    /// The volume is pinned or has an adoption barrier, so replay needs its artifact root.
    ArtifactRootRequired,
    /// The artifact volume was restored by file copy and must be rebound before replay.
    RebindRequired,
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}

impl From<artifact_fs::Error> for Error {
    fn from(e: artifact_fs::Error) -> Self {
        Self::Storage(e)
    }
}

/// `(seq, recorded_us, event_kind, entity_id, scope_id, original_purge_after_us, purged_us,
/// content_digest, policy_revision, chain_digest)`, as exported.
type Record = (
    i64,
    i64,
    String,
    String,
    String,
    i64,
    i64,
    String,
    Option<i64>,
    String,
);

/// A checksummed export: installation origin, every record from 1 in order, and watermark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    records: Vec<Record>,
    pub origin_us: i64,
    pub seq: i64,
    pub digest: String,
}

async fn read_committed(pool: &PgPool) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Whether the restore gate is open. A schema before 41 has no gate table, so nothing can have
/// closed it and work proceeds as before; a missing gate row, or any error, reads as closed.
pub async fn gate_open(c: &mut PgConnection) -> Result<bool, sqlx::Error> {
    let gated: bool = sqlx::query_scalar(
        "SELECT to_regclass('openmettle.restore_reconciliation_gate') IS NOT NULL",
    )
    .fetch_one(&mut *c)
    .await?;
    if !gated {
        return Ok(true);
    }
    Ok(
        sqlx::query_scalar("SELECT open FROM openmettle.restore_reconciliation_gate WHERE id")
            .fetch_optional(c)
            .await?
            .unwrap_or(false),
    )
}

/// Exports the whole journal and its installation origin from one snapshot, as the owner.
pub async fn export(pool: &PgPool) -> Result<String, Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let us = |column: &str| format!("(extract(epoch FROM {column}) * 1000000)::bigint");
    let records: Vec<Record> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT journal_seq, {}, event_kind, entity_id::text, scope_id::text, {}, {},
                encode(content_digest, 'hex'), policy_revision, encode(chain_digest, 'hex')
           FROM openmettle.deletion_journal ORDER BY journal_seq",
        us("recorded_at"),
        us("original_purge_after"),
        us("purged_at")
    )))
    .fetch_all(&mut *tx)
    .await?;
    let (seq, chain, origin_us, at): (i64, String, i64, i64) =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT journal_seq, encode(chain_digest, 'hex'), {}, {}
               FROM openmettle.deletion_journal_head WHERE id",
            us("coverage_started_at"),
            us("clock_timestamp()")
        )))
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut text = format!("{HEADER}\norigin {origin_us}\n");
    for (i, r) in records.iter().enumerate() {
        if r.0 != i as i64 + 1 {
            return Err(Error::Export("journal out of sequence"));
        }
        let policy = r.8.map_or("-".into(), |p| p.to_string());
        let _ = writeln!(
            text,
            "{} {} {} {} {} {} {} {} {policy} {}",
            r.0, r.1, r.2, r.3, r.4, r.5, r.6, r.7, r.9
        );
    }
    if (seq, chain.as_str()) != records.last().map_or((0, GENESIS), |r| (r.0, r.9.as_str())) {
        return Err(Error::Export("journal head does not match its last record"));
    }
    let _ = writeln!(text, "watermark {seq} {chain} {at}");
    let sum = hex(&digest(text.as_bytes()));
    let _ = writeln!(text, "sha256 {sum}");
    Ok(text)
}

impl Export {
    /// Checks the checksum, format, origin, strict 64-char lowercase hex digests, canonical UUIDs,
    /// record order (1, 2, 3, ... with no gap), and that the watermark names the last record.
    /// The database verifies origin, locked watermark, and hash chain during replay.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let split = text
            .rfind("\nsha256 ")
            .ok_or(Error::Export("missing checksum"))?
            + 1;
        let (body, trailer) = text.split_at(split);
        if trailer != format!("sha256 {}\n", hex(&digest(body.as_bytes()))) {
            return Err(Error::Export("checksum mismatch"));
        }
        if body.contains('\r') {
            return Err(Error::Export("malformed line"));
        }
        let mut lines = body.lines();
        if lines.next() != Some(HEADER) {
            return Err(Error::Export("unknown format"));
        }
        let number = |s: &str| {
            s.parse::<i64>()
                .map_err(|_| Error::Export("malformed number"))
        };
        let origin_us = match lines.next() {
            Some(line) => match line.split(' ').collect::<Vec<_>>()[..] {
                ["origin", origin] => number(origin)?,
                _ => return Err(Error::Export("missing or malformed origin")),
            },
            None => return Err(Error::Export("missing or malformed origin")),
        };
        let mut records: Vec<Record> = Vec::new();
        let mut watermark = None;
        for line in lines {
            match line.split(' ').collect::<Vec<_>>()[..] {
                ["watermark", seq, chain, at] if watermark.is_none() => {
                    let seq = number(seq)?;
                    if seq < 0 {
                        return Err(Error::Export("malformed number"));
                    }
                    if !is_valid_digest(chain) {
                        return Err(Error::Export("malformed digest"));
                    }
                    number(at)?;
                    watermark = Some((seq, chain.to_owned()));
                }
                [
                    seq,
                    at,
                    kind,
                    entity,
                    scope,
                    after,
                    purged,
                    content,
                    policy,
                    chain,
                ] if watermark.is_none() => {
                    let seq = number(seq)?;
                    if seq != records.len() as i64 + 1 {
                        return Err(Error::Export("records out of sequence"));
                    }
                    if kind != "artifact_revision.purged" {
                        return Err(Error::Export("unknown event kind"));
                    }
                    if !runs::is_canonical_uuid(entity) || !runs::is_canonical_uuid(scope) {
                        return Err(Error::Export("malformed uuid"));
                    }
                    if !is_valid_digest(content) || !is_valid_digest(chain) {
                        return Err(Error::Export("malformed digest"));
                    }
                    let policy = match policy {
                        "-" => None,
                        p => {
                            let rev = number(p)?;
                            if rev <= 0 {
                                return Err(Error::Export("malformed number"));
                            }
                            Some(rev)
                        }
                    };
                    records.push((
                        seq,
                        number(at)?,
                        kind.into(),
                        entity.into(),
                        scope.into(),
                        number(after)?,
                        number(purged)?,
                        content.into(),
                        policy,
                        chain.into(),
                    ));
                }
                _ => return Err(Error::Export("malformed line")),
            }
        }
        let (seq, digest) = watermark.ok_or(Error::Export("missing watermark"))?;
        if (seq, digest.as_str()) != records.last().map_or((0, GENESIS), |r| (r.0, r.9.as_str())) {
            return Err(Error::Export("watermark does not match the last record"));
        }
        Ok(Self {
            records,
            origin_us,
            seq,
            digest,
        })
    }
}

/// Closes the gate after a restore (migration 41's `restore_gate_lock`) with the independently
/// recorded target watermark `(required_seq, required_digest)` and `coverage_complete` flag,
/// returning `(snapshot_journal_seq, required_journal_seq, coverage_complete)`.
pub async fn lock(
    pool: &PgPool,
    required_seq: i64,
    required_digest: &str,
    coverage_complete: bool,
) -> Result<(i64, i64, bool), Error> {
    if required_seq < 0 {
        return Err(Error::Invalid("invalid sequence"));
    }
    if !is_valid_digest(required_digest) {
        return Err(Error::Invalid("invalid chain digest"));
    }
    let mut tx = read_committed(pool).await?;
    let state = sqlx::query_as(
        "SELECT snapshot_journal_seq, required_journal_seq, coverage_complete
           FROM openmettle.restore_gate_lock($1, decode($2, 'hex'), $3)",
    )
    .bind(required_seq)
    .bind(required_digest)
    .bind(coverage_complete)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(state)
}

/// Audited operator break-glass acceptance of an unexported purge window after the last surviving
/// export (`restore_accept_coverage_gap`). Returns `true` when freshly applied and `false` on an
/// exact idempotent replay.
pub async fn accept_coverage_gap(
    pool: &PgPool,
    operator_id: &str,
    request_key: &str,
    reason: &str,
) -> Result<bool, Error> {
    if !runs::is_canonical_uuid(operator_id) {
        return Err(Error::Invalid("invalid operator id"));
    }
    if !valid_trimmed_text(request_key, 128) {
        return Err(Error::Invalid("invalid request key"));
    }
    if !valid_trimmed_text(reason, 512) {
        return Err(Error::Invalid("invalid reason"));
    }
    let mut tx = read_committed(pool).await?;
    let applied: bool =
        sqlx::query_scalar("SELECT openmettle.restore_accept_coverage_gap($1::uuid, $2, $3)")
            .bind(operator_id)
            .bind(request_key)
            .bind(reason)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(applied)
}

/// Preflight check for whether `store` was restored by file copy without running
/// `openmettle-admin storage rebind`. Returns `Err(Error::RebindRequired)` if detected.
pub async fn check_rebind(pool: &PgPool, store: &Store) -> Result<(), Error> {
    if store.awaits_rebind() {
        return Err(Error::RebindRequired);
    }
    let _ = store.verify_startup(pool, false).await;
    if store.awaits_rebind() {
        return Err(Error::RebindRequired);
    }
    Ok(())
}

/// The database phase: verifies installation origin and locked watermark via
/// `restore_verify_export` and replays every record in ONE `READ COMMITTED` transaction, rolling
/// everything back on any mismatch. Returns how many records were new to the restored journal.
pub async fn apply(pool: &PgPool, export: &Export) -> Result<u64, Error> {
    let mut tx = read_committed(pool).await?;
    sqlx::query("SELECT openmettle.restore_verify_export($1, $2, decode($3, 'hex'))")
        .bind(export.origin_us)
        .bind(export.seq)
        .bind(&export.digest)
        .execute(&mut *tx)
        .await?;
    let mut applied = 0;
    for r in &export.records {
        let new: bool = sqlx::query_scalar(
            "SELECT openmettle.deletion_journal_replay($1, $2, $3, $4::uuid, $5::uuid, $6, $7,
                    decode($8, 'hex'), $9, decode($10, 'hex'))",
        )
        .bind(r.0)
        .bind(r.1)
        .bind(&r.2)
        .bind(&r.3)
        .bind(&r.4)
        .bind(r.5)
        .bind(r.6)
        .bind(&r.7)
        .bind(r.8)
        .bind(&r.9)
        .fetch_one(&mut *tx)
        .await?;
        applied += u64::from(new);
    }
    tx.commit().await?;
    Ok(applied)
}

/// The volume phase, rerunnable after `apply` committed: refuses unrebound copied volumes and
/// active adoption/rebind barriers, purges resurrected payloads of replayed revisions, scrubs
/// unsettled uploads that cannot survive a restore, verifies the volume and ledgers with zero
/// unsettled payloads, and opens the gate if migration 41's checks pass.
pub async fn finish(pool: &PgPool, store: Option<&Store>, export: &Export) -> Result<(), Error> {
    let (pinned, adopting): (bool, bool) = sqlx::query_as(
        "SELECT volume_id IS NOT NULL, adoption_run_id IS NOT NULL
           FROM openmettle.storage_volume_control WHERE id",
    )
    .fetch_one(pool)
    .await?;
    if (pinned || adopting) && store.is_none() {
        return Err(Error::ArtifactRootRequired);
    }
    if let Some(store) = store {
        if store.awaits_rebind() {
            return Err(Error::RebindRequired);
        }
        if adopting {
            sqlx::query("SELECT openmettle.storage_lock_pinned_volume()")
                .execute(pool)
                .await?;
        }
        if let Err(err) = artifact_fs::purge_journaled(pool, store).await {
            return Err(if store.awaits_rebind() {
                Error::RebindRequired
            } else {
                err.into()
            });
        }
        if let Err(err) = artifact_fs::scrub_unsettled_on_restore(pool, store).await {
            return Err(if store.awaits_rebind() {
                Error::RebindRequired
            } else {
                err.into()
            });
        }
    }
    let drift = match artifact_fs::verify_accounting_drift(pool, store).await {
        Ok(drift) => drift,
        Err(err) => {
            return Err(if store.is_some_and(Store::awaits_rebind) {
                Error::RebindRequired
            } else {
                err.into()
            });
        }
    };
    if !drift.healthy() || drift.unsettled_payloads != 0 {
        return Err(Error::Drift);
    }
    let mut tx = read_committed(pool).await?;
    sqlx::query("SELECT openmettle.restore_gate_open($1, decode($2, 'hex'))")
        .bind(export.seq)
        .bind(&export.digest)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(body: &str) -> String {
        let sum = hex(&digest(body.as_bytes()));
        format!("{body}sha256 {sum}\n")
    }

    #[test]
    fn parse_validates_origin_hex_and_uuids() {
        let valid_empty = seal(&format!(
            "{HEADER}\norigin 1700000000000000\nwatermark 0 {GENESIS} 1700000000000001\n"
        ));
        let parsed = Export::parse(&valid_empty).unwrap();
        assert_eq!(parsed.origin_us, 1_700_000_000_000_000);
        assert_eq!(parsed.seq, 0);
        assert_eq!(parsed.digest, GENESIS);

        // Missing origin line is refused.
        let missing_origin = seal(&format!("{HEADER}\nwatermark 0 {GENESIS} 1\n"));
        assert!(matches!(
            Export::parse(&missing_origin),
            Err(Error::Export("missing or malformed origin"))
        ));

        // Uppercase or truncated hex digests are refused before SQL decode().
        let upper = "A".repeat(64);
        let bad_wm = seal(&format!("{HEADER}\norigin 1\nwatermark 0 {upper} 2\n"));
        assert!(matches!(
            Export::parse(&bad_wm),
            Err(Error::Export("malformed digest"))
        ));

        let short = "0".repeat(62);
        let bad_len = seal(&format!("{HEADER}\norigin 1\nwatermark 0 {short} 2\n"));
        assert!(matches!(
            Export::parse(&bad_len),
            Err(Error::Export("malformed digest"))
        ));

        // Malformed UUID or bad hex in a record line is refused.
        let entity = "00000000-0000-4000-8000-000000000001";
        let scope = "00000000-0000-4000-8000-000000000002";
        let d = "a".repeat(64);
        let bad_uuid = seal(&format!(
            "{HEADER}\norigin 1\n1 10 artifact_revision.purged NOT-A-UUID {scope} 5 10 {d} 1 {d}\nwatermark 1 {d} 11\n"
        ));
        assert!(matches!(
            Export::parse(&bad_uuid),
            Err(Error::Export("malformed uuid"))
        ));

        let bad_content = seal(&format!(
            "{HEADER}\norigin 1\n1 10 artifact_revision.purged {entity} {scope} 5 10 zzz 1 {d}\nwatermark 1 {d} 11\n"
        ));
        assert!(matches!(
            Export::parse(&bad_content),
            Err(Error::Export("malformed digest"))
        ));

        let valid_one = seal(&format!(
            "{HEADER}\norigin 1\n1 10 artifact_revision.purged {entity} {scope} 5 10 {d} - {d}\nwatermark 1 {d} 11\n"
        ));
        let parsed = Export::parse(&valid_one).unwrap();
        assert_eq!(parsed.seq, 1);
        assert_eq!(parsed.digest, d);
    }
}
