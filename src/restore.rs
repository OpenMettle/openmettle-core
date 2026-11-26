//! Restore reconciliation (ADR 0041): deletion journal export, the owner's verification and
//! replay of an export into a restored database, exclusive restore volume-phase leasing,
//! unsettled-upload scrub, audited break-glass coverage-gap acceptance, and the gate the worker
//! reads and locks `FOR SHARE` before claiming runs or purging.
//! Migration 41 makes every database decision: origin, watermark, pinned checkpoints, chain and
//! record checks, lag against the restored snapshot and locked requirement, coverage completeness,
//! volume-phase lease ownership, and whether the gate may open. This module moves the records and
//! drives the volume-pinned purge and scrub.
//!
//! Export format, one line each, `\n` terminated:
//! - header `openmettle.deletion_journal.export/1`
//! - `origin <coverage_started_us>` (Unix microseconds of `deletion_journal_head.coverage_started_at`)
//! - zero or more record lines:
//!   `seq recorded_us event_kind entity_id scope_id original_purge_after_us purged_us content_digest policy_revision chain_digest`
//!   (times in Unix microseconds, digests in 64-character lowercase hex, canonical UUIDs, `-` for NULL policy revision)
//! - `watermark <origin_us> <seq> <chain_digest> <exported_us>`
//! - `sha256 <hex>` over every preceding byte.
//!
//! The checksum detects damage, not forgery: the chain, pinned checkpoints, and installation
//! origin are verified against the restored database and the independently recorded
//! `(required_origin_us, required_seq, required_digest)` watermark.
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
    /// A caller-supplied argument (origin, digest, sequence, UUID, request key or reason) is invalid.
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
        match e {
            artifact_fs::Error::Storage(runs::Error::Database(db)) => Self::Database(db),
            other => Self::Storage(other),
        }
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

/// Result of closing or updating the restore reconciliation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateLock {
    pub restore_run_id: String,
    pub origin_us: i64,
    pub snapshot_seq: i64,
    pub required_seq: i64,
    pub coverage_complete: bool,
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

/// Lock the restore reconciliation gate `FOR SHARE` inside the caller's transaction, returning
/// `true` only when it is open (or on pre-41 schemas where the gate helper does not exist yet).
pub(crate) async fn lock_open_gate(c: &mut PgConnection) -> Result<bool, sqlx::Error> {
    let gated: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('openmettle.restore_gate_lock_open()') IS NOT NULL",
    )
    .fetch_one(&mut *c)
    .await?;
    if !gated {
        return Ok(true);
    }
    sqlx::query_scalar("SELECT openmettle.restore_gate_lock_open()")
        .fetch_one(c)
        .await
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
    let _ = writeln!(text, "watermark {origin_us} {seq} {chain} {at}");
    let sum = hex(&digest(text.as_bytes()));
    let _ = writeln!(text, "sha256 {sum}");
    Ok(text)
}

impl Export {
    /// Checks the checksum, format, origin, strict 64-char lowercase hex digests, canonical UUIDs,
    /// record order (1, 2, 3, ... with no gap), and that the watermark names the same origin and
    /// the last record. The database verifies origin, locked watermark, pinned checkpoints, and
    /// hash chain during replay.
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
                ["watermark", wm_origin, seq, chain, at] if watermark.is_none() => {
                    let wm_origin = number(wm_origin)?;
                    if wm_origin != origin_us {
                        return Err(Error::Export(
                            "watermark origin does not match export origin",
                        ));
                    }
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

/// Closes or updates the gate after a restore (migration 41's `restore_gate_lock`) with the
/// independently recorded installation `origin_us`, target watermark `(required_seq,
/// required_digest)`, `coverage_complete` flag, optional `replace_restore_run`, and `new_restore`.
pub async fn lock(
    pool: &PgPool,
    origin_us: i64,
    required_seq: i64,
    required_digest: &str,
    coverage_complete: bool,
    replace_restore_run: Option<&str>,
    new_restore: bool,
) -> Result<GateLock, Error> {
    if required_seq < 0 {
        return Err(Error::Invalid("invalid sequence"));
    }
    if !is_valid_digest(required_digest) {
        return Err(Error::Invalid("invalid chain digest"));
    }
    if let Some(run_id) = replace_restore_run
        && !runs::is_canonical_uuid(run_id)
    {
        return Err(Error::Invalid("invalid restore run id"));
    }
    let mut tx = read_committed(pool).await?;
    let (restore_run_id, required_origin_us, snapshot_seq, required_seq, coverage_complete): (
        String,
        i64,
        i64,
        i64,
        bool,
    ) = sqlx::query_as(
        "SELECT restore_run_id::text, required_origin_us, snapshot_journal_seq,
                required_journal_seq, coverage_complete
           FROM openmettle.restore_gate_lock($1, $2, decode($3, 'hex'), $4, $5::uuid, $6)",
    )
    .bind(origin_us)
    .bind(required_seq)
    .bind(required_digest)
    .bind(coverage_complete)
    .bind(replace_restore_run)
    .bind(new_restore)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(GateLock {
        restore_run_id,
        origin_us: required_origin_us,
        snapshot_seq,
        required_seq,
        coverage_complete,
    })
}

/// Audited operator break-glass acceptance of an unexported purge window after the last surviving
/// export (`restore_accept_coverage_gap`), bound to the active `restore_run_id`. Returns `true`
/// when freshly applied and `false` on an exact idempotent replay.
pub async fn accept_coverage_gap(
    pool: &PgPool,
    restore_run_id: &str,
    operator_id: &str,
    request_key: &str,
    reason: &str,
) -> Result<bool, Error> {
    if !runs::is_canonical_uuid(restore_run_id) {
        return Err(Error::Invalid("invalid restore run id"));
    }
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
    let applied: bool = sqlx::query_scalar(
        "SELECT openmettle.restore_accept_coverage_gap($1::uuid, $2::uuid, $3, $4)",
    )
    .bind(restore_run_id)
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
/// `restore_verify_export`, replays every record, and verifies all pinned checkpoints via
/// `restore_verify_checkpoints` in ONE `READ COMMITTED` transaction, rolling everything back on
/// any mismatch. Returns how many records were new to the restored journal.
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
    sqlx::query("SELECT openmettle.restore_verify_checkpoints()")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(applied)
}

async fn claim_volume_phase(pool: &PgPool, export: &Export) -> Result<(String, String), Error> {
    let mut tx = read_committed(pool).await?;
    let lease: (String, String) = sqlx::query_as(
        "SELECT restore_run_id::text, volume_claim_token::text
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'))",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(lease)
}

async fn release_volume_phase(
    pool: &PgPool,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = read_committed(pool).await?;
    sqlx::query("SELECT openmettle.restore_release_volume_phase($1::uuid, $2::uuid)")
        .bind(restore_run_id)
        .bind(claim_token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

async fn finish_claimed(
    pool: &PgPool,
    store: Option<&Store>,
    export: &Export,
    adopting: bool,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<(), Error> {
    if let Some(store) = store {
        if store.awaits_rebind() {
            return Err(Error::RebindRequired);
        }
        if adopting {
            sqlx::query("SELECT openmettle.storage_lock_pinned_volume()")
                .execute(pool)
                .await?;
        }
        if let Err(err) =
            artifact_fs::purge_journaled(pool, store, restore_run_id, claim_token).await
        {
            return Err(if store.awaits_rebind() {
                Error::RebindRequired
            } else {
                err.into()
            });
        }
        if let Err(err) =
            artifact_fs::scrub_unsettled_on_restore(pool, store, restore_run_id, claim_token).await
        {
            return Err(if store.awaits_rebind() {
                Error::RebindRequired
            } else {
                err.into()
            });
        }
    }
    // Hold `storage_volume_control FOR SHARE` continuously on Connection 1 across drift
    // verification and until AFTER `restore_gate_open` commits on Connection 2, serializing with
    // any concurrent `storage rebind` / `storage adopt` / auto-pin.
    let mut tx_pin = read_committed(pool).await?;
    sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '300s'")
        .execute(&mut *tx_pin)
        .await?;
    let (vol, adopting_now, has_rows): (Option<String>, bool, bool) = sqlx::query_as(
        "SELECT volume_id::text, adoption_run_id IS NOT NULL,
                EXISTS (SELECT FROM openmettle.storage_reservations)
                OR EXISTS (SELECT FROM openmettle.artifact_revisions)
           FROM openmettle.storage_volume_control
          WHERE id
            FOR SHARE",
    )
    .fetch_one(&mut *tx_pin)
    .await?;
    let expected_volume_id: Option<String> = if let Some(store) = store {
        if adopting_now {
            sqlx::query("SELECT openmettle.storage_lock_pinned_volume()")
                .execute(&mut *tx_pin)
                .await?;
            return Err(Error::Storage(artifact_fs::Error::Io));
        }
        let pin = match store.prepare_pin_on(&mut tx_pin).await {
            Ok(Some(pin)) => pin,
            Ok(None) => return Err(Error::Storage(artifact_fs::Error::Io)),
            Err(err) => {
                return Err(if store.awaits_rebind() {
                    Error::RebindRequired
                } else {
                    err.into()
                });
            }
        };
        if vol.as_deref() != Some(pin.as_str()) {
            return Err(Error::Storage(artifact_fs::Error::Io));
        }
        let drift = match artifact_fs::verify_volume_with_lease(
            &mut tx_pin,
            pool,
            store,
            &pin,
            restore_run_id,
            claim_token,
        )
        .await
        {
            Ok(drift) => drift,
            Err(err) => {
                return Err(if store.awaits_rebind() {
                    Error::RebindRequired
                } else {
                    err.into()
                });
            }
        };
        if !drift.healthy() || drift.unsettled_payloads != 0 {
            return Err(Error::Drift);
        }
        Some(pin)
    } else {
        if vol.is_some() || adopting_now {
            return Err(Error::ArtifactRootRequired);
        }
        if has_rows {
            return Err(Error::Storage(artifact_fs::Error::Io));
        }
        let drift = artifact_fs::verify_ledgers_on(&mut tx_pin).await?;
        if !drift.healthy() {
            return Err(Error::Drift);
        }
        None
    };
    let mut open_tx = read_committed(pool).await?;
    sqlx::query(
        "SELECT openmettle.restore_gate_open($1::uuid, $2::uuid, $3, $4, decode($5, 'hex'), $6::uuid)",
    )
    .bind(restore_run_id)
    .bind(claim_token)
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(expected_volume_id.as_deref())
    .execute(&mut *open_tx)
    .await?;
    open_tx.commit().await?;
    tx_pin.commit().await?;
    Ok(())
}

/// The volume phase, serialized via `restore_claim_volume_phase` and rerunnable after `apply`
/// committed: refuses concurrent volume phases (`OMR02`), unrebound copied volumes
/// (`RebindRequired`), and active adoption/rebind barriers (`OMQ03`), purges resurrected payloads
/// of replayed revisions, scrubs unsettled uploads that cannot survive a restore, verifies the
/// volume and ledgers with zero unsettled payloads, and opens the gate if migration 41's checks
/// pass. On any clean error after claiming the lease, releases the caller's own lease before
/// returning so operator repair and retry proceed immediately.
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
    let (restore_run_id, claim_token) = claim_volume_phase(pool, export).await?;
    let result = finish_claimed(pool, store, export, adopting, &restore_run_id, &claim_token).await;
    if result.is_err() {
        let _ = release_volume_phase(pool, &restore_run_id, &claim_token).await;
    }
    result
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
            "{HEADER}\norigin 1700000000000000\nwatermark 1700000000000000 0 {GENESIS} 1700000000000001\n"
        ));
        let parsed = Export::parse(&valid_empty).unwrap();
        assert_eq!(parsed.origin_us, 1_700_000_000_000_000);
        assert_eq!(parsed.seq, 0);
        assert_eq!(parsed.digest, GENESIS);

        // Missing origin line is refused.
        let missing_origin = seal(&format!("{HEADER}\nwatermark 1 0 {GENESIS} 2\n"));
        assert!(matches!(
            Export::parse(&missing_origin),
            Err(Error::Export("missing or malformed origin"))
        ));

        // Mismatched origin between header and watermark line is refused.
        let mismatched_origin = seal(&format!("{HEADER}\norigin 1\nwatermark 2 0 {GENESIS} 3\n"));
        assert!(matches!(
            Export::parse(&mismatched_origin),
            Err(Error::Export(
                "watermark origin does not match export origin"
            ))
        ));

        // Legacy watermark without origin_us is refused as malformed line.
        let legacy_wm = seal(&format!("{HEADER}\norigin 1\nwatermark 0 {GENESIS} 2\n"));
        assert!(matches!(
            Export::parse(&legacy_wm),
            Err(Error::Export("malformed line"))
        ));

        // Uppercase or truncated hex digests are refused before SQL decode().
        let upper = "A".repeat(64);
        let bad_wm = seal(&format!("{HEADER}\norigin 1\nwatermark 1 0 {upper} 2\n"));
        assert!(matches!(
            Export::parse(&bad_wm),
            Err(Error::Export("malformed digest"))
        ));

        let short = "0".repeat(62);
        let bad_len = seal(&format!("{HEADER}\norigin 1\nwatermark 1 0 {short} 2\n"));
        assert!(matches!(
            Export::parse(&bad_len),
            Err(Error::Export("malformed digest"))
        ));

        // Malformed UUID or bad hex in a record line is refused.
        let entity = "00000000-0000-4000-8000-000000000001";
        let scope = "00000000-0000-4000-8000-000000000002";
        let d = "a".repeat(64);
        let bad_uuid = seal(&format!(
            "{HEADER}\norigin 1\n1 10 artifact_revision.purged NOT-A-UUID {scope} 5 10 {d} 1 {d}\nwatermark 1 1 {d} 11\n"
        ));
        assert!(matches!(
            Export::parse(&bad_uuid),
            Err(Error::Export("malformed uuid"))
        ));

        let bad_content = seal(&format!(
            "{HEADER}\norigin 1\n1 10 artifact_revision.purged {entity} {scope} 5 10 zzz 1 {d}\nwatermark 1 1 {d} 11\n"
        ));
        assert!(matches!(
            Export::parse(&bad_content),
            Err(Error::Export("malformed digest"))
        ));

        let valid_one = seal(&format!(
            "{HEADER}\norigin 1\n1 10 artifact_revision.purged {entity} {scope} 5 10 {d} - {d}\nwatermark 1 1 {d} 11\n"
        ));
        let parsed = Export::parse(&valid_one).unwrap();
        assert_eq!(parsed.seq, 1);
        assert_eq!(parsed.digest, d);
    }
}
