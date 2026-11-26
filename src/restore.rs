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
//! - optional `lifecycle_origin <lifecycle_coverage_started_us>` (emitted on schema 42+ for
//!   `deletion_journal_head.lifecycle_coverage_started_at`; absent on pre-42 exports)
//! - zero or more record lines (times in Unix microseconds, digests in 64-character lowercase hex,
//!   canonical UUIDs, `-` for NULL optional columns):
//!   - `artifact_revision.purged` (10 fields):
//!     `seq recorded_us event_kind entity_id scope_id original_purge_after_us purged_us content_digest policy_revision chain_digest`
//!   - `artifact_revision.retained`, `artifact_revision.deadline_adjusted`, `artifact_revision.restored` (11 fields):
//!     `seq recorded_us event_kind entity_id scope_id original_purge_after_us purged_us content_digest policy_revision chain_digest retained_us`
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
use sqlx::{ConnectOptions, Connection, PgConnection, PgPool, Postgres, Transaction};
use std::{fmt::Write, future::Future, pin::Pin, time::Duration};

const HEADER: &str = "openmettle.deletion_journal.export/1";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Heartbeat renewal period during drift verification (well inside the 300 s volume-phase lease).
const VOLUME_PHASE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

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

/// One exported `openmettle.deletion_journal` record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    seq: i64,
    recorded_us: i64,
    event_kind: String,
    entity_id: String,
    scope_id: String,
    original_purge_after_us: Option<i64>,
    purged_us: Option<i64>,
    content_digest: String,
    policy_revision: Option<i64>,
    chain_digest: String,
    retained_us: Option<i64>,
}

/// Raw SQL tuple matching [`export`].
type ExportRow = (
    i64,
    i64,
    String,
    String,
    String,
    Option<i64>,
    Option<i64>,
    String,
    Option<i64>,
    String,
    Option<i64>,
);

/// A checksummed export: installation origin, optional schema-42 lifecycle origin, every record
/// from 1 in order, and watermark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    records: Vec<Record>,
    pub origin_us: i64,
    pub lifecycle_origin_us: Option<i64>,
    pub seq: i64,
    pub digest: String,
}

/// Result of closing or updating the restore reconciliation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateLock {
    pub restore_run_id: String,
    pub origin_us: i64,
    pub lifecycle_origin_us: Option<i64>,
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
/// `true` only when it is open (or on pre-41 schemas where `restore_reconciliation_gate` does not
/// exist). On schema 41+, invokes `openmettle.restore_gate_lock_open()` unconditionally so a role
/// lacking `EXECUTE` fails closed instead of bypassing a closed gate.
pub(crate) async fn lock_open_gate(c: &mut PgConnection) -> Result<bool, sqlx::Error> {
    let gated: bool = sqlx::query_scalar(
        "SELECT to_regclass('openmettle.restore_reconciliation_gate') IS NOT NULL",
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

/// Lock the restore reconciliation gate `FOR SHARE` and refuse with a `StoreError::Database`
/// (`503 unavailable` on `/v1`) when the gate is closed.
pub(crate) async fn require_open_gate(
    c: &mut PgConnection,
) -> Result<(), crate::authz::store::StoreError> {
    if !lock_open_gate(c).await? {
        return Err(crate::authz::store::StoreError::Database(
            sqlx::Error::Protocol("restore reconciliation pending".into()),
        ));
    }
    Ok(())
}

/// Exports the whole journal and its installation origin from one snapshot, as the owner.
pub async fn export(pool: &PgPool) -> Result<String, Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let us = |column: &str| format!("(extract(epoch FROM {column}) * 1000000)::bigint");
    let has_retained: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
               FROM pg_catalog.pg_attribute
              WHERE attrelid = to_regclass('openmettle.deletion_journal')
                AND attname = 'retained_at'
                AND NOT attisdropped
         )",
    )
    .fetch_one(&mut *tx)
    .await?;
    let retained_expr = if has_retained {
        us("retained_at")
    } else {
        "NULL::bigint".to_owned()
    };
    let rows: Vec<ExportRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT journal_seq, {}, event_kind, entity_id::text, scope_id::text, {}, {},
                encode(content_digest, 'hex'), policy_revision, encode(chain_digest, 'hex'), {}
           FROM openmettle.deletion_journal ORDER BY journal_seq",
        us("recorded_at"),
        us("original_purge_after"),
        us("purged_at"),
        retained_expr,
    )))
    .fetch_all(&mut *tx)
    .await?;
    let has_lifecycle_origin: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
               FROM pg_catalog.pg_attribute
              WHERE attrelid = to_regclass('openmettle.deletion_journal_head')
                AND attname = 'lifecycle_coverage_started_at'
                AND NOT attisdropped
         )",
    )
    .fetch_one(&mut *tx)
    .await?;
    let lifecycle_origin_expr = if has_lifecycle_origin {
        us("lifecycle_coverage_started_at")
    } else {
        "NULL::bigint".to_owned()
    };
    let (seq, chain, origin_us, lifecycle_origin_us, at): (i64, String, i64, Option<i64>, i64) =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT journal_seq, encode(chain_digest, 'hex'), {}, {}, {}
               FROM openmettle.deletion_journal_head WHERE id",
            us("coverage_started_at"),
            lifecycle_origin_expr,
            us("clock_timestamp()")
        )))
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    let fmt_opt = |v: Option<i64>| v.map_or_else(|| "-".to_owned(), |n| n.to_string());
    let mut text = format!("{HEADER}\norigin {origin_us}\n");
    if let Some(lifecycle_origin_us) = lifecycle_origin_us {
        let _ = writeln!(text, "lifecycle_origin {lifecycle_origin_us}");
    }
    for (i, r) in rows.iter().enumerate() {
        if r.0 != i as i64 + 1 {
            return Err(Error::Export("journal out of sequence"));
        }
        let after = fmt_opt(r.5);
        let purged = fmt_opt(r.6);
        let policy = fmt_opt(r.8);
        if r.2 == "artifact_revision.purged" {
            let _ = writeln!(
                text,
                "{} {} {} {} {} {after} {purged} {} {policy} {}",
                r.0, r.1, r.2, r.3, r.4, r.7, r.9
            );
        } else {
            let retained = fmt_opt(r.10);
            let _ = writeln!(
                text,
                "{} {} {} {} {} {after} {purged} {} {policy} {} {retained}",
                r.0, r.1, r.2, r.3, r.4, r.7, r.9
            );
        }
    }
    if (seq, chain.as_str()) != rows.last().map_or((0, GENESIS), |r| (r.0, r.9.as_str())) {
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
        let mut lines = body.lines().peekable();
        if lines.next() != Some(HEADER) {
            return Err(Error::Export("unknown format"));
        }
        let number = |s: &str| {
            s.parse::<i64>()
                .map_err(|_| Error::Export("malformed number"))
        };
        let opt_number = |s: &str| -> Result<Option<i64>, Error> {
            match s {
                "-" => Ok(None),
                other => Ok(Some(number(other)?)),
            }
        };
        let origin_us = match lines.next() {
            Some(line) => match line.split(' ').collect::<Vec<_>>()[..] {
                ["origin", origin] => number(origin)?,
                _ => return Err(Error::Export("missing or malformed origin")),
            },
            None => return Err(Error::Export("missing or malformed origin")),
        };
        let lifecycle_origin_us = if lines
            .peek()
            .is_some_and(|line| line.starts_with("lifecycle_origin"))
        {
            let line = lines.next().unwrap_or_default();
            match line.split(' ').collect::<Vec<_>>()[..] {
                ["lifecycle_origin", origin] => Some(number(origin)?),
                _ => return Err(Error::Export("malformed lifecycle origin")),
            }
        } else {
            None
        };
        let mut records: Vec<Record> = Vec::new();
        let mut watermark = None;
        for line in lines {
            let fields: Vec<&str> = line.split(' ').collect();
            match fields[..] {
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
                    records.push(Record {
                        seq,
                        recorded_us: number(at)?,
                        event_kind: kind.into(),
                        entity_id: entity.into(),
                        scope_id: scope.into(),
                        original_purge_after_us: Some(number(after)?),
                        purged_us: Some(number(purged)?),
                        content_digest: content.into(),
                        policy_revision: policy,
                        chain_digest: chain.into(),
                        retained_us: None,
                    });
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
                    retained,
                ] if watermark.is_none() => {
                    if lifecycle_origin_us.is_none() {
                        return Err(Error::Export("missing lifecycle origin"));
                    }
                    let seq = number(seq)?;
                    if seq != records.len() as i64 + 1 {
                        return Err(Error::Export("records out of sequence"));
                    }
                    if !matches!(
                        kind,
                        "artifact_revision.retained"
                            | "artifact_revision.deadline_adjusted"
                            | "artifact_revision.restored"
                    ) {
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
                    let original_purge_after_us = opt_number(after)?;
                    let purged_us = opt_number(purged)?;
                    let retained_us = opt_number(retained)?;
                    match kind {
                        "artifact_revision.retained" | "artifact_revision.deadline_adjusted" => {
                            let (Some(a), None, Some(r)) =
                                (original_purge_after_us, purged_us, retained_us)
                            else {
                                return Err(Error::Export("malformed line"));
                            };
                            if a < r {
                                return Err(Error::Export("malformed number"));
                            }
                        }
                        "artifact_revision.restored" => {
                            if original_purge_after_us.is_some()
                                || purged_us.is_some()
                                || retained_us.is_some()
                            {
                                return Err(Error::Export("malformed line"));
                            }
                        }
                        _ => return Err(Error::Export("unknown event kind")),
                    }
                    records.push(Record {
                        seq,
                        recorded_us: number(at)?,
                        event_kind: kind.into(),
                        entity_id: entity.into(),
                        scope_id: scope.into(),
                        original_purge_after_us,
                        purged_us,
                        content_digest: content.into(),
                        policy_revision: policy,
                        chain_digest: chain.into(),
                        retained_us,
                    });
                }
                _ => return Err(Error::Export("malformed line")),
            }
        }
        let (seq, digest) = watermark.ok_or(Error::Export("missing watermark"))?;
        if (seq, digest.as_str())
            != records
                .last()
                .map_or((0, GENESIS), |r| (r.seq, r.chain_digest.as_str()))
        {
            return Err(Error::Export("watermark does not match the last record"));
        }
        Ok(Self {
            records,
            origin_us,
            lifecycle_origin_us,
            seq,
            digest,
        })
    }
}

/// Closes or updates the gate after a restore (migration 41/42's `restore_gate_lock`) with the
/// independently recorded installation `origin_us`, optional schema-42 `lifecycle_origin_us`,
/// target watermark `(required_seq, required_digest)`, `coverage_complete` flag, optional
/// `replace_restore_run`, and `new_restore`.
#[allow(clippy::too_many_arguments)]
pub async fn lock(
    pool: &PgPool,
    origin_us: i64,
    lifecycle_origin_us: Option<i64>,
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
    let (
        restore_run_id,
        required_origin_us,
        required_lifecycle_origin_us,
        snapshot_seq,
        required_seq,
        coverage_complete,
    ): (String, i64, Option<i64>, i64, i64, bool) = sqlx::query_as(
        "SELECT restore_run_id::text, required_origin_us, required_lifecycle_origin_us,
                snapshot_journal_seq, required_journal_seq, coverage_complete
           FROM openmettle.restore_gate_lock($1, $2, decode($3, 'hex'), $4, $5::uuid, $6, $7)",
    )
    .bind(origin_us)
    .bind(required_seq)
    .bind(required_digest)
    .bind(coverage_complete)
    .bind(replace_restore_run)
    .bind(new_restore)
    .bind(lifecycle_origin_us)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(GateLock {
        restore_run_id,
        origin_us: required_origin_us,
        lifecycle_origin_us: required_lifecycle_origin_us,
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
    sqlx::query("SELECT openmettle.restore_verify_export($1, $2, decode($3, 'hex'), $4)")
        .bind(export.origin_us)
        .bind(export.seq)
        .bind(&export.digest)
        .bind(export.lifecycle_origin_us)
        .execute(&mut *tx)
        .await?;
    let mut applied = 0;
    for r in &export.records {
        let new: bool = sqlx::query_scalar(
            "SELECT openmettle.deletion_journal_replay($1, $2, $3, $4::uuid, $5::uuid, $6, $7,
                    decode($8, 'hex'), $9, decode($10, 'hex'), $11)",
        )
        .bind(r.seq)
        .bind(r.recorded_us)
        .bind(&r.event_kind)
        .bind(&r.entity_id)
        .bind(&r.scope_id)
        .bind(r.original_purge_after_us)
        .bind(r.purged_us)
        .bind(&r.content_digest)
        .bind(r.policy_revision)
        .bind(&r.chain_digest)
        .bind(r.retained_us)
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
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4)",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(lease)
}

async fn renew_volume_phase(
    pool: &PgPool,
    restore_run_id: &str,
    claim_token: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = read_committed(pool).await?;
    sqlx::query("SELECT openmettle.restore_renew_volume_phase($1::uuid, $2::uuid)")
        .bind(restore_run_id)
        .bind(claim_token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
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

/// Sends `pg_cancel_backend` (or `pg_terminate_backend` when `terminate` is true) for
/// `backend_pid`. Uses `pool` when open and falls back to a direct, pool-independent connection
/// opened from `pool.connect_options()` so cancellation and termination still succeed when
/// `pool.close()` is in progress.
async fn signal_backend(pool: &PgPool, backend_pid: i32, terminate: bool) {
    let sql = if terminate {
        "SELECT pg_terminate_backend($1)"
    } else {
        "SELECT pg_cancel_backend($1)"
    };
    if !pool.is_closed()
        && tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query(sql).bind(backend_pid).execute(pool),
        )
        .await
        .is_ok_and(|res| res.is_ok())
    {
        return;
    }
    let options = pool.connect_options();
    if let Ok(Ok(mut conn)) = tokio::time::timeout(Duration::from_secs(5), options.connect()).await
    {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            sqlx::query(sql).bind(backend_pid).execute(&mut conn),
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.close()).await;
    }
}

async fn cancel_and_unwind<T, F>(pool: &PgPool, tx_pin_pid: i32, fut: &mut Pin<&mut F>)
where
    F: Future<Output = Result<T, Error>>,
{
    signal_backend(pool, tx_pin_pid, false).await;
    if tokio::time::timeout(Duration::from_secs(5), fut.as_mut())
        .await
        .is_err()
    {
        signal_backend(pool, tx_pin_pid, true).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), fut.as_mut()).await;
    }
}

/// Runs `fut` (which must use only Connection 1 (`tx_pin`, backend `tx_pin_pid`) and filesystem
/// I/O, never `pool`) while renewing the restore volume-phase lease on `pool` (Connection 2) up
/// front, on every elapsed `renew_interval` tick, and once on completion. Because `fut` never
/// borrows from `pool`, a 2-connection pool never contends with itself even while long SQL queries
/// run on Connection 1. If a heartbeat renewal fails or `pool.close()` begins while `fut` is
/// blocked on Backend 1, cancels (and if needed terminates) `tx_pin_pid` via `pool` or a direct
/// pool-independent connection from `pool.connect_options()` and awaits `fut` unwinding so the
/// caller can synchronously roll back `tx_pin` and release `storage_volume_control FOR SHARE`
/// before returning.
async fn with_volume_phase_heartbeat<T, F>(
    pool: &PgPool,
    tx_pin_pid: i32,
    restore_run_id: &str,
    claim_token: &str,
    renew_interval: Duration,
    fut: F,
) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    renew_volume_phase(pool, restore_run_id, claim_token).await?;
    let mut ticker =
        tokio::time::interval_at(tokio::time::Instant::now() + renew_interval, renew_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let close_event = pool.close_event();
    tokio::pin!(close_event);
    tokio::pin!(fut);
    loop {
        tokio::select! {
            biased;
            _ = &mut close_event => {
                cancel_and_unwind(pool, tx_pin_pid, &mut fut).await;
                return Err(sqlx::Error::PoolClosed.into());
            }
            _ = ticker.tick() => {
                if let Err(renew_err) = renew_volume_phase(pool, restore_run_id, claim_token).await {
                    cancel_and_unwind(pool, tx_pin_pid, &mut fut).await;
                    return Err(renew_err.into());
                }
            }
            res = &mut fut => {
                let out = res?;
                renew_volume_phase(pool, restore_run_id, claim_token).await?;
                return Ok(out);
            }
        }
    }
}

async fn finish_claimed(
    pool: &PgPool,
    store: Option<&Store>,
    export: &Export,
    adopting: bool,
    restore_run_id: &str,
    claim_token: &str,
    renew_interval: Duration,
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
    // verification and until Connection 2 (`open_tx`) has executed `restore_gate_open` (which
    // itself locks `restore_reconciliation_gate FOR UPDATE` and `storage_volume_control FOR
    // SHARE`). Commit `tx_pin` BEFORE committing `open_tx` so if `tx_pin`'s backend died after
    // verification (releasing its share lock early), `tx_pin.commit()` fails and `open_tx` rolls
    // back leaving the restore gate closed. On every error path after opening `tx_pin`, explicitly
    // await `tx_pin.rollback()` before returning so `storage_volume_control FOR SHARE` is released
    // synchronously before `finish` returns.
    let mut tx_pin = read_committed(pool).await?;
    let outcome: Result<Option<String>, Error> = async {
        sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '300s'")
            .execute(&mut *tx_pin)
            .await?;
        let tx_pin_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx_pin)
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
        let yield_interval = (renew_interval / 2).max(Duration::from_millis(1));
        if let Some(store) = store {
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
            let drift = with_volume_phase_heartbeat(
                pool,
                tx_pin_pid,
                restore_run_id,
                claim_token,
                renew_interval,
                async {
                    artifact_fs::verify_volume_on(&mut tx_pin, store, &pin, yield_interval)
                        .await
                        .map_err(|err| {
                            if store.awaits_rebind() {
                                Error::RebindRequired
                            } else {
                                err.into()
                            }
                        })
                },
            )
            .await?;
            if !drift.healthy() || drift.unsettled_payloads != 0 {
                return Err(Error::Drift);
            }
            Ok(Some(pin))
        } else {
            if vol.is_some() || adopting_now {
                return Err(Error::ArtifactRootRequired);
            }
            if has_rows {
                return Err(Error::Storage(artifact_fs::Error::Io));
            }
            let drift = with_volume_phase_heartbeat(
                pool,
                tx_pin_pid,
                restore_run_id,
                claim_token,
                renew_interval,
                async {
                    artifact_fs::verify_ledgers_on(&mut tx_pin)
                        .await
                        .map_err(Error::from)
                },
            )
            .await?;
            if !drift.healthy() {
                return Err(Error::Drift);
            }
            Ok(None)
        }
    }
    .await;
    let expected_volume_id = match outcome {
        Ok(expected_volume_id) => expected_volume_id,
        Err(err) => {
            let _ = tokio::time::timeout(Duration::from_secs(5), tx_pin.rollback()).await;
            return Err(err);
        }
    };
    let mut open_tx = match read_committed(pool).await {
        Ok(tx) => tx,
        Err(err) => {
            let _ = tokio::time::timeout(Duration::from_secs(5), tx_pin.rollback()).await;
            return Err(err.into());
        }
    };
    if let Err(err) = sqlx::query(
        "SELECT openmettle.restore_gate_open($1::uuid, $2::uuid, $3, $4, decode($5, 'hex'), $6::uuid, $7)",
    )
    .bind(restore_run_id)
    .bind(claim_token)
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(expected_volume_id.as_deref())
    .bind(export.lifecycle_origin_us)
    .execute(&mut *open_tx)
    .await
    {
        let _ = tokio::time::timeout(Duration::from_secs(5), open_tx.rollback()).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), tx_pin.rollback()).await;
        return Err(err.into());
    }
    if let Err(err) = tx_pin.commit().await {
        let _ = tokio::time::timeout(Duration::from_secs(5), open_tx.rollback()).await;
        return Err(err.into());
    }
    open_tx.commit().await?;
    Ok(())
}

/// The volume phase, serialized via `restore_claim_volume_phase` and rerunnable after `apply`
/// committed: refuses concurrent volume phases (`OMR02`), unrebound copied volumes
/// (`RebindRequired`), and active adoption/rebind barriers (`OMQ03`), purges resurrected payloads
/// of replayed revisions, scrubs unsettled uploads that cannot survive a restore, verifies the
/// volume and ledgers with zero unsettled payloads while renewing the lease on a heartbeat, and
/// opens the gate if migration 41's checks pass. On any clean error after claiming the lease,
/// releases the caller's own lease before returning so operator repair and retry proceed
/// immediately.
pub async fn finish(pool: &PgPool, store: Option<&Store>, export: &Export) -> Result<(), Error> {
    finish_with_heartbeat(pool, store, export, VOLUME_PHASE_HEARTBEAT_INTERVAL).await
}

/// [`finish`] with an explicit lease-renewal heartbeat interval for deterministic lease-crossing
/// tests.
#[doc(hidden)]
pub async fn finish_with_heartbeat(
    pool: &PgPool,
    store: Option<&Store>,
    export: &Export,
    renew_interval: Duration,
) -> Result<(), Error> {
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
    let result = finish_claimed(
        pool,
        store,
        export,
        adopting,
        &restore_run_id,
        &claim_token,
        renew_interval,
    )
    .await;
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
        assert_eq!(parsed.lifecycle_origin_us, None);

        // PR3 lifecycle commitment event kinds (11 fields) require lifecycle_origin and enforce
        // per-kind invariants.
        let valid_lifecycle = seal(&format!(
            "{HEADER}\norigin 1\nlifecycle_origin 2\n\
             1 10 artifact_revision.retained {entity} {scope} 100 - {d} 1 {d} 50\n\
             2 20 artifact_revision.deadline_adjusted {entity} {scope} 80 - {d} 2 {d} 50\n\
             3 30 artifact_revision.restored {entity} {scope} - - {d} - {d} -\n\
             4 40 artifact_revision.purged {entity} {scope} 90 95 {d} 2 {d}\n\
             watermark 1 4 {d} 41\n"
        ));
        let parsed = Export::parse(&valid_lifecycle).unwrap();
        assert_eq!(parsed.lifecycle_origin_us, Some(2));
        assert_eq!(parsed.seq, 4);
        assert_eq!(parsed.records[0].retained_us, Some(50));
        assert_eq!(parsed.records[0].original_purge_after_us, Some(100));
        assert_eq!(parsed.records[0].purged_us, None);
        assert_eq!(parsed.records[2].retained_us, None);
        assert_eq!(parsed.records[2].original_purge_after_us, None);
        assert_eq!(parsed.records[3].purged_us, Some(95));

        // 11-field lifecycle event without lifecycle_origin header is refused.
        let missing_lc = seal(&format!(
            "{HEADER}\norigin 1\n1 10 artifact_revision.retained {entity} {scope} 100 - {d} 1 {d} 50\nwatermark 1 1 {d} 11\n"
        ));
        assert!(matches!(
            Export::parse(&missing_lc),
            Err(Error::Export("missing lifecycle origin"))
        ));

        // Malformed or duplicate lifecycle_origin lines are refused.
        let bad_lc = seal(&format!(
            "{HEADER}\norigin 1\nlifecycle_origin abc\nwatermark 1 0 {GENESIS} 2\n"
        ));
        assert!(matches!(
            Export::parse(&bad_lc),
            Err(Error::Export("malformed number"))
        ));
        let dup_lc = seal(&format!(
            "{HEADER}\norigin 1\nlifecycle_origin 2\nlifecycle_origin 3\nwatermark 1 0 {GENESIS} 4\n"
        ));
        assert!(matches!(
            Export::parse(&dup_lc),
            Err(Error::Export("malformed line"))
        ));

        // Retained record with purge_after < retained_at is refused.
        let bad_order = seal(&format!(
            "{HEADER}\norigin 1\nlifecycle_origin 2\n1 10 artifact_revision.retained {entity} {scope} 40 - {d} 1 {d} 50\nwatermark 1 1 {d} 11\n"
        ));
        assert!(matches!(
            Export::parse(&bad_order),
            Err(Error::Export("malformed number"))
        ));

        // Restored record carrying a timestamp is refused.
        let bad_restored = seal(&format!(
            "{HEADER}\norigin 1\nlifecycle_origin 2\n1 10 artifact_revision.restored {entity} {scope} 40 - {d} - {d} -\nwatermark 1 1 {d} 11\n"
        ));
        assert!(matches!(
            Export::parse(&bad_restored),
            Err(Error::Export("malformed line"))
        ));
    }
}
