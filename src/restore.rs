//! Restore reconciliation (ADR 0041): deletion journal export, the owner's replay of an export
//! into a restored database, and the gate the worker reads before claiming runs or purging.
//! Migration 29 makes every decision: chain and record checks, lag against the restored snapshot
//! and the required watermark, and whether the gate may open. This module moves the records and
//! drives the volume-pinned purge of resurrected payloads.
//!
//! Export format, one line each, `\n` terminated: the header `openmettle.deletion_journal.export/1`;
//! per record `seq recorded_us event_kind entity_id scope_id original_purge_after_us purged_us
//! content_digest policy_revision chain_digest` (times in the Unix microseconds the chain hashes,
//! digests in lowercase hex, `-` for no policy revision); `watermark seq chain_digest exported_us`;
//! and `sha256 <hex>` over every preceding byte. The checksum detects damage, not forgery: the
//! chain is anchored in the restored database, and the export is not signed.
use crate::{
    artifact_fs::{self, Store},
    authz::projects::hex,
    runs::digest,
};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::fmt::Write;

const HEADER: &str = "openmettle.deletion_journal.export/1";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug)]
pub enum Error {
    /// The export is truncated, fails its checksum, is malformed or out of sequence.
    Export(&'static str),
    /// A migration 29 check refused (OMR02 to OMR05, 25000) or the database failed. Every
    /// refusal rolled its transaction back.
    Database(sqlx::Error),
    /// Purging a resurrected payload, or reading the volume, failed.
    Storage(artifact_fs::Error),
    /// The volume and the ledgers disagree after the purges.
    Drift,
    /// The volume is pinned, so replay needs its artifact root.
    ArtifactRootRequired,
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

/// A checksummed export: every record from 1, in order, ending at the watermark.
pub struct Export {
    records: Vec<Record>,
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

/// Whether the restore gate is open. A schema before 29 has no gate table, so nothing can have
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

/// Exports the whole journal from one snapshot, as the owner.
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
    let (seq, chain, at): (i64, String, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT journal_seq, encode(chain_digest, 'hex'), {} FROM openmettle.deletion_journal_head",
        us("clock_timestamp()")
    )))
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut text = format!("{HEADER}\n");
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
    /// Checks the checksum, the format, the order (1, 2, 3, … with no gap) and that the
    /// watermark names the last record. The database checks the chain during replay.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let split = text
            .rfind("\nsha256 ")
            .ok_or(Error::Export("missing checksum"))?
            + 1;
        let (body, trailer) = text.split_at(split);
        if trailer != format!("sha256 {}\n", hex(&digest(body.as_bytes()))) {
            return Err(Error::Export("checksum mismatch"));
        }
        let mut lines = body.lines();
        if lines.next() != Some(HEADER) {
            return Err(Error::Export("unknown format"));
        }
        let number = |s: &str| {
            s.parse::<i64>()
                .map_err(|_| Error::Export("malformed number"))
        };
        let mut records: Vec<Record> = Vec::new();
        let mut watermark = None;
        for line in lines {
            match line.split(' ').collect::<Vec<_>>()[..] {
                ["watermark", seq, chain, at] if watermark.is_none() => {
                    number(at)?;
                    watermark = Some((number(seq)?, chain.to_owned()));
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
                    let policy = match policy {
                        "-" => None,
                        p => Some(number(p)?),
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
            seq,
            digest,
        })
    }
}

/// Closes the gate after a restore (migration 29's `restore_gate_lock`) and returns the
/// snapshot and required sequences.
pub async fn lock(pool: &PgPool, required: i64) -> Result<(i64, i64), Error> {
    let mut tx = read_committed(pool).await?;
    let sequences = sqlx::query_as(
        "SELECT snapshot_journal_seq, required_journal_seq FROM openmettle.restore_gate_lock($1)",
    )
    .bind(required)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(sequences)
}

/// The database phase: replays every record in one transaction, committed only if all pass.
/// Returns how many records were new to the restored journal.
pub async fn apply(pool: &PgPool, export: &Export) -> Result<u64, Error> {
    let mut tx = read_committed(pool).await?;
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

/// The volume phase, rerunnable after `apply` committed: purges the resurrected payloads of
/// replayed revisions, verifies the volume and ledgers, and opens the gate if migration 29's
/// checks pass. A pinned volume requires its store.
pub async fn finish(pool: &PgPool, store: Option<&Store>, export: &Export) -> Result<(), Error> {
    let pinned: bool = sqlx::query_scalar(
        "SELECT volume_id IS NOT NULL FROM openmettle.storage_volume_control WHERE id",
    )
    .fetch_one(pool)
    .await?;
    if pinned && store.is_none() {
        return Err(Error::ArtifactRootRequired);
    }
    if let Some(store) = store {
        artifact_fs::purge_journaled(pool, store).await?;
    }
    if !artifact_fs::verify_accounting_drift(pool, store)
        .await?
        .healthy()
    {
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
