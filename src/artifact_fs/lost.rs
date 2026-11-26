//! Owner-only declaration of an unrecoverable artifact payload as permanently lost after a
//! restore (ADR 0040 / ADR 0041, issue #154).
//!
//! Deliberately separate from `storage rebind` so `rebind` stays strictly non-destructive on
//! settled revisions. Refuses intact verifiable payloads, purging payloads already accepted by
//! `rebind`, live open volumes without a barrier/closed restore gate, closed restore gates whose
//! deletion journal has not caught up to `required_journal_seq`, non-owner logins, active file
//! locks, and any file with a foreign hard link outside this reservation's four names.
use super::{
    FS_TX_IDLE_TIMEOUT, TX_FENCE_BUDGET,
    adoption::{self, COMMIT_UNKNOWN, Failure, READ_FAILED, RevisionDigests},
    rebind::{
        self, CHANGED, Entry, Ledger, Names, OwnedNames, Plan, has_foreign_hard_link,
        lock_reservation_files, reservation_names, stat_reservation, unlink_reservation_files,
    },
    volume::Volume,
};
use crate::runs::is_canonical_uuid;
use rustix::fs as at;
use sqlx::{Connection, PgConnection, Row};
use std::{
    collections::HashMap,
    fs::File,
    io::{Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Instant,
};

const FENCE_EXPIRED: &str = "filesystem fence budget expired";
const TERMINAL_PURGE_COMMITTED: &str = "artifact revision already has a terminal purge commitment; run storage rebind or restore replay to complete the purge";

pub struct Options<'a> {
    pub root: &'a Path,
    pub revision: &'a str,
    pub operator_id: &'a str,
    pub request_key: &'a str,
    pub reason: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// `true` when freshly applied; `false` on an exact idempotent retry of `request_key`.
    pub applied: bool,
    pub revision_id: String,
    pub reservation_id: String,
    pub scope_id: String,
    pub artifact_id: String,
    pub previous_state: String,
    pub journal_seq: i64,
    pub unlinked_files: usize,
}

fn valid_trimmed_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.bytes().any(|b| b.is_ascii_control())
}

fn map_sql_error(err: sqlx::Error) -> Failure {
    if let sqlx::Error::Database(db) = &err {
        return match db.code().as_deref() {
            Some("42501") => Failure("owner login required"),
            Some("23505") => Failure("request key already used with different parameters"),
            Some("22023") => Failure("invalid declare-lost parameters"),
            Some("P0002") => Failure("artifact revision not found"),
            Some("OMR03") => Failure("post-replay lost journal tail verification failed"),
            Some("OMR04") => {
                let msg = db.message();
                if msg.contains("unreconciled retained or purging") {
                    Failure(
                        "unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal",
                    )
                } else if msg.contains("lifecycle baseline") {
                    Failure(
                        "replay the deletion journal and lifecycle baseline before declaring payloads lost",
                    )
                } else {
                    Failure("replay the deletion journal before declaring payloads lost")
                }
            }
            Some("OMR02") => Failure("restore volume phase is active"),
            Some("OMQ03") => {
                let msg = db.message();
                if msg.contains("live and open") {
                    Failure(
                        "volume is live and open; storage declare-lost requires an active adoption barrier or a closed restore gate",
                    )
                } else if msg.contains("already declared lost") {
                    Failure("artifact revision payload is already declared lost")
                } else if msg.contains("terminal purge commitment") {
                    Failure(TERMINAL_PURGE_COMMITTED)
                } else if msg.contains("purged") {
                    Failure("cannot declare a purged artifact revision lost")
                } else if msg.contains("not pinned") {
                    Failure("volume is not pinned")
                } else {
                    Failure("artifact revision is not eligible to be declared lost")
                }
            }
            _ => Failure("database operation failed"),
        };
    }
    Failure::from(err)
}

fn check_fence(deadline: Instant) -> Result<(), Failure> {
    if Instant::now() >= deadline {
        return Err(Failure(FENCE_EXPIRED));
    }
    Ok(())
}

/// Checks whether ANY file under the reservation's names verifies intact against `(size_bytes,
/// content_digest)` (independently of anchor or layout mismatches) or is an already-truncated
/// `purging` layout accepted by `storage rebind`. Returns `Err(...)` to refuse `declare-lost`, or
/// `Ok(())` when the payload is genuinely missing/corrupt/unrecoverable and has no foreign hard
/// links.
fn check_unrecoverable_and_no_foreign_links(
    ledger: &Ledger<'_>,
    entries: &[Option<Entry>; 4],
    locked: &mut [(u64, File)],
    reservation_id: &str,
    size_bytes: u64,
    content_digest: &[u8],
) -> Result<(), Failure> {
    let [staging, reclaim, revision, purge] = *entries;
    let names = Names {
        staging,
        reclaim,
        revision,
        purge,
    };
    // Verify candidate payload files across ALL four reservation names BEFORE `rebind::classify`
    // so an unexpected anchor or split layout (including a 0-byte revision surviving at an anchor)
    // can never bypass SHA-256 verification and unlink intact payload bytes.
    let mut checked_inos: Vec<u64> = Vec::with_capacity(4);
    for e in entries.iter().flatten() {
        if e.len != size_bytes {
            continue;
        }
        if checked_inos.contains(&e.ino) {
            continue;
        }
        checked_inos.push(e.ino);
        if let Some((_, file)) = locked.iter_mut().find(|(file_ino, _)| *file_ino == e.ino) {
            file.seek(SeekFrom::Start(0))?;
            let mut digests = RevisionDigests::default();
            match digests.verify(reservation_id, file, size_bytes, content_digest) {
                Ok(()) => {
                    return Err(match rebind::classify(ledger, &names) {
                        Ok(Plan::Content(_)) => {
                            Failure("payload verifies intact; run storage rebind instead")
                        }
                        _ => Failure(
                            "payload verifies intact; resolve layout mismatch or run storage rebind instead",
                        ),
                    });
                }
                Err(Failure("size_or_digest_mismatch" | READ_FAILED)) => {}
                Err(other) => return Err(other),
            }
        }
    }
    if matches!(rebind::classify(ledger, &names), Ok(Plan::Empty { .. }))
        && ledger.revision == Some("purging")
    {
        return Err(Failure(
            "purging payload is already acceptable to storage rebind",
        ));
    }
    if has_foreign_hard_link(entries) {
        return Err(Failure("foreign hard link"));
    }
    Ok(())
}

type ReservationEntries = [Option<Entry>; 4];
type LockedFiles = Vec<(u64, File)>;

fn inspect_and_lock(
    v: &Volume,
    names: &OwnedNames,
    check_links: bool,
) -> Result<(ReservationEntries, LockedFiles), Failure> {
    let entries = stat_reservation(v, names)?.ok_or(Failure("invalid volume entry"))?;
    let locked = lock_reservation_files(v, names, &entries, check_links)?;
    Ok((entries, locked))
}

/// Re-verifies, on continuously-held `LOCK_EX` descriptors, that every reservation path still
/// maps to the exact stat'd `(ino, len, links)` and that no foreign hard link appeared.
fn verify_locked_reservation(
    v: &Volume,
    names: &OwnedNames,
    entries: &ReservationEntries,
    locked: &LockedFiles,
    mtimes: &[(i64, i64)],
) -> Result<(), Failure> {
    let current = stat_reservation(v, names)?.ok_or(Failure("invalid volume entry"))?;
    let mut own_links: HashMap<u64, u64> = HashMap::new();
    let mut expected_len: HashMap<u64, u64> = HashMap::new();
    for e in entries.iter().flatten() {
        *own_links.entry(e.ino).or_insert(0) += 1;
        expected_len.insert(e.ino, e.len);
    }
    if locked.len() != own_links.len() || mtimes.len() != locked.len() {
        return Err(Failure(CHANGED));
    }
    for ((ino, file), &(mtime, mtime_nsec)) in locked.iter().zip(mtimes.iter()) {
        let Some(&own) = own_links.get(ino) else {
            return Err(Failure(CHANGED));
        };
        let meta = file.metadata()?;
        if meta.ino() != *ino
            || meta.dev() != v.dev
            || meta.len() != expected_len[ino]
            || meta.mtime() != mtime
            || meta.mtime_nsec() != mtime_nsec
        {
            return Err(Failure(CHANGED));
        }
        let nlink = meta.nlink();
        if nlink > own {
            return Err(Failure("foreign hard link"));
        }
        if nlink < own {
            return Err(Failure(CHANGED));
        }
    }
    if current != *entries {
        return Err(Failure(CHANGED));
    }
    Ok(())
}

fn snapshot_mtimes(locked: &LockedFiles) -> Result<Vec<(i64, i64)>, Failure> {
    locked
        .iter()
        .map(|(_, file)| {
            let meta = file.metadata()?;
            Ok((meta.mtime(), meta.mtime_nsec()))
        })
        .collect()
}

/// Post-commit unlink under continuously-held exclusive file locks and bounded by `deadline`.
/// Always syncs both reservation directories (`revisions` and `staging`) even when `entries` is
/// empty so an idempotent retry after a crash between `unlinkat` and `fsync` still establishes
/// directory durability.
fn unlink_after_commit(
    v: &Volume,
    pin: &str,
    names: &OwnedNames,
    entries: &ReservationEntries,
    locked: &LockedFiles,
    mtimes: &[(i64, i64)],
    deadline: Instant,
) -> Result<usize, Failure> {
    check_fence(deadline)?;
    v.verify(pin)?;
    verify_locked_reservation(v, names, entries, locked, mtimes)?;
    let unlinked = if entries.iter().any(Option::is_some) {
        unlink_reservation_files(v, names, entries, Some(deadline))?
    } else {
        0
    };
    check_fence(deadline)?;
    at::fsync(&v.revisions)?;
    at::fsync(&v.staging)?;
    Ok(unlinked)
}

/// Declare one settled artifact revision's unrecoverable payload permanently lost.
pub async fn declare_lost(c: &mut PgConnection, opts: &Options<'_>) -> Result<Outcome, Failure> {
    if !is_canonical_uuid(opts.revision) {
        return Err(Failure("invalid revision id"));
    }
    if !is_canonical_uuid(opts.operator_id) {
        return Err(Failure("invalid operator id"));
    }
    if !valid_trimmed_text(opts.request_key, 128) {
        return Err(Failure("invalid request key"));
    }
    if !valid_trimmed_text(opts.reason, 512) {
        return Err(Failure("invalid reason"));
    }

    let v = Volume::open(opts.root, false)?;
    let _ = adoption::owner_run(c).await?;

    // Read-only preflight outside the write transaction so hashing a large intact payload never
    // holds PostgreSQL row locks across disk I/O. Exclusive file locks acquired here are held
    // continuously across the locked READ COMMITTED transaction and post-commit unlink.
    let preflight = sqlx::query(
        "SELECT svc.volume_id::text AS pin,
                svc.adoption_run_id IS NOT NULL AS adopting,
                g.open AS gate_open,
                (NOT g.open AND g.volume_claim_token IS NOT NULL AND g.volume_lease_until > clock_timestamp()) AS volume_active,
                (
                    NOT g.open
                    AND (
                        h.journal_seq < g.required_journal_seq
                        OR (h.journal_seq = g.required_journal_seq
                            AND h.chain_digest IS DISTINCT FROM g.required_chain_digest)
                    )
                ) AS journal_pending,
                (NOT g.open AND h.journal_seq > g.required_journal_seq) AS tail_verify_needed,
                (
                    NOT g.open
                    AND g.required_lifecycle_origin_us IS NOT NULL
                    AND CASE
                        WHEN g.required_lifecycle_origin_us = g.snapshot_lifecycle_origin_us THEN
                            g.required_lifecycle_baseline_digest IS DISTINCT FROM g.snapshot_lifecycle_baseline_digest
                            OR g.required_lifecycle_baseline_digest IS DISTINCT FROM h.lifecycle_baseline_digest
                        ELSE
                            g.replayed_lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest
                            OR (extract(epoch FROM h.lifecycle_coverage_started_at) * 1000000)::bigint
                                IS DISTINCT FROM g.required_lifecycle_origin_us
                            OR h.lifecycle_baseline_digest IS DISTINCT FROM g.required_lifecycle_baseline_digest
                    END
                ) AS baseline_pending,
                (
                    NOT g.open
                    AND g.required_lifecycle_origin_us IS NOT NULL
                    AND EXISTS (
                        SELECT 1
                          FROM openmettle.artifact_revisions r2
                         WHERE r2.state IN ('retained', 'purging')
                           AND NOT EXISTS (
                               SELECT 1
                                 FROM openmettle.retention_upgrade_baseline b
                                WHERE b.artifact_revision_id = r2.id
                           )
                           AND NOT EXISTS (
                               SELECT 1
                                 FROM openmettle.deletion_journal j
                                WHERE j.entity_id = r2.id
                                  AND j.event_kind IN ('artifact_revision.retained', 'artifact_revision.purged')
                           )
                    )
                ) AS uncovered_lifecycle
           FROM openmettle.storage_volume_control svc
           JOIN openmettle.restore_reconciliation_gate g ON g.id
           JOIN openmettle.deletion_journal_head h ON h.id
          WHERE svc.id",
    )
    .fetch_one(&mut *c)
    .await?;

    let pin: Option<String> = preflight.try_get("pin")?;
    let adopting: bool = preflight.try_get("adopting")?;
    let gate_open: bool = preflight.try_get("gate_open")?;
    let volume_active: bool = preflight.try_get("volume_active")?;
    let journal_pending: bool = preflight.try_get("journal_pending")?;
    let tail_verify_needed: bool = preflight.try_get("tail_verify_needed")?;
    let baseline_pending: bool = preflight.try_get("baseline_pending")?;
    let uncovered_lifecycle: bool = preflight.try_get("uncovered_lifecycle")?;

    let pin = pin.ok_or(Failure("volume is not pinned"))?;
    v.verify(&pin)?;
    if !adopting && gate_open {
        return Err(Failure(
            "volume is live and open; storage declare-lost requires an active adoption barrier or a closed restore gate",
        ));
    }
    if volume_active {
        return Err(Failure("restore volume phase is active"));
    }
    if journal_pending {
        return Err(Failure(
            "replay the deletion journal before declaring payloads lost",
        ));
    }
    if tail_verify_needed {
        sqlx::query(
            "SELECT openmettle.restore_verify_lost_journal_tail(
                        g.required_journal_seq,
                        g.required_chain_digest,
                        g.restore_run_id
                    )
               FROM openmettle.restore_reconciliation_gate g
              WHERE g.id AND NOT g.open",
        )
        .execute(&mut *c)
        .await
        .map_err(map_sql_error)?;
    }
    if baseline_pending {
        return Err(Failure(
            "replay the deletion journal and lifecycle baseline before declaring payloads lost",
        ));
    }
    if uncovered_lifecycle {
        return Err(Failure(
            "unreconciled retained or purging revisions remain outside lifecycle baseline and deletion journal",
        ));
    }

    let existing_audit: Option<(String, Option<String>, String, String, String)> = sqlx::query_as(
        "SELECT action, operator_id::text, target_kind, target_id, reason
           FROM openmettle.authorization_audit
          WHERE actor_kind = 'operator'
            AND (
                (action = 'storage.declare_payload_lost' AND request_key = $1)
                OR (operator_id = $2::uuid AND request_key = $1)
            )
          LIMIT 1",
    )
    .bind(opts.request_key)
    .bind(opts.operator_id)
    .fetch_optional(&mut *c)
    .await?;
    let is_replay = if let Some((action, op_id, target_kind, target_id, reason)) = existing_audit {
        if action == "storage.declare_payload_lost"
            && op_id.as_deref() == Some(opts.operator_id)
            && target_kind == "artifact_revision"
            && target_id == opts.revision
            && reason == opts.reason
        {
            true
        } else {
            return Err(Failure(
                "request key already used with different parameters",
            ));
        }
    } else {
        false
    };

    let target = sqlx::query(
        "SELECT s.id::text AS reservation_id, s.state AS reservation_state, s.reclaim_state,
                r.state AS revision_state, r.purge_stage, r.size_bytes, r.content_digest,
                EXISTS (
                    SELECT 1
                      FROM openmettle.deletion_journal dj
                     WHERE dj.scope_id = r.scope_id
                       AND dj.entity_id = r.id
                       AND dj.event_kind = 'artifact_revision.purged'
                ) AS has_purge_commitment
           FROM openmettle.artifact_revisions r
           JOIN openmettle.storage_reservations s
             ON s.scope_id = r.scope_id AND s.id = r.reservation_id
          WHERE r.id = $1::uuid",
    )
    .bind(opts.revision)
    .fetch_optional(&mut *c)
    .await?
    .ok_or(Failure("artifact revision not found"))?;

    let pre_res_id: String = target.try_get("reservation_id")?;
    let pre_res_state: String = target.try_get("reservation_state")?;
    let pre_reclaim: String = target.try_get("reclaim_state")?;
    let pre_rev_state: String = target.try_get("revision_state")?;
    let pre_purge_stage: String = target.try_get("purge_stage")?;
    let pre_size: i64 = target.try_get("size_bytes")?;
    let pre_digest: Vec<u8> = target.try_get("content_digest")?;
    let pre_has_purge_commitment: bool = target.try_get("has_purge_commitment")?;
    let size_u64 = u64::try_from(pre_size).map_err(|_| Failure("invalid revision size"))?;

    let names = reservation_names(&pre_res_id);
    // Hold the exclusive file locks continuously from preflight verification across DB commit and
    // post-commit unlink so no window exists for replacement or foreign hard linking.
    let (entries, locked, mtimes) = if !is_replay {
        if pre_res_state != "settled" {
            return Err(Failure(
                "artifact revision is not eligible to be declared lost",
            ));
        }
        match pre_rev_state.as_str() {
            "active" | "retained" | "purging" => {}
            "lost" => {
                return Err(Failure(
                    "artifact revision payload is already declared lost",
                ));
            }
            "purged" => return Err(Failure("cannot declare a purged artifact revision lost")),
            _ => {
                return Err(Failure(
                    "artifact revision is not eligible to be declared lost",
                ));
            }
        }
        if pre_has_purge_commitment {
            return Err(Failure(TERMINAL_PURGE_COMMITTED));
        }
        let (entries, mut locked) = inspect_and_lock(&v, &names, false)?;
        let ledger = Ledger {
            state: &pre_res_state,
            reclaim: &pre_reclaim,
            revision: Some(&pre_rev_state),
            purge: Some(&pre_purge_stage),
        };
        check_unrecoverable_and_no_foreign_links(
            &ledger,
            &entries,
            &mut locked,
            &pre_res_id,
            size_u64,
            &pre_digest,
        )?;
        let mtimes = snapshot_mtimes(&locked)?;
        verify_locked_reservation(&v, &names, &entries, &locked, &mtimes)?;
        (entries, locked, mtimes)
    } else {
        if pre_rev_state != "lost" {
            return Err(Failure(
                "replayed declare-lost target revision is not in lost state",
            ));
        }
        let (entries, locked) = inspect_and_lock(&v, &names, true)?;
        let mtimes = snapshot_mtimes(&locked)?;
        (entries, locked, mtimes)
    };

    // Atomic READ COMMITTED transaction: acquire canonical locks via storage_declare_payload_lost,
    // re-verify volume sentinel, fence deadline, and continuously-held locked descriptors, then
    // commit durable DB state BEFORE unlinking leftover files on disk.
    let mut tx = c.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    sqlx::query(FS_TX_IDLE_TIMEOUT).execute(&mut *tx).await?;
    let fence_deadline = Instant::now() + TX_FENCE_BUDGET;

    let (applied, reservation_id, scope_id, artifact_id, previous_state, journal_seq): (
        bool,
        String,
        String,
        String,
        String,
        i64,
    ) = sqlx::query_as(
        "SELECT applied, reservation_id::text, scope_id::text, artifact_id::text,
                previous_state, journal_seq
           FROM openmettle.storage_declare_payload_lost($1::uuid, $2::uuid, $3, $4)",
    )
    .bind(opts.revision)
    .bind(opts.operator_id)
    .bind(opts.request_key)
    .bind(opts.reason)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_sql_error)?;

    if reservation_id != pre_res_id || (applied && previous_state != pre_rev_state) {
        return Err(Failure(CHANGED));
    }
    check_fence(fence_deadline)?;
    v.verify(&pin)?;
    verify_locked_reservation(&v, &names, &entries, &locked, &mtimes)?;
    check_fence(fence_deadline)?;

    tx.commit().await.map_err(|_| Failure(COMMIT_UNKNOWN))?;

    let unlinked_files =
        unlink_after_commit(&v, &pin, &names, &entries, &locked, &mtimes, fence_deadline)?;
    drop(locked);
    Ok(Outcome {
        applied,
        revision_id: opts.revision.to_owned(),
        reservation_id,
        scope_id,
        artifact_id,
        previous_state,
        journal_seq,
        unlinked_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_config::tests::support::Dir;
    use sha2::{Digest, Sha256};

    #[test]
    fn intact_and_acceptable_purging_payloads_are_refused() {
        let dir = Dir::new();
        let root = dir.path("vol");
        std::fs::create_dir(&root).unwrap();
        let v = Volume::open(Path::new(&root), true).unwrap();
        let res_id = "11111111-1111-4111-8111-111111111111";
        let payload = b"intact-bytes";
        let digest = Sha256::digest(payload).to_vec();
        let rev_path = Path::new(&root).join("revisions").join(res_id);
        std::fs::write(&rev_path, payload).unwrap();

        let names = reservation_names(res_id);
        let (entries, mut locked) = inspect_and_lock(&v, &names, false).unwrap();
        for state in ["active", "retained", "purging"] {
            let ledger = Ledger {
                state: "settled",
                reclaim: "none",
                revision: Some(state),
                purge: Some("none"),
            };
            let err = check_unrecoverable_and_no_foreign_links(
                &ledger,
                &entries,
                &mut locked,
                res_id,
                payload.len() as u64,
                &digest,
            )
            .unwrap_err();
            assert_eq!(err.0, "payload verifies intact; run storage rebind instead");
        }
        drop(locked);

        // Truncating a purging payload makes it acceptable to `storage rebind` as Plan::Empty.
        std::fs::write(&rev_path, b"").unwrap();
        let (entries, mut locked) = inspect_and_lock(&v, &names, false).unwrap();
        let purging = Ledger {
            state: "settled",
            reclaim: "none",
            revision: Some("purging"),
            purge: Some("none"),
        };
        let err = check_unrecoverable_and_no_foreign_links(
            &purging,
            &entries,
            &mut locked,
            res_id,
            payload.len() as u64,
            &digest,
        )
        .unwrap_err();
        assert_eq!(
            err.0,
            "purging payload is already acceptable to storage rebind"
        );
    }

    #[test]
    fn corrupt_payload_is_accepted_unless_foreign_hard_linked() {
        let dir = Dir::new();
        let root = dir.path("vol");
        std::fs::create_dir(&root).unwrap();
        let v = Volume::open(Path::new(&root), true).unwrap();
        let res_id = "22222222-2222-4222-8222-222222222222";
        let expected = b"expected-bytes";
        let digest = Sha256::digest(expected).to_vec();
        let rev_path = Path::new(&root).join("revisions").join(res_id);
        std::fs::write(&rev_path, b"corrupt!").unwrap();

        let names = reservation_names(res_id);
        let ledger = Ledger {
            state: "settled",
            reclaim: "none",
            revision: Some("active"),
            purge: Some("none"),
        };
        let (entries, mut locked) = inspect_and_lock(&v, &names, false).unwrap();
        check_unrecoverable_and_no_foreign_links(
            &ledger,
            &entries,
            &mut locked,
            res_id,
            expected.len() as u64,
            &digest,
        )
        .unwrap();
        drop(locked);

        // Adding a foreign hard link refuses declare-lost cleanup.
        let foreign = Path::new(&root).join("foreign");
        std::fs::hard_link(&rev_path, &foreign).unwrap();
        let err = inspect_and_lock(&v, &names, true).unwrap_err();
        assert_eq!(err.0, "foreign hard link");
        assert_eq!(std::fs::read(&foreign).unwrap(), b"corrupt!");
    }

    #[test]
    fn valid_trimmed_text_enforces_bounds_and_control_bytes() {
        assert!(valid_trimmed_text("key-1", 128));
        assert!(!valid_trimmed_text("", 128));
        assert!(!valid_trimmed_text(" leading", 128));
        assert!(!valid_trimmed_text("trailing ", 128));
        assert!(!valid_trimmed_text("line\nbreak", 128));
        assert!(!valid_trimmed_text(&"a".repeat(129), 128));
    }

    #[test]
    fn intact_payload_with_stale_purge_anchor_or_staged_copy_is_refused() {
        let dir = Dir::new();
        let root = dir.path("vol");
        std::fs::create_dir(&root).unwrap();
        let v = Volume::open(Path::new(&root), true).unwrap();
        let res_id = "33333333-3333-4333-8333-333333333333";
        let payload = b"intact-despite-stray-anchor";
        let digest = Sha256::digest(payload).to_vec();
        let rev_path = Path::new(&root).join("revisions").join(res_id);
        let purge_path = Path::new(&root)
            .join("revisions")
            .join(format!(".purge.{res_id}"));
        std::fs::write(&rev_path, payload).unwrap();
        // Stray `.purge.<id>` hard link causes `rebind::classify` to return Err("unexpected purge
        // anchor") on active/retained or Err("anchor is not empty") on purging. SHA-256 must run
        // independently and refuse unlinking the intact payload.
        std::fs::hard_link(&rev_path, &purge_path).unwrap();

        let names = reservation_names(res_id);
        let (entries, mut locked) = inspect_and_lock(&v, &names, false).unwrap();
        for state in ["active", "retained", "purging"] {
            let ledger = Ledger {
                state: "settled",
                reclaim: "none",
                revision: Some(state),
                purge: Some("none"),
            };
            let err = check_unrecoverable_and_no_foreign_links(
                &ledger,
                &entries,
                &mut locked,
                res_id,
                payload.len() as u64,
                &digest,
            )
            .unwrap_err();
            assert_eq!(
                err.0,
                "payload verifies intact; resolve layout mismatch or run storage rebind instead"
            );
        }
        drop(locked);
        assert_eq!(std::fs::read(&rev_path).unwrap(), payload);
        assert_eq!(std::fs::read(&purge_path).unwrap(), payload);

        // Intact bytes remaining only in `staging/<id>` must also be refused.
        let staging_path = Path::new(&root).join("staging").join(res_id);
        std::fs::remove_file(&rev_path).unwrap();
        std::fs::remove_file(&purge_path).unwrap();
        std::fs::write(&staging_path, payload).unwrap();
        let (entries, mut locked) = inspect_and_lock(&v, &names, false).unwrap();
        let active = Ledger {
            state: "settled",
            reclaim: "none",
            revision: Some("active"),
            purge: Some("none"),
        };
        let err = check_unrecoverable_and_no_foreign_links(
            &active,
            &entries,
            &mut locked,
            res_id,
            payload.len() as u64,
            &digest,
        )
        .unwrap_err();
        assert_eq!(
            err.0,
            "payload verifies intact; resolve layout mismatch or run storage rebind instead"
        );
    }

    #[test]
    fn continuous_flock_detects_foreign_link_and_expired_fence_aborts_before_unlink() {
        let dir = Dir::new();
        let root = dir.path("vol");
        std::fs::create_dir(&root).unwrap();
        let v = Volume::open(Path::new(&root), true).unwrap();
        let pin = v
            .publish_identity("44444444-4444-4444-8444-444444444444")
            .unwrap();
        let res_id = "55555555-5555-4555-8555-555555555555";
        let rev_path = Path::new(&root).join("revisions").join(res_id);
        std::fs::write(&rev_path, b"corrupt").unwrap();

        let names = reservation_names(res_id);
        let (entries, locked) = inspect_and_lock(&v, &names, true).unwrap();
        let mtimes = snapshot_mtimes(&locked).unwrap();

        // 1. Expired fence budget aborts strictly before unlinking, leaving the file untouched.
        let expired = Instant::now() - std::time::Duration::from_secs(1);
        let err =
            unlink_after_commit(&v, &pin, &names, &entries, &locked, &mtimes, expired).unwrap_err();
        assert_eq!(err.0, FENCE_EXPIRED);
        assert!(rev_path.exists());

        // 2. While `locked` is held continuously (no drop/reopen), an added foreign hard link is
        //    detected and blocks unlinking.
        let foreign = Path::new(&root).join("foreign-after-lock");
        std::fs::hard_link(&rev_path, &foreign).unwrap();
        let valid = Instant::now() + std::time::Duration::from_secs(60);
        let err =
            unlink_after_commit(&v, &pin, &names, &entries, &locked, &mtimes, valid).unwrap_err();
        assert_eq!(err.0, "foreign hard link");
        assert!(rev_path.exists());
        assert_eq!(std::fs::read(&foreign).unwrap(), b"corrupt");

        // Removing the foreign link lets post-commit unlink succeed under the same held lock.
        std::fs::remove_file(&foreign).unwrap();
        let unlinked =
            unlink_after_commit(&v, &pin, &names, &entries, &locked, &mtimes, valid).unwrap();
        assert_eq!(unlinked, 1);
        assert!(!rev_path.exists());
        drop(locked);

        // Even when all four reservation names are already absent, `unlink_after_commit` still
        // checks the fence budget and syncs both directories cleanly on retry.
        let (empty_entries, empty_locked) = inspect_and_lock(&v, &names, true).unwrap();
        assert!(empty_entries.iter().all(Option::is_none));
        let err = unlink_after_commit(
            &v,
            &pin,
            &names,
            &empty_entries,
            &empty_locked,
            &[],
            expired,
        )
        .unwrap_err();
        assert_eq!(err.0, FENCE_EXPIRED);
        assert_eq!(
            unlink_after_commit(&v, &pin, &names, &empty_entries, &empty_locked, &[], valid)
                .unwrap(),
            0
        );
    }

    #[test]
    fn zero_byte_revision_surviving_at_anchor_is_refused_as_intact() {
        let dir = Dir::new();
        let root = dir.path("vol");
        std::fs::create_dir(&root).unwrap();
        let v = Volume::open(Path::new(&root), true).unwrap();
        let res_id = "66666666-6666-4666-8666-666666666666";
        let digest = Sha256::digest(b"").to_vec();
        let names = reservation_names(res_id);

        for (anchor_path, state) in [
            (
                Path::new(&root)
                    .join("revisions")
                    .join(format!(".purge.{res_id}")),
                "active",
            ),
            (
                Path::new(&root)
                    .join("staging")
                    .join(format!(".reclaim.{res_id}")),
                "retained",
            ),
        ] {
            std::fs::write(&anchor_path, b"").unwrap();
            let (entries, mut locked) = inspect_and_lock(&v, &names, false).unwrap();
            let ledger = Ledger {
                state: "settled",
                reclaim: "none",
                revision: Some(state),
                purge: Some("none"),
            };
            let err = check_unrecoverable_and_no_foreign_links(
                &ledger,
                &entries,
                &mut locked,
                res_id,
                0,
                &digest,
            )
            .unwrap_err();
            assert_eq!(
                err.0,
                "payload verifies intact; resolve layout mismatch or run storage rebind instead"
            );
            drop(locked);
            assert!(anchor_path.exists());
            std::fs::remove_file(&anchor_path).unwrap();
        }
    }
}
