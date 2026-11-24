//! Owner-run rebinding of payload inodes after a file-copy restore (ADR 0040, amendment of
//! 24 November 2026). A copy keeps every byte and creates new files, whose inode numbers may
//! or may not differ from the originals. An inode number is therefore never evidence here.
//! A settled payload is accepted only when its size and SHA-256 match the ledger. The ledger
//! holds neither for an unsettled upload, and no writer survives a restore to settle it, so
//! its bytes are discarded and the row is bound to the emptied file: the same evidence the
//! reconciler requires before it binds a file it did not create.
use super::{
    adoption::{self, Failure, READ_FAILED, RESCAN, RevisionDigests},
    drift::{self, Drift},
    volume::Volume,
};
use rustix::fs as at;
use sqlx::{Connection, PgConnection, Row, postgres::PgRow};
use std::{
    collections::{HashMap, HashSet},
    fs::{File, TryLockError},
    io::ErrorKind,
    os::unix::fs::MetadataExt,
    path::Path,
};

pub struct Options<'a> {
    pub root: &'a Path,
    /// The barrier a failed or interrupted run left behind.
    pub replace: Option<&'a str>,
}

#[derive(Debug, Default)]
pub struct Report {
    /// Reservations now bound to another inode.
    pub rebound: usize,
    /// Unsettled uploads whose bytes were discarded.
    pub emptied: usize,
    /// Reservations that verified under the inode they already carried.
    pub unchanged: usize,
    /// Quarantined reservations. They are reported and left exactly as they were.
    pub quarantined: Vec<String>,
    /// Reservations left untouched, each with its reason.
    pub failures: Vec<(String, &'static str)>,
    /// The filesystem drift check on the result. Not run when a reservation failed.
    pub drift: Option<Drift>,
    /// The barrier this run still holds unless the report is [`Self::complete`].
    pub run: String,
}

impl Report {
    /// Every reservation verified and the drift check finds no file mismatch: no recorded
    /// inode, size or name that disagrees with the volume. Only then is the barrier released.
    /// Quarantined reservations and accounting drift are states a running system tolerates;
    /// they are reported and do not keep a restored volume closed.
    pub fn complete(&self) -> bool {
        self.failures.is_empty() && self.drift.as_ref().is_some_and(|drift| drift.files == 0)
    }
}

/// A run that stopped before it could report.
#[derive(Debug)]
pub struct Stopped {
    pub reason: &'static str,
    /// `None`: no file and no row changed, and the barrier is as the run found it. Otherwise
    /// the run may already have emptied uploads and still holds the barrier under this value.
    pub run: Option<String>,
}

const CHANGED: &str = "volume changed during rebind";

const INVENTORY: &str =
    "SELECT s.id::text,s.state,s.reclaim_state,s.payload_ino::text,s.adoption_unverified,
    s.publish_pending,r.state AS revision_state,r.purge_stage,r.size_bytes,r.content_digest
    FROM openmettle.storage_reservations s LEFT JOIN openmettle.artifact_revisions r
    ON r.scope_id=s.scope_id AND r.reservation_id=s.id ORDER BY s.id";

/// Everything the scan relied on. The locked apply requires it unchanged.
type Identity = (
    String,
    String,
    String,
    Option<String>,
    bool,
    bool,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<Vec<u8>>,
);
fn identity(row: &PgRow) -> Identity {
    (
        row.get("id"),
        row.get("state"),
        row.get("reclaim_state"),
        row.get("payload_ino"),
        row.get("adoption_unverified"),
        row.get("publish_pending"),
        row.get("revision_state"),
        row.get("purge_stage"),
        row.get("size_bytes"),
        row.get("content_digest"),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    ino: u64,
    len: u64,
    links: u64,
}

/// The four names one reservation can own.
#[derive(Clone, Copy, Debug, Default)]
struct Names {
    staging: Option<Entry>,
    reclaim: Option<Entry>,
    revision: Option<Entry>,
    purge: Option<Entry>,
}

struct Ledger<'a> {
    state: &'a str,
    reclaim: &'a str,
    revision: Option<&'a str>,
    purge: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// The lifecycle state owns no file and none is present.
    Skip,
    /// Accept the published payload once its size and SHA-256 match the ledger.
    Content(u64),
    /// Accept an empty file. `truncate` first discards an unsettled upload's bytes.
    Empty { ino: u64, truncate: bool },
}

/// Decide what a bound, unquarantined reservation needs, from its lifecycle state and every
/// name found on disk. The layouts accepted here are the ones the drift check accepts, with
/// one difference: no inode number is compared with the ledger, because a copy can keep one
/// by chance. An error leaves the reservation untouched.
fn classify(l: &Ledger<'_>, n: &Names) -> Result<Plan, &'static str> {
    let reclaim_allowed = matches!(
        (l.state, l.reclaim),
        ("reserved", "claiming" | "truncated") | ("released", "anchor_pending_unlink")
    );
    let purge_allowed = l.revision == Some("purging")
        || (l.revision == Some("purged") && l.purge == Some("anchor_pending_unlink"));
    if n.reclaim.is_some() && !reclaim_allowed {
        return Err("unexpected reclaim anchor");
    }
    if n.purge.is_some() && !purge_allowed {
        return Err("unexpected purge anchor");
    }
    if [n.reclaim, n.purge]
        .into_iter()
        .flatten()
        .any(|e| e.len != 0)
    {
        return Err("anchor is not empty");
    }
    let present: Vec<Entry> = [n.staging, n.revision, n.reclaim, n.purge]
        .into_iter()
        .flatten()
        .collect();
    // A copy that split one file into several is not repaired here.
    if present.iter().any(|e| e.ino != present[0].ino) {
        return Err("intra_reservation_inode_mismatch");
    }
    let empty = |e: Entry| {
        Ok(Plan::Empty {
            ino: e.ino,
            truncate: false,
        })
    };
    match (l.state, l.revision) {
        // A closed reservation keeps at most its pending anchor.
        ("released", _) | ("settled", Some("purged")) => {
            if n.staging.is_some() || n.revision.is_some() {
                return Err("unexpected payload");
            }
            n.reclaim.or(n.purge).map_or(Ok(Plan::Skip), empty)
        }
        ("settled", Some("active" | "retained")) => match n.revision {
            Some(published) => Ok(Plan::Content(published.ino)),
            None => Err("missing revision"),
        },
        ("settled", Some("purging")) => match (n.revision, n.purge) {
            // Claimed for purge but not yet truncated: the bytes are still the revision's.
            (Some(published), _) if published.len != 0 => Ok(Plan::Content(published.ino)),
            (Some(truncated), _) => empty(truncated),
            (None, Some(anchor)) => empty(anchor),
            // A staging name alone is neither the published payload nor its anchor.
            (None, None) => Err("missing revision"),
        },
        ("reserved", _) => {
            let Some(&file) = present.first() else {
                return Err("missing reservation file");
            };
            if l.reclaim == "truncated" && (n.reclaim.is_none() || present.len() != 1) {
                return Err("truncated_visible_name_present");
            }
            if file.len == 0 {
                return empty(file);
            }
            // Never empty bytes that a name outside this reservation also reaches.
            if file.links != present.len() as u64 {
                return Err("foreign hard link");
            }
            Ok(Plan::Empty {
                ino: file.ino,
                truncate: true,
            })
        }
        _ => Err("missing revision"),
    }
}

enum Evidence {
    Content { size: u64, digest: Vec<u8> },
    Empty { truncate: bool },
}

/// One reservation's four names, as `(in revisions, name)`.
type OwnedNames = [(bool, String); 4];

/// A reservation whose file the scan accepted. No descriptor is kept between the scan and
/// the apply: each step reopens the file and requires it unchanged.
struct Binding {
    id: String,
    bound: u64,
    ino: u64,
    /// The row is `reserved` and still marked for publication.
    pending: bool,
    names: OwnedNames,
    /// The inode each name held during the scan.
    seen: [Option<u64>; 4],
    /// The name to open.
    at: usize,
    evidence: Evidence,
}

fn directory(v: &Volume, revisions: bool) -> &File {
    if revisions { &v.revisions } else { &v.staging }
}

impl Binding {
    /// Open the file, take its exclusive lock and require every name the reservation owns to
    /// hold what the scan saw. `None`: the file exists but cannot be opened.
    fn open(&self, v: &Volume) -> Result<Option<File>, Failure> {
        let (revisions, name) = &self.names[self.at];
        // Opened for writing so that the exclusive lock also works over NFS.
        let file = match v.regular(directory(v, *revisions), name, true) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Failure("reservation in use")),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        if file.metadata()?.ino() != self.ino {
            return Err(Failure(CHANGED));
        }
        for ((revisions, name), seen) in self.names.iter().zip(self.seen) {
            if v.inode(directory(v, *revisions), name)? != seen {
                return Err(Failure(CHANGED));
            }
        }
        Ok(Some(file))
    }

    /// Discard an unsettled upload's bytes. Immediately before, the reservation's names and
    /// the link count of the descriptor being truncated are checked again: together they
    /// show that every link to the file is one of the reservation's own names. A process
    /// that changes the volume after this check is not detected.
    fn truncate(&self, v: &Volume) -> Result<(), Failure> {
        let file = self.open(v)?.ok_or(Failure(CHANGED))?;
        let own = self.seen.iter().filter(|i| **i == Some(self.ino)).count() as u64;
        if file.metadata()?.nlink() != own {
            return Err(Failure(CHANGED));
        }
        file.set_len(0)?;
        file.sync_all()?;
        Ok(())
    }
}

#[derive(Default)]
struct Scan {
    digests: RevisionDigests,
    bindings: Vec<Binding>,
    report: Report,
}

impl Scan {
    fn inspect(
        &mut self,
        v: &Volume,
        row: &PgRow,
        observed: Observed,
        aliased: bool,
    ) -> Result<(), Failure> {
        let id: &str = row.try_get("id")?;
        if row.try_get("adoption_unverified")? {
            self.report.quarantined.push(id.to_owned());
            return Ok(());
        }
        // Binding a reservation that never had an inode is adoption's decision.
        let Some(bound) = row.try_get::<Option<&str>, _>("payload_ino")? else {
            return Ok(());
        };
        let mut fail = |reason| self.report.failures.push((id.to_owned(), reason));
        if aliased {
            fail("cross_reservation_inode_alias");
            return Ok(());
        }
        let Some(entries) = observed.entries else {
            fail("invalid volume entry");
            return Ok(());
        };
        let ledger = Ledger {
            state: row.try_get("state")?,
            reclaim: row.try_get("reclaim_state")?,
            revision: row.try_get("revision_state")?,
            purge: row.try_get("purge_stage")?,
        };
        let [staging, reclaim, revision, purge] = entries;
        let plan = classify(
            &ledger,
            &Names {
                staging,
                reclaim,
                revision,
                purge,
            },
        );
        let seen = entries.map(|e| e.map(|e| e.ino));
        let (ino, at, evidence) = match plan {
            Err(reason) => {
                fail(reason);
                return Ok(());
            }
            Ok(Plan::Skip) => return Ok(()),
            // The published name is index 2 of the reservation's names.
            Ok(Plan::Content(ino)) => (
                ino,
                2,
                Evidence::Content {
                    size: row.try_get::<i64, _>("size_bytes")? as u64,
                    digest: row.try_get("content_digest")?,
                },
            ),
            Ok(Plan::Empty { ino, truncate }) => (
                ino,
                seen.iter()
                    .position(|i| *i == Some(ino))
                    .ok_or(Failure(CHANGED))?,
                Evidence::Empty { truncate },
            ),
        };
        let binding = Binding {
            id: id.to_owned(),
            bound: bound.parse().map_err(|_| Failure("invalid inode"))?,
            ino,
            pending: row.try_get("publish_pending")?,
            names: observed.names,
            seen,
            at,
            evidence,
        };
        // Opening also shows that no other process holds the file.
        let Some(mut file) = binding.open(v)? else {
            fail("payload is not accessible");
            return Ok(());
        };
        if let Evidence::Content { size, digest } = &binding.evidence {
            match self.digests.verify(id, &mut file, *size, digest) {
                Ok(()) => {}
                Err(Failure(reason @ ("size_or_digest_mismatch" | READ_FAILED))) => {
                    fail(reason);
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        self.bindings.push(binding);
        Ok(())
    }
}

/// What each of one reservation's names holds on disk. `entries` is `None` when a name is
/// not a regular file on this volume.
struct Observed {
    names: OwnedNames,
    entries: Option<[Option<Entry>; 4]>,
}

#[allow(clippy::unnecessary_cast)]
fn entry(stat: &at::Stat) -> Entry {
    Entry {
        ino: stat.st_ino,
        len: stat.st_size as u64,
        links: stat.st_nlink as u64,
    }
}

/// Stat every name of every reservation, and collect the reservations that share an inode
/// with another one.
fn observe(v: &Volume, rows: &[PgRow]) -> Result<(Vec<Observed>, HashSet<String>), Failure> {
    let mut owners: HashMap<u64, String> = HashMap::new();
    let mut aliased = HashSet::new();
    let mut observed = Vec::with_capacity(rows.len());
    for row in rows {
        let id: &str = row.try_get("id")?;
        let names = [
            (false, id.to_owned()),
            (false, format!(".reclaim.{id}")),
            (true, id.to_owned()),
            (true, format!(".purge.{id}")),
        ];
        let mut entries = Some([None; 4]);
        for (slot, (revisions, name)) in names.iter().enumerate() {
            match v.stat(directory(v, *revisions), name) {
                Ok(Some(stat)) => {
                    if let Some(other) = owners.insert(stat.st_ino, id.to_owned())
                        && other != id
                    {
                        aliased.insert(other);
                        aliased.insert(id.to_owned());
                    }
                    if let Some(entries) = &mut entries {
                        entries[slot] = Some(entry(&stat));
                    }
                }
                Ok(None) => {}
                Err(_) => entries = None,
            }
        }
        observed.push(Observed { names, entries });
    }
    Ok((observed, aliased))
}

/// Rebind the pinned volume at `opts.root`. A report that is not [`Report::complete`] has
/// committed every reservation that verified and keeps the barrier.
pub async fn rebind(c: &mut PgConnection, opts: &Options<'_>) -> Result<Report, Stopped> {
    let refused = |failure: Failure| Stopped {
        reason: failure.0,
        run: None,
    };
    let v = Volume::open(opts.root, false).map_err(|e| refused(e.into()))?;
    let run = adoption::owner_run(c).await.map_err(refused)?;
    let pin = adoption::take_barrier(c, &v, &run, opts.replace)
        .await
        .map_err(refused)?;
    let mut modified = false;
    let failure = match &pin {
        Some(pin) => match scan_and_apply(c, &v, &run, pin, &mut modified).await {
            Ok(report) => return Ok(report),
            Err(failure) => failure,
        },
        None => Failure("volume is not pinned"),
    };
    // Hand the barrier back only when no file was modified. The statement also confirms the
    // rollback: it runs after the abandoned transaction on the same connection.
    let untouched = !modified
        && adoption::restore_barrier(c, &run, opts.replace)
            .await
            .is_ok();
    Err(Stopped {
        reason: failure.0,
        run: (!untouched).then_some(run),
    })
}

async fn scan_and_apply(
    c: &mut PgConnection,
    v: &Volume,
    run: &str,
    pin: &str,
    modified: &mut bool,
) -> Result<Report, Failure> {
    // The barrier keeps every runtime process out, so hashing needs no SQL lock.
    let rows = sqlx::query(INVENTORY).fetch_all(&mut *c).await?;
    let (observed, aliased) = observe(v, &rows)?;
    let mut scan = Scan::default();
    for (row, observed) in rows.iter().zip(observed) {
        let id: &str = row.try_get("id")?;
        scan.inspect(v, row, observed, aliased.contains(id))?;
    }

    let mut tx = c.begin().await?;
    sqlx::query("SELECT id FROM openmettle.storage_reservations ORDER BY id FOR UPDATE")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT id FROM openmettle.artifact_revisions ORDER BY id FOR UPDATE")
        .execute(&mut *tx)
        .await?;
    // A later run that replaced this barrier fences this one out here.
    let own: Option<bool> = sqlx::query_scalar(
        "SELECT adoption_run_id=$1::uuid FROM openmettle.storage_volume_control WHERE id FOR UPDATE",
    )
    .bind(run)
    .fetch_one(&mut *tx)
    .await?;
    if own != Some(true) {
        return Err(Failure("adoption ownership changed"));
    }
    v.verify(pin)?;
    let locked = sqlx::query(INVENTORY).fetch_all(&mut *tx).await?;
    if !locked.iter().map(identity).eq(rows.iter().map(identity)) {
        return Err(Failure("ledger changed during rebind"));
    }
    // Before the first write: every file is still the one inspected, and every file whose
    // inode is about to be recorded is durable.
    scan.digests.recheck = true;
    for b in &scan.bindings {
        let mut file = b.open(v)?.ok_or(Failure(CHANGED))?;
        match &b.evidence {
            Evidence::Content { size, digest } => {
                scan.digests.verify(&b.id, &mut file, *size, digest)?
            }
            Evidence::Empty { truncate: false } if file.metadata()?.len() != 0 => {
                return Err(Failure(RESCAN));
            }
            Evidence::Empty { .. } => {}
        }
        if b.ino != b.bound {
            file.sync_all()?;
        }
    }
    let mut report = scan.report;
    for b in &scan.bindings {
        if matches!(b.evidence, Evidence::Empty { truncate: true }) {
            // From here a failing run keeps the barrier.
            *modified = true;
            b.truncate(v)?;
            report.emptied += 1;
        }
    }
    // The directory entries behind every recorded inode are durable before the commit.
    for dir in [&v.root, &v.staging, &v.revisions] {
        at::fsync(dir)?;
    }
    for b in &scan.bindings {
        if b.ino == b.bound {
            report.unchanged += 1;
            if !b.pending {
                continue;
            }
        } else {
            report.rebound += 1;
        }
        let updated = sqlx::query(
            "UPDATE openmettle.storage_reservations SET payload_ino=$2::text::numeric,publish_pending=false
             WHERE id=$1::uuid AND payload_ino=$3::text::numeric AND NOT adoption_unverified",
        )
        .bind(&b.id)
        .bind(b.ino.to_string())
        .bind(b.bound.to_string())
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(Failure("ledger changed during rebind"));
        }
    }
    // The barrier is never released on a volume where the drift check finds a file mismatch.
    if report.failures.is_empty() {
        let drift = drift::verify_volume(&mut tx, v, pin)
            .await
            .map_err(|_| Failure("drift verification failed"))?;
        report.drift = Some(drift);
    }
    if report.complete() {
        adoption::restore_barrier(&mut tx, run, None).await?;
    }
    tx.commit().await?;
    report.run = run.to_owned();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_config::tests::support::Dir;

    fn entry(ino: u64, len: u64, links: u64) -> Option<Entry> {
        Some(Entry { ino, len, links })
    }
    fn ledger<'a>(
        state: &'a str,
        reclaim: &'a str,
        revision: Option<&'a str>,
        purge: Option<&'a str>,
    ) -> Ledger<'a> {
        Ledger {
            state,
            reclaim,
            revision,
            purge,
        }
    }
    const NONE: Names = Names {
        staging: None,
        reclaim: None,
        revision: None,
        purge: None,
    };
    const EMPTY: Result<Plan, &str> = Ok(Plan::Empty {
        ino: 40,
        truncate: false,
    });
    const DISCARD: Result<Plan, &str> = Ok(Plan::Empty {
        ino: 40,
        truncate: true,
    });

    #[test]
    fn a_settled_payload_is_accepted_only_through_its_content() {
        for state in ["active", "retained"] {
            let l = ledger("settled", "none", Some(state), Some("none"));
            let published = Names {
                revision: entry(40, 9, 1),
                ..NONE
            };
            assert_eq!(classify(&l, &published), Ok(Plan::Content(40)));
            // The staging name left before detachment is the same file.
            let linked = Names {
                revision: entry(40, 9, 2),
                staging: entry(40, 9, 2),
                ..NONE
            };
            assert_eq!(classify(&l, &linked), Ok(Plan::Content(40)));
            let split = Names {
                staging: entry(41, 9, 1),
                ..linked
            };
            assert_eq!(
                classify(&l, &split),
                Err("intra_reservation_inode_mismatch")
            );
            assert_eq!(classify(&l, &NONE), Err("missing revision"));
            let staged_only = Names {
                staging: entry(40, 9, 1),
                ..NONE
            };
            assert_eq!(classify(&l, &staged_only), Err("missing revision"));
            let anchored = Names {
                purge: entry(40, 0, 2),
                ..published
            };
            assert_eq!(classify(&l, &anchored), Err("unexpected purge anchor"));
        }
    }

    #[test]
    fn an_unsettled_upload_is_emptied_never_verified() {
        for reclaim in ["none", "claiming"] {
            let l = ledger("reserved", reclaim, None, None);
            let staged = Names {
                staging: entry(40, 9, 1),
                ..NONE
            };
            assert_eq!(classify(&l, &staged), DISCARD);
            // Published but not settled: both names are one file, emptied once.
            let published = Names {
                staging: entry(40, 9, 2),
                revision: entry(40, 9, 2),
                ..NONE
            };
            assert_eq!(classify(&l, &published), DISCARD);
            // A link from outside the reservation's own names forbids truncation.
            let foreign = Names {
                staging: entry(40, 9, 2),
                ..NONE
            };
            assert_eq!(classify(&l, &foreign), Err("foreign hard link"));
            let split = Names {
                revision: entry(41, 9, 1),
                ..published
            };
            assert_eq!(
                classify(&l, &split),
                Err("intra_reservation_inode_mismatch")
            );
            // An upload already emptied (an earlier interrupted run) is only bound.
            let empty = Names {
                staging: entry(40, 0, 1),
                ..NONE
            };
            assert_eq!(classify(&l, &empty), EMPTY);
            assert_eq!(classify(&l, &NONE), Err("missing reservation file"));
            let purge = Names {
                purge: entry(40, 0, 2),
                ..empty
            };
            assert_eq!(classify(&l, &purge), Err("unexpected purge anchor"));
        }
        let anchored = Names {
            reclaim: entry(40, 9, 1),
            ..NONE
        };
        let claiming = ledger("reserved", "claiming", None, None);
        assert_eq!(classify(&claiming, &anchored), Err("anchor is not empty"));
        let unclaimed = ledger("reserved", "none", None, None);
        assert_eq!(
            classify(&unclaimed, &anchored),
            Err("unexpected reclaim anchor")
        );
    }

    #[test]
    fn anchors_and_truncated_payloads_are_accepted_only_when_empty() {
        let anchor = Names {
            reclaim: entry(40, 0, 1),
            ..NONE
        };
        let purge = Names {
            purge: entry(40, 0, 1),
            ..NONE
        };
        let truncated = ledger("reserved", "truncated", None, None);
        assert_eq!(classify(&truncated, &anchor), EMPTY);
        let visible = Names {
            staging: entry(40, 0, 2),
            ..anchor
        };
        assert_eq!(
            classify(&truncated, &visible),
            Err("truncated_visible_name_present")
        );
        let released = ledger("released", "anchor_pending_unlink", None, None);
        assert_eq!(classify(&released, &anchor), EMPTY);
        assert_eq!(classify(&released, &NONE), Ok(Plan::Skip));
        let nonempty = Names {
            reclaim: entry(40, 3, 1),
            ..NONE
        };
        assert_eq!(classify(&released, &nonempty), Err("anchor is not empty"));

        let purged = ledger(
            "settled",
            "none",
            Some("purged"),
            Some("anchor_pending_unlink"),
        );
        assert_eq!(classify(&purged, &purge), EMPTY);
        assert_eq!(classify(&purged, &NONE), Ok(Plan::Skip));
    }

    #[test]
    fn a_purging_revision_needs_its_published_payload_or_its_anchor() {
        let purging = ledger("settled", "none", Some("purging"), Some("none"));
        // Claimed but not yet truncated: still the revision's bytes, whatever the number.
        let full = Names {
            revision: entry(40, 9, 1),
            ..NONE
        };
        assert_eq!(classify(&purging, &full), Ok(Plan::Content(40)));
        let truncated = Names {
            revision: entry(40, 0, 2),
            purge: entry(40, 0, 2),
            ..NONE
        };
        assert_eq!(classify(&purging, &truncated), EMPTY);
        let anchor = Names {
            purge: entry(40, 0, 1),
            ..NONE
        };
        assert_eq!(classify(&purging, &anchor), EMPTY);
        let both = Names {
            revision: entry(40, 9, 2),
            purge: entry(40, 9, 2),
            ..NONE
        };
        assert_eq!(classify(&purging, &both), Err("anchor is not empty"));
        assert_eq!(classify(&purging, &NONE), Err("missing revision"));
        // The drift check rejects a purge that has only a staging name.
        let staged = Names {
            staging: entry(40, 0, 1),
            ..NONE
        };
        assert_eq!(classify(&purging, &staged), Err("missing revision"));
    }

    #[test]
    fn a_closed_reservation_owns_no_payload() {
        let payload = Names {
            staging: entry(40, 9, 1),
            ..NONE
        };
        let anchor = Names {
            reclaim: entry(40, 0, 1),
            ..NONE
        };
        for l in [
            ledger("released", "none", None, None),
            ledger("released", "anchor_pending_unlink", None, None),
            ledger("settled", "none", Some("purged"), Some("none")),
        ] {
            assert_eq!(classify(&l, &payload), Err("unexpected payload"));
        }
        let closed = ledger("released", "none", None, None);
        assert_eq!(classify(&closed, &NONE), Ok(Plan::Skip));
        assert_eq!(classify(&closed, &anchor), Err("unexpected reclaim anchor"));
    }

    /// A published, unsettled upload as the scan saw it: two names, one file.
    fn two_name_upload(dir: &Dir) -> (Volume, Binding) {
        let root = dir.path("volume");
        std::fs::create_dir(&root).unwrap();
        let v = Volume::open(Path::new(&root), true).unwrap();
        let id = "5f0c2f0e-7d0a-4c55-9a43-3d0b8a2f6c11";
        let staged = Path::new(&root).join("staging").join(id);
        std::fs::write(&staged, b"unsettled").unwrap();
        std::fs::hard_link(&staged, Path::new(&root).join("revisions").join(id)).unwrap();
        let ino = std::fs::metadata(&staged).unwrap().ino();
        let binding = Binding {
            id: id.into(),
            bound: 7,
            ino,
            pending: true,
            names: [
                (false, id.into()),
                (false, format!(".reclaim.{id}")),
                (true, id.into()),
                (true, format!(".purge.{id}")),
            ],
            seen: [Some(ino), None, Some(ino), None],
            at: 0,
            evidence: Evidence::Empty { truncate: true },
        };
        (v, binding)
    }

    #[test]
    fn truncation_empties_a_file_only_its_reservation_links_to() {
        let dir = Dir::new();
        let (v, binding) = two_name_upload(&dir);
        binding.truncate(&v).unwrap();
        let staged = Path::new(&dir.path("volume"))
            .join("staging")
            .join(&binding.id);
        assert_eq!(std::fs::metadata(staged).unwrap().len(), 0);
    }

    #[test]
    fn truncation_rechecks_every_name_the_reservation_owns() {
        let dir = Dir::new();
        let (v, binding) = two_name_upload(&dir);
        let root = dir.path("volume");
        let root = Path::new(&root);
        // Between the scan and the truncation the published name is replaced by a link from
        // outside the reservation. The link count is unchanged.
        std::fs::remove_file(root.join("revisions").join(&binding.id)).unwrap();
        let foreign = root.join("foreign");
        std::fs::hard_link(root.join("staging").join(&binding.id), &foreign).unwrap();
        assert_eq!(binding.truncate(&v).unwrap_err().0, CHANGED);
        assert_eq!(std::fs::read(foreign).unwrap(), b"unsettled");
    }
}
