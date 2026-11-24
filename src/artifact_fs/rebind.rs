//! Owner-run rebinding of payload inodes after a file-copy restore (ADR 0040, amendment of
//! 24 November 2026). A copy keeps every byte and changes every inode number. A settled
//! payload is bound to its copied file only when the file's size and SHA-256 match the ledger.
//! The ledger holds neither for an unsettled upload, and no writer survives a restore to
//! settle it, so its bytes are discarded and the row is bound to the emptied file: the same
//! evidence the reconciler requires before it binds a file it did not create.
use super::{
    adoption::{self, Failure, READ_FAILED, RESCAN, RevisionDigests},
    volume::Volume,
};
use sqlx::{Connection, PgConnection, Row, postgres::PgRow};
use std::{
    collections::{HashMap, HashSet},
    fs::{File, TryLockError},
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
    /// Reservations whose files already matched.
    pub unchanged: usize,
    /// Quarantined reservations, which are left to the owner.
    pub quarantined: usize,
    /// Reservations left untouched, each with its reason.
    pub failures: Vec<(String, &'static str)>,
    /// The barrier this run still holds when `failures` is not empty.
    pub run: String,
}

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
    bound: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// The ledger expects no file for this reservation.
    Skip,
    /// The files already carry the bound inode.
    Keep,
    /// Bind once the published payload's size and SHA-256 match the ledger.
    Content(u64),
    /// Bind to an empty file. `truncate` first discards an unsettled upload's bytes.
    Empty { ino: u64, truncate: bool },
}

/// Decide what a bound, unquarantined reservation needs, from its ledger state and the names
/// found on disk. An error leaves the reservation untouched.
fn classify(l: &Ledger<'_>, n: &Names) -> Result<Plan, &'static str> {
    let live = matches!(l.revision, Some("active" | "retained"));
    let owned = match (l.state, l.reclaim, l.revision, l.purge) {
        ("reserved", ..) => [n.staging, n.revision, n.reclaim],
        ("released", "anchor_pending_unlink", ..) => [n.reclaim, None, None],
        ("settled", _, Some("active" | "retained"), _) => [n.revision, n.staging, None],
        ("settled", _, Some("purging"), _) => [n.revision, n.staging, n.purge],
        ("settled", _, Some("purged"), Some("anchor_pending_unlink")) => [n.purge, None, None],
        _ => return Ok(Plan::Skip),
    };
    let present: Vec<Entry> = owned.into_iter().flatten().collect();
    let Some(&file) = present.first() else {
        return match l.state {
            "reserved" => Err("missing reservation file"),
            _ if live || l.revision == Some("purging") => Err("missing revision"),
            // The pending anchor is already unlinked; the sweep only clears the marker.
            _ => Ok(Plan::Skip),
        };
    };
    // A copy that split one file into several is not repaired here.
    if present.iter().any(|e| e.ino != file.ino) {
        return Err("intra_reservation_inode_mismatch");
    }
    if live {
        // Verified even under an unchanged inode number, which a copy can produce by chance.
        return match n.revision {
            Some(_) => Ok(Plan::Content(file.ino)),
            None => Err("missing revision"),
        };
    }
    if file.ino == l.bound {
        return Ok(Plan::Keep);
    }
    match (l.state, l.revision) {
        ("reserved", _) => {
            if l.reclaim == "truncated" && (n.reclaim.is_none() || present.len() != 1) {
                return Err("truncated_visible_name_present");
            }
            if file.len == 0 {
                return Ok(Plan::Empty {
                    ino: file.ino,
                    truncate: false,
                });
            }
            if n.reclaim.is_some() {
                return Err("anchor is not empty");
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
        // Claimed for purge but not yet truncated: the bytes are still the revision's.
        ("settled", Some("purging")) if file.len != 0 => match (n.purge, n.revision) {
            (Some(_), _) => Err("anchor is not empty"),
            (None, None) => Err("missing revision"),
            (None, Some(_)) => Ok(Plan::Content(file.ino)),
        },
        _ if file.len != 0 => Err("anchor is not empty"),
        _ => Ok(Plan::Empty {
            ino: file.ino,
            truncate: false,
        }),
    }
}

enum Evidence {
    Content {
        size: u64,
        digest: Vec<u8>,
    },
    /// The descriptor keeps its exclusive lock until the apply transaction ends.
    Empty {
        file: File,
        revisions: bool,
        name: String,
        /// The link count that made truncation safe; zero when nothing is truncated.
        truncate_links: u64,
    },
}

struct Binding {
    id: String,
    bound: u64,
    ino: u64,
    evidence: Evidence,
}

fn lock(file: &File) -> Result<(), Failure> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(Failure("reservation in use")),
        Err(TryLockError::Error(e)) => Err(e.into()),
    }
}

fn directory(v: &Volume, revisions: bool) -> &File {
    if revisions { &v.revisions } else { &v.staging }
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
        observed: &Observed,
        aliased: bool,
    ) -> Result<(), Failure> {
        let id: &str = row.try_get("id")?;
        if row.try_get("adoption_unverified")? {
            self.report.quarantined += 1;
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
            bound: bound.parse().map_err(|_| Failure("invalid inode"))?,
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
        let (ino, evidence) = match plan {
            Err(reason) => {
                fail(reason);
                return Ok(());
            }
            Ok(Plan::Skip) => return Ok(()),
            Ok(Plan::Keep) => {
                self.report.unchanged += 1;
                return Ok(());
            }
            Ok(Plan::Content(ino)) => {
                let size = row.try_get::<i64, _>("size_bytes")? as u64;
                let digest: Vec<u8> = row.try_get("content_digest")?;
                // Opened for writing so that the exclusive lock also works over NFS.
                let mut file = v.regular(&v.revisions, id, true)?;
                lock(&file)?;
                match self.digests.verify(id, &mut file, size, &digest) {
                    Ok(()) => {}
                    Err(Failure(reason @ ("size_or_digest_mismatch" | READ_FAILED))) => {
                        fail(reason);
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
                v.matches(&file, &v.revisions, id, ino)?;
                (ino, Evidence::Content { size, digest })
            }
            Ok(Plan::Empty { ino, truncate }) => {
                let (at, entry) = observed
                    .names
                    .iter()
                    .zip(entries)
                    .find_map(|(at, e)| e.filter(|e| e.ino == ino).map(|e| (at, e)))
                    .ok_or(Failure("volume verification failed"))?;
                let file = v.regular(directory(v, at.0), &at.1, true)?;
                lock(&file)?;
                v.matches(&file, directory(v, at.0), &at.1, ino)?;
                let evidence = Evidence::Empty {
                    file,
                    revisions: at.0,
                    name: at.1.clone(),
                    truncate_links: if truncate { entry.links } else { 0 },
                };
                (ino, evidence)
            }
        };
        self.bindings.push(Binding {
            id: id.to_owned(),
            bound: ledger.bound,
            ino,
            evidence,
        });
        Ok(())
    }
}

/// One reservation's four names, as `(in revisions, name)`, and what each holds on disk.
/// `entries` is `None` when a name is not a regular file on this volume.
struct Observed {
    names: [(bool, String); 4],
    entries: Option<[Option<Entry>; 4]>,
}

#[allow(clippy::unnecessary_cast)]
fn entry(stat: &rustix::fs::Stat) -> Entry {
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

/// Rebind the pinned volume at `opts.root`. Returns `Err` when the run was refused: no row
/// changed and the barrier is as it was found. Otherwise every reservation that verified is
/// committed, and the barrier is released only when the report carries no failure.
pub async fn rebind(c: &mut PgConnection, opts: &Options<'_>) -> Result<Report, Failure> {
    let v = Volume::open(opts.root, false)?;
    let run = adoption::owner_run(c).await?;
    let pin = adoption::take_barrier(c, &v, &run, opts.replace).await?;
    let result = match &pin {
        Some(pin) => scan_and_apply(c, &v, &run, pin).await,
        None => Err(Failure("volume is not pinned")),
    };
    if result.is_err() {
        // A refused run hands the barrier back as it found it.
        sqlx::query(
            "UPDATE openmettle.storage_volume_control SET adoption_run_id=$2::uuid
             WHERE id AND adoption_run_id=$1::uuid",
        )
        .bind(&run)
        .bind(opts.replace)
        .execute(c)
        .await?;
    }
    result
}

async fn scan_and_apply(
    c: &mut PgConnection,
    v: &Volume,
    run: &str,
    pin: &str,
) -> Result<Report, Failure> {
    // The barrier keeps every runtime process out, so hashing needs no SQL lock.
    let rows = sqlx::query(INVENTORY).fetch_all(&mut *c).await?;
    let (observed, aliased) = observe(v, &rows)?;
    let mut scan = Scan::default();
    for (row, observed) in rows.iter().zip(&observed) {
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
    // Confirm every file is still the one inspected before the first write.
    scan.digests.recheck = true;
    for b in &scan.bindings {
        match &b.evidence {
            Evidence::Content { size, digest } => {
                let mut file = v.regular(&v.revisions, &b.id, true)?;
                v.matches(&file, &v.revisions, &b.id, b.ino)?;
                scan.digests.verify(&b.id, &mut file, *size, digest)?;
            }
            Evidence::Empty {
                file,
                revisions,
                name,
                truncate_links,
            } => {
                v.matches(file, directory(v, *revisions), name, b.ino)?;
                let m = file.metadata()?;
                if match truncate_links {
                    0 => m.len() != 0,
                    links => m.nlink() != *links,
                } {
                    return Err(Failure(RESCAN));
                }
            }
        }
    }
    let mut report = scan.report;
    for b in &scan.bindings {
        if let Evidence::Empty {
            file,
            truncate_links: 1..,
            ..
        } = &b.evidence
        {
            file.set_len(0)?;
            file.sync_all()?;
            report.emptied += 1;
        }
        if b.ino == b.bound {
            report.unchanged += 1;
            continue;
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
        report.rebound += 1;
    }
    if report.failures.is_empty() {
        sqlx::query(
            "UPDATE openmettle.storage_volume_control SET adoption_run_id=NULL
             WHERE id AND adoption_run_id=$1::uuid",
        )
        .bind(run)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    report.run = run.to_owned();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            bound: 7,
        }
    }
    const NONE: Names = Names {
        staging: None,
        reclaim: None,
        revision: None,
        purge: None,
    };

    #[test]
    fn a_settled_payload_is_bound_only_through_its_content() {
        for state in ["active", "retained"] {
            let l = ledger("settled", "none", Some(state), Some("none"));
            // Even an unchanged inode number is no evidence on a copied volume.
            for ino in [7, 40] {
                let published = Names {
                    revision: entry(ino, 9, 1),
                    ..NONE
                };
                assert_eq!(classify(&l, &published), Ok(Plan::Content(ino)));
            }
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
            assert_eq!(
                classify(&l, &staged),
                Ok(Plan::Empty {
                    ino: 40,
                    truncate: true
                })
            );
            // Published but not settled: both names are one file, emptied once.
            let published = Names {
                staging: entry(40, 9, 2),
                revision: entry(40, 9, 2),
                ..NONE
            };
            assert_eq!(
                classify(&l, &published),
                Ok(Plan::Empty {
                    ino: 40,
                    truncate: true
                })
            );
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
            assert_eq!(
                classify(&l, &empty),
                Ok(Plan::Empty {
                    ino: 40,
                    truncate: false
                })
            );
            // The original volume: the file still carries the bound inode and keeps its bytes.
            let original = Names {
                staging: entry(7, 9, 1),
                ..NONE
            };
            assert_eq!(classify(&l, &original), Ok(Plan::Keep));
            assert_eq!(classify(&l, &NONE), Err("missing reservation file"));
        }
        let claiming = ledger("reserved", "claiming", None, None);
        let anchored = Names {
            reclaim: entry(40, 9, 1),
            ..NONE
        };
        assert_eq!(classify(&claiming, &anchored), Err("anchor is not empty"));
    }

    #[test]
    fn anchors_and_truncated_payloads_are_bound_only_when_empty() {
        let anchor = Names {
            reclaim: entry(40, 0, 1),
            ..NONE
        };
        let purge = Names {
            purge: entry(40, 0, 1),
            ..NONE
        };
        let empty = Ok(Plan::Empty {
            ino: 40,
            truncate: false,
        });
        let truncated = ledger("reserved", "truncated", None, None);
        assert_eq!(classify(&truncated, &anchor), empty);
        let visible = Names {
            staging: entry(40, 0, 2),
            ..anchor
        };
        assert_eq!(
            classify(&truncated, &visible),
            Err("truncated_visible_name_present")
        );
        let released = ledger("released", "anchor_pending_unlink", None, None);
        assert_eq!(classify(&released, &anchor), empty);
        assert_eq!(classify(&released, &NONE), Ok(Plan::Skip));
        let nonempty = Names {
            reclaim: entry(40, 3, 1),
            ..NONE
        };
        assert_eq!(classify(&released, &nonempty), Err("anchor is not empty"));

        let purging = ledger("settled", "none", Some("purging"), Some("none"));
        assert_eq!(classify(&purging, &purge), empty);
        // Claimed but not yet truncated: still the revision's bytes.
        let full = Names {
            revision: entry(40, 9, 1),
            ..NONE
        };
        assert_eq!(classify(&purging, &full), Ok(Plan::Content(40)));
        let both = Names {
            revision: entry(40, 9, 2),
            purge: entry(40, 9, 2),
            ..NONE
        };
        assert_eq!(classify(&purging, &both), Err("anchor is not empty"));
        assert_eq!(classify(&purging, &NONE), Err("missing revision"));
        let purged = ledger(
            "settled",
            "none",
            Some("purged"),
            Some("anchor_pending_unlink"),
        );
        assert_eq!(classify(&purged, &purge), empty);
        let bound = Names {
            purge: entry(7, 0, 1),
            ..NONE
        };
        assert_eq!(classify(&purged, &bound), Ok(Plan::Keep));
    }

    #[test]
    fn states_without_files_are_skipped() {
        let anything = Names {
            staging: entry(40, 9, 1),
            reclaim: entry(41, 0, 1),
            revision: entry(42, 9, 1),
            purge: entry(43, 0, 1),
        };
        for l in [
            ledger("released", "none", None, None),
            ledger("settled", "none", Some("purged"), Some("none")),
        ] {
            assert_eq!(classify(&l, &anything), Ok(Plan::Skip));
        }
    }
}
