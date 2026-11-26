//! Owner-run rebinding of payload inodes after a file-copy restore (ADR 0040, amendment of
//! 24 November 2026). A copy keeps every byte and creates new files, whose inode numbers may
//! or may not differ from the originals. An inode number is therefore never evidence here.
//! A settled payload is accepted only when its size and SHA-256 match the ledger. The ledger
//! holds neither for an unsettled upload, and no writer survives a restore to settle it, so
//! its bytes are discarded and the row is bound to the emptied file: the same evidence the
//! reconciler requires before it binds a file it did not create.
use super::{
    adoption::{self, COMMIT_UNKNOWN, Failure, READ_FAILED, RESCAN, RevisionDigests},
    drift::{self, Drift},
    volume::Volume,
};
use rustix::{fs as at, io::Errno};
use sqlx::{Connection, PgConnection, Row, postgres::PgRow};
use std::{
    collections::{HashMap, HashSet},
    fs::{File, TryLockError},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Instant,
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
    /// Reservations that never recorded an inode and have bytes under their staging name.
    /// They are reported and left exactly as they were; the reconciler quarantines them.
    pub unbound_staged: Vec<String>,
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
    pub barrier: Barrier,
}

/// What a stopped run knows about the barrier.
#[derive(Debug)]
pub enum Barrier {
    /// No file and no row changed, and the barrier is as the run found it.
    AsFound,
    /// The run emptied uploads and still holds the barrier under this value.
    Held(String),
    /// A commit or the hand-back got no answer. The barrier may or may not carry this value,
    /// which is the one the run used; only the database can tell.
    Unknown(String),
}

const CHANGED: &str = "volume changed during rebind";
const INACCESSIBLE: &str = "payload is not accessible";

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
pub(super) struct Entry {
    pub ino: u64,
    pub len: u64,
    pub links: u64,
}

/// The four names one reservation can own.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Names {
    pub staging: Option<Entry>,
    pub reclaim: Option<Entry>,
    pub revision: Option<Entry>,
    pub purge: Option<Entry>,
}

pub(super) struct Ledger<'a> {
    pub state: &'a str,
    pub reclaim: &'a str,
    pub revision: Option<&'a str>,
    pub purge: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// The lifecycle state owns no file and none is present.
    Skip,
    /// Accept the published payload once its size and SHA-256 match the ledger.
    Content(u64),
    /// Accept an empty file. `truncate` first discards an unsettled upload's bytes.
    Empty { ino: u64, truncate: bool },
    /// A lost revision still has leftover reservation files on disk with no foreign hard links.
    Cleanup,
}

/// Returns `true` if any present inode among a reservation's four names has links outside
/// those four names (including cross-reservation inode aliases or external hard links).
pub(super) fn has_foreign_hard_link(entries: &[Option<Entry>; 4]) -> bool {
    for entry in entries.iter().flatten() {
        let own = entries
            .iter()
            .flatten()
            .filter(|other| other.ino == entry.ino)
            .count() as u64;
        if entry.links != own {
            return true;
        }
    }
    false
}

/// Decide what a bound, unquarantined reservation needs, from its lifecycle state and every
/// name found on disk. The layouts accepted here are the ones the drift check accepts, with
/// one difference: no inode number is compared with the ledger, because a copy can keep one
/// by chance. An error leaves the reservation untouched.
pub(super) fn classify(l: &Ledger<'_>, n: &Names) -> Result<Plan, &'static str> {
    let all = [n.staging, n.reclaim, n.revision, n.purge];
    if l.state == "settled" && l.revision == Some("lost") {
        if all.iter().all(Option::is_none) {
            return Ok(Plan::Skip);
        }
        if has_foreign_hard_link(&all) {
            return Err("foreign hard link");
        }
        return Ok(Plan::Cleanup);
    }
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

/// Validate a reservation that never recorded an inode. `true`: it is reserved and has
/// bytes under its staging name, which the reconciler quarantines when the reservation
/// expires (`reclaim::release`). Every other name is one the drift check rejects.
fn classify_unbound(l: &Ledger<'_>, n: &Names) -> Result<bool, &'static str> {
    if l.state == "settled" && l.revision == Some("lost") {
        let all = [n.staging, n.reclaim, n.revision, n.purge];
        if all.iter().all(Option::is_none) {
            return Ok(false);
        }
        if has_foreign_hard_link(&all) {
            return Err("foreign hard link");
        }
        return Ok(false);
    }
    if n.reclaim.is_some() {
        return Err("unexpected reclaim anchor");
    }
    if n.purge.is_some() {
        return Err("unexpected purge anchor");
    }
    match (l.state, l.revision) {
        ("reserved", _) if n.revision.is_none() => Ok(n.staging.is_some_and(|e| e.len != 0)),
        ("released", _) | ("settled", Some("purged"))
            if n.staging.is_none() && n.revision.is_none() =>
        {
            Ok(false)
        }
        ("reserved" | "released", _) | ("settled", Some("purged")) => Err("unexpected payload"),
        _ => Err("reservation has no recorded inode"),
    }
}

enum Evidence {
    Content { size: u64, digest: Vec<u8> },
    Empty { truncate: bool },
}

/// One reservation's four names, as `(in revisions, name)`.
pub(super) type OwnedNames = [(bool, String); 4];

pub(super) fn reservation_names(id: &str) -> OwnedNames {
    [
        (false, id.to_owned()),
        (false, format!(".reclaim.{id}")),
        (true, id.to_owned()),
        (true, format!(".purge.{id}")),
    ]
}

/// Stat all four names of a reservation. `Ok(None)` means at least one name is not a regular
/// file on this volume.
pub(super) fn stat_reservation(
    v: &Volume,
    names: &OwnedNames,
) -> Result<Option<[Option<Entry>; 4]>, Failure> {
    let mut entries = [None; 4];
    for (slot, (revisions, name)) in names.iter().enumerate() {
        match v.stat(directory(v, *revisions), name) {
            Ok(Some(stat)) => entries[slot] = Some(entry(&stat)),
            Ok(None) => {}
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(entries))
}

/// Open and exclusively `flock` every unique regular inode present among a reservation's four
/// names, verifying each name still maps to its stat'd inode and optionally checking that no
/// foreign hard links exist outside those four names.
pub(super) fn lock_reservation_files(
    v: &Volume,
    names: &OwnedNames,
    entries: &[Option<Entry>; 4],
    check_links: bool,
) -> Result<Vec<(u64, File)>, Failure> {
    let mut own_links: HashMap<u64, u64> = HashMap::new();
    let mut unique_slots: Vec<(u64, usize)> = Vec::new();
    for (slot, maybe) in entries.iter().enumerate() {
        let Some(e) = maybe else { continue };
        let count = own_links.entry(e.ino).or_insert(0);
        if *count == 0 {
            unique_slots.push((e.ino, slot));
        }
        *count += 1;
    }
    let mut locked = Vec::with_capacity(unique_slots.len());
    for (ino, slot) in unique_slots {
        let (revisions, name) = &names[slot];
        let file = match v.regular(directory(v, *revisions), name, true) {
            Ok(file) => file,
            Err(e) if file_specific(&e) => return Err(Failure(INACCESSIBLE)),
            Err(e) => return Err(e.into()),
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Failure("reservation in use")),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let meta = file.metadata()?;
        if meta.ino() != ino || meta.dev() != v.dev {
            return Err(Failure(CHANGED));
        }
        locked.push((ino, file));
    }
    for ((revisions, name), expected) in names.iter().zip(entries.iter()) {
        if v.inode(directory(v, *revisions), name)? != expected.map(|e| e.ino) {
            return Err(Failure(CHANGED));
        }
    }
    if check_links {
        for (ino, file) in &locked {
            let nlink = file.metadata()?.nlink();
            let own = own_links[ino];
            if nlink > own {
                return Err(Failure("foreign hard link"));
            }
            if nlink < own {
                return Err(Failure(CHANGED));
            }
        }
    }
    Ok(locked)
}

/// Unlink every present name among a reservation's four names and `fsync` each touched
/// directory. Call only while holding the exclusive locks from [`lock_reservation_files`].
pub(super) fn unlink_reservation_files(
    v: &Volume,
    names: &OwnedNames,
    entries: &[Option<Entry>; 4],
    deadline: Option<Instant>,
) -> Result<usize, Failure> {
    let mut unlinked = 0;
    let mut touched_staging = false;
    let mut touched_revisions = false;
    for ((revisions, name), entry) in names.iter().zip(entries.iter()) {
        let Some(e) = entry else { continue };
        let dir = directory(v, *revisions);
        if let Some(deadline) = deadline {
            v.unlink_before(dir, name, e.ino, deadline)?;
        } else {
            v.unlink(dir, name, e.ino)?;
        }
        if *revisions {
            touched_revisions = true;
        } else {
            touched_staging = true;
        }
        unlinked += 1;
    }
    if touched_staging {
        at::fsync(&v.staging)?;
    }
    if touched_revisions {
        at::fsync(&v.revisions)?;
    }
    Ok(unlinked)
}

/// A lost revision that still has leftover files on disk or a stale recorded `payload_ino`.
struct LostCleanup {
    id: String,
    bound: Option<u64>,
    names: OwnedNames,
    entries: [Option<Entry>; 4],
}

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

pub(super) fn directory(v: &Volume, revisions: bool) -> &File {
    if revisions { &v.revisions } else { &v.staging }
}

/// An open error that concerns this one file, such as a wrong mode or a read error. It fails
/// the reservation, not the run. Not file-specific: the process ran out of descriptors or
/// memory, the name vanished after the scan, or the volume's identity check failed (which
/// carries no OS error).
fn file_specific(error: &std::io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        !matches!(
            Errno::from_raw_os_error(code),
            Errno::MFILE | Errno::NFILE | Errno::NOMEM | Errno::NOENT
        )
    })
}

impl Binding {
    /// Open the file, take its exclusive lock and require every name the reservation owns to
    /// hold what the scan saw. `None`: the file exists but cannot be opened.
    fn open(&self, v: &Volume) -> Result<Option<File>, Failure> {
        let (revisions, name) = &self.names[self.at];
        // Opened for writing so that the exclusive lock also works over NFS.
        let file = match v.regular(directory(v, *revisions), name, true) {
            Ok(file) => file,
            Err(e) if file_specific(&e) => return Ok(None),
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
    /// `modified` is set immediately before the first byte is discarded. `false`: the file
    /// could not be opened and nothing was discarded.
    fn truncate(&self, v: &Volume, modified: &mut bool) -> Result<bool, Failure> {
        let Some(file) = self.open(v)? else {
            return Ok(false);
        };
        let own = self.seen.iter().filter(|i| **i == Some(self.ino)).count() as u64;
        if file.metadata()?.nlink() != own {
            return Err(Failure(CHANGED));
        }
        // From here a failing run keeps the barrier.
        *modified = true;
        file.set_len(0)?;
        file.sync_all()?;
        Ok(true)
    }
}

#[derive(Default)]
struct Scan {
    digests: RevisionDigests,
    bindings: Vec<Binding>,
    lost_cleanups: Vec<LostCleanup>,
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
        let bound = row.try_get::<Option<&str>, _>("payload_ino")?;
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
        let names = Names {
            staging,
            reclaim,
            revision,
            purge,
        };
        if ledger.state == "settled" && ledger.revision == Some("lost") {
            let bound = bound
                .map(str::parse::<u64>)
                .transpose()
                .map_err(|_| Failure("invalid inode"))?;
            if entries.iter().all(Option::is_none) && bound.is_none() {
                return Ok(());
            }
            if has_foreign_hard_link(&entries) {
                fail("foreign hard link");
                return Ok(());
            }
            // Verify every present file can be opened and exclusively locked without foreign links.
            if let Err(err) = lock_reservation_files(v, &observed.names, &entries, true) {
                match err.0 {
                    INACCESSIBLE | "foreign hard link" => {
                        fail(err.0);
                        return Ok(());
                    }
                    _ => return Err(err),
                }
            }
            self.lost_cleanups.push(LostCleanup {
                id: id.to_owned(),
                bound,
                names: observed.names,
                entries,
            });
            return Ok(());
        }
        // Binding a reservation that never had an inode is adoption's decision. Its layout
        // is still validated, and its file is never touched.
        let Some(bound) = bound else {
            match classify_unbound(&ledger, &names) {
                Err(reason) => fail(reason),
                Ok(true) => self.report.unbound_staged.push(id.to_owned()),
                Ok(false) => {}
            }
            return Ok(());
        };
        let plan = classify(&ledger, &names);
        let seen = entries.map(|e| e.map(|e| e.ino));
        let (ino, at, evidence) = match plan {
            Err(reason) => {
                fail(reason);
                return Ok(());
            }
            Ok(Plan::Skip | Plan::Cleanup) => return Ok(()),
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
            fail(INACCESSIBLE);
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
        let names = reservation_names(id);
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
        barrier: Barrier::AsFound,
    };
    let v = Volume::open(opts.root, false).map_err(|e| refused(e.into()))?;
    let run = adoption::owner_run(c).await.map_err(refused)?;
    let pin = match adoption::take_barrier(c, &v, &run, opts.replace).await {
        Ok(pin) => pin,
        // The barrier may or may not have been installed.
        Err(Failure(COMMIT_UNKNOWN)) => {
            return Err(Stopped {
                reason: COMMIT_UNKNOWN,
                barrier: Barrier::Unknown(run),
            });
        }
        Err(failure) => return Err(refused(failure)),
    };
    let mut modified = false;
    let failure = match &pin {
        Some(pin) => match scan_and_apply(c, &v, &run, pin, &mut modified).await {
            Ok(report) => return Ok(report),
            Err(failure) => failure,
        },
        None => Failure("volume is not pinned"),
    };
    let barrier = if failure.0 == COMMIT_UNKNOWN {
        // The final commit may have released the barrier or kept it. Handing it back now
        // could open a volume the commit had closed.
        Barrier::Unknown(run)
    } else if modified {
        Barrier::Held(run)
    } else if adoption::restore_barrier(c, &run, opts.replace)
        .await
        .is_ok()
    {
        // The statement also confirms the rollback: it runs after the abandoned transaction
        // on the same connection.
        Barrier::AsFound
    } else {
        Barrier::Unknown(run)
    };
    Err(Stopped {
        reason: failure.0,
        barrier,
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
    let mut report = scan.report;
    let mut accepted = Vec::with_capacity(scan.bindings.len());
    for b in &scan.bindings {
        // A file that cannot be reopened fails its reservation, as in the scan.
        let Some(mut file) = b.open(v)? else {
            report.failures.push((b.id.clone(), INACCESSIBLE));
            continue;
        };
        match &b.evidence {
            Evidence::Content { size, digest } => {
                scan.digests.verify(&b.id, &mut file, *size, digest)?
            }
            Evidence::Empty { truncate: false } if file.metadata()?.len() != 0 => {
                return Err(Failure(RESCAN));
            }
            Evidence::Empty { .. } => {}
        }
        // Whatever its inode number: an equal number does not show that the data is durable.
        file.sync_all()?;
        accepted.push(b);
    }
    let mut bound = Vec::with_capacity(accepted.len());
    for b in accepted {
        if matches!(b.evidence, Evidence::Empty { truncate: true }) {
            if !b.truncate(v, modified)? {
                report.failures.push((b.id.clone(), INACCESSIBLE));
                continue;
            }
            report.emptied += 1;
        }
        bound.push(b);
    }
    let mut cleared_lost = Vec::with_capacity(scan.lost_cleanups.len());
    for lost in &scan.lost_cleanups {
        let locked = match lock_reservation_files(v, &lost.names, &lost.entries, true) {
            Ok(locked) => locked,
            Err(Failure(reason @ (INACCESSIBLE | "foreign hard link"))) => {
                report.failures.push((lost.id.clone(), reason));
                continue;
            }
            Err(err) => return Err(err),
        };
        if lost.entries.iter().any(Option::is_some) {
            *modified = true;
            unlink_reservation_files(v, &lost.names, &lost.entries, None)?;
        }
        drop(locked);
        cleared_lost.push(lost);
    }
    // The directory entries behind every recorded inode are durable before the commit.
    for dir in [&v.root, &v.staging, &v.revisions] {
        at::fsync(dir)?;
    }
    for lost in cleared_lost {
        if let Some(prev) = lost.bound {
            let updated = sqlx::query(
                "UPDATE openmettle.storage_reservations SET payload_ino=NULL,publish_pending=false
                 WHERE id=$1::uuid AND payload_ino=$2::text::numeric AND NOT adoption_unverified",
            )
            .bind(&lost.id)
            .bind(prev.to_string())
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(Failure("ledger changed during rebind"));
            }
        }
    }
    for b in bound {
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
    tx.commit().await.map_err(|_| Failure(COMMIT_UNKNOWN))?;
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

    #[test]
    fn an_unbound_reservation_is_validated_and_only_reported() {
        let reserved = ledger("reserved", "none", None, None);
        assert_eq!(classify_unbound(&reserved, &NONE), Ok(false));
        // An empty staging file is one the reconciler binds and reclaims itself.
        let empty = Names {
            staging: entry(40, 0, 1),
            ..NONE
        };
        assert_eq!(classify_unbound(&reserved, &empty), Ok(false));
        // Bytes under the staging name: the reconciler quarantines the reservation.
        let staged = Names {
            staging: entry(40, 9, 1),
            ..NONE
        };
        assert_eq!(classify_unbound(&reserved, &staged), Ok(true));
        let published = Names {
            revision: entry(40, 9, 1),
            ..NONE
        };
        assert_eq!(
            classify_unbound(&reserved, &published),
            Err("unexpected payload")
        );
        let anchored = Names {
            reclaim: entry(40, 0, 1),
            ..NONE
        };
        assert_eq!(
            classify_unbound(&reserved, &anchored),
            Err("unexpected reclaim anchor")
        );
        let released = ledger("released", "none", None, None);
        assert_eq!(classify_unbound(&released, &NONE), Ok(false));
        assert_eq!(
            classify_unbound(&released, &staged),
            Err("unexpected payload")
        );
        let settled = ledger("settled", "none", Some("active"), Some("none"));
        assert_eq!(
            classify_unbound(&settled, &published),
            Err("reservation has no recorded inode")
        );
        let lost = ledger("settled", "none", Some("lost"), Some("none"));
        assert_eq!(classify(&lost, &NONE), Ok(Plan::Skip));
        assert_eq!(classify(&lost, &published), Ok(Plan::Cleanup));
        assert_eq!(classify_unbound(&lost, &NONE), Ok(false));
        assert_eq!(classify_unbound(&lost, &published), Ok(false));
        let linked = Names {
            staging: entry(40, 9, 2),
            revision: entry(40, 9, 2),
            ..NONE
        };
        assert_eq!(classify(&lost, &linked), Ok(Plan::Cleanup));
        let foreign = Names {
            revision: entry(40, 9, 2),
            ..NONE
        };
        assert_eq!(classify(&lost, &foreign), Err("foreign hard link"));
        assert_eq!(classify_unbound(&lost, &foreign), Err("foreign hard link"));
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
        let mut modified = false;
        assert!(binding.truncate(&v, &mut modified).unwrap());
        assert!(modified);
        let staged = Path::new(&dir.path("volume"))
            .join("staging")
            .join(&binding.id);
        assert_eq!(std::fs::metadata(staged).unwrap().len(), 0);
    }

    #[test]
    fn truncation_refuses_a_link_the_reservations_names_do_not_explain() {
        let dir = Dir::new();
        let (v, binding) = two_name_upload(&dir);
        let root = dir.path("volume");
        let root = Path::new(&root);
        // Both names are as the scan saw them; a third link appeared elsewhere.
        let foreign = root.join("foreign");
        std::fs::hard_link(root.join("staging").join(&binding.id), &foreign).unwrap();
        let mut modified = false;
        assert_eq!(binding.truncate(&v, &mut modified).unwrap_err().0, CHANGED);
        assert!(!modified);
        assert_eq!(std::fs::read(foreign).unwrap(), b"unsettled");
    }

    #[test]
    fn only_an_error_about_the_file_itself_fails_the_reservation() {
        let error = |errno: Errno| std::io::Error::from_raw_os_error(errno.raw_os_error());
        for errno in [Errno::ACCESS, Errno::PERM, Errno::IO, Errno::ROFS] {
            assert!(file_specific(&error(errno)), "{errno:?}");
        }
        // The process ran out of descriptors or memory, or the file vanished after the scan.
        for errno in [Errno::MFILE, Errno::NFILE, Errno::NOMEM, Errno::NOENT] {
            assert!(!file_specific(&error(errno)), "{errno:?}");
        }
        // The volume's own identity mismatch carries no OS error.
        assert!(!file_specific(&std::io::Error::other("identity")));
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
        let mut modified = false;
        assert_eq!(binding.truncate(&v, &mut modified).unwrap_err().0, CHANGED);
        // A refused check modified nothing, so it must not keep a barrier that was clear.
        assert!(!modified);
        assert_eq!(std::fs::read(foreign).unwrap(), b"unsettled");
    }
}
