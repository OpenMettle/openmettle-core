//! Generic PVC POSIX artifact archive (`OMART01`), destination/config hygiene, and GFS
//! retention pruning (`7 daily, 4 weekly, 3 monthly` default) for ADR 0046.

use super::crypto::{KeyRingPaths, file_dev_ino};
use crate::runs;
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use rustix::fs::{self as at, AtFlags, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const ARTIFACT_ARCHIVE_MAGIC: &[u8; 8] = b"OMART01\0";
const ENTRY_FILE: u8 = 0x01;
const ENTRY_END: u8 = 0x00;
const VOLUME_SENTINEL: &str = ".openmettle-volume-id";
const MAX_CONFIG_FILE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_BACKUP_META_BYTES: usize = 64 * 1024;
const COPY_BUF_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub enum ArchiveError {
    Invalid(&'static str),
    Integrity(&'static str),
    Io(io::Error),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(msg) => f.write_str(msg),
            Self::Integrity(msg) => f.write_str(msg),
            Self::Io(_) => f.write_str("backup archive filesystem I/O error"),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<io::Error> for ArchiveError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustix::io::Errno> for ArchiveError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

/// Settled artifact revision row expected on disk during quiesced backup capture.
#[derive(Clone, Debug)]
pub struct SettledArtifactRecord {
    pub revision_id: String,
    pub reservation_id: String,
    pub state: String,
    pub size_bytes: i64,
    pub content_digest: [u8; 32],
    pub payload_ino: Option<u64>,
}

/// Summary of an archived `OMART01` generic PVC artifact stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactArchiveSummary {
    pub volume_id: Option<String>,
    pub revision_count: u64,
    pub payload_bytes: u64,
}

/// Open a regular file without following symlinks and with `O_CLOEXEC | O_NONBLOCK`.
pub fn open_regular_nofollow(path: &Path) -> Result<fs::File, ArchiveError> {
    if !path.is_absolute() {
        return Err(ArchiveError::Invalid("path must be absolute"));
    }
    let fd = at::openat(
        at::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ArchiveError::Invalid("regular file unreadable or symlink refused"))?;
    let file = fs::File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(ArchiveError::Invalid("expected a regular file"));
    }
    Ok(file)
}

/// Read an entire regular file without following symlinks or blocking on FIFOs, enforcing an
/// explicit upper size bound before and during reading.
pub(crate) fn read_regular_bounded_nofollow(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, ArchiveError> {
    let file = open_regular_nofollow(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > max_bytes as u64 {
        return Err(ArchiveError::Invalid(
            "regular file exceeds maximum allowed size",
        ));
    }
    let mut bytes = Vec::with_capacity((meta.len() as usize).min(max_bytes) + 1);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(ArchiveError::Invalid(
            "regular file exceeds maximum allowed size",
        ));
    }
    Ok(bytes)
}

/// Open a directory descriptor without following symlinks and with `O_CLOEXEC`.
fn open_dir_nofollow(
    parent: impl std::os::fd::AsFd,
    path: &Path,
) -> Result<fs::File, ArchiveError> {
    let fd = at::openat(
        parent,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(fs::File::from(fd))
}

fn read_volume_sentinel(
    dir: &fs::File,
    expected_dev: u64,
    expected_role: &str,
) -> Result<String, ArchiveError> {
    let fd = at::openat(
        dir,
        VOLUME_SENTINEL,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ArchiveError::Integrity("artifact volume sentinel missing or unreadable"))?;
    let f = fs::File::from(fd);
    let m = f.metadata()?;
    if !m.is_file() || m.dev() != expected_dev || (m.mode() & 0o777) != 0o600 || m.len() > 64 {
        return Err(ArchiveError::Integrity("artifact volume sentinel invalid"));
    }
    let mut text = String::new();
    f.take(64).read_to_string(&mut text)?;
    let id = text
        .strip_suffix(&format!(":{expected_role}\n"))
        .ok_or(ArchiveError::Integrity(
            "artifact volume sentinel malformed",
        ))?;
    runs::uuid(id).map_err(|_| ArchiveError::Integrity("artifact volume sentinel invalid UUID"))?;
    Ok(id.to_owned())
}

/// Stream every settled artifact payload from `artifact_root` (generic POSIX PVC file copy,
/// zero CSI snapshot assumptions) into `writer` in deterministic `OMART01` format, verifying
/// `.openmettle-volume-id`, `O_NOFOLLOW`, single hard link (`nlink == 1`), `payload_ino`, exact
/// `size_bytes`, and live SHA-256 `content_digest` against PostgreSQL metadata.
pub fn write_artifact_archive(
    artifact_root: Option<&Path>,
    pinned_volume_id: Option<&str>,
    records: &[SettledArtifactRecord],
    writer: &mut dyn Write,
) -> Result<ArtifactArchiveSummary, ArchiveError> {
    writer.write_all(ARTIFACT_ARCHIVE_MAGIC)?;

    let Some(root_path) = artifact_root else {
        if pinned_volume_id.is_some() || !records.is_empty() {
            return Err(ArchiveError::Invalid(
                "--artifact-root is required when the artifact storage volume is pinned",
            ));
        }
        writer.write_all(&[0u8])?; // has_volume_id = false
        writer.write_all(&[ENTRY_END])?;
        writer.flush()?;
        return Ok(ArtifactArchiveSummary {
            volume_id: None,
            revision_count: 0,
            payload_bytes: 0,
        });
    };

    if !root_path.is_absolute() {
        return Err(ArchiveError::Invalid("artifact root must be absolute"));
    }
    let root_dir = open_dir_nofollow(at::CWD, root_path)?;
    let root_dev = root_dir.metadata()?.dev();
    let staging_dir = open_dir_nofollow(&root_dir, Path::new("staging"))?;
    let revisions_dir = open_dir_nofollow(&root_dir, Path::new("revisions"))?;
    if staging_dir.metadata()?.dev() != root_dev || revisions_dir.metadata()?.dev() != root_dev {
        return Err(ArchiveError::Integrity(
            "artifact subdirectories reside on another device",
        ));
    }

    let volume_id = match pinned_volume_id {
        Some(expected) => {
            for (dir, role) in [
                (&root_dir, "root"),
                (&staging_dir, "staging"),
                (&revisions_dir, "revisions"),
            ] {
                if read_volume_sentinel(dir, root_dev, role)? != expected {
                    return Err(ArchiveError::Integrity(
                        "artifact volume sentinel does not match PostgreSQL volume pin",
                    ));
                }
            }
            Some(expected.to_owned())
        }
        None => None,
    };

    // Ensure staging contains no live unsettled payload files after drain.
    for entry in at::Dir::read_from(&staging_dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| ArchiveError::Integrity("non-UTF-8 entry in staging directory"))?;
        if matches!(name, "." | ".." | VOLUME_SENTINEL) {
            continue;
        }
        return Err(ArchiveError::Integrity(
            "unexpected file remains in artifact staging directory after drain",
        ));
    }

    // Write volume_id header.
    match &volume_id {
        Some(vid) => {
            writer.write_all(&[1u8])?;
            write_u16_str(writer, vid)?;
        }
        None => writer.write_all(&[0u8])?,
    }

    let mut expected_names = BTreeSet::new();
    let mut sorted: Vec<&SettledArtifactRecord> = records.iter().collect();
    sorted.sort_by(|a, b| a.reservation_id.cmp(&b.reservation_id));

    let mut buf = vec![0u8; COPY_BUF_BYTES];
    let mut total_bytes: u64 = 0;

    for rec in &sorted {
        if rec.size_bytes < 0 {
            return Err(ArchiveError::Integrity("negative artifact revision size"));
        }
        runs::uuid(&rec.reservation_id)
            .map_err(|_| ArchiveError::Integrity("invalid reservation UUID"))?;
        runs::uuid(&rec.revision_id)
            .map_err(|_| ArchiveError::Integrity("invalid revision UUID"))?;
        expected_names.insert(rec.reservation_id.as_str());

        let stat = at::statat(
            &revisions_dir,
            rec.reservation_id.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| ArchiveError::Integrity("settled artifact payload missing on disk"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(ArchiveError::Integrity(
                "settled artifact entry is not a regular file",
            ));
        }
        let fd = at::openat(
            &revisions_dir,
            rec.reservation_id.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ArchiveError::Integrity("settled artifact payload unreadable"))?;
        let mut file = fs::File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file() || meta.dev() != root_dev || meta.ino() != stat.st_ino {
            return Err(ArchiveError::Integrity(
                "artifact payload identity mismatch",
            ));
        }
        if meta.nlink() != 1 {
            return Err(ArchiveError::Integrity(
                "artifact payload has foreign or extra hard links",
            ));
        }
        if let Some(bound_ino) = rec.payload_ino
            && meta.ino() != bound_ino
        {
            return Err(ArchiveError::Integrity(
                "artifact payload inode does not match PostgreSQL ledger",
            ));
        }
        let expected_size = rec.size_bytes as u64;
        if meta.len() != expected_size {
            return Err(ArchiveError::Integrity(
                "artifact payload size does not match PostgreSQL ledger",
            ));
        }

        writer.write_all(&[ENTRY_FILE])?;
        write_u16_str(writer, &rec.reservation_id)?;
        write_u16_str(writer, &rec.revision_id)?;
        write_u16_str(writer, &rec.state)?;
        writer.write_all(&rec.content_digest)?;
        writer.write_all(&expected_size.to_be_bytes())?;

        let mut hasher = Sha256::new();
        let mut copied: u64 = 0;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            writer.write_all(&buf[..n])?;
            copied = copied
                .checked_add(n as u64)
                .ok_or(ArchiveError::Integrity("artifact byte count overflow"))?;
        }
        let computed: [u8; 32] = hasher.finalize().into();
        if copied != expected_size || computed != rec.content_digest {
            return Err(ArchiveError::Integrity(
                "artifact payload SHA-256 or byte count failed verification during backup capture",
            ));
        }
        total_bytes = total_bytes
            .checked_add(copied)
            .ok_or(ArchiveError::Integrity("total artifact bytes overflow"))?;
    }

    // Verify no stray files exist in `revisions/`.
    for entry in at::Dir::read_from(&revisions_dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| ArchiveError::Integrity("non-UTF-8 entry in revisions directory"))?;
        if matches!(name, "." | ".." | VOLUME_SENTINEL) {
            continue;
        }
        if !expected_names.contains(name) {
            return Err(ArchiveError::Integrity(
                "unexpected unmanaged file in artifact revisions directory",
            ));
        }
    }

    writer.write_all(&[ENTRY_END])?;
    writer.flush()?;
    Ok(ArtifactArchiveSummary {
        volume_id,
        revision_count: sorted.len() as u64,
        payload_bytes: total_bytes,
    })
}

/// Unpack a decrypted `OMART01` stream into `artifacts_dir` (`0700` dirs, `0600` files),
/// recreating `.openmettle-volume-id` sentinels and every verified `revisions/<reservation_id>`
/// file so `openmettle-admin storage rebind` and `restore replay` can consume it directly.
pub fn unpack_artifact_archive(
    reader: &mut dyn Read,
    artifacts_dir: &Path,
) -> Result<ArtifactArchiveSummary, ArchiveError> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != ARTIFACT_ARCHIVE_MAGIC {
        return Err(ArchiveError::Integrity(
            "invalid OMART01 artifact archive magic",
        ));
    }

    let mut has_vol = [0u8; 1];
    reader.read_exact(&mut has_vol)?;
    let volume_id = match has_vol[0] {
        0 => None,
        1 => {
            let vid = read_u16_str(reader, 64)?;
            runs::uuid(&vid)
                .map_err(|_| ArchiveError::Integrity("invalid volume UUID in archive"))?;
            Some(vid)
        }
        _ => return Err(ArchiveError::Integrity("invalid OMART01 volume flag")),
    };

    create_dir_0700(artifacts_dir)?;
    let staging_dir = artifacts_dir.join("staging");
    let revisions_dir = artifacts_dir.join("revisions");
    create_dir_0700(&staging_dir)?;
    create_dir_0700(&revisions_dir)?;

    if let Some(vid) = &volume_id {
        for (dir, role) in [
            (artifacts_dir, "root"),
            (staging_dir.as_path(), "staging"),
            (revisions_dir.as_path(), "revisions"),
        ] {
            write_file_0600(
                &dir.join(VOLUME_SENTINEL),
                format!("{vid}:{role}\n").as_bytes(),
            )?;
        }
    }

    let mut seen_names = BTreeSet::new();
    let mut buf = vec![0u8; COPY_BUF_BYTES];
    let mut revision_count: u64 = 0;
    let mut payload_bytes: u64 = 0;

    loop {
        let mut kind = [0u8; 1];
        reader.read_exact(&mut kind)?;
        match kind[0] {
            ENTRY_END => {
                let mut trailing = [0u8; 1];
                if reader.read(&mut trailing)? != 0 {
                    return Err(ArchiveError::Integrity(
                        "unexpected trailing bytes in OMART01 archive",
                    ));
                }
                break;
            }
            ENTRY_FILE => {
                let reservation_id = read_u16_str(reader, 64)?;
                let revision_id = read_u16_str(reader, 64)?;
                let state = read_u16_str(reader, 32)?;
                runs::uuid(&reservation_id)
                    .map_err(|_| ArchiveError::Integrity("invalid reservation UUID in archive"))?;
                runs::uuid(&revision_id)
                    .map_err(|_| ArchiveError::Integrity("invalid revision UUID in archive"))?;
                if !matches!(state.as_str(), "active" | "retained" | "purging") {
                    return Err(ArchiveError::Integrity("invalid revision state in archive"));
                }
                if !seen_names.insert(reservation_id.clone()) {
                    return Err(ArchiveError::Integrity(
                        "duplicate reservation entry in OMART01 archive",
                    ));
                }
                let mut expected_sha = [0u8; 32];
                reader.read_exact(&mut expected_sha)?;
                let mut size_buf = [0u8; 8];
                reader.read_exact(&mut size_buf)?;
                let size_bytes = u64::from_be_bytes(size_buf);

                let dest_path = revisions_dir.join(&reservation_id);
                let mut out = open_new_file_0600(&dest_path)?;
                let mut hasher = Sha256::new();
                let mut remaining = size_bytes;
                while remaining > 0 {
                    let want = (remaining as usize).min(buf.len());
                    reader.read_exact(&mut buf[..want])?;
                    hasher.update(&buf[..want]);
                    out.write_all(&buf[..want])?;
                    remaining -= want as u64;
                }
                out.sync_all()?;
                let computed: [u8; 32] = hasher.finalize().into();
                if computed != expected_sha {
                    return Err(ArchiveError::Integrity(
                        "unpacked artifact payload failed SHA-256 verification",
                    ));
                }
                revision_count += 1;
                payload_bytes = payload_bytes
                    .checked_add(size_bytes)
                    .ok_or(ArchiveError::Integrity("unpacked artifact byte overflow"))?;
            }
            _ => return Err(ArchiveError::Integrity("unknown OMART01 entry tag")),
        }
    }

    fsync_dir(&revisions_dir)?;
    fsync_dir(&staging_dir)?;
    fsync_dir(artifacts_dir)?;

    Ok(ArtifactArchiveSummary {
        volume_id,
        revision_count,
        payload_bytes,
    })
}

fn write_u16_str(writer: &mut dyn Write, s: &str) -> Result<(), ArchiveError> {
    let len =
        u16::try_from(s.len()).map_err(|_| ArchiveError::Invalid("archive field too long"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(s.as_bytes())?;
    Ok(())
}

fn read_u16_str(reader: &mut dyn Read, max_len: usize) -> Result<String, ArchiveError> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max_len {
        return Err(ArchiveError::Integrity("invalid archive string length"));
    }
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| ArchiveError::Integrity("non-UTF-8 archive field"))
}

pub(crate) fn create_dir_0700(path: &Path) -> Result<(), ArchiveError> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn open_new_file_0600(path: &Path) -> Result<fs::File, ArchiveError> {
    let parent = path
        .parent()
        .ok_or(ArchiveError::Invalid("file path missing parent"))?;
    let name = path
        .file_name()
        .ok_or(ArchiveError::Invalid("file path missing file name"))?;
    let dir = open_dir_nofollow(at::CWD, parent)?;
    let fd = at::openat(
        &dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    Ok(fs::File::from(fd))
}

pub(crate) fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<(), ArchiveError> {
    let mut f = open_new_file_0600(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Open an existing regular file read-only without following symlinks and `fsync` its data/inode.
pub(crate) fn fsync_regular_file_nofollow(path: &Path) -> Result<(), ArchiveError> {
    let file = open_regular_nofollow(path)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn fsync_dir(path: &Path) -> Result<(), ArchiveError> {
    let dir = open_dir_nofollow(at::CWD, path)?;
    at::fsync(&dir)?;
    Ok(())
}

// --- destination & non-secret config-file hygiene ---------------------------------------------

fn paths_overlap(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

fn is_inside_git_workspace(path: &Path) -> bool {
    let mut cur = Some(path);
    while let Some(dir) = cur {
        if dir.join(".git").exists() {
            return true;
        }
        cur = dir.parent();
    }
    false
}

fn is_temp_location(canon: &Path) -> bool {
    let mut forbidden = vec![
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/private/var/tmp"),
    ];
    if let Ok(tmpdir) = std::env::var("TMPDIR")
        && !tmpdir.is_empty()
    {
        forbidden.push(PathBuf::from(&tmpdir));
        if let Ok(c) = fs::canonicalize(&tmpdir) {
            forbidden.push(c);
        }
    }
    forbidden.into_iter().any(|t| {
        let tc = fs::canonicalize(&t).unwrap_or(t);
        canon == tc || canon.starts_with(&tc)
    })
}

/// Validate destination root isolation (off-workstation mount hygiene, distinct from
/// `ARTIFACTS_DIR` and key directories, optional separate mount device check).
pub fn validate_destination_root(
    dest_root: &Path,
    artifact_root: Option<&Path>,
    keyring_paths: &KeyRingPaths,
    require_separate_device: bool,
    allow_local_test_paths: bool,
) -> Result<PathBuf, ArchiveError> {
    if !dest_root.is_absolute() {
        return Err(ArchiveError::Invalid("--destination-root must be absolute"));
    }
    let sym = fs::symlink_metadata(dest_root)
        .map_err(|_| ArchiveError::Invalid("--destination-root does not exist"))?;
    if sym.file_type().is_symlink() || !sym.is_dir() {
        return Err(ArchiveError::Invalid(
            "--destination-root must be an existing non-symlink directory",
        ));
    }
    let dest_canon = fs::canonicalize(dest_root)
        .map_err(|_| ArchiveError::Invalid("--destination-root could not be canonicalized"))?;
    let dest_meta = fs::metadata(&dest_canon)?;

    if !allow_local_test_paths {
        if is_temp_location(&dest_canon) {
            return Err(ArchiveError::Invalid(
                "--destination-root must not lie under TMPDIR, /tmp, or /var/tmp",
            ));
        }
        if is_inside_git_workspace(&dest_canon) {
            return Err(ArchiveError::Invalid(
                "--destination-root must not lie inside a git workspace",
            ));
        }
    }

    if let Some(art) = artifact_root {
        let art_canon = fs::canonicalize(art)
            .map_err(|_| ArchiveError::Invalid("--artifact-root could not be canonicalized"))?;
        let art_meta = fs::metadata(&art_canon)?;
        if paths_overlap(&dest_canon, &art_canon)
            || (dest_meta.dev(), dest_meta.ino()) == (art_meta.dev(), art_meta.ino())
        {
            return Err(ArchiveError::Invalid(
                "--destination-root must be distinct from --artifact-root",
            ));
        }
        if require_separate_device && dest_meta.dev() == art_meta.dev() {
            return Err(ArchiveError::Invalid(
                "--destination-root must reside on a separate storage device from --artifact-root",
            ));
        }
    } else if require_separate_device {
        let root_meta = fs::metadata("/")?;
        if dest_meta.dev() == root_meta.dev() {
            return Err(ArchiveError::Invalid(
                "--destination-root must reside on a separate storage device from /",
            ));
        }
    }

    // Refuse overlap with backup keyring config or key files (and enforce separate device when
    // requested so DB-only captures and individually mounted key files fail closed).
    for key_path in keyring_paths
        .config_path
        .iter()
        .chain(keyring_paths.key_files.iter())
    {
        let kc = fs::canonicalize(key_path)
            .map_err(|_| ArchiveError::Invalid("backup key path could not be canonicalized"))?;
        let kdir = kc.parent().ok_or(ArchiveError::Invalid(
            "backup key path has no parent directory",
        ))?;
        if paths_overlap(&dest_canon, kdir) {
            return Err(ArchiveError::Invalid(
                "--destination-root must not overlap backup key custody directory",
            ));
        }
        if require_separate_device {
            let kmeta = fs::metadata(kdir).map_err(|_| {
                ArchiveError::Invalid("backup key custody directory metadata unreadable")
            })?;
            if dest_meta.dev() == kmeta.dev() {
                return Err(ArchiveError::Invalid(
                    "--destination-root must reside on a separate storage device from backup key custody directory",
                ));
            }
        }
    }
    if require_separate_device
        && keyring_paths
            .protected_inodes
            .iter()
            .any(|&(dev, _)| dev == dest_meta.dev())
    {
        return Err(ArchiveError::Invalid(
            "--destination-root must reside on a separate storage device from backup key files",
        ));
    }

    Ok(dest_canon)
}

/// Validated non-secret config entry bundled into `config.json.enc`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundledConfigFile {
    pub name: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub content_utf8: String,
}

fn valid_config_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && !name.eq_ignore_ascii_case("vault-key-inventory.json")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn contains_forbidden_secret_material(text: &str) -> bool {
    if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
        return true;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(text)
        && json_looks_like_secret_material(&val)
    {
        return true;
    }
    false
}

fn json_looks_like_secret_material(val: &serde_json::Value) -> bool {
    match val {
        serde_json::Value::Object(map) => {
            // Refuse vault/backup keyring manifests or raw key/token fields.
            if map.contains_key("active_key_id") && map.contains_key("keys") {
                return true;
            }
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "master_key"
                        | "backup_key"
                        | "vault_key"
                        | "private_key"
                        | "secret_key"
                        | "access_token"
                        | "refresh_token"
                        | "client_secret"
                        | "database_password"
                        | "password"
                ) {
                    return true;
                }
                if json_looks_like_secret_material(v) {
                    return true;
                }
            }
            false
        }
        serde_json::Value::Array(items) => items.iter().any(json_looks_like_secret_material),
        _ => false,
    }
}

/// Protected backup and vault key custody identities (both `(dev, ino)` pairs and raw/canonical
/// paths) used to refuse bundling key material into `--config-file`, `--neo4j-dump`, or
/// `--chroma-archive`, including across atomic `rename` key rotations.
#[derive(Clone, Debug, Default)]
pub(crate) struct ProtectedKeyCustody {
    pub(crate) inodes: BTreeSet<(u64, u64)>,
    pub(crate) paths: BTreeSet<PathBuf>,
}

impl ProtectedKeyCustody {
    fn insert_path(&mut self, path: &Path) {
        self.paths.insert(path.to_path_buf());
        if let Ok(canon) = fs::canonicalize(path) {
            self.paths.insert(canon);
        }
    }

    pub(crate) fn matches(&self, path: &Path, dev_ino: (u64, u64)) -> bool {
        if self.inodes.contains(&dev_ino) || self.paths.contains(path) {
            return true;
        }
        fs::canonicalize(path)
            .ok()
            .is_some_and(|canon| self.paths.contains(&canon))
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.inodes.extend(other.inodes);
        self.paths.extend(other.paths);
    }
}

fn collect_keyring_config_custody(
    cfg_path: &Path,
    unreadable_cfg: &'static str,
    malformed_cfg: &'static str,
    malformed_entry: &'static str,
    unreadable_key: &'static str,
    protected: &mut ProtectedKeyCustody,
) -> Result<(), ArchiveError> {
    protected.insert_path(cfg_path);
    let ino = file_dev_ino(cfg_path).ok_or(ArchiveError::Invalid(unreadable_cfg))?;
    protected.inodes.insert(ino);
    let file = fs::File::open(cfg_path).map_err(|_| ArchiveError::Invalid(unreadable_cfg))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ArchiveError::Invalid(unreadable_cfg))?;
    if bytes.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ArchiveError::Invalid(malformed_cfg));
    }
    let val: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ArchiveError::Invalid(malformed_cfg))?;
    let keys = val
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or(ArchiveError::Invalid(malformed_cfg))?;
    for item in keys {
        let key_path = item
            .get("file")
            .and_then(serde_json::Value::as_str)
            .ok_or(ArchiveError::Invalid(malformed_entry))?;
        let kp = Path::new(key_path);
        protected.insert_path(kp);
        let key_ino = file_dev_ino(kp).ok_or(ArchiveError::Invalid(unreadable_key))?;
        protected.inodes.insert(key_ino);
    }
    Ok(())
}

/// Collect every `(dev, ino)` and path belonging to the active backup keyring (both originally
/// loaded inodes and current on-disk paths/inodes so atomic post-load `rename` rotations are also
/// blocked) and any configured vault keyring (`OPENMETTLE_{API,WORKER,ADMIN}_VAULT_KEYS_CONFIG`,
/// `VAULT_KEYS_CONFIG`). Fails closed whenever a configured backup or vault keyring or any
/// referenced key file is unreadable or malformed.
pub(crate) fn collect_protected_key_custody(
    keyring_paths: &KeyRingPaths,
) -> Result<ProtectedKeyCustody, ArchiveError> {
    let mut protected = ProtectedKeyCustody {
        inodes: keyring_paths.protected_inodes.clone(),
        paths: BTreeSet::new(),
    };
    if let Some(cfg_path) = &keyring_paths.config_path {
        collect_keyring_config_custody(
            cfg_path,
            "configured backup keyring is unreadable; refusing to bundle external files",
            "configured backup keyring is malformed; refusing to bundle external files",
            "configured backup keyring entry is malformed; refusing to bundle external files",
            "configured backup key file is unreadable; refusing to bundle external files",
            &mut protected,
        )?;
    }
    for key_file in &keyring_paths.key_files {
        protected.insert_path(key_file);
        let key_ino = file_dev_ino(key_file).ok_or(ArchiveError::Invalid(
            "configured backup key file is unreadable; refusing to bundle external files",
        ))?;
        protected.inodes.insert(key_ino);
    }
    for var in [
        "OPENMETTLE_API_VAULT_KEYS_CONFIG",
        "OPENMETTLE_WORKER_VAULT_KEYS_CONFIG",
        "OPENMETTLE_ADMIN_VAULT_KEYS_CONFIG",
        "VAULT_KEYS_CONFIG",
    ] {
        let Ok(raw) = std::env::var(var) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        collect_keyring_config_custody(
            Path::new(&raw),
            "configured vault keyring is unreadable; refusing to bundle external files",
            "configured vault keyring is malformed; refusing to bundle external files",
            "configured vault keyring entry is malformed; refusing to bundle external files",
            "configured vault key file is unreadable; refusing to bundle external files",
            &mut protected,
        )?;
    }
    Ok(protected)
}

#[cfg(test)]
pub(crate) fn collect_protected_key_inodes(
    keyring_paths: &KeyRingPaths,
) -> Result<BTreeSet<(u64, u64)>, ArchiveError> {
    Ok(collect_protected_key_custody(keyring_paths)?.inodes)
}

/// Validated, open `O_NOFOLLOW` descriptor for a `--config-file NAME=PATH` candidate whose bytes
/// have not yet been read. Separating open from read lets callers perform one shared post-open
/// key-custody scan across every open external archive and config descriptor before consuming any
/// file contents.
pub(crate) struct OpenedConfigFile {
    name: String,
    path: PathBuf,
    file: fs::File,
    len: u64,
    perm: u32,
    dev_ino: (u64, u64),
}

impl OpenedConfigFile {
    pub(crate) fn verify_not_protected(
        &self,
        custody: &ProtectedKeyCustody,
    ) -> Result<(), ArchiveError> {
        if custody.matches(&self.path, self.dev_ino) {
            return Err(ArchiveError::Invalid(
                "--config-file refuses vault or backup key files",
            ));
        }
        Ok(())
    }
}

/// Phase 1 of `--config-file` loading: validate names/paths, open every candidate with
/// `O_NOFOLLOW`, verify regular-file size bounds, and check against the pre-open key custody set
/// without reading any file bytes.
pub(crate) fn open_non_secret_config_files(
    specs: &[(String, PathBuf)],
    protected: &ProtectedKeyCustody,
) -> Result<Vec<OpenedConfigFile>, ArchiveError> {
    let mut seen_names = BTreeSet::new();
    let mut opened = Vec::with_capacity(specs.len());
    for (name, path) in specs {
        if !valid_config_name(name) || !seen_names.insert(name.to_ascii_lowercase()) {
            return Err(ArchiveError::Invalid(
                "invalid, reserved, or duplicate --config-file name",
            ));
        }
        if !path.is_absolute() {
            return Err(ArchiveError::Invalid("--config-file path must be absolute"));
        }
        let file = open_regular_nofollow(path).map_err(|_| {
            ArchiveError::Invalid("--config-file must be an existing non-symlink regular file")
        })?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > MAX_CONFIG_FILE_BYTES as u64 {
            return Err(ArchiveError::Invalid(
                "--config-file must be a regular file <= 1 MiB",
            ));
        }
        let entry = OpenedConfigFile {
            name: name.clone(),
            path: path.clone(),
            file,
            len: meta.len(),
            perm: meta.permissions().mode() & 0o777,
            dev_ino: (meta.dev(), meta.ino()),
        };
        entry.verify_not_protected(protected)?;
        opened.push(entry);
    }
    Ok(opened)
}

/// Phase 2 of `--config-file` loading: read and validate UTF-8 and non-secret content rules from
/// descriptors that have already passed the post-open key-custody scan.
pub(crate) fn read_opened_config_files(
    opened: Vec<OpenedConfigFile>,
) -> Result<Vec<BundledConfigFile>, ArchiveError> {
    let mut out = Vec::with_capacity(opened.len());
    for entry in opened {
        let mut bytes = Vec::with_capacity((entry.len as usize).min(MAX_CONFIG_FILE_BYTES) + 1);
        entry
            .file
            .take(MAX_CONFIG_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CONFIG_FILE_BYTES {
            return Err(ArchiveError::Invalid("--config-file exceeds 1 MiB"));
        }
        // Refuse 32-byte raw binary key files or owner-only binary key files.
        let text = String::from_utf8(bytes).map_err(|_| {
            ArchiveError::Invalid("--config-file must be UTF-8 non-secret configuration")
        })?;
        if contains_forbidden_secret_material(&text) {
            return Err(ArchiveError::Invalid(
                "--config-file appears to contain secret or key material",
            ));
        }
        if matches!(entry.perm, 0o400 | 0o600) && text.len() == 32 && !text.contains('\n') {
            return Err(ArchiveError::Invalid(
                "--config-file refuses 32-byte owner-only key-like files",
            ));
        }
        let sha256 = crate::authz::projects::hex(&Sha256::digest(text.as_bytes()));
        out.push(BundledConfigFile {
            name: entry.name,
            sha256,
            size_bytes: text.len() as u64,
            content_utf8: text,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Load and validate non-secret `--config-file NAME=PATH` entries using `O_NOFOLLOW` descriptor
/// reads, refusing backup/vault key files (checked both before and after opening all candidate
/// descriptors so atomic `rename` rotations cannot race past custody checks), reserved generated
/// names, private keys, and JSON objects holding vault/backup key material. Fails closed whenever
/// a configured backup or vault keyring cannot be read or parsed.
pub fn load_non_secret_config_files(
    specs: &[(String, PathBuf)],
    keyring_paths: &KeyRingPaths,
) -> Result<Vec<BundledConfigFile>, ArchiveError> {
    let mut protected = collect_protected_key_custody(keyring_paths)?;
    let opened = open_non_secret_config_files(specs, &protected)?;
    if !opened.is_empty() {
        protected.extend(collect_protected_key_custody(keyring_paths)?);
        for entry in &opened {
            entry.verify_not_protected(&protected)?;
        }
    }
    read_opened_config_files(opened)
}

// --- Unencrypted non-secret routing header (`backup-meta.json`) & GFS retention ---------------

/// Unencrypted non-secret routing header stored beside encrypted `.enc` files.
/// `backup prune` still cryptographically verifies `manifest.json.enc` and component `.enc`
/// digests before trusting any set to supersede older retained backups.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupMeta {
    pub format: String,
    pub installation_id: String,
    pub backup_run_id: String,
    pub completed_at: String,
    pub destination_domain: String,
    pub encryption_key_id: String,
    pub manifest_ciphertext_sha256: String,
    pub bundle_digest: String,
    pub state: String,
}

/// Grandfather-Father-Son retention counts (`7 daily, 4 weekly, 3 monthly` default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GfsPolicy {
    pub keep_daily: usize,
    pub keep_weekly: usize,
    pub keep_monthly: usize,
}

impl Default for GfsPolicy {
    fn default() -> Self {
        Self {
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 3,
        }
    }
}

impl GfsPolicy {
    pub fn validate(self) -> Result<(), ArchiveError> {
        if self.keep_daily == 0 || self.keep_weekly == 0 || self.keep_monthly == 0 {
            return Err(ArchiveError::Invalid(
                "GFS retention counts must each be at least 1",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSetCandidate {
    pub dir_name: String,
    pub installation_id: String,
    pub destination_domain: String,
    pub backup_run_id: String,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruneReport {
    pub kept: Vec<String>,
    pub pruned: Vec<String>,
    pub skipped_unverified: Vec<String>,
}

/// Deterministic GFS selector over verified complete backup sets, scoped independently per
/// `(installation_id, destination_domain)` so installations sharing a destination root never
/// prune each other's backups. Within each scope, always keeps the newest set unconditionally,
/// plus the newest set from each of the most recent `keep_daily` distinct UTC dates,
/// `keep_weekly` distinct ISO weeks, and `keep_monthly` distinct calendar months.
pub fn select_gfs_retention(
    candidates: &[BackupSetCandidate],
    policy: GfsPolicy,
) -> Result<(BTreeSet<String>, Vec<String>), ArchiveError> {
    policy.validate()?;
    let mut by_scope: BTreeMap<(&str, &str), Vec<&BackupSetCandidate>> = BTreeMap::new();
    for c in candidates {
        by_scope
            .entry((c.installation_id.as_str(), c.destination_domain.as_str()))
            .or_default()
            .push(c);
    }

    let mut kept = BTreeSet::new();
    let mut pruned = Vec::new();
    for mut group in by_scope.into_values() {
        group.sort_by(|a, b| {
            b.completed_at
                .cmp(&a.completed_at)
                .then_with(|| b.backup_run_id.cmp(&a.backup_run_id))
                .then_with(|| b.dir_name.cmp(&a.dir_name))
        });

        let mut daily: BTreeMap<NaiveDate, &str> = BTreeMap::new();
        let mut weekly: BTreeMap<(i32, u32), &str> = BTreeMap::new();
        let mut monthly: BTreeMap<(i32, u32), &str> = BTreeMap::new();
        let mut group_kept = BTreeSet::new();

        for (idx, c) in group.iter().enumerate() {
            if idx == 0 {
                group_kept.insert(c.dir_name.clone());
            }
            let date = c.completed_at.date_naive();
            if daily.len() < policy.keep_daily && !daily.contains_key(&date) {
                daily.insert(date, &c.dir_name);
                group_kept.insert(c.dir_name.clone());
            }
            let iso = date.iso_week();
            let wk = (iso.year(), iso.week());
            if weekly.len() < policy.keep_weekly && !weekly.contains_key(&wk) {
                weekly.insert(wk, &c.dir_name);
                group_kept.insert(c.dir_name.clone());
            }
            let mo = (date.year(), date.month());
            if monthly.len() < policy.keep_monthly && !monthly.contains_key(&mo) {
                monthly.insert(mo, &c.dir_name);
                group_kept.insert(c.dir_name.clone());
            }
        }

        for c in &group {
            if !group_kept.contains(&c.dir_name) {
                pruned.push(c.dir_name.clone());
            }
        }
        kept.extend(group_kept);
    }
    pruned.sort();
    Ok((kept, pruned))
}

/// Scan `dest_root` for `backup-*` sets, require cryptographic & structural verification via
/// `verify_dir` before any set can enter GFS bucket selection, scope optionally to one
/// `(installation_id, destination_domain)`, and remove only verified expired sets unless
/// `dry_run`. Any `backup-*` directory failing verification is excluded from GFS selection,
/// reported in `skipped_unverified`, and never deleted.
pub fn prune_destination_with_verifier(
    dest_root: &Path,
    policy: GfsPolicy,
    scope_filter: Option<(&str, &str)>,
    dry_run: bool,
    verify_dir: impl Fn(&Path, &BackupMeta) -> bool,
) -> Result<PruneReport, ArchiveError> {
    policy.validate()?;
    if !dest_root.is_absolute() || !dest_root.is_dir() {
        return Err(ArchiveError::Invalid(
            "--destination-root must be an existing absolute directory",
        ));
    }

    let mut candidates = Vec::new();
    let mut skipped_unverified = Vec::new();
    for entry in fs::read_dir(dest_root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with("backup-") {
            continue;
        }
        let dir_path = entry.path();
        let meta_path = dir_path.join("backup-meta.json");
        let Ok(meta_bytes) = read_regular_bounded_nofollow(&meta_path, MAX_BACKUP_META_BYTES)
        else {
            if matches!(
                fs::symlink_metadata(&dir_path),
                Err(ref err) if err.kind() == io::ErrorKind::NotFound
            ) {
                continue;
            }
            skipped_unverified.push(name);
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<BackupMeta>(&meta_bytes) else {
            skipped_unverified.push(name);
            continue;
        };
        if meta.state != "complete"
            || runs::uuid(&meta.backup_run_id).is_err()
            || runs::uuid(&meta.installation_id).is_err()
            || !name.ends_with(&format!("-{}", meta.backup_run_id))
        {
            skipped_unverified.push(name);
            continue;
        }
        let Ok(completed_at) = DateTime::parse_from_rfc3339(&meta.completed_at) else {
            skipped_unverified.push(name);
            continue;
        };
        if let Some((want_inst, want_dom)) = scope_filter
            && (
                meta.installation_id.as_str(),
                meta.destination_domain.as_str(),
            ) != (want_inst, want_dom)
        {
            continue;
        }
        if !verify_dir(&dir_path, &meta) {
            if matches!(
                fs::symlink_metadata(&dir_path),
                Err(ref err) if err.kind() == io::ErrorKind::NotFound
            ) {
                continue;
            }
            skipped_unverified.push(name);
            continue;
        }
        candidates.push(BackupSetCandidate {
            dir_name: name,
            installation_id: meta.installation_id,
            destination_domain: meta.destination_domain,
            backup_run_id: meta.backup_run_id,
            completed_at: completed_at.with_timezone(&Utc),
        });
    }

    let (kept_set, pruned) = select_gfs_retention(&candidates, policy)?;
    if !dry_run {
        for dir_name in &pruned {
            let target = dest_root.join(dir_name);
            for attempt in 0..8 {
                match fs::remove_dir_all(&target) {
                    Ok(()) => break,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        if !target.exists() {
                            break;
                        }
                        if attempt == 7 {
                            return Err(err.into());
                        }
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }
        if !pruned.is_empty() {
            fsync_dir(dest_root)?;
        }
    }

    let mut kept: Vec<String> = kept_set.into_iter().collect();
    kept.sort();
    skipped_unverified.sort();
    Ok(PruneReport {
        kept,
        pruned,
        skipped_unverified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const INST_A: &str = "11111111-1111-4111-8111-111111111111";
    const INST_B: &str = "22222222-2222-4222-8222-222222222222";

    fn cand_for(inst: &str, name: &str, y: i32, m: u32, d: u32, h: u32) -> BackupSetCandidate {
        BackupSetCandidate {
            dir_name: name.to_owned(),
            installation_id: inst.to_owned(),
            destination_domain: "offhost-test".to_owned(),
            backup_run_id: format!(
                "00000000-0000-4000-8000-{:012}",
                y as u64 * 10000 + m as u64 * 100 + d as u64 + h as u64 * 1000000
            ),
            completed_at: Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap(),
        }
    }

    fn cand(name: &str, y: i32, m: u32, d: u32, h: u32) -> BackupSetCandidate {
        cand_for(INST_A, name, y, m, d, h)
    }

    #[test]
    fn gfs_retention_keeps_7_daily_4_weekly_3_monthly_and_isolates_installations() {
        // Build 120 consecutive daily backups from 2026-08-01 through 2026-11-28.
        let start = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();
        let mut all = Vec::new();
        for offset in 0..120 {
            let date = start + chrono::Duration::days(offset);
            all.push(cand(
                &format!("backup-{}", date.format("%Y%m%d")),
                date.year(),
                date.month(),
                date.day(),
                2,
            ));
        }
        // Add a second backup on the latest day; only the newer one occupies the daily slot.
        let latest = start + chrono::Duration::days(119);
        all.push(cand(
            &format!("backup-{}-later", latest.format("%Y%m%d")),
            latest.year(),
            latest.month(),
            latest.day(),
            14,
        ));
        // Add an older backup from a DIFFERENT installation_id: must be retained independently.
        all.push(cand_for(INST_B, "backup-inst-b-20260701", 2026, 7, 1, 2));

        let (kept, pruned) = select_gfs_retention(&all, GfsPolicy::default()).unwrap();
        assert!(kept.contains(&format!("backup-{}-later", latest.format("%Y%m%d"))));
        assert!(!kept.contains(&format!("backup-{}", latest.format("%Y%m%d"))));
        assert!(kept.contains("backup-inst-b-20260701"));
        assert!(kept.len() >= 11 && kept.len() <= 15, "kept={kept:?}");
        assert_eq!(kept.len() + pruned.len(), all.len());
        assert!(kept.contains("backup-20261031"), "kept={kept:?}");
        assert!(kept.contains("backup-20260930"), "kept={kept:?}");
        assert!(!kept.contains("backup-20260831"), "kept={kept:?}");
    }

    #[test]
    fn destination_validation_rejects_tmp_and_git_workspace_when_strict() {
        let cwd = std::env::current_dir().unwrap();
        assert!(
            validate_destination_root(&cwd, None, &KeyRingPaths::default(), false, false).is_err()
        );
        let tmp = std::env::temp_dir();
        assert!(
            validate_destination_root(&tmp, None, &KeyRingPaths::default(), false, false).is_err()
        );
    }

    #[test]
    fn config_loader_refuses_secret_json_reserved_name_and_private_keys() {
        let dir = std::env::temp_dir().join(format!("om-backup-cfg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let good = dir.join("catalog.json");
        fs::write(&good, r#"{"version":1,"models":["example"]}"#).unwrap();
        let loaded = load_non_secret_config_files(
            &[("catalog.json".into(), good.clone())],
            &KeyRingPaths::default(),
        )
        .unwrap();
        assert_eq!(loaded.len(), 1);

        // Reserved generated unpack filename must be rejected at preflight (case-insensitively).
        assert!(
            load_non_secret_config_files(
                &[("Vault-Key-Inventory.json".into(), good.clone())],
                &KeyRingPaths::default(),
            )
            .is_err()
        );

        let bad_ring = dir.join("keys.json");
        fs::write(
            &bad_ring,
            r#"{"version":1,"active_key_id":"k1","keys":[{"id":"k1","file":"/etc/k"}]}"#,
        )
        .unwrap();
        assert!(
            load_non_secret_config_files(
                &[("keys.json".into(), bad_ring)],
                &KeyRingPaths::default()
            )
            .is_err()
        );

        let bad_pem = dir.join("priv.txt");
        fs::write(
            &bad_pem,
            concat!(
                "-----BEGIN EC ",
                "PRIVATE KEY-----\nfake\n-----END EC ",
                "PRIVATE KEY-----\n"
            ),
        )
        .unwrap();
        assert!(
            load_non_secret_config_files(&[("priv.txt".into(), bad_pem)], &KeyRingPaths::default())
                .is_err()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_skips_fifo_symlink_and_oversized_backup_meta_without_blocking() {
        let dir = std::env::temp_dir().join(format!("om-backup-prune-meta-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let fifo_dir = dir.join("backup-20261126T010000Z-11111111-1111-4111-8111-111111111111");
        fs::create_dir_all(&fifo_dir).unwrap();
        let fifo_path = fifo_dir.join("backup-meta.json");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("mkfifo should be available on unix");
        assert!(status.success(), "mkfifo failed");

        let sym_dir = dir.join("backup-20261126T020000Z-22222222-2222-4222-8222-222222222222");
        fs::create_dir_all(&sym_dir).unwrap();
        let target = dir.join("outside.json");
        fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, sym_dir.join("backup-meta.json")).unwrap();

        let big_dir = dir.join("backup-20261126T030000Z-33333333-3333-4333-8333-333333333333");
        fs::create_dir_all(&big_dir).unwrap();
        fs::write(
            big_dir.join("backup-meta.json"),
            vec![b' '; MAX_BACKUP_META_BYTES + 16],
        )
        .unwrap();

        let started = std::time::Instant::now();
        let report =
            prune_destination_with_verifier(&dir, GfsPolicy::default(), None, false, |_, _| true)
                .unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "prune blocked on non-regular backup-meta.json"
        );
        assert_eq!(report.skipped_unverified.len(), 3, "{report:?}");
        assert!(report.kept.is_empty());
        assert!(report.pruned.is_empty());
        assert!(fifo_dir.exists() && sym_dir.exists() && big_dir.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn destination_validation_fails_closed_on_missing_key_path_and_same_device_protected_inode() {
        let dir = std::env::temp_dir().join(format!("om-backup-dest-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dest_meta = fs::metadata(&dir).unwrap();

        // Missing/un-canonicalizable key path must fail closed rather than silently skipping.
        let missing_ring = KeyRingPaths {
            config_path: Some(dir.join("nonexistent-keyring.json")),
            key_files: Vec::new(),
            protected_inodes: BTreeSet::new(),
        };
        assert!(validate_destination_root(&dir, None, &missing_ring, false, true).is_err());

        // Same-device protected inode (e.g., individually mounted key file) must fail closed when
        // `require_separate_device` is requested.
        let mut protected_inodes = BTreeSet::new();
        protected_inodes.insert((dest_meta.dev(), 999_999));
        let same_dev_ring = KeyRingPaths {
            config_path: None,
            key_files: Vec::new(),
            protected_inodes,
        };
        assert!(validate_destination_root(&dir, None, &same_dev_ring, true, true).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_dir_0700_sets_owner_only_permissions() {
        let base = std::env::temp_dir().join(format!("om-backup-mkdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let target = base.join("restricted");
        create_dir_0700(&target).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected mode 0700, got {:o}", mode);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn prune_tolerates_concurrent_removal_of_expired_backup_directory() {
        let dir = std::env::temp_dir().join(format!("om-backup-prune-race-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let make_set = |name: &str, run_id: &str, completed_at: &str| {
            let bdir = dir.join(name);
            create_dir_0700(&bdir).unwrap();
            let meta = BackupMeta {
                format: "openmettle-backup-meta/v1".to_owned(),
                installation_id: INST_A.to_owned(),
                backup_run_id: run_id.to_owned(),
                completed_at: completed_at.to_owned(),
                destination_domain: "offhost-race".to_owned(),
                encryption_key_id: "k1".to_owned(),
                manifest_ciphertext_sha256: "a".repeat(64),
                bundle_digest: "b".repeat(64),
                state: "complete".to_owned(),
            };
            write_file_0600(
                &bdir.join("backup-meta.json"),
                &serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
            bdir
        };

        let expired_1 = make_set(
            "backup-20261126T010000Z-11111111-1111-4111-8111-111111111111",
            "11111111-1111-4111-8111-111111111111",
            "2026-11-26T01:00:00Z",
        );
        let expired_2 = make_set(
            "backup-20261126T020000Z-22222222-2222-4222-8222-222222222222",
            "22222222-2222-4222-8222-222222222222",
            "2026-11-26T02:00:00Z",
        );
        let kept_newest = make_set(
            "backup-20261126T030000Z-33333333-3333-4333-8333-333333333333",
            "33333333-3333-4333-8333-333333333333",
            "2026-11-26T03:00:00Z",
        );

        // Simulate a concurrent pruner deleting `expired_1` after it was verified and selected,
        // before `prune_destination_with_verifier` runs `remove_dir_all` on it.
        let expired_1_clone = expired_1.clone();
        let report = prune_destination_with_verifier(
            &dir,
            GfsPolicy {
                keep_daily: 1,
                keep_weekly: 1,
                keep_monthly: 1,
            },
            None,
            false,
            move |path, _| {
                if path == expired_1_clone {
                    let _ = fs::remove_dir_all(&expired_1_clone);
                }
                true
            },
        )
        .unwrap();

        assert_eq!(report.kept.len(), 1);
        assert_eq!(report.pruned.len(), 2);
        assert!(kept_newest.is_dir());
        assert!(!expired_1.exists());
        assert!(!expired_2.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn collect_protected_key_inodes_blocks_hardlink_and_atomically_rotated_key_file() {
        use super::super::crypto::BackupKeyRing;

        let dir = std::env::temp_dir().join(format!(
            "om-backup-key-rotate-inodes-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        create_dir_0700(&dir).unwrap();

        let key_path = dir.join("bk1.key");
        let cfg_path = dir.join("backup-keys.json");
        write_file_0600(&key_path, &[0x41u8; 32]).unwrap();
        write_file_0600(
            &cfg_path,
            serde_json::json!({
                "version": 1,
                "active_key_id": "bk1",
                "keys": [{ "id": "bk1", "file": key_path.to_str().unwrap() }]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();

        let ring = BackupKeyRing::load_from_config(&cfg_path).unwrap();

        // Retain a hard link to the original inode, then atomically replace `key_path` with a
        // brand-new inode via `rename`.
        let old_hardlink = dir.join("old-bk1-hardlink.txt");
        fs::hard_link(&key_path, &old_hardlink).unwrap();
        let replacement_tmp = dir.join("bk1.key.new");
        write_file_0600(&replacement_tmp, &[0x42u8; 32]).unwrap();
        fs::rename(&replacement_tmp, &key_path).unwrap();

        let old_ino = file_dev_ino(&old_hardlink).unwrap();
        let new_ino = file_dev_ino(&key_path).unwrap();
        assert_ne!(old_ino, new_ino, "atomic rename must allocate a new inode");

        let protected = collect_protected_key_inodes(ring.paths()).unwrap();
        assert!(
            protected.contains(&old_ino),
            "pre-rotation hardlink inode must stay protected"
        );
        assert!(
            protected.contains(&new_ino),
            "post-rotation key inode must be re-stat'd and protected"
        );
        assert!(
            load_non_secret_config_files(&[("old.txt".into(), old_hardlink)], ring.paths())
                .is_err()
        );
        assert!(
            load_non_secret_config_files(&[("new.txt".into(), key_path.clone())], ring.paths())
                .is_err()
        );

        // Also fail closed if the configured backup keyring config becomes malformed.
        fs::write(&cfg_path, b"{not-json").unwrap();
        assert!(collect_protected_key_inodes(ring.paths()).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_key_custody_matches_direct_path_and_post_open_rotation() {
        use super::super::crypto::BackupKeyRing;

        let dir = std::env::temp_dir().join(format!(
            "om-backup-key-custody-postopen-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        create_dir_0700(&dir).unwrap();

        let key_path = dir.join("bk1.key");
        let cfg_path = dir.join("backup-keys.json");
        write_file_0600(&key_path, &[0x41u8; 32]).unwrap();
        write_file_0600(
            &cfg_path,
            serde_json::json!({
                "version": 1,
                "active_key_id": "bk1",
                "keys": [{ "id": "bk1", "file": key_path.to_str().unwrap() }]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();

        let ring = BackupKeyRing::load_from_config(&cfg_path).unwrap();
        let mut custody = collect_protected_key_custody(ring.paths()).unwrap();

        // Direct path match catches configured key & keyring paths regardless of inode.
        assert!(custody.matches(&key_path, (0, 0)));
        assert!(custody.matches(&cfg_path, (0, 0)));

        // Simulate an atomic `rename` rotation occurring AFTER the pre-open custody scan, with a
        // hard link to the brand-new rotated key inode opened before the post-open re-scan.
        let replacement_tmp = dir.join("bk1.key.rotated");
        write_file_0600(&replacement_tmp, &[0x42u8; 32]).unwrap();
        fs::rename(&replacement_tmp, &key_path).unwrap();
        let rotated_hardlink = dir.join("rotated-key-hardlink.bin");
        fs::hard_link(&key_path, &rotated_hardlink).unwrap();

        let new_ino = file_dev_ino(&rotated_hardlink).unwrap();
        assert!(
            !custody.matches(&rotated_hardlink, new_ino),
            "pre-rotation custody alone cannot yet know the post-rotation inode of a hard link"
        );

        // Post-open custody refresh catches the opened hard link before any bytes are consumed.
        custody.extend(collect_protected_key_custody(ring.paths()).unwrap());
        assert!(custody.matches(&rotated_hardlink, new_ino));
        assert!(
            load_non_secret_config_files(&[("leak.txt".into(), rotated_hardlink)], ring.paths())
                .is_err()
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
