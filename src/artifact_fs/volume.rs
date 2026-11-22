//! Directory-relative operations shared by runtime storage and owner adoption.
use super::{REVISIONS, STAGING};
use rustix::{
    fs::{self as at, AtFlags, FileType, Mode, OFlags},
    io::Errno,
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const SENTINEL: &str = ".openmettle-volume-id";
fn dirs() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW
}
fn invalid() -> io::Error {
    io::Error::other("artifact volume identity mismatch")
}

#[derive(Debug)]
pub(super) struct Volume {
    path: PathBuf,
    pub root: File,
    pub staging: File,
    pub revisions: File,
    pub dev: u64,
}

impl Volume {
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid());
        }
        let root = File::from(at::open(path, dirs(), Mode::empty())?);
        let dev = root.metadata()?.dev();
        let directory = |name: &str| -> io::Result<File> {
            if create {
                match at::mkdirat(&root, name, Mode::RWXU) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            let file = File::from(at::openat(&root, name, dirs(), Mode::empty())?);
            if file.metadata()?.dev() != dev {
                return Err(invalid());
            }
            Ok(file)
        };
        let staging = directory(STAGING)?;
        let revisions = directory(REVISIONS)?;
        if staging.metadata()?.ino() == revisions.metadata()?.ino() {
            return Err(invalid());
        }
        if create {
            at::fsync(&root)?;
        }
        Ok(Self {
            path: path.into(),
            root,
            staging,
            revisions,
            dev,
        })
    }
    pub fn recheck(&self) -> io::Result<()> {
        let current = Self::open(&self.path, false)?;
        for (before, after) in [
            (&self.root, &current.root),
            (&self.staging, &current.staging),
            (&self.revisions, &current.revisions),
        ] {
            let a = before.metadata()?;
            let b = after.metadata()?;
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn inode(&self, dir: &File, name: impl AsRef<OsStr>) -> io::Result<Option<u64>> {
        let name = name.as_ref();
        match at::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s)
                if FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
                    && u128::try_from(s.st_dev).ok() == Some(u128::from(self.dev)) =>
            {
                Ok(Some(s.st_ino))
            }
            Ok(_) => Err(invalid()),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn matches(
        &self,
        f: &File,
        dir: &File,
        name: impl AsRef<OsStr>,
        ino: u64,
    ) -> io::Result<()> {
        let name = name.as_ref();
        let m = f.metadata()?;
        if !m.is_file()
            || m.dev() != self.dev
            || m.ino() != ino
            || self.inode(dir, name)? != Some(ino)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn regular(&self, dir: &File, name: impl AsRef<OsStr>, writable: bool) -> io::Result<File> {
        let name = name.as_ref();
        let flags = if writable {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        };
        let f = File::from(at::openat(
            dir,
            name,
            flags | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        self.matches(&f, dir, name, f.metadata()?.ino())?;
        Ok(f)
    }
    pub fn unlink(&self, dir: &File, name: impl AsRef<OsStr>, ino: u64) -> io::Result<()> {
        let name = name.as_ref();
        if self.inode(dir, name)? != Some(ino) {
            return Err(invalid());
        }
        at::unlinkat(dir, name, AtFlags::empty())?;
        Ok(())
    }
    fn sentinel(&self, dir: &File, role: &str) -> io::Result<String> {
        let f = self.regular(dir, SENTINEL, false)?;
        if f.metadata()?.mode() & 0o777 != 0o600 || f.metadata()?.len() > 64 {
            return Err(invalid());
        }
        let mut text = String::new();
        f.take(64).read_to_string(&mut text)?;
        let id = text
            .strip_suffix(&format!(":{role}\n"))
            .ok_or_else(invalid)?;
        crate::runs::uuid(id).map_err(|_| invalid())?;
        Ok(id.to_owned())
    }
    fn entries(&self) -> [(&File, &'static str); 3] {
        [
            (&self.root, "root"),
            (&self.staging, STAGING),
            (&self.revisions, REVISIONS),
        ]
    }
    pub fn verify(&self, id: &str) -> io::Result<()> {
        self.recheck()?;
        for (dir, role) in self.entries() {
            if self.sentinel(dir, role)? != id {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn publish_identity(&self, proposed: &str) -> io::Result<String> {
        crate::runs::uuid(proposed).map_err(|_| invalid())?;
        self.recheck()?;
        let mut winner = match self.inode(&self.root, SENTINEL)? {
            Some(_) => self.sentinel(&self.root, "root")?,
            None => proposed.to_owned(),
        };
        for (dir, role) in self.entries() {
            let tmp = format!("{SENTINEL}.tmp.{}", proposed.replace('-', ""));
            // Fresh proposals are unique per invocation. Publish only fully durable files.
            let mut f = File::from(at::openat(
                dir,
                tmp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )?);
            let result = (|| -> io::Result<()> {
                writeln!(f, "{winner}:{role}")?;
                f.sync_all()?;
                match at::linkat(dir, tmp.as_str(), dir, SENTINEL, AtFlags::empty()) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                Ok(())
            })();
            at::unlinkat(dir, tmp.as_str(), AtFlags::empty())?;
            result?;
            at::fsync(dir)?;
            let observed = self.sentinel(dir, role)?;
            if role == "root" {
                winner = observed;
            } else if observed != winner {
                return Err(invalid());
            }
        }
        self.verify(&winner)?;
        Ok(winner)
    }
    /// Only the owner can call this while it holds the database volume row exclusively.
    pub fn remove_stale_temps(&self) -> io::Result<()> {
        for (dir, _) in self.entries() {
            for entry in at::Dir::read_from(dir)? {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().ok() else {
                    continue;
                };
                let Some(suffix) = name.strip_prefix(".openmettle-volume-id.tmp.") else {
                    continue;
                };
                if suffix.len() != 32 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
                    continue;
                }
                let Some(ino) = self.inode(dir, name)? else {
                    continue;
                };
                let file = self.regular(dir, name, false)?;
                if file
                    .metadata()?
                    .modified()?
                    .elapsed()
                    .is_ok_and(|age| age.as_secs() > 300)
                {
                    self.unlink(dir, name, ino)?;
                    at::fsync(dir)?;
                }
            }
        }
        Ok(())
    }
    pub fn detach_staged(&self, id: &str, ino: u64) -> io::Result<()> {
        let f = self.regular(&self.staging, id, false)?;
        f.try_lock_shared()?;
        self.matches(&f, &self.staging, id, ino)?;
        self.matches(&f, &self.revisions, id, ino)?;
        self.unlink(&self.staging, id, ino)?;
        at::fsync(&self.staging)?;
        Ok(())
    }
}
