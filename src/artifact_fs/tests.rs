//! Filesystem behaviour without PostgreSQL, in per-test temporary directories. The database
//! composition (`ingest` and the reconcilers) is covered by `tests/schema/artifact_fs.rs`.
use super::*;
use crate::auth_config::tests::support::Dir;
use std::os::unix::fs::{PermissionsExt, symlink};

const RESERVATION: &str = "0b0a5d9e-1c1e-4c6a-9a49-3f1d2b7c8e10";

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

/// A store under `dir/root`, removed with `dir`.
fn store(dir: &Dir) -> Store {
    fs::create_dir(dir.path("root")).unwrap();
    Store::open(Path::new(&dir.path("root"))).unwrap()
}

#[test]
fn open_creates_private_subdirectories_and_is_repeatable() {
    let dir = Dir::new();
    let store = store(&dir);
    for sub in [STAGING, REVISIONS] {
        let path = Path::new(&dir.path("root")).join(sub);
        assert!(fs::symlink_metadata(&path).unwrap().is_dir());
        assert_eq!(mode(&path), 0o700);
    }
    store.volume.recheck().unwrap();
    // Existing subdirectories are reused, not replaced.
    fs::write(Path::new(&dir.path("root/revisions")).join("kept"), b"x").unwrap();
    let again = Store::open(Path::new(&dir.path("root"))).unwrap();
    assert!(
        again
            .volume
            .inode(&again.volume.revisions, "kept")
            .unwrap()
            .is_some()
    );
}

#[test]
fn open_refuses_unusable_directories() {
    let dir = Dir::new();
    fs::create_dir(dir.path("real")).unwrap();
    fs::write(dir.path("file"), b"x").unwrap();
    symlink(dir.path("real"), dir.path("link")).unwrap();
    for refused in [
        String::new(),
        "relative/artifacts".into(),
        dir.path("absent"),
        dir.path("file"),
        dir.path("link"),
    ] {
        assert_eq!(
            Store::open(Path::new(&refused)).err(),
            Some(InvalidDirectory),
            "{refused:?}"
        );
    }
    // A symbolic link above the leaf is allowed.
    let above = Path::new(&dir.path("link")).join("nested");
    fs::create_dir(&above).unwrap();
    assert!(Store::open(&above).is_ok());
    // A subdirectory name taken by a file or a symbolic link is refused.
    for (name, sub) in [("with-file", STAGING), ("with-link", REVISIONS)] {
        fs::create_dir(dir.path(name)).unwrap();
        let path = Path::new(&dir.path(name)).join(sub);
        if sub == STAGING {
            fs::write(&path, b"x").unwrap();
        } else {
            symlink(dir.path("real"), &path).unwrap();
        }
        assert_eq!(
            Store::open(Path::new(&dir.path(name))).err(),
            Some(InvalidDirectory)
        );
    }
    // A directory whose subdirectories cannot be created is refused.
    fs::create_dir(dir.path("read-only")).unwrap();
    fs::set_permissions(dir.path("read-only"), fs::Permissions::from_mode(0o500)).unwrap();
    let refused = Store::open(Path::new(&dir.path("read-only")));
    // A privileged user ignores the mode, so the case says nothing there.
    let privileged = fs::write(Path::new(&dir.path("read-only")).join("probe"), b"x").is_ok();
    fs::set_permissions(dir.path("read-only"), fs::Permissions::from_mode(0o700)).unwrap();
    if !privileged {
        assert_eq!(refused.err(), Some(InvalidDirectory));
    }
}

#[tokio::test]
async fn paths_come_only_from_a_canonical_reservation_uuid() {
    let dir = Dir::new();
    let store = store(&dir);
    assert!(store.stage(RESERVATION).await.is_ok());
    for refused in [
        "../0b0a5d9e-1c1e-4c6a-9a49-3f1d2b7c8e1",
        "0B0A5D9E-1C1E-4C6A-9A49-3F1D2B7C8E10",
        "0b0a5d9e-1c1e-4c6a-9a49-3f1d2b7c8e10/",
        "report.pdf",
        "",
    ] {
        assert!(store.stage(refused).await.is_err(), "{refused:?}");
    }
}

#[tokio::test]
async fn staging_is_exclusive_private_and_keeps_abandoned_inode_for_reclamation() {
    let dir = Dir::new();
    let store = store(&dir);
    let mut staged = store.stage(RESERVATION).await.unwrap();
    let path = Path::new(&dir.path("root/staging")).join(RESERVATION);
    assert_eq!(mode(&path), 0o600);
    // A second request under the same reservation never touches the first one's file.
    assert!(matches!(
        store.stage(RESERVATION).await,
        Err(Error::InProgress)
    ));
    staged.write(b"partial".to_vec()).await.unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"partial");
    // An interrupted write leaves the same inode for the fenced reconciler.
    let before = staged.ino;
    {
        let write = staged.write(vec![1; 1 << 20]);
        tokio::pin!(write);
        let _ = futures_poll_once(write.as_mut()).await;
    }
    drop(staged);
    assert_eq!(fs::metadata(path).unwrap().ino(), before);
    assert!(
        fs::read_dir(dir.path("root/revisions"))
            .unwrap()
            .next()
            .is_none()
    );
}

/// Polls `future` once, as a request future that is dropped mid-write would be.
async fn futures_poll_once<F: std::future::Future + Unpin>(future: F) -> Option<F::Output> {
    let mut future = Some(future);
    std::future::poll_fn(|cx| {
        let polled = std::pin::Pin::new(future.as_mut().unwrap()).poll(cx);
        std::task::Poll::Ready(match polled {
            std::task::Poll::Ready(value) => Some(value),
            std::task::Poll::Pending => None,
        })
    })
    .await
}

#[tokio::test]
async fn publish_never_replaces_a_collision_and_preserves_both_links_until_detach() {
    let dir = Dir::new();
    let store = store(&dir);
    // A foreign revision file must survive a publication attempt.
    fs::write(
        Path::new(&dir.path("root/revisions")).join(RESERVATION),
        b"stale",
    )
    .unwrap();
    let mut staged = store.stage(RESERVATION).await.unwrap();
    for chunk in [b"hello ".to_vec(), b"world".to_vec()] {
        staged.write(chunk).await.unwrap();
    }
    staged.sync().await.unwrap();
    assert!(staged.publish().is_err());
    let published = Path::new(&dir.path("root/revisions")).join(RESERVATION);
    assert_eq!(fs::read(&published).unwrap(), b"stale");
    fs::remove_file(&published).unwrap();
    staged.publish().unwrap();
    let ino = staged.ino;
    assert_eq!(fs::metadata(&published).unwrap().ino(), ino);
    assert_eq!(mode(&published), 0o600);
    let cleaner = store
        .volume
        .regular(&store.volume.staging, RESERVATION, true)
        .unwrap();
    assert!(matches!(
        cleaner.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(staged);
    store.volume.detach_staged(RESERVATION, ino).unwrap();
    assert_eq!(fs::read(&published).unwrap(), b"hello world");
}

#[tokio::test]
async fn sink_enforces_the_ceiling_without_a_declared_length() {
    let dir = Dir::new();
    let store = store(&dir);
    let mut sink = Sink {
        hasher: Sha256::new(),
        size: 0,
        max: 10,
        staged: Some(store.stage(RESERVATION).await.unwrap()),
    };
    for _ in 0..10 {
        sink.write(vec![b'a']).await.unwrap();
    }
    assert!(matches!(sink.write(vec![b'a']).await, Err(Error::TooLarge)));
    assert_eq!(sink.size, 10);
    assert_eq!(
        fs::read(Path::new(&dir.path("root/staging")).join(RESERVATION)).unwrap(),
        [b'a'; 10]
    );
    assert_eq!(
        <[u8; 32]>::from(sink.hasher.clone().finalize()),
        <[u8; 32]>::from(Sha256::digest([b'a'; 10]))
    );
    drop(sink);
    assert!(
        Path::new(&dir.path("root/staging"))
            .join(RESERVATION)
            .exists()
    );
}

#[test]
fn errors_are_fixed_text() {
    for error in [
        Error::TooLarge,
        Error::Rejected,
        Error::InProgress,
        Error::Body,
        Error::Io,
        Error::Missing,
        Error::Multipart(multipart::Error::Truncated),
        Error::Storage(runs::Error::Conflict),
    ] {
        assert!(!error.to_string().is_empty());
    }
}

/// Asserts that `fd` is not inherited by a child process.
fn assert_cloexec(fd: impl std::os::fd::AsFd, what: &str) {
    let flags = rustix::io::fcntl_getfd(fd).unwrap();
    assert!(flags.contains(rustix::io::FdFlags::CLOEXEC), "{what}");
}

#[tokio::test]
async fn store_descriptors_are_close_on_exec() {
    let dir = Dir::new();
    let store = store(&dir);
    let v = &store.volume;
    for (fd, what) in [
        (&v.root, "root"),
        (&v.staging, "staging"),
        (&v.revisions, "revisions"),
    ] {
        assert_cloexec(fd, what);
    }
    let staged = store.stage(RESERVATION).await.unwrap();
    assert_cloexec(staged.file.as_ref().unwrap(), "staged payload");
    for writable in [false, true] {
        assert_cloexec(
            v.regular(&v.staging, RESERVATION, writable).unwrap(),
            "regular",
        );
    }
}

/// Kills and reaps the child when the test ends, whatever the outcome.
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn a_child_process_does_not_keep_a_released_store_lock() {
    let dir = Dir::new();
    let store = store(&dir);
    // `Staged` holds a shared `flock` on the payload until it is dropped.
    let staged = store.stage(RESERVATION).await.unwrap();
    let _child = Child(
        std::process::Command::new("sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    drop(staged);
    let v = &store.volume;
    let cleaner = v.regular(&v.staging, RESERVATION, true).unwrap();
    // An inherited descriptor keeps the lock for the child's lifetime. macOS may still hold
    // close-on-exec descriptors for a few milliseconds while the child finishes `exec`.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while let Err(e) = cleaner.try_lock() {
        assert!(std::time::Instant::now() < deadline, "{e:?}");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
