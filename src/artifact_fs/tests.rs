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
    assert_eq!(store.staging, Path::new(&dir.path("root")).join(STAGING));
    // Existing subdirectories are reused, not replaced.
    fs::write(store.revisions.join("kept"), b"x").unwrap();
    let again = Store::open(Path::new(&dir.path("root"))).unwrap();
    assert!(again.revisions.join("kept").exists());
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

#[test]
fn paths_come_only_from_a_canonical_reservation_uuid() {
    let dir = Dir::new();
    let store = store(&dir);
    let (staging, revision) = store.paths(RESERVATION).unwrap();
    assert_eq!(staging, store.staging.join(RESERVATION));
    assert_eq!(revision, store.revisions.join(RESERVATION));
    for refused in [
        "../0b0a5d9e-1c1e-4c6a-9a49-3f1d2b7c8e1",
        "0B0A5D9E-1C1E-4C6A-9A49-3F1D2B7C8E10",
        "0b0a5d9e-1c1e-4c6a-9a49-3f1d2b7c8e10/",
        "report.pdf",
        "",
    ] {
        assert!(store.paths(refused).is_err(), "{refused:?}");
    }
}

#[tokio::test]
async fn staging_is_exclusive_private_and_unlinked_when_abandoned() {
    let dir = Dir::new();
    let store = store(&dir);
    let mut staged = store.stage(RESERVATION).await.unwrap();
    let path = store.staging.join(RESERVATION);
    assert_eq!(mode(&path), 0o600);
    // A second request under the same reservation never touches the first one's file.
    assert!(matches!(
        store.stage(RESERVATION).await,
        Err(Error::InProgress)
    ));
    staged.write(b"partial".to_vec()).await.unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"partial");
    drop(staged);
    assert!(!path.exists());
    // A cancelled write leaves nothing behind either.
    let mut staged = store.stage(RESERVATION).await.unwrap();
    {
        let write = staged.write(vec![1; 1 << 20]);
        tokio::pin!(write);
        let _ = futures_poll_once(write.as_mut()).await;
    }
    drop(staged);
    assert!(!path.exists());
    assert!(fs::read_dir(&store.revisions).unwrap().next().is_none());
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
async fn publish_syncs_and_renames_into_revisions() {
    let dir = Dir::new();
    let store = store(&dir);
    // A stale revision file of the same reservation (crash before settle) is replaced.
    fs::write(store.revisions.join(RESERVATION), b"stale").unwrap();
    let mut staged = store.stage(RESERVATION).await.unwrap();
    for chunk in [b"hello ".to_vec(), b"world".to_vec()] {
        staged.write(chunk).await.unwrap();
    }
    staged.sync().await.unwrap();
    staged.publish().await.unwrap();
    assert!(!store.staging.join(RESERVATION).exists());
    let published = store.revisions.join(RESERVATION);
    assert_eq!(fs::read(&published).unwrap(), b"hello world");
    assert_eq!(mode(&published), 0o600);
    store.remove(RESERVATION).await.unwrap();
    assert!(!published.exists());
    // Removing absent files is not an error.
    store.remove(RESERVATION).await.unwrap();
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
        fs::read(store.staging.join(RESERVATION)).unwrap(),
        [b'a'; 10]
    );
    assert_eq!(
        <[u8; 32]>::from(sink.hasher.clone().finalize()),
        <[u8; 32]>::from(Sha256::digest([b'a'; 10]))
    );
    drop(sink);
    assert!(!store.staging.join(RESERVATION).exists());
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
