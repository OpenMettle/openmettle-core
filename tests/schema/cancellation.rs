//! Isolated PostgreSQL tests. The proxy withholds an observed ReadyForQuery packet after
//! SAVEPOINT/RELEASE/ROLLBACK, so cancellation is at the protocol roundtrip, not a sleep guess.
use super::*;
use std::net::Shutdown;
use std::sync::mpsc;

pub(super) struct ResponseBarrier {
    pub(super) port: u16,
    reached: Option<tokio::sync::oneshot::Receiver<()>>,
    resume: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<std::io::Result<()>>>,
}
impl ResponseBarrier {
    pub(super) fn new(command: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let options = admin_options();
        let destination = (options.get_host().to_owned(), options.get_port());
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (resume, resume_rx) = mpsc::channel();
        let worker = thread::spawn(move || -> std::io::Result<()> {
            let (mut client, _) = listener.accept()?;
            let mut server = TcpStream::connect(destination)?;
            server.set_read_timeout(Some(Duration::from_secs(30)))?;
            let mut upstream_client = client.try_clone()?;
            let mut upstream_server = server.try_clone()?;
            let upstream = thread::spawn(move || {
                let _ = std::io::copy(&mut upstream_client, &mut upstream_server);
                let _ = upstream_server.shutdown(Shutdown::Write);
            });
            let mut reached_tx = Some(reached_tx);
            let mut selected = false;
            let result = (|| {
                loop {
                    let mut header = [0; 5];
                    match server.read_exact(&mut header) {
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                        other => other?,
                    }
                    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
                    if !(4..=1024 * 1024).contains(&length) {
                        return Err(std::io::Error::other("invalid backend frame size"));
                    }
                    let mut body = vec![0; length - 4];
                    server.read_exact(&mut body)?;
                    if header[0] == b'C' && body == command {
                        selected = true;
                    }
                    if header[0] == b'Z'
                        && selected
                        && let Some(sender) = reached_tx.take()
                    {
                        let _ = sender.send(());
                        resume_rx
                            .recv_timeout(Duration::from_secs(15))
                            .map_err(|_| std::io::Error::other("barrier not released"))?;
                    }
                    client.write_all(&header)?;
                    client.write_all(&body)?;
                }
            })();
            let _ = client.shutdown(Shutdown::Both);
            let _ = server.shutdown(Shutdown::Both);
            upstream.join().unwrap();
            result
        });
        Self {
            port,
            reached: Some(reached),
            resume: Some(resume),
            thread: Some(worker),
        }
    }
    fn resume(&mut self) {
        if let Some(sender) = self.resume.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for ResponseBarrier {
    fn drop(&mut self) {
        self.resume();
        // Connection declared after the proxy is dropped first on test failure, closing I/O.
        if let Some(worker) = self.thread.take() {
            let _ = worker.join();
        }
    }
}

// Generic only over the concrete helper and commit futures being tested, not production behavior.
pub(super) async fn cancel_at_response<F>(barrier: &mut ResponseBarrier, future: F)
where
    F: std::future::Future,
{
    let mut future = Box::pin(future);
    let reached = barrier.reached.take().unwrap();
    tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(10),reached) => result.unwrap().unwrap(),
        _=&mut future => panic!("helper completed before protocol barrier"),
    }
    drop(future);
    barrier.resume();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn cancellation_consumes_owner_at_savepoint_open_and_cleanup() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "base").await;
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    let op = runs::record_intent(&mut tx, &intent(&c, &run))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let baseline = count(&db, "SELECT count(*) FROM openmettle.run_events").await;
    // Four helpers while opening, plus both successful release and error rollback.
    for (which, command) in [
        (0, b"SAVEPOINT\0".as_slice()),
        (1, b"SAVEPOINT\0"),
        (2, b"SAVEPOINT\0"),
        (3, b"SAVEPOINT\0"),
        (1, b"RELEASE\0"),
        (4, b"ROLLBACK\0"),
    ] {
        let mut barrier = ResponseBarrier::new(command);
        let role = if which == 0 { API } else { WORKER };
        let options = role_options(&db.0, role)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut connection = PgConnection::connect_with(&options).await.unwrap();
        let mut tx = WriteTransaction::begin(&mut connection).await.unwrap();
        // A prior caller write must be rolled back, even after a successful helper release.
        let previous = message(
            tx.connection().unwrap(),
            &c.scope,
            &c.conversation,
            Some(&c.message),
        )
        .await
        .unwrap();
        match which {
            0 => {
                cancel_at_response(
                    &mut barrier,
                    runs::create_run(&mut tx, &c.input("cancelled-create")),
                )
                .await;
            }
            1 => {
                cancel_at_response(
                    &mut barrier,
                    runs::append_event(
                        &mut tx,
                        &c.scope,
                        &run,
                        "cancelled-append",
                        payload(b"payload"),
                    ),
                )
                .await;
            }
            2 => {
                let mut i = intent(&c, &run);
                i.key = "cancelled-intent";
                cancel_at_response(&mut barrier, runs::record_intent(&mut tx, &i)).await;
            }
            3 => {
                let o = Observation {
                    scope: &c.scope,
                    run: &run,
                    operation: &op,
                    key: "cancelled-observation",
                    expected_revision: 0,
                    outcome: "outcome_unknown",
                    handle: None,
                    evidence: payload(b"uncertain"),
                };
                cancel_at_response(&mut barrier, runs::record_observation(&mut tx, &o)).await;
            }
            _ => {
                let mut i = intent(&c, &run);
                i.target = "conflicting-target";
                cancel_at_response(&mut barrier, runs::record_intent(&mut tx, &i)).await;
            }
        }
        assert!(matches!(
            tx.connection(),
            Err(Error::TransactionUnavailable)
        ));
        assert!(matches!(
            runs::append_event(&mut tx, &c.scope, &run, "reuse", payload(b"x")).await,
            Err(Error::TransactionUnavailable)
        ));
        assert!(matches!(
            tx.commit().await,
            Err(Error::TransactionUnavailable)
        ));
        // Close the cancelled connection; no handle can accidentally commit/reuse it. A fresh
        // connection is the documented recovery boundary for uncertain protocol cleanup.
        connection.close().await.unwrap();
        drop(barrier);
        let mut fresh = connect(&db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut fresh).await.unwrap();
        let missing: i64 =
            sqlx::query_scalar("SELECT count(*) FROM openmettle.messages WHERE id=$1::uuid")
                .bind(previous)
                .fetch_one(tx.connection().unwrap())
                .await
                .unwrap();
        assert_eq!(missing, 0);
        assert_eq!(
            count(&db, "SELECT count(*) FROM openmettle.run_events").await,
            baseline
        );
        assert_eq!(count(&db, "SELECT count(*) FROM openmettle.runs").await, 1);
        assert_eq!(
            count(&db, "SELECT count(*) FROM openmettle.operations").await,
            1
        );
        assert_eq!(
            count(&db, "SELECT revision FROM openmettle.operations").await,
            0
        );
        // Prove locks were released and the next independent transaction can complete.
        tokio::time::timeout(
            Duration::from_secs(2),
            runs::append_event(&mut tx, &c.scope, &run, "fresh", payload(b"fresh")),
        )
        .await
        .unwrap()
        .unwrap();
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn cancellation_during_run_lock_rolls_back_caller_writes() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "base").await;
    let mut blocker = connect(&db.0, API).await;
    let mut held = WriteTransaction::begin(&mut blocker).await.unwrap();
    runs::append_event(&mut held, &c.scope, &run, "held", payload(b"held"))
        .await
        .unwrap();
    let mut cn = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let previous = message(
        tx.connection().unwrap(),
        &c.scope,
        &c.conversation,
        Some(&c.message),
    )
    .await
    .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(tx.connection().unwrap())
        .await
        .unwrap();
    let mut future = Box::pin(runs::append_event(
        &mut tx,
        &c.scope,
        &run,
        "cancelled",
        payload(b"x"),
    ));
    let mut admin = db.admin().await;
    let waiting = async {
        loop {
            let blocked:bool=sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')").bind(pid).fetch_one(&mut admin).await.unwrap();
            if blocked {
                break;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        result=tokio::time::timeout(Duration::from_secs(10),waiting)=>result.unwrap(),
        _=&mut future=>panic!("helper completed without blocking"),
    }
    drop(future);
    assert!(matches!(
        tx.commit().await,
        Err(Error::TransactionUnavailable)
    ));
    // Let PostgreSQL finish the outstanding query before flushing queued rollback.
    held.rollback().await.unwrap();
    // Unlike cleanup-response cancellation, query cancellation can reuse the connection once
    // pending rollback has been flushed. The old WriteTransaction remains consumed.
    cn.ping().await.unwrap();
    let mut fresh = WriteTransaction::begin(&mut cn).await.unwrap();
    let missing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.messages WHERE id=$1::uuid")
            .bind(previous)
            .fetch_one(fresh.connection().unwrap())
            .await
            .unwrap();
    assert_eq!(missing, 0);
    assert_eq!(
        runs::append_event(&mut fresh, &c.scope, &run, "fresh", payload(b"fresh"))
            .await
            .unwrap(),
        2
    );
    fresh.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn ordinary_conflict_preserves_previous_caller_write() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "base").await;
    db.admin().await.execute("ALTER TABLE openmettle.run_events ADD CONSTRAINT fixture_failure CHECK (append_key <> 'reject') NOT VALID").await.unwrap();
    let mut cn = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    let previous = message(
        tx.connection().unwrap(),
        &c.scope,
        &c.conversation,
        Some(&c.message),
    )
    .await
    .unwrap();
    let mut changed = c.input("base");
    changed.config = b"different";
    assert!(matches!(
        runs::create_run(&mut tx, &changed).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        runs::append_event(&mut tx, &c.scope, &run, "reject", payload(b"rejected")).await,
        Err(Error::Database(_))
    ));
    assert_eq!(
        runs::append_event(&mut tx, &c.scope, &run, "next", payload(b"next"))
            .await
            .unwrap(),
        2
    );
    tx.commit().await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.messages WHERE id=$1::uuid")
            .bind(previous)
            .fetch_one(&mut cn)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn pinned_sqlx_borrowed_savepoint_cancellation_reproduces_false_commit() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let mut barrier = ResponseBarrier::new(b"SAVEPOINT\0");
    let options = role_options(&db.0, API)
        .host("127.0.0.1")
        .port(barrier.port)
        .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut cn = PgConnection::connect_with(&options).await.unwrap();
    let mut tx = cn.begin().await.unwrap();
    let previous = message(&mut tx, &c.scope, &c.conversation, Some(&c.message))
        .await
        .unwrap();
    cancel_at_response(&mut barrier, sqlx::Acquire::begin(&mut tx)).await;
    // This deliberately exercises the old API hazard, not the new owner. SQLx reports Ok
    // although its cancellation guard already queued a full rollback at the previous depth.
    tx.commit().await.unwrap();
    cn.ping().await.unwrap();
    let missing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.messages WHERE id=$1::uuid")
            .bind(previous)
            .fetch_one(&mut cn)
            .await
            .unwrap();
    assert_eq!(missing, 0);
    cn.close().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn cancelled_borrowed_savepoint_cannot_escape_owner() {
    let db = TestDb::migrated().await;
    let c = Context::new(&db).await;
    let run = c.run(&db, "borrowed-cancellation").await;
    // Test commit directly, then helper reuse directly; neither relies on connection() to
    // detect the lost transaction first. Reuse the connection to prove queued rollback.
    for reuse in [false, true] {
        let mut barrier = ResponseBarrier::new(b"SAVEPOINT\0");
        let options = role_options(&db.0, API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
        let mut cn = PgConnection::connect_with(&options).await.unwrap();
        let mut tx = runs::WriteTransaction::begin(&mut cn).await.unwrap();
        let previous = message(
            tx.connection().unwrap(),
            &c.scope,
            &c.conversation,
            Some(&c.message),
        )
        .await
        .unwrap();
        cancel_at_response(&mut barrier, sqlx::Acquire::begin(tx.connection().unwrap())).await;
        if reuse {
            assert!(matches!(
                runs::append_event(&mut tx, &c.scope, &run, "escape", payload(b"x")).await,
                Err(Error::TransactionUnavailable)
            ));
            assert!(matches!(
                tx.connection(),
                Err(Error::TransactionUnavailable)
            ));
        }
        assert!(matches!(
            tx.commit().await,
            Err(Error::TransactionUnavailable)
        ));
        cn.ping().await.unwrap();
        let missing: i64 =
            sqlx::query_scalar("SELECT count(*) FROM openmettle.messages WHERE id=$1::uuid")
                .bind(previous)
                .fetch_one(&mut cn)
                .await
                .unwrap();
        assert_eq!(missing, 0);
        let mut fresh = runs::WriteTransaction::begin(&mut cn).await.unwrap();
        runs::append_event(
            &mut fresh,
            &c.scope,
            &run,
            if reuse { "fresh-reuse" } else { "fresh-commit" },
            payload(b"fresh"),
        )
        .await
        .unwrap();
        fresh.commit().await.unwrap();
        cn.close().await.unwrap();
    }
}
