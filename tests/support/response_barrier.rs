//! Test-only PostgreSQL response barrier; never linked into production.
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::Duration,
};
pub(crate) struct ResponseBarrier {
    pub(crate) port: u16,
    reached: Option<tokio::sync::oneshot::Receiver<()>>,
    resume: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<std::io::Result<()>>>,
}
impl ResponseBarrier {
    pub(crate) fn new(command: &'static [u8]) -> Self {
        Self::nth(command, 1)
    }
    /// Withholds ReadyForQuery after the `occurrence`-th matching CommandComplete (1-based).
    pub(crate) fn nth(command: &'static [u8], occurrence: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let options: sqlx::postgres::PgConnectOptions = std::env::var("TEST_DATABASE_URL")
            .expect("isolated TEST_DATABASE_URL")
            .parse()
            .unwrap();
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
            let mut matched = 0;
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
                        matched += 1;
                        selected |= matched == occurrence;
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
    pub(crate) async fn wait_reached(&mut self) {
        tokio::time::timeout(Duration::from_secs(30), self.reached.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
    pub(crate) fn resume(&mut self) {
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
pub(crate) async fn cancel_at_response<F>(barrier: &mut ResponseBarrier, future: F)
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
