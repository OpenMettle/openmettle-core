//! Generic bounded HTTP/1.1 core evidence (ADR 0010), driven directly through `Route::send` with
//! caller-chosen method, content type, limits and DNS pool. Synthetic hosts, in-memory PKI,
//! loopback only.
use super::*;
use crate::provider_http::fixture::{self, Ca, Reply, Server};
use std::sync::{
    Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};

const PROTOBUF: &str = "application/x-protobuf";

fn url(port: u16) -> String {
    format!("https://{}:{port}/v1/traces", fixture::HOST)
}

/// Owns what a caller lends to `Route`, with a caller-chosen DNS pool.
struct Owner {
    endpoint: Endpoint,
    tls: Arc<rustls::ClientConfig>,
    lookup: Lookup,
    slots: Arc<Semaphore>,
    loopback: bool,
}
impl Owner {
    fn new(port: u16, ca: &Ca, slots: Arc<Semaphore>) -> Self {
        Self {
            endpoint: endpoint(&url(port)).unwrap(),
            tls: client_config(roots(Trust::Bundle(&ca.pem())).unwrap()).unwrap(),
            lookup: Arc::new(fixture::loopback),
            slots,
            loopback: true,
        }
    }
    fn lookup(
        mut self,
        lookup: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.lookup = Arc::new(lookup);
        self
    }
    fn route(&self) -> Route<'_> {
        Route {
            endpoint: &self.endpoint,
            allowed: &[],
            tls: &self.tls,
            lookup: &self.lookup,
            slots: &self.slots,
            loopback: self.loopback,
        }
    }
    async fn post(&self, body: &[u8], limits: &Limits) -> Result<HttpResponse, Error> {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static(PROTOBUF),
        );
        self.route()
            .send(http::Method::POST, &headers, body.to_vec(), limits)
            .await
    }
}

fn limits() -> Limits {
    Limits {
        request_body: 16,
        response_body: 32,
        response_headers: 32,
        response_header_bytes: 8 * 1024,
        setup: Duration::from_secs(2),
        total: Duration::from_secs(4),
    }
}

fn slots(n: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(n))
}

fn counted(
    lookups: &Arc<AtomicUsize>,
) -> impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + use<> {
    let lookups = lookups.clone();
    move |host, port| {
        lookups.fetch_add(1, Ordering::SeqCst);
        fixture::loopback(host, port)
    }
}

#[tokio::test]
async fn post_sends_caller_content_type_and_exact_binary_body_once() {
    let ca = Ca::new();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let seen = sent.clone();
    let server = Server::start(ca.leaf(fixture::HOST, false), move |received| {
        *seen.lock().unwrap() = received.body.clone();
        Reply::Bytes(fixture::response(
            200,
            &[("content-type", PROTOBUF)],
            b"\x00ok",
        ))
    })
    .await;
    let owner = Owner::new(server.port, &ca, slots(1));
    let body = [
        0u8, 1, 2, 0xff, b'\r', b'\n', 0, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    ];
    assert_eq!(body.len(), limits().request_body);
    let response = owner.post(&body, &limits()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"\x00ok");
    assert_eq!(*sent.lock().unwrap(), body);
    let head = server.heads.lock().unwrap()[0].to_ascii_lowercase();
    assert!(head.starts_with("post /v1/traces http/1.1\r\n"), "{head}");
    assert!(head.contains(&format!("\r\nhost: {}:{}\r\n", fixture::HOST, server.port)));
    assert!(head.contains("\r\nconnection: close\r\n"));
    assert!(head.contains(&format!("\r\ncontent-type: {PROTOBUF}\r\n")));
    assert!(head.contains("\r\ncontent-length: 16\r\n"));
    for absent in [
        "accept-encoding",
        "\r\nte:",
        "upgrade",
        "proxy",
        "authorization",
        "cookie",
    ] {
        assert!(!head.contains(absent), "{absent}");
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refusals_happen_before_dns_or_any_wire_bytes() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    let lookups = Arc::new(AtomicUsize::new(0));
    let owner = Owner::new(server.port, &ca, slots(1)).lookup(counted(&lookups));
    let route = owner.route();
    // One byte over the caller's request cap.
    assert_eq!(
        owner.post(&[0; 17], &limits()).await.unwrap_err(),
        Error::Destination
    );
    let protobuf = || {
        let mut h = http::HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static(PROTOBUF),
        );
        h
    };
    let mut cases: Vec<(http::Method, http::HeaderMap, Vec<u8>)> = vec![
        (http::Method::GET, http::HeaderMap::new(), vec![1]),
        (http::Method::PUT, protobuf(), vec![]),
        (http::Method::DELETE, http::HeaderMap::new(), vec![]),
        (http::Method::CONNECT, http::HeaderMap::new(), vec![]),
    ];
    for (name, value) in [
        ("authorization", "Bearer synthetic"),
        ("cookie", "session=synthetic"),
        ("host", "attacker.example.test"),
        ("connection", "keep-alive"),
        ("transfer-encoding", "chunked"),
        ("content-encoding", "gzip"),
        ("content-type", "text/plain"),
    ] {
        let mut headers = protobuf();
        headers.append(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_static(value),
        );
        cases.push((http::Method::POST, headers, vec![]));
    }
    for (method, headers, body) in cases {
        assert_eq!(
            route
                .send(method, &headers, body, &limits())
                .await
                .unwrap_err(),
            Error::Destination
        );
    }
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    // An empty-bodied GET with Accept is admitted.
    let mut accept = http::HeaderMap::new();
    accept.insert(
        header::ACCEPT,
        http::HeaderValue::from_static("application/json"),
    );
    route
        .send(http::Method::GET, &accept, Vec::new(), &limits())
        .await
        .unwrap();
    assert!(server.heads.lock().unwrap()[0].starts_with("GET /v1/traces "));
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn production_route_refuses_loopback_and_private_answers() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    let mut owner = Owner::new(server.port, &ca, slots(1));
    owner.loopback = false;
    assert_eq!(
        owner.post(b"x", &limits()).await.unwrap_err(),
        Error::Address
    );
    let p = server.port;
    let owner = Owner::new(p, &ca, slots(1)).lookup(move |_, _| {
        Ok(vec![
            SocketAddr::from(([127, 0, 0, 1], p)),
            SocketAddr::from(([10, 0, 0, 1], p)),
        ])
    });
    assert_eq!(
        owner.post(b"x", &limits()).await.unwrap_err(),
        Error::Address
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn redirects_and_non_success_statuses_return_without_follow_or_retry() {
    let ca = Ca::new();
    let target = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    let location = url(target.port);
    for status in [301, 302, 307, 308, 400, 429, 500, 503] {
        let location = location.clone();
        let server = Server::start(ca.leaf(fixture::HOST, false), move |_| {
            Reply::Bytes(fixture::response(
                status,
                &[("location", &location), ("retry-after", "0")],
                b"",
            ))
        })
        .await;
        let owner = Owner::new(server.port, &ca, slots(1));
        let response = owner.post(b"x", &limits()).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    }
    assert_eq!(target.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn caller_response_cap_bounds_declared_streamed_and_header_bytes() {
    let ca = Ca::new();
    let cases: Vec<(Reply, Result<usize, Error>)> = vec![
        (
            Reply::Bytes(fixture::response(200, &[], &[b'x'; 32])),
            Ok(32),
        ),
        (
            Reply::Bytes(fixture::response(200, &[], &[b'x'; 33])),
            Err(Error::TooLarge),
        ),
        // Declared over the cap, then stalled: a body read would time out instead.
        (
            Reply::Stall(b"HTTP/1.1 200 OK\r\ncontent-length: 33\r\n\r\n".to_vec()),
            Err(Error::TooLarge),
        ),
        (
            Reply::Bytes(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n28\r\n\
                  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n0\r\n\r\n"
                    .to_vec(),
            ),
            Err(Error::TooLarge),
        ),
        (
            Reply::Bytes(
                format!(
                    "HTTP/1.1 200 OK\r\nx: {}\r\ncontent-length: 0\r\n\r\n",
                    "a".repeat(9000)
                )
                .into_bytes(),
            ),
            Err(Error::TooLarge),
        ),
        (
            Reply::Bytes(
                b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 0\r\n\r\n".to_vec(),
            ),
            Err(Error::Protocol),
        ),
        (
            Reply::Bytes(b"HTTP/1.1 200 OK\r\n\r\nclose-delimited".to_vec()),
            Err(Error::Protocol),
        ),
    ];
    for (reply, expected) in cases {
        let reply = Mutex::new(Some(reply));
        let server = Server::start(ca.leaf(fixture::HOST, false), move |_| {
            reply.lock().unwrap().take().unwrap()
        })
        .await;
        let owner = Owner::new(server.port, &ca, slots(1));
        let mut bounded = limits();
        bounded.total = Duration::from_secs(1);
        let result = owner.post(b"x", &bounded).await.map(|r| r.body().len());
        assert_eq!(result, expected);
    }
}

#[tokio::test]
async fn total_deadline_cancels_and_dropping_closes_the_socket() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| Reply::Stall(Vec::new())).await;
    let owner = Owner::new(server.port, &ca, slots(1));
    let mut short = limits();
    short.total = Duration::from_millis(500);
    assert_eq!(owner.post(b"x", &short).await.unwrap_err(), Error::Timeout);
    tokio::time::timeout(Duration::from_secs(5), server.closed.notified())
        .await
        .expect("the deadline closes the socket");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    // Dropping the request future closes the connection too. A fresh server keeps the
    // `entered` signal unambiguous.
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| Reply::Stall(Vec::new())).await;
    let owner = Owner::new(server.port, &ca, slots(1));
    let normal = limits();
    let mut call = Box::pin(owner.post(b"x", &normal));
    tokio::select! {
        _ = server.entered.notified() => (),
        _ = &mut call => panic!("stalled server completed"),
    }
    drop(call);
    tokio::time::timeout(Duration::from_secs(5), server.closed.notified())
        .await
        .expect("dropping the request closes the socket");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

/// Blocks lookups until released; counts entries. Release on drop so shutdown cannot hang.
#[derive(Default)]
struct Gate {
    entered: AtomicUsize,
    released: Mutex<bool>,
    wake: Condvar,
    signal: tokio::sync::Notify,
}
impl Gate {
    fn lookup(self: &Arc<Self>) -> impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + use<> {
        let gate = self.clone();
        move |_, _| {
            gate.entered.fetch_add(1, Ordering::SeqCst);
            gate.signal.notify_one();
            let mut released = gate.released.lock().unwrap();
            while !*released {
                released = gate.wake.wait(released).unwrap();
            }
            Err(io::Error::other("synthetic"))
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
struct Unblock(Arc<Gate>);
impl Drop for Unblock {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exhausted_dns_pool_does_not_starve_another_owners_pool() {
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    let gate = Arc::new(Gate::default());
    let _unblock = Unblock(gate.clone());
    // A provider-sized pool whose every lookup hangs, and a small independent pool.
    let busy = slots(8);
    let hung = Owner::new(server.port, &ca, busy.clone()).lookup(gate.lookup());
    let normal = limits();
    let mut quick = limits();
    quick.setup = Duration::from_millis(300);
    for n in 1..=8 {
        let call = hung.post(b"x", &normal);
        tokio::pin!(call);
        tokio::select! {
            _ = async {
                while gate.entered.load(Ordering::SeqCst) < n {
                    gate.signal.notified().await;
                }
            } => (),
            _ = &mut call => panic!("blocked lookup completed"),
        }
    }
    // Every abandoned lookup still owns its slot: the busy owner queues out.
    assert_eq!(busy.available_permits(), 0);
    assert_eq!(hung.post(b"x", &quick).await.unwrap_err(), Error::Timeout);
    assert_eq!(gate.entered.load(Ordering::SeqCst), 8);
    // A separate owner with its own single slot is unaffected and completes end to end.
    let other = Owner::new(server.port, &ca, slots(1));
    other.post(b"x", &normal).await.unwrap();
    assert_eq!(other.slots.available_permits(), 1);
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
    gate.release();
    drop(
        tokio::time::timeout(Duration::from_secs(5), busy.acquire_many(8))
            .await
            .unwrap()
            .unwrap(),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn total_deadline_clamps_setup_when_shorter_than_setup() {
    let ca = Ca::new();
    let gate = Arc::new(Gate::default());
    let _unblock = Unblock(gate.clone());
    let pool = slots(1);
    let hung = Owner::new(8443, &ca, pool.clone()).lookup(gate.lookup());
    let mut tight = limits();
    tight.setup = Duration::from_secs(5);
    tight.total = Duration::from_millis(150);
    let began = Instant::now();
    assert_eq!(hung.post(b"x", &tight).await.unwrap_err(), Error::Timeout);
    assert!(
        began.elapsed() < Duration::from_secs(1),
        "setup must not outlive a shorter total deadline"
    );
    gate.release();
    drop(
        tokio::time::timeout(Duration::from_secs(5), pool.acquire_owned())
            .await
            .unwrap()
            .unwrap(),
    );
}

const PROXY_CHILD: &str = "OPENMETTLE_HTTP_CORE_PROXY_CHILD";

/// Runs in a child process with proxy variables set by the parent; skipped otherwise.
#[tokio::test]
#[ignore = "child process of core_ignores_environment_proxies"]
async fn core_environment_proxy_child() {
    if std::env::var(PROXY_CHILD).as_deref() != Ok("1") {
        return;
    }
    let ca = Ca::new();
    let server = Server::start(ca.leaf(fixture::HOST, false), |_| {
        Reply::Bytes(fixture::json(b"{}"))
    })
    .await;
    Owner::new(server.port, &ca, slots(1))
        .post(b"x", &limits())
        .await
        .unwrap();
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);
}

#[test]
fn core_ignores_environment_proxies() {
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", proxy.local_addr().unwrap());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "provider_http::transport::tests::core_environment_proxy_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env(PROXY_CHILD, "1");
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        child.env(name, &address);
    }
    child.env_remove("NO_PROXY").env_remove("no_proxy");
    let output = child.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    proxy.set_nonblocking(true).unwrap();
    assert_eq!(
        proxy.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "a proxy connection was made"
    );
}
