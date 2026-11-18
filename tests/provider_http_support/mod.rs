//! In-process synthetic TLS provider for the token transport (ADR 0010). Certificates and keys
//! are generated in memory per test; nothing is written to disk and no external network is used.
//! The server writes scripted raw HTTP/1.1 bytes so malformed framing can be exercised.
use super::{ProviderTransport, Trust};
use openidconnect::{HttpRequest, http};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};

mod ca;
pub use ca::{Ca, Identity};

pub const HOST: &str = "provider.example.test";

pub fn url(port: u16) -> String {
    format!("https://{HOST}:{port}/token")
}

pub struct Received {
    pub head: String,
    pub body: Vec<u8>,
}
pub enum Reply {
    /// Write, then close the TLS session.
    Bytes(Vec<u8>),
    /// Close without a response after reading the request.
    Close,
    /// Wait for a deterministic test barrier before responding.
    Gate(Arc<Notify>, Vec<u8>),
    /// Write (possibly nothing), then wait for the client to disconnect.
    Stall(Vec<u8>),
    /// Write this chunk every 50 ms until the client disconnects.
    Drip(Vec<u8>, Vec<u8>),
}
type Script = Arc<dyn Fn(&Received) -> Reply + Send + Sync>;

pub struct Server {
    pub port: u16,
    pub connections: Arc<AtomicUsize>,
    pub requests: Arc<AtomicUsize>,
    pub heads: Arc<Mutex<Vec<String>>>,
    /// Signalled once a full request has been read.
    pub entered: Arc<Notify>,
    /// Signalled when the client closes a stalled connection.
    pub closed: Arc<Notify>,
}
pub fn acceptor(identity: Identity) -> tokio_rustls::TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(identity.chain, identity.key)
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}
impl Server {
    pub async fn start(
        identity: Identity,
        script: impl Fn(&Received) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let acceptor = acceptor(identity);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = Self {
            port: listener.local_addr().unwrap().port(),
            connections: Arc::default(),
            requests: Arc::default(),
            heads: Arc::default(),
            entered: Arc::default(),
            closed: Arc::default(),
        };
        let script: Script = Arc::new(script);
        let (connections, requests, heads, entered, closed) = (
            server.connections.clone(),
            server.requests.clone(),
            server.heads.clone(),
            server.entered.clone(),
            server.closed.clone(),
        );
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let Some(received) = read_request(&mut tls).await else {
                    continue;
                };
                requests.fetch_add(1, Ordering::SeqCst);
                heads.lock().unwrap().push(received.head.clone());
                entered.notify_one();
                match script(&received) {
                    Reply::Bytes(bytes) => {
                        let _ = tls.write_all(&bytes).await;
                        let _ = tls.shutdown().await;
                    }
                    Reply::Close => drop(tls),
                    Reply::Gate(gate, bytes) => {
                        gate.notified().await;
                        let _ = tls.write_all(&bytes).await;
                        let _ = tls.shutdown().await;
                    }
                    Reply::Stall(bytes) => {
                        let _ = tls.write_all(&bytes).await;
                        let _ = tls.flush().await;
                        let mut buf = [0; 64];
                        while matches!(tls.read(&mut buf).await, Ok(n) if n > 0) {}
                        closed.notify_one();
                    }
                    Reply::Drip(first, chunk) => {
                        let _ = tls.write_all(&first).await;
                        loop {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            if tls.write_all(&chunk).await.is_err() || tls.flush().await.is_err() {
                                break;
                            }
                        }
                        closed.notify_one();
                    }
                }
            }
        });
        server
    }
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Option<Received> {
    let mut data = Vec::new();
    let mut buf = [0; 4096];
    let end = loop {
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 || data.len() > 64 * 1024 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8(data[..end].to_vec()).ok()?;
    let length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = data[end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Some(Received { head, body })
}

/// A well-formed response with an exact Content-Length.
pub fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\n", body.len());
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}
pub fn json(body: &[u8]) -> Vec<u8> {
    response(200, &[("content-type", "application/json")], body)
}

/// Resolves the configured host to the loopback fixture only.
pub fn loopback(_: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
}

pub fn transport(port: u16, ca: &Ca) -> ProviderTransport {
    ProviderTransport::new(&url(port), Trust::Bundle(&ca.pem()), &[])
        .unwrap()
        .with_lookup(loopback)
        .allow_loopback_fixture()
}

/// The request shape the library produces for a public-client token exchange.
pub fn token_request(url: &str) -> HttpRequest {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header(http::header::ACCEPT, "application/json")
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(b"grant_type=authorization_code&code=synthetic".to_vec())
        .unwrap()
}
