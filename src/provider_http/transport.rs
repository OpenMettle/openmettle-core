//! Reusable bounded HTTP/1.1 client core (ADR 0010), shared by every configured outbound client.
//!
//! A caller owns its destination policy, TLS configuration and DNS slot pool, and lends them to a
//! [`Route`] per request. The core enforces the security-relevant parts of ADR 0010 for every
//! caller: canonical HTTPS endpoint, address policy over every DNS answer, explicit rustls (ring)
//! with ALPN `http/1.1`, one request per connection with `Connection: close`, no proxy, redirect or
//! retry, strict response framing and caller-supplied size and deadline bounds. The connection is
//! driven inside the caller's future; dropping it closes the socket. Callers apply any stricter
//! request admission of their own before calling [`Route::send`].
//!
//! The one exception to HTTPS is [`gateway_endpoint`], the route of metered turns to OpenMettle's
//! own gateway inside the cluster (ADR 0044): it may also be `http://`, and then has no TLS. Every
//! other rule applies to it unchanged.
use super::{Error, MAX_ADDRESSES, MAX_TRUST_BUNDLE_BYTES, Trust};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{client::conn::http1, header};
use hyper_util::rt::TokioIo;
use openidconnect::{HttpResponse, http, url};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Semaphore,
    time::Instant,
};

/// hyper's minimum permitted connection read buffer.
const MAX_READ_BUFFER: usize = 8 * 1024;
const MAX_TRUST_CERTIFICATES: usize = 256;
const MAX_ENDPOINT_BYTES: usize = 2048;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Range {
    pub(super) network: IpAddr,
    pub(super) prefix: u8,
}
impl Range {
    const fn v4(a: [u8; 4], prefix: u8) -> Self {
        Self {
            network: IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])),
            prefix,
        }
    }
    const fn v6(s: [u16; 8], prefix: u8) -> Self {
        Self {
            network: IpAddr::V6(Ipv6Addr::new(
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            )),
            prefix,
        }
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
    fn within(&self, outer: &Range) -> bool {
        self.prefix >= outer.prefix && outer.contains(self.network)
    }
}

// IANA IPv4/IPv6 Special-Purpose Address Registries (both last updated 2025-10-09).
/// Never permitted, even inside an allowlisted private range: cloud metadata/platform services.
const HARD_DENY: [Range; 3] = [
    Range::v4([100, 100, 100, 200], 32),
    Range::v4([168, 63, 129, 16], 32),
    Range::v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254], 128),
];
/// Eligible only through an explicit per-destination allowlist entry.
const PRIVATE: [Range; 5] = [
    Range::v4([10, 0, 0, 0], 8),
    Range::v4([172, 16, 0, 0], 12),
    Range::v4([192, 168, 0, 0], 16),
    Range::v4([100, 64, 0, 0], 10),
    Range::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
];
/// IPv4 special-purpose blocks plus multicast. Globally reachable AS112/AMT/anycast blocks are
/// conservatively refused: no configured destination is expected there.
const DENY_V4: [Range; 14] = [
    Range::v4([0, 0, 0, 0], 8),
    Range::v4([127, 0, 0, 0], 8),
    Range::v4([169, 254, 0, 0], 16),
    Range::v4([192, 0, 0, 0], 24),
    Range::v4([192, 0, 2, 0], 24),
    Range::v4([192, 31, 196, 0], 24),
    Range::v4([192, 52, 193, 0], 24),
    Range::v4([192, 88, 99, 0], 24),
    Range::v4([192, 175, 48, 0], 24),
    Range::v4([198, 18, 0, 0], 15),
    Range::v4([198, 51, 100, 0], 24),
    Range::v4([203, 0, 113, 0], 24),
    Range::v4([224, 0, 0, 0], 4),
    Range::v4([240, 0, 0, 0], 4),
];
/// Public IPv6 is only space IANA has allocated to the RIRs (IPv6 Global Unicast Address
/// Assignments, last updated 2025-10-10). Everything else, including unallocated 2000::/3,
/// loopback, unspecified, IPv4-mapped/compatible, NAT64 64:ff9b::/96 and 64:ff9b:1::/48,
/// discard/dummy, SRv6, link-local and multicast, is refused rather than decoded. A future IANA
/// allocation fails closed until this table is updated.
const ALLOCATED_V6: [Range; 34] = [
    // APNIC, ARIN, RIPE NCC, LACNIC, AFRINIC, in registry order per RIR.
    rir(0x2001, 0x200, 23),
    rir(0x2001, 0xc00, 23),
    rir(0x2001, 0xe00, 23),
    rir(0x2001, 0x4400, 23),
    rir(0x2001, 0x8000, 19),
    rir(0x2001, 0xa000, 20),
    rir(0x2001, 0xb000, 20),
    rir(0x2400, 0x0, 12),
    rir(0x2410, 0x0, 12),
    rir(0x2001, 0x400, 23),
    rir(0x2001, 0x1800, 23),
    rir(0x2001, 0x4800, 23),
    rir(0x2600, 0x0, 12),
    rir(0x2610, 0x0, 23),
    rir(0x2620, 0x0, 23),
    rir(0x2630, 0x0, 12),
    rir(0x2001, 0x600, 23),
    rir(0x2001, 0x800, 22),
    rir(0x2001, 0x1400, 22),
    rir(0x2001, 0x1a00, 23),
    rir(0x2001, 0x1c00, 22),
    rir(0x2001, 0x2000, 19),
    rir(0x2001, 0x4000, 23),
    rir(0x2001, 0x4600, 23),
    rir(0x2001, 0x4a00, 23),
    rir(0x2001, 0x4c00, 23),
    rir(0x2001, 0x5000, 20),
    rir(0x2003, 0x0, 18),
    rir(0x2a00, 0x0, 12),
    rir(0x2a10, 0x0, 12),
    rir(0x2001, 0x1200, 23),
    rir(0x2800, 0x0, 12),
    rir(0x2001, 0x4200, 23),
    rir(0x2c00, 0x0, 12),
];
const fn rir(a: u16, b: u16, prefix: u8) -> Range {
    Range::v6([a, b, 0, 0, 0, 0, 0, 0], prefix)
}
/// Special-purpose blocks overlapping or adjacent to allocations: the whole IETF block (Teredo,
/// benchmarking, ORCHID, anycast), documentation, 6to4 and AS112 delegation.
const DENY_V6: [Range; 5] = [
    Range::v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    Range::v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
    Range::v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
    Range::v6([0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0], 48),
    Range::v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
];

pub(crate) fn permitted(ip: IpAddr, allowed: &[Range]) -> bool {
    if HARD_DENY.iter().any(|r| r.contains(ip)) {
        return false;
    }
    if PRIVATE.iter().any(|r| r.contains(ip)) {
        return allowed.iter().any(|r| r.contains(ip));
    }
    match ip {
        IpAddr::V4(_) => !DENY_V4.iter().any(|r| r.contains(ip)),
        IpAddr::V6(_) => {
            ALLOCATED_V6.iter().any(|r| r.contains(ip)) && !DENY_V6.iter().any(|r| r.contains(ip))
        }
    }
}

pub(crate) fn private_range(value: &str) -> Result<Range, Error> {
    let (address, prefix) = value.split_once('/').ok_or(Error::Configuration)?;
    let network: IpAddr = address.parse().map_err(|_| Error::Configuration)?;
    if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Configuration);
    }
    let prefix: u8 = prefix.parse().map_err(|_| Error::Configuration)?;
    let max = if network.is_ipv4() { 32 } else { 128 };
    let range = Range { network, prefix };
    // Canonical text, no host bits, and inside one RFC 1918/CGNAT/ULA block.
    if prefix > max
        || value != format!("{network}/{prefix}")
        || masked(network, prefix) != network
        || !PRIVATE.iter().any(|outer| range.within(outer))
    {
        return Err(Error::Configuration);
    }
    Ok(range)
}
fn masked(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(
            u32::from(a) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0),
        )),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(
            u128::from(a) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0),
        )),
    }
}

/// A canonical HTTPS URL with a DNS host; IP literals and every ambiguous form are refused.
#[derive(Clone)]
pub(crate) struct Endpoint {
    pub(crate) url: String,
    host: String,
    port: u16,
    authority: String,
    pub(super) path: String,
    /// `https://`. Only [`gateway_endpoint`] makes one without TLS.
    tls: bool,
}
pub(crate) fn endpoint(value: &str) -> Result<Endpoint, Error> {
    parse(value, false)
}
/// [`endpoint`], except that `http://` is accepted as well and then means no TLS. Only for the
/// route of metered turns to OpenMettle's own gateway (`inference::Gateway::metered`); every
/// other client keeps [`endpoint`].
pub(super) fn gateway_endpoint(value: &str) -> Result<Endpoint, Error> {
    parse(value, true)
}
fn parse(value: &str, plain: bool) -> Result<Endpoint, Error> {
    if value.is_empty()
        || value.len() > MAX_ENDPOINT_BYTES
        || value.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || value.contains(['\\', '?', '#', '@', '%'])
    {
        return Err(Error::Configuration);
    }
    let parsed = url::Url::parse(value).map_err(|_| Error::Configuration)?;
    let tls = match parsed.scheme() {
        "https" => true,
        "http" if plain => false,
        _ => return Err(Error::Configuration),
    };
    // Canonical input only: no case, default-port, dot-segment or encoding variants.
    if parsed.as_str() != value || parsed.cannot_be_a_base() {
        return Err(Error::Configuration);
    }
    let Some(url::Host::Domain(host)) = parsed.host() else {
        return Err(Error::Configuration);
    };
    if host.len() > 253
        || host.ends_with('.')
        || host.starts_with('.')
        || host.contains("..")
        || !host.contains('.')
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        || ServerName::try_from(host).is_err()
    {
        return Err(Error::Configuration);
    }
    let port = parsed.port_or_known_default().ok_or(Error::Configuration)?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok(Endpoint {
        url: value.to_owned(),
        host: host.to_owned(),
        port,
        authority,
        path: parsed.path().to_owned(),
        tls,
    })
}
impl Endpoint {
    /// Whether this endpoint is `https://`.
    pub(super) fn tls(&self) -> bool {
        self.tls
    }
}

pub(crate) fn roots(trust: Trust<'_>) -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    match trust {
        Trust::Native => {
            let loaded = rustls_native_certs::load_native_certs();
            if !loaded.errors.is_empty() {
                return Err(Error::Configuration);
            }
            let (added, _unparsable) = roots.add_parsable_certificates(loaded.certs);
            if added == 0 {
                return Err(Error::Configuration);
            }
        }
        Trust::Bundle(pem) => {
            if pem.is_empty() || pem.len() > MAX_TRUST_BUNDLE_BYTES {
                return Err(Error::Configuration);
            }
            let sections = pem.windows(11).filter(|w| w == b"-----BEGIN ").count();
            let certs = CertificateDer::pem_slice_iter(pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::Configuration)?;
            if certs.is_empty() || certs.len() > MAX_TRUST_CERTIFICATES || certs.len() != sections {
                return Err(Error::Configuration);
            }
            for cert in certs {
                roots.add(cert).map_err(|_| Error::Configuration)?;
            }
        }
    }
    Ok(roots)
}

/// rustls with the explicit ring provider: TLS 1.3/1.2, ALPN `http/1.1`, no client certificate,
/// session resumption or early data.
pub(crate) fn client_config(
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| Error::Configuration)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;
    Ok(Arc::new(tls))
}

pub(crate) type Lookup = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;
pub(crate) fn system_lookup(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    // One more than the bound, so extra answers fail instead of being silently truncated.
    Ok((host, port)
        .to_socket_addrs()?
        .take(MAX_ADDRESSES + 1)
        .collect())
}

/// Per-caller bounds. `setup` covers DNS queueing, lookup, TCP connect and TLS (clamped to
/// `total`); `total` covers the whole request including setup. Response header limits are
/// enforced by hyper's parser (`response_header_bytes` is additionally capped by
/// `MAX_READ_BUFFER`, 8 KiB).
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) request_body: usize,
    pub(crate) response_body: usize,
    pub(crate) response_headers: usize,
    pub(crate) response_header_bytes: usize,
    pub(crate) setup: Duration,
    pub(crate) total: Duration,
}

/// One configured destination, borrowed from its owner for a request. `slots` is the owner's DNS
/// lookup pool: separate owners pass separate semaphores so one cannot exhaust another's slots.
/// `tls` is present exactly when the endpoint is `https://`; [`Route::connect`] refuses any other
/// pairing, so an `https://` endpoint is never sent without TLS.
pub(crate) struct Route<'a> {
    pub(crate) endpoint: &'a Endpoint,
    pub(crate) allowed: &'a [Range],
    pub(crate) tls: Option<&'a Arc<rustls::ClientConfig>>,
    pub(crate) lookup: &'a Lookup,
    pub(crate) slots: &'a Arc<Semaphore>,
    /// Test fixture seam: additionally permits 127.0.0.1 and ::1. Absent from production builds.
    #[cfg(test)]
    pub(crate) loopback: bool,
}

/// An open connection to a configured destination: TLS, or plain TCP for an `http://` gateway
/// endpoint.
pub(crate) trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

// Scoped to construction of one existing inference request. Its codec owns the
// headers; consume the ID before any stream callback or other request can run.
tokio::task_local! {
    pub(super) static BILLABLE_REQUEST: std::cell::Cell<Option<header::HeaderValue>>;
}

impl Route<'_> {
    /// Sends one request to the configured endpoint. Only `GET` (empty body) and `POST` are
    /// accepted, and the only caller headers are at most one `Accept` and one `Content-Type`; the
    /// core adds `Host` and `Connection: close`. Every refusal happens before any DNS work. A
    /// non-2xx or 3xx response is returned to the caller: nothing is retried or followed.
    pub(crate) async fn send(
        &self,
        method: http::Method,
        headers: &http::HeaderMap,
        body: Vec<u8>,
        limits: &Limits,
    ) -> Result<HttpResponse, Error> {
        if !(method == http::Method::POST || method == http::Method::GET && body.is_empty())
            || body.len() > limits.request_body
            || headers.keys_len() != headers.len()
            || headers
                .keys()
                .any(|k| k != header::ACCEPT && k != header::CONTENT_TYPE)
        {
            return Err(Error::Destination);
        }
        self.send_admitted(method, headers, body, limits).await
    }

    /// Gateway admin constructs its pinned method, path and sensitive headers internally.
    pub(super) async fn send_admitted(
        &self,
        method: http::Method,
        headers: &http::HeaderMap,
        body: Vec<u8>,
        limits: &Limits,
    ) -> Result<HttpResponse, Error> {
        let start = Instant::now();
        let total = start + limits.total;
        let setup = (start + limits.setup).min(total);
        if body.len() > limits.request_body {
            return Err(Error::TooLarge);
        }
        let outbound = self.request(method, headers, body)?;
        let connection = self.connect(setup).await?;
        tokio::time::timeout_at(
            total,
            self.exchange(connection, outbound, total, limits, |response| {
                read(response, limits.response_body)
            }),
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub(super) async fn connect(&self, setup: Instant) -> Result<Box<dyn Connection>, Error> {
        if self.endpoint.tls != self.tls.is_some() {
            return Err(Error::Configuration);
        }
        let answers = self.resolve(setup).await?;
        // Alternate only on TCP failure, before any TLS or HTTP bytes; connect to validated
        // addresses only, so a later DNS answer cannot redirect this request.
        let mut tcp = None;
        for address in answers {
            match tokio::time::timeout_at(setup, TcpStream::connect(address)).await {
                Err(_) => return Err(Error::Timeout),
                Ok(Ok(stream)) => {
                    tcp = Some(stream);
                    break;
                }
                Ok(Err(_)) => continue,
            }
        }
        let tcp = tcp.ok_or(Error::Connect)?;
        tcp.set_nodelay(true).map_err(|_| Error::Connect)?;
        // A plain `http://` gateway endpoint: no certificate, so the host name only selects the
        // DNS answers checked above and the `Host` header.
        let Some(tls) = self.tls else {
            return Ok(Box::new(tcp));
        };
        // Certificate validation uses the configured host name, never the connected address.
        let name =
            ServerName::try_from(self.endpoint.host.clone()).map_err(|_| Error::Configuration)?;
        let stream = tokio::time::timeout_at(
            setup,
            tokio_rustls::TlsConnector::from(tls.clone()).connect(name, tcp),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Tls)?;
        Ok(Box::new(stream))
    }

    fn address_permitted(&self, ip: IpAddr) -> bool {
        #[cfg(test)]
        if self.loopback
            && (ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST))
        {
            return true;
        }
        permitted(ip, self.allowed)
    }

    /// The OS lookup runs on Tokio's blocking pool and cannot be cancelled. Its slot permit moves
    /// into the blocking closure, so an abandoned lookup keeps its slot until it really finishes;
    /// at most the owner's slot count of lookups exist for that owner. Only the configured host and
    /// port enter the closure: no request, credential or HTTP state.
    async fn resolve(&self, deadline: Instant) -> Result<Vec<SocketAddr>, Error> {
        let permit = tokio::time::timeout_at(deadline, self.slots.clone().acquire_owned())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Resolve)?;
        let (lookup, host, port) = (
            self.lookup.clone(),
            self.endpoint.host.clone(),
            self.endpoint.port,
        );
        let job = tokio::task::spawn_blocking(move || {
            let answers = lookup(&host, port);
            drop(permit);
            answers
        });
        let answers = tokio::time::timeout_at(deadline, job)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Resolve)?
            .map_err(|_| Error::Resolve)?;
        if answers.is_empty() || answers.len() > MAX_ADDRESSES {
            return Err(Error::Resolve);
        }
        // Every answer must pass before any connection; one refused answer refuses them all.
        if answers
            .iter()
            .any(|a| a.port() != port || !self.address_permitted(a.ip()))
        {
            return Err(Error::Address);
        }
        Ok(answers)
    }

    pub(super) fn request(
        &self,
        method: http::Method,
        headers: &http::HeaderMap,
        body: Vec<u8>,
    ) -> Result<http::Request<Full<Bytes>>, Error> {
        let mut outbound = http::Request::builder()
            .method(method)
            .uri(self.endpoint.path.as_str())
            .header(header::HOST, self.endpoint.authority.as_str())
            .header(header::CONNECTION, "close");
        if headers.contains_key(header::AUTHORIZATION)
            && let Ok(Some(id)) = BILLABLE_REQUEST.try_with(std::cell::Cell::take)
        {
            outbound = outbound.header("x-request-id", id);
        }
        for (name, value) in headers {
            outbound = outbound.header(name, value);
        }
        outbound
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| Error::Destination)
    }

    pub(super) async fn exchange<T, E: From<Error>, F: Future<Output = Result<T, E>>>(
        &self,
        connection: Box<dyn Connection>,
        outbound: http::Request<Full<Bytes>>,
        header_deadline: Instant,
        limits: &Limits,
        consume: impl FnOnce(hyper::Response<hyper::body::Incoming>) -> F,
    ) -> Result<T, E> {
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(limits.response_headers)
            .max_header_size(limits.response_header_bytes)
            .max_buf_size(MAX_READ_BUFFER)
            .handshake::<_, Full<Bytes>>(TokioIo::new(connection))
            .await
            .map_err(|_| Error::Protocol)?;
        // Driven here, never spawned: the connection lives exactly as long as this future.
        let response = async {
            let response = tokio::time::timeout_at(header_deadline, sender.send_request(outbound))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(hyper_error)?;
            consume(response).await
        };
        tokio::pin!(connection, response);
        let mut driving = true;
        loop {
            tokio::select! {
                result = &mut response => return result,
                // A connection error reaches the response or body future as well.
                _ = &mut connection, if driving => driving = false,
            }
        }
    }
}

fn hyper_error(error: hyper::Error) -> Error {
    if error.is_parse_too_large() {
        Error::TooLarge
    } else {
        Error::Protocol
    }
}

/// Strict framing: one Content-Length or exactly `chunked`; no close-delimited body, encoding,
/// duplicated length/type/encoding or trailers. Oversized declared lengths fail before reading.
async fn read(
    response: hyper::Response<hyper::body::Incoming>,
    max_body: usize,
) -> Result<HttpResponse, Error> {
    let (parts, body) = response.into_parts();
    let length = framed_length(&parts, max_body)?;
    let headers = &parts.headers;
    let mut collected = Vec::with_capacity(length.unwrap_or(0) as usize);
    let mut body = Limited::new(body, max_body);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            if e.is::<http_body_util::LengthLimitError>() {
                Error::TooLarge
            } else {
                match e.downcast::<hyper::Error>() {
                    Ok(e) => hyper_error(*e),
                    Err(_) => Error::Protocol,
                }
            }
        })?;
        match frame.into_data() {
            Ok(data) => collected.extend_from_slice(&data),
            Err(_) => return Err(Error::Protocol),
        }
    }
    if length.is_some_and(|n| n != collected.len() as u64) {
        return Err(Error::Protocol);
    }
    let mut out = http::Response::builder()
        .status(parts.status)
        .version(parts.version);
    for (name, value) in headers {
        out = out.header(name, value);
    }
    out.body(collected).map_err(|_| Error::Protocol)
}

pub(super) fn framed_length(
    parts: &http::response::Parts,
    max_body: usize,
) -> Result<Option<u64>, Error> {
    let headers = &parts.headers;
    let count = |name| headers.get_all(name).iter().count();
    if count(header::CONTENT_TYPE) > 1
        || count(header::CONTENT_LENGTH) > 1
        || count(header::TRANSFER_ENCODING) > 1
        || headers
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(Error::Protocol);
    }
    let chunked = match headers.get(header::TRANSFER_ENCODING) {
        None => false,
        Some(v) if v.as_bytes().eq_ignore_ascii_case(b"chunked") => true,
        Some(_) => return Err(Error::Protocol),
    };
    let length = match headers.get(header::CONTENT_LENGTH) {
        None => None,
        Some(v) => {
            let text = v.to_str().map_err(|_| Error::Protocol)?;
            if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Protocol);
            }
            Some(text.parse::<u64>().map_err(|_| Error::Protocol)?)
        }
    };
    let bodiless = parts.status == http::StatusCode::NO_CONTENT
        || parts.status == http::StatusCode::NOT_MODIFIED;
    if chunked && length.is_some() || !chunked && length.is_none() && !bodiless {
        return Err(Error::Protocol);
    }
    if length.is_some_and(|n| n > max_body as u64) {
        return Err(Error::TooLarge);
    }
    Ok(length)
}

#[cfg(test)]
#[path = "transport/tests.rs"]
mod tests;
