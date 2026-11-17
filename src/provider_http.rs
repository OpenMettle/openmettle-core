//! Configured provider transport (ADRs 0010/0011): one request per TLS connection.
//!
//! Every outbound byte goes to a deployment-configured HTTPS endpoint, after DNS answers pass an
//! address policy. hyper parses HTTP/1.1 and rustls (ring) performs TLS. The connection is driven
//! inside the caller's future: nothing HTTP- or credential-bearing is spawned, pooled, retried or
//! redirected, and dropping the future closes the socket. The only work that can outlive a dropped
//! request is a bounded operating-system DNS lookup (see `resolve`). Configured document GETs
//! share these bounds; metadata cannot select destinations. No
//! proxy, HTTP/2, compression, client certificate or early data.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{client::conn::http1, header};
use hyper_util::rt::TokioIo;
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse, http, url};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::{
    fmt,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::{net::TcpStream, sync::Semaphore, time::Instant};

/// Response body limit, equal to the login exchange bound and enforced while streaming.
pub const MAX_RESPONSE_BYTES: usize = crate::login::MAX_RESPONSE_BYTES;
/// Response header count and aggregate bytes (status line included), enforced by hyper's parser.
pub const MAX_RESPONSE_HEADERS: usize = 32;
pub const MAX_RESPONSE_HEADER_BYTES: usize = 8 * 1024;
/// hyper's minimum permitted connection read buffer.
const MAX_READ_BUFFER: usize = 8 * 1024;
/// Library request bounds: code, verifier, client and callback after form encoding.
pub const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024;
const MAX_REQUEST_HEADERS: usize = 4;
const MAX_REQUEST_HEADER_BYTES: usize = 1024;
/// More answers than this fail the request instead of being truncated.
pub const MAX_ADDRESSES: usize = 64;
pub const MAX_PRIVATE_RANGES: usize = 32;
const MAX_TRUST_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_TRUST_CERTIFICATES: usize = 256;
const MAX_ENDPOINT_BYTES: usize = 2048;
/// Process-wide limit on outstanding operating-system DNS lookups, including abandoned ones.
pub const DNS_LOOKUP_SLOTS: usize = 8;
/// Queue, lookup, TCP connect and TLS handshake share this budget.
pub const SETUP_DEADLINE: Duration = Duration::from_secs(5);
/// Whole request, matching (not extending) the login exchange deadline.
pub const TOTAL_DEADLINE: Duration = Duration::from_secs(10);

static DNS_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(DNS_LOOKUP_SLOTS)));

/// Fieldless, fixed-text errors: never a URL, host, address, header or body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Destination,
    Resolve,
    Address,
    Connect,
    Tls,
    Protocol,
    TooLarge,
    Timeout,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid provider transport configuration",
            Self::Destination => "provider request is not the configured destination",
            Self::Resolve => "provider name resolution failed",
            Self::Address => "provider address is not permitted",
            Self::Connect => "provider connection failed",
            Self::Tls => "provider TLS verification failed",
            Self::Protocol => "provider response was not acceptable",
            Self::TooLarge => "provider response exceeded limits",
            Self::Timeout => "provider request timed out",
        })
    }
}
impl std::error::Error for Error {}

/// Deployment-selected trust anchors. A bundle replaces the native roots; it never augments them.
pub enum Trust<'a> {
    /// Platform roots via rustls-native-certs; `SSL_CERT_FILE`/`SSL_CERT_DIR` are deployment
    /// authority when set. Any load error or an empty result fails closed.
    Native,
    /// PEM certificates only (1–256, ≤ 1 MiB). Any other PEM section or parse error fails closed.
    Bundle(&'a [u8]),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Range {
    network: IpAddr,
    prefix: u8,
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
/// Eligible only through an explicit per-provider allowlist entry.
const PRIVATE: [Range; 5] = [
    Range::v4([10, 0, 0, 0], 8),
    Range::v4([172, 16, 0, 0], 12),
    Range::v4([192, 168, 0, 0], 16),
    Range::v4([100, 64, 0, 0], 10),
    Range::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
];
/// IPv4 special-purpose blocks plus multicast. Globally reachable AS112/AMT/anycast blocks are
/// conservatively refused: no identity provider is expected there.
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

fn permitted(ip: IpAddr, allowed: &[Range]) -> bool {
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

fn private_range(value: &str) -> Result<Range, Error> {
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
struct Endpoint {
    url: String,
    host: String,
    port: u16,
    authority: String,
    path: String,
}
fn endpoint(value: &str) -> Result<Endpoint, Error> {
    if value.is_empty()
        || value.len() > MAX_ENDPOINT_BYTES
        || value.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || value.contains(['\\', '?', '#', '@', '%'])
    {
        return Err(Error::Configuration);
    }
    let parsed = url::Url::parse(value).map_err(|_| Error::Configuration)?;
    // Canonical input only: no case, default-port, dot-segment or encoding variants.
    if parsed.as_str() != value || parsed.scheme() != "https" || parsed.cannot_be_a_base() {
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
    })
}

fn roots(trust: Trust<'_>) -> Result<rustls::RootCertStore, Error> {
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

type Lookup = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;
fn system_lookup(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    // One more than the bound, so extra answers fail instead of being silently truncated.
    Ok((host, port)
        .to_socket_addrs()?
        .take(MAX_ADDRESSES + 1)
        .collect())
}

/// Token-endpoint transport for one provider. Implements the library's `AsyncHttpClient`.
#[derive(Clone)]
pub struct ProviderTransport {
    method: http::Method,
    trust_digest: [u8; 32],
    endpoint: Endpoint,
    allowed: Vec<Range>,
    tls: Arc<rustls::ClientConfig>,
    lookup: Lookup,
    slots: Arc<Semaphore>,
    setup: Duration,
    total: Duration,
    #[cfg(test)]
    loopback: bool,
}
impl fmt::Debug for ProviderTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderTransport(..)")
    }
}

impl ProviderTransport {
    /// `token_endpoint` and `private_ranges` are deployment configuration, never request input.
    /// Private ranges default to none: a self-hosted provider is reachable only when every DNS
    /// answer falls inside an explicit subnet of 10/8, 172.16/12, 192.168/16, 100.64/10 or fc00::/7.
    pub fn new(
        token_endpoint: &str,
        trust: Trust<'_>,
        private_ranges: &[&str],
    ) -> Result<Self, Error> {
        if private_ranges.len() > MAX_PRIVATE_RANGES {
            return Err(Error::Configuration);
        }
        let endpoint = endpoint(token_endpoint)?;
        let allowed = private_ranges
            .iter()
            .map(|r| private_range(r))
            .collect::<Result<Vec<_>, _>>()?;
        use sha2::{Digest, Sha256};
        let roots = roots(trust)?;
        let mut hash = Sha256::new();
        for root in &roots.roots {
            for value in [
                root.subject.as_ref(),
                root.subject_public_key_info.as_ref(),
                root.name_constraints
                    .as_ref()
                    .map(|v| v.as_ref())
                    .unwrap_or_default(),
            ] {
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value);
            }
        }
        let trust_digest = hash.finalize().into();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| Error::Configuration)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        Ok(Self {
            method: http::Method::POST,
            trust_digest,
            endpoint,
            allowed,
            tls: Arc::new(tls),
            lookup: Arc::new(system_lookup),
            slots: DNS_SLOTS.clone(),
            setup: SETUP_DEADLINE,
            total: TOTAL_DEADLINE,
            #[cfg(test)]
            loopback: false,
        })
    }

    fn address_permitted(&self, ip: IpAddr) -> bool {
        #[cfg(test)]
        if self.loopback
            && (ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST))
        {
            return true;
        }
        permitted(ip, &self.allowed)
    }

    /// Exact configured URL/method and bounded headers/body, before any DNS.
    /// The public token constructor remains POST-only; document GET permits only Accept.
    fn admit(&self, request: &HttpRequest) -> Result<(), Error> {
        let headers = request.headers();
        if request.method() != self.method
            || (self.method == http::Method::GET
                && (!request.body().is_empty() || headers.keys().any(|k| k != header::ACCEPT)))
            || request.uri().to_string() != self.endpoint.url
            || request.version() != http::Version::HTTP_11
            || request.body().len() > MAX_REQUEST_BODY_BYTES
            || headers.len() > MAX_REQUEST_HEADERS
            || headers.keys_len() != headers.len()
            || headers
                .iter()
                .map(|(k, v)| k.as_str().len() + v.len())
                .sum::<usize>()
                > MAX_REQUEST_HEADER_BYTES
            || headers
                .keys()
                .any(|k| k != header::ACCEPT && k != header::CONTENT_TYPE)
        {
            return Err(Error::Destination);
        }
        Ok(())
    }

    /// The OS lookup runs on Tokio's blocking pool and cannot be cancelled. Its slot permit moves
    /// into the blocking closure, so an abandoned lookup keeps its slot until it really finishes;
    /// at most `DNS_LOOKUP_SLOTS` lookups exist process-wide. Only the configured host and port
    /// enter the closure: no request, credential or HTTP state.
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

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        let start = Instant::now();
        let setup = start + self.setup;
        self.admit(&request)?;
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
        // Certificate validation uses the configured host name, never the connected address.
        let name =
            ServerName::try_from(self.endpoint.host.clone()).map_err(|_| Error::Configuration)?;
        let tls = tokio::time::timeout_at(
            setup,
            tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, tcp),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Tls)?;
        tokio::time::timeout_at(start + self.total, self.exchange(tls, request))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn exchange(
        &self,
        tls: tokio_rustls::client::TlsStream<TcpStream>,
        request: HttpRequest,
    ) -> Result<HttpResponse, Error> {
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(MAX_RESPONSE_HEADERS)
            .max_header_size(MAX_RESPONSE_HEADER_BYTES)
            .max_buf_size(MAX_READ_BUFFER)
            .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|_| Error::Protocol)?;
        let (parts, body) = request.into_parts();
        let mut outbound = http::Request::builder()
            .method(self.method.clone())
            .uri(self.endpoint.path.as_str())
            .header(header::HOST, self.endpoint.authority.as_str())
            .header(header::CONNECTION, "close");
        for (name, value) in &parts.headers {
            outbound = outbound.header(name, value);
        }
        let outbound = outbound
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| Error::Destination)?;
        // Driven here, never spawned: the connection lives exactly as long as this future.
        let response = async {
            let response = sender.send_request(outbound).await.map_err(hyper_error)?;
            read(response).await
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
async fn read(response: hyper::Response<hyper::body::Incoming>) -> Result<HttpResponse, Error> {
    let (parts, body) = response.into_parts();
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
    if length.is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
        return Err(Error::TooLarge);
    }
    let mut collected = Vec::with_capacity(length.unwrap_or(0) as usize);
    let mut body = Limited::new(body, MAX_RESPONSE_BYTES);
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

impl<'c> AsyncHttpClient<'c> for ProviderTransport {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Error>> + Send + 'c>>;
    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.send(request))
    }
}

/// Two deployment-configured document capabilities. No URL is accepted at fetch time.
#[derive(Clone)]
pub struct ProviderDocuments {
    discovery: ProviderTransport,
    jwks: ProviderTransport,
}
impl fmt::Debug for ProviderDocuments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderDocuments(..)")
    }
}
impl ProviderDocuments {
    pub(crate) fn configured(
        token: &ProviderTransport,
        discovery: &str,
        jwks: &str,
    ) -> Result<Self, Error> {
        let get = |url: &str| -> Result<ProviderTransport, Error> {
            let mut transport = token.clone();
            transport.endpoint = endpoint(url)?;
            transport.method = http::Method::GET;
            Ok(transport)
        };
        Ok(Self {
            discovery: get(discovery)?,
            jwks: get(jwks)?,
        })
    }
    pub async fn fetch_discovery(&self) -> Result<HttpResponse, Error> {
        Self::fetch(&self.discovery).await
    }
    pub async fn fetch_jwks(&self) -> Result<HttpResponse, Error> {
        Self::fetch(&self.jwks).await
    }
    async fn fetch(transport: &ProviderTransport) -> Result<HttpResponse, Error> {
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(&transport.endpoint.url)
            .header(header::ACCEPT, "application/json, application/jwk-set+json")
            .body(Vec::new())
            .map_err(|_| Error::Destination)?;
        transport.send(request).await
    }
}
impl ProviderTransport {
    // Hash the effective roots, not a caller-provided policy label. Address policy is included.
    pub(crate) fn policy_binding(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        // Construction fingerprints the effective trust anchors, including name constraints.
        digest.update(self.trust_digest);
        for range in &self.allowed {
            let network = range.network.to_string();
            digest.update((network.len() as u64).to_be_bytes());
            digest.update(network.as_bytes());
            digest.update([range.prefix]);
        }
        digest.finalize().to_vec()
    }
}

/// Test seams. They exist only in `cfg(test)` builds; production construction is `new` only.
#[cfg(test)]
impl ProviderTransport {
    pub(crate) fn with_lookup(
        mut self,
        lookup: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.lookup = Arc::new(lookup);
        self
    }
    /// A private slot pool and shorter deadlines; the production pool stays process-wide.
    pub(crate) fn with_limits(
        mut self,
        slots: Arc<Semaphore>,
        setup: Duration,
        total: Duration,
    ) -> Self {
        self.slots = slots;
        self.setup = setup;
        self.total = total;
        self
    }
    /// Permits 127.0.0.1 and ::1 only, for the in-process TLS fixture.
    pub(crate) fn allow_loopback_fixture(mut self) -> Self {
        self.loopback = true;
        self
    }
}

#[cfg(test)]
#[path = "../tests/provider_http_support/mod.rs"]
pub(crate) mod fixture;

#[cfg(test)]
#[path = "../tests/provider_http_support/tests.rs"]
mod tests;
