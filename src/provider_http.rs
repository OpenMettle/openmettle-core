//! Configured provider transport (ADRs 0010/0011): one request per TLS connection.
//!
//! Every outbound byte goes to a deployment-configured HTTPS endpoint, after DNS answers pass an
//! address policy. hyper parses HTTP/1.1 and rustls (ring) performs TLS. The connection is driven
//! inside the caller's future: nothing HTTP- or credential-bearing is spawned, pooled, retried or
//! redirected, and dropping the future closes the socket. The only work that can outlive a dropped
//! request is a bounded operating-system DNS lookup (see `transport`). Configured document GETs
//! share these bounds; metadata cannot select destinations. No
//! proxy, HTTP/2, compression, client certificate or early data.
//!
//! The reusable bounded HTTP/1.1 core lives in [`transport`]; this module adds the provider's
//! request admission, its process-wide DNS slot pool and its limits.
use crate::{
    authz::gateway::Dispatch,
    model_config::{Catalog, Effective},
};
use hyper::header::{self, HeaderValue};
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse, http};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::Semaphore;

pub mod gateway;
pub mod inference;
pub(crate) mod transport;
use transport::{Endpoint, Limits, Lookup, Range, Route, endpoint, private_range};
// Names the existing provider tests reach through `use super::*`.
#[cfg(test)]
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
#[cfg(test)]
use transport::permitted;

/// Response body limit, equal to the login exchange bound and enforced while streaming.
pub const MAX_RESPONSE_BYTES: usize = crate::login::MAX_RESPONSE_BYTES;
/// Response header count and aggregate bytes (status line included), enforced by hyper's parser.
pub const MAX_RESPONSE_HEADERS: usize = 32;
pub const MAX_RESPONSE_HEADER_BYTES: usize = 8 * 1024;
/// Library request bounds: code, verifier, client and callback after form encoding.
pub const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024;
const MAX_REQUEST_HEADERS: usize = 4;
pub const MAX_REQUEST_HEADER_BYTES: usize = 1024;
/// More answers than this fail the request instead of being truncated.
pub const MAX_ADDRESSES: usize = 64;
pub const MAX_PRIVATE_RANGES: usize = 32;
/// Trust bundle ceiling, shared with the deployment loader's bounded file read.
pub const MAX_TRUST_BUNDLE_BYTES: usize = 1024 * 1024;
/// Process-wide limit on outstanding operating-system DNS lookups, including abandoned ones.
pub const DNS_LOOKUP_SLOTS: usize = 8;
/// Queue, lookup, TCP connect and TLS handshake share this budget.
pub const SETUP_DEADLINE: Duration = Duration::from_secs(5);
/// Whole request, matching (not extending) the login exchange deadline.
pub const TOTAL_DEADLINE: Duration = Duration::from_secs(10);

/// Provider transports share this pool; other outbound clients own separate pools.
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

/// Token-endpoint transport for one provider. Implements the library's `AsyncHttpClient`.
#[derive(Clone)]
pub struct ProviderTransport {
    operation: crate::telemetry::metrics::ProviderOperation,
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
        let roots = transport::roots(trust)?;
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
        Ok(Self {
            operation: crate::telemetry::metrics::ProviderOperation::Token,
            method: http::Method::POST,
            trust_digest,
            endpoint,
            allowed,
            tls: transport::client_config(roots)?,
            lookup: Arc::new(transport::system_lookup),
            slots: DNS_SLOTS.clone(),
            setup: SETUP_DEADLINE,
            total: TOTAL_DEADLINE,
            #[cfg(test)]
            loopback: false,
        })
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

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, Error> {
        use crate::telemetry::metrics::{self, ProviderOutcome};
        let started = std::time::Instant::now();
        let result = async {
            self.admit(&request)?;
            let route = Route {
                endpoint: &self.endpoint,
                allowed: &self.allowed,
                tls: &self.tls,
                lookup: &self.lookup,
                slots: &self.slots,
                #[cfg(test)]
                loopback: self.loopback,
            };
            let limits = Limits {
                request_body: MAX_REQUEST_BODY_BYTES,
                response_body: MAX_RESPONSE_BYTES,
                response_headers: MAX_RESPONSE_HEADERS,
                response_header_bytes: MAX_RESPONSE_HEADER_BYTES,
                setup: self.setup,
                total: self.total,
            };
            let (parts, body) = request.into_parts();
            route
                .send(parts.method, &parts.headers, body, &limits)
                .await
        }
        .await;
        let outcome = match &result {
            Ok(response) if response.status().is_success() => ProviderOutcome::Ok,
            Ok(_) => ProviderOutcome::HttpError,
            Err(Error::Timeout) => ProviderOutcome::Timeout,
            Err(Error::Destination | Error::Address | Error::Configuration) => {
                ProviderOutcome::Refused
            }
            Err(Error::TooLarge) => ProviderOutcome::BodyLimit,
            Err(Error::Resolve | Error::Connect | Error::Tls | Error::Protocol) => {
                ProviderOutcome::Transport
            }
        };
        metrics::global().record_provider_http(self.operation, outcome, started.elapsed());
        result
    }
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
        use crate::telemetry::metrics::ProviderOperation;
        let get = |url: &str, operation: ProviderOperation| -> Result<ProviderTransport, Error> {
            let mut transport = token.clone();
            transport.operation = operation;
            transport.endpoint = endpoint(url)?;
            transport.method = http::Method::GET;
            Ok(transport)
        };
        Ok(Self {
            discovery: get(discovery, ProviderOperation::Discovery)?,
            jwks: get(jwks, ProviderOperation::Jwks)?,
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

#[cfg(test)]
#[path = "../tests/provider_inference/redaction.rs"]
mod inference_redaction;

/// Borrowed view over an installation and pinned inference route for single-use billable sends.
pub struct BillableInferenceRef<'a> {
    pub installation: &'a str,
    pub route: &'a inference::Gateway,
}

impl BillableInferenceRef<'_> {
    pub async fn send<F: Future<Output = ()>>(
        &self,
        dispatch: Dispatch,
        catalog: &Catalog,
        effective: &Effective,
        request: &inference::Request,
        run: Option<inference::RunStop>,
        visible: impl FnMut(inference::VisibleDelta) -> F,
    ) -> Result<inference::Turn, inference::Error> {
        if self.installation != dispatch.installation
            || effective.model != dispatch.model
            || dispatch.server != run.is_some()
        {
            return Err(inference::Error::Credential);
        }
        let id = HeaderValue::from_str(&dispatch.id).map_err(|_| inference::Error::Credential)?;
        let token = dispatch
            .authorization
            .to_str()
            .ok()
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(inference::Error::Credential)?;
        let cred = inference::Credential::Bearer(token);
        transport::BILLABLE_REQUEST
            .scope(std::cell::Cell::new(Some(id)), async {
                match run {
                    Some(stop) => {
                        self.route
                            .server(catalog, effective, request, cred, stop, visible)
                            .await
                    }
                    None => {
                        self.route
                            .caller(catalog, effective, request, cred, visible)
                            .await
                    }
                }
            })
            .await
    }
}

/// Couples the installation, authorized model and call identity to the existing
/// inference codecs. The database connection is returned before this method runs.
pub struct BillableInference {
    pub installation: String,
    pub route: inference::Gateway,
}
impl BillableInference {
    pub async fn send<F: Future<Output = ()>>(
        &self,
        dispatch: Dispatch,
        catalog: &Catalog,
        effective: &Effective,
        request: &inference::Request,
        run: Option<inference::RunStop>,
        visible: impl FnMut(inference::VisibleDelta) -> F,
    ) -> Result<inference::Turn, inference::Error> {
        BillableInferenceRef {
            installation: &self.installation,
            route: &self.route,
        }
        .send(dispatch, catalog, effective, request, run, visible)
        .await
    }
}
