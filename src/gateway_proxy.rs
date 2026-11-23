//! `openmettle-gateway`, increment 1 of OpenMettle's own inference proxy (V1-06). It accepts
//! `POST /v1/chat/completions`, forwards it to one plain-HTTP upstream (SGLang) and writes the
//! usage the upstream reported through [`settlement::ingest`], connected as
//! `openmettle_gateway`.
//!
//! - **Correlation.** The caller names a handed-off gateway request in `x-request-id`. The
//!   report's routing fields come from that stored row, never from the caller. An unusable or
//!   unknown ID is refused before anything is sent upstream.
//! - **Forwarding.** The request body goes upstream byte for byte, with only `Content-Type`,
//!   `Accept`, `Accept-Encoding: identity` and the request ID; `Authorization`, cookies and
//!   fields the caller names in `Connection` are not forwarded. The upstream status,
//!   `Content-Type` and body are relayed chunk by chunk as they arrive. Only identity bodies
//!   pass in either direction.
//! - **Usage.** One relay task per request copies each upstream chunk to the caller and to the
//!   usage reader and then writes at most one final report itself, so the write does not depend
//!   on the caller staying connected. A response that is not a completed 200 with a usage object
//!   leaves no report and one `gateway.usage.unrecorded` event; the hold stays as it was.
//!
//! Not deployable: this increment has no caller authentication and no model enforcement. See
//! `docs/operator/gateway-proxy.md`.
mod usage;

use crate::{
    authz::gateway::{Error as StoreError, settlement},
    bounded_positive,
    provider_http::gateway::UsageReport,
    runs::is_canonical_uuid,
    telemetry::{self, RequestId, UsageGap},
    v1::{Problem, problem},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header, uri::Authority},
    response::Response,
    routing::post,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body as _, Frame, Incoming, SizeHint},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use sqlx::PgPool;
use std::{
    future::Future,
    net::Ipv6Addr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, watch},
    time::{Instant, sleep_until, timeout},
};
use usage::{Extract, Usage};

/// The one route this increment serves, forwarded to the same path upstream.
pub const ROUTE: &str = "/v1/chat/completions";
/// Largest caller request body: the worker's largest inference request.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Longest wait for the caller's request body.
const REQUEST_READ: Duration = Duration::from_secs(10);
/// Upstream chunks held for a caller that reads more slowly than the upstream writes.
const RELAY_BUFFER: usize = 8;
/// Pauses before the second and third attempt to store a report after a transient failure.
const WRITE_RETRIES: [Duration; 2] = [Duration::from_millis(100), Duration::from_millis(500)];
/// Each attempt to store a report gets this many `DB_TIMEOUT_MS` before it is abandoned and
/// retried, also when its database connection has stopped answering.
const WRITE_ATTEMPT_TIMEOUTS: u32 = 5;
/// SGLang counts reasoning tokens inside `completion_tokens` (recorded 23 Nov 2026), so
/// settlement must not add them again.
const REASONING_INCLUDED: bool = true;

const CORRELATION: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request needs one x-request-id header holding a canonical lowercase UUID.",
);
const UNKNOWN: Problem = problem(
    StatusCode::NOT_FOUND,
    "not_found",
    "No handed-off gateway request matches the x-request-id header.",
);
const BODY: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request body exceeds 2 MiB or did not arrive in time.",
);
const ENCODED_REQUEST: Problem = problem(
    StatusCode::UNSUPPORTED_MEDIA_TYPE,
    "unsupported_media_type",
    "Only an identity-encoded request body is accepted.",
);
const UNAVAILABLE: Problem = problem(
    StatusCode::SERVICE_UNAVAILABLE,
    "unavailable",
    "The service is temporarily unavailable; try again later.",
);
const UPSTREAM: Problem = problem(
    StatusCode::BAD_GATEWAY,
    "provider_failure",
    "The model server could not be reached.",
);
const ENCODED_RESPONSE: Problem = problem(
    StatusCode::BAD_GATEWAY,
    "provider_failure",
    "The model server answered with an unsupported content encoding.",
);
const UPSTREAM_TIMEOUT: Problem = problem(
    StatusCode::GATEWAY_TIMEOUT,
    "timeout",
    "The model server did not answer in time.",
);

/// The gateway's own settings, read after the shared process settings.
#[derive(Clone, Debug)]
pub(crate) struct Settings {
    upstream: Authority,
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl Settings {
    /// `UPSTREAM_URL` (required), `UPSTREAM_CONNECT_TIMEOUT_MS` and
    /// `UPSTREAM_IDLE_TIMEOUT_MS`. Refusals name the key, never the value.
    pub(crate) fn parse(
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Self, &'static str> {
        let url = get("UPSTREAM_URL")?.ok_or("UPSTREAM_URL is required")?;
        let upstream = origin(&url)?;
        let millis = |key, default, max| -> Result<Duration, &'static str> {
            Ok(Duration::from_millis(bounded_positive(
                get(key)?,
                default,
                max,
            )?))
        };
        Ok(Self {
            upstream,
            connect_timeout: millis("UPSTREAM_CONNECT_TIMEOUT_MS", 5_000, 30_000)?,
            idle_timeout: millis("UPSTREAM_IDLE_TIMEOUT_MS", 120_000, 3_600_000)?,
        })
    }

    async fn connect(&self) -> Result<TcpStream, UsageGap> {
        let host = self.upstream.host();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = self.upstream.port_u16().unwrap_or(80);
        match timeout(self.connect_timeout, TcpStream::connect((host, port))).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(_)) => Err(UsageGap::UpstreamTransport),
            Err(_) => Err(UsageGap::UpstreamTimeout),
        }
    }
}

/// An `http://host[:port]` origin with at most a `/` path. TLS is not supported in this
/// increment; user information, another path, a query and a fragment are refused. A bracketed
/// host must be an IPv6 address, followed by nothing or by a port.
fn origin(url: &str) -> Result<Authority, &'static str> {
    const INVALID: &str = "invalid UPSTREAM_URL";
    let uri: Uri = url.parse().map_err(|_| INVALID)?;
    match uri.scheme_str() {
        Some("http") => {}
        Some(_) => return Err("UPSTREAM_URL must use http://"),
        None => return Err(INVALID),
    }
    let authority = uri.authority().ok_or(INVALID)?;
    let host = authority.host();
    let host_valid = match host.strip_prefix('[') {
        Some(literal) => literal
            .strip_suffix(']')
            .is_some_and(|address| address.parse::<Ipv6Addr>().is_ok()),
        None => !host.is_empty() && !host.contains(['[', ']']),
    };
    let port_valid = match authority.as_str().strip_prefix(host) {
        Some("") => true,
        Some(port) => port.strip_prefix(':').is_some_and(|port| {
            port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|p| p > 0)
        }),
        None => false,
    };
    if host_valid
        && port_valid
        && !authority.as_str().contains('@')
        && !url.contains('#')
        && matches!(uri.path_and_query().map(|p| p.as_str()), None | Some("/"))
    {
        Ok(authority.clone())
    } else {
        Err(INVALID)
    }
}

/// The values of `name`, unless the message's `Connection` field names it as hop-by-hop.
fn end_to_end<'h>(
    headers: &'h HeaderMap,
    name: &HeaderName,
) -> impl Iterator<Item = &'h HeaderValue> {
    let hop_by_hop = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name.as_str()));
    headers.get_all(name).iter().filter(move |_| !hop_by_hop)
}

/// No content coding other than `identity`.
fn identity(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .all(|value| {
            value.to_str().is_ok_and(|codings| {
                codings
                    .split(',')
                    .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
            })
        })
}

/// Relay tasks still running. Shutdown waits for them after the listener has drained, so a
/// report whose usage was read is written before the pool closes.
#[derive(Clone)]
pub(crate) struct Relays(Arc<watch::Sender<usize>>);

impl Relays {
    fn new() -> Self {
        Self(Arc::new(watch::Sender::new(0)))
    }
    fn start(&self) -> Running {
        self.0.send_modify(|n| *n += 1);
        Running(self.0.clone())
    }
    pub(crate) async fn idle(&self) {
        let _ = self.0.subscribe().wait_for(|n| *n == 0).await;
    }
}

struct Running(Arc<watch::Sender<usize>>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

struct Proxy {
    settings: Settings,
    pool: PgPool,
    database_timeout: Duration,
    relays: Relays,
}

/// The proxy route over `pool`, which must be a login of `openmettle_gateway`, and the handle
/// shutdown uses to wait for running relays.
pub(crate) fn router(
    settings: Settings,
    pool: PgPool,
    database_timeout: Duration,
) -> (Router, Relays) {
    let relays = Relays::new();
    let proxy = Arc::new(Proxy {
        settings,
        pool,
        database_timeout,
        relays: relays.clone(),
    });
    (
        Router::new().route(ROUTE, post(forward)).with_state(proxy),
        relays,
    )
}

async fn forward(State(proxy): State<Arc<Proxy>>, request: Request) -> Response {
    let id = request.extensions().get::<RequestId>().copied();
    match proxy.forward(request).await {
        Ok(response) => response,
        Err(problem) => problem.response(id),
    }
}

/// The routing fields of a handed-off request, as stored.
struct Routing {
    installation: String,
    principal: String,
    scope: String,
    source: String,
}

/// Exactly one `x-request-id` holding a canonical lowercase UUID.
fn correlation(headers: &HeaderMap) -> Result<String, Problem> {
    let mut values = headers.get_all("x-request-id").iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|id| is_canonical_uuid(id))
            .map(str::to_owned)
            .ok_or(CORRELATION),
        _ => Err(CORRELATION),
    }
}

impl Proxy {
    async fn forward(&self, request: Request) -> Result<Response, Problem> {
        let (parts, body) = request.into_parts();
        let id = correlation(&parts.headers)?;
        if !identity(&parts.headers) {
            return Err(ENCODED_REQUEST);
        }
        let routing = self.routing(&id).await?;
        // From here on, every early end, including the server dropping this handler because the
        // caller left, logs why nothing was recorded.
        let mut unrecorded = Unrecorded {
            id: &id,
            gap: Some(UsageGap::RequestBody),
        };
        let body = match timeout(REQUEST_READ, axum::body::to_bytes(body, MAX_REQUEST_BYTES)).await
        {
            Ok(Ok(body)) => body,
            _ => return Err(BODY),
        };
        let mut outbound = hyper::Request::post(ROUTE)
            .header(header::HOST, self.settings.upstream.as_str())
            .header(header::CONNECTION, "close")
            .header(header::ACCEPT_ENCODING, "identity")
            .header("x-request-id", &id)
            .body(Full::new(body))
            .map_err(|_| CORRELATION)?;
        for name in [header::CONTENT_TYPE, header::ACCEPT] {
            for value in end_to_end(&parts.headers, &name) {
                outbound.headers_mut().append(name.clone(), value.clone());
            }
        }
        unrecorded.gap = Some(UsageGap::CallerDisconnected);
        let (upstream, response) = match self.exchange(outbound).await {
            Ok(exchanged) => exchanged,
            Err(gap) => {
                unrecorded.gap = Some(gap);
                return Err(match gap {
                    UsageGap::UpstreamTimeout => UPSTREAM_TIMEOUT,
                    _ => UPSTREAM,
                });
            }
        };
        let (head, body) = response.into_parts();
        // Neither relayed unlabelled nor read for usage; the upstream connection closes here.
        if !identity(&head.headers) {
            unrecorded.gap = Some(UsageGap::UpstreamEncoding);
            return Err(ENCODED_RESPONSE);
        }
        unrecorded.gap = None;
        drop(unrecorded);
        let (frames, receiver) = mpsc::channel(RELAY_BUFFER);
        let complete = Arc::new(AtomicBool::new(false));
        let mut relayed = Response::new(Body::new(Relayed {
            frames: receiver,
            complete: complete.clone(),
            hint: body.size_hint(),
            ended: false,
        }));
        *relayed.status_mut() = head.status;
        for value in end_to_end(&head.headers, &header::CONTENT_TYPE) {
            relayed
                .headers_mut()
                .append(header::CONTENT_TYPE, value.clone());
        }
        let relay = Relay {
            extract: (head.status == StatusCode::OK)
                .then(|| Extract::new(head.headers.get(header::CONTENT_TYPE))),
            id,
            routing,
            upstream,
            body,
            frames,
            complete,
            delivering: true,
            drain_by: None,
            idle: self.settings.idle_timeout,
            pool: self.pool.clone(),
            write_limit: self.database_timeout * WRITE_ATTEMPT_TIMEOUTS,
            _running: self.relays.start(),
        };
        tokio::spawn(relay.run());
        Ok(relayed)
    }

    /// The stored routing fields of `id` while it is handed off.
    async fn routing(&self, id: &str) -> Result<Routing, Problem> {
        let row = sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT q.installation::text, b.principal::text, q.scope_id::text,
                    q.report_source::text
               FROM openmettle.gateway_requests q
               JOIN openmettle.gateway_bindings b ON b.id = q.binding_id
              WHERE q.id = $1::uuid AND q.state = 'handed_off'",
        )
        .bind(id)
        .fetch_optional(&self.pool);
        match timeout(self.database_timeout, row).await {
            Ok(Ok(Some((installation, principal, scope, source)))) => Ok(Routing {
                installation,
                principal,
                scope,
                source,
            }),
            Ok(Ok(None)) => Err(UNKNOWN),
            _ => Err(UNAVAILABLE),
        }
    }

    /// Sends `outbound` on a new connection and waits for the response head.
    async fn exchange(
        &self,
        outbound: hyper::Request<Full<Bytes>>,
    ) -> Result<(Upstream, hyper::Response<Incoming>), UsageGap> {
        let stream = self.settings.connect().await?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| UsageGap::UpstreamTransport)?;
        let mut upstream = Upstream {
            connection: Box::pin(connection),
            open: true,
        };
        let head = timeout(self.settings.idle_timeout, sender.send_request(outbound));
        match upstream.drive(head).await {
            Ok(Ok(response)) => Ok((upstream, response)),
            Ok(Err(_)) => Err(UsageGap::UpstreamTransport),
            Err(_) => Err(UsageGap::UpstreamTimeout),
        }
    }
}

/// Logs `gap` for a handled request that ends before its relay starts: a refusal after the
/// lookup, or the server dropping the handler because the caller left, which also closes the
/// upstream connection.
struct Unrecorded<'a> {
    id: &'a str,
    gap: Option<UsageGap>,
}

impl Drop for Unrecorded<'_> {
    fn drop(&mut self) {
        if let Some(gap) = self.gap {
            telemetry::gateway_usage_unrecorded(self.id, gap);
        }
    }
}

/// One upstream connection. It is polled only while its owner waits on it and never spawned,
/// so dropping it closes the connection.
struct Upstream {
    connection: Pin<Box<http1::Connection<TokioIo<TcpStream>, Full<Bytes>>>>,
    open: bool,
}

impl Upstream {
    async fn drive<T>(&mut self, work: impl Future<Output = T>) -> T {
        tokio::pin!(work);
        loop {
            tokio::select! {
                out = &mut work => return out,
                // A connection failure also reaches the response or body future.
                _ = &mut self.connection, if self.open => self.open = false,
            }
        }
    }
}

/// What the caller reads: the upstream's chunks as they arrive. It ends cleanly only after the
/// upstream body did and the caller received every chunk. Any other end is an error, so the
/// caller gets a prefix of the upstream bytes and an unclean end, never a response that looks
/// complete; how much of the prefix still reaches it is not promised.
struct Relayed {
    frames: mpsc::Receiver<Bytes>,
    complete: Arc<AtomicBool>,
    hint: SizeHint,
    ended: bool,
}

impl hyper::body::Body for Relayed {
    type Data = Bytes;
    type Error = Cut;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Cut>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        Poll::Ready(match ready!(self.frames.poll_recv(cx)) {
            Some(data) => Some(Ok(Frame::data(data))),
            None => {
                self.ended = true;
                (!self.complete.load(Ordering::Acquire)).then_some(Err(Cut))
            }
        })
    }

    fn size_hint(&self) -> SizeHint {
        self.hint
    }
}

/// The upstream response ended early or failed.
#[derive(Debug)]
struct Cut;

impl std::fmt::Display for Cut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upstream response cut")
    }
}

impl std::error::Error for Cut {}

/// Copies one upstream body to the caller and the usage reader, then reports.
struct Relay {
    id: String,
    routing: Routing,
    upstream: Upstream,
    body: Incoming,
    frames: mpsc::Sender<Bytes>,
    complete: Arc<AtomicBool>,
    /// `None` unless the upstream answered 200.
    extract: Option<Extract>,
    /// Whether the caller still gets every chunk.
    delivering: bool,
    /// Set once the caller has gone: the rest of the body must arrive by then.
    drain_by: Option<Instant>,
    idle: Duration,
    pool: PgPool,
    /// Bound on each attempt to store the report.
    write_limit: Duration,
    _running: Running,
}

impl Relay {
    async fn run(mut self) {
        let copied = self.copy().await;
        if copied.is_ok() && self.delivering {
            self.complete.store(true, Ordering::Release);
        }
        let Self {
            id,
            routing,
            upstream,
            body,
            frames,
            extract,
            pool,
            write_limit,
            _running,
            ..
        } = self;
        // Close the upstream connection and end the caller's body before writing.
        drop((upstream, body, frames));
        let usage = match (extract, copied) {
            (None, _) => Err(UsageGap::UpstreamStatus),
            (Some(_), Err(gap)) => Err(gap),
            (Some(extract), Ok(())) => extract.finish(),
        };
        match usage {
            Ok(usage) => record(&pool, &report(id, routing, usage), write_limit).await,
            Err(gap) => telemetry::gateway_usage_unrecorded(&id, gap),
        }
    }

    /// Reads the upstream body to its end. The caller gets every chunk until it leaves or stops
    /// reading; after that the rest is read only while the usage may still be in hand, checked
    /// after every read, and within one idle timeout in total. Otherwise the upstream
    /// connection is dropped.
    async fn copy(&mut self) -> Result<(), UsageGap> {
        loop {
            let drain_by = self.drain_by;
            let frame = tokio::select! {
                () = self.frames.closed(), if self.delivering => {
                    self.detach()?;
                    continue;
                }
                () = sleep_until(drain_by.unwrap_or_else(Instant::now)), if drain_by.is_some() => {
                    return Err(UsageGap::UpstreamTimeout);
                }
                frame = self.upstream.drive(timeout(self.idle, self.body.frame())) => frame,
            };
            let data = match frame {
                Err(_) => return Err(UsageGap::UpstreamTimeout),
                Ok(None) => return Ok(()),
                Ok(Some(Err(_))) => return Err(UsageGap::Incomplete),
                Ok(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => data,
                    // Trailers carry no body bytes.
                    Err(_) => continue,
                },
            };
            if let Some(extract) = &mut self.extract {
                extract.feed(&data);
            }
            if self.delivering {
                // A caller that takes no chunk for an idle timeout is treated as gone.
                if !matches!(timeout(self.idle, self.frames.send(data)).await, Ok(Ok(()))) {
                    self.detach()?;
                }
            } else if !self.draining() {
                return Err(UsageGap::CallerDisconnected);
            }
        }
    }

    /// The caller has gone or stopped reading, so it will not get the rest. Reading on is worth
    /// it only while the usage may already be in hand.
    fn detach(&mut self) -> Result<(), UsageGap> {
        self.delivering = false;
        if !self.draining() {
            return Err(UsageGap::CallerDisconnected);
        }
        self.drain_by = Some(Instant::now() + self.idle);
        Ok(())
    }

    fn draining(&self) -> bool {
        self.extract.as_ref().is_some_and(Extract::worth_draining)
    }
}

/// One final report built from the stored routing fields. The proxy writes at most one report
/// per request, so the report takes the request's own ID at revision 0: a retry, or a repeated
/// dispatch of the same request with the same usage, writes the identical report, which
/// settlement accepts once.
fn report(id: String, routing: Routing, usage: Usage) -> UsageReport {
    UsageReport {
        report_id: id.clone(),
        request: id,
        installation: routing.installation,
        principal: routing.principal,
        scope: routing.scope,
        source: routing.source,
        revision: 0,
        r#final: true,
        prompt_tokens: Some(usage.prompt),
        completion_tokens: Some(usage.completion),
        reasoning_tokens: usage.reasoning,
        reasoning_included: usage.reasoning.map(|_| REASONING_INCLUDED),
        cost: None,
        unit: None,
    }
}

/// Stores `report`, retrying a transient database failure twice. Each attempt is bounded by
/// `limit`: an abandoned attempt rolls back when its connection is next used, and sqlx tests a
/// connection before it rejoins the pool. An identical report is accepted again as a duplicate,
/// so a retry after an ambiguous commit is safe. No local spool.
async fn record(pool: &PgPool, report: &UsageReport, limit: Duration) {
    let mut attempt = 0;
    loop {
        let outcome = timeout(limit, settlement::ingest(pool, report))
            .await
            .unwrap_or(Err(StoreError::Database));
        match outcome {
            Ok(_) => return,
            Err(StoreError::Database | StoreError::Retryable) if attempt < WRITE_RETRIES.len() => {
                tokio::time::sleep(WRITE_RETRIES[attempt]).await;
                attempt += 1;
            }
            Err(error) => return telemetry::gateway_usage_failed(&report.request, &error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(pairs: &[(&str, &str)]) -> Result<Settings, &'static str> {
        Settings::parse(|key| {
            Ok(pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_owned()))
        })
    }

    #[test]
    fn upstream_must_be_a_plain_http_origin() {
        for (url, host) in [
            ("http://127.0.0.1:30000", "127.0.0.1:30000"),
            ("http://127.0.0.1:30000/", "127.0.0.1:30000"),
            ("http://sglang.models.svc:30000", "sglang.models.svc:30000"),
            ("http://[::1]:30000", "[::1]:30000"),
            ("http://[::1]", "[::1]"),
            ("http://localhost", "localhost"),
        ] {
            let settings = parse(&[("UPSTREAM_URL", url)]).unwrap();
            assert_eq!(settings.upstream.as_str(), host, "{url}");
            assert_eq!(settings.connect_timeout, Duration::from_secs(5));
            assert_eq!(settings.idle_timeout, Duration::from_secs(120));
        }
        for (url, refusal) in [
            ("https://127.0.0.1:30000", "UPSTREAM_URL must use http://"),
            ("ftp://127.0.0.1:30000", "UPSTREAM_URL must use http://"),
            ("127.0.0.1:30000", "invalid UPSTREAM_URL"),
            ("", "invalid UPSTREAM_URL"),
            ("http://", "invalid UPSTREAM_URL"),
            ("http://user@127.0.0.1:30000", "invalid UPSTREAM_URL"),
            ("http://127.0.0.1:30000/v1", "invalid UPSTREAM_URL"),
            ("http://127.0.0.1:30000/?a=b", "invalid UPSTREAM_URL"),
            ("http://127.0.0.1:30000/#a", "invalid UPSTREAM_URL"),
            ("http://127.0.0.1:99999", "invalid UPSTREAM_URL"),
            ("http://127.0.0.1:0", "invalid UPSTREAM_URL"),
            ("http://127.0.0.1:", "invalid UPSTREAM_URL"),
            ("http://exa mple", "invalid UPSTREAM_URL"),
            ("http://[::1]typo:8080", "invalid UPSTREAM_URL"),
            ("http://[]:8080", "invalid UPSTREAM_URL"),
            ("http://[127.0.0.1]:8080", "invalid UPSTREAM_URL"),
            ("http://[::1]:+80", "invalid UPSTREAM_URL"),
            ("http://a]b:8080", "invalid UPSTREAM_URL"),
        ] {
            assert_eq!(
                parse(&[("UPSTREAM_URL", url)]).err(),
                Some(refusal),
                "{url}"
            );
        }
        assert_eq!(parse(&[]).err(), Some("UPSTREAM_URL is required"));
    }

    #[test]
    fn upstream_timeouts_are_bounded() {
        let url = ("UPSTREAM_URL", "http://127.0.0.1:30000");
        let settings = parse(&[
            url,
            ("UPSTREAM_CONNECT_TIMEOUT_MS", "250"),
            ("UPSTREAM_IDLE_TIMEOUT_MS", "3600000"),
        ])
        .unwrap();
        assert_eq!(settings.connect_timeout, Duration::from_millis(250));
        assert_eq!(settings.idle_timeout, Duration::from_secs(3600));
        for (key, value) in [
            ("UPSTREAM_CONNECT_TIMEOUT_MS", "0"),
            ("UPSTREAM_CONNECT_TIMEOUT_MS", "30001"),
            ("UPSTREAM_IDLE_TIMEOUT_MS", "3600001"),
            ("UPSTREAM_IDLE_TIMEOUT_MS", "soon"),
        ] {
            assert!(parse(&[url, (key, value)]).is_err(), "{key}={value}");
        }
    }

    #[test]
    fn correlation_takes_exactly_one_canonical_id() {
        let id = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let mut headers = HeaderMap::new();
        assert_eq!(correlation(&headers), Err(CORRELATION));
        headers.insert("x-request-id", id.parse().unwrap());
        assert_eq!(correlation(&headers).as_deref(), Ok(id));
        headers.append("x-request-id", id.parse().unwrap());
        assert_eq!(correlation(&headers), Err(CORRELATION));
        for bad in [
            "0F8FAD5B-D9CB-469F-A165-70867728950E",
            "0f8fad5bd9cb469fa16570867728950e",
            "{0f8fad5b-d9cb-469f-a165-70867728950e}",
            "",
        ] {
            headers.insert("x-request-id", bad.parse().unwrap());
            assert_eq!(correlation(&headers), Err(CORRELATION), "{bad}");
        }
    }

    #[test]
    fn a_report_takes_its_identity_from_the_request() {
        let routing = || Routing {
            installation: "00000000-0000-4000-8000-000000000001".into(),
            principal: "00000000-0000-4000-8000-000000000002".into(),
            scope: "00000000-0000-4000-8000-000000000003".into(),
            source: "00000000-0000-4000-8000-000000000004".into(),
        };
        let id = "0f8fad5b-d9cb-469f-a165-70867728950e";
        let usage = Usage {
            prompt: 67,
            completion: 37,
            reasoning: Some(33),
        };
        let first = report(id.into(), routing(), usage);
        let again = report(id.into(), routing(), usage);
        assert!(first.valid());
        assert_eq!(
            (first.report_id.as_str(), first.revision, first.r#final),
            (id, 0, true)
        );
        assert_eq!(
            serde_json::to_value(&first).unwrap(),
            serde_json::to_value(&again).unwrap()
        );
        // Reasoning is inside the completion count, so it is not added again.
        assert_eq!(first.reasoning_included, Some(true));
        assert_eq!(first.measured(), Some(67 + 37));
        let plain = report(
            id.into(),
            routing(),
            Usage {
                reasoning: None,
                ..usage
            },
        );
        assert_eq!(
            (plain.reasoning_tokens, plain.reasoning_included),
            (None, None)
        );
    }
}
