//! `openmettle-gateway`, OpenMettle's own inference proxy (V1-06, ADR 0044). It accepts
//! `POST /v1/chat/completions`, forwards it to one plain-HTTP upstream (SGLang) and writes the
//! usage the upstream reported through [`settlement::ingest`], connected as
//! `openmettle_gateway`.
//!
//! - **Authentication and single dispatch.** The caller names a handed-off gateway request in
//!   `x-request-id` and presents that request's bearer in `Authorization`: the per-round value
//!   whose hash the handoff stored, never the dispatch secret. The database spends the
//!   request's one dispatch before the body is read: an unknown request or a wrong bearer is
//!   refused alike, and a second dispatch is a conflict. The report's routing fields come from
//!   the stored row, never from the caller.
//! - **Model.** The stored model must be the one this gateway serves, and the body's top-level
//!   `model` must equal it. The upstream answers any model name from its loaded model, so
//!   nothing else checks it.
//! - **Forwarding and prefix-cache isolation.** Top-level proxy-owned SGLang cache/routing fields
//!   (`cache_salt`, `extra_key`, `session_id`, `rid`, `lora_path`) are refused (`400 validation`,
//!   `UsageGap::RequestBody`) before connecting upstream. Otherwise the proxy derives a 64-char
//!   lowercase hex `cache_salt` (scoped per authorized scope/owner/model or fresh per request) and
//!   appends it right before the JSON object's closing `}`, preserving caller bytes verbatim. Only
//!   `Content-Type`, `Accept`, `Accept-Encoding: identity` and the request ID are forwarded;
//!   `Authorization`, cookies and fields the caller names in `Connection` are not forwarded. The
//!   upstream status, `Content-Type` and body are relayed chunk by chunk as they arrive. Only
//!   identity bodies pass in either direction, and only HTTP/1.1 callers are served.
//! - **Usage.** One relay task per request copies each upstream chunk to the caller and to the
//!   usage reader and then writes one final report itself, so the write does not depend on the
//!   caller staying connected. A completed 200 with a usage object is reported with its counts.
//!   Any other end of a request whose dispatch was spent is reported without counts and with
//!   the reason, which closes the hold (ADR 0044, amendment of 24 November 2026), and logs one
//!   `gateway.usage.unrecorded` event.
//!
//! The listener is plain HTTP. The packaged worker may call it so inside the cluster, or
//! through a TLS terminator in front of it. Not deployable yet (no image target, chart or
//! network policy, increment 7). Requests that were never dispatched, or whose report the proxy
//! could not write, are closed by the worker's maintenance sweep at revision 0 (increment 3b).
//! See `docs/operator/gateway-proxy.md`.
mod usage;

use crate::{
    authz::{
        gateway::{self, Consumed, Error as StoreError, Routing, settlement},
        projects::hex,
    },
    bounded_positive,
    provider_http::{gateway::UsageReport, inference::json},
    runs::{digest, identity as framed_identity, is_canonical_uuid},
    telemetry::{self, RequestId, UsageGap},
    v1::{Problem, problem},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, Version, header, uri::Authority},
    response::Response,
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body as _, Frame, Incoming, SizeHint},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
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
    runtime::Handle,
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
/// Each write transaction, spending a dispatch or storing a report, gets this many
/// `DB_TIMEOUT_MS` before the proxy stops waiting for it, also when its database connection has
/// stopped answering. A report write is then retried.
const WRITE_ATTEMPT_TIMEOUTS: u32 = 5;
/// SGLang counts reasoning tokens inside `completion_tokens` (recorded 23 Nov 2026), so
/// settlement must not add them again.
const REASONING_INCLUDED: bool = true;
/// The revision of the one report the proxy writes for a request. Revision 0 is left to the
/// sweep that closes a request nobody reported: settlement lets a higher final revision correct
/// a lower one, so a report of the proxy that arrives late replaces the sweep's record, and the
/// sweep can never replace the proxy's.
const REPORT_REVISION: i64 = 1;

const CORRELATION: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request needs one x-request-id header holding a canonical lowercase UUID.",
);
const CONNECTION: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The Connection header could not be read.",
);
const UNAUTHENTICATED: Problem = problem(
    StatusCode::UNAUTHORIZED,
    "unauthenticated",
    "The request needs one Authorization header with the bearer of the request named in x-request-id.",
);
const REPLAY: Problem = problem(
    StatusCode::CONFLICT,
    "conflict",
    "The request named in x-request-id was already dispatched.",
);
const NOT_SERVED: Problem = problem(
    StatusCode::FORBIDDEN,
    "policy",
    "This gateway does not serve the model the request was reserved for.",
);
const MODEL: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request body must be a JSON object whose model is the one the request was reserved for.",
);
const BODY: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request body exceeds 2 MiB or did not arrive in time.",
);
const RESERVED_FIELD: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request body must not set proxy-owned cache or routing fields.",
);
const RESERVED_KEYS: [&str; 5] = ["cache_salt", "extra_key", "session_id", "rid", "lora_path"];

/// How the proxy derives `cache_salt` for upstream prefix-cache isolation (ADR 0044, increment 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheMode {
    Scoped,
    PerRequest,
}
const VERSION: Problem = problem(
    StatusCode::HTTP_VERSION_NOT_SUPPORTED,
    "http_version_not_supported",
    "This route needs HTTP/1.1.",
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
    /// The catalog model ID the upstream serves.
    model: String,
    cache_mode: CacheMode,
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl Settings {
    /// `UPSTREAM_URL` and `MODEL` (both required), optional `CACHE_MODE`,
    /// `UPSTREAM_CONNECT_TIMEOUT_MS` and `UPSTREAM_IDLE_TIMEOUT_MS`. Refusals name the key, never
    /// the value.
    pub(crate) fn parse(
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Self, &'static str> {
        let url = get("UPSTREAM_URL")?.ok_or("UPSTREAM_URL is required")?;
        let upstream = origin(&url)?;
        let model = get("MODEL")?.ok_or("MODEL is required")?;
        // The bound of a stored request's model.
        if model.is_empty() || model.len() > 128 {
            return Err("invalid MODEL");
        }
        let cache_mode = match get("CACHE_MODE")?.as_deref() {
            None | Some("scoped") => CacheMode::Scoped,
            Some("per_request") => CacheMode::PerRequest,
            Some(_) => return Err("invalid CACHE_MODE"),
        };
        let millis = |key, default, max| -> Result<Duration, &'static str> {
            Ok(Duration::from_millis(bounded_positive(
                get(key)?,
                default,
                max,
            )?))
        };
        Ok(Self {
            upstream,
            model,
            cache_mode,
            connect_timeout: millis("UPSTREAM_CONNECT_TIMEOUT_MS", 5_000, 30_000)?,
            idle_timeout: millis("UPSTREAM_IDLE_TIMEOUT_MS", 120_000, 3_600_000)?,
        })
    }

    async fn connect(&self) -> Result<TcpStream, Problem> {
        let host = self.upstream.host();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = self.upstream.port_u16().unwrap_or(80);
        match timeout(self.connect_timeout, TcpStream::connect((host, port))).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(_)) => Err(UPSTREAM),
            Err(_) => Err(UPSTREAM_TIMEOUT),
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

/// Whether every `Connection` value is visible ASCII and spaces only, so its nominations can
/// all be read. A horizontal tab is refused too, although a header value may hold one.
fn connection_readable(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONNECTION).iter().all(|value| {
        value
            .as_bytes()
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte))
    })
}

/// The values of `name`, unless the message's `Connection` field names it as hop-by-hop. The
/// caller's request is first checked with [`connection_readable`].
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

/// No content coding other than `identity`, and no transfer coding other than one `chunked`:
/// hyper removes only the chunk framing, so any other coding would pass through unlabelled.
fn identity(headers: &HeaderMap) -> bool {
    let mut transfer = headers.get_all(header::TRANSFER_ENCODING).iter();
    let framing = match (transfer.next(), transfer.next()) {
        (None, _) => true,
        (Some(coding), None) => coding
            .as_bytes()
            .trim_ascii()
            .eq_ignore_ascii_case(b"chunked"),
        _ => false,
    };
    framing
        && headers
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
        Err(problem) => {
            let mut response = problem.response(id);
            if problem == UNAUTHENTICATED {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            response
        }
    }
}

/// Exactly one `x-request-id` holding a canonical lowercase UUID. One named in `Connection` is
/// hop-by-hop and counts as absent.
fn correlation(headers: &HeaderMap) -> Result<String, Problem> {
    let name = HeaderName::from_static("x-request-id");
    let mut values = end_to_end(headers, &name);
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

/// The round bearer of exactly one `Authorization: Bearer` header: 32 bytes as 43 unpadded
/// base64url characters, in their one canonical spelling. A header named in `Connection` is
/// hop-by-hop and counts as absent.
fn credential(headers: &HeaderMap) -> Result<[u8; 32], Problem> {
    let mut values = end_to_end(headers, &header::AUTHORIZATION);
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(UNAUTHENTICATED);
    };
    value
        .as_bytes()
        .strip_prefix(b"Bearer ")
        .and_then(|token| URL_SAFE_NO_PAD.decode(token).ok())
        .and_then(|bearer| bearer.try_into().ok())
        .ok_or(UNAUTHENTICATED)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyRejection {
    ModelMismatch,
    ReservedField,
}

/// Validates that `body` is one unique-key JSON object whose top-level `model` equals `model`
/// and that sets none of SGLang's proxy-owned cache/routing fields (`RESERVED_KEYS`).
fn validate_body(body: &[u8], model: &str) -> Result<(), BodyRejection> {
    let Ok(serde_json::Value::Object(request)) = json::parse(body) else {
        return Err(BodyRejection::ModelMismatch);
    };
    if request.get("model").and_then(|named| named.as_str()) != Some(model) {
        return Err(BodyRejection::ModelMismatch);
    }
    if RESERVED_KEYS.iter().any(|key| request.contains_key(*key)) {
        return Err(BodyRejection::ReservedField);
    }
    Ok(())
}

/// Derives the 64-character lowercase hex SHA-256 `cache_salt` for `routing` under `mode`.
/// Never logged, emitted in telemetry, or returned in error responses.
fn derive_cache_salt(
    mode: CacheMode,
    routing: &Routing,
    request_id: &str,
) -> Result<String, Problem> {
    let input = match mode {
        CacheMode::Scoped => {
            let (kind, owner): (&[u8], &[u8]) = match routing.cache_owner.as_deref() {
                None => (b"shared", b""),
                Some(owner) => (b"owner", owner.as_bytes()),
            };
            framed_identity(
                b"openmettle.cache-salt.v1\0",
                &[
                    routing.installation.as_bytes(),
                    routing.scope.as_bytes(),
                    kind,
                    owner,
                    routing.model.as_bytes(),
                ],
            )
        }
        CacheMode::PerRequest => {
            let mut nonce = [0u8; 32];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| UNAVAILABLE)?;
            framed_identity(
                b"openmettle.cache-salt-request.v1\0",
                &[
                    routing.installation.as_bytes(),
                    request_id.as_bytes(),
                    &nonce,
                ],
            )
        }
    };
    Ok(hex(&digest(&input)))
}

/// Appends `,"cache_salt":"<salt_hex>"` immediately before the validated JSON object's closing
/// `}`, stripping only trailing RFC 8259 whitespace and leaving all caller bytes before `}`
/// untouched.
fn inject_cache_salt(body: &[u8], salt_hex: &str) -> Result<Bytes, Problem> {
    debug_assert_eq!(salt_hex.len(), 64);
    debug_assert!(
        salt_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    );
    let trimmed_len = body
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .map_or(0, |i| i + 1);
    let trimmed = &body[..trimmed_len];
    if trimmed.last() != Some(&b'}') {
        return Err(MODEL);
    }
    const PREFIX: &[u8] = br#","cache_salt":""#;
    const SUFFIX: &[u8] = br#""}"#;
    let mut out =
        Vec::with_capacity(trimmed.len() - 1 + PREFIX.len() + salt_hex.len() + SUFFIX.len());
    out.extend_from_slice(&trimmed[..trimmed.len() - 1]);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(salt_hex.as_bytes());
    out.extend_from_slice(SUFFIX);
    Ok(Bytes::from(out))
}

fn prepare_outbound_body(
    body: &[u8],
    mode: CacheMode,
    routing: &Routing,
    request_id: &str,
) -> Result<Bytes, (UsageGap, Problem)> {
    if let Err(rejection) = validate_body(body, &routing.model) {
        return Err(match rejection {
            BodyRejection::ModelMismatch => (UsageGap::ModelMismatch, MODEL),
            BodyRejection::ReservedField => (UsageGap::RequestBody, RESERVED_FIELD),
        });
    }
    let salt = derive_cache_salt(mode, routing, request_id)
        .map_err(|problem| (UsageGap::UpstreamConnect, problem))?;
    inject_cache_salt(body, &salt).map_err(|problem| (UsageGap::ModelMismatch, problem))
}

impl Proxy {
    async fn forward(&self, request: Request) -> Result<Response, Problem> {
        let (parts, body) = request.into_parts();
        // HTTP/1.0 ends an unsized body by closing the connection, so a cut stream would look
        // complete to the caller.
        if parts.version != Version::HTTP_11 {
            return Err(VERSION);
        }
        // An unreadable `Connection` value could name `Authorization` or the request ID as
        // hop-by-hop without `end_to_end` seeing it. Refuse before either is looked at.
        if !connection_readable(&parts.headers) {
            return Err(CONNECTION);
        }
        let id = correlation(&parts.headers)?;
        let bearer = credential(&parts.headers)?;
        if !identity(&parts.headers) {
            return Err(ENCODED_REQUEST);
        }
        // From here on the request's one dispatch is spent, or may be. Every early end,
        // including the server dropping this handler because the caller left, logs why there is
        // no usage and, once the dispatch is known to be spent, closes the request with that
        // reason.
        let mut unrecorded = Unrecorded {
            proxy: self,
            id: &id,
            routing: None,
            gap: Some(UsageGap::DispatchUnconfirmed),
        };
        // The caller is authenticated and the dispatch spent before any body is buffered.
        let routing = match self.consume(&id, bearer).await {
            Ok(routing) => routing,
            Err(problem) => {
                if problem != UNAVAILABLE {
                    // Refused or a replay: this call spent nothing.
                    unrecorded.gap = None;
                }
                return Err(problem);
            }
        };
        unrecorded.routing = Some(routing.clone());
        if routing.model != self.settings.model {
            unrecorded.gap = Some(UsageGap::ModelNotServed);
            return Err(NOT_SERVED);
        }
        unrecorded.gap = Some(UsageGap::RequestBody);
        let body = match timeout(REQUEST_READ, axum::body::to_bytes(body, MAX_REQUEST_BYTES)).await
        {
            Ok(Ok(body)) => body,
            _ => return Err(BODY),
        };
        let outbound_body =
            match prepare_outbound_body(&body, self.settings.cache_mode, &routing, &id) {
                Ok(outbound) => outbound,
                Err((gap, problem)) => {
                    unrecorded.gap = Some(gap);
                    return Err(problem);
                }
            };
        let mut outbound = hyper::Request::post(ROUTE)
            .header(header::HOST, self.settings.upstream.as_str())
            .header(header::CONNECTION, "close")
            .header(header::ACCEPT_ENCODING, "identity")
            .header("x-request-id", &id)
            .body(Full::new(outbound_body))
            .map_err(|_| CORRELATION)?;
        for name in [header::CONTENT_TYPE, header::ACCEPT] {
            for value in end_to_end(&parts.headers, &name) {
                outbound.headers_mut().append(name.clone(), value.clone());
            }
        }
        // Nothing is sent before the connection exists, also when the caller leaves meanwhile.
        unrecorded.gap = Some(UsageGap::UpstreamConnect);
        let stream = self.settings.connect().await?;
        unrecorded.gap = Some(UsageGap::CallerDisconnected);
        let (upstream, response) = match self.exchange(stream, outbound).await {
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

    /// Spends the one dispatch of `id` for the holder of `bearer` and returns the stored
    /// routing fields. Like every database exchange here, the transaction runs in its own task:
    /// past the deadline the proxy stops waiting for it but never cancels it in flight, so an
    /// unanswered exchange may still spend the dispatch.
    async fn consume(&self, id: &str, bearer: [u8; 32]) -> Result<Routing, Problem> {
        let (pool, id) = (self.pool.clone(), id.to_owned());
        let spent = tokio::spawn(async move { gateway::consume(&pool, &id, &bearer).await });
        match timeout(self.database_timeout * WRITE_ATTEMPT_TIMEOUTS, spent).await {
            Ok(Ok(Ok(Consumed::Once(routing)))) => Ok(routing),
            Ok(Ok(Ok(Consumed::Replay))) => Err(REPLAY),
            Ok(Ok(Ok(Consumed::Refused))) => Err(UNAUTHENTICATED),
            _ => Err(UNAVAILABLE),
        }
    }

    /// Sends `outbound` on the new connection `stream` and waits for the response head.
    async fn exchange(
        &self,
        stream: TcpStream,
        outbound: hyper::Request<Full<Bytes>>,
    ) -> Result<(Upstream, hyper::Response<Incoming>), UsageGap> {
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

/// Ends a handled request that stops before its relay starts with `gap`: a refusal once the
/// dispatch is or may be spent, or the server dropping the handler because the caller left,
/// which also closes the upstream connection. The gap is logged. Once `routing` is set the
/// dispatch is known to be spent, and a task of its own then stores the final incomplete
/// report, which shutdown waits for like a relay.
struct Unrecorded<'a> {
    proxy: &'a Proxy,
    id: &'a str,
    routing: Option<Routing>,
    gap: Option<UsageGap>,
}

impl Drop for Unrecorded<'_> {
    fn drop(&mut self) {
        let Some(gap) = self.gap else { return };
        telemetry::gateway_usage_unrecorded(self.id, gap);
        // Without a runtime the process is ending and nothing can be written any more.
        if let (Some(routing), Ok(runtime)) = (self.routing.take(), Handle::try_current()) {
            let (pool, id) = (self.proxy.pool.clone(), self.id.to_owned());
            let limit = self.proxy.database_timeout * WRITE_ATTEMPT_TIMEOUTS;
            let running = self.proxy.relays.start();
            runtime.spawn(async move {
                record(&pool, id, routing, Err(gap), limit).await;
                drop(running);
            });
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
    /// Set once the caller has gone: reading stops when it passes.
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
        if self.delivered(&copied) {
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
        if let Err(gap) = usage {
            telemetry::gateway_usage_unrecorded(&id, gap);
        }
        record(&pool, id, routing, usage, write_limit).await;
    }

    /// Reads the upstream body to its end. The caller gets every chunk until it leaves or stops
    /// reading; after that the rest is read only while the usage may still be in hand, checked
    /// after every read, and reading stops once one idle timeout has passed since then. A body
    /// that ends as that deadline falls still counts. Otherwise the upstream connection is
    /// dropped.
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

    /// Whether the caller's response may end cleanly: the upstream body completed and the
    /// caller received every chunk.
    fn delivered(&self, copied: &Result<(), UsageGap>) -> bool {
        copied.is_ok() && self.delivering
    }

    fn draining(&self) -> bool {
        self.extract.as_ref().is_some_and(Extract::worth_draining)
    }
}

/// One final report built from the stored routing fields, with the counts of `usage` or, for a
/// request that ended without usage, with none. A request is dispatched once and the proxy
/// writes one report for it, so the report takes the request's own ID at [`REPORT_REVISION`]: a
/// retried write stores the identical report, which settlement accepts once.
fn report(id: String, routing: Routing, usage: Option<Usage>) -> UsageReport {
    let reasoning = usage.and_then(|usage| usage.reasoning);
    UsageReport {
        report_id: id.clone(),
        request: id,
        installation: routing.installation,
        principal: routing.principal,
        scope: routing.scope,
        source: routing.source,
        revision: REPORT_REVISION,
        r#final: true,
        prompt_tokens: usage.map(|usage| usage.prompt),
        completion_tokens: usage.map(|usage| usage.completion),
        reasoning_tokens: reasoning,
        reasoning_included: reasoning.map(|_| REASONING_INCLUDED),
        cost: None,
        unit: None,
    }
}

/// Stores the one report of request `id`: the usage the upstream reported, or the reason there
/// is none. Either closes the request's token hold; a report without counts is never written
/// without its reason, because settlement would then keep the hold for good. A transient
/// database failure is retried twice. No local spool.
///
/// Each attempt runs in its own task and is never cancelled in flight: sqlx counts a transaction
/// only once the server acknowledges `BEGIN`, so a cancelled `BEGIN` could put its connection
/// back in the pool inside a transaction. The proxy waits `limit` for an attempt; past that it
/// retries while the abandoned attempt finishes or fails on its own, bounded by settlement's
/// lock and statement timeouts unless its connection has gone silent. Overlap is safe:
/// settlement locks the request and accepts the identical report once.
async fn record(
    pool: &PgPool,
    id: String,
    routing: Routing,
    usage: Result<Usage, UsageGap>,
    limit: Duration,
) {
    let report = report(id, routing, usage.ok());
    let reason = usage.err().map(UsageGap::as_str);
    let mut attempt = 0;
    loop {
        let (pool, owned) = (pool.clone(), report.clone());
        let task = tokio::spawn(async move {
            match reason {
                None => settlement::ingest(&pool, &owned).await,
                Some(reason) => settlement::ingest_incomplete(&pool, &owned, reason).await,
            }
        });
        let outcome = match timeout(limit, task).await {
            Ok(Ok(outcome)) => outcome,
            // Abandoned past `limit`, or the attempt panicked.
            _ => Err(StoreError::Database),
        };
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
    use sqlx::postgres::PgPoolOptions;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
    };

    const SERVED: (&str, &str) = ("MODEL", "synthetic-model");

    /// The settings in `pairs`, the last value of a repeated key winning.
    fn parse(pairs: &[(&str, &str)]) -> Result<Settings, &'static str> {
        Settings::parse(|key| {
            Ok(pairs
                .iter()
                .rfind(|(k, _)| *k == key)
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
            let settings = parse(&[("UPSTREAM_URL", url), SERVED]).unwrap();
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
                parse(&[("UPSTREAM_URL", url), SERVED]).err(),
                Some(refusal),
                "{url}"
            );
        }
        assert_eq!(parse(&[SERVED]).err(), Some("UPSTREAM_URL is required"));
    }

    #[test]
    fn the_served_model_is_required_and_bounded() {
        let url = ("UPSTREAM_URL", "http://127.0.0.1:30000");
        assert_eq!(parse(&[url, SERVED]).unwrap().model, "synthetic-model");
        let longest = "m".repeat(128);
        assert_eq!(parse(&[url, ("MODEL", &longest)]).unwrap().model, longest);
        assert_eq!(parse(&[url]).err(), Some("MODEL is required"));
        for model in ["", &"m".repeat(129)] {
            assert_eq!(
                parse(&[url, ("MODEL", model)]).err(),
                Some("invalid MODEL"),
                "{} bytes",
                model.len()
            );
        }
    }

    #[test]
    fn upstream_timeouts_are_bounded() {
        let url = ("UPSTREAM_URL", "http://127.0.0.1:30000");
        let settings = parse(&[
            url,
            SERVED,
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
            assert_eq!(
                parse(&[url, SERVED, (key, value)]).err(),
                Some(match value {
                    "soon" => "invalid numeric configuration",
                    _ => "configuration outside allowed range",
                }),
                "{key}={value}"
            );
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

    /// Its base64url spelling uses both characters the standard alphabet lacks.
    const BEARER: [u8; 32] = [0xfb; 32];

    #[test]
    fn the_credential_is_exactly_one_canonical_bearer() {
        let token = URL_SAFE_NO_PAD.encode(BEARER);
        assert_eq!(token, "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s");
        let bearer = |token: &str| format!("Bearer {token}").parse::<HeaderValue>().unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(credential(&headers), Err(UNAUTHENTICATED));
        headers.insert(header::AUTHORIZATION, bearer(&token));
        assert_eq!(credential(&headers), Ok(BEARER));
        // Named as hop-by-hop, it counts as absent.
        headers.insert(header::CONNECTION, "close, Authorization".parse().unwrap());
        assert_eq!(credential(&headers), Err(UNAUTHENTICATED));
        headers.remove(header::CONNECTION);
        headers.append(header::AUTHORIZATION, bearer(&token));
        assert_eq!(credential(&headers), Err(UNAUTHENTICATED));
        for bad in [
            token.clone() + "=",
            // 31 and 33 bytes.
            token[..42].to_owned(),
            token.clone() + "AA",
            // The standard alphabet, and the same 32 bytes spelled with a stray low bit.
            token.replace('-', "+").replace('_', "/"),
            token[..42].to_owned() + "t",
            String::new(),
        ] {
            headers.insert(header::AUTHORIZATION, bearer(&bad));
            assert_eq!(credential(&headers), Err(UNAUTHENTICATED), "{bad}");
        }
        for other in [
            format!("bearer {token}"),
            format!("Bearer  {token}"),
            format!("Basic {token}"),
            token,
        ] {
            headers.insert(header::AUTHORIZATION, other.parse().unwrap());
            assert_eq!(credential(&headers), Err(UNAUTHENTICATED), "{other}");
        }
    }

    #[test]
    fn a_connection_field_that_cannot_be_read_is_not_trusted() {
        let mut headers = HeaderMap::new();
        assert!(connection_readable(&headers));
        headers.insert(header::CONNECTION, "close, Authorization".parse().unwrap());
        assert!(connection_readable(&headers));
        // One readable value does not excuse an unreadable one.
        let hidden = HeaderValue::from_bytes(b"Authorization\xff").unwrap();
        headers.append(header::CONNECTION, hidden);
        assert!(!connection_readable(&headers));
        // A tab is a legal header byte, and still not one a nomination is read through.
        for tabbed in [
            &b"close,\tAuthorization"[..],
            b"Authori\tzation",
            b"\tclose",
        ] {
            let mut headers = HeaderMap::new();
            let value = HeaderValue::from_bytes(tabbed).unwrap();
            assert!(value.to_str().is_ok());
            headers.insert(header::CONNECTION, value);
            assert!(!connection_readable(&headers));
        }
    }

    #[test]
    fn the_body_must_name_the_reserved_model_once() {
        assert_eq!(
            validate_body(br#"{"model":"a","messages":[]}"#, "a"),
            Ok(())
        );
        assert_eq!(
            validate_body(br#" {"messages":[],"model":"a"} "#, "a"),
            Ok(())
        );
        for body in [
            &br#"{"model":"b","messages":[]}"#[..],
            br#"{"messages":[]}"#,
            br#"{"model":null}"#,
            br#"{"model":["a"]}"#,
            br#"{"model":"A"}"#,
            br#"{"model":"a ","messages":[]}"#,
            // A second `model` could be the one the upstream reads.
            br#"{"model":"a","model":"b"}"#,
            br#"{"model":"b","model":"a"}"#,
            br#"{"model":"a","model":"a"}"#,
            br#"{"request":{"model":"a"}}"#,
            br#"[{"model":"a"}]"#,
            br#""a""#,
            br#"{"model":"a"}{"model":"a"}"#,
            br#"{"model":"a""#,
            b"",
        ] {
            assert_eq!(
                validate_body(body, "a"),
                Err(BodyRejection::ModelMismatch),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    const ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

    fn routing() -> Routing {
        Routing {
            installation: "00000000-0000-4000-8000-000000000001".into(),
            principal: "00000000-0000-4000-8000-000000000002".into(),
            scope: "00000000-0000-4000-8000-000000000003".into(),
            source: "00000000-0000-4000-8000-000000000004".into(),
            model: SERVED.1.into(),
            cache_owner: None,
        }
    }

    #[test]
    fn cache_mode_setting_is_validated() {
        let url = ("UPSTREAM_URL", "http://127.0.0.1:30000");
        assert_eq!(parse(&[url, SERVED]).unwrap().cache_mode, CacheMode::Scoped);
        assert_eq!(
            parse(&[url, SERVED, ("CACHE_MODE", "scoped")])
                .unwrap()
                .cache_mode,
            CacheMode::Scoped
        );
        assert_eq!(
            parse(&[url, SERVED, ("CACHE_MODE", "per_request")])
                .unwrap()
                .cache_mode,
            CacheMode::PerRequest
        );
        for bad in [
            "",
            "SCOPED",
            "per-request",
            "off",
            " scoped",
            "per_request ",
        ] {
            assert_eq!(
                parse(&[url, SERVED, ("CACHE_MODE", bad)]).err(),
                Some("invalid CACHE_MODE"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn cache_salt_derivation_is_deterministic_domain_separated_and_random_per_request() {
        let is_hex64 =
            |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let base = routing();
        let shared = derive_cache_salt(CacheMode::Scoped, &base, ID).unwrap();
        assert!(is_hex64(&shared), "{shared}");
        assert_eq!(
            shared,
            derive_cache_salt(
                CacheMode::Scoped,
                &base,
                "11111111-1111-4111-8111-111111111111"
            )
            .unwrap()
        );
        // Domain and field-boundary collision resistance: None vs Some("") vs Some("shared"),
        // and ("ab", "c") vs ("a", "bc").
        let empty_owner = Routing {
            cache_owner: Some(String::new()),
            ..base.clone()
        };
        let named_shared = Routing {
            cache_owner: Some("shared".into()),
            ..base.clone()
        };
        let owned = Routing {
            cache_owner: Some("00000000-0000-4000-8000-0000000000aa".into()),
            ..base.clone()
        };
        let s_empty = derive_cache_salt(CacheMode::Scoped, &empty_owner, ID).unwrap();
        let s_named = derive_cache_salt(CacheMode::Scoped, &named_shared, ID).unwrap();
        let s_owned = derive_cache_salt(CacheMode::Scoped, &owned, ID).unwrap();
        for salt in [&s_empty, &s_named, &s_owned] {
            assert!(is_hex64(salt), "{salt}");
        }
        assert_ne!(shared, s_empty);
        assert_ne!(shared, s_named);
        assert_ne!(s_empty, s_named);
        assert_ne!(shared, s_owned);

        let left = Routing {
            scope: "ab".into(),
            model: "c".into(),
            ..base.clone()
        };
        let right = Routing {
            scope: "a".into(),
            model: "bc".into(),
            ..base.clone()
        };
        assert_ne!(
            derive_cache_salt(CacheMode::Scoped, &left, ID).unwrap(),
            derive_cache_salt(CacheMode::Scoped, &right, ID).unwrap()
        );

        let pr_1 = derive_cache_salt(CacheMode::PerRequest, &base, ID).unwrap();
        let pr_2 = derive_cache_salt(CacheMode::PerRequest, &base, ID).unwrap();
        assert!(is_hex64(&pr_1), "{pr_1}");
        assert!(is_hex64(&pr_2), "{pr_2}");
        assert_ne!(pr_1, pr_2);
        assert_ne!(pr_1, shared);
    }

    #[test]
    fn body_validation_and_injection_preserve_bytes_and_reject_reserved_fields() {
        let base = routing();
        // Exact byte-preserving injection: preserves key order, whitespace, nested strings
        // mentioning reserved keys, and exact float literals (e.g. 0.70, 1e-5, 1.0).
        let raw = br#"{  "temperature": 0.70, "top_p": 1.0, "eps": 1e-5, "model": "synthetic-model", "messages": [{"role":"user","content":"{\"cache_salt\":\"ignored\",\"extra_key\":\"ok\"}"}], "metadata": {"extra_key": "nested-ok"} }  "#;
        let out = prepare_outbound_body(raw, CacheMode::Scoped, &base, ID).unwrap();
        let expected_salt = derive_cache_salt(CacheMode::Scoped, &base, ID).unwrap();
        let expected_prefix = br#"{  "temperature": 0.70, "top_p": 1.0, "eps": 1e-5, "model": "synthetic-model", "messages": [{"role":"user","content":"{\"cache_salt\":\"ignored\",\"extra_key\":\"ok\"}"}], "metadata": {"extra_key": "nested-ok"} ,"cache_salt":""#;
        let mut expected = Vec::new();
        expected.extend_from_slice(expected_prefix);
        expected.extend_from_slice(expected_salt.as_bytes());
        expected.extend_from_slice(br#""}"#);
        assert_eq!(out.as_ref(), expected.as_slice());
        // Result is valid unique-key JSON carrying the derived `cache_salt`.
        let parsed = json::parse(&out).unwrap();
        assert_eq!(
            parsed.get("cache_salt").and_then(|v| v.as_str()),
            Some(expected_salt.as_str())
        );

        // A full MAX_REQUEST_BYTES (2 MiB) caller body is accepted and rewritten cleanly.
        let head = br#"{"model":"synthetic-model","pad":""#;
        let tail = br#""}"#;
        let pad_len = MAX_REQUEST_BYTES - head.len() - tail.len();
        let mut max_body = Vec::with_capacity(MAX_REQUEST_BYTES);
        max_body.extend_from_slice(head);
        max_body.resize(head.len() + pad_len, b'a');
        max_body.extend_from_slice(tail);
        assert_eq!(max_body.len(), MAX_REQUEST_BYTES);
        let max_out = prepare_outbound_body(&max_body, CacheMode::Scoped, &base, ID).unwrap();
        assert_eq!(
            max_out.len(),
            MAX_REQUEST_BYTES + br#","cache_salt":""#.len() + 64 + 1
        );
        assert!(json::parse(&max_out).is_ok());

        // Every top-level reserved field is refused (including null and unicode-escaped keys).
        for key in RESERVED_KEYS {
            for val in [r#""x""#, "null", "123"] {
                let body = format!(r#"{{"model":"synthetic-model","{key}":{val}}}"#);
                assert_eq!(
                    prepare_outbound_body(body.as_bytes(), CacheMode::Scoped, &base, ID),
                    Err((UsageGap::RequestBody, RESERVED_FIELD)),
                    "{body}"
                );
            }
        }
        let escaped = br#"{"model":"synthetic-model","\u0063ache_salt":"sneaky"}"#;
        assert_eq!(
            prepare_outbound_body(escaped, CacheMode::Scoped, &base, ID),
            Err((UsageGap::RequestBody, RESERVED_FIELD))
        );
        // Duplicate keys still fail as ModelMismatch.
        let dup = br#"{"model":"synthetic-model","messages":[],"messages":[]}"#;
        assert_eq!(
            prepare_outbound_body(dup, CacheMode::Scoped, &base, ID),
            Err((UsageGap::ModelMismatch, MODEL))
        );
    }

    #[test]
    fn a_report_takes_its_identity_from_the_request() {
        let id = ID;
        let usage = Usage {
            prompt: 67,
            completion: 37,
            reasoning: Some(33),
        };
        let first = report(id.into(), routing(), Some(usage));
        let again = report(id.into(), routing(), Some(usage));
        assert!(first.valid());
        // Revision 0 is the sweep's, so that the proxy's report always supersedes it.
        assert_eq!(
            (first.report_id.as_str(), first.revision, first.r#final),
            (id, 1, true)
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
            Some(Usage {
                reasoning: None,
                ..usage
            }),
        );
        assert_eq!(
            (plain.reasoning_tokens, plain.reasoning_included),
            (None, None)
        );
    }

    /// The report of a request that ended without usage has the same identity, revision and
    /// finality as a complete one and no count at all: it never passes for a measurement.
    /// `record` stores it only together with its reason.
    #[test]
    fn a_report_without_usage_carries_no_count() {
        let none = report(ID.into(), routing(), None);
        assert!(none.valid());
        assert_eq!(
            (none.report_id.as_str(), none.revision, none.r#final),
            (ID, 1, true)
        );
        assert_eq!(
            (
                none.prompt_tokens,
                none.completion_tokens,
                none.reasoning_tokens,
                none.reasoning_included,
                none.measured()
            ),
            (None, None, None, None, None)
        );
    }

    /// The reasons the proxy reports are the vocabulary of migration 31's CHECK on
    /// `gateway_usage_reports.incomplete`; `dispatch_unconfirmed` is only ever logged.
    #[test]
    fn the_reported_reasons_are_the_vocabulary_of_migration_31() {
        let migration = include_str!("../migrations/0031_gateway_incomplete_usage_reports.sql");
        let (_, list) = migration.split_once("incomplete IN (").unwrap();
        let (list, _) = list.split_once(')').unwrap();
        let mut stored: Vec<&str> = list
            .split(',')
            .map(|v| v.trim().trim_matches('\''))
            .collect();
        stored.sort_unstable();
        let mut reported: Vec<&str> = [
            UsageGap::ModelNotServed,
            UsageGap::ModelMismatch,
            UsageGap::RequestBody,
            UsageGap::UpstreamConnect,
            UsageGap::UpstreamStatus,
            UsageGap::UpstreamTransport,
            UsageGap::UpstreamEncoding,
            UsageGap::UpstreamTimeout,
            UsageGap::Incomplete,
            UsageGap::CallerDisconnected,
            UsageGap::NoUsage,
            UsageGap::Unparsable,
        ]
        .into_iter()
        .map(UsageGap::as_str)
        .collect();
        reported.sort_unstable();
        assert_eq!(stored, reported);
        assert!(!stored.contains(&UsageGap::DispatchUnconfirmed.as_str()));

        // Migration 32 adds only the two sweep-only revision-0 reasons, which the proxy never emits.
        let m32 = include_str!("../migrations/0032_gateway_unreported_request_sweep.sql");
        let (_, sweep_list) = m32.split_once("revision = 0 AND incomplete IN (").unwrap();
        let (sweep_list, _) = sweep_list.split_once(')').unwrap();
        let mut sweep_reasons: Vec<&str> = sweep_list
            .split(',')
            .map(|v| v.trim().trim_matches('\''))
            .collect();
        sweep_reasons.sort_unstable();
        assert_eq!(sweep_reasons, ["not_dispatched", "unreported"]);
        for reason in sweep_reasons {
            assert!(!reported.contains(&reason));
        }
    }

    fn chunk(data: &[u8]) -> Vec<u8> {
        let mut chunk = format!("{:x}\r\n", data.len()).into_bytes();
        chunk.extend_from_slice(data);
        chunk.extend_from_slice(b"\r\n");
        chunk
    }

    /// One SSE chunk with content and the usage so far.
    fn event(completion: usize) -> Vec<u8> {
        chunk(
            format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"x\"}}}}],\
                 \"usage\":{{\"prompt_tokens\":5,\"completion_tokens\":{completion}}}}}\n\n"
            )
            .as_bytes(),
        )
    }

    /// Answers one request with `head` and `before`, then, once `gate` opens, `after`. Yields
    /// whether every write went out.
    async fn upstream(
        head: &str,
        before: Vec<Vec<u8>>,
        after: Vec<Vec<u8>>,
        gate: oneshot::Receiver<()>,
    ) -> (String, tokio::task::JoinHandle<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let head = head.as_bytes().to_vec();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                    return false;
                }
                request.push(byte[0]);
            }
            for write in std::iter::once(head).chain(before) {
                if socket.write_all(&write).await.is_err() {
                    return false;
                }
            }
            if gate.await.is_err() {
                return false;
            }
            for write in after {
                if socket.write_all(&write).await.is_err() {
                    return false;
                }
            }
            true
        });
        (address, task)
    }

    /// A relay of the answer from `address`, with the caller's end of its channel. Nothing here
    /// reaches a database.
    async fn relay(address: &str, idle: Duration) -> (Relay, mpsc::Receiver<Bytes>) {
        let url = format!("http://{address}");
        let idle_ms = idle.as_millis().to_string();
        let settings = parse(&[
            ("UPSTREAM_URL", &url),
            SERVED,
            ("UPSTREAM_IDLE_TIMEOUT_MS", &idle_ms),
        ])
        .unwrap();
        let unused = "postgres://unused@127.0.0.1:1/unused".parse().unwrap();
        let proxy = Proxy {
            settings,
            pool: PgPoolOptions::new().connect_lazy_with(unused),
            database_timeout: Duration::from_secs(1),
            relays: Relays::new(),
        };
        let outbound = hyper::Request::post(ROUTE)
            .header(header::HOST, address)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let stream = proxy.settings.connect().await.unwrap();
        let (upstream, response) = proxy.exchange(stream, outbound).await.unwrap();
        let (head, body) = response.into_parts();
        let (frames, receiver) = mpsc::channel(RELAY_BUFFER);
        let relay = Relay {
            extract: Some(Extract::new(head.headers.get(header::CONTENT_TYPE))),
            id: ID.into(),
            routing: routing(),
            upstream,
            body,
            frames,
            complete: Arc::new(AtomicBool::new(false)),
            delivering: true,
            drain_by: None,
            idle,
            pool: proxy.pool.clone(),
            write_limit: Duration::from_secs(1),
            _running: proxy.relays.start(),
        };
        (relay, receiver)
    }

    const SSE: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
        transfer-encoding: chunked\r\n\r\n";

    /// A caller that takes no chunk for an idle timeout is detached: it gets nothing more and no
    /// clean end, while the relay reads on and still finds the final usage. The caller never
    /// reads, so the relay channel fills; only then are the final usage and the end released,
    /// and the relay can read them only after its next send has waited one idle timeout.
    #[tokio::test]
    async fn a_caller_that_stops_reading_is_detached_and_the_usage_still_counted() {
        let (gate, open) = oneshot::channel();
        let before = (1..=RELAY_BUFFER + 4).map(event).collect();
        let after = vec![event(99), chunk(b"data: [DONE]\n\n"), b"0\r\n\r\n".to_vec()];
        let (address, upstream) = upstream(SSE, before, after, open).await;
        let (mut relay, receiver) = relay(&address, Duration::from_millis(500)).await;
        let release = async {
            while receiver.len() < RELAY_BUFFER {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            gate.send(()).unwrap();
        };
        let (copied, ()) = tokio::join!(relay.copy(), release);
        assert_eq!(copied, Ok(()));
        assert!(!relay.delivering);
        assert!(
            !relay.delivered(&copied),
            "a caller that missed chunks must not see a clean end"
        );
        assert_eq!(receiver.len(), RELAY_BUFFER);
        assert_eq!(
            relay.extract.take().unwrap().finish(),
            Ok(Usage {
                prompt: 5,
                completion: 99,
                reasoning: None
            })
        );
        assert!(upstream.await.unwrap());
    }

    /// After the caller has gone, the relay reads on only while the usage stays within reach.
    /// The caller takes the first chunk and leaves; only then does the rest of a JSON answer,
    /// four times the parse bound, arrive, so the relay detaches within the bound and must
    /// stop on a later read.
    #[tokio::test]
    async fn a_detached_relay_stops_once_the_usage_is_out_of_reach() {
        let piece = 64 * 1024;
        let pieces = 4 * usage::MAX_JSON_BYTES / piece;
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
             content-length: {}\r\n\r\n",
            pieces * piece
        );
        let mut first = br#"{"usage":{"prompt_tokens":1,"completion_tokens":1},"pad":""#.to_vec();
        first.resize(piece, b'x');
        let after = vec![vec![b'x'; piece]; pieces - 1];
        let (gate, open) = oneshot::channel();
        let (address, _upstream) = upstream(&head, vec![first], after, open).await;
        let (mut relay, mut receiver) = relay(&address, Duration::from_secs(30)).await;
        let leave = async move {
            receiver.recv().await.unwrap();
            drop(receiver);
            gate.send(()).unwrap();
        };
        let (copied, ()) = tokio::join!(relay.copy(), leave);
        assert_eq!(copied, Err(UsageGap::CallerDisconnected));
    }
}
