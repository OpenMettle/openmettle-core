//! Stateless Streamable HTTP MCP (`2026-07-28`) transport over [`super::transport`] (ADR 0039).
//!
//! Enforces a dedicated process-wide 8-slot DNS semaphore isolated from OIDC and gateway
//! inference, canonical `https://` endpoints with SSRF address policy and `rustls` (ring) TLS
//! 1.2/1.3 ALPN `http/1.1`, restricted stateless outbound headers (no `Mcp-Session-Id`, no
//! `Mcp-Param-*`, exact `#value-encoding` on `Mcp-Name`), RFC 9110 §15.2 bounded interim `1xx`
//! handling (`<= 4` non-`101` interim responses; immediate refusal on `101 Switching Protocols`),
//! strict final status classification, `4 MiB` streaming body caps via `http_body_util::Limited`,
//! and canary-safe error surfaces that never echo URLs, hosts, IPs, credentials, arguments,
//! handles, or upstream payloads.

use super::{Error, MAX_PRIVATE_RANGES, Trust, transport};
use crate::{provider_keys::documents::unique, worker::Stop};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, StatusCode,
    client::conn::http1,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use hyper_util::rt::TokioIo;
use serde_json::{Map, Value, json};
use std::{
    fmt,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, Semaphore, watch},
    time::{Instant, sleep_until, timeout_at},
};

/// Pinned MCP Streamable HTTP protocol revision (ADR 0039).
pub const PROTOCOL_VERSION: &str = "2026-07-28";
/// Maximum outbound HTTP/1.1 request header block bytes (request line + headers).
pub const MAX_REQUEST_HEADER_BYTES: usize = 2 * 1024;
/// Maximum outbound JSON-RPC request body bytes.
pub const MAX_REQUEST_BODY_BYTES: usize = 128 * 1024;
/// Maximum decoded HTTP/1.1 response body bytes across `application/json`, chunked, and SSE.
pub const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum response headers per interim or final header block.
pub const MAX_RESPONSE_HEADERS: usize = super::MAX_RESPONSE_HEADERS;
/// Maximum response header block size per interim or final header block.
pub const MAX_RESPONSE_HEADER_BYTES: usize = super::MAX_RESPONSE_HEADER_BYTES;
/// Maximum non-`101` interim `1xx` responses accepted before the final response.
pub const MAX_INTERIM_RESPONSES: usize = 4;
/// Maximum `Retry-After` delay accepted for a retry.
pub const MAX_RETRY_AFTER_SECS: u64 = 60;
/// Default setup (DNS + TCP + TLS) timeout.
pub const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Default per-read idle timeout while awaiting response headers or body/SSE frames.
pub const DEFAULT_IDLE_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Default whole-call timeout.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum allowed whole-call timeout (ADR 0039 / PLAN-10: 300 seconds).
pub const MAX_CALL_TIMEOUT: Duration = Duration::from_secs(300);

const MAX_READ_BUFFER: usize = 8 * 1024;
const HEADER_PROTOCOL_VERSION: HeaderName = HeaderName::from_static("mcp-protocol-version");
const HEADER_MCP_METHOD: HeaderName = HeaderName::from_static("mcp-method");
const HEADER_MCP_NAME: HeaderName = HeaderName::from_static("mcp-name");
const HEADER_IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// Dedicated process-wide DNS lookup slot pool isolated from OIDC and gateway inference.
static MCP_DNS_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(super::DNS_LOOKUP_SLOTS)));

/// MCP `2026-07-28` `#value-encoding` for `Mcp-Name` HTTP header values.
///
/// Passes through raw ASCII unchanged strictly when non-empty, every byte is in `0x20..=0x7E`
/// (excluding every control byte `0x00..=0x1F` including HTAB `0x09`, `0x7F`, and non-ASCII
/// `>= 0x80`), there is no leading or trailing `0x20` space, and the value does not
/// simultaneously start with `"=?base64?"` and end with `"?="`. Otherwise wraps the UTF-8
/// bytes in `=?base64?<standard-base64>?=`.
pub fn encode_mcp_name(name: &str) -> String {
    let bytes = name.as_bytes();
    let needs_encoding = bytes.is_empty()
        || bytes[0] == b' '
        || bytes[bytes.len() - 1] == b' '
        || bytes.iter().any(|&b| !(0x20..=0x7E).contains(&b))
        || (name.starts_with("=?base64?") && name.ends_with("?="));
    if needs_encoding {
        format!("=?base64?{}?=", STANDARD.encode(bytes))
    } else {
        name.to_owned()
    }
}

/// Parsed `Retry-After` directive on retryable HTTP status responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryAfter {
    /// Absent, duplicate, or non-integer (ignored; caller uses jittered backoff).
    None,
    /// Single valid integer delay in seconds within `0..=60`.
    Seconds(u64),
    /// Single valid integer delay exceeding `60` seconds (fail without retry).
    TooLong,
}

fn parse_retry_after(headers: &HeaderMap) -> RetryAfter {
    let mut values = headers.get_all(header::RETRY_AFTER).iter();
    let Some(first) = values.next() else {
        return RetryAfter::None;
    };
    if values.next().is_some() {
        return RetryAfter::None;
    }
    let Ok(text) = first.to_str() else {
        return RetryAfter::None;
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return RetryAfter::None;
    }
    match text.parse::<u64>() {
        Ok(secs) if secs <= MAX_RETRY_AFTER_SECS => RetryAfter::Seconds(secs),
        _ => RetryAfter::TooLong,
    }
}

/// Redacted transport fault category. Never contains URLs, hosts, IPs, tokens, or payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// JSON-RPC `-32602` (`is_tool_error = false`) or MCP `result.isError == true` (`true`).
    Semantic { is_tool_error: bool },
    /// Retryable transport/HTTP fault (DNS/connect/timeout, disconnect, or `408`/`429`/`502`/`503`/`504`).
    Transient(RetryAfter),
    /// Non-retryable refusal (validation, SSRF, TLS, `101`, `> 4` `1xx`, final non-`200`, framing,
    /// `> 4 MiB`, server-initiated request, `input_required`, or non-`-32602` JSON-RPC error).
    TerminalRefusal,
    /// Caller-supplied worker stop watch fired before completion.
    Stopped(Stop),
}

/// Fault returned by one single-shot [`McpTransport`] call, carrying strict pre-send provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportFault {
    pub kind: FaultKind,
    /// `false` ONLY when zero request bytes could have left this process (pre-send admission,
    /// DNS resolution, SSRF rejection, TCP connect, TLS handshake, or pre-connect stop/timeout).
    pub bytes_may_have_left: bool,
}

impl fmt::Display for TransportFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            FaultKind::Semantic { .. } => "mcp semantic fault",
            FaultKind::Transient(_) => "mcp transient fault",
            FaultKind::TerminalRefusal => "mcp terminal refusal",
            FaultKind::Stopped(_) => "mcp call stopped",
        })
    }
}
impl std::error::Error for TransportFault {}

/// Per-destination MCP transport timeouts.
#[derive(Clone, Copy, Debug)]
pub struct McpTimeouts {
    pub setup: Duration,
    pub idle_read: Duration,
    pub call: Duration,
}

impl Default for McpTimeouts {
    fn default() -> Self {
        Self {
            setup: DEFAULT_SETUP_TIMEOUT,
            idle_read: DEFAULT_IDLE_READ_TIMEOUT,
            call: DEFAULT_CALL_TIMEOUT,
        }
    }
}

/// Optional contract-pinned idempotency header (never `Mcp-Session-Id` or `Mcp-Param-*`).
#[derive(Clone, Copy)]
pub struct IdempotencyHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// Optional contract-pinned `params._meta` idempotency field.
#[derive(Clone, Copy)]
pub struct IdempotencyMeta<'a> {
    pub field: &'a str,
    pub value: &'a str,
}

/// Arguments for a single stateless `tools/call` invocation.
pub struct ToolCallRequest<'a> {
    pub request_id: &'a str,
    pub tool_name: &'a str,
    pub arguments: &'a Value,
    pub bearer_token: Option<&'a str>,
    pub idempotency_header: Option<IdempotencyHeader<'a>>,
    pub idempotency_meta: Option<IdempotencyMeta<'a>>,
}

/// Normalized successful MCP `tools/call` payload. `Debug` is redacted.
pub struct ToolCallSuccess {
    pub text: String,
    /// Decoded text `content` blocks in wire order; empty for structured-only replies.
    pub content_blocks: Vec<String>,
    pub structured: Option<Value>,
    pub meta: Option<Value>,
}

impl fmt::Debug for ToolCallSuccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ToolCallSuccess(..)")
    }
}

/// One remote tool entry returned by `tools/list`. `Debug` is redacted.
#[derive(Clone)]
pub struct RemoteToolDeclaration {
    pub name: String,
    pub input_schema: Value,
}

impl fmt::Debug for RemoteToolDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RemoteToolDeclaration(..)")
    }
}

/// One deployment-configured HTTPS Streamable HTTP MCP (`2026-07-28`) destination.
#[derive(Clone)]
pub struct McpTransport {
    endpoint: transport::Endpoint,
    allowed: Vec<transport::Range>,
    tls: Arc<rustls::ClientConfig>,
    lookup: transport::Lookup,
    slots: Arc<Semaphore>,
    timeouts: McpTimeouts,
    #[cfg(test)]
    loopback: bool,
}

impl fmt::Debug for McpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpTransport(..)")
    }
}

impl McpTransport {
    /// Construct a canonical `https://` MCP transport with explicit trust anchors and optional
    /// RFC 1918/CGNAT/ULA private ranges. Rejects plain `http://`, IP literals, query/fragment,
    /// invalid ranges, and zero/overflowing timeouts.
    pub fn new(
        endpoint_url: &str,
        trust: Trust<'_>,
        private_ranges: &[&str],
        timeouts: McpTimeouts,
    ) -> Result<Self, Error> {
        if private_ranges.len() > MAX_PRIVATE_RANGES
            || timeouts.setup.is_zero()
            || timeouts.idle_read.is_zero()
            || timeouts.call.is_zero()
            || timeouts.call > MAX_CALL_TIMEOUT
            || Instant::now().checked_add(timeouts.setup).is_none()
            || Instant::now().checked_add(timeouts.idle_read).is_none()
            || Instant::now().checked_add(timeouts.call).is_none()
        {
            return Err(Error::Configuration);
        }
        let endpoint = transport::endpoint(endpoint_url)?;
        let allowed = private_ranges
            .iter()
            .map(|r| transport::private_range(r))
            .collect::<Result<Vec<_>, _>>()?;
        let roots = transport::roots(trust)?;
        let tls = transport::client_config(roots)?;
        Ok(Self {
            endpoint,
            allowed,
            tls,
            lookup: Arc::new(transport::system_lookup),
            slots: MCP_DNS_SLOTS.clone(),
            timeouts,
            #[cfg(test)]
            loopback: false,
        })
    }

    /// Canonical `https://host[:port]` origin of this pinned MCP endpoint.
    pub fn origin(&self) -> String {
        format!("https://{}", self.endpoint.authority)
    }

    /// Execute one stateless `tools/list` call for catalog verification against this pinned server.
    pub async fn tools_list(
        &self,
        request_id: &str,
        bearer_token: Option<&str>,
        deadline: Instant,
        stop: &mut watch::Receiver<Option<Stop>>,
    ) -> Result<Vec<RemoteToolDeclaration>, TransportFault> {
        if request_id.is_empty() || request_id.len() > 128 {
            return Err(pre_send(FaultKind::TerminalRefusal));
        }
        let headers = build_headers("tools/list", None, bearer_token, None)?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        });
        let result = self
            .send_jsonrpc(headers, body, request_id, deadline, stop)
            .await?;
        parse_tools_list(&result).ok_or(TransportFault {
            kind: FaultKind::TerminalRefusal,
            bytes_may_have_left: true,
        })
    }

    /// Execute one stateless `tools/call` invocation with exact MCP `2026-07-28` wire framing.
    pub async fn tools_call(
        &self,
        request: &ToolCallRequest<'_>,
        deadline: Instant,
        stop: &mut watch::Receiver<Option<Stop>>,
    ) -> Result<ToolCallSuccess, TransportFault> {
        if request.request_id.is_empty()
            || request.request_id.len() > 128
            || request.tool_name.is_empty()
            || request.tool_name.len() > 256
            || !request.arguments.is_object()
        {
            return Err(pre_send(FaultKind::TerminalRefusal));
        }
        let mut meta = Map::new();
        meta.insert(
            "io.modelcontextprotocol/protocolVersion".into(),
            Value::String(PROTOCOL_VERSION.into()),
        );
        meta.insert(
            "io.modelcontextprotocol/clientCapabilities".into(),
            Value::Object(Map::new()),
        );
        if let Some(idem) = request.idempotency_meta {
            if idem.field.is_empty()
                || idem.field.len() > 128
                || idem.field.starts_with("io.modelcontextprotocol/")
                || idem.value.is_empty()
                || idem.value.len() > 256
            {
                return Err(pre_send(FaultKind::TerminalRefusal));
            }
            meta.insert(idem.field.into(), Value::String(idem.value.into()));
        }
        let headers = build_headers(
            "tools/call",
            Some(request.tool_name),
            request.bearer_token,
            request.idempotency_header,
        )?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": request.request_id,
            "method": "tools/call",
            "params": {
                "name": request.tool_name,
                "arguments": request.arguments,
                "_meta": Value::Object(meta),
            }
        });
        let result = self
            .send_jsonrpc(headers, body, request.request_id, deadline, stop)
            .await?;
        parse_tool_call_result(&result).map_err(|kind| TransportFault {
            kind,
            bytes_may_have_left: true,
        })
    }

    fn route(&self) -> transport::Route<'_> {
        transport::Route {
            endpoint: &self.endpoint,
            allowed: &self.allowed,
            tls: Some(&self.tls),
            lookup: &self.lookup,
            slots: &self.slots,
            #[cfg(test)]
            loopback: self.loopback,
        }
    }

    async fn send_jsonrpc(
        &self,
        headers: HeaderMap,
        body_value: Value,
        expected_id: &str,
        caller_deadline: Instant,
        stop: &mut watch::Receiver<Option<Stop>>,
    ) -> Result<Value, TransportFault> {
        if let Some(why) = *stop.borrow() {
            return Err(pre_send(FaultKind::Stopped(why)));
        }
        let start = Instant::now();
        let total = caller_deadline.min(start + self.timeouts.call);
        if start >= total {
            return Err(pre_send(FaultKind::Transient(RetryAfter::None)));
        }
        let setup = (start + self.timeouts.setup).min(total);
        let body =
            serde_json::to_vec(&body_value).map_err(|_| pre_send(FaultKind::TerminalRefusal))?;
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(pre_send(FaultKind::TerminalRefusal));
        }
        let route = self.route();
        let body_len = body.len();
        let outbound = route
            .request(Method::POST, &headers, body)
            .map_err(|_| pre_send(FaultKind::TerminalRefusal))?;
        let header_bytes = request_head_bytes(&self.endpoint.path, outbound.headers(), body_len);
        if header_bytes > MAX_REQUEST_HEADER_BYTES {
            return Err(pre_send(FaultKind::TerminalRefusal));
        }

        let bytes_sent = AtomicBool::new(false);
        let work = async {
            let connection = route.connect(setup).await.map_err(map_pre_send_error)?;
            bytes_sent.store(true, Ordering::SeqCst);
            exchange_mcp(
                connection,
                outbound,
                expected_id,
                total,
                self.timeouts.idle_read,
            )
            .await
        };
        tokio::select! {
            biased;
            waited = stop.wait_for(Option::is_some) => {
                let why = waited.ok().and_then(|v| *v).unwrap_or(Stop::LeaseLost);
                Err(TransportFault {
                    kind: FaultKind::Stopped(why),
                    bytes_may_have_left: bytes_sent.load(Ordering::SeqCst),
                })
            }
            result = work => result,
        }
    }
}

fn pre_send(kind: FaultKind) -> TransportFault {
    TransportFault {
        kind,
        bytes_may_have_left: false,
    }
}

fn map_pre_send_error(error: Error) -> TransportFault {
    let kind = match error {
        Error::Resolve | Error::Connect | Error::Timeout => FaultKind::Transient(RetryAfter::None),
        Error::Configuration
        | Error::Destination
        | Error::Address
        | Error::Tls
        | Error::Protocol
        | Error::TooLarge => FaultKind::TerminalRefusal,
    };
    pre_send(kind)
}

fn request_head_bytes(path: &str, headers: &HeaderMap, body_len: usize) -> usize {
    let request_line = "POST ".len() + path.len() + " HTTP/1.1\r\n".len();
    let content_length = "content-length: ".len() + body_len.to_string().len() + "\r\n".len();
    let header_sum: usize = headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4)
        .sum();
    request_line + header_sum + content_length + 2
}

fn build_headers(
    method_name: &'static str,
    tool_name: Option<&str>,
    bearer_token: Option<&str>,
    idempotency: Option<IdempotencyHeader<'_>>,
) -> Result<HeaderMap, TransportFault> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    headers.insert(
        HEADER_PROTOCOL_VERSION,
        HeaderValue::from_static(PROTOCOL_VERSION),
    );
    headers.insert(HEADER_MCP_METHOD, HeaderValue::from_static(method_name));
    if let Some(name) = tool_name {
        let encoded = encode_mcp_name(name);
        let value =
            HeaderValue::from_str(&encoded).map_err(|_| pre_send(FaultKind::TerminalRefusal))?;
        headers.insert(HEADER_MCP_NAME, value);
    }
    if let Some(token) = bearer_token {
        if token.is_empty()
            || token.len() > MAX_REQUEST_HEADER_BYTES
            || !token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(pre_send(FaultKind::TerminalRefusal));
        }
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| pre_send(FaultKind::TerminalRefusal))?;
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);
    }
    if let Some(idem) = idempotency {
        validate_idempotency_header(idem)?;
        let header_value =
            HeaderValue::from_str(idem.value).map_err(|_| pre_send(FaultKind::TerminalRefusal))?;
        headers.insert(HEADER_IDEMPOTENCY_KEY, header_value);
    }
    Ok(headers)
}

pub(crate) fn is_allowed_idempotency_header_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("idempotency-key")
}

fn validate_idempotency_header(idem: IdempotencyHeader<'_>) -> Result<(), TransportFault> {
    if !is_allowed_idempotency_header_name(idem.name)
        || idem.value.is_empty()
        || idem.value.len() > 256
        || !idem.value.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(pre_send(FaultKind::TerminalRefusal));
    }
    Ok(())
}

async fn exchange_mcp(
    connection: Box<dyn transport::Connection>,
    mut outbound: hyper::Request<Full<Bytes>>,
    expected_id: &str,
    deadline: Instant,
    idle_read: Duration,
) -> Result<Value, TransportFault> {
    let interim_count = Arc::new(AtomicUsize::new(0));
    let interim_overflow = Arc::new(Notify::new());
    let interim_activity = Arc::new(Notify::new());
    {
        let count = interim_count.clone();
        let overflow = interim_overflow.clone();
        let activity = interim_activity.clone();
        hyper::ext::on_informational(&mut outbound, move |_res| {
            if count.fetch_add(1, Ordering::SeqCst) + 1 > MAX_INTERIM_RESPONSES {
                overflow.notify_one();
            } else {
                activity.notify_one();
            }
        });
    }
    let (mut sender, conn) = http1::Builder::new()
        .max_headers(MAX_RESPONSE_HEADERS)
        .max_header_size(MAX_RESPONSE_HEADER_BYTES)
        .max_buf_size(MAX_READ_BUFFER)
        .handshake::<_, Full<Bytes>>(TokioIo::new(connection))
        .await
        .map_err(|e| post_send_hyper_error(&e))?;

    let response_fut = async {
        let send_fut = sender.send_request(outbound);
        tokio::pin!(send_fut);
        let res = loop {
            let step_deadline = deadline.min(Instant::now() + idle_read);
            tokio::select! {
                biased;
                _ = interim_overflow.notified() => {
                    return Err(post_send(FaultKind::TerminalRefusal));
                }
                sent = &mut send_fut => match sent {
                    Err(e) => return Err(post_send_hyper_error(&e)),
                    Ok(r) => break r,
                },
                _ = interim_activity.notified() => {
                    if Instant::now() >= deadline {
                        return Err(post_send(FaultKind::Transient(RetryAfter::None)));
                    }
                }
                _ = sleep_until(step_deadline) => {
                    return Err(post_send(FaultKind::Transient(RetryAfter::None)));
                }
            }
        };
        if interim_count.load(Ordering::SeqCst) > MAX_INTERIM_RESPONSES {
            return Err(post_send(FaultKind::TerminalRefusal));
        }
        decode_response(res, expected_id, deadline, idle_read).await
    };

    tokio::pin!(conn, response_fut);
    let mut driving = true;
    loop {
        tokio::select! {
            result = &mut response_fut => return result,
            _ = &mut conn, if driving => driving = false,
        }
    }
}

fn post_send(kind: FaultKind) -> TransportFault {
    TransportFault {
        kind,
        bytes_may_have_left: true,
    }
}

fn post_send_hyper_error(e: &hyper::Error) -> TransportFault {
    if e.is_parse() || e.is_parse_too_large() {
        return post_send(FaultKind::TerminalRefusal);
    }
    let mut src = std::error::Error::source(e);
    while let Some(err) = src {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind;
            let kind = match io.kind() {
                ErrorKind::InvalidData | ErrorKind::InvalidInput => FaultKind::TerminalRefusal,
                ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
                | ErrorKind::NotConnected
                | ErrorKind::NetworkDown
                | ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
                | ErrorKind::TimedOut
                | ErrorKind::Interrupted => FaultKind::Transient(RetryAfter::None),
                _ => FaultKind::TerminalRefusal,
            };
            return post_send(kind);
        }
        src = err.source();
    }
    if e.is_incomplete_message() || e.is_closed() || e.is_canceled() || e.is_body_write_aborted() {
        post_send(FaultKind::Transient(RetryAfter::None))
    } else {
        post_send(FaultKind::TerminalRefusal)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseMedia {
    Json,
    Sse,
}

fn parse_media_type(headers: &HeaderMap) -> Result<ResponseMedia, TransportFault> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(first) = values.next() else {
        return Err(post_send(FaultKind::TerminalRefusal));
    };
    if values.next().is_some() {
        return Err(post_send(FaultKind::TerminalRefusal));
    }
    let text = first
        .to_str()
        .map_err(|_| post_send(FaultKind::TerminalRefusal))?;
    let mut parts = text.split(';').map(str::trim);
    let media = match parts.next().unwrap_or("") {
        m if m.eq_ignore_ascii_case("application/json") => ResponseMedia::Json,
        m if m.eq_ignore_ascii_case("text/event-stream") => ResponseMedia::Sse,
        _ => return Err(post_send(FaultKind::TerminalRefusal)),
    };
    if let Some(param) = parts.next() {
        let Some((k, v)) = param.split_once('=') else {
            return Err(post_send(FaultKind::TerminalRefusal));
        };
        if !k.trim().eq_ignore_ascii_case("charset")
            || !(v.trim().eq_ignore_ascii_case("utf-8")
                || v.trim().eq_ignore_ascii_case("\"utf-8\""))
            || parts.next().is_some()
        {
            return Err(post_send(FaultKind::TerminalRefusal));
        }
    }
    Ok(media)
}

fn map_body_frame_error(err: Box<dyn std::error::Error + Send + Sync>) -> TransportFault {
    if err
        .downcast_ref::<http_body_util::LengthLimitError>()
        .is_some()
    {
        return post_send(FaultKind::TerminalRefusal);
    }
    if let Some(hyper_err) = err.downcast_ref::<hyper::Error>() {
        return post_send_hyper_error(hyper_err);
    }
    post_send(FaultKind::TerminalRefusal)
}

async fn decode_response(
    response: hyper::Response<hyper::body::Incoming>,
    expected_id: &str,
    deadline: Instant,
    idle_read: Duration,
) -> Result<Value, TransportFault> {
    let (head, body) = response.into_parts();
    if head.status == StatusCode::SWITCHING_PROTOCOLS {
        return Err(post_send(FaultKind::TerminalRefusal));
    }
    match head.status.as_u16() {
        200 => {}
        408 | 429 | 502 | 503 | 504 => {
            return Err(post_send(FaultKind::Transient(parse_retry_after(
                &head.headers,
            ))));
        }
        _ => return Err(post_send(FaultKind::TerminalRefusal)),
    }
    let length = transport::framed_length(&head, MAX_RESPONSE_BODY_BYTES)
        .map_err(|_| post_send(FaultKind::TerminalRefusal))?;
    let media = parse_media_type(&head.headers)?;
    let mut limited = Limited::new(body, MAX_RESPONSE_BODY_BYTES);
    let mut total: usize = 0;

    match media {
        ResponseMedia::Json => {
            let mut buf = Vec::with_capacity(length.unwrap_or(0).min(65_536) as usize);
            loop {
                let read_deadline = deadline.min(Instant::now() + idle_read);
                let Some(frame) = timeout_at(read_deadline, limited.frame())
                    .await
                    .map_err(|_| post_send(FaultKind::Transient(RetryAfter::None)))?
                else {
                    break;
                };
                let frame = frame.map_err(map_body_frame_error)?;
                let data = frame
                    .into_data()
                    .map_err(|_| post_send(FaultKind::TerminalRefusal))?;
                total += data.len();
                buf.extend_from_slice(&data);
            }
            if length.is_some_and(|n| n != total as u64) {
                return Err(post_send(FaultKind::TerminalRefusal));
            }
            let value = unique(&buf).map_err(|_| post_send(FaultKind::TerminalRefusal))?;
            match classify_jsonrpc_message(value, expected_id, false)? {
                JsonRpcFrame::Final(FinalPayload::Result(result)) => Ok(result),
                JsonRpcFrame::Final(FinalPayload::InvalidParams) => {
                    Err(post_send(FaultKind::Semantic {
                        is_tool_error: false,
                    }))
                }
                JsonRpcFrame::Progress => Err(post_send(FaultKind::TerminalRefusal)),
            }
        }
        ResponseMedia::Sse => {
            let mut parser = McpSseParser::default();
            let mut final_payload: Option<FinalPayload> = None;
            loop {
                let read_deadline = deadline.min(Instant::now() + idle_read);
                let Some(frame) = timeout_at(read_deadline, limited.frame())
                    .await
                    .map_err(|_| post_send(FaultKind::Transient(RetryAfter::None)))?
                else {
                    break;
                };
                let frame = frame.map_err(map_body_frame_error)?;
                let data = frame
                    .into_data()
                    .map_err(|_| post_send(FaultKind::TerminalRefusal))?;
                total += data.len();
                for &b in &data {
                    let Some(event) = parser.byte(b)? else {
                        continue;
                    };
                    if let Some(name) = event.name.as_deref()
                        && name != "message"
                    {
                        return Err(post_send(FaultKind::TerminalRefusal));
                    }
                    if final_payload.is_some() {
                        return Err(post_send(FaultKind::TerminalRefusal));
                    }
                    let value =
                        unique(&event.data).map_err(|_| post_send(FaultKind::TerminalRefusal))?;
                    match classify_jsonrpc_message(value, expected_id, true)? {
                        JsonRpcFrame::Progress => {}
                        JsonRpcFrame::Final(payload) => final_payload = Some(payload),
                    }
                }
            }
            if length.is_some_and(|n| n != total as u64) || !parser.ended() {
                return Err(post_send(FaultKind::TerminalRefusal));
            }
            match final_payload {
                Some(FinalPayload::Result(result)) => Ok(result),
                Some(FinalPayload::InvalidParams) => Err(post_send(FaultKind::Semantic {
                    is_tool_error: false,
                })),
                None => Err(post_send(FaultKind::TerminalRefusal)),
            }
        }
    }
}

enum FinalPayload {
    Result(Value),
    InvalidParams,
}

enum JsonRpcFrame {
    Progress,
    Final(FinalPayload),
}

fn classify_jsonrpc_message(
    value: Value,
    expected_id: &str,
    allow_progress: bool,
) -> Result<JsonRpcFrame, TransportFault> {
    let Some(obj) = value.as_object() else {
        return Err(post_send(FaultKind::TerminalRefusal));
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(post_send(FaultKind::TerminalRefusal));
    }
    if let Some(method) = obj.get("method") {
        // Server-initiated JSON-RPC requests (`method` + `id`) violate the stateless profile.
        if obj.contains_key("id") {
            return Err(post_send(FaultKind::TerminalRefusal));
        }
        if allow_progress && method.as_str() == Some("notifications/progress") {
            return Ok(JsonRpcFrame::Progress);
        }
        return Err(post_send(FaultKind::TerminalRefusal));
    }
    if !obj
        .keys()
        .all(|k| matches!(k.as_str(), "jsonrpc" | "id" | "result" | "error"))
    {
        return Err(post_send(FaultKind::TerminalRefusal));
    }
    if obj.get("id").and_then(Value::as_str) != Some(expected_id) {
        return Err(post_send(FaultKind::TerminalRefusal));
    }
    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");
    if has_result == has_error {
        return Err(post_send(FaultKind::TerminalRefusal));
    }
    if let Some(err) = obj.get("error") {
        let err_obj = err
            .as_object()
            .ok_or_else(|| post_send(FaultKind::TerminalRefusal))?;
        if !err_obj
            .keys()
            .all(|k| matches!(k.as_str(), "code" | "message" | "data"))
        {
            return Err(post_send(FaultKind::TerminalRefusal));
        }
        let code = err_obj
            .get("code")
            .and_then(Value::as_i64)
            .ok_or_else(|| post_send(FaultKind::TerminalRefusal))?;
        if err_obj.get("message").and_then(Value::as_str).is_none() {
            return Err(post_send(FaultKind::TerminalRefusal));
        }
        return if code == -32602 {
            Ok(JsonRpcFrame::Final(FinalPayload::InvalidParams))
        } else {
            Err(post_send(FaultKind::TerminalRefusal))
        };
    }
    Ok(JsonRpcFrame::Final(FinalPayload::Result(
        obj.get("result")
            .cloned()
            .ok_or_else(|| post_send(FaultKind::TerminalRefusal))?,
    )))
}

struct SseEvent {
    name: Option<String>,
    data: Vec<u8>,
}

/// Bounded SSE parser supporting `4 MiB` MCP payloads (with UTF-8 validation per line).
#[derive(Default)]
struct McpSseParser {
    line: Vec<u8>,
    data: Vec<u8>,
    name: Option<String>,
    after_cr: bool,
}

impl McpSseParser {
    fn byte(&mut self, b: u8) -> Result<Option<SseEvent>, TransportFault> {
        if std::mem::take(&mut self.after_cr) && b == b'\n' {
            return Ok(None);
        }
        if !matches!(b, b'\r' | b'\n') {
            if self.line.len() >= MAX_RESPONSE_BODY_BYTES {
                return Err(post_send(FaultKind::TerminalRefusal));
            }
            self.line.push(b);
            return Ok(None);
        }
        self.after_cr = b == b'\r';
        let line =
            std::str::from_utf8(&self.line).map_err(|_| post_send(FaultKind::TerminalRefusal))?;
        if line.is_empty() {
            let name = self.name.take();
            self.line.clear();
            if self.data.pop().is_some() {
                return Ok(Some(SseEvent {
                    name,
                    data: std::mem::take(&mut self.data),
                }));
            }
            return Ok(None);
        }
        if !line.starts_with(':') {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "data" => {
                    if value.len() + 1 > MAX_RESPONSE_BODY_BYTES - self.data.len() {
                        return Err(post_send(FaultKind::TerminalRefusal));
                    }
                    self.data.extend_from_slice(value.as_bytes());
                    self.data.push(b'\n');
                }
                "event" => self.name = Some(value.to_owned()),
                "id" | "retry" => {}
                _ => return Err(post_send(FaultKind::TerminalRefusal)),
            }
        }
        self.line.clear();
        Ok(None)
    }

    fn ended(&self) -> bool {
        self.line.is_empty() && self.data.is_empty() && self.name.is_none()
    }
}

fn check_stateless_result_envelope(obj: &Map<String, Value>) -> Result<(), FaultKind> {
    // Reject MCP `2026-07-28` non-complete `resultType` (`input_required`, `partial`, non-string,
    // etc.) and interactive elicitation indicators under the stateless profile.
    if let Some(result_type) = obj.get("resultType")
        && result_type.as_str() != Some("complete")
    {
        return Err(FaultKind::TerminalRefusal);
    }
    if obj.get("status").and_then(Value::as_str) == Some("input_required")
        || obj.get("input_required") == Some(&Value::Bool(true))
        || obj.get("inputRequired") == Some(&Value::Bool(true))
    {
        return Err(FaultKind::TerminalRefusal);
    }
    Ok(())
}

fn parse_tools_list(result: &Value) -> Option<Vec<RemoteToolDeclaration>> {
    let obj = result.as_object()?;
    check_stateless_result_envelope(obj).ok()?;
    let tools = obj.get("tools")?.as_array()?;
    let mut out = Vec::with_capacity(tools.len());
    for entry in tools {
        let obj = entry.as_object()?;
        let name = obj.get("name")?.as_str()?.to_owned();
        let schema = obj.get("inputSchema")?;
        if !schema.is_object() {
            return None;
        }
        out.push(RemoteToolDeclaration {
            name,
            input_schema: schema.clone(),
        });
    }
    Some(out)
}

fn parse_tool_call_result(result: &Value) -> Result<ToolCallSuccess, FaultKind> {
    let obj = result.as_object().ok_or(FaultKind::TerminalRefusal)?;
    check_stateless_result_envelope(obj)?;
    if let Some(is_error) = obj.get("isError") {
        match is_error.as_bool() {
            Some(true) => {
                return Err(FaultKind::Semantic {
                    is_tool_error: true,
                });
            }
            Some(false) => {}
            None => return Err(FaultKind::TerminalRefusal),
        }
    }
    let structured = obj.get("structuredContent").cloned();
    let meta = obj.get("_meta").cloned();
    let mut chunks = Vec::new();
    if let Some(content) = obj.get("content") {
        let items = content.as_array().ok_or(FaultKind::TerminalRefusal)?;
        for item in items {
            let item_obj = item.as_object().ok_or(FaultKind::TerminalRefusal)?;
            let kind = item_obj
                .get("type")
                .and_then(Value::as_str)
                .ok_or(FaultKind::TerminalRefusal)?;
            if kind == "text" {
                let text = item_obj
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or(FaultKind::TerminalRefusal)?;
                chunks.push(text);
            } else {
                // Reject `input_required` items and unsupported binary/resource content blocks.
                return Err(FaultKind::TerminalRefusal);
            }
        }
    }
    let (content_blocks, text) = if !chunks.is_empty() {
        let joined = chunks.join("\n");
        let blocks = chunks.into_iter().map(str::to_owned).collect();
        (blocks, joined)
    } else if let Some(ref s) = structured {
        (Vec::new(), s.to_string())
    } else {
        return Err(FaultKind::TerminalRefusal);
    };
    if text.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(FaultKind::TerminalRefusal);
    }
    Ok(ToolCallSuccess {
        text,
        content_blocks,
        structured,
        meta,
    })
}

/// Test seams. Absent from production builds; integration tests reach local TLS via `TEST_GATEWAY_HOST`.
#[cfg(test)]
impl McpTransport {
    pub(crate) fn with_lookup(
        mut self,
        lookup: impl Fn(&str, u16) -> std::io::Result<Vec<std::net::SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.lookup = Arc::new(lookup);
        self
    }

    pub(crate) fn allow_loopback_fixture(mut self) -> Self {
        self.loopback = true;
        self
    }

    pub(crate) fn with_slots(mut self, slots: Arc<Semaphore>) -> Self {
        self.slots = slots;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_http::fixture::{Ca, HOST, Reply, Server, loopback, response};
    use std::net::SocketAddr;
    use std::sync::Mutex;

    fn mcp_transport(port: u16, ca: &Ca) -> McpTransport {
        McpTransport::new(
            &format!("https://{HOST}:{port}/mcp"),
            Trust::Bundle(&ca.pem()),
            &[],
            McpTimeouts {
                setup: Duration::from_secs(3),
                idle_read: Duration::from_secs(3),
                call: Duration::from_secs(5),
            },
        )
        .unwrap()
        .with_lookup(loopback)
        .allow_loopback_fixture()
    }

    fn stop_rx() -> (watch::Sender<Option<Stop>>, watch::Receiver<Option<Stop>>) {
        watch::channel(None)
    }

    #[test]
    fn mcp_name_value_encoding_matches_2026_07_28_spec() {
        assert_eq!(encode_mcp_name("execute_sql"), "execute_sql");
        assert_eq!(
            encode_mcp_name("left\tright"),
            "=?base64?bGVmdAlyaWdodA==?="
        );
        assert_eq!(encode_mcp_name(""), "=?base64??=");
        assert_eq!(encode_mcp_name(" leading"), "=?base64?IGxlYWRpbmc=?=");
        assert_eq!(encode_mcp_name("trailing "), "=?base64?dHJhaWxpbmcg?=");
        assert_eq!(encode_mcp_name("café"), "=?base64?Y2Fmw6k=?=");
        assert_eq!(
            encode_mcp_name("=?base64?literal?="),
            format!("=?base64?{}?=", STANDARD.encode(b"=?base64?literal?="))
        );
        // Only simultaneously starting with `=?base64?` AND ending with `?=` triggers sentinel encoding.
        assert_eq!(encode_mcp_name("=?base64?unclosed"), "=?base64?unclosed");
        // Control characters 0x00..=0x1F and 0x7F must encode.
        assert!(encode_mcp_name("a\x00b").starts_with("=?base64?"));
        assert!(encode_mcp_name("a\x1fb").starts_with("=?base64?"));
        assert!(encode_mcp_name("a\x7fb").starts_with("=?base64?"));
    }

    #[tokio::test]
    async fn wire_headers_meta_json_sse_and_mcp_name_encoding() {
        let ca = Ca::new();
        let captured = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
        let captured_server = captured.clone();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_server = counter.clone();
        let server = Server::start(ca.leaf(HOST, false), move |req| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            captured_server
                .lock()
                .unwrap()
                .push((req.head.clone(), body.clone()));
            let id = body["id"].as_str().unwrap();
            if counter_server.fetch_add(1, Ordering::SeqCst) == 0 {
                let payload = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{"type": "text", "text": "json-ok"}]
                    }
                })
                .to_string();
                Reply::Bytes(response(
                    200,
                    &[("content-type", "APPLICATION/JSON; charset=UTF-8")],
                    payload.as_bytes(),
                ))
            } else {
                let sse = format!(
                    ": keep-alive comment\r\n\r\ndata: {}\n\nevent: message\ndata: {}\n\n",
                    json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {"progress": 1, "total": 2}
                    }),
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{"type": "text", "text": "sse-ok"}]
                        }
                    })
                );
                Reply::Bytes(response(
                    200,
                    &[("content-type", "text/event-stream; charset=\"utf-8\"")],
                    sse.as_bytes(),
                ))
            }
        })
        .await;

        let transport = mcp_transport(server.port, &ca);
        let (_tx, mut stop) = stop_rx();
        let deadline = Instant::now() + Duration::from_secs(5);
        let args = json!({"sql": "SELECT 1"});
        let res1 = transport
            .tools_call(
                &ToolCallRequest {
                    request_id: "req-1",
                    tool_name: "left\tright",
                    arguments: &args,
                    bearer_token: Some("canary-bearer-secret"),
                    idempotency_header: Some(IdempotencyHeader {
                        name: "Idempotency-Key",
                        value: "idem-key-1",
                    }),
                    idempotency_meta: Some(IdempotencyMeta {
                        field: "openmettle/idempotencyKey",
                        value: "idem-key-1",
                    }),
                },
                deadline,
                &mut stop,
            )
            .await
            .unwrap();
        assert_eq!(res1.text, "json-ok");

        let res2 = transport
            .tools_call(
                &ToolCallRequest {
                    request_id: "req-2",
                    tool_name: "café",
                    arguments: &args,
                    bearer_token: None,
                    idempotency_header: None,
                    idempotency_meta: None,
                },
                deadline,
                &mut stop,
            )
            .await
            .unwrap();
        assert_eq!(res2.text, "sse-ok");

        let log = captured.lock().unwrap();
        assert_eq!(log.len(), 2);
        let (head1, body1) = &log[0];
        let lower1 = head1.to_ascii_lowercase();
        assert!(lower1.contains("mcp-protocol-version: 2026-07-28\r\n"));
        assert!(lower1.contains("mcp-method: tools/call\r\n"));
        assert!(head1.contains("mcp-name: =?base64?bGVmdAlyaWdodA==?=\r\n"));
        assert!(lower1.contains("accept: application/json, text/event-stream\r\n"));
        assert!(lower1.contains("idempotency-key: idem-key-1\r\n"));
        assert!(lower1.contains("authorization: bearer canary-bearer-secret\r\n"));
        assert!(!lower1.contains("mcp-session-id"));
        assert!(!lower1.contains("mcp-param-"));
        assert_eq!(body1["params"]["name"], "left\tright");
        assert_eq!(
            body1["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            body1["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            json!({})
        );
        assert_eq!(
            body1["params"]["_meta"]["openmettle/idempotencyKey"],
            "idem-key-1"
        );

        let (head2, body2) = &log[1];
        assert!(head2.contains("mcp-name: =?base64?Y2Fmw6k=?=\r\n"));
        assert_eq!(body2["params"]["name"], "café");
    }

    #[tokio::test]
    async fn interim_1xx_bounds_and_101_refusal() {
        let ca = Ca::new();
        let mode = Arc::new(AtomicUsize::new(0));
        let mode_server = mode.clone();
        let server = Server::start(ca.leaf(HOST, false), move |req| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let id = body["id"].as_str().unwrap();
            let ok = response(
                200,
                &[("content-type", "application/json")],
                json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"after-103"}]}})
                    .to_string()
                    .as_bytes(),
            );
            match mode_server.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    // 4 interim 103 Early Hints -> accepted
                    let mut raw = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
                        .repeat(4);
                    raw.extend_from_slice(&ok);
                    Reply::Bytes(raw)
                }
                1 => {
                    // 5 interim 103 Early Hints -> TerminalRefusal
                    let mut raw = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
                        .repeat(5);
                    raw.extend_from_slice(&ok);
                    Reply::Bytes(raw)
                }
                _ => {
                    // Unrequested 101 Switching Protocols -> immediate TerminalRefusal
                    Reply::Bytes(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                            .to_vec(),
                    )
                }
            }
        })
        .await;

        let transport = mcp_transport(server.port, &ca);
        let (_tx, mut stop) = stop_rx();
        let args = json!({});
        let req = |id| ToolCallRequest {
            request_id: id,
            tool_name: "execute_sql",
            arguments: &args,
            bearer_token: None,
            idempotency_header: None,
            idempotency_meta: None,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(
            transport
                .tools_call(&req("four-103"), deadline, &mut stop)
                .await
                .unwrap()
                .text,
            "after-103"
        );
        assert_eq!(
            transport
                .tools_call(&req("five-103"), deadline, &mut stop)
                .await
                .unwrap_err(),
            TransportFault {
                kind: FaultKind::TerminalRefusal,
                bytes_may_have_left: true,
            }
        );
        assert_eq!(
            transport
                .tools_call(&req("proto-101"), deadline, &mut stop)
                .await
                .unwrap_err(),
            TransportFault {
                kind: FaultKind::TerminalRefusal,
                bytes_may_have_left: true,
            }
        );
    }

    #[tokio::test]
    async fn final_status_matrix_and_retry_after_parsing() {
        type StatusCase = (u16, Vec<(&'static str, &'static str)>, FaultKind);
        let ca = Ca::new();
        let statuses: Vec<StatusCase> = vec![
            (408, vec![], FaultKind::Transient(RetryAfter::None)),
            (
                429,
                vec![("retry-after", "12")],
                FaultKind::Transient(RetryAfter::Seconds(12)),
            ),
            (
                503,
                vec![("retry-after", "61")],
                FaultKind::Transient(RetryAfter::TooLong),
            ),
            (
                502,
                vec![("retry-after", "not-a-number")],
                FaultKind::Transient(RetryAfter::None),
            ),
            (
                504,
                vec![("retry-after", "5"), ("retry-after", "10")],
                FaultKind::Transient(RetryAfter::None),
            ),
            (201, vec![], FaultKind::TerminalRefusal),
            (202, vec![], FaultKind::TerminalRefusal),
            (204, vec![], FaultKind::TerminalRefusal),
            (
                302,
                vec![("location", "https://evil.example/")],
                FaultKind::TerminalRefusal,
            ),
            (400, vec![], FaultKind::TerminalRefusal),
            (401, vec![], FaultKind::TerminalRefusal),
            (403, vec![], FaultKind::TerminalRefusal),
            (404, vec![], FaultKind::TerminalRefusal),
            (500, vec![], FaultKind::TerminalRefusal),
            (501, vec![], FaultKind::TerminalRefusal),
            (505, vec![], FaultKind::TerminalRefusal),
        ];
        let scripted = Arc::new(statuses.clone());
        let idx = Arc::new(AtomicUsize::new(0));
        let idx_server = idx.clone();
        let server = Server::start(ca.leaf(HOST, false), move |_| {
            let i = idx_server.fetch_add(1, Ordering::SeqCst);
            let (code, ref hdrs, _) = scripted[i];
            if code == 204 {
                Reply::Bytes(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            } else {
                Reply::Bytes(response(code, hdrs, b"upstream-canary-body"))
            }
        })
        .await;

        let transport = mcp_transport(server.port, &ca);
        let (_tx, mut stop) = stop_rx();
        let args = json!({});
        for (i, (code, _, expected)) in statuses.iter().enumerate() {
            let id = format!("status-{i}");
            let err = transport
                .tools_call(
                    &ToolCallRequest {
                        request_id: &id,
                        tool_name: "write_item",
                        arguments: &args,
                        bearer_token: None,
                        idempotency_header: None,
                        idempotency_meta: None,
                    },
                    Instant::now() + Duration::from_secs(5),
                    &mut stop,
                )
                .await
                .unwrap_err();
            assert_eq!(err.kind, *expected, "status {code}");
            assert!(err.bytes_may_have_left, "status {code}");
            assert!(!format!("{err:?} {err}").contains("upstream-canary-body"));
        }
    }

    #[tokio::test]
    async fn body_framing_size_sse_semantic_and_redaction_rules() {
        let ca = Ca::new();
        let cases: Vec<(&'static str, Vec<u8>, FaultKind)> = vec![
            (
                "non-utf8-charset",
                response(
                    200,
                    &[("content-type", "application/json; charset=iso-8859-1")],
                    br#"{"jsonrpc":"2.0","id":"c0","result":{"content":[{"type":"text","text":"ok"}]}}"#,
                ),
                FaultKind::TerminalRefusal,
            ),
            (
                "gzip-encoding",
                response(
                    200,
                    &[
                        ("content-type", "application/json"),
                        ("content-encoding", "gzip"),
                    ],
                    b"{}",
                ),
                FaultKind::TerminalRefusal,
            ),
            (
                "chunked-trailer",
                {
                    let payload = br#"{"jsonrpc":"2.0","id":"c2","result":{"content":[{"type":"text","text":"ok"}]}}"#;
                    let mut raw = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n",
                        payload.len()
                    )
                    .into_bytes();
                    raw.extend_from_slice(payload);
                    raw.extend_from_slice(b"\r\n0\r\nX-Trailer: forbidden\r\n\r\n");
                    raw
                },
                FaultKind::TerminalRefusal,
            ),
            (
                "mismatched-id",
                response(
                    200,
                    &[("content-type", "application/json")],
                    br#"{"jsonrpc":"2.0","id":"wrong","result":{"content":[{"type":"text","text":"ok"}]}}"#,
                ),
                FaultKind::TerminalRefusal,
            ),
            (
                "duplicate-sse-final",
                response(
                    200,
                    &[("content-type", "text/event-stream")],
                    b"data: {\"jsonrpc\":\"2.0\",\"id\":\"c4\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"1\"}]}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"c4\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"2\"}]}}\n\n",
                ),
                FaultKind::TerminalRefusal,
            ),
            (
                "premature-sse-eof",
                response(
                    200,
                    &[("content-type", "text/event-stream")],
                    b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
                ),
                FaultKind::TerminalRefusal,
            ),
            (
                "server-initiated-request",
                response(
                    200,
                    &[("content-type", "text/event-stream")],
                    b"data: {\"jsonrpc\":\"2.0\",\"id\":\"srv-1\",\"method\":\"elicitation/create\",\"params\":{}}\n\n",
                ),
                FaultKind::TerminalRefusal,
            ),
            (
                "input-required",
                response(
                    200,
                    &[("content-type", "application/json")],
                    br#"{"jsonrpc":"2.0","id":"c7","result":{"status":"input_required","content":[{"type":"text","text":"need input"}]}}"#,
                ),
                FaultKind::TerminalRefusal,
            ),
            (
                "over-4mib-declared",
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                    MAX_RESPONSE_BODY_BYTES + 1
                )
                .into_bytes(),
                FaultKind::TerminalRefusal,
            ),
            (
                "over-4mib-chunked",
                {
                    let mut raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
                    let chunk = vec![b'a'; 64 * 1024];
                    for _ in 0..65 {
                        raw.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                        raw.extend_from_slice(&chunk);
                        raw.extend_from_slice(b"\r\n");
                    }
                    raw.extend_from_slice(b"0\r\n\r\n");
                    raw
                },
                FaultKind::TerminalRefusal,
            ),
            (
                "too-many-headers",
                {
                    let mut raw = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n".to_vec();
                    for i in 0..33 {
                        raw.extend_from_slice(format!("x-h-{i}: v\r\n").as_bytes());
                    }
                    raw.extend_from_slice(b"\r\n{}");
                    raw
                },
                FaultKind::TerminalRefusal,
            ),
            (
                "header-block-over-8k",
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nx-big: {}\r\n\r\n{{}}",
                    "v".repeat(MAX_RESPONSE_HEADER_BYTES + 64)
                )
                .into_bytes(),
                FaultKind::TerminalRefusal,
            ),
            (
                "jsonrpc-invalid-params",
                response(
                    200,
                    &[("content-type", "application/json")],
                    br#"{"jsonrpc":"2.0","id":"c12","error":{"code":-32602,"message":"canary-error-detail"}}"#,
                ),
                FaultKind::Semantic {
                    is_tool_error: false,
                },
            ),
            (
                "mcp-is-error-true",
                response(
                    200,
                    &[("content-type", "application/json")],
                    br#"{"jsonrpc":"2.0","id":"c13","result":{"isError":true,"content":[{"type":"text","text":"canary-tool-error"}]}}"#,
                ),
                FaultKind::Semantic {
                    is_tool_error: true,
                },
            ),
        ];

        let payloads: Arc<Vec<Vec<u8>>> =
            Arc::new(cases.iter().map(|(_, b, _)| b.clone()).collect());
        let idx = Arc::new(AtomicUsize::new(0));
        let idx_server = idx.clone();
        let server = Server::start(ca.leaf(HOST, false), move |_| {
            let i = idx_server.fetch_add(1, Ordering::SeqCst);
            Reply::Bytes(payloads[i].clone())
        })
        .await;

        let transport = mcp_transport(server.port, &ca);
        let (_tx, mut stop) = stop_rx();
        let args = json!({});
        for (i, (label, _, expected)) in cases.iter().enumerate() {
            let id = format!("c{i}");
            let err = transport
                .tools_call(
                    &ToolCallRequest {
                        request_id: &id,
                        tool_name: "execute_sql",
                        arguments: &args,
                        bearer_token: None,
                        idempotency_header: None,
                        idempotency_meta: None,
                    },
                    Instant::now() + Duration::from_secs(5),
                    &mut stop,
                )
                .await
                .unwrap_err();
            assert_eq!(err.kind, *expected, "case {label}");
            assert!(err.bytes_may_have_left, "case {label}");
            let rendered = format!("{err:?} {err} {transport:?}");
            assert!(!rendered.contains("canary"));
            assert!(!rendered.contains(HOST));
        }
    }

    #[tokio::test]
    async fn ssrf_tls_and_pre_send_refusals_report_zero_bytes_sent() {
        let ca = Ca::new();
        let wrong_ca = Ca::new();
        let server = Server::start(wrong_ca.leaf(HOST, false), |_| {
            Reply::Bytes(response(
                200,
                &[("content-type", "application/json")],
                b"{}",
            ))
        })
        .await;
        let (_tx, mut stop) = stop_rx();
        let args = json!({});
        let req = ToolCallRequest {
            request_id: "pre-1",
            tool_name: "execute_sql",
            arguments: &args,
            bearer_token: Some("canary-secret"),
            idempotency_header: None,
            idempotency_meta: None,
        };

        // Untrusted TLS certificate -> TerminalRefusal, bytes_may_have_left == false
        let bad_tls = mcp_transport(server.port, &ca);
        let err = bad_tls
            .tools_call(&req, Instant::now() + Duration::from_secs(5), &mut stop)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            TransportFault {
                kind: FaultKind::TerminalRefusal,
                bytes_may_have_left: false,
            }
        );

        // SSRF link-local / cloud metadata address -> TerminalRefusal, bytes_may_have_left == false
        let ssrf = McpTransport::new(
            &format!("https://{HOST}/mcp"),
            Trust::Bundle(&ca.pem()),
            &[],
            McpTimeouts::default(),
        )
        .unwrap()
        .with_lookup(|_, port| Ok(vec![SocketAddr::from(([169, 254, 169, 254], port))]));
        let err = ssrf
            .tools_call(&req, Instant::now() + Duration::from_secs(5), &mut stop)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            TransportFault {
                kind: FaultKind::TerminalRefusal,
                bytes_may_have_left: false,
            }
        );

        // Forbidden header names (`Mcp-Session-Id`, `Mcp-Param-*`, `Authorization`, `Expect`,
        // `Content-Encoding`, `X-Custom-Key`) are rejected pre-send; only `Idempotency-Key`
        // (case-insensitive) is accepted.
        for bad_hdr in [
            "Mcp-Session-Id",
            "Mcp-Param-Foo",
            "Authorization",
            "Expect",
            "Content-Encoding",
            "X-Custom-Key",
        ] {
            let err = bad_tls
                .tools_call(
                    &ToolCallRequest {
                        idempotency_header: Some(IdempotencyHeader {
                            name: bad_hdr,
                            value: "val",
                        }),
                        ..req
                    },
                    Instant::now() + Duration::from_secs(5),
                    &mut stop,
                )
                .await
                .unwrap_err();
            assert_eq!(
                err,
                TransportFault {
                    kind: FaultKind::TerminalRefusal,
                    bytes_may_have_left: false,
                },
                "header {bad_hdr} must fail pre-send"
            );
        }

        // Whole-call timeout > 300s or zero idle_read rejected at construction.
        assert_eq!(
            McpTransport::new(
                &format!("https://{HOST}/mcp"),
                Trust::Bundle(&ca.pem()),
                &[],
                McpTimeouts {
                    setup: Duration::from_secs(5),
                    idle_read: Duration::from_secs(15),
                    call: Duration::from_secs(301),
                },
            )
            .unwrap_err(),
            Error::Configuration
        );
        assert_eq!(
            McpTransport::new(
                &format!("https://{HOST}/mcp"),
                Trust::Bundle(&ca.pem()),
                &[],
                McpTimeouts {
                    setup: Duration::from_secs(5),
                    idle_read: Duration::ZERO,
                    call: Duration::from_secs(30),
                },
            )
            .unwrap_err(),
            Error::Configuration
        );

        // Plain http:// and IP literals rejected at construction.
        assert_eq!(
            McpTransport::new(
                "http://mcp.example.test/mcp",
                Trust::Bundle(&ca.pem()),
                &[],
                McpTimeouts::default(),
            )
            .unwrap_err(),
            Error::Configuration
        );
        assert_eq!(
            McpTransport::new(
                "https://10.0.0.1/mcp",
                Trust::Bundle(&ca.pem()),
                &["10.0.0.0/8"],
                McpTimeouts::default(),
            )
            .unwrap_err(),
            Error::Configuration
        );

        // Exhausted DNS slot semaphore fails pre-send with Transient and zero bytes sent,
        // and MCP_DNS_SLOTS is strictly distinct from provider_http::DNS_SLOTS.
        assert!(!Arc::ptr_eq(&MCP_DNS_SLOTS, &super::super::DNS_SLOTS));
        let full = Arc::new(Semaphore::new(1));
        let _held = full.clone().acquire_owned().await.unwrap();
        let starved = McpTransport::new(
            &format!("https://{HOST}/mcp"),
            Trust::Bundle(&ca.pem()),
            &[],
            McpTimeouts {
                setup: Duration::from_millis(50),
                idle_read: Duration::from_millis(50),
                call: Duration::from_millis(100),
            },
        )
        .unwrap()
        .with_lookup(loopback)
        .allow_loopback_fixture()
        .with_slots(full);
        let err = starved
            .tools_call(&req, Instant::now() + Duration::from_secs(1), &mut stop)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            TransportFault {
                kind: FaultKind::Transient(RetryAfter::None),
                bytes_may_have_left: false,
            }
        );
    }

    #[tokio::test]
    async fn chunked_positive_control_result_type_error_structure_sse_32602_idle_and_mid_body_close()
     {
        let ca = Ca::new();
        let ok_chunked_payload =
            br#"{"jsonrpc":"2.0","id":"chunk-ok","result":{"content":[{"type":"text","text":"ok"}]}}"#;
        let mut ok_chunked = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n",
            ok_chunked_payload.len()
        )
        .into_bytes();
        ok_chunked.extend_from_slice(ok_chunked_payload);
        ok_chunked.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut trailer_chunked = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n",
            ok_chunked_payload.len()
        )
        .into_bytes();
        trailer_chunked.extend_from_slice(ok_chunked_payload);
        trailer_chunked.extend_from_slice(b"\r\n0\r\nX-Trailer: forbidden\r\n\r\n");

        // Mid-body close (truncated chunked stream) -> Transient (`bytes_may_have_left: true`).
        let truncated_chunked =
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n50\r\n{\"jsonrpc\":\"2.0\""
                .to_vec();
        // Corrupt chunk framing -> TerminalRefusal.
        let corrupt_chunked =
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\nZZ\r\nnot-hex\r\n"
                .to_vec();

        let script_idx = Arc::new(AtomicUsize::new(0));
        let idx_srv = script_idx.clone();
        let ok_chunked_srv = ok_chunked.clone();
        let trailer_chunked_srv = trailer_chunked.clone();
        let server = Server::start(ca.leaf(HOST, false), move |req| {
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let id = body["id"].as_str().unwrap().to_owned();
            match idx_srv.fetch_add(1, Ordering::SeqCst) {
                // 0: valid chunked positive control (no trailers)
                0 => Reply::Bytes(ok_chunked_srv.clone()),
                // 1: identical chunked body WITH trailers -> TerminalRefusal
                1 => Reply::Bytes(trailer_chunked_srv.clone()),
                // 2: `resultType: "complete"` -> allowed
                2 => Reply::Bytes(response(
                    200,
                    &[("content-type", "application/json")],
                    json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"complete","content":[{"type":"text","text":"done"}]}})
                        .to_string()
                        .as_bytes(),
                )),
                // 3: `resultType: "input_required"` -> TerminalRefusal
                3 => Reply::Bytes(response(
                    200,
                    &[("content-type", "application/json")],
                    json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"input_required","content":[{"type":"text","text":"need"}]}})
                        .to_string()
                        .as_bytes(),
                )),
                // 4: `resultType: "partial"` -> TerminalRefusal
                4 => Reply::Bytes(response(
                    200,
                    &[("content-type", "application/json")],
                    json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"partial","content":[{"type":"text","text":"part"}]}})
                        .to_string()
                        .as_bytes(),
                )),
                // 5: non-string `resultType: 123` -> TerminalRefusal
                5 => Reply::Bytes(response(
                    200,
                    &[("content-type", "application/json")],
                    json!({"jsonrpc":"2.0","id":id,"result":{"resultType":123,"content":[{"type":"text","text":"bad"}]}})
                        .to_string()
                        .as_bytes(),
                )),
                // 6: `tools/list` with `resultType: "input_required"` -> TerminalRefusal
                6 => Reply::Bytes(response(
                    200,
                    &[("content-type", "application/json")],
                    json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"input_required","tools":[]}})
                        .to_string()
                        .as_bytes(),
                )),
                // 7: malformed `-32602` missing `message` -> TerminalRefusal
                7 => Reply::Bytes(response(
                    200,
                    &[("content-type", "application/json")],
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602}})
                        .to_string()
                        .as_bytes(),
                )),
                // 8: malformed `-32602` with extra unknown field -> TerminalRefusal
                8 => Reply::Bytes(response(
                    200,
                    &[("content-type", "application/json")],
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"bad","extra":true}})
                        .to_string()
                        .as_bytes(),
                )),
                // 9: SSE `-32602` followed by duplicate final event -> TerminalRefusal
                9 => Reply::Bytes(response(
                    200,
                    &[("content-type", "text/event-stream")],
                    format!(
                        "data: {}\n\ndata: {}\n\n",
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"bad"}}),
                        json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"second"}]}})
                    )
                    .as_bytes(),
                )),
                // 10: SSE `-32602` followed by trailing corrupt/unterminated bytes -> TerminalRefusal
                10 => Reply::Bytes(response(
                    200,
                    &[("content-type", "text/event-stream")],
                    format!(
                        "data: {}\n\ndata: {{corrupt",
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"bad"}})
                    )
                    .as_bytes(),
                )),
                // 11: clean SSE `-32602` with EOF -> Semantic { is_tool_error: false }
                11 => Reply::Bytes(response(
                    200,
                    &[("content-type", "text/event-stream")],
                    format!(
                        "data: {}\n\n",
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"bad"}})
                    )
                    .as_bytes(),
                )),
                // 12: mid-body truncated chunked close -> Transient (bytes_may_have_left: true)
                12 => Reply::Bytes(truncated_chunked.clone()),
                // 13: corrupt chunked framing -> TerminalRefusal
                13 => Reply::Bytes(corrupt_chunked.clone()),
                // 14: stalled SSE stream after progress event -> idle_read Transient
                _ => {
                    let ev = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n";
                    let mut raw = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n",
                        ev.len()
                    )
                    .into_bytes();
                    raw.extend_from_slice(ev);
                    raw.extend_from_slice(b"\r\n");
                    Reply::Stall(raw)
                }
            }
        })
        .await;

        let transport = mcp_transport(server.port, &ca);
        let (_tx, mut stop) = stop_rx();
        let args = json!({});
        let call = |id: &'static str| ToolCallRequest {
            request_id: id,
            tool_name: "execute_sql",
            arguments: &args,
            bearer_token: None,
            idempotency_header: Some(IdempotencyHeader {
                name: "idempotency-key",
                value: "idem-lower",
            }),
            idempotency_meta: None,
        };
        let deadline = || Instant::now() + Duration::from_secs(5);

        // 0: valid chunked without trailers succeeds (also verifies lowercase `idempotency-key`).
        assert_eq!(
            transport
                .tools_call(&call("chunk-ok"), deadline(), &mut stop)
                .await
                .unwrap()
                .text,
            "ok"
        );
        // 1: identical chunked body WITH trailers fails closed.
        assert_eq!(
            transport
                .tools_call(&call("chunk-ok"), deadline(), &mut stop)
                .await
                .unwrap_err(),
            TransportFault {
                kind: FaultKind::TerminalRefusal,
                bytes_may_have_left: true,
            }
        );
        // 2: `resultType: "complete"` succeeds.
        assert_eq!(
            transport
                .tools_call(&call("rt-ok"), deadline(), &mut stop)
                .await
                .unwrap()
                .text,
            "done"
        );
        // 3-5: non-complete `resultType` fails closed.
        for id in ["rt-input", "rt-partial", "rt-num"] {
            assert_eq!(
                transport
                    .tools_call(&call(id), deadline(), &mut stop)
                    .await
                    .unwrap_err()
                    .kind,
                FaultKind::TerminalRefusal,
                "case {id}"
            );
        }
        // 6: `tools/list` with `resultType: "input_required"` fails closed.
        assert_eq!(
            transport
                .tools_list("list-rt", None, deadline(), &mut stop)
                .await
                .unwrap_err()
                .kind,
            FaultKind::TerminalRefusal
        );
        // 7-10: malformed `-32602` & SSE `-32602` + duplicate/trailing bytes -> TerminalRefusal.
        for id in ["err-nomsg", "err-extra", "sse-dup", "sse-corrupt"] {
            assert_eq!(
                transport
                    .tools_call(&call(id), deadline(), &mut stop)
                    .await
                    .unwrap_err()
                    .kind,
                FaultKind::TerminalRefusal,
                "case {id}"
            );
        }
        // 11: clean SSE `-32602` -> Semantic { is_tool_error: false }.
        assert_eq!(
            transport
                .tools_call(&call("sse-ok-32602"), deadline(), &mut stop)
                .await
                .unwrap_err(),
            TransportFault {
                kind: FaultKind::Semantic {
                    is_tool_error: false,
                },
                bytes_may_have_left: true,
            }
        );
        // 12: mid-body close -> Transient (`bytes_may_have_left: true`).
        assert_eq!(
            transport
                .tools_call(&call("mid-close"), deadline(), &mut stop)
                .await
                .unwrap_err(),
            TransportFault {
                kind: FaultKind::Transient(RetryAfter::None),
                bytes_may_have_left: true,
            }
        );
        // 13: corrupt chunk framing -> TerminalRefusal.
        assert_eq!(
            transport
                .tools_call(&call("corrupt-chunk"), deadline(), &mut stop)
                .await
                .unwrap_err(),
            TransportFault {
                kind: FaultKind::TerminalRefusal,
                bytes_may_have_left: true,
            }
        );
        // 14: idle_read timeout aborts stalled SSE stream well before `call` timeout.
        let fast_idle = McpTransport::new(
            &format!("https://{HOST}:{}/mcp", server.port),
            Trust::Bundle(&ca.pem()),
            &[],
            McpTimeouts {
                setup: Duration::from_secs(3),
                idle_read: Duration::from_millis(120),
                call: Duration::from_secs(10),
            },
        )
        .unwrap()
        .with_lookup(loopback)
        .allow_loopback_fixture();
        let err = fast_idle
            .tools_call(
                &call("sse-stall"),
                Instant::now() + Duration::from_secs(10),
                &mut stop,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            TransportFault {
                kind: FaultKind::Transient(RetryAfter::None),
                bytes_may_have_left: true,
            }
        );
    }
}
