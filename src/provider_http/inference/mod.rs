//! One pinned inference route. The caller owns admission, tool execution and settlement.
//! Only visible text is streamed. Calls become available after the entire response validates.
mod chat;
mod decode;
mod json;
mod request;
mod responses;
mod schema;
pub(crate) mod stream;
mod turn;

pub use request::{History, ImageType, Request, Tool};
pub use schema::SchemaSubset;
pub use turn::{Answer, Call, CallGroup, Reasoning, ToolError, Turn, Usage, VisibleDelta};

use super::{Trust, transport};
use crate::authz::gateway::problem::{Cause, GatewayStep, Problem as GatewayProblem};
use crate::{
    authz::leases::FailReason,
    model_config::{Catalog, Effective, ProfilePin},
    worker::{ActiveRun, StepResult, Stop},
};
use hyper::header::{self, HeaderMap, HeaderValue};
use std::{
    fmt,
    future::Future,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, watch},
    time::{Instant, sleep_until, timeout_at},
};

const BODY: usize = 2 * 1024 * 1024;
const MAX_TEXT: usize = 65536;
const MAX_PARTS: usize = 128;
const MAX_CALLS: usize = 128;
const MAX_ARGUMENT: usize = 65536;
static DNS_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(super::DNS_LOOKUP_SLOTS)));

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Chat,
    Responses,
}

/// Deployment-owned qualification for one model, profile revision tuple and exact HTTPS route.
/// Cancellation closes the local connection. It cannot confirm remote cancellation or billing.
pub struct Qualification {
    pub model: String,
    pub pin: ProfilePin,
    pub protocol: Protocol,
    pub json: bool,
    pub sse: bool,
    pub functions: Option<SchemaSubset>,
    /// Inline PNG/JPEG user inputs. This route never fetches a user-supplied URL.
    pub images: bool,
    pub parallel: bool,
    pub usage: bool,
    /// Patched Chat parser emits whitespace on the content lane inside a tool JSON object.
    pub tool_separator_whitespace: bool,
}

#[derive(Clone, Copy)]
pub struct Timeouts {
    pub setup: Duration,
    pub idle: Duration,
    pub overall: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Gateway(GatewayProblem),
    Validation,
    Provisioning,
    Credential,
    Provider,
    Malformed,
    Incomplete,
    Filtered,
    RateLimited(Option<u32>),
    Unavailable,
    Timeout,
    Stopped(Stop),
}

impl Error {
    /// Fixed application projection. A timeout after headers uses the same code in the active stream.
    pub fn problem(self) -> (u16, &'static str, &'static str) {
        match self {
            Self::Gateway(p) => p.public(),
            Self::Validation => (
                400,
                "validation",
                "Unsupported or invalid inference request.",
            ),
            Self::Provisioning => (
                503,
                "provisioning",
                "Gateway access for this account is being provisioned.",
            ),
            Self::RateLimited(_) => (429, "rate_limited", "Gateway rate limit reached."),
            Self::Unavailable => (503, "unavailable", "Gateway unavailable."),
            Self::Timeout => (504, "timeout", "Gateway request timed out."),
            Self::Stopped(_) => (503, "unavailable", "Inference stopped."),
            _ => (502, "provider_failure", "Gateway inference failed."),
        }
    }
    /// Fixed final error payload when the facade has already committed streaming headers.
    pub fn stream_error(self, protocol: Protocol) -> serde_json::Value {
        use serde_json::json;
        let (_, code, message) = self.problem();
        match protocol {
            Protocol::Chat => json!({"error":{"code":code,"message":message}}),
            Protocol::Responses => json!({"type":"error","code":code,"message":message}),
        }
    }
    fn for_profile(self, qualified: bool) -> Self {
        if !qualified {
            return self;
        }
        let problem = match self {
            Self::Gateway(p) => p,
            Self::Credential => GatewayProblem::Failure(Cause::Protection),
            Self::Provisioning => GatewayProblem::Provisioning,
            Self::RateLimited(delay) => GatewayProblem::RateLimited(delay),
            Self::Unavailable => GatewayProblem::Unavailable,
            Self::Timeout => GatewayProblem::Timeout,
            Self::Malformed | Self::Incomplete | Self::Provider => {
                GatewayProblem::Failure(Cause::Protocol)
            }
            Self::Filtered | Self::Stopped(_) | Self::Validation => return self,
        };
        problem.record(match problem {
            GatewayProblem::Policy => GatewayStep::Policy,
            GatewayProblem::Failure(Cause::Unknown | Cause::Protection) => GatewayStep::Key,
            _ => GatewayStep::Readiness,
        });
        Self::Gateway(problem)
    }
    pub fn step_result(self) -> StepResult {
        match self {
            Self::Stopped(_) => StepResult::Stopped,
            _ => StepResult::Failed(FailReason::StepFailed),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.problem().2)
    }
}
impl std::error::Error for Error {}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        match e {
            super::Error::Timeout => Self::Timeout,
            super::Error::Protocol | super::Error::TooLarge => Self::Malformed,
            super::Error::Connect | super::Error::Resolve => Self::Unavailable,
            _ => Self::Provider,
        }
    }
}

/// Obtained from the gateway credential owner at dispatch. Only that owner can establish missing entitlement.
pub enum Credential<'a> {
    Bearer(&'a str),
    MissingEntitlement,
    Broken,
}

pub struct RunStop {
    stop: watch::Receiver<Option<Stop>>,
    execution_deadline: Instant,
}
impl RunStop {
    /// Pass `cx.stop.clone()`. The renewable StepContext deadline snapshot is not an input.
    pub fn from_worker(run: &ActiveRun, stop: watch::Receiver<Option<Stop>>) -> Self {
        Self {
            stop,
            execution_deadline: run.execution_deadline,
        }
    }
    async fn signal(&mut self) -> Error {
        match self.stop.wait_for(Option::is_some).await {
            Ok(value) => Error::Stopped(value.expect("watch predicate")),
            Err(_) => Error::Unavailable,
        }
    }
}

/// Validated and wire-encoded inference request borrowing its originating [`Gateway`],
/// authoritative model profile, and source [`Request`] so none can be substituted or mutated
/// between [`Gateway::prepare`] and dispatch.
pub struct PreparedRequest<'a> {
    gateway: &'a Gateway,
    model: String,
    profile: &'a crate::model_config::Profile,
    request: &'a Request,
    server: bool,
    round_tokens: Option<i64>,
    output_reserve: Option<i64>,
    round_cost: Option<u128>,
    requires_device_slot: bool,
    body: Vec<u8>,
}

impl<'a> PreparedRequest<'a> {
    pub(crate) fn gateway(&self) -> &'a Gateway {
        self.gateway
    }

    pub(crate) fn model_name(&self) -> &str {
        &self.model
    }

    pub(crate) fn is_server(&self) -> bool {
        self.server
    }

    pub(crate) fn round_tokens(&self) -> Option<i64> {
        self.round_tokens
    }

    pub(crate) fn output_reserve(&self) -> Option<i64> {
        self.output_reserve
    }

    pub(crate) fn round_cost(&self) -> Option<u128> {
        self.round_cost
    }

    pub(crate) fn requires_device_slot(&self) -> bool {
        self.requires_device_slot
    }
}

enum Outbound<'a> {
    Raw(&'a Catalog, &'a Effective, &'a Request),
    Prepared(PreparedRequest<'a>),
}

pub struct Gateway {
    endpoint: transport::Endpoint,
    allowed: Vec<transport::Range>,
    tls: Arc<rustls::ClientConfig>,
    lookup: transport::Lookup,
    qualification: Qualification,
    family_policy_v1: bool,
    timeouts: Timeouts,
    #[cfg(test)]
    loopback: bool,
}
impl Gateway {
    pub fn new(
        endpoint: &str,
        trust: Trust<'_>,
        ranges: &[&str],
        qualification: Qualification,
        timeouts: Timeouts,
    ) -> Result<Self, Error> {
        if ranges.len() > super::MAX_PRIVATE_RANGES
            || [timeouts.setup, timeouts.idle, timeouts.overall]
                .iter()
                .any(|t| t.is_zero() || Instant::now().checked_add(*t).is_none())
        {
            return Err(Error::Validation);
        }
        Ok(Self {
            endpoint: transport::endpoint(endpoint)?,
            allowed: ranges
                .iter()
                .map(|r| transport::private_range(r))
                .collect::<Result<_, _>>()?,
            tls: transport::client_config(transport::roots(trust)?)?,
            lookup: Arc::new(transport::system_lookup),
            qualification,
            family_policy_v1: false,
            timeouts,
            #[cfg(test)]
            loopback: false,
        })
    }

    /// Enable ADR 0037 error semantics on this exact HTTPS route after qualifying its
    /// family-policy-v1 refusal header. Generic external provider profiles retain ADR 0038.
    pub fn with_family_policy_v1(mut self) -> Self {
        self.family_policy_v1 = true;
        self
    }

    fn route(&self) -> transport::Route<'_> {
        transport::Route {
            endpoint: &self.endpoint,
            allowed: &self.allowed,
            tls: &self.tls,
            lookup: &self.lookup,
            slots: &DNS_SLOTS,
            #[cfg(test)]
            loopback: self.loopback,
        }
    }

    fn build_outbound_with_headers(
        &self,
        headers: HeaderMap,
        body: Vec<u8>,
        body_len: usize,
    ) -> Result<hyper::Request<http_body_util::Full<bytes::Bytes>>, Error> {
        let content_length = body_len.to_string();
        let outbound = self.route().request(hyper::Method::POST, &headers, body)?;
        let header_bytes = outbound
            .headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 4)
            .sum::<usize>()
            + "content-length: ".len()
            + content_length.len()
            + 4;
        if header_bytes > super::MAX_REQUEST_HEADER_BYTES {
            return Err(Error::Credential);
        }
        Ok(outbound)
    }

    /// Validate that `prepared` originated from this exact [`Gateway`] instance and that the
    /// complete outbound HTTP headers (including `Host`, `Connection`, `Authorization`, `Accept`,
    /// `Content-Type`, `Content-Length`, and any scoped `x-request-id`) fit within
    /// [`super::MAX_REQUEST_HEADER_BYTES`] before committing a billable gateway handoff.
    pub(crate) fn validate_outbound_headers(
        &self,
        credential: Credential<'_>,
        prepared: &PreparedRequest<'_>,
    ) -> Result<(), Error> {
        if !std::ptr::eq(self, prepared.gateway) {
            return Err(Error::Validation.for_profile(self.family_policy_v1));
        }
        let headers = headers(credential, prepared.request.stream)
            .map_err(|e| e.for_profile(self.family_policy_v1))?;
        self.build_outbound_with_headers(headers, Vec::new(), prepared.body.len())
            .map(|_| ())
            .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    /// Validate model/profile selection against this route and wire-encode the outbound JSON body
    /// before reserving or committing a billable gateway handoff.
    pub fn prepare<'a>(
        &'a self,
        catalog: &'a Catalog,
        effective: &Effective,
        request: &'a Request,
        server: bool,
    ) -> Result<PreparedRequest<'a>, Error> {
        self.prepare_inner(catalog, effective, request, server)
            .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    fn prepare_inner<'a>(
        &'a self,
        catalog: &'a Catalog,
        effective: &Effective,
        request: &'a Request,
        server: bool,
    ) -> Result<PreparedRequest<'a>, Error> {
        // The catalog checks both snapshot revision and profile pin, even for a caller
        // with unknown capacity. Admission owns the populated path and prompt estimate.
        catalog
            .budget(effective, &[], None)
            .map_err(|_| Error::Validation)?;
        let profile = catalog
            .model(&effective.model)
            .filter(|p| {
                p.pin == effective.profile
                    && p.pin == self.qualification.pin
                    && self.qualification.model == effective.model
            })
            .ok_or(Error::Validation)?;
        let round_tokens = effective
            .ceiling
            .value
            .and_then(|n| i64::try_from(n).ok())
            .filter(|&n| n > 0);
        let output_reserve = effective
            .output_reserve
            .value
            .and_then(|n| i64::try_from(n).ok())
            .filter(|&n| n > 0);
        let round_cost = match effective.ceiling.value {
            Some(tokens) => profile
                .round_cost_ceiling(tokens)
                .map_err(|_| Error::Validation)?,
            None => None,
        };
        let requires_device_slot = profile.requires_device_slot;
        let body = request.encode(&self.qualification, profile, effective, server)?;
        Ok(PreparedRequest {
            gateway: self,
            model: effective.model.clone(),
            profile,
            request,
            server,
            round_tokens,
            output_reserve,
            round_cost,
            requires_device_slot,
            body,
        })
    }

    /// The facade captures its tool list at entry. It may forward visible deltas under
    /// backpressure, then release proposed calls on success. Project an error with
    /// `problem` before headers or `stream_error` in a stream that has already started.
    pub async fn caller<F: Future<Output = ()>>(
        &self,
        catalog: &Catalog,
        effective: &Effective,
        request: &Request,
        credential: Credential<'_>,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        self.complete_prepared(
            Outbound::Raw(catalog, effective, request),
            credential,
            None,
            visible,
        )
        .await
        .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    /// Transmit a pre-validated, pre-encoded caller request without repeating wire encoding.
    pub async fn caller_prepared<F: Future<Output = ()>>(
        &self,
        prepared: PreparedRequest<'_>,
        credential: Credential<'_>,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        self.complete_prepared(Outbound::Prepared(prepared), credential, None, visible)
            .await
            .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    /// One model step after the executor's leased authority check. The executor owns
    /// rounds, approvals, fenced effects and publication. Map an error with `step_result`.
    pub async fn server<F: Future<Output = ()>>(
        &self,
        catalog: &Catalog,
        effective: &Effective,
        request: &Request,
        credential: Credential<'_>,
        run: RunStop,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        self.complete_prepared(
            Outbound::Raw(catalog, effective, request),
            credential,
            Some(run),
            visible,
        )
        .await
        .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    /// Transmit a pre-validated, pre-encoded leased server request without repeating wire encoding.
    pub async fn server_prepared<F: Future<Output = ()>>(
        &self,
        prepared: PreparedRequest<'_>,
        credential: Credential<'_>,
        run: RunStop,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        self.complete_prepared(Outbound::Prepared(prepared), credential, Some(run), visible)
            .await
            .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    async fn complete_prepared<F: Future<Output = ()>>(
        &self,
        input: Outbound<'_>,
        credential: Credential<'_>,
        mut run: Option<RunStop>,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        let start = Instant::now();
        let server = run.is_some();
        let dispatch = async {
            let stream = match &input {
                Outbound::Raw(_, _, request) => request.stream,
                Outbound::Prepared(prepared) => prepared.request.stream,
            };
            // Provisioning or a broken credential takes precedence over model selection.
            let headers = headers(credential, stream)?;
            let prepared = match input {
                Outbound::Raw(catalog, effective, request) => {
                    self.prepare_inner(catalog, effective, request, server)?
                }
                Outbound::Prepared(prepared) => {
                    if !std::ptr::eq(self, prepared.gateway)
                        || prepared.server != server
                        || self.qualification.model != prepared.model
                        || self.qualification.pin != prepared.profile.pin
                    {
                        return Err(Error::Validation);
                    }
                    prepared
                }
            };
            let PreparedRequest {
                profile,
                request,
                body,
                ..
            } = prepared;
            let body_len = body.len();
            let outbound = self.build_outbound_with_headers(headers, body, body_len)?;
            let route = self.route();
            let limits = transport::Limits {
                request_body: BODY,
                response_body: BODY,
                response_headers: super::MAX_RESPONSE_HEADERS,
                response_header_bytes: super::MAX_RESPONSE_HEADER_BYTES,
                setup: self.timeouts.setup,
                total: self.timeouts.overall,
            };
            let tls = route
                .connect(start + self.timeouts.setup)
                .await
                .map_err(|e| match e {
                    super::Error::Tls | super::Error::Address if self.family_policy_v1 => {
                        Error::Unavailable
                    }
                    e => Error::from(e),
                })?;
            route
                .exchange(
                    tls,
                    outbound,
                    Instant::now() + self.timeouts.idle,
                    &limits,
                    |response| decode::receive(response, self, profile, request, server, visible),
                )
                .await
        };
        let overall = start + self.timeouts.overall;
        let bounded = timeout_at(overall, dispatch);
        if let Some(run) = run.as_mut() {
            // Scope the HTTP future so the socket drops before waiting for the runner's deadline signal.
            let deadline = run.execution_deadline;
            let completed = tokio::select! {
                biased;
                e = run.signal() => return Err(e),
                _ = sleep_until(deadline) => None,
                result = bounded => Some(result),
            };
            if let Some(cause) = *run.stop.borrow() {
                return Err(Error::Stopped(cause));
            }
            if let Some(result) = completed
                && Instant::now() < deadline
            {
                return within_overall(result, overall);
            }
            Err(run.signal().await)
        } else {
            within_overall(bounded.await, overall)
        }
    }
}

// A ready HTTP frame or synchronous terminal validation can finish without yielding to a timer.
fn within_overall(
    result: Result<Result<Turn, Error>, tokio::time::error::Elapsed>,
    deadline: Instant,
) -> Result<Turn, Error> {
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    result.map_err(|_| Error::Timeout)?
}

fn headers(credential: Credential<'_>, stream: bool) -> Result<HeaderMap, Error> {
    let bearer = match credential {
        Credential::Bearer(token) => {
            if token.is_empty()
                || token.len()
                    > super::MAX_REQUEST_HEADER_BYTES - b"authorization: Bearer \r\n".len()
                || !token.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(Error::Credential);
            }
            let mut bearer =
                HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| Error::Credential)?;
            bearer.set_sensitive(true);
            bearer
        }
        Credential::MissingEntitlement => return Err(Error::Provisioning),
        Credential::Broken => return Err(Error::Credential),
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, bearer);
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static(if stream {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(headers)
}

#[cfg(test)]
impl Gateway {
    pub(crate) fn fixture_lookup(&mut self, lookup: transport::Lookup) {
        self.loopback = true;
        self.lookup = lookup;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_is_single_and_sensitive() {
        let h = headers(Credential::Bearer("fixture-only"), true).unwrap();
        assert_eq!(h.get_all(header::AUTHORIZATION).iter().count(), 1);
        assert!(h[header::AUTHORIZATION].is_sensitive());
    }
}
