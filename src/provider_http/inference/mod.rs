//! One pinned inference route. The caller owns admission, tool execution and settlement.
//! Only visible text is streamed. Calls become available after the entire response validates.
mod chat;
mod decode;
mod json;
mod request;
mod responses;
mod schema;
mod stream;
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

/// Validated and wire-encoded inference request ready to transmit without re-encoding once a
/// dispatch credential is obtained.
pub struct PreparedRequest {
    model: String,
    profile: ProfilePin,
    stream: bool,
    server: bool,
    body: Vec<u8>,
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

    /// Validate model/profile selection against this route and wire-encode the outbound JSON body
    /// before reserving or committing a billable gateway handoff.
    pub fn prepare(
        &self,
        catalog: &Catalog,
        effective: &Effective,
        request: &Request,
        server: bool,
    ) -> Result<PreparedRequest, Error> {
        self.prepare_inner(catalog, effective, request, server)
            .map(|(_, prepared)| prepared)
            .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    fn prepare_inner<'a>(
        &self,
        catalog: &'a Catalog,
        effective: &Effective,
        request: &Request,
        server: bool,
    ) -> Result<(&'a crate::model_config::Profile, PreparedRequest), Error> {
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
        let body = request.encode(&self.qualification, profile, effective, server)?;
        Ok((
            profile,
            PreparedRequest {
                model: effective.model.clone(),
                profile: effective.profile.clone(),
                stream: request.stream,
                server,
                body,
            },
        ))
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
        self.complete_prepared(catalog, effective, request, None, credential, None, visible)
            .await
            .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    /// Transmit a pre-validated, pre-encoded caller request without repeating wire encoding.
    pub async fn caller_prepared<F: Future<Output = ()>>(
        &self,
        catalog: &Catalog,
        effective: &Effective,
        request: &Request,
        prepared: PreparedRequest,
        credential: Credential<'_>,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        self.complete_prepared(
            catalog,
            effective,
            request,
            Some(prepared),
            credential,
            None,
            visible,
        )
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
            catalog,
            effective,
            request,
            None,
            credential,
            Some(run),
            visible,
        )
        .await
        .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    /// Transmit a pre-validated, pre-encoded leased server request without repeating wire encoding.
    #[allow(clippy::too_many_arguments)]
    pub async fn server_prepared<F: Future<Output = ()>>(
        &self,
        catalog: &Catalog,
        effective: &Effective,
        request: &Request,
        prepared: PreparedRequest,
        credential: Credential<'_>,
        run: RunStop,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        self.complete_prepared(
            catalog,
            effective,
            request,
            Some(prepared),
            credential,
            Some(run),
            visible,
        )
        .await
        .map_err(|e| e.for_profile(self.family_policy_v1))
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_prepared<F: Future<Output = ()>>(
        &self,
        catalog: &Catalog,
        effective: &Effective,
        request: &Request,
        prepared: Option<PreparedRequest>,
        credential: Credential<'_>,
        mut run: Option<RunStop>,
        visible: impl FnMut(VisibleDelta) -> F,
    ) -> Result<Turn, Error> {
        let start = Instant::now();
        let server = run.is_some();
        let dispatch = async {
            // Provisioning or a broken credential takes precedence over model selection.
            let headers = headers(credential, request.stream)?;
            let (profile, body) = match prepared {
                Some(prepared) => {
                    if prepared.model != effective.model
                        || prepared.profile != effective.profile
                        || prepared.stream != request.stream
                        || prepared.server != server
                    {
                        return Err(Error::Validation);
                    }
                    let profile = catalog
                        .model(&effective.model)
                        .filter(|p| {
                            p.pin == effective.profile
                                && p.pin == self.qualification.pin
                                && self.qualification.model == effective.model
                        })
                        .ok_or(Error::Validation)?;
                    (profile, prepared.body)
                }
                None => {
                    let (profile, prepared) =
                        self.prepare_inner(catalog, effective, request, server)?;
                    (profile, prepared.body)
                }
            };
            let route = transport::Route {
                endpoint: &self.endpoint,
                allowed: &self.allowed,
                tls: &self.tls,
                lookup: &self.lookup,
                slots: &DNS_SLOTS,
                #[cfg(test)]
                loopback: self.loopback,
            };
            let limits = transport::Limits {
                request_body: BODY,
                response_body: BODY,
                response_headers: super::MAX_RESPONSE_HEADERS,
                response_header_bytes: super::MAX_RESPONSE_HEADER_BYTES,
                setup: self.timeouts.setup,
                total: self.timeouts.overall,
            };
            let content_length = body.len().to_string();
            let outbound = route.request(hyper::Method::POST, &headers, body)?;
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
