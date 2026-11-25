//! Public problems contain only static text and a validated numeric retry delay.
use super::Error;
pub use crate::telemetry::metrics::{GatewayCause as Cause, GatewayStep};
use hyper::header::{HeaderMap, RETRY_AFTER};

pub(crate) fn retry_delay(headers: &HeaderMap) -> Option<u32> {
    let mut values = headers.get_all(RETRY_AFTER).iter();
    let s = values.next()?.to_str().ok()?;
    if values.next().is_some() || s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| *n <= 86400)
}

impl Error {
    pub fn cause(self) -> Cause {
        use super::super::Error as Transport;
        match self {
            Self::Refused(401 | 403) => Cause::ServiceAuth,
            Self::Transport(Transport::Timeout) => Cause::Timeout,
            Self::Deferred(_)
            | Self::Transport(
                Transport::Resolve | Transport::Connect | Transport::Tls | Transport::Address,
            ) => Cause::Transport,
            _ => Cause::Protocol,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    Unauthenticated,
    Hidden,
    Policy,
    Provisioning,
    Failure(Cause),
    Unavailable,
    Timeout,
    RateLimited(Option<u32>),
}

impl Problem {
    pub fn public(self) -> (u16, &'static str, &'static str) {
        match self {
            Self::Unauthenticated => (
                401,
                "unauthenticated",
                "A valid OpenMettle application session is required.",
            ),
            Self::Hidden => (
                404,
                "not_found",
                "The resource does not exist or is not visible to the caller.",
            ),
            Self::Policy => (
                403,
                "policy",
                "Account policy does not permit this model request. Ask your account administrator about access.",
            ),
            Self::Provisioning => (
                503,
                "provisioning",
                "Gateway access for your account is being set up. If this persists, contact your account administrator.",
            ),
            Self::Failure(_) => (
                502,
                "provider_failure",
                "Gateway request failed. Contact the operator with the request ID.",
            ),
            Self::Unavailable => (
                503,
                "unavailable",
                "Gateway access is unavailable. Contact the operator with the request ID.",
            ),
            Self::Timeout => (504, "timeout", "The gateway request timed out."),
            Self::RateLimited(_) => (429, "rate_limited", "The gateway request was rate limited."),
        }
    }
    pub fn from_admin(e: Error) -> Self {
        match e.cause() {
            Cause::Transport => Self::Unavailable,
            Cause::Timeout => Self::Timeout,
            c => Self::Failure(c),
        }
    }
    /// Only the qualified inference route may assert this versioned refusal header.
    /// Neither upstream error messages nor forwarded client headers are evidence.
    pub fn from_inference(status: u16, headers: &HeaderMap, qualified_policy: bool) -> Self {
        let mut values = headers.get_all("openmettle-policy-refusal").iter();
        match status {
            403 if qualified_policy
                && values.next().is_some_and(|v| v == "family-policy-v1")
                && values.next().is_none() =>
            {
                Self::Policy
            }
            401 | 403 => Self::Failure(Cause::Unknown),
            503 => Self::Unavailable,
            504 => Self::Timeout,
            429 => Self::RateLimited(retry_delay(headers)),
            _ => Self::Failure(Cause::Protocol),
        }
    }
    pub fn record(self, step: GatewayStep) {
        let cause = match self {
            Self::Policy => Cause::Policy,
            Self::Failure(c) => c,
            Self::Unavailable => Cause::Transport,
            Self::Timeout => Cause::Timeout,
            _ => return,
        };
        crate::telemetry::gateway_failure(step, cause);
    }
}

#[derive(Clone, Copy)]
pub enum Access {
    Inactive,
    Hidden,
    Denied,
    Entitled,
}
/// Gate the caller's model selection closure (including its default lookup) on local
/// authority, known operational failure and confirmed readiness, in that order.
pub fn select<T>(
    access: Access,
    known: Option<Problem>,
    ready: bool,
    model: impl FnOnce() -> T,
) -> Result<T, Problem> {
    match access {
        Access::Inactive => Err(Problem::Unauthenticated),
        Access::Hidden => Err(Problem::Hidden),
        Access::Denied => Err(Problem::Policy),
        Access::Entitled => match known {
            Some(p) => Err(p),
            None if !ready => Err(Problem::Provisioning),
            None => Ok(model()),
        },
    }
}
