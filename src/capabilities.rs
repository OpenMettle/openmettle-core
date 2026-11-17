//! Internal evaluation only: inputs must come from future server policy, never a client.
//! No inventory lookup, authorization enforcement, provider adapter or HTTP serialization.
use std::{
    future::Future,
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorization {
    Allowed,
    Denied,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    Hidden,
    Visible(Authorization),
}

#[derive(Clone, Copy, Debug)]
pub struct Input {
    pub installed: bool,
    pub enabled: bool,
    pub caller: Caller,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ready,
    Degraded,
    Unavailable,
    Unknown,
}

impl Status {
    /// Unknown vocabulary must never become a successful observation.
    pub fn from_code(code: &str) -> Self {
        match code {
            "ready" => Self::Ready,
            "degraded" => Self::Degraded,
            "unavailable" => Self::Unavailable,
            _ => Self::Unknown,
        }
    }
}

/// Only bounded outcomes cross the observation seam; raw errors cannot be returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Status(Status),
    ProviderFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Disabled,
    Timeout,
    ProviderFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readiness {
    pub status: Status,
    pub observed_at: Option<SystemTime>,
    pub reason: Option<Reason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub installed: bool,
    pub authorization: Authorization,
    pub readiness: Option<Readiness>,
}

impl Evaluation {
    /// A discovery hint, never permission to execute. Future consumers must also
    /// recognize the capability kind and recheck current server policy on use.
    pub fn offered(&self) -> bool {
        self.installed
            && self.authorization == Authorization::Allowed
            && self.readiness.is_some_and(|r| {
                matches!(r.status, Status::Ready | Status::Degraded)
                    && r.observed_at.is_some()
                    && r.reason.is_none()
            })
    }
}

/// Evaluate one already caller-scoped entry. Hidden entries leave no outcome.
/// The lazy observer is not even constructed for absent, disabled or non-allowed entries.
/// Deadline is clamped to 1 ms..=5 s. Observer futures must yield and be cancellation-safe:
/// timeout/drop cancels the future, not detached tasks or external side effects.
/// No caller of this function exists in the health/readiness runtime.
pub async fn evaluate<F, Fut>(input: Input, deadline: Duration, observe: F) -> Option<Evaluation>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Observation>,
{
    let Caller::Visible(authorization) = input.caller else {
        return None;
    };
    let mut result = Evaluation {
        installed: input.installed,
        authorization,
        readiness: None,
    };
    if !input.installed {
        return Some(result);
    }
    let mut readiness = Readiness {
        status: Status::Unknown,
        observed_at: None,
        reason: None,
    };
    if !input.enabled {
        readiness.reason = Some(Reason::Disabled);
    } else if authorization == Authorization::Allowed {
        let outcome = tokio::time::timeout(
            deadline.clamp(Duration::from_millis(1), Duration::from_secs(5)),
            async { observe().await },
        )
        .await;
        match outcome {
            Ok(Observation::Status(status)) => {
                readiness.status = status;
                if status != Status::Unknown {
                    readiness.observed_at = Some(SystemTime::now());
                }
            }
            Ok(Observation::ProviderFailure) => {
                readiness.status = Status::Unavailable;
                readiness.observed_at = Some(SystemTime::now());
                readiness.reason = Some(Reason::ProviderFailure);
            }
            Err(_) => {
                // A timeout provides no current provider-status observation.
                readiness.reason = Some(Reason::Timeout);
            }
        }
    }
    result.readiness = Some(readiness);
    Some(result)
}
