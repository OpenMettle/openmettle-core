//! Synthetic ADR 0037 admin profile. A deployment must qualify its exact remote
//! contract before enabling it. No public API accepts an arbitrary method, URL or headers.
#[path = "gateway/problem.rs"]
pub mod problem;
#[path = "gateway/profile.rs"]
mod profile;
pub use profile::{Action, FamilyDirectory, Mutation, Receipt, UsageReport};

use super::{Trust, transport};
use crate::provider_keys::gateway::Bearer;
use hyper::{
    Method, StatusCode,
    header::{self, HeaderMap, HeaderValue},
};
use rustls::crypto::SharedSecret;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::{sync::Semaphore, time::Instant};

static DNS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));
const MAX_PAGES: u16 = 32;
const PAGE_SIZE: usize = 64;

pub fn retry_backoff() -> Duration {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut jitter = [0; 1];
    let _ = SystemRandom::new().fill(&mut jitter);
    Duration::from_millis(1000 + u64::from(jitter[0]) * 4)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Transport(super::Error),
    Deferred(Duration),
    Refused(u16),
    Protocol,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transport(_) => "gateway admin transport failed",
            Self::Deferred(_) => "gateway admin retry deferred",
            Self::Refused(_) => "gateway administration refused",
            Self::Protocol => "gateway admin response invalid",
        })
    }
}
impl std::error::Error for Error {}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Transport(e)
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Principal,
    Budget,
    Key,
}
impl Resource {
    fn collection(self) -> &'static str {
        match self {
            Self::Principal => "principals",
            Self::Budget => "budgets",
            Self::Key => "keys",
        }
    }
}

/// Stable application-chosen handles from the committed intent. The remote
/// profile must enforce uniqueness and compare all fields on create and recovery.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub resource: Resource,
    pub installation: String,
    pub principal: String,
    pub budget: String,
    pub target: String,
    pub operation: String,
    pub revision: i64,
    pub expected_revision: i64,
}
impl Create {
    fn valid(&self) -> bool {
        self.revision > 0
            && self.expected_revision >= 0
            && [
                &self.installation,
                &self.principal,
                &self.budget,
                &self.target,
                &self.operation,
            ]
            .into_iter()
            .all(|s| crate::runs::is_canonical_uuid(s))
            && match self.resource {
                Resource::Principal => self.target == self.principal,
                Resource::Budget => self.target == self.budget,
                Resource::Key => true,
            }
    }
    fn path(&self) -> String {
        format!("/admin/v1/{}/{}", self.resource.collection(), self.target)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observed<'a> {
    intent: Create,
    bearer: Option<&'a str>,
}
/// Evidence of a successful probe on this client. Consumed by one reconciliation step.
pub struct Ready<'a> {
    admin: &'a Admin,
    deadline: Instant,
}

pub struct Admin {
    origin: transport::Endpoint,
    allowed: Vec<transport::Range>,
    tls: Arc<rustls::ClientConfig>,
    lookup: transport::Lookup,
    admin: HeaderValue,
    #[cfg(test)]
    loopback: bool,
}
impl fmt::Debug for Admin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayAdmin(..)")
    }
}
impl Admin {
    pub fn new(
        origin: &str,
        trust: Trust<'_>,
        ranges: &[&str],
        admin: Bearer,
    ) -> Result<Self, Error> {
        let origin = transport::endpoint(origin)?;
        if origin.path != "/" || ranges.len() > super::MAX_PRIVATE_RANGES {
            return Err(Error::Protocol);
        }
        Ok(Self {
            origin,
            allowed: ranges
                .iter()
                .map(|v| transport::private_range(v))
                .collect::<Result<_, _>>()?,
            tls: transport::client_config(transport::roots(trust)?)?,
            lookup: Arc::new(transport::system_lookup),
            admin: admin.authorization(),
            #[cfg(test)]
            loopback: false,
        })
    }

    async fn request(
        &self,
        method: Method,
        path: String,
        mutation: Option<(&str, Vec<u8>)>,
        deadline: Instant,
    ) -> Result<hyper::Response<SharedSecret>, Error> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(super::Error::Timeout.into());
        }
        let mut endpoint = self.origin.clone();
        endpoint.path = path;
        let route = transport::Route {
            endpoint: &endpoint,
            allowed: &self.allowed,
            tls: &self.tls,
            lookup: &self.lookup,
            slots: &DNS,
            #[cfg(test)]
            loopback: self.loopback,
        };
        let limits = transport::Limits {
            request_body: 8192,
            response_body: 65536,
            response_headers: 32,
            response_header_bytes: 8192,
            setup: super::SETUP_DEADLINE,
            total: remaining.min(super::TOTAL_DEADLINE),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, self.admin.clone());
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let body = if let Some((operation, body)) = mutation {
            headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
            headers.insert(
                "idempotency-key",
                HeaderValue::from_str(operation).map_err(|_| Error::Protocol)?,
            );
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            body
        } else {
            Vec::new()
        };
        let conditional_put = method == Method::PUT && !body.is_empty();
        let res = tokio::time::timeout_at(
            deadline,
            route.send_admitted(method, &headers, body, &limits),
        )
        .await
        .map_err(|_| super::Error::Timeout)??
        .map(SharedSecret::from);
        let status = res.status();
        match status.as_u16() {
            408 | 429 | 503 => {
                let valid = problem::retry_delay(res.headers());
                // A later sweep owns the retry. No sleep or replay inside a batch.
                let delay = valid
                    .map(|n| Duration::from_secs(n.into()))
                    .unwrap_or_else(retry_backoff);
                Err(Error::Deferred(delay))
            }
            412 if conditional_put => Ok(res),
            400..=499 if status != StatusCode::NOT_FOUND => Err(Error::Refused(status.as_u16())),
            200..=299 | 404 => Ok(res),
            _ => Err(Error::Protocol),
        }
    }

    pub async fn ready(&self, deadline: Instant) -> Result<Ready<'_>, Error> {
        let res = self
            .request(Method::GET, "/admin/v1/ready".into(), None, deadline)
            .await?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Readiness {
            ready: bool,
        }

        if res.status() == 200
            && serde_json::from_slice::<Readiness>(res.body().secret_bytes()).is_ok_and(|r| r.ready)
        {
            Ok(Ready {
                admin: self,
                deadline,
            })
        } else {
            Err(Error::Protocol)
        }
    }

    /// Recover first, including after an ambiguous create. Only authoritative
    /// absence permits conditional PUT. The profile returns the same secret on
    /// authenticated recovery of a key. No destructive recovery operation exists.
    pub async fn ensure(&self, i: &Create, deadline: Instant) -> Result<Option<Bearer>, Error> {
        if !i.valid() {
            return Err(Error::Protocol);
        }
        self.ready(deadline).await?;
        let mut res = self.request(Method::GET, i.path(), None, deadline).await?;
        if res.status() == 404 {
            res = self
                .request(
                    Method::PUT,
                    i.path(),
                    Some((
                        &i.operation,
                        serde_json::to_vec(i).map_err(|_| Error::Protocol)?,
                    )),
                    deadline,
                )
                .await?;
            if !matches!(res.status().as_u16(), 200 | 201 | 412) {
                return Err(Error::Protocol);
            }
            drop(res);
            res = self.request(Method::GET, i.path(), None, deadline).await?;
        }
        if res.status() != StatusCode::OK {
            return Err(Error::Protocol);
        }
        let observed: Observed =
            serde_json::from_slice(res.body().secret_bytes()).map_err(|_| Error::Protocol)?;
        if &observed.intent != i {
            return Err(Error::Protocol);
        }
        match (i.resource, observed.bearer) {
            (Resource::Key, Some(value)) => Bearer::new(value.as_bytes())
                .map(Some)
                .map_err(|_| Error::Protocol),
            (Resource::Budget | Resource::Principal, None) => Ok(None),
            _ => Err(Error::Protocol),
        }
    }

    /// Only fixed-size integer pages on the pinned collection. Untrusted response
    /// data can never choose a link, skip a page or extend a batch.
    pub async fn list(&self, resource: Resource, deadline: Instant) -> Result<Vec<String>, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Page {
            ids: Vec<String>,
            more: bool,
        }
        let mut ids = Vec::new();
        for page in 1..=MAX_PAGES {
            let path = format!(
                "/admin/v1/{}?page={page}&limit={PAGE_SIZE}",
                resource.collection()
            );
            let res = self.request(Method::GET, path, None, deadline).await?;
            if res.status() != 200 {
                return Err(Error::Protocol);
            }
            let p: Page =
                serde_json::from_slice(res.body().secret_bytes()).map_err(|_| Error::Protocol)?;
            if p.ids.len() > PAGE_SIZE
                || (p.more && p.ids.is_empty())
                || !p.ids.iter().all(|id| crate::runs::is_canonical_uuid(id))
            {
                return Err(Error::Protocol);
            }
            ids.extend(p.ids);
            if !p.more {
                return Ok(ids);
            }
        }
        Err(Error::Protocol)
    }
}

#[cfg(test)]
impl Admin {
    pub fn fixture(&mut self, lookup: transport::Lookup, loopback: bool) {
        self.lookup = lookup;
        self.loopback = loopback;
    }
}
