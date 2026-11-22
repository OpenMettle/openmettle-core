//! Qualified synthetic v1 profile. Each operation is an immutable receipt. The server
//! must fence by principal revision, preserve rotation budgets and retain suspension
//! tombstones even for principals or staged keys whose create has not arrived.
//! The first principal/suspend operation may advance a watermark at or below
//! expected_revision (intermediate local plans can be superseded before remote I/O).
//! Every dependent operation requires the exact active revision. Resource mutation,
//! watermark and immutable operation receipt must commit atomically at the peer.
//! Principal revocation covers all its keys, including an unacknowledged issue.
use super::{Admin, Bearer, Error, Instant, Method};
use crate::runs::is_canonical_uuid;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Principal,
    Budget,
    Attach,
    Policy,
    Issue,
    Renew,
    Rotate,
    Suspend,
    Revoke,
}
impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Budget => "budget",
            Self::Attach => "attach",
            Self::Policy => "policy",
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Rotate => "rotate",
            Self::Suspend => "suspend",
            Self::Revoke => "revoke",
        }
    }
    pub fn issues_key(self) -> bool {
        matches!(self, Self::Issue | Self::Renew | Self::Rotate)
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub installation: String,
    pub principal: String,
    pub budget: String,
    pub operation: String,
    pub revision: i64,
    pub expected_revision: i64,
    pub generation: i64,
    pub target: String,
    pub action: Action,
    pub policy: Option<serde_json::Value>,
}
pub struct Receipt {
    pub key: Option<Bearer>,
    pub expires_ms: Option<i64>,
}

impl super::Ready<'_> {
    /// Readiness is checked by the sweep immediately before this call. Recover by
    /// immutable operation identity first, then verify the readback of the committed effect.
    pub async fn reconcile(self, m: &Mutation) -> Result<Receipt, Error> {
        let deadline = self.deadline;
        let admin = self.admin;
        if ![
            &m.installation,
            &m.principal,
            &m.budget,
            &m.operation,
            &m.target,
        ]
        .iter()
        .all(|id| is_canonical_uuid(id))
            || m.revision < 1
            || !(0..=m.revision).contains(&m.expected_revision)
            || m.generation < 0
            || (m.action == Action::Policy) != m.policy.is_some()
        {
            return Err(Error::Protocol);
        }
        let path = format!("/admin/v1/operations/{}", m.operation);
        let mut res = admin
            .request(Method::GET, path.clone(), None, deadline)
            .await?;
        if res.status() == 404 {
            let payload = serde_json::to_vec(m).map_err(|_| Error::Protocol)?;
            let write = admin
                .request(
                    Method::PUT,
                    path.clone(),
                    Some((&m.operation, payload)),
                    deadline,
                )
                .await?;
            if !matches!(write.status().as_u16(), 200 | 201 | 412) {
                return Err(Error::Protocol);
            }
            drop(write);
            res = admin.request(Method::GET, path, None, deadline).await?;
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Observation<'a> {
            applied: Mutation,
            bearer: Option<&'a str>,
            expires_ms: Option<i64>,
        }
        if res.status() != 200 {
            return Err(Error::Protocol);
        }
        let o: Observation =
            serde_json::from_slice(res.body().secret_bytes()).map_err(|_| Error::Protocol)?;
        if &o.applied != m {
            return Err(Error::Protocol);
        }
        match (m.action.issues_key(), o.bearer, o.expires_ms) {
            (true, Some(v), Some(ms)) if (1..=253402300799999).contains(&ms) => Ok(Receipt {
                key: Some(Bearer::new(v.as_bytes()).map_err(|_| Error::Protocol)?),
                expires_ms: Some(ms),
            }),
            (false, None, None) => Ok(Receipt {
                key: None,
                expires_ms: None,
            }),
            _ => Err(Error::Protocol),
        }
    }
}

impl Admin {
    pub async fn usage(
        &self,
        request: &str,
        deadline: Instant,
    ) -> Result<Option<UsageReport>, Error> {
        if !is_canonical_uuid(request) {
            return Err(Error::Protocol);
        }
        let res = self
            .request(
                Method::GET,
                format!("/admin/v1/usage/{request}"),
                None,
                deadline,
            )
            .await?;
        if res.status() == 404 {
            return Ok(None);
        }
        if res.status() != 200 {
            return Err(Error::Protocol);
        }
        let r: UsageReport =
            serde_json::from_slice(res.body().secret_bytes()).map_err(|_| Error::Protocol)?;
        if !r.valid() || r.request != request {
            return Err(Error::Protocol);
        }
        Ok(Some(r))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageReport {
    pub request: String,
    pub installation: String,
    pub principal: String,
    pub scope: String,
    pub source: String,
    pub report_id: String,
    pub revision: i64,
    pub r#final: bool,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub reasoning_tokens: Option<i64>,
    pub reasoning_included: Option<bool>,
    pub cost: Option<String>,
    pub unit: Option<String>,
}
impl UsageReport {
    pub fn valid(&self) -> bool {
        [
            &self.request,
            &self.installation,
            &self.principal,
            &self.scope,
            &self.source,
            &self.report_id,
        ]
        .iter()
        .all(|id| is_canonical_uuid(id))
            && self.revision >= 0
            && [
                self.prompt_tokens,
                self.completion_tokens,
                self.reasoning_tokens,
            ]
            .into_iter()
            .flatten()
            .all(|n| n >= 0)
            && (self.reasoning_tokens.is_none() || self.reasoning_included.is_some())
            && match (&self.cost, &self.unit) {
                (None, None) => true,
                (Some(c), Some(u)) => {
                    let (whole, fraction) = c
                        .split_once('.')
                        .map_or((c.as_str(), None), |(w, f)| (w, Some(f)));
                    (1..=18).contains(&whole.len())
                        && whole.bytes().all(|b| b.is_ascii_digit())
                        && fraction.is_none_or(|f| {
                            (1..=12).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit())
                        })
                        && (1..=32).contains(&u.len())
                        && u.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                }
                _ => false,
            }
    }
    pub fn measured(&self) -> Option<i128> {
        if [
            self.prompt_tokens,
            self.completion_tokens,
            self.reasoning_tokens,
        ]
        .iter()
        .all(Option::is_none)
        {
            return None;
        }
        let output = i128::from(self.completion_tokens.unwrap_or(0));
        let reasoning = i128::from(self.reasoning_tokens.unwrap_or(0));
        Some(
            i128::from(self.prompt_tokens.unwrap_or(0))
                + if self.reasoning_included == Some(true) {
                    output.max(reasoning)
                } else {
                    output + reasoning
                },
        )
    }
}

/// A revision-consistent read of gateway-owned schedules. A changing page invalidates the
/// snapshot; a later sweep starts again. The gateway enforces this revision at inference time.
#[derive(Default)]
pub struct FamilyDirectory {
    pub revision: i64,
    pub invalid_children: std::collections::BTreeSet<String>,
    pub children: std::collections::BTreeMap<String, crate::authz::gateway::family::FamilyPolicy>,
}
impl Admin {
    pub async fn family_directory(
        &self,
        installation: &str,
        deadline: Instant,
    ) -> Result<FamilyDirectory, Error> {
        if !is_canonical_uuid(installation) {
            return Err(Error::Protocol);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Child {
            user: String,
            #[serde(default)]
            policy: serde_json::Value,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Page {
            installation: String,
            revision: i64,
            children: Vec<Child>,
            more: bool,
        }
        let mut directory = FamilyDirectory::default();
        for index in 1..=super::MAX_PAGES {
            let path = format!(
                "/admin/v1/family/{installation}?page={index}&limit={}",
                super::PAGE_SIZE
            );
            let response = self.request(Method::GET, path, None, deadline).await?;
            if response.status() != 200 {
                return Err(Error::Protocol);
            }
            let page: Page = serde_json::from_slice(response.body().secret_bytes())
                .map_err(|_| Error::Protocol)?;
            if page.installation != installation
                || page.revision < 1
                || (index > 1 && directory.revision != page.revision)
                || page.children.len() > super::PAGE_SIZE
                || (page.more && page.children.is_empty())
            {
                return Err(Error::Protocol);
            }
            directory.revision = page.revision;
            for child in page.children {
                if !is_canonical_uuid(&child.user)
                    || directory.children.contains_key(&child.user)
                    || directory.invalid_children.contains(&child.user)
                {
                    return Err(Error::Protocol);
                }
                match serde_json::from_value::<crate::authz::gateway::family::FamilyPolicy>(
                    child.policy,
                ) {
                    Ok(policy) if policy.valid() => {
                        directory.children.insert(child.user, policy);
                    }
                    _ => {
                        directory.invalid_children.insert(child.user);
                    }
                }
            }
            if !page.more {
                return Ok(directory);
            }
        }
        Err(Error::Protocol)
    }
}
