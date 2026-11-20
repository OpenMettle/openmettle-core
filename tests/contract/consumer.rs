//! Independent typed consumer of the v1 contract, written from the OpenAPI document as a
//! client would be. It shares no types with the server and performs no schema validation:
//! it decodes what it relies on, tolerates unknown fields and vocabulary, and rejects
//! values it cannot represent exactly.
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Canonical decimal string to i64; never truncates through a float.
pub fn parse_decimal(text: &str, allow_zero: bool) -> Result<i64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("not a canonical decimal: {text:?}"));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(format!("leading zero: {text:?}"));
    }
    let value = text
        .parse::<i64>()
        .map_err(|_| format!("outside signed 64-bit range: {text:?}"))?;
    if value == 0 && !allow_zero {
        return Err("zero is not a positive sequence".into());
    }
    Ok(value)
}

#[derive(Debug, PartialEq)]
pub enum VersionError {
    UnsupportedMajor(String),
    Malformed(String),
}

/// Returns the minor version when the response major is supported (1).
pub fn check_api_version(header: &str) -> Result<u32, VersionError> {
    let malformed = || VersionError::Malformed(header.to_owned());
    let (major, minor) = header.split_once('.').ok_or_else(malformed)?;
    let canonical = |s: &str| {
        !s.is_empty()
            && s.len() <= 7
            && s.bytes().all(|b| b.is_ascii_digit())
            && !(s.len() > 1 && s.starts_with('0'))
    };
    if !canonical(major) || !canonical(minor) {
        return Err(malformed());
    }
    if major != "1" {
        return Err(VersionError::UnsupportedMajor(major.to_owned()));
    }
    minor.parse().map_err(|_| malformed())
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Authorization {
    Allowed,
    Denied,
    /// null on the wire: not determined. Never treated as Denied or Allowed.
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadinessState {
    Ready,
    Degraded,
    Unavailable,
    Unknown,
    Unrecognized(String),
}

impl ReadinessState {
    fn from_wire(state: String) -> Self {
        match state.as_str() {
            "ready" => Self::Ready,
            "degraded" => Self::Degraded,
            "unavailable" => Self::Unavailable,
            "unknown" => Self::Unknown,
            _ => Self::Unrecognized(state),
        }
    }
    /// Only observed ready or degraded providers may be offered to a user.
    pub fn usable(&self) -> bool {
        matches!(self, Self::Ready | Self::Degraded)
    }
}

#[derive(Debug)]
pub struct Readiness {
    pub state: ReadinessState,
    pub observed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapabilityKind {
    Inference,
    Tool,
    Media,
    Memory,
    Retrieval,
    Unrecognized(String),
}

impl CapabilityKind {
    fn from_wire(kind: String) -> Self {
        match kind.as_str() {
            "inference" => Self::Inference,
            "tool" => Self::Tool,
            "media" => Self::Media,
            "memory" => Self::Memory,
            "retrieval" => Self::Retrieval,
            _ => Self::Unrecognized(kind),
        }
    }
}

#[derive(Debug)]
pub struct Capability {
    pub id: String,
    pub kind: CapabilityKind,
    pub installed: bool,
    pub authorization: Authorization,
    pub readiness: Option<Readiness>,
}

impl Capability {
    /// A client may offer the capability only when every dimension positively allows it.
    pub fn offerable(&self) -> bool {
        !matches!(self.kind, CapabilityKind::Unrecognized(_))
            && self.installed
            && self.authorization == Authorization::Allowed
            && self.readiness.as_ref().is_some_and(|r| r.state.usable())
    }
}

#[derive(Deserialize)]
struct WireReadiness {
    state: String,
    observed_at: Option<String>,
}

#[derive(Deserialize)]
struct WireCapability {
    id: String,
    kind: String,
    installed: bool,
    #[serde(deserialize_with = "required_nullable")]
    authorization: Option<bool>,
    readiness: Option<WireReadiness>,
}

#[derive(Deserialize)]
struct WireCapabilityList {
    #[allow(dead_code)]
    generated_at: String,
    capabilities: Vec<WireCapability>,
}

pub fn decode_capabilities(value: &Value) -> Result<Vec<Capability>, String> {
    let list: WireCapabilityList =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for wire in list.capabilities {
        if !seen.insert(wire.id.clone()) {
            return Err(format!("duplicate capability {}", wire.id));
        }
        if wire.installed != wire.readiness.is_some() {
            return Err(format!("{}: readiness must accompany installed", wire.id));
        }
        if let Some(r) = &wire.readiness
            && ["ready", "degraded", "unavailable"].contains(&r.state.as_str())
            && r.observed_at.is_none()
        {
            return Err(format!("{}: an observed state needs observed_at", wire.id));
        }
        out.push(Capability {
            id: wire.id,
            kind: CapabilityKind::from_wire(wire.kind),
            installed: wire.installed,
            authorization: match wire.authorization {
                Some(true) => Authorization::Allowed,
                Some(false) => Authorization::Denied,
                None => Authorization::Unknown,
            },
            readiness: wire.readiness.map(|r| Readiness {
                observed: r.observed_at.is_some(),
                state: ReadinessState::from_wire(r.state),
            }),
        });
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Category {
    Validation,
    InvalidCursor,
    Unauthenticated,
    Policy,
    NotFound,
    Conflict,
    IdempotencyConflict,
    Quota,
    RateLimited,
    Unavailable,
    Provisioning,
    Timeout,
    ProviderFailure,
    Internal,
    /// Unrecognized code, classified only by status class.
    OtherClient(String),
    OtherServer(String),
}

#[derive(Debug)]
pub struct Problem {
    pub status: u16,
    pub category: Category,
    pub detail: Option<String>,
}

#[derive(Deserialize)]
struct WireProblem {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    title: String,
    status: u16,
    code: String,
    detail: Option<String>,
    #[allow(dead_code)]
    request_id: String,
}

pub fn decode_problem(value: &Value) -> Result<Problem, String> {
    let wire: WireProblem = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let known = match wire.code.as_str() {
        "validation" => Some((Category::Validation, 400)),
        "invalid_cursor" => Some((Category::InvalidCursor, 400)),
        "unauthenticated" => Some((Category::Unauthenticated, 401)),
        "policy" => Some((Category::Policy, 403)),
        "not_found" => Some((Category::NotFound, 404)),
        "conflict" => Some((Category::Conflict, 409)),
        "idempotency_conflict" => Some((Category::IdempotencyConflict, 409)),
        "quota" => Some((Category::Quota, 429)),
        "rate_limited" => Some((Category::RateLimited, 429)),
        "internal" => Some((Category::Internal, 500)),
        "provider_failure" => Some((Category::ProviderFailure, 502)),
        "unavailable" => Some((Category::Unavailable, 503)),
        "provisioning" => Some((Category::Provisioning, 503)),
        "timeout" => Some((Category::Timeout, 504)),
        _ => None,
    };
    let category = match known {
        Some((category, status)) if status == wire.status => category,
        Some(_) => {
            return Err(format!(
                "{} does not match status {}",
                wire.code, wire.status
            ));
        }
        None => match wire.status {
            400..=499 => Category::OtherClient(wire.code),
            500..=599 => Category::OtherServer(wire.code),
            _ => return Err(format!("status {} is not a problem status", wire.status)),
        },
    };
    Ok(Problem {
        status: wire.status,
        category,
        detail: wire.detail,
    })
}

#[derive(Deserialize)]
struct WirePage {
    #[serde(deserialize_with = "required_nullable")]
    next_cursor: Option<String>,
}

pub fn decode_page(value: &Value) -> Result<Option<String>, String> {
    let page: WirePage = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    Ok(page.next_cursor)
}

#[derive(Debug)]
pub struct RunEvent {
    pub run_id: String,
    pub sequence: i64,
    /// No event types are defined by this contract revision; every type is surfaced as
    /// unrecognized and ignored by presentation.
    pub unrecognized_type: String,
    pub data: Map<String, Value>,
}

#[derive(Deserialize)]
struct WireItem {
    id: String,
    data: String,
}

#[derive(Deserialize)]
struct WireRunEvent {
    run_id: String,
    sequence: String,
    #[serde(rename = "type")]
    kind: String,
    #[allow(dead_code)]
    type_version: u32,
    #[allow(dead_code)]
    occurred_at: String,
    data: Map<String, Value>,
}

#[derive(Debug)]
pub enum Applied {
    New(RunEvent),
    Duplicate,
}

/// Client-side SSE cursor state for one run.
#[derive(Default)]
pub struct EventCursor {
    pub last_id: Option<String>,
    pub last_sequence: Option<i64>,
}

impl EventCursor {
    /// Decodes one parsed SSE item. Returns an error without advancing when the item
    /// cannot be decoded; otherwise the opaque cursor advances, including for
    /// unrecognized event types. Already-seen sequences are reported as duplicates.
    pub fn apply(&mut self, item: &Value) -> Result<Applied, String> {
        let item: WireItem = serde_json::from_value(item.clone()).map_err(|e| e.to_string())?;
        let event: WireRunEvent = serde_json::from_str(&item.data).map_err(|e| e.to_string())?;
        let sequence = parse_decimal(&event.sequence, false)?;
        self.last_id = Some(item.id);
        if self.last_sequence.is_some_and(|last| sequence <= last) {
            return Ok(Applied::Duplicate);
        }
        self.last_sequence = Some(sequence);
        Ok(Applied::New(RunEvent {
            run_id: event.run_id,
            sequence,
            unrecognized_type: event.kind,
            data: event.data,
        }))
    }
}

// --- projects, conversations and artifacts (V1-05) ---------------------------------------------

/// A project role. An unrecognized role is surfaced, and the client assumes nothing from it.
#[derive(Debug, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Editor,
    Owner,
    Unrecognized(String),
}

impl Role {
    fn from_wire(role: String) -> Self {
        match role.as_str() {
            "viewer" => Self::Viewer,
            "editor" => Self::Editor,
            "owner" => Self::Owner,
            _ => Self::Unrecognized(role),
        }
    }
    /// Only an owner is offered settings, lifecycle and member management.
    pub fn manages_project(&self) -> bool {
        *self == Self::Owner
    }
}

/// A resource access. An unrecognized access is never treated as write.
#[derive(Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Unrecognized(String),
}

impl Access {
    fn from_wire(access: String) -> Self {
        match access.as_str() {
            "read" => Self::Read,
            "write" => Self::Write,
            _ => Self::Unrecognized(access),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Grantee {
    User(String),
    LocalGroup(String),
    OidcGroup(String),
    WholeProject,
    Unrecognized(String),
}

#[derive(Deserialize)]
struct WireGrantee {
    kind: String,
    grantee_id: Option<String>,
}

fn grantee(wire: WireGrantee) -> Result<Grantee, String> {
    Ok(match (wire.kind.as_str(), wire.grantee_id) {
        ("user", Some(id)) => Grantee::User(id),
        ("local_group", Some(id)) => Grantee::LocalGroup(id),
        ("oidc_group", Some(id)) => Grantee::OidcGroup(id),
        ("project", None) => Grantee::WholeProject,
        ("user" | "local_group" | "oidc_group" | "project", _) => {
            return Err(format!("malformed {} grantee", wire.kind));
        }
        _ => Grantee::Unrecognized(wire.kind),
    })
}

#[derive(Debug)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub defaults: Map<String, Value>,
    pub revision: i64,
    pub archived: bool,
    pub role: Role,
}

#[derive(Deserialize)]
struct WireProject {
    project_id: String,
    #[allow(dead_code)]
    scope_id: String,
    name: String,
    #[allow(dead_code)]
    instructions: String,
    defaults: Map<String, Value>,
    revision: String,
    archived: bool,
    role: String,
}

pub fn decode_project(value: &Value) -> Result<Project, String> {
    let wire: WireProject = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    Ok(Project {
        id: wire.project_id,
        name: wire.name,
        defaults: wire.defaults,
        revision: parse_decimal(&wire.revision, true)?,
        archived: wire.archived,
        role: Role::from_wire(wire.role),
    })
}

#[derive(Debug)]
pub struct MemberGrant {
    pub project_id: String,
    pub grantee: Grantee,
    pub role: Role,
}

#[derive(Deserialize)]
struct WireMemberGrant {
    project_id: String,
    grantee: WireGrantee,
    role: String,
}

pub fn decode_member_grant(value: &Value) -> Result<MemberGrant, String> {
    let wire: WireMemberGrant = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    Ok(MemberGrant {
        project_id: wire.project_id,
        grantee: grantee(wire.grantee)?,
        role: Role::from_wire(wire.role),
    })
}

#[derive(Debug)]
pub struct Share {
    pub resource_kind: String,
    pub resource_id: String,
    pub grantee: Grantee,
    pub access: Access,
}

#[derive(Deserialize)]
struct WireShare {
    resource_kind: String,
    resource_id: String,
    grantee: WireGrantee,
    access: String,
}

pub fn decode_share(value: &Value) -> Result<Share, String> {
    let wire: WireShare = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    Ok(Share {
        resource_kind: wire.resource_kind,
        resource_id: wire.resource_id,
        grantee: grantee(wire.grantee)?,
        access: Access::from_wire(wire.access),
    })
}

/// The caller's access to one conversation or artifact.
#[derive(Debug)]
pub struct ItemAccess {
    pub id: String,
    /// `None` in a personal scope.
    pub project_id: Option<String>,
    pub last_revision: Option<i64>,
    pub access: Access,
    pub can_manage_shares: bool,
}

#[derive(Deserialize)]
struct WireItemAccess {
    conversation_id: Option<String>,
    artifact_id: Option<String>,
    #[allow(dead_code)]
    scope_kind: String,
    #[allow(dead_code)]
    scope_id: String,
    #[serde(deserialize_with = "required_nullable")]
    project_id: Option<String>,
    #[allow(dead_code)]
    created_at: String,
    last_revision: Option<String>,
    access: String,
    can_manage_shares: bool,
}

/// An artifact also requires its exact last revision.
pub fn decode_item_access(value: &Value, artifact: bool) -> Result<ItemAccess, String> {
    let wire: WireItemAccess = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let (id, last_revision) = match artifact {
        true => (
            wire.artifact_id.ok_or("missing artifact_id")?,
            Some(parse_decimal(
                &wire.last_revision.ok_or("missing last_revision")?,
                true,
            )?),
        ),
        false => (wire.conversation_id.ok_or("missing conversation_id")?, None),
    };
    Ok(ItemAccess {
        id,
        project_id: wire.project_id,
        last_revision,
        access: Access::from_wire(wire.access),
        can_manage_shares: wire.can_manage_shares,
    })
}
