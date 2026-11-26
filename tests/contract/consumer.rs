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

/// Canonical base-10 integer string for `WideNonNegativeDecimal` (`numeric(38, 0)`), up to 38
/// digits (`0..=10^38 - 1`). Every valid value fits losslessly in `u128`.
pub fn parse_wide_decimal(text: &str) -> Result<u128, String> {
    if text.is_empty() || text.len() > 38 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("not a canonical wide decimal: {text:?}"));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(format!("leading zero: {text:?}"));
    }
    text.parse::<u128>()
        .map_err(|_| format!("outside 38-digit range: {text:?}"))
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
    RangeNotSatisfiable,
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

#[derive(Debug, PartialEq, Eq)]
pub struct ProblemQuota {
    pub resource_kind: String,
    pub scope_kind: String,
}

#[derive(Debug)]
pub struct Problem {
    pub status: u16,
    pub category: Category,
    pub detail: Option<String>,
    pub quota: Option<ProblemQuota>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProblemQuota {
    resource_kind: String,
    scope_kind: String,
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
    quota: Option<WireProblemQuota>,
}

pub fn decode_problem(value: &Value) -> Result<Problem, String> {
    let wire: WireProblem = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let quota = match wire.quota {
        Some(q) => {
            if !matches!(q.scope_kind.as_str(), "personal" | "project" | "instance") {
                return Err(format!("invalid quota scope_kind {}", q.scope_kind));
            }
            if q.resource_kind.is_empty() {
                return Err("empty quota resource_kind".into());
            }
            Some(ProblemQuota {
                resource_kind: q.resource_kind,
                scope_kind: q.scope_kind,
            })
        }
        None => None,
    };
    let known = match wire.code.as_str() {
        "validation" => Some((Category::Validation, 400)),
        "invalid_cursor" => Some((Category::InvalidCursor, 400)),
        "unauthenticated" => Some((Category::Unauthenticated, 401)),
        "policy" => Some((Category::Policy, 403)),
        "not_found" => Some((Category::NotFound, 404)),
        "conflict" => Some((Category::Conflict, 409)),
        "idempotency_conflict" => Some((Category::IdempotencyConflict, 409)),
        "range_not_satisfiable" => Some((Category::RangeNotSatisfiable, 416)),
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
        quota,
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
    pub kind: EventKind,
    pub data: Map<String, Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EventKind {
    Created,
    Started,
    ApprovalRequested,
    ApprovalDecided,
    Waiting(Reason),
    Resumed,
    Cancelled(Reason),
    Failed(Reason),
    Unknown(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reason {
    Requested,
    Revoked,
    QueueExpired,
    Approval,
    ApprovalExpired,
    InvalidWait,
    Unknown(String),
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
    type_version: u32,
    #[allow(dead_code)]
    occurred_at: String,
    data: Map<String, Value>,
}

impl WireRunEvent {
    fn decode(self) -> Result<RunEvent, String> {
        let kind = match (self.kind.as_str(), self.type_version) {
            ("run.created", 1) => EventKind::Created,
            ("run.started", 1) => EventKind::Started,
            ("run.approval_requested", 1) => EventKind::ApprovalRequested,
            ("run.approval_decided", 1) => EventKind::ApprovalDecided,
            ("run.resumed", 1) => EventKind::Resumed,
            ("run.cancelled" | "run.failed" | "run.waiting", 1) => {
                let value = self
                    .data
                    .get("reason")
                    .and_then(Value::as_str)
                    .ok_or("missing event reason")?;
                let reason = match value {
                    "requested" => Reason::Requested,
                    "revoked" => Reason::Revoked,
                    "queue_expired" => Reason::QueueExpired,
                    "approval" => Reason::Approval,
                    "approval_expired" => Reason::ApprovalExpired,
                    "invalid_wait" => Reason::InvalidWait,
                    other => Reason::Unknown(other.to_owned()),
                };
                match self.kind.as_str() {
                    "run.failed" => EventKind::Failed(reason),
                    "run.waiting" => EventKind::Waiting(reason),
                    _ => EventKind::Cancelled(reason),
                }
            }
            _ => EventKind::Unknown(self.kind),
        };
        Ok(RunEvent {
            sequence: parse_decimal(&self.sequence, false)?,
            run_id: self.run_id,
            kind,
            data: self.data,
        })
    }
}

#[derive(Deserialize)]
struct WireRun {
    branch_id: Option<String>,
    input_message_id: Option<String>,
    run_id: String,
    conversation_id: String,
    state: String,
    created_at: String,
    last_sequence: String,
    resume_cursor: String,
    #[serde(deserialize_with = "required_nullable")]
    terminal: Option<WireRunEvent>,
}

pub struct Run {
    pub branch_id: Option<String>,
    pub input_message_id: Option<String>,
    pub run_id: String,
    pub conversation_id: String,
    pub state: String,
    pub created_at: String,
    pub last_sequence: i64,
    pub resume_cursor: String,
    pub terminal: Option<RunEvent>,
}

pub fn decode_run(value: &Value) -> Result<Run, String> {
    let wire: WireRun = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    Ok(Run {
        branch_id: wire.branch_id,
        input_message_id: wire.input_message_id,
        run_id: wire.run_id,
        conversation_id: wire.conversation_id,
        state: wire.state,
        created_at: wire.created_at,
        last_sequence: parse_decimal(&wire.last_sequence, false)?,
        resume_cursor: wire.resume_cursor,
        terminal: wire.terminal.map(WireRunEvent::decode).transpose()?,
    })
}

/// One SSE dispatch block. Comments and unknown fields have no UI effect.
pub fn sse_item(block: &str) -> Option<Value> {
    let mut id = "";
    let mut data = Vec::new();
    for line in block.lines() {
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "id" => id = value,
            "data" => data.push(value),
            _ => (),
        }
    }
    (!data.is_empty()).then(|| serde_json::json!({"id": id, "data": data.join("\n")}))
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
        let event = event.decode()?;
        let sequence = event.sequence;
        if self.last_sequence.is_some_and(|last| sequence <= last) {
            return Ok(Applied::Duplicate);
        }
        self.last_id = Some(item.id);
        self.last_sequence = Some(sequence);
        Ok(Applied::New(event))
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

/// A revision's lifecycle state. Only an active revision is offered for download; an
/// unrecognized state never is.
#[derive(Debug, PartialEq, Eq)]
pub enum RevisionState {
    Active,
    Retained,
    Purging,
    Purged,
    Unrecognized(String),
}

impl RevisionState {
    fn from_wire(state: String) -> Self {
        match state.as_str() {
            "active" => Self::Active,
            "retained" => Self::Retained,
            "purging" => Self::Purging,
            "purged" => Self::Purged,
            _ => Self::Unrecognized(state),
        }
    }
    pub fn downloadable(&self) -> bool {
        *self == Self::Active
    }
}

/// One immutable artifact revision.
#[derive(Debug)]
pub struct ArtifactRevision {
    pub artifact_id: String,
    pub revision_id: String,
    pub revision: i64,
    pub project_id: Option<String>,
    pub media_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub display_name: Option<String>,
    pub state: RevisionState,
    pub retained_at: Option<String>,
    pub purge_after: Option<String>,
}

#[derive(Deserialize)]
struct WireArtifactRevision {
    artifact_id: String,
    revision_id: String,
    revision: String,
    #[allow(dead_code)]
    scope_kind: String,
    #[allow(dead_code)]
    scope_id: String,
    #[serde(deserialize_with = "required_nullable")]
    project_id: Option<String>,
    media_type: String,
    size_bytes: String,
    sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    display_name: Option<String>,
    state: String,
    #[allow(dead_code)]
    created_at: String,
    #[serde(deserialize_with = "required_nullable")]
    retained_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    purge_after: Option<String>,
}

/// The revision number and size are exact; the digest is 64 lowercase hexadecimal digits.
pub fn decode_revision(value: &Value) -> Result<ArtifactRevision, String> {
    let wire: WireArtifactRevision =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if wire.sha256.len() != 64 || !wire.sha256.bytes().all(hex) {
        return Err("sha256 is not 64 lowercase hexadecimal digits".into());
    }
    Ok(ArtifactRevision {
        artifact_id: wire.artifact_id,
        revision_id: wire.revision_id,
        revision: parse_decimal(&wire.revision, false)?,
        project_id: wire.project_id,
        media_type: wire.media_type,
        size_bytes: parse_decimal(&wire.size_bytes, true)?,
        sha256: wire.sha256,
        display_name: wire.display_name,
        state: RevisionState::from_wire(wire.state),
        retained_at: wire.retained_at,
        purge_after: wire.purge_after,
    })
}

// A chat client selects returned graph IDs, renders only known visible part kinds and
// treats an unfamiliar readiness or count vocabulary as unknown.
#[derive(Deserialize)]
struct Collection {
    items: Vec<Value>,
    page_info: WirePage,
}
#[derive(Deserialize)]
struct RootIds {
    conversation_id: String,
    branch_id: String,
    scope_id: String,
}
#[derive(Deserialize)]
struct BranchSelection {
    branch_id: String,
    history_available: bool,
    #[serde(deserialize_with = "required_nullable")]
    head_message_id: Option<String>,
}
#[derive(Deserialize)]
struct HistoryItem {
    message_id: String,
    role: String,
    parts: Vec<Value>,
    #[serde(deserialize_with = "required_nullable")]
    input_count: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    output_count: Option<String>,
    #[serde(default)]
    stop_reason: Option<String>,
}
#[derive(Deserialize)]
struct Descriptor {
    model_id: String,
    installed: bool,
    authorization: bool,
    readiness: WireReadiness,
}
#[derive(Deserialize)]
struct CountField {
    source: String,
    #[serde(deserialize_with = "required_nullable")]
    value: Option<String>,
}
fn text_field<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {key}"))
}
fn decode_descriptor(v: &Value, preset: bool) -> Result<(), String> {
    let desc: Descriptor = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
    if desc.model_id.is_empty() {
        return Err("missing model".into());
    }
    // All three dimensions are necessary to present a runnable selection.
    let _can_run = desc.installed
        && desc.authorization
        && desc.readiness.state == "ready"
        && desc.readiness.observed_at.is_some();
    if preset {
        text_field(v, "preset_id")?;
        text_field(v, "revision")?;
    }
    Ok(())
}
fn decode_branch(v: &Value) -> Result<(), String> {
    let b: BranchSelection = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
    if b.branch_id.is_empty() || (!b.history_available && b.head_message_id.is_some()) {
        return Err("invalid branch selection".into());
    }
    Ok(())
}
fn decode_message(v: &Value) -> Result<(), String> {
    let m: HistoryItem = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
    if m.message_id.is_empty() || m.role.is_empty() {
        return Err("missing turn identity".into());
    }
    if m.stop_reason.as_deref().is_some_and(str::is_empty) {
        return Err("empty stop_reason".into());
    }
    if m.role == "user" && m.stop_reason.is_some() {
        return Err("user message cannot have stop_reason".into());
    }
    for n in [m.input_count, m.output_count].into_iter().flatten() {
        parse_decimal(&n, true)?;
    }
    for p in m.parts {
        text_field(&p, "part_id")?;
        match text_field(&p, "kind")? {
            "text" => {
                text_field(&p, "text")?;
            }
            "attachment" => {
                text_field(&p, "revision_id")?;
                text_field(&p, "state")?;
            }
            _ => (),
        }
    }
    Ok(())
}
fn decode_preview(v: &Value) -> Result<(), String> {
    for name in ["ceiling", "context_window", "output_reserve"] {
        let field: CountField =
            serde_json::from_value(v[name].clone()).map_err(|e| e.to_string())?;
        if field.source.is_empty() {
            return Err("missing source".into());
        }
        if let Some(n) = field.value {
            parse_decimal(&n, true)?;
        }
    }
    for value in [
        &v["usable_input"],
        &v["measured"]["input_count"],
        &v["measured"]["output_count"],
    ] {
        if !value.is_null() {
            parse_decimal(value.as_str().ok_or("invalid count")?, true)?;
        }
    }
    if text_field(&v["prompt"], "kind")? == "estimated" {
        text_field(&v["prompt"], "estimator_revision")?;
        parse_decimal(text_field(&v["prompt"], "count")?, true)?;
    }
    Ok(())
}
pub fn decode_conversation_operation(op: &str, v: &Value) -> Result<(), String> {
    match op {
        "getRun" | "createRun" | "cancelRun" => decode_run(v).map(drop),
        "listRunApprovals" => {
            let items = v["items"].as_array().ok_or("missing approvals")?;
            if items.len() > 1 {
                return Err("multiple pending requests".into());
            }
            for item in items {
                for field in [
                    "approval_id",
                    "tool_id",
                    "tool_version",
                    "destination",
                    "binding_digest",
                    "approval_expires_at",
                ] {
                    text_field(item, field)?;
                }
                let arguments: Value = serde_json::from_str(text_field(item, "arguments_json")?)
                    .map_err(|e| e.to_string())?;
                if !arguments.is_object() {
                    return Err("invalid arguments".into());
                }
            }
            Ok(())
        }
        "decideRunApproval" => {
            for field in ["approval_id", "decision", "binding_digest", "decided_at"] {
                text_field(v, field)?;
            }
            Ok(())
        }
        "previewConfiguration" => decode_preview(v),
        "getPreset" => decode_descriptor(v, true),
        "createBranch" | "getBranch" => decode_branch(v),
        "createConversation" => {
            let ids: RootIds = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
            if [ids.branch_id, ids.conversation_id, ids.scope_id]
                .iter()
                .any(String::is_empty)
            {
                return Err("missing root".into());
            }
            Ok(())
        }
        _ => {
            let page: Collection = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
            if page.page_info.next_cursor.is_some_and(|s| s.is_empty()) {
                return Err("empty cursor".into());
            }
            for item in page.items {
                match op {
                    "listModels" | "listPresets" => decode_descriptor(&item, op == "listPresets")?,
                    "listConversations" => {
                        decode_item_access(&item, false)?;
                    }
                    "listBranches" => decode_branch(&item)?,
                    "listMessages" => decode_message(&item)?,
                    _ => return Err("unknown operation".into()),
                }
            }
            Ok(())
        }
    }
}

// --- quotas (ADR 0040 PR3) --------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum QuotaStatus {
    Ok,
    Warning,
    HardLimit,
    Unconfigured,
    Unrecognized(String),
}

impl QuotaStatus {
    fn from_wire(s: String) -> Self {
        match s.as_str() {
            "ok" => Self::Ok,
            "warning" => Self::Warning,
            "hard_limit" => Self::HardLimit,
            "unconfigured" => Self::Unconfigured,
            _ => Self::Unrecognized(s),
        }
    }
}

#[derive(Debug)]
pub struct QuotaStorage {
    pub limit_bytes: Option<i64>,
    pub limit_source: String,
    pub active_bytes: i64,
    pub retained_bytes: i64,
    pub reserved_bytes: i64,
    pub charged_bytes: i64,
    pub remaining_bytes: Option<i64>,
    pub status: QuotaStatus,
}

#[derive(Debug)]
pub struct QuotaUsage {
    pub resource_kind: String,
    pub unit: Option<String>,
    pub window_kind: String,
    pub limit: Option<i64>,
    pub limit_source: String,
    pub active_used: u128,
    pub reserved_held: u128,
    pub remaining: Option<i64>,
    pub status: QuotaStatus,
}

#[derive(Debug)]
pub struct QuotaDeviceReservations {
    pub reserved_held: u128,
    pub limit: Option<i64>,
    pub status: QuotaStatus,
}

#[derive(Debug)]
pub struct QuotaWarning {
    pub resource_kind: String,
    pub threshold_pct: u16,
    pub dedupe_bucket: String,
    pub triggered_at: String,
}

#[derive(Debug)]
pub struct QuotaSummary {
    pub scope_id: String,
    pub scope_kind: String,
    pub storage: QuotaStorage,
    pub usage: Vec<QuotaUsage>,
    pub has_actor_execution: bool,
    pub round_cap_limit: Option<i64>,
    pub device_reservations: QuotaDeviceReservations,
    pub warnings: Vec<QuotaWarning>,
}

#[derive(Debug)]
pub struct QuotaOverride {
    pub scope_id: String,
    pub scope_kind: String,
    pub resource_kind: String,
    pub hard_limit: i64,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revision: i64,
    pub updated_at: String,
}

#[derive(Deserialize)]
struct WireQuotaStorage {
    #[serde(deserialize_with = "required_nullable")]
    limit_bytes: Option<String>,
    limit_source: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_nullable")]
    override_expires_at: Option<String>,
    active_bytes: String,
    retained_bytes: String,
    reserved_bytes: String,
    charged_bytes: String,
    #[serde(deserialize_with = "required_nullable")]
    remaining_bytes: Option<String>,
    warn_thresholds: Vec<u16>,
    status: String,
}

#[derive(Deserialize)]
struct WireQuotaUsage {
    resource_kind: String,
    #[serde(deserialize_with = "required_nullable")]
    unit: Option<String>,
    window_kind: String,
    #[allow(dead_code)]
    window_start: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_nullable")]
    window_end: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    limit: Option<String>,
    limit_source: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_nullable")]
    override_expires_at: Option<String>,
    active_used: String,
    reserved_held: String,
    #[serde(deserialize_with = "required_nullable")]
    remaining: Option<String>,
    warn_thresholds: Vec<u16>,
    status: String,
    #[allow(dead_code)]
    authoritative_source: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_nullable")]
    last_reconciled_at: Option<String>,
}

#[derive(Deserialize)]
struct WireQuotaExecCounter {
    current: String,
    #[serde(deserialize_with = "required_nullable")]
    limit: Option<String>,
    #[allow(dead_code)]
    limit_source: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_nullable")]
    override_expires_at: Option<String>,
}

#[derive(Deserialize)]
struct WireQuotaLimitProj {
    #[serde(deserialize_with = "required_nullable")]
    limit: Option<String>,
    #[allow(dead_code)]
    limit_source: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_nullable")]
    override_expires_at: Option<String>,
}

#[derive(Deserialize)]
struct WireQuotaExecution {
    live_runs_per_scope: WireQuotaExecCounter,
    executing_runs_per_scope: WireQuotaExecCounter,
    round_cap: WireQuotaLimitProj,
    live_runs_per_actor: Option<WireQuotaExecCounter>,
    executing_runs_per_actor: Option<WireQuotaExecCounter>,
}

#[derive(Deserialize)]
struct WireQuotaDeviceRes {
    reserved_held: String,
    #[serde(deserialize_with = "required_nullable")]
    limit: Option<String>,
    #[allow(dead_code)]
    limit_source: String,
    #[allow(dead_code)]
    #[serde(deserialize_with = "required_nullable")]
    override_expires_at: Option<String>,
    warn_thresholds: Vec<u16>,
    status: String,
}

#[derive(Deserialize)]
struct WireQuotaDeviceCap {
    active_reservations: WireQuotaDeviceRes,
}

#[derive(Deserialize)]
struct WireQuotaWarning {
    resource_kind: String,
    threshold_pct: u16,
    dedupe_bucket: String,
    triggered_at: String,
}

#[derive(Deserialize)]
struct WireQuotaSummary {
    scope_id: String,
    scope_kind: String,
    #[allow(dead_code)]
    observed_at: String,
    storage: WireQuotaStorage,
    usage: Vec<WireQuotaUsage>,
    execution: WireQuotaExecution,
    device_capacity: WireQuotaDeviceCap,
    warnings: Vec<WireQuotaWarning>,
}

fn opt_decimal(v: Option<&str>) -> Result<Option<i64>, String> {
    v.map(|s| parse_decimal(s, true)).transpose()
}

pub fn decode_quota_summary(value: &Value) -> Result<QuotaSummary, String> {
    let exec_obj = value
        .get("execution")
        .and_then(Value::as_object)
        .ok_or("missing execution object")?;
    let has_live_actor_key = exec_obj.contains_key("live_runs_per_actor");
    let has_exec_actor_key = exec_obj.contains_key("executing_runs_per_actor");
    let wire: WireQuotaSummary =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if wire.storage.warn_thresholds.len() != 2 {
        return Err("storage warn_thresholds must have two items".into());
    }
    let storage = QuotaStorage {
        limit_bytes: opt_decimal(wire.storage.limit_bytes.as_deref())?,
        limit_source: wire.storage.limit_source,
        active_bytes: parse_decimal(&wire.storage.active_bytes, true)?,
        retained_bytes: parse_decimal(&wire.storage.retained_bytes, true)?,
        reserved_bytes: parse_decimal(&wire.storage.reserved_bytes, true)?,
        charged_bytes: parse_decimal(&wire.storage.charged_bytes, true)?,
        remaining_bytes: opt_decimal(wire.storage.remaining_bytes.as_deref())?,
        status: QuotaStatus::from_wire(wire.storage.status),
    };
    let mut usage = Vec::with_capacity(wire.usage.len());
    for item in wire.usage {
        if item.warn_thresholds.len() != 2 {
            return Err("usage warn_thresholds must have two items".into());
        }
        usage.push(QuotaUsage {
            resource_kind: item.resource_kind,
            unit: item.unit,
            window_kind: item.window_kind,
            limit: opt_decimal(item.limit.as_deref())?,
            limit_source: item.limit_source,
            active_used: parse_wide_decimal(&item.active_used)?,
            reserved_held: parse_wide_decimal(&item.reserved_held)?,
            remaining: opt_decimal(item.remaining.as_deref())?,
            status: QuotaStatus::from_wire(item.status),
        });
    }
    for c in [
        &wire.execution.live_runs_per_scope,
        &wire.execution.executing_runs_per_scope,
    ] {
        parse_decimal(&c.current, true)?;
        opt_decimal(c.limit.as_deref())?;
    }
    for c in [
        &wire.execution.live_runs_per_actor,
        &wire.execution.executing_runs_per_actor,
    ]
    .into_iter()
    .flatten()
    {
        parse_decimal(&c.current, true)?;
        opt_decimal(c.limit.as_deref())?;
    }
    match wire.scope_kind.as_str() {
        "personal"
            if wire.execution.live_runs_per_actor.is_none()
                || wire.execution.executing_runs_per_actor.is_none() =>
        {
            return Err(
                "personal quota summary requires live_runs_per_actor and executing_runs_per_actor"
                    .into(),
            );
        }
        "project"
            if has_live_actor_key
                || has_exec_actor_key
                || wire.execution.live_runs_per_actor.is_some()
                || wire.execution.executing_runs_per_actor.is_some() =>
        {
            return Err("project quota summary must omit per-actor execution counters".into());
        }
        _ => {}
    }
    let round_cap_limit = opt_decimal(wire.execution.round_cap.limit.as_deref())?;
    let dev = wire.device_capacity.active_reservations;
    if dev.warn_thresholds.len() != 2 {
        return Err("device warn_thresholds must have two items".into());
    }
    let device_reservations = QuotaDeviceReservations {
        reserved_held: parse_wide_decimal(&dev.reserved_held)?,
        limit: opt_decimal(dev.limit.as_deref())?,
        status: QuotaStatus::from_wire(dev.status),
    };
    let warnings = wire
        .warnings
        .into_iter()
        .map(|w| QuotaWarning {
            resource_kind: w.resource_kind,
            threshold_pct: w.threshold_pct,
            dedupe_bucket: w.dedupe_bucket,
            triggered_at: w.triggered_at,
        })
        .collect();
    Ok(QuotaSummary {
        scope_id: wire.scope_id,
        scope_kind: wire.scope_kind,
        storage,
        usage,
        has_actor_execution: wire.execution.live_runs_per_actor.is_some()
            && wire.execution.executing_runs_per_actor.is_some(),
        round_cap_limit,
        device_reservations,
        warnings,
    })
}

/// Validates `QuotaOverrideReason` against the server's 1..=256 UTF-8 byte bound (no NUL).
pub fn validate_quota_override_reason(reason: &str) -> Result<(), String> {
    if reason.is_empty() || reason.len() > 256 || reason.contains('\0') {
        return Err("override reason must be 1 to 256 UTF-8 bytes without NUL".into());
    }
    Ok(())
}

/// Builds a validated `QuotaOverrideSetRequest` JSON payload matching server byte bounds.
pub fn encode_quota_override_set_request(
    hard_limit: u64,
    expires_at: Option<&str>,
    reason: &str,
) -> Result<Value, String> {
    validate_quota_override_reason(reason)?;
    let mut map = Map::new();
    map.insert("hard_limit".into(), Value::String(hard_limit.to_string()));
    if let Some(ts) = expires_at {
        map.insert("expires_at".into(), Value::String(ts.to_owned()));
    }
    map.insert("reason".into(), Value::String(reason.to_owned()));
    Ok(Value::Object(map))
}

/// Builds a validated `QuotaOverrideRevokeRequest` JSON payload matching server byte bounds.
pub fn encode_quota_override_revoke_request(reason: &str) -> Result<Value, String> {
    validate_quota_override_reason(reason)?;
    let mut map = Map::new();
    map.insert("reason".into(), Value::String(reason.to_owned()));
    Ok(Value::Object(map))
}

#[derive(Deserialize)]
struct WireQuotaOverride {
    scope_id: String,
    scope_kind: String,
    resource_kind: String,
    hard_limit: String,
    #[serde(deserialize_with = "required_nullable")]
    expires_at: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    revoked_at: Option<String>,
    revision: String,
    updated_at: String,
}

pub fn decode_quota_override(value: &Value) -> Result<QuotaOverride, String> {
    let wire: WireQuotaOverride =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    Ok(QuotaOverride {
        scope_id: wire.scope_id,
        scope_kind: wire.scope_kind,
        resource_kind: wire.resource_kind,
        hard_limit: parse_decimal(&wire.hard_limit, true)?,
        expires_at: wire.expires_at,
        revoked_at: wire.revoked_at,
        revision: parse_decimal(&wire.revision, false)?,
        updated_at: wire.updated_at,
    })
}

// --- shared capacity visibility & operator inspection (V1-18 / ADR 0042) -----------------------

#[derive(Debug, PartialEq, Eq)]
pub enum CapacityAvailability {
    Ready,
    Busy,
    QueuedEstimate,
    Unavailable,
    Unrecognized(String),
}

impl CapacityAvailability {
    fn from_wire(value: String) -> Self {
        match value.as_str() {
            "ready" => Self::Ready,
            "busy" => Self::Busy,
            "queued_estimate" => Self::QueuedEstimate,
            "unavailable" => Self::Unavailable,
            _ => Self::Unrecognized(value),
        }
    }

    pub fn ready_now(&self) -> bool {
        *self == Self::Ready
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProfileCapacity {
    pub profile: String,
    pub availability: CapacityAvailability,
    pub estimated_wait_seconds: Option<u32>,
}

#[derive(Deserialize)]
struct WireProfileCapacity {
    profile: String,
    availability: String,
    #[serde(deserialize_with = "required_nullable")]
    estimated_wait_seconds: Option<u32>,
}

#[derive(Deserialize)]
struct WireCapacitySummary {
    profiles: Vec<WireProfileCapacity>,
}

pub fn decode_capacity_summary(value: &Value) -> Result<Vec<ProfileCapacity>, String> {
    let wire: WireCapacitySummary =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(wire.profiles.len());
    for item in wire.profiles {
        if item.profile.is_empty() || item.profile.len() > 128 {
            return Err("invalid profile name".into());
        }
        let availability = CapacityAvailability::from_wire(item.availability);
        match (&availability, item.estimated_wait_seconds) {
            (CapacityAvailability::QueuedEstimate, Some(wait)) if (1..=86_400).contains(&wait) => {}
            (CapacityAvailability::QueuedEstimate, _) => {
                return Err("queued_estimate requires estimated_wait_seconds in 1..=86400".into());
            }
            (
                CapacityAvailability::Ready
                | CapacityAvailability::Busy
                | CapacityAvailability::Unavailable,
                None,
            ) => {}
            (
                CapacityAvailability::Ready
                | CapacityAvailability::Busy
                | CapacityAvailability::Unavailable,
                Some(_),
            ) => {
                return Err(
                    "non-queued availability must report null estimated_wait_seconds".into(),
                );
            }
            (CapacityAvailability::Unrecognized(_), Some(wait))
                if !(1..=86_400).contains(&wait) =>
            {
                return Err("estimated_wait_seconds out of bounds".into());
            }
            (CapacityAvailability::Unrecognized(_), _) => {}
        }
        out.push(ProfileCapacity {
            profile: item.profile,
            availability,
            estimated_wait_seconds: item.estimated_wait_seconds,
        });
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapacityDeviceObservation {
    pub device_id: String,
    pub total_bytes: i64,
    pub committed_bytes: i64,
    pub actual_used_bytes: i64,
    pub reclaimable_bytes: i64,
    pub safety_headroom_bytes: i64,
    pub active_chat_floor_bytes: i64,
    pub grantable_bytes: i64,
    pub effective_grantable_bytes: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapacityGroupTotals {
    pub total_bytes: u128,
    pub committed_bytes: u128,
    pub actual_used_bytes: u128,
    pub reclaimable_bytes: u128,
    pub safety_headroom_bytes: u128,
    pub active_chat_floor_bytes: u128,
    pub grantable_bytes: u128,
    pub effective_grantable_bytes: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdminCapacityGroup {
    pub group_id: String,
    pub controller_epoch: i64,
    pub admits_bursts: bool,
    pub observation_revision: i64,
    pub observed_at: Option<String>,
    pub totals: CapacityGroupTotals,
    pub devices: Vec<CapacityDeviceObservation>,
}

#[derive(Deserialize)]
struct WireCapacityDeviceObservation {
    device_id: String,
    total_bytes: String,
    committed_bytes: String,
    actual_used_bytes: String,
    reclaimable_bytes: String,
    safety_headroom_bytes: String,
    active_chat_floor_bytes: String,
    grantable_bytes: String,
    effective_grantable_bytes: String,
}

#[derive(Deserialize)]
struct WireCapacityGroupTotals {
    total_bytes: String,
    committed_bytes: String,
    actual_used_bytes: String,
    reclaimable_bytes: String,
    safety_headroom_bytes: String,
    active_chat_floor_bytes: String,
    grantable_bytes: String,
    effective_grantable_bytes: String,
}

#[derive(Deserialize)]
struct WireAdminCapacityGroup {
    group_id: String,
    controller_epoch: String,
    admits_bursts: bool,
    observation_revision: String,
    #[serde(deserialize_with = "required_nullable")]
    observed_at: Option<String>,
    totals: WireCapacityGroupTotals,
    devices: Vec<WireCapacityDeviceObservation>,
}

#[derive(Deserialize)]
struct WireAdminCapacityGroupList {
    groups: Vec<WireAdminCapacityGroup>,
}

pub fn decode_admin_capacity_groups(value: &Value) -> Result<Vec<AdminCapacityGroup>, String> {
    let wire: WireAdminCapacityGroupList =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(wire.groups.len());
    for g in wire.groups {
        let totals = CapacityGroupTotals {
            total_bytes: parse_wide_decimal(&g.totals.total_bytes)?,
            committed_bytes: parse_wide_decimal(&g.totals.committed_bytes)?,
            actual_used_bytes: parse_wide_decimal(&g.totals.actual_used_bytes)?,
            reclaimable_bytes: parse_wide_decimal(&g.totals.reclaimable_bytes)?,
            safety_headroom_bytes: parse_wide_decimal(&g.totals.safety_headroom_bytes)?,
            active_chat_floor_bytes: parse_wide_decimal(&g.totals.active_chat_floor_bytes)?,
            grantable_bytes: parse_wide_decimal(&g.totals.grantable_bytes)?,
            effective_grantable_bytes: parse_wide_decimal(&g.totals.effective_grantable_bytes)?,
        };
        let mut devices = Vec::with_capacity(g.devices.len());
        for d in g.devices {
            devices.push(CapacityDeviceObservation {
                device_id: d.device_id,
                total_bytes: parse_decimal(&d.total_bytes, true)?,
                committed_bytes: parse_decimal(&d.committed_bytes, true)?,
                actual_used_bytes: parse_decimal(&d.actual_used_bytes, true)?,
                reclaimable_bytes: parse_decimal(&d.reclaimable_bytes, true)?,
                safety_headroom_bytes: parse_decimal(&d.safety_headroom_bytes, true)?,
                active_chat_floor_bytes: parse_decimal(&d.active_chat_floor_bytes, true)?,
                grantable_bytes: parse_decimal(&d.grantable_bytes, true)?,
                effective_grantable_bytes: parse_decimal(&d.effective_grantable_bytes, true)?,
            });
        }
        out.push(AdminCapacityGroup {
            group_id: g.group_id,
            controller_epoch: parse_decimal(&g.controller_epoch, true)?,
            admits_bursts: g.admits_bursts,
            observation_revision: parse_decimal(&g.observation_revision, true)?,
            observed_at: g.observed_at,
            totals,
            devices,
        });
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub revision: i64,
    pub grace_seconds: i32,
    pub min_grace_seconds: i32,
    pub max_grace_seconds: i32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RestoreGateStatus {
    pub open: bool,
    pub snapshot_journal_seq: Option<i64>,
    pub required_journal_seq: Option<i64>,
    pub coverage_complete: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeletionJournalStatus {
    pub journal_seq: i64,
    pub coverage_started_at: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AdminRetentionStatus {
    pub policy: RetentionPolicy,
    pub restore_gate: RestoreGateStatus,
    pub deletion_journal: DeletionJournalStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RetentionDeadlinesSummary {
    pub policy_revision: i64,
    pub target_grace_seconds: i32,
    pub scope_id: Option<String>,
    pub affected_revisions: i64,
    pub affected_bytes: i64,
}

#[derive(Deserialize)]
struct WireRetentionPolicy {
    revision: String,
    grace_seconds: i32,
    min_grace_seconds: i32,
    max_grace_seconds: i32,
}

#[derive(Deserialize)]
struct WireRestoreGateStatus {
    open: bool,
    #[serde(deserialize_with = "required_nullable")]
    snapshot_journal_seq: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    required_journal_seq: Option<String>,
    coverage_complete: bool,
}

#[derive(Deserialize)]
struct WireDeletionJournalStatus {
    journal_seq: String,
    coverage_started_at: String,
}

#[derive(Deserialize)]
struct WireAdminRetentionStatus {
    policy: WireRetentionPolicy,
    restore_gate: WireRestoreGateStatus,
    deletion_journal: WireDeletionJournalStatus,
}

#[derive(Deserialize)]
struct WireRetentionDeadlinesPreview {
    current_policy_revision: String,
    target_grace_seconds: i32,
    #[serde(deserialize_with = "required_nullable")]
    scope_id: Option<String>,
    affected_revisions: String,
    affected_bytes: String,
}

#[derive(Deserialize)]
struct WireRetentionDeadlinesApplyResult {
    policy_revision: String,
    target_grace_seconds: i32,
    #[serde(deserialize_with = "required_nullable")]
    scope_id: Option<String>,
    affected_revisions: String,
    affected_bytes: String,
}

pub fn decode_retention_policy(value: &Value) -> Result<RetentionPolicy, String> {
    let wire: WireRetentionPolicy =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if wire.grace_seconds < 0 || wire.min_grace_seconds < 0 || wire.max_grace_seconds < 0 {
        return Err("negative grace_seconds".into());
    }
    Ok(RetentionPolicy {
        revision: parse_decimal(&wire.revision, false)?,
        grace_seconds: wire.grace_seconds,
        min_grace_seconds: wire.min_grace_seconds,
        max_grace_seconds: wire.max_grace_seconds,
    })
}

pub fn decode_admin_retention_status(value: &Value) -> Result<AdminRetentionStatus, String> {
    let wire: WireAdminRetentionStatus =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if wire.policy.grace_seconds < 0
        || wire.policy.min_grace_seconds < 0
        || wire.policy.max_grace_seconds < 0
    {
        return Err("negative grace_seconds".into());
    }
    Ok(AdminRetentionStatus {
        policy: RetentionPolicy {
            revision: parse_decimal(&wire.policy.revision, false)?,
            grace_seconds: wire.policy.grace_seconds,
            min_grace_seconds: wire.policy.min_grace_seconds,
            max_grace_seconds: wire.policy.max_grace_seconds,
        },
        restore_gate: RestoreGateStatus {
            open: wire.restore_gate.open,
            snapshot_journal_seq: wire
                .restore_gate
                .snapshot_journal_seq
                .as_deref()
                .map(|s| parse_decimal(s, true))
                .transpose()?,
            required_journal_seq: wire
                .restore_gate
                .required_journal_seq
                .as_deref()
                .map(|s| parse_decimal(s, true))
                .transpose()?,
            coverage_complete: wire.restore_gate.coverage_complete,
        },
        deletion_journal: DeletionJournalStatus {
            journal_seq: parse_decimal(&wire.deletion_journal.journal_seq, true)?,
            coverage_started_at: wire.deletion_journal.coverage_started_at,
        },
    })
}

pub fn decode_retention_deadlines_preview(
    value: &Value,
) -> Result<RetentionDeadlinesSummary, String> {
    let wire: WireRetentionDeadlinesPreview =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if wire.target_grace_seconds < 0 {
        return Err("negative target_grace_seconds".into());
    }
    Ok(RetentionDeadlinesSummary {
        policy_revision: parse_decimal(&wire.current_policy_revision, false)?,
        target_grace_seconds: wire.target_grace_seconds,
        scope_id: wire.scope_id,
        affected_revisions: parse_decimal(&wire.affected_revisions, true)?,
        affected_bytes: parse_decimal(&wire.affected_bytes, true)?,
    })
}

pub fn decode_retention_deadlines_apply_result(
    value: &Value,
) -> Result<RetentionDeadlinesSummary, String> {
    let wire: WireRetentionDeadlinesApplyResult =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    if wire.target_grace_seconds < 0 {
        return Err("negative target_grace_seconds".into());
    }
    Ok(RetentionDeadlinesSummary {
        policy_revision: parse_decimal(&wire.policy_revision, false)?,
        target_grace_seconds: wire.target_grace_seconds,
        scope_id: wire.scope_id,
        affected_revisions: parse_decimal(&wire.affected_revisions, true)?,
        affected_bytes: parse_decimal(&wire.affected_bytes, true)?,
    })
}
