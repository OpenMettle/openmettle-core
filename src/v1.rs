//! Authenticated application API routes under `/v1` (ADR 0007; ADRs 0027, 0031 and 0034).
//!
//! **Off by default.** `crate::app` mounts [`router`] beside the browser sign-in routes only
//! when `OPENMETTLE_API_AUTH_CONFIG` names a version-2 settings document (ADR 0025). Without it
//! every `/v1` path is an unknown route.
//!
//! One implementation decides every request, in this order. Steps 1–5 do no database work.
//!
//! 1. Route and method. An operation the contract does not define is `404 not_found`.
//! 2. Bounds on the parsed head: the browser router's target, header-count and header-byte
//!    ceilings.
//! 3. Acquire a permit immediately. Event streams have a separate 128-slot limit.
//!    Exhaustion returns `503 unavailable`.
//! 4. The session channel. Exactly one of the `__Host-openmettle-session` cookie (ADR 0019),
//!    with the configured `Origin` on an unsafe method and on any request that sends one, or
//!    one `Authorization: Bearer` native credential (ADR 0029). Both, neither, a repeated
//!    field or a refused `Origin` is `401 unauthenticated`.
//! 5. Request shape: the path identifiers, a write's `Idempotency-Key` and the body profile:
//!    empty, or one bounded `application/json` object (128 KiB for admission and preview,
//!    64 KiB for other operations) read within
//!    [`BODY_READ_TIMEOUT`]. A refusal is `400 validation`. An artifact upload instead checks
//!    its query and multipart `Content-Type`, and its body is streamed later; a download checks
//!    its `Range`. An artifact payload operation without `ARTIFACTS_DIR` is then
//!    `503 provisioning` (see [`artifacts`]). Run reads require cursor keys (ADR 0034).
//! 6. Session validation on the primary, then the operation within [`OPERATION_TIMEOUT`]. The
//!    principal and every target are hydrated on the primary for this request alone and
//!    decided by `crate::authz`; nothing is cached across requests.
//!
//! Every response, success or problem, carries `OpenMettle-API-Version` and
//! `Cache-Control: no-store`. A problem has a fixed title and detail per category and never
//! echoes a request value, identifier, credential, database error or internal reason.
use crate::{
    artifact_fs,
    authz::{
        self, GrantPermission, GrantVocabulary, Grantee, PROJECT_ROLE, Principal, ProjectRole,
        RESOURCE_GRANT, ResourceAccess, ResourceKind,
        approvals::EffectSession,
        projects::{self, ProjectSettingsInput, ProjectView, ResourceView},
        store::{self, AuditContext, StoreError},
    },
    browser_auth::{BrowserAuth, Checkout, handoff, native::NativeAuth, router as limits},
    grants, sessions,
    telemetry::RequestId,
};
use axum::{
    Router,
    body::{Body, Bytes, HttpBody, to_bytes},
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    response::Response,
    routing::any,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// The contract version every response reports (ADR 0007).
pub const API_VERSION: &str = "1.0";
/// Requests inside the API routes at once.
pub const MAX_IN_FLIGHT: usize = 256;
/// Bytes of one JSON request body: room for the largest project settings (ADR 0027).
pub const MAX_BODY_BYTES: usize = 65_536;
/// Longest wait for a JSON request body, counted while the in-flight permit is held.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Longest database phase of one operation, including the wait for a pooled connection.
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const VERSION_HEADER: HeaderName = HeaderName::from_static("openmettle-api-version");
const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
/// Domain of the request key derived from a client `Idempotency-Key`.
const IDEMPOTENCY_DOMAIN: &[u8] = b"openmettle/v1-idempotency/1\0";
/// Request ID of a problem when the operating system's random source failed.
const NIL_REQUEST_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Additive closed low-cardinality quota refusal metadata (ADR 0040).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QuotaDetail {
    resource_kind: &'static str,
    scope_kind: &'static str,
}

/// One ADR 0007 problem category: a status, a stable code and a fixed, safe detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Problem {
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    quota: Option<QuotaDetail>,
}

pub(crate) const fn problem(
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
) -> Problem {
    Problem {
        status,
        code,
        detail,
        quota: None,
    }
}

const fn quota_problem(
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    resource_kind: &'static str,
    scope_kind: &'static str,
) -> Problem {
    Problem {
        status,
        code,
        detail,
        quota: Some(QuotaDetail {
            resource_kind,
            scope_kind,
        }),
    }
}

const INVALID: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request does not satisfy the API contract.",
);
const HEAD_TOO_LARGE: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request target or headers exceed their limits.",
);
const IDENTIFIER: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The path identifier is not a canonical lowercase UUID.",
);
const KEY_REQUIRED: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "A state-changing request needs one Idempotency-Key of 1 to 128 visible ASCII characters.",
);
const BODY: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The request body does not match the operation's media type or schema.",
);
const UNAUTHENTICATED: Problem = problem(
    StatusCode::UNAUTHORIZED,
    "unauthenticated",
    "A valid OpenMettle application session is required.",
);
const POLICY: Problem = problem(
    StatusCode::FORBIDDEN,
    "policy",
    "The caller may not perform this action.",
);
const NOT_FOUND: Problem = problem(
    StatusCode::NOT_FOUND,
    "not_found",
    "The resource does not exist or is not visible to the caller.",
);
const CONFLICT: Problem = problem(
    StatusCode::CONFLICT,
    "conflict",
    "The request conflicts with the current state of the resource.",
);
const KEY_CONFLICT: Problem = problem(
    StatusCode::CONFLICT,
    "idempotency_conflict",
    "The Idempotency-Key was already used for a different request.",
);
const INTERNAL: Problem = problem(
    StatusCode::INTERNAL_SERVER_ERROR,
    "internal",
    "An unexpected server failure occurred.",
);
const UNAVAILABLE: Problem = problem(
    StatusCode::SERVICE_UNAVAILABLE,
    "unavailable",
    "The service is temporarily unavailable; try again later.",
);
const TIMEOUT: Problem = problem(
    StatusCode::GATEWAY_TIMEOUT,
    "timeout",
    "The request did not complete in time.",
);
const PROVISIONING: Problem = problem(
    StatusCode::SERVICE_UNAVAILABLE,
    "provisioning",
    "This deployment is not provisioned for the request.",
);

impl Problem {
    pub(crate) fn response(self, id: Option<RequestId>) -> Response {
        let mut body = json!({
            "type": "about:blank",
            "title": self.status.canonical_reason().unwrap_or("Error"),
            "status": self.status.as_u16(),
            "code": self.code,
            "detail": self.detail,
            "request_id": id.map_or_else(|| NIL_REQUEST_ID.to_owned(), |id| id.to_string()),
        });
        if let Some(quota) = self.quota {
            body["quota"] = json!({
                "resource_kind": quota.resource_kind,
                "scope_kind": quota.scope_kind,
            });
        }
        let mut response = respond(self.status, Some("application/problem+json"), body);
        if self == submission::QUEUE_FULL {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

/// The ADR 0007 mapping of a policy denial; the internal reason never reaches the wire.
fn denied(reason: authz::DenialReason) -> Problem {
    use authz::DenialReason::{InactivePrincipal, NotFound, Policy, Unauthenticated};
    match reason {
        Unauthenticated | InactivePrincipal => UNAUTHENTICATED,
        NotFound => NOT_FOUND,
        Policy(_) => POLICY,
    }
}

fn store_problem(error: StoreError) -> Problem {
    match error {
        StoreError::Denied(reason) => denied(reason),
        StoreError::InvalidInput(_) => INVALID,
        StoreError::Conflict(store::KEY_REUSED) => KEY_CONFLICT,
        StoreError::Conflict(_) => CONFLICT,
        StoreError::NotFound => NOT_FOUND,
        StoreError::Database(_) => UNAVAILABLE,
    }
}

/// A validation, deadline or capacity failure is never `unauthenticated`: only a credential
/// the primary refused is.
fn session_problem(error: sessions::Error) -> Problem {
    use sessions::Error::{Capacity, Configuration, Database, Random, Rejected, Timeout};
    match error {
        Rejected => UNAUTHENTICATED,
        Timeout => TIMEOUT,
        Configuration | Capacity | Random | Database => UNAVAILABLE,
    }
}

/// Every response: the contract version and never stored.
fn respond(status: StatusCode, media: Option<&'static str>, body: Value) -> Response {
    let mut response = match media {
        Some(_) => Response::new(Body::from(body.to_string())),
        None => Response::new(Body::empty()),
    };
    *response.status_mut() = status;
    let headers = response.headers_mut();
    response_headers(headers);
    if let Some(media) = media {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
    }
    response
}

fn response_headers(headers: &mut HeaderMap) {
    headers.insert(VERSION_HEADER, HeaderValue::from_static(API_VERSION));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn single_header(
    headers: &HeaderMap,
    name: HeaderName,
    duplicate: Problem,
) -> Result<Option<&HeaderValue>, Problem> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(duplicate);
    }
    Ok(first)
}

fn reply(status: StatusCode, body: Value) -> Response {
    respond(status, Some("application/json"), body)
}

fn no_content() -> Response {
    respond(StatusCode::NO_CONTENT, None, Value::Null)
}

/// The mounted application operations, each named by its `operationId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    CreateConversation,
    ListConversations,
    CreateBranch,
    ListBranches,
    GetBranch,
    ListMessages,
    ListModels,
    ListPresets,
    GetPreset,
    PreviewConfiguration,
    CreateRun,
    CancelRun,
    GetRun,
    StreamRunEvents,
    ListRunApprovals,
    DecideRunApproval,
    ListCapabilities,
    CreateProject,
    GetProject,
    UpdateProjectSettings,
    ArchiveProject,
    RestoreProject,
    DeleteProject,
    SetProjectMemberRole,
    RevokeProjectMember,
    GetResource(ResourceKind),
    ShareResource(ResourceKind),
    RevokeResourceShare(ResourceKind),
    CreateArtifact,
    CreateArtifactRevision,
    GetArtifactRevision,
    DownloadArtifactRevision,
    GetPersonalQuotas,
    GetProjectQuotas,
    SetQuotaOverride,
    RevokeQuotaOverride,
}

impl Op {
    /// The contract `operationId`. It also scopes an idempotency key.
    fn id(self) -> &'static str {
        use ResourceKind::Conversation;
        match self {
            Self::CreateConversation => "createConversation",
            Self::ListConversations => "listConversations",
            Self::CreateBranch => "createBranch",
            Self::ListBranches => "listBranches",
            Self::GetBranch => "getBranch",
            Self::ListMessages => "listMessages",
            Self::ListModels => "listModels",
            Self::ListPresets => "listPresets",
            Self::GetPreset => "getPreset",
            Self::PreviewConfiguration => "previewConfiguration",
            Self::CreateRun => "createRun",
            Self::CancelRun => "cancelRun",
            Self::GetRun => "getRun",
            Self::ListRunApprovals => "listRunApprovals",
            Self::DecideRunApproval => "decideRunApproval",
            Self::StreamRunEvents => "streamRunEvents",
            Self::ListCapabilities => "listCapabilities",
            Self::CreateProject => "createProject",
            Self::GetProject => "getProject",
            Self::UpdateProjectSettings => "updateProjectSettings",
            Self::ArchiveProject => "archiveProject",
            Self::RestoreProject => "restoreProject",
            Self::DeleteProject => "deleteProject",
            Self::SetProjectMemberRole => "setProjectMemberRole",
            Self::RevokeProjectMember => "revokeProjectMember",
            Self::GetResource(Conversation) => "getConversation",
            Self::GetResource(_) => "getArtifact",
            Self::ShareResource(Conversation) => "shareConversation",
            Self::ShareResource(_) => "shareArtifact",
            Self::RevokeResourceShare(Conversation) => "revokeConversationShare",
            Self::RevokeResourceShare(_) => "revokeArtifactShare",
            Self::CreateArtifact => "createArtifact",
            Self::CreateArtifactRevision => "createArtifactRevision",
            Self::GetArtifactRevision => "getArtifactRevision",
            Self::DownloadArtifactRevision => "downloadArtifactRevision",
            Self::GetPersonalQuotas => "getPersonalQuotas",
            Self::GetProjectQuotas => "getProjectQuotas",
            Self::SetQuotaOverride => "setQuotaOverride",
            Self::RevokeQuotaOverride => "revokeQuotaOverride",
        }
    }
    fn reads(self) -> bool {
        matches!(
            self,
            Self::ListConversations
                | Self::ListBranches
                | Self::GetBranch
                | Self::ListMessages
                | Self::ListModels
                | Self::ListPresets
                | Self::GetPreset
                | Self::PreviewConfiguration
                | Self::GetRun
                | Self::ListRunApprovals
                | Self::StreamRunEvents
                | Self::ListCapabilities
                | Self::GetProject
                | Self::GetResource(_)
                | Self::GetArtifactRevision
                | Self::DownloadArtifactRevision
                | Self::GetPersonalQuotas
                | Self::GetProjectQuotas
        )
    }
    /// Streams a `multipart/form-data` artifact upload (ADR 0031).
    fn uploads(self) -> bool {
        matches!(self, Self::CreateArtifact | Self::CreateArtifactRevision)
    }
    /// Takes one JSON object; every other operation takes an empty body.
    fn json(self) -> bool {
        matches!(
            self,
            Self::CreateRun
                | Self::DecideRunApproval
                | Self::CreateConversation
                | Self::CreateBranch
                | Self::PreviewConfiguration
                | Self::CreateProject
                | Self::UpdateProjectSettings
                | Self::SetProjectMemberRole
                | Self::RevokeProjectMember
                | Self::ShareResource(_)
                | Self::RevokeResourceShare(_)
                | Self::SetQuotaOverride
                | Self::RevokeQuotaOverride
        )
    }
    /// Names its target by a UUID in the third path segment.
    fn targeted(self) -> bool {
        !matches!(
            self,
            Self::GetPreset
                | Self::ListModels
                | Self::ListPresets
                | Self::CreateRun
                | Self::ListConversations
                | Self::CreateConversation
                | Self::ListCapabilities
                | Self::CreateProject
                | Self::CreateArtifact
                | Self::GetPersonalQuotas
                | Self::SetQuotaOverride
                | Self::RevokeQuotaOverride
        )
    }
}

// --- request bodies: closed objects, as the contract's request schemas ------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewProject {
    name: String,
    #[serde(default)]
    instructions: String,
    #[serde(default = "empty_object")]
    defaults: Value,
    reason: Option<String>,
}

fn empty_object() -> Value {
    json!({})
}

/// Every setting is replaced, so each is required.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsUpdate {
    name: String,
    instructions: String,
    defaults: Value,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberRole {
    grantee: GranteeBody,
    role: String,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Share {
    grantee: GranteeBody,
    access: String,
    reason: Option<String>,
}

/// A member revocation or a share revocation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    grantee: GranteeBody,
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GranteeBody {
    kind: String,
    grantee_id: Option<String>,
}

impl GranteeBody {
    /// The policy grantee. `project` names no identifier and is valid only for a share.
    fn grantee(self, shares: bool) -> Result<Grantee, Problem> {
        match (self.kind.as_str(), self.grantee_id) {
            ("user", Some(id)) => Ok(Grantee::User(id)),
            ("local_group", Some(id)) => Ok(Grantee::LocalGroup(id)),
            ("oidc_group", Some(id)) => Ok(Grantee::OidcGroup(id)),
            ("project", None) if shares => Ok(Grantee::Project),
            _ => Err(BODY),
        }
    }
}

fn grantee_json(grantee: &Grantee) -> Value {
    let (kind, user, local_group, oidc_group) = grants::Grantee::from(grantee).columns();
    match user.or(local_group).or(oidc_group) {
        Some(id) => json!({ "kind": kind, "grantee_id": id }),
        None => json!({ "kind": kind }),
    }
}

/// Serde also accepts a positional array for a derived struct; the contract requires one object.
fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Problem> {
    if !body.trim_ascii_start().starts_with(b"{") {
        return Err(BODY);
    }
    serde_json::from_slice(body).map_err(|_| BODY)
}

fn parse_unique<T: DeserializeOwned>(body: &[u8]) -> Result<T, Problem> {
    let value = crate::provider_keys::documents::unique(body).map_err(|_| BODY)?;
    if !value.is_object() {
        return Err(BODY);
    }
    serde_json::from_value(value).map_err(|_| BODY)
}

// A wire enum is a JSON string. Serde's default unit-enum decoder also accepts tagged objects.
fn string_enum<'de, D: serde::Deserializer<'de>, T: DeserializeOwned>(d: D) -> Result<T, D::Error> {
    T::deserialize(serde::de::value::StringDeserializer::new(
        String::deserialize(d)?,
    ))
}

/// A role or access key, matched exactly by the one grant vocabulary (ADR 0027).
fn vocabulary<P>(
    format: &str,
    key: &str,
    narrow: fn(GrantPermission) -> Result<P, authz::VocabularyError>,
) -> Result<P, Problem> {
    GrantVocabulary::parse(format, 1, key)
        .and_then(narrow)
        .map_err(|_| BODY)
}

/// A request body decoded and checked before any database work.
#[cfg_attr(test, derive(Debug, PartialEq))]
enum Input {
    Empty,
    Settings {
        name: String,
        instructions: String,
        defaults: Value,
        selection: Box<crate::model_config::Selection>,
    },
    /// A role grant, or a revocation without a role.
    Member {
        grantee: Grantee,
        role: Option<ProjectRole>,
    },
    /// A share, or a revocation without an access.
    Share {
        grantee: Grantee,
        access: Option<ResourceAccess>,
    },
}

/// Decodes the body of `op` with its optional audit reason. Settings are checked with the
/// store's own rules, so an invalid setting is refused before the session is validated.
fn decode(op: Op, body: &[u8]) -> Result<(Input, Option<String>), Problem> {
    let (input, reason) = match op {
        Op::CreateProject => {
            let b: NewProject = parse_unique(body)?;
            (settings(b.name, b.instructions, b.defaults)?, b.reason)
        }
        Op::UpdateProjectSettings => {
            let b: SettingsUpdate = parse_unique(body)?;
            (settings(b.name, b.instructions, b.defaults)?, b.reason)
        }
        Op::SetProjectMemberRole => {
            let b: MemberRole = parse(body)?;
            let role = vocabulary(PROJECT_ROLE, &b.role, GrantPermission::project_role)?;
            let grantee = b.grantee.grantee(false)?;
            let role = Some(role);
            (Input::Member { grantee, role }, b.reason)
        }
        Op::RevokeProjectMember => {
            let b: Revoke = parse(body)?;
            let grantee = b.grantee.grantee(false)?;
            (
                Input::Member {
                    grantee,
                    role: None,
                },
                b.reason,
            )
        }
        Op::ShareResource(_) => {
            let b: Share = parse(body)?;
            let access = vocabulary(RESOURCE_GRANT, &b.access, GrantPermission::resource_access)?;
            let grantee = b.grantee.grantee(true)?;
            let access = Some(access);
            (Input::Share { grantee, access }, b.reason)
        }
        Op::RevokeResourceShare(_) => {
            let b: Revoke = parse(body)?;
            let grantee = b.grantee.grantee(true)?;
            (
                Input::Share {
                    grantee,
                    access: None,
                },
                b.reason,
            )
        }
        _ => (Input::Empty, None),
    };
    // The audit bound (ADR 0027): 1 to 512 bytes without NUL.
    if reason
        .as_deref()
        .is_some_and(|reason| !crate::runs::bounded(reason, 512))
    {
        return Err(BODY);
    }
    Ok((input, reason))
}

fn settings(name: String, instructions: String, defaults: Value) -> Result<Input, Problem> {
    ProjectSettingsInput {
        name: &name,
        instructions: &instructions,
        defaults: &defaults,
    }
    .validate()
    .map_err(store_problem)?;
    let selection = crate::model_config::Selection::from_defaults(&defaults, "")?;
    Ok(Input::Settings {
        name,
        instructions,
        defaults,
        selection: Box::new(selection),
    })
}

// --- request shape ----------------------------------------------------------------------------

/// `application/json`, optionally with the one parameter `charset=utf-8`; case-insensitive.
fn json_media_type(value: &[u8]) -> bool {
    let mut parts = value.split(|b| *b == b';').map(<[u8]>::trim_ascii);
    parts
        .next()
        .is_some_and(|media| media.eq_ignore_ascii_case(b"application/json"))
        && parts
            .next()
            .is_none_or(|parameter| parameter.eq_ignore_ascii_case(b"charset=utf-8"))
        && parts.next().is_none()
}

/// The body profile of `op`, decided from metadata before anything is read. A JSON body is
/// then read up to its bound within the read timeout.
async fn read_body(op: Op, headers: &HeaderMap, body: Body) -> Result<Bytes, Problem> {
    if !op.json() {
        return match limits::empty_body(headers, &body) {
            true => Ok(Bytes::new()),
            false => Err(BODY),
        };
    }
    let mut media = headers.get_all(header::CONTENT_TYPE).iter();
    let declared = match (media.next(), media.next()) {
        (Some(value), None) => json_media_type(value.as_bytes()),
        _ => false,
    };
    let limit = if matches!(op, Op::CreateRun | Op::PreviewConfiguration) {
        131072
    } else {
        MAX_BODY_BYTES
    };
    if !declared || body.size_hint().lower() > limit as u64 {
        return Err(BODY);
    }
    match tokio::time::timeout(BODY_READ_TIMEOUT, to_bytes(body, limit)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        _ => Err(BODY),
    }
}

/// The UUID in path segment `n` (the first path parameter is segment 3), as the router matched
/// it. Unreserved characters only, so the raw segment is exactly
/// the identifier.
fn path_id(parts: &Parts, n: usize) -> Result<&str, Problem> {
    parts
        .uri
        .path()
        .split('/')
        .nth(n)
        .filter(|id| crate::runs::uuid(id).is_ok())
        .ok_or(IDENTIFIER)
}

/// One `Idempotency-Key` of 1 to 128 visible ASCII characters (ADR 0007).
fn idempotency_key(headers: &HeaderMap) -> Result<&str, Problem> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(KEY_REQUIRED);
    };
    let key = value.as_bytes();
    if !(1..=128).contains(&key.len()) || !key.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(KEY_REQUIRED);
    }
    value.to_str().map_err(|_| KEY_REQUIRED)
}

/// ADR 0007 scopes a client key to the authenticated actor, the operation and its target. The
/// audit table keys on `(actor, request_key)`, so the request key binds the rest: one client
/// key reused on another operation or target is a new request, never a replay or a conflict.
/// A SHA-256 digest in lowercase hex: 64 bytes, within the audit bound.
fn request_key(op: Op, target: &str, key: &str) -> String {
    let identity = crate::runs::identity(
        IDEMPOTENCY_DOMAIN,
        &[op.id().as_bytes(), target.as_bytes(), key.as_bytes()],
    );
    projects::hex(&crate::runs::digest(&identity))
}

/// ADR 0007 `Timestamp`: RFC 3339 UTC with exactly six fractional digits and `Z`.
fn timestamp(micros: i64) -> Result<String, Problem> {
    chrono::DateTime::from_timestamp_micros(micros)
        .map(|at| at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
        .ok_or(INTERNAL)
}

// --- responses --------------------------------------------------------------------------------

fn project_json(view: &ProjectView) -> Value {
    let settings = &view.settings;
    json!({
        "project_id": settings.project_id,
        "scope_id": settings.scope_id,
        "name": settings.name,
        "instructions": settings.instructions,
        "defaults": settings.defaults,
        "revision": settings.revision.to_string(),
        "archived": settings.archived,
        "role": projects::role_key(view.role),
    })
}

fn resource_json(kind: ResourceKind, id: &str, view: &ResourceView) -> Result<Value, Problem> {
    let mut body = json!({
        "scope_kind": if view.project_id.is_some() { "project" } else { "personal" },
        "scope_id": view.scope_id,
        "project_id": view.project_id,
        "created_at": timestamp(view.created_us)?,
        "access": projects::access_key(view.access),
        "can_manage_shares": view.can_manage_shares,
    });
    if kind == ResourceKind::Conversation {
        body["conversation_id"] = id.into();
    } else {
        body["artifact_id"] = id.into();
        body["last_revision"] = view.last_revision.unwrap_or_default().to_string().into();
    }
    Ok(body)
}

// --- the router -------------------------------------------------------------------------------

/// The authenticated session channel of one request, before validation.
enum Session {
    Browser(String),
    Native(Arc<NativeAuth>, String),
}

struct Api {
    browser: Arc<BrowserAuth>,
    native: Option<Arc<NativeAuth>>,
    /// The configured browser application origin, compared byte for byte (ADR 0019).
    origin: String,
    /// The primary pool the sign-in services also use (ADR 0016).
    pool: PgPool,
    /// The validated `ARTIFACTS_DIR` (ADR 0031); `None` refuses the payload operations.
    artifacts: Option<artifact_fs::Store>,
    in_flight: Semaphore,
    streams: Arc<Semaphore>,
}

/// Builds the `/v1` routes over the mounted browser service, the optional native service, the
/// configured browser origin, the primary pool and the optional artifact store. Mount it with
/// `Router::merge`; the sign-in settings checks refuse every `/v1` path
/// (`browser_auth::router::reserved`), so the merge cannot panic. `/v1` and any other path
/// under it are `404 not_found` problems.
pub fn router(
    browser: Arc<BrowserAuth>,
    native: Option<Arc<NativeAuth>>,
    origin: &str,
    pool: PgPool,
    artifacts: Option<artifact_fs::Store>,
) -> Router {
    let api = Arc::new(Api {
        browser,
        native,
        origin: origin.to_owned(),
        pool,
        artifacts,
        in_flight: Semaphore::new(MAX_IN_FLIGHT),
        streams: Arc::new(Semaphore::new(runs::SSE_MAX_IN_FLIGHT)),
    });
    let mut router = Router::new();
    // Every other path under the prefix also answers with a versioned problem.
    let rest = [("/v1", vec![]), ("/v1/{*rest}", vec![])];
    for (path, operations) in routes().into_iter().chain(rest) {
        let api = api.clone();
        let operations: Arc<[(Method, Op)]> = operations.into();
        // `any`, not `get`: HEAD is decided here like every other method.
        router = router.route(
            path,
            any(move |request: Request| {
                let api = api.clone();
                let operations = operations.clone();
                async move { api.serve(&operations, request).await }
            }),
        );
    }
    router
}

/// Every contract path template with its operations, by method.
fn routes() -> [(&'static str, Vec<(Method, Op)>); 35] {
    use Op::*;
    use ResourceKind::{Artifact, Conversation};
    let (get, put, post) = (Method::GET, Method::PUT, Method::POST);
    [
        (
            "/v1/conversations",
            vec![
                (get.clone(), ListConversations),
                (post.clone(), CreateConversation),
            ],
        ),
        (
            "/v1/conversations/{conversation_id}/branches",
            vec![(get.clone(), ListBranches), (post.clone(), CreateBranch)],
        ),
        (
            "/v1/conversations/{conversation_id}/branches/{branch_id}",
            vec![(get.clone(), GetBranch)],
        ),
        (
            "/v1/conversations/{conversation_id}/branches/{branch_id}/messages",
            vec![(get.clone(), ListMessages)],
        ),
        (
            "/v1/conversations/{conversation_id}/branches/{branch_id}/effective-configuration",
            vec![(post.clone(), PreviewConfiguration)],
        ),
        ("/v1/models", vec![(get.clone(), ListModels)]),
        ("/v1/presets", vec![(get.clone(), ListPresets)]),
        ("/v1/presets/{preset_id}", vec![(get.clone(), GetPreset)]),
        ("/v1/runs", vec![(post.clone(), CreateRun)]),
        ("/v1/runs/{run_id}/cancel", vec![(post.clone(), CancelRun)]),
        (
            "/v1/runs/{run_id}/approvals",
            vec![(get.clone(), ListRunApprovals)],
        ),
        (
            "/v1/runs/{run_id}/approvals/{approval_id}/decision",
            vec![(post.clone(), DecideRunApproval)],
        ),
        ("/v1/runs/{run_id}", vec![(get.clone(), GetRun)]),
        (
            "/v1/runs/{run_id}/events",
            vec![(get.clone(), StreamRunEvents)],
        ),
        ("/v1/capabilities", vec![(get.clone(), ListCapabilities)]),
        ("/v1/projects", vec![(post.clone(), CreateProject)]),
        (
            "/v1/projects/{project_id}",
            vec![
                (get.clone(), GetProject),
                (put.clone(), UpdateProjectSettings),
                (Method::DELETE, DeleteProject),
            ],
        ),
        (
            "/v1/projects/{project_id}/archive",
            vec![(post.clone(), ArchiveProject)],
        ),
        (
            "/v1/projects/{project_id}/restore",
            vec![(post.clone(), RestoreProject)],
        ),
        (
            "/v1/projects/{project_id}/members",
            vec![(put.clone(), SetProjectMemberRole)],
        ),
        (
            "/v1/projects/{project_id}/members/revoke",
            vec![(post.clone(), RevokeProjectMember)],
        ),
        (
            "/v1/conversations/{conversation_id}",
            vec![(get.clone(), GetResource(Conversation))],
        ),
        (
            "/v1/conversations/{conversation_id}/shares",
            vec![(put.clone(), ShareResource(Conversation))],
        ),
        (
            "/v1/conversations/{conversation_id}/shares/revoke",
            vec![(post.clone(), RevokeResourceShare(Conversation))],
        ),
        ("/v1/artifacts", vec![(post.clone(), CreateArtifact)]),
        (
            "/v1/artifacts/{artifact_id}",
            vec![(get.clone(), GetResource(Artifact))],
        ),
        (
            "/v1/artifacts/{artifact_id}/shares",
            vec![(put.clone(), ShareResource(Artifact))],
        ),
        (
            "/v1/artifacts/{artifact_id}/shares/revoke",
            vec![(post.clone(), RevokeResourceShare(Artifact))],
        ),
        (
            "/v1/artifacts/{artifact_id}/revisions",
            vec![(post.clone(), CreateArtifactRevision)],
        ),
        (
            "/v1/artifacts/{artifact_id}/revisions/{revision_id}",
            vec![(get.clone(), GetArtifactRevision)],
        ),
        (
            "/v1/artifacts/{artifact_id}/revisions/{revision_id}/content",
            vec![(get.clone(), DownloadArtifactRevision)],
        ),
        (
            "/v1/quotas/personal",
            vec![(get.clone(), GetPersonalQuotas)],
        ),
        (
            "/v1/projects/{project_id}/quotas",
            vec![(get, GetProjectQuotas)],
        ),
        (
            "/v1/admin/scopes/{scope_id}/quotas/{resource_kind}",
            vec![(put, SetQuotaOverride)],
        ),
        (
            "/v1/admin/scopes/{scope_id}/quotas/{resource_kind}/revoke",
            vec![(post, RevokeQuotaOverride)],
        ),
    ]
}

/// The request's ID, inserted by `telemetry::observe`, so a problem names the logged request.
fn request_id(extensions: &axum::http::Extensions) -> Option<RequestId> {
    extensions
        .get::<RequestId>()
        .copied()
        .or_else(RequestId::generate)
}

impl Api {
    async fn serve(self: &Arc<Self>, operations: &[(Method, Op)], request: Request) -> Response {
        let head = request.method() == Method::HEAD;
        let id = request_id(request.extensions());
        let mut response = self
            .handle(operations, request)
            .await
            .unwrap_or_else(|problem| problem.response(id));
        if head {
            *response.body_mut() = Body::empty();
        }
        response
    }

    async fn handle(
        self: &Arc<Self>,
        operations: &[(Method, Op)],
        request: Request,
    ) -> Result<Response, Problem> {
        let (mut parts, body) = request.into_parts();
        // HEAD is GET without a body, which the server never sends.
        let method = match parts.method {
            Method::HEAD => Method::GET,
            ref method => method.clone(),
        };
        let op = operations
            .iter()
            .find(|(allowed, _)| *allowed == method)
            .map(|(_, op)| *op)
            .ok_or(NOT_FOUND)?;
        if limits::target_bytes(&parts.uri) > limits::MAX_TARGET_BYTES
            || parts.headers.len() > limits::MAX_HEADER_FIELDS
            || limits::header_bytes(&parts.headers) > limits::MAX_HEADER_BYTES
        {
            return Err(HEAD_TOO_LARGE);
        }
        // `try_acquire` never waits. The permit is released when this future completes or is
        // dropped, including on client disconnect.
        if op == Op::StreamRunEvents {
            let permit = self
                .streams
                .clone()
                .try_acquire_owned()
                .map_err(|_| UNAVAILABLE)?;
            return self.stream_events(parts, body, permit).await;
        }
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return Err(UNAVAILABLE);
        };
        let session = self.session(&parts)?;
        let target = if op.targeted() {
            path_id(&parts, 3)?
        } else {
            ""
        };
        if op.uploads() {
            let key = idempotency_key(&parts.headers)?;
            return self.upload(op, &parts, body, session, target, key).await;
        }
        let key = match op.reads() {
            true => None,
            false => Some(idempotency_key(&parts.headers)?.to_owned()),
        };
        let body = read_body(op, &parts.headers, body).await?;
        if matches!(
            op,
            Op::GetPersonalQuotas
                | Op::GetProjectQuotas
                | Op::SetQuotaOverride
                | Op::RevokeQuotaOverride
        ) {
            return self
                .quota_operation(op, &parts, session, target, key.as_deref(), &body)
                .await;
        }
        if matches!(op, Op::GetArtifactRevision | Op::DownloadArtifactRevision) {
            return self.revision(op, &parts, session, target).await;
        }
        if matches!(op, Op::ListRunApprovals | Op::DecideRunApproval) {
            return self
                .approval_operation(op, &parts, &session, target, key.as_deref(), &body)
                .await;
        }
        if op == Op::GetRun {
            return self.snapshot(&parts, session, target).await;
        }
        if matches!(
            op,
            Op::CreateConversation
                | Op::ListConversations
                | Op::CreateBranch
                | Op::ListBranches
                | Op::GetBranch
                | Op::ListMessages
                | Op::ListModels
                | Op::ListPresets
                | Op::GetPreset
                | Op::PreviewConfiguration
                | Op::CreateRun
                | Op::CancelRun
        ) {
            return self
                .conversation_operation(op, &mut parts, session, key.as_deref(), &body)
                .await;
        }
        let key = key.map(|raw| request_key(op, target, &raw));
        let (input, reason) = decode(op, &body)?;
        let context = self.authenticate(&session).await?;
        let call = Call {
            op,
            context: &context,
            target,
            key: key.as_deref().unwrap_or_default(),
            reason: reason.as_deref(),
        };
        let catalog = parts
            .extensions
            .get::<Arc<crate::model_config::Catalog>>()
            .map(Arc::as_ref);
        self.run(call, input, catalog).await
    }

    /// Selects one session channel from the head alone, before any database work.
    fn session(&self, parts: &Parts) -> Result<Session, Problem> {
        let headers = &parts.headers;
        let cookie = handoff::cookie_values(headers, handoff::SESSION_COOKIE)
            .next()
            .is_some();
        let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
        match (cookie, authorization.next(), authorization.next()) {
            (true, None, _) if self.same_origin(parts) => {
                handoff::single_cookie(headers, handoff::SESSION_COOKIE)
                    .filter(|c| sessions::well_formed(c).is_ok())
                    .map(|cookie| Session::Browser(cookie.to_owned()))
                    .ok_or(UNAUTHENTICATED)
            }
            (false, Some(value), None) => {
                let bearer = value
                    .to_str()
                    .ok()
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .filter(|c| sessions::well_formed(c).is_ok());
                match (self.native.as_ref(), bearer) {
                    (Some(native), Some(bearer)) => {
                        Ok(Session::Native(native.clone(), bearer.to_owned()))
                    }
                    _ => Err(UNAUTHENTICATED),
                }
            }
            _ => Err(UNAUTHENTICATED),
        }
    }

    /// The cookie channel's CSRF binding (ADRs 0007 and 0019): an unsafe method needs exactly
    /// one `Origin` with the configured bytes; a safe method may omit it, but any `Origin` it
    /// sends must be that one. `null`, a list and a repeated field all fail.
    fn same_origin(&self, parts: &Parts) -> bool {
        let mut origins = parts.headers.get_all(header::ORIGIN).iter();
        match (origins.next(), origins.next()) {
            (None, _) => matches!(parts.method, Method::GET | Method::HEAD),
            (Some(origin), None) => origin.as_bytes() == self.origin.as_bytes(),
            _ => false,
        }
    }

    async fn authenticate(&self, session: &Session) -> Result<EffectSession, Problem> {
        match session {
            Session::Browser(cookie) => self.browser.validate_effect(cookie, None).await,
            Session::Native(native, bearer) => native.validate_effect(bearer).await,
        }
        .map_err(session_problem)
    }

    /// One bounded database phase on one pooled connection. A database failure, an elapsed
    /// deadline or a dropped future leaves the outcome of a statement or commit unknown, so
    /// that connection is closed rather than returned to the pool (ADR 0016).
    async fn database<T>(
        &self,
        work: impl AsyncFnOnce(&mut PgConnection) -> Result<T, StoreError>,
    ) -> Result<T, Problem> {
        self.with_connection(async |c| work(c).await.map_err(store_problem))
            .await
    }

    async fn with_connection<T>(
        &self,
        work: impl AsyncFnOnce(&mut PgConnection) -> Result<T, Problem>,
    ) -> Result<T, Problem> {
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            let mut db = Checkout::acquire(&self.pool).await?;
            let result = work(db.lend()).await;
            db.settle(!matches!(result.as_ref().err(), Some(p) if *p == UNAVAILABLE));
            result
        })
        .await
        .map_err(|_| TIMEOUT)?
    }

    async fn run(
        &self,
        call: Call<'_>,
        input: Input,
        catalog: Option<&crate::model_config::Catalog>,
    ) -> Result<Response, Problem> {
        let Call {
            op,
            context,
            target,
            ..
        } = call;
        let now = context.observed_ms();
        let audit = call.audit();
        match (op, input) {
            (Op::ListCapabilities, _) => {
                self.database(async |c| principal(c, context).await.map(drop))
                    .await?;
                // A core-only installation: no optional provider is installed (ADR 0007).
                let generated_at = timestamp(now.saturating_mul(1000))?;
                let list = json!({ "generated_at": generated_at, "capabilities": [] });
                Ok(reply(StatusCode::OK, list))
            }
            (Op::GetProject, _) => {
                let view = self
                    .database(async |c| read_project(c, context, target).await)
                    .await?;
                Ok(reply(StatusCode::OK, project_json(&view)))
            }
            (
                Op::CreateProject | Op::UpdateProjectSettings,
                Input::Settings {
                    name,
                    instructions,
                    defaults,
                    selection,
                },
            ) => {
                let settings = ProjectSettingsInput {
                    name: &name,
                    instructions: &instructions,
                    defaults: &defaults,
                };
                let check_defaults = async |c: &mut PgConnection, actor: &Principal| {
                    catalog::check_project_defaults(c, actor, catalog, &selection).await
                };
                let view = self
                    .database(async |c| {
                        let project = if op == Op::CreateProject {
                            projects::create_project_checked(c, &audit, &settings, check_defaults)
                                .await?
                        } else {
                            projects::update_project_settings_checked(
                                c,
                                &audit,
                                target,
                                &settings,
                                check_defaults,
                            )
                            .await?
                        };
                        read_project(c, context, project.target_id()).await
                    })
                    .await?;
                let status = match op {
                    Op::CreateProject => StatusCode::CREATED,
                    _ => StatusCode::OK,
                };
                Ok(reply(status, project_json(&view)))
            }
            (Op::ArchiveProject | Op::RestoreProject, _) => {
                let view = self
                    .database(async |c| {
                        if op == Op::ArchiveProject {
                            projects::archive_project(c, &audit, target).await?;
                        } else {
                            projects::restore_project(c, &audit, target).await?;
                        }
                        read_project(c, context, target).await
                    })
                    .await?;
                Ok(reply(StatusCode::OK, project_json(&view)))
            }
            (Op::DeleteProject, _) => {
                self.database(async |c| projects::delete_project(c, &audit, target).await)
                    .await?;
                Ok(no_content())
            }
            (_, Input::Member { grantee, role }) => {
                self.database(async |c| match role {
                    Some(role) => {
                        projects::set_project_member_role(c, &audit, target, &grantee, role).await
                    }
                    None => projects::revoke_project_member(c, &audit, target, &grantee).await,
                })
                .await?;
                Ok(match role {
                    Some(role) => reply(
                        StatusCode::OK,
                        json!({
                            "project_id": target,
                            "grantee": grantee_json(&grantee),
                            "role": projects::role_key(role),
                        }),
                    ),
                    None => no_content(),
                })
            }
            (Op::GetResource(kind), _) => {
                let view = self
                    .database(async |c| {
                        let principal = principal(c, context).await?;
                        projects::read_resource(c, &principal, kind, target, now).await
                    })
                    .await?;
                Ok(reply(StatusCode::OK, resource_json(kind, target, &view)?))
            }
            (
                Op::ShareResource(kind) | Op::RevokeResourceShare(kind),
                Input::Share { grantee, access },
            ) => {
                let resource_kind = projects::resource_kind(kind).map_err(store_problem)?;
                self.database(async |c| match access {
                    Some(access) => {
                        projects::share_resource(c, &audit, kind, target, &grantee, access).await
                    }
                    None => projects::unshare_resource(c, &audit, kind, target, &grantee).await,
                })
                .await?;
                Ok(match access {
                    Some(access) => reply(
                        StatusCode::OK,
                        json!({
                            "resource_kind": resource_kind,
                            "resource_id": target,
                            "grantee": grantee_json(&grantee),
                            "access": projects::access_key(access),
                        }),
                    ),
                    None => no_content(),
                })
            }
            // `decode` yields each operation's own input, so no other pair occurs.
            _ => Err(INTERNAL),
        }
    }
}

/// One validated, authenticated request.
#[derive(Clone, Copy)]
struct Call<'a> {
    op: Op,
    context: &'a EffectSession,
    /// The path identifier, or empty for an untargeted operation.
    target: &'a str,
    /// The derived request key of a write, or empty for a read.
    key: &'a str,
    /// The client's audit reason, if any.
    reason: Option<&'a str>,
}

impl<'a> Call<'a> {
    /// The audit context of a write. The reason defaults to the operation's identifier. A read
    /// never uses it.
    fn audit(self) -> AuditContext<'a> {
        AuditContext {
            actor_user_id: self.context.user_id(),
            actor_approval_id: self.context.approval_id(),
            now_ms: self.context.observed_ms(),
            request_key: self.key,
            reason: self.reason.unwrap_or(self.op.id()),
        }
    }
}

/// The session's principal, hydrated on the primary for this request; it must be active.
async fn principal(
    c: &mut PgConnection,
    context: &sessions::Context,
) -> Result<Principal, StoreError> {
    let principal = store::hydrate_api_principal(
        c,
        context.user_id(),
        context.approval_id(),
        context.observed_ms(),
    )
    .await?;
    authz::require(principal.as_ref())
        .cloned()
        .map_err(StoreError::Denied)
}

async fn read_project(
    c: &mut PgConnection,
    context: &sessions::Context,
    project_id: &str,
) -> Result<ProjectView, StoreError> {
    let principal = principal(c, context).await?;
    projects::read_project(c, &principal, project_id, context.observed_ms()).await
}

impl From<StoreError> for Problem {
    fn from(e: StoreError) -> Self {
        store_problem(e)
    }
}
impl From<sqlx::Error> for Problem {
    fn from(_: sqlx::Error) -> Self {
        UNAVAILABLE
    }
}
impl From<crate::runs::Error> for Problem {
    fn from(e: crate::runs::Error) -> Self {
        store_problem(e.into())
    }
}
impl From<crate::model_config::Error> for Problem {
    fn from(e: crate::model_config::Error) -> Self {
        use crate::model_config::Error::*;
        match e {
            Invalid(_) => INVALID,
            Unauthorized => POLICY,
            Provisioning => PROVISIONING,
        }
    }
}

mod approvals;
pub use approvals::ApprovalDisplayPolicy;
mod artifacts;
mod catalog;
mod conversations;
mod pagination;
mod quotas;
mod runs;
mod submission;

#[cfg(test)]
mod tests;
