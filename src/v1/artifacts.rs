//! The artifact payload operations of `/v1` (ADR 0031 PR2): multipart uploads into a scope or
//! onto an existing artifact, immutable revision metadata and grant-checked downloads with
//! single byte ranges. Each runs after the shared route, bound, permit and session steps of
//! the parent module, in this order:
//!
//! - **Upload.** Query (`scope_id` for a new artifact, optional `max_bytes`), one
//!   `multipart/form-data` `Content-Type` with a valid boundary, then `ARTIFACTS_DIR`
//!   (`503 provisioning` when unset). Only then the session is validated and the target scope
//!   or artifact authorized on the primary, before `storage::reserve` or any staging file.
//!   [`artifact_fs::ingest`] streams the body with bounded memory within [`UPLOAD_TIMEOUT`].
//! - **Revision metadata.** Current `Read` on the artifact, then the revision of that artifact.
//! - **Download.** The `Range` header and `ARTIFACTS_DIR`, then current `Download` on the
//!   artifact on every request, then only an `active` revision streams from the store.
use super::{
    Api, BODY, CONFLICT, INTERNAL, INVALID, KEY_CONFLICT, NOT_FOUND, Op, PROVISIONING, Problem,
    Session, TIMEOUT, UNAVAILABLE, path_id, principal, problem, reply, request_id, request_key,
    response_headers, single_header, timestamp,
};
use crate::{
    artifact_fs::{self, UPLOAD_TIMEOUT},
    authz::{
        Action, DenialReason,
        projects::{self, hex},
        store::StoreError,
    },
    multipart::Parser,
    runs,
    storage::{self, Revision},
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;
use std::fmt::Write as _;

/// The largest file one upload may carry, and the default reservation ceiling.
pub const MAX_UPLOAD_BYTES: i64 = 64 * 1024 * 1024;

const TOO_LARGE: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The file exceeds the upload byte ceiling.",
);
const RANGE: Problem = problem(
    StatusCode::BAD_REQUEST,
    "validation",
    "The Range header must name one byte range.",
);
const IN_PROGRESS: Problem = problem(
    StatusCode::CONFLICT,
    "conflict",
    "Another upload with this Idempotency-Key is in progress.",
);
const NOT_SERVABLE: Problem = problem(
    StatusCode::CONFLICT,
    "conflict",
    "The revision's content is not available in its current state.",
);
const QUOTA: Problem = problem(
    StatusCode::TOO_MANY_REQUESTS,
    "quota",
    "The storage quota does not allow this upload.",
);
const UNSATISFIABLE: Problem = problem(
    StatusCode::RANGE_NOT_SATISFIABLE,
    "range_not_satisfiable",
    "The requested range does not overlap the content.",
);

/// The closed `metadata` part. It has no members yet; new optional members are additive.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadMetadata {}

/// The upload's metadata part is one closed JSON object.
fn metadata(bytes: &[u8]) -> bool {
    super::parse::<UploadMetadata>(bytes).is_ok()
}

/// The query of an upload: a new artifact's optional target scope and the byte ceiling.
#[derive(Debug, PartialEq, Eq)]
struct UploadQuery<'a> {
    scope: Option<&'a str>,
    max_bytes: i64,
}

/// `scope_id` (a canonical UUID, `createArtifact` only) and `max_bytes` (a canonical decimal
/// from 1 to [`MAX_UPLOAD_BYTES`]), each at most once; nothing else. Values are unreserved
/// characters, so no percent-decoding is needed: an encoded value is refused.
fn upload_query(op: Op, query: Option<&str>) -> Result<UploadQuery<'_>, Problem> {
    let mut out = UploadQuery {
        scope: None,
        max_bytes: MAX_UPLOAD_BYTES,
    };
    let mut ceiling = false;
    for pair in query.into_iter().flat_map(|q| q.split('&')) {
        match pair.split_once('=') {
            Some(("scope_id", id))
                if op == Op::CreateArtifact && out.scope.is_none() && runs::uuid(id).is_ok() =>
            {
                out.scope = Some(id);
            }
            Some(("max_bytes", n)) if !ceiling => {
                let canonical = !n.is_empty()
                    && n.len() <= 19
                    && n.bytes().all(|b| b.is_ascii_digit())
                    && !n.starts_with('0');
                out.max_bytes = n
                    .parse()
                    .ok()
                    .filter(|n| canonical && (1..=MAX_UPLOAD_BYTES).contains(n))
                    .ok_or(INVALID)?;
                ceiling = true;
            }
            _ => return Err(INVALID),
        }
    }
    Ok(out)
}

/// One RFC 9110 §14.1.2 byte range: `first-last`, `first-` or `-suffix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteRange {
    From(u64, Option<u64>),
    Suffix(u64),
}

impl ByteRange {
    /// The satisfiable inclusive `(first, last)` within `total` bytes, or `None`.
    fn resolve(self, total: u64) -> Option<(u64, u64)> {
        match self {
            Self::From(first, _) if first >= total => None,
            Self::From(first, last) => Some((first, last.map_or(total - 1, |l| l.min(total - 1)))),
            Self::Suffix(0) => None,
            Self::Suffix(n) => (total > 0).then(|| (total - n.min(total), total - 1)),
        }
    }
}

/// The one `Range` of a download, checked before any database work. An `If-Range` field makes
/// the server send the whole content: no validator is issued, so none can match. A repeated
/// field, another unit, a list or a malformed range is `400 validation`. Digits beyond 64 bits
/// saturate, so such a range is unsatisfiable rather than malformed.
fn byte_range(headers: &HeaderMap) -> Result<Option<ByteRange>, Problem> {
    if headers.contains_key(header::IF_RANGE) {
        return Ok(None);
    }
    let Some(value) = single_header(headers, header::RANGE, RANGE)? else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| RANGE)?;
    let spec = value
        .get(..6)
        .filter(|unit| unit.eq_ignore_ascii_case("bytes="))
        .map(|_| &value[6..])
        .ok_or(RANGE)?;
    let (first, last) = spec.split_once('-').ok_or(RANGE)?;
    let number = |text: &str| match !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        true => Ok(text.parse().unwrap_or(u64::MAX)),
        false => Err(RANGE),
    };
    let range = match (first.is_empty(), last.is_empty()) {
        (true, _) => ByteRange::Suffix(number(last)?),
        (false, true) => ByteRange::From(number(first)?, None),
        (false, false) => {
            let (first, last) = (number(first)?, number(last)?);
            if last < first {
                return Err(RANGE);
            }
            ByteRange::From(first, Some(last))
        }
    };
    Ok(Some(range))
}

/// `attachment`, with the display name as an RFC 8187 `filename*` in which every byte outside
/// `attr-char` is percent-encoded: no quote, separator or control byte reaches the header.
fn disposition(name: Option<&str>) -> HeaderValue {
    let mut value = String::from("attachment");
    if let Some(name) = name {
        value.push_str("; filename*=UTF-8''");
        for b in name.bytes() {
            if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                value.push(char::from(b));
            } else {
                let _ = write!(value, "%{b:02X}");
            }
        }
    }
    HeaderValue::from_str(&value).unwrap_or(HeaderValue::from_static("attachment"))
}

/// The wire form of one revision: never its reservation or a path.
fn revision_json(r: &Revision) -> Result<Value, Problem> {
    Ok(json!({
        "artifact_id": r.artifact_id,
        "revision_id": r.id,
        "revision": r.revision.to_string(),
        "scope_kind": if r.project_id.is_some() { "project" } else { "personal" },
        "scope_id": r.scope_id,
        "project_id": r.project_id,
        "media_type": r.media_type,
        "size_bytes": r.size_bytes.to_string(),
        "sha256": hex(&r.content_digest),
        "display_name": r.display_name,
        "state": r.state,
        "created_at": timestamp(r.created_us)?,
    }))
}

fn ingest_problem(error: artifact_fs::Error) -> Problem {
    use artifact_fs::Error::{
        Body, InProgress, Io, Missing, Multipart, Rejected, Storage, TooLarge,
    };
    match error {
        Multipart(_) | Rejected | Body => BODY,
        TooLarge => TOO_LARGE,
        InProgress => IN_PROGRESS,
        Io | Missing => INTERNAL,
        Storage(error) => storage_problem(error),
    }
}

/// ADR 0005 refusals of an upload. A reservation or settlement conflict is a changed request
/// (or a spent key) under the same `Idempotency-Key`.
fn storage_problem(error: runs::Error) -> Problem {
    use runs::Error::{
        Conflict, Database, InstanceLimit, Invalid, LimitUnconfigured, NotEligible, NotFound,
        OwnerLimit, StaleRevision, TransactionUnavailable, Unresolved,
    };
    match error {
        OwnerLimit | InstanceLimit => QUOTA,
        LimitUnconfigured => PROVISIONING,
        Conflict => KEY_CONFLICT,
        NotFound => NOT_FOUND,
        Invalid => INVALID,
        StaleRevision | NotEligible | Unresolved => CONFLICT,
        Database(_) | TransactionUnavailable => UNAVAILABLE,
    }
}

/// Revision `revision` of `artifact`; one of another artifact, or none, is concealed.
async fn read_revision(
    c: &mut PgConnection,
    artifact: &str,
    revision: &str,
) -> Result<Revision, StoreError> {
    storage::read_revision(c, artifact, revision)
        .await?
        .ok_or(StoreError::Denied(DenialReason::NotFound))
}

/// Exactly one `Content-Type` that the multipart parser accepts.
fn multipart_type(headers: &HeaderMap) -> Result<&str, Problem> {
    let value = single_header(headers, header::CONTENT_TYPE, BODY)?.ok_or(BODY)?;
    let value = value.to_str().map_err(|_| BODY)?;
    Parser::new(value).map_err(|_| BODY)?;
    Ok(value)
}

impl Api {
    /// `createArtifact` and `createArtifactRevision`. `target` is the artifact of a new
    /// revision; `client_key` is the raw `Idempotency-Key`, scoped here to the operation and its
    /// target scope or artifact.
    pub(super) async fn upload(
        &self,
        op: Op,
        parts: &Parts,
        body: Body,
        session: Session,
        target: &str,
        client_key: &str,
    ) -> Result<Response, Problem> {
        let query = upload_query(op, parts.uri.query())?;
        let content_type = multipart_type(&parts.headers)?;
        let store = self.artifacts.as_ref().ok_or(PROVISIONING)?;
        let context = self.authenticate(&session).await?;
        let (actor, now) = (context.user_id(), context.observed_ms());
        let (scope, key, artifact) = if op == Op::CreateArtifact {
            let scope = query.scope.unwrap_or(context.personal_scope_id());
            let key = request_key(op, scope, client_key);
            let artifact = self
                .database(async |c| {
                    let principal = principal(c, &context).await?;
                    projects::authorize_create_in_scope(c, &principal, scope, now).await?;
                    Ok(storage::upload_artifact(c, scope, actor, &key).await?)
                })
                .await?;
            (scope.to_owned(), key, artifact)
        } else {
            let located = self
                .database(async |c| {
                    let principal = principal(c, &context).await?;
                    projects::authorize_artifact(c, &principal, target, Action::Write, now).await
                })
                .await?;
            let key = request_key(op, target, client_key);
            (located.scope_id, key, target.to_owned())
        };
        let upload = artifact_fs::Upload {
            scope: &scope,
            actor,
            key: &key,
            artifact: &artifact,
            max_bytes: query.max_bytes,
            content_type,
        };
        let ingest = artifact_fs::ingest(&self.pool, store, &upload, body, |form| {
            metadata(&form.metadata)
        });
        let stored = tokio::time::timeout(UPLOAD_TIMEOUT, ingest)
            .await
            .map_err(|_| TIMEOUT)?
            .map_err(ingest_problem)?;
        let revision = self
            .database(async |c| read_revision(c, &artifact, &stored.revision).await)
            .await?;
        Ok(reply(StatusCode::CREATED, revision_json(&revision)?))
    }

    /// `getArtifactRevision` and `downloadArtifactRevision` of `artifact`.
    pub(super) async fn revision(
        &self,
        op: Op,
        parts: &Parts,
        session: Session,
        artifact: &str,
    ) -> Result<Response, Problem> {
        let revision_id = path_id(parts, 5)?;
        let download = op == Op::DownloadArtifactRevision;
        let (range, store) = match download {
            true => (
                byte_range(&parts.headers)?,
                Some(self.artifacts.as_ref().ok_or(PROVISIONING)?),
            ),
            false => (None, None),
        };
        let context = self.authenticate(&session).await?;
        let action = if download {
            Action::Download
        } else {
            Action::Read
        };
        let revision = self
            .database(async |c| {
                let principal = principal(c, &context).await?;
                let now = context.observed_ms();
                projects::authorize_artifact(c, &principal, artifact, action, now).await?;
                read_revision(c, artifact, revision_id).await
            })
            .await?;
        let Some(store) = store else {
            return Ok(reply(StatusCode::OK, revision_json(&revision)?));
        };
        if revision.state != "active" {
            return Err(NOT_SERVABLE);
        }
        let total = u64::try_from(revision.size_bytes).map_err(|_| INTERNAL)?;
        let (status, first, len) = match range.map(|r| r.resolve(total)) {
            None => (StatusCode::OK, 0, total),
            Some(Some((first, last))) => (StatusCode::PARTIAL_CONTENT, first, last - first + 1),
            Some(None) => {
                let mut response = UNSATISFIABLE.response(request_id(&parts.extensions));
                let unsatisfied = HeaderValue::from_str(&format!("bytes */{total}"));
                response
                    .headers_mut()
                    .insert(header::CONTENT_RANGE, unsatisfied.map_err(|_| INTERNAL)?);
                return Ok(response);
            }
        };
        let media_type = HeaderValue::from_str(&revision.media_type).map_err(|_| INTERNAL)?;
        let content = store
            .read(&revision.reservation_id, revision.size_bytes, first, len)
            .await
            .map_err(|_| INTERNAL)?;
        let mut response = Response::new(Body::new(content));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        response_headers(headers);
        headers.insert(header::CONTENT_TYPE, media_type);
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::CONTENT_DISPOSITION,
            disposition(revision.display_name.as_deref()),
        );
        if status == StatusCode::PARTIAL_CONTENT {
            let last = first + len - 1;
            let range = HeaderValue::from_str(&format!("bytes {first}-{last}/{total}"));
            headers.insert(header::CONTENT_RANGE, range.map_err(|_| INTERNAL)?);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
