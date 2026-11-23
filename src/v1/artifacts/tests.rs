//! Pure helpers of the artifact payload operations. Uploads and downloads are exercised over
//! PostgreSQL in `tests/schema/authz_http.rs`; the refusals decided before the database run
//! through the real binary in `tests/contract.rs`.
use super::*;
use axum::http::HeaderName;

const SCOPE: &str = "0f0e0d0c-0b0a-4908-8706-050403020100";

#[test]
fn upload_query_takes_one_scope_and_one_bounded_ceiling() {
    let full = UploadQuery {
        scope: None,
        max_bytes: MAX_UPLOAD_BYTES,
    };
    assert_eq!(upload_query(Op::CreateArtifact, None), Ok(full));
    let both = format!("scope_id={SCOPE}&max_bytes=10");
    assert_eq!(
        upload_query(Op::CreateArtifact, Some(&both)),
        Ok(UploadQuery {
            scope: Some(SCOPE),
            max_bytes: 10
        })
    );
    assert_eq!(
        upload_query(Op::CreateArtifactRevision, Some("max_bytes=67108864")),
        Ok(UploadQuery {
            scope: None,
            max_bytes: MAX_UPLOAD_BYTES
        })
    );
    for (op, query) in [
        // A new revision's scope is its artifact's; a scope is refused.
        (Op::CreateArtifactRevision, format!("scope_id={SCOPE}")),
        (
            Op::CreateArtifact,
            format!("scope_id={SCOPE}&scope_id={SCOPE}"),
        ),
        (
            Op::CreateArtifact,
            "scope_id=0F0E0D0C-0B0A-4908-8706-050403020100".into(),
        ),
        (Op::CreateArtifact, "scope_id=".into()),
        (Op::CreateArtifact, "max_bytes=0".into()),
        (Op::CreateArtifact, "max_bytes=010".into()),
        (Op::CreateArtifact, "max_bytes=67108865".into()),
        (Op::CreateArtifact, "max_bytes=99999999999999999999".into()),
        (Op::CreateArtifact, "max_bytes=1&max_bytes=1".into()),
        (Op::CreateArtifact, "max_bytes=%31".into()),
        (Op::CreateArtifact, "max_bytes=+1".into()),
        (Op::CreateArtifact, "other=1".into()),
        (Op::CreateArtifact, "max_bytes".into()),
        (Op::CreateArtifact, String::new()),
    ] {
        assert_eq!(upload_query(op, Some(&query)), Err(INVALID), "{query}");
    }
}

fn headers(fields: &[(HeaderName, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in fields {
        map.append(name.clone(), HeaderValue::from_str(value).unwrap());
    }
    map
}

fn range(value: &str) -> Result<Option<ByteRange>, Problem> {
    byte_range(&headers(&[(header::RANGE, value)]))
}

#[test]
fn ranges_are_one_rfc_9110_byte_range() {
    use ByteRange::{From, Suffix};
    assert_eq!(byte_range(&HeaderMap::new()), Ok(None));
    for (value, expected) in [
        ("bytes=0-0", From(0, Some(0))),
        ("bytes=2-5", From(2, Some(5))),
        ("BYTES=2-", From(2, None)),
        ("bytes=-3", Suffix(3)),
        ("bytes=-0", Suffix(0)),
        // Beyond 64 bits saturates: unsatisfiable, not malformed.
        ("bytes=99999999999999999999-", From(u64::MAX, None)),
    ] {
        assert_eq!(range(value), Ok(Some(expected)), "{value}");
    }
    for value in [
        "bytes=0-1,4-5",
        "bytes=5-2",
        "bytes=-",
        "bytes=",
        "bytes=a-b",
        "bytes= 0-1",
        "bytes=0-1 ",
        "items=0-1",
        "bytes 0-1",
        "0-1",
    ] {
        assert_eq!(range(value), Err(RANGE), "{value}");
    }
    let repeated = headers(&[(header::RANGE, "bytes=0-1"), (header::RANGE, "bytes=0-1")]);
    assert_eq!(byte_range(&repeated), Err(RANGE));
    // No validator is issued, so an `If-Range` never matches: the whole content is sent.
    let conditional = headers(&[(header::RANGE, "bytes=0-1"), (header::IF_RANGE, "\"x\"")]);
    assert_eq!(byte_range(&conditional), Ok(None));
}

#[test]
fn ranges_resolve_within_the_content_or_not_at_all() {
    use ByteRange::{From, Suffix};
    for (range, total, expected) in [
        (From(0, None), 10, Some((0, 9))),
        (From(2, Some(5)), 10, Some((2, 5))),
        (From(2, Some(50)), 10, Some((2, 9))),
        (From(9, Some(9)), 10, Some((9, 9))),
        (From(10, None), 10, None),
        (From(u64::MAX, None), 10, None),
        (Suffix(3), 10, Some((7, 9))),
        (Suffix(30), 10, Some((0, 9))),
        (Suffix(0), 10, None),
        // An empty file satisfies no range.
        (From(0, Some(0)), 0, None),
        (From(0, None), 0, None),
        (Suffix(1), 0, None),
    ] {
        assert_eq!(range.resolve(total), expected, "{range:?} of {total}");
    }
}

#[test]
fn dispositions_encode_every_unsafe_byte() {
    assert_eq!(disposition(None), "attachment");
    assert_eq!(
        disposition(Some("report-v1.2.txt")),
        "attachment; filename*=UTF-8''report-v1.2.txt"
    );
    let hostile = disposition(Some("a\"; filename=x.html;\\é %"));
    assert_eq!(
        hostile,
        "attachment; filename*=UTF-8''a%22%3B%20filename%3Dx.html%3B%5C%C3%A9%20%25"
    );
    let value = hostile.to_str().unwrap();
    assert_eq!(value.matches(';').count(), 1);
    assert!(!value.contains('"') && !value.contains('\\'));
}

#[test]
fn metadata_is_one_closed_object() {
    assert!(metadata(b"{}"));
    assert!(metadata(b" { } "));
    for refused in [
        &b"{\"scope_id\":\"x\"}"[..],
        b"[]",
        b"null",
        b"",
        b"{",
        b"{}{}",
        b"\xff",
    ] {
        assert!(!metadata(refused), "{refused:?}");
    }
}

#[test]
fn revisions_serialize_without_internal_identifiers() {
    let revision = Revision {
        id: "a1".into(),
        artifact_id: "a0".into(),
        revision: 2,
        scope_id: SCOPE.into(),
        project_id: None,
        reservation_id: "CANARY-reservation".into(),
        size_bytes: 9_007_199_254_740_993,
        content_digest: vec![0xab; 32],
        media_type: "text/plain;charset=utf-8".into(),
        display_name: None,
        state: "active".into(),
        created_us: 1_763_370_000_000_001,
    };
    let body = revision_json(&revision).unwrap();
    assert_eq!(
        body,
        json!({
            "artifact_id": "a0",
            "revision_id": "a1",
            "revision": "2",
            "scope_kind": "personal",
            "scope_id": SCOPE,
            "project_id": null,
            "media_type": "text/plain;charset=utf-8",
            "size_bytes": "9007199254740993",
            "sha256": "ab".repeat(32),
            "display_name": null,
            "state": "active",
            "created_at": "2025-11-17T09:00:00.000001Z",
        })
    );
    assert!(!body.to_string().contains("CANARY"));
}

#[test]
fn upload_failures_map_to_adr_0007_categories() {
    use crate::multipart::Error as M;
    use artifact_fs::Error as E;
    for (error, expected) in [
        (E::Multipart(M::Truncated), BODY),
        (E::Multipart(M::DuplicatePart), BODY),
        (E::Rejected, BODY),
        (E::Body, BODY),
        (E::TooLarge, TOO_LARGE),
        (E::InProgress, IN_PROGRESS),
        (E::Io, INTERNAL),
        (E::Missing, INTERNAL),
        (E::Storage(runs::Error::OwnerLimit), QUOTA),
        (E::Storage(runs::Error::InstanceLimit), QUOTA),
        (E::Storage(runs::Error::LimitUnconfigured), PROVISIONING),
        (
            E::Storage(runs::Error::InstanceLimitUnconfigured),
            PROVISIONING,
        ),
        (E::Storage(runs::Error::Conflict), KEY_CONFLICT),
        (E::Storage(runs::Error::NotFound), NOT_FOUND),
        (E::Storage(runs::Error::Invalid), INVALID),
        (E::Storage(runs::Error::TransactionUnavailable), UNAVAILABLE),
    ] {
        assert_eq!(ingest_problem(error), expected);
    }
    for problem in [
        TOO_LARGE,
        RANGE,
        IN_PROGRESS,
        NOT_SERVABLE,
        QUOTA,
        UNSATISFIABLE,
    ] {
        let expected = match problem.code {
            "validation" => 400,
            "conflict" => 409,
            "range_not_satisfiable" => 416,
            "quota" => 429,
            other => panic!("unexpected code {other}"),
        };
        assert_eq!(problem.status.as_u16(), expected);
        assert!((1..=512).contains(&problem.detail.len()));
    }
}

#[test]
fn multipart_type_needs_one_valid_boundary() {
    let ok = headers(&[(header::CONTENT_TYPE, "multipart/form-data; boundary=x")]);
    assert_eq!(multipart_type(&ok), Ok("multipart/form-data; boundary=x"));
    for fields in [
        vec![],
        vec![(header::CONTENT_TYPE, "application/json")],
        vec![(header::CONTENT_TYPE, "multipart/form-data")],
        vec![(header::CONTENT_TYPE, "multipart/mixed; boundary=x")],
        vec![
            (header::CONTENT_TYPE, "multipart/form-data; boundary=x"),
            (header::CONTENT_TYPE, "multipart/form-data; boundary=x"),
        ],
    ] {
        assert_eq!(multipart_type(&headers(&fields)), Err(BODY), "{fields:?}");
    }
}
