//! Pure helpers of the `/v1` routes. Request handling is tested through `crate::app` in
//! `src/tests.rs`, the problem shape against the contract in `tests/contract.rs`, and the
//! operations against PostgreSQL in `tests/schema/authz_http.rs`.
use super::*;
use crate::authz::{DenialReason, PolicyReason};
use std::collections::BTreeSet;

const CONTRACT: &str = include_str!("../../contracts/openapi/openmettle-v1.json");

/// The served routes are exactly the contract's implemented operations: the same path
/// templates, methods and `operationId`s, so telemetry records the contract's templates.
#[test]
fn routes_are_the_implemented_contract_operations() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let mut documented = BTreeSet::new();
    for (path, item) in contract["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            assert_eq!(operation["x-openmettle-implementation"], "implemented");
            let id = operation["operationId"].as_str().unwrap().to_owned();
            documented.insert((path.clone(), method.to_ascii_uppercase(), id));
        }
    }
    let mut served = BTreeSet::new();
    for (path, operations) in routes() {
        for (method, op) in operations {
            served.insert((path.to_owned(), method.to_string(), op.id().to_owned()));
        }
    }
    assert_eq!(served, documented);
    assert_eq!(served.len(), 15);
    for (path, _) in routes() {
        assert_eq!(
            crate::telemetry::metrics::RouteClass::of(path),
            crate::telemetry::metrics::RouteClass::V1
        );
    }
}

#[test]
fn every_write_and_only_a_write_needs_a_key_and_reads_take_no_body() {
    for (_, operations) in routes() {
        for (method, op) in operations {
            assert_eq!(op.reads(), method == Method::GET, "{}", op.id());
            if op.reads() {
                assert!(!op.json(), "{}", op.id());
            }
            // Every path parameter is the third segment.
            assert_eq!(
                op.targeted(),
                op.id() != "listCapabilities" && op.id() != "createProject"
            );
        }
    }
}

/// The mapping equals ADR 0007 as `DenialReason` defines it, and no internal reason reaches
/// the detail.
#[test]
fn denials_and_store_errors_map_to_adr_0007_categories() {
    for reason in [
        DenialReason::Unauthenticated,
        DenialReason::InactivePrincipal,
        DenialReason::NotFound,
        DenialReason::Policy(PolicyReason::LastProjectOwner),
        DenialReason::Policy(PolicyReason::NotShareManager),
    ] {
        let problem = denied(reason);
        assert_eq!(
            (problem.status.as_u16(), problem.code),
            (reason.status(), reason.code())
        );
        assert!(!problem.detail.contains("owner") && !problem.detail.contains("share"));
    }
    let cases = [
        (StoreError::InvalidInput("name"), INVALID),
        (StoreError::Conflict(store::KEY_REUSED), KEY_CONFLICT),
        (StoreError::Conflict("project is archived"), CONFLICT),
        (
            StoreError::Conflict("target is already in the requested state"),
            CONFLICT,
        ),
        (StoreError::NotFound, NOT_FOUND),
        (
            StoreError::Database(sqlx::Error::Protocol("CANARY detail".into())),
            UNAVAILABLE,
        ),
        (StoreError::Denied(DenialReason::NotFound), NOT_FOUND),
    ];
    for (error, expected) in cases {
        assert_eq!(store_problem(error), expected);
    }
    assert_eq!(store_problem(projects::ARCHIVED), CONFLICT);
    use sessions::Error::*;
    for (error, expected) in [
        (Rejected, UNAUTHENTICATED),
        (Timeout, TIMEOUT),
        (Database, UNAVAILABLE),
        (Capacity, UNAVAILABLE),
        (Random, UNAVAILABLE),
        (Configuration, UNAVAILABLE),
    ] {
        assert_eq!(session_problem(error), expected);
    }
}

/// Every fixed problem matches the contract's code/status binding and bounds.
#[test]
fn problems_are_fixed_bounded_and_versioned() {
    let all = [
        INVALID,
        HEAD_TOO_LARGE,
        IDENTIFIER,
        KEY_REQUIRED,
        BODY,
        UNAUTHENTICATED,
        POLICY,
        NOT_FOUND,
        CONFLICT,
        KEY_CONFLICT,
        INTERNAL,
        UNAVAILABLE,
        TIMEOUT,
    ];
    for problem in all {
        let expected = match problem.code {
            "validation" => 400,
            "unauthenticated" => 401,
            "policy" => 403,
            "not_found" => 404,
            "conflict" | "idempotency_conflict" => 409,
            "internal" => 500,
            "unavailable" => 503,
            "timeout" => 504,
            other => panic!("unexpected code {other}"),
        };
        assert_eq!(problem.status.as_u16(), expected, "{}", problem.code);
        assert!((1..=512).contains(&problem.detail.len()));
        let response = problem.response(RequestId::generate());
        let headers = response.headers();
        assert_eq!(headers[&VERSION_HEADER], API_VERSION);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    }
    // Without a request ID, a problem still names a valid UUID.
    let response = NOT_FOUND.response(None);
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let no_content = no_content();
    assert_eq!(no_content.headers()[&VERSION_HEADER], API_VERSION);
    assert!(!no_content.headers().contains_key(header::CONTENT_TYPE));
}

#[test]
fn json_media_type_allows_only_utf8_charset() {
    for ok in [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        "application/json;charset=UTF-8",
        " application/json ",
    ] {
        assert!(json_media_type(ok.as_bytes()), "{ok}");
    }
    for bad in [
        "",
        "text/plain",
        "application/json-patch+json",
        "application/problem+json",
        "application/json; charset=latin1",
        "application/json; charset=utf-8; x=y",
        "application/json, text/plain",
        "application/x-www-form-urlencoded",
    ] {
        assert!(!json_media_type(bad.as_bytes()), "{bad}");
    }
}

#[test]
fn idempotency_keys_are_one_bounded_visible_ascii_field() {
    let headers = |values: &[&[u8]]| {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(IDEMPOTENCY_KEY, HeaderValue::from_bytes(value).unwrap());
        }
        headers
    };
    let longest = "k".repeat(128);
    for ok in ["k", "retry-7f3a:create-run", "!~", longest.as_str()] {
        assert_eq!(idempotency_key(&headers(&[ok.as_bytes()])), Ok(ok));
    }
    let too_long = "k".repeat(129);
    for bad in [
        &[][..],
        &[b"has space".as_slice()][..],
        &[b"tab\tkey".as_slice()][..],
        &[too_long.as_bytes()][..],
        &["cl\u{e9}".as_bytes()][..],
        &[b"a".as_slice(), b"a".as_slice()][..],
        &[b"".as_slice()][..],
    ] {
        assert_eq!(idempotency_key(&headers(bad)), Err(KEY_REQUIRED), "{bad:?}");
    }
}

/// The derived key is fixed-length hex, deterministic, and distinct per operation, target and
/// client key, so a key reused elsewhere is a new request rather than a replay or conflict.
#[test]
fn request_keys_scope_a_client_key_to_its_operation_and_target() {
    let a = "0f0e0d0c-0b0a-4908-8706-050403020100";
    let b = "1f0e0d0c-0b0a-4908-8706-050403020100";
    let key = request_key(Op::DeleteProject, a, "k");
    assert_eq!(key.len(), 64);
    assert!(
        key.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    );
    assert_eq!(key, request_key(Op::DeleteProject, a, "k"));
    let others = [
        request_key(Op::ArchiveProject, a, "k"),
        request_key(Op::DeleteProject, b, "k"),
        request_key(Op::DeleteProject, a, "k2"),
        request_key(Op::ShareResource(ResourceKind::Conversation), a, "k"),
        request_key(Op::ShareResource(ResourceKind::Artifact), a, "k"),
        // Field boundaries are length-prefixed, so shifting bytes between fields differs.
        request_key(Op::DeleteProject, "", &format!("{a}k")),
    ];
    for other in others {
        assert_ne!(key, other);
    }
    // The client key never appears in the derived key.
    assert!(!request_key(Op::CreateProject, "", "CANARY").contains("CANARY"));
}

#[test]
fn timestamps_have_six_fractional_digits_in_utc() {
    assert_eq!(timestamp(0).unwrap(), "1970-01-01T00:00:00.000000Z");
    assert_eq!(
        timestamp(1_795_000_000_123_456).unwrap(),
        "2026-11-18T11:06:40.123456Z"
    );
    assert_eq!(timestamp(i64::MAX), Err(INTERNAL));
}

#[test]
fn bodies_are_closed_json_objects_decoded_before_the_database() {
    let user = "0f0e0d0c-0b0a-4908-8706-050403020100";
    let decoded = decode(Op::CreateProject, br#"{"name":"Alpha"}"#).unwrap();
    assert_eq!(
        decoded,
        (
            Input::Settings {
                name: "Alpha".into(),
                instructions: String::new(),
                defaults: json!({}),
            },
            None
        )
    );
    let decoded = decode(
        Op::SetProjectMemberRole,
        format!(r#"{{"grantee":{{"kind":"user","grantee_id":"{user}"}},"role":"editor","reason":"why"}}"#)
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        decoded,
        (
            Input::Member {
                grantee: Grantee::User(user.into()),
                role: Some(ProjectRole::Editor),
            },
            Some("why".into())
        )
    );
    let decoded = decode(
        Op::ShareResource(ResourceKind::Artifact),
        br#"{"grantee":{"kind":"project"},"access":"write"}"#,
    )
    .unwrap();
    assert_eq!(
        decoded.0,
        Input::Share {
            grantee: Grantee::Project,
            access: Some(ResourceAccess::Write),
        }
    );
    let revoke = decode(
        Op::RevokeResourceShare(ResourceKind::Conversation),
        br#"{"grantee":{"kind":"oidc_group","grantee_id":"team"}}"#,
    )
    .unwrap();
    assert_eq!(
        revoke.0,
        Input::Share {
            grantee: Grantee::OidcGroup("team".into()),
            access: None,
        }
    );
    assert_eq!(decode(Op::GetProject, b"").unwrap(), (Input::Empty, None));

    let long_reason = format!(r#"{{"name":"A","reason":"{}"}}"#, "r".repeat(513));
    let refused: [(Op, &[u8]); 21] = [
        (Op::CreateProject, b""),
        (Op::CreateProject, b"[\"Alpha\"]"),
        (Op::CreateProject, b"null"),
        (Op::CreateProject, br#"{"name":"A","owner":"x"}"#),
        (Op::CreateProject, br#"{"name":"A","name":"B"}"#),
        (Op::CreateProject, br#"{"name":" A"}"#),
        (Op::CreateProject, br#"{"name":"A","defaults":[]}"#),
        (Op::CreateProject, br#"{"name":"A","defaults":null}"#),
        (
            Op::CreateProject,
            br#"{"name":"A","defaults":{"folder_id":"x"}}"#,
        ),
        (
            Op::CreateProject,
            br#"{"name":"A","defaults":{"collection_ids":[]}}"#,
        ),
        (Op::CreateProject, br#"{"name":"A","reason":""}"#),
        (Op::CreateProject, long_reason.as_bytes()),
        // Every setting is replaced, so a partial update is refused.
        (
            Op::UpdateProjectSettings,
            br#"{"name":"A","instructions":""}"#,
        ),
        (
            Op::SetProjectMemberRole,
            br#"{"grantee":{"kind":"project"},"role":"viewer"}"#,
        ),
        (
            Op::SetProjectMemberRole,
            br#"{"grantee":{"kind":"user","grantee_id":"u"},"role":"Owner"}"#,
        ),
        (
            Op::SetProjectMemberRole,
            br#"{"grantee":{"kind":"user","grantee_id":"u"},"role":"admin"}"#,
        ),
        (
            Op::RevokeProjectMember,
            br#"{"grantee":{"kind":"user","grantee_id":"u"},"role":"viewer"}"#,
        ),
        (
            Op::ShareResource(ResourceKind::Conversation),
            br#"{"grantee":{"kind":"project","grantee_id":"x"},"access":"read"}"#,
        ),
        (
            Op::ShareResource(ResourceKind::Conversation),
            br#"{"grantee":{"kind":"user"},"access":"read"}"#,
        ),
        (
            Op::ShareResource(ResourceKind::Conversation),
            br#"{"grantee":{"kind":"team","grantee_id":"x"},"access":"read"}"#,
        ),
        (
            Op::ShareResource(ResourceKind::Conversation),
            br#"{"grantee":{"kind":"user","grantee_id":"u","x":1},"access":"read"}"#,
        ),
    ];
    for (op, body) in refused {
        let error = decode(op, body).unwrap_err();
        assert_eq!(
            error.code,
            "validation",
            "{}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn grantees_serialize_with_their_kind_and_identifier() {
    assert_eq!(
        grantee_json(&Grantee::LocalGroup("g".into())),
        json!({"kind": "local_group", "grantee_id": "g"})
    );
    assert_eq!(grantee_json(&Grantee::Project), json!({"kind": "project"}));
}

/// Artifacts are read with `Read`; `Download` is the same decision for every caller.
#[test]
fn artifact_read_and_download_are_one_decision() {
    use crate::authz::{Action, Principal, Resource, Scope, authorize_resource};
    let owner = Principal {
        user_id: "u".into(),
        personal_scope_id: "s".into(),
        account_active: true,
        approval_active: true,
        provider_active: true,
        ..Principal::default()
    };
    let other = Principal {
        user_id: "o".into(),
        personal_scope_id: "t".into(),
        ..owner.clone()
    };
    let artifact = Resource {
        kind: ResourceKind::Artifact,
        id: "a".into(),
        creator_user_id: "u".into(),
        scope: Scope::Personal {
            scope_id: "s".into(),
            owner_user_id: "u".into(),
        },
        shares: Vec::new(),
    };
    for principal in [&owner, &other] {
        assert_eq!(
            authorize_resource(principal, &artifact, Action::Read),
            authorize_resource(principal, &artifact, Action::Download)
        );
    }
}
