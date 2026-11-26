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
    assert_eq!(served.len(), 48);
    for (path, _) in routes() {
        assert_eq!(
            crate::telemetry::metrics::RouteClass::of(path),
            crate::telemetry::metrics::RouteClass::V1
        );
    }
}

#[test]
fn every_write_and_only_a_write_needs_a_key_and_reads_take_no_body() {
    for (path, operations) in routes() {
        for (method, op) in operations {
            assert_eq!(
                op.reads(),
                method == Method::GET
                    || matches!(
                        op,
                        Op::PreviewConfiguration | Op::PreviewAdminRetentionDeadlines
                    ),
                "{}",
                op.id()
            );
            if method == Method::GET {
                assert!(!op.json(), "{}", op.id());
            }
            // The first path parameter is the third segment.
            assert_eq!(
                op.targeted(),
                path.split('/')
                    .nth(3)
                    .is_some_and(|v| v.starts_with('{') && v != "{preset_id}")
            );
            // An upload streams its own multipart body, and only an upload does.
            assert_eq!(op.uploads(), op.id().starts_with("createArtifact"));
            assert!(!(op.uploads() && op.json()));
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
        PROVISIONING,
    ];
    for problem in all {
        let expected = match problem.code {
            "validation" => 400,
            "unauthenticated" => 401,
            "policy" => 403,
            "not_found" => 404,
            "conflict" | "idempotency_conflict" => 409,
            "internal" => 500,
            "unavailable" | "provisioning" => 503,
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
                selection: Default::default(),
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
    let refused: [(Op, &[u8]); 22] = [
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
            br#"{"name":"A","defaults":{"model_config":{"model":[]}}}"#,
        ),
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

#[tokio::test]
async fn saturated_streams_refuse_immediately_and_leave_unary_capacity() {
    use crate::auth_config::tests::support;
    let dir = support::Dir::new();
    let document = support::document_v2(&dir, &crate::provider_http::fixture::Ca::new().pem());
    let path = dir.write("auth.json", document.to_string().as_bytes());
    let settings = crate::auth_config::load(std::path::Path::new(&path)).unwrap();
    let pool = PgPool::connect_lazy("postgres://localhost/unused").unwrap();
    let api = Arc::new(Api {
        browser: Arc::new(BrowserAuth::new(settings, pool.clone(), pool.clone())),
        native: None,
        origin: "https://app.example.test".into(),
        pool,
        artifacts: None,
        in_flight: Semaphore::new(MAX_IN_FLIGHT),
        streams: Arc::new(Semaphore::new(runs::SSE_MAX_IN_FLIGHT)),
    });
    let occupied = api.streams.clone().try_acquire_many_owned(128).unwrap();
    let call = async |op| {
        api.serve(&[(Method::GET, op)], Request::new(Body::empty()))
            .await
            .status()
    };
    assert_eq!(
        call(Op::StreamRunEvents).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(call(Op::GetRun).await, StatusCode::UNAUTHORIZED);
    drop(occupied);
    assert_eq!(call(Op::StreamRunEvents).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn raw_limits_cover_json_escapes_before_decoding() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (op, bound) in [
        (Op::CreateRun, 131072),
        (Op::PreviewConfiguration, 131072),
        (Op::CreateBranch, 65536),
        (Op::CreateConversation, 65536),
        (Op::UpdateProjectSettings, 65536),
    ] {
        let mut data = br#"{"escaped":"\u0061"}"#.to_vec();
        data.resize(bound, b' ');
        assert_eq!(
            read_body(op, &headers, Body::from(data.clone()))
                .await
                .unwrap()
                .len(),
            bound
        );
        data.push(b' ');
        assert_eq!(
            read_body(op, &headers, Body::from(data)).await.unwrap_err(),
            BODY
        );
    }
}

#[tokio::test]
async fn streamed_json_body_limit_counts_bytes_across_chunks() {
    use hyper::body::Frame;
    use std::{
        convert::Infallible,
        pin::Pin,
        task::{Context, Poll},
    };

    struct Chunks(std::array::IntoIter<Bytes, 2>);
    impl HttpBody for Chunks {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.0.next().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (op, limit) in [
        (Op::CreateConversation, MAX_BODY_BYTES),
        (Op::CreateRun, 131072),
    ] {
        for extra in [0, 1] {
            let chunks = [
                Bytes::from(vec![b' '; limit - 1]),
                Bytes::from(vec![b' '; 1 + extra]),
            ];
            let body = Body::from_stream(Body::new(Chunks(chunks.into_iter())).into_data_stream());
            assert_eq!(body.size_hint().lower(), 0);
            let size = read_body(op, &headers, body).await.map(|bytes| bytes.len());
            assert_eq!(size, if extra == 0 { Ok(limit) } else { Err(BODY) });
        }
    }
}

#[tokio::test]
async fn managed_routes_keep_request_values_out_of_logs_and_exported_spans() {
    use crate::{
        auth_config::tests::support,
        telemetry::{
            self, Format, Process, Verbosity, otlp,
            tests::{
                Capture, exchange,
                otlp::{Collector, finish},
            },
        },
    };
    let dir = support::Dir::new();
    let doc = support::document_v2(&dir, &crate::provider_http::fixture::Ca::new().pem());
    let settings = crate::auth_config::load(std::path::Path::new(
        &dir.write("auth.json", doc.to_string().as_bytes()),
    ))
    .unwrap();
    let pool = PgPool::connect_lazy("postgres://localhost/unused").unwrap();
    let api = router(
        Arc::new(BrowserAuth::new(settings, pool.clone(), pool.clone())),
        None,
        "https://app.example.test",
        pool,
        None,
    );
    let collector = Collector::accepting().await;
    let (tracer, exporter) = otlp::start(collector.destination(), Process::Api);
    let (capture, _guard) =
        Capture::install_traced(Format::Json, Verbosity::Debug, tracer.unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, telemetry::observe(api))
            .await
            .unwrap()
    });
    let id = "00000000-0000-0000-0000-000000001021";
    let paths = [
        "/v1/runs".to_owned(),
        format!("/v1/conversations/{id}/branches/{id}/effective-configuration"),
        "/v1/presets/CANARY-preset".into(),
    ];
    let body = r#"{"prompt":"CANARY-prompt","instructions":"CANARY-instruction"}"#;
    for path in paths {
        let method = if path.contains("presets") {
            "GET"
        } else {
            "POST"
        };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\ncontent-type: application/json\r\nidempotency-key: CANARY-key\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(exchange(address, request.as_bytes()).await, 401);
    }
    assert_eq!(capture.events("http.request.completed").len(), 3);
    capture.assert_absent(&[b"CANARY", id.as_bytes()]);
    finish(exporter).await;
    assert_eq!(collector.spans().len(), 3);
    collector.assert_absent(&[b"CANARY", id.as_bytes()]);
}

#[test]
fn quota_override_bodies_and_problem_extensions_are_validated_and_closed() {
    use crate::quotas::QuotaResourceKind as K;

    let (limit, exp, reason) = quotas::parse_set_override(
        K::UsageTokens,
        br#"{"hard_limit":"500000","expires_at":"2026-12-31T23:59:59.000000Z","reason":"cohort"}"#,
    )
    .unwrap();
    assert_eq!(limit, 500_000);
    assert_eq!(exp.as_deref(), Some("2026-12-31T23:59:59.000000Z"));
    assert_eq!(reason, "cohort");

    let (limit, exp, reason) = quotas::parse_set_override(
        K::StorageBytes,
        br#"{"hard_limit":"0","reason":"freeze uploads"}"#,
    )
    .unwrap();
    assert_eq!((limit, exp, reason.as_str()), (0, None, "freeze uploads"));

    // round_cap requires 1..=1000.
    assert_eq!(
        quotas::parse_set_override(K::RoundCap, br#"{"hard_limit":"1","reason":"min"}"#)
            .unwrap()
            .0,
        1
    );
    assert_eq!(
        quotas::parse_set_override(K::RoundCap, br#"{"hard_limit":"1000","reason":"max"}"#)
            .unwrap()
            .0,
        1000
    );
    for bad in [
        (K::RoundCap, br#"{"hard_limit":"0","reason":"low"}"#.as_slice()),
        (K::RoundCap, br#"{"hard_limit":"1001","reason":"high"}"#.as_slice()),
        (K::UsageTokens, br#"{"hard_limit":"01","reason":"leading zero"}"#.as_slice()),
        (
            K::UsageTokens,
            br#"{"hard_limit":"9223372036854775808","reason":"overflow"}"#.as_slice(),
        ),
        (K::UsageTokens, br#"{"hard_limit":10,"reason":"number"}"#.as_slice()),
        (
            K::UsageTokens,
            br#"{"hard_limit":"10","expires_at":"2026-12-31T23:59:59Z","reason":"bad ts"}"#.as_slice(),
        ),
        (
            K::UsageTokens,
            br#"{"hard_limit":"10","expires_at":"2026-12-31T23:59:59.000000+00:00","reason":"offset"}"#.as_slice(),
        ),
        (K::UsageTokens, br#"{"hard_limit":"10","reason":""}"#.as_slice()),
        (
            K::UsageTokens,
            br#"{"hard_limit":"10","reason":"ok","extra":1}"#.as_slice(),
        ),
        (
            K::UsageTokens,
            br#"{"hard_limit":"10","hard_limit":"20","reason":"dup"}"#.as_slice(),
        ),
    ] {
        assert_eq!(
            quotas::parse_set_override(bad.0, bad.1).unwrap_err().code,
            "validation"
        );
    }

    assert_eq!(
        quotas::parse_revoke_override(br#"{"reason":"reset"}"#).unwrap(),
        "reset"
    );
    for bad in [
        br#"{"reason":""}"#.as_slice(),
        br#"{"reason":"ok","extra":true}"#.as_slice(),
        br#"{}"#.as_slice(),
    ] {
        assert_eq!(
            quotas::parse_revoke_override(bad).unwrap_err().code,
            "validation"
        );
    }

    // Request key scoping isolates set vs revoke, scope_id, and resource_kind.
    let s1 = "0f0e0d0c-0b0a-4908-8706-050403020100";
    let k1 = request_key(Op::SetQuotaOverride, &format!("{s1}/usage_tokens"), "k");
    let k2 = request_key(Op::RevokeQuotaOverride, &format!("{s1}/usage_tokens"), "k");
    let k3 = request_key(Op::SetQuotaOverride, &format!("{s1}/storage_bytes"), "k");
    assert_ne!(k1, k2);
    assert_ne!(k1, k3);

    // Closed quota extension serializes only resource_kind and scope_kind.
    let p = quota_problem(
        StatusCode::TOO_MANY_REQUESTS,
        "quota",
        "The usage budget does not allow this request.",
        "usage_tokens",
        "personal",
    );
    assert_eq!(
        p.quota,
        Some(QuotaDetail {
            resource_kind: "usage_tokens",
            scope_kind: "personal",
        })
    );
}
