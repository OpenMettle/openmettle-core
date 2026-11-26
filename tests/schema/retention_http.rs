//! ADR 0041 PR3: authenticated `/v1` artifact disassociation & pre-expiry restore routes,
//! audited `account_admin` retention policy / deadline preview & apply / restore-gate health
//! routes, and `/v1` `503 unavailable` gating while `restore_reconciliation_gate.open = false`,
//! tested end-to-end against the real `openmettle-api` binary and PostgreSQL 18.
use super::*;
use crate::{auth_config_support::Dir, ca::Ca, durable::retention::assert_chain};
use openmettle_core::restore;
use std::path::PathBuf;

const CANARY_FILENAME: &str = "CANARY-pr3-private-filename.txt";
const CANARY_CONTENT: &str = "CANARY-pr3-private-payload-bytes";

/// Starts a full mounted `openmettle-api` binary with artifacts directory, catalog, cursor keys,
/// admission limits, and debug stderr logging so redaction canaries can be verified.
fn start_full_api(db: &TestDb) -> (Api, PathBuf) {
    let dir = Dir::new();
    fs::create_dir(dir.path("artifacts")).unwrap();
    let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
    doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    let mut catalog: Value =
        serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    catalog["models"]["a"]["pin"]["provider"] = "synthetic-sglang".into();
    catalog["models"]["a"]["prompt_bound"] = json!({
        "fixed_tokens": 4,
        "tokens_per_turn": 4,
        "tokens_per_part": 2,
        "tokens_per_byte": 1,
        "tokens_per_attachment": 10
    });
    doc["catalog_file"] = json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
    doc["admission_limits"] = json!({
        "live_per_actor": 4,
        "live_per_scope": 8,
        "queued_in_instance": 32,
        "queue_timeout_seconds": 300,
        "round_cap": 10
    });
    Api::configured_logged(db, dir, doc, 4)
}

async fn seed_token_quotas(owner: &mut PgConnection) {
    for scope_kind in ["instance", "personal", "project"] {
        sqlx::query(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ($1, 'usage_tokens', 100000)
             ON CONFLICT (scope_kind, resource_kind) DO NOTHING",
        )
        .bind(scope_kind)
        .execute(&mut *owner)
        .await
        .unwrap();
    }
}

async fn assert_storage_reconciled(db: &TestDb) {
    let ok: bool = sqlx::query_scalar(
        "SELECT (SELECT (active_bytes, retained_bytes, reserved_bytes) FROM openmettle.storage_instance)
              = (SELECT (coalesce(sum(active_bytes), 0)::bigint,
                         coalesce(sum(retained_bytes), 0)::bigint,
                         coalesce(sum(reserved_bytes), 0)::bigint)
                   FROM openmettle.storage_accounts)",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap();
    assert!(ok, "storage_instance totals disagree with storage_accounts");
}

fn assert_no_canary_in_logs(log_path: &Path, canaries: &[&str]) {
    let logs = fs::read_to_string(log_path).unwrap_or_default();
    for canary in canaries {
        assert!(
            !logs.contains(canary),
            "API stderr logs leaked canary {canary:?}"
        );
    }
}

async fn assert_no_canary_in_audit_or_journal(db: &TestDb, canaries: &[&str]) {
    let mut adm = db.admin().await;
    let audit_rows: Vec<String> = sqlx::query_scalar(
        "SELECT concat_ws(' ', action, target_kind, target_id, reason, details::text)
           FROM openmettle.authorization_audit",
    )
    .fetch_all(&mut adm)
    .await
    .unwrap();
    let journal_rows: Vec<String> =
        sqlx::query_scalar("SELECT j::text FROM openmettle.deletion_journal j")
            .fetch_all(&mut adm)
            .await
            .unwrap();
    for canary in canaries {
        for row in audit_rows.iter().chain(journal_rows.iter()) {
            assert!(
                !row.contains(canary),
                "audit or deletion_journal leaked canary {canary:?}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn artifact_disassociation_and_pre_expiry_restore_routes_enforce_authz_idempotency_and_deadlines()
 {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    limits(&db, Some(GIB), Some(GIB)).await;
    seed_token_quotas(&mut owner).await;
    sqlx::query(
        "UPDATE openmettle.retention_policy
            SET min_grace_seconds = 0, max_grace_seconds = 86400, grace_seconds = 3600
          WHERE id",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let (api, log_path) = start_full_api(&db);
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let reader = account(&mut owner, PROVIDER, true, FUTURE).await;
    let viewer = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (a_b, a_n) = (browser(&db, &alice, 1).await, native(&db, &alice, 2).await);
    let (b_n, r_n, v_n) = (
        native(&db, &bob, 3).await,
        native(&db, &reader, 4).await,
        native(&db, &viewer, 5).await,
    );
    let (alice_b, alice_n) = (As::Browser(&a_b), As::Native(&a_n));
    let (bob_n, reader_n, viewer_n) = (As::Native(&b_n), As::Native(&r_n), As::Native(&v_n));
    let personal = personal_of(&db, &alice).await;

    // Upload a personal artifact with two revisions carrying a redaction canary filename & content.
    let body1 = form(
        "pr3-a",
        &[
            file_part(Some(CANARY_FILENAME), "text/plain", CANARY_CONTENT),
            metadata_part("{}"),
        ],
        true,
    );
    let rev1 = success(api.upload(alice_b, "/v1/artifacts", "up-r1", &body1), 201);
    assert!(validate_openapi_schema(
        "#/components/schemas/ArtifactRevision",
        &rev1
    ));
    let decoded_r1 = consumer::decode_revision(&rev1).unwrap();
    assert_eq!(decoded_r1.state, consumer::RevisionState::Active);
    assert_eq!(decoded_r1.retained_at, None);
    assert_eq!(decoded_r1.purge_after, None);
    let art_id = decoded_r1.artifact_id.clone();
    let r1_id = decoded_r1.revision_id.clone();

    let body2 = form(
        "pr3-b",
        &[
            file_part(Some("second.txt"), "text/plain", "second-payload"),
            metadata_part("{}"),
        ],
        true,
    );
    let rev2 = success(
        api.upload(
            alice_n,
            &format!("/v1/artifacts/{art_id}/revisions"),
            "up-r2",
            &body2,
        ),
        201,
    );
    let r2_id = rev2["revision_id"].as_str().unwrap().to_owned();
    let total_bytes = (CANARY_CONTENT.len() + "second-payload".len()) as i64;
    assert_eq!(charged(&db, &personal).await, (total_bytes, 0, 0));

    // Share personal artifact read-only with `reader`.
    success(
        api.call(
            alice_b,
            "PUT",
            &format!("/v1/artifacts/{art_id}/shares"),
            Some("share-r"),
            Some(&shared("user", Some(&reader.user), "read")),
        ),
        200,
    );

    // Concealment & authorization: outsider gets 404, read-only share gets 403.
    let r1_path = format!("/v1/artifacts/{art_id}/revisions/{r1_id}");
    let r1_restore = format!("{r1_path}/restore");
    let r1_content = format!("{r1_path}/content");
    refused(
        api.call(
            bob_n,
            "DELETE",
            &format!("/v1/artifacts/{art_id}"),
            Some("b1"),
            None,
        ),
        404,
        "not_found",
    );
    refused(
        api.call(bob_n, "DELETE", &r1_path, Some("b2"), None),
        404,
        "not_found",
    );
    refused(
        api.call(bob_n, "POST", &r1_restore, Some("b3"), None),
        404,
        "not_found",
    );
    refused(
        api.call(
            reader_n,
            "DELETE",
            &format!("/v1/artifacts/{art_id}"),
            Some("r1"),
            None,
        ),
        403,
        "policy",
    );
    refused(
        api.call(reader_n, "DELETE", &r1_path, Some("r2"), None),
        403,
        "policy",
    );
    refused(
        api.call(reader_n, "POST", &r1_restore, Some("r3"), None),
        403,
        "policy",
    );

    // Single-revision disassociation transitions active -> retained, stamps retained_at/purge_after,
    // keeps bytes charged, immediately blocks downloads and new run attachments with 409 conflict.
    let retained = success(
        api.call(alice_b, "DELETE", &r1_path, Some("del-r1"), None),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/ArtifactRevision",
        &retained
    ));
    let dec_ret = consumer::decode_revision(&retained).unwrap();
    assert_eq!(dec_ret.state, consumer::RevisionState::Retained);
    assert!(dec_ret.retained_at.is_some());
    assert!(dec_ret.purge_after.is_some());
    assert_eq!(
        charged(&db, &personal).await,
        (
            "second-payload".len() as i64,
            CANARY_CONTENT.len() as i64,
            0
        )
    );
    // Exact retry on the other channel returns 200 with identical timestamps.
    let replayed = success(
        api.call(alice_n, "DELETE", &r1_path, Some("del-r1"), None),
        200,
    );
    assert_eq!(replayed["retained_at"], retained["retained_at"]);
    assert_eq!(replayed["purge_after"], retained["purge_after"]);
    // Non-replayed DELETE on already retained revision stays idempotent without altering deadline.
    let already_ret = success(
        api.call(alice_b, "DELETE", &r1_path, Some("del-r1-again"), None),
        200,
    );
    assert_eq!(already_ret["purge_after"], retained["purge_after"]);
    // Download of retained revision fails with 409 conflict.
    let (dl_status, _, _) = api.download(alice_b, "GET", &r1_content, None);
    assert_eq!(dl_status, 409);

    // POST /v1/runs attaching a visible retained revision fails with 409 conflict (whereas an
    // unknown/unshared revision stays concealed as 404 not_found).
    let conv = success(
        api.call(
            alice_b,
            "POST",
            "/v1/conversations",
            Some("conv-ret"),
            Some(&json!({})),
        ),
        201,
    );
    let attach_run = |rev_id: &str, msg_id: &str| {
        json!({
            "conversation_id": conv["conversation_id"],
            "branch_id": conv["branch_id"],
            "proposal": {
                "expected_head_message_id": null,
                "turn": {
                    "mode": "append",
                    "input_message_id": msg_id,
                    "parts": [{"attachment": rev_id}]
                },
                "selection": {
                    "model": "a",
                    "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                },
                "requested_rounds": 1
            }
        })
    };
    refused(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("run-retained"),
            Some(&attach_run(&r1_id, "00000000-0000-4000-8000-00000000a101")),
        ),
        409,
        "conflict",
    );
    refused(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("run-unknown"),
            Some(&attach_run(
                "00000000-0000-4000-8000-00000000dead",
                "00000000-0000-4000-8000-00000000a102",
            )),
        ),
        404,
        "not_found",
    );

    // Revoke `reader`'s share before pre-expiry restore; restore returns r1 to active, restores
    // downloadability, shifts retained -> active bytes, and does NOT reinstate the revoked share.
    success(
        api.call(
            alice_b,
            "POST",
            &format!("/v1/artifacts/{art_id}/shares/revoke"),
            Some("unshare-r"),
            Some(&grantee("user", Some(&reader.user))),
        ),
        204,
    );
    let restored = success(
        api.call(alice_b, "POST", &r1_restore, Some("rest-r1"), None),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/ArtifactRevision",
        &restored
    ));
    let dec_rest = consumer::decode_revision(&restored).unwrap();
    assert_eq!(dec_rest.state, consumer::RevisionState::Active);
    assert_eq!(dec_rest.retained_at, None);
    assert_eq!(dec_rest.purge_after, None);
    assert_eq!(charged(&db, &personal).await, (total_bytes, 0, 0));
    let (dl_status, _, dl_body) = api.download(alice_n, "GET", &r1_content, None);
    assert_eq!((dl_status, dl_body.as_str()), (200, CANARY_CONTENT));
    refused(
        api.call(reader_n, "GET", &r1_path, None, None),
        404,
        "not_found",
    );
    // Exact retry of restore succeeds; non-replayed restore on already-active returns 409 conflict.
    let rest_replay = success(
        api.call(alice_n, "POST", &r1_restore, Some("rest-r1"), None),
        200,
    );
    assert_eq!(rest_replay["state"], "active");
    refused(
        api.call(alice_b, "POST", &r1_restore, Some("rest-r1-new"), None),
        409,
        "conflict",
    );

    // Whole-artifact DELETE disassociates both active revisions, returns 204, and replays cleanly.
    success(
        api.call(
            alice_b,
            "DELETE",
            &format!("/v1/artifacts/{art_id}"),
            Some("del-art"),
            None,
        ),
        204,
    );
    success(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{art_id}"),
            Some("del-art"),
            None,
        ),
        204,
    );
    assert_eq!(charged(&db, &personal).await, (0, total_bytes, 0));

    // Expire r2's deadline -> pre-expiry restore returns 409 conflict.
    let r2_path = format!("/v1/artifacts/{art_id}/revisions/{r2_id}");
    let r2_restore = format!("{r2_path}/restore");
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
            SET retained_at = clock_timestamp() - interval '10 seconds',
                purge_after = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&r2_id)
    .execute(&mut owner)
    .await
    .unwrap();
    refused(
        api.call(alice_b, "POST", &r2_restore, Some("rest-r2-exp"), None),
        409,
        "conflict",
    );

    // Claim and confirm purge of r2 -> non-replayed DELETE and restore both return 409 conflict.
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::begin_purge(&mut tx, &personal, &r2_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    refused(
        api.call(alice_b, "DELETE", &r2_path, Some("del-r2-purging"), None),
        409,
        "conflict",
    );
    refused(
        api.call(alice_b, "POST", &r2_restore, Some("rest-r2-purging"), None),
        409,
        "conflict",
    );
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::confirm_purge(&mut tx, &personal, &r2_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    refused(
        api.call(alice_b, "DELETE", &r2_path, Some("del-r2-purged"), None),
        409,
        "conflict",
    );
    refused(
        api.call(alice_b, "POST", &r2_restore, Some("rest-r2-purged"), None),
        409,
        "conflict",
    );

    // Project scope: viewer gets 403, archived project refuses delete & restore with 409, deleted
    // project conceals with 404.
    let proj = success(
        api.call(
            alice_b,
            "POST",
            "/v1/projects",
            Some("pr3-proj"),
            Some(&json!({"name": "Retention Project"})),
        ),
        201,
    );
    let proj_id = proj["project_id"].as_str().unwrap().to_owned();
    let proj_scope = proj["scope_id"].as_str().unwrap().to_owned();
    success(
        api.call(
            alice_b,
            "PUT",
            &format!("/v1/projects/{proj_id}/members"),
            Some("add-viewer"),
            Some(&member(("user", &viewer.user), "viewer")),
        ),
        200,
    );
    let p_rev = success(
        api.upload(
            alice_b,
            &format!("/v1/artifacts?scope_id={proj_scope}"),
            "up-proj",
            &body2,
        ),
        201,
    );
    let p_art = p_rev["artifact_id"].as_str().unwrap().to_owned();
    let p_rev_id = p_rev["revision_id"].as_str().unwrap().to_owned();
    success(
        api.call(
            alice_b,
            "PUT",
            &format!("/v1/artifacts/{p_art}/shares"),
            Some("share-proj"),
            Some(&shared("project", None, "read")),
        ),
        200,
    );
    refused(
        api.call(
            viewer_n,
            "DELETE",
            &format!("/v1/artifacts/{p_art}/revisions/{p_rev_id}"),
            Some("v-del"),
            None,
        ),
        403,
        "policy",
    );
    success(
        api.call(
            alice_b,
            "POST",
            &format!("/v1/projects/{proj_id}/archive"),
            Some("arch"),
            None,
        ),
        200,
    );
    refused(
        api.call(
            alice_b,
            "DELETE",
            &format!("/v1/artifacts/{p_art}/revisions/{p_rev_id}"),
            Some("arch-del"),
            None,
        ),
        409,
        "conflict",
    );
    success(
        api.call(
            alice_b,
            "DELETE",
            &format!("/v1/projects/{proj_id}"),
            Some("del-proj"),
            None,
        ),
        204,
    );
    refused(
        api.call(
            alice_b,
            "DELETE",
            &format!("/v1/artifacts/{p_art}/revisions/{p_rev_id}"),
            Some("gone-del"),
            None,
        ),
        404,
        "not_found",
    );

    assert_chain(&db).await;
    assert_storage_reconciled(&db).await;
    drop(api);
    assert_no_canary_in_logs(&log_path, &[CANARY_FILENAME, CANARY_CONTENT]);
    assert_no_canary_in_audit_or_journal(&db, &[CANARY_FILENAME, CANARY_CONTENT]).await;
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn admin_retention_status_policy_and_deadlines_routes_enforce_authz_bounds_idempotency_and_privacy()
 {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    limits(&db, Some(GIB), Some(GIB)).await;

    let (api, log_path) = start_full_api(&db);
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let disabled_admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &disabled_admin).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;

    let admin_tok = native(&db, &admin, 1).await;
    let admin_cookie = browser(&db, &admin, 2).await;
    let disabled_tok = native(&db, &disabled_admin, 3).await;
    let alice_tok = native(&db, &alice, 4).await;
    let (admin_n, admin_b) = (As::Native(&admin_tok), As::Browser(&admin_cookie));
    let (disabled_n, alice_n) = (As::Native(&disabled_tok), As::Native(&alice_tok));

    sqlx::query("UPDATE openmettle.users SET disabled_at = clock_timestamp() WHERE id = $1::uuid")
        .bind(&disabled_admin.user)
        .execute(&mut owner)
        .await
        .unwrap();

    // Authorization: non-admin gets 403 policy; disabled admin gets 401 unauthenticated.
    for (who, expected_status, expected_code) in [
        (alice_n, 403, "policy"),
        (disabled_n, 401, "unauthenticated"),
    ] {
        refused(
            api.call(who, "GET", "/v1/admin/retention/status", None, None),
            expected_status,
            expected_code,
        );
        refused(
            api.call(
                who,
                "PUT",
                "/v1/admin/retention/policy",
                Some("k-pol"),
                Some(&json!({"grace_seconds": 2_592_000, "reason": "test"})),
            ),
            expected_status,
            expected_code,
        );
        refused(
            api.call(
                who,
                "POST",
                "/v1/admin/retention/deadlines/preview",
                None,
                Some(&json!({"target_grace_seconds": 2_592_000})),
            ),
            expected_status,
            expected_code,
        );
        refused(
            api.call(
                who,
                "POST",
                "/v1/admin/retention/deadlines/apply",
                Some("k-app"),
                Some(&json!({
                    "expected_policy_revision": "1",
                    "target_grace_seconds": 2_592_000,
                    "reason": "test"
                })),
            ),
            expected_status,
            expected_code,
        );
    }

    // Read status: decodes with consumer and OpenAPI schema.
    let status = success(
        api.call(admin_n, "GET", "/v1/admin/retention/status", None, None),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/AdminRetentionStatus",
        &status
    ));
    let dec_status = consumer::decode_admin_retention_status(&status).unwrap();
    assert_eq!(dec_status.policy.revision, 1);
    assert_eq!(dec_status.policy.grace_seconds, 2_592_000);
    assert!(dec_status.restore_gate.open);
    assert_eq!(dec_status.restore_gate.snapshot_journal_seq, None);
    assert_eq!(dec_status.restore_gate.required_journal_seq, None);
    assert!(dec_status.restore_gate.coverage_complete);
    assert_eq!(dec_status.deletion_journal.journal_seq, 0);

    // Default deployment bounds refuse 3600 with 400 validation.
    refused(
        api.call(
            admin_n,
            "PUT",
            "/v1/admin/retention/policy",
            Some("oob"),
            Some(&json!({"grace_seconds": 3600, "reason": "outside bounds"})),
        ),
        400,
        "validation",
    );

    // Widen deployment bounds via owner and update policy via PUT /v1/admin/retention/policy.
    sqlx::query(
        "UPDATE openmettle.retention_policy
            SET min_grace_seconds = 0, max_grace_seconds = 31536000
          WHERE id",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let updated = success(
        api.call(
            admin_b,
            "PUT",
            "/v1/admin/retention/policy",
            Some("pol-3600"),
            Some(&json!({"grace_seconds": 3600, "reason": "one hour grace"})),
        ),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/RetentionPolicy",
        &updated
    ));
    let dec_pol = consumer::decode_retention_policy(&updated).unwrap();
    assert_eq!(dec_pol.grace_seconds, 3600);
    assert_eq!(dec_pol.min_grace_seconds, 0);
    assert_eq!(dec_pol.max_grace_seconds, 31_536_000);
    // Exact retry replays; reused key with different params returns 409 idempotency_conflict.
    let replayed_pol = success(
        api.call(
            admin_n,
            "PUT",
            "/v1/admin/retention/policy",
            Some("pol-3600"),
            Some(&json!({"grace_seconds": 3600, "reason": "one hour grace"})),
        ),
        200,
    );
    assert_eq!(replayed_pol, updated);
    refused(
        api.call(
            admin_n,
            "PUT",
            "/v1/admin/retention/policy",
            Some("pol-3600"),
            Some(&json!({"grace_seconds": 120, "reason": "one hour grace"})),
        ),
        409,
        "idempotency_conflict",
    );

    // Upload and retain two private revisions in two distinct scopes with canary metadata.
    let personal_scope = personal_of(&db, &alice).await;
    let proj = success(
        api.call(
            alice_n,
            "POST",
            "/v1/projects",
            Some("p-ret"),
            Some(&json!({"name": "Scoped Retention"})),
        ),
        201,
    );
    let proj_scope = proj["scope_id"].as_str().unwrap().to_owned();
    let payload_p = "personal-retained-payload";
    let payload_proj = CANARY_CONTENT;
    let body_p = form(
        "b-p",
        &[
            file_part(Some("personal.txt"), "text/plain", payload_p),
            metadata_part("{}"),
        ],
        true,
    );
    let body_proj = form(
        "b-proj",
        &[
            file_part(Some(CANARY_FILENAME), "text/plain", payload_proj),
            metadata_part("{}"),
        ],
        true,
    );
    let r_p = success(api.upload(alice_n, "/v1/artifacts", "up-p", &body_p), 201);
    let r_proj = success(
        api.upload(
            alice_n,
            &format!("/v1/artifacts?scope_id={proj_scope}"),
            "up-proj",
            &body_proj,
        ),
        201,
    );
    let (a_p, id_p) = (
        r_p["artifact_id"].as_str().unwrap().to_owned(),
        r_p["revision_id"].as_str().unwrap().to_owned(),
    );
    let (a_proj, id_proj) = (
        r_proj["artifact_id"].as_str().unwrap().to_owned(),
        r_proj["revision_id"].as_str().unwrap().to_owned(),
    );
    success(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{a_p}/revisions/{id_p}"),
            Some("del-p"),
            None,
        ),
        200,
    );
    success(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{a_proj}/revisions/{id_proj}"),
            Some("del-proj"),
            None,
        ),
        200,
    );

    // Update policy to 120s so we have a fresh revision to pin in apply.
    let pol_120 = success(
        api.call(
            admin_n,
            "PUT",
            "/v1/admin/retention/policy",
            Some("pol-120"),
            Some(&json!({"grace_seconds": 120, "reason": "shorten to 2m"})),
        ),
        200,
    );
    let cur_rev = pol_120["revision"].as_str().unwrap().to_owned();

    // Preview is a read-only POST (no Idempotency-Key required), returns counts/bytes only.
    let preview_all = success(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/preview",
            None,
            Some(&json!({"target_grace_seconds": 120})),
        ),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/RetentionDeadlinesPreview",
        &preview_all
    ));
    let cur_rev_num: i64 = cur_rev.parse().unwrap();
    let dec_prev = consumer::decode_retention_deadlines_preview(&preview_all).unwrap();
    assert_eq!(dec_prev.policy_revision, cur_rev_num);
    assert_eq!(dec_prev.affected_revisions, 2);
    assert_eq!(
        dec_prev.affected_bytes,
        (payload_p.len() + payload_proj.len()) as i64
    );
    assert_eq!(dec_prev.scope_id, None);

    let preview_scoped = success(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/preview",
            None,
            Some(&json!({"target_grace_seconds": 120, "scope_id": proj_scope})),
        ),
        200,
    );
    assert_eq!(preview_scoped["affected_revisions"], "1");
    assert_eq!(
        preview_scoped["affected_bytes"],
        payload_proj.len().to_string()
    );
    assert_eq!(preview_scoped["scope_id"], proj_scope);
    refused(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/preview",
            None,
            Some(&json!({
                "target_grace_seconds": 120,
                "scope_id": "00000000-0000-4000-8000-00000000cafe"
            })),
        ),
        404,
        "not_found",
    );
    refused(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/preview",
            None,
            Some(&json!({"target_grace_seconds": 40_000_000})),
        ),
        400,
        "validation",
    );

    // Apply: stale expected_policy_revision -> 409 conflict; unknown scope -> 404 not_found.
    refused(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/apply",
            Some("apply-stale"),
            Some(&json!({
                "expected_policy_revision": "1",
                "target_grace_seconds": 120,
                "reason": "stale rev"
            })),
        ),
        409,
        "conflict",
    );
    refused(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/apply",
            Some("apply-404"),
            Some(&json!({
                "expected_policy_revision": cur_rev,
                "target_grace_seconds": 120,
                "scope_id": "00000000-0000-4000-8000-00000000cafe",
                "reason": "missing scope"
            })),
        ),
        404,
        "not_found",
    );

    // Apply scoped to proj_scope: adjusts only proj_scope's revision, leaves personal_scope alone.
    let applied = success(
        api.call(
            admin_b,
            "POST",
            "/v1/admin/retention/deadlines/apply",
            Some("apply-scoped"),
            Some(&json!({
                "expected_policy_revision": cur_rev,
                "target_grace_seconds": 120,
                "scope_id": proj_scope,
                "reason": "shorten project retained revisions"
            })),
        ),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/RetentionDeadlinesApplyResult",
        &applied
    ));
    let dec_app = consumer::decode_retention_deadlines_apply_result(&applied).unwrap();
    assert_eq!(dec_app.policy_revision, cur_rev_num);
    assert_eq!(dec_app.affected_revisions, 1);
    assert_eq!(dec_app.affected_bytes, payload_proj.len() as i64);
    assert_eq!(dec_app.scope_id.as_deref(), Some(proj_scope.as_str()));

    // Exact replay returns identical result; reusing key with different scope_id returns 409 idempotency_conflict.
    let replayed_app = success(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/apply",
            Some("apply-scoped"),
            Some(&json!({
                "expected_policy_revision": cur_rev,
                "target_grace_seconds": 120,
                "scope_id": proj_scope,
                "reason": "shorten project retained revisions"
            })),
        ),
        200,
    );
    assert_eq!(replayed_app, applied);
    refused(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/apply",
            Some("apply-scoped"),
            Some(&json!({
                "expected_policy_revision": cur_rev,
                "target_grace_seconds": 120,
                "scope_id": personal_scope,
                "reason": "shorten project retained revisions"
            })),
        ),
        409,
        "idempotency_conflict",
    );

    // Verify deadlines in DB: proj revision is 120s, personal revision stays 3600s.
    let grace_of = async |rev_id: &str| -> i64 {
        sqlx::query_scalar(
            "SELECT extract(epoch FROM purge_after - retained_at)::bigint
               FROM openmettle.artifact_revisions WHERE id = $1::uuid",
        )
        .bind(rev_id)
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
    };
    assert_eq!(grace_of(&id_proj).await, 120);
    assert_eq!(grace_of(&id_p).await, 3600);

    // Verify zero private artifact/revision IDs or canary names leaked into admin responses,
    // audit rows, or API logs.
    for resp in [&status, &preview_all, &preview_scoped, &applied] {
        let s = resp.to_string();
        for forbidden in [
            &a_p,
            &id_p,
            &a_proj,
            &id_proj,
            CANARY_FILENAME,
            CANARY_CONTENT,
        ] {
            assert!(!s.contains(forbidden), "admin response leaked {forbidden}");
        }
    }
    let admin_audit: String = sqlx::query_scalar(
        "SELECT details::text FROM openmettle.authorization_audit
          WHERE action = 'retention.deadlines_apply'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    for forbidden in [
        &a_p,
        &id_p,
        &a_proj,
        &id_proj,
        CANARY_FILENAME,
        CANARY_CONTENT,
    ] {
        assert!(
            !admin_audit.contains(forbidden),
            "retention.deadlines_apply audit row leaked {forbidden}"
        );
    }

    assert_chain(&db).await;
    assert_storage_reconciled(&db).await;
    drop(api);
    assert_no_canary_in_logs(&log_path, &[CANARY_FILENAME, CANARY_CONTENT]);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn closed_restore_gate_returns_503_unavailable_for_mutations_and_downloads_while_reads_stay_available()
 {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    limits(&db, Some(GIB), Some(GIB)).await;
    seed_token_quotas(&mut owner).await;
    sqlx::query(
        "UPDATE openmettle.retention_policy
            SET min_grace_seconds = 0, max_grace_seconds = 86400, grace_seconds = 3600
          WHERE id",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let (api, _log_path) = start_full_api(&db);
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin_tok = native(&db, &admin, 1).await;
    let alice_tok = native(&db, &alice, 2).await;
    let (admin_n, alice_n) = (As::Native(&admin_tok), As::Native(&alice_tok));
    let personal = personal_of(&db, &alice).await;

    // Seed baseline resources while gate is open: active revision, retained revision, conversation,
    // and queued run.
    let body = form(
        "gate-up",
        &[
            file_part(Some("doc.txt"), "text/plain", "gate-content"),
            metadata_part("{}"),
        ],
        true,
    );
    let active_rev = success(api.upload(alice_n, "/v1/artifacts", "g-up1", &body), 201);
    let active_art = active_rev["artifact_id"].as_str().unwrap().to_owned();
    let active_rev_id = active_rev["revision_id"].as_str().unwrap().to_owned();

    let retained_rev = success(
        api.upload(
            alice_n,
            &format!("/v1/artifacts/{active_art}/revisions"),
            "g-up2",
            &body,
        ),
        201,
    );
    let retained_rev_id = retained_rev["revision_id"].as_str().unwrap().to_owned();
    success(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{active_art}/revisions/{retained_rev_id}"),
            Some("g-ret"),
            None,
        ),
        200,
    );

    let conv = success(
        api.call(
            alice_n,
            "POST",
            "/v1/conversations",
            Some("g-conv"),
            Some(&json!({})),
        ),
        201,
    );
    let conv_id = conv["conversation_id"].as_str().unwrap().to_owned();
    let branch_id = conv["branch_id"].as_str().unwrap().to_owned();
    let run = success(
        api.call(
            alice_n,
            "POST",
            "/v1/runs",
            Some("g-run"),
            Some(&json!({
                "conversation_id": conv_id,
                "branch_id": branch_id,
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": "00000000-0000-4000-8000-00000000b001",
                        "parts": [{"text": "seed run"}]
                    },
                    "selection": {
                        "model": "a",
                        "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                    },
                    "requested_rounds": 1
                }
            })),
        ),
        201,
    );
    let run_id = run["run_id"].as_str().unwrap().to_owned();

    // Close the restore reconciliation gate at the current journal head.
    let owner_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, OWNER))
        .await
        .unwrap();
    let (origin_us, head_seq, head_digest): (i64, i64, String) = sqlx::query_as(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint,
                journal_seq,
                encode(chain_digest, 'hex')
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    restore::lock(
        &owner_pool,
        origin_us,
        head_seq,
        &head_digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();

    // Every mutating `/v1` route AND artifact content download must return `503 unavailable`.
    refused(
        api.call(
            alice_n,
            "POST",
            "/v1/projects",
            Some("closed-proj"),
            Some(&json!({"name": "Blocked"})),
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            alice_n,
            "POST",
            "/v1/conversations",
            Some("closed-conv"),
            Some(&json!({})),
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            alice_n,
            "POST",
            &format!("/v1/conversations/{conv_id}/branches"),
            Some("closed-branch"),
            Some(&json!({})),
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            alice_n,
            "POST",
            "/v1/runs",
            Some("closed-run"),
            Some(&json!({
                "conversation_id": conv_id,
                "branch_id": branch_id,
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": "00000000-0000-4000-8000-00000000b002",
                        "parts": [{"text": "blocked run"}]
                    },
                    "selection": {
                        "model": "a",
                        "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                    },
                    "requested_rounds": 1
                }
            })),
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            alice_n,
            "POST",
            &format!("/v1/runs/{run_id}/cancel"),
            Some("closed-cancel"),
            None,
        ),
        503,
        "unavailable",
    );
    refused(
        api.upload(alice_n, "/v1/artifacts", "closed-up", &body),
        503,
        "unavailable",
    );
    refused(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{active_art}"),
            Some("closed-del-art"),
            None,
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{active_art}/revisions/{active_rev_id}"),
            Some("closed-del-rev"),
            None,
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            alice_n,
            "POST",
            &format!("/v1/artifacts/{active_art}/revisions/{retained_rev_id}/restore"),
            Some("closed-restore-rev"),
            None,
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            admin_n,
            "PUT",
            "/v1/admin/retention/policy",
            Some("closed-pol"),
            Some(&json!({"grace_seconds": 600, "reason": "blocked"})),
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/apply",
            Some("closed-apply"),
            Some(&json!({
                "expected_policy_revision": "2",
                "target_grace_seconds": 600,
                "reason": "blocked"
            })),
        ),
        503,
        "unavailable",
    );
    refused(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{personal}/quotas/storage_bytes"),
            Some("closed-quota"),
            Some(&json!({"hard_limit": "2048", "reason": "blocked"})),
        ),
        503,
        "unavailable",
    );
    let (dl_status, _, dl_body) = api.download(
        alice_n,
        "GET",
        &format!("/v1/artifacts/{active_art}/revisions/{active_rev_id}/content"),
        None,
    );
    assert_eq!(dl_status, 503, "{dl_body}");
    let dl_problem: Value = serde_json::from_str(&dl_body).unwrap();
    assert_eq!(dl_problem["code"], "unavailable");

    // Non-content read routes remain available while the gate is closed.
    success(
        api.call(alice_n, "GET", "/v1/capabilities", None, None),
        200,
    );
    let rev_meta = success(
        api.call(
            alice_n,
            "GET",
            &format!("/v1/artifacts/{active_art}/revisions/{active_rev_id}"),
            None,
            None,
        ),
        200,
    );
    assert_eq!(rev_meta["state"], "active");

    let gate_status = success(
        api.call(admin_n, "GET", "/v1/admin/retention/status", None, None),
        200,
    );
    let dec_gate = consumer::decode_admin_retention_status(&gate_status).unwrap();
    assert!(!dec_gate.restore_gate.open);
    assert_eq!(dec_gate.restore_gate.snapshot_journal_seq, Some(head_seq));
    assert_eq!(dec_gate.restore_gate.required_journal_seq, Some(head_seq));
    assert!(dec_gate.restore_gate.coverage_complete);

    let closed_preview = success(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/preview",
            None,
            Some(&json!({"target_grace_seconds": 600})),
        ),
        200,
    );
    assert_eq!(closed_preview["affected_revisions"], "1");

    // Reopen the gate and verify mutations and downloads immediately resume.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id)
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex')) c",
    )
    .bind(origin_us)
    .bind(head_seq)
    .bind(&head_digest)
    .execute(&owner_pool)
    .await
    .unwrap();

    let (dl_ok, _, dl_bytes) = api.download(
        alice_n,
        "GET",
        &format!("/v1/artifacts/{active_art}/revisions/{active_rev_id}/content"),
        None,
    );
    assert_eq!((dl_ok, dl_bytes.as_str()), (200, "gate-content"));
    success(
        api.call(
            alice_n,
            "POST",
            "/v1/projects",
            Some("reopened-proj"),
            Some(&json!({"name": "Resumed"})),
        ),
        201,
    );
    success(
        api.call(
            admin_n,
            "PUT",
            "/v1/admin/retention/policy",
            Some("reopened-pol"),
            Some(&json!({"grace_seconds": 600, "reason": "resumed"})),
        ),
        200,
    );
}
