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

    // POST /v1/runs attaching a visible retained revision excludes it with 404 not_found
    // (ADR 0036 & ADR 0041), matching unknown/unshared revisions.
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
        404,
        "not_found",
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
    // Fresh DELETE and restore on a purged revision conceal it with 404 not_found (P2 #11).
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::confirm_purge(&mut tx, &personal, &r2_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    refused(
        api.call(alice_b, "DELETE", &r2_path, Some("del-r2-purged"), None),
        404,
        "not_found",
    );
    refused(
        api.call(alice_b, "POST", &r2_restore, Some("rest-r2-purged"), None),
        404,
        "not_found",
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

    // Verify content/run-history read routes succeed while the gate is open, and open an active
    // SSE stream BEFORE closing the gate so we can verify active SSE termination on gate close.
    let messages_path = format!("/v1/conversations/{conv_id}/branches/{branch_id}/messages");
    let run_path = format!("/v1/runs/{run_id}");
    let approvals_path = format!("/v1/runs/{run_id}/approvals");
    let events_path = format!("/v1/runs/{run_id}/events");
    success(api.call(alice_n, "GET", &messages_path, None, None), 200);
    success(api.call(alice_n, "GET", &run_path, None, None), 200);
    success(api.call(alice_n, "GET", &approvals_path, None, None), 200);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sse = tokio::net::TcpStream::connect(&api.bind).await.unwrap();
    let sse_req = format!(
        "GET {events_path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {alice_tok}\r\nConnection: close\r\n\r\n",
        api.bind
    );
    sse.write_all(sse_req.as_bytes()).await.unwrap();
    let mut sse_buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !String::from_utf8_lossy(&sse_buf).contains("\n\n") {
        let n = tokio::time::timeout_at(head_deadline, sse.read(&mut tmp))
            .await
            .expect("SSE headers timed out")
            .unwrap();
        assert!(n > 0, "SSE stream closed prematurely before gate lock");
        sse_buf.extend_from_slice(&tmp[..n]);
    }
    let sse_head = String::from_utf8_lossy(&sse_buf);
    assert!(sse_head.starts_with("HTTP/1.1 200 "), "{sse_head}");

    // Close the restore reconciliation gate at the current journal head.
    let owner_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, OWNER))
        .await
        .unwrap();
    let (origin_us, lifecycle_origin_us, lifecycle_baseline, head_seq, head_digest): (
        i64,
        Option<i64>,
        Option<String>,
        i64,
        String,
    ) = sqlx::query_as(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint,
                (extract(epoch FROM lifecycle_coverage_started_at) * 1000000)::bigint,
                encode(lifecycle_baseline_digest, 'hex'),
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
        lifecycle_origin_us,
        lifecycle_baseline.as_deref(),
        head_seq,
        &head_digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();

    // Active SSE stream must terminate promptly once the gate closes (P1 #5).
    let sse_eof = tokio::time::timeout(Duration::from_secs(5), async {
        let mut rest = Vec::new();
        sse.read_to_end(&mut rest).await.unwrap();
        rest
    })
    .await
    .expect("active SSE stream did not terminate after restore gate closed");
    drop(sse_eof);

    // Every mutating `/v1` route, settled upload replay (P1 #6), download, AND content/run-history
    // read route (P1 #5) must return `503 unavailable`.
    refused(
        api.call(alice_n, "GET", &messages_path, None, None),
        503,
        "unavailable",
    );
    refused(
        api.call(alice_n, "GET", &run_path, None, None),
        503,
        "unavailable",
    );
    refused(
        api.call(alice_n, "GET", &approvals_path, None, None),
        503,
        "unavailable",
    );
    refused(
        api.call(alice_n, "GET", &events_path, None, None),
        503,
        "unavailable",
    );
    // Settled upload retry with the exact earlier Idempotency-Key (`g-up1`) also returns 503.
    refused(
        api.upload(alice_n, "/v1/artifacts", "g-up1", &body),
        503,
        "unavailable",
    );
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

    // Verify P2 #12/#13: both admin inspection routes committed redacted authorization_audit rows
    // even while the restore gate was closed.
    let (status_audits, preview_audits): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE action = 'retention.status_read'),
                count(*) FILTER (WHERE action = 'retention.deadlines_preview')
           FROM openmettle.authorization_audit",
    )
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert!(status_audits >= 1 && preview_audits >= 1);

    // Reopen the gate and verify mutations, downloads, and run/message reads immediately resume.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4,
                    decode($5, 'hex')
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4, decode($5, 'hex')) c",
    )
    .bind(origin_us)
    .bind(head_seq)
    .bind(&head_digest)
    .bind(lifecycle_origin_us)
    .bind(lifecycle_baseline.as_deref())
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
    success(api.call(alice_n, "GET", &messages_path, None, None), 200);
    success(api.call(alice_n, "GET", &run_path, None, None), 200);
    success(api.call(alice_n, "GET", &approvals_path, None, None), 200);
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

/// Cross-provider Review #1 regressions (P1 #4 admission fence, P1 #7 live-referenced delete &
/// held restore refusals, P2 #9 personal-artifact unshare lock serialization, P2 #10 stored
/// transition receipt replay across restore/re-delete/purge, P2 #11 unknown revision concealment
/// under read-only share, and P2 #12/#13 server-clock admin read expiry & audit logging).
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn review_regressions_live_refs_holds_receipts_concealment_unshare_and_admin_reads() {
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
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let reader = account(&mut owner, PROVIDER, true, FUTURE).await;
    let collab = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (admin_tok, alice_tok, reader_tok, collab_tok) = (
        native(&db, &admin, 1).await,
        native(&db, &alice, 2).await,
        native(&db, &reader, 3).await,
        native(&db, &collab, 4).await,
    );
    let (admin_n, alice_n, reader_n) = (
        As::Native(&admin_tok),
        As::Native(&alice_tok),
        As::Native(&reader_tok),
    );
    let personal = personal_of(&db, &alice).await;

    let upload_body = |tag: &str, text: &str| {
        form(
            tag,
            &[
                file_part(Some(CANARY_FILENAME), "text/plain", text),
                metadata_part("{}"),
            ],
            true,
        )
    };

    // --- P2 #11: read-only share on unknown revision UUID gets 404 not_found (NOT 403 policy) ---
    let art_ro = success(
        api.upload(
            alice_n,
            "/v1/artifacts",
            "ro-up",
            &upload_body("ro", "ro-data"),
        ),
        201,
    );
    let art_ro_id = art_ro["artifact_id"].as_str().unwrap().to_owned();
    let rev_ro_id = art_ro["revision_id"].as_str().unwrap().to_owned();
    success(
        api.call(
            alice_n,
            "PUT",
            &format!("/v1/artifacts/{art_ro_id}/shares"),
            Some("ro-share"),
            Some(&shared("user", Some(&reader.user), "read")),
        ),
        200,
    );
    let missing_rev = "00000000-0000-4000-8000-00000000dead";
    refused(
        api.call(
            reader_n,
            "DELETE",
            &format!("/v1/artifacts/{art_ro_id}/revisions/{missing_rev}"),
            Some("ro-del-missing"),
            None,
        ),
        404,
        "not_found",
    );
    refused(
        api.call(
            reader_n,
            "POST",
            &format!("/v1/artifacts/{art_ro_id}/revisions/{missing_rev}/restore"),
            Some("ro-rest-missing"),
            None,
        ),
        404,
        "not_found",
    );
    // On an existing active revision, read-only share still gets 403 policy.
    refused(
        api.call(
            reader_n,
            "DELETE",
            &format!("/v1/artifacts/{art_ro_id}/revisions/{rev_ro_id}"),
            Some("ro-del-real"),
            None,
        ),
        403,
        "policy",
    );

    // --- P1 #7: live-referenced delete refusal (message_parts + unfinished run) & held restore ---
    let art_ref = success(
        api.upload(
            alice_n,
            "/v1/artifacts",
            "ref-up1",
            &upload_body("ref1", "attached-bytes"),
        ),
        201,
    );
    let art_ref_id = art_ref["artifact_id"].as_str().unwrap().to_owned();
    let rev_attached = art_ref["revision_id"].as_str().unwrap().to_owned();
    let rev_sibling = success(
        api.upload(
            alice_n,
            &format!("/v1/artifacts/{art_ref_id}/revisions"),
            "ref-up2",
            &upload_body("ref2", "unattached-sibling"),
        ),
        201,
    )["revision_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let conv = success(
        api.call(
            alice_n,
            "POST",
            "/v1/conversations",
            Some("ref-conv"),
            Some(&json!({})),
        ),
        201,
    );
    let run = success(
        api.call(
            alice_n,
            "POST",
            "/v1/runs",
            Some("ref-run"),
            Some(&json!({
                "conversation_id": conv["conversation_id"],
                "branch_id": conv["branch_id"],
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": "00000000-0000-4000-8000-00000000c001",
                        "parts": [{"attachment": rev_attached}]
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

    // Single-revision DELETE and whole-artifact DELETE both fail with 409 conflict without
    // partially retaining the unattached sibling revision!
    refused(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{art_ref_id}/revisions/{rev_attached}"),
            Some("del-attached-1"),
            None,
        ),
        409,
        "conflict",
    );
    refused(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{art_ref_id}"),
            Some("del-attached-art"),
            None,
        ),
        409,
        "conflict",
    );
    for rev in [&rev_attached, &rev_sibling] {
        let st: String = sqlx::query_scalar(
            "SELECT state FROM openmettle.artifact_revisions WHERE id = $1::uuid",
        )
        .bind(rev)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(st, "active", "refused delete must leave {rev} active");
    }

    // Also test unfinished-run reference (storage_reservations.run_id -> queued run):
    sqlx::query(
        "UPDATE openmettle.storage_reservations
            SET run_id = $2::uuid
          WHERE id = (SELECT reservation_id FROM openmettle.artifact_revisions WHERE id = $1::uuid)",
    )
    .bind(&rev_sibling)
    .bind(&run_id)
    .execute(&mut owner)
    .await
    .unwrap();
    refused(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{art_ref_id}/revisions/{rev_sibling}"),
            Some("del-unfinished-run"),
            None,
        ),
        409,
        "conflict",
    );
    sqlx::query(
        "UPDATE openmettle.storage_reservations
            SET run_id = NULL
          WHERE id = (SELECT reservation_id FROM openmettle.artifact_revisions WHERE id = $1::uuid)",
    )
    .bind(&rev_sibling)
    .execute(&mut owner)
    .await
    .unwrap();

    // Operator retention hold blocks pre-expiry restore with 409 conflict until removed.
    success(
        api.call(
            alice_n,
            "DELETE",
            &format!("/v1/artifacts/{art_ref_id}/revisions/{rev_sibling}"),
            Some("del-sibling-ok"),
            None,
        ),
        200,
    );
    sqlx::query(
        "INSERT INTO openmettle.artifact_retention_holds (scope_id, artifact_revision_id)
         VALUES ($1::uuid, $2::uuid)",
    )
    .bind(&personal)
    .bind(&rev_sibling)
    .execute(&mut owner)
    .await
    .unwrap();
    refused(
        api.call(
            alice_n,
            "POST",
            &format!("/v1/artifacts/{art_ref_id}/revisions/{rev_sibling}/restore"),
            Some("rest-held"),
            None,
        ),
        409,
        "conflict",
    );
    sqlx::query(
        "DELETE FROM openmettle.artifact_retention_holds
          WHERE scope_id = $1::uuid AND artifact_revision_id = $2::uuid",
    )
    .bind(&personal)
    .bind(&rev_sibling)
    .execute(&mut owner)
    .await
    .unwrap();
    let restored_sibling = success(
        api.call(
            alice_n,
            "POST",
            &format!("/v1/artifacts/{art_ref_id}/revisions/{rev_sibling}/restore"),
            Some("rest-unheld"),
            None,
        ),
        200,
    );
    assert_eq!(restored_sibling["state"], "active");

    // --- P2 #10: exact Idempotency-Key replays original transition receipt across restore/re-delete/purge ---
    let art_rec = success(
        api.upload(
            alice_n,
            "/v1/artifacts",
            "rec-up",
            &upload_body("rec", "receipt-bytes"),
        ),
        201,
    );
    let art_rec_id = art_rec["artifact_id"].as_str().unwrap().to_owned();
    let rev_rec_id = art_rec["revision_id"].as_str().unwrap().to_owned();
    let rec_path = format!("/v1/artifacts/{art_rec_id}/revisions/{rev_rec_id}");
    let rec_restore = format!("{rec_path}/restore");

    let del1 = success(
        api.call(alice_n, "DELETE", &rec_path, Some("rec-del-1"), None),
        200,
    );
    assert_eq!(del1["state"], "retained");
    let rest1 = success(
        api.call(alice_n, "POST", &rec_restore, Some("rec-rest-1"), None),
        200,
    );
    assert_eq!(rest1["state"], "active");

    // Replay rec-del-1 while revision is active -> returns ORIGINAL retained receipt without mutating!
    let del1_replay_active = success(
        api.call(alice_n, "DELETE", &rec_path, Some("rec-del-1"), None),
        200,
    );
    assert_eq!(del1_replay_active, del1);
    assert_eq!(
        success(api.call(alice_n, "GET", &rec_path, None, None), 200)["state"],
        "active"
    );

    // Re-delete with a new key -> replay rec-rest-1 while revision is retained -> returns ORIGINAL
    // active receipt without mutating!
    tokio::time::sleep(Duration::from_millis(20)).await;
    let del2 = success(
        api.call(alice_n, "DELETE", &rec_path, Some("rec-del-2"), None),
        200,
    );
    assert_ne!(del2["retained_at"], del1["retained_at"]);
    let rest1_replay_ret = success(
        api.call(alice_n, "POST", &rec_restore, Some("rec-rest-1"), None),
        200,
    );
    assert_eq!(rest1_replay_ret, rest1);
    assert_eq!(
        success(api.call(alice_n, "GET", &rec_path, None, None), 200)["state"],
        "retained"
    );

    // Expire and purge the revision -> replay rec-del-1 STILL returns original retained receipt,
    // while fresh DELETE / restore keys return 404 not_found!
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
            SET retained_at = clock_timestamp() - interval '10 seconds',
                purge_after = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&rev_rec_id)
    .execute(&mut owner)
    .await
    .unwrap();
    let mut worker = connect(&db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::begin_purge(&mut tx, &personal, &rev_rec_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    storage::confirm_purge(&mut tx, &personal, &rev_rec_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let del1_replay_purged = success(
        api.call(alice_n, "DELETE", &rec_path, Some("rec-del-1"), None),
        200,
    );
    assert_eq!(del1_replay_purged, del1);
    refused(
        api.call(alice_n, "DELETE", &rec_path, Some("rec-del-fresh"), None),
        404,
        "not_found",
    );
    refused(
        api.call(alice_n, "POST", &rec_restore, Some("rec-rest-fresh"), None),
        404,
        "not_found",
    );

    // --- P2 #9: personal-artifact collaborator delete serializes with owner resource.unshare ---
    let art_col = success(
        api.upload(
            alice_n,
            "/v1/artifacts",
            "col-up",
            &upload_body("col", "collab-bytes"),
        ),
        201,
    );
    let art_col_id = art_col["artifact_id"].as_str().unwrap().to_owned();
    let rev_col_id = art_col["revision_id"].as_str().unwrap().to_owned();
    success(
        api.call(
            alice_n,
            "PUT",
            &format!("/v1/artifacts/{art_col_id}/shares"),
            Some("col-share"),
            Some(&shared("user", Some(&collab.user), "write")),
        ),
        200,
    );

    // Hold alice's user row FOR NO KEY UPDATE (the exact lock resource.unshare takes), revoke
    // collab's share inside that tx, spawn collab's DELETE so it blocks on alice's user row, then
    // commit the unshare and confirm collab's delete is refused with 404 not_found.
    let mut holder_conn = connect(&db.0, OWNER).await;
    let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut holder_conn)
        .await
        .unwrap();
    let mut holder_tx = holder_conn.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&alice.user)
        .execute(&mut *holder_tx)
        .await
        .unwrap();
    sqlx::query(
        "WITH target AS (
             SELECT id, scope_id, last_revision
               FROM openmettle.grant_assignments
              WHERE target_kind = 'artifact'
                AND target_id = $1::uuid
                AND grantee_user_id = $2::uuid
         ),
         revoked AS (
             INSERT INTO openmettle.grant_changes (
                 scope_id, assignment_id, revision, source_kind, actor_user_id,
                 request_key, decision, cycle_id, request_identity, request_digest
             )
             SELECT scope_id, id, last_revision + 1, 'direct', $3::uuid,
                    'col-unshare-race', 'revoke', NULL,
                    decode('00', 'hex'), decode(repeat('00', 32), 'hex')
               FROM target
             RETURNING assignment_id, revision
         )
         UPDATE openmettle.grant_assignments ga
            SET last_revision = r.revision
           FROM revoked r
          WHERE ga.id = r.assignment_id",
    )
    .bind(&art_col_id)
    .bind(&collab.user)
    .bind(&alice.user)
    .execute(&mut *holder_tx)
    .await
    .unwrap();
    let collab_bind = api.bind.clone();
    let collab_tok_owned = collab_tok.clone();
    let collab_path = format!("/v1/artifacts/{art_col_id}/revisions/{rev_col_id}");
    let collab_task = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(&collab_bind).unwrap();
        let req = format!(
            "DELETE {collab_path} HTTP/1.1\r\nHost: {collab_bind}\r\nAuthorization: Bearer {collab_tok_owned}\r\nIdempotency-Key: col-race-del\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    });
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(holder_pid)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(
            Instant::now() < wait_deadline,
            "collab delete did not block on owner users row"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    holder_tx.commit().await.unwrap();
    let collab_resp = collab_task.await.unwrap();
    assert!(
        collab_resp.starts_with("HTTP/1.1 404 "),
        "expected 404 after serialized unshare, got {collab_resp}"
    );
    let col_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.artifact_revisions WHERE id = $1::uuid")
            .bind(&rev_col_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(col_state, "active");

    // --- P1 #4: DownloadArtifactRevision admission serializes with restore_gate_lock ---
    let (origin_us, lifecycle_origin_us, lifecycle_baseline, head_seq, head_digest): (
        i64,
        Option<i64>,
        Option<String>,
        i64,
        String,
    ) = sqlx::query_as(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint,
                (extract(epoch FROM lifecycle_coverage_started_at) * 1000000)::bigint,
                encode(lifecycle_baseline_digest, 'hex'),
                journal_seq,
                encode(chain_digest, 'hex')
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let mut gate_holder = connect(&db.0, OWNER).await;
    let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut gate_holder)
        .await
        .unwrap();
    let mut gate_tx = gate_holder.begin().await.unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, $2, decode($3, 'hex'), true, NULL, true, $4, decode($5, 'hex'))",
    )
    .bind(origin_us)
    .bind(head_seq)
    .bind(&head_digest)
    .bind(lifecycle_origin_us)
    .bind(lifecycle_baseline.as_deref())
    .execute(&mut *gate_tx)
    .await
    .unwrap();
    let dl_bind = api.bind.clone();
    let dl_tok = alice_tok.clone();
    let dl_path = format!("/v1/artifacts/{art_col_id}/revisions/{rev_col_id}/content");
    let dl_task = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(&dl_bind).unwrap();
        let req = format!(
            "GET {dl_path} HTTP/1.1\r\nHost: {dl_bind}\r\nAuthorization: Bearer {dl_tok}\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    });
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(gate_pid)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(
            Instant::now() < wait_deadline,
            "download did not serialize on restore_gate_lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    gate_tx.commit().await.unwrap();
    let dl_resp = dl_task.await.unwrap();
    assert!(
        dl_resp.starts_with("HTTP/1.1 503 "),
        "expected 503 after serialized restore_gate_lock commit, got {dl_resp}"
    );

    // --- P2 #12/#13: server-clock expiry cannot be bypassed with stale p_now_ms ---
    let expired_admin = account(&mut owner, PROVIDER, true, 1_000).await;
    make_admin(&mut owner, &expired_admin).await;
    let mut api_conn = connect(&db.0, API).await;
    let stale_status =
        sqlx::query("SELECT * FROM openmettle.admin_retention_status($1::uuid, $2::uuid, 1)")
            .bind(&expired_admin.user)
            .bind(&expired_admin.approval)
            .execute(&mut api_conn)
            .await;
    assert_eq!(sqlstate(stale_status), "42501");
    let stale_preview = sqlx::query(
        "SELECT * FROM openmettle.retention_preview_deadlines($1::uuid, $2::uuid, 1, 120, NULL)",
    )
    .bind(&expired_admin.user)
    .bind(&expired_admin.approval)
    .execute(&mut api_conn)
    .await;
    assert_eq!(sqlstate(stale_preview), "42501");

    // Verify valid admin status/preview write redacted audit rows and leak zero canaries.
    success(
        api.call(admin_n, "GET", "/v1/admin/retention/status", None, None),
        200,
    );
    success(
        api.call(
            admin_n,
            "POST",
            "/v1/admin/retention/deadlines/preview",
            None,
            Some(&json!({"target_grace_seconds": 120})),
        ),
        200,
    );
    assert_chain(&db).await;
    assert_storage_reconciled(&db).await;
    drop(api);
    assert_no_canary_in_logs(&log_path, &[CANARY_FILENAME]);
    assert_no_canary_in_audit_or_journal(&db, &[CANARY_FILENAME]).await;
}

/// Review #2 P1 #2, P1 #3, and P2 #4 regressions against mounted `v1::router` and PostgreSQL 18:
/// - P1 #2: a multi-chunk (> 64 KiB) HTTP download paused after chunk 1 across a full
///   `restore::lock -> restore_gate_open -> retain` cycle aborts without serving retained bytes.
/// - P1 #3: `ListRunApprovals` blocked on `runs FOR UPDATE` while `restore::lock` closes the gate
///   returns `503 unavailable` (never `200` with `arguments_json` / `destination`), and
///   `ListMessages` serializes inside its `READ COMMITTED` tx against `restore_gate_lock`.
/// - P2 #4: `StreamRunEvents` over a backpressured HTTP transport pauses mid-stream after event 1;
///   closing the restore gate terminates the stream before the tail of the seeded events can leak.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn review2_download_cycle_approvals_lock_messages_tx_and_sse_backpressure() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, client::conn::http1};
    use hyper_util::rt::TokioIo;
    use openmettle_core::{
        artifact_fs::Store,
        auth_config,
        authz::{
            approvals::park,
            leases::LeaseSettings,
            runs::{self as queue, ClaimLimits},
        },
        browser_auth::{BrowserAuth, native::NativeAuth},
        v1,
        worker::StepTasks,
    };
    use sqlx::PgPool;
    use std::{
        collections::VecDeque,
        io,
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll, Waker},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct PipeBuf {
        buf: VecDeque<u8>,
        cap: usize,
        closed: bool,
        read_waker: Option<Waker>,
        write_waker: Option<Waker>,
    }

    struct PipeEnd {
        rx: Arc<Mutex<PipeBuf>>,
        tx: Arc<Mutex<PipeBuf>>,
    }

    impl Drop for PipeEnd {
        fn drop(&mut self) {
            if let Ok(mut tx) = self.tx.lock() {
                tx.closed = true;
                if let Some(w) = tx.read_waker.take() {
                    w.wake();
                }
            }
            if let Ok(mut rx) = self.rx.lock() {
                rx.closed = true;
                if let Some(w) = rx.write_waker.take() {
                    w.wake();
                }
            }
        }
    }

    impl AsyncRead for PipeEnd {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut rx = self.rx.lock().unwrap();
            if !rx.buf.is_empty() {
                let n = rx.buf.len().min(buf.remaining());
                for _ in 0..n {
                    buf.put_slice(&[rx.buf.pop_front().unwrap()]);
                }
                if let Some(w) = rx.write_waker.take() {
                    w.wake();
                }
                return Poll::Ready(Ok(()));
            }
            if rx.closed {
                return Poll::Ready(Ok(()));
            }
            rx.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    impl AsyncWrite for PipeEnd {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut tx = self.tx.lock().unwrap();
            if tx.closed {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
            }
            let avail = tx.cap.saturating_sub(tx.buf.len());
            if avail == 0 {
                tx.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = avail.min(data.len());
            tx.buf.extend(&data[..n]);
            if let Some(w) = tx.read_waker.take() {
                w.wake();
            }
            Poll::Ready(Ok(n))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let mut tx = self.tx.lock().unwrap();
            if tx.closed {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed")));
            }
            let mut avail = tx.cap.saturating_sub(tx.buf.len());
            if avail == 0 {
                tx.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let mut written = 0;
            for slice in bufs {
                if avail == 0 {
                    break;
                }
                let n = avail.min(slice.len());
                tx.buf.extend(&slice[..n]);
                written += n;
                avail -= n;
            }
            if written > 0
                && let Some(w) = tx.read_waker.take()
            {
                w.wake();
            }
            Poll::Ready(Ok(written))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut tx = self.tx.lock().unwrap();
            tx.closed = true;
            if let Some(w) = tx.read_waker.take() {
                w.wake();
            }
            Poll::Ready(Ok(()))
        }
    }

    fn pipe_pair(c2s_cap: usize, s2c_cap: usize) -> (PipeEnd, PipeEnd) {
        let c2s = Arc::new(Mutex::new(PipeBuf {
            buf: VecDeque::new(),
            cap: c2s_cap,
            closed: false,
            read_waker: None,
            write_waker: None,
        }));
        let s2c = Arc::new(Mutex::new(PipeBuf {
            buf: VecDeque::new(),
            cap: s2c_cap,
            closed: false,
            read_waker: None,
            write_waker: None,
        }));
        (
            PipeEnd {
                rx: s2c.clone(),
                tx: c2s.clone(),
            },
            PipeEnd { rx: c2s, tx: s2c },
        )
    }

    struct MemListener {
        rx: tokio::sync::mpsc::UnboundedReceiver<PipeEnd>,
    }

    impl axum::serve::Listener for MemListener {
        type Io = PipeEnd;
        type Addr = ();

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            match self.rx.recv().await {
                Some(io) => (io, ()),
                None => std::future::pending().await,
            }
        }

        fn local_addr(&self) -> io::Result<Self::Addr> {
            Ok(())
        }
    }

    struct AbortTask<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for AbortTask<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

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

    let dir = Dir::new();
    let art_root = PathBuf::from(dir.path("artifacts"));
    fs::create_dir(&art_root).unwrap();
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
    let auth_path = dir.write("auth.json", &serde_json::to_vec(&doc).unwrap());
    let (mut settings, profile) = auth_config::load_browser(Path::new(&auth_path)).unwrap();
    let native_cfg = settings.native().unwrap().clone();
    let v1_extensions = v1::AuthExtensions::take(&mut settings);
    let api_pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(role_options(&db.0, API))
        .await
        .unwrap();
    let issuance_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, ISSUANCE))
        .await
        .unwrap();
    let store = Store::open(&art_root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    let browser = Arc::new(BrowserAuth::new(settings, api_pool.clone(), issuance_pool));
    let n = native_cfg.settings();
    let native_auth = NativeAuth::new(
        browser.clone(),
        n.provider,
        n.issuer,
        n.callback,
        n.client,
        n.redirect,
        n.max_in_flight,
    )
    .unwrap();
    let router = v1_extensions
        .apply(v1::router(
            browser,
            Some(Arc::new(native_auth)),
            profile.handoff().origin,
            api_pool.clone(),
            Some(store),
        ))
        .layer(axum::Extension(v1::ApprovalDisplayPolicy(Arc::new(
            crate::approvals::Policy::default(),
        ))));

    let (conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let _server = AbortTask(tokio::spawn(async move {
        let _ = axum::serve(MemListener { rx: conn_rx }, router).await;
    }));

    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_tok = native(&db, &alice, 1).await;
    let personal_scope = personal_of(&db, &alice).await;
    let auth_hdr = format!("Bearer {alice_tok}");
    let owner_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, OWNER))
        .await
        .unwrap();

    let open_req = |s2c_cap: usize,
                    method: &str,
                    uri: &str,
                    key: Option<&str>,
                    content_type: Option<&str>,
                    body: Vec<u8>| {
        let conn_tx = conn_tx.clone();
        let auth_hdr = auth_hdr.clone();
        let method = method.to_owned();
        let uri = uri.to_owned();
        let key = key.map(str::to_owned);
        let content_type = content_type.map(str::to_owned);
        async move {
            let (client_io, server_io) = pipe_pair(1024 * 1024, s2c_cap);
            conn_tx.send(server_io).unwrap();
            let (mut sender, conn) = http1::handshake(TokioIo::new(client_io)).await.unwrap();
            let guard = AbortTask(tokio::spawn(conn));
            let mut builder = Request::builder()
                .method(method.as_str())
                .uri(uri.as_str())
                .header("host", "app.example.test")
                .header("authorization", auth_hdr);
            if let Some(k) = key {
                builder = builder.header("idempotency-key", k);
            }
            if let Some(ct) = content_type {
                builder = builder.header("content-type", ct);
            }
            let resp = sender
                .send_request(builder.body(Full::new(Bytes::from(body))).unwrap())
                .await
                .unwrap();
            (resp, guard)
        }
    };

    async fn head_state(pool: &PgPool) -> (i64, Option<i64>, Option<String>, i64, String) {
        sqlx::query_as::<_, (i64, Option<i64>, Option<String>, i64, String)>(
            "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint,
                    (extract(epoch FROM lifecycle_coverage_started_at) * 1000000)::bigint,
                    encode(lifecycle_baseline_digest, 'hex'),
                    journal_seq,
                    encode(chain_digest, 'hex')
               FROM openmettle.deletion_journal_head WHERE id",
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn reopen_gate(
        pool: &PgPool,
        origin_us: i64,
        lc_origin: Option<i64>,
        lc_baseline: Option<String>,
        head_seq: i64,
        head_digest: String,
    ) {
        sqlx::query(
            "SELECT openmettle.restore_gate_open(
                        c.restore_run_id,
                        c.volume_claim_token,
                        $1,
                        $2,
                        decode($3, 'hex'),
                        (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                        $4,
                        decode($5, 'hex')
                    )
               FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4, decode($5, 'hex')) c",
        )
        .bind(origin_us)
        .bind(head_seq)
        .bind(&head_digest)
        .bind(lc_origin)
        .bind(lc_baseline.as_deref())
        .execute(pool)
        .await
        .unwrap();
    }

    // --- P1 #2: multi-chunk (512 KiB = 8 x 64 KiB) download paused across close -> reopen -> retain ---
    let big_len = 512 * 1024;
    let big_payload = "Z".repeat(big_len);
    let upload_body = form(
        "r2-big",
        &[
            file_part(Some("big.txt"), "text/plain", &big_payload),
            metadata_part("{}"),
        ],
        true,
    );
    let (up_resp, _up_guard) = open_req(
        64 * 1024,
        "POST",
        "/v1/artifacts",
        Some("r2-big-up"),
        Some("multipart/form-data; boundary=r2-big"),
        upload_body.into_bytes(),
    )
    .await;
    assert_eq!(up_resp.status(), 201);
    let up_json: Value =
        serde_json::from_slice(&up_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let art_id = up_json["artifact_id"].as_str().unwrap().to_owned();
    let rev_id = up_json["revision_id"].as_str().unwrap().to_owned();

    // Use a 256-byte server-to-client pipe so Hyper cannot drain the 512 KiB file ahead of the client.
    let (dl_resp, _dl_guard) = open_req(
        256,
        "GET",
        &format!("/v1/artifacts/{art_id}/revisions/{rev_id}/content"),
        None,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(dl_resp.status(), 200);
    let mut dl_body = dl_resp.into_body();
    let first = dl_body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(!first.is_empty());
    let mut total_downloaded = first.len();

    // Pause client after reading the first slice across a FULL close -> reopen -> retain cycle!
    let (origin_us, lc_origin, lc_baseline, head_seq, head_digest) = head_state(&owner_pool).await;
    restore::lock(
        &owner_pool,
        origin_us,
        lc_origin,
        lc_baseline.as_deref(),
        head_seq,
        &head_digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    reopen_gate(
        &owner_pool,
        origin_us,
        lc_origin,
        lc_baseline,
        head_seq,
        head_digest,
    )
    .await;
    let (del_resp, _del_guard) = open_req(
        64 * 1024,
        "DELETE",
        &format!("/v1/artifacts/{art_id}/revisions/{rev_id}"),
        Some("r2-big-del"),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(del_resp.status(), 200);
    let _ = del_resp.into_body().collect().await.unwrap();

    // Drain the paused download: once buffered bytes from chunk 1 clear, Content::poll_frame must
    // abort with an error before serving the retained remainder of the 512 KiB payload.
    let mut saw_error = false;
    while let Some(frame) = dl_body.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(data) = f.into_data() {
                    total_downloaded += data.len();
                }
            }
            Err(_) => {
                saw_error = true;
                break;
            }
        }
    }
    assert!(
        saw_error && total_downloaded < big_len,
        "expected mid-stream abort after gate cycle + retain, saw_error={saw_error} total={total_downloaded}/{big_len}"
    );
    drop(dl_body);
    drop(_dl_guard);

    // --- Review #4 P2 #3: online DELETE /v1/artifacts/{id} WITHOUT gate closure aborts mid-stream ---
    let upload_body2 = form(
        "r4-big",
        &[
            file_part(Some("big2.txt"), "text/plain", &big_payload),
            metadata_part("{}"),
        ],
        true,
    );
    let (up_resp2, _up_guard2) = open_req(
        64 * 1024,
        "POST",
        "/v1/artifacts",
        Some("r4-big-up"),
        Some("multipart/form-data; boundary=r4-big"),
        upload_body2.into_bytes(),
    )
    .await;
    assert_eq!(up_resp2.status(), 201);
    let up_json2: Value =
        serde_json::from_slice(&up_resp2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let art2_id = up_json2["artifact_id"].as_str().unwrap().to_owned();
    let rev2_id = up_json2["revision_id"].as_str().unwrap().to_owned();

    let (dl_resp2, _dl_guard2) = open_req(
        256,
        "GET",
        &format!("/v1/artifacts/{art2_id}/revisions/{rev2_id}/content"),
        None,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(dl_resp2.status(), 200);
    let mut dl_body2 = dl_resp2.into_body();
    let first2 = dl_body2
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(!first2.is_empty());
    let mut total_downloaded2 = first2.len();

    // Disassociate via DELETE /v1/artifacts/{id} WITHOUT closing the restore gate.
    let (del_resp2, _del_guard2) = open_req(
        64 * 1024,
        "DELETE",
        &format!("/v1/artifacts/{art2_id}"),
        Some("r4-big-del"),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(del_resp2.status(), 204);
    let _ = del_resp2.into_body().collect().await.unwrap();

    let mut saw_error2 = false;
    while let Some(frame) = dl_body2.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(data) = f.into_data() {
                    total_downloaded2 += data.len();
                }
            }
            Err(_) => {
                saw_error2 = true;
                break;
            }
        }
    }
    assert!(
        saw_error2 && total_downloaded2 < big_len,
        "expected mid-stream abort after online DELETE /v1/artifacts/{{id}} without gate closure, saw_error={saw_error2} total={total_downloaded2}/{big_len}"
    );
    drop(dl_body2);
    drop(_dl_guard2);

    // --- Seed a conversation, branch, waiting run with pending approval via mounted v1 routes ---
    let (conv_resp, _conv_guard) = open_req(
        64 * 1024,
        "POST",
        "/v1/conversations",
        Some("r2-conv"),
        Some("application/json"),
        serde_json::to_vec(&json!({})).unwrap(),
    )
    .await;
    assert_eq!(conv_resp.status(), 201);
    let conv_json: Value =
        serde_json::from_slice(&conv_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let conv_id = conv_json["conversation_id"].as_str().unwrap().to_owned();
    let branch_id = conv_json["branch_id"].as_str().unwrap().to_owned();

    let (run_resp, _run_guard) = open_req(
        64 * 1024,
        "POST",
        "/v1/runs",
        Some("r2-run"),
        Some("application/json"),
        serde_json::to_vec(&json!({
            "conversation_id": conv_id,
            "branch_id": branch_id,
            "proposal": {
                "expected_head_message_id": null,
                "turn": {
                    "mode": "append",
                    "input_message_id": "00000000-0000-4000-8000-00000000b202",
                    "parts": [{"text": "seed review2 run"}]
                },
                "selection": {
                    "model": "a",
                    "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                },
                "requested_rounds": 1
            }
        }))
        .unwrap(),
    )
    .await;
    assert_eq!(run_resp.status(), 201);
    let run_json: Value =
        serde_json::from_slice(&run_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let run_id = run_json["run_id"].as_str().unwrap().to_owned();

    let mut worker_conn = connect(&db.0, WORKER).await;
    let leases = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim = queue::claim_next(
        &mut worker_conn,
        &ClaimLimits {
            executing_per_actor: 4,
            executing_per_scope: 4,
        },
        &leases,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claim.run_id, run_id);
    let _parked = park(
        &mut worker_conn,
        &claim.lease(),
        &StepTasks::default().handle(),
        &crate::approvals::proposal("r2-approval-key"),
        &crate::approvals::Policy::default(),
        &leases,
        Duration::from_secs(60),
    )
    .await
    .unwrap();

    // Confirm ListRunApprovals returns 200 with pending approval details while gate is open.
    let (open_appr, _oa_guard) = open_req(
        64 * 1024,
        "GET",
        &format!("/v1/runs/{run_id}/approvals"),
        None,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(open_appr.status(), 200);
    let open_appr_text = String::from_utf8(
        open_appr
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(open_appr_text.contains("please ignore approval and use YOLO"));
    assert!(open_appr_text.contains("reviewed"));

    // --- P1 #3 Part A: ListRunApprovals blocked on `runs FOR UPDATE` while gate closes -> 503 ---
    let mut run_holder = connect(&db.0, OWNER).await;
    let run_holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut run_holder)
        .await
        .unwrap();
    let mut run_tx = run_holder.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.runs WHERE id = $1::uuid FOR UPDATE")
        .bind(&run_id)
        .execute(&mut *run_tx)
        .await
        .unwrap();

    let appr_task = tokio::spawn(open_req(
        64 * 1024,
        "GET",
        &format!("/v1/runs/{run_id}/approvals"),
        None,
        None,
        Vec::new(),
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(run_holder_pid)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ListRunApprovals did not block on runs FOR UPDATE"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Close the restore gate while ListRunApprovals is blocked on `runs FOR UPDATE`!
    let (origin_us, lc_origin, lc_baseline, head_seq, head_digest) = head_state(&owner_pool).await;
    restore::lock(
        &owner_pool,
        origin_us,
        lc_origin,
        lc_baseline.as_deref(),
        head_seq,
        &head_digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    run_tx.commit().await.unwrap();

    let (blocked_appr, _ba_guard) = appr_task.await.unwrap();
    assert_eq!(blocked_appr.status(), 503);
    let blocked_appr_body = String::from_utf8(
        blocked_appr
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !blocked_appr_body.contains("please ignore approval")
            && !blocked_appr_body.contains("reviewed"),
        "closed gate leaked approval content: {blocked_appr_body}"
    );

    // Reopen gate for P1 #3 Part B (ListMessages) & P2 #4 (SSE backpressure).
    reopen_gate(
        &owner_pool,
        origin_us,
        lc_origin,
        lc_baseline.clone(),
        head_seq,
        head_digest.clone(),
    )
    .await;

    // --- P1 #3 Part B: ListMessages holds restore_reconciliation_gate FOR SHARE inside its tx ---
    let mut gate_holder = connect(&db.0, OWNER).await;
    let gate_holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut gate_holder)
        .await
        .unwrap();
    let mut gate_tx = gate_holder.begin().await.unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, $2, decode($3, 'hex'), true, NULL, true, $4, decode($5, 'hex'))",
    )
    .bind(origin_us)
    .bind(head_seq)
    .bind(&head_digest)
    .bind(lc_origin)
    .bind(lc_baseline.as_deref())
    .execute(&mut *gate_tx)
    .await
    .unwrap();
    let msg_task = tokio::spawn(open_req(
        64 * 1024,
        "GET",
        &format!("/v1/conversations/{conv_id}/branches/{branch_id}/messages"),
        None,
        None,
        Vec::new(),
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
        )
        .bind(gate_holder_pid)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ListMessages did not serialize on restore_gate_lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    gate_tx.commit().await.unwrap();
    let (msg_resp, _msg_guard) = msg_task.await.unwrap();
    assert_eq!(msg_resp.status(), 503);
    let _ = msg_resp.into_body().collect().await.unwrap();

    // Reopen gate for P2 #4 (SSE per-event cutoff under backpressure).
    reopen_gate(
        &owner_pool,
        origin_us,
        lc_origin,
        lc_baseline.clone(),
        head_seq,
        head_digest.clone(),
    )
    .await;

    // --- P2 #4: Seed 76 additional events (5 DB batches of 16); pause under backpressure after
    // reading 5 events so Hyper's ~8 KiB HTTP/1.1 write buffer fills mid-batch, then close gate ---
    let cur_last: i64 =
        sqlx::query_scalar("SELECT last_event_sequence FROM openmettle.runs WHERE id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let target_last = cur_last + 76;
    sqlx::query(
        "INSERT INTO openmettle.run_events
            (scope_id, run_id, sequence, append_key, format, format_version, payload, identity, digest)
         SELECT $1::uuid, $2::uuid, s, 'r2-sse-' || s, 'openmettle.run-resumed', 1, '{}'::bytea,
                decode('00', 'hex'), sha256(convert_to('r2-sse-' || s, 'UTF8'))
           FROM generate_series($3::bigint, $4::bigint) AS s",
    )
    .bind(&personal_scope)
    .bind(&run_id)
    .bind(cur_last + 1)
    .bind(target_last)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.runs SET last_event_sequence = $2 WHERE id = $1::uuid")
        .bind(&run_id)
        .bind(target_last)
        .execute(&mut owner)
        .await
        .unwrap();

    let (sse_resp, _sse_guard) = open_req(
        256,
        "GET",
        &format!("/v1/runs/{run_id}/events"),
        None,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(sse_resp.status(), 200);
    let mut sse_body = sse_resp.into_body();
    let mut raw_buf = Vec::new();
    let mut delivered_seqs: Vec<i64> = Vec::new();
    let parse_blocks = |buf: &mut Vec<u8>, seqs: &mut Vec<i64>| {
        while let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
            let block: Vec<u8> = buf.drain(..pos + 2).collect();
            if let Ok(text) = std::str::from_utf8(&block)
                && let Some(data_line) = text.lines().find_map(|l| l.strip_prefix("data: "))
                && let Ok(v) = serde_json::from_str::<Value>(data_line)
                && let Some(seq) = v["sequence"].as_str().and_then(|s| s.parse::<i64>().ok())
            {
                seqs.push(seq);
            }
        }
    };
    while delivered_seqs.len() < 5 {
        let frame = sse_body.frame().await.unwrap().unwrap();
        if let Ok(data) = frame.into_data() {
            raw_buf.extend_from_slice(&data);
            parse_blocks(&mut raw_buf, &mut delivered_seqs);
        }
    }
    assert_eq!(delivered_seqs[0], 1);

    // Yield long enough that an un-backpressured stream would drain all 80 events; with vectored
    // WriteStrategy::Queue (MAX_BUF_LIST_BUFFERS = 16) + mpsc::channel(16), the producer parks
    // genuinely on tx.reserve() mid-batch inside batch 3 (33..=48).
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Close the restore gate while the producer is backpressured mid-batch!
    restore::lock(
        &owner_pool,
        origin_us,
        lc_origin,
        lc_baseline.as_deref(),
        head_seq,
        &head_digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();

    // Drain remaining buffered frames to EOF and verify the stream cut off mid-batch before
    // the remainder of the seeded events could be sent.
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Some(frame) = tokio::time::timeout_at(drain_deadline, sse_body.frame())
        .await
        .expect("backpressured SSE stream did not terminate after gate close")
    {
        if let Ok(frame) = frame
            && let Ok(bytes) = frame.into_data()
        {
            raw_buf.extend_from_slice(&bytes);
            parse_blocks(&mut raw_buf, &mut delivered_seqs);
        }
    }
    let last_delivered = *delivered_seqs.last().unwrap();
    assert!(
        !delivered_seqs.contains(&target_last),
        "tail event {target_last} must never be delivered after gate close: {delivered_seqs:?}"
    );
    assert!(
        last_delivered < target_last - 20,
        "backpressured SSE stream must cut off well before tail ({last_delivered} of {target_last}): {delivered_seqs:?}"
    );
    assert_ne!(
        last_delivered % 16,
        0,
        "expected intra-batch cutoff under backpressure (not only at BATCH_LIMIT=16 boundary), got last={last_delivered}"
    );
}
