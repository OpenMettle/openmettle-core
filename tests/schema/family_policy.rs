//! ADR 0044 (V1-06 increment 4, migration 35): family policy tables, SQL evaluator
//! (`openmettle.family_policy_permits`), four enforcement points (API admission/preview, worker
//! claim/recheck, PostgreSQL handoff/confirm, PostgreSQL proxy dispatch), audited `openmettle_api`
//! store operations, `openmettle-admin family` CLI, role/trigger boundaries, and `34 -> 35`
//! upgrade verification.
use super::authz_store::{
    Account, FUTURE, NOW, PROVIDER, UNKNOWN, account, applied, audit, conflict, ctx, denied,
    make_admin, providers,
};
use super::*;
use crate::{
    auth_config_support,
    authz_runs::{chat, personal_of, seeded_session},
    ca, consumer,
    run_admission::LEASES,
};
use openmettle_core::{
    authz::{
        DenialReason, PolicyReason,
        gateway::family::{FamilyGrantee, FamilyPolicyInput, FamilyPolicyRuleKind, Hours},
        runs::{
            self as queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission,
            RunRecheckOutcome, RunRecheckRequest,
        },
        store::{self, StoreError, WriteOutcome},
    },
    grants::{self, Assignment, ChangeInput, Decision, Grantee, MappingInput, Target},
    model_config::{SNAPSHOT_FORMAT, SNAPSHOT_VERSION},
    runs::{RunInput, WriteTransaction},
    sessions,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader},
};

const CATALOG: &[u8] = include_bytes!("../fixtures/conversation-catalog-v1.json");
const ISSUER: &str = "https://authz-store.example.test";
const FAMILY_RULE: &str = "00000000-0000-4000-8000-00000000f001";
const INSTALL: &str = "00000000-0000-4000-8000-00000000f0b1";
const OPERATOR_ID: &str = "00000000-0000-4000-8000-00000000f009";
const INPUT_1: &str = "00000000-0000-4000-8000-00000000f101";
const INPUT_2: &str = "00000000-0000-4000-8000-00000000f102";

const LIMITS: AdmissionLimits = AdmissionLimits {
    live_per_actor: 64,
    live_per_scope: 64,
    queued_in_instance: 64,
    queue_timeout: Duration::from_secs(300),
    round_cap: 4,
};
const CLAIMS: ClaimLimits = ClaimLimits {
    executing_per_actor: 64,
    executing_per_scope: 64,
};

fn admin_binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openmettle-admin"));
    scrub_env(&mut command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

async fn permits_iso(c: &mut PgConnection, account: &Account, model: &str, iso_utc: &str) -> bool {
    sqlx::query_scalar(
        "SELECT openmettle.family_policy_permits($1::uuid, $2::uuid, $3, $4::timestamptz)",
    )
    .bind(&account.user)
    .bind(&account.approval)
    .bind(model)
    .bind(iso_utc)
    .fetch_one(c)
    .await
    .unwrap()
}

/// Enroll `account` in an ADR 0021 OIDC `group` membership observation for `claim_value`
/// observed around `at_ms`.
async fn enroll_oidc_group(
    db: &TestDb,
    account: &Account,
    rule_id: &str,
    claim_value: &str,
    state: &str,
    at_ms: i64,
) {
    let mut owner = connect(&db.0, OWNER).await;
    let (project_id, scope_id) = project(&mut owner, &account.user).await;
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    grants::record_mapping_revision(
        &mut tx,
        &MappingInput {
            rule: rule_id,
            provider: PROVIDER,
            issuer: ISSUER,
            actor: &account.user,
            key: &format!("fam-rule-{rule_id}"),
            expected_revision: 0,
            enabled: true,
            selector_kind: "group",
            claim_name: "groups",
            claim_value,
            binding_format: "openmettle.project-member",
            binding_version: 1,
            binding: project_id.as_bytes(),
        },
    )
    .await
    .unwrap();
    let change_id = if state == "present" {
        let receipt = grants::change_grant(
            &mut tx,
            &ChangeInput {
                assignment: Assignment {
                    scope: &scope_id,
                    target: Target::Project(&project_id),
                    grantee: Grantee::User(&account.user),
                    format: "openmettle.project-member",
                    version: 1,
                    key: &account.approval,
                    mapping_rule: Some(rule_id),
                },
                actor: &account.user,
                key: &format!("fam-grant-{rule_id}"),
                expected_revision: 0,
                mapping_revision: Some(1),
                decision: Decision::Grant,
            },
        )
        .await
        .unwrap();
        Some(receipt.change)
    } else {
        None
    };
    tx.commit().await.unwrap();

    sqlx::query(
        "WITH c AS (
           INSERT INTO openmettle.membership_configuration_changes
               (request_id, approval_id, previous_revision, rule_id, rule_revision, project_id,
                scope_id, max_age_seconds, enabled, baseline_change, floor_ms, actor, reason)
           VALUES (gen_random_uuid(), $1::uuid, 0, $2::uuid, 1, $3::uuid, $4::uuid, 3600, true,
                   NULL, NULL, gen_random_uuid(), 'synthetic family oidc enrollment')
           RETURNING revision)
         INSERT INTO openmettle.membership_observations
             (approval_id, config_revision, enabled, floor_ms, rule_id, rule_revision, project_id,
              scope_id, max_age_seconds, issued_ms, expires_ms, observation, epoch,
              approval_generation, user_generation)
         SELECT $1::uuid, c.revision, true, NULL, $2::uuid, 1, $3::uuid, $4::uuid, 3600,
                $6 - 1000, $6 + 600000, ROW($7::text, $5::uuid)::openmettle.membership_evidence,
                (SELECT max(epoch) FROM openmettle.login_provider_revisions
                  WHERE provider_id = $8::uuid), 0, 0
           FROM c",
    )
    .bind(&account.approval)
    .bind(rule_id)
    .bind(&project_id)
    .bind(&scope_id)
    .bind(change_id)
    .bind(at_ms)
    .bind(state)
    .bind(PROVIDER)
    .execute(&mut owner)
    .await
    .unwrap();
}

struct ApiServer {
    bind: String,
    _process: Process,
    _dir: auth_config_support::Dir,
}

impl ApiServer {
    fn start(db: &TestDb) -> Self {
        let mut catalog: Value = serde_json::from_slice(CATALOG).unwrap();
        catalog["revision"] = json!("catalog/family-1");
        catalog["models"]["a"]["defaults"]["controls"]["output_reserve"] = json!(512);
        catalog["models"]["a"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        // Give model "b" full qualification too so study-hours default fallback can admit it.
        catalog["models"]["b"]["context_window"] = json!(8192);
        catalog["models"]["b"]["output_limit"] = json!(2048);
        catalog["models"]["b"]["defaults"]["controls"]["output_reserve"] = json!(512);
        catalog["models"]["b"]["estimator_revision"] = json!("fixture-bound/1");
        catalog["models"]["b"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        Self::start_with_catalog(db, catalog)
    }

    fn start_with_catalog(db: &TestDb, catalog: Value) -> Self {
        let dir = auth_config_support::Dir::new();
        let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
        doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
        doc["admission_limits"] = json!({
            "live_per_actor": 16,
            "live_per_scope": 16,
            "queued_in_instance": 16,
            "queue_timeout_seconds": 300,
            "round_cap": 4
        });
        doc["catalog_file"] = json!(dir.path("catalog.json"));
        dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap());
        let path = dir.write("auth.json", &serde_json::to_vec(&doc).unwrap());
        let bind = address();
        let mut process = Process(
            binary("api")
                .env("OPENMETTLE_API_AUTH_CONFIG", path)
                .env("OPENMETTLE_API_BIND", &bind)
                .env("OPENMETTLE_API_DATABASE_URL", db.url(API))
                .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", db.url(ISSUANCE))
                .stdout(Stdio::null())
                .stderr(fs::File::create(dir.path("log")).unwrap())
                .spawn()
                .unwrap(),
        );
        wait_ready(&mut process, &bind);
        Self {
            bind,
            _process: process,
            _dir: dir,
        }
    }

    fn call(
        &self,
        channel: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let data = body.map(Value::to_string).unwrap_or_default();
        let key_hdr = key
            .map(|k| format!("Idempotency-Key: {k}\r\n"))
            .unwrap_or_default();
        let media = if body.is_some() {
            "Content-Type: application/json\r\n"
        } else {
            ""
        };
        let mut stream = TcpStream::connect(&self.bind).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: app.example.test\r\n{channel}\r\n{key_hdr}{media}Content-Length: {}\r\n\r\n{data}",
            data.len()
        );
        stream.write_all(req.as_bytes()).unwrap();
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        loop {
            let n = reader.read_line(&mut headers).unwrap();
            assert!(n > 0, "incomplete HTTP headers");
            if headers.ends_with("\r\n\r\n") {
                break;
            }
        }
        let lower = headers.to_ascii_lowercase();
        let status: u16 = lower[9..12].parse().unwrap();
        let len: usize = lower
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .unwrap()
            .parse()
            .unwrap();
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).unwrap();
        let value: Value = if buf.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&buf).unwrap()
        };
        if status >= 400 {
            consumer::decode_problem(&value).unwrap();
        }
        (status, value)
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_dst_spring_forward_and_autumn_fallback_in_sql() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let kid = account(&mut owner, PROVIDER, true, FUTURE).await;

    // 1. Europe/London DST spring forward (2026-03-29: 01:00 GMT jumps to 02:00 BST)
    //    and autumn fall-back (2026-10-25: 01:00-01:59 occurs twice, BST then GMT).
    //    Quiet 01:30-03:00 (90..180), study 16:00-18:00 (960..1080), study_allow = {'b'}.
    let policy_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_user_id, active, zone,
              quiet_start_minute, quiet_end_minute, study_start_minute, study_end_minute)
         VALUES ('user', $1::uuid, true, 'Europe/London', 90, 180, 960, 1080)
         RETURNING id::text",
    )
    .bind(&kid.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
         VALUES ($1::uuid, 'study_allow', 'b', true),
                ($1::uuid, 'disabled', 'blocked', true)",
    )
    .bind(&policy_id)
    .execute(&mut owner)
    .await
    .unwrap();

    let mut worker = connect(&db.0, WORKER).await;
    let mut api = connect(&db.0, API).await;

    // NULL inputs fail closed.
    let null_res: bool =
        sqlx::query_scalar("SELECT openmettle.family_policy_permits(NULL, $1::uuid, 'a', now())")
            .bind(&kid.approval)
            .fetch_one(&mut api)
            .await
            .unwrap();
    assert!(!null_res);

    // Spring-forward gap (01:00-01:59 never occurs in Europe/London on 2026-03-29):
    assert!(permits_iso(&mut worker, &kid, "a", "2026-03-29T00:59:00Z").await);
    assert!(!permits_iso(&mut worker, &kid, "a", "2026-03-29T01:00:00Z").await);
    assert!(!permits_iso(&mut api, &kid, "b", "2026-03-29T01:59:59Z").await);
    assert!(permits_iso(&mut api, &kid, "a", "2026-03-29T02:00:00Z").await);

    // Autumn fall-back (2026-10-25: 01:30 occurs at 00:30Z BST and again at 01:30Z GMT):
    assert!(permits_iso(&mut worker, &kid, "a", "2026-10-25T00:29:59Z").await);
    assert!(!permits_iso(&mut worker, &kid, "a", "2026-10-25T00:30:00Z").await);
    assert!(!permits_iso(&mut worker, &kid, "a", "2026-10-25T01:30:00Z").await);
    assert!(!permits_iso(&mut worker, &kid, "a", "2026-10-25T02:59:59Z").await);
    assert!(permits_iso(&mut worker, &kid, "a", "2026-10-25T03:00:00Z").await);

    // Study window (16:00-18:00 BST on 2026-06-15 = 15:00Z..17:00Z): 'b' allowed, 'a' denied.
    assert!(permits_iso(&mut api, &kid, "b", "2026-06-15T15:30:00Z").await);
    assert!(!permits_iso(&mut api, &kid, "a", "2026-06-15T15:30:00Z").await);
    // Disabled switch wins at all times (even outside quiet/study).
    assert!(!permits_iso(&mut api, &kid, "blocked", "2026-06-15T10:00:00Z").await);

    // 2. America/New_York overnight quiet (22:00-02:30 -> 1320..150) across spring-forward
    //    (2026-03-08 02:00 EST -> 03:00 EDT) and autumn fall-back (2026-11-01 01:30 twice).
    sqlx::query(
        "UPDATE openmettle.family_policies
            SET zone = 'America/New_York',
                quiet_start_minute = 1320,
                quiet_end_minute = 150,
                study_start_minute = NULL,
                study_end_minute = NULL,
                revision = revision + 1
          WHERE id = $1::uuid",
    )
    .bind(&policy_id)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(!permits_iso(&mut worker, &kid, "a", "2026-03-08T06:59:59Z").await);
    assert!(permits_iso(&mut worker, &kid, "a", "2026-03-08T07:00:00Z").await);
    assert!(!permits_iso(&mut worker, &kid, "a", "2026-11-01T05:30:00Z").await);
    assert!(!permits_iso(&mut worker, &kid, "a", "2026-11-01T06:30:00Z").await);
    assert!(permits_iso(&mut worker, &kid, "a", "2026-11-01T07:30:00Z").await);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_oidc_group_inheritance_fail_closed_and_override() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let child = account(&mut owner, PROVIDER, true, FUTURE).await;
    let adult = account(&mut owner, PROVIDER, true, FUTURE).await;
    let unenrolled = account(&mut owner, PROVIDER, true, FUTURE).await;

    // 2027-01-15T22:30:00Z (ms = 1800052200000) is inside quiet 22:00-07:00 UTC.
    let quiet_iso = "2027-01-15T22:30:00Z";
    let quiet_ms: i64 = 1_800_052_200_000;
    let day_iso = "2027-01-15T12:00:00Z";
    let day_ms: i64 = 1_800_014_400_000;

    // Household policy on OIDC group 'Family': quiet 22:00-07:00 UTC.
    sqlx::query(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_oidc_group_id, active, zone,
              quiet_start_minute, quiet_end_minute)
         VALUES ('oidc_group', 'Family', true, 'UTC', 1320, 420)",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    // Also attach a local_group policy (study 11:00-13:00 UTC allowing only 'b') to child.
    let lg_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.local_groups (name, created_by_user_id, updated_by_user_id)
         VALUES ('Kids', $1::uuid, $1::uuid) RETURNING id::text",
    )
    .bind(&adult.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.local_group_memberships (group_id, user_id, active, updated_by_user_id)
         VALUES ($1::uuid, $2::uuid, true, $3::uuid)",
    )
    .bind(&lg_id)
    .bind(&child.user)
    .bind(&adult.user)
    .execute(&mut owner)
    .await
    .unwrap();
    let lg_pol: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_local_group_id, active, zone,
              study_start_minute, study_end_minute)
         VALUES ('local_group', $1::uuid, true, 'UTC', 660, 780)
         RETURNING id::text",
    )
    .bind(&lg_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
         VALUES ($1::uuid, 'study_allow', 'b', true)",
    )
    .bind(&lg_pol)
    .execute(&mut owner)
    .await
    .unwrap();

    // Enroll child as fresh 'present' in 'Family', adult as fresh 'absent' in 'Family'.
    enroll_oidc_group(&db, &child, FAMILY_RULE, "Family", "present", day_ms).await;
    let adult_rule = "00000000-0000-4000-8000-00000000f002";
    enroll_oidc_group(&db, &adult, adult_rule, "Family", "absent", quiet_ms).await;

    let mut api = connect(&db.0, API).await;

    // Multi-policy intersection: during 12:00Z local_group study allows 'b', denies 'a'.
    assert!(permits_iso(&mut api, &child, "b", day_iso).await);
    assert!(!permits_iso(&mut api, &child, "a", day_iso).await);

    // Disabling the local_group removes its restriction while OIDC 'Family' stays active.
    sqlx::query(
        "UPDATE openmettle.local_groups SET disabled_at = clock_timestamp() WHERE id = $1::uuid",
    )
    .bind(&lg_id)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(permits_iso(&mut api, &child, "a", day_iso).await);

    // Fresh 'present' inherits 'Family' quiet hours at 22:30Z.
    sqlx::query(
        "UPDATE openmettle.membership_observations
            SET issued_ms = $2 - 1000, expires_ms = $2 + 600000
          WHERE approval_id = $1::uuid",
    )
    .bind(&child.approval)
    .bind(quiet_ms)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(!permits_iso(&mut api, &child, "a", quiet_iso).await);

    // Confirmed fresh 'absent' and unenrolled users are completely unaffected even at 22:30Z.
    assert!(permits_iso(&mut api, &adult, "a", quiet_iso).await);
    assert!(permits_iso(&mut api, &unenrolled, "a", quiet_iso).await);

    // Every bad OIDC observation state fails closed even during daytime (12:00Z)!
    let reset_day = async |owner: &mut PgConnection| {
        sqlx::query("UPDATE openmettle.users SET session_generation = 0 WHERE id = $1::uuid")
            .bind(&child.user)
            .execute(&mut *owner)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE openmettle.membership_observations
                SET issued_ms = $2 - 1000,
                    expires_ms = $2 + 600000,
                    epoch = 1,
                    observation = ROW('present', (observation).change_id)::openmettle.membership_evidence,
                    approval_generation = 0,
                    user_generation = 0
              WHERE approval_id = $1::uuid",
        )
        .bind(&child.approval)
        .bind(day_ms)
        .execute(&mut *owner)
        .await
        .unwrap();
    };
    for (label, sql) in [
        (
            "expired",
            format!(
                "UPDATE openmettle.membership_observations SET expires_ms = {day_ms} WHERE approval_id = '{}'::uuid",
                child.approval
            ),
        ),
        (
            "partial",
            format!(
                "UPDATE openmettle.membership_observations SET observation = ROW('partial', (observation).change_id)::openmettle.membership_evidence WHERE approval_id = '{}'::uuid",
                child.approval
            ),
        ),
        (
            "ambiguous",
            format!(
                "UPDATE openmettle.membership_observations SET observation = ROW('ambiguous', (observation).change_id)::openmettle.membership_evidence WHERE approval_id = '{}'::uuid",
                child.approval
            ),
        ),
        (
            "stale",
            format!(
                "UPDATE openmettle.membership_observations SET observation = ROW('stale', (observation).change_id)::openmettle.membership_evidence WHERE approval_id = '{}'::uuid",
                child.approval
            ),
        ),
        (
            "failed",
            format!(
                "UPDATE openmettle.membership_observations SET observation = ROW('failed', (observation).change_id)::openmettle.membership_evidence WHERE approval_id = '{}'::uuid",
                child.approval
            ),
        ),
        (
            "missing_never_observed",
            format!(
                "UPDATE openmettle.membership_observations SET issued_ms = NULL, expires_ms = NULL, epoch = NULL, approval_generation = NULL, user_generation = NULL, observation = ROW('missing', (observation).change_id)::openmettle.membership_evidence WHERE approval_id = '{}'::uuid",
                child.approval
            ),
        ),
        (
            "mismatched_user_generation",
            format!(
                "UPDATE openmettle.users SET session_generation = 1 WHERE id = '{}'::uuid",
                child.user
            ),
        ),
    ] {
        reset_day(&mut owner).await;
        assert!(
            permits_iso(&mut api, &child, "a", day_iso).await,
            "pre {label}"
        );
        owner.execute(AssertSqlSafe(sql)).await.unwrap();
        assert!(
            !permits_iso(&mut api, &child, "a", day_iso).await,
            "fail-closed {label}"
        );
    }

    // Per-user `override_group_schedules = true` exempts the user from group schedules AND OIDC fail-closed!
    sqlx::query(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_user_id, active, zone, override_group_schedules)
         VALUES ('user', $1::uuid, true, 'UTC', true)",
    )
    .bind(&child.user)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(permits_iso(&mut api, &child, "a", day_iso).await);
    assert!(permits_iso(&mut api, &child, "a", quiet_iso).await);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_http_admission_preview_study_fallback_and_catalog_visibility() {
    let db = TestDb::migrated().await;
    super::run_admission::seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let origin = "https://app.example.test";
    let cookie = format!(
        "Cookie: __Host-openmettle-session={}\r\nOrigin: {origin}",
        seeded_session(&db, &actor, 51, None).await
    );
    let server = ApiServer::start(&db);

    // Create a project whose default model is "a", and a conversation inside it.
    let (status, proj) = server.call(
        &cookie,
        "POST",
        "/v1/projects",
        Some("fam-proj-1"),
        Some(&json!({"name": "Family Project", "defaults": {"model_config": {"model": "a"}}})),
    );
    assert_eq!(status, 201, "{proj}");
    let proj_id = proj["project_id"].as_str().unwrap();
    let scope_id = proj["scope_id"].as_str().unwrap();
    let (status, conv) = server.call(
        &cookie,
        "POST",
        "/v1/conversations",
        Some("fam-conv-1"),
        Some(&json!({"scope_id": scope_id})),
    );
    assert_eq!(status, 201, "{conv}");
    let conv_id = conv["conversation_id"].as_str().unwrap();
    let branch_id = conv["branch_id"].as_str().unwrap();

    // Admit one run BEFORE quiet hours so we can verify exact idempotent replay during quiet hours.
    let first_body = json!({
        "conversation_id": conv_id,
        "branch_id": branch_id,
        "proposal": {
            "expected_head_message_id": null,
            "turn": {"mode": "append", "input_message_id": INPUT_1, "parts": [{"text": "hello"}]},
            "selection": {"model": "a"}
        }
    });
    let (status, first_run) = server.call(
        &cookie,
        "POST",
        "/v1/runs",
        Some("fam-replay-key"),
        Some(&first_body),
    );
    assert_eq!(status, 201, "{first_run}");

    // Activate 24h-minus-1m quiet hours covering the current UTC minute (start = now-1, end = now-2).
    let (cur_min,): (i32,) = sqlx::query_as(
        "SELECT (extract(hour FROM clock_timestamp() AT TIME ZONE 'UTC')::int * 60
               + extract(minute FROM clock_timestamp() AT TIME ZONE 'UTC')::int)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let q_start = (cur_min + 1439) % 1440;
    let q_end = (cur_min + 1438) % 1440;
    let policy_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_user_id, active, zone, quiet_start_minute, quiet_end_minute)
         VALUES ('user', $1::uuid, true, 'UTC', $2, $3)
         RETURNING id::text",
    )
    .bind(&actor.user)
    .bind(q_start as i16)
    .bind(q_end as i16)
    .fetch_one(&mut owner)
    .await
    .unwrap();

    // GET /v1/models, GET /v1/presets, GET /v1/presets/{id}, and PUT /v1/projects
    // (check_project_defaults) stay UNCHANGED during quiet hours (Owner Decision #2).
    let (status, models_resp) = server.call(&cookie, "GET", "/v1/models", None, None);
    assert_eq!(status, 200, "{models_resp}");
    assert_eq!(models_resp["items"].as_array().unwrap().len(), 2);
    let (status, presets_resp) = server.call(&cookie, "GET", "/v1/presets", None, None);
    assert_eq!(status, 200, "{presets_resp}");
    assert!(!presets_resp["items"].as_array().unwrap().is_empty());
    let (status, preset_resp) = server.call(&cookie, "GET", "/v1/presets/study", None, None);
    assert_eq!(status, 200, "{preset_resp}");
    let (status, proj_upd) = server.call(
        &cookie,
        "PUT",
        &format!("/v1/projects/{proj_id}"),
        Some("fam-proj-upd"),
        Some(&json!({"name": "Family Project Updated", "instructions": "", "defaults": {"model_config": {"model": "a"}}})),
    );
    assert_eq!(status, 200, "{proj_upd}");

    // Exact idempotent replay during quiet hours succeeds with 200 OK and returns the same run!
    let (status, replayed) = server.call(
        &cookie,
        "POST",
        "/v1/runs",
        Some("fam-replay-key"),
        Some(&first_body),
    );
    assert_eq!(status, 200, "{replayed}");
    assert_eq!(replayed["run_id"], first_run["run_id"]);

    let (status, conv2) = server.call(
        &cookie,
        "POST",
        "/v1/conversations",
        Some("fam-conv-2"),
        Some(&json!({"scope_id": scope_id})),
    );
    assert_eq!(status, 201, "{conv2}");
    let conv2_id = conv2["conversation_id"].as_str().unwrap();
    let branch2_id = conv2["branch_id"].as_str().unwrap();
    let preview2_path =
        format!("/v1/conversations/{conv2_id}/branches/{branch2_id}/effective-configuration");

    // Fresh /v1/runs and effective-configuration during quiet hours return 403 policy, while an
    // unknown catalog model still returns 400 validation (not masked as 403 policy).
    let fresh_proposal = json!({
        "expected_head_message_id": null,
        "turn": {"mode": "append", "input_message_id": INPUT_2, "parts": [{"text": "night"}]},
        "selection": {}
    });
    let unknown_proposal = json!({
        "expected_head_message_id": null,
        "turn": {"mode": "append", "input_message_id": INPUT_2, "parts": [{"text": "night"}]},
        "selection": {"model": "does-not-exist"}
    });
    let (status, err) = server.call(
        &cookie,
        "POST",
        &preview2_path,
        None,
        Some(&unknown_proposal),
    );
    assert_eq!(status, 400, "{err}");
    assert_eq!(err["code"], "validation");
    let (status, err) = server.call(&cookie, "POST", &preview2_path, None, Some(&fresh_proposal));
    assert_eq!(status, 403, "{err}");
    assert_eq!(err["code"], "policy");
    let (status, err) = server.call(
        &cookie,
        "POST",
        "/v1/runs",
        Some("fam-quiet-fresh"),
        Some(&json!({"conversation_id": conv2_id, "branch_id": branch2_id, "proposal": fresh_proposal})),
    );
    assert_eq!(status, 403, "{err}");
    assert_eq!(err["code"], "policy");

    // Switch to active study hours allowing ONLY model "b" (project default "a" is restricted).
    sqlx::query(
        "UPDATE openmettle.family_policies
            SET quiet_start_minute = NULL,
                quiet_end_minute = NULL,
                study_start_minute = $2,
                study_end_minute = $3,
                revision = revision + 1
          WHERE id = $1::uuid",
    )
    .bind(&policy_id)
    .bind(q_start as i16)
    .bind(q_end as i16)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
         VALUES ($1::uuid, 'study_allow', 'b', true)",
    )
    .bind(&policy_id)
    .execute(&mut owner)
    .await
    .unwrap();

    // Explicit disallowed model "a" or preset "study" -> 403 policy.
    for sel in [json!({"model": "a"}), json!({"preset": "study"})] {
        let explicit = json!({
            "expected_head_message_id": null,
            "turn": {"mode": "append", "input_message_id": INPUT_2, "parts": [{"text": "study"}]},
            "selection": sel
        });
        let (status, err) = server.call(&cookie, "POST", &preview2_path, None, Some(&explicit));
        assert_eq!(status, 403, "{err}");
        assert_eq!(err["code"], "policy");
    }

    // Omitted selection (`selection: {}`): auto-skips restricted project default "a" and selects "b"!
    let (status, prev) = server.call(&cookie, "POST", &preview2_path, None, Some(&fresh_proposal));
    assert_eq!(status, 200, "{prev}");
    assert_eq!(prev["model"], "b");
    let (status, run_b) = server.call(
        &cookie,
        "POST",
        "/v1/runs",
        Some("fam-study-fallback"),
        Some(&json!({"conversation_id": conv2_id, "branch_id": branch2_id, "proposal": fresh_proposal})),
    );
    assert_eq!(status, 201, "{run_b}");
    let run_b_id = run_b["run_id"].as_str().unwrap();
    let cfg_bytes: Vec<u8> =
        sqlx::query_scalar("SELECT config_snapshot FROM openmettle.runs WHERE id = $1::uuid")
            .bind(run_b_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let cfg: Value = serde_json::from_slice(&cfg_bytes).unwrap();
    assert_eq!(cfg["effective"]["model"], "b");
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_worker_recheck_and_gateway_handoff_dispatch_refusal() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &actor).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // Admit conversation v1 runs and one synthetic non-conversation run.
    let mut api = connect(&db.0, API).await;
    let conv_id = chat(&db, &scope, "personal", &actor).await;
    let catalog = openmettle_core::model_config::Catalog::load(CATALOG).unwrap();
    let sel_a: openmettle_core::model_config::Selection =
        serde_json::from_value(json!({"model": "a"})).unwrap();
    let cfg_a = serde_json::to_vec(&openmettle_core::model_config::ConfigSnapshot {
        effective: catalog
            .resolve(&Default::default(), &sel_a, None, |_, _| true)
            .unwrap(),
        required_capabilities: Default::default(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: None,
    })
    .unwrap();
    let admit_one = async |api: &mut PgConnection, key: &str, format: &str, cfg: &[u8]| -> String {
        let (branch, msg) = quotas::branch_and_message(api, &scope, &conv_id).await;
        let mut tx = WriteTransaction::begin(api).await.unwrap();
        let adm = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &actor.user,
                    conversation: &conv_id,
                    branch: &branch,
                    message: &msg,
                    key,
                    format,
                    version: SNAPSHOT_VERSION,
                    input: b"{}",
                    config: cfg,
                },
                actor_approval_id: &actor.approval,
                capabilities: &[],
                requested_rounds: Some(3),
                now_ms: NOW,
                cost_qualified: None,
            },
            &LIMITS,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        match adm {
            Admission::Admitted { run_id, .. } => run_id,
            other => panic!("expected admission, got {other:?}"),
        }
    };
    let claimed_run_id = admit_one(&mut api, "fam-w-1", SNAPSHOT_FORMAT, &cfg_a).await;
    let mut worker = connect(&db.0, WORKER).await;
    let active_claim = queue::claim_next(&mut worker, &CLAIMS, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active_claim.run_id, claimed_run_id);

    let queued_run_id = admit_one(&mut api, "fam-w-2", SNAPSHOT_FORMAT, &cfg_a).await;
    let synthetic_run_id =
        admit_one(&mut api, "fam-w-syn", "openmettle.synthetic-run", b"{}").await;
    let bad_snap_run_id = admit_one(&mut api, "fam-w-bad", SNAPSHOT_FORMAT, b"{}").await;

    let res_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 150)
         RETURNING id::text",
    )
    .bind(&scope)
    .bind(&actor.user)
    .bind(&actor.approval)
    .bind(&active_claim.run_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();

    let insert_req =
        async |worker: &mut PgConnection, req_id: &str, round: i32, secret: &[u8; 32]| {
            sqlx::query(
                "INSERT INTO openmettle.gateway_requests
                 (id, reservation_id, scope_id, actor_user_id, approval_id, installation,
                  model, units, dispatch_hash, run_id, round)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid,
                     'a', 50, sha256($7), $8::uuid, $9)",
            )
            .bind(req_id)
            .bind(&res_id)
            .bind(&scope)
            .bind(&actor.user)
            .bind(&actor.approval)
            .bind(INSTALL)
            .bind(secret.as_slice())
            .bind(&active_claim.run_id)
            .bind(round)
            .execute(worker)
            .await
            .unwrap();
        };

    // Round 1: hand off and confirm BEFORE family policy is enabled.
    let s1 = [0x11u8; 32];
    let b1 = [0x21u8; 32];
    let req1 = "00000000-0000-4000-8000-00000000f201";
    insert_req(&mut worker, req1, 1, &s1).await;
    {
        let mut tx = worker.begin().await.unwrap();
        let ok: bool = sqlx::query_scalar(
            "SELECT openmettle.gateway_handoff_round($1::uuid, $2, $3::uuid, sha256($4))",
        )
        .bind(req1)
        .bind(s1.as_slice())
        .bind(&active_claim.claim_token)
        .bind(b1.as_slice())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(ok);
        sqlx::query("SELECT openmettle.gateway_handoff_round_confirm($1::uuid, $2, $3::uuid)")
            .bind(req1)
            .bind(s1.as_slice())
            .bind(&active_claim.claim_token)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Round 2: reserve before policy, then enable disabled-model policy for model "a".
    let s2 = [0x12u8; 32];
    let b2 = [0x22u8; 32];
    let req2 = "00000000-0000-4000-8000-00000000f202";
    insert_req(&mut worker, req2, 2, &s2).await;

    // Malformed `openmettle.conversation` v1 snapshot fails closed even with no policy row.
    assert_eq!(
        queue::recheck_run(
            &mut worker,
            &RunRecheckRequest {
                scope_id: &scope,
                run_id: &bad_snap_run_id,
                actor_approval_id: &actor.approval,
                capabilities: &[],
                extra_target: None,
                now_ms: NOW,
            },
        )
        .await
        .unwrap(),
        RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy))
    );

    let policy_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_user_id, active, zone)
         VALUES ('user', $1::uuid, true, 'UTC') RETURNING id::text",
    )
    .bind(&actor.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
         VALUES ($1::uuid, 'disabled', 'a', true)",
    )
    .bind(&policy_id)
    .execute(&mut owner)
    .await
    .unwrap();

    // Synthetic non-conversation run is unaffected by family policy recheck.
    assert_eq!(
        queue::recheck_run(
            &mut worker,
            &RunRecheckRequest {
                scope_id: &scope,
                run_id: &synthetic_run_id,
                actor_approval_id: &actor.approval,
                capabilities: &[],
                extra_target: None,
                now_ms: NOW,
            },
        )
        .await
        .unwrap(),
        RunRecheckOutcome::Continue
    );

    // Enforcement point 3: gateway_handoff_round refuses round 2, and confirm fails with 42501 on req1!
    let ok2: bool = sqlx::query_scalar(
        "SELECT openmettle.gateway_handoff_round($1::uuid, $2, $3::uuid, sha256($4))",
    )
    .bind(req2)
    .bind(s2.as_slice())
    .bind(&active_claim.claim_token)
    .bind(b2.as_slice())
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert!(
        !ok2,
        "round 2 handoff must be refused once model 'a' is disabled"
    );
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.gateway_handoff_round_confirm($1::uuid, $2, $3::uuid)")
                .bind(req1)
                .bind(s1.as_slice())
                .bind(&active_claim.claim_token)
                .execute(&mut worker)
                .await
        ),
        "42501"
    );

    // Enforcement point 4: gateway_dispatch refuses already-handed-off round 1 (returns no row)!
    let mut gw = connect(&db.0, pg::GATEWAY).await;
    let dispatched: Option<(bool,)> =
        sqlx::query_as("SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(req1)
            .bind(b1.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap();
    assert!(
        dispatched.is_none(),
        "gateway_dispatch must refuse once family policy blocks model"
    );

    // Enforcement point 2: recheck_run cancels queued run, recheck_leased settles running run!
    assert_eq!(
        queue::recheck_run(
            &mut worker,
            &RunRecheckRequest {
                scope_id: &scope,
                run_id: &queued_run_id,
                actor_approval_id: &actor.approval,
                capabilities: &[],
                extra_target: None,
                now_ms: NOW,
            },
        )
        .await
        .unwrap(),
        RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy))
    );
    let outcome = queue::recheck_leased(
        &mut worker,
        &active_claim.lease(),
        &RunRecheckRequest {
            scope_id: &active_claim.scope_id,
            run_id: &active_claim.run_id,
            actor_approval_id: &active_claim.actor_approval_id,
            capabilities: &[],
            extra_target: None,
            now_ms: NOW,
        },
        &LEASES,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy))
    );
    for run_id in [&queued_run_id, &active_claim.run_id] {
        let (state, reason): (String, Option<String>) =
            sqlx::query_as("SELECT state, cancel_reason FROM openmettle.runs WHERE id = $1::uuid")
                .bind(run_id)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        assert_eq!(state, "cancelled");
        assert_eq!(reason.as_deref(), Some("revoked"));
    }

    // Once the run is cancelled, worker sweep closes undispatched req1 as `not_dispatched` at 0 charge!
    let closed: Option<String> =
        sqlx::query_scalar("SELECT openmettle.gateway_close_unreported($1::uuid)")
            .bind(req1)
            .fetch_one(&mut worker)
            .await
            .unwrap();
    assert_eq!(closed.as_deref(), Some("not_dispatched"));
    let (rev, final_flag, measured, outstanding): (i64, bool, Option<String>, String) =
        sqlx::query_as(
            "SELECT revision, final, measured::text, outstanding::text
               FROM openmettle.gateway_settlements WHERE request_id = $1::uuid",
        )
        .bind(req1)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(
        (rev, final_flag, measured, outstanding),
        (0, true, None, "0".into())
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_store_api_authz_audit_idempotency_and_disable_serialization() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let other_admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let member = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    make_admin(&mut owner, &other_admin).await;

    let mut api = connect(&db.0, API).await;
    let group_id =
        applied(store::create_local_group(&mut api, &ctx(&admin, "grp-1"), "FamilyLocal").await);

    let input = FamilyPolicyInput {
        zone: "Europe/London".into(),
        quiet: Hours::parse_window("22:00-07:00"),
        study: Hours::parse_window("16:00-18:00"),
        override_group_schedules: false,
    };
    let lg_grantee = FamilyGrantee::LocalGroup(group_id.clone());

    // Non-admin refused.
    assert_eq!(
        denied(
            store::set_family_policy(&mut api, &ctx(&member, "non-adm"), &lg_grantee, &input).await
        ),
        DenialReason::Policy(PolicyReason::NotAccountAdmin)
    );
    // Unknown timezone refused cleanly with InvalidInput("zone").
    assert!(matches!(
        store::set_family_policy(
            &mut api,
            &ctx(&admin, "bad-tz"),
            &lg_grantee,
            &FamilyPolicyInput {
                zone: "Mars/Olympus".into(),
                ..input.clone()
            },
        )
        .await,
        Err(StoreError::InvalidInput("zone"))
    ));
    // Missing user/group refused with NotFound.
    assert!(matches!(
        store::set_family_policy(
            &mut api,
            &ctx(&admin, "missing-u"),
            &FamilyGrantee::User(UNKNOWN.into()),
            &input,
        )
        .await,
        Err(StoreError::NotFound)
    ));
    // override_group_schedules on group refused.
    assert!(matches!(
        store::set_family_policy(
            &mut api,
            &ctx(&admin, "bad-ov"),
            &lg_grantee,
            &FamilyPolicyInput {
                override_group_schedules: true,
                ..input.clone()
            },
        )
        .await,
        Err(StoreError::InvalidInput("override_group_schedules"))
    ));

    // Apply, replay idempotently, reject conflicting reuse, reject UNCHANGED on new key.
    let pid = applied(
        store::set_family_policy(&mut api, &ctx(&admin, "fp-set-1"), &lg_grantee, &input).await,
    );
    assert_eq!(
        store::set_family_policy(&mut api, &ctx(&admin, "fp-set-1"), &lg_grantee, &input)
            .await
            .unwrap(),
        WriteOutcome::Replayed {
            target_id: pid.clone()
        }
    );
    assert_eq!(
        conflict(store::clear_family_policy(&mut api, &ctx(&admin, "fp-set-1"), &lg_grantee).await),
        store::KEY_REUSED
    );
    assert_eq!(
        conflict(
            store::set_family_policy(&mut api, &ctx(&admin, "fp-set-dup"), &lg_grantee, &input)
                .await
        ),
        "target is already in the requested state"
    );

    // Model rules (study_allow + disabled) and read helper.
    assert_eq!(
        applied(
            store::set_family_policy_model(
                &mut api,
                &ctx(&admin, "fp-m-1"),
                &lg_grantee,
                FamilyPolicyRuleKind::StudyAllow,
                "b",
                true,
            )
            .await
        ),
        pid
    );
    assert_eq!(
        applied(
            store::set_family_policy_model(
                &mut api,
                &ctx(&admin, "fp-m-2"),
                &lg_grantee,
                FamilyPolicyRuleKind::Disabled,
                "a",
                true,
            )
            .await
        ),
        pid
    );
    let rec = store::load_family_policy(&mut api, &lg_grantee)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec.id, pid);
    assert!(rec.active);
    assert_eq!(rec.revision, 1);
    assert!(rec.study_models.contains("b"));
    assert!(rec.disabled_models.contains("a"));

    // Clear and replay clear.
    assert_eq!(
        applied(store::clear_family_policy(&mut api, &ctx(&admin, "fp-clr-1"), &lg_grantee).await),
        pid
    );
    assert_eq!(
        store::clear_family_policy(&mut api, &ctx(&admin, "fp-clr-1"), &lg_grantee)
            .await
            .unwrap(),
        WriteOutcome::Replayed {
            target_id: pid.clone()
        }
    );
    let rec = store::load_family_policy(&mut api, &lg_grantee)
        .await
        .unwrap()
        .unwrap();
    assert!(!rec.active);
    assert_eq!(rec.revision, 2);

    // Verify user audit rows.
    let trail = audit(&db).await;
    let fam_actions: Vec<&str> = trail
        .iter()
        .filter(|row| row.3 == "family_policy")
        .map(|row| row.2.as_str())
        .collect();
    assert_eq!(
        fam_actions,
        vec![
            "family_policy.set",
            "family_policy.model_study_allow",
            "family_policy.model_disable",
            "family_policy.clear",
        ]
    );

    // Concurrent admin disable via sessions::disable_user serializes cleanly with set_family_policy.
    let policy =
        sessions::Policy::new(Duration::from_secs(60), 10, Duration::from_secs(30)).unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT session_generation FROM openmettle.users WHERE id = $1::uuid")
            .bind(&admin.user)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    sessions::disable_user(&mut api, &admin.user, generation, &policy)
        .await
        .unwrap();
    assert_eq!(
        denied(
            store::set_family_policy(
                &mut api,
                &ctx(&admin, "after-disable"),
                &FamilyGrantee::OidcGroup("Family".into()),
                &input,
            )
            .await
        ),
        DenialReason::InactivePrincipal
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_admin_cli_e2e_and_audit() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let user = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &user).await;

    let run_admin = |label: &str, args: &[&str]| {
        let mut cmd = admin_binary();
        cmd.env("OPENMETTLE_ADMIN_DATABASE_URL", db.url(OWNER))
            .args(args);
        run_cli(&mut cmd, &format!("openmettle-admin family ({label})"))
    };

    // 1. Set household OIDC-group policy via real openmettle-admin binary.
    let out = run_admin(
        "set-policy initial",
        &[
            "family",
            "set-policy",
            "--oidc-group",
            "Family",
            "--zone",
            "Europe/London",
            "--quiet",
            "22:00-07:00",
            "--study",
            "16:00-18:00",
            "--operator-id",
            OPERATOR_ID,
            "--request-key",
            "cli-fam-1",
            "--reason",
            "initial household schedule",
        ],
    );
    assert!(out.status.success(), "set-policy failed: {}", stderr(&out));

    // 2. Exact replay with same request-key succeeds idempotently (revision stays 1).
    let replay = run_admin(
        "set-policy replay",
        &[
            "family",
            "set-policy",
            "--oidc-group",
            "Family",
            "--zone",
            "Europe/London",
            "--quiet",
            "22:00-07:00",
            "--study",
            "16:00-18:00",
            "--operator-id",
            OPERATOR_ID,
            "--request-key",
            "cli-fam-1",
            "--reason",
            "initial household schedule",
        ],
    );
    assert!(
        replay.status.success(),
        "replay failed: {}",
        stderr(&replay)
    );

    // 3. Conflicting request-key reuse fails.
    let conflict_out = run_admin(
        "set-policy conflicting request-key",
        &[
            "family",
            "set-policy",
            "--oidc-group",
            "Other",
            "--zone",
            "UTC",
            "--operator-id",
            OPERATOR_ID,
            "--request-key",
            "cli-fam-1",
            "--reason",
            "conflicting reuse",
        ],
    );
    assert!(!conflict_out.status.success());

    // 4. Add a study_allow model and verify audit rows.
    let model_out = run_admin(
        "set-model study_allow",
        &[
            "family",
            "set-model",
            "--oidc-group",
            "Family",
            "--kind",
            "study_allow",
            "--model",
            "b",
            "--enable",
            "--operator-id",
            OPERATOR_ID,
            "--request-key",
            "cli-fam-2",
            "--reason",
            "allow study model b",
        ],
    );
    assert!(
        model_out.status.success(),
        "set-model failed: {}",
        stderr(&model_out)
    );

    // 5. Reject invalid HH:MM-HH:MM (equal start/end, out-of-range) and override on group.
    for (label, bad_args) in [
        (
            "equal start/end quiet window",
            &[
                "family",
                "set-policy",
                "--oidc-group",
                "Family",
                "--zone",
                "UTC",
                "--quiet",
                "22:00-22:00",
                "--operator-id",
                OPERATOR_ID,
                "--request-key",
                "cli-bad-1",
                "--reason",
                "bad window",
            ][..],
        ),
        (
            "override-group-schedules on group",
            &[
                "family",
                "set-policy",
                "--oidc-group",
                "Family",
                "--zone",
                "UTC",
                "--override-group-schedules",
                "--operator-id",
                OPERATOR_ID,
                "--request-key",
                "cli-bad-2",
                "--reason",
                "override on group",
            ][..],
        ),
        (
            "unknown timezone",
            &[
                "family",
                "set-policy",
                "--oidc-group",
                "Family",
                "--zone",
                "Mars/Olympus",
                "--operator-id",
                OPERATOR_ID,
                "--request-key",
                "cli-bad-3",
                "--reason",
                "unknown tz",
            ][..],
        ),
    ] {
        let bad = run_admin(label, bad_args);
        assert!(!bad.status.success(), "expected failure for {label}");
    }

    // 6. Clear policy and verify operator audit trail.
    let clear = run_admin(
        "clear-policy",
        &[
            "family",
            "clear-policy",
            "--oidc-group",
            "Family",
            "--operator-id",
            OPERATOR_ID,
            "--request-key",
            "cli-fam-3",
            "--reason",
            "holiday pause",
        ],
    );
    assert!(
        clear.status.success(),
        "clear-policy failed: {}",
        stderr(&clear)
    );

    let actions: Vec<(String, String)> = sqlx::query_as(
        "SELECT actor_kind, action FROM openmettle.authorization_audit
          WHERE operator_id = $1::uuid ORDER BY occurred_at, id",
    )
    .bind(OPERATOR_ID)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        actions,
        vec![
            ("operator".into(), "family_policy.set".into()),
            ("operator".into(), "family_policy.model_study_allow".into()),
            ("operator".into(), "family_policy.clear".into()),
        ]
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_role_boundaries_triggers_and_upgrade_34_to_35() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..34]).await.unwrap();

    // Seed pre-upgrade state on schema 34.
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let user = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &user).await;
    let before = snapshot_at(
        &mut owner,
        &["users", "account_admins", "authorization_audit"],
        34,
    )
    .await;

    // Upgrade 34 -> 35 and verify existing data intact + boundaries clean.
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(
        snapshot_at(
            &mut owner,
            &["users", "account_admins", "authorization_audit"],
            34,
        )
        .await,
        before
    );
    let empty_count: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM openmettle.family_policies),
                (SELECT count(*) FROM openmettle.family_policy_models)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(empty_count, (0, 0));

    // Role privilege boundaries: worker, gateway, issuance have NO table grants on family tables;
    // gateway & issuance have NO EXECUTE on family_policy_permits; API has NO DELETE.
    for role in [WORKER, pg::GATEWAY, ISSUANCE] {
        for table in [
            "openmettle.family_policies",
            "openmettle.family_policy_models",
        ] {
            for priv_name in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
                let has: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
                    .bind(role)
                    .bind(table)
                    .bind(priv_name)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
                assert!(!has, "{role} must not have {priv_name} on {table}");
            }
        }
    }
    for (role, expect_exec) in [
        (API, true),
        (WORKER, true),
        (pg::GATEWAY, false),
        (ISSUANCE, false),
    ] {
        let has: bool = sqlx::query_scalar(
            "SELECT has_function_privilege($1, 'openmettle.family_policy_permits(uuid,uuid,text,timestamptz)', 'EXECUTE')",
        )
        .bind(role)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(has, expect_exec, "{role} EXECUTE on family_policy_permits");
    }
    for (role, expect_exec) in [
        (API, true),
        (WORKER, false),
        (pg::GATEWAY, false),
        (ISSUANCE, false),
    ] {
        let has: bool = sqlx::query_scalar(
            "SELECT has_function_privilege($1, 'openmettle.family_policy_filter_models(uuid,uuid,text[],timestamptz)', 'EXECUTE')",
        )
        .bind(role)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            has, expect_exec,
            "{role} EXECUTE on family_policy_filter_models"
        );
    }

    // Trigger guards on openmettle_api:
    // - NULL updated_by_user_id refused (23514)
    // - unknown timezone refused (23514)
    // - DELETE refused (42501)
    // - non-increasing revision on UPDATE refused (23514)
    let mut api = connect(&db.0, API).await;
    expect_state(
        &mut api,
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_oidc_group_id, active, zone)
         VALUES ('oidc_group', 'Family', true, 'UTC')",
        "23514",
    )
    .await;
    expect_state(
        &mut api,
        &format!(
            "INSERT INTO openmettle.family_policies
                 (grantee_kind, grantee_oidc_group_id, active, zone, updated_by_user_id)
             VALUES ('oidc_group', 'Family', true, 'Mars/Olympus', '{}'::uuid)",
            user.user
        ),
        "23514",
    )
    .await;
    let pid: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_oidc_group_id, active, zone, updated_by_user_id)
         VALUES ('oidc_group', 'Family', true, 'UTC', $1::uuid)
         RETURNING id::text",
    )
    .bind(&user.user)
    .fetch_one(&mut api)
    .await
    .unwrap();
    expect_state(&mut api, "DELETE FROM openmettle.family_policies", "42501").await;
    expect_state(
        &mut api,
        "DELETE FROM openmettle.family_policy_models",
        "42501",
    )
    .await;
    expect_state(
        &mut api,
        &format!(
            "UPDATE openmettle.family_policies SET active = false, revision = 1 WHERE id = '{pid}'::uuid"
        ),
        "23514",
    )
    .await;
    expect_state(
        &mut api,
        &format!(
            "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
             VALUES ('{pid}'::uuid, 'disabled', 'a', true)"
        ),
        "23514",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_1_oidc_and_schema_checks() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let child = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;

    let day_iso = "2027-01-15T12:00:00Z";
    let day_ms: i64 = 1_800_014_400_000;
    enroll_oidc_group(&db, &child, FAMILY_RULE, "Family", "present", day_ms).await;

    // Activate OIDC 'Family' policy with quiet hours (22:00-07:00 UTC) so daytime is permitted
    // when evidence is fresh, but any suspended/disabled/superseded enrollment MUST fail closed.
    let policy_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_oidc_group_id, active, zone, quiet_start_minute, quiet_end_minute)
         VALUES ('oidc_group', 'Family', true, 'UTC', 1320, 420)
         RETURNING id::text",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();

    let mut api = connect(&db.0, API).await;
    assert!(permits_iso(&mut api, &child, "a", day_iso).await);

    // P1 #1a: suspended membership_observations (`enabled = false`) must fail closed.
    sqlx::query("UPDATE openmettle.membership_observations SET enabled = false WHERE approval_id = $1::uuid")
        .bind(&child.approval)
        .execute(&mut owner)
        .await
        .unwrap();
    assert!(
        !permits_iso(&mut api, &child, "a", day_iso).await,
        "suspended membership_observations must fail closed"
    );
    sqlx::query(
        "UPDATE openmettle.membership_observations SET enabled = true WHERE approval_id = $1::uuid",
    )
    .bind(&child.approval)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(permits_iso(&mut api, &child, "a", day_iso).await);

    // P1 #1b: disabling the enrolled mapping revision (`v.enabled = false`) must fail closed.
    let (proj_id, _scope_id): (String, String) = sqlx::query_as(
        "SELECT project_id::text, scope_id::text FROM openmettle.membership_observations WHERE approval_id = $1::uuid",
    )
    .bind(&child.approval)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    {
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        grants::record_mapping_revision(
            &mut tx,
            &MappingInput {
                rule: FAMILY_RULE,
                provider: PROVIDER,
                issuer: ISSUER,
                actor: &child.user,
                key: "fam-rule-disable",
                expected_revision: 1,
                selector_kind: "group",
                claim_name: "groups",
                claim_value: "Family",
                binding_format: "openmettle.project-member",
                binding_version: 1,
                binding: proj_id.as_bytes(),
                enabled: false,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    assert!(
        !permits_iso(&mut api, &child, "a", day_iso).await,
        "superseded/disabled mapping revision must fail closed"
    );

    // P1 #1c: updating mapping rule to a DIFFERENT selector ('Other') while `mo` is still enrolled
    // on revision 1 ('Family') must STILL fail closed!
    {
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        grants::record_mapping_revision(
            &mut tx,
            &MappingInput {
                rule: FAMILY_RULE,
                provider: PROVIDER,
                issuer: ISSUER,
                actor: &child.user,
                key: "fam-rule-other",
                expected_revision: 2,
                selector_kind: "group",
                claim_name: "groups",
                claim_value: "Other",
                binding_format: "openmettle.project-member",
                binding_version: 1,
                binding: proj_id.as_bytes(),
                enabled: true,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    assert!(
        !permits_iso(&mut api, &child, "a", day_iso).await,
        "superseded mapping rule moved to another selector must still fail closed on enrolled 'Family' claim"
    );

    // P1 #1d: enrolled on rev 1 ('Other'), later revised to rev 2 ('Family') -> must fail closed!
    let other_child = account(&mut owner, PROVIDER, true, FUTURE).await;
    let other_rule = "00000000-0000-4000-8000-00000000f002";
    enroll_oidc_group(&db, &other_child, other_rule, "Other", "present", day_ms).await;
    assert!(permits_iso(&mut api, &other_child, "a", day_iso).await);
    let other_proj: String = sqlx::query_scalar(
        "SELECT project_id::text FROM openmettle.membership_observations WHERE approval_id = $1::uuid",
    )
    .bind(&other_child.approval)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    {
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        grants::record_mapping_revision(
            &mut tx,
            &MappingInput {
                rule: other_rule,
                provider: PROVIDER,
                issuer: ISSUER,
                actor: &other_child.user,
                key: "fam-rule-promote",
                expected_revision: 1,
                selector_kind: "group",
                claim_name: "groups",
                claim_value: "Family",
                binding_format: "openmettle.project-member",
                binding_version: 1,
                binding: other_proj.as_bytes(),
                enabled: true,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    assert!(
        !permits_iso(&mut api, &other_child, "a", day_iso).await,
        "mapping rule revised to target active 'Family' claim must fail closed until re-observed"
    );

    // P2 #11: half-NULL quiet or study windows must be rejected with 23514 on INSERT and UPDATE.
    for sql in [
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_oidc_group_id, active, zone, quiet_start_minute)
         VALUES ('oidc_group', 'HalfQ1', true, 'UTC', 60)"
            .to_owned(),
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_oidc_group_id, active, zone, quiet_end_minute)
         VALUES ('oidc_group', 'HalfQ2', true, 'UTC', 60)"
            .to_owned(),
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_oidc_group_id, active, zone, study_start_minute)
         VALUES ('oidc_group', 'HalfS1', true, 'UTC', 60)"
            .to_owned(),
        "INSERT INTO openmettle.family_policies (grantee_kind, grantee_oidc_group_id, active, zone, study_end_minute)
         VALUES ('oidc_group', 'HalfS2', true, 'UTC', 60)"
            .to_owned(),
        format!(
            "UPDATE openmettle.family_policies SET quiet_end_minute = NULL, revision = revision + 1 WHERE id = '{policy_id}'::uuid"
        ),
    ] {
        expect_state(&mut owner, &sql, "23514").await;
    }

    // P3 #12: model names with leading/trailing spaces match model_config::name across SQL, store, and CLI.
    applied(
        store::set_family_policy_model(
            &mut api,
            &ctx(&admin, "padded-model-store"),
            &FamilyGrantee::OidcGroup("Family".into()),
            FamilyPolicyRuleKind::Disabled,
            " padded-model ",
            true,
        )
        .await,
    );
    let rec = store::load_family_policy(&mut api, &FamilyGrantee::OidcGroup("Family".into()))
        .await
        .unwrap()
        .unwrap();
    assert!(rec.disabled_models.contains(" padded-model "));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_1_concurrency_locks() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let scope = personal_of(&db, &actor).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let conv_id = chat(&db, &scope, "personal", &actor).await;

    let mut api = connect(&db.0, API).await;
    let group_id =
        applied(store::create_local_group(&mut api, &ctx(&admin, "r1-grp"), "LockGroup").await);

    // P1 #2: add_local_group_member must block on account_admin_lock held FOR SHARE by handoff.
    {
        let mut holder = connect(&db.0, OWNER).await;
        let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut holder)
            .await
            .unwrap();
        let mut tx = holder.begin().await.unwrap();
        sqlx::query("SELECT FROM openmettle.account_admin_lock FOR SHARE")
            .execute(&mut *tx)
            .await
            .unwrap();

        let mut peer_api = connect(&db.0, API).await;
        let admin_c = admin.clone();
        let group_c = group_id.clone();
        let actor_user = actor.user.clone();
        let handle = tokio::spawn(async move {
            store::add_local_group_member(
                &mut peer_api,
                &ctx(&admin_c, "r1-add-member"),
                &group_c,
                &actor_user,
            )
            .await
        });
        wait_for_blocked_peer(&db, holder_pid).await;
        tx.commit().await.unwrap();
        applied(handle.await.unwrap());
    }

    // P1 #3: gateway_dispatch must serialize with concurrent account_admin_lock FOR UPDATE policy
    // activation, while a wrong bearer still returns immediately without taking locks.
    {
        let (branch, msg) = quotas::branch_and_message(&mut api, &scope, &conv_id).await;
        let catalog = openmettle_core::model_config::Catalog::load(CATALOG).unwrap();
        let sel: openmettle_core::model_config::Selection =
            serde_json::from_value(json!({"model": "a"})).unwrap();
        let cfg = serde_json::to_vec(&openmettle_core::model_config::ConfigSnapshot {
            effective: catalog
                .resolve(&Default::default(), &sel, None, |_, _| true)
                .unwrap(),
            required_capabilities: Default::default(),
            policy_revision: "openmettle.authz/1".into(),
            cost_bound: None,
        })
        .unwrap();
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let adm = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &actor.user,
                    conversation: &conv_id,
                    branch: &branch,
                    message: &msg,
                    key: "r1-disp-run",
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: b"{}",
                    config: &cfg,
                },
                actor_approval_id: &actor.approval,
                capabilities: &[],
                requested_rounds: Some(2),
                now_ms: NOW,
                cost_qualified: None,
            },
            &LIMITS,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let run_id = match adm {
            Admission::Admitted { run_id, .. } => run_id,
            other => panic!("unexpected {other:?}"),
        };
        let mut worker = connect(&db.0, WORKER).await;
        let claim = queue::claim_next(&mut worker, &CLAIMS, &LEASES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.run_id, run_id);

        let res_id: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_reservations
                 (id, scope_id, actor_user_id, approval_id, run_id, units)
             VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 100)
             RETURNING id::text",
        )
        .bind(&scope)
        .bind(&actor.user)
        .bind(&actor.approval)
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let req_id = "00000000-0000-4000-8000-00000000f301";
        let secret = [0x31u8; 32];
        let bearer = [0x41u8; 32];
        sqlx::query(
            "INSERT INTO openmettle.gateway_requests
                 (id, reservation_id, scope_id, actor_user_id, approval_id, installation,
                  model, units, dispatch_hash, run_id, round)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid,
                     'a', 50, sha256($7), $8::uuid, 1)",
        )
        .bind(req_id)
        .bind(&res_id)
        .bind(&scope)
        .bind(&actor.user)
        .bind(&actor.approval)
        .bind(INSTALL)
        .bind(secret.as_slice())
        .bind(&run_id)
        .execute(&mut worker)
        .await
        .unwrap();
        let ok: bool = sqlx::query_scalar(
            "SELECT openmettle.gateway_handoff_round($1::uuid, $2, $3::uuid, sha256($4))",
        )
        .bind(req_id)
        .bind(secret.as_slice())
        .bind(&claim.claim_token)
        .bind(bearer.as_slice())
        .fetch_one(&mut worker)
        .await
        .unwrap();
        assert!(ok);

        // Hold account_admin_lock FOR UPDATE and insert a disabled-model policy for 'a' (uncommitted).
        let mut writer = connect(&db.0, OWNER).await;
        let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut writer)
            .await
            .unwrap();
        let mut wtx = writer.begin().await.unwrap();
        sqlx::query("SELECT FROM openmettle.account_admin_lock FOR UPDATE")
            .execute(&mut *wtx)
            .await
            .unwrap();
        let pid: String = sqlx::query_scalar(
            "INSERT INTO openmettle.family_policies (grantee_kind, grantee_user_id, active, zone)
             VALUES ('user', $1::uuid, true, 'UTC') RETURNING id::text",
        )
        .bind(&actor.user)
        .fetch_one(&mut *wtx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
             VALUES ($1::uuid, 'disabled', 'a', true)",
        )
        .bind(&pid)
        .execute(&mut *wtx)
        .await
        .unwrap();

        // Wrong bearer must NOT block on account_admin_lock.
        let mut gw_wrong = connect(&db.0, pg::GATEWAY).await;
        let wrong_res: Option<(bool,)> = sqlx::query_as(
            "SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))",
        )
        .bind(req_id)
        .bind([0xffu8; 32].as_slice())
        .fetch_optional(&mut gw_wrong)
        .await
        .unwrap();
        assert!(wrong_res.is_none());

        // Valid bearer MUST block on account_admin_lock, then observe the committed restriction.
        let mut gw = connect(&db.0, pg::GATEWAY).await;
        let handle = tokio::spawn(async move {
            sqlx::query_as::<_, (bool,)>(
                "SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))",
            )
            .bind(req_id)
            .bind(bearer.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap()
        });
        wait_for_blocked_peer(&db, writer_pid).await;
        wtx.commit().await.unwrap();
        assert!(
            handle.await.unwrap().is_none(),
            "gateway_dispatch must observe the committed family policy and refuse dispatch"
        );
    }

    // P1 #4: admin's set_family_policy must block on concurrent approval withdrawal and be denied.
    {
        let mut withdrawer = connect(&db.0, OWNER).await;
        let withdrawer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut withdrawer)
            .await
            .unwrap();
        let mut tx = withdrawer.begin().await.unwrap();
        sqlx::query(
            "UPDATE openmettle.local_identity_approvals SET active = false WHERE id = $1::uuid",
        )
        .bind(&admin.approval)
        .execute(&mut *tx)
        .await
        .unwrap();

        let mut peer_api = connect(&db.0, API).await;
        let admin_c = admin.clone();
        let handle = tokio::spawn(async move {
            store::set_family_policy(
                &mut peer_api,
                &ctx(&admin_c, "r1-after-approval-withdraw"),
                &FamilyGrantee::OidcGroup("BlockedAdmin".into()),
                &FamilyPolicyInput {
                    zone: "UTC".into(),
                    quiet: None,
                    study: None,
                    override_group_schedules: false,
                },
            )
            .await
        });
        wait_for_blocked_peer(&db, withdrawer_pid).await;
        tx.commit().await.unwrap();
        assert_eq!(
            denied(handle.await.unwrap()),
            DenialReason::InactivePrincipal
        );
        assert!(
            store::load_family_policy(&mut api, &FamilyGrantee::OidcGroup("BlockedAdmin".into()))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_1_fallback_perf_and_worker_recheck() {
    let db = TestDb::migrated().await;
    super::run_admission::seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let origin = "https://app.example.test";
    let cookie = format!(
        "Cookie: __Host-openmettle-session={}\r\nOrigin: {origin}",
        seeded_session(&db, &actor, 61, None).await
    );

    // P2 #6: omitted selection with NO project default -> 400 validation; capability-denied
    // project preset -> 403 policy WITHOUT falling back to model "b".
    {
        let mut cap_catalog: Value = serde_json::from_slice(CATALOG).unwrap();
        cap_catalog["revision"] = json!("catalog/family-cap-1");
        cap_catalog["models"]["a"]["required_capabilities"] = json!({"model.a": "on_by_default"});
        cap_catalog["models"]["a"]["defaults"]["controls"]["output_reserve"] = json!(512);
        cap_catalog["models"]["a"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        cap_catalog["models"]["b"]["context_window"] = json!(8192);
        cap_catalog["models"]["b"]["output_limit"] = json!(2048);
        cap_catalog["models"]["b"]["defaults"]["controls"]["output_reserve"] = json!(512);
        cap_catalog["models"]["b"]["estimator_revision"] = json!("fixture-bound/1");
        cap_catalog["models"]["b"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        let server = ApiServer::start_with_catalog(&db, cap_catalog);
        let (status, proj_empty) = server.call(
            &cookie,
            "POST",
            "/v1/projects",
            Some("r1-empty-proj"),
            Some(&json!({"name": "No Default"})),
        );
        assert_eq!(status, 201, "{proj_empty}");
        let (status, conv_empty) = server.call(
            &cookie,
            "POST",
            "/v1/conversations",
            Some("r1-empty-conv"),
            Some(&json!({"scope_id": proj_empty["scope_id"]})),
        );
        assert_eq!(status, 201, "{conv_empty}");
        let preview_empty = format!(
            "/v1/conversations/{}/branches/{}/effective-configuration",
            conv_empty["conversation_id"].as_str().unwrap(),
            conv_empty["branch_id"].as_str().unwrap()
        );
        let empty_sel = json!({
            "expected_head_message_id": null,
            "turn": {"mode": "append", "input_message_id": INPUT_1, "parts": [{"text": "hi"}]},
            "selection": {}
        });
        let (status, err) = server.call(&cookie, "POST", &preview_empty, None, Some(&empty_sel));
        assert_eq!(
            status, 400,
            "omitted selection with no project default must stay 400: {err}"
        );
        assert_eq!(err["code"], "validation");

        let (status, proj_cap) = server.call(
            &cookie,
            "POST",
            "/v1/projects",
            Some("r1-cap-proj"),
            Some(
                &json!({"name": "Cap Default", "defaults": {"model_config": {"preset": "study"}}}),
            ),
        );
        assert_eq!(status, 201, "{proj_cap}");
        let (status, conv_cap) = server.call(
            &cookie,
            "POST",
            "/v1/conversations",
            Some("r1-cap-conv"),
            Some(&json!({"scope_id": proj_cap["scope_id"]})),
        );
        assert_eq!(status, 201, "{conv_cap}");
        sqlx::query(
            "INSERT INTO openmettle.user_capability_denies (user_id, capability, denied, updated_by_user_id)
             VALUES ($1::uuid, 'model.a', true, $1::uuid)",
        )
        .bind(&actor.user)
        .execute(&mut owner)
        .await
        .unwrap();
        let preview_cap = format!(
            "/v1/conversations/{}/branches/{}/effective-configuration",
            conv_cap["conversation_id"].as_str().unwrap(),
            conv_cap["branch_id"].as_str().unwrap()
        );
        let (status, err) = server.call(&cookie, "POST", &preview_cap, None, Some(&empty_sel));
        assert_eq!(
            status, 403,
            "capability-denied project default must NOT fall back to model 'b': {err}"
        );
        assert_eq!(err["code"], "policy");
        sqlx::query("DELETE FROM openmettle.user_capability_denies WHERE user_id = $1::uuid")
            .bind(&actor.user)
            .execute(&mut owner)
            .await
            .unwrap();
    }

    // P2 #5: 256-model catalog with active Europe/London study policy must complete well under
    // 500ms for both explicit selection and study-hours fallback (no per-model pg_timezone_names scan).
    {
        let mut catalog: Value = serde_json::from_slice(CATALOG).unwrap();
        catalog["revision"] = json!("catalog/family-256");
        let mut base_model = catalog["models"]["b"].clone();
        base_model["context_window"] = json!(8192);
        base_model["output_limit"] = json!(2048);
        base_model["defaults"] = json!({"controls": {"output_reserve": 512}});
        base_model["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        base_model["replay"] = json!([]);
        let models_map = catalog["models"].as_object_mut().unwrap();
        for idx in 0..256 {
            models_map.insert(format!("m{idx:03}"), base_model.clone());
        }
        let server = ApiServer::start_with_catalog(&db, catalog);
        let (cur_min,): (i32,) = sqlx::query_as(
            "SELECT (extract(hour FROM clock_timestamp() AT TIME ZONE 'Europe/London')::int * 60
                   + extract(minute FROM clock_timestamp() AT TIME ZONE 'Europe/London')::int)",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let s_start = (cur_min + 1439) % 1440;
        let s_end = (cur_min + 1438) % 1440;
        let pid: String = sqlx::query_scalar(
            "INSERT INTO openmettle.family_policies
                 (grantee_kind, grantee_user_id, active, zone, study_start_minute, study_end_minute)
             VALUES ('user', $1::uuid, true, 'Europe/London', $2, $3)
             RETURNING id::text",
        )
        .bind(&actor.user)
        .bind(s_start as i16)
        .bind(s_end as i16)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.family_policy_models (policy_id, rule_kind, model, active)
             VALUES ($1::uuid, 'study_allow', 'm255', true)",
        )
        .bind(&pid)
        .execute(&mut owner)
        .await
        .unwrap();

        let (status, proj) = server.call(
            &cookie,
            "POST",
            "/v1/projects",
            Some("r1-256-proj"),
            Some(
                &json!({"name": "Large Catalog", "defaults": {"model_config": {"model": "m000"}}}),
            ),
        );
        assert_eq!(status, 201, "{proj}");
        let (status, conv) = server.call(
            &cookie,
            "POST",
            "/v1/conversations",
            Some("r1-256-conv"),
            Some(&json!({"scope_id": proj["scope_id"]})),
        );
        assert_eq!(status, 201, "{conv}");
        let preview = format!(
            "/v1/conversations/{}/branches/{}/effective-configuration",
            conv["conversation_id"].as_str().unwrap(),
            conv["branch_id"].as_str().unwrap()
        );

        let t0 = Instant::now();
        let (status, explicit_ok) = server.call(
            &cookie,
            "POST",
            &preview,
            None,
            Some(&json!({
                "expected_head_message_id": null,
                "turn": {"mode": "append", "input_message_id": INPUT_1, "parts": [{"text": "fast"}]},
                "selection": {"model": "m255"}
            })),
        );
        let explicit_elapsed = t0.elapsed();
        assert_eq!(status, 200, "{explicit_ok}");
        assert!(
            explicit_elapsed < Duration::from_millis(500),
            "explicit 256-model preview took {explicit_elapsed:?}"
        );

        let t1 = Instant::now();
        let (status, fallback_ok) = server.call(
            &cookie,
            "POST",
            &preview,
            None,
            Some(&json!({
                "expected_head_message_id": null,
                "turn": {"mode": "append", "input_message_id": INPUT_1, "parts": [{"text": "fallback"}]},
                "selection": {}
            })),
        );
        let fallback_elapsed = t1.elapsed();
        assert_eq!(status, 200, "{fallback_ok}");
        assert_eq!(fallback_ok["model"], "m255");
        assert!(
            fallback_elapsed < Duration::from_millis(500),
            "fallback 256-model preview took {fallback_elapsed:?}"
        );

        // Clear the user's policy before worker recheck assertions below.
        sqlx::query(
            "UPDATE openmettle.family_policies SET active = false, revision = revision + 1 WHERE id = $1::uuid",
        )
        .bind(&pid)
        .execute(&mut owner)
        .await
        .unwrap();
    }

    // P2 #7, P2 #8, P2 #9: worker recheck approval binding, post-fence clock, and strict ConfigSnapshot decoding.
    {
        let mut api = connect(&db.0, API).await;
        let mut worker = connect(&db.0, WORKER).await;
        let scope = personal_of(&db, &actor).await;
        let conv_id = chat(&db, &scope, "personal", &actor).await;
        let catalog = openmettle_core::model_config::Catalog::load(CATALOG).unwrap();
        let sel: openmettle_core::model_config::Selection =
            serde_json::from_value(json!({"model": "a"})).unwrap();
        let valid_cfg = serde_json::to_vec(&openmettle_core::model_config::ConfigSnapshot {
            effective: catalog
                .resolve(&Default::default(), &sel, None, |_, _| true)
                .unwrap(),
            required_capabilities: Default::default(),
            policy_revision: "openmettle.authz/1".into(),
            cost_bound: None,
        })
        .unwrap();
        let partial_cfg = json!({"effective": {"model": "a"}, "required_capabilities": {}})
            .to_string()
            .into_bytes();

        let admit = async |api: &mut PgConnection, key: &str, cfg: &[u8]| -> String {
            let (branch, msg) = quotas::branch_and_message(api, &scope, &conv_id).await;
            let mut tx = WriteTransaction::begin(api).await.unwrap();
            let adm = queue::admit_run(
                &mut tx,
                &RunAdmission {
                    input: RunInput {
                        scope: &scope,
                        actor: &actor.user,
                        conversation: &conv_id,
                        branch: &branch,
                        message: &msg,
                        key,
                        format: SNAPSHOT_FORMAT,
                        version: SNAPSHOT_VERSION,
                        input: b"{}",
                        config: cfg,
                    },
                    actor_approval_id: &actor.approval,
                    capabilities: &[],
                    requested_rounds: Some(2),
                    now_ms: NOW,
                    cost_qualified: None,
                },
                &LIMITS,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            match adm {
                Admission::Admitted { run_id, .. } => run_id,
                other => panic!("unexpected {other:?}"),
            }
        };

        // P2 #9: partial v1 snapshot (has effective.model string, misses full ConfigSnapshot fields)
        // must fail closed even with no active family policy.
        let partial_run = admit(&mut api, "r1-partial-snap", &partial_cfg).await;
        assert_eq!(
            queue::recheck_run(
                &mut worker,
                &RunRecheckRequest {
                    scope_id: &scope,
                    run_id: &partial_run,
                    actor_approval_id: &actor.approval,
                    capabilities: &[],
                    extra_target: None,
                    now_ms: NOW,
                },
            )
            .await
            .unwrap(),
            RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy))
        );

        // P2 #7: recheck_run rejects mismatched actor_approval_id even when it belongs to the same user.
        let second_identity: String = sqlx::query_scalar(
            "INSERT INTO openmettle.user_identities (user_id, issuer, subject)
             VALUES ($1::uuid, $2, 'second-subject')
             RETURNING id::text",
        )
        .bind(&actor.user)
        .bind(ISSUER)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let second_approval: String = sqlx::query_scalar(
            "INSERT INTO openmettle.local_identity_approvals
                 (identity_id, provider_id, active, expires_ms, changed_by, change_reason)
             VALUES ($1::uuid, $2::uuid, true, $3, 'fixture', 'second approval')
             RETURNING id::text",
        )
        .bind(&second_identity)
        .bind(PROVIDER)
        .bind(FUTURE)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let valid_run = admit(&mut api, "r1-valid-snap", &valid_cfg).await;
        assert!(matches!(
            queue::recheck_run(
                &mut worker,
                &RunRecheckRequest {
                    scope_id: &scope,
                    run_id: &valid_run,
                    actor_approval_id: &second_approval,
                    capabilities: &[],
                    extra_target: None,
                    now_ms: NOW,
                },
            )
            .await,
            Err(StoreError::InvalidInput("actor_approval_id"))
        ));

        // P2 #8: recheck_leased evaluates schedule boundaries at post-fence clock_timestamp(),
        // ignoring a stale caller-supplied now_ms from 12 hours earlier.
        let claim = queue::claim_next(&mut worker, &CLAIMS, &LEASES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.run_id, valid_run);
        let (cur_min, now_db_ms): (i32, i64) = sqlx::query_as(
            "SELECT (extract(hour FROM clock_timestamp() AT TIME ZONE 'UTC')::int * 60
                   + extract(minute FROM clock_timestamp() AT TIME ZONE 'UTC')::int),
                    floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let q_start = (cur_min + 1435) % 1440;
        let q_end = (cur_min + 5) % 1440;
        sqlx::query(
            "UPDATE openmettle.family_policies
                SET active = true,
                    zone = 'UTC',
                    quiet_start_minute = $2,
                    quiet_end_minute = $3,
                    study_start_minute = NULL,
                    study_end_minute = NULL,
                    revision = revision + 1
              WHERE grantee_kind = 'user' AND grantee_user_id = $1::uuid",
        )
        .bind(&actor.user)
        .bind(q_start as i16)
        .bind(q_end as i16)
        .execute(&mut owner)
        .await
        .unwrap();
        let stale_outside_quiet_ms = now_db_ms - 12 * 3_600_000;
        assert_eq!(
            queue::recheck_leased(
                &mut worker,
                &claim.lease(),
                &RunRecheckRequest {
                    scope_id: &claim.scope_id,
                    run_id: &claim.run_id,
                    actor_approval_id: &claim.actor_approval_id,
                    capabilities: &[],
                    extra_target: None,
                    now_ms: stale_outside_quiet_ms,
                },
                &LEASES,
            )
            .await
            .unwrap(),
            RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy))
        );
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_2_dispatch_principal_check_and_replay() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &actor).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let conv_id = chat(&db, &scope, "personal", &actor).await;

    let catalog = openmettle_core::model_config::Catalog::load(CATALOG).unwrap();
    let sel: openmettle_core::model_config::Selection =
        serde_json::from_value(json!({"model": "a"})).unwrap();
    let cfg_a = serde_json::to_vec(&openmettle_core::model_config::ConfigSnapshot {
        effective: catalog
            .resolve(&Default::default(), &sel, None, |_, _| true)
            .unwrap(),
        required_capabilities: Default::default(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: None,
    })
    .unwrap();

    let mut api = connect(&db.0, API).await;
    let (branch, msg) = quotas::branch_and_message(&mut api, &scope, &conv_id).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id, .. } = queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &actor.user,
                conversation: &conv_id,
                branch: &branch,
                message: &msg,
                key: "r2-dispatch-run",
                format: SNAPSHOT_FORMAT,
                version: SNAPSHOT_VERSION,
                input: b"{}",
                config: &cfg_a,
            },
            actor_approval_id: &actor.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: NOW,
            cost_qualified: None,
        },
        &LIMITS,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    tx.commit().await.unwrap();

    let mut worker = connect(&db.0, WORKER).await;
    let claim = queue::claim_next(&mut worker, &CLAIMS, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.run_id, run_id);

    let res_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, $4::uuid, 150)
         RETURNING id::text",
    )
    .bind(&scope)
    .bind(&actor.user)
    .bind(&actor.approval)
    .bind(&claim.run_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();

    let handoff = async |worker: &mut PgConnection,
                         req_id: &str,
                         round: i32,
                         secret: &[u8; 32],
                         bearer: &[u8; 32]| {
        sqlx::query(
            "INSERT INTO openmettle.gateway_requests
                 (id, reservation_id, scope_id, actor_user_id, approval_id, installation,
                  model, units, dispatch_hash, run_id, round)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid,
                     'a', 50, sha256($7), $8::uuid, $9)",
        )
        .bind(req_id)
        .bind(&res_id)
        .bind(&scope)
        .bind(&actor.user)
        .bind(&actor.approval)
        .bind(INSTALL)
        .bind(secret.as_slice())
        .bind(&claim.run_id)
        .bind(round)
        .execute(&mut *worker)
        .await
        .unwrap();
        let mut tx = worker.begin().await.unwrap();
        let ok: bool = sqlx::query_scalar(
            "SELECT openmettle.gateway_handoff_round($1::uuid, $2, $3::uuid, sha256($4))",
        )
        .bind(req_id)
        .bind(secret.as_slice())
        .bind(&claim.claim_token)
        .bind(bearer.as_slice())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(ok);
        sqlx::query("SELECT openmettle.gateway_handoff_round_confirm($1::uuid, $2, $3::uuid)")
            .bind(req_id)
            .bind(secret.as_slice())
            .bind(&claim.claim_token)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    };

    let req_replay = "00000000-0000-4000-8000-00000000f301";
    let s_replay = [0x31u8; 32];
    let b_replay = [0x41u8; 32];
    handoff(&mut worker, req_replay, 1, &s_replay, &b_replay).await;

    let req_first = "00000000-0000-4000-8000-00000000f302";
    let s_first = [0x32u8; 32];
    let b_first = [0x42u8; 32];
    handoff(&mut worker, req_first, 2, &s_first, &b_first).await;

    let mut gw = connect(&db.0, pg::GATEWAY).await;
    // Spend req_replay while the actor's approval and user row are active.
    let first_spend: Option<(bool,)> =
        sqlx::query_as("SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(req_replay)
            .bind(b_replay.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap();
    assert_eq!(first_spend, Some((false,)));

    // Withdraw the approval while the run is still `running` (before any worker recheck).
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals
            SET active = false, revision = revision + 1, access_generation = access_generation + 1
          WHERE id = $1::uuid",
    )
    .bind(&actor.approval)
    .execute(&mut owner)
    .await
    .unwrap();

    // First dispatch on req_first MUST fail closed (0 rows, dispatched_at remains NULL).
    let withdrawn_first: Option<(bool,)> =
        sqlx::query_as("SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(req_first)
            .bind(b_first.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap();
    assert_eq!(
        withdrawn_first, None,
        "first dispatch must fail closed when approval is withdrawn"
    );

    // Expired approval on first dispatch MUST fail closed.
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals
            SET active = true, expires_ms = 1, revision = revision + 1
          WHERE id = $1::uuid",
    )
    .bind(&actor.approval)
    .execute(&mut owner)
    .await
    .unwrap();
    let expired_first: Option<(bool,)> =
        sqlx::query_as("SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(req_first)
            .bind(b_first.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap();
    assert_eq!(
        expired_first, None,
        "first dispatch must fail closed when approval is expired"
    );

    // Disabled user on first dispatch MUST fail closed.
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals
            SET expires_ms = $2, revision = revision + 1
          WHERE id = $1::uuid",
    )
    .bind(&actor.approval)
    .bind(FUTURE)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.users SET disabled_at = clock_timestamp() WHERE id = $1::uuid")
        .bind(&actor.user)
        .execute(&mut owner)
        .await
        .unwrap();
    let disabled_first: Option<(bool,)> =
        sqlx::query_as("SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(req_first)
            .bind(b_first.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap();
    assert_eq!(
        disabled_first, None,
        "first dispatch must fail closed when user is disabled"
    );

    // Replay of already-spent req_replay MUST still return `replayed = true` even after withdrawal/disable.
    let replay_after_revocation: Option<(bool,)> =
        sqlx::query_as("SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(req_replay)
            .bind(b_replay.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap();
    assert_eq!(replay_after_revocation, Some((true,)));

    // Restoring the user allows req_first's first dispatch to proceed cleanly.
    sqlx::query("UPDATE openmettle.users SET disabled_at = NULL WHERE id = $1::uuid")
        .bind(&actor.user)
        .execute(&mut owner)
        .await
        .unwrap();
    let restored_first: Option<(bool,)> =
        sqlx::query_as("SELECT replayed FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(req_first)
            .bind(b_first.as_slice())
            .fetch_optional(&mut gw)
            .await
            .unwrap();
    assert_eq!(restored_first, Some((false,)));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_2_admin_write_post_lock_expiry() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let db_now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let expiring_admin = account(&mut owner, PROVIDER, true, db_now_ms + 250).await;
    let backup_admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &expiring_admin).await;
    make_admin(&mut owner, &backup_admin).await;

    let mut holder = connect(&db.0, API).await;
    holder.execute("BEGIN").await.unwrap();
    holder
        .execute("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
        .await
        .unwrap();

    let db_name = db.0.clone();
    let actor = expiring_admin.clone();
    let writer = tokio::spawn(async move {
        let mut c = connect(&db_name, API).await;
        let audit_ctx = store::AuditContext {
            actor_user_id: &actor.user,
            actor_approval_id: &actor.approval,
            now_ms: db_now_ms,
            request_key: "r2-expiring-admin-write",
            reason: "approval expires while waiting on account_admin_lock",
        };
        store::set_family_policy(
            &mut c,
            &audit_ctx,
            &FamilyGrantee::OidcGroup("Family".into()),
            &FamilyPolicyInput {
                zone: "UTC".into(),
                quiet: None,
                study: None,
                override_group_schedules: false,
            },
        )
        .await
    });

    super::authz_store::wait_for_lock_waiters(&db, 1).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    holder.execute("ROLLBACK").await.unwrap();

    let res = writer.await.unwrap();
    assert_eq!(
        denied(res),
        DenialReason::InactivePrincipal,
        "admin write whose approval expired during lock wait must be denied"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_2_oidc_inconsistent_history_fails_closed() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;

    let day_iso = "2027-01-15T12:00:00Z";
    let day_ms: i64 = 1_800_014_400_000;

    sqlx::query(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_oidc_group_id, active, zone, quiet_start_minute, quiet_end_minute)
         VALUES ('oidc_group', 'Family', true, 'UTC', 1320, 420)",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    // 1. Missing latest mapping revision (`r.last_revision` has no row in `grant_mapping_revisions`) fails closed.
    let child_missing = account(&mut owner, PROVIDER, true, FUTURE).await;
    enroll_oidc_group(
        &db,
        &child_missing,
        FAMILY_RULE,
        "Family",
        "present",
        day_ms,
    )
    .await;
    let mut api = connect(&db.0, API).await;
    assert!(permits_iso(&mut api, &child_missing, "a", day_iso).await);
    sqlx::query("UPDATE openmettle.grant_mapping_rules SET last_revision = 99 WHERE id = $1::uuid")
        .bind(FAMILY_RULE)
        .execute(&mut owner)
        .await
        .unwrap();
    assert!(
        !permits_iso(&mut api, &child_missing, "a", day_iso).await,
        "missing latest mapping revision must fail closed"
    );

    // 2. An `absent` observation pointing at an unrevoked `grant` row in `grant_changes` fails closed.
    const RULE_BAD_ABSENT: &str = "00000000-0000-4000-8000-00000000f002";
    let child_bad_absent = account(&mut owner, PROVIDER, true, FUTURE).await;
    enroll_oidc_group(
        &db,
        &child_bad_absent,
        RULE_BAD_ABSENT,
        "Family",
        "present",
        day_ms,
    )
    .await;
    assert!(permits_iso(&mut api, &child_bad_absent, "a", day_iso).await);
    sqlx::query(
        "UPDATE openmettle.membership_observations
            SET observation.state = 'absent'
          WHERE approval_id = $1::uuid",
    )
    .bind(&child_bad_absent.approval)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(
        !permits_iso(&mut api, &child_bad_absent, "a", day_iso).await,
        "absent observation pointing to an active grant change must fail closed"
    );

    // 3. Valid `absent` observations (never-granted and properly revoked) remain permitted.
    const RULE_NEVER_GRANTED: &str = "00000000-0000-4000-8000-00000000f003";
    let child_never = account(&mut owner, PROVIDER, true, FUTURE).await;
    enroll_oidc_group(
        &db,
        &child_never,
        RULE_NEVER_GRANTED,
        "Family",
        "absent",
        day_ms,
    )
    .await;
    assert!(permits_iso(&mut api, &child_never, "a", day_iso).await);

    const RULE_REVOKED: &str = "00000000-0000-4000-8000-00000000f004";
    let child_revoked = account(&mut owner, PROVIDER, true, FUTURE).await;
    enroll_oidc_group(
        &db,
        &child_revoked,
        RULE_REVOKED,
        "Family",
        "present",
        day_ms,
    )
    .await;
    let (proj_id, scope_id, grant_change_id): (String, String, String) = sqlx::query_as(
        "SELECT project_id::text, scope_id::text, ((observation).change_id)::text
           FROM openmettle.membership_observations
          WHERE approval_id = $1::uuid",
    )
    .bind(&child_revoked.approval)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let revoke_change_id = {
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let receipt = grants::change_grant(
            &mut tx,
            &ChangeInput {
                assignment: Assignment {
                    scope: &scope_id,
                    target: Target::Project(&proj_id),
                    grantee: Grantee::User(&child_revoked.user),
                    format: "openmettle.project-member",
                    version: 1,
                    key: &child_revoked.approval,
                    mapping_rule: Some(RULE_REVOKED),
                },
                actor: &child_revoked.user,
                key: "r2-revoke-family",
                expected_revision: 1,
                mapping_revision: Some(1),
                decision: Decision::Revoke(Some(&grant_change_id)),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        receipt.change
    };
    sqlx::query(
        "UPDATE openmettle.membership_observations
            SET observation = ROW('absent'::text, $2::uuid)::openmettle.membership_evidence
          WHERE approval_id = $1::uuid",
    )
    .bind(&child_revoked.approval)
    .bind(&revoke_change_id)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(
        permits_iso(&mut api, &child_revoked, "a", day_iso).await,
        "absent observation with matching revoke receipt must remain permitted"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_2_snapshot_object_shape_and_execution_mode() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &actor).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let conv_id = chat(&db, &scope, "personal", &actor).await;

    let catalog = openmettle_core::model_config::Catalog::load(CATALOG).unwrap();
    let sel: openmettle_core::model_config::Selection =
        serde_json::from_value(json!({"model": "a"})).unwrap();
    let eff = catalog
        .resolve(&Default::default(), &sel, None, |_, _| true)
        .unwrap();

    // Positional-array encoding deserializes via derived Serde `visit_seq`, so worker recheck must
    // explicitly reject non-object shapes just like SQL `gateway_round_authority`.
    let array_cfg = serde_json::to_vec(&json!([eff, {}, "openmettle.authz/1", null])).unwrap();
    assert!(
        serde_json::from_slice::<openmettle_core::model_config::ConfigSnapshot>(&array_cfg).is_ok()
    );

    let mut valid_doc = serde_json::to_value(openmettle_core::model_config::ConfigSnapshot {
        effective: eff,
        required_capabilities: Default::default(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: None,
    })
    .unwrap();
    valid_doc
        .as_object_mut()
        .unwrap()
        .insert("execution_mode".into(), json!("yolo"));
    let yolo_cfg = serde_json::to_vec(&valid_doc).unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let admit = async |api: &mut PgConnection, key: &str, cfg: &[u8]| -> String {
        let (branch, msg) = quotas::branch_and_message(api, &scope, &conv_id).await;
        let mut tx = WriteTransaction::begin(api).await.unwrap();
        let Admission::Admitted { run_id, .. } = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &actor.user,
                    conversation: &conv_id,
                    branch: &branch,
                    message: &msg,
                    key,
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: b"{}",
                    config: cfg,
                },
                actor_approval_id: &actor.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: NOW,
                cost_qualified: None,
            },
            &LIMITS,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        tx.commit().await.unwrap();
        run_id
    };

    let array_run = admit(&mut api, "r2-array-snap", &array_cfg).await;
    assert_eq!(
        queue::recheck_run(
            &mut worker,
            &RunRecheckRequest {
                scope_id: &scope,
                run_id: &array_run,
                actor_approval_id: &actor.approval,
                capabilities: &[],
                extra_target: None,
                now_ms: NOW,
            },
        )
        .await
        .unwrap(),
        RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy))
    );

    // Nested positional arrays (e.g. `cost_bound` or `effective.ceiling` as 2-element arrays)
    // must also be rejected.
    let mut nested_cb = valid_doc.clone();
    nested_cb
        .as_object_mut()
        .unwrap()
        .insert("cost_bound".into(), json!([50, 1]));
    let mut nested_ceiling = valid_doc.clone();
    nested_ceiling["effective"]["ceiling"] = json!([100, "model"]);
    for (idx, bad_doc) in [nested_cb, nested_ceiling].into_iter().enumerate() {
        let bad_bytes = serde_json::to_vec(&bad_doc).unwrap();
        let bad_run = admit(&mut api, &format!("r2-nested-arr-{idx}"), &bad_bytes).await;
        assert_eq!(
            queue::recheck_run(
                &mut worker,
                &RunRecheckRequest {
                    scope_id: &scope,
                    run_id: &bad_run,
                    actor_approval_id: &actor.approval,
                    capabilities: &[],
                    extra_target: None,
                    now_ms: NOW,
                },
            )
            .await
            .unwrap(),
            RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy))
        );
    }

    let yolo_run = admit(&mut api, "r2-yolo-snap", &yolo_cfg).await;
    assert_eq!(
        queue::recheck_run(
            &mut worker,
            &RunRecheckRequest {
                scope_id: &scope,
                run_id: &yolo_run,
                actor_approval_id: &actor.approval,
                capabilities: &[],
                extra_target: None,
                now_ms: NOW,
            },
        )
        .await
        .unwrap(),
        RunRecheckOutcome::Continue
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_3_missing_latest_revision_from_other_claim_fails_closed() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;

    let day_iso = "2027-01-15T12:00:00Z";
    let day_ms: i64 = 1_800_014_400_000;

    sqlx::query(
        "INSERT INTO openmettle.family_policies
             (grantee_kind, grantee_oidc_group_id, active, zone, quiet_start_minute, quiet_end_minute)
         VALUES ('oidc_group', 'Family', true, 'UTC', 1320, 420)",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    // Enrolled under `'Other'` (permitted while revision 1 is current), then `last_revision` advances
    // to 99 with no `grant_mapping_revisions` row (so whether revision 99 targets `'Family'` is unknown).
    const RULE_OTHER: &str = "00000000-0000-4000-8000-00000000f005";
    let child_other = account(&mut owner, PROVIDER, true, FUTURE).await;
    enroll_oidc_group(&db, &child_other, RULE_OTHER, "Other", "present", day_ms).await;

    let mut api = connect(&db.0, API).await;
    assert!(permits_iso(&mut api, &child_other, "a", day_iso).await);

    sqlx::query("UPDATE openmettle.grant_mapping_rules SET last_revision = 99 WHERE id = $1::uuid")
        .bind(RULE_OTHER)
        .execute(&mut owner)
        .await
        .unwrap();
    assert!(
        !permits_iso(&mut api, &child_other, "a", day_iso).await,
        "missing latest mapping revision on an Other-enrolled rule must fail closed when any oidc_group policy is active"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_3_snapshot_rejects_enum_map_encodings() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &actor).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let conv_id = chat(&db, &scope, "personal", &actor).await;

    let catalog = openmettle_core::model_config::Catalog::load(CATALOG).unwrap();
    let sel: openmettle_core::model_config::Selection =
        serde_json::from_value(json!({"model": "a"})).unwrap();
    let eff = catalog
        .resolve(&Default::default(), &sel, None, |_, _| true)
        .unwrap();
    let base_doc = serde_json::to_value(openmettle_core::model_config::ConfigSnapshot {
        effective: eff,
        required_capabilities: Default::default(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: None,
    })
    .unwrap();

    // Serde decodes unit-variant enums from `{"variant": null}` maps; SQL handoff requires strings.
    let mut bad_cap_gate = base_doc.clone();
    bad_cap_gate["required_capabilities"] = json!({"fixture.cap": {"on_by_default": null}});
    assert!(
        serde_json::from_value::<openmettle_core::model_config::ConfigSnapshot>(
            bad_cap_gate.clone()
        )
        .is_ok()
    );

    let mut bad_model_source = base_doc.clone();
    bad_model_source["effective"]["model_source"] = json!({"request": null});
    assert!(
        serde_json::from_value::<openmettle_core::model_config::ConfigSnapshot>(
            bad_model_source.clone()
        )
        .is_ok()
    );

    let mut bad_field_source = base_doc;
    bad_field_source["effective"]["ceiling"]["source"] = json!({"model": null});
    assert!(
        serde_json::from_value::<openmettle_core::model_config::ConfigSnapshot>(
            bad_field_source.clone()
        )
        .is_ok()
    );

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    for (idx, bad_doc) in [bad_cap_gate, bad_model_source, bad_field_source]
        .into_iter()
        .enumerate()
    {
        let (branch, msg) = quotas::branch_and_message(&mut api, &scope, &conv_id).await;
        let bad_bytes = serde_json::to_vec(&bad_doc).unwrap();
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let Admission::Admitted { run_id, .. } = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &actor.user,
                    conversation: &conv_id,
                    branch: &branch,
                    message: &msg,
                    key: &format!("r3-enum-map-{idx}"),
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: b"{}",
                    config: &bad_bytes,
                },
                actor_approval_id: &actor.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: NOW,
                cost_qualified: None,
            },
            &LIMITS,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        tx.commit().await.unwrap();

        assert_eq!(
            queue::recheck_run(
                &mut worker,
                &RunRecheckRequest {
                    scope_id: &scope,
                    run_id: &run_id,
                    actor_approval_id: &actor.approval,
                    capabilities: &[],
                    extra_target: None,
                    now_ms: NOW,
                },
            )
            .await
            .unwrap(),
            RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy)),
            "enum map case {idx} must be rejected"
        );
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn family_policy_review_4_snapshot_rejects_omitted_effective_and_field_keys() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &actor).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let conv_id = chat(&db, &scope, "personal", &actor).await;

    let catalog = openmettle_core::model_config::Catalog::load(CATALOG).unwrap();
    let sel: openmettle_core::model_config::Selection =
        serde_json::from_value(json!({"model": "a"})).unwrap();
    let eff = catalog
        .resolve(&Default::default(), &sel, None, |_, _| true)
        .unwrap();
    let base_doc = serde_json::to_value(openmettle_core::model_config::ConfigSnapshot {
        effective: eff,
        required_capabilities: Default::default(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: None,
    })
    .unwrap();

    // Omitting `effective.temperature.value` silently drops model `a`'s pinned `0.2` in Serde;
    // omitting `effective.preset_source` removes a required serialized member of `Effective`.
    let mut missing_temp_val = base_doc.clone();
    missing_temp_val["effective"]["temperature"]
        .as_object_mut()
        .unwrap()
        .remove("value");
    let mut missing_preset_source = base_doc.clone();
    missing_preset_source["effective"]
        .as_object_mut()
        .unwrap()
        .remove("preset_source");

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    for (idx, bad_doc) in [missing_temp_val, missing_preset_source]
        .into_iter()
        .enumerate()
    {
        let (branch, msg) = quotas::branch_and_message(&mut api, &scope, &conv_id).await;
        let bad_bytes = serde_json::to_vec(&bad_doc).unwrap();
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let Admission::Admitted { run_id, .. } = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &actor.user,
                    conversation: &conv_id,
                    branch: &branch,
                    message: &msg,
                    key: &format!("r4-missing-key-{idx}"),
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: b"{}",
                    config: &bad_bytes,
                },
                actor_approval_id: &actor.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: NOW,
                cost_qualified: None,
            },
            &LIMITS,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        tx.commit().await.unwrap();

        assert_eq!(
            queue::recheck_run(
                &mut worker,
                &RunRecheckRequest {
                    scope_id: &scope,
                    run_id: &run_id,
                    actor_approval_id: &actor.approval,
                    capabilities: &[],
                    extra_target: None,
                    now_ms: NOW,
                },
            )
            .await
            .unwrap(),
            RunRecheckOutcome::Invalidated(DenialReason::Policy(PolicyReason::FamilyPolicy)),
            "omitted member case {idx} must be rejected"
        );
    }

    // Explicit `null` on nullable members (`preset_source: null`, `top_p.value: null`) remains valid.
    assert!(base_doc["effective"]["preset_source"].is_null());
    assert!(base_doc["effective"]["top_p"]["value"].is_null());
    let (branch, msg) = quotas::branch_and_message(&mut api, &scope, &conv_id).await;
    let valid_bytes = serde_json::to_vec(&base_doc).unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted {
        run_id: valid_run_id,
        ..
    } = queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &actor.user,
                conversation: &conv_id,
                branch: &branch,
                message: &msg,
                key: "r4-explicit-null-ok",
                format: SNAPSHOT_FORMAT,
                version: SNAPSHOT_VERSION,
                input: b"{}",
                config: &valid_bytes,
            },
            actor_approval_id: &actor.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: NOW,
            cost_qualified: None,
        },
        &LIMITS,
    )
    .await
    .unwrap()
    else {
        panic!("expected admission");
    };
    tx.commit().await.unwrap();
    assert_eq!(
        queue::recheck_run(
            &mut worker,
            &RunRecheckRequest {
                scope_id: &scope,
                run_id: &valid_run_id,
                actor_approval_id: &actor.approval,
                capabilities: &[],
                extra_target: None,
                now_ms: NOW,
            },
        )
        .await
        .unwrap(),
        RunRecheckOutcome::Continue
    );
}
