//! Real managed callback, sealed proof, approved session, grant history and evidence read.
use super::*;
use crate::{
    grants,
    membership::{Observation::*, current},
    runs::WriteTransaction,
};
use sessions::{seed, session_policy};

const RULE: &str = "00000000-0000-0000-0000-00000000012a";

async fn proof(f: &mut Flow, issued: i64, claims: Value) -> ExchangedIdentity {
    proof_for(f, "synthetic-subject", issued, claims).await
}
async fn proof_for(f: &mut Flow, subject: &str, issued: i64, claims: Value) -> ExchangedIdentity {
    let p = f.h.provider.clone();
    let started = f.begin(&p).await;
    f.arm(&started);
    let url = openidconnect::url::Url::parse(started.authorization_url.expose()).unwrap();
    let nonce = url.query_pairs().find(|(k, _)| k == "nonce").unwrap().1;
    f.h.script.lock().unwrap().token = signing::membership_token(subject, &nonce, issued, claims);
    f.consume(&p, &started)
        .await
        .unwrap()
        .exchange_with_keys(&p, &auth::Policy::default())
        .await
        .unwrap()
}

struct Enrollment {
    now: i64,
    user: String,
    approval: String,
    project: String,
    scope: String,
    direct: grants::GrantReceipt,
}

async fn enroll(f: &mut Flow) -> Enrollment {
    // Use primary time for signing and the synthetic TLS metadata Date in this test.
    // All observed issue times are a few seconds in the past, with no sleeps.
    let now = crate::sessions::now(&mut f.api).await.unwrap() / 1000;
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(now as u64);
    f.h.script.lock().unwrap().date = wall;
    *f.h.manager.inner.clock.lock().unwrap() = Some(Arc::new(move || Sample {
        wall,
        mono: Instant::now(),
    }));
    let user = seed(f, true, true).await;
    let approval: String =
        sqlx::query_scalar("SELECT id::text FROM openmettle.local_identity_approvals")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let (project,scope): (String,String) = sqlx::query_as(
        "WITH ids AS (SELECT gen_random_uuid() p,gen_random_uuid() s),
        sc AS (INSERT INTO openmettle.scopes(id,kind,project_id) SELECT s,'project',p FROM ids),
        pr AS (INSERT INTO openmettle.projects(id,scope_id,created_by_user_id) SELECT p,s,$1::uuid FROM ids)
        SELECT p::text,s::text FROM ids",
    )
    .bind(&user)
    .fetch_one(&mut f.owner)
    .await.unwrap();
    let mut tx = WriteTransaction::begin(&mut f.owner).await.unwrap();
    let mapping = grants::MappingInput {
        rule: RULE,
        provider: signing::ID,
        issuer: signing::ISSUER,
        actor: &user,
        key: "fixture-mapping",
        expected_revision: 0,
        enabled: true,
        selector_kind: "group",
        claim_name: "groups",
        claim_value: "team",
        binding_format: "openmettle.project-member",
        binding_version: 1,
        binding: project.as_bytes(),
    };
    grants::record_mapping_revision(&mut tx, &mapping)
        .await
        .unwrap();
    let direct = grants::change_grant(
        &mut tx,
        &grants::ChangeInput {
            assignment: grants::Assignment {
                scope: &scope,
                target: grants::Target::Project(&project),
                grantee: &user,
                format: "openmettle.project-member",
                version: 1,
                key: &approval,
                mapping_rule: None,
            },
            actor: &user,
            key: "direct",
            expected_revision: 0,
            mapping_revision: None,
            decision: grants::Decision::Grant,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("INSERT INTO openmettle.membership_observations(approval_id,rule_id,rule_revision,project_id,scope_id,max_age_seconds)
        VALUES ($1::uuid,$2::uuid,1,$3::uuid,$4::uuid,180)").bind(&approval).bind(RULE).bind(&project).bind(&scope)
        .execute(&mut f.owner).await.unwrap();

    Enrollment {
        now,
        user,
        approval,
        project,
        scope,
        direct,
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn approved_project_mapping_orders_real_assertions_and_preserves_direct_grants() {
    let mut f = Flow::new().await;
    let Enrollment {
        now,
        user,
        approval,
        project,
        scope,
        direct,
    } = enroll(&mut f).await;
    assert!(
        f.api
            .execute("UPDATE openmettle.membership_observations SET max_age_seconds=3600")
            .await
            .is_err()
    );
    assert!(
        f.db.connect(WORKER)
            .await
            .execute("SELECT * FROM openmettle.membership_observations")
            .await
            .is_err()
    );
    let p = f.h.provider.clone();
    assert_eq!(
        current(&mut f.api, &approval, &project, &session_policy())
            .await
            .unwrap(),
        Missing
    );
    for (age, claims, result, history) in [
        (200, json!({"groups":["team"]}), Stale, 0),
        (30, json!({"groups":["team"]}), Present, 1),
        (29, json!({"groups":["team"]}), Present, 1),
        (30, json!({"groups":[]}), Present, 1), // older than latest confirming observation
        (28, json!({"roles":["team"]}), Missing, 1),
        (27, json!({"groups":["team"],"hasgroups":true}), Partial, 1),
        (26, json!({"groups":[]}), Absent, 2),
        (26, json!({"groups":["team"]}), Ambiguous, 2),
        (27, json!({"groups":["team"]}), Ambiguous, 2),
        (25, json!({"groups":["team"]}), Present, 3),
    ] {
        let exchanged = proof(&mut f, now - age, claims).await;
        let credential = p
            .issue_session(&mut f.api, exchanged, &session_policy())
            .await
            .unwrap();
        let ctx = crate::sessions::validate(&mut f.api, credential.expose(), &session_policy())
            .await
            .unwrap();
        assert_eq!(ctx.user_id(), user);
        assert_eq!(
            current(&mut f.api, &approval, &project, &session_policy())
                .await
                .unwrap(),
            result
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.grant_changes WHERE mapping_rule_id=$1::uuid",
        )
        .bind(RULE)
        .fetch_one(&mut f.api)
        .await
        .unwrap();
        assert_eq!(count, history);
    }
    assert_eq!(
        current(&mut f.api, &approval, RULE, &session_policy())
            .await
            .unwrap(),
        Failed
    );
    // Another subject signed by the same client cannot use this approval or fence.
    let collision = proof_for(
        &mut f,
        "other-subject",
        now - 1,
        json!({"groups":[],"email":"team@example.test"}),
    )
    .await;
    assert!(
        p.issue_session(&mut f.api, collision, &session_policy())
            .await
            .is_err()
    );
    assert_eq!(
        current(&mut f.api, &approval, &project, &session_policy())
            .await
            .unwrap(),
        Present
    );
    // Two different committed login gates and two API connections race the same approval.
    // The removal is newer than the positive proof irrespective of row-lock acquisition order.
    let positive = proof(&mut f, now - 21, json!({"groups":["team"]})).await;
    let removal = proof(&mut f, now - 20, json!({"groups":[]})).await;
    let policy = session_policy();
    let mut second = f.db.connect(API).await;
    let (first, second_result) = tokio::join!(
        p.issue_session(&mut f.api, removal, &policy),
        p.issue_session(&mut second, positive, &policy)
    );
    first.unwrap();
    second_result.unwrap();
    assert_eq!(
        current(&mut f.api, &approval, &project, &policy)
            .await
            .unwrap(),
        Absent
    );
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.grant_changes WHERE mapping_rule_id=$1::uuid",
    )
    .bind(RULE)
    .fetch_one(&mut f.api)
    .await
    .unwrap();
    assert_eq!(remaining, 4);
    let confirmation = proof(&mut f, now - 19, json!({"groups":["team"]})).await;
    p.issue_session(&mut f.api, confirmation, &policy)
        .await
        .unwrap();

    // Reduce the owner-chosen window. Current reads immediately expire the last confirmation.
    f.owner
        .execute("UPDATE openmettle.membership_observations SET max_age_seconds=1")
        .await
        .unwrap();
    assert_eq!(
        current(&mut f.api, &approval, &project, &session_policy())
            .await
            .unwrap(),
        Stale
    );
    assert!(
        grants::read_assignment(&mut f.api, &scope, &direct.assignment)
            .await
            .unwrap()
            .unwrap()
            .recorded_active
    );
    // An active authority revision change invalidates both the prior membership and
    // a proof exchanged before it. A later fresh login can use the new epoch.
    let held = proof(&mut f, now - 2, json!({"groups":["team"]})).await;
    write(&mut f.owner, Some("v1")).await;
    assert!(p.issue_session(&mut f.api, held, &policy).await.is_err());
    assert_eq!(
        current(&mut f.api, &approval, &project, &policy)
            .await
            .unwrap(),
        Failed
    );
    let exchanged = proof(&mut f, now - 1, json!({"groups":["team"]})).await;
    f.owner.execute("UPDATE openmettle.users SET disabled_at=clock_timestamp(),session_generation=session_generation+1").await.unwrap();
    assert!(
        p.issue_session(&mut f.api, exchanged, &session_policy())
            .await
            .is_err()
    );
    assert_eq!(
        current(&mut f.api, &approval, &project, &session_policy())
            .await
            .unwrap(),
        Failed
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn failed_issuance_rolls_back_grant_and_fence_and_rule_change_invalidates_evidence() {
    let mut f = Flow::new().await;
    let Enrollment {
        now,
        user,
        approval,
        project,
        ..
    } = enroll(&mut f).await;
    let p = f.h.provider.clone();
    let policy = session_policy();
    // A real failure after reconciliation and before issuance commits.
    f.owner
        .execute(
            "ALTER TABLE openmettle.local_sessions ADD CONSTRAINT fixture_refuse CHECK (false)",
        )
        .await
        .unwrap();
    let exchanged = proof(&mut f, now - 3, json!({"groups":["team"]})).await;
    assert!(
        p.issue_session(&mut f.api, exchanged, &policy)
            .await
            .is_err()
    );
    assert_eq!(
        current(&mut f.api, &approval, &project, &policy)
            .await
            .unwrap(),
        Missing
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.grant_assignments WHERE mapping_rule_id=$1::uuid",
    )
    .bind(RULE)
    .fetch_one(&mut f.api)
    .await
    .unwrap();
    assert_eq!(count, 0);
    f.owner
        .execute("ALTER TABLE openmettle.local_sessions DROP CONSTRAINT fixture_refuse")
        .await
        .unwrap();
    let exchanged = proof(&mut f, now - 3, json!({"groups":["team"]})).await;
    p.issue_session(&mut f.api, exchanged, &policy)
        .await
        .unwrap();
    assert_eq!(
        current(&mut f.api, &approval, &project, &policy)
            .await
            .unwrap(),
        Present
    );

    // Even an enabled replacement at the same project requires a new owner enrollment.
    let mut tx = WriteTransaction::begin(&mut f.owner).await.unwrap();
    grants::record_mapping_revision(
        &mut tx,
        &grants::MappingInput {
            rule: RULE,
            provider: signing::ID,
            issuer: signing::ISSUER,
            actor: &user,
            key: "replace-selector",
            expected_revision: 1,
            enabled: true,
            selector_kind: "app_role",
            claim_name: "roles",
            claim_value: "new-team",
            binding_format: "openmettle.project-member",
            binding_version: 1,
            binding: project.as_bytes(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        current(&mut f.api, &approval, &project, &policy)
            .await
            .unwrap(),
        Failed
    );
    let exchanged = proof(&mut f, now - 2, json!({"roles":["new-team"]})).await;
    p.issue_session(&mut f.api, exchanged, &policy)
        .await
        .unwrap();
    assert_eq!(
        current(&mut f.api, &approval, &project, &policy)
            .await
            .unwrap(),
        Failed
    );
}
