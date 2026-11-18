//! Real managed callback, sealed proof, approved session, grant history and evidence read.
use super::*;
use crate::{
    grants,
    membership::{Observation::*, current},
    runs::WriteTransaction,
};
use sessions::{seed, session_policy};
use std::io::Write;

const RULE: &str = "00000000-0000-0000-0000-00000000012a";
/// Synthetic operator change-record reference; deliberately not an OpenMettle user.
const OPERATOR: &str = "00000000-0000-0000-0000-0000000003aa";

async fn proof(f: &mut Flow, issued: i64, claims: Value) -> ExchangedIdentity {
    proof_for(f, "synthetic-subject", issued, claims).await
}
async fn proof_for(f: &mut Flow, subject: &str, issued: i64, claims: Value) -> ExchangedIdentity {
    let p = f.h.provider.clone();
    exchange(f, &p, subject, issued, claims, &auth::Policy::default()).await
}
async fn exchange(
    f: &mut Flow,
    p: &ManagedProvider,
    subject: &str,
    issued: i64,
    claims: Value,
    policy: &auth::Policy,
) -> ExchangedIdentity {
    let started = f.begin(p).await;
    f.arm(&started);
    let url = openidconnect::url::Url::parse(started.authorization_url.expose()).unwrap();
    let nonce = url.query_pairs().find(|(k, _)| k == "nonce").unwrap().1;
    f.h.script.lock().unwrap().token = signing::membership_token(subject, &nonce, issued, claims);
    f.consume(p, &started)
        .await
        .unwrap()
        .exchange_with_keys(p, policy)
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

struct Configuration<'a> {
    rule: &'a str,
    revision: i64,
    age: i32,
    baseline: &'a str,
    enabled: bool,
}
impl Default for Configuration<'_> {
    fn default() -> Self {
        Self {
            rule: RULE,
            revision: 1,
            age: 180,
            baseline: "none",
            enabled: true,
        }
    }
}

impl Enrollment {
    async fn revision(&self, f: &mut Flow) -> i64 {
        sqlx::query_scalar("SELECT coalesce(max(config_revision),0) FROM openmettle.membership_observations WHERE approval_id=$1::uuid")
            .bind(&self.approval).fetch_one(&mut f.owner).await.unwrap()
    }
    fn configure(
        &self,
        f: &Flow,
        role: &str,
        expected: i64,
        request: &str,
        config: Configuration<'_>,
    ) -> std::process::Output {
        let revision = config.revision.to_string();
        let expected = expected.to_string();
        let age = config.age.to_string();
        let vars = [
            ("request", request),
            ("actor", self.user.as_str()),
            ("reason", "synthetic membership test"),
            ("approval", self.approval.as_str()),
            ("expected_revision", &expected),
            ("rule", config.rule),
            ("rule_revision", &revision),
            ("project", &self.project),
            ("scope", &self.scope),
            ("enabled", if config.enabled { "true" } else { "false" }),
            ("age", &age),
            ("baseline", config.baseline),
        ];
        let mut child = psql::start(&f.db.name, role, PASSWORD, &vars);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(include_bytes!(
                "../../../../docs/operator/configure-project-membership.psql"
            ))
            .unwrap();
        child.wait_with_output().unwrap()
    }
    fn start_withdrawal(&self, f: &Flow, role: &str, request: &str) -> std::process::Child {
        let vars = [
            ("approval", self.approval.as_str()),
            ("request", request),
            ("actor", OPERATOR),
        ];
        let mut child = psql::start(&f.db.name, role, PASSWORD, &vars);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(include_bytes!(
                "../../../../docs/operator/withdraw-project-membership.psql"
            ))
            .unwrap();
        child
    }
    fn withdraw(&self, f: &Flow, role: &str, request: &str) -> std::process::Output {
        self.start_withdrawal(f, role, request)
            .wait_with_output()
            .unwrap()
    }
    async fn reset(&self, f: &mut Flow, config: Configuration<'_>) -> String {
        let request: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
        let expected = self.revision(f).await;
        let out = self.configure(f, OWNER, expected, &request, config);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        request
    }
    async fn observe(&self, f: &mut Flow) -> crate::membership::Observation {
        current(&mut f.api, &self.approval, &self.project, &session_policy())
            .await
            .unwrap()
    }
    fn assignment(&self) -> grants::Assignment<'_> {
        grants::Assignment {
            scope: &self.scope,
            target: grants::Target::Project(&self.project),
            grantee: &self.user,
            format: "openmettle.project-member",
            version: 1,
            key: &self.approval,
            mapping_rule: Some(RULE),
        }
    }
    async fn submit(&self, f: &mut Flow, age: i64, groups: Value) {
        let p = f.h.provider.clone();
        let token = proof(f, self.now - age, json!({"groups":groups})).await;
        p.issue_session(&mut f.api, token, &session_policy())
            .await
            .unwrap();
    }
    async fn head(&self, f: &mut Flow) -> grants::GrantReceipt {
        let (change,assignment,revision,granted,cycle)=sqlx::query_as("SELECT h.id::text,g.id::text,h.revision,h.decision='grant',h.cycle_id::text
            FROM openmettle.grant_assignments g JOIN openmettle.grant_changes h ON h.assignment_id=g.id AND h.revision=g.last_revision
            WHERE g.assignment_key=$1 AND g.mapping_rule_id=$2::uuid")
            .bind(&self.approval).bind(RULE).fetch_one(&mut f.api).await.unwrap();
        grants::GrantReceipt {
            change,
            assignment,
            revision,
            granted,
            cycle,
        }
    }
}
async fn enroll(f: &mut Flow) -> Enrollment {
    let e = prepare(f).await;
    e.reset(f, Configuration::default()).await;
    e
}

async fn project(f: &mut Flow, user: &str) -> (String, String) {
    sqlx::query_as(
        "WITH ids AS (SELECT gen_random_uuid() p,gen_random_uuid() s),
        sc AS (INSERT INTO openmettle.scopes(id,kind,project_id) SELECT s,'project',p FROM ids),
        pr AS (INSERT INTO openmettle.projects(id,scope_id,created_by_user_id) SELECT p,s,$1::uuid FROM ids)
        SELECT p::text,s::text FROM ids",
    )
    .bind(user)
    .fetch_one(&mut f.owner)
    .await.unwrap()
}

async fn prepare(f: &mut Flow) -> Enrollment {
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
    let (project, scope) = project(f, &user).await;
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
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
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
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
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

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn v5_withdrawal_and_aba_require_owner_resync_and_post_reset_exchange() {
    let mut refresh = policy();
    refresh.deadline = Duration::from_secs(30);
    let mut f = Flow::with(Harness::with_policy(refresh).await).await;
    let e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    let first = e.head(&mut f).await;
    assert_eq!(e.observe(&mut f).await, Present);
    let held = proof(&mut f, e.now - 29, json!({"groups":["team"]})).await;
    // The v5 writer already owns the rule. Issuance must reach a lock wait on it
    // with the user locked, before v5 takes its actor FK KEY SHARE on that user.
    let mut db = f.db.connect(API).await;
    let mut writer = WriteTransaction::begin(&mut db).await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.grant_mapping_rules WHERE id=$1::uuid FOR NO KEY UPDATE",
    )
    .bind(RULE)
    .execute(writer.connection().unwrap())
    .await
    .unwrap();
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(writer.connection().unwrap())
        .await
        .unwrap();
    let reader_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = sessions::statistics_observer(&f.db).await;
    let withdraw = async {
        sessions::waiting(&mut observer, reader_pid).await;
        let blocked: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
            .bind(writer_pid)
            .bind(reader_pid)
            .fetch_one(&mut observer)
            .await
            .unwrap();
        assert!(blocked);
        let revoke = grants::change_grant(
            &mut writer,
            &grants::ChangeInput {
                assignment: e.assignment(),
                actor: &e.user,
                key: "external-withdraw",
                expected_revision: first.revision,
                mapping_revision: Some(1),
                decision: grants::Decision::Revoke(first.cycle.as_deref()),
            },
        )
        .await
        .unwrap();
        writer.commit().await.unwrap();
        revoke
    };
    let policy = session_policy();
    let (identity, revoke) = tokio::join!(
        f.h.provider.issue_session(&mut f.api, held, &policy),
        withdraw
    );
    identity.unwrap();
    assert_eq!(revoke.cycle, first.cycle);
    assert_eq!(e.head(&mut f).await.change, revoke.change);
    assert_eq!(e.observe(&mut f).await, Failed);
    let mut writer = WriteTransaction::begin(&mut db).await.unwrap();
    let second = grants::change_grant(
        &mut writer,
        &grants::ChangeInput {
            assignment: e.assignment(),
            actor: &e.user,
            key: "external-restore",
            expected_revision: revoke.revision,
            mapping_revision: Some(1),
            decision: grants::Decision::Grant,
        },
    )
    .await
    .unwrap();
    writer.commit().await.unwrap();
    assert_eq!(first.assignment, second.assignment);
    assert_ne!(first.cycle, second.cycle);
    assert_eq!(second.revision, first.revision + 2);
    assert_eq!(e.observe(&mut f).await, Failed);
    e.submit(&mut f, 28, json!([])).await;
    assert_eq!(e.head(&mut f).await.change, second.change);
    let held = proof(&mut f, e.now - 20, json!({"groups":["team"]})).await;
    let request = e
        .reset(
            &mut f,
            Configuration {
                baseline: &second.change,
                ..Default::default()
            },
        )
        .await;
    f.h.provider
        .issue_session(&mut f.api, held, &policy)
        .await
        .unwrap();
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 28, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 19, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    // Recovery after missing acknowledgement: the immutable receipt identifies the exact adopted head.
    let receipt: (String, String, i64) = sqlx::query_as(
        "SELECT approval_id::text,baseline_change::text,floor_ms
        FROM openmettle.membership_configuration_changes WHERE request_id=$1::uuid",
    )
    .bind(request)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(receipt, (e.approval, second.change, (e.now - 28) * 1000));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn existing_history_requires_inspected_head_and_interval_aba_cannot_revive() {
    let mut f = Flow::new().await;
    let e = prepare(&mut f).await;
    let mut t = WriteTransaction::begin(&mut f.api).await.unwrap();
    let initial = grants::change_grant(
        &mut t,
        &grants::ChangeInput {
            assignment: e.assignment(),
            actor: &e.user,
            key: "existing",
            expected_revision: 0,
            mapping_revision: Some(1),
            decision: grants::Decision::Grant,
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let request = "00000000-0000-0000-0000-0000000000ef";
    assert!(
        !e.configure(&f, OWNER, 0, request, Default::default())
            .status
            .success()
    );
    assert!(
        !e.configure(
            &f,
            API,
            0,
            request,
            Configuration {
                baseline: &initial.change,
                ..Default::default()
            }
        )
        .status
        .success()
    );
    e.reset(
        &mut f,
        Configuration {
            baseline: &initial.change,
            ..Default::default()
        },
    )
    .await;
    e.submit(&mut f, 20, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    e.reset(
        &mut f,
        Configuration {
            baseline: &initial.change,
            age: 1,
            ..Default::default()
        },
    )
    .await;
    e.submit(&mut f, 18, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Stale);
    e.reset(
        &mut f,
        Configuration {
            baseline: &initial.change,
            ..Default::default()
        },
    )
    .await;
    e.submit(&mut f, 18, json!(["team"])).await;
    e.submit(&mut f, 20, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 17, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    assert_eq!(e.head(&mut f).await.change, initial.change);
    let before = e.revision(&mut f).await;
    let suspended = e
        .reset(
            &mut f,
            Configuration {
                baseline: &initial.change,
                enabled: false,
                ..Default::default()
            },
        )
        .await;
    assert_eq!(e.observe(&mut f).await, Failed);
    e.submit(&mut f, 16, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Failed);
    assert!(
        !e.configure(
            &f,
            OWNER,
            before,
            &suspended,
            Configuration {
                baseline: &initial.change,
                ..Default::default()
            }
        )
        .status
        .success()
    );
    e.reset(
        &mut f,
        Configuration {
            baseline: &initial.change,
            ..Default::default()
        },
    )
    .await;
    e.submit(&mut f, 17, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 15, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn independent_generations_and_same_iat_shorter_expiry() {
    let mut f = Flow::new().await;
    let e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    let p = f.h.provider.clone();
    let short = auth::Policy::new(Duration::from_secs(60), Duration::from_secs(1)).unwrap();
    let token = exchange(
        &mut f,
        &p,
        "synthetic-subject",
        e.now - 30,
        json!({"groups":["team"]}),
        &short,
    )
    .await;
    p.issue_session(&mut f.api, token, &session_policy())
        .await
        .unwrap();
    e.submit(&mut f, 30, json!(["team"])).await;
    let expiry: i64 =
        sqlx::query_scalar("SELECT expires_ms FROM openmettle.membership_observations")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_eq!(expiry, (e.now + 30) * 1000);
    assert_eq!(e.observe(&mut f).await, Present);
    crate::sessions::disable_user(&mut f.api, &e.user, 0, &session_policy())
        .await
        .unwrap();
    assert_eq!(e.observe(&mut f).await, Failed);
    f.owner
        .execute(
            "UPDATE openmettle.users SET disabled_at=NULL,session_generation=session_generation+1",
        )
        .await
        .unwrap();
    assert_eq!(e.observe(&mut f).await, Failed);
    e.submit(&mut f, 29, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    f.owner.execute("UPDATE openmettle.local_identity_approvals SET active=false,revision=revision+1,access_generation=access_generation+1").await.unwrap();
    assert_eq!(e.observe(&mut f).await, Failed);
    f.owner.execute("UPDATE openmettle.local_identity_approvals SET active=true,revision=revision+1,access_generation=access_generation+1").await.unwrap();
    assert_eq!(e.observe(&mut f).await, Failed);
    e.submit(&mut f, 28, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn membership_expiry_while_issuing_commits_removal_and_valid_identity_session() {
    use crate::response_barrier::ResponseBarrier;
    let mut refresh = policy();
    refresh.deadline = Duration::from_secs(30);
    let mut f = Flow::with(Harness::with_policy(refresh).await).await;
    let mut e = prepare(&mut f).await;
    e.reset(
        &mut f,
        Configuration {
            age: 5,
            ..Default::default()
        },
    )
    .await;
    // Connection setup and the owner operation precede the short window.
    let mut barrier = ResponseBarrier::nth(b"UPDATE 1\0", 2);
    let options =
        f.db.options(API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable);
    let mut cn = PgConnection::connect_with(&options).await.unwrap();
    e.now = crate::sessions::now(&mut f.api).await.unwrap() / 1000;
    e.submit(&mut f, 1, json!(["team"])).await;
    let initial = e.head(&mut f).await;
    assert_eq!(e.observe(&mut f).await, Present);
    let token = proof(&mut f, e.now, json!({"groups":[]})).await;
    let p = f.h.provider.clone();
    let policy = session_policy();
    // UPDATE assignment, then UPDATE observation. Hold that second acknowledgement
    // before the final authentication and approval checks. Sample the actual DB clock.
    let credential = {
        let issuance = p.issue_session(&mut cn, token, &policy);
        tokio::pin!(issuance);
        tokio::select! {
            ()=barrier.wait_reached()=>{},
            ended=&mut issuance=>panic!("ended before observation write: {ended:?}"),
        }
        let expires = (e.now + 5) * 1000;
        let before = crate::sessions::now(&mut f.owner).await.unwrap();
        assert!(before < expires);
        while crate::sessions::now(&mut f.owner).await.unwrap() < expires {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        barrier.resume();
        issuance.await.unwrap()
    };
    cn.close().await.unwrap();
    drop(barrier);
    assert_eq!(
        crate::sessions::validate(&mut f.api, credential.expose(), &policy)
            .await
            .unwrap()
            .user_id(),
        e.user
    );
    let stored:(String,i64)=sqlx::query_as("SELECT (observation).state,issued_ms FROM openmettle.membership_observations WHERE approval_id=$1::uuid")
        .bind(&e.approval).fetch_one(&mut f.api).await.unwrap();
    assert_eq!(stored, ("stale".into(), e.now * 1000));
    let removal = e.head(&mut f).await;
    assert!(!removal.granted);
    assert_eq!(removal.cycle, initial.cycle);
    assert_eq!(removal.revision, initial.revision + 1);
    assert_eq!(e.observe(&mut f).await, Stale);
    e.submit(&mut f, 1, json!(["team"])).await;
    assert_eq!(e.head(&mut f).await.change, removal.change);
    assert_eq!(e.observe(&mut f).await, Stale);
}

async fn record_rule(f: &mut Flow, rule: &str, provider: &str, user: &str, project: &str) {
    let mut tx = WriteTransaction::begin(&mut f.owner).await.unwrap();
    grants::record_mapping_revision(
        &mut tx,
        &grants::MappingInput {
            rule,
            provider,
            issuer: signing::ISSUER,
            actor: user,
            key: "synthetic-rule",
            expected_revision: 0,
            enabled: true,
            selector_kind: "group",
            claim_name: "groups",
            claim_value: "team",
            binding_format: "openmettle.project-member",
            binding_version: 1,
            binding: project.as_bytes(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn replacement_pins_the_new_rule_scope_and_assignment_and_fences_return_to_old_target() {
    let mut refresh = policy();
    refresh.deadline = Duration::from_secs(30);
    let mut f = Flow::with(Harness::with_policy(refresh).await).await;
    let mut e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    let old = e.head(&mut f).await;
    let old_project = e.project.clone();
    let old_scope = e.scope.clone();
    let (project, scope) = project(&mut f, &e.user).await;
    let rule = "00000000-0000-0000-0000-0000000002aa";
    record_rule(&mut f, rule, signing::ID, &e.user, &project).await;
    let pending = proof(&mut f, e.now - 2, json!({"groups":["team"]})).await;
    e.project = project;
    e.scope = scope;
    e.reset(
        &mut f,
        Configuration {
            rule,
            ..Default::default()
        },
    )
    .await;
    f.h.provider
        .issue_session(&mut f.api, pending, &session_policy())
        .await
        .unwrap();
    assert_eq!(e.observe(&mut f).await, Missing);
    assert_eq!(
        current(&mut f.api, &e.approval, &old_project, &session_policy())
            .await
            .unwrap(),
        Failed
    );
    e.submit(&mut f, 30, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 29, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    let (assignment,cycle,revision):(String,String,i64)=sqlx::query_as("SELECT h.assignment_id::text,h.cycle_id::text,h.revision
        FROM openmettle.membership_observations m JOIN openmettle.grant_changes h ON h.id=(m.observation).change_id
        WHERE h.scope_id=$1::uuid AND h.mapping_rule_id=$2::uuid").bind(&e.scope).bind(rule).fetch_one(&mut f.api).await.unwrap();
    assert_ne!(assignment, old.assignment);
    assert_ne!(Some(cycle), old.cycle);
    assert_eq!(revision, 1);
    e.project = old_project;
    e.scope = old_scope;
    e.reset(
        &mut f,
        Configuration {
            baseline: &old.change,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 29, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 28, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn two_provider_specific_approvals_for_one_identity_reconcile_independently() {
    let mut f = Flow::new().await;
    let mut e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    let first = e.approval.clone();
    let other = "00000000-0000-0000-0000-0000000002bb";
    let rule = "00000000-0000-0000-0000-0000000002cc";
    sqlx::query(
        "INSERT INTO openmettle.login_providers(id,issuer,client_id,changed_by,change_reason)
        VALUES ($1::uuid,$2,$3,'fixture-owner','second configuration')",
    )
    .bind(other)
    .bind(signing::ISSUER)
    .bind(signing::CLIENT)
    .execute(&mut f.owner)
    .await
    .unwrap();
    sqlx::query(APPEND)
        .bind(other)
        .bind("v1")
        .execute(&mut f.owner)
        .await
        .unwrap();
    e.approval=sqlx::query_scalar("INSERT INTO openmettle.local_identity_approvals(provider_id,identity_id,active,expires_ms,changed_by,change_reason)
        SELECT $1::uuid,identity_id,true,expires_ms,'fixture-owner','second approval' FROM openmettle.local_identity_approvals WHERE id=$2::uuid RETURNING id::text")
        .bind(other).bind(&first).fetch_one(&mut f.owner).await.unwrap();
    record_rule(&mut f, rule, other, &e.user, &e.project).await;
    e.reset(
        &mut f,
        Configuration {
            rule,
            ..Default::default()
        },
    )
    .await;
    let second =
        f.h.manager
            .register(Harness::endpoint_config(
                &f.h.server,
                &f.h.ca,
                other,
                "v1",
                signing::AUTH,
                signing::CALLBACK,
            ))
            .unwrap();
    let token = exchange(
        &mut f,
        &second,
        "synthetic-subject",
        e.now - 20,
        json!({"groups":["team"]}),
        &auth::Policy::default(),
    )
    .await;
    second
        .issue_session(&mut f.api, token, &session_policy())
        .await
        .unwrap();
    assert_eq!(e.observe(&mut f).await, Present);
    e.submit(&mut f, 10, json!([])).await; // first provider signs a removal
    assert_eq!(
        current(&mut f.api, &first, &e.project, &session_policy())
            .await
            .unwrap(),
        Absent
    );
    assert_eq!(e.observe(&mut f).await, Present);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn independent_aba_after_confirmation_invalidates_a_still_fresh_present_row() {
    let mut f = Flow::new().await;
    let e = enroll(&mut f).await;
    e.submit(&mut f, 20, json!(["team"])).await;
    let first = e.head(&mut f).await;
    assert_eq!(e.observe(&mut f).await, Present);
    // Commit both external changes after issuance. A reader never sees the intervening
    // withdrawal, and there is no subsequent login to invalidate the stored positive.
    let mut writer = WriteTransaction::begin(&mut f.api).await.unwrap();
    let revoke = grants::ChangeInput {
        assignment: e.assignment(),
        actor: &e.user,
        key: "external-revoke",
        expected_revision: first.revision,
        mapping_revision: Some(1),
        decision: grants::Decision::Revoke(first.cycle.as_deref()),
    };
    let withdrawal = grants::change_grant(&mut writer, &revoke).await.unwrap();
    let new = grants::change_grant(
        &mut writer,
        &grants::ChangeInput {
            key: "external-regrant",
            expected_revision: withdrawal.revision,
            decision: grants::Decision::Grant,
            ..revoke
        },
    )
    .await
    .unwrap();
    writer.commit().await.unwrap();
    assert_eq!(new.assignment, first.assignment);
    assert_eq!(new.revision, first.revision + 2);
    assert_ne!(new.cycle, first.cycle);
    let stored: (String, String) = sqlx::query_as(
        "SELECT (observation).state,(observation).change_id::text
        FROM openmettle.membership_observations WHERE approval_id=$1::uuid",
    )
    .bind(&e.approval)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(stored, ("present".into(), first.change));
    let raw = grants::read_assignment(&mut f.api, &e.scope, &first.assignment)
        .await
        .unwrap()
        .unwrap();
    assert!(raw.recorded_active && raw.mapping_eligible);
    assert_eq!(e.observe(&mut f).await, Failed);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn future_issue_time_records_no_evidence_and_cannot_block_a_correct_proof() {
    let mut f = Flow::new().await;
    let e = enroll(&mut f).await;
    // Within the verifier's default 60 s future skew, but after the primary clock.
    e.submit(&mut f, -30, json!(["team"])).await;
    let stored: (Option<i64>, String) = sqlx::query_as(
        "SELECT issued_ms,(observation).state FROM openmettle.membership_observations
        WHERE approval_id=$1::uuid",
    )
    .bind(&e.approval)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(stored, (None, "missing".into()));
    assert_eq!(e.observe(&mut f).await, Missing);
    e.submit(&mut f, 1, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
}

async fn new_request(f: &mut Flow) -> String {
    sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}
async fn head_of(f: &mut Flow, assignment: &str) -> grants::GrantReceipt {
    let (change, revision, granted, cycle) = sqlx::query_as(
        "SELECT h.id::text,h.revision,h.decision='grant',h.cycle_id::text
        FROM openmettle.grant_assignments g JOIN openmettle.grant_changes h
          ON h.assignment_id=g.id AND h.revision=g.last_revision WHERE g.id=$1::uuid",
    )
    .bind(assignment)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    grants::GrantReceipt {
        change,
        assignment: assignment.into(),
        revision,
        granted,
        cycle,
    }
}
fn committed(out: &std::process::Output, count: usize) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("membership withdrawal committed: {count} assignments")
    );
}
// A refusal never commits, prints nothing to stdout and never echoes an input value.
fn refused(out: &std::process::Output, inputs: &[&str]) -> String {
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    for input in inputs {
        assert!(!stderr.contains(input), "{stderr}");
    }
    stderr
}
// Each withdrawal is an ordinary v5 revoke of the exact active cycle at the next revision.
fn assert_withdrawn(before: &grants::GrantReceipt, after: &grants::GrantReceipt) {
    assert!(before.granted && !after.granted);
    assert_eq!(after.assignment, before.assignment);
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(after.cycle, before.cycle);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn withdrawal_revokes_only_mapped_grants_and_records_replayable_receipts() {
    let mut f = Flow::new().await;
    let e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    let granted = e.head(&mut f).await;
    let request = new_request(&mut f).await;
    committed(&e.withdraw(&f, OWNER, &request), 1);
    let withdrawn = e.head(&mut f).await;
    assert_withdrawn(&granted, &withdrawn);
    // The direct grant shares grantee, target, format and key, and stays recorded active.
    assert_eq!(head_of(&mut f, &e.direct.assignment).await, e.direct);
    assert_eq!(e.observe(&mut f).await, Failed);
    // The receipt names the request and operator reference, with the grantee as actor.
    // Its ADR 0006 identity is exact: the library replays it instead of reporting a conflict.
    let key = format!("membership-withdraw/{request}/{OPERATOR}/1");
    let receipts: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT actor_user_id::text,request_key,source_kind FROM openmettle.grant_changes
        WHERE starts_with(request_key,'membership-withdraw/')",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(receipts, [(e.user.clone(), key.clone(), "mapped".into())]);
    let mut tx = WriteTransaction::begin(&mut f.api).await.unwrap();
    let replay = grants::change_grant(
        &mut tx,
        &grants::ChangeInput {
            assignment: e.assignment(),
            actor: &e.user,
            key: &key,
            expected_revision: granted.revision,
            mapping_revision: Some(1),
            decision: grants::Decision::Revoke(granted.cycle.as_deref()),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(replay, withdrawn);
    // Explicit owner resynchronization adopts the withdrawal. A reused request is refused
    // even with an active grant to withdraw. A new request withdraws it.
    e.reset(
        &mut f,
        Configuration {
            baseline: &withdrawn.change,
            ..Default::default()
        },
    )
    .await;
    e.submit(&mut f, 29, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    let regranted = e.head(&mut f).await;
    let stderr = refused(
        &e.withdraw(&f, OWNER, &request),
        &[&e.approval, &request, OPERATOR],
    );
    assert!(stderr.contains("membership withdrawal refused"), "{stderr}");
    assert_eq!(e.head(&mut f).await, regranted);
    let second = new_request(&mut f).await;
    committed(&e.withdraw(&f, OWNER, &second), 1);
    assert_withdrawn(&regranted, &e.head(&mut f).await);
    // Nothing active remains: a further request is refused without changes.
    let third = new_request(&mut f).await;
    refused(
        &e.withdraw(&f, OWNER, &third),
        &[&e.approval, &third, OPERATOR],
    );
    assert_eq!(head_of(&mut f, &e.direct.assignment).await, e.direct);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn withdrawal_includes_grants_left_on_superseded_targets() {
    let mut f = Flow::new().await;
    let mut e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    let old = e.head(&mut f).await;
    let (project, scope) = project(&mut f, &e.user).await;
    let rule = "00000000-0000-0000-0000-0000000002aa";
    record_rule(&mut f, rule, signing::ID, &e.user, &project).await;
    e.project = project;
    e.scope = scope;
    e.reset(
        &mut f,
        Configuration {
            rule,
            ..Default::default()
        },
    )
    .await;
    e.submit(&mut f, 29, json!(["team"])).await;
    assert_eq!(e.observe(&mut f).await, Present);
    let assignment: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.grant_assignments WHERE mapping_rule_id=$1::uuid",
    )
    .bind(rule)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    let current = head_of(&mut f, &assignment).await;
    // Replacement does not revoke. The superseded target's derived grant is still active.
    assert_eq!(head_of(&mut f, &old.assignment).await, old);
    let request = new_request(&mut f).await;
    committed(&e.withdraw(&f, OWNER, &request), 2);
    for before in [old, current] {
        assert_withdrawn(&before, &head_of(&mut f, &before.assignment).await);
    }
    assert_eq!(head_of(&mut f, &e.direct.assignment).await, e.direct);
    assert_eq!(e.observe(&mut f).await, Failed);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn held_proof_from_before_withdrawal_cannot_regrant() {
    let mut f = Flow::new().await;
    let e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    // Exchanged before the withdrawal, against the same enrollment revision.
    let held = proof(&mut f, e.now - 20, json!({"groups":["team"]})).await;
    let request = new_request(&mut f).await;
    committed(&e.withdraw(&f, OWNER, &request), 1);
    let withdrawn = e.head(&mut f).await;
    f.h.provider
        .issue_session(&mut f.api, held, &session_policy())
        .await
        .unwrap();
    assert_eq!(e.head(&mut f).await, withdrawn);
    assert_eq!(e.observe(&mut f).await, Failed);
    // A fresh proof is fenced too until the owner resynchronizes.
    e.submit(&mut f, 10, json!(["team"])).await;
    assert_eq!(e.head(&mut f).await, withdrawn);
    assert_eq!(e.observe(&mut f).await, Failed);
}

async fn blocked_by(observer: &mut PgConnection, waiter: i32, holder: i32) -> bool {
    sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
        .bind(holder)
        .bind(waiter)
        .fetch_one(observer)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn concurrent_issuance_waits_for_withdrawal_without_deadlock() {
    let mut refresh = policy();
    refresh.deadline = Duration::from_secs(30);
    let mut f = Flow::with(Harness::with_policy(refresh).await).await;
    let e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    let held = proof(&mut f, e.now - 20, json!({"groups":["team"]})).await;
    // An independent mapped writer owns the rule. The withdrawal then waits on the rule
    // while holding the user, which is where issuance must queue behind it.
    let mut db = f.db.connect(API).await;
    let mut writer = WriteTransaction::begin(&mut db).await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.grant_mapping_rules WHERE id=$1::uuid FOR NO KEY UPDATE",
    )
    .bind(RULE)
    .execute(writer.connection().unwrap())
    .await
    .unwrap();
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(writer.connection().unwrap())
        .await
        .unwrap();
    let reader_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut f.api)
        .await
        .unwrap();
    let mut observer = sessions::statistics_observer(&f.db).await;
    let request = new_request(&mut f).await;
    let child = e.start_withdrawal(&f, OWNER, &request);
    let withdrawal = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap());
    let operator_pid: i32 = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity WHERE datname=$1 AND usename='openmettle_owner'
                 AND application_name='psql' AND wait_event_type='Lock'",
            )
            .bind(&f.db.name)
            .fetch_optional(&mut observer)
            .await
            .unwrap();
            if let Some(pid) = pid {
                break pid;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(blocked_by(&mut observer, operator_pid, writer_pid).await);
    let release = async {
        sessions::waiting(&mut observer, reader_pid).await;
        assert!(blocked_by(&mut observer, reader_pid, operator_pid).await);
        writer.commit().await.unwrap();
    };
    let policy = session_policy();
    let (identity, ()) = tokio::join!(
        f.h.provider.issue_session(&mut f.api, held, &policy),
        release
    );
    identity.unwrap();
    committed(&withdrawal.await.unwrap(), 1);
    let withdrawn = e.head(&mut f).await;
    assert!(!withdrawn.granted);
    assert_eq!(e.observe(&mut f).await, Failed);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn api_role_and_invalid_input_cannot_withdraw() {
    let mut f = Flow::new().await;
    let e = enroll(&mut f).await;
    e.submit(&mut f, 30, json!(["team"])).await;
    let granted = e.head(&mut f).await;
    let request = new_request(&mut f).await;
    refused(
        &e.withdraw(&f, API, &request),
        &[&e.approval, &request, OPERATOR],
    );
    // Non-canonical input is refused before any cast, without echoing it.
    let upper = request.to_uppercase();
    let stderr = refused(
        &e.withdraw(&f, OWNER, &upper),
        &[&e.approval, &upper, OPERATOR],
    );
    assert!(stderr.contains("membership withdrawal refused"), "{stderr}");
    assert_eq!(e.head(&mut f).await, granted);
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.grant_changes
        WHERE starts_with(request_key,'membership-withdraw/')",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(receipts, 0);
    // Control: the same canonical request succeeds as the owner.
    committed(&e.withdraw(&f, OWNER, &request), 1);
}
