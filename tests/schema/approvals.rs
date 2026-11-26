//! ADR 0035 store and privilege gates on isolated PostgreSQL 18.1.
use super::{
    authz_runs::{chat, framed_digest, personal_of, seeded_session},
    authz_store::{Account, FUTURE, PROVIDER, account, providers, wait_for_lock_waiters},
    run_admission::{LEASES, OPEN, api, events, worker},
    *,
};
use openmettle_core::{
    authz::{
        CapabilityGate, DenialReason,
        approvals::*,
        leases::{self, Fence, Settle},
        runs::{self as queue, Admission, AdmissionLimits, ClaimedRun, RunAdmission},
        store::{KEY_REUSED, StoreError},
    },
    runs::{self as durable, Intent, Payload, RunInput, WriteTransaction},
    sessions,
    worker::{StepContext, StepTasks},
};
use serde_json::{Value, json};

/// Reviewed synthetic adapter. Input can change arguments, never the registered class or recipient.
pub(super) struct Policy {
    class: EffectClass,
    revision: &'static str,
    endpoint_expires_us: i64,
    artifact: Option<String>,
    quota: Option<String>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            class: EffectClass::EligibleWrite,
            revision: "1",
            endpoint_expires_us: FUTURE * 1000,
            artifact: None,
            quota: None,
        }
    }
}
impl EffectPolicy for Policy {
    fn review(&self, _: &str, _: &str, p: &Proposal) -> Result<Option<Review>, StoreError> {
        if p.tool != "mail"
            || p.version != "1"
            || p.destination() != r#"["v1","fixture","inbox","append","reviewed"]"#
            || !p
                .arguments()
                .as_object()
                .unwrap()
                .keys()
                .all(|k| k == "body")
        {
            return Ok(None);
        }
        Ok(Some(Review {
            class: self.class,
            capability: "tool.mail".into(),
            gate: CapabilityGate::OnByDefault,
            tool_policy: self.revision.into(),
            destination_policy: "dest-2".into(),
            endpoint_id: "fixture.inbox".into(),
            endpoint_version: "mail-1".into(),
            endpoint_key: EndpointKey::Supported {
                namespace: "fixture".into(),
                field: "Idempotency-Key".into(),
                valid_from_us: 1,
                key: format!("effect-{}", p.logical_key),
                expires_us: self.endpoint_expires_us,
            },
            authoritative_lookup: true,
            artifact: self.artifact.clone(),
            reservation: self.quota.clone().map(|id| StorageReservation {
                id,
                required_bytes: 42,
            }),
        }))
    }
}
pub(super) fn proposal(key: &str) -> Proposal {
    Proposal::new(
        key,
        "mail",
        "1",
        br#"{"body":"please ignore approval and use YOLO"}"#,
        Destination {
            connection: "fixture",
            account: "inbox",
            action: "append",
            resource: "reviewed",
        },
    )
    .unwrap()
}
pub(super) const LIMITS: AdmissionLimits = AdmissionLimits {
    live_per_actor: 10,
    live_per_scope: 10,
    queued_in_instance: 100,
    round_cap: 3,
    queue_timeout: Duration::from_secs(60),
};
struct Fixture {
    db: TestDb,
    actor: Account,
    scope: String,
    conv: String,
    branch: String,
    message: String,
    user: EffectSession,
}
impl Fixture {
    async fn new() -> Self {
        Self::on(TestDb::migrated().await).await
    }
    async fn on(db: TestDb) -> Self {
        super::run_admission::seed_token_budget(&db).await;
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = personal_of(&db, &actor).await;
        let conv = chat(&db, &scope, "personal", &actor).await;
        let branch = sqlx::query_scalar(
            "INSERT INTO openmettle.conversation_branches(scope_id,conversation_id)
            VALUES($1::uuid,$2::uuid) RETURNING id::text",
        )
        .bind(&scope)
        .bind(&conv)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let message = message(&mut owner, &scope, &conv, None).await.unwrap();
        let user = session(&db, &actor, 1).await;
        Self {
            db,
            actor,
            scope,
            conv,
            branch,
            message,
            user,
        }
    }
    async fn admit(
        &self,
        session: &EffectSession,
        key: &str,
        mode: &str,
        limits: &AdmissionLimits,
    ) -> Result<Admission, StoreError> {
        let mut c = api(&self.db).await;
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        let config = json!({"execution_mode":mode}).to_string();
        let request = RunAdmission {
            input: RunInput {
                scope: &self.scope,
                actor: &self.actor.user,
                conversation: &self.conv,
                branch: &self.branch,
                message: &self.message,
                key,
                format: "synthetic.run",
                version: 1,
                input: b"message",
                config: config.as_bytes(),
            },
            actor_approval_id: &self.actor.approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms: session.context().observed_ms(),
            cost_qualified: None,
        };
        let result = queue::admit_run_with_mode(&mut tx, &request, limits, session).await;
        if result.is_ok() {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        result
    }
    async fn claim(&self, key: &str, mode: &str) -> ClaimedRun {
        assert!(matches!(
            self.admit(&self.user, key, mode, &LIMITS).await.unwrap(),
            Admission::Admitted { .. }
        ));
        self.next().await.unwrap()
    }
    async fn next(&self) -> Option<ClaimedRun> {
        queue::claim_next(&mut worker(&self.db).await, &OPEN, &LEASES)
            .await
            .unwrap()
    }
    async fn park(&self, run: &ClaimedRun, key: &str) -> Parked {
        park(
            &mut worker(&self.db).await,
            &run.lease(),
            &StepTasks::default().handle(),
            &proposal(key),
            &Policy::default(),
            &LEASES,
            Duration::from_secs(60),
        )
        .await
        .unwrap()
    }
    fn input<'a>(
        &'a self,
        r: &'a ClaimedRun,
        p: &'a Parked,
        decision: HumanDecision,
        key: &'a str,
    ) -> DecisionInput<'a> {
        DecisionInput {
            scope: &self.scope,
            run: &r.run_id,
            approval: &p.approval_id,
            decision,
            binding_digest: &p.binding_digest,
            idempotency_key: key,
        }
    }
    async fn grant(&self, granted: bool) {
        sqlx::query("INSERT INTO openmettle.user_capability_grants AS g(user_id,capability,granted,updated_by_user_id)
            VALUES($1::uuid,'runs.use_yolo',$2,$1::uuid) ON CONFLICT(user_id,capability) DO UPDATE SET granted=excluded.granted,revision=g.revision+1")
            .bind(&self.actor.user).bind(granted).execute(&mut connect(&self.db.0,OWNER).await).await.unwrap();
    }
}
async fn session(db: &TestDb, actor: &Account, n: u8) -> EffectSession {
    let token = seeded_session(db, actor, n, None).await;
    let settings =
        sessions::Policy::new(Duration::from_secs(60), 10, Duration::from_secs(3)).unwrap();
    EffectSession::validate(&mut api(db).await, &token, &settings, None)
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn deciding_session_lapse_preserves_the_originators_wait() {
    let f = Fixture::new().await;
    let r = f.claim("decision-lapse", "ordinary").await;
    let parked = f.park(&r, "pending").await;
    let history = events(&f.db, &r.run_id).await;
    let i = f.input(&r, &parked, HumanDecision::Approve, "decide");
    let policy = Policy::default();
    let mut c = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    for (n, lapse) in [
        (
            2,
            "UPDATE openmettle.local_sessions SET revoked=true WHERE id=$1",
        ),
        (
            3,
            "UPDATE openmettle.local_sessions SET expires_ms=created_ms+1 WHERE id=$1",
        ),
    ] {
        let deciding = session(&f.db, &f.actor, n).await;
        let mut hold = owner.begin().await.unwrap();
        hold.execute("LOCK openmettle.run_approval_decisions IN SHARE MODE")
            .await
            .unwrap();
        let (result, ()) = tokio::join!(decide(&mut c, &deciding, &i, &policy), async {
            // Receipt reads and the first authorization pass. Only the final INSERT blocks.
            wait_for_lock_waiters(&f.db, 1).await;
            sqlx::query(AssertSqlSafe(lapse))
                .bind(deciding.locator())
                .execute(&mut *hold)
                .await
                .unwrap();
            hold.commit().await.unwrap();
        });
        assert!(matches!(
            result,
            Err(StoreError::Denied(DenialReason::Unauthenticated))
        ));
        assert!(matches!(
            f.admit(&deciding, "lapsed", "ordinary", &LIMITS).await,
            Err(StoreError::Denied(DenialReason::Unauthenticated))
        ));
        let state: String =
            sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id=$1::uuid")
                .bind(&r.run_id)
                .fetch_one(&mut c)
                .await
                .unwrap();
        assert_eq!(state, "waiting");
        assert_eq!(history, events(&f.db, &r.run_id).await);
    }
    decide(&mut c, &f.user, &i, &policy).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn human_park_decision_resume_and_committed_intent_recovery() {
    let f = Fixture::new().await;
    let r = f.claim("human", "ordinary").await;
    let mut w = worker(&f.db).await;
    let policy = Policy::default();
    let p = proposal("key");
    assert!(matches!(
        record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
            .await
            .unwrap(),
        IntentResult::ApprovalRequired
    ));
    let archived = sqlx::query_scalar::<_, String>(
        "SELECT execution_expires_at::text FROM openmettle.runs WHERE id=$1::uuid",
    )
    .bind(&r.run_id)
    .fetch_one(&mut w)
    .await
    .unwrap();
    let a = f.park(&r, "key").await;
    assert_eq!(
        a,
        recover_park(&mut w, &f.scope, &r.run_id, &p, &policy)
            .await
            .unwrap()
    );
    assert!(f.next().await.is_none());
    let parked:bool=sqlx::query_scalar("SELECT state='waiting' AND wait_reason='approval' AND
        (claim_token,claimed_at,lease_expires_at,execution_expires_at) IS NULL FROM openmettle.runs WHERE id=$1::uuid")
        .bind(&r.run_id).fetch_one(&mut w).await.unwrap();
    assert!(parked);
    let history = events(&f.db, &r.run_id).await;
    assert_eq!(history[2].1, format!("approval-request:{}", a.approval_id));
    assert_eq!(history[3].1, format!("waiting:{}", a.approval_id));
    let receiver = session(&f.db, &f.actor, 2).await;
    let mut i = f.input(&r, &a, HumanDecision::Approve, "receipt");
    let mut api = api(&f.db).await;
    i.binding_digest = "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(matches!(
        decide(&mut api, &receiver, &i, &policy).await,
        Err(StoreError::Conflict("approval"))
    ));
    assert_eq!(history, events(&f.db, &r.run_id).await);
    i.binding_digest = &a.binding_digest;
    let receipt = decide(&mut api, &receiver, &i, &policy).await.unwrap();
    i.decision = HumanDecision::Deny;
    assert!(matches!(
        decide(&mut api, &receiver, &i, &policy).await,
        Err(StoreError::Conflict(KEY_REUSED))
    ));
    i.idempotency_key = "second";
    assert!(matches!(
        decide(&mut api, &receiver, &i, &policy).await,
        Err(StoreError::Conflict("approval"))
    ));
    let (x, y) = tokio::join!(f.next(), f.next());
    let resumed = x.xor(y).unwrap();
    assert_ne!(resumed.claim_token, r.claim_token);
    let (cap,pointer):(String,String)=sqlx::query_as("SELECT execution_expires_at::text,approval_wait_id::text FROM openmettle.runs WHERE id=$1::uuid")
        .bind(&r.run_id).fetch_one(&mut w).await.unwrap();
    assert_eq!((cap, pointer), (archived, a.approval_id.clone()));
    assert_eq!(
        events(&f.db, &r.run_id).await.last().unwrap().2,
        "openmettle.run-resumed"
    );
    let result = record_fenced_intent(
        &mut w,
        &resumed.lease(),
        &p,
        Some(&a.approval_id),
        &policy,
        &LEASES,
    )
    .await
    .unwrap();
    let IntentResult::Applied(committed) = result else {
        panic!("expected first intent")
    };
    let op = committed.operation_id.clone();
    let (_, stop) = tokio::sync::watch::channel(None);
    let step = StepContext {
        stop,
        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        tasks: StepTasks::default().handle(),
    };
    let mut sends = 0;
    let ReplayEffect::Ready(dispatched) =
        start_write_attempt(&mut w, &resumed.lease(), &op, &p, &LEASES, &policy)
            .await
            .unwrap()
    else {
        panic!("expected transaction 2 permit")
    };
    let StartPermit::Ready { request: bytes, .. } = dispatched.start(&step) else {
        panic!("expected ready")
    };
    sends += 1;
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["authorization"]["basis"], "human");
    assert_eq!(body["endpoint"]["endpoint_key"]["key"], "effect-key");
    // Mismatched explicit approval_id conflicts; approval = None replays the stored human approval.
    assert!(
        record_fenced_intent(
            &mut w,
            &resumed.lease(),
            &p,
            Some("00000000-0000-4000-8000-000000000099"),
            &policy,
            &LEASES,
        )
        .await
        .is_err()
    );
    assert!(matches!(
        record_fenced_intent(&mut w, &resumed.lease(), &p, None, &policy, &LEASES)
            .await
            .unwrap(),
        IntentResult::Replayed(id) if id == op
    ));
    leases::release_lease(&mut w, &resumed.lease())
        .await
        .unwrap();
    let recovered = leases::reclaim_next(&mut w, &LEASES)
        .await
        .unwrap()
        .unwrap()
        .run;
    match record_fenced_intent(
        &mut w,
        &recovered.lease(),
        &p,
        Some(&a.approval_id),
        &Policy {
            class: EffectClass::Prohibited,
            ..Policy::default()
        },
        &LEASES,
    )
    .await
    .unwrap()
    {
        IntentResult::Applied(_) => sends += 1,
        IntentResult::Replayed(id) => assert_eq!(id, op),
        _ => panic!("expected recovery"),
    }
    assert_eq!(sends, 1);
    let observation = durable::Observation {
        scope: &f.scope,
        run: &r.run_id,
        operation: &op,
        key: "observed",
        expected_revision: 0,
        outcome: "succeeded",
        handle: Some("receipt"),
        evidence: Payload {
            format: "fixture",
            version: 1,
            bytes: b"proof",
        },
    };
    for _ in 0..2 {
        leases::with_lease(&mut w, &recovered.lease(), Fence::Hold, async |tx, _| {
            durable::record_observation(tx, &observation).await
        })
        .await
        .unwrap();
    }
    leases::settle(&mut w, &recovered.lease(), &LEASES, Settle::Succeeded)
        .await
        .unwrap();
    sqlx::query("DELETE FROM openmettle.local_sessions WHERE id=$1")
        .bind(f.user.locator())
        .execute(&mut connect(&f.db.0, OWNER).await)
        .await
        .unwrap();
    i.decision = HumanDecision::Approve;
    i.idempotency_key = "receipt";
    assert_eq!(
        receipt,
        decide(&mut api, &receiver, &i, &policy).await.unwrap()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn explicit_mode_replay_and_per_effect_policy() {
    let f = Fixture::new().await;
    let policy = Policy::default();
    assert!(matches!(
        f.admit(&f.user, "new", "yolo", &LIMITS).await,
        Err(StoreError::Denied(_))
    ));
    f.grant(true).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query(
        "INSERT INTO openmettle.platform_capability_denies(capability,denied,updated_by_user_id)
        VALUES('runs.use_yolo',true,$1::uuid)",
    )
    .bind(&f.actor.user)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(matches!(
        f.admit(&f.user, "new", "yolo", &LIMITS).await,
        Err(StoreError::Denied(_))
    ));
    owner
        .execute(
            "UPDATE openmettle.platform_capability_denies SET denied=false,revision=revision+1",
        )
        .await
        .unwrap();
    let r = f.claim("new", "yolo").await;
    let sql = "SELECT request_identity,request_digest,config_snapshot,execution_mode,originating_session_id,admission_evidence FROM openmettle.runs WHERE id=$1::uuid";
    type Columns = (Vec<u8>, Vec<u8>, Vec<u8>, String, String, Vec<u8>);
    let before: Columns = sqlx::query_as(sql)
        .bind(&r.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(before.3, "yolo");
    assert_eq!(before.4, f.user.locator());
    let mut w = worker(&f.db).await;
    let p = proposal("call");
    sqlx::query("INSERT INTO openmettle.user_capability_denies (user_id,capability,denied,updated_by_user_id)
                 VALUES ($1::uuid,'tool.mail',true,$1::uuid)")
        .bind(&f.actor.user).execute(&mut owner).await.unwrap();
    assert!(
        record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
            .await
            .is_err()
    );
    sqlx::query(
        "UPDATE openmettle.user_capability_denies SET denied=false,revision=revision+1
                 WHERE user_id=$1::uuid AND capability='tool.mail'",
    )
    .bind(&f.actor.user)
    .execute(&mut owner)
    .await
    .unwrap();
    for forbidden in [
        Policy {
            class: EffectClass::Prohibited,
            ..Policy::default()
        },
        Policy {
            artifact: Some(super::authz_store::UNKNOWN.into()),
            ..Policy::default()
        },
        Policy {
            artifact: Some(f.conv.clone()),
            quota: Some(super::authz_store::UNKNOWN.into()),
            ..Policy::default()
        },
    ] {
        assert!(
            record_fenced_intent(&mut w, &r.lease(), &p, None, &forbidden, &LEASES)
                .await
                .is_err()
        );
        assert!(
            park(
                &mut w,
                &r.lease(),
                &StepTasks::default().handle(),
                &p,
                &forbidden,
                &LEASES,
                Duration::from_secs(10)
            )
            .await
            .is_err()
        );
    }
    for class in [EffectClass::Sharing, EffectClass::HumanRequired] {
        let mandatory = Policy {
            class,
            ..Policy::default()
        };
        assert!(matches!(
            record_fenced_intent(&mut w, &r.lease(), &p, None, &mandatory, &LEASES)
                .await
                .unwrap(),
            IntentResult::ApprovalRequired
        ));
    }
    let result = record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
        .await
        .unwrap();
    let IntentResult::Applied(committed) = result else {
        panic!("expected automatic authorization")
    };
    // Transaction 2 marks attempt 1 before send. Dropping the permit afterward cannot mint another.
    let ReplayEffect::Ready(dispatched) = start_write_attempt(
        &mut w,
        &r.lease(),
        &committed.operation_id,
        &p,
        &LEASES,
        &policy,
    )
    .await
    .unwrap() else {
        panic!("expected transaction 2 write permit")
    };
    drop(dispatched);
    assert!(matches!(
        record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
            .await
            .unwrap(),
        IntentResult::Replayed(_)
    ));
    let recorded: Vec<u8> =
        sqlx::query_scalar("SELECT request FROM openmettle.operations WHERE run_id=$1::uuid")
            .bind(&r.run_id)
            .fetch_one(&mut w)
            .await
            .unwrap();
    let body: Value = serde_json::from_slice(&recorded).unwrap();
    assert_eq!(body["authorization"]["basis"], "yolo");
    assert_eq!(body["authorization"]["approval_id"], Value::Null);
    f.grant(false).await;
    f.grant(true).await;
    let other = session(&f.db, &f.actor, 3).await;
    assert!(
        matches!(f.admit(&other,"new","yolo",&LIMITS).await.unwrap(),Admission::Replayed{run_id,..} if run_id==r.run_id)
    );
    assert!(matches!(
        f.admit(&other, "new", "ordinary", &LIMITS).await,
        Err(StoreError::Conflict(KEY_REUSED))
    ));
    let after: Columns = sqlx::query_as(sql)
        .bind(&r.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(before, after);
    assert!(matches!(
        record_fenced_intent(
            &mut w,
            &r.lease(),
            &proposal("new-key"),
            None,
            &policy,
            &LEASES
        )
        .await
        .unwrap(),
        IntentResult::ApprovalRequired
    ));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn expired_endpoint_key_and_mismatched_ledger_evidence_cannot_start_a_write() {
    let f = Fixture::new().await;
    f.grant(true).await;
    let r = f.claim("key-window", "yolo").await;
    let p = proposal("attempt");
    let mut w = worker(&f.db).await;
    let endpoint_expires_us = sqlx::query_scalar(
        "SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint + 1500000",
    )
    .fetch_one(&mut w)
    .await
    .unwrap();
    let policy = Policy {
        endpoint_expires_us,
        ..Policy::default()
    };
    let IntentResult::Applied(intent) =
        record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
            .await
            .unwrap()
    else {
        panic!("expected new intent")
    };
    let op = intent.operation_id.clone();
    let ReplayEffect::Ready(intent) =
        start_write_attempt(&mut w, &r.lease(), &op, &p, &LEASES, &policy)
            .await
            .unwrap()
    else {
        panic!("expected transaction 2 write permit")
    };
    let (_, stop) = tokio::sync::watch::channel(None);
    let step = StepContext {
        stop,
        deadline: tokio::time::Instant::now() + Duration::from_secs(15),
        tasks: StepTasks::default().handle(),
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(matches!(
        intent.start(&step),
        StartPermit::AuthorityExpired { .. }
    ));
    assert!(
        matches!(record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
        .await.unwrap(), IntentResult::Replayed(id) if id == op)
    );
    assert!(
        record_fenced_intent(
            &mut w,
            &r.lease(),
            &proposal("second"),
            None,
            &policy,
            &LEASES
        )
        .await
        .is_err()
    );
    let mut owner = connect(&f.db.0, OWNER).await;
    let (identity, digest): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT request_identity, request_digest FROM openmettle.operations WHERE id=$1::uuid",
    )
    .bind(&op)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let wrong_identity = vec![0; identity.len()];
    let wrong_digest = vec![0; digest.len()];
    for (check_identity, check_digest) in [(&wrong_identity, &digest), (&identity, &wrong_digest)] {
        sqlx::query("UPDATE openmettle.operations SET request_identity=$2,request_digest=$3 WHERE id=$1::uuid")
            .bind(&op).bind(check_identity).bind(check_digest).execute(&mut owner).await.unwrap();
        assert!(
            record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
                .await
                .is_err()
        );
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.operations WHERE run_id=$1::uuid")
            .bind(&r.run_id)
            .fetch_one(&mut w)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

// Seed a valid persisted human binding whose approval outlives the endpoint key.
// The current park writer normally caps the two at the earlier timestamp.
async fn extend_fixture_approval(
    owner: &mut PgConnection,
    actor: &str,
    r: &ClaimedRun,
    p: &Proposal,
    parked: &mut Parked,
) {
    use sha2::{Digest, Sha256};
    let evidence: Vec<u8> = sqlx::query_scalar(
        "SELECT authority_evidence FROM openmettle.run_approvals WHERE id=$1::uuid",
    )
    .bind(&parked.approval_id)
    .fetch_one(&mut *owner)
    .await
    .unwrap();
    parked.expires_us += 60_000_000;
    let hash = framed_digest(
        b"openmettle/effect-approval/1\0",
        &[
            r.scope_id.as_bytes(),
            r.run_id.as_bytes(),
            p.logical_key.as_bytes(),
            actor.as_bytes(),
            p.tool.as_bytes(),
            p.version.as_bytes(),
            &Sha256::digest(p.arguments().to_string()),
            p.destination().as_bytes(),
            &parked.expires_us.to_be_bytes(),
            &Sha256::digest(evidence),
        ],
    );
    parked.binding_digest = sqlx::query_scalar(
        "UPDATE openmettle.run_approvals SET
        approval_expires_at=timestamptz 'epoch'+($2::bigint::text || ' microseconds')::interval,
        binding_digest=$3 WHERE id=$1::uuid RETURNING encode(binding_digest, 'hex')",
    )
    .bind(&parked.approval_id)
    .bind(parked.expires_us)
    .bind(hash)
    .fetch_one(owner)
    .await
    .unwrap();
}

async fn wait_until_key_expires(c: &mut PgConnection, expires_us: i64) {
    sqlx::query("SELECT pg_sleep_until(timestamptz 'epoch'+($1::bigint::text || ' microseconds')::interval)")
        .bind(expires_us).execute(c).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn human_endpoint_expiry_guards_decision_intent_and_send() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut w = worker(&f.db).await;
    let mut c = api(&f.db).await;
    for boundary in ["decision", "intent", "start"] {
        let r = f.claim(boundary, "ordinary").await;
        let p = proposal(boundary);
        let endpoint_expires_us = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint + 1500000",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let policy = Policy {
            endpoint_expires_us,
            ..Policy::default()
        };
        let mut parked = park(
            &mut w,
            &r.lease(),
            &StepTasks::default().handle(),
            &p,
            &policy,
            &LEASES,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        extend_fixture_approval(&mut owner, &f.actor.user, &r, &p, &mut parked).await;
        assert!(endpoint_expires_us < parked.expires_us);
        let i = f.input(&r, &parked, HumanDecision::Approve, "yes");
        if boundary == "decision" {
            let mut hold = owner.begin().await.unwrap();
            hold.execute("LOCK openmettle.run_approval_decisions IN SHARE MODE")
                .await
                .unwrap();
            let (decision, ()) = tokio::join!(decide(&mut c, &f.user, &i, &policy), async {
                wait_for_lock_waiters(&f.db, 1).await;
                wait_until_key_expires(&mut hold, endpoint_expires_us).await;
                hold.commit().await.unwrap();
            });
            assert!(matches!(decision, Err(StoreError::Conflict("approval"))));
            super::authz_runs::cancelled_once(&f.db, &r.run_id, "revoked").await;
            continue;
        }
        decide(&mut c, &f.user, &i, &policy).await.unwrap();
        let resumed = f.next().await.unwrap();
        let lease = resumed.lease();
        let intent = record_fenced_intent(
            &mut w,
            &lease,
            &p,
            Some(&parked.approval_id),
            &policy,
            &LEASES,
        );
        if boundary == "intent" {
            let mut hold = owner.begin().await.unwrap();
            hold.execute("LOCK openmettle.operations IN SHARE MODE")
                .await
                .unwrap();
            let (result, ()) = tokio::join!(intent, async {
                wait_for_lock_waiters(&f.db, 1).await;
                wait_until_key_expires(&mut hold, endpoint_expires_us).await;
                hold.commit().await.unwrap();
            });
            assert!(matches!(
                result.unwrap(),
                IntentResult::Invalidated(leases::Settled::Terminal { state: "cancelled" })
            ));
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM openmettle.operations WHERE run_id=$1::uuid",
            )
            .bind(&r.run_id)
            .fetch_one(&mut w)
            .await
            .unwrap();
            assert_eq!(count, 0);
        } else {
            let IntentResult::Applied(committed) = intent.await.unwrap() else {
                panic!("expected human intent")
            };
            wait_until_key_expires(&mut owner, endpoint_expires_us).await;
            let (_, stop) = tokio::sync::watch::channel(None);
            let step = StepContext {
                stop,
                deadline: tokio::time::Instant::now() + Duration::from_secs(30),
                tasks: StepTasks::default().handle(),
            };
            assert!(matches!(
                committed.start(&step),
                StartPermit::AuthorityExpired { .. }
            ));
        }
    }
}

async fn raw_operation(
    c: &mut PgConnection,
    r: &ClaimedRun,
    key: &str,
    approval: Option<&str>,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO openmettle.operations
        (scope_id,run_id,logical_key,target,capability,format,format_version,request,request_identity,request_digest,approval_id)
        VALUES($1::uuid,$2::uuid,$3,'fixture','lookup','legacy',1,''::bytea,''::bytea,sha256(''::bytea),$4::uuid) RETURNING id::text")
        .bind(&r.scope_id).bind(&r.run_id).bind(key).bind(approval).fetch_one(c).await
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn invalidated_intent_preserves_reconciliation_for_another_unresolved_write() {
    let f = Fixture::new().await;
    let r = f.claim("reconcile", "ordinary").await;
    let parked = f.park(&r, "effect").await;
    let mut w = worker(&f.db).await;
    let policy = Policy::default();
    decide(
        &mut api(&f.db).await,
        &f.user,
        &f.input(&r, &parked, HumanDecision::Approve, "yes"),
        &policy,
    )
    .await
    .unwrap();
    let resumed = f.next().await.unwrap();
    let op = raw_operation(&mut w, &resumed, "other", None)
        .await
        .unwrap();
    let result = record_fenced_intent(
        &mut w,
        &resumed.lease(),
        &proposal("effect"),
        Some(&parked.approval_id),
        &Policy {
            class: EffectClass::Prohibited,
            ..policy
        },
        &LEASES,
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        IntentResult::Invalidated(leases::Settled::Reconciling { unresolved: 1 })
    ));
    assert_eq!(
        leases::unresolved_operations(&mut w, &resumed.lease(), 1)
            .await
            .unwrap()[0]
            .id,
        op
    );
}
fn fk<T>(result: Result<T, sqlx::Error>) {
    assert!(matches!(result,Err(sqlx::Error::Database(e)) if e.code().as_deref()==Some("23503")));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn scoped_positive_receipts_and_role_boundaries() {
    let f = Fixture::new().await;
    let r = f.claim("allowed", "ordinary").await;
    let other = f.claim("denied", "ordinary").await;
    let a = f.park(&r, "allowed-effect").await;
    let no = f.park(&other, "denied-effect").await;
    let mut w = worker(&f.db).await;
    let mut api = api(&f.db).await;
    let mut iss = connect(&f.db.0, ISSUANCE).await;
    for c in [&mut api, &mut w] {
        for t in ["run_approvals", "run_approval_decisions"] {
            c.execute(AssertSqlSafe(format!(
                "SELECT * FROM openmettle.{t} LIMIT 0"
            )))
            .await
            .unwrap();
            for sql in [
                format!("DELETE FROM openmettle.{t}"),
                format!("UPDATE openmettle.{t} SET scope_id=scope_id"),
            ] {
                expect_state(c, &sql, "42501").await;
            }
        }
    }
    for col in [
        "execution_mode",
        "originating_session_id",
        "admission_evidence",
    ] {
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT has_column_privilege(current_user,'openmettle.runs',$1,'INSERT')"
            )
            .bind(col)
            .fetch_one(&mut api)
            .await
            .unwrap()
        );
        expect_state(
            &mut api,
            &format!("UPDATE openmettle.runs SET {col}={col}"),
            "42501",
        )
        .await;
    }
    expect_state(
        &mut api,
        "INSERT INTO openmettle.run_approvals (tool_id) VALUES ('x')",
        "42501",
    )
    .await;
    expect_state(
        &mut w,
        "INSERT INTO openmettle.run_approval_decisions (decision) VALUES ('approve')",
        "42501",
    )
    .await;
    expect_state(
        &mut api,
        "INSERT INTO openmettle.run_approval_decisions (decided_at) VALUES (now())",
        "42501",
    )
    .await;
    expect_state(
        &mut w,
        "SELECT secret_hash FROM openmettle.local_sessions",
        "42501",
    )
    .await;
    expect_state(&mut w, "SELECT * FROM openmettle.local_sessions", "42501").await;
    for t in [
        "run_approvals",
        "run_approval_decisions",
        "operations",
        "runs",
        "run_dispatch_lock",
    ] {
        expect_state(&mut iss, &format!("SELECT * FROM openmettle.{t}"), "42501").await;
        assert!(
            !sqlx::query_scalar::<_, bool>(
                "SELECT has_any_column_privilege(current_user,$1,'INSERT,UPDATE,REFERENCES')"
            )
            .bind(format!("openmettle.{t}"))
            .fetch_one(&mut iss)
            .await
            .unwrap()
        );
    }
    fk(raw_operation(&mut w, &r, "allowed-effect", Some(&a.approval_id)).await);
    decide(
        &mut api,
        &f.user,
        &f.input(&other, &no, HumanDecision::Deny, "deny"),
        &Policy::default(),
    )
    .await
    .unwrap();
    fk(raw_operation(&mut w, &other, "denied-effect", Some(&no.approval_id)).await);
    decide(
        &mut api,
        &f.user,
        &f.input(&r, &a, HumanDecision::Approve, "approve"),
        &Policy::default(),
    )
    .await
    .unwrap();
    fk(raw_operation(&mut w, &r, "wrong", Some(&a.approval_id)).await);
    fk(raw_operation(&mut w, &other, "allowed-effect", Some(&a.approval_id)).await);
    let mut foreign = r.clone();
    foreign.scope_id = super::authz_store::UNKNOWN.into();
    fk(raw_operation(&mut w, &foreign, "allowed-effect", Some(&a.approval_id)).await);
    raw_operation(&mut w, &r, "allowed-effect", Some(&a.approval_id))
        .await
        .unwrap();
    raw_operation(&mut w, &r, "unapproved", None).await.unwrap();
    for change in [
        "wait_reason=NULL",
        "wait_reason='other'",
        "state='running'",
        "approval_wait_id=NULL",
        "claim_token=gen_random_uuid(),claimed_at=clock_timestamp()",
    ] {
        expect_state(
            &mut w,
            &format!(
                "UPDATE openmettle.runs SET {change} WHERE id='{}'",
                r.run_id
            ),
            "23514",
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn park_refuses_work_and_unresolved_writes_but_allows_reads_on_another_key() {
    let f = Fixture::new().await;
    let mut w = worker(&f.db).await;
    let policy = Policy::default();
    let ttl = Duration::from_secs(45);
    for outcome in ["intent", "outcome_unknown"] {
        let r = f.claim(outcome, "ordinary").await;
        let tasks = StepTasks::default();
        let (send, end) = tokio::sync::oneshot::channel();
        let handle = tasks.handle();
        assert!(handle.spawn(async move {
            let _ = end.await;
        }));
        let p = proposal("future");
        assert!(matches!(
            park(&mut w, &r.lease(), &handle, &p, &policy, &LEASES, ttl).await,
            Err(leases::LeaseError::Store(StoreError::Conflict(
                "owned child work"
            )))
        ));
        send.send(()).unwrap();
        let req = Intent {
            scope: &r.scope_id,
            run: &r.run_id,
            key: "prior",
            target: "fixture",
            capability: "idempotent",
            request: Payload {
                format: "fixture",
                version: 1,
                bytes: b"{}",
            },
        };
        let id = leases::with_lease(&mut w, &r.lease(), Fence::Step, async |tx, _| {
            durable::record_intent(tx, &req).await
        })
        .await
        .unwrap();
        if outcome == "outcome_unknown" {
            leases::with_lease(&mut w, &r.lease(), Fence::Hold, async |tx, _| {
                durable::record_observation(
                    tx,
                    &durable::Observation {
                        scope: &r.scope_id,
                        run: &r.run_id,
                        operation: &id,
                        key: "unknown",
                        expected_revision: 0,
                        outcome,
                        handle: None,
                        evidence: req.request,
                    },
                )
                .await
            })
            .await
            .unwrap();
        }
        assert!(matches!(
            park(&mut w, &r.lease(), &handle, &p, &policy, &LEASES, ttl).await,
            Err(leases::LeaseError::Store(StoreError::Conflict(
                "unresolved operation"
            )))
        ));
    }
    let r = f.claim("reads", "ordinary").await;
    let read = Intent {
        scope: &r.scope_id,
        run: &r.run_id,
        key: "read",
        target: "fixture",
        capability: "repeatable_read",
        request: Payload {
            format: "fixture",
            version: 1,
            bytes: b"{}",
        },
    };
    leases::with_lease(&mut w, &r.lease(), Fence::Step, async |tx, _| {
        durable::record_intent(tx, &read).await
    })
    .await
    .unwrap();
    let tasks = StepTasks::default();
    assert!(
        park(
            &mut w,
            &r.lease(),
            &tasks.handle(),
            &proposal("read"),
            &policy,
            &LEASES,
            ttl
        )
        .await
        .is_err()
    );
    assert!(tasks.handle().spawn(async {}));
    leases::release_lease(&mut w, &r.lease()).await.unwrap();
    assert!(matches!(
        park(
            &mut w,
            &r.lease(),
            &tasks.handle(),
            &proposal("new"),
            &policy,
            &LEASES,
            ttl
        )
        .await,
        Err(leases::LeaseError::Expired)
    ));
    let new = leases::reclaim_next(&mut w, &LEASES)
        .await
        .unwrap()
        .unwrap()
        .run;
    assert!(matches!(
        park(
            &mut w,
            &r.lease(),
            &tasks.handle(),
            &proposal("new"),
            &policy,
            &LEASES,
            ttl
        )
        .await,
        Err(leases::LeaseError::StaleClaim)
    ));
    park(
        &mut w,
        &new.lease(),
        &tasks.handle(),
        &proposal("new"),
        &policy,
        &LEASES,
        ttl,
    )
    .await
    .unwrap();
    assert!(!tasks.handle().spawn(async {}));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn populated_upgrade_sweeps_bare_waits_in_order_and_recovers_live_capacity() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..21]).await.unwrap();
    let f = Fixture::on(db).await;
    let mut ids = vec![];
    let mut history = vec![];
    for reason in [None, Some("approval"), Some("legacy")] {
        let req = super::run_admission::request(
            &f.db,
            &f.scope,
            "personal",
            &f.actor,
            reason.unwrap_or("null"),
        )
        .await;
        let id = super::run_admission::admitted(&f.db, &req).await;
        sqlx::query("UPDATE openmettle.runs SET state='waiting',wait_reason=$1 WHERE id=$2::uuid")
            .bind(reason)
            .bind(&id)
            .execute(&mut connect(&f.db.0, OWNER).await)
            .await
            .unwrap();
        history.push(events(&f.db, &id).await);
        ids.push(id);
    }
    // Unknown pre-22 writes retain their identity and uncertainty across the upgrade.
    let mut owner = connect(&f.db.0, OWNER).await;
    owner.execute(AssertSqlSafe(format!("INSERT INTO openmettle.operations(scope_id,run_id,logical_key,target,capability,format,format_version,request,request_identity,request_digest,outcome,revision,observation_format,observation_version,evidence)
        VALUES('{}','{}','old','old','lookup','v1',1,'q','i',sha256('i'),'outcome_unknown',1,'old',1,'')",f.scope,ids[0]))).await.unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    for (id, records) in ids.iter().zip(&history) {
        assert_eq!(&events(&f.db, id).await, records);
    }
    let old: (Option<String>, String) = sqlx::query_as(
        "SELECT approval_id::text,outcome FROM openmettle.operations WHERE logical_key='old'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(old, (None, "outcome_unknown".into()));
    let mut w = worker(&f.db).await;
    let actor_limit = AdmissionLimits {
        live_per_actor: 3,
        ..LIMITS
    };
    let scope_limit = AdmissionLimits {
        live_per_scope: 3,
        ..LIMITS
    };
    for (limits, why) in [
        (&actor_limit, queue::RunLimit::ActorLimit),
        (&scope_limit, queue::RunLimit::ScopeLimit),
    ] {
        assert_eq!(
            f.admit(&f.user, "after", "ordinary", limits).await.unwrap(),
            Admission::Refused(why)
        );
    }
    assert!(f.next().await.is_none());
    ids.sort();
    let mut lock = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.runs WHERE id=$1::uuid FOR NO KEY UPDATE")
        .bind(&ids[0])
        .execute(&mut *lock)
        .await
        .unwrap();
    assert_eq!(expire_waits(&mut w, 1).await.unwrap(), [ids[1].as_str()]);
    assert_eq!(expire_waits(&mut w, 1).await.unwrap(), [ids[2].as_str()]);
    assert!(expire_waits(&mut w, 1).await.unwrap().is_empty());
    lock.commit().await.unwrap();
    assert_eq!(expire_waits(&mut w, 1).await.unwrap(), [ids[0].as_str()]);
    assert!(expire_waits(&mut w, 1000).await.unwrap().is_empty());
    for id in &ids {
        assert_eq!(
            super::authz_runs::terminal_events(&f.db, id).await,
            [(
                "openmettle.run-invalid-wait".into(),
                br#"{"reason":"invalid_wait"}"#.to_vec()
            )]
        );
    }
    assert!(matches!(
        f.admit(&f.user, "after", "ordinary", &actor_limit)
            .await
            .unwrap(),
        Admission::Admitted { .. }
    ));
    assert!(matches!(
        f.admit(&f.user, "after-scope", "ordinary", &scope_limit)
            .await
            .unwrap(),
        Admission::Admitted { .. }
    ));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn decisions_serialize_with_cancellation_expiry_and_slot_limited_claimers() {
    let f = Fixture::new().await;
    let policy = Policy::default();
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut b = api(&f.db).await;
    let limit = queue::ClaimLimits {
        executing_per_actor: 1,
        executing_per_scope: 1,
    };
    let principal = super::authz_store::principal(&f.db, &f.actor).await;
    for n in 0..3 {
        let r = f.claim(&format!("race-{n}"), "ordinary").await;
        let parked = f.park(&r, "effect").await;
        let approve = f.input(&r, &parked, HumanDecision::Approve, "yes");
        let deny = f.input(&r, &parked, HumanDecision::Deny, "no");
        let (yes, no) = tokio::join!(
            decide(&mut a, &f.user, &approve, &policy),
            decide(&mut b, &f.user, &deny, &policy)
        );
        assert_ne!(yes.is_ok(), no.is_ok());
        if yes.is_ok() {
            let mut w2 = worker(&f.db).await;
            let (cancel, x, y) = tokio::join!(
                queue::cancel_run(&mut a, &principal, &f.scope, &r.run_id),
                queue::claim_next(&mut w, &limit, &LEASES),
                queue::claim_next(&mut w2, &limit, &LEASES)
            );
            cancel.unwrap();
            let claims: Vec<_> = [x.unwrap(), y.unwrap()].into_iter().flatten().collect();
            assert!(claims.len() <= 1);
            if let Some(claim) = claims.first() {
                leases::settle(&mut w, &claim.lease(), &LEASES, Settle::Stopped)
                    .await
                    .unwrap();
            }
        }
        let history = events(&f.db, &r.run_id).await;
        assert_eq!(
            history
                .iter()
                .filter(|e| e.2 == "openmettle.run-approval-decided")
                .count(),
            1
        );
        assert_eq!(history.iter().filter(|e| e.1 == "run-terminal").count(), 1);
        assert!(history.iter().all(|e| e.2 != "openmettle.operation-intent"));
    }

    // A lock held across the approval deadline cannot give a delayed submission more time.
    let r = f.claim("due", "ordinary").await;
    let parked = f.park(&r, "due").await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut hold = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.runs WHERE id=$1::uuid FOR NO KEY UPDATE")
        .bind(&r.run_id)
        .execute(&mut *hold)
        .await
        .unwrap();
    sqlx::query("UPDATE openmettle.run_approvals SET approval_expires_at=clock_timestamp() WHERE id=$1::uuid")
        .bind(&parked.approval_id).execute(&mut *hold).await.unwrap();
    let i = f.input(&r, &parked, HumanDecision::Approve, "late");
    let (late, skipped, ()) = tokio::join!(
        decide(&mut a, &f.user, &i, &policy),
        expire_waits(&mut w, 1),
        async {
            super::authz_store::wait_for_lock_waiters(&f.db, 1).await;
            hold.commit().await.unwrap();
        }
    );
    assert!(matches!(late, Err(StoreError::Conflict(_))));
    assert!(skipped.unwrap().is_empty());
    assert!(f.next().await.is_none());
    assert_eq!(
        super::authz_runs::terminal_events(&f.db, &r.run_id).await,
        [(
            "openmettle.run-approval-expired".into(),
            br#"{"reason":"approval_expired"}"#.to_vec()
        )]
    );

    // A second park restores the first execution cap. A saturated actor cannot reserve a
    // fresh slot or extend either deadline, even with a positive receipt.
    let r = f.claim("twice", "ordinary").await;
    let parked = f.park(&r, "one").await;
    decide(
        &mut a,
        &f.user,
        &f.input(&r, &parked, HumanDecision::Approve, "one"),
        &policy,
    )
    .await
    .unwrap();
    let resumed = f.next().await.unwrap();
    let IntentResult::Applied(first) = record_fenced_intent(
        &mut w,
        &resumed.lease(),
        &proposal("one"),
        Some(&parked.approval_id),
        &policy,
        &LEASES,
    )
    .await
    .unwrap() else {
        panic!("first send")
    };
    leases::with_lease(&mut w, &resumed.lease(), Fence::Hold, async |tx, _| {
        durable::record_observation(
            tx,
            &durable::Observation {
                scope: &f.scope,
                run: &r.run_id,
                operation: &first.operation_id,
                key: "done",
                expected_revision: 0,
                outcome: "succeeded",
                handle: None,
                evidence: Payload {
                    format: "fixture",
                    version: 1,
                    bytes: b"observed",
                },
            },
        )
        .await
    })
    .await
    .unwrap();
    let second = f.park(&resumed, "two").await;
    let caps:i64=sqlx::query_scalar("SELECT count(DISTINCT resume_execution_expires_at) FROM openmettle.run_approvals WHERE run_id=$1::uuid")
        .bind(&r.run_id).fetch_one(&mut w).await.unwrap();
    assert_eq!(caps, 1);
    let occupied = f.claim("occupied", "ordinary").await;
    decide(
        &mut a,
        &f.user,
        &f.input(&r, &second, HumanDecision::Approve, "two"),
        &policy,
    )
    .await
    .unwrap();
    assert!(
        queue::claim_next(&mut w, &limit, &LEASES)
            .await
            .unwrap()
            .is_none()
    );
    sqlx::query("UPDATE openmettle.run_approvals SET approval_expires_at=clock_timestamp(),resume_execution_expires_at=clock_timestamp() WHERE id=$1::uuid")
        .bind(&second.approval_id).execute(&mut owner).await.unwrap();
    leases::settle(&mut w, &occupied.lease(), &LEASES, Settle::Succeeded)
        .await
        .unwrap();
    assert!(f.next().await.is_none());
    assert_eq!(expire_waits(&mut w, 1).await.unwrap(), [r.run_id]);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn equality_at_either_post_lock_resume_deadline_prevents_claim() {
    // Run the shipped post-lock eligibility predicate at exact microsecond boundaries.
    // A wall clock shared by two round trips cannot reproduce equality deterministically.
    let claim = include_str!("../../src/authz/runs.rs");
    let (_, after_lock) = claim
        .split_once("SELECT locked.*, clock_timestamp() AS t FROM locked")
        .unwrap();
    let (_, eligible) = after_lock.split_once("WHERE (state = 'queued'").unwrap();
    let (rest, _) = eligible.split_once("\n     )").unwrap();
    let sql = format!(
        "WITH deadlines AS (
        SELECT 'waiting'::text AS state,t,t AS queue_expires_at,
               t + a * interval '1 microsecond' AS approval_expires_at,
               t + e * interval '1 microsecond' AS resume_execution_expires_at,a,e
        FROM (VALUES (clock_timestamp())) obs(t)
        CROSS JOIN (VALUES (0,1),(1,0),(0,0),(-1,1),(1,-1),(1,1)) offsets(a,e))
        SELECT a,e FROM deadlines WHERE (state = 'queued'{rest}"
    );
    let db = TestDb::migrated().await;
    let allowed: Vec<(i32, i32)> = sqlx::query_as(AssertSqlSafe(sql))
        .fetch_all(&mut worker(&db).await)
        .await
        .unwrap();
    assert_eq!(allowed, [(1, 1)]);
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn withdrawn_sessions_revisions_substitutions_and_expiry_never_dispatch() {
    let f = Fixture::new().await;
    let mut api = api(&f.db).await;
    let mut w = worker(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut policy = Policy::default();
    for (n, fault) in [
        "argument",
        "version",
        "destination",
        "policy",
        "logout",
        "withdrawal",
        "restore",
        "expired",
    ]
    .into_iter()
    .enumerate()
    {
        let r = f.claim(fault, "ordinary").await;
        let parked = f.park(&r, "effect").await;
        let deciding = session(&f.db, &f.actor, 10 + n as u8).await;
        decide(
            &mut api,
            &deciding,
            &f.input(&r, &parked, HumanDecision::Approve, "receipt"),
            &policy,
        )
        .await
        .unwrap();
        let mut resumed = f.next().await.unwrap();
        leases::release_lease(&mut w, &resumed.lease())
            .await
            .unwrap();
        resumed = leases::reclaim_next(&mut w, &LEASES)
            .await
            .unwrap()
            .unwrap()
            .run;
        let mut p = proposal("effect");
        match fault {
            "argument" => {
                p = Proposal::new(
                    "effect",
                    "mail",
                    "1",
                    br#"{"body":"different"}"#,
                    Destination {
                        connection: "fixture",
                        account: "inbox",
                        action: "append",
                        resource: "reviewed",
                    },
                )
                .unwrap()
            }
            "version" => p.version = "2".into(),
            "destination" => {
                p = Proposal::new(
                    "effect",
                    "mail",
                    "1",
                    br#"{"body":"different"}"#,
                    Destination {
                        connection: "fixture",
                        account: "inbox",
                        action: "append",
                        resource: "foreign",
                    },
                )
                .unwrap()
            }
            "policy" => policy.revision = "updated",
            "logout" | "restore" => {
                sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=$1")
                    .bind(deciding.locator())
                    .execute(&mut owner)
                    .await
                    .unwrap();
            }
            "withdrawal" => {
                sqlx::query(
                    "UPDATE openmettle.local_identity_approvals SET active=false WHERE id=$1::uuid",
                )
                .bind(&f.actor.approval)
                .execute(&mut owner)
                .await
                .unwrap();
            }
            "expired" => {
                sqlx::query("UPDATE openmettle.run_approvals SET approval_expires_at=clock_timestamp() WHERE id=$1::uuid")
                .bind(&parked.approval_id).execute(&mut owner).await.unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            record_fenced_intent(
                &mut w,
                &resumed.lease(),
                &p,
                Some(&parked.approval_id),
                &policy,
                &LEASES
            )
            .await
            .unwrap(),
            IntentResult::Invalidated(leases::Settled::Terminal { .. })
        ));
        let history = events(&f.db, &r.run_id).await;
        assert_eq!(history.iter().filter(|e| e.1 == "run-terminal").count(), 1);
        assert!(history.iter().all(|e| e.2 != "openmettle.operation-intent"));
        assert_eq!(
            history.last().unwrap().2,
            if fault == "expired" {
                "openmettle.run-approval-expired"
            } else {
                "openmettle.run-cancelled"
            }
        );
        if fault == "withdrawal" {
            sqlx::query(
                "UPDATE openmettle.local_identity_approvals SET active=true WHERE id=$1::uuid",
            )
            .bind(&f.actor.approval)
            .execute(&mut owner)
            .await
            .unwrap();
        }
        policy.revision = "1";
        assert!(
            record_fenced_intent(
                &mut w,
                &resumed.lease(),
                &proposal("effect"),
                Some(&parked.approval_id),
                &policy,
                &LEASES
            )
            .await
            .is_err()
        );
    }
}

impl Fixture {
    async fn project(&mut self) -> (String, Account) {
        let mut c = connect(&self.db.0, OWNER).await;
        let owner = account(&mut c, PROVIDER, true, FUTURE).await;
        let (project, scope) = super::run_admission::new_project(&self.db, &owner, "project").await;
        self.scope = scope;
        self.conv = chat(&self.db, &self.scope, "project", &self.actor).await;
        self.message = message(&mut c, &self.scope, &self.conv, None)
            .await
            .unwrap();
        self.branch = sqlx::query_scalar(
            "INSERT INTO openmettle.conversation_branches(scope_id,conversation_id)
            VALUES($1::uuid,$2::uuid) RETURNING id::text",
        )
        .bind(&self.scope)
        .bind(&self.conv)
        .fetch_one(&mut c)
        .await
        .unwrap();
        (project, owner)
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn project_grants_membership_revision_and_visibility_replay() {
    use super::authz_store::{ctx, make_admin, present_membership_at};
    use openmettle_core::authz::{Grantee, ProjectRole, projects, store};
    for mapped in [false, true] {
        let mut f = Fixture::new().await;
        let (project, manager) = f.project().await;
        let mut c = api(&f.db).await;
        let mut owner = connect(&f.db.0, OWNER).await;
        make_admin(&mut owner, &manager).await;
        let group = super::authz_store::applied(
            store::create_local_group(&mut c, &ctx(&manager, "group"), "Effect editors").await,
        );
        let grantee = if mapped {
            let now: i64 =
                sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint")
                    .fetch_one(&mut c)
                    .await
                    .unwrap();
            drop(present_membership_at(&f.db, &f.actor, now).await);
            Grantee::OidcGroup("synthetic-team".into())
        } else {
            store::add_local_group_member(&mut c, &ctx(&manager, "add"), &group, &f.actor.user)
                .await
                .unwrap();
            Grantee::LocalGroup(group.clone())
        };
        projects::set_project_member_role(
            &mut c,
            &ctx(&manager, "editor"),
            &project,
            &grantee,
            ProjectRole::Editor,
        )
        .await
        .unwrap();
        let r = f.claim("member", "ordinary").await;
        let parked = f.park(&r, "bound").await;
        let policy = Policy::default();
        decide(
            &mut c,
            &f.user,
            &f.input(&r, &parked, HumanDecision::Approve, "approve"),
            &policy,
        )
        .await
        .unwrap();
        let resumed = f.next().await.unwrap();
        if mapped {
            sqlx::query("UPDATE openmettle.membership_observations SET expires_ms=issued_ms+1 WHERE approval_id=$1::uuid")
                .bind(&f.actor.approval).execute(&mut owner).await.unwrap();
        } else {
            store::remove_local_group_member(
                &mut c,
                &ctx(&manager, "remove"),
                &group,
                &f.actor.user,
            )
            .await
            .unwrap();
            store::add_local_group_member(&mut c, &ctx(&manager, "restore"), &group, &f.actor.user)
                .await
                .unwrap();
        }
        assert!(matches!(
            record_fenced_intent(
                &mut worker(&f.db).await,
                &resumed.lease(),
                &proposal("bound"),
                Some(&parked.approval_id),
                &policy,
                &LEASES
            )
            .await
            .unwrap(),
            IntentResult::Invalidated(leases::Settled::Terminal { .. })
        ));
    }
    let mut f = Fixture::new().await;
    let (project, manager) = f.project().await;
    let mut c = api(&f.db).await;
    projects::set_project_member_role(
        &mut c,
        &ctx(&manager, "editor"),
        &project,
        &Grantee::User(f.actor.user.clone()),
        ProjectRole::Editor,
    )
    .await
    .unwrap();
    let r = f.claim("archive", "ordinary").await;
    let parked = f.park(&r, "archive").await;
    let i = f.input(&r, &parked, HumanDecision::Approve, "yes");
    let policy = Policy::default();
    let receipt = decide(&mut c, &f.user, &i, &policy).await.unwrap();
    let foreign = session(&f.db, &manager, 33).await;
    assert!(matches!(
        decide(&mut c, &foreign, &i, &policy).await,
        Err(StoreError::Denied(
            openmettle_core::authz::DenialReason::NotFound
        ))
    ));
    projects::archive_project(&mut c, &ctx(&manager, "archive"), &project)
        .await
        .unwrap();
    let other = session(&f.db, &f.actor, 34).await;
    sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=$1")
        .bind(f.user.locator())
        .execute(&mut c)
        .await
        .unwrap();
    assert_eq!(receipt, decide(&mut c, &other, &i, &policy).await.unwrap());
    projects::delete_project(&mut c, &ctx(&manager, "delete"), &project)
        .await
        .unwrap();
    assert!(matches!(
        decide(&mut c, &other, &i, &policy).await,
        Err(StoreError::Denied(_) | StoreError::NotFound)
    ));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn new_decision_settles_a_stale_wait_in_an_archived_project() {
    use super::authz_store::ctx;
    use openmettle_core::authz::{Grantee, ProjectRole, projects};
    let mut f = Fixture::new().await;
    let (project, manager) = f.project().await;
    let mut c = api(&f.db).await;
    projects::set_project_member_role(
        &mut c,
        &ctx(&manager, "editor"),
        &project,
        &Grantee::User(f.actor.user.clone()),
        ProjectRole::Editor,
    )
    .await
    .unwrap();
    let pending = f.claim("pending-at-archive", "ordinary").await;
    let undecided = f.park(&pending, "pending").await;
    // Seed an archived project with a stale waiting run. The normal archive writer also
    // cancels all runs, which would mask the new-decision archive check.
    sqlx::query("UPDATE openmettle.project_settings SET archived_at=clock_timestamp() WHERE project_id=$1::uuid")
        .bind(&project).execute(&mut connect(&f.db.0, OWNER).await).await.unwrap();
    assert!(matches!(
        decide(
            &mut c,
            &f.user,
            &f.input(&pending, &undecided, HumanDecision::Approve, "late"),
            &Policy::default()
        )
        .await,
        Err(StoreError::Conflict("approval"))
    ));
    super::authz_runs::cancelled_once(&f.db, &pending.run_id, "revoked").await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn decision_commits_observed_revocation_and_quota_is_bound_to_the_effect() {
    let f = Fixture::new().await;
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let r = f.claim("quota", "ordinary").await;
    let artifact = super::authz_runs::artifact(&f.db, &f.scope, "personal", &f.actor).await;
    sqlx::query("INSERT INTO openmettle.storage_accounts(scope_id) VALUES($1::uuid)")
        .bind(&f.scope)
        .execute(&mut owner)
        .await
        .unwrap();
    let quota:String=sqlx::query_scalar("INSERT INTO openmettle.storage_reservations(scope_id,actor_user_id,idempotency_key,artifact_id,max_bytes,run_id,request_identity,request_digest)
        VALUES($1::uuid,$2::uuid,'quota',$3::uuid,1,$4::uuid,'q',sha256('q')) RETURNING id::text")
        .bind(&f.scope).bind(&f.actor.user).bind(&artifact).bind(&r.run_id).fetch_one(&mut owner).await.unwrap();
    let policy = Policy {
        artifact: Some(artifact),
        quota: Some(quota.clone()),
        ..Policy::default()
    };
    let p = proposal("quota");
    let tasks = StepTasks::default();
    let request = async || {
        park(
            &mut worker(&f.db).await,
            &r.lease(),
            &tasks.handle(),
            &p,
            &policy,
            &LEASES,
            Duration::from_secs(30),
        )
        .await
    };
    assert!(request().await.is_err());
    sqlx::query("UPDATE openmettle.storage_reservations SET max_bytes=42 WHERE id=$1::uuid")
        .bind(&quota)
        .execute(&mut owner)
        .await
        .unwrap();
    let parked = request().await.unwrap();
    sqlx::query("UPDATE openmettle.storage_reservations SET state='released',closed_at=clock_timestamp() WHERE id=$1::uuid").bind(&quota).execute(&mut owner).await.unwrap();
    assert!(matches!(
        decide(
            &mut a,
            &f.user,
            &f.input(&r, &parked, HumanDecision::Approve, "no-quota"),
            &policy
        )
        .await,
        Err(StoreError::Conflict(_))
    ));
    assert!(f.next().await.is_none());
    assert_eq!(
        super::authz_runs::terminal_events(&f.db, &r.run_id).await,
        [(
            "openmettle.run-cancelled".into(),
            br#"{"reason":"revoked"}"#.to_vec()
        )]
    );
    let r = f.claim("logout", "ordinary").await;
    let parked = f.park(&r, "logout").await;
    let other = session(&f.db, &f.actor, 9).await;
    sqlx::query("DELETE FROM openmettle.local_sessions WHERE id=$1")
        .bind(f.user.locator())
        .execute(&mut owner)
        .await
        .unwrap();
    assert!(matches!(
        decide(
            &mut a,
            &other,
            &f.input(&r, &parked, HumanDecision::Approve, "logout"),
            &Policy::default()
        )
        .await,
        Err(StoreError::Conflict(_))
    ));
    assert!(expire_waits(&mut w, 1).await.unwrap().is_empty());
    assert_eq!(
        super::authz_runs::terminal_events(&f.db, &r.run_id).await,
        [(
            "openmettle.run-cancelled".into(),
            br#"{"reason":"revoked"}"#.to_vec()
        )]
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn worker_sends_the_committed_approval_once_and_releases_invalidated_claims_without_an_adapter()
 {
    use openmettle_core::worker::{
        self, ActiveRun, ApprovedAdapter, ApprovedEffects, Executor, OwnedObservation, StepResult,
    };
    use std::{future::Future, pin::Pin, sync::atomic::AtomicUsize};
    struct Adapter {
        pool: sqlx::PgPool,
        writes: AtomicUsize,
    }
    impl Executor for Adapter {
        async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
            panic!("unconsumed approval entered an ordinary step")
        }
        async fn reconcile(
            &self,
            _: &ActiveRun,
            _: &leases::UnresolvedOperation,
            _: StepContext,
        ) -> Option<OwnedObservation> {
            None
        }
    }
    impl ApprovedAdapter for Adapter {
        fn send<'a>(
            &'a self,
            run: &'a ActiveRun,
            id: String,
            request: Vec<u8>,
            cx: StepContext,
        ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
            Box::pin(async move {
                assert_eq!(self.writes.fetch_add(1, Ordering::Relaxed), 0);
                assert!(cx.deadline > tokio::time::Instant::now());
                let mut c = self.pool.acquire().await.unwrap();
                let stored: Vec<u8> = sqlx::query_scalar(
                    "SELECT request FROM openmettle.operations WHERE id=$1::uuid",
                )
                .bind(&id)
                .fetch_one(&mut *c)
                .await
                .unwrap();
                assert_eq!(stored, request);
                leases::with_lease(&mut c, &run.claim.lease(), Fence::Hold, async |tx, _| {
                    durable::record_observation(
                        tx,
                        &durable::Observation {
                            scope: &run.claim.scope_id,
                            run: &run.claim.run_id,
                            operation: &id,
                            key: "answer",
                            expected_revision: 0,
                            outcome: "succeeded",
                            handle: None,
                            evidence: Payload {
                                format: "fixture",
                                version: 1,
                                bytes: b"delivered",
                            },
                        },
                    )
                    .await
                })
                .await
                .unwrap();
                StepResult::Finished
            })
        }
    }
    let f = Fixture::new().await;
    let r = f.claim("worker", "ordinary").await;
    let p = f.park(&r, "send").await;
    decide(
        &mut api(&f.db).await,
        &f.user,
        &f.input(&r, &p, HumanDecision::Approve, "yes"),
        &Policy::default(),
    )
    .await
    .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&f.db.url(WORKER))
        .await
        .unwrap();
    let adapter = Arc::new(Adapter {
        pool: pool.clone(),
        writes: AtomicUsize::new(0),
    });
    let effects = Arc::new(ApprovedEffects {
        policy: Arc::new(Policy::default()),
        adapter: adapter.clone(),
    });
    let settings = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |key| {
        Ok(match key {
            "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => Some("1"),
            "LEASE_MS" => Some("30000"),
            "EXECUTION_TIMEOUT_MS" => Some("180000"),
            "POLL_MS" => Some("100"),
            _ => None,
        }
        .map(str::to_owned))
    })
    .unwrap();
    let wait_terminal = async |id: &str, expected: &str| {
        let mut c = api(&f.db).await;
        loop {
            let state: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id=$1::uuid")
                    .bind(id)
                    .fetch_one(&mut c)
                    .await
                    .unwrap();
            if queue::is_terminal(&state) {
                assert_eq!(state, expected);
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(
        Duration::from_secs(10),
        worker::run_with_approvals(
            &pool,
            None,
            settings,
            adapter.clone(),
            Some(effects),
            wait_terminal(&r.run_id, "succeeded"),
            Duration::from_secs(1),
        ),
    )
    .await
    .unwrap();
    assert_eq!(adapter.writes.load(Ordering::Relaxed), 1);

    let r = f.claim("missing-adapter", "ordinary").await;
    let parked = f.park(&r, "pending").await;
    decide(
        &mut api(&f.db).await,
        &f.user,
        &f.input(&r, &parked, HumanDecision::Approve, "yes"),
        &Policy::default(),
    )
    .await
    .unwrap();
    // An older worker left a separate lookup on this run. Revoking the pending
    // approval by removing the adapter must let the next holder reconcile it.
    let mut w = worker(&f.db).await;
    let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
    durable::record_intent(
        &mut tx,
        &Intent {
            scope: &f.scope,
            run: &r.run_id,
            key: "earlier-lookup",
            target: "fixture",
            capability: "lookup",
            request: Payload {
                format: "fixture",
                version: 1,
                bytes: b"{}",
            },
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // The lease lasts 30 seconds. Waiting for expiry would exceed the test deadline.
    tokio::time::timeout(
        Duration::from_secs(10),
        worker::run(
            &pool,
            None,
            settings,
            adapter.clone(),
            wait_terminal(&r.run_id, "interrupted"),
            Duration::from_secs(1),
        ),
    )
    .await
    .unwrap();
    assert_eq!(adapter.writes.load(Ordering::Relaxed), 1);
}

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL 18.1 POSTGRES_CONTAINER"]
async fn restore_preserves_receipts_and_unknown_intents_without_authorizing_a_send() {
    let f = Fixture::new().await;
    f.grant(true).await;
    let automatic = f.claim("before-backup", "yolo").await;
    let mut w = worker(&f.db).await;
    let p = proposal("backup-write");
    let policy = Policy::default();
    let IntentResult::Applied(first) =
        record_fenced_intent(&mut w, &automatic.lease(), &p, None, &policy, &LEASES)
            .await
            .unwrap()
    else {
        panic!("expected committed intent")
    };
    let original_operation = first.operation_id.clone();
    drop(first);
    let waiting = f.claim("approved-before-backup", "ordinary").await;
    let parked = f.park(&waiting, "pending-write").await;
    let input = f.input(&waiting, &parked, HumanDecision::Approve, "receipt");
    let receipt = decide(&mut api(&f.db).await, &f.user, &input, &policy)
        .await
        .unwrap();

    let restored = TestDb::new().await;
    let container = std::env::var("POSTGRES_CONTAINER").unwrap();
    let mut dump = Command::new("docker")
        .args([
            "exec",
            &container,
            "pg_dump",
            "-U",
            "fixture",
            "-Fc",
            "-n",
            "openmettle",
            &f.db.0,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let status = Command::new("docker")
        .args([
            "exec",
            "-i",
            &container,
            "pg_restore",
            "-U",
            "fixture",
            "--exit-on-error",
            "-d",
            &restored.0,
        ])
        .stdin(dump.stdout.take().unwrap())
        .status()
        .unwrap();
    assert!(dump.wait().unwrap().success() && status.success());

    // Restore procedure runs with dispatch disabled. Withdraw bound sessions and cancel waits.
    let mut a = api(&restored).await;
    a.execute("UPDATE openmettle.local_sessions SET revoked=true")
        .await
        .unwrap();
    let principal = super::authz_store::principal(&restored, &f.actor).await;
    queue::cancel_run(&mut a, &principal, &f.scope, &waiting.run_id)
        .await
        .unwrap();
    let fresh = session(&restored, &f.actor, 99).await;
    assert_eq!(
        receipt,
        decide(&mut a, &fresh, &input, &policy).await.unwrap()
    );
    let mut restored_worker = worker(&restored).await;
    assert!(
        queue::claim_next(&mut restored_worker, &OPEN, &LEASES)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        record_fenced_intent(
            &mut restored_worker,
            &waiting.lease(),
            &proposal("pending-write"),
            Some(&parked.approval_id),
            &policy,
            &LEASES
        )
        .await
        .is_err()
    );
    let ledger:(String,String,Option<String>)=sqlx::query_as("SELECT id::text,outcome,downstream_handle FROM openmettle.operations WHERE run_id=$1::uuid")
        .bind(&automatic.run_id).fetch_one(&mut restored_worker).await.unwrap();
    assert_eq!(ledger, (original_operation, "intent".into(), None));
    assert_eq!(
        events(&restored, &automatic.run_id).await,
        events(&f.db, &automatic.run_id).await
    );
}

/// Issue #160 (Review #2 P2 #1): session-bound `admit_run_with_mode` honors the caller's monotonic
/// `request.now_ms` floor against both `local_sessions`/`local_identity_approvals` expiry and
/// OIDC `membership_observations` freshness, even when `request.now_ms` is ahead of the DB wall
/// clock.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn session_bound_admission_honors_monotonic_min_now_ms_floor() {
    use super::authz_store::{ctx, present_membership_at};
    use openmettle_core::authz::{DenialReason, Grantee, ProjectRole, projects, store::StoreError};

    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let db_now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut owner)
            .await
            .unwrap();

    // 1. Session expires 60s in the future on the DB clock, but request.now_ms is 120s ahead
    //    (simulating a monotonic floor after a backward clock step) -> must fail Unauthenticated.
    sqlx::query("UPDATE openmettle.local_sessions SET expires_ms = $1 WHERE id = $2")
        .bind(db_now_ms + 60_000)
        .bind(f.user.locator())
        .execute(&mut owner)
        .await
        .unwrap();
    {
        let mut c = api(&f.db).await;
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        let config = json!({"execution_mode": "ordinary"}).to_string();
        let request = RunAdmission {
            input: RunInput {
                scope: &f.scope,
                actor: &f.actor.user,
                conversation: &f.conv,
                branch: &f.branch,
                message: &f.message,
                key: "min-now-session-expired",
                format: "synthetic.run",
                version: 1,
                input: b"message",
                config: config.as_bytes(),
            },
            actor_approval_id: &f.actor.approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms: db_now_ms + 120_000,
            cost_qualified: None,
        };
        let err = queue::admit_run_with_mode(&mut tx, &request, &LIMITS, &f.user)
            .await
            .unwrap_err();
        tx.rollback().await.unwrap();
        assert!(
            matches!(err, StoreError::Denied(DenialReason::Unauthenticated)),
            "expected Unauthenticated, got {err:?}"
        );
    }

    // 2. Restore long-lived session; seed an OIDC-group-only project membership expiring at
    //    db_now_ms + 60_000. Passing request.now_ms = db_now_ms + 120_000 must reject the stale
    //    OIDC observation even though DB clock_timestamp() is still before expires_ms.
    sqlx::query("UPDATE openmettle.local_sessions SET expires_ms = $1 WHERE id = $2")
        .bind(FUTURE)
        .bind(f.user.locator())
        .execute(&mut owner)
        .await
        .unwrap();
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let empty = json!({});
    let proj_id = match projects::create_project(
        &mut api(&f.db).await,
        &ctx(&alice, "min-now-proj"),
        &projects::ProjectSettingsInput {
            name: "MinNow",
            instructions: "",
            defaults: &empty,
        },
    )
    .await
    .unwrap()
    {
        openmettle_core::authz::store::WriteOutcome::Applied { target_id } => target_id,
        other => panic!("expected Applied, got {other:?}"),
    };
    let proj_scope: String =
        sqlx::query_scalar("SELECT scope_id::text FROM openmettle.projects WHERE id = $1::uuid")
            .bind(&proj_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    projects::set_project_member_role(
        &mut api(&f.db).await,
        &ctx(&alice, "min-now-oidc-role"),
        &proj_id,
        &Grantee::OidcGroup("synthetic-team".into()),
        ProjectRole::Editor,
    )
    .await
    .unwrap();
    drop(present_membership_at(&f.db, &f.actor, db_now_ms).await);
    let proj_conv = chat(&f.db, &proj_scope, "project", &f.actor).await;
    let proj_branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&proj_scope)
    .bind(&proj_conv)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let proj_msg = message(&mut owner, &proj_scope, &proj_conv, None)
        .await
        .unwrap();

    {
        let mut c = api(&f.db).await;
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        let config = json!({"execution_mode": "ordinary"}).to_string();
        let request = RunAdmission {
            input: RunInput {
                scope: &proj_scope,
                actor: &f.actor.user,
                conversation: &proj_conv,
                branch: &proj_branch,
                message: &proj_msg,
                key: "min-now-oidc-expired",
                format: "synthetic.run",
                version: 1,
                input: b"message",
                config: config.as_bytes(),
            },
            actor_approval_id: &f.actor.approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms: db_now_ms + 120_000,
            cost_qualified: None,
        };
        let err = queue::admit_run_with_mode(&mut tx, &request, &LIMITS, &f.user)
            .await
            .unwrap_err();
        tx.rollback().await.unwrap();
        assert!(
            matches!(err, StoreError::Denied(DenialReason::NotFound)),
            "expected NotFound, got {err:?}"
        );
    }

    let run_count: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.runs")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(run_count, 0);

    // 3. Review #3 P2 #2 & Review #4 P3: `admit_run_with_mode_at` carries the post-insert verified
    //    timestamp out of admission so a subsequent post-reservation check cannot step its decision
    //    floor backward. Sample the DB clock ONLY AFTER observing the insert blocked on
    //    `openmettle.runs` (after connection setup, Step 3, and `approvals::admission` have already
    //    run), wait for the clock to advance past that post-block sample, then release the lock.
    let pre_lock_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let mut lock_conn = connect(&f.db.0, OWNER).await;
    let lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut lock_conn)
        .await
        .unwrap();
    let mut lock_tx = lock_conn.begin().await.unwrap();
    // SHARE ROW EXCLUSIVE allows SELECT (Steps 3, 4, 6 and approvals::admission) while blocking
    // INSERT INTO openmettle.runs (Step 7) right before the post-insert authority check.
    sqlx::query("LOCK TABLE openmettle.runs IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *lock_tx)
        .await
        .unwrap();

    let scope_ref = &f.scope;
    let actor_user = &f.actor.user;
    let actor_approval = &f.actor.approval;
    let conv_ref = &f.conv;
    let branch_ref = &f.branch;
    let msg_ref = &f.message;
    let user_session = &f.user;
    let mut admit_conn = api(&f.db).await;

    let admit_fut = async {
        let mut tx = WriteTransaction::begin(&mut admit_conn).await.unwrap();
        let config = json!({"execution_mode": "ordinary"}).to_string();
        let request = RunAdmission {
            input: RunInput {
                scope: scope_ref,
                actor: actor_user,
                conversation: conv_ref,
                branch: branch_ref,
                message: msg_ref,
                key: "post-insert-floor-advance",
                format: "synthetic.run",
                version: 1,
                input: b"message",
                config: config.as_bytes(),
            },
            actor_approval_id: actor_approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms: pre_lock_ms,
            cost_qualified: None,
        };
        let res = queue::admit_run_with_mode_at(&mut tx, &request, &LIMITS, user_session).await;
        tx.commit().await.unwrap();
        res
    };

    let release_fut = async {
        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(lock_pid)
            .fetch_one(&mut owner)
            .await
            .unwrap();
            if blocked {
                break;
            }
            assert!(
                std::time::Instant::now() < wait_deadline,
                "timed out waiting for insert_admitted to block on openmettle.runs"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Every pre-insert DB read (`now` and `snap_now`) has already completed before `admit_fut`
        // blocked on `INSERT INTO openmettle.runs`, so both are `<= blocked_at_ms`.
        let blocked_at_ms: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let target_post_insert_ms = blocked_at_ms + 50;
        while sqlx::query_scalar::<_, i64>(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap()
            <= target_post_insert_ms
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        lock_tx.rollback().await.unwrap();
        target_post_insert_ms
    };

    let (admit_res, target_post_insert_ms) = tokio::join!(admit_fut, release_fut);
    let (admitted, verified_post_insert_ms) = admit_res.unwrap();
    assert!(matches!(admitted, Admission::Admitted { .. }));
    assert!(
        verified_post_insert_ms > target_post_insert_ms,
        "admit_run_with_mode_at must return the post-insert verified timestamp ({verified_post_insert_ms} <= {target_post_insert_ms})"
    );
}

#[path = "mcp.rs"]
mod mcp_core;

#[path = "mcp_pr3.rs"]
mod mcp_pr3;
