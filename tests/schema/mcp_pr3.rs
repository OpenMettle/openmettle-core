//! ADR 0039 PR3 verification on isolated PostgreSQL 18.1 and synthetic `rcgen` TLS:
//! migration 0039 rollout gate + terminal write trigger, PENDING_EFFECT 3-valued logic,
//! two-phase durable write intents, MCP 2026-07-28 transport/adapter, fault/retry matrix,
//! destination-authorized reconciliation, spill + artifact.read_range, and PLAN-10/PLAN-22 bounds.

use super::*;
use openmettle_core::{
    artifact_fs::Store,
    mcp::{
        self, INLINE_BYTES, ScopedAdapter,
        contract::{
            ExternalRegistry, ExternalToolContract, IdempotencyCarrier, IdempotencyWindow,
            ReconcileSpec,
        },
        external::{
            CredentialOutcome, CredentialRequest, DestinationAuthorizer, ExternalCall,
            ExternalMcpAdapter, GatedCredentialProvider, McpCredential, McpCredentialProvider,
            ReconcileTarget,
        },
    },
    provider_http::{
        Trust,
        mcp::{McpTimeouts, McpTransport},
    },
    worker::{
        self, ActiveRun, ApprovedAdapter, ApprovedEffects, DeclaredTool, Executor,
        OwnedObservation, StepResult, Stop,
    },
};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::Instant,
};

fn fresh_step(secs: u64) -> (tokio::sync::watch::Sender<Option<Stop>>, StepContext) {
    let (stop, rx) = tokio::sync::watch::channel(None);
    (
        stop,
        StepContext {
            stop: rx,
            deadline: Instant::now() + Duration::from_secs(secs),
            tasks: StepTasks::default().handle(),
        },
    )
}

fn admin_command(db_url: &str, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_openmettle-admin"));
    scrub_env(&mut cmd);
    cmd.env("OPENMETTLE_ADMIN_DATABASE_URL", db_url)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_cli(&mut cmd, "openmettle-admin")
}

// --- Synthetic rcgen TLS MCP Server on TEST_GATEWAY_HOST ------------------------------------

struct CapturedRequest {
    head: String,
    body: Value,
}

type TlsScript = Arc<dyn Fn(&CapturedRequest) -> Vec<u8> + Send + Sync>;

struct SyntheticMcpServer {
    host: String,
    ip: IpAddr,
    port: u16,
    ca_pem: Vec<u8>,
    requests: Arc<AtomicUsize>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl SyntheticMcpServer {
    async fn start(script: impl Fn(&CapturedRequest) -> Vec<u8> + Send + Sync + 'static) -> Self {
        let host = std::env::var("TEST_GATEWAY_HOST")
            .expect("TEST_GATEWAY_HOST must name a private address of this host");
        let mut ips: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(&*host, 0))
            .expect("TEST_GATEWAY_HOST resolves")
            .map(|a| a.ip())
            .collect();
        ips.sort();
        ips.dedup();
        let [ip] = ips[..] else {
            panic!("TEST_GATEWAY_HOST must resolve to one address");
        };
        let ca = super::super::ca::Ca::new();
        let identity = ca.leaf(&host, false);
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(identity.chain, identity.key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let script: TlsScript = Arc::new(script);
        let req_count = requests.clone();
        let cap_log = captured.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let script = script.clone();
                let req_count = req_count.clone();
                let cap_log = cap_log.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Some((head, body_bytes)) = read_http_request(&mut tls).await else {
                        return;
                    };
                    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
                    let cap = CapturedRequest { head, body };
                    req_count.fetch_add(1, Ordering::SeqCst);
                    let reply = script(&cap);
                    cap_log.lock().unwrap().push(cap);
                    let _ = tls.write_all(&reply).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            host,
            ip,
            port,
            ca_pem: ca.pem(),
            requests,
            captured,
        }
    }

    fn transport(&self) -> Arc<McpTransport> {
        self.transport_with_timeouts(McpTimeouts {
            setup: Duration::from_secs(5),
            idle_read: Duration::from_secs(5),
            call: Duration::from_secs(10),
        })
    }

    fn transport_with_timeouts(&self, timeouts: McpTimeouts) -> Arc<McpTransport> {
        let prefix = if self.ip.is_ipv4() { 32 } else { 128 };
        let range = format!("{}/{prefix}", self.ip);
        Arc::new(
            McpTransport::new(
                &format!("https://{}:{}/mcp", self.host, self.port),
                Trust::Bundle(&self.ca_pem),
                &[&range],
                timeouts,
            )
            .unwrap(),
        )
    }
}

async fn read_http_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Option<(String, Vec<u8>)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    let end = loop {
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 || data.len() > 256 * 1024 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
    };
    let head = String::from_utf8(data[..end].to_vec()).ok()?;
    let length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = data[end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&buf[..n]);
    }
    Some((head, body))
}

fn http_response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} OK\r\ncontent-length: {}\r\n", body.len());
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

fn jsonrpc_ok(id: &str, text: &str, structured: Option<Value>) -> Vec<u8> {
    let mut result = json!({"content": [{"type": "text", "text": text}]});
    if let Some(s) = structured {
        result["structuredContent"] = s;
    }
    let body = json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
    http_response(
        200,
        &[("content-type", "application/json")],
        body.as_bytes(),
    )
}

// --- Credential & Reconcile Authorizer Fixtures ---------------------------------------------

struct CountingCredentials {
    token: Option<String>,
    lookups: Arc<AtomicUsize>,
}

impl McpCredentialProvider for CountingCredentials {
    fn resolve<'a>(
        &'a self,
        _request: CredentialRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = CredentialOutcome> + Send + 'a>> {
        Box::pin(async move {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            match &self.token {
                Some(t) => CredentialOutcome::Ready(McpCredential::bearer(t.clone())),
                None => CredentialOutcome::Unavailable,
            }
        })
    }
}

struct ToggleReconcileAuth {
    allowed: Arc<AtomicBool>,
    checks: Arc<AtomicUsize>,
}

impl DestinationAuthorizer for ToggleReconcileAuth {
    fn authorize_reconcile<'a>(
        &'a self,
        _conn: &'a mut PgConnection,
        _target: ReconcileTarget<'a>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            self.checks.fetch_add(1, Ordering::SeqCst);
            self.allowed.load(Ordering::SeqCst)
        })
    }
}

fn make_contract(
    tool_id: &str,
    remote_name: &str,
    class: EffectClass,
    idempotency: Option<IdempotencyWindow>,
    authoritative_lookup: bool,
    reconcile: Option<ReconcileSpec>,
) -> ExternalToolContract {
    ExternalToolContract {
        tool_id: tool_id.into(),
        remote_name: remote_name.into(),
        version: "1".into(),
        description: format!("Synthetic {tool_id}"),
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["item"],
            "properties": {
                "item": {"type": "string", "minLength": 1, "maxLength": 128}
            }
        }),
        schema_digest: [0; 32],
        connection_id: "synth-mcp".into(),
        account_id: "acct-1".into(),
        action: "invoke".into(),
        resource_field: Some("item".into()),
        fixed_resource: "default".into(),
        class,
        capability: "tool.mail".into(),
        gate: CapabilityGate::OnByDefault,
        tool_policy: "mcp.v1".into(),
        destination_policy: "synth.v1".into(),
        endpoint_id: "synth-mcp".into(),
        endpoint_version: "1".into(),
        idempotency,
        authoritative_lookup,
        semantic_errors_are_side_effect_free: true,
        handle_field: Some("handle".into()),
        reconcile,
        call_timeout: Duration::from_secs(10),
    }
}

fn test_registry(expires_us: i64) -> ExternalRegistry {
    let mut reg = ExternalRegistry::new();
    reg.register(make_contract(
        "mcp.read",
        "execute_sql",
        EffectClass::Read,
        None,
        false,
        None,
    ))
    .unwrap();
    reg.register(make_contract(
        "mcp.idem",
        "left\tright",
        EffectClass::EligibleWrite,
        Some(IdempotencyWindow {
            namespace: "synth".into(),
            carrier: IdempotencyCarrier::Header("Idempotency-Key".into()),
            valid_from_us: 1,
            expires_us,
        }),
        true,
        Some(ReconcileSpec {
            lookup_tool: "mcp.status".into(),
            lookup_scope: "status.read".into(),
            handle_argument: Some("handle".into()),
            deterministic_key_argument: Some("idem_key".into()),
            status_field: "status".into(),
        }),
    ))
    .unwrap();
    reg.register(make_contract(
        "mcp.lookup_handle",
        "mcp.lookup_handle",
        EffectClass::EligibleWrite,
        None,
        true,
        Some(ReconcileSpec {
            lookup_tool: "mcp.status".into(),
            lookup_scope: "status.read".into(),
            handle_argument: Some("handle".into()),
            deterministic_key_argument: None,
            status_field: "status".into(),
        }),
    ))
    .unwrap();
    reg.register(make_contract(
        "mcp.lookup_det",
        "mcp.lookup_det",
        EffectClass::EligibleWrite,
        None,
        true,
        Some(ReconcileSpec {
            lookup_tool: "mcp.status".into(),
            lookup_scope: "status.read".into(),
            handle_argument: Some("handle".into()),
            deterministic_key_argument: Some("logical_key".into()),
            status_field: "status".into(),
        }),
    ))
    .unwrap();
    reg.register(make_contract(
        "mcp.nonrep",
        "mcp.nonrep",
        EffectClass::EligibleWrite,
        None,
        false,
        None,
    ))
    .unwrap();
    reg
}

// ============================================================================================
// 1. Migration 0039: rollout gate, openmettle-admin activation, boundaries & trigger
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn migration_0039_rollout_gate_admin_activation_and_terminal_write_trigger() {
    // (a) Fresh bootstrap from version 0 starts with `two_phase_effect_intents_enabled = true`.
    let fresh = Fixture::new().await;
    let mut w = worker(&fresh.db).await;
    let mut a = api(&fresh.db).await;
    let mut owner = connect(&fresh.db.0, OWNER).await;
    assert!(two_phase_effect_intents_enabled(&mut w).await.unwrap());
    assert!(two_phase_effect_intents_enabled(&mut a).await.unwrap());
    for c in [&mut w, &mut a] {
        let err = sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = false",
        )
        .execute(&mut *c)
        .await
        .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
    }
    let op_upd =
        sqlx::query("UPDATE openmettle.operations SET dispatched_attempts = 1 WHERE false")
            .execute(&mut a)
            .await
            .unwrap_err();
    assert_eq!(
        op_upd.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );

    // (b) Populated upgrade from 0038 -> 0039 starts with `two_phase_effect_intents_enabled = false`.
    let upgraded_db = TestDb::new().await;
    migrate::apply(
        &upgraded_db.settings(Duration::from_secs(10)),
        &MIGRATIONS[..38],
    )
    .await
    .unwrap();
    let f = Fixture::on(upgraded_db).await;
    f.grant(true).await;
    migrate::apply(&f.db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();

    let mut uw = worker(&f.db).await;
    assert!(!two_phase_effect_intents_enabled(&mut uw).await.unwrap());

    // While gate is false:
    // 1. Legacy non-MCP writes keep `dispatched_attempts IS NULL`.
    let r = f.claim("legacy-compat", "yolo").await;
    let p_legacy = proposal("legacy-write");
    let IntentResult::Applied(legacy_committed) = record_fenced_intent(
        &mut uw,
        &r.lease(),
        &p_legacy,
        None,
        &Policy::default(),
        &LEASES,
    )
    .await
    .unwrap() else {
        panic!("expected legacy write intent");
    };
    let legacy_attempts: Option<i32> = sqlx::query_scalar(
        "SELECT dispatched_attempts FROM openmettle.operations WHERE id = $1::uuid",
    )
    .bind(&legacy_committed.operation_id)
    .fetch_one(&mut uw)
    .await
    .unwrap();
    assert_eq!(legacy_attempts, None);

    // 2. ScopedAdapter fails closed with zero new operations rows while gate is false.
    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("vol"));
    std::fs::create_dir(&root).unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    let (_stop_tx, step) = fresh_step(20);
    let active = ActiveRun {
        claim: r.clone(),
        state: leases::ExecState::Running,
        execution_deadline: step.deadline,
    };
    let scoped = ScopedAdapter::new(worker_pool.clone(), store.clone(), LEASES);
    let read_args = json!({
        "artifact_id": "00000000-0000-4000-8000-000000000001",
        "revision_id": "00000000-0000-4000-8000-000000000002"
    })
    .to_string();
    let StepResult::ToolOutput(refused_scoped) = scoped
        .call(
            &active,
            step.clone(),
            "gated-read",
            mcp::READ_RANGE,
            "1",
            read_args.as_bytes(),
        )
        .await
    else {
        panic!("expected ToolOutput refusal when feature gate is false");
    };
    assert_eq!(
        serde_json::from_str::<Value>(&refused_scoped).unwrap()["fault_code"],
        "terminal_refusal"
    );
    let op_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid")
            .bind(&r.run_id)
            .fetch_one(&mut uw)
            .await
            .unwrap();
    assert_eq!(
        op_count, 1,
        "gated ScopedAdapter must create 0 operation rows"
    );

    // (c) `openmettle-admin runtime activate-two-phase-intents` is idempotent and flips gate to true.
    for _ in 0..2 {
        let out = admin_command(&f.db.url(OWNER), &["runtime", "activate-two-phase-intents"]);
        assert!(
            out.status.success(),
            "admin activation failed: {}",
            stderr(&out)
        );
    }
    assert!(two_phase_effect_intents_enabled(&mut uw).await.unwrap());

    // After activation, new writes start with `dispatched_attempts = 0`.
    let r2 = f.claim("post-activate", "yolo").await;
    let p_two_phase = proposal("two-phase-write");
    let IntentResult::Applied(tp_committed) = record_fenced_intent(
        &mut uw,
        &r2.lease(),
        &p_two_phase,
        None,
        &Policy::default(),
        &LEASES,
    )
    .await
    .unwrap() else {
        panic!("expected two-phase write intent");
    };
    let tp_attempts: Option<i32> = sqlx::query_scalar(
        "SELECT dispatched_attempts FROM openmettle.operations WHERE id = $1::uuid",
    )
    .bind(&tp_committed.operation_id)
    .fetch_one(&mut uw)
    .await
    .unwrap();
    assert_eq!(tp_attempts, Some(0));

    // (d) Defense-in-depth trigger `openmettle.resolve_terminal_write_intents()`:
    // - Rejects `state = 'succeeded'` with ERRCODE 23514 whenever ANY open write exists (even `0`).
    let mut u_owner = connect(&f.db.0, OWNER).await;
    let succ_err = sqlx::query(
        "UPDATE openmettle.runs SET state = 'succeeded', wait_reason = NULL WHERE id = $1::uuid",
    )
    .bind(&r2.run_id)
    .execute(&mut u_owner)
    .await
    .unwrap_err();
    assert_eq!(
        succ_err.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );

    // - On terminal non-succeeded (`failed`, `cancelled`, `interrupted`), transitions remaining
    //   rev-0 write intents to `outcome = 'outcome_unknown', revision = 1` strictly before `run-terminal`.
    for (i, target_state) in ["failed", "cancelled", "interrupted"]
        .into_iter()
        .enumerate()
    {
        let rt = fresh.claim(&format!("trig-{i}"), "ordinary").await;
        let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
        let op_id = durable::record_intent(
            &mut tx,
            &Intent {
                scope: &fresh.scope,
                run: &rt.run_id,
                key: "raw-write",
                target: "dest",
                capability: "non_repeatable",
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

        let mut tx = WriteTransaction::begin(&mut owner).await.unwrap();
        sqlx::query(
            "UPDATE openmettle.runs SET state = $2, wait_reason = NULL WHERE id = $1::uuid",
        )
        .bind(&rt.run_id)
        .bind(target_state)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();
        durable::append_event(
            &mut tx,
            &fresh.scope,
            &rt.run_id,
            "run-terminal",
            Payload {
                format: "openmettle.run-failed",
                version: 1,
                bytes: br#"{"reason":"step_failed"}"#,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let (outcome, rev): (String, i64) = sqlx::query_as(
            "SELECT outcome, revision FROM openmettle.operations WHERE id = $1::uuid",
        )
        .bind(&op_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((outcome.as_str(), rev), ("outcome_unknown", 1));

        // Verify exact event ordering: unresolved-write:<op> strictly precedes run-terminal.
        let evs = events(&fresh.db, &rt.run_id).await;
        let obs_pos = evs
            .iter()
            .position(|e| e.1 == format!("unresolved-write:{op_id}"))
            .expect("unresolved-write observation event");
        let term_pos = evs
            .iter()
            .position(|e| e.1 == "run-terminal")
            .expect("run-terminal event");
        assert!(obs_pos < term_pos);
        assert_eq!(term_pos + 1, evs.len());

        // Idempotent replay of the trigger's exact ADR 0004 observation identity succeeds.
        let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
        let replay_rev = durable::record_observation(
            &mut tx,
            &durable::Observation {
                scope: &fresh.scope,
                run: &rt.run_id,
                operation: &op_id,
                key: &format!("unresolved-write:{op_id}"),
                expected_revision: 0,
                outcome: "outcome_unknown",
                handle: None,
                evidence: Payload {
                    format: "openmettle.unresolved-write",
                    version: 1,
                    bytes: br#"{"reason":"unresolved_write_intent"}"#,
                },
            },
        )
        .await
        .unwrap();
        assert_eq!(replay_rev, 1);
        tx.commit().await.unwrap();

        // Terminal cursor at last_event_sequence sees 0 subsequent events (`204 No Content` SSE).
        let last_seq: i64 = sqlx::query_scalar(
            "SELECT last_event_sequence FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid",
        )
        .bind(&fresh.scope)
        .bind(&rt.run_id)
        .fetch_one(&mut a)
        .await
        .unwrap();
        assert_eq!(last_seq, evs.last().unwrap().0);
        let after_term: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.run_events WHERE scope_id=$1::uuid AND run_id=$2::uuid AND sequence > $3",
        )
        .bind(&fresh.scope)
        .bind(&rt.run_id)
        .bind(last_seq)
        .fetch_one(&mut a)
        .await
        .unwrap();
        assert_eq!(after_term, 0);
    }
}

// ============================================================================================
// 2. PENDING_EFFECT 3-valued logic, Handoff (> lease vs <= lease), Cancel, Guards, Mixed Writes
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn pending_effect_three_valued_logic_handoff_cancel_guards_and_mixed_writes() {
    let f = Fixture::new().await;
    f.grant(true).await;
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let policy = Policy::default();

    // --- (a) PENDING_EFFECT 3-valued logic across none, 0, NULL, 1, succeeded ---
    let r = f.claim("pending-3vl", "ordinary").await;
    let p = proposal("p3vl");
    let parked = park(
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
    let decider = session(&f.db, &f.actor, 10).await;
    decide(
        &mut a,
        &decider,
        &f.input(&r, &parked, HumanDecision::Approve, "ok"),
        &policy,
    )
    .await
    .unwrap();
    let r = f.next().await.unwrap();

    // No operation row yet -> pending_effect discovers it via worker::execute path (check SQL directly).
    let pending_sql = "SELECT a.id::text FROM openmettle.runs r
        LEFT JOIN openmettle.run_approvals a ON a.id=r.approval_wait_id
          AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id=a.run_id AND o.logical_key=a.logical_key
            AND (o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE)
        WHERE r.id=$1::uuid";
    let discovered = async |c: &mut PgConnection| -> Option<String> {
        sqlx::query_scalar(pending_sql)
            .bind(&r.run_id)
            .fetch_one(c)
            .await
            .unwrap()
    };
    assert_eq!(
        discovered(&mut w).await.as_deref(),
        Some(parked.approval_id.as_str())
    );

    // Insert Tx1 write (`dispatched_attempts = 0`) -> STILL discovered!
    let IntentResult::Applied(committed) = record_fenced_intent(
        &mut w,
        &r.lease(),
        &p,
        Some(&parked.approval_id),
        &policy,
        &LEASES,
    )
    .await
    .unwrap() else {
        panic!("expected Tx1 write");
    };
    assert_eq!(
        discovered(&mut w).await.as_deref(),
        Some(parked.approval_id.as_str())
    );

    // Settle::Succeeded and park MUST refuse while `dispatched_attempts = 0` write is open!
    assert!(matches!(
        leases::settle(&mut w, &r.lease(), &LEASES, Settle::Succeeded).await,
        Err(leases::LeaseError::Store(StoreError::Conflict(
            "unresolved operation"
        )))
    ));
    assert!(matches!(
        park(
            &mut w,
            &r.lease(),
            &StepTasks::default().handle(),
            &proposal("second-park"),
            &policy,
            &LEASES,
            Duration::from_secs(60),
        )
        .await,
        Err(leases::LeaseError::Store(StoreError::Conflict(
            "unresolved operation"
        )))
    ));

    // Legacy `dispatched_attempts IS NULL` -> NOT discovered (3-valued `UNKNOWN IS NOT TRUE = TRUE`).
    let r_null = f.claim("pending-null", "ordinary").await;
    let p_null = proposal("pnull");
    let parked_null = park(
        &mut w,
        &r_null.lease(),
        &StepTasks::default().handle(),
        &p_null,
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    decide(
        &mut a,
        &decider,
        &f.input(&r_null, &parked_null, HumanDecision::Approve, "ok-null"),
        &policy,
    )
    .await
    .unwrap();
    let r_null = f.next().await.unwrap();
    sqlx::query(
        "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = false",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let IntentResult::Applied(_) = record_fenced_intent(
        &mut w,
        &r_null.lease(),
        &p_null,
        Some(&parked_null.approval_id),
        &policy,
        &LEASES,
    )
    .await
    .unwrap() else {
        panic!("expected legacy NULL write");
    };
    sqlx::query(
        "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = true",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let null_found: Option<String> = sqlx::query_scalar(pending_sql)
        .bind(&r_null.run_id)
        .fetch_one(&mut w)
        .await
        .unwrap();
    assert_eq!(
        null_found, None,
        "NULL dispatched_attempts must stay excluded"
    );

    // Advance `committed` to `dispatched_attempts = 1` -> NOT discovered.
    assert!(matches!(
        start_write_attempt(
            &mut w,
            &r.lease(),
            &committed.operation_id,
            &p,
            &LEASES,
            &policy
        )
        .await
        .unwrap(),
        ReplayEffect::Ready(_)
    ));
    assert_eq!(discovered(&mut w).await, None);
    for r_done in [&r, &r_null] {
        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&r_done.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        leases::settle(&mut w, &r_done.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // --- (b) Consumed human approval AND automatic YOLO write Handoff (> lease -> reclaim & once) ---
    struct SingleSendExecutor {
        pool: PgPool,
        sends: Arc<AtomicUsize>,
        handoff_first: Arc<AtomicBool>,
        done: Arc<tokio::sync::Notify>,
    }
    impl Executor for SingleSendExecutor {
        async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
            self.done.notify_one();
            StepResult::Finished
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
    impl ApprovedAdapter for SingleSendExecutor {
        fn send<'a>(
            &'a self,
            run: &'a ActiveRun,
            op: String,
            _: Vec<u8>,
            _: StepContext,
        ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
            Box::pin(async move {
                assert!(!self.handoff_first.load(Ordering::SeqCst));
                self.sends.fetch_add(1, Ordering::SeqCst);
                let mut c = self.pool.acquire().await.unwrap();
                leases::with_lease(&mut c, &run.claim.lease(), Fence::Hold, async |tx, _| {
                    durable::record_observation(
                        tx,
                        &durable::Observation {
                            scope: &run.claim.scope_id,
                            run: &run.claim.run_id,
                            operation: &op,
                            key: &format!("obs:{op}"),
                            expected_revision: 0,
                            outcome: "succeeded",
                            handle: None,
                            evidence: Payload {
                                format: "fixture",
                                version: 1,
                                bytes: b"ok",
                            },
                        },
                    )
                    .await
                })
                .await
                .unwrap();
                StepResult::ToolOutput("done".into())
            })
        }
    }

    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    for (label, human) in [("human-handoff", true), ("yolo-handoff", false)] {
        let rh = f
            .claim(label, if human { "ordinary" } else { "yolo" })
            .await;
        let ph = proposal(label);
        let (rh, approval_id) = if human {
            let pk = park(
                &mut w,
                &rh.lease(),
                &StepTasks::default().handle(),
                &ph,
                &policy,
                &LEASES,
                Duration::from_secs(60),
            )
            .await
            .unwrap();
            decide(
                &mut a,
                &decider,
                &f.input(&rh, &pk, HumanDecision::Approve, label),
                &policy,
            )
            .await
            .unwrap();
            (f.next().await.unwrap(), Some(pk.approval_id))
        } else {
            (rh, None)
        };
        // Worker 1 commits Tx1 (`dispatched_attempts = 0`) and hands off before Tx2 (> lease left).
        let IntentResult::Applied(tx1) = record_fenced_intent(
            &mut w,
            &rh.lease(),
            &ph,
            approval_id.as_deref(),
            &policy,
            &LEASES,
        )
        .await
        .unwrap() else {
            panic!("expected Tx1 {label}");
        };
        leases::release_lease(&mut w, &rh.lease()).await.unwrap();

        // Worker 2 runs `worker::run_with_approvals`, reclaims, discovers it, executes ONCE, finishes!
        let sends = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(tokio::sync::Notify::new());
        let exec = Arc::new(SingleSendExecutor {
            pool: worker_pool.clone(),
            sends: sends.clone(),
            handoff_first: Arc::new(AtomicBool::new(false)),
            done: done.clone(),
        });
        let approved = Arc::new(ApprovedEffects {
            policy: Arc::new(Policy::default()),
            adapter: exec.clone(),
        });
        let settings = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
            Ok(Some(
                match k {
                    "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                    "LEASE_MS" => "30000",
                    "EXECUTION_TIMEOUT_MS" => "180000",
                    "POLL_MS" => "100",
                    "SWEEP_MS" => "1000",
                    _ => return Ok(None),
                }
                .into(),
            ))
        })
        .unwrap();
        let (shut_tx, shut_rx) = oneshot::channel();
        let task = tokio::spawn({
            let pool = worker_pool.clone();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec,
                    Some(approved),
                    async move {
                        let _ = shut_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        tokio::time::timeout(Duration::from_secs(10), done.notified())
            .await
            .expect("successor completed reclaimed zero-attempt write");
        let _ = shut_tx.send(());
        task.await.unwrap();

        assert_eq!(sends.load(Ordering::SeqCst), 1, "{label} sent once");
        let (run_state, op_outcome, attempts): (String, String, i32) = sqlx::query_as(
            "SELECT r.state, o.outcome, o.dispatched_attempts
               FROM openmettle.runs r JOIN openmettle.operations o ON o.run_id = r.id
              WHERE r.id = $1::uuid AND o.id = $2::uuid",
        )
        .bind(&rh.run_id)
        .bind(&tx1.operation_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            (run_state.as_str(), op_outcome.as_str(), attempts),
            ("succeeded", "succeeded", 1),
            "{label}"
        );
    }

    // --- (c) Handoff with `<= settings.lease` remaining -> immediate DeadlineExceeded + failed ---
    let r_short = f.claim("short-handoff", "yolo").await;
    let p_short = proposal("short-op");
    let IntentResult::Applied(short_op) =
        record_fenced_intent(&mut w, &r_short.lease(), &p_short, None, &policy, &LEASES)
            .await
            .unwrap()
    else {
        panic!("expected short Tx1");
    };
    // Now run an actual worker holding the run, shrink `execution_expires_at` to 10s (< 30s lease)
    // while held, and return `StepResult::Handoff` -> `WorkEnd::Handoff` -> `leases::handoff`:
    // must immediately settle `Resolution::DeadlineExceeded` and close `dispatched_attempts = 0` to `failed`!
    struct HandoffOnce {
        owner_url: String,
        shut: Mutex<Option<oneshot::Sender<()>>>,
        handed: Arc<tokio::sync::Notify>,
    }
    impl Executor for HandoffOnce {
        async fn step(&self, run: &ActiveRun, _: StepContext) -> StepResult {
            let mut own = sqlx::PgConnection::connect(&self.owner_url).await.unwrap();
            sqlx::query(
                "UPDATE openmettle.runs
                    SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '10 seconds'),
                        execution_expires_at = clock_timestamp() + interval '10 seconds'
                  WHERE id = $1::uuid",
            )
            .bind(&run.claim.run_id)
            .execute(&mut own)
            .await
            .unwrap();
            if let Some(tx) = self.shut.lock().unwrap().take() {
                let _ = tx.send(());
            }
            self.handed.notify_one();
            StepResult::Handoff
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
    // Directly test `Settle::Succeeded` guard when `!time` with open `dispatched_attempts = 0`
    // on a separate short-deadline run, then run `HandoffOnce` on `r_short`!
    {
        let r_guard = f.claim("short-guard", "yolo").await;
        let p_guard = proposal("short-guard-op");
        let IntentResult::Applied(_) =
            record_fenced_intent(&mut w, &r_guard.lease(), &p_guard, None, &policy, &LEASES)
                .await
                .unwrap()
        else {
            panic!("expected guard Tx1");
        };
        sqlx::query(
            "UPDATE openmettle.runs
                SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '10 seconds'),
                    execution_expires_at = clock_timestamp() + interval '10 seconds'
              WHERE id = $1::uuid",
        )
        .bind(&r_guard.run_id)
        .execute(&mut owner)
        .await
        .unwrap();
        assert!(matches!(
            leases::settle(&mut w, &r_guard.lease(), &LEASES, Settle::Succeeded).await,
            Err(leases::LeaseError::Store(StoreError::Conflict(
                "unresolved operation"
            )))
        ));
        assert_eq!(
            leases::settle(&mut w, &r_guard.lease(), &LEASES, Settle::Stopped)
                .await
                .unwrap(),
            leases::Settled::Terminal { state: "failed" }
        );
    }
    leases::release_lease(&mut w, &r_short.lease())
        .await
        .unwrap();
    let handed = Arc::new(tokio::sync::Notify::new());
    let settings_short = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
        Ok(Some(
            match k {
                "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                "LEASE_MS" => "30000",
                "EXECUTION_TIMEOUT_MS" => "180000",
                "POLL_MS" => "100",
                "SWEEP_MS" => "1000",
                _ => return Ok(None),
            }
            .into(),
        ))
    })
    .unwrap();
    let (sh_tx, sh_rx) = oneshot::channel();
    let short_task = tokio::spawn({
        let pool = worker_pool.clone();
        let exec = Arc::new(HandoffOnce {
            owner_url: f.db.url(OWNER),
            shut: Mutex::new(Some(sh_tx)),
            handed: handed.clone(),
        });
        async move {
            worker::run(
                &pool,
                None,
                settings_short,
                exec,
                async move {
                    let _ = sh_rx.await;
                },
                Duration::from_secs(4),
            )
            .await;
        }
    });
    tokio::time::timeout(Duration::from_secs(10), handed.notified())
        .await
        .expect("worker observed short-deadline handoff");
    short_task.await.unwrap();
    let short_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
            .bind(&r_short.run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(short_state, "failed");
    let (op_outcome, op_rev): (String, i64) =
        sqlx::query_as("SELECT outcome, revision FROM openmettle.operations WHERE id = $1::uuid")
            .bind(&short_op.operation_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!((op_outcome.as_str(), op_rev), ("failed", 1));
    let evs = events(&f.db, &r_short.run_id).await;
    let obs_pos = evs
        .iter()
        .position(|e| e.1 == format!("unsent-write:{}", short_op.operation_id))
        .expect("unsent-write observation before terminal");
    let term_pos = evs.iter().position(|e| e.1 == "run-terminal").unwrap();
    assert!(obs_pos < term_pos);
    assert_eq!(
        evs[term_pos].3,
        br#"{"reason":"deadline_exceeded"}"#.as_slice()
    );

    // --- (d) Stop::Cancel / ExecState::Cancelling direct cancellation + Settle::Succeeded guard ---
    let r_can = f.claim("cancel-zero", "yolo").await;
    let p_can = proposal("cancel-op");
    let IntentResult::Applied(can_op) =
        record_fenced_intent(&mut w, &r_can.lease(), &p_can, None, &policy, &LEASES)
            .await
            .unwrap()
    else {
        panic!("expected cancel Tx1");
    };
    let principal = super::super::authz_store::principal(&f.db, &f.actor).await;
    queue::cancel_run(&mut a, &principal, &f.scope, &r_can.run_id)
        .await
        .unwrap();
    // In ExecState::Cancelling, Settle::Succeeded MUST still reject with Conflict!
    assert!(matches!(
        leases::settle(&mut w, &r_can.lease(), &LEASES, Settle::Succeeded).await,
        Err(leases::LeaseError::Store(StoreError::Conflict(
            "unresolved operation"
        )))
    ));
    let settled = leases::settle(&mut w, &r_can.lease(), &LEASES, Settle::Stopped)
        .await
        .unwrap();
    assert_eq!(settled, leases::Settled::Terminal { state: "cancelled" });
    let (can_outcome, can_rev): (String, i64) =
        sqlx::query_as("SELECT outcome, revision FROM openmettle.operations WHERE id = $1::uuid")
            .bind(&can_op.operation_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!((can_outcome.as_str(), can_rev), ("failed", 1));

    // --- (e) Mixed writes: 1 `dispatched_attempts = 0` + 1 `dispatched_attempts = 1` ---
    let r_mix = f.claim("mixed-writes", "yolo").await;
    let p0 = proposal("mix-zero");
    let p1 = proposal("mix-one");
    let IntentResult::Applied(op0) =
        record_fenced_intent(&mut w, &r_mix.lease(), &p0, None, &policy, &LEASES)
            .await
            .unwrap()
    else {
        panic!("expected mix-zero");
    };
    let IntentResult::Applied(op1) =
        record_fenced_intent(&mut w, &r_mix.lease(), &p1, None, &policy, &LEASES)
            .await
            .unwrap()
    else {
        panic!("expected mix-one");
    };
    assert!(matches!(
        start_write_attempt(
            &mut w,
            &r_mix.lease(),
            &op1.operation_id,
            &p1,
            &LEASES,
            &policy
        )
        .await
        .unwrap(),
        ReplayEffect::Ready(_)
    ));
    let unresolved = leases::unresolved_operations(&mut w, &r_mix.lease(), 10)
        .await
        .unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, op1.operation_id);
    assert_eq!(unresolved[0].dispatched_attempts, Some(1));

    // With `time == false`, settling settles directly to `interrupted` (`unresolved = 1`),
    // closing `op0` -> `failed` (`revision = 1`) and `op1` -> `outcome_unknown` (`revision = 1`)
    // strictly before `run-terminal`.
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '5 seconds'),
                execution_expires_at = clock_timestamp() + interval '5 seconds'
          WHERE id = $1::uuid",
    )
    .bind(&r_mix.run_id)
    .execute(&mut owner)
    .await
    .unwrap();
    let settled = leases::settle(&mut w, &r_mix.lease(), &LEASES, Settle::Stopped)
        .await
        .unwrap();
    assert_eq!(
        settled,
        leases::Settled::Terminal {
            state: "interrupted"
        }
    );
    let (o0, r0): (String, i64) =
        sqlx::query_as("SELECT outcome, revision FROM openmettle.operations WHERE id = $1::uuid")
            .bind(&op0.operation_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let (o1, r1): (String, i64) =
        sqlx::query_as("SELECT outcome, revision FROM openmettle.operations WHERE id = $1::uuid")
            .bind(&op1.operation_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!((o0.as_str(), r0), ("failed", 1));
    assert_eq!((o1.as_str(), r1), ("outcome_unknown", 1));
    let evs = events(&f.db, &r_mix.run_id).await;
    let term_pos = evs.iter().position(|e| e.1 == "run-terminal").unwrap();
    assert_eq!(evs[term_pos].2, "openmettle.run-interrupted");
    assert_eq!(evs[term_pos].3, br#"{"unresolved":1}"#.as_slice());
    let u0_pos = evs
        .iter()
        .position(|e| e.1 == format!("unsent-write:{}", op0.operation_id))
        .unwrap();
    let u1_pos = evs
        .iter()
        .position(|e| e.1 == format!("unresolved-write:{}", op1.operation_id))
        .unwrap();
    assert!(u0_pos < term_pos && u1_pos < term_pos);
}

// ============================================================================================
// 3. Durable 0->1->2->3 Attempts, Authority Precedes Exhaustion, Shorter Decider, LeaseLost
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn two_phase_durable_attempts_shorter_decider_and_lease_lost() {
    let f = Fixture::new().await;
    f.grant(true).await;
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let policy = Policy::default();

    // (a) Durable 0 -> 1 -> 2 -> 3 write attempts and live authority checked BEFORE exhaustion at 3.
    for (label, revoke_at_3) in [("exhaust-valid", false), ("revoke-at-3", true)] {
        let r = f.claim(label, "yolo").await;
        let p = proposal(label);
        let IntentResult::Applied(tx1) =
            record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
                .await
                .unwrap()
        else {
            panic!("expected Tx1");
        };
        assert!(matches!(
            start_write_attempt(&mut w, &r.lease(), &tx1.operation_id, &p, &LEASES, &policy)
                .await
                .unwrap(),
            ReplayEffect::Ready(_)
        ));
        for expected in [2i32, 3] {
            assert!(matches!(
                start_write_retry(&mut w, &r.lease(), &tx1.operation_id, &p, &LEASES, &policy)
                    .await
                    .unwrap(),
                ReplayEffect::Ready(_)
            ));
            let n: i32 = sqlx::query_scalar(
                "SELECT dispatched_attempts FROM openmettle.operations WHERE id = $1::uuid",
            )
            .bind(&tx1.operation_id)
            .fetch_one(&mut w)
            .await
            .unwrap();
            assert_eq!(n, expected);
        }
        let check_policy = if revoke_at_3 {
            Policy {
                revision: "revoked-at-3",
                ..Policy::default()
            }
        } else {
            Policy::default()
        };
        let res = start_write_retry(
            &mut w,
            &r.lease(),
            &tx1.operation_id,
            &p,
            &LEASES,
            &check_policy,
        )
        .await
        .unwrap();
        if revoke_at_3 {
            assert!(matches!(
                res,
                ReplayEffect::Invalidated(leases::Settled::Reconciling { unresolved: 1 })
            ));
        } else {
            assert!(matches!(res, ReplayEffect::Exhausted));
            // Exhausted write must NOT be downgraded to `failed`!
            let outcome: String =
                sqlx::query_scalar("SELECT outcome FROM openmettle.operations WHERE id = $1::uuid")
                    .bind(&tx1.operation_id)
                    .fetch_one(&mut w)
                    .await
                    .unwrap();
            assert_eq!(outcome, "intent");
        }
        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&r.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        leases::settle(&mut w, &r.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // Legacy `dispatched_attempts IS NULL` write also checks live authority BEFORE exhaustion.
    for (label, revoke_null) in [("null-exhaust-valid", false), ("null-revoke", true)] {
        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = false",
        )
        .execute(&mut owner)
        .await
        .unwrap();
        let r = f.claim(label, "yolo").await;
        let p = proposal(label);
        let IntentResult::Applied(tx1) =
            record_fenced_intent(&mut w, &r.lease(), &p, None, &policy, &LEASES)
                .await
                .unwrap()
        else {
            panic!("expected legacy NULL Tx1");
        };
        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = true",
        )
        .execute(&mut owner)
        .await
        .unwrap();
        let check_policy = if revoke_null {
            Policy {
                revision: "revoked-null",
                ..Policy::default()
            }
        } else {
            Policy::default()
        };
        let res = start_write_retry(
            &mut w,
            &r.lease(),
            &tx1.operation_id,
            &p,
            &LEASES,
            &check_policy,
        )
        .await
        .unwrap();
        if revoke_null {
            assert!(matches!(
                res,
                ReplayEffect::Invalidated(leases::Settled::Reconciling { unresolved: 1 })
            ));
        } else {
            assert!(matches!(res, ReplayEffect::Exhausted));
        }
        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&r.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        leases::settle(&mut w, &r.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // (b) Shorter-lived deciding_session_id: natural expiry -> ApprovalExpired (`failed`),
    //     vs explicit revocation -> `cancelled` (`{"reason":"revoked"}`), both with 0 sends.
    for (idx, natural_expiry) in [true, false].into_iter().enumerate() {
        let label = format!("decider-{idx}");
        let r = f.claim(&label, "ordinary").await;
        let p = proposal(&label);
        let pk = park(
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
        let decider = session(&f.db, &f.actor, 70 + idx as u8).await;
        decide(
            &mut a,
            &decider,
            &f.input(&r, &pk, HumanDecision::Approve, &label),
            &policy,
        )
        .await
        .unwrap();
        let r = f.next().await.unwrap();
        let IntentResult::Applied(tx1) = record_fenced_intent(
            &mut w,
            &r.lease(),
            &p,
            Some(&pk.approval_id),
            &policy,
            &LEASES,
        )
        .await
        .unwrap() else {
            panic!("expected Tx1");
        };
        if natural_expiry {
            sqlx::query(
                "UPDATE openmettle.local_sessions
                    SET expires_ms = floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint - 1000
                  WHERE id = $1",
            )
            .bind(decider.locator())
            .execute(&mut owner)
            .await
            .unwrap();
        } else {
            sqlx::query("UPDATE openmettle.local_sessions SET revoked = true WHERE id = $1")
                .bind(decider.locator())
                .execute(&mut owner)
                .await
                .unwrap();
        }
        let res = start_write_attempt(&mut w, &r.lease(), &tx1.operation_id, &p, &LEASES, &policy)
            .await
            .unwrap();
        let ReplayEffect::Invalidated(leases::Settled::Terminal { state }) = res else {
            panic!("expected terminal invalidation before attempt 1");
        };
        assert_eq!(
            state,
            if natural_expiry {
                "failed"
            } else {
                "cancelled"
            }
        );
        let (attempts, outcome): (i32, String) = sqlx::query_as(
            "SELECT dispatched_attempts, outcome FROM openmettle.operations WHERE id = $1::uuid",
        )
        .bind(&tx1.operation_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((attempts, outcome.as_str()), (0, "failed"));
        let term = super::super::authz_runs::terminal_events(&f.db, &r.run_id).await;
        if natural_expiry {
            assert_eq!(term[0].0, "openmettle.run-approval-expired");
        } else {
            assert_eq!(term[0].0, "openmettle.run-cancelled");
            assert_eq!(term[0].1, br#"{"reason":"revoked"}"#);
        }
    }

    // (c) Deposed worker (`LeaseLost`) on both reclaimed non-terminal and already-terminal runs,
    //     plus `Settled::Reconciling` immediate `leases::release_lease` in `worker::run_with_approvals`.
    struct RevokeOnSend {
        pool: PgPool,
        owner_url: String,
        session_id: String,
        shut: Mutex<Option<oneshot::Sender<()>>>,
        done: Arc<tokio::sync::Notify>,
    }
    impl Executor for RevokeOnSend {
        async fn step(&self, run: &ActiveRun, cx: StepContext) -> StepResult {
            let p = proposal("reconcile-rel");
            let mut c = self.pool.acquire().await.unwrap();
            let IntentResult::Applied(tx1) = record_fenced_intent(
                &mut c,
                &run.claim.lease(),
                &p,
                None,
                &Policy::default(),
                &LEASES,
            )
            .await
            .unwrap() else {
                panic!("expected Tx1");
            };
            // Advance to attempt 1 (ambiguous write), then revoke the session so the post-send
            // authority check settles `Settled::Reconciling { unresolved: 1 }`!
            assert!(matches!(
                start_write_attempt(
                    &mut c,
                    &run.claim.lease(),
                    &tx1.operation_id,
                    &p,
                    &LEASES,
                    &Policy::default(),
                )
                .await
                .unwrap(),
                ReplayEffect::Ready(_)
            ));
            let mut own = sqlx::PgConnection::connect(&self.owner_url).await.unwrap();
            sqlx::query("UPDATE openmettle.local_sessions SET revoked = true WHERE id = $1")
                .bind(&self.session_id)
                .execute(&mut own)
                .await
                .unwrap();
            let res = recheck_replay_effect_authority(
                &mut c,
                &run.claim.lease(),
                &tx1.operation_id,
                &p,
                &LEASES,
                &Policy::default(),
            )
            .await
            .unwrap();
            let ReplayEffect::Invalidated(settled) = res else {
                panic!("expected Settled::Reconciling invalidation");
            };
            assert_eq!(settled, leases::Settled::Reconciling { unresolved: 1 });
            let _ = cx;
            // Signal worker shutdown BEFORE returning so the claiming loop exits right after
            // `run_one` releases the reconciling lease instead of immediately reclaiming it itself.
            if let Some(tx) = self.shut.lock().unwrap().take() {
                let _ = tx.send(());
            }
            self.done.notify_one();
            StepResult::Invalidated(settled)
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
    {
        let r_rel = f.claim("reconcile-release", "yolo").await;
        leases::release_lease(&mut w, &r_rel.lease()).await.unwrap();
        let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
        let done = Arc::new(tokio::sync::Notify::new());
        let (shut_tx, shut_rx) = oneshot::channel();
        let exec = Arc::new(RevokeOnSend {
            pool: worker_pool.clone(),
            owner_url: f.db.url(OWNER),
            session_id: f.user.locator().to_owned(),
            shut: Mutex::new(Some(shut_tx)),
            done: done.clone(),
        });
        let settings = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
            Ok(Some(
                match k {
                    "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                    "LEASE_MS" => "30000",
                    "EXECUTION_TIMEOUT_MS" => "180000",
                    "POLL_MS" => "100",
                    "SWEEP_MS" => "1000",
                    _ => return Ok(None),
                }
                .into(),
            ))
        })
        .unwrap();
        let task = tokio::spawn({
            let pool = worker_pool.clone();
            async move {
                worker::run(
                    &pool,
                    None,
                    settings,
                    exec,
                    async move {
                        let _ = shut_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        tokio::time::timeout(Duration::from_secs(10), done.notified())
            .await
            .expect("worker invalidated into reconciling");
        task.await.unwrap();
        let (state, lease_due): (String, bool) = sqlx::query_as(
            "SELECT state, lease_expires_at <= clock_timestamp() FROM openmettle.runs WHERE id = $1::uuid",
        )
        .bind(&r_rel.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(state, "reconciling");
        assert!(
            lease_due,
            "Settled::Reconciling must immediately release lease (lease_expires_at <= now)"
        );
        // A successor reconciler can reclaim immediately without waiting for the 30s lease.
        let reclaimed = leases::reclaim_next(&mut w, &LEASES)
            .await
            .unwrap()
            .expect("reconciling run immediately reclaimable");
        assert_eq!(reclaimed.run.run_id, r_rel.run_id);
        assert_eq!(reclaimed.state, leases::ExecState::Reconciling);
        leases::settle(&mut w, &reclaimed.run.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
        // Restore session so remaining assertions in this test keep working.
        sqlx::query("UPDATE openmettle.local_sessions SET revoked = false WHERE id = $1")
            .bind(f.user.locator())
            .execute(&mut owner)
            .await
            .unwrap();
    }

    let r_dep = f.claim("deposed-nonterm", "yolo").await;
    let p_dep = proposal("dep-op");
    let IntentResult::Applied(dep_op) =
        record_fenced_intent(&mut w, &r_dep.lease(), &p_dep, None, &policy, &LEASES)
            .await
            .unwrap()
    else {
        panic!("expected Tx1");
    };
    leases::release_lease(&mut w, &r_dep.lease()).await.unwrap();
    let successor = leases::reclaim_next(&mut w, &LEASES)
        .await
        .unwrap()
        .unwrap()
        .run;
    // Deposed worker's stale lease cannot increment dispatched_attempts.
    assert!(matches!(
        start_write_attempt(
            &mut w,
            &r_dep.lease(),
            &dep_op.operation_id,
            &p_dep,
            &LEASES,
            &policy
        )
        .await,
        Err(leases::LeaseError::StaleClaim)
    ));
    let attempts_still_zero: i32 = sqlx::query_scalar(
        "SELECT dispatched_attempts FROM openmettle.operations WHERE id = $1::uuid",
    )
    .bind(&dep_op.operation_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(attempts_still_zero, 0);

    // Successor settles terminal; deposed worker gets Terminal / LeaseLost and cannot touch anything.
    leases::settle(
        &mut w,
        &successor.lease(),
        &LEASES,
        Settle::Failed(leases::FailReason::StepFailed),
    )
    .await
    .unwrap();
    assert!(matches!(
        start_write_attempt(
            &mut w,
            &r_dep.lease(),
            &dep_op.operation_id,
            &p_dep,
            &LEASES,
            &policy
        )
        .await,
        Err(leases::LeaseError::Terminal { .. })
    ));
}

// ============================================================================================
// 4. End-to-End External MCP over Synthetic rcgen TLS: Faults, Retries, Reconcile, Spill/Range
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn external_mcp_tls_end_to_end_faults_retries_reconcile_and_spill_read_range() {
    let f = Fixture::new().await;
    f.grant(true).await;
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;

    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("mcp-spill"));
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_instance SET personal_limit_bytes=2000000, instance_budget_bytes=2000000",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    // Scripted synthetic TLS MCP server keyed by `params.arguments.item` or `method`.
    let idem_attempts = Arc::new(AtomicUsize::new(0));
    let read_attempts = Arc::new(AtomicUsize::new(0));
    let big_body = format!("{}{}", "alpha-line\n".repeat(1200), "Ω-tail\n".repeat(600));
    let big_body_srv = big_body.clone();
    let idem_attempts_srv = idem_attempts.clone();
    let read_attempts_srv = read_attempts.clone();
    let reg_for_list = test_registry(FUTURE * 1000);
    let list_tools_json: Value = Value::Array(
        [
            "mcp.read",
            "mcp.idem",
            "mcp.lookup_handle",
            "mcp.lookup_det",
            "mcp.nonrep",
        ]
        .into_iter()
        .map(|name| {
            let c = reg_for_list.get(name, "1").unwrap();
            json!({"name": c.remote_name, "inputSchema": c.input_schema})
        })
        .collect(),
    );

    let server = SyntheticMcpServer::start(move |req| {
        let id = req.body["id"].as_str().unwrap_or("0");
        let method = req.body["method"].as_str().unwrap_or("");
        if method == "tools/list" {
            let body = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": list_tools_json}})
                .to_string();
            return http_response(200, &[("content-type", "application/json")], body.as_bytes());
        }
        let tool = req.body["params"]["name"].as_str().unwrap_or("");
        let args = &req.body["params"]["arguments"];
        if tool == "mcp.status" {
            let returned_handle = match args.get("handle").and_then(Value::as_str) {
                Some("h-conflict") => "h-other",
                Some(h) => h,
                None => "h-reconciled",
            };
            return jsonrpc_ok(
                id,
                r#"{"status":"succeeded"}"#,
                Some(json!({"status": "succeeded", "handle": returned_handle})),
            );
        }
        let item = args["item"].as_str().unwrap_or("");
        match item {
            "spill-roundtrip" => jsonrpc_ok(
                id,
                &big_body_srv,
                Some(json!({"handle": "h-spill-1"})),
            ),
            "retry-idem" => {
                if idem_attempts_srv.fetch_add(1, Ordering::SeqCst) == 0 {
                    http_response(503, &[("retry-after", "0")], b"busy")
                } else {
                    jsonrpc_ok(id, "idem-recovered", Some(json!({"handle": "h-idem"})))
                }
            }
            "retry-too-long" => http_response(429, &[("retry-after", "61")], b"slow down"),
            "lookup-503" | "nonrep-503" => http_response(503, &[("retry-after", "0")], b"busy"),
            "read-revoke-503" => {
                read_attempts_srv.fetch_add(1, Ordering::SeqCst);
                http_response(503, &[("retry-after", "0")], b"busy")
            }
            "err-401" => http_response(401, &[], b"canary-401"),
            "err-403" => http_response(403, &[], b"canary-403"),
            "err-500" => http_response(500, &[], b"canary-500"),
            "err-101" => b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n".to_vec(),
            "err-204" => b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
            "err-302" => http_response(302, &[("location", "https://evil.test/")], b""),
            "err-input-req" => {
                let b = json!({"jsonrpc":"2.0","id":id,"result":{"status":"input_required","content":[{"type":"text","text":"canary"}]}}).to_string();
                http_response(200, &[("content-type", "application/json")], b.as_bytes())
            }
            "err-semantic-32602" => {
                let b = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"canary-secret-param"}}).to_string();
                http_response(200, &[("content-type", "application/json")], b.as_bytes())
            }
            "err-is-error" => {
                let b = json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":"canary-tool-fail"}]}}).to_string();
                http_response(200, &[("content-type", "application/json")], b.as_bytes())
            }
            _ => jsonrpc_ok(id, "ok", None),
        }
    })
    .await;

    let transport = server.transport();
    let registry = Arc::new(test_registry(FUTURE * 1000));

    // Verify `tools/list` wire round trip against pinned contracts.
    {
        let (_tx, mut stop) = tokio::sync::watch::channel(None);
        let remote = transport
            .tools_list(
                "list-1",
                Some("tok-1"),
                Instant::now() + Duration::from_secs(5),
                &mut stop,
            )
            .await
            .unwrap();
        assert!(registry.verify_tools_list("synth-mcp", &remote).is_ok());
    }

    let mut transports = BTreeMap::new();
    transports.insert("synth-mcp".to_owned(), transport.clone());

    // (a) Gated V1-28 credential provider fails closed before Transaction 1 (0 operations, 0 HTTP).
    let reqs_before_gated = server.requests.load(Ordering::SeqCst);
    let gated_adapter = Arc::new(ExternalMcpAdapter::new(
        worker_pool.clone(),
        LEASES,
        registry.clone(),
        transports.clone(),
        Arc::new(GatedCredentialProvider),
        Arc::new(ToggleReconcileAuth {
            allowed: Arc::new(AtomicBool::new(true)),
            checks: Arc::new(AtomicUsize::new(0)),
        }),
    ));
    let r_gated = f.claim("gated-cred", "yolo").await;
    let (_st, step) = fresh_step(20);
    let active_gated = ActiveRun {
        claim: r_gated.clone(),
        state: leases::ExecState::Running,
        execution_deadline: step.deadline,
    };
    let StepResult::ToolOutput(gated_out) = gated_adapter
        .call(
            &active_gated,
            step.clone(),
            ExternalCall {
                key: "k-gated",
                tool: "mcp.idem",
                version: "1",
                raw_args: br#"{"item":"spill-roundtrip"}"#,
                approval: None,
            },
        )
        .await
    else {
        panic!("expected gated ToolOutput refusal");
    };
    assert_eq!(
        serde_json::from_str::<Value>(&gated_out).unwrap()["fault_code"],
        "terminal_refusal"
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), reqs_before_gated);
    let gated_ops: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid")
            .bind(&r_gated.run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(gated_ops, 0);
    leases::settle(&mut w, &r_gated.lease(), &LEASES, Settle::Succeeded)
        .await
        .unwrap();

    // Live credential + toggleable reconcile authorizer adapter.
    let cred_lookups = Arc::new(AtomicUsize::new(0));
    let reconcile_allowed = Arc::new(AtomicBool::new(true));
    let reconcile_checks = Arc::new(AtomicUsize::new(0));
    let adapter = Arc::new(
        ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports,
            Arc::new(CountingCredentials {
                token: Some("synthetic-mcp-token".into()),
                lookups: cred_lookups.clone(),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: reconcile_allowed.clone(),
                checks: reconcile_checks.clone(),
            }),
        )
        .with_artifacts(store.clone()),
    );

    // (b) End-to-end `park -> decide -> resume -> ExternalMcpAdapter -> spill -> artifact.read_range`
    //     + positive replay with `approval = None` + conflict on mismatched `Some(other)`
    //     + replay refusal on retained spill / session logout.
    let r_e2e = f.claim("e2e-spill", "ordinary").await;
    let p_e2e = registry
        .proposal("k-e2e", "mcp.idem", "1", br#"{"item":"spill-roundtrip"}"#)
        .unwrap();
    let pk_e2e = park(
        &mut w,
        &r_e2e.lease(),
        &StepTasks::default().handle(),
        &p_e2e,
        registry.as_ref(),
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let decider = session(&f.db, &f.actor, 91).await;
    decide(
        &mut a,
        &decider,
        &f.input(&r_e2e, &pk_e2e, HumanDecision::Approve, "e2e"),
        registry.as_ref(),
    )
    .await
    .unwrap();
    let r_e2e = f.next().await.unwrap();
    let (_st, step_e2e) = fresh_step(25);
    let active_e2e = ActiveRun {
        claim: r_e2e.clone(),
        state: leases::ExecState::Running,
        execution_deadline: step_e2e.deadline,
    };
    let t0 = Instant::now();
    let StepResult::ToolOutput(spill_json) = adapter
        .call(
            &active_e2e,
            step_e2e.clone(),
            ExternalCall {
                key: "k-e2e",
                tool: "mcp.idem",
                version: "1",
                raw_args: br#"{"item":"spill-roundtrip"}"#,
                approval: Some(&pk_e2e.approval_id),
            },
        )
        .await
    else {
        panic!("expected spilled ToolOutput");
    };
    let mcp_call_and_spill_us = t0.elapsed().as_micros();
    assert!(mcp_call_and_spill_us > 0);
    assert!(spill_json.len() <= INLINE_BYTES);
    let spill_val: Value = serde_json::from_str(&spill_json).unwrap();
    assert_eq!(spill_val["storage"], "spilled");
    let art_id = spill_val["provenance"]["artifact_id"].as_str().unwrap();
    let rev_id = spill_val["provenance"]["revision_id"].as_str().unwrap();
    let op_id = spill_val["provenance"]["operation_id"].as_str().unwrap();
    let stored_handle: Option<String> = sqlx::query_scalar(
        "SELECT downstream_handle FROM openmettle.operations WHERE id = $1::uuid",
    )
    .bind(op_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(stored_handle.as_deref(), Some("h-spill-1"));

    // Positive same-key replay with `approval = None` resolves stored human approval!
    let StepResult::ToolOutput(replayed_json) = adapter
        .call(
            &active_e2e,
            step_e2e.clone(),
            ExternalCall {
                key: "k-e2e",
                tool: "mcp.idem",
                version: "1",
                raw_args: br#"{"item":"spill-roundtrip"}"#,
                approval: None,
            },
        )
        .await
    else {
        panic!("expected replayed ToolOutput with approval = None");
    };
    assert_eq!(replayed_json, spill_json);
    // Mismatched explicit approval_id conflicts!
    assert!(
        record_fenced_intent(
            &mut w,
            &r_e2e.lease(),
            &p_e2e,
            Some("00000000-0000-4000-8000-000000000088"),
            registry.as_ref(),
            &LEASES,
        )
        .await
        .is_err()
    );

    // Read full spilled payload back via ScopedAdapter `artifact.read_range`.
    let scoped = ScopedAdapter::new(worker_pool.clone(), store.clone(), LEASES);
    let mut reconstructed = String::new();
    let mut offset = 0u64;
    let mut page_idx = 0usize;
    let t_read = Instant::now();
    loop {
        let args = json!({
            "artifact_id": art_id,
            "revision_id": rev_id,
            "offset": offset,
            "max_bytes": INLINE_BYTES
        })
        .to_string();
        let StepResult::ToolOutput(page) = scoped
            .call(
                &active_e2e,
                step_e2e.clone(),
                &format!("range-{page_idx}"),
                mcp::READ_RANGE,
                "1",
                args.as_bytes(),
            )
            .await
        else {
            panic!("expected read_range page");
        };
        assert!(page.len() <= INLINE_BYTES);
        let pv: Value = serde_json::from_str(&page).unwrap();
        let chunk = pv["text"].as_str().unwrap();
        reconstructed.push_str(chunk);
        offset = pv["next_offset"].as_u64().unwrap();
        if pv["eof"] == true {
            break;
        }
        page_idx += 1;
    }
    let read_range_us = t_read.elapsed().as_micros();
    assert_eq!(reconstructed, big_body);
    let plan22_record = json!({
        "mcp_call_and_spill_us": mcp_call_and_spill_us,
        "read_range_us": read_range_us,
        "e2e_mcp_spill_and_read_range_us": mcp_call_and_spill_us + read_range_us,
        "inline_preview_bytes": spill_json.len(),
        "spilled_bytes": big_body.len(),
    });
    assert!(plan22_record["mcp_call_and_spill_us"].as_u64().unwrap() > 0);
    assert!(plan22_record["read_range_us"].as_u64().unwrap() > 0);
    println!("PLAN-22: {plan22_record}");

    // Retaining the spilled revision invalidates replay of the spilled operation!
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
            SET state = 'retained', retained_at = clock_timestamp(), purge_after = clock_timestamp() + interval '1 day'
          WHERE id = $1::uuid",
    )
    .bind(rev_id)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(matches!(
        adapter
            .call(
                &active_e2e,
                step_e2e.clone(),
                ExternalCall {
                    key: "k-e2e",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"spill-roundtrip"}"#,
                    approval: None,
                },
            )
            .await,
        StepResult::Invalidated(leases::Settled::Terminal { state: "cancelled" })
    ));

    // (c) Retries & sticky send-uncertainty:
    // 1. `idempotent` write retries 503 with Retry-After: 0 (`dispatched_attempts: 1 -> 2`) and succeeds
    //    sending the exact same Idempotency-Key header across attempts!
    let cap_before = server.captured.lock().unwrap().len();
    let r_idem = f.claim("retry-idem", "yolo").await;
    let (_st, step_i) = fresh_step(20);
    let active_idem = ActiveRun {
        claim: r_idem.clone(),
        state: leases::ExecState::Running,
        execution_deadline: step_i.deadline,
    };
    let StepResult::ToolOutput(idem_out) = adapter
        .call(
            &active_idem,
            step_i.clone(),
            ExternalCall {
                key: "k-idem",
                tool: "mcp.idem",
                version: "1",
                raw_args: br#"{"item":"retry-idem"}"#,
                approval: None,
            },
        )
        .await
    else {
        panic!("expected idempotent retry success");
    };
    assert_eq!(
        serde_json::from_str::<Value>(&idem_out).unwrap()["text"],
        "idem-recovered"
    );
    let idem_attempts_db: i32 = sqlx::query_scalar(
        "SELECT dispatched_attempts FROM openmettle.operations WHERE run_id = $1::uuid AND logical_key = 'k-idem'",
    )
    .bind(&r_idem.run_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(idem_attempts_db, 2);
    leases::settle(&mut w, &r_idem.lease(), &LEASES, Settle::Succeeded)
        .await
        .unwrap();
    {
        let cap = server.captured.lock().unwrap();
        let slice = &cap[cap_before..];
        assert_eq!(slice.len(), 2);
        let extract_idem = |h: &str| {
            h.lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("idempotency-key")
                        .then(|| v.trim().to_owned())
                })
                .expect("Idempotency-Key header")
        };
        assert_eq!(extract_idem(&slice[0].head), extract_idem(&slice[1].head));
        assert!(
            slice[0]
                .head
                .contains("mcp-name: =?base64?bGVmdAlyaWdodA==?=\r\n")
        );
    }

    // 2. `idempotent` write with Retry-After: 61 -> no retry -> outcome_unknown + StepResult::Stopped.
    let before_61 = server.requests.load(Ordering::SeqCst);
    let r_61 = f.claim("retry-61", "yolo").await;
    let active_61 = ActiveRun {
        claim: r_61.clone(),
        state: leases::ExecState::Running,
        execution_deadline: step_i.deadline,
    };
    assert!(matches!(
        adapter
            .call(
                &active_61,
                step_i.clone(),
                ExternalCall {
                    key: "k-61",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"retry-too-long"}"#,
                    approval: None,
                },
            )
            .await,
        StepResult::Stopped
    ));
    assert_eq!(server.requests.load(Ordering::SeqCst), before_61 + 1);
    let outcome_61: String =
        sqlx::query_scalar("SELECT outcome FROM openmettle.operations WHERE run_id = $1::uuid")
            .bind(&r_61.run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(outcome_61, "outcome_unknown");
    sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
        .bind(&r_61.run_id)
        .execute(&mut owner)
        .await
        .unwrap();
    assert_eq!(
        leases::settle(&mut w, &r_61.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap(),
        leases::Settled::Terminal {
            state: "interrupted"
        }
    );

    // 3. Post-send write refusal matrix (401, 403, 500, 101, 204, 302, input_required) AND
    //    `lookup`/`non_repeatable` 503 -> EVERY one commits `outcome_unknown` + `StepResult::Stopped`
    //    with ZERO retries (1 HTTP call total)!
    for (idx, (tool, item)) in [
        ("mcp.idem", "err-401"),
        ("mcp.idem", "err-403"),
        ("mcp.idem", "err-500"),
        ("mcp.idem", "err-101"),
        ("mcp.idem", "err-204"),
        ("mcp.idem", "err-302"),
        ("mcp.idem", "err-input-req"),
        ("mcp.lookup_handle", "lookup-503"),
        ("mcp.nonrep", "nonrep-503"),
    ]
    .into_iter()
    .enumerate()
    {
        let reqs = server.requests.load(Ordering::SeqCst);
        let r_ref = f.claim(&format!("ref-{idx}"), "yolo").await;
        let active_ref = ActiveRun {
            claim: r_ref.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step_i.deadline,
        };
        let args = json!({"item": item}).to_string();
        assert!(
            matches!(
                adapter
                    .call(
                        &active_ref,
                        step_i.clone(),
                        ExternalCall {
                            key: &format!("k-ref-{idx}"),
                            tool,
                            version: "1",
                            raw_args: args.as_bytes(),
                            approval: None,
                        },
                    )
                    .await,
                StepResult::Stopped
            ),
            "post-send write {item} must return StepResult::Stopped"
        );
        assert_eq!(
            server.requests.load(Ordering::SeqCst),
            reqs + 1,
            "{item} must not retry"
        );
        let (outcome, attempts): (String, i32) = sqlx::query_as(
            "SELECT outcome, dispatched_attempts FROM openmettle.operations WHERE run_id = $1::uuid",
        )
        .bind(&r_ref.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            (outcome.as_str(), attempts),
            ("outcome_unknown", 1),
            "{item}"
        );
        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&r_ref.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        assert_eq!(
            leases::settle(&mut w, &r_ref.lease(), &LEASES, Settle::Stopped)
                .await
                .unwrap(),
            leases::Settled::Terminal {
                state: "interrupted"
            }
        );
    }

    // 4. Semantic `-32602` & side-effect-free `isError: true` -> `failed` + inline `tool_error`
    //    with `retryable_by_model: true` and zero canary echo.
    for (idx, item) in ["err-semantic-32602", "err-is-error"]
        .into_iter()
        .enumerate()
    {
        let r_sem = f.claim(&format!("sem-{idx}"), "yolo").await;
        let active_sem = ActiveRun {
            claim: r_sem.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step_i.deadline,
        };
        let args = json!({"item": item}).to_string();
        let StepResult::ToolOutput(env) = adapter
            .call(
                &active_sem,
                step_i.clone(),
                ExternalCall {
                    key: &format!("k-sem-{idx}"),
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: args.as_bytes(),
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected inline semantic tool_error for {item}");
        };
        assert!(!env.contains("canary"));
        let v: Value = serde_json::from_str(&env).unwrap();
        assert_eq!(v["status"], "tool_error");
        assert_eq!(v["fault_code"], "semantic");
        assert_eq!(v["retryable_by_model"], true);
        let outcome: String =
            sqlx::query_scalar("SELECT outcome FROM openmettle.operations WHERE run_id = $1::uuid")
                .bind(&r_sem.run_id)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        assert_eq!(outcome, "failed");
        leases::settle(&mut w, &r_sem.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    // 5. Caller-independent `repeatable_read` retry invalidation:
    //    `dispatched_attempts = 1` receives transient 503, then session is revoked before attempt 2 ->
    //    `outcome = 'failed'`, `openmettle.run-cancelled` (`revoked`), 1 total HTTP call!
    {
        let r_rr = f.claim("read-revoke-retry", "ordinary").await;
        let p_rr = registry
            .proposal("k-rr", "mcp.read", "1", br#"{"item":"read-revoke-503"}"#)
            .unwrap();
        let IntentResult::Applied(tx1) = record_fenced_intent(
            &mut w,
            &r_rr.lease(),
            &p_rr,
            None,
            registry.as_ref(),
            &LEASES,
        )
        .await
        .unwrap() else {
            panic!("expected read Tx1");
        };
        assert!(matches!(
            start_replayed_read(
                &mut w,
                &r_rr.lease(),
                &tx1.operation_id,
                &p_rr,
                &LEASES,
                registry.as_ref(),
            )
            .await
            .unwrap(),
            ReplayEffect::Ready(_)
        ));
        let reqs0 = server.requests.load(Ordering::SeqCst);
        let (_st, mut step_rr) = fresh_step(15);
        let err = transport
            .tools_call(
                &openmettle_core::provider_http::mcp::ToolCallRequest {
                    request_id: "rr-1",
                    tool_name: "execute_sql",
                    arguments: p_rr.arguments(),
                    bearer_token: Some("synthetic-mcp-token"),
                    idempotency_header: None,
                    idempotency_meta: None,
                },
                step_rr.deadline,
                &mut step_rr.stop,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err.kind,
            openmettle_core::provider_http::mcp::FaultKind::Transient(_)
        ));
        assert_eq!(server.requests.load(Ordering::SeqCst), reqs0 + 1);
        // Revoke actor session before attempt 2; start_replayed_read settles cancelled + failed with 0 extra HTTP!
        sqlx::query("UPDATE openmettle.local_sessions SET revoked = true WHERE id = $1")
            .bind(f.user.locator())
            .execute(&mut owner)
            .await
            .unwrap();
        let retry_res = start_replayed_read(
            &mut w,
            &r_rr.lease(),
            &tx1.operation_id,
            &p_rr,
            &LEASES,
            registry.as_ref(),
        )
        .await
        .unwrap();
        assert!(matches!(
            retry_res,
            ReplayEffect::Invalidated(leases::Settled::Terminal { state: "cancelled" })
        ));
        let (outcome, attempts): (String, i32) = sqlx::query_as(
            "SELECT outcome, dispatched_attempts FROM openmettle.operations WHERE id = $1::uuid",
        )
        .bind(&tx1.operation_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((outcome.as_str(), attempts), ("failed", 1));
        assert_eq!(server.requests.load(Ordering::SeqCst), reqs0 + 1);
        sqlx::query("UPDATE openmettle.local_sessions SET revoked = false WHERE id = $1")
            .bind(f.user.locator())
            .execute(&mut owner)
            .await
            .unwrap();
    }

    // (d) `Executor::reconcile` (`ExternalMcpAdapter::reconcile_operation`) matrix:
    // Helper to create an unresolved write in `ExecState::Reconciling` and invoke `reconcile_operation`.
    let make_reconciling = async |label: &str,
                                  tool: &str,
                                  dispatch: bool,
                                  set_handle: Option<&str>|
           -> (ActiveRun, leases::UnresolvedOperation) {
        let rr = f.claim(label, "yolo").await;
        let prop = registry
            .proposal(label, tool, "1", br#"{"item":"rec-item"}"#)
            .unwrap();
        let IntentResult::Applied(tx1) = record_fenced_intent(
            &mut worker(&f.db).await,
            &rr.lease(),
            &prop,
            None,
            registry.as_ref(),
            &LEASES,
        )
        .await
        .unwrap() else {
            panic!("expected Tx1 for {label}");
        };
        if dispatch {
            assert!(matches!(
                start_write_attempt(
                    &mut worker(&f.db).await,
                    &rr.lease(),
                    &tx1.operation_id,
                    &prop,
                    &LEASES,
                    registry.as_ref(),
                )
                .await
                .unwrap(),
                ReplayEffect::Ready(_)
            ));
        }
        let (outcome, revision) = if let Some(h) = set_handle {
            let mut cw = worker(&f.db).await;
            leases::with_lease(&mut cw, &rr.lease(), Fence::Hold, async |tx, _| {
                durable::record_observation(
                    tx,
                    &durable::Observation {
                        scope: &rr.scope_id,
                        run: &rr.run_id,
                        operation: &tx1.operation_id,
                        key: &format!("handle-unknown:{}", tx1.operation_id),
                        expected_revision: 0,
                        outcome: "outcome_unknown",
                        handle: Some(h),
                        evidence: Payload {
                            format: "openmettle.unresolved-write",
                            version: 1,
                            bytes: br#"{"reason":"handle_learned"}"#,
                        },
                    },
                )
                .await
            })
            .await
            .unwrap();
            ("outcome_unknown", 1i64)
        } else {
            ("intent", 0i64)
        };
        if dispatch {
            assert_eq!(
                leases::settle(
                    &mut worker(&f.db).await,
                    &rr.lease(),
                    &LEASES,
                    Settle::Stopped
                )
                .await
                .unwrap(),
                leases::Settled::Reconciling { unresolved: 1 }
            );
        }
        let capability: String =
            sqlx::query_scalar("SELECT capability FROM openmettle.operations WHERE id = $1::uuid")
                .bind(&tx1.operation_id)
                .fetch_one(&mut connect(&f.db.0, OWNER).await)
                .await
                .unwrap();
        let op = leases::UnresolvedOperation {
            id: tx1.operation_id,
            logical_key: label.into(),
            target: prop.destination().into(),
            capability,
            outcome: outcome.into(),
            revision,
            downstream_handle: set_handle.map(str::to_owned),
            dispatched_attempts: Some(if dispatch { 1 } else { 0 }),
        };
        let active = ActiveRun {
            claim: rr,
            state: leases::ExecState::Reconciling,
            execution_deadline: Instant::now() + Duration::from_secs(20),
        };
        (active, op)
    };

    // 1. `dispatched_attempts = 0` -> `failed` with ZERO credential lookups & ZERO HTTP calls.
    {
        let (active, op) = make_reconciling("rec-zero", "mcp.lookup_handle", false, None).await;
        let l0 = cred_lookups.load(Ordering::SeqCst);
        let h0 = server.requests.load(Ordering::SeqCst);
        let obs = adapter
            .reconcile_operation(&active, &op, step_i.clone())
            .await
            .expect("zero-attempt write resolves to failed");
        assert_eq!(obs.outcome, "failed");
        assert_eq!(cred_lookups.load(Ordering::SeqCst), l0);
        assert_eq!(server.requests.load(Ordering::SeqCst), h0);
        leases::settle(
            &mut w,
            &active.claim.lease(),
            &LEASES,
            Settle::Failed(leases::FailReason::StepFailed),
        )
        .await
        .unwrap();
    }

    // 2. Destination revocation -> returns `None` with ZERO credential lookups & ZERO HTTP calls!
    {
        let (active, op) =
            make_reconciling("rec-revoked", "mcp.lookup_handle", true, Some("h-1")).await;
        reconcile_allowed.store(false, Ordering::SeqCst);
        let l0 = cred_lookups.load(Ordering::SeqCst);
        let h0 = server.requests.load(Ordering::SeqCst);
        let c0 = reconcile_checks.load(Ordering::SeqCst);
        let obs = adapter
            .reconcile_operation(&active, &op, step_i.clone())
            .await;
        assert!(
            obs.is_none(),
            "revoked destination must refuse reconciliation"
        );
        assert_eq!(reconcile_checks.load(Ordering::SeqCst), c0 + 1);
        assert_eq!(cred_lookups.load(Ordering::SeqCst), l0);
        assert_eq!(server.requests.load(Ordering::SeqCst), h0);
        reconcile_allowed.store(true, Ordering::SeqCst);
        leases::settle(&mut w, &active.claim.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // 3. `lookup` with `downstream_handle` -> read-only lookup succeeds -> `succeeded`!
    {
        let (active, op) =
            make_reconciling("rec-handle-ok", "mcp.lookup_handle", true, Some("h-2")).await;
        let obs = adapter
            .reconcile_operation(&active, &op, step_i.clone())
            .await
            .expect("lookup with handle resolves");
        assert_eq!(obs.outcome, "succeeded");
        leases::settle(&mut w, &active.claim.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // 4. `lookup` WITHOUT `downstream_handle`:
    //    - without deterministic key -> `outcome_unknown` with 0 lookups & 0 HTTP!
    //    - with deterministic key -> resolves to `succeeded`!
    {
        let (active, op) = make_reconciling("rec-no-handle", "mcp.lookup_handle", true, None).await;
        let l0 = cred_lookups.load(Ordering::SeqCst);
        let h0 = server.requests.load(Ordering::SeqCst);
        let obs = adapter
            .reconcile_operation(&active, &op, step_i.clone())
            .await
            .expect("lookup without handle/det key resolves to outcome_unknown");
        assert_eq!(obs.outcome, "outcome_unknown");
        assert_eq!(cred_lookups.load(Ordering::SeqCst), l0);
        assert_eq!(server.requests.load(Ordering::SeqCst), h0);
        leases::settle(&mut w, &active.claim.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();

        let (active_det, op_det) =
            make_reconciling("rec-det-ok", "mcp.lookup_det", true, None).await;
        let obs_det = adapter
            .reconcile_operation(&active_det, &op_det, step_i.clone())
            .await
            .expect("lookup with deterministic key resolves");
        assert_eq!(obs_det.outcome, "succeeded");
        leases::settle(&mut w, &active_det.claim.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // 5. `idempotent` read-only status lookup resolves to `succeeded`.
    {
        let (active, op) = make_reconciling("rec-idem-ok", "mcp.idem", true, None).await;
        let obs = adapter
            .reconcile_operation(&active, &op, step_i.clone())
            .await
            .expect("idempotent status lookup resolves");
        assert_eq!(obs.outcome, "succeeded");
        leases::settle(&mut w, &active.claim.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // 6. `non_repeatable` -> `outcome_unknown` with 0 lookups & 0 HTTP.
    {
        let (active, op) = make_reconciling("rec-nonrep", "mcp.nonrep", true, None).await;
        let l0 = cred_lookups.load(Ordering::SeqCst);
        let h0 = server.requests.load(Ordering::SeqCst);
        let obs = adapter
            .reconcile_operation(&active, &op, step_i.clone())
            .await
            .expect("non_repeatable resolves to outcome_unknown");
        assert_eq!(obs.outcome, "outcome_unknown");
        assert_eq!(cred_lookups.load(Ordering::SeqCst), l0);
        assert_eq!(server.requests.load(Ordering::SeqCst), h0);
        leases::settle(&mut w, &active.claim.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // 7. `repeatable_read` -> excluded (`None` with 0 lookups & 0 HTTP).
    {
        let (active, mut op) = make_reconciling("rec-read-skip", "mcp.nonrep", true, None).await;
        op.capability = "repeatable_read".into();
        let l0 = cred_lookups.load(Ordering::SeqCst);
        let h0 = server.requests.load(Ordering::SeqCst);
        assert!(
            adapter
                .reconcile_operation(&active, &op, step_i.clone())
                .await
                .is_none()
        );
        assert_eq!(cred_lookups.load(Ordering::SeqCst), l0);
        assert_eq!(server.requests.load(Ordering::SeqCst), h0);
        leases::settle(&mut w, &active.claim.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }
}

// ============================================================================================
// 5. Review #1 Regressions: Same-Claim Race, Resumed Preflight, TurnExecutor Reclaim,
//    Rebound Reconcile Refusal, and Full Worker Reconciliation + Handle Conflict
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn review1_two_phase_race_preflight_turn_reclaim_and_reconcile_regressions() {
    use openmettle_core::{
        authz::{
            branches::{
                self, Conversation, Operation, Part, UserInput,
                snapshot::{Intent as TurnIntent, Snapshots},
            },
            store::{AuditContext, WriteOutcome},
        },
        model_config::{
            Catalog, ConfigSnapshot, Effective, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection,
        },
        provider_http::inference::{
            self, Call, Gateway, Protocol, Qualification, Request, Timeouts, Tool,
        },
        runs::RunInput,
        worker::turns::{Route, TurnExecutor, TurnRoutes},
    };

    let f = Fixture::new().await;
    f.grant(true).await;
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let policy = Policy::default();

    // --- (a) P1 #1: Concurrent same-claim race on dispatched_attempts = 0 ---
    // (1) Direct concurrent `start_write_attempt` race on two connections under the same claim:
    //     exactly one gets `Ready`, the other gets `Pending` (never double-send, never false revoke).
    {
        let r_race = f.claim("same-claim-race", "yolo").await;
        let p_race = proposal("race-op");
        let IntentResult::Applied(tx1) =
            record_fenced_intent(&mut w, &r_race.lease(), &p_race, None, &policy, &LEASES)
                .await
                .unwrap()
        else {
            panic!("expected Tx1 for race");
        };
        let mut w1 = worker(&f.db).await;
        let mut w2 = worker(&f.db).await;
        let race_lease = r_race.lease();
        let (res1, res2) = tokio::join!(
            start_write_attempt(
                &mut w1,
                &race_lease,
                &tx1.operation_id,
                &p_race,
                &LEASES,
                &policy,
            ),
            start_write_attempt(
                &mut w2,
                &race_lease,
                &tx1.operation_id,
                &p_race,
                &LEASES,
                &policy,
            ),
        );
        let outcomes = [res1.unwrap(), res2.unwrap()];
        let ready_count = outcomes
            .iter()
            .filter(|r| matches!(r, ReplayEffect::Ready(_)))
            .count();
        let pending_count = outcomes
            .iter()
            .filter(|r| matches!(r, ReplayEffect::Pending))
            .count();
        assert_eq!(ready_count, 1, "exactly one caller wins attempt 0 -> 1");
        assert_eq!(
            pending_count, 1,
            "same-claim loser must see ReplayEffect::Pending (not Exhausted or Invalidated)"
        );
        let (run_state, attempts): (String, i32) = sqlx::query_as(
            "SELECT r.state, o.dispatched_attempts
               FROM openmettle.runs r JOIN openmettle.operations o ON o.run_id = r.id
              WHERE r.id = $1::uuid AND o.id = $2::uuid",
        )
        .bind(&r_race.run_id)
        .bind(&tx1.operation_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((run_state.as_str(), attempts), ("running", 1));
        // Complete the winning write and settle cleanly.
        leases::with_lease(&mut w, &r_race.lease(), Fence::Hold, async |tx, _| {
            durable::record_observation(
                tx,
                &durable::Observation {
                    scope: &r_race.scope_id,
                    run: &r_race.run_id,
                    operation: &tx1.operation_id,
                    key: &format!("race-obs:{}", tx1.operation_id),
                    expected_revision: 0,
                    outcome: "succeeded",
                    handle: None,
                    evidence: Payload {
                        format: "fixture",
                        version: 1,
                        bytes: b"ok",
                    },
                },
            )
            .await
        })
        .await
        .unwrap();
        leases::settle(&mut w, &r_race.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    // Shared synthetic MCP server serving tools/list, tools/call, and mcp.status for this test.
    let mut reg_builder = test_registry(FUTURE * 1000);
    let mut turn_contract = reg_builder.get("mcp.idem", "1").unwrap().clone();
    turn_contract.tool_id = "mcp_idem".into();
    turn_contract.remote_name = "mcp_idem".into();
    turn_contract.input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["item"],
        "properties": {
            "item": {"type": "string"}
        }
    });
    reg_builder.register(turn_contract).unwrap();
    let registry = Arc::new(reg_builder);
    let list_tools_json: Value = Value::Array(
        [
            "mcp.read",
            "mcp.idem",
            "mcp_idem",
            "mcp.lookup_handle",
            "mcp.lookup_det",
            "mcp.nonrep",
        ]
        .into_iter()
        .map(|name| {
            let c = registry.get(name, "1").unwrap();
            json!({"name": c.remote_name, "inputSchema": c.input_schema})
        })
        .collect(),
    );
    let mcp_tool_calls = Arc::new(AtomicUsize::new(0));
    let mcp_tool_calls_srv = mcp_tool_calls.clone();
    let mcp_server = SyntheticMcpServer::start(move |req| {
        let id = req.body["id"].as_str().unwrap_or("0");
        let method = req.body["method"].as_str().unwrap_or("");
        if method == "tools/list" {
            let body = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": list_tools_json}})
                .to_string();
            return http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            );
        }
        let tool = req.body["params"]["name"].as_str().unwrap_or("");
        let args = &req.body["params"]["arguments"];
        if tool == "mcp.status" {
            let returned_handle = match args.get("handle").and_then(Value::as_str) {
                Some("h-conflict") => "h-other",
                Some(h) => h,
                None => "h-reconciled",
            };
            return jsonrpc_ok(
                id,
                r#"{"status":"succeeded"}"#,
                Some(json!({"status": "succeeded", "handle": returned_handle})),
            );
        }
        mcp_tool_calls_srv.fetch_add(1, Ordering::SeqCst);
        jsonrpc_ok(id, "turn-write-ok", Some(json!({"handle": "h-turn-1"})))
    })
    .await;

    let mut transports = BTreeMap::new();
    transports.insert("synth-mcp".to_owned(), mcp_server.transport());

    // --- (b) P1 #2: Resumed human approval runs ExternalMcpAdapter::preflight before Tx1 ---
    {
        struct ResumeExecutor;
        impl Executor for ResumeExecutor {
            async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
                StepResult::Finished
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

        let decider = session(&f.db, &f.actor, 41).await;
        for (label, disable_gate, gated_creds) in [
            ("resumed-gate-off", true, false),
            ("resumed-cred-unavail", false, true),
        ] {
            let r_ap = f.claim(label, "ordinary").await;
            let p_ap = registry
                .proposal(label, "mcp.idem", "1", br#"{"item":"resumed-check"}"#)
                .unwrap();
            let pk = park(
                &mut w,
                &r_ap.lease(),
                &StepTasks::default().handle(),
                &p_ap,
                registry.as_ref(),
                &LEASES,
                Duration::from_secs(60),
            )
            .await
            .unwrap();
            decide(
                &mut a,
                &decider,
                &f.input(&r_ap, &pk, HumanDecision::Approve, label),
                registry.as_ref(),
            )
            .await
            .unwrap();

            if disable_gate {
                sqlx::query(
                    "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = false",
                )
                .execute(&mut owner)
                .await
                .unwrap();
            }

            let creds: Arc<dyn McpCredentialProvider> = if gated_creds {
                Arc::new(GatedCredentialProvider)
            } else {
                Arc::new(CountingCredentials {
                    token: Some("tok-preflight".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                })
            };
            let adapter = Arc::new(ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                creds,
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            ));
            let http_before = mcp_server.requests.load(Ordering::SeqCst);
            let settings = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
                Ok(Some(
                    match k {
                        "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                        "LEASE_MS" => "30000",
                        "EXECUTION_TIMEOUT_MS" => "180000",
                        "POLL_MS" => "100",
                        "SWEEP_MS" => "1000",
                        _ => return Ok(None),
                    }
                    .into(),
                ))
            })
            .unwrap();
            let (sh_tx, sh_rx) = oneshot::channel();
            let task = tokio::spawn({
                let pool = worker_pool.clone();
                let approved = Arc::new(adapter.approved_effects());
                async move {
                    worker::run_with_approvals(
                        &pool,
                        None,
                        settings,
                        Arc::new(ResumeExecutor),
                        Some(approved),
                        async move {
                            let _ = sh_rx.await;
                        },
                        Duration::from_secs(4),
                    )
                    .await;
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let final_state = loop {
                let s: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&r_ap.run_id)
                        .fetch_one(&mut owner)
                        .await
                        .unwrap();
                if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                    break s;
                }
                assert!(Instant::now() < deadline, "{label} timed out");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let _ = sh_tx.send(());
            task.await.unwrap();

            if disable_gate {
                sqlx::query(
                    "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = true",
                )
                .execute(&mut owner)
                .await
                .unwrap();
            }

            assert_eq!(final_state, "failed", "{label}");
            let ops_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid",
            )
            .bind(&r_ap.run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
            assert_eq!(ops_count, 0, "{label} must write 0 operations rows");
            assert_eq!(
                mcp_server.requests.load(Ordering::SeqCst),
                http_before,
                "{label} must issue 0 HTTP requests"
            );
        }
    }

    // --- (c) P1 #3: Real TurnExecutor automatic YOLO write handoff (attempts = 0) & reclaim ---
    {
        let model_round = Arc::new(AtomicUsize::new(0));
        let model_round_srv = model_round.clone();
        let seen_tool_result = Arc::new(AtomicBool::new(false));
        let seen_tool_result_srv = seen_tool_result.clone();
        let model_server = SyntheticMcpServer::start(move |req| {
            let round = model_round_srv.fetch_add(1, Ordering::SeqCst);
            if round == 0 {
                let body = json!({
                    "id": "chatcmpl-r1",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_yolo_1",
                                "type": "function",
                                "function": {
                                    "name": "mcp_idem",
                                    "arguments": "{\"item\":\"turn-reclaim\"}"
                                }
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                })
                .to_string();
                http_response(
                    200,
                    &[("content-type", "application/json")],
                    body.as_bytes(),
                )
            } else {
                if req.body.to_string().contains("turn-write-ok") {
                    seen_tool_result_srv.store(true, Ordering::SeqCst);
                }
                let body = json!({
                    "id": "chatcmpl-r2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "All done!"
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 5}
                })
                .to_string();
                http_response(
                    200,
                    &[("content-type", "application/json")],
                    body.as_bytes(),
                )
            }
        })
        .await;

        let catalog_bytes = include_bytes!("../fixtures/conversation-catalog-v1.json");
        let catalog = Arc::new(Catalog::load(catalog_bytes).unwrap());
        let selection: Selection = serde_json::from_value(
            json!({"model": "a", "layer": {"controls": {"output_reserve": 256}}}),
        )
        .unwrap();
        let snapshot = ConfigSnapshot {
            effective: catalog
                .resolve(&Selection::default(), &selection, None, |_, _| true)
                .unwrap(),
            required_capabilities: catalog.model("a").unwrap().required_capabilities.clone(),
            policy_revision: "openmettle.authz/1".into(),
            cost_bound: catalog.model("a").unwrap().cost_bound,
        };

        let prefix = if model_server.ip.is_ipv4() { 32 } else { 128 };
        let range = format!("{}/{prefix}", model_server.ip);
        let gateway = Arc::new(
            Gateway::new(
                &format!(
                    "https://{}:{}/v1/chat/completions",
                    model_server.host, model_server.port
                ),
                Trust::Bundle(&model_server.ca_pem),
                &[&range],
                Qualification {
                    model: "a".into(),
                    pin: catalog.model("a").unwrap().pin.clone(),
                    protocol: Protocol::Chat,
                    json: true,
                    sse: false,
                    functions: Some(inference::SchemaSubset::Flat),
                    images: false,
                    parallel: false,
                    usage: true,
                    tool_separator_whitespace: false,
                },
                Timeouts {
                    setup: Duration::from_secs(5),
                    idle: Duration::from_secs(15),
                    overall: Duration::from_secs(30),
                },
            )
            .unwrap(),
        );

        struct McpTurnRoutes {
            gateway: Arc<Gateway>,
            registry: Arc<ExternalRegistry>,
        }
        impl TurnRoutes for McpTurnRoutes {
            async fn route(
                &self,
                _: &ClaimedRun,
                _: &str,
                _: &Effective,
            ) -> Result<Route, inference::Error> {
                Ok(Route::metered(
                    self.gateway.clone(),
                    "00000000-0000-4000-8000-000000000091".into(),
                    false,
                ))
            }
            fn tools(&self, _: &ClaimedRun) -> Vec<Tool> {
                vec![self.registry.get("mcp_idem", "1").unwrap().declaration()]
            }
            fn declared_tools(&self, _: &ClaimedRun) -> Vec<DeclaredTool> {
                vec![self.registry.get("mcp_idem", "1").unwrap().declared_tool()]
            }
            fn tool_prompt_bound(&self, _: &Effective, request: &Request) -> Option<u64> {
                (request.history.len() <= 16).then_some(4096)
            }
            fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
                self.registry
                    .proposal(
                        &call.id,
                        &call.name,
                        "1",
                        &serde_json::to_vec(&call.arguments).ok()?,
                    )
                    .ok()
            }
        }

        // Wrapper policy that triggers Stop::Shutdown synchronously during Tx1's `review` on Worker 1,
        // so Tx1 commits (`dispatched_attempts = 0`) and `EffectDispatch::send` stops BEFORE Tx2!
        struct StopOnFirstReview {
            inner: Arc<ExternalRegistry>,
            stop: Mutex<Option<tokio::sync::watch::Sender<Option<Stop>>>>,
        }
        impl approvals::EffectPolicy for StopOnFirstReview {
            fn review(
                &self,
                scope: &str,
                run: &str,
                p: &Proposal,
            ) -> Result<Option<Review>, StoreError> {
                if let Some(tx) = self.stop.lock().unwrap().take() {
                    let _ = tx.send(Some(Stop::Shutdown));
                }
                self.inner.review(scope, run, p)
            }
            fn requires_two_phase_writes(&self) -> bool {
                self.inner.requires_two_phase_writes()
            }
        }

        // Admit a real conversation + YOLO run.
        let audit_ctx = |key: &'static str| AuditContext {
            actor_user_id: &f.actor.user,
            actor_approval_id: &f.actor.approval,
            now_ms: f.user.context().observed_ms(),
            request_key: key,
            reason: "review1 turn reclaim test",
        };
        let conv = match branches::create_conversation(&mut a, &audit_ctx("turn-conv"), &f.scope)
            .await
            .unwrap()
        {
            WriteOutcome::Applied { target_id } | WriteOutcome::Replayed { target_id } => target_id,
        };
        let msg_id = "00000000-0000-4000-8000-000000001403";
        let chat = Conversation {
            scope: &f.scope,
            id: &conv.conversation_id,
        };
        let parts = [Part::Text("invoke mcp.idem".into())];
        let turn_op = Operation::Append(UserInput {
            id: msg_id,
            parts: &parts,
        });
        let turn_intent = TurnIntent {
            source_branch_id: &conv.branch_id,
            expected_head_message_id: None,
            operation: turn_op,
            selection: &selection,
            requested_rounds: Some(3),
        };
        let actor_principal = super::super::authz_store::principal(&f.db, &f.actor).await;
        let mut tx = WriteTransaction::begin(&mut a).await.unwrap();
        branches::prepare_turn(
            &mut tx,
            &audit_ctx("turn-msg"),
            chat,
            &conv.branch_id,
            None,
            turn_op,
        )
        .await
        .unwrap();
        let history = branches::history(
            tx.connection().unwrap(),
            &actor_principal,
            chat,
            &conv.branch_id,
            f.user.context().observed_ms(),
        )
        .await
        .unwrap()
        .unwrap();
        let pins = Snapshots::encode(&turn_intent, &history, &catalog, &snapshot).unwrap();
        let mut snap_val: Value = serde_json::from_slice(&pins.config).unwrap();
        snap_val["execution_mode"] = json!("yolo");
        let snapshot_bytes = serde_json::to_vec(&snap_val).unwrap();
        let admission = queue::admit_run_with_mode(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &f.scope,
                    actor: &f.actor.user,
                    conversation: &conv.conversation_id,
                    branch: &conv.branch_id,
                    message: msg_id,
                    key: "turn-yolo-reclaim",
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: &pins.input,
                    config: &snapshot_bytes,
                },
                actor_approval_id: &f.actor.approval,
                capabilities: &[],
                requested_rounds: Some(3),
                now_ms: f.user.context().observed_ms(),
                cost_qualified: None,
            },
            &LIMITS,
            &f.user,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let Admission::Admitted { run_id, .. } = admission else {
            panic!("expected admitted turn run");
        };

        let mcp_calls_before = mcp_tool_calls.load(Ordering::SeqCst);
        let claim1 = f.next().await.expect("claim turn run");
        assert_eq!(claim1.run_id, run_id);

        let adapter1 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-turn".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let (stop_tx1, step1) = fresh_step(30);
        let effects1 = Arc::new(ApprovedEffects {
            policy: Arc::new(StopOnFirstReview {
                inner: registry.clone(),
                stop: Mutex::new(Some(stop_tx1)),
            }),
            adapter: adapter1,
        });
        let exec1 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            McpTurnRoutes {
                gateway: gateway.clone(),
                registry: registry.clone(),
            },
        )
        .with_effects(effects1);
        let active1 = ActiveRun {
            claim: claim1.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        let step_res1 = exec1.step(&active1, step1).await;
        let step_res1_tag = match &step_res1 {
            StepResult::Handoff => "Handoff".to_owned(),
            StepResult::Stopped => "Stopped".to_owned(),
            StepResult::LeaseLost => "LeaseLost".to_owned(),
            StepResult::Finished => "Finished".to_owned(),
            StepResult::Continue => "Continue".to_owned(),
            StepResult::Failed(r) => format!("Failed({r:?})"),
            StepResult::Invalidated(s) => format!("Invalidated({s:?})"),
            StepResult::Answer(_) => "Answer".to_owned(),
            StepResult::ToolOutput(s) => format!("ToolOutput({s})"),
            StepResult::ToolResponse(r) => format!("ToolResponse({r:?})"),
            StepResult::ToolSuccess { .. } => "ToolSuccess".to_owned(),
        };
        assert!(
            matches!(step_res1, StepResult::Handoff),
            "Worker 1 must hand off before Tx2 after Stop::Shutdown; got {step_res1_tag}, model_rounds={}, mcp_reqs={}",
            model_round.load(Ordering::SeqCst),
            mcp_server.requests.load(Ordering::SeqCst)
        );
        leases::release_lease(&mut w, &claim1.lease())
            .await
            .unwrap();
        // Verify Tx1 committed with dispatched_attempts == 0 and 0 tools/call sent.
        let (att0, out0): (i32, String) = sqlx::query_as(
            "SELECT dispatched_attempts, outcome FROM openmettle.operations
              WHERE run_id = $1::uuid AND logical_key = 'call_yolo_1'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((att0, out0.as_str()), (0, "intent"));
        assert_eq!(mcp_tool_calls.load(Ordering::SeqCst), mcp_calls_before);

        // Worker 2 runs the full `worker::run_with_approvals` loop with a real TurnExecutor!
        let adapter2 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-turn".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let approved2 = Arc::new(adapter2.approved_effects());
        let exec2 = Arc::new(
            TurnExecutor::new(
                worker_pool.clone(),
                catalog,
                LEASES,
                McpTurnRoutes {
                    gateway,
                    registry: registry.clone(),
                },
            )
            .with_effects(approved2.clone()),
        );
        let settings = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
            Ok(Some(
                match k {
                    "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                    "LEASE_MS" => "30000",
                    "EXECUTION_TIMEOUT_MS" => "180000",
                    "POLL_MS" => "100",
                    "SWEEP_MS" => "1000",
                    _ => return Ok(None),
                }
                .into(),
            ))
        })
        .unwrap();
        let (sh_tx, sh_rx) = oneshot::channel();
        let task2 = tokio::spawn({
            let pool = worker_pool.clone();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec2,
                    Some(approved2),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "Worker 2 TurnExecutor timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task2.await.unwrap();

        assert_eq!(final_state, "succeeded");
        let (att1, out1): (i32, String) = sqlx::query_as(
            "SELECT dispatched_attempts, outcome FROM openmettle.operations
              WHERE run_id = $1::uuid AND logical_key = 'call_yolo_1'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((att1, out1.as_str()), (1, "succeeded"));
        assert_eq!(mcp_tool_calls.load(Ordering::SeqCst), mcp_calls_before + 1);
        assert!(seen_tool_result.load(Ordering::SeqCst));
        assert_eq!(model_round.load(Ordering::SeqCst), 2);
    }

    // --- (d) P1 #4 & P2 #1: Rebound contract refusal + full worker reconciliation commit + handle conflict ---
    {
        let make_unknown = async |label: &str, handle: &str| -> (ClaimedRun, String) {
            let rr = f.claim(label, "yolo").await;
            let prop = registry
                .proposal(label, "mcp.lookup_handle", "1", br#"{"item":"rec-item"}"#)
                .unwrap();
            let IntentResult::Applied(tx1) = record_fenced_intent(
                &mut worker(&f.db).await,
                &rr.lease(),
                &prop,
                None,
                registry.as_ref(),
                &LEASES,
            )
            .await
            .unwrap() else {
                panic!("expected Tx1 for {label}");
            };
            assert!(matches!(
                start_write_attempt(
                    &mut worker(&f.db).await,
                    &rr.lease(),
                    &tx1.operation_id,
                    &prop,
                    &LEASES,
                    registry.as_ref(),
                )
                .await
                .unwrap(),
                ReplayEffect::Ready(_)
            ));
            let mut cw = worker(&f.db).await;
            leases::with_lease(&mut cw, &rr.lease(), Fence::Hold, async |tx, _| {
                durable::record_observation(
                    tx,
                    &durable::Observation {
                        scope: &rr.scope_id,
                        run: &rr.run_id,
                        operation: &tx1.operation_id,
                        key: &format!("unknown-init:{}", tx1.operation_id),
                        expected_revision: 0,
                        outcome: "outcome_unknown",
                        handle: Some(handle),
                        evidence: Payload {
                            format: "openmettle.unresolved-write",
                            version: 1,
                            bytes: br#"{"reason":"handle_recorded"}"#,
                        },
                    },
                )
                .await
            })
            .await
            .unwrap();
            assert_eq!(
                leases::settle(&mut cw, &rr.lease(), &LEASES, Settle::Stopped)
                    .await
                    .unwrap(),
                leases::Settled::Reconciling { unresolved: 1 }
            );
            (rr, tx1.operation_id)
        };

        // P1 #4: Rebind ("mcp.lookup_handle", "1") to a different connection/account -> None, 0 authz, 0 creds, 0 HTTP!
        {
            let (rr, op_id) = make_unknown("rebind-test", "h-rebind").await;
            let mut rebound_reg = ExternalRegistry::new();
            let mut rebound_contract = registry.get("mcp.lookup_handle", "1").unwrap().clone();
            rebound_contract.connection_id = "other-mcp".into();
            rebound_contract.account_id = "acct-other".into();
            rebound_reg.register(rebound_contract).unwrap();
            let mut rebound_transports = BTreeMap::new();
            rebound_transports.insert("other-mcp".to_owned(), mcp_server.transport());
            let checks = Arc::new(AtomicUsize::new(0));
            let lookups = Arc::new(AtomicUsize::new(0));
            let rebound_adapter = ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                Arc::new(rebound_reg),
                rebound_transports,
                Arc::new(CountingCredentials {
                    token: Some("tok-other".into()),
                    lookups: lookups.clone(),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: checks.clone(),
                }),
            );
            let http0 = mcp_server.requests.load(Ordering::SeqCst);
            let op = leases::unresolved_operations(&mut w, &rr.lease(), 10)
                .await
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(op.id, op_id);
            let (_st, step) = fresh_step(15);
            let active = ActiveRun {
                claim: rr.clone(),
                state: leases::ExecState::Reconciling,
                execution_deadline: step.deadline,
            };
            assert!(
                rebound_adapter
                    .reconcile_operation(&active, &op, step)
                    .await
                    .is_none()
            );
            assert_eq!(checks.load(Ordering::SeqCst), 0);
            assert_eq!(lookups.load(Ordering::SeqCst), 0);
            assert_eq!(mcp_server.requests.load(Ordering::SeqCst), http0);
            leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
                .await
                .unwrap();
        }

        // P2 #1: Full worker reconciliation loop commits OwnedObservation (revision 1 -> 2)
        // when remote handle matches, AND settles `interrupted` when remote handle conflicts!
        struct ReconcileWorkerExec {
            adapter: Arc<ExternalMcpAdapter>,
        }
        impl Executor for ReconcileWorkerExec {
            async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
                StepResult::Finished
            }
            async fn reconcile(
                &self,
                run: &ActiveRun,
                op: &leases::UnresolvedOperation,
                cx: StepContext,
            ) -> Option<OwnedObservation> {
                self.adapter.reconcile_operation(run, op, cx).await
            }
        }

        let live_adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-rec".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));

        for (label, handle, expect_unresolved, expect_op_outcome, expect_rev, expect_handle) in [
            ("rec-worker-ok", "h-2", 0u64, "succeeded", 2i64, "h-2"),
            (
                "rec-worker-conflict",
                "h-conflict",
                1u64,
                "outcome_unknown",
                1i64,
                "h-conflict",
            ),
        ] {
            let (rr, op_id) = make_unknown(label, handle).await;
            leases::release_lease(&mut w, &rr.lease()).await.unwrap();
            let settings = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
                Ok(Some(
                    match k {
                        "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                        "LEASE_MS" => "30000",
                        "EXECUTION_TIMEOUT_MS" => "180000",
                        "POLL_MS" => "100",
                        "SWEEP_MS" => "1000",
                        _ => return Ok(None),
                    }
                    .into(),
                ))
            })
            .unwrap();
            let (sh_tx, sh_rx) = oneshot::channel();
            let task = tokio::spawn({
                let pool = worker_pool.clone();
                let exec = Arc::new(ReconcileWorkerExec {
                    adapter: live_adapter.clone(),
                });
                async move {
                    worker::run(
                        &pool,
                        None,
                        settings,
                        exec,
                        async move {
                            let _ = sh_rx.await;
                        },
                        Duration::from_secs(4),
                    )
                    .await;
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let final_state = loop {
                let s: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&rr.run_id)
                        .fetch_one(&mut owner)
                        .await
                        .unwrap();
                if s != "reconciling" && s != "running" {
                    break s;
                }
                assert!(Instant::now() < deadline, "{label} timed out");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let _ = sh_tx.send(());
            task.await.unwrap();

            assert_eq!(final_state, "interrupted", "{label}");
            let term = super::super::authz_runs::terminal_events(&f.db, &rr.run_id).await;
            assert_eq!(term[0].0, "openmettle.run-interrupted", "{label}");
            assert_eq!(
                serde_json::from_slice::<Value>(&term[0].1).unwrap()["unresolved"],
                expect_unresolved,
                "{label}"
            );
            let (op_out, op_rev, op_handle): (String, i64, Option<String>) = sqlx::query_as(
                "SELECT outcome, revision, downstream_handle FROM openmettle.operations WHERE id = $1::uuid",
            )
            .bind(&op_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
            assert_eq!(
                (op_out.as_str(), op_rev, op_handle.as_deref()),
                (expect_op_outcome, expect_rev, Some(expect_handle)),
                "{label}"
            );
        }
    }
}

// ============================================================================================
// 6. Review #1 Regressions: Catalog Drift Gate, Handle Redaction (Inline + Spill),
//    resultType / -32602 PG18 Write Outcomes, Logical call_timeout Bound, Mid-Body Close
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn review1_catalog_drift_handle_redaction_wire_faults_timeout_and_mid_body_close() {
    let f = Fixture::new().await;
    f.grant(true).await;
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;

    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("mcp-r1-spill"));
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_instance SET personal_limit_bytes=2000000, instance_budget_bytes=2000000",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    // --- (a) P1 #5: Upstream tools/list drift fails closed on BOTH call() and resumed approval ---
    {
        let drift_calls = Arc::new(AtomicUsize::new(0));
        let drift_calls_srv = drift_calls.clone();
        let drift_server = SyntheticMcpServer::start(move |req| {
            let id = req.body["id"].as_str().unwrap_or("0");
            if req.body["method"].as_str() == Some("tools/list") {
                // Return a drifted schema for `left\tright` (`maxLength: 999` instead of `128`).
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [{
                            "name": "left\tright",
                            "inputSchema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["item"],
                                "properties": {
                                    "item": {"type": "string", "minLength": 1, "maxLength": 999}
                                }
                            }
                        }]
                    }
                })
                .to_string();
                return http_response(
                    200,
                    &[("content-type", "application/json")],
                    body.as_bytes(),
                );
            }
            drift_calls_srv.fetch_add(1, Ordering::SeqCst);
            jsonrpc_ok(id, "should-never-run", None)
        })
        .await;

        let registry = Arc::new(test_registry(FUTURE * 1000));
        let mut transports = BTreeMap::new();
        transports.insert("synth-mcp".to_owned(), drift_server.transport());
        let adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports,
            Arc::new(CountingCredentials {
                token: Some("tok-drift".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));

        // Direct call() refuses with 0 operations rows and 0 tools/call requests.
        let r_drift = f.claim("catalog-drift-call", "yolo").await;
        let (_st, step) = fresh_step(15);
        let active = ActiveRun {
            claim: r_drift.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };
        let StepResult::ToolOutput(out) = adapter
            .call(
                &active,
                step,
                ExternalCall {
                    key: "k-drift",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"x"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected refusal on drifted catalog");
        };
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap()["fault_code"],
            "terminal_refusal"
        );
        assert_eq!(drift_calls.load(Ordering::SeqCst), 0);
        let ops: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid",
        )
        .bind(&r_drift.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(ops, 0);
        leases::settle(&mut w, &r_drift.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();

        // Resumed human approval via worker::run_with_approvals also refuses with 0 operations & 0 tools/call.
        struct ResumeExec;
        impl Executor for ResumeExec {
            async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
                StepResult::Finished
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
        let r_ap = f.claim("catalog-drift-resume", "ordinary").await;
        let p_ap = registry
            .proposal("k-drift-ap", "mcp.idem", "1", br#"{"item":"x"}"#)
            .unwrap();
        let pk = park(
            &mut w,
            &r_ap.lease(),
            &StepTasks::default().handle(),
            &p_ap,
            registry.as_ref(),
            &LEASES,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let decider = session(&f.db, &f.actor, 42).await;
        decide(
            &mut a,
            &decider,
            &f.input(&r_ap, &pk, HumanDecision::Approve, "drift-ap"),
            registry.as_ref(),
        )
        .await
        .unwrap();
        let settings = openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
            Ok(Some(
                match k {
                    "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                    "LEASE_MS" => "30000",
                    "EXECUTION_TIMEOUT_MS" => "180000",
                    "POLL_MS" => "100",
                    "SWEEP_MS" => "1000",
                    _ => return Ok(None),
                }
                .into(),
            ))
        })
        .unwrap();
        let (sh_tx, sh_rx) = oneshot::channel();
        let task = tokio::spawn({
            let pool = worker_pool.clone();
            let approved = Arc::new(adapter.approved_effects());
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    Arc::new(ResumeExec),
                    Some(approved),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&r_ap.run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "catalog drift resume timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task.await.unwrap();
        assert_eq!(final_state, "failed");
        assert_eq!(drift_calls.load(Ordering::SeqCst), 0);
        let ops_ap: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid",
        )
        .bind(&r_ap.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(ops_ap, 0);
    }

    // --- (b) P1 #7, P1 #8, P1 #9, P2 #2, P2 #3 over synthetic TLS + PG18 ---
    let reg_base = test_registry(FUTURE * 1000);
    let mut reg_custom = test_registry(FUTURE * 1000);
    let mut short_timeout_contract = reg_base.get("mcp.idem", "1").unwrap().clone();
    short_timeout_contract.tool_id = "mcp.idem_short".into();
    short_timeout_contract.remote_name = "mcp.idem_short".into();
    short_timeout_contract.call_timeout = Duration::from_secs(1);
    reg_custom.register(short_timeout_contract).unwrap();
    let registry = Arc::new(reg_custom);

    let list_tools_json: Value = Value::Array(
        [
            "mcp.read",
            "mcp.idem",
            "mcp.idem_short",
            "mcp.lookup_handle",
            "mcp.lookup_det",
            "mcp.nonrep",
        ]
        .into_iter()
        .map(|name| {
            let c = registry.get(name, "1").unwrap();
            json!({"name": c.remote_name, "inputSchema": c.input_schema})
        })
        .collect(),
    );

    const HANDLE_CANARY: &str = "h-secret-canary-999";
    let read_close_count = Arc::new(AtomicUsize::new(0));
    let idem_close_count = Arc::new(AtomicUsize::new(0));
    let read_close_srv = read_close_count.clone();
    let idem_close_srv = idem_close_count.clone();
    let large_payload = "Z".repeat(INLINE_BYTES + 4096);
    let large_payload_srv = large_payload.clone();

    let server = SyntheticMcpServer::start(move |req| {
        let id = req.body["id"].as_str().unwrap_or("0");
        if req.body["method"].as_str() == Some("tools/list") {
            let body = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": list_tools_json}})
                .to_string();
            return http_response(200, &[("content-type", "application/json")], body.as_bytes());
        }
        let item = req.body["params"]["arguments"]["item"]
            .as_str()
            .unwrap_or("");
        match item {
            // P1 #7: resultType failures
            "rt-input" => http_response(
                200,
                &[("content-type", "application/json")],
                json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"input_required","content":[{"type":"text","text":"need"}]}})
                    .to_string()
                    .as_bytes(),
            ),
            "rt-partial" => http_response(
                200,
                &[("content-type", "application/json")],
                json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"partial","content":[{"type":"text","text":"part"}]}})
                    .to_string()
                    .as_bytes(),
            ),
            "rt-num" => http_response(
                200,
                &[("content-type", "application/json")],
                json!({"jsonrpc":"2.0","id":id,"result":{"resultType":123,"content":[{"type":"text","text":"num"}]}})
                    .to_string()
                    .as_bytes(),
            ),
            // P1 #8: malformed -32602 and SSE -32602 + duplicate final response
            "err-32602-malformed" => http_response(
                200,
                &[("content-type", "application/json")],
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602}})
                    .to_string()
                    .as_bytes(),
            ),
            "err-32602-sse-dup" => http_response(
                200,
                &[("content-type", "text/event-stream")],
                format!(
                    "data: {}\n\ndata: {}\n\n",
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"bad"}}),
                    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"second"}]}})
                )
                .as_bytes(),
            ),
            // P1 #9: inline structured-only, text-echo, and spilled structured-only responses
            "handle-inline-structured" => {
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "structuredContent": {
                            "handle": HANDLE_CANARY,
                            "ok": true
                        }
                    }
                })
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            }
            "handle-text-echo" => jsonrpc_ok(
                id,
                &format!("created {HANDLE_CANARY} done"),
                Some(json!({"handle": HANDLE_CANARY})),
            ),
            "handle-spilled-structured" => {
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "structuredContent": {
                            "handle": HANDLE_CANARY,
                            "payload": large_payload_srv
                        }
                    }
                })
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            }
            // P2 #2: Retry-After: 2 exceeds 1s call_timeout
            "retry-after-2s" => http_response(503, &[("retry-after", "2")], b"busy"),
            // P2 #3: mid-body truncated chunked close on first attempt, then 200 OK
            "mid-close-read" => {
                if read_close_srv.fetch_add(1, Ordering::SeqCst) == 0 {
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n50\r\n{\"jsonrpc\":\"2.0\"".to_vec()
                } else {
                    jsonrpc_ok(id, "read-recovered", None)
                }
            }
            "mid-close-idem" => {
                if idem_close_srv.fetch_add(1, Ordering::SeqCst) == 0 {
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n50\r\n{\"jsonrpc\":\"2.0\"".to_vec()
                } else {
                    jsonrpc_ok(id, "idem-close-recovered", Some(json!({"handle": "h-close"})))
                }
            }
            "mid-close-nonrep" => {
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n50\r\n{\"jsonrpc\":\"2.0\"".to_vec()
            }
            _ => jsonrpc_ok(id, "ok", None),
        }
    })
    .await;

    let mut transports = BTreeMap::new();
    transports.insert("synth-mcp".to_owned(), server.transport());
    let adapter = Arc::new(
        ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports,
            Arc::new(CountingCredentials {
                token: Some("tok-r1".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .with_artifacts(store.clone()),
    );

    // P1 #7 & P1 #8: non-complete resultType, malformed -32602, and SSE -32602 + dup -> outcome_unknown
    for (idx, item) in [
        "rt-input",
        "rt-partial",
        "rt-num",
        "err-32602-malformed",
        "err-32602-sse-dup",
    ]
    .into_iter()
    .enumerate()
    {
        let rr = f.claim(&format!("wire-unk-{idx}"), "yolo").await;
        let (_st, step) = fresh_step(20);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };
        let args = json!({"item": item}).to_string();
        assert!(
            matches!(
                adapter
                    .call(
                        &active,
                        step,
                        ExternalCall {
                            key: &format!("k-unk-{idx}"),
                            tool: "mcp.idem",
                            version: "1",
                            raw_args: args.as_bytes(),
                            approval: None,
                        },
                    )
                    .await,
                StepResult::Stopped
            ),
            "{item} must fail closed as outcome_unknown"
        );
        let outcome: String =
            sqlx::query_scalar("SELECT outcome FROM openmettle.operations WHERE run_id = $1::uuid")
                .bind(&rr.run_id)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        assert_eq!(outcome, "outcome_unknown", "{item}");
        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&rr.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // P1 #9: Handle redaction across inline structured-only, text-echo, and spilled structured-only.
    {
        let rr = f.claim("handle-redact", "yolo").await;
        let (_st, step) = fresh_step(25);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };

        // (i) Inline structured-only
        let StepResult::ToolOutput(inline_out) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-h-inline",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"handle-inline-structured"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected inline structured ToolOutput");
        };
        assert!(!inline_out.contains(HANDLE_CANARY));
        assert!(!inline_out.contains("\"handle\""));
        let inline_val: Value = serde_json::from_str(&inline_out).unwrap();
        assert_eq!(inline_val["text"], r#"{"ok":true}"#);
        let h_inline: Option<String> = sqlx::query_scalar(
            "SELECT downstream_handle FROM openmettle.operations WHERE run_id = $1::uuid AND logical_key = 'k-h-inline'",
        )
        .bind(&rr.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(h_inline.as_deref(), Some(HANDLE_CANARY));

        // (ii) Text response echoing the handle literal
        let StepResult::ToolOutput(echo_out) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-h-echo",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"handle-text-echo"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected text-echo ToolOutput");
        };
        assert!(!echo_out.contains(HANDLE_CANARY));
        assert_eq!(
            serde_json::from_str::<Value>(&echo_out).unwrap()["text"],
            "created [REDACTED] done"
        );

        // (iii) Spilled (> 16 KiB) structured-only response
        let StepResult::ToolOutput(spill_out) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-h-spill",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"handle-spilled-structured"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected spilled structured ToolOutput");
        };
        assert!(!spill_out.contains(HANDLE_CANARY));
        let sv: Value = serde_json::from_str(&spill_out).unwrap();
        assert_eq!(sv["storage"], "spilled");
        let art_id = sv["provenance"]["artifact_id"].as_str().unwrap();
        let rev_id = sv["provenance"]["revision_id"].as_str().unwrap();
        let h_spill: Option<String> = sqlx::query_scalar(
            "SELECT downstream_handle FROM openmettle.operations WHERE run_id = $1::uuid AND logical_key = 'k-h-spill'",
        )
        .bind(&rr.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(h_spill.as_deref(), Some(HANDLE_CANARY));

        // Reconstruct spilled bytes via artifact.read_range and verify zero handle leakage.
        let scoped = ScopedAdapter::new(worker_pool.clone(), store.clone(), LEASES);
        let mut spilled_text = String::new();
        let mut offset = 0u64;
        let mut page = 0usize;
        loop {
            let args = json!({
                "artifact_id": art_id,
                "revision_id": rev_id,
                "offset": offset,
                "max_bytes": INLINE_BYTES
            })
            .to_string();
            let StepResult::ToolOutput(chunk_json) = scoped
                .call(
                    &active,
                    step.clone(),
                    &format!("h-range-{page}"),
                    mcp::READ_RANGE,
                    "1",
                    args.as_bytes(),
                )
                .await
            else {
                panic!("expected read_range page");
            };
            let pv: Value = serde_json::from_str(&chunk_json).unwrap();
            spilled_text.push_str(pv["text"].as_str().unwrap());
            offset = pv["next_offset"].as_u64().unwrap();
            if pv["eof"] == true {
                break;
            }
            page += 1;
        }
        assert!(!spilled_text.contains(HANDLE_CANARY));
        assert!(!spilled_text.contains("\"handle\""));
        assert!(spilled_text.contains(&large_payload));
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    // P2 #2: 1s logical call_timeout bounds retry loop under a 30s lease (Retry-After: 2 -> no retry!).
    {
        let rr = f.claim("call-timeout-bound", "yolo").await;
        let (_st, step) = fresh_step(30);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };
        let reqs0 = server.requests.load(Ordering::SeqCst);
        assert!(matches!(
            adapter
                .call(
                    &active,
                    step,
                    ExternalCall {
                        key: "k-short-to",
                        tool: "mcp.idem_short",
                        version: "1",
                        raw_args: br#"{"item":"retry-after-2s"}"#,
                        approval: None,
                    },
                )
                .await,
            StepResult::Stopped
        ));
        assert_eq!(server.requests.load(Ordering::SeqCst), reqs0 + 1);
        let outcome: String =
            sqlx::query_scalar("SELECT outcome FROM openmettle.operations WHERE run_id = $1::uuid")
                .bind(&rr.run_id)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        assert_eq!(outcome, "outcome_unknown");
        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&rr.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }

    // P2 #3: Mid-body close retries for repeatable_read and idempotent, never for non_repeatable!
    {
        let rr = f.claim("mid-close-matrix", "yolo").await;
        let (_st, step) = fresh_step(25);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };

        let StepResult::ToolOutput(read_out) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-mc-read",
                    tool: "mcp.read",
                    version: "1",
                    raw_args: br#"{"item":"mid-close-read"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("repeatable_read must retry mid-body close");
        };
        assert_eq!(
            serde_json::from_str::<Value>(&read_out).unwrap()["text"],
            "read-recovered"
        );
        assert_eq!(read_close_count.load(Ordering::SeqCst), 2);

        let StepResult::ToolOutput(idem_out) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-mc-idem",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"mid-close-idem"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("idempotent write must retry mid-body close");
        };
        assert_eq!(
            serde_json::from_str::<Value>(&idem_out).unwrap()["text"],
            "idem-close-recovered"
        );
        assert_eq!(idem_close_count.load(Ordering::SeqCst), 2);
        let idem_att: i32 = sqlx::query_scalar(
            "SELECT dispatched_attempts FROM openmettle.operations WHERE run_id = $1::uuid AND logical_key = 'k-mc-idem'",
        )
        .bind(&rr.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(idem_att, 2);

        let reqs0 = server.requests.load(Ordering::SeqCst);
        assert!(matches!(
            adapter
                .call(
                    &active,
                    step,
                    ExternalCall {
                        key: "k-mc-nonrep",
                        tool: "mcp.nonrep",
                        version: "1",
                        raw_args: br#"{"item":"mid-close-nonrep"}"#,
                        approval: None,
                    },
                )
                .await,
            StepResult::Stopped
        ));
        assert_eq!(server.requests.load(Ordering::SeqCst), reqs0 + 1);
        let (nonrep_out, nonrep_att): (String, i32) = sqlx::query_as(
            "SELECT outcome, dispatched_attempts FROM openmettle.operations
              WHERE run_id = $1::uuid AND logical_key = 'k-mc-nonrep'",
        )
        .bind(&rr.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((nonrep_out.as_str(), nonrep_att), ("outcome_unknown", 1));
        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&rr.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }
}

// ============================================================================================
// 7. Review #2 Regressions: Tx1 Gate TOCTOU, Catalog TTL + 503 Handoff + Turn Tool Filtering,
//    Multi-Round & Multi-Call TurnExecutor Reclaim, Reconcile Exact Review Equality,
//    Structured Handle Redaction & Malformed Handle Matrix, Constrained Schema Default Expansion,
//    Non-Lookup outcome_unknown Reconcile, and Bounded Credential Resolution
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn review2_toctou_ttl_multicall_multiround_reconcile_handle_and_deadline_regressions() {
    use openmettle_core::{
        authz::{
            branches::{
                self, Conversation, Operation, Part, UserInput,
                snapshot::{Intent as TurnIntent, Snapshots},
            },
            store::{AuditContext, WriteOutcome},
        },
        model_config::{
            Catalog, ConfigSnapshot, Effective, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection,
        },
        provider_http::inference::{
            self, Call, Gateway, Protocol, Qualification, Request, Timeouts, Tool,
        },
        runs::RunInput,
        worker::turns::{Route, TurnExecutor, TurnRoutes},
    };

    let f = Fixture::new().await;
    f.grant(true).await;
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let mut w = worker(&f.db).await;
    let mut a = api(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;

    // Build extended registry with flat/rich/multi-account/short-timeout/missing-conn contracts.
    let mut reg_builder = test_registry(FUTURE * 1000);
    let mut read_turn = reg_builder.get("mcp.read", "1").unwrap().clone();
    read_turn.tool_id = "mcp_read".into();
    read_turn.remote_name = "mcp_read".into();
    reg_builder.register(read_turn).unwrap();

    let mut idem_turn = reg_builder.get("mcp.idem", "1").unwrap().clone();
    idem_turn.tool_id = "mcp_idem".into();
    idem_turn.remote_name = "mcp_idem".into();
    reg_builder.register(idem_turn).unwrap();

    let mut acct2_read = reg_builder.get("mcp.read", "1").unwrap().clone();
    acct2_read.tool_id = "mcp.read_acct2".into();
    acct2_read.remote_name = "mcp.read_acct2".into();
    acct2_read.account_id = "acct-2".into();
    reg_builder.register(acct2_read).unwrap();

    let mut rich = reg_builder.get("mcp.idem", "1").unwrap().clone();
    rich.tool_id = "mcp_rich".into();
    rich.remote_name = "mcp_rich".into();
    rich.resource_field = Some("doc_id".into());
    rich.input_schema = json!({
        "type": "object",
        "title": "RichWrite",
        "description": "Constrained external write",
        "additionalProperties": false,
        "required": ["doc_id", "mode"],
        "properties": {
            "doc_id": {
                "type": "string",
                "description": "Target document UUID",
                "format": "uuid",
                "minLength": 36,
                "maxLength": 36
            },
            "mode": {
                "type": "string",
                "enum": ["append", "replace"],
                "minLength": 1,
                "maxLength": 16
            },
            "retries": {
                "type": "integer",
                "minimum": 0,
                "maximum": 3,
                "default": 2
            }
        }
    });
    reg_builder.register(rich).unwrap();

    let mut short_to = reg_builder.get("mcp.idem", "1").unwrap().clone();
    short_to.tool_id = "mcp.idem_short".into();
    short_to.remote_name = "mcp.idem_short".into();
    short_to.call_timeout = Duration::from_secs(1);
    reg_builder.register(short_to).unwrap();

    let registry = Arc::new(reg_builder);

    // --- (a) P1 #1: Transaction 1 enforces two_phase_effect_intents_enabled atomically for ExternalRegistry ---
    {
        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = false",
        )
        .execute(&mut owner)
        .await
        .unwrap();

        // Direct record_fenced_intent (simulating gate flip between preflight and Tx1) refuses
        // BOTH automatic writes and reads with 0 operations rows.
        let r_auto = f.claim("r2-tx1-toctou-auto", "yolo").await;
        for (key, tool) in [
            ("k-toctou-write", "mcp.idem"),
            ("k-toctou-read", "mcp.read"),
        ] {
            let prop = registry
                .proposal(key, tool, "1", br#"{"item":"toctou"}"#)
                .unwrap();
            let err = record_fenced_intent(
                &mut w,
                &r_auto.lease(),
                &prop,
                None,
                registry.as_ref(),
                &LEASES,
            )
            .await
            .err()
            .expect("ExternalRegistry Tx1 must reject when gate is off");
            assert!(
                matches!(err, leases::LeaseError::Store(StoreError::Denied(_))),
                "{tool} expected Denied, got {err:?}"
            );
        }
        let ops_auto: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid",
        )
        .bind(&r_auto.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(ops_auto, 0);
        leases::settle(&mut w, &r_auto.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();

        // Human-approved write whose gate flips off before Tx1 invalidates cleanly with 0 operations rows.
        let r_hum = f.claim("r2-tx1-toctou-human", "ordinary").await;
        let p_hum = registry
            .proposal("k-toctou-hum", "mcp.idem", "1", br#"{"item":"toctou-h"}"#)
            .unwrap();
        let pk_hum = park(
            &mut w,
            &r_hum.lease(),
            &StepTasks::default().handle(),
            &p_hum,
            registry.as_ref(),
            &LEASES,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let decider = session(&f.db, &f.actor, 61).await;
        decide(
            &mut a,
            &decider,
            &f.input(&r_hum, &pk_hum, HumanDecision::Approve, "r2-toctou"),
            registry.as_ref(),
        )
        .await
        .unwrap();
        let r_hum = f.next().await.unwrap();
        let res_hum = record_fenced_intent(
            &mut w,
            &r_hum.lease(),
            &p_hum,
            Some(&pk_hum.approval_id),
            registry.as_ref(),
            &LEASES,
        )
        .await
        .unwrap();
        assert!(matches!(res_hum, IntentResult::Invalidated(_)));
        let ops_hum: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid",
        )
        .bind(&r_hum.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(ops_hum, 0);

        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = true",
        )
        .execute(&mut owner)
        .await
        .unwrap();
    }

    // Shared synthetic TLS MCP server with dynamic tools/list controls and payload capture.
    let list_tools_json: Value = Value::Array(
        [
            "mcp.read",
            "mcp.read_acct2",
            "mcp.idem",
            "mcp.idem_short",
            "mcp.lookup_handle",
            "mcp.lookup_det",
            "mcp.nonrep",
            "mcp_read",
            "mcp_idem",
            "mcp_rich",
        ]
        .into_iter()
        .map(|name| {
            let c = registry.get(name, "1").unwrap();
            json!({"name": c.remote_name, "inputSchema": c.input_schema})
        })
        .collect(),
    );
    let tools_list_calls = Arc::new(AtomicUsize::new(0));
    let transient_list_503_once = Arc::new(AtomicBool::new(false));
    let drift_list_enabled = Arc::new(AtomicBool::new(false));
    let mcp_read_calls = Arc::new(AtomicUsize::new(0));
    let mcp_idem_calls = Arc::new(AtomicUsize::new(0));
    let rich_received_args: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));

    let tools_list_calls_srv = tools_list_calls.clone();
    let transient_503_srv = transient_list_503_once.clone();
    let drift_list_srv = drift_list_enabled.clone();
    let mcp_read_calls_srv = mcp_read_calls.clone();
    let mcp_idem_calls_srv = mcp_idem_calls.clone();
    let rich_received_srv = rich_received_args.clone();

    let server = SyntheticMcpServer::start(move |req| {
        let id = req.body["id"].as_str().unwrap_or("0");
        let method = req.body["method"].as_str().unwrap_or("");
        if method == "tools/list" {
            tools_list_calls_srv.fetch_add(1, Ordering::SeqCst);
            if transient_503_srv.swap(false, Ordering::SeqCst) {
                return http_response(503, &[("retry-after", "0")], b"catalog-unavailable");
            }
            if drift_list_srv.load(Ordering::SeqCst) {
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [{
                            "name": "mcp_idem",
                            "inputSchema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["item"],
                                "properties": {
                                    "item": {"type": "string", "minLength": 1, "maxLength": 9999}
                                }
                            }
                        }]
                    }
                })
                .to_string();
                return http_response(
                    200,
                    &[("content-type", "application/json")],
                    body.as_bytes(),
                );
            }
            let body = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": list_tools_json}})
                .to_string();
            return http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            );
        }
        let tool = req.body["params"]["name"].as_str().unwrap_or("");
        let args = &req.body["params"]["arguments"];
        if tool == "mcp.status" {
            if args.get("handle").and_then(Value::as_str) == Some("h-bad-remote") {
                return jsonrpc_ok(
                    id,
                    r#"{"status":"succeeded"}"#,
                    Some(json!({"status": "succeeded", "handle": "bad space"})),
                );
            }
            return jsonrpc_ok(
                id,
                r#"{"status":"succeeded"}"#,
                Some(json!({"status": "succeeded", "handle": "h-ok"})),
            );
        }
        if tool == "mcp_rich" {
            *rich_received_srv.lock().unwrap() = Some(args.clone());
            return jsonrpc_ok(id, "rich-ok", Some(json!({"handle": "h-rich"})));
        }
        if tool == "mcp_read" {
            mcp_read_calls_srv.fetch_add(1, Ordering::SeqCst);
            return jsonrpc_ok(id, "r1-read-ok", None);
        }
        if tool == "mcp_idem" {
            mcp_idem_calls_srv.fetch_add(1, Ordering::SeqCst);
            return jsonrpc_ok(id, "r2-write-ok", Some(json!({"handle": "h-r2"})));
        }
        let item = args["item"].as_str().unwrap_or("");
        match item {
            "handle-escaped" => {
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "structuredContent": {
                            "handle": "h\"quote\\1",
                            "note": "ref h\"quote\\1 done",
                            "count": 1
                        }
                    }
                })
                .to_string();
                http_response(
                    200,
                    &[("content-type", "application/json")],
                    body.as_bytes(),
                )
            }
            "handle-short-1" => {
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "structuredContent": {
                            "handle": "1",
                            "count": 1,
                            "label": "id-1"
                        }
                    }
                })
                .to_string();
                http_response(
                    200,
                    &[("content-type", "application/json")],
                    body.as_bytes(),
                )
            }
            "handle-bad-space" => jsonrpc_ok(id, "ok", Some(json!({"handle": "bad space"}))),
            "handle-bad-num" => jsonrpc_ok(id, "ok", Some(json!({"handle": 123}))),
            _ => jsonrpc_ok(id, "ok", Some(json!({"handle": "h-default"}))),
        }
    })
    .await;

    let mut transports = BTreeMap::new();
    transports.insert("synth-mcp".to_owned(), server.transport());

    let worker_settings = || {
        openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
            Ok(Some(
                match k {
                    "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                    "LEASE_MS" => "30000",
                    "EXECUTION_TIMEOUT_MS" => "180000",
                    "POLL_MS" => "100",
                    "SWEEP_MS" => "1000",
                    _ => return Ok(None),
                }
                .into(),
            ))
        })
        .unwrap()
    };

    // --- (b) P1 #2: Catalog TTL expiry, account/scope key isolation, and 503 handoff on resumed approval ---
    {
        let ttl_adapter = Arc::new(
            ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-ttl".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            )
            .with_catalog_ttl(Duration::from_millis(800)),
        );
        let rr = f.claim("r2-ttl", "yolo").await;
        let (_st, step) = fresh_step(20);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };
        let list0 = tools_list_calls.load(Ordering::SeqCst);
        for k in ["k-ttl-1", "k-ttl-2"] {
            assert!(matches!(
                ttl_adapter
                    .call(
                        &active,
                        step.clone(),
                        ExternalCall {
                            key: k,
                            tool: "mcp.read",
                            version: "1",
                            raw_args: br#"{"item":"a"}"#,
                            approval: None,
                        },
                    )
                    .await,
                StepResult::ToolOutput(_)
            ));
        }
        assert_eq!(
            tools_list_calls.load(Ordering::SeqCst),
            list0 + 1,
            "second call within TTL must hit cache"
        );
        // Distinct account_id on the same connection must NOT reuse acct-1's cache entry.
        assert!(matches!(
            ttl_adapter
                .call(
                    &active,
                    step.clone(),
                    ExternalCall {
                        key: "k-ttl-acct2",
                        tool: "mcp.read_acct2",
                        version: "1",
                        raw_args: br#"{"item":"a"}"#,
                        approval: None,
                    },
                )
                .await,
            StepResult::ToolOutput(_)
        ));
        assert_eq!(
            tools_list_calls.load(Ordering::SeqCst),
            list0 + 2,
            "different account_id must re-verify tools/list"
        );
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(matches!(
            ttl_adapter
                .call(
                    &active,
                    step,
                    ExternalCall {
                        key: "k-ttl-3",
                        tool: "mcp.read",
                        version: "1",
                        raw_args: br#"{"item":"a"}"#,
                        approval: None,
                    },
                )
                .await,
            StepResult::ToolOutput(_)
        ));
        assert_eq!(
            tools_list_calls.load(Ordering::SeqCst),
            list0 + 3,
            "call after TTL expiry must re-verify tools/list"
        );
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();

        // Resumed human approval receiving transient 503 on tools/list MUST hand off (NOT fail)
        // and succeed once the catalog endpoint recovers!
        struct FinishExec;
        impl Executor for FinishExec {
            async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
                StepResult::Finished
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
        let r_503 = f.claim("r2-503-handoff", "ordinary").await;
        let p_503 = registry
            .proposal("k-503-ap", "mcp.idem", "1", br#"{"item":"503-ok"}"#)
            .unwrap();
        let pk_503 = park(
            &mut w,
            &r_503.lease(),
            &StepTasks::default().handle(),
            &p_503,
            registry.as_ref(),
            &LEASES,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let decider = session(&f.db, &f.actor, 62).await;
        decide(
            &mut a,
            &decider,
            &f.input(&r_503, &pk_503, HumanDecision::Approve, "r2-503"),
            registry.as_ref(),
        )
        .await
        .unwrap();
        transient_list_503_once.store(true, Ordering::SeqCst);
        let list_before_503 = tools_list_calls.load(Ordering::SeqCst);
        let fresh_adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-503".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let (sh_tx, sh_rx) = oneshot::channel();
        let task = tokio::spawn({
            let pool = worker_pool.clone();
            let approved = Arc::new(fresh_adapter.approved_effects());
            let settings = worker_settings();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    Arc::new(FinishExec),
                    Some(approved),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&r_503.run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "503 handoff resume timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task.await.unwrap();
        assert_eq!(
            final_state, "succeeded",
            "transient tools/list 503 must hand off and succeed on retry"
        );
        assert!(tools_list_calls.load(Ordering::SeqCst) >= list_before_503 + 2);
    }

    // --- Helper to admit real TurnExecutor YOLO runs ---
    let catalog_bytes = include_bytes!("../fixtures/conversation-catalog-v1.json");
    let catalog = Arc::new(Catalog::load(catalog_bytes).unwrap());
    let selection: Selection = serde_json::from_value(
        json!({"model": "a", "layer": {"controls": {"output_reserve": 256}}}),
    )
    .unwrap();
    let snapshot = ConfigSnapshot {
        effective: catalog
            .resolve(&Selection::default(), &selection, None, |_, _| true)
            .unwrap(),
        required_capabilities: catalog.model("a").unwrap().required_capabilities.clone(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: catalog.model("a").unwrap().cost_bound,
    };
    let make_gateway = |srv: &SyntheticMcpServer, parallel: bool| -> Arc<Gateway> {
        let prefix = if srv.ip.is_ipv4() { 32 } else { 128 };
        let range = format!("{}/{prefix}", srv.ip);
        Arc::new(
            Gateway::new(
                &format!("https://{}:{}/v1/chat/completions", srv.host, srv.port),
                Trust::Bundle(&srv.ca_pem),
                &[&range],
                Qualification {
                    model: "a".into(),
                    pin: catalog.model("a").unwrap().pin.clone(),
                    protocol: Protocol::Chat,
                    json: true,
                    sse: false,
                    functions: Some(inference::SchemaSubset::Flat),
                    images: false,
                    parallel,
                    usage: true,
                    tool_separator_whitespace: false,
                },
                Timeouts {
                    setup: Duration::from_secs(5),
                    idle: Duration::from_secs(15),
                    overall: Duration::from_secs(30),
                },
            )
            .unwrap(),
        )
    };

    struct DynamicTurnRoutes {
        gateway: Arc<Gateway>,
        registry: Arc<ExternalRegistry>,
        tool_ids: Vec<&'static str>,
    }
    impl TurnRoutes for DynamicTurnRoutes {
        async fn route(
            &self,
            _: &ClaimedRun,
            _: &str,
            _: &Effective,
        ) -> Result<Route, inference::Error> {
            Ok(Route::metered(
                self.gateway.clone(),
                "00000000-0000-4000-8000-000000000091".into(),
                false,
            ))
        }
        fn tools(&self, _: &ClaimedRun) -> Vec<Tool> {
            self.tool_ids
                .iter()
                .map(|id| self.registry.get(id, "1").unwrap().declaration())
                .collect()
        }
        fn declared_tools(&self, _: &ClaimedRun) -> Vec<DeclaredTool> {
            self.tool_ids
                .iter()
                .map(|id| self.registry.get(id, "1").unwrap().declared_tool())
                .collect()
        }
        fn tool_prompt_bound(&self, _: &Effective, request: &Request) -> Option<u64> {
            (request.history.len() <= 32).then_some(4096)
        }
        fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
            self.registry
                .proposal(
                    &call.id,
                    &call.name,
                    "1",
                    &serde_json::to_vec(&call.arguments).ok()?,
                )
                .ok()
        }
    }

    struct StopOnToolReview {
        inner: Arc<ExternalRegistry>,
        target_tool: &'static str,
        stop: Mutex<Option<tokio::sync::watch::Sender<Option<Stop>>>>,
    }
    impl approvals::EffectPolicy for StopOnToolReview {
        fn review(
            &self,
            scope: &str,
            run: &str,
            p: &Proposal,
        ) -> Result<Option<Review>, StoreError> {
            if p.tool == self.target_tool
                && let Some(tx) = self.stop.lock().unwrap().take()
            {
                let _ = tx.send(Some(Stop::Shutdown));
            }
            self.inner.review(scope, run, p)
        }
        fn requires_two_phase_writes(&self) -> bool {
            self.inner.requires_two_phase_writes()
        }
    }

    struct CountingPreflightAdapter {
        inner: Arc<ExternalMcpAdapter>,
        preflights: Arc<Mutex<BTreeMap<String, usize>>>,
        refuse_key: Option<&'static str>,
    }
    impl ApprovedAdapter for CountingPreflightAdapter {
        fn preflight<'a>(
            &'a self,
            run: &'a ActiveRun,
            proposal: &'a Proposal,
            step: &'a StepContext,
        ) -> Pin<Box<dyn Future<Output = Result<(), worker::PreflightError>> + Send + 'a>> {
            *self
                .preflights
                .lock()
                .unwrap()
                .entry(proposal.logical_key.clone())
                .or_insert(0) += 1;
            if self.refuse_key == Some(proposal.logical_key.as_str()) {
                return Box::pin(async { Err(worker::PreflightError::Refused) });
            }
            self.inner.preflight(run, proposal, step)
        }
        fn verify_turn_call_proposal(
            &self,
            call: &Call,
            proposal: &Proposal,
            expected_external_version: Option<&str>,
        ) -> bool {
            self.inner
                .verify_turn_call_proposal(call, proposal, expected_external_version)
        }
        fn filter_turn_tools<'a>(
            &'a self,
            run: &'a ActiveRun,
            tools: Vec<DeclaredTool>,
            step: &'a StepContext,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Tool>, StepResult>> + Send + 'a>> {
            self.inner.filter_turn_tools(run, tools, step)
        }
        fn send<'a>(
            &'a self,
            run: &'a ActiveRun,
            operation_id: String,
            request: Vec<u8>,
            step: StepContext,
        ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
            self.inner.send(run, operation_id, request, step)
        }
    }

    let admit_yolo_turn = async |key: &'static str, msg_id: &'static str, rounds: i64| -> String {
        let mut ac = api(&f.db).await;
        let audit_ctx = |k: &'static str| AuditContext {
            actor_user_id: &f.actor.user,
            actor_approval_id: &f.actor.approval,
            now_ms: f.user.context().observed_ms(),
            request_key: k,
            reason: "review2 turn test",
        };
        let conv = match branches::create_conversation(&mut ac, &audit_ctx(key), &f.scope)
            .await
            .unwrap()
        {
            WriteOutcome::Applied { target_id } | WriteOutcome::Replayed { target_id } => target_id,
        };
        let chat = Conversation {
            scope: &f.scope,
            id: &conv.conversation_id,
        };
        let parts = [Part::Text("run external tool".into())];
        let turn_op = Operation::Append(UserInput {
            id: msg_id,
            parts: &parts,
        });
        let turn_intent = TurnIntent {
            source_branch_id: &conv.branch_id,
            expected_head_message_id: None,
            operation: turn_op,
            selection: &selection,
            requested_rounds: Some(rounds),
        };
        let actor_principal = super::super::authz_store::principal(&f.db, &f.actor).await;
        let mut tx = WriteTransaction::begin(&mut ac).await.unwrap();
        let msg_key = Box::leak(format!("{key}-msg").into_boxed_str());
        branches::prepare_turn(
            &mut tx,
            &audit_ctx(msg_key),
            chat,
            &conv.branch_id,
            None,
            turn_op,
        )
        .await
        .unwrap();
        let history = branches::history(
            tx.connection().unwrap(),
            &actor_principal,
            chat,
            &conv.branch_id,
            f.user.context().observed_ms(),
        )
        .await
        .unwrap()
        .unwrap();
        let pins = Snapshots::encode(&turn_intent, &history, &catalog, &snapshot).unwrap();
        let mut snap_val: Value = serde_json::from_slice(&pins.config).unwrap();
        snap_val["execution_mode"] = json!("yolo");
        let snapshot_bytes = serde_json::to_vec(&snap_val).unwrap();
        let admission = queue::admit_run_with_mode(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &f.scope,
                    actor: &f.actor.user,
                    conversation: &conv.conversation_id,
                    branch: &conv.branch_id,
                    message: msg_id,
                    key,
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: &pins.input,
                    config: &snapshot_bytes,
                },
                actor_approval_id: &f.actor.approval,
                capabilities: &[],
                requested_rounds: Some(rounds),
                now_ms: f.user.context().observed_ms(),
                cost_qualified: None,
            },
            &LIMITS,
            &f.user,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let Admission::Admitted { run_id, .. } = admission else {
            panic!("expected admitted turn run for {key}");
        };
        run_id
    };

    // --- (c) P2 #5: TurnExecutor filters out drifted external tools before advertising to model ---
    {
        drift_list_enabled.store(true, Ordering::SeqCst);
        let saw_tools_field = Arc::new(AtomicBool::new(false));
        let saw_tools_srv = saw_tools_field.clone();
        let model_srv = SyntheticMcpServer::start(move |req| {
            if req.body.get("tools").is_some_and(|v| !v.is_null()) {
                saw_tools_srv.store(true, Ordering::SeqCst);
            }
            let body = json!({
                "id": "chatcmpl-drift-filter",
                "object": "chat.completion",
                "model": "a",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "No tools advertised"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 4}
            })
            .to_string();
            http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            )
        })
        .await;

        let run_id =
            admit_yolo_turn("r2-filter-drift", "00000000-0000-4000-8000-000000002401", 2).await;
        let adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-filter".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let approved = Arc::new(adapter.approved_effects());
        let exec = Arc::new(
            TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                DynamicTurnRoutes {
                    gateway: make_gateway(&model_srv, false),
                    registry: registry.clone(),
                    tool_ids: vec!["mcp_idem"],
                },
            )
            .with_effects(approved.clone()),
        );
        let (sh_tx, sh_rx) = oneshot::channel();
        let task = tokio::spawn({
            let pool = worker_pool.clone();
            let settings = worker_settings();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec,
                    Some(approved),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "filter drift turn timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task.await.unwrap();
        drift_list_enabled.store(false, Ordering::SeqCst);

        assert_eq!(final_state, "succeeded");
        assert!(
            !saw_tools_field.load(Ordering::SeqCst),
            "drifted external tool must be omitted before offering tools to the model"
        );
    }

    // --- (d) P1 #3: Multi-round TurnExecutor reclaim (Round 1 read -> Round 2 write handoff -> Round 3 finish) ---
    {
        let mr_rounds = Arc::new(AtomicUsize::new(0));
        let mr_rounds_srv = mr_rounds.clone();
        let saw_both = Arc::new(AtomicBool::new(false));
        let saw_both_srv = saw_both.clone();
        let model_srv = SyntheticMcpServer::start(move |req| {
            let r = mr_rounds_srv.fetch_add(1, Ordering::SeqCst);
            let body = match r {
                0 => json!({
                    "id": "chatcmpl-mr-1",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_mr_1",
                                "type": "function",
                                "function": {"name": "mcp_read", "arguments": "{\"item\":\"r1\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                }),
                1 => json!({
                    "id": "chatcmpl-mr-2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_mr_2",
                                "type": "function",
                                "function": {"name": "mcp_idem", "arguments": "{\"item\":\"r2\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 15, "completion_tokens": 5}
                }),
                _ => {
                    let s = req.body.to_string();
                    if s.contains("r1-read-ok") && s.contains("r2-write-ok") {
                        saw_both_srv.store(true, Ordering::SeqCst);
                    }
                    json!({
                        "id": "chatcmpl-mr-3",
                        "object": "chat.completion",
                        "model": "a",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "Multi-round done!"},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 25, "completion_tokens": 5}
                    })
                }
            }
            .to_string();
            http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            )
        })
        .await;

        let read0 = mcp_read_calls.load(Ordering::SeqCst);
        let idem0 = mcp_idem_calls.load(Ordering::SeqCst);
        let run_id =
            admit_yolo_turn("r2-multi-round", "00000000-0000-4000-8000-000000002402", 4).await;
        let claim1 = f.next().await.expect("claim multi-round run");
        assert_eq!(claim1.run_id, run_id);

        let adapter1 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-mr".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let (stop_tx1, step1) = fresh_step(30);
        let effects1 = Arc::new(ApprovedEffects {
            policy: Arc::new(StopOnToolReview {
                inner: registry.clone(),
                target_tool: "mcp_idem",
                stop: Mutex::new(Some(stop_tx1)),
            }),
            adapter: adapter1,
        });
        let exec1 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            DynamicTurnRoutes {
                gateway: make_gateway(&model_srv, false),
                registry: registry.clone(),
                tool_ids: vec!["mcp_read", "mcp_idem"],
            },
        )
        .with_effects(effects1);
        let active1 = ActiveRun {
            claim: claim1.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec1.step(&active1, step1).await,
            StepResult::Handoff
        ));
        leases::release_lease(&mut w, &claim1.lease())
            .await
            .unwrap();
        assert_eq!(mcp_read_calls.load(Ordering::SeqCst), read0 + 1);
        assert_eq!(mcp_idem_calls.load(Ordering::SeqCst), idem0);
        assert_eq!(mr_rounds.load(Ordering::SeqCst), 2);

        // Worker 2 reclaims across rounds 1..=2, skips Round 1 read, completes Round 2 write ONCE,
        // runs Round 3 with full history, and succeeds!
        let adapter2 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-mr".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let approved2 = Arc::new(adapter2.approved_effects());
        let exec2 = Arc::new(
            TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                DynamicTurnRoutes {
                    gateway: make_gateway(&model_srv, false),
                    registry: registry.clone(),
                    tool_ids: vec!["mcp_read", "mcp_idem"],
                },
            )
            .with_effects(approved2.clone()),
        );
        let (sh_tx, sh_rx) = oneshot::channel();
        let task2 = tokio::spawn({
            let pool = worker_pool.clone();
            let settings = worker_settings();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec2,
                    Some(approved2),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "multi-round reclaim timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task2.await.unwrap();

        assert_eq!(final_state, "succeeded");
        assert_eq!(
            mcp_read_calls.load(Ordering::SeqCst),
            read0 + 1,
            "Round 1 read must not be re-executed on Worker 2"
        );
        assert_eq!(mcp_idem_calls.load(Ordering::SeqCst), idem0 + 1);
        assert_eq!(mr_rounds.load(Ordering::SeqCst), 3);
        assert!(saw_both.load(Ordering::SeqCst));
    }

    // --- (e) P2 #1: Multi-call reclaim [refused, open-zero write, trailing write] ---
    {
        let model_srv = SyntheticMcpServer::start(move |_req| {
            let body = json!({
                "id": "chatcmpl-mc-1",
                "object": "chat.completion",
                "model": "a",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [
                            {
                                "id": "call_mc_0",
                                "type": "function",
                                "function": {"name": "mcp_idem", "arguments": "{\"item\":\"c0\"}"}
                            },
                            {
                                "id": "call_mc_1",
                                "type": "function",
                                "function": {"name": "mcp_idem", "arguments": "{\"item\":\"c1\"}"}
                            },
                            {
                                "id": "call_mc_2",
                                "type": "function",
                                "function": {"name": "mcp_idem", "arguments": "{\"item\":\"c2\"}"}
                            }
                        ]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8}
            })
            .to_string();
            http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            )
        })
        .await;

        let idem0 = mcp_idem_calls.load(Ordering::SeqCst);
        let run_id =
            admit_yolo_turn("r2-multi-call", "00000000-0000-4000-8000-000000002403", 3).await;
        let claim1 = f.next().await.expect("claim multi-call run");
        assert_eq!(claim1.run_id, run_id);

        let w1_preflights = Arc::new(Mutex::new(BTreeMap::new()));
        let inner1 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-mc".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let adapter1 = Arc::new(CountingPreflightAdapter {
            inner: inner1,
            preflights: w1_preflights,
            refuse_key: Some("call_mc_0"),
        });
        let (stop_tx1, step1) = fresh_step(30);
        let effects1 = Arc::new(ApprovedEffects {
            policy: Arc::new(StopOnToolReview {
                inner: registry.clone(),
                target_tool: "mcp_idem",
                stop: Mutex::new(Some(stop_tx1)),
            }),
            adapter: adapter1,
        });
        let exec1 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            DynamicTurnRoutes {
                gateway: make_gateway(&model_srv, true),
                registry: registry.clone(),
                tool_ids: vec!["mcp_idem"],
            },
        )
        .with_effects(effects1);
        let active1 = ActiveRun {
            claim: claim1.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec1.step(&active1, step1).await,
            StepResult::Handoff
        ));
        leases::release_lease(&mut w, &claim1.lease())
            .await
            .unwrap();

        // Worker 2 has GatedCredentialProvider so call_mc_1's preflight returns Refused:
        // call_mc_0 must NOT be re-preflighted (reused from turn-result:1:0),
        // call_mc_1 fails the run immediately (trigger closes it to outcome = 'failed'),
        // and call_mc_2 is NEVER preflighted or inserted!
        let w2_preflights = Arc::new(Mutex::new(BTreeMap::new()));
        let inner2 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(GatedCredentialProvider),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let approved2 = Arc::new(ApprovedEffects {
            policy: registry.clone(),
            adapter: Arc::new(CountingPreflightAdapter {
                inner: inner2,
                preflights: w2_preflights.clone(),
                refuse_key: None,
            }),
        });
        let exec2 = Arc::new(
            TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                DynamicTurnRoutes {
                    gateway: make_gateway(&model_srv, true),
                    registry: registry.clone(),
                    tool_ids: vec!["mcp_idem"],
                },
            )
            .with_effects(approved2.clone()),
        );
        let (sh_tx, sh_rx) = oneshot::channel();
        let task2 = tokio::spawn({
            let pool = worker_pool.clone();
            let settings = worker_settings();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec2,
                    Some(approved2),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "multi-call reclaim timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task2.await.unwrap();

        assert_eq!(final_state, "failed");
        assert_eq!(mcp_idem_calls.load(Ordering::SeqCst), idem0);
        {
            let pf = w2_preflights.lock().unwrap();
            assert_eq!(
                pf.get("call_mc_0"),
                None,
                "call_mc_0 must be reused from turn-result"
            );
            assert_eq!(
                pf.get("call_mc_1"),
                Some(&1),
                "call_mc_1 must run preflight"
            );
            assert_eq!(pf.get("call_mc_2"), None, "call_mc_2 must never execute");
        }
        let ops: Vec<(String, String, Option<i32>)> = sqlx::query_as(
            "SELECT logical_key, outcome, dispatched_attempts FROM openmettle.operations
              WHERE run_id = $1::uuid ORDER BY logical_key",
        )
        .bind(&run_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(ops, vec![("call_mc_1".into(), "failed".into(), Some(0))]);
    }

    // --- (f) P1 #6: Real TurnExecutor round with constrained MCP contract & default expansion ---
    {
        let rich_rounds = Arc::new(AtomicUsize::new(0));
        let rich_rounds_srv = rich_rounds.clone();
        let model_srv = SyntheticMcpServer::start(move |_req| {
            let body = if rich_rounds_srv.fetch_add(1, Ordering::SeqCst) == 0 {
                json!({
                    "id": "chatcmpl-rich-1",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_rich_1",
                                "type": "function",
                                "function": {
                                    "name": "mcp_rich",
                                    "arguments": "{\"doc_id\":\"00000000-0000-4000-8000-000000000001\",\"mode\":\"append\"}"
                                }
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                })
            } else {
                json!({
                    "id": "chatcmpl-rich-2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Rich schema ok"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 16, "completion_tokens": 4}
                })
            }
            .to_string();
            http_response(200, &[("content-type", "application/json")], body.as_bytes())
        })
        .await;

        let run_id =
            admit_yolo_turn("r2-rich-schema", "00000000-0000-4000-8000-000000002404", 3).await;
        let adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-rich".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let approved = Arc::new(adapter.approved_effects());
        let exec = Arc::new(
            TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                DynamicTurnRoutes {
                    gateway: make_gateway(&model_srv, false),
                    registry: registry.clone(),
                    tool_ids: vec!["mcp_rich"],
                },
            )
            .with_effects(approved.clone()),
        );
        let (sh_tx, sh_rx) = oneshot::channel();
        let task = tokio::spawn({
            let pool = worker_pool.clone();
            let settings = worker_settings();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec,
                    Some(approved),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "rich schema turn timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task.await.unwrap();

        assert_eq!(final_state, "succeeded");
        let sent = rich_received_args
            .lock()
            .unwrap()
            .clone()
            .expect("mcp_rich must have been invoked");
        assert_eq!(
            sent["retries"], 2,
            "schema default must be expanded on dispatch"
        );
        assert_eq!(sent["mode"], "append");
    }

    // --- (g) P1 #5 & P2 #2: Escaped/short handle redaction + malformed handle on write, read & reconcile ---
    {
        let adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-h".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let rr = f.claim("r2-handles", "yolo").await;
        let (_st, step) = fresh_step(25);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };

        // Escaped handle
        let StepResult::ToolOutput(esc_out) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-h-esc",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"handle-escaped"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected escaped handle ToolOutput");
        };
        let esc_env: Value = serde_json::from_str(&esc_out).unwrap();
        let esc_inner: Value = serde_json::from_str(esc_env["text"].as_str().unwrap()).unwrap();
        assert!(esc_inner.get("handle").is_none());
        assert_eq!(esc_inner["note"], "ref [REDACTED] done");
        assert_eq!(esc_inner["count"], 1);
        let db_esc: Option<String> = sqlx::query_scalar(
            "SELECT downstream_handle FROM openmettle.operations WHERE run_id=$1::uuid AND logical_key='k-h-esc'",
        )
        .bind(&rr.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(db_esc.as_deref(), Some("h\"quote\\1"));

        // Short handle "1" preserves integer `"count": 1`
        let StepResult::ToolOutput(short_out) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-h-short",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"handle-short-1"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected short handle ToolOutput");
        };
        let short_env: Value = serde_json::from_str(&short_out).unwrap();
        let short_inner: Value = serde_json::from_str(short_env["text"].as_str().unwrap()).unwrap();
        assert!(short_inner.get("handle").is_none());
        assert_eq!(short_inner["count"], 1);
        assert_eq!(short_inner["label"], "id-[REDACTED]");

        // Malformed handle on read -> TerminalRefusal
        let mut reg_read_h = ExternalRegistry::new();
        let mut read_with_h = registry.get("mcp.read", "1").unwrap().clone();
        read_with_h.handle_field = Some("handle".into());
        reg_read_h.register(read_with_h).unwrap();
        let read_h_adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            Arc::new(reg_read_h),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-rh".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let StepResult::ToolOutput(read_mal) = read_h_adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-h-read-bad",
                    tool: "mcp.read",
                    version: "1",
                    raw_args: br#"{"item":"handle-bad-space"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected TerminalRefusal on malformed read handle");
        };
        assert_eq!(
            serde_json::from_str::<Value>(&read_mal).unwrap()["fault_code"],
            "terminal_refusal"
        );
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();

        // Malformed handle on write ("bad space" and 123) -> outcome_unknown + StepResult::Stopped
        for (idx, item) in ["handle-bad-space", "handle-bad-num"]
            .into_iter()
            .enumerate()
        {
            let rw = f.claim(&format!("r2-bad-h-{idx}"), "yolo").await;
            let (_st, st) = fresh_step(20);
            let act = ActiveRun {
                claim: rw.clone(),
                state: leases::ExecState::Running,
                execution_deadline: st.deadline,
            };
            let args = json!({"item": item}).to_string();
            assert!(matches!(
                adapter
                    .call(
                        &act,
                        st,
                        ExternalCall {
                            key: &format!("k-bh-{idx}"),
                            tool: "mcp.idem",
                            version: "1",
                            raw_args: args.as_bytes(),
                            approval: None,
                        },
                    )
                    .await,
                StepResult::Stopped
            ));
            let (out, h): (String, Option<String>) = sqlx::query_as(
                "SELECT outcome, downstream_handle FROM openmettle.operations WHERE run_id = $1::uuid",
            )
            .bind(&rw.run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
            assert_eq!((out.as_str(), h), ("outcome_unknown", None));
            sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
                .bind(&rw.run_id)
                .execute(&mut owner)
                .await
                .unwrap();
            leases::settle(&mut w, &rw.lease(), &LEASES, Settle::Stopped)
                .await
                .unwrap();
        }
    }

    // --- (h) P1 #4, P2 #2 (reconcile malformed handle), and P2 #3 (non-lookup outcome_unknown -> None) ---
    {
        let make_reconciling =
            async |label: &str, tool: &str, handle: Option<&str>| -> ClaimedRun {
                let rr = f.claim(label, "yolo").await;
                let prop = registry
                    .proposal(label, tool, "1", br#"{"item":"rec-r2"}"#)
                    .unwrap();
                let IntentResult::Applied(tx1) = record_fenced_intent(
                    &mut worker(&f.db).await,
                    &rr.lease(),
                    &prop,
                    None,
                    registry.as_ref(),
                    &LEASES,
                )
                .await
                .unwrap() else {
                    panic!("expected Tx1 for {label}");
                };
                assert!(matches!(
                    start_write_attempt(
                        &mut worker(&f.db).await,
                        &rr.lease(),
                        &tx1.operation_id,
                        &prop,
                        &LEASES,
                        registry.as_ref(),
                    )
                    .await
                    .unwrap(),
                    ReplayEffect::Ready(_)
                ));
                let mut cw = worker(&f.db).await;
                leases::with_lease(&mut cw, &rr.lease(), Fence::Hold, async |tx, _| {
                    durable::record_observation(
                        tx,
                        &durable::Observation {
                            scope: &rr.scope_id,
                            run: &rr.run_id,
                            operation: &tx1.operation_id,
                            key: &format!("r2-unk:{}", tx1.operation_id),
                            expected_revision: 0,
                            outcome: "outcome_unknown",
                            handle,
                            evidence: Payload {
                                format: "openmettle.unresolved-write",
                                version: 1,
                                bytes: br#"{"reason":"unknown"}"#,
                            },
                        },
                    )
                    .await
                })
                .await
                .unwrap();
                assert_eq!(
                    leases::settle(&mut cw, &rr.lease(), &LEASES, Settle::Stopped)
                        .await
                        .unwrap(),
                    leases::Settled::Reconciling { unresolved: 1 }
                );
                rr
            };

        // P1 #4: Rebind changing ONLY EndpointKey::Supported.expires_us -> None, 0 authz, 0 creds, 0 HTTP!
        {
            let rr = make_reconciling("r2-rebind-window", "mcp.idem", None).await;
            let mut rebound_reg = ExternalRegistry::new();
            let mut c = registry.get("mcp.idem", "1").unwrap().clone();
            c.idempotency.as_mut().unwrap().expires_us += 1_000_000;
            rebound_reg.register(c).unwrap();
            let checks = Arc::new(AtomicUsize::new(0));
            let lookups = Arc::new(AtomicUsize::new(0));
            let rebound_adapter = ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                Arc::new(rebound_reg),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-reb".into()),
                    lookups: lookups.clone(),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: checks.clone(),
                }),
            );
            let http0 = server.requests.load(Ordering::SeqCst);
            let op = leases::unresolved_operations(&mut w, &rr.lease(), 10)
                .await
                .unwrap()
                .pop()
                .unwrap();
            let (_st, step) = fresh_step(15);
            let active = ActiveRun {
                claim: rr.clone(),
                state: leases::ExecState::Reconciling,
                execution_deadline: step.deadline,
            };
            assert!(
                rebound_adapter
                    .reconcile_operation(&active, &op, step)
                    .await
                    .is_none()
            );
            assert_eq!(checks.load(Ordering::SeqCst), 0);
            assert_eq!(lookups.load(Ordering::SeqCst), 0);
            assert_eq!(server.requests.load(Ordering::SeqCst), http0);
            leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
                .await
                .unwrap();
        }

        // P2 #2: Reconcile response with malformed handle ("bad space") -> returns None!
        {
            let rr =
                make_reconciling("r2-rec-bad-h", "mcp.lookup_handle", Some("h-bad-remote")).await;
            let adapter = ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-rec".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            );
            let op = leases::unresolved_operations(&mut w, &rr.lease(), 10)
                .await
                .unwrap()
                .pop()
                .unwrap();
            let (_st, step) = fresh_step(15);
            let active = ActiveRun {
                claim: rr.clone(),
                state: leases::ExecState::Reconciling,
                execution_deadline: step.deadline,
            };
            assert!(
                adapter
                    .reconcile_operation(&active, &op, step)
                    .await
                    .is_none()
            );
            leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
                .await
                .unwrap();
        }

        // P2 #3: Non-lookup already at outcome_unknown (revision = 1) -> returns None (no collision)!
        {
            let rr = make_reconciling("r2-nonrep-unk", "mcp.nonrep", None).await;
            let adapter = ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-nr".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            );
            let op = leases::unresolved_operations(&mut w, &rr.lease(), 10)
                .await
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(op.outcome, "outcome_unknown");
            let (_st, step) = fresh_step(15);
            let active = ActiveRun {
                claim: rr.clone(),
                state: leases::ExecState::Reconciling,
                execution_deadline: step.deadline,
            };
            assert!(
                adapter
                    .reconcile_operation(&active, &op, step)
                    .await
                    .is_none()
            );
            leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
                .await
                .unwrap();
        }
    }

    // --- (i) P2 #4: Slow credential provider bounded by call_timeout (1s) under 30s lease ---
    {
        struct SlowCredentials(Duration);
        impl McpCredentialProvider for SlowCredentials {
            fn resolve<'a>(
                &'a self,
                _request: CredentialRequest<'a>,
            ) -> Pin<Box<dyn Future<Output = CredentialOutcome> + Send + 'a>> {
                let delay = self.0;
                Box::pin(async move {
                    tokio::time::sleep(delay).await;
                    CredentialOutcome::Ready(McpCredential::bearer("too-late"))
                })
            }
        }
        let slow_adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports,
            Arc::new(SlowCredentials(Duration::from_secs(5))),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let rr = f.claim("r2-slow-cred", "yolo").await;
        let (_st, step) = fresh_step(30);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };
        let reqs0 = server.requests.load(Ordering::SeqCst);
        let t0 = Instant::now();
        let StepResult::ToolOutput(out) = slow_adapter
            .call(
                &active,
                step,
                ExternalCall {
                    key: "k-slow-cred",
                    tool: "mcp.idem_short",
                    version: "1",
                    raw_args: br#"{"item":"slow"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected Transient ToolOutput on slow credential provider");
        };
        let elapsed = t0.elapsed();
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap()["fault_code"],
            "transient"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "credential lookup must abort at 1s call_timeout, took {elapsed:?}"
        );
        assert_eq!(server.requests.load(Ordering::SeqCst), reqs0);
        let ops: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid",
        )
        .bind(&rr.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(ops, 0);
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }
}

// ============================================================================================
// 8. Review #3 Regressions: Existing-Row Gate Re-Auth + Tx2 Defense, Proposal Injection Guard,
//    Object-Key & Top-Level JSON String Handle Redaction (Inline + Spilled), Transient Handoff
//    Recovery + InvalidArguments Round Persistence, DeclaredTool Ownership/Versioning,
//    Post-Continuation tool_prompt_bound, and Entry-Bounded Send Budget
// ============================================================================================

#[tokio::test]
#[ignore = "isolated PostgreSQL 18.1"]
async fn review3_gate_reauth_proposal_guard_key_redaction_handoff_declared_tools_and_budget_regressions()
 {
    use openmettle_core::{
        authz::{
            branches::{
                self, Conversation, Operation, Part, UserInput,
                snapshot::{Intent as TurnIntent, Snapshots},
            },
            store::{AuditContext, WriteOutcome},
        },
        model_config::{
            Catalog, ConfigSnapshot, Effective, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection,
        },
        provider_http::inference::{
            self, Call, Gateway, Protocol, Qualification, Request, Timeouts, Tool,
        },
        runs::RunInput,
        worker::turns::{Route, TurnExecutor, TurnRoutes},
    };

    let f = Fixture::new().await;
    f.grant(true).await;
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let mut w = worker(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;

    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("mcp-r3-spill"));
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_instance SET personal_limit_bytes=2000000, instance_budget_bytes=2000000",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    // Extended registry with optional non-defaulted field, defaulted field, multi-version tool,
    // and tight-timeout contract.
    let mut reg_builder = test_registry(FUTURE * 1000);
    let mut read_turn = reg_builder.get("mcp.read", "1").unwrap().clone();
    read_turn.tool_id = "mcp_read".into();
    read_turn.remote_name = "mcp_read".into();
    reg_builder.register(read_turn).unwrap();

    let mut idem_turn = reg_builder.get("mcp.idem", "1").unwrap().clone();
    idem_turn.tool_id = "mcp_idem".into();
    idem_turn.remote_name = "mcp_idem".into();
    reg_builder.register(idem_turn).unwrap();

    let mut opt_contract = reg_builder.get("mcp.idem", "1").unwrap().clone();
    opt_contract.tool_id = "mcp_opt".into();
    opt_contract.remote_name = "mcp_opt".into();
    opt_contract.input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["item"],
        "properties": {
            "item": {"type": "string", "minLength": 1, "maxLength": 64},
            "note": {"type": "string", "minLength": 1, "maxLength": 64},
            "retries": {"type": "integer", "minimum": 0, "maximum": 3, "default": 2}
        }
    });
    reg_builder.register(opt_contract).unwrap();

    let mut ver_v1 = reg_builder.get("mcp.read", "1").unwrap().clone();
    ver_v1.tool_id = "mcp_ver".into();
    ver_v1.remote_name = "mcp_ver".into();
    ver_v1.version = "1".into();
    ver_v1.connection_id = "synth-mcp".into();
    reg_builder.register(ver_v1).unwrap();

    let mut ver_v2 = reg_builder.get("mcp.read", "1").unwrap().clone();
    ver_v2.tool_id = "mcp_ver".into();
    ver_v2.remote_name = "mcp_ver".into();
    ver_v2.version = "2".into();
    ver_v2.connection_id = "broken-conn".into();
    reg_builder.register(ver_v2).unwrap();

    let mut tight_to = reg_builder.get("mcp.idem", "1").unwrap().clone();
    tight_to.tool_id = "mcp.tight_to".into();
    tight_to.remote_name = "mcp.tight_to".into();
    tight_to.call_timeout = Duration::from_millis(150);
    reg_builder.register(tight_to).unwrap();

    let registry = Arc::new(reg_builder);

    // --- (a) P1 #1: Existing attempts=0 re-authorization and Tx2 start_write_attempt enforce gate ---
    {
        let rr = f.claim("r3-existing-gate", "yolo").await;
        let prop = registry
            .proposal("k-r3-gate", "mcp.idem", "1", br#"{"item":"gate-reauth"}"#)
            .unwrap();
        let IntentResult::Applied(tx1) =
            record_fenced_intent(&mut w, &rr.lease(), &prop, None, registry.as_ref(), &LEASES)
                .await
                .unwrap()
        else {
            panic!("expected Tx1 Applied");
        };

        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = false",
        )
        .execute(&mut owner)
        .await
        .unwrap();

        let reauth_err =
            record_fenced_intent(&mut w, &rr.lease(), &prop, None, registry.as_ref(), &LEASES)
                .await
                .err()
                .expect(
                    "re-authorizing existing attempts=0 write must fail closed when gate is off",
                );
        assert!(matches!(
            reauth_err,
            leases::LeaseError::Store(StoreError::Denied(_))
        ));

        let tx2_err = start_write_attempt(
            &mut w,
            &rr.lease(),
            &tx1.operation_id,
            &prop,
            &LEASES,
            registry.as_ref(),
        )
        .await
        .err()
        .expect("Tx2 start_write_attempt must fail closed when gate is off");
        assert!(matches!(
            tx2_err,
            leases::LeaseError::Store(StoreError::Denied(_))
        ));

        // Run stays running with cancel_reason IS NULL (not misclassified as Revoked),
        // and operation stays at outcome='intent', dispatched_attempts=0.
        let (run_state, cancel_reason): (String, Option<String>) =
            sqlx::query_as("SELECT state, cancel_reason FROM openmettle.runs WHERE id = $1::uuid")
                .bind(&rr.run_id)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        assert_eq!((run_state.as_str(), cancel_reason), ("running", None));
        let (op_out, op_att): (String, Option<i32>) = sqlx::query_as(
            "SELECT outcome, dispatched_attempts FROM openmettle.operations WHERE id = $1::uuid",
        )
        .bind(&tx1.operation_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((op_out.as_str(), op_att), ("intent", Some(0)));

        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = true",
        )
        .execute(&mut owner)
        .await
        .unwrap();
        leases::settle(
            &mut w,
            &rr.lease(),
            &LEASES,
            Settle::Failed(leases::FailReason::StepFailed),
        )
        .await
        .unwrap();
    }

    // Shared synthetic TLS MCP server for sections (b)-(h).
    let list_tools_json: Value = Value::Array(
        [
            "mcp.read",
            "mcp.idem",
            "mcp.lookup_handle",
            "mcp.lookup_det",
            "mcp.nonrep",
            "mcp_read",
            "mcp_idem",
            "mcp_opt",
            "mcp_ver",
            "mcp.tight_to",
        ]
        .into_iter()
        .map(|name| {
            let c = registry.get(name, "1").unwrap();
            json!({"name": c.remote_name, "inputSchema": c.input_schema})
        })
        .collect(),
    );
    let transient_503_once = Arc::new(AtomicBool::new(false));
    let drift_list = Arc::new(AtomicBool::new(false));
    let read_calls = Arc::new(AtomicUsize::new(0));
    let idem_calls = Arc::new(AtomicUsize::new(0));
    let opt_calls = Arc::new(AtomicUsize::new(0));
    let opt_args_seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let ver_calls = Arc::new(AtomicUsize::new(0));
    let tight_calls = Arc::new(AtomicUsize::new(0));
    let pad_big = "Q".repeat(INLINE_BYTES + 4096);

    let transient_503_srv = transient_503_once.clone();
    let drift_list_srv = drift_list.clone();
    let read_calls_srv = read_calls.clone();
    let idem_calls_srv = idem_calls.clone();
    let opt_calls_srv = opt_calls.clone();
    let opt_args_srv = opt_args_seen.clone();
    let ver_calls_srv = ver_calls.clone();
    let tight_calls_srv = tight_calls.clone();
    let pad_big_srv = pad_big.clone();

    let server = SyntheticMcpServer::start(move |req| {
        let id = req.body["id"].as_str().unwrap_or("0");
        let method = req.body["method"].as_str().unwrap_or("");
        if method == "tools/list" {
            if transient_503_srv.swap(false, Ordering::SeqCst) {
                return http_response(503, &[("retry-after", "0")], b"temp-unavailable");
            }
            if drift_list_srv.load(Ordering::SeqCst) {
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [{
                            "name": "mcp_read",
                            "inputSchema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["item"],
                                "properties": {"item": {"type": "string", "minLength": 1, "maxLength": 9999}}
                            }
                        }]
                    }
                })
                .to_string();
                return http_response(200, &[("content-type", "application/json")], body.as_bytes());
            }
            let body = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": list_tools_json}})
                .to_string();
            return http_response(200, &[("content-type", "application/json")], body.as_bytes());
        }
        let tool = req.body["params"]["name"].as_str().unwrap_or("");
        let args = &req.body["params"]["arguments"];
        match tool {
            "mcp_read" => {
                read_calls_srv.fetch_add(1, Ordering::SeqCst);
                jsonrpc_ok(id, "r3-read-ok", None)
            }
            "mcp_idem" => {
                idem_calls_srv.fetch_add(1, Ordering::SeqCst);
                jsonrpc_ok(id, "r3-write-ok", Some(json!({"handle": "h-r3-idem"})))
            }
            "mcp_opt" => {
                opt_calls_srv.fetch_add(1, Ordering::SeqCst);
                opt_args_srv.lock().unwrap().push(args.clone());
                jsonrpc_ok(id, "r3-opt-ok", Some(json!({"handle": "h-r3-opt"})))
            }
            "mcp_ver" => {
                ver_calls_srv.fetch_add(1, Ordering::SeqCst);
                jsonrpc_ok(id, "r3-ver-v1-ok", None)
            }
            "mcp.tight_to" => {
                tight_calls_srv.fetch_add(1, Ordering::SeqCst);
                jsonrpc_ok(id, "never-reached", None)
            }
            _ => {
                let item = args["item"].as_str().unwrap_or("");
                match item {
                    "key-redact-inline" => {
                        let body = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "structuredContent": {
                                    "handle": "h-key-9",
                                    "[REDACTED]": "keep",
                                    "h-key-9": {"nested-h-key-9": "v-h-key-9"}
                                }
                            }
                        })
                        .to_string();
                        http_response(200, &[("content-type", "application/json")], body.as_bytes())
                    }
                    "key-redact-spilled" => {
                        let body = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "structuredContent": {
                                    "handle": "h-key-9",
                                    "[REDACTED]": "keep",
                                    "h-key-9": {"nested-h-key-9": "v-h-key-9"},
                                    "pad": pad_big_srv
                                }
                            }
                        })
                        .to_string();
                        http_response(200, &[("content-type", "application/json")], body.as_bytes())
                    }
                    "top-str-inline" => {
                        let escaped = "h\"quote\\1";
                        jsonrpc_ok(
                            id,
                            &json!(format!("prefix {escaped} suffix")).to_string(),
                            Some(json!({"handle": escaped})),
                        )
                    }
                    "top-str-spilled" => {
                        let escaped = "h\"quote\\1";
                        jsonrpc_ok(
                            id,
                            &json!(format!("prefix {escaped} {pad_big_srv} suffix")).to_string(),
                            Some(json!({"handle": escaped})),
                        )
                    }
                    _ => jsonrpc_ok(id, "ok", None),
                }
            }
        }
    })
    .await;

    let mut transports = BTreeMap::new();
    transports.insert("synth-mcp".to_owned(), server.transport());

    let worker_settings = || {
        openmettle_core::WorkerSettings::parse(Duration::from_secs(1), |k| {
            Ok(Some(
                match k {
                    "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                    "LEASE_MS" => "30000",
                    "EXECUTION_TIMEOUT_MS" => "180000",
                    "POLL_MS" => "100",
                    "SWEEP_MS" => "1000",
                    _ => return Ok(None),
                }
                .into(),
            ))
        })
        .unwrap()
    };

    // --- (c) P1 #3: Object-key + top-level JSON string handle redaction (inline + spilled) ---
    {
        let adapter = Arc::new(
            ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-r3-h".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            )
            .with_artifacts(store.clone()),
        );
        let scoped = ScopedAdapter::new(worker_pool.clone(), store.clone(), LEASES);
        let rr = f.claim("r3-handle-keys", "yolo").await;
        let (_st, step) = fresh_step(25);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };

        let read_all_spilled = async |art_id: &str, rev_id: &str, prefix: &str| -> String {
            let mut full = String::new();
            let mut offset = 0u64;
            let mut page = 0usize;
            loop {
                let args = json!({
                    "artifact_id": art_id,
                    "revision_id": rev_id,
                    "offset": offset,
                    "max_bytes": INLINE_BYTES
                })
                .to_string();
                let StepResult::ToolOutput(chunk_json) = scoped
                    .call(
                        &active,
                        step.clone(),
                        &format!("{prefix}-{page}"),
                        mcp::READ_RANGE,
                        "1",
                        args.as_bytes(),
                    )
                    .await
                else {
                    panic!("expected read_range page");
                };
                let pv: Value = serde_json::from_str(&chunk_json).unwrap();
                full.push_str(pv["text"].as_str().unwrap());
                offset = pv["next_offset"].as_u64().unwrap();
                if pv["eof"] == true {
                    break;
                }
                page += 1;
            }
            full
        };

        // 1. Inline object-key redaction with collision
        let StepResult::ToolOutput(k_inline) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r3-ki",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"key-redact-inline"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected inline key redaction ToolOutput");
        };
        assert!(!k_inline.contains("h-key-9"));
        let ki_val: Value = serde_json::from_str(
            serde_json::from_str::<Value>(&k_inline).unwrap()["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ki_val["[REDACTED]"], "keep");
        assert_eq!(ki_val["[REDACTED]#2"]["nested-[REDACTED]"], "v-[REDACTED]");

        // 2. Spilled object-key redaction with collision
        let StepResult::ToolOutput(k_spill) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r3-ks",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"key-redact-spilled"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected spilled key redaction ToolOutput");
        };
        assert!(!k_spill.contains("h-key-9"));
        let ks_env: Value = serde_json::from_str(&k_spill).unwrap();
        assert_eq!(ks_env["storage"], "spilled");
        let ks_full = read_all_spilled(
            ks_env["provenance"]["artifact_id"].as_str().unwrap(),
            ks_env["provenance"]["revision_id"].as_str().unwrap(),
            "r3-ks",
        )
        .await;
        assert!(!ks_full.contains("h-key-9"));
        let ks_parsed: Value = serde_json::from_str(&ks_full).unwrap();
        assert_eq!(ks_parsed["[REDACTED]"], "keep");
        assert_eq!(
            ks_parsed["[REDACTED]#2"]["nested-[REDACTED]"],
            "v-[REDACTED]"
        );

        // 3. Inline top-level JSON string with JSON-escaped handle
        let StepResult::ToolOutput(s_inline) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r3-si",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"top-str-inline"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected inline top-str ToolOutput");
        };
        assert!(!s_inline.contains("quote"));
        let si_inner: Value = serde_json::from_str(
            serde_json::from_str::<Value>(&s_inline).unwrap()["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(si_inner, json!("prefix [REDACTED] suffix"));

        // 4. Spilled top-level JSON string with JSON-escaped handle
        let StepResult::ToolOutput(s_spill) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r3-ss",
                    tool: "mcp.idem",
                    version: "1",
                    raw_args: br#"{"item":"top-str-spilled"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected spilled top-str ToolOutput");
        };
        assert!(!s_spill.contains("quote"));
        let ss_env: Value = serde_json::from_str(&s_spill).unwrap();
        assert_eq!(ss_env["storage"], "spilled");
        let ss_full = read_all_spilled(
            ss_env["provenance"]["artifact_id"].as_str().unwrap(),
            ss_env["provenance"]["revision_id"].as_str().unwrap(),
            "r3-ss",
        )
        .await;
        assert!(!ss_full.contains("quote"));
        assert!(!ss_full.contains("h\"quote\\1"));
        assert!(ss_full.contains("[REDACTED]"));

        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    // Shared TurnExecutor helpers for sections (b), (d), (e), (f), (g).
    let catalog_bytes = include_bytes!("../fixtures/conversation-catalog-v1.json");
    let catalog = Arc::new(Catalog::load(catalog_bytes).unwrap());
    let selection: Selection = serde_json::from_value(
        json!({"model": "a", "layer": {"controls": {"output_reserve": 256}}}),
    )
    .unwrap();
    let snapshot = ConfigSnapshot {
        effective: catalog
            .resolve(&Selection::default(), &selection, None, |_, _| true)
            .unwrap(),
        required_capabilities: catalog.model("a").unwrap().required_capabilities.clone(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: catalog.model("a").unwrap().cost_bound,
    };
    let make_gateway = |srv: &SyntheticMcpServer, parallel: bool| -> Arc<Gateway> {
        let prefix = if srv.ip.is_ipv4() { 32 } else { 128 };
        let range = format!("{}/{prefix}", srv.ip);
        Arc::new(
            Gateway::new(
                &format!("https://{}:{}/v1/chat/completions", srv.host, srv.port),
                Trust::Bundle(&srv.ca_pem),
                &[&range],
                Qualification {
                    model: "a".into(),
                    pin: catalog.model("a").unwrap().pin.clone(),
                    protocol: Protocol::Chat,
                    json: true,
                    sse: false,
                    functions: Some(inference::SchemaSubset::Flat),
                    images: false,
                    parallel,
                    usage: true,
                    tool_separator_whitespace: false,
                },
                Timeouts {
                    setup: Duration::from_secs(5),
                    idle: Duration::from_secs(15),
                    overall: Duration::from_secs(30),
                },
            )
            .unwrap(),
        )
    };
    let admit_yolo_turn = async |key: &'static str, msg_id: &'static str, rounds: i64| -> String {
        let mut ac = api(&f.db).await;
        let audit_ctx = |k: &'static str| AuditContext {
            actor_user_id: &f.actor.user,
            actor_approval_id: &f.actor.approval,
            now_ms: f.user.context().observed_ms(),
            request_key: k,
            reason: "review3 turn test",
        };
        let conv = match branches::create_conversation(&mut ac, &audit_ctx(key), &f.scope)
            .await
            .unwrap()
        {
            WriteOutcome::Applied { target_id } | WriteOutcome::Replayed { target_id } => target_id,
        };
        let chat = Conversation {
            scope: &f.scope,
            id: &conv.conversation_id,
        };
        let parts = [Part::Text("run review3 turn".into())];
        let turn_op = Operation::Append(UserInput {
            id: msg_id,
            parts: &parts,
        });
        let turn_intent = TurnIntent {
            source_branch_id: &conv.branch_id,
            expected_head_message_id: None,
            operation: turn_op,
            selection: &selection,
            requested_rounds: Some(rounds),
        };
        let actor_principal = super::super::authz_store::principal(&f.db, &f.actor).await;
        let mut tx = WriteTransaction::begin(&mut ac).await.unwrap();
        let msg_key = Box::leak(format!("{key}-msg").into_boxed_str());
        branches::prepare_turn(
            &mut tx,
            &audit_ctx(msg_key),
            chat,
            &conv.branch_id,
            None,
            turn_op,
        )
        .await
        .unwrap();
        let history = branches::history(
            tx.connection().unwrap(),
            &actor_principal,
            chat,
            &conv.branch_id,
            f.user.context().observed_ms(),
        )
        .await
        .unwrap()
        .unwrap();
        let pins = Snapshots::encode(&turn_intent, &history, &catalog, &snapshot).unwrap();
        let mut snap_val: Value = serde_json::from_slice(&pins.config).unwrap();
        snap_val["execution_mode"] = json!("yolo");
        let snapshot_bytes = serde_json::to_vec(&snap_val).unwrap();
        let admission = queue::admit_run_with_mode(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &f.scope,
                    actor: &f.actor.user,
                    conversation: &conv.conversation_id,
                    branch: &conv.branch_id,
                    message: msg_id,
                    key,
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: &pins.input,
                    config: &snapshot_bytes,
                },
                actor_approval_id: &f.actor.approval,
                capabilities: &[],
                requested_rounds: Some(rounds),
                now_ms: f.user.context().observed_ms(),
                cost_qualified: None,
            },
            &LIMITS,
            &f.user,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let Admission::Admitted { run_id, .. } = admission else {
            panic!("expected admitted turn run for {key}");
        };
        run_id
    };

    // --- (b) P1 #2: Route-injected optional non-defaulted field refused; genuine schema default allowed ---
    {
        struct InjectingOptRoutes {
            gateway: Arc<Gateway>,
            registry: Arc<ExternalRegistry>,
            inject_for_call_id: &'static str,
        }
        impl TurnRoutes for InjectingOptRoutes {
            async fn route(
                &self,
                _: &ClaimedRun,
                _: &str,
                _: &Effective,
            ) -> Result<Route, inference::Error> {
                Ok(Route::metered(
                    self.gateway.clone(),
                    "00000000-0000-4000-8000-000000000091".into(),
                    false,
                ))
            }
            fn declared_tools(&self, _: &ClaimedRun) -> Vec<DeclaredTool> {
                vec![self.registry.get("mcp_opt", "1").unwrap().declared_tool()]
            }
            fn tool_prompt_bound(&self, _: &Effective, request: &Request) -> Option<u64> {
                (request.history.len() <= 32).then_some(4096)
            }
            fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
                let mut args = call.arguments.clone();
                if call.id == self.inject_for_call_id
                    && let Some(obj) = args.as_object_mut()
                {
                    obj.insert("note".into(), json!("route-injected"));
                }
                self.registry
                    .proposal(&call.id, &call.name, "1", &serde_json::to_vec(&args).ok()?)
                    .ok()
            }
        }

        let rounds = Arc::new(AtomicUsize::new(0));
        let rounds_srv = rounds.clone();
        let saw_refusal = Arc::new(AtomicBool::new(false));
        let saw_refusal_srv = saw_refusal.clone();
        let model_srv = SyntheticMcpServer::start(move |req| {
            let r = rounds_srv.fetch_add(1, Ordering::SeqCst);
            let body = if r == 0 {
                json!({
                    "id": "chatcmpl-opt-1",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [
                                {
                                    "id": "call_opt_injected",
                                    "type": "function",
                                    "function": {"name": "mcp_opt", "arguments": "{\"item\":\"bad\"}"}
                                },
                                {
                                    "id": "call_opt_default",
                                    "type": "function",
                                    "function": {"name": "mcp_opt", "arguments": "{\"item\":\"good\"}"}
                                }
                            ]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 6}
                })
            } else {
                if req.body.to_string().contains("terminal_refusal") {
                    saw_refusal_srv.store(true, Ordering::SeqCst);
                }
                json!({
                    "id": "chatcmpl-opt-2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Done opt check"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 18, "completion_tokens": 4}
                })
            }
            .to_string();
            http_response(200, &[("content-type", "application/json")], body.as_bytes())
        })
        .await;

        let opt0 = opt_calls.load(Ordering::SeqCst);
        let run_id =
            admit_yolo_turn("r3-opt-inject", "00000000-0000-4000-8000-000000003401", 3).await;
        let adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-opt".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let approved = Arc::new(adapter.approved_effects());
        let exec = Arc::new(
            TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                InjectingOptRoutes {
                    gateway: make_gateway(&model_srv, true),
                    registry: registry.clone(),
                    inject_for_call_id: "call_opt_injected",
                },
            )
            .with_effects(approved.clone()),
        );
        let (sh_tx, sh_rx) = oneshot::channel();
        let task = tokio::spawn({
            let pool = worker_pool.clone();
            let settings = worker_settings();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec,
                    Some(approved),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(Instant::now() < deadline, "opt inject test timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task.await.unwrap();

        assert_eq!(final_state, "succeeded");
        assert!(saw_refusal.load(Ordering::SeqCst));
        assert_eq!(opt_calls.load(Ordering::SeqCst), opt0 + 1);
        let ops: Vec<String> = sqlx::query_scalar(
            "SELECT logical_key FROM openmettle.operations WHERE run_id = $1::uuid ORDER BY logical_key",
        )
        .bind(&run_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(ops, vec!["call_opt_default"]);
        let seen = opt_args_seen.lock().unwrap();
        assert_eq!(seen.last().unwrap()["item"], "good");
        assert_eq!(seen.last().unwrap()["retries"], 2);
        assert!(seen.last().unwrap().get("note").is_none());
    }

    // --- (d) P1 #4: Round 1 tool succeeds -> Round 2 filter_turn_tools transient 503 Handoff -> Worker 2 succeeds ---
    {
        struct SimpleDeclaredRoutes {
            gateway: Arc<Gateway>,
            registry: Arc<ExternalRegistry>,
            declared: Vec<DeclaredTool>,
            bound_override: Option<u64>,
        }
        impl TurnRoutes for SimpleDeclaredRoutes {
            async fn route(
                &self,
                _: &ClaimedRun,
                _: &str,
                _: &Effective,
            ) -> Result<Route, inference::Error> {
                Ok(Route::metered(
                    self.gateway.clone(),
                    "00000000-0000-4000-8000-000000000091".into(),
                    false,
                ))
            }
            fn declared_tools(&self, _: &ClaimedRun) -> Vec<DeclaredTool> {
                self.declared.clone()
            }
            fn tool_prompt_bound(&self, _: &Effective, request: &Request) -> Option<u64> {
                if let Some(b) = self.bound_override
                    && request.tools.is_none()
                {
                    return Some(b);
                }
                (request.history.len() <= 32).then_some(4096)
            }
            fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
                self.registry
                    .proposal(
                        &call.id,
                        &call.name,
                        "1",
                        &serde_json::to_vec(&call.arguments).ok()?,
                    )
                    .ok()
            }
        }

        let rounds = Arc::new(AtomicUsize::new(0));
        let rounds_srv = rounds.clone();
        let trigger_503 = transient_503_once.clone();
        let saw_r1_result = Arc::new(AtomicBool::new(false));
        let saw_r1_srv = saw_r1_result.clone();
        let model_srv = SyntheticMcpServer::start(move |req| {
            let r = rounds_srv.fetch_add(1, Ordering::SeqCst);
            let body = if r == 0 {
                // Arm a one-shot 503 on tools/list so Round 2's filter_turn_tools hands off!
                trigger_503.store(true, Ordering::SeqCst);
                json!({
                    "id": "chatcmpl-ho-1",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_ho_1",
                                "type": "function",
                                "function": {"name": "mcp_read", "arguments": "{\"item\":\"ho\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                })
            } else {
                if req.body.to_string().contains("r3-read-ok") {
                    saw_r1_srv.store(true, Ordering::SeqCst);
                }
                json!({
                    "id": "chatcmpl-ho-2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Handoff recovered!"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 18, "completion_tokens": 4}
                })
            }
            .to_string();
            http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            )
        })
        .await;

        let read0 = read_calls.load(Ordering::SeqCst);
        let run_id =
            admit_yolo_turn("r3-transient-ho", "00000000-0000-4000-8000-000000003402", 3).await;
        let claim1 = f.next().await.expect("claim transient handoff run");
        assert_eq!(claim1.run_id, run_id);

        struct HandoffSecondFilterAdapter {
            inner: Arc<ExternalMcpAdapter>,
            filter_calls: Arc<AtomicUsize>,
        }
        impl ApprovedAdapter for HandoffSecondFilterAdapter {
            fn preflight<'a>(
                &'a self,
                run: &'a ActiveRun,
                proposal: &'a Proposal,
                step: &'a StepContext,
            ) -> Pin<Box<dyn Future<Output = Result<(), worker::PreflightError>> + Send + 'a>>
            {
                self.inner.preflight(run, proposal, step)
            }
            fn verify_turn_call_proposal(
                &self,
                call: &Call,
                proposal: &Proposal,
                expected_external_version: Option<&str>,
            ) -> bool {
                self.inner
                    .verify_turn_call_proposal(call, proposal, expected_external_version)
            }
            fn filter_turn_tools<'a>(
                &'a self,
                run: &'a ActiveRun,
                tools: Vec<DeclaredTool>,
                step: &'a StepContext,
            ) -> Pin<Box<dyn Future<Output = Result<Vec<Tool>, StepResult>> + Send + 'a>>
            {
                if self.filter_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    return Box::pin(async { Err(StepResult::Handoff) });
                }
                self.inner.filter_turn_tools(run, tools, step)
            }
            fn send<'a>(
                &'a self,
                run: &'a ActiveRun,
                operation_id: String,
                request: Vec<u8>,
                step: StepContext,
            ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
                self.inner.send(run, operation_id, request, step)
            }
        }

        transient_503_once.store(false, Ordering::SeqCst);
        let filter_calls = Arc::new(AtomicUsize::new(0));
        let adapter_ho1 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-ho".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let effects_ho1 = Arc::new(ApprovedEffects {
            policy: registry.clone(),
            adapter: Arc::new(HandoffSecondFilterAdapter {
                inner: adapter_ho1,
                filter_calls,
            }),
        });
        let exec_ho1 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            SimpleDeclaredRoutes {
                gateway: make_gateway(&model_srv, false),
                registry: registry.clone(),
                declared: vec![registry.get("mcp_read", "1").unwrap().declared_tool()],
                bound_override: None,
            },
        )
        .with_effects(effects_ho1);
        let (_st, step_ho1) = fresh_step(30);
        let active_ho1 = ActiveRun {
            claim: claim1.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec_ho1.step(&active_ho1, step_ho1).await,
            StepResult::Handoff
        ));
        leases::release_lease(&mut w, &claim1.lease())
            .await
            .unwrap();
        assert_eq!(read_calls.load(Ordering::SeqCst), read0 + 1);
        assert_eq!(rounds.load(Ordering::SeqCst), 1);

        // Worker 2 reclaims, reconstructs Round 1 via turn-handoff:1, skips re-calling mcp_read,
        // completes Round 2, and settles succeeded!
        transient_503_once.store(false, Ordering::SeqCst);
        let adapter_ho2 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-ho".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let approved_ho2 = Arc::new(adapter_ho2.approved_effects());
        let exec_ho2 = Arc::new(
            TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                SimpleDeclaredRoutes {
                    gateway: make_gateway(&model_srv, false),
                    registry: registry.clone(),
                    declared: vec![registry.get("mcp_read", "1").unwrap().declared_tool()],
                    bound_override: None,
                },
            )
            .with_effects(approved_ho2.clone()),
        );
        let (sh_tx, sh_rx) = oneshot::channel();
        let task2 = tokio::spawn({
            let pool = worker_pool.clone();
            let settings = worker_settings();
            async move {
                worker::run_with_approvals(
                    &pool,
                    None,
                    settings,
                    exec_ho2,
                    Some(approved_ho2),
                    async move {
                        let _ = sh_rx.await;
                    },
                    Duration::from_secs(4),
                )
                .await;
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let final_state = loop {
            let s: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                break s;
            }
            assert!(
                Instant::now() < deadline,
                "transient handoff resume timed out"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let _ = sh_tx.send(());
        task2.await.unwrap();

        assert_eq!(final_state, "succeeded");
        assert_eq!(
            read_calls.load(Ordering::SeqCst),
            read0 + 1,
            "Round 1 read must not re-run on Worker 2"
        );
        assert_eq!(rounds.load(Ordering::SeqCst), 2);
        assert!(saw_r1_result.load(Ordering::SeqCst));

        // --- (e) P2 #1: Round 1 InvalidArguments -> Round 2 write handoff at attempts=0 -> Worker 2 succeeds ---
        {
            struct StopOnIdemReview {
                inner: Arc<ExternalRegistry>,
                stop: Mutex<Option<tokio::sync::watch::Sender<Option<Stop>>>>,
            }
            impl approvals::EffectPolicy for StopOnIdemReview {
                fn review(
                    &self,
                    scope: &str,
                    run: &str,
                    p: &Proposal,
                ) -> Result<Option<Review>, StoreError> {
                    if p.tool == "mcp_idem"
                        && let Some(tx) = self.stop.lock().unwrap().take()
                    {
                        let _ = tx.send(Some(Stop::Shutdown));
                    }
                    self.inner.review(scope, run, p)
                }
                fn requires_two_phase_writes(&self) -> bool {
                    self.inner.requires_two_phase_writes()
                }
            }

            let inv_rounds = Arc::new(AtomicUsize::new(0));
            let inv_rounds_srv = inv_rounds.clone();
            let saw_rejected_and_ok = Arc::new(AtomicBool::new(false));
            let saw_rej_srv = saw_rejected_and_ok.clone();
            let inv_model_srv = SyntheticMcpServer::start(move |req| {
                let r = inv_rounds_srv.fetch_add(1, Ordering::SeqCst);
                let body = match r {
                    0 => json!({
                        "id": "chatcmpl-inv-1",
                        "object": "chat.completion",
                        "model": "a",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": null,
                                "tool_calls": [{
                                    "id": "call_inv_1",
                                    "type": "function",
                                    "function": {"name": "mcp_idem", "arguments": "{\"bogus\":1}"}
                                }]
                            },
                            "finish_reason": "tool_calls"
                        }],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                    }),
                    1 => json!({
                        "id": "chatcmpl-inv-2",
                        "object": "chat.completion",
                        "model": "a",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": null,
                                "tool_calls": [{
                                    "id": "call_inv_2",
                                    "type": "function",
                                    "function": {"name": "mcp_idem", "arguments": "{\"item\":\"valid\"}"}
                                }]
                            },
                            "finish_reason": "tool_calls"
                        }],
                        "usage": {"prompt_tokens": 15, "completion_tokens": 5}
                    }),
                    _ => {
                        let s = req.body.to_string();
                        if s.contains("invalid_tool_arguments") && s.contains("r3-write-ok") {
                            saw_rej_srv.store(true, Ordering::SeqCst);
                        }
                        json!({
                            "id": "chatcmpl-inv-3",
                            "object": "chat.completion",
                            "model": "a",
                            "choices": [{
                                "index": 0,
                                "message": {"role": "assistant", "content": "Rejected+write recovered!"},
                                "finish_reason": "stop"
                            }],
                            "usage": {"prompt_tokens": 22, "completion_tokens": 5}
                        })
                    }
                }
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            })
            .await;

            let idem0 = idem_calls.load(Ordering::SeqCst);
            let run_id =
                admit_yolo_turn("r3-inv-reclaim", "00000000-0000-4000-8000-000000003403", 4).await;
            let claim1 = f.next().await.expect("claim inv reclaim run");
            assert_eq!(claim1.run_id, run_id);

            let adapter1 = Arc::new(ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-inv".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            ));
            let (stop_tx1, step1) = fresh_step(30);
            let effects1 = Arc::new(ApprovedEffects {
                policy: Arc::new(StopOnIdemReview {
                    inner: registry.clone(),
                    stop: Mutex::new(Some(stop_tx1)),
                }),
                adapter: adapter1,
            });
            let exec1 = TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                SimpleDeclaredRoutes {
                    gateway: make_gateway(&inv_model_srv, false),
                    registry: registry.clone(),
                    declared: vec![registry.get("mcp_idem", "1").unwrap().declared_tool()],
                    bound_override: None,
                },
            )
            .with_effects(effects1);
            let active1 = ActiveRun {
                claim: claim1.clone(),
                state: leases::ExecState::Running,
                execution_deadline: Instant::now() + Duration::from_secs(120),
            };
            assert!(matches!(
                exec1.step(&active1, step1).await,
                StepResult::Handoff
            ));
            leases::release_lease(&mut w, &claim1.lease())
                .await
                .unwrap();
            assert_eq!(idem_calls.load(Ordering::SeqCst), idem0);
            assert_eq!(inv_rounds.load(Ordering::SeqCst), 2);

            let adapter2 = Arc::new(ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-inv".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            ));
            let approved2 = Arc::new(adapter2.approved_effects());
            let exec2 = Arc::new(
                TurnExecutor::new(
                    worker_pool.clone(),
                    catalog.clone(),
                    LEASES,
                    SimpleDeclaredRoutes {
                        gateway: make_gateway(&inv_model_srv, false),
                        registry: registry.clone(),
                        declared: vec![registry.get("mcp_idem", "1").unwrap().declared_tool()],
                        bound_override: None,
                    },
                )
                .with_effects(approved2.clone()),
            );
            let (sh_tx, sh_rx) = oneshot::channel();
            let task = tokio::spawn({
                let pool = worker_pool.clone();
                let settings = worker_settings();
                async move {
                    worker::run_with_approvals(
                        &pool,
                        None,
                        settings,
                        exec2,
                        Some(approved2),
                        async move {
                            let _ = sh_rx.await;
                        },
                        Duration::from_secs(4),
                    )
                    .await;
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let final_state = loop {
                let s: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&run_id)
                        .fetch_one(&mut owner)
                        .await
                        .unwrap();
                if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                    break s;
                }
                assert!(Instant::now() < deadline, "inv reclaim timed out");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let _ = sh_tx.send(());
            task.await.unwrap();

            assert_eq!(final_state, "succeeded");
            assert_eq!(idem_calls.load(Ordering::SeqCst), idem0 + 1);
            assert_eq!(inv_rounds.load(Ordering::SeqCst), 3);
            assert!(saw_rejected_and_ok.load(Ordering::SeqCst));
        }

        // --- (f) P2 #2: Removed external DeclaredTool dropped; pinned v1 isolated from broken v2 ---
        {
            let removed_decl = DeclaredTool::external(
                Tool {
                    name: "mcp_removed".into(),
                    description: "Removed contract".into(),
                    parameters: json!({"type": "object", "additionalProperties": false, "properties": {}}),
                },
                "1",
            );
            let v1_decl = registry.get("mcp_ver", "1").unwrap().declared_tool();
            let advertised_names: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let adv_srv = advertised_names.clone();
            let ver_rounds = Arc::new(AtomicUsize::new(0));
            let ver_rounds_srv = ver_rounds.clone();
            let ver_model_srv = SyntheticMcpServer::start(move |req| {
                let r = ver_rounds_srv.fetch_add(1, Ordering::SeqCst);
                if r == 0 {
                    if let Some(tools) = req.body.get("tools").and_then(Value::as_array) {
                        let names = tools
                            .iter()
                            .filter_map(|t| t["function"]["name"].as_str().map(str::to_owned))
                            .collect();
                        *adv_srv.lock().unwrap() = names;
                    }
                    let body = json!({
                        "id": "chatcmpl-ver-1",
                        "object": "chat.completion",
                        "model": "a",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": null,
                                "tool_calls": [{
                                    "id": "call_ver_1",
                                    "type": "function",
                                    "function": {"name": "mcp_ver", "arguments": "{\"item\":\"v1\"}"}
                                }]
                            },
                            "finish_reason": "tool_calls"
                        }],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                    })
                    .to_string();
                    http_response(200, &[("content-type", "application/json")], body.as_bytes())
                } else {
                    let body = json!({
                        "id": "chatcmpl-ver-2",
                        "object": "chat.completion",
                        "model": "a",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "v1 ok"},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 16, "completion_tokens": 4}
                    })
                    .to_string();
                    http_response(200, &[("content-type", "application/json")], body.as_bytes())
                }
            })
            .await;

            let ver0 = ver_calls.load(Ordering::SeqCst);
            let run_id =
                admit_yolo_turn("r3-declared-ver", "00000000-0000-4000-8000-000000003404", 3).await;
            let adapter = Arc::new(ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-ver".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            ));
            let approved = Arc::new(adapter.approved_effects());
            let exec = Arc::new(
                TurnExecutor::new(
                    worker_pool.clone(),
                    catalog.clone(),
                    LEASES,
                    SimpleDeclaredRoutes {
                        gateway: make_gateway(&ver_model_srv, false),
                        registry: registry.clone(),
                        declared: vec![removed_decl, v1_decl],
                        bound_override: None,
                    },
                )
                .with_effects(approved.clone()),
            );
            let (sh_tx, sh_rx) = oneshot::channel();
            let task = tokio::spawn({
                let pool = worker_pool.clone();
                let settings = worker_settings();
                async move {
                    worker::run_with_approvals(
                        &pool,
                        None,
                        settings,
                        exec,
                        Some(approved),
                        async move {
                            let _ = sh_rx.await;
                        },
                        Duration::from_secs(4),
                    )
                    .await;
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let final_state = loop {
                let s: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&run_id)
                        .fetch_one(&mut owner)
                        .await
                        .unwrap();
                if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                    break s;
                }
                assert!(Instant::now() < deadline, "declared version test timed out");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let _ = sh_tx.send(());
            task.await.unwrap();

            assert_eq!(final_state, "succeeded");
            assert_eq!(*advertised_names.lock().unwrap(), vec!["mcp_ver"]);
            assert_eq!(ver_calls.load(Ordering::SeqCst), ver0 + 1);
        }

        // --- (g) P2 #3: tool_prompt_bound still enforced when Round 2 filters out the last tool ---
        {
            let b_rounds = Arc::new(AtomicUsize::new(0));
            let b_rounds_srv = b_rounds.clone();
            let drift_trigger = drift_list.clone();
            let bound_model_srv = SyntheticMcpServer::start(move |_req| {
                let r = b_rounds_srv.fetch_add(1, Ordering::SeqCst);
                let body = if r == 0 {
                    // Drift tools/list before Round 2 so filter_turn_tools returns tools == None!
                    drift_trigger.store(true, Ordering::SeqCst);
                    json!({
                        "id": "chatcmpl-bnd-1",
                        "object": "chat.completion",
                        "model": "a",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": null,
                                "tool_calls": [{
                                    "id": "call_bnd_1",
                                    "type": "function",
                                    "function": {"name": "mcp_read", "arguments": "{\"item\":\"b\"}"}
                                }]
                            },
                            "finish_reason": "tool_calls"
                        }],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                    })
                } else {
                    json!({
                        "id": "chatcmpl-bnd-2",
                        "object": "chat.completion",
                        "model": "a",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "should-never-reach"},
                            "finish_reason": "stop"
                        }],
                        "usage": {"prompt_tokens": 15, "completion_tokens": 5}
                    })
                }
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            })
            .await;

            // Round 1 uses TTL=60s (so `mcp_read` preflight uses Round 1's cached catalog),
            // and before Round 2 we wait? No — even cleaner: use a tiny adapter that drops
            // tools on the 2nd `filter_turn_tools` call (simulating catalog drift right before Round 2)!
            drift_list.store(false, Ordering::SeqCst);
            struct DropOnSecondFilterAdapter {
                inner: Arc<ExternalMcpAdapter>,
                calls: Arc<AtomicUsize>,
            }
            impl ApprovedAdapter for DropOnSecondFilterAdapter {
                fn preflight<'a>(
                    &'a self,
                    run: &'a ActiveRun,
                    proposal: &'a Proposal,
                    step: &'a StepContext,
                ) -> Pin<Box<dyn Future<Output = Result<(), worker::PreflightError>> + Send + 'a>>
                {
                    self.inner.preflight(run, proposal, step)
                }
                fn verify_turn_call_proposal(
                    &self,
                    call: &Call,
                    proposal: &Proposal,
                    expected_external_version: Option<&str>,
                ) -> bool {
                    self.inner
                        .verify_turn_call_proposal(call, proposal, expected_external_version)
                }
                fn filter_turn_tools<'a>(
                    &'a self,
                    run: &'a ActiveRun,
                    tools: Vec<DeclaredTool>,
                    step: &'a StepContext,
                ) -> Pin<Box<dyn Future<Output = Result<Vec<Tool>, StepResult>> + Send + 'a>>
                {
                    if self.calls.fetch_add(1, Ordering::SeqCst) >= 1 {
                        return Box::pin(async { Ok(Vec::new()) });
                    }
                    self.inner.filter_turn_tools(run, tools, step)
                }
                fn send<'a>(
                    &'a self,
                    run: &'a ActiveRun,
                    operation_id: String,
                    request: Vec<u8>,
                    step: StepContext,
                ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
                    self.inner.send(run, operation_id, request, step)
                }
            }

            let run_id =
                admit_yolo_turn("r3-bound-cont", "00000000-0000-4000-8000-000000003405", 3).await;
            let inner = Arc::new(ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-bnd".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            ));
            let approved = Arc::new(ApprovedEffects {
                policy: registry.clone(),
                adapter: Arc::new(DropOnSecondFilterAdapter {
                    inner,
                    calls: Arc::new(AtomicUsize::new(0)),
                }),
            });
            let exec = Arc::new(
                TurnExecutor::new(
                    worker_pool.clone(),
                    catalog.clone(),
                    LEASES,
                    SimpleDeclaredRoutes {
                        gateway: make_gateway(&bound_model_srv, false),
                        registry: registry.clone(),
                        declared: vec![registry.get("mcp_read", "1").unwrap().declared_tool()],
                        bound_override: Some(u64::MAX),
                    },
                )
                .with_effects(approved.clone()),
            );
            let (sh_tx, sh_rx) = oneshot::channel();
            let task = tokio::spawn({
                let pool = worker_pool.clone();
                let settings = worker_settings();
                async move {
                    worker::run_with_approvals(
                        &pool,
                        None,
                        settings,
                        exec,
                        Some(approved),
                        async move {
                            let _ = sh_rx.await;
                        },
                        Duration::from_secs(4),
                    )
                    .await;
                }
            });
            let deadline = Instant::now() + Duration::from_secs(10);
            let final_state = loop {
                let s: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&run_id)
                        .fetch_one(&mut owner)
                        .await
                        .unwrap();
                if !matches!(s.as_str(), "queued" | "waiting" | "running") {
                    break s;
                }
                assert!(Instant::now() < deadline, "prompt bound test timed out");
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let _ = sh_tx.send(());
            task.await.unwrap();
            drift_list.store(false, Ordering::SeqCst);

            assert_eq!(final_state, "failed");
            assert_eq!(
                b_rounds.load(Ordering::SeqCst),
                1,
                "Round 2 must be blocked before provider dispatch when tool_prompt_bound exceeds usable_input"
            );
        }
    }

    // --- (h) P2 #4: logical_call_deadline bounds initial pool acquire + actor lookup before HTTP ---
    {
        let tight_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&f.db.url(WORKER))
            .await
            .unwrap();
        let tight_adapter = Arc::new(ExternalMcpAdapter::new(
            tight_pool.clone(),
            LEASES,
            registry.clone(),
            transports,
            Arc::new(CountingCredentials {
                token: Some("tok-tight".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let rr = f.claim("r3-tight-send", "yolo").await;
        let prop = registry
            .proposal("k-tight-1", "mcp.tight_to", "1", br#"{"item":"t"}"#)
            .unwrap();
        let IntentResult::Applied(tx1) =
            record_fenced_intent(&mut w, &rr.lease(), &prop, None, registry.as_ref(), &LEASES)
                .await
                .unwrap()
        else {
            panic!("expected Tx1");
        };
        let ReplayEffect::Ready(_) = start_write_attempt(
            &mut w,
            &rr.lease(),
            &tx1.operation_id,
            &prop,
            &LEASES,
            registry.as_ref(),
        )
        .await
        .unwrap() else {
            panic!("expected Tx2 Ready");
        };
        let req_bytes: Vec<u8> =
            sqlx::query_scalar("SELECT request FROM openmettle.operations WHERE id = $1::uuid")
                .bind(&tx1.operation_id)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        let (_st, step) = fresh_step(30);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };
        // Hold the sole connection on tight_pool so initial send setup exceeds 150ms call_timeout.
        let held_conn = tight_pool.acquire().await.unwrap();
        let t0 = Instant::now();
        let res = tight_adapter
            .send(&active, tx1.operation_id.clone(), req_bytes, step)
            .await;
        let elapsed = t0.elapsed();
        drop(held_conn);

        assert!(matches!(
            res,
            StepResult::ToolResponse(Err(mcp::ToolFault::Transient))
        ));
        assert!(
            elapsed < Duration::from_secs(2),
            "initial send setup must be bounded by 150ms call_timeout, took {elapsed:?}"
        );
        assert_eq!(tight_calls.load(Ordering::SeqCst), 0);

        sqlx::query("UPDATE openmettle.runs SET lease_expires_at = least(lease_expires_at, clock_timestamp() + interval '1 second'), execution_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid")
            .bind(&rr.run_id)
            .execute(&mut owner)
            .await
            .unwrap();
        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Stopped)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL container"]
async fn review4_version_pin_key_redaction_multiblock_collision_and_abandoned_round_regressions() {
    use openmettle_core::{
        artifact_fs::Store,
        authz::{
            branches::{
                self, Conversation, Operation, Part, UserInput,
                snapshot::{Intent as TurnIntent, Snapshots},
            },
            store::{AuditContext, WriteOutcome},
        },
        model_config::{
            Catalog, ConfigSnapshot, Effective, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection,
        },
        provider_http::inference::{
            self, Call, Gateway, Protocol, Qualification, Request, Timeouts, Tool,
        },
        runs::RunInput,
        worker::turns::{Route, TurnExecutor, TurnRoutes},
    };

    let f = Fixture::new().await;
    f.grant(true).await;
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let mut w = worker(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;

    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("mcp-r4-spill"));
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_instance SET personal_limit_bytes=4000000, instance_budget_bytes=4000000",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let mut reg_builder = test_registry(FUTURE * 1000);
    let mut read_v1 = reg_builder.get("mcp.read", "1").unwrap().clone();
    read_v1.tool_id = "mcp_read".into();
    read_v1.remote_name = "mcp_read".into();
    read_v1.version = "1".into();
    read_v1.connection_id = "synth-v1".into();
    read_v1.endpoint_id = "ep-v1".into();
    reg_builder.register(read_v1.clone()).unwrap();

    let mut read_v2 = read_v1.clone();
    read_v2.version = "2".into();
    read_v2.connection_id = "synth-v2".into();
    read_v2.endpoint_id = "ep-v2".into();
    reg_builder.register(read_v2).unwrap();

    let mut idem_v1 = reg_builder.get("mcp.idem", "1").unwrap().clone();
    idem_v1.tool_id = "mcp_idem".into();
    idem_v1.remote_name = "mcp_idem".into();
    idem_v1.version = "1".into();
    idem_v1.connection_id = "synth-v1".into();
    idem_v1.endpoint_id = "ep-v1".into();
    reg_builder.register(idem_v1.clone()).unwrap();

    let mut idem_v2 = idem_v1.clone();
    idem_v2.version = "2".into();
    idem_v2.connection_id = "synth-v2".into();
    idem_v2.endpoint_id = "ep-v2".into();
    reg_builder.register(idem_v2).unwrap();

    let registry = Arc::new(reg_builder);

    let v1_read_calls = Arc::new(AtomicUsize::new(0));
    let v1_idem_calls = Arc::new(AtomicUsize::new(0));
    let v2_calls = Arc::new(AtomicUsize::new(0));
    let pad_big = "R".repeat(INLINE_BYTES + 4096);

    let v1_read_srv = v1_read_calls.clone();
    let v1_idem_srv = v1_idem_calls.clone();
    let pad_srv = pad_big.clone();
    let server_v1 = SyntheticMcpServer::start(move |req| {
        let id = req.body["id"].as_str().unwrap_or("0");
        let method = req.body["method"].as_str().unwrap_or("");
        if method == "tools/list" {
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {"name": "mcp_read", "inputSchema": read_v1.input_schema},
                        {"name": "mcp_idem", "inputSchema": idem_v1.input_schema}
                    ]
                }
            })
            .to_string();
            return http_response(200, &[("content-type", "application/json")], body.as_bytes());
        }
        let tool = req.body["params"]["name"].as_str().unwrap_or("");
        let item = req.body["params"]["arguments"]["item"]
            .as_str()
            .unwrap_or("");
        match (tool, item) {
            ("mcp_read", _) => {
                v1_read_srv.fetch_add(1, Ordering::SeqCst);
                jsonrpc_ok(id, "r4-v1-read-ok", None)
            }
            ("mcp_idem", "mb-inline") => {
                let h = "h\"mb\\1";
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json!({"b1": format!("a {h} z")}).to_string()},
                            {"type": "text", "text": json!(format!("b2 {h} end")).to_string()}
                        ],
                        "structuredContent": {"handle": h}
                    }
                })
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            }
            ("mcp_idem", "mb-spilled") => {
                let h = "h\"mb\\1";
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json!({"b1": format!("a {h} {pad_srv}")}).to_string()},
                            {"type": "text", "text": json!(format!("b2 {h} end")).to_string()}
                        ],
                        "structuredContent": {"handle": h}
                    }
                })
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            }
            ("mcp_idem", "deep-json-spilled") => {
                let h = "h\"deep\\1";
                let mut deep = format!("{{\"leaf\":{}}}", json!(format!("x {h} y")));
                for _ in 0..150 {
                    deep = format!("[{deep}]");
                }
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [
                            {"type": "text", "text": deep},
                            {"type": "text", "text": "10"},
                            {"type": "text", "text": pad_srv}
                        ],
                        "structuredContent": {"handle": h}
                    }
                })
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            }
            ("mcp_idem", "tricky-key-inline") => {
                let h = "D]#";
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "structuredContent": {
                            "handle": h,
                            "[REDACTED]": "keep",
                            "p-D]#": "v-D]#",
                            "p-D]#D]#": "v2",
                            "D]#": "v3"
                        }
                    }
                })
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            }
            ("mcp_idem", "tricky-key-spilled") => {
                let h = "EDACT";
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "structuredContent": {
                            "handle": h,
                            "[REDACTED]": "keep",
                            "***": "keep-stars",
                            "p-EDACT": "v-EDACT",
                            "EDACT": "v3",
                            "pad": pad_srv
                        }
                    }
                })
                .to_string();
                http_response(200, &[("content-type", "application/json")], body.as_bytes())
            }
            ("mcp_idem", _) => {
                v1_idem_srv.fetch_add(1, Ordering::SeqCst);
                jsonrpc_ok(id, "r4-v1-idem-ok", Some(json!({"handle": "h-r4-idem"})))
            }
            _ => jsonrpc_ok(id, "ok", None),
        }
    })
    .await;

    let read_schema_v2 = registry.get("mcp_read", "2").unwrap().input_schema.clone();
    let idem_schema_v2 = registry.get("mcp_idem", "2").unwrap().input_schema.clone();
    let v2_srv = v2_calls.clone();
    let server_v2 = SyntheticMcpServer::start(move |req| {
        let id = req.body["id"].as_str().unwrap_or("0");
        let method = req.body["method"].as_str().unwrap_or("");
        if method == "tools/list" {
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {"name": "mcp_read", "inputSchema": read_schema_v2},
                        {"name": "mcp_idem", "inputSchema": idem_schema_v2}
                    ]
                }
            })
            .to_string();
            return http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            );
        }
        v2_srv.fetch_add(1, Ordering::SeqCst);
        jsonrpc_ok(id, "r4-v2-unexpected", Some(json!({"handle": "h-v2"})))
    })
    .await;

    let mut transports = BTreeMap::new();
    transports.insert("synth-v1".to_owned(), server_v1.transport());
    transports.insert("synth-v2".to_owned(), server_v2.transport());

    // --- (a) P1 #2 + P1 #3: Multi-block JSON-escaped handle & adversarial key collisions (inline + spilled) ---
    {
        let adapter = Arc::new(
            ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-r4-h".into()),
                    lookups: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            )
            .with_artifacts(store.clone()),
        );
        let scoped = ScopedAdapter::new(worker_pool.clone(), store.clone(), LEASES);
        let rr = f.claim("r4-handle-mb-keys", "yolo").await;
        let (_st, step) = fresh_step(25);
        let active = ActiveRun {
            claim: rr.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step.deadline,
        };
        let read_all_spilled = async |art_id: &str, rev_id: &str, prefix: &str| -> String {
            let mut full = String::new();
            let mut offset = 0u64;
            let mut page = 0usize;
            loop {
                let args = json!({
                    "artifact_id": art_id,
                    "revision_id": rev_id,
                    "offset": offset,
                    "max_bytes": INLINE_BYTES
                })
                .to_string();
                let StepResult::ToolOutput(chunk_json) = scoped
                    .call(
                        &active,
                        step.clone(),
                        &format!("{prefix}-{page}"),
                        mcp::READ_RANGE,
                        "1",
                        args.as_bytes(),
                    )
                    .await
                else {
                    panic!("expected read_range page");
                };
                let pv: Value = serde_json::from_str(&chunk_json).unwrap();
                full.push_str(pv["text"].as_str().unwrap());
                offset = pv["next_offset"].as_u64().unwrap();
                if pv["eof"] == true {
                    break;
                }
                page += 1;
            }
            full
        };

        let StepResult::ToolOutput(mb_in) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r4-mb-in",
                    tool: "mcp_idem",
                    version: "1",
                    raw_args: br#"{"item":"mb-inline"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected mb-inline ToolOutput");
        };
        assert!(!mb_in.contains("mb"));

        let StepResult::ToolOutput(mb_sp) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r4-mb-sp",
                    tool: "mcp_idem",
                    version: "1",
                    raw_args: br#"{"item":"mb-spilled"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected mb-spilled ToolOutput");
        };
        assert!(!mb_sp.contains("mb"));
        let mb_env: Value = serde_json::from_str(&mb_sp).unwrap();
        assert_eq!(mb_env["storage"], "spilled");
        let mb_full = read_all_spilled(
            mb_env["provenance"]["artifact_id"].as_str().unwrap(),
            mb_env["provenance"]["revision_id"].as_str().unwrap(),
            "r4-mb",
        )
        .await;
        assert!(!mb_full.contains("mb"));

        let StepResult::ToolOutput(dj_sp) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r5-dj-sp",
                    tool: "mcp_idem",
                    version: "1",
                    raw_args: br#"{"item":"deep-json-spilled"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected deep-json-spilled ToolOutput");
        };
        assert!(!dj_sp.contains("deep"));
        let dj_env: Value = serde_json::from_str(&dj_sp).unwrap();
        assert_eq!(dj_env["storage"], "spilled");
        let dj_full = read_all_spilled(
            dj_env["provenance"]["artifact_id"].as_str().unwrap(),
            dj_env["provenance"]["revision_id"].as_str().unwrap(),
            "r5-dj",
        )
        .await;
        assert!(!dj_full.contains("deep"));
        assert!(dj_full.starts_with("[REDACTED]\n10\n"));

        let StepResult::ToolOutput(tk_in) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r4-tk-in",
                    tool: "mcp_idem",
                    version: "1",
                    raw_args: br#"{"item":"tricky-key-inline"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected tricky-key-inline ToolOutput");
        };
        assert!(!tk_in.contains("D]#"));

        let StepResult::ToolOutput(tk_sp) = adapter
            .call(
                &active,
                step.clone(),
                ExternalCall {
                    key: "k-r4-tk-sp",
                    tool: "mcp_idem",
                    version: "1",
                    raw_args: br#"{"item":"tricky-key-spilled"}"#,
                    approval: None,
                },
            )
            .await
        else {
            panic!("expected tricky-key-spilled ToolOutput");
        };
        let tk_env: Value = serde_json::from_str(&tk_sp).unwrap();
        assert_eq!(tk_env["storage"], "spilled");
        let tk_full = read_all_spilled(
            tk_env["provenance"]["artifact_id"].as_str().unwrap(),
            tk_env["provenance"]["revision_id"].as_str().unwrap(),
            "r4-tk",
        )
        .await;
        assert!(!tk_full.contains("EDACT"));

        leases::settle(&mut w, &rr.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    let catalog_bytes = include_bytes!("../fixtures/conversation-catalog-v1.json");
    let catalog = Arc::new(Catalog::load(catalog_bytes).unwrap());
    let selection: Selection = serde_json::from_value(
        json!({"model": "a", "layer": {"controls": {"output_reserve": 256}}}),
    )
    .unwrap();
    let snapshot = ConfigSnapshot {
        effective: catalog
            .resolve(&Selection::default(), &selection, None, |_, _| true)
            .unwrap(),
        required_capabilities: catalog.model("a").unwrap().required_capabilities.clone(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: catalog.model("a").unwrap().cost_bound,
    };
    let make_gateway = |srv: &SyntheticMcpServer| -> Arc<Gateway> {
        let prefix = if srv.ip.is_ipv4() { 32 } else { 128 };
        let range = format!("{}/{prefix}", srv.ip);
        Arc::new(
            Gateway::new(
                &format!("https://{}:{}/v1/chat/completions", srv.host, srv.port),
                Trust::Bundle(&srv.ca_pem),
                &[&range],
                Qualification {
                    model: "a".into(),
                    pin: catalog.model("a").unwrap().pin.clone(),
                    protocol: Protocol::Chat,
                    json: true,
                    sse: false,
                    functions: Some(inference::SchemaSubset::Flat),
                    images: false,
                    parallel: false,
                    usage: true,
                    tool_separator_whitespace: false,
                },
                Timeouts {
                    setup: Duration::from_secs(5),
                    idle: Duration::from_secs(15),
                    overall: Duration::from_secs(30),
                },
            )
            .unwrap(),
        )
    };
    let admit_yolo_turn = async |key: &'static str, msg_id: &'static str, rounds: i64| -> String {
        let mut ac = api(&f.db).await;
        let audit_ctx = |k: &'static str| AuditContext {
            actor_user_id: &f.actor.user,
            actor_approval_id: &f.actor.approval,
            now_ms: f.user.context().observed_ms(),
            request_key: k,
            reason: "review4 turn test",
        };
        let conv = match branches::create_conversation(&mut ac, &audit_ctx(key), &f.scope)
            .await
            .unwrap()
        {
            WriteOutcome::Applied { target_id } | WriteOutcome::Replayed { target_id } => target_id,
        };
        let chat = Conversation {
            scope: &f.scope,
            id: &conv.conversation_id,
        };
        let parts = [Part::Text("run review4 turn".into())];
        let turn_op = Operation::Append(UserInput {
            id: msg_id,
            parts: &parts,
        });
        let turn_intent = TurnIntent {
            source_branch_id: &conv.branch_id,
            expected_head_message_id: None,
            operation: turn_op,
            selection: &selection,
            requested_rounds: Some(rounds),
        };
        let actor_principal = super::super::authz_store::principal(&f.db, &f.actor).await;
        let mut tx = WriteTransaction::begin(&mut ac).await.unwrap();
        let msg_key = Box::leak(format!("{key}-msg").into_boxed_str());
        branches::prepare_turn(
            &mut tx,
            &audit_ctx(msg_key),
            chat,
            &conv.branch_id,
            None,
            turn_op,
        )
        .await
        .unwrap();
        let history = branches::history(
            tx.connection().unwrap(),
            &actor_principal,
            chat,
            &conv.branch_id,
            f.user.context().observed_ms(),
        )
        .await
        .unwrap()
        .unwrap();
        let pins = Snapshots::encode(&turn_intent, &history, &catalog, &snapshot).unwrap();
        let mut snap_val: Value = serde_json::from_slice(&pins.config).unwrap();
        snap_val["execution_mode"] = json!("yolo");
        let snapshot_bytes = serde_json::to_vec(&snap_val).unwrap();
        let admission = queue::admit_run_with_mode(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &f.scope,
                    actor: &f.actor.user,
                    conversation: &conv.conversation_id,
                    branch: &conv.branch_id,
                    message: msg_id,
                    key,
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: &pins.input,
                    config: &snapshot_bytes,
                },
                actor_approval_id: &f.actor.approval,
                capabilities: &[],
                requested_rounds: Some(rounds),
                now_ms: f.user.context().observed_ms(),
                cost_qualified: None,
            },
            &LIMITS,
            &f.user,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let Admission::Admitted { run_id, .. } = admission else {
            panic!("expected admitted turn run for {key}");
        };
        run_id
    };

    struct VersionSwitchRoutes {
        gateway: Arc<Gateway>,
        registry: Arc<ExternalRegistry>,
        propose_version: &'static str,
    }
    impl TurnRoutes for VersionSwitchRoutes {
        async fn route(
            &self,
            _: &ClaimedRun,
            _: &str,
            _: &Effective,
        ) -> Result<Route, inference::Error> {
            Ok(Route::metered(
                self.gateway.clone(),
                "00000000-0000-4000-8000-000000000091".into(),
                false,
            ))
        }
        fn declared_tools(&self, _: &ClaimedRun) -> Vec<DeclaredTool> {
            vec![
                self.registry.get("mcp_read", "1").unwrap().declared_tool(),
                self.registry.get("mcp_idem", "1").unwrap().declared_tool(),
            ]
        }
        fn tool_prompt_bound(&self, _: &Effective, request: &Request) -> Option<u64> {
            (request.history.len() <= 32).then_some(4096)
        }
        fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
            self.registry
                .proposal(
                    &call.id,
                    &call.name,
                    self.propose_version,
                    &serde_json::to_vec(&call.arguments).ok()?,
                )
                .ok()
        }
    }

    // --- (b) P1 #1: Live route advertises v1 (`synth-v1`) and proposes registered v2 (`synth-v2`) -> refused with 0 HTTP & 0 ops ---
    {
        let saw_refusal = Arc::new(AtomicBool::new(false));
        let saw_refusal_srv = saw_refusal.clone();
        let m_rounds = Arc::new(AtomicUsize::new(0));
        let m_rounds_srv = m_rounds.clone();
        let model_srv = SyntheticMcpServer::start(move |req| {
            let r = m_rounds_srv.fetch_add(1, Ordering::SeqCst);
            let body = if r == 0 {
                json!({
                    "id": "chatcmpl-vs-1",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_vs_1",
                                "type": "function",
                                "function": {"name": "mcp_read", "arguments": "{\"item\":\"vswitch\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                })
            } else {
                if req.body.to_string().contains("terminal_refusal") {
                    saw_refusal_srv.store(true, Ordering::SeqCst);
                }
                json!({
                    "id": "chatcmpl-vs-2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Refused version switch!"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 16, "completion_tokens": 4}
                })
            }
            .to_string();
            http_response(200, &[("content-type", "application/json")], body.as_bytes())
        })
        .await;

        let r1_before = v1_read_calls.load(Ordering::SeqCst);
        let r2_before = v2_calls.load(Ordering::SeqCst);
        let run_id =
            admit_yolo_turn("r4-ver-switch", "00000000-0000-4000-8000-000000004401", 3).await;
        let claim = f.next().await.expect("claim version-switch run");
        assert_eq!(claim.run_id, run_id);

        let adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-vs".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let exec = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "2",
            },
        )
        .with_effects(Arc::new(adapter.approved_effects()));
        let (_st, step) = fresh_step(30);
        let active = ActiveRun {
            claim: claim.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec.step(&active, step).await,
            StepResult::Answer(_)
        ));
        assert!(saw_refusal.load(Ordering::SeqCst));
        assert_eq!(v1_read_calls.load(Ordering::SeqCst), r1_before);
        assert_eq!(v2_calls.load(Ordering::SeqCst), r2_before);
        let op_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.operations WHERE run_id = $1::uuid",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(op_count, 0);
        leases::settle(&mut w, &claim.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    // --- (c) P2 #1: DeclaredTool::internal colliding with registered external MCP contract fails closed ---
    {
        struct LegacyInternalCollisionRoutes {
            gateway: Arc<Gateway>,
            tool: Tool,
        }
        impl TurnRoutes for LegacyInternalCollisionRoutes {
            async fn route(
                &self,
                _: &ClaimedRun,
                _: &str,
                _: &Effective,
            ) -> Result<Route, inference::Error> {
                Ok(Route::metered(
                    self.gateway.clone(),
                    "00000000-0000-4000-8000-000000000091".into(),
                    false,
                ))
            }
            fn tools(&self, _: &ClaimedRun) -> Vec<Tool> {
                vec![self.tool.clone()]
            }
            fn tool_prompt_bound(&self, _: &Effective, _: &Request) -> Option<u64> {
                Some(4096)
            }
        }

        let m_calls = Arc::new(AtomicUsize::new(0));
        let m_calls_srv = m_calls.clone();
        let model_srv = SyntheticMcpServer::start(move |_| {
            m_calls_srv.fetch_add(1, Ordering::SeqCst);
            http_response(500, &[], b"unreachable")
        })
        .await;
        let run_id =
            admit_yolo_turn("r4-int-collide", "00000000-0000-4000-8000-000000004402", 3).await;
        let claim = f.next().await.expect("claim internal-collision run");
        assert_eq!(claim.run_id, run_id);

        let adapter = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-ic".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let exec = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            LegacyInternalCollisionRoutes {
                gateway: make_gateway(&model_srv),
                tool: registry.get("mcp_read", "1").unwrap().declared_tool().tool,
            },
        )
        .with_effects(Arc::new(adapter.approved_effects()));
        let (_st, step) = fresh_step(30);
        let active = ActiveRun {
            claim: claim.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec.step(&active, step).await,
            StepResult::Failed(leases::FailReason::StepFailed)
        ));
        assert_eq!(m_calls.load(Ordering::SeqCst), 0);
        leases::settle(
            &mut w,
            &claim.lease(),
            &LEASES,
            Settle::Failed(leases::FailReason::StepFailed),
        )
        .await
        .unwrap();
    }

    // --- (d) P2 #2: Abandoned pre-effect Round 1 (`model-round:1`, no `turn-calls:1`) + Round 2 tool + `turn-handoff:2` -> Worker 3 succeeds ---
    {
        struct HandoffSecondFilter {
            inner: Arc<ExternalMcpAdapter>,
            calls: Arc<AtomicUsize>,
        }
        impl ApprovedAdapter for HandoffSecondFilter {
            fn preflight<'a>(
                &'a self,
                run: &'a ActiveRun,
                proposal: &'a Proposal,
                step: &'a StepContext,
            ) -> Pin<Box<dyn Future<Output = Result<(), worker::PreflightError>> + Send + 'a>>
            {
                self.inner.preflight(run, proposal, step)
            }
            fn verify_turn_call_proposal(
                &self,
                call: &Call,
                proposal: &Proposal,
                expected_external_version: Option<&str>,
            ) -> bool {
                self.inner
                    .verify_turn_call_proposal(call, proposal, expected_external_version)
            }
            fn filter_turn_tools<'a>(
                &'a self,
                run: &'a ActiveRun,
                tools: Vec<DeclaredTool>,
                step: &'a StepContext,
            ) -> Pin<Box<dyn Future<Output = Result<Vec<Tool>, StepResult>> + Send + 'a>>
            {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    return Box::pin(async { Err(StepResult::Handoff) });
                }
                self.inner.filter_turn_tools(run, tools, step)
            }
            fn send<'a>(
                &'a self,
                run: &'a ActiveRun,
                operation_id: String,
                request: Vec<u8>,
                step: StepContext,
            ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
                self.inner.send(run, operation_id, request, step)
            }
        }

        let (st1, step1) = fresh_step(30);
        let st1_slot = Arc::new(Mutex::new(Some(st1)));
        let st1_srv = st1_slot.clone();
        let m_attempts = Arc::new(AtomicUsize::new(0));
        let m_attempts_srv = m_attempts.clone();
        let saw_r2_output = Arc::new(AtomicBool::new(false));
        let saw_r2_srv = saw_r2_output.clone();
        let model_srv = SyntheticMcpServer::start(move |req| {
            let att = m_attempts_srv.fetch_add(1, Ordering::SeqCst);
            if att == 0 {
                if let Some(tx) = st1_srv.lock().unwrap().take() {
                    let _ = tx.send(Some(Stop::Shutdown));
                }
                std::thread::sleep(Duration::from_millis(80));
                return http_response(503, &[("retry-after", "0")], b"aborted");
            }
            let body = if att == 1 {
                json!({
                    "id": "chatcmpl-ab-2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_ab_r2",
                                "type": "function",
                                "function": {"name": "mcp_read", "arguments": "{\"item\":\"ab\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                })
            } else {
                if req.body.to_string().contains("r4-v1-read-ok") {
                    saw_r2_srv.store(true, Ordering::SeqCst);
                }
                json!({
                    "id": "chatcmpl-ab-3",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Recovered after abandoned round 1!"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 18, "completion_tokens": 4}
                })
            }
            .to_string();
            http_response(200, &[("content-type", "application/json")], body.as_bytes())
        })
        .await;

        let r1_before = v1_read_calls.load(Ordering::SeqCst);
        let run_id =
            admit_yolo_turn("r4-abandoned-r1", "00000000-0000-4000-8000-000000004403", 3).await;

        let claim1 = f.next().await.expect("claim1 abandoned r1");
        assert_eq!(claim1.run_id, run_id);
        let adapter1 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-ab".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let exec1 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "1",
            },
        )
        .with_effects(Arc::new(adapter1.approved_effects()));
        let active1 = ActiveRun {
            claim: claim1.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec1.step(&active1, step1).await,
            StepResult::Stopped
        ));
        leases::release_lease(&mut w, &claim1.lease())
            .await
            .unwrap();

        let (mr_after_w1, tc_after_w1): (i64, i64) = sqlx::query_as(
            "SELECT
                count(*) FILTER (WHERE format = 'openmettle.model-round'),
                count(*) FILTER (WHERE format = 'openmettle.turn-calls')
             FROM openmettle.run_events WHERE run_id = $1::uuid",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((mr_after_w1, tc_after_w1), (1, 0));

        let claim2 = leases::reclaim_next(&mut w, &LEASES)
            .await
            .unwrap()
            .expect("claim2 abandoned r1")
            .run;
        assert_eq!(claim2.run_id, run_id);
        let adapter2_inner = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-ab".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let effects2 = Arc::new(ApprovedEffects {
            policy: registry.clone(),
            adapter: Arc::new(HandoffSecondFilter {
                inner: adapter2_inner,
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        });
        let exec2 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "1",
            },
        )
        .with_effects(effects2);
        let (_st2, step2) = fresh_step(30);
        let active2 = ActiveRun {
            claim: claim2.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec2.step(&active2, step2).await,
            StepResult::Handoff
        ));
        leases::release_lease(&mut w, &claim2.lease())
            .await
            .unwrap();
        assert_eq!(v1_read_calls.load(Ordering::SeqCst), r1_before + 1);

        let claim3 = leases::reclaim_next(&mut w, &LEASES)
            .await
            .unwrap()
            .expect("claim3 abandoned r1")
            .run;
        assert_eq!(claim3.run_id, run_id);
        let adapter3 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-ab".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let exec3 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "1",
            },
        )
        .with_effects(Arc::new(adapter3.approved_effects()));
        let (_st3, step3) = fresh_step(30);
        let active3 = ActiveRun {
            claim: claim3.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec3.step(&active3, step3).await,
            StepResult::Answer(_)
        ));
        assert!(saw_r2_output.load(Ordering::SeqCst));
        assert_eq!(v1_read_calls.load(Ordering::SeqCst), r1_before + 1);
        leases::settle(&mut w, &claim3.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    // --- (e) P1 #1 + P2 #2: Abandoned Round 1 + Round 2 `has_pending_auto` rejects recovery version switch to v2, succeeds on v1 ---
    {
        struct AbortPreflightAfterCalls {
            inner: Arc<ExternalMcpAdapter>,
        }
        impl ApprovedAdapter for AbortPreflightAfterCalls {
            fn preflight<'a>(
                &'a self,
                _: &'a ActiveRun,
                _: &'a Proposal,
                _: &'a StepContext,
            ) -> Pin<Box<dyn Future<Output = Result<(), worker::PreflightError>> + Send + 'a>>
            {
                Box::pin(async {
                    Err(worker::PreflightError::Store(StoreError::Conflict(
                        "crash-at-tx1",
                    )))
                })
            }
            fn verify_turn_call_proposal(
                &self,
                call: &Call,
                proposal: &Proposal,
                expected_external_version: Option<&str>,
            ) -> bool {
                self.inner
                    .verify_turn_call_proposal(call, proposal, expected_external_version)
            }
            fn filter_turn_tools<'a>(
                &'a self,
                run: &'a ActiveRun,
                tools: Vec<DeclaredTool>,
                step: &'a StepContext,
            ) -> Pin<Box<dyn Future<Output = Result<Vec<Tool>, StepResult>> + Send + 'a>>
            {
                self.inner.filter_turn_tools(run, tools, step)
            }
            fn send<'a>(
                &'a self,
                run: &'a ActiveRun,
                operation_id: String,
                request: Vec<u8>,
                step: StepContext,
            ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
                self.inner.send(run, operation_id, request, step)
            }
        }

        let (st1, step1) = fresh_step(30);
        let st1_slot = Arc::new(Mutex::new(Some(st1)));
        let st1_srv = st1_slot.clone();
        let m_att = Arc::new(AtomicUsize::new(0));
        let m_att_srv = m_att.clone();
        let model_srv = SyntheticMcpServer::start(move |_| {
            let att = m_att_srv.fetch_add(1, Ordering::SeqCst);
            if att == 0 {
                if let Some(tx) = st1_srv.lock().unwrap().take() {
                    let _ = tx.send(Some(Stop::Shutdown));
                }
                std::thread::sleep(Duration::from_millis(80));
                return http_response(503, &[("retry-after", "0")], b"aborted");
            }
            let body = if att == 1 {
                json!({
                    "id": "chatcmpl-rec-2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_rec_r2",
                                "type": "function",
                                "function": {"name": "mcp_idem", "arguments": "{\"item\":\"rec\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                })
            } else {
                json!({
                    "id": "chatcmpl-rec-3",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Recovered pending auto!"},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 18, "completion_tokens": 4}
                })
            }
            .to_string();
            http_response(
                200,
                &[("content-type", "application/json")],
                body.as_bytes(),
            )
        })
        .await;

        let idem0 = v1_idem_calls.load(Ordering::SeqCst);
        let v2_0 = v2_calls.load(Ordering::SeqCst);
        let run_id = admit_yolo_turn("r4-rec-ver", "00000000-0000-4000-8000-000000004404", 3).await;

        // Worker 1 abandons pre-effect Round 1.
        let claim1 = f.next().await.expect("claim1 rec-ver");
        assert_eq!(claim1.run_id, run_id);
        let adapter1 = Arc::new(ExternalMcpAdapter::new(
            worker_pool.clone(),
            LEASES,
            registry.clone(),
            transports.clone(),
            Arc::new(CountingCredentials {
                token: Some("tok-rv".into()),
                lookups: Arc::new(AtomicUsize::new(0)),
            }),
            Arc::new(ToggleReconcileAuth {
                allowed: Arc::new(AtomicBool::new(true)),
                checks: Arc::new(AtomicUsize::new(0)),
            }),
        ));
        let exec1 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "1",
            },
        )
        .with_effects(Arc::new(adapter1.approved_effects()));
        let active1 = ActiveRun {
            claim: claim1.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec1.step(&active1, step1).await,
            StepResult::Stopped
        ));
        leases::release_lease(&mut w, &claim1.lease())
            .await
            .unwrap();

        // Worker 2 persists `turn-calls:2` (`advertised = v1`, `continuation_rounds = [2]`) and commits Tx1 (`attempts = 0`), then loses lease before Tx2.
        let claim2 = leases::reclaim_next(&mut w, &LEASES)
            .await
            .unwrap()
            .expect("claim2 rec-ver")
            .run;
        let effects2 = Arc::new(ApprovedEffects {
            policy: registry.clone(),
            adapter: Arc::new(AbortPreflightAfterCalls {
                inner: adapter1.clone(),
            }),
        });
        let exec2 = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "1",
            },
        )
        .with_effects(effects2);
        let (_st2, step2) = fresh_step(30);
        let active2 = ActiveRun {
            claim: claim2.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec2.step(&active2, step2).await,
            StepResult::LeaseLost
        ));
        let prop_v1 = registry
            .proposal("call_rec_r2", "mcp_idem", "1", br#"{"item":"rec"}"#)
            .unwrap();
        assert!(matches!(
            record_fenced_intent(
                &mut w,
                &claim2.lease(),
                &prop_v1,
                None,
                registry.as_ref(),
                &LEASES
            )
            .await
            .unwrap(),
            IntentResult::Applied(_)
        ));
        leases::release_lease(&mut w, &claim2.lease())
            .await
            .unwrap();

        // Worker 3a attempts recovery with `propose_version: "2"` -> MUST fail closed (`StepFailed`), 0 v2 calls!
        let claim3a = leases::reclaim_next(&mut w, &LEASES)
            .await
            .unwrap()
            .expect("claim3a rec-ver")
            .run;
        let exec3a = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "2",
            },
        )
        .with_effects(Arc::new(adapter1.approved_effects()));
        let (_st3a, step3a) = fresh_step(30);
        let active3a = ActiveRun {
            claim: claim3a.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec3a.step(&active3a, step3a).await,
            StepResult::Failed(leases::FailReason::StepFailed)
        ));
        assert_eq!(v2_calls.load(Ordering::SeqCst), v2_0);
        assert_eq!(v1_idem_calls.load(Ordering::SeqCst), idem0);
        leases::release_lease(&mut w, &claim3a.lease())
            .await
            .unwrap();

        // Worker 3b recovers cleanly with `propose_version: "1"`, finishes Tx2 + send (`idem0 + 1`), and completes Round 3!
        let claim3b = leases::reclaim_next(&mut w, &LEASES)
            .await
            .unwrap()
            .expect("claim3b rec-ver")
            .run;
        let exec3b = TurnExecutor::new(
            worker_pool.clone(),
            catalog.clone(),
            LEASES,
            VersionSwitchRoutes {
                gateway: make_gateway(&model_srv),
                registry: registry.clone(),
                propose_version: "1",
            },
        )
        .with_effects(Arc::new(adapter1.approved_effects()));
        let (_st3b, step3b) = fresh_step(30);
        let active3b = ActiveRun {
            claim: claim3b.clone(),
            state: leases::ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        assert!(matches!(
            exec3b.step(&active3b, step3b).await,
            StepResult::Answer(_)
        ));
        assert_eq!(v1_idem_calls.load(Ordering::SeqCst), idem0 + 1);
        assert_eq!(v2_calls.load(Ordering::SeqCst), v2_0);
        leases::settle(&mut w, &claim3b.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();
    }

    // --- (f) Review #5 regressions: gate-off read filter, spilled >128-nested JSON withholding, and transcript row bounds ---
    {
        let cred_lookups = Arc::new(AtomicUsize::new(0));
        let adapter_r5 = Arc::new(
            ExternalMcpAdapter::new(
                worker_pool.clone(),
                LEASES,
                registry.clone(),
                transports.clone(),
                Arc::new(CountingCredentials {
                    token: Some("tok-r5".into()),
                    lookups: cred_lookups.clone(),
                }),
                Arc::new(ToggleReconcileAuth {
                    allowed: Arc::new(AtomicBool::new(true)),
                    checks: Arc::new(AtomicUsize::new(0)),
                }),
            )
            .with_artifacts(store.clone()),
        );

        // 1. Gate-disabled `filter_turn_tools` skips ALL external declarations (including `repeatable_read`)
        //    with zero credential lookups, while preserving non-colliding internal tools.
        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = false",
        )
        .execute(&mut owner)
        .await
        .unwrap();
        let rr_gate = f.claim("r5-filter-gate-off", "yolo").await;
        let (_st_g, step_g) = fresh_step(25);
        let active_g = ActiveRun {
            claim: rr_gate.clone(),
            state: leases::ExecState::Running,
            execution_deadline: step_g.deadline,
        };
        let internal_tool = Tool {
            name: mcp::READ_RANGE.into(),
            description: "read range".into(),
            parameters: json!({"type": "object", "additionalProperties": false}),
        };
        let Ok(kept_off) = adapter_r5
            .filter_turn_tools(
                &active_g,
                vec![
                    registry.get("mcp_read", "1").unwrap().declared_tool(),
                    registry.get("mcp_idem", "1").unwrap().declared_tool(),
                    DeclaredTool::internal(internal_tool.clone()),
                ],
                &step_g,
            )
            .await
        else {
            panic!("expected filter_turn_tools Ok");
        };
        assert!(kept_off == vec![internal_tool]);
        assert_eq!(
            cred_lookups.load(Ordering::SeqCst),
            0,
            "gate-disabled worker must not perform credential lookup or tools/list for external reads"
        );
        sqlx::query(
            "UPDATE openmettle.runtime_feature_gates SET two_phase_effect_intents_enabled = true",
        )
        .execute(&mut owner)
        .await
        .unwrap();
        leases::settle(&mut w, &rr_gate.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap();

        // 2. Recovery rejects extra out-of-bounds `turn-result:1:1` or unsupported `format_version = 2`
        //    on `turn-calls` BEFORE resuming a pending write (`0` MCP HTTP calls).
        for (idx_case, bad_version) in [(0usize, false), (1usize, true)] {
            let key: &'static str = if bad_version {
                "r5-bad-fmt-ver"
            } else {
                "r5-oob-result"
            };
            let msg_id: &'static str = if bad_version {
                "00000000-0000-4000-8000-000000004502"
            } else {
                "00000000-0000-4000-8000-000000004501"
            };
            let run_id = admit_yolo_turn(key, msg_id, 3).await;
            let claim_a = f.next().await.expect("claim r5 transcript");
            assert_eq!(claim_a.run_id, run_id);

            if bad_version {
                // Pre-populate Round 1 with `model-round:1` + `turn-calls:1` at unsupported `format_version = 2`
                // (append-only via `append_event`, testing that recovery never mistakes an unknown-version
                // `turn-calls:1` row for an abandoned round).
                leases::with_lease(
                    &mut w,
                    &claim_a.lease(),
                    leases::Fence::Step,
                    async |tx, _| {
                        openmettle_core::runs::append_event(
                            tx,
                            &claim_a.scope_id,
                            &claim_a.run_id,
                            "model-round:1",
                            openmettle_core::runs::Payload {
                                format: "openmettle.model-round",
                                version: 1,
                                bytes: b"{}",
                            },
                        )
                        .await?;
                        openmettle_core::runs::append_event(
                            tx,
                            &claim_a.scope_id,
                            &claim_a.run_id,
                            "turn-calls:1",
                            openmettle_core::runs::Payload {
                                format: "openmettle.turn-calls",
                                version: 2,
                                bytes: b"{}",
                            },
                        )
                        .await?;
                        Ok(())
                    },
                )
                .await
                .unwrap();
            }

            let m_srv = SyntheticMcpServer::start(move |_| {
                let body = json!({
                    "id": "chatcmpl-r5",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_r5_0",
                                "type": "function",
                                "function": {"name": "mcp_idem", "arguments": "{\"item\":\"r5\"}"}
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}
                })
                .to_string();
                http_response(
                    200,
                    &[("content-type", "application/json")],
                    body.as_bytes(),
                )
            })
            .await;

            struct StopAtPreflight {
                inner: Arc<ExternalMcpAdapter>,
            }
            impl ApprovedAdapter for StopAtPreflight {
                fn preflight<'a>(
                    &'a self,
                    _: &'a ActiveRun,
                    _: &'a Proposal,
                    _: &'a StepContext,
                ) -> Pin<Box<dyn Future<Output = Result<(), worker::PreflightError>> + Send + 'a>>
                {
                    Box::pin(async {
                        Err(worker::PreflightError::Store(StoreError::Conflict(
                            "stop-r5",
                        )))
                    })
                }
                fn verify_turn_call_proposal(
                    &self,
                    call: &Call,
                    proposal: &Proposal,
                    expected_external_version: Option<&str>,
                ) -> bool {
                    self.inner
                        .verify_turn_call_proposal(call, proposal, expected_external_version)
                }
                fn filter_turn_tools<'a>(
                    &'a self,
                    run: &'a ActiveRun,
                    tools: Vec<DeclaredTool>,
                    step: &'a StepContext,
                ) -> Pin<Box<dyn Future<Output = Result<Vec<Tool>, StepResult>> + Send + 'a>>
                {
                    self.inner.filter_turn_tools(run, tools, step)
                }
                fn send<'a>(
                    &'a self,
                    run: &'a ActiveRun,
                    operation_id: String,
                    request: Vec<u8>,
                    step: StepContext,
                ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
                    self.inner.send(run, operation_id, request, step)
                }
            }

            let exec_a = TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                VersionSwitchRoutes {
                    gateway: make_gateway(&m_srv),
                    registry: registry.clone(),
                    propose_version: "1",
                },
            )
            .with_effects(Arc::new(ApprovedEffects {
                policy: registry.clone(),
                adapter: Arc::new(StopAtPreflight {
                    inner: adapter_r5.clone(),
                }),
            }));
            let (_st_a, step_a) = fresh_step(30);
            let active_a = ActiveRun {
                claim: claim_a.clone(),
                state: leases::ExecState::Running,
                execution_deadline: Instant::now() + Duration::from_secs(120),
            };
            assert!(matches!(
                exec_a.step(&active_a, step_a).await,
                StepResult::LeaseLost
            ));
            let prop_r5 = registry
                .proposal("call_r5_0", "mcp_idem", "1", br#"{"item":"r5"}"#)
                .unwrap();
            assert!(matches!(
                record_fenced_intent(
                    &mut w,
                    &claim_a.lease(),
                    &prop_r5,
                    None,
                    registry.as_ref(),
                    &LEASES
                )
                .await
                .unwrap(),
                IntentResult::Applied(_)
            ));

            if !bad_version {
                // Inject an out-of-bounds `turn-result:{round}:1` row on a 1-call round (`idx_case == 0`).
                let _ = idx_case;
                leases::with_lease(
                    &mut w,
                    &claim_a.lease(),
                    leases::Fence::Step,
                    async |tx, _| {
                        openmettle_core::runs::append_event(
                            tx,
                            &claim_a.scope_id,
                            &claim_a.run_id,
                            "turn-result:1:1",
                            openmettle_core::runs::Payload {
                                format: "openmettle.turn-result",
                                version: 1,
                                bytes: br#"{"call_id":"bogus","operation_id":null,"output":"x"}"#,
                            },
                        )
                        .await?;
                        Ok(())
                    },
                )
                .await
                .unwrap();
            }
            leases::release_lease(&mut w, &claim_a.lease())
                .await
                .unwrap();

            let idem_before = v1_idem_calls.load(Ordering::SeqCst);
            let claim_b = leases::reclaim_next(&mut w, &LEASES)
                .await
                .unwrap()
                .expect("reclaim r5 corrupted transcript")
                .run;
            let exec_b = TurnExecutor::new(
                worker_pool.clone(),
                catalog.clone(),
                LEASES,
                VersionSwitchRoutes {
                    gateway: make_gateway(&m_srv),
                    registry: registry.clone(),
                    propose_version: "1",
                },
            )
            .with_effects(Arc::new(adapter_r5.approved_effects()));
            let (_st_b, step_b) = fresh_step(30);
            let active_b = ActiveRun {
                claim: claim_b.clone(),
                state: leases::ExecState::Running,
                execution_deadline: Instant::now() + Duration::from_secs(120),
            };
            assert!(matches!(
                exec_b.step(&active_b, step_b).await,
                StepResult::Failed(leases::FailReason::StepFailed)
            ));
            assert_eq!(
                v1_idem_calls.load(Ordering::SeqCst),
                idem_before,
                "corrupted transcript must fail closed before dispatching pending write"
            );
            leases::settle(
                &mut w,
                &claim_b.lease(),
                &LEASES,
                Settle::Failed(leases::FailReason::StepFailed),
            )
            .await
            .unwrap();
        }
    }
}
