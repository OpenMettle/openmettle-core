//! The production reservation -> handoff -> inference path, using actual database
//! logins, a held PostgreSQL commit response and a loopback-only synthetic TLS peer.
use super::*;
use crate::{
    authz::{
        gateway::{self, Authority, Call, Reservation},
        leases::ExecState,
        runs::ClaimedRun,
    },
    model_config::{Catalog, Selection},
    provider_http::{
        BillableInference,
        gateway::{Admin, Create, Resource},
        inference::{Gateway, History, Protocol, Qualification, Request, RunStop, Timeouts},
    },
    provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
    response_barrier::{ResponseBarrier, cancel_at_response},
    runs::WriteTransaction,
    worker::ActiveRun,
};
use sqlx::{PgPool, Row};

const INSTALL: &str = "00000000-0000-4000-8000-000000000101";
const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000102";
const BUDGET: &str = "00000000-0000-4000-8000-000000000103";
const TARGET: &str = "00000000-0000-4000-8000-000000000104";
const OP: &str = "00000000-0000-4000-8000-000000000105";
const USER: &str = "synthetic-recoverable-user-key";
fn keys() -> GatewayKeys {
    GatewayKeys::new(&[("synthetic".into(), [36; 32])]).unwrap()
}
async fn id(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn recovered_user_key_dispatches_only_after_acknowledged_commits_on_each_login() {
    let mut f = Flow::new().await;
    sqlx::query(
        "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES('personal','usage_tokens',1000000),('project','usage_tokens',1000000)",
    )
    .execute(&mut f.owner)
    .await
    .unwrap();
    let actor = sessions::seed(&mut f, true, true).await;
    let credential = sessions::issue(&mut f).await;
    let (scope,approval):(String,String)=sqlx::query_as("SELECT sc.id::text,s.approval_id::text
        FROM openmettle.local_sessions s JOIN openmettle.scopes sc ON sc.personal_user_id=s.user_id WHERE s.user_id=$1::uuid")
        .bind(&actor).fetch_one(&mut f.owner).await.unwrap();
    let api = pooled::one_slot(f.db.options(API));
    let worker = pooled::one_slot(f.db.options(WORKER));
    let gateway_pool = pooled::one_slot(f.db.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&actor)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&gateway_pool)
    .await
    .unwrap();

    let create = Create {
        resource: Resource::Key,
        installation: INSTALL.into(),
        principal: PRINCIPAL.into(),
        budget: BUDGET.into(),
        target: TARGET.into(),
        operation: OP.into(),
        revision: 1,
        expected_revision: 0,
    };
    let ca = tls::Ca::new();
    let mut_record = Arc::new(Mutex::new(None::<Vec<u8>>));
    let record = mut_record.clone();
    let admin = tls::Server::start(ca.leaf(tls::HOST, false), move |r| {
        assert!(r.head.contains("authorization: Bearer synthetic-admin\r\n"));
        if r.head.starts_with("GET /admin/v1/ready ") {
            return tls::Reply::Bytes(tls::json(br#"{"ready":true}"#));
        }
        let mut record = record.lock().unwrap();
        if r.head.starts_with("PUT ") {
            assert!(record.is_none());
            let intent: Value = serde_json::from_slice(&r.body).unwrap();
            *record = Some(serde_json::to_vec(&json!({"intent":intent,"bearer":USER})).unwrap());
            return tls::Reply::Close;
        }
        tls::Reply::Bytes(
            record
                .as_deref()
                .map_or_else(|| tls::response(404, &[], b""), tls::json),
        )
    })
    .await;
    let mut client = Admin::new(
        &format!("https://{}:{}/", tls::HOST, admin.port),
        Trust::Bundle(&ca.pem()),
        &[],
        Bearer::new(b"synthetic-admin").unwrap(),
    )
    .unwrap();
    client.fixture(Arc::new(tls::loopback), true);
    let deadline = Instant::now() + Duration::from_secs(5);
    assert!(client.ensure(&create, deadline).await.is_err());
    let raw = client.ensure(&create, deadline).await.unwrap().unwrap();
    assert_eq!(admin.requests.load(Ordering::SeqCst), 5);
    let sealer = GatewaySealer::new(keys(), gateway_pool.clone());
    let (finger, e) = sealer
        .seal(
            &Context {
                installation: INSTALL,
                user_id: &actor,
                binding_id: &binding,
                principal: PRINCIPAL,
                generation: 1,
            },
            &raw,
        )
        .await
        .unwrap();
    drop(raw);
    sqlx::query("INSERT INTO openmettle.gateway_generations (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
        VALUES ($1::uuid,1,$2::uuid,clock_timestamp()+interval '1 hour',$3,$4,$5,$6)")
        .bind(&binding).bind(TARGET).bind(&e.key_id).bind(finger.as_slice()).bind(e.nonce.as_slice()).bind(e.ciphertext).execute(&gateway_pool).await.unwrap();
    sqlx::query("INSERT INTO openmettle.gateway_policy (binding_id,revision,scope_id,approval_id,model,report_source,provider_generation,approval_generation,user_generation,capabilities)
        VALUES ($1::uuid,1,$2::uuid,$3::uuid,'a',gen_random_uuid(),0,0,0,'{}')")
        .bind(&binding).bind(&scope).bind(&approval).execute(&gateway_pool).await.unwrap();
    sqlx::query("UPDATE openmettle.gateway_bindings SET state='ready',observed_revision=1,active_generation=1").execute(&gateway_pool).await.unwrap();
    let row=sqlx::query("WITH chat AS (INSERT INTO openmettle.conversations (scope_id,scope_kind,owner_user_id)
        VALUES ($1::uuid,'personal',$2::uuid) RETURNING id,scope_id), branch AS (
        INSERT INTO openmettle.conversation_branches (scope_id,conversation_id) SELECT scope_id,id FROM chat RETURNING id),
        msg AS (INSERT INTO openmettle.messages (scope_id,conversation_id) SELECT scope_id,id FROM chat RETURNING id)
        INSERT INTO openmettle.runs (scope_id,actor_user_id,conversation_id,branch_id,input_message_id,idempotency_key,snapshot_format,snapshot_version,
            input_snapshot,config_snapshot,request_identity,request_digest,actor_approval_id,round_limit,queue_expires_at,
            execution_mode,originating_session_id,admission_evidence,claim_token,claimed_at,state,lease_expires_at,execution_expires_at)
        SELECT chat.scope_id,$2::uuid,chat.id,branch.id,msg.id,'fixture','synthetic',1,'{}','{}','{}',sha256(''::bytea),$3::uuid,8,
            now()+interval '10 minutes','ordinary',$4,'{}',gen_random_uuid(),now(),'running',now()+interval '2 minutes',now()+interval '5 minutes'
        FROM chat,branch,msg RETURNING id::text,claim_token::text")
        .bind(&scope).bind(&actor).bind(&approval).bind(&credential.expose()[..43]).fetch_one(&mut f.owner).await.unwrap();
    let run: String = row.get(0);
    let lease: String = row.get(1);
    let run_hold = id(&api).await;
    let mut c = api.acquire().await.unwrap();
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    gateway::hold(
        &mut tx,
        &Reservation {
            id: &run_hold,
            scope_id: &scope,
            actor: &actor,
            approval: &approval,
        },
        Some(&run),
        100,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    drop(c);

    let catalog = Catalog::load(include_bytes!(
        "../../../../tests/fixtures/conversation-catalog-v1.json"
    ))
    .unwrap();
    let effective = catalog
        .resolve(
            &Selection::default(),
            &serde_json::from_value(json!({"model":"a"})).unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    let peer=tls::Server::start(ca.leaf(tls::HOST,false),|r|{
        assert!(r.head.starts_with("POST /v1/chat/completions "));
        assert!(r.head.contains(&format!("authorization: Bearer {USER}\r\n")));
        assert!(!r.head.contains("synthetic-admin"));
        tls::Reply::Bytes(tls::json(br#"{"choices":[{"index":0,"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}]}"#))
    }).await;
    let mut route = Gateway::new(
        &format!("https://{}:{}/v1/chat/completions", tls::HOST, peer.port),
        Trust::Bundle(&ca.pem()),
        &[],
        Qualification {
            model: "a".into(),
            pin: effective.profile.clone(),
            protocol: Protocol::Chat,
            json: true,
            sse: false,
            functions: None,
            images: false,
            parallel: false,
            usage: false,
            tool_separator_whitespace: false,
        },
        Timeouts {
            setup: Duration::from_secs(2),
            idle: Duration::from_secs(2),
            overall: Duration::from_secs(4),
        },
    )
    .unwrap();
    route.fixture_lookup(Arc::new(tls::loopback));
    let client = BillableInference {
        installation: INSTALL.into(),
        route,
    };
    let req = Request {
        history: vec![History::User("synthetic".into())],
        tools: None,
        parallel: None,
        stream: false,
    };
    let active = ActiveRun {
        claim: ClaimedRun {
            scope_id: scope.clone(),
            run_id: run.clone(),
            claim_token: lease.clone(),
            actor_approval_id: approval.clone(),
            round_limit: 8,
            lease_remaining: Duration::from_secs(30),
            execution_remaining: Duration::from_secs(60),
        },
        state: ExecState::Running,
        execution_deadline: Instant::now() + Duration::from_secs(60),
    };
    let (_stop, rx) = tokio::sync::watch::channel(None);
    for (idx, (role, pool)) in [(API, &api), (WORKER, &worker)].into_iter().enumerate() {
        if role == WORKER {
            // Logout bars caller sessions. General background inference still uses
            // the actor's current authority and the run lease (ADRs 0027 and 0035).
            sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=$1")
                .bind(&credential.expose()[..43])
                .execute(&mut f.owner)
                .await
                .unwrap();
        }
        for n in 1..=3 {
            let server = role == WORKER;
            let caller_id = id(&api).await;
            let call = Call {
                reservation: Reservation {
                    id: if server { &run_hold } else { &caller_id },
                    scope_id: &scope,
                    actor: &actor,
                    approval: &approval,
                },
                installation: INSTALL,
                model: "a",
                units: 10,
                authority: if server {
                    Authority::Lease {
                        run: &run,
                        round: n,
                        token: &lease,
                    }
                } else {
                    Authority::Session {
                        credential: credential.expose(),
                        native_audience: None,
                    }
                },
            };
            let ring = keys();
            if n < 3 {
                // The first COMMIT is the hold, the second is the handoff. In
                // each case the database committed but its ReadyForQuery is held.
                let mut barrier = ResponseBarrier::nth(b"COMMIT\0", n as usize);
                let proxy = pooled::one_slot(
                    f.db.options(role)
                        .host("127.0.0.1")
                        .port(barrier.port)
                        .ssl_mode(sqlx::postgres::PgSslMode::Disable),
                );
                cancel_at_response(&mut barrier, async {
                    let pending = gateway::reserve(&proxy, call).await.unwrap();
                    let ticket = pending.handoff(&proxy, &ring).await.unwrap();
                    client
                        .send(
                            ticket,
                            &catalog,
                            &effective,
                            &req,
                            server.then(|| RunStop::from_worker(&active, rx.clone())),
                            |_| async {},
                        )
                        .await
                        .unwrap();
                })
                .await;
                proxy.close().await;
                drop(barrier);
                assert_eq!(peer.requests.load(Ordering::SeqCst), idx);
                continue;
            }
            let pending = gateway::reserve(pool, call).await.unwrap();
            let ticket = pending.handoff(pool, &ring).await.unwrap();
            // Independent primary connection sees the committed hold and handoff
            // while the TLS peer has observed no request for this identity.
            let state: String = sqlx::query_scalar(
                "SELECT state FROM openmettle.gateway_requests WHERE id=$1::uuid",
            )
            .bind(&pending.id)
            .fetch_one(&gateway_pool)
            .await
            .unwrap();
            assert_eq!(state, "handed_off");
            assert_eq!(peer.requests.load(Ordering::SeqCst), idx);
            client
                .send(
                    ticket,
                    &catalog,
                    &effective,
                    &req,
                    server.then(|| RunStop::from_worker(&active, rx.clone())),
                    |_| async {},
                )
                .await
                .unwrap();
            assert!(
                peer.heads.lock().unwrap()[idx]
                    .contains(&format!("x-request-id: {}\r\n", pending.id))
            );
            assert!(!pending.release(pool).await.unwrap());
        }
    }
}
