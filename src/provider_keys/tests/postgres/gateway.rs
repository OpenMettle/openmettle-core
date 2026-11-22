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
    backfill_after_cancellation(&mut f, &gateway_pool, &run).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn reconciliation_discovers_redemption_and_fences_inflight_renewal_on_grant_loss() {
    use gateway::reconcile::{Profile, Sweep};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;
    let mut f = Flow::new().await;
    let g = pooled::one_slot(f.db.options(pg::GATEWAY));
    let replica = pooled::one_slot(f.db.options(pg::GATEWAY));
    let sealer = GatewaySealer::new(keys(), g.clone());
    let ca = tls::Ca::new();
    let records = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
    let remote = records.clone();
    let renew = Arc::new(Notify::new());
    let allow_reply = Arc::new(Notify::new());
    let entered = renew.clone();
    let resume = allow_reply.clone();
    let drop_first = AtomicBool::new(true);
    let watermark = Mutex::new(0_i64);
    let readiness = Arc::new(AtomicBool::new(true));
    let remote_ready = readiness.clone();
    let directory = Arc::new(Mutex::new(
        json!({"installation":INSTALL,"revision":1,"children":[],"more":false}),
    ));
    let family = directory.clone();
    let peer=tls::Server::start(ca.leaf(tls::HOST,false),move |r|{
        let line:Vec<_>=r.head.lines().next().unwrap().split_whitespace().collect();
        if line[1]==format!("/admin/v1/family/{INSTALL}?page=1&limit=64") {
            return tls::Reply::Bytes(tls::json(&serde_json::to_vec(&*family.lock().unwrap()).unwrap()));
        }
        if line[1]=="/admin/v1/ready" {
            return tls::Reply::Bytes(if remote_ready.load(Ordering::SeqCst){tls::json(br#"{"ready":true}"#)}else{tls::response(503,&[("retry-after","1")],b"")});
        }
        let path=line[1].strip_prefix("/admin/v1/operations/").unwrap();
        let mut db=remote.lock().unwrap();
        if line[0]=="GET" {
            return tls::Reply::Bytes(db.get(path).map_or_else(||tls::response(404,&[],b""),|v|tls::json(&serde_json::to_vec(v).unwrap())));
        }
        assert_eq!(line[0],"PUT");
        let m:Value=serde_json::from_slice(&r.body).unwrap();
        assert_eq!(m["operation"],path);
        assert!(r.head.contains("if-none-match: *\r\n"));
        let rev=m["revision"].as_i64().unwrap();
        let expected=m["expected_revision"].as_i64().unwrap();
        let mut fence=watermark.lock().unwrap();
        let first=matches!(m["action"].as_str(),Some("principal"|"suspend"));
        if (first && *fence>expected) || (!first && (*fence!=expected || *fence!=rev)) {
            return tls::Reply::Bytes(tls::response(409,&[],b"stale operation"));
        }
        *fence=rev;
        let is_key=matches!(m["action"].as_str(),Some("issue"|"renew"|"rotate"));
        let reply=json!({"applied":m,"bearer":is_key.then_some(USER),"expires_ms":is_key.then_some(4102444800000_i64)});
        assert!(db.insert(path.into(),reply).is_none());
        if m["action"]=="issue" && drop_first.swap(false,Ordering::SeqCst){return tls::Reply::Close;}
        if m["action"]=="renew"{entered.notify_one();return tls::Reply::Gate(resume.clone(),tls::response(201,&[],b""));}
        tls::Reply::Bytes(tls::response(201,&[],b""))
    }).await;
    let mut admin = Admin::new(
        &format!("https://{}:{}/", tls::HOST, peer.port),
        Trust::Bundle(&ca.pem()),
        &[],
        Bearer::new(b"fixture-gateway-admin").unwrap(),
    )
    .unwrap();
    admin.fixture(Arc::new(tls::loopback), true);
    let mut config: Value = serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/conversation-catalog-v1.json"
    ))
    .unwrap();
    for model in config["models"].as_object_mut().unwrap().values_mut() {
        model["required_capabilities"] = json!({"inference":"opt_in"});
    }
    let catalog = Catalog::load(&serde_json::to_vec(&config).unwrap()).unwrap();
    let families = Default::default();
    let mut profile = Profile {
        installation: INSTALL,
        report_source: TARGET,
        revision: 1,
        rotation_epoch: 0,
        renew_before: Duration::from_secs(60),
        catalog: &catalog,
        families: &families,
    };
    let until = || Instant::now() + Duration::from_secs(20);
    let code = invitations::invite(&f);
    let mut s = Sweep::default();
    assert_eq!(
        s.page(&g, &admin, &sealer, &profile, 16, until())
            .await
            .unwrap(),
        0
    );
    let provider = f.h.provider.clone();
    let (_, proof) = f.exchanged_with(&provider, Some(&code)).await;
    let credential = provider
        .issue_session(
            &mut f.issuance,
            &mut f.api,
            proof,
            &sessions::session_policy(),
        )
        .await
        .unwrap();
    let (actor,approval,scope):(String,String,String)=sqlx::query_as("SELECT s.user_id::text,s.approval_id::text,sc.id::text
        FROM openmettle.local_sessions s JOIN openmettle.scopes sc ON sc.personal_user_id=s.user_id WHERE s.id=$1")
        .bind(&credential.expose()[..43]).fetch_one(&mut f.owner).await.unwrap();
    assert_eq!(
        s.page(&g, &admin, &sealer, &profile, 16, until())
            .await
            .unwrap(),
        0
    );
    sqlx::query("INSERT INTO openmettle.user_capability_grants(user_id,capability,granted,updated_by_user_id)
        VALUES ($1::uuid,'inference',true,$1::uuid)").bind(&actor).execute(&mut f.owner).await.unwrap();
    let mut s2 = Sweep::default();
    let (a, b) = tokio::join!(
        s.page(&g, &admin, &sealer, &profile, 16, until()),
        s2.page(&replica, &admin, &sealer, &profile, 16, until())
    );
    a.unwrap();
    b.unwrap();
    assert!(sqlx::query_scalar::<_,bool>("SELECT due_at<now()+interval '1 minute' FROM openmettle.gateway_intents WHERE action='issue'").fetch_one(&g).await.unwrap());
    // Let the restarted replica recover the immutable issue receipt after the lost reply.
    sqlx::query("UPDATE openmettle.gateway_intents SET due_at=now() WHERE NOT complete")
        .execute(&g)
        .await
        .unwrap();
    s2.page(&replica, &admin, &sealer, &profile, 16, until())
        .await
        .unwrap();
    let state = || {
        sqlx::query_as::<_, (String, String, i64)>(
            "SELECT state,budget::text,desired_revision FROM openmettle.gateway_bindings",
        )
        .fetch_one(&g)
    };
    let (ready, budget, rev) = state().await.unwrap();
    assert_eq!((ready.as_str(), rev), ("ready", 1));
    assert_eq!(records.lock().unwrap().len(), 5);
    sqlx::query("INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit) VALUES('personal','usage_tokens',1000000)").execute(&mut f.owner).await.unwrap();
    f.owner.execute("UPDATE openmettle.quota_defaults SET hard_limit=1000,cost_denomination='credits' WHERE scope_kind='instance' AND resource_kind='usage_cost_micros'").await.unwrap();
    f.owner.execute("INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit) VALUES('personal','usage_cost_micros',100)").await.unwrap();
    let api = pooled::one_slot(f.db.options(API));
    let reservation = id(&api).await;
    let call = Call {
        reservation: Reservation {
            id: &reservation,
            scope_id: &scope,
            actor: &actor,
            approval: &approval,
        },
        installation: INSTALL,
        model: "a",
        units: 100,
        authority: Authority::Session {
            credential: credential.expose(),
            native_audience: None,
        },
    };
    let pending = gateway::reserve_with_cost(&api, call, Some(40))
        .await
        .unwrap();
    pending.handoff(&api, &keys()).await.unwrap();

    // An explicit rotation keeps the budget and retires the identified predecessor.
    profile.rotation_epoch = 1;
    profile.revision += 1;
    s.page(&g, &admin, &sealer, &profile, 16, until())
        .await
        .unwrap();
    assert_eq!(state().await.unwrap(), ("ready".into(), budget.clone(), 2));
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM openmettle.gateway_audit WHERE step='revoke' AND outcome='confirmed'").fetch_one(&g).await.unwrap(),1);
    let no_send_id = id(&api).await;
    let no_send = gateway::reserve_with_cost(
        &api,
        Call {
            reservation: Reservation {
                id: &no_send_id,
                scope_id: &scope,
                actor: &actor,
                approval: &approval,
            },
            installation: INSTALL,
            model: "a",
            units: 100,
            authority: Authority::Session {
                credential: credential.expose(),
                native_audience: None,
            },
        },
        Some(10),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.gateway_generations SET expires_at=now()+interval '45 seconds' WHERE generation=2").execute(&g).await.unwrap();
    let lose_grant = async {
        tokio::time::timeout(Duration::from_secs(10), renew.notified())
            .await
            .unwrap();
        sqlx::query("UPDATE openmettle.user_capability_grants SET granted=false")
            .execute(&mut f.owner)
            .await
            .unwrap();
        assert!(matches!(
            no_send.handoff(&api, &keys()).await,
            Err(gateway::Error::Refused)
        ));
        allow_reply.notify_one();
    };
    let (work, ()) = tokio::join!(
        s.page(&g, &admin, &sealer, &profile, 16, until()),
        lose_grant
    );
    work.unwrap();
    assert_eq!(
        state().await.unwrap(),
        ("revoked".into(), budget.clone(), 4)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM openmettle.gateway_generations WHERE generation=3"
        )
        .fetch_one(&g)
        .await
        .unwrap(),
        0
    );
    assert!(no_send.release(&api).await.unwrap());

    sqlx::query("UPDATE openmettle.user_capability_grants SET granted=true")
        .execute(&mut f.owner)
        .await
        .unwrap();
    s2.page(&replica, &admin, &sealer, &profile, 16, until())
        .await
        .unwrap();
    assert_eq!(state().await.unwrap(), ("ready".into(), budget.clone(), 5));
    sqlx::query("UPDATE openmettle.users SET disabled_at=now()")
        .execute(&mut f.owner)
        .await
        .unwrap();
    readiness.store(false, Ordering::SeqCst);
    let before = records.lock().unwrap().len();
    s.page(&g, &admin, &sealer, &profile, 16, until())
        .await
        .unwrap();
    assert_eq!(
        state().await.unwrap(),
        ("suspended".into(), budget.clone(), 6)
    );
    assert_eq!(records.lock().unwrap().len(), before);
    readiness.store(true, Ordering::SeqCst);
    sqlx::query("UPDATE openmettle.gateway_intents SET due_at=now() WHERE NOT complete")
        .execute(&g)
        .await
        .unwrap();
    s2.page(&replica, &admin, &sealer, &profile, 16, until())
        .await
        .unwrap();
    assert_eq!(state().await.unwrap(), ("revoked".into(), budget, 6));
    // A new gateway-owned restriction arrives without an application configuration change.
    sqlx::query("UPDATE openmettle.users SET disabled_at=NULL")
        .execute(&mut f.owner)
        .await
        .unwrap();
    *directory.lock().unwrap() = json!({"installation":INSTALL,"revision":2,"more":false,"children":[{"user":actor,
        "policy":{"revision":3,"zone":"Europe/London","quiet":null,"study":null,"study_models":[],"disabled_models":["a"]}}]});
    s.page(&g, &admin, &sealer, &profile, 16, until())
        .await
        .unwrap();
    let models: Vec<String> = sqlx::query_scalar(
        "SELECT pol.model FROM openmettle.gateway_policy pol JOIN openmettle.gateway_bindings b
        ON b.id=pol.binding_id AND b.observed_revision=pol.revision ORDER BY pol.model",
    )
    .fetch_all(&g)
    .await
    .unwrap();
    assert!(!models.is_empty() && !models.iter().any(|m| m == "a"));
    let principal: String =
        sqlx::query_scalar("SELECT principal::text FROM openmettle.gateway_bindings")
            .fetch_one(&g)
            .await
            .unwrap();
    let report = crate::provider_http::gateway::UsageReport {
        request: pending.id,
        installation: INSTALL.into(),
        principal,
        scope,
        source: TARGET.into(),
        report_id: id(&g).await,
        revision: 1,
        r#final: false,
        prompt_tokens: Some(20),
        completion_tokens: Some(10),
        reasoning_tokens: Some(5),
        reasoning_included: Some(true),
        cost: None,
        unit: None,
    };
    check_usage(&g, &replica, &mut f, report).await;
}

async fn check_usage(
    g: &PgPool,
    replica: &PgPool,
    f: &mut Flow,
    mut r: crate::provider_http::gateway::UsageReport,
) {
    use gateway::settlement::{Outcome::*, ingest};
    let (a, b) = tokio::join!(ingest(g, &r), ingest(replica, &r));
    assert!(matches!(
        (a.unwrap(), b.unwrap()),
        (Applied, Duplicate) | (Duplicate, Applied)
    ));
    let balances = || {
        sqlx::query_as::<_,(Option<String>,i64,String,i64)>("SELECT s.measured::text,s.outstanding,h.settled_units::text,h.held_units
         FROM openmettle.gateway_settlements s JOIN openmettle.quota_reservations h ON h.gateway_request_id=s.request_id AND h.resource_kind='usage_tokens'").fetch_one(g)
    };
    assert_eq!(
        balances().await.unwrap(),
        (Some("30".into()), 70, "30".into(), 70)
    );
    let mut invalid = r.clone();
    invalid.cost = Some("1".into());
    invalid.unit = Some("credits".into());
    assert_eq!(ingest(g, &invalid).await, Err(gateway::Error::Conflict));
    invalid.source = id(g).await;
    assert_eq!(ingest(g, &invalid).await, Err(gateway::Error::Refused));
    invalid.source = r.source.clone();
    invalid.scope = id(g).await;
    assert_eq!(ingest(g, &invalid).await, Err(gateway::Error::Refused));
    // Fold retains the missing prompt and the held balance across partial observations.
    r.revision = 2;
    r.prompt_tokens = None;
    r.completion_tokens = Some(25);
    r.reasoning_tokens = None;
    assert_eq!(ingest(g, &r).await, Ok(Applied));
    assert_eq!(
        balances().await.unwrap(),
        (Some("25".into()), 55, "45".into(), 55)
    );
    let cost = || {
        sqlx::query_as::<_,(String,i64)>("SELECT settled_units::text,held_units FROM openmettle.quota_reservations WHERE resource_kind='usage_cost_micros' AND gateway_request_id=$1::uuid").bind(r.request.clone()).fetch_one(g)
    };
    assert_eq!(cost().await.unwrap(), ("0".into(), 40));
    r.cost = Some("12.123456789012".into());
    r.unit = Some("foreign".into());
    r.revision = 4;
    assert_eq!(ingest(g, &r).await, Err(gateway::Error::Refused));
    r.unit = Some("credits".into());
    r.revision = 4;
    r.r#final = true;
    r.completion_tokens = None;
    assert_eq!(ingest(g, &r).await, Ok(Applied));
    assert_eq!(balances().await.unwrap(), (None, 55, "45".into(), 55));
    assert_eq!(cost().await.unwrap(), ("13".into(), 0));
    for rev in [3, 5] {
        r.revision = rev;
        r.r#final = false;
        assert_eq!(ingest(g, &r).await, Ok(Superseded));
    }
    r.r#final = true;
    r.revision = 6;
    r.prompt_tokens = Some(i64::MAX);
    r.completion_tokens = Some(i64::MAX);
    r.reasoning_tokens = Some(i64::MAX);
    r.reasoning_included = Some(false);
    assert_eq!(ingest(replica, &r).await, Ok(Applied));
    let wide = (i128::from(i64::MAX) * 3).to_string();
    assert_eq!(balances().await.unwrap(), (Some(wide.clone()), 0, wide, 0));
    r.revision = 7;
    r.cost = Some("0".into());
    r.prompt_tokens = Some(0);
    r.completion_tokens = Some(0);
    r.reasoning_tokens = Some(0);
    assert_eq!(ingest(g, &r).await, Ok(Applied));
    assert_eq!(ingest(replica, &r).await, Ok(Duplicate));
    assert_eq!(
        balances().await.unwrap(),
        (Some("0".into()), 0, "0".into(), 0)
    );
    assert_eq!(cost().await.unwrap(), ("0".into(), 0));
    let drift:(i64,i64,i64,i64)=sqlx::query_as("SELECT storage_mismatches,budget_mismatches,settlement_mismatches,pending_gateway_reconciliations FROM openmettle.quota_verify_accounting_drift()")
        .fetch_one(&mut f.owner).await.unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}

/// Exercise the same production handoffs after the caller and executor have returned.
async fn backfill_after_cancellation(f: &mut Flow, g: &PgPool, run: &str) {
    use crate::provider_http::gateway::UsageReport;
    use gateway::settlement::{Backfill, Outcome, ingest};
    use std::collections::HashMap;
    let rows:Vec<(String,String,String,String,bool)>=sqlx::query_as("SELECT q.id::text,q.scope_id::text,q.report_source::text,b.principal::text,q.run_id IS NOT NULL
        FROM openmettle.gateway_requests q JOIN openmettle.gateway_bindings b ON q.binding_id=b.id
        WHERE q.state='handed_off' ORDER BY q.created_at,q.id")
        .fetch_all(g).await.unwrap();
    assert!(rows.len() >= 2);
    let mut reports = HashMap::new();
    let mut run_report = None;
    for (request, scope, source, principal, is_run) in rows {
        let r = UsageReport {
            request: request.clone(),
            scope,
            principal,
            source,
            installation: INSTALL.into(),
            revision: 2,
            report_id: id(g).await,
            r#final: true,
            prompt_tokens: Some(4),
            completion_tokens: Some(3),
            reasoning_tokens: None,
            reasoning_included: None,
            cost: None,
            unit: None,
        };
        if is_run {
            run_report = Some(r.clone());
        }
        reports.insert(request, r);
    }
    let r = run_report.unwrap();
    let mut cancel = pooled::one_slot(f.db.options(API)).acquire().await.unwrap();
    let actor: String =
        sqlx::query_scalar("SELECT actor_user_id::text FROM openmettle.runs WHERE id=$1::uuid")
            .bind(run)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let approval: String =
        sqlx::query_scalar("SELECT actor_approval_id::text FROM openmettle.runs WHERE id=$1::uuid")
            .bind(run)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let now = crate::sessions::now(&mut f.api).await.unwrap();
    let principal = crate::authz::store::hydrate_api_principal(&mut cancel, &actor, &approval, now)
        .await
        .unwrap()
        .unwrap();
    let mut barrier = ResponseBarrier::nth(b"COMMIT\0", 1);
    let proxy = pooled::one_slot(
        f.db.options(pg::GATEWAY)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable),
    );
    let ((), cancelled) = tokio::join!(
        cancel_at_response(&mut barrier, async {
            ingest(&proxy, &r).await.unwrap();
        }),
        crate::authz::runs::cancel_run(&mut cancel, &principal, &r.scope, run)
    );
    cancelled.unwrap();
    drop(barrier);
    proxy.close().await;
    assert_eq!(ingest(g, &r).await, Ok(Outcome::Duplicate));
    let total = reports.len() as i64;
    let served = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let available = served.clone();
    let ca = tls::Ca::new();
    let peer = tls::Server::start(ca.leaf(tls::HOST, false), move |r| {
        let line = r.head.lines().next().unwrap();
        let request = line
            .strip_prefix("GET /admin/v1/usage/")
            .unwrap()
            .strip_suffix(" HTTP/1.1")
            .unwrap();
        if !available.load(Ordering::SeqCst) {
            return tls::Reply::Bytes(tls::response(404, &[], b""));
        }
        tls::Reply::Bytes(tls::json(&serde_json::to_vec(&reports[request]).unwrap()))
    })
    .await;
    let mut admin = Admin::new(
        &format!("https://{}:{}/", tls::HOST, peer.port),
        Trust::Bundle(&ca.pem()),
        &[],
        Bearer::new(b"fixture-reporting-profile").unwrap(),
    )
    .unwrap();
    admin.fixture(Arc::new(tls::loopback), true);
    let until = || Instant::now() + Duration::from_secs(5);
    let mut backfill = Backfill::default();
    assert_eq!(
        backfill.page(g, &admin, INSTALL, 1, until()).await.unwrap(),
        1
    );
    served.store(true, Ordering::SeqCst);
    let mut restart = Backfill::default();
    for _ in 0..total {
        restart.page(g, &admin, INSTALL, 1, until()).await.unwrap();
    }
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM openmettle.gateway_settlements WHERE final AND outstanding=0 AND measured=7").fetch_one(g).await.unwrap(),total);
    let drift:(i64,i64,i64,i64)=sqlx::query_as("SELECT storage_mismatches,budget_mismatches,settlement_mismatches,pending_gateway_reconciliations FROM openmettle.quota_verify_accounting_drift()")
        .fetch_one(&mut f.owner).await.unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}

#[tokio::test]
async fn qualified_inference_decodes_policy_only_on_pinned_evidence() {
    let (capture, _guard) = crate::telemetry::tests::Capture::install(
        crate::telemetry::Format::Json,
        crate::telemetry::Verbosity::Debug,
    );
    use crate::authz::gateway::problem::{Cause, Problem};
    use crate::provider_http::inference::{Credential, Error};
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
    let ca = tls::Ca::new();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let peer = tls::Server::start(ca.leaf(tls::HOST, false), move |r| {
        assert!(r.head.starts_with("POST /v1/chat/completions "));
        let n = next.fetch_add(1, Ordering::SeqCst);
        let (code, headers) = match n {
            0 => (403, vec![("openmettle-policy-refusal", "family-policy-v1")]),
            1 => (403, vec![("x-error", "child-synthetic")]),
            2 => (401, vec![("openmettle-policy-refusal", "family-policy-v1")]),
            3 => (502, vec![]),
            4 => (503, vec![]),
            5 => (504, vec![]),
            6 => (429, vec![("retry-after", "3")]),
            7 => (429, vec![("retry-after", "86401")]),
            _ => (200, vec![("content-type", "application/json")]),
        };
        tls::Reply::Bytes(tls::response(
            code,
            &headers,
            b"synthetic-child-token-url-prompt",
        ))
    })
    .await;
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
            overall: Duration::from_secs(3),
        },
    )
    .unwrap()
    .with_family_policy_v1();
    route.fixture_lookup(Arc::new(tls::loopback));
    let req = Request {
        history: vec![History::User("synthetic".into())],
        tools: None,
        parallel: None,
        stream: false,
    };
    for expected in [
        Problem::Policy,
        Problem::Failure(Cause::Unknown),
        Problem::Failure(Cause::Unknown),
        Problem::Failure(Cause::Protocol),
        Problem::Unavailable,
        Problem::Timeout,
        Problem::RateLimited(Some(3)),
        Problem::RateLimited(None),
        Problem::Failure(Cause::Protocol),
    ] {
        let e = route
            .caller(
                &catalog,
                &effective,
                &req,
                Credential::Bearer(USER),
                |_| async {},
            )
            .await
            .err()
            .unwrap();
        assert_eq!(e, Error::Gateway(expected));
        assert_eq!(e.problem(), expected.public());
        assert!(
            !e.stream_error(Protocol::Chat)
                .to_string()
                .contains("synthetic")
        );
    }
    assert_eq!(peer.requests.load(Ordering::SeqCst), 9);
    let failures = capture.events("gateway.failed");
    assert_eq!(failures.len(), 7);
    assert_eq!(failures[0]["gateway.step"], "policy");
    assert_eq!(failures[0]["error.type"], "policy");
    assert_eq!(failures[1]["error.type"], "unknown");
    capture.assert_absent(&[
        USER.as_bytes(),
        tls::HOST.as_bytes(),
        b"synthetic-child-token-url-prompt",
        b"child-synthetic",
        b"/v1/chat/completions",
    ]);
}
