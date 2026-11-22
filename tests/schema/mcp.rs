//! Scoped adapter, mixed-version repair and storage boundaries on a disposable primary.
use super::*;
use openmettle_core::{
    artifact_fs::{self, SpillContext, Store},
    mcp::{self, ScopedAdapter},
    worker::{ActiveRun, StepResult},
};
use sqlx::PgPool;

fn read_policy() -> Policy {
    Policy {
        class: EffectClass::Read,
        ..Default::default()
    }
}
fn step() -> (
    tokio::sync::watch::Sender<Option<openmettle_core::worker::Stop>>,
    StepContext,
) {
    let (stop, rx) = tokio::sync::watch::channel(None);
    (
        stop,
        StepContext {
            stop: rx,
            deadline: tokio::time::Instant::now() + Duration::from_secs(20),
            tasks: StepTasks::default().handle(),
        },
    )
}
async fn intent(f: &Fixture, r: &ClaimedRun, p: &Proposal, policy: &Policy) -> String {
    let IntentResult::Applied(i) = record_fenced_intent(
        &mut worker(&f.db).await,
        &r.lease(),
        p,
        None,
        policy,
        &LEASES,
    )
    .await
    .unwrap() else {
        panic!("expected new read intent")
    };
    i.operation_id
}
fn output(step: StepResult) -> Value {
    let StepResult::ToolOutput(s) = step else {
        panic!("expected tool output")
    };
    assert!(s.len() <= mcp::INLINE_BYTES);
    serde_json::from_str(&s).unwrap()
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn attempts_are_durable_and_authority_precedes_exhaustion() {
    let f = Fixture::new().await;
    let mut w = worker(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let policy = read_policy();
    for (key, revoked, expired) in [
        ("valid", false, false),
        ("revoked", true, false),
        ("expired", false, true),
    ] {
        let r = f.claim(key, "ordinary").await;
        let p = proposal(key);
        let op = intent(&f, &r, &p, &policy).await;
        let launch = async |w: &mut PgConnection| {
            start_replayed_read(w, &r.lease(), &op, &p, &LEASES, &policy)
                .await
                .unwrap()
        };
        let (n,expiry):(i32,i64)=sqlx::query_as("SELECT dispatched_attempts,effective_expires_us FROM openmettle.operations WHERE id=$1::uuid")
            .bind(&op).fetch_one(&mut w).await.unwrap();
        assert_eq!(n, 0);
        assert!(expiry > 0);
        for expected in 1..=3 {
            assert!(matches!(launch(&mut w).await, ReplayEffect::Ready(_)));
            assert_eq!(
                sqlx::query_scalar::<_, i32>(
                    "SELECT dispatched_attempts FROM openmettle.operations WHERE id=$1::uuid"
                )
                .bind(&op)
                .fetch_one(&mut w)
                .await
                .unwrap(),
                expected
            );
        }
        for bad in [
            "dispatched_attempts=2",
            "dispatched_attempts=NULL",
            "dispatched_attempts=4",
            "effective_expires_us=1",
        ] {
            let e = sqlx::query(AssertSqlSafe(format!(
                "UPDATE openmettle.operations SET {bad} WHERE id=$1::uuid"
            )))
            .bind(&op)
            .execute(&mut owner)
            .await
            .unwrap_err();
            assert_eq!(
                e.as_database_error().unwrap().code().as_deref(),
                Some("23514")
            );
        }
        let changed = Policy {
            revision: "changed",
            ..read_policy()
        };
        if expired {
            sqlx::query("UPDATE openmettle.local_sessions SET expires_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE id=$1")
                .bind(f.user.locator()).execute(&mut owner).await.unwrap();
        }
        let result = start_replayed_read(
            &mut w,
            &r.lease(),
            &op,
            &p,
            &LEASES,
            if revoked { &changed } else { &policy },
        )
        .await
        .unwrap();
        if revoked || expired {
            let ReplayEffect::Invalidated(leases::Settled::Terminal { state }) = result else {
                panic!("authority wins at attempt three")
            };
            assert_eq!(state, if expired { "failed" } else { "cancelled" });
            if expired {
                assert_eq!(
                    super::super::authz_runs::terminal_events(&f.db, &r.run_id).await[0].0,
                    "openmettle.run-approval-expired"
                );
            }
        } else {
            let ReplayEffect::Observed {
                succeeded: false,
                output: Some(s),
            } = result
            else {
                panic!("expected observed exhaustion")
            };
            assert_eq!(
                serde_json::from_str::<Value>(&s).unwrap()["status"],
                "tool_error"
            );
            leases::settle(&mut w, &r.lease(), &LEASES, Settle::Succeeded)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn spill_is_private_atomic_and_read_range_revalidates_cached_pages() {
    let f = Fixture::new().await;
    let r = f.claim("spill", "ordinary").await;
    let p = proposal("large");
    let policy = read_policy();
    let op = intent(&f, &r, &p, &policy).await;
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("payload"));
    std::fs::create_dir(&root).unwrap();
    Store::open(&root)
        .unwrap()
        .initialize_api(&api_pool)
        .await
        .unwrap();
    let store = Store::open(&root).unwrap();
    store.probe_writable().unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.storage_instance SET personal_limit_bytes=1000000,instance_budget_bytes=1000000").execute(&mut owner).await.unwrap();
    let (_stop, step) = step();
    let cx = SpillContext {
        pool: &worker_pool,
        lease: r.lease(),
        proposal: &p,
        operation: &op,
        step: &step,
    };
    assert!(matches!(
        start_replayed_read(
            &mut worker(&f.db).await,
            &r.lease(),
            &op,
            &p,
            &LEASES,
            &policy
        )
        .await
        .unwrap(),
        ReplayEffect::Ready(_)
    ));
    let original = format!("{}{}", "\u{001b}".repeat(6000), "雪\n".repeat(500));
    let spill =
        output(artifact_fs::publish_bytes(&cx, Some(&store), &original, &LEASES, &policy).await);
    assert_eq!(spill["storage"], "spilled");
    assert_eq!(spill["truncated"], true);
    assert!(original.starts_with(spill["head"].as_str().unwrap()));
    assert!(original.ends_with(spill["tail"].as_str().unwrap()));
    assert_eq!(
        spill,
        output(artifact_fs::publish_bytes(&cx, Some(&store), &original, &LEASES, &policy).await)
    );
    let prov = &spill["provenance"];
    let artifact = prov["artifact_id"].as_str().unwrap();
    let revision = prov["revision_id"].as_str().unwrap();
    let (actor, charged, state): (String, i64, String) = sqlx::query_as(
        "SELECT a.owner_user_id::text,s.settled_bytes,o.outcome
        FROM openmettle.artifacts a JOIN openmettle.storage_reservations s ON a.id=s.artifact_id
        JOIN openmettle.operations o ON o.id=s.operation_id WHERE o.id=$1::uuid",
    )
    .bind(&op)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(actor, f.actor.user);
    assert_eq!(charged, original.len() as i64);
    assert_eq!(state, "succeeded");
    let run = ActiveRun {
        state: leases::ExecState::Running,
        execution_deadline: step.deadline,
        claim: r.clone(),
    };
    let adapter = ScopedAdapter::new(worker_pool.clone(), store.clone(), LEASES);
    let invoke = async |key: &str, args: &[u8]| {
        adapter
            .call(&run, step.clone(), key, mcp::READ_RANGE, "1", args)
            .await
    };
    assert_eq!(
        output(invoke("reject", br#"{"max_bytes":3}"#).await)["status"],
        "tool_error"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM openmettle.operations WHERE run_id=$1::uuid"
        )
        .bind(&r.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap(),
        1
    );
    let beyond =
        json!({"artifact_id":artifact,"revision_id":revision,"offset":i64::MAX}).to_string();
    let fault = output(invoke("past-end", beyond.as_bytes()).await);
    assert_eq!(fault["status"], "tool_error");
    assert_eq!(fault["fault_code"], "semantic");
    assert_eq!(output(invoke("past-end", beyond.as_bytes()).await), fault);
    let (outcome,attempts,reservations):(String,i32,i64)=sqlx::query_as(
        "SELECT o.outcome,o.dispatched_attempts,(SELECT count(*) FROM openmettle.storage_reservations s WHERE s.operation_id=o.id)
         FROM openmettle.operations o WHERE o.run_id=$1::uuid AND logical_key='past-end'")
        .bind(&r.run_id).fetch_one(&mut owner).await.unwrap();
    assert_eq!((outcome.as_str(), attempts, reservations), ("failed", 1, 0));
    let missing =
        json!({"artifact_id":artifact,"revision_id":"00000000-0000-4000-8000-000000000011"});
    assert_eq!(
        output(invoke("missing", missing.to_string().as_bytes()).await),
        fault
    );
    let other = proposal("unconfigured");
    let other_op = intent(&f, &r, &other, &policy).await;
    let fallback = output(
        artifact_fs::publish_bytes(
            &SpillContext {
                proposal: &other,
                operation: &other_op,
                ..cx
            },
            None,
            &original,
            &LEASES,
            &policy,
        )
        .await,
    );
    assert_eq!(fallback["status"], "ok");
    assert_eq!(fallback["storage"], "truncated_no_spill");
    assert_eq!(fallback["spill_error"], "store_unconfigured");
    assert_eq!(
        fallback["provenance"]["content_sha256"],
        prov["content_sha256"]
    );
    let mut offset = 0u64;
    let mut page = 0;
    let mut first = String::new();
    loop {
        let args=json!({"artifact_id":artifact,"revision_id":revision,"max_bytes":16384,"offset":offset}).to_string();
        let key = format!("page-{page}");
        let result = output(invoke(&key, args.as_bytes()).await);
        if page == 0 {
            first = args.clone();
            assert_eq!(output(invoke(&key, args.as_bytes()).await), result);
        }
        let text = result["text"].as_str().unwrap();
        assert!(!text.is_empty());
        assert!(text.lines().count() <= 200);
        assert!(original[offset as usize..].starts_with(text));
        offset += text.len() as u64;
        assert_eq!(result["next_offset"], offset);
        if result["eof"] == true {
            break;
        }
        page += 1;
    }
    assert_eq!(offset as usize, original.len());
    sqlx::query("UPDATE openmettle.artifact_revisions SET state='retained',retained_at=clock_timestamp(),purge_after=clock_timestamp()+interval '1 day' WHERE id=$1::uuid")
        .bind(revision).execute(&mut owner).await.unwrap();
    // A fresh read of a retained revision and replay of a prior failure both stay recoverable.
    assert_eq!(output(invoke("retained", first.as_bytes()).await), fault);
    assert_eq!(output(invoke("past-end", beyond.as_bytes()).await), fault);
    assert!(matches!(
        invoke("page-0", first.as_bytes()).await,
        StepResult::Invalidated(leases::Settled::Terminal { state: "cancelled" })
    ));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn a_displaced_volume_creates_no_spill_reservation() {
    let f = Fixture::new().await;
    let r = f.claim("mount", "ordinary").await;
    let policy = read_policy();
    let proposal = proposal("displaced");
    let op = intent(&f, &r, &proposal, &policy).await;
    let pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api = PgPool::connect(&f.db.url(API)).await.unwrap();
    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("volume"));
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api).await.unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.storage_instance SET personal_limit_bytes=100000,instance_budget_bytes=100000")
        .execute(&mut owner).await.unwrap();
    std::fs::rename(root.join("staging"), root.join("original-staging")).unwrap();
    std::fs::create_dir(root.join("staging")).unwrap();
    let (_sender, step) = step();
    let cx = SpillContext {
        pool: &pool,
        lease: r.lease(),
        proposal: &proposal,
        operation: &op,
        step: &step,
    };
    let response = output(
        artifact_fs::publish_bytes(
            &cx,
            Some(&store),
            &"x".repeat(mcp::INLINE_BYTES + 1),
            &LEASES,
            &policy,
        )
        .await,
    );
    assert_eq!(response["storage"], "truncated_no_spill");
    assert_eq!(response["spill_error"], "storage_io");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM openmettle.storage_reservations WHERE operation_id=$1::uuid"
        )
        .bind(&op)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn completed_non_repeatable_writes_preserve_success_when_authority_lapses() {
    struct NonRepeatable;
    impl EffectPolicy for NonRepeatable {
        fn review(
            &self,
            scope: &str,
            run: &str,
            p: &Proposal,
        ) -> Result<Option<Review>, StoreError> {
            let mut review = Policy::default().review(scope, run, p)?;
            if let Some(r) = &mut review {
                r.endpoint_key = EndpointKey::Unsupported;
                r.authoritative_lookup = false;
            }
            Ok(review)
        }
    }
    let f = Fixture::new().await;
    let pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("volume"));
    std::fs::create_dir(&root).unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.storage_instance SET personal_limit_bytes=100000,instance_budget_bytes=100000")
        .execute(&mut owner).await.unwrap();
    let mut w = worker(&f.db).await;
    for (index, (large, expired)) in [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        let key = format!("write-{index}");
        let p = proposal(&key);
        let r = f.claim(&key, "ordinary").await;
        let parked = park(
            &mut w,
            &r.lease(),
            &StepTasks::default().handle(),
            &p,
            &NonRepeatable,
            &LEASES,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let decider = session(&f.db, &f.actor, 40 + index as u8).await;
        decide(
            &mut api(&f.db).await,
            &decider,
            &f.input(&r, &parked, HumanDecision::Approve, "approved"),
            &NonRepeatable,
        )
        .await
        .unwrap();
        let r = f.next().await.unwrap();
        let IntentResult::Applied(committed) = record_fenced_intent(
            &mut w,
            &r.lease(),
            &p,
            Some(&parked.approval_id),
            &NonRepeatable,
            &LEASES,
        )
        .await
        .unwrap() else {
            panic!("expected a committed write");
        };
        let op = committed.operation_id;
        if expired {
            sqlx::query("UPDATE openmettle.local_sessions SET expires_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE id=$1")
                .bind(decider.locator()).execute(&mut owner).await.unwrap();
        } else {
            sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=$1")
                .bind(decider.locator())
                .execute(&mut owner)
                .await
                .unwrap();
        }
        let (_sender, step) = step();
        let cx = SpillContext {
            pool: &pool,
            lease: r.lease(),
            proposal: &p,
            operation: &op,
            step: &step,
        };
        let text = if large {
            "x".repeat(mcp::INLINE_BYTES + 1)
        } else {
            "completed".into()
        };
        let result =
            artifact_fs::publish_bytes(&cx, Some(&store), &text, &LEASES, &NonRepeatable).await;
        let StepResult::Invalidated(leases::Settled::Terminal { state }) = result else {
            panic!("expected terminal invalidation without model output");
        };
        assert_eq!(state, if expired { "failed" } else { "cancelled" });
        let (capability,outcome,revision,evidence,reservations):(String,String,i64,Vec<u8>,i64) = sqlx::query_as(
            "SELECT capability,outcome,revision,evidence,(SELECT count(*) FROM openmettle.storage_reservations WHERE operation_id=o.id)
             FROM openmettle.operations o WHERE o.id=$1::uuid")
            .bind(&op).fetch_one(&pool).await.unwrap();
        assert_eq!(
            (
                capability.as_str(),
                outcome.as_str(),
                revision,
                reservations
            ),
            ("non_repeatable", "succeeded", 1, 0)
        );
        let evidence: Value = serde_json::from_slice(&evidence).unwrap();
        assert_eq!(
            evidence["storage"],
            if large {
                "truncated_no_spill"
            } else {
                "inline"
            }
        );
        if large {
            assert_eq!(evidence["spill_error"], "storage_io");
        }
        let events = super::super::authz_runs::terminal_events(&f.db, &r.run_id).await;
        assert_eq!(events.len(), 1);
        if expired {
            assert_eq!(events[0].0, "openmettle.run-approval-expired");
        } else {
            assert_eq!(
                events[0],
                (
                    "openmettle.run-cancelled".into(),
                    br#"{"reason":"revoked"}"#.to_vec()
                )
            );
        }
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn completed_calls_survive_tool_cutoff_and_cancel_but_never_commit_after_lease_loss() {
    use openmettle_core::worker::Stop;
    let f = Fixture::new().await;
    let r = f.claim("known-result", "ordinary").await;
    let pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let policy = read_policy();
    let large = "x".repeat(mcp::INLINE_BYTES + 1);
    for (key, why) in [
        ("cutoff", None),
        ("lost", Some(Stop::LeaseLost)),
        ("cancel", Some(Stop::Cancel)),
    ] {
        let p = proposal(key);
        let op = intent(&f, &r, &p, &policy).await;
        let (stop, mut step) = step();
        step.deadline = tokio::time::Instant::now();
        if why == Some(Stop::Cancel) {
            let principal = super::super::authz_store::principal(&f.db, &f.actor).await;
            queue::cancel_run(&mut api(&f.db).await, &principal, &f.scope, &r.run_id)
                .await
                .unwrap();
        }
        stop.send_replace(why);
        let result = artifact_fs::publish_bytes(
            &SpillContext {
                pool: &pool,
                lease: r.lease(),
                proposal: &p,
                operation: &op,
                step: &step,
            },
            None,
            &large,
            &LEASES,
            &policy,
        )
        .await;
        match why {
            Some(Stop::LeaseLost) => assert!(matches!(result, StepResult::LeaseLost)),
            Some(Stop::Cancel) => assert!(matches!(result, StepResult::Stopped)),
            None => assert_eq!(output(result)["storage"], "truncated_no_spill"),
            _ => unreachable!(),
        }
        let (outcome, revision): (String, i64) =
            sqlx::query_as("SELECT outcome,revision FROM openmettle.operations WHERE id=$1::uuid")
                .bind(&op)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (outcome.as_str(), revision),
            if why == Some(Stop::LeaseLost) {
                ("intent", 0)
            } else {
                ("succeeded", 1)
            }
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn migration_repairs_legacy_reads_and_api_transition_preserves_observation_identity() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..24])
        .await
        .unwrap();
    let f = Fixture::on(db).await;
    let r = f.claim("upgrade", "ordinary").await;
    let mut w = worker(&f.db).await;
    let make = async |c: &mut PgConnection, key: &str| {
        let mut tx = WriteTransaction::begin(c).await.unwrap();
        let op = durable::record_intent(
            &mut tx,
            &Intent {
                scope: &f.scope,
                run: &r.run_id,
                key,
                target: "legacy",
                capability: "repeatable_read",
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
        op
    };
    let first = make(&mut w, "pre-upgrade").await;
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.runs SET state='waiting',wait_reason='tool' WHERE id=$1::uuid")
        .bind(&r.run_id)
        .execute(&mut owner)
        .await
        .unwrap();
    migrate::apply(&f.db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let second = make(&mut w, "legacy-binary").await;
    let mut a = api(&f.db).await;
    sqlx::query("UPDATE openmettle.runs SET state='cancelled',wait_reason=NULL WHERE id=$1::uuid")
        .bind(&r.run_id)
        .execute(&mut a)
        .await
        .unwrap();
    for op in [&first, &second] {
        let key = format!("abandoned-read:{op}");
        let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
        assert_eq!(
            durable::record_observation(
                &mut tx,
                &durable::Observation {
                    scope: &f.scope,
                    run: &r.run_id,
                    operation: op,
                    key: &key,
                    expected_revision: 0,
                    outcome: "failed",
                    handle: None,
                    evidence: Payload {
                        format: "openmettle.abandoned-read",
                        version: 1,
                        bytes: br#"{"reason":"abandoned_read"}"#
                    }
                }
            )
            .await
            .unwrap(),
            1
        );
        tx.commit().await.unwrap();
    }
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM openmettle.run_events WHERE run_id=$1::uuid AND append_key LIKE 'abandoned-read:%'")
        .bind(&r.run_id).fetch_one(&mut owner).await.unwrap(),2);
    let update = sqlx::query("UPDATE openmettle.operations SET dispatched_attempts=1 WHERE false")
        .execute(&mut a)
        .await
        .unwrap_err();
    assert_eq!(
        update.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18"]
async fn spill_cleaner_owns_only_resolved_old_spills_and_never_overwrites_a_replacement() {
    use openmettle_core::storage::{self, ReservationInput};
    use std::{fs, os::unix::fs::MetadataExt};
    let f = Fixture::new().await;
    let r = f.claim("spill-cleaner", "ordinary").await;
    let policy = read_policy();
    let worker_pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    let api_pool = PgPool::connect(&f.db.url(API)).await.unwrap();
    let mut w = worker(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("storage"));
    fs::create_dir(&root).unwrap();
    let store = Store::open(&root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    sqlx::query("UPDATE openmettle.storage_instance SET personal_limit_bytes=100000,instance_budget_bytes=100000")
        .execute(&mut owner).await.unwrap();
    let mut rows = Vec::new();
    for (i, key) in ["large", "cutoff", "unbound", "foreign"]
        .into_iter()
        .enumerate()
    {
        let p = proposal(key);
        let op = intent(&f, &r, &p, &policy).await;
        let artifact: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut w)
            .await
            .unwrap();
        let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
        let id = storage::reserve(
            &mut tx,
            &ReservationInput {
                scope: &f.scope,
                actor: &f.actor.user,
                key: &format!("tool-spill:{op}:{artifact}"),
                artifact: &artifact,
                max_bytes: 20,
                run: Some(&r.run_id),
                operation: Some(&op),
            },
        )
        .await
        .unwrap()
        .id;
        tx.commit().await.unwrap();
        let staging = root.join("staging").join(&id);
        let rev = root.join("revisions").join(&id);
        if i != 2 {
            fs::write(&staging, b"original").unwrap();
            let ino = fs::metadata(&staging).unwrap().ino();
            sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,payload_ino=$2::text::numeric,publish_pending=true WHERE id=$1::uuid")
                .bind(&id).bind(ino.to_string()).execute(&mut owner).await.unwrap();
            if i == 3 {
                fs::write(&rev, b"foreign").unwrap();
            } else {
                fs::hard_link(&staging, &rev).unwrap();
            }
        }
        if i != 1 {
            let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
            durable::record_observation(
                &mut tx,
                &durable::Observation {
                    scope: &f.scope,
                    run: &r.run_id,
                    operation: &op,
                    key: &format!("observed:{op}"),
                    expected_revision: 0,
                    outcome: "failed",
                    handle: None,
                    evidence: Payload {
                        format: "fixture",
                        version: 1,
                        bytes: b"failed",
                    },
                },
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        rows.push(id);
    }
    assert_eq!(
        artifact_fs::reconcile_run_spills(&worker_pool, &store, Duration::from_secs(900), 100)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        artifact_fs::reconcile_expired(&worker_pool, &store, Duration::ZERO, 100)
            .await
            .unwrap(),
        0
    );
    assert!(
        artifact_fs::reconcile_run_spills(&worker_pool, &store, Duration::ZERO, 100)
            .await
            .is_err()
    );
    for (i, id) in rows.iter().enumerate() {
        let (state,bad):(String,bool)=sqlx::query_as("SELECT state,adoption_unverified FROM openmettle.storage_reservations WHERE id=$1::uuid")
            .bind(id).fetch_one(&mut w).await.unwrap();
        assert_eq!(
            state,
            if i == 1 || i == 3 {
                "reserved"
            } else {
                "released"
            }
        );
        assert_eq!(bad, i == 3);
        let rev = root.join("revisions").join(id);
        if i == 3 {
            assert_eq!(fs::read(rev).unwrap(), b"foreign");
        } else if i == 1 {
            assert_eq!(fs::read(rev).unwrap(), b"original");
        } else {
            assert!(!rev.exists());
        }
    }
}
