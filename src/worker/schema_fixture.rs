//! Worker process for the schema suite. Only the library test binary has the adapter's
//! loopback DNS fixture. Production transport never accepts a loopback gateway.
use super::*;
use crate::provider_http::{
    Trust,
    fixture::loopback,
    inference::{Protocol, Qualification, Timeouts},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::BufRead,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Deserialize)]
struct MeteredSetup {
    installation: String,
    #[serde(default)]
    device_grant_id: Option<String>,
}

#[derive(Deserialize)]
struct Setup {
    database: String,
    catalog: Value,
    actor: String,
    scope: String,
    port: u16,
    ca: String,
    tools: bool,
    artifacts: Option<std::path::PathBuf>,
    stop_during_observation: bool,
    #[serde(default)]
    metered: Option<MeteredSetup>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    parallel: bool,
    #[serde(default)]
    tool_separator_whitespace: bool,
    #[serde(default)]
    recorded_tools: bool,
    #[serde(default)]
    pause_after_first_tool_lock: Option<i64>,
}

struct Routes {
    gateways: BTreeMap<String, Arc<Gateway>>,
    scope: String,
    actor: String,
    metered: Option<MeteredSetup>,
    stream: bool,
    recorded_tools: bool,
}
impl TurnRoutes for Routes {
    async fn route(
        &self,
        claim: &ClaimedRun,
        actor: &str,
        model: &Effective,
    ) -> Result<Route, inference::Error> {
        if claim.scope_id != self.scope || actor != self.actor {
            return Err(inference::Error::Credential);
        }
        let gateway = self
            .gateways
            .get(&model.model)
            .ok_or(inference::Error::Provisioning)?
            .clone();
        if let Some(metered) = &self.metered {
            let mut route = Route::metered(gateway, metered.installation.clone(), self.stream);
            if let Some(grant) = &metered.device_grant_id {
                route = route.with_device_grant(grant.clone());
            }
            Ok(route)
        } else {
            Ok(Route::bearer(
                gateway,
                "synthetic-turn-credential".into(),
                self.stream,
            ))
        }
    }
    fn tools(&self, _: &ClaimedRun) -> Vec<Tool> {
        if self.recorded_tools {
            let params = serde_json::json!({
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"]
            });
            return vec![
                Tool {
                    name: "get_weather".into(),
                    description: "Get the weather for a city".into(),
                    parameters: params.clone(),
                },
                Tool {
                    name: "get_time".into(),
                    description: "Get the local time for a city".into(),
                    parameters: params,
                },
            ];
        }
        vec![Tool {
            name: "lookup".into(),
            description: "Read a synthetic value".into(),
            parameters: serde_json::json!({"type":"object","properties":{},"additionalProperties":false}),
        }]
    }
    fn tool_prompt_bound(&self, _: &Effective, request: &Request) -> Option<u64> {
        // The fixture offers short-argument tools with fixed short results. Bound
        // the synthetic template only for the short transcripts exercised by the suite.
        (request.history.len() <= 16).then_some(4096)
    }
    fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
        let resource = if call.name == "lookup" {
            "sample"
        } else {
            call.name.as_str()
        };
        Proposal::new(
            &call.id,
            &call.name,
            "1",
            &serde_json::to_vec(&call.arguments).ok()?,
            approvals::Destination {
                connection: "fixture",
                account: "test",
                action: "read",
                resource,
            },
        )
        .ok()
    }
}

struct Lookup {
    pool: PgPool,
    shutdown: Option<Arc<tokio::sync::Notify>>,
    recorded_tools: bool,
    pause_after_first_tool_lock: Option<i64>,
    completed: AtomicUsize,
}
impl EffectPolicy for Lookup {
    fn review(&self, _: &str, _: &str, p: &Proposal) -> Result<Option<Review>, StoreError> {
        let valid = if self.recorded_tools {
            matches!(p.tool.as_str(), "get_weather" | "get_time")
                && p.version == "1"
                && p.arguments().as_object().is_some_and(|m| {
                    m.len() == 1 && m.get("city").and_then(Value::as_str).is_some()
                })
                && p.destination() == format!(r#"["v1","fixture","test","read","{}"]"#, p.tool)
        } else {
            p.tool == "lookup"
                && p.version == "1"
                && p.arguments() == &serde_json::json!({})
                && p.destination() == r#"["v1","fixture","test","read","sample"]"#
        };
        Ok(valid.then(|| Review {
            class: approvals::EffectClass::Read,
            capability: format!("tool.{}", p.tool),
            gate: crate::authz::CapabilityGate::OnByDefault,
            tool_policy: "1".into(),
            destination_policy: "1".into(),
            endpoint_id: "fixture".into(),
            endpoint_version: "1".into(),
            endpoint_key: approvals::EndpointKey::Unsupported,
            authoritative_lookup: false,
            artifact: None,
            reservation: None,
        }))
    }
}
impl ApprovedAdapter for Lookup {
    fn send<'a>(
        &'a self,
        run: &'a ActiveRun,
        op: String,
        _: Vec<u8>,
        mut step: StepContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
        Box::pin(async move {
            let mut c = self.pool.acquire().await.unwrap();
            let lease = run.claim.lease();
            let target: String = sqlx::query_scalar(
                "SELECT target FROM openmettle.operations
                  WHERE scope_id = $1::uuid AND run_id = $2::uuid AND id = $3::uuid",
            )
            .bind(lease.scope_id)
            .bind(lease.run_id)
            .bind(&op)
            .fetch_one(&mut *c)
            .await
            .unwrap();
            let obs_key = format!("fixture-result:{op}");
            let output = if target == r#"["v1","fixture","test","read","get_weather"]"# {
                "weather:Paris".to_owned()
            } else if target == r#"["v1","fixture","test","read","get_time"]"# {
                "time:Paris".to_owned()
            } else {
                "registered result".to_owned()
            };
            leases::with_lease(&mut c, &lease, Fence::Hold, async |tx, _| {
                record_observation(
                    tx,
                    &Observation {
                        scope: lease.scope_id,
                        run: lease.run_id,
                        operation: &op,
                        key: &obs_key,
                        expected_revision: 0,
                        outcome: "succeeded",
                        handle: None,
                        evidence: Payload {
                            format: "fixture.observed",
                            version: 1,
                            bytes: b"{}",
                        },
                    },
                )
                .await?;
                if let Some(shutdown) = &self.shutdown {
                    // Request shutdown while this write is still uncommitted.
                    shutdown.notify_one();
                    step.stop.wait_for(Option::is_some).await.unwrap();
                }
                Ok(())
            })
            .await
            .unwrap();
            if let Some(lock_key) = self.pause_after_first_tool_lock
                && self.completed.fetch_add(1, Ordering::SeqCst) == 0
            {
                sqlx::query("SELECT pg_advisory_lock($1)")
                    .bind(lock_key)
                    .execute(&mut *c)
                    .await
                    .unwrap();
                sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(lock_key)
                    .execute(&mut *c)
                    .await
                    .unwrap();
            }
            if step.stop.borrow().is_some() {
                StepResult::Stopped
            } else {
                StepResult::ToolOutput(output)
            }
        })
    }
}

#[tokio::test]
#[ignore = "child worker driven by tests/schema/worker_leases.rs"]
async fn worker_process() {
    if std::env::var_os("OPENMETTLE_TEST_TURN_WORKER").is_none() {
        return;
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    let setup: Setup = serde_json::from_str(&line).expect("schema worker setup");
    let catalog = Arc::new(Catalog::load(&serde_json::to_vec(&setup.catalog).unwrap()).unwrap());
    let mut gateways = BTreeMap::new();
    for model in catalog.models().keys() {
        let (protocol, path) = if model == "b" {
            (Protocol::Responses, "/v1/responses")
        } else {
            (Protocol::Chat, "/v1/chat/completions")
        };
        let mut gateway = Gateway::new(
            &format!("https://provider.example.test:{}{path}", setup.port),
            Trust::Bundle(setup.ca.as_bytes()),
            &[],
            Qualification {
                model: model.clone(),
                pin: catalog.model(model).unwrap().pin.clone(),
                protocol,
                json: !setup.stream,
                sse: setup.stream,
                functions: Some(inference::SchemaSubset::Flat),
                images: setup.artifacts.is_some(),
                parallel: setup.parallel,
                usage: true,
                tool_separator_whitespace: setup.tool_separator_whitespace,
            },
            Timeouts {
                setup: Duration::from_secs(5),
                idle: Duration::from_secs(45),
                overall: Duration::from_secs(50),
            },
        )
        .unwrap();
        gateway.fixture_lookup(Arc::new(loopback));
        gateways.insert(model.clone(), Arc::new(gateway));
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&setup.database)
        .await
        .unwrap();
    let settings = WorkerSettings::parse(Duration::from_secs(1), |key| {
        Ok(match key {
            "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => Some("1".into()),
            "LEASE_MS" => Some("30000".into()),
            "EXECUTION_TIMEOUT_MS" => Some("180000".into()),
            "POLL_MS" => Some("100".into()),
            "SWEEP_MS" => Some("1000".into()),
            _ => None,
        })
    })
    .unwrap();
    let routes = Routes {
        gateways,
        actor: setup.actor,
        scope: setup.scope,
        metered: setup.metered,
        stream: setup.stream,
        recorded_tools: setup.recorded_tools,
    };
    let mut executor = TurnExecutor::new(
        pool.clone(),
        catalog,
        settings.policy.unwrap().leases,
        routes,
    );
    if let Some(path) = setup.artifacts {
        executor = executor.with_artifacts(artifact_fs::Store::open(&path).unwrap());
    }
    let observation_shutdown = Arc::new(tokio::sync::Notify::new());
    if setup.tools {
        let lookup = Arc::new(Lookup {
            pool: pool.clone(),
            shutdown: setup
                .stop_during_observation
                .then(|| observation_shutdown.clone()),
            recorded_tools: setup.recorded_tools,
            pause_after_first_tool_lock: setup.pause_after_first_tool_lock,
            completed: AtomicUsize::new(0),
        });
        executor = executor.with_effects(Arc::new(ApprovedEffects {
            policy: lookup.clone(),
            adapter: lookup,
        }));
    }
    let shutdown = async {
        if setup.stop_during_observation {
            observation_shutdown.notified().await;
        } else {
            tokio::task::spawn_blocking(|| {
                std::io::stdin()
                    .lock()
                    .read_line(&mut String::new())
                    .unwrap()
            })
            .await
            .unwrap();
        }
    };
    super::super::run(
        &pool,
        None,
        settings,
        Arc::new(executor),
        shutdown,
        Duration::from_secs(4),
    )
    .await;
}
