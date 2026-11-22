//! Worker process for the schema suite. Only the library test binary has the adapter's
//! loopback DNS fixture. Production transport never accepts a loopback gateway.
use super::*;
use crate::provider_http::{
    Trust,
    fixture::loopback,
    inference::{Protocol, Qualification, Timeouts},
};
use serde::Deserialize;
use std::{collections::BTreeMap, io::BufRead};

#[derive(Deserialize)]
struct MeteredSetup {
    installation: String,
    key_id: String,
    key_bytes: [u8; 32],
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
}

struct Routes {
    gateways: BTreeMap<String, Arc<Gateway>>,
    scope: String,
    actor: String,
    metered: Option<(String, Arc<crate::provider_keys::gateway::GatewayKeys>)>,
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
        if let Some((installation, keys)) = &self.metered {
            Ok(Route::metered(
                gateway,
                installation.clone(),
                keys.clone(),
                false,
            ))
        } else {
            Ok(Route::bearer(
                gateway,
                "synthetic-turn-credential".into(),
                false,
            ))
        }
    }
    fn tools(&self, _: &ClaimedRun) -> Vec<Tool> {
        vec![Tool {
            name: "lookup".into(),
            description: "Read a synthetic value".into(),
            parameters: serde_json::json!({"type":"object","properties":{},"additionalProperties":false}),
        }]
    }
    fn tool_prompt_bound(&self, _: &Effective, request: &Request) -> Option<u64> {
        // The fixture offers one empty-argument tool with a fixed short result. Bound
        // the synthetic template only for the short transcripts exercised by the suite.
        (request.history.len() <= 16).then_some(4096)
    }
    fn proposal(&self, _: &ClaimedRun, call: &Call) -> Option<Proposal> {
        Proposal::new(
            &call.id,
            &call.name,
            "1",
            &serde_json::to_vec(&call.arguments).ok()?,
            approvals::Destination {
                connection: "fixture",
                account: "test",
                action: "read",
                resource: "sample",
            },
        )
        .ok()
    }
}

struct Lookup {
    pool: PgPool,
    shutdown: Option<Arc<tokio::sync::Notify>>,
}
impl EffectPolicy for Lookup {
    fn review(&self, _: &str, _: &str, p: &Proposal) -> Result<Option<Review>, StoreError> {
        Ok((p.tool == "lookup"
            && p.version == "1"
            && p.arguments() == &serde_json::json!({})
            && p.destination() == r#"["v1","fixture","test","read","sample"]"#)
            .then(|| Review {
                class: approvals::EffectClass::Read,
                capability: "tool.lookup".into(),
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
            leases::with_lease(&mut c, &lease, Fence::Hold, async |tx, _| {
                record_observation(
                    tx,
                    &Observation {
                        scope: lease.scope_id,
                        run: lease.run_id,
                        operation: &op,
                        key: "fixture-lookup-result",
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
            if step.stop.borrow().is_some() {
                StepResult::Stopped
            } else {
                StepResult::ToolOutput("registered result".into())
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
    for (model, protocol, path) in [
        ("a", Protocol::Chat, "/v1/chat/completions"),
        ("b", Protocol::Responses, "/v1/responses"),
    ] {
        let mut gateway = Gateway::new(
            &format!("https://provider.example.test:{}{path}", setup.port),
            Trust::Bundle(setup.ca.as_bytes()),
            &[],
            Qualification {
                model: model.into(),
                pin: catalog.model(model).unwrap().pin.clone(),
                protocol,
                json: true,
                sse: false,
                functions: Some(inference::SchemaSubset::Flat),
                images: setup.artifacts.is_some(),
                parallel: false,
                usage: true,
                tool_separator_whitespace: false,
            },
            Timeouts {
                setup: Duration::from_secs(5),
                idle: Duration::from_secs(45),
                overall: Duration::from_secs(50),
            },
        )
        .unwrap();
        gateway.fixture_lookup(Arc::new(loopback));
        gateways.insert(model.to_string(), Arc::new(gateway));
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
    let metered = setup.metered.map(|m| {
        (
            m.installation,
            Arc::new(
                crate::provider_keys::gateway::GatewayKeys::new(&[(m.key_id, m.key_bytes)])
                    .unwrap(),
            ),
        )
    });
    let routes = Routes {
        gateways,
        actor: setup.actor,
        scope: setup.scope,
        metered,
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
