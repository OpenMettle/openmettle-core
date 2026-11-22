//! Reviewed server-owned tools for the restricted stateless MCP 2026-07-28 profile.
mod range;
pub(crate) mod result;

use crate::{
    artifact_fs::Store,
    authz::{
        CapabilityGate,
        approvals::{self, Destination, EffectClass, EffectPolicy, EndpointKey, Proposal, Review},
        leases::{self, Lease},
        store::StoreError,
    },
    provider_http::inference::Tool,
    runs::{self, Observation, Payload, WriteTransaction},
    worker::{ActiveRun, ApprovedAdapter, ApprovedEffects, StepContext, StepResult},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{future::Future, pin::Pin, sync::Arc};

pub const READ_RANGE: &str = "artifact.read_range";
pub const INLINE_BYTES: usize = 16_384;
pub const RESULT_FORMAT: &str = "openmettle.tool-result";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolFault {
    Semantic,
    Transient,
    TerminalRefusal,
}

impl ToolFault {
    pub fn envelope(self) -> String {
        let (code, summary) = match self {
            Self::Semantic => ("semantic", "The requested content or range cannot be read."),
            Self::Transient => (
                "transient",
                "The tool did not complete within its available attempts.",
            ),
            Self::TerminalRefusal => (
                "terminal_refusal",
                "The reviewed tool contract refused the call.",
            ),
        };
        json!({"status":"tool_error","fault_code":code,"summary":summary,"retryable_by_model":self==Self::Semantic}).to_string()
    }
}

/// The catalog is compiled into the server. Upstream metadata can verify an entry only.
pub struct Registry;
impl Registry {
    pub fn read_range(&self) -> Tool {
        let uuid = json!({"type":"string","format":"uuid"});
        Tool {
            name: READ_RANGE.into(),
            description: "Read one bounded UTF-8 page of an active artifact revision.".into(),
            parameters: json!({"type":"object","additionalProperties":false,"required":["artifact_id","revision_id"],
                "properties":{"artifact_id":uuid,"revision_id":uuid,"offset":{"type":"integer","minimum":0,"maximum":i64::MAX,"default":0},
                "max_bytes":{"type":"integer","minimum":4,"maximum":INLINE_BYTES,"default":8192}}}),
        }
    }

    /// Exact schema equality rejects annotations (including nested x-mcp-header), open
    /// objects, and altered defaults before a declaration is offered to the model.
    pub fn verify_schema(&self, name: &str, version: &str, raw: &[u8]) -> Result<Tool, ToolFault> {
        let spec = self.read_range();
        if name != spec.name
            || version != "1"
            || raw.len() > 65_536
            || crate::provider_keys::documents::unique(raw).ok().as_ref() != Some(&spec.parameters)
        {
            return Err(ToolFault::TerminalRefusal);
        }
        Ok(spec)
    }

    pub fn proposal(
        &self,
        scope: &str,
        key: &str,
        name: &str,
        version: &str,
        raw: &[u8],
    ) -> Result<Proposal, ToolFault> {
        use ToolFault::TerminalRefusal as Refused;
        if name != READ_RANGE
            || version != "1"
            || !runs::is_canonical_uuid(scope)
            || key.contains('*')
            || key.chars().any(char::is_control)
        {
            return Err(Refused);
        }
        let args = approvals::canonical_arguments(raw).map_err(|_| Refused)?;
        let fields = args.as_object().ok_or(Refused)?;
        // This closed, flat contract admits four scalar properties. Its grammar also
        // enforces the shared depth, string, array and object-size bounds.
        if fields.keys().any(|k| {
            !matches!(
                k.as_str(),
                "artifact_id" | "revision_id" | "offset" | "max_bytes"
            )
        }) {
            return Err(Refused);
        }
        let artifact = canonical_id(&args["artifact_id"])?;
        let revision = canonical_id(&args["revision_id"])?;
        let integer = |key: &str, default| match fields.get(key) {
            Some(v) => v.as_i64().ok_or(Refused),
            None => Ok(default),
        };
        let offset = integer("offset", 0)?;
        let max = integer("max_bytes", 8192)?;
        if offset < 0 || !(4..=INLINE_BYTES as i64).contains(&max) {
            return Err(Refused);
        }
        let normalized =
            json!({"artifact_id":artifact,"revision_id":revision,"offset":offset,"max_bytes":max});
        Proposal::new(
            key,
            name,
            version,
            normalized.to_string().as_bytes(),
            Destination {
                connection: "internal",
                account: scope,
                action: name,
                resource: artifact,
            },
        )
        .map_err(|_| Refused)
    }
}

fn canonical_id(v: &Value) -> Result<&str, ToolFault> {
    v.as_str()
        .filter(|id| runs::is_canonical_uuid(id))
        .ok_or(ToolFault::TerminalRefusal)
}

impl EffectPolicy for Registry {
    fn review(&self, scope: &str, _: &str, p: &Proposal) -> Result<Option<Review>, StoreError> {
        let Ok(expected) = self.proposal(
            scope,
            &p.logical_key,
            &p.tool,
            &p.version,
            p.arguments().to_string().as_bytes(),
        ) else {
            return Ok(None);
        };
        if expected.arguments() != p.arguments() || expected.destination() != p.destination() {
            return Ok(None);
        }
        Ok(Some(Review {
            class: EffectClass::Read,
            capability: "tools.artifact.read".into(),
            gate: CapabilityGate::OnByDefault,
            tool_policy: "artifact.read_range.v1".into(),
            destination_policy: "internal.scoped.v1".into(),
            endpoint_id: READ_RANGE.into(),
            endpoint_version: "1".into(),
            endpoint_key: EndpointKey::Unsupported,
            authoritative_lookup: false,
            artifact: p.arguments()["artifact_id"].as_str().map(str::to_owned),
            reservation: None,
        }))
    }
}

pub(crate) async fn observe(
    tx: &mut WriteTransaction<'_>,
    lease: &Lease<'_>,
    op: &str,
    succeeded: bool,
    evidence: &str,
) -> Result<(), runs::Error> {
    if evidence.len() > INLINE_BYTES {
        return Err(runs::Error::Invalid);
    }
    runs::record_observation(
        tx,
        &Observation {
            scope: lease.scope_id,
            run: lease.run_id,
            operation: op,
            key: &format!("tool-result:{op}"),
            expected_revision: 0,
            outcome: if succeeded { "succeeded" } else { "failed" },
            handle: None,
            evidence: Payload {
                format: RESULT_FORMAT,
                version: 1,
                bytes: evidence.as_bytes(),
            },
        },
    )
    .await?;
    Ok(())
}

/// Record a known response under the run lock. A local lease-loss notification can
/// arrive during either the lock wait or the observation write, before PostgreSQL's
/// lease actually expires. In both cases the transaction must roll back.
pub(crate) async fn observe_known(
    c: &mut sqlx::PgConnection,
    lease: &Lease<'_>,
    step: &StepContext,
    operation: &str,
    success: bool,
    output: &str,
) -> Result<(), leases::LeaseError> {
    let check = || {
        if *step.stop.borrow() == Some(crate::worker::Stop::LeaseLost) {
            Err(runs::Error::Conflict)
        } else {
            Ok(())
        }
    };
    let record = async |c: &mut sqlx::PgConnection, fence| {
        leases::with_lease(c, lease, fence, async |tx, _| {
            check()?;
            observe(tx, lease, operation, success, output).await?;
            check()
        })
        .await
    };
    let result = if step.stop.borrow().is_some() {
        record(c, leases::Fence::Hold).await
    } else {
        match record(c, leases::Fence::Step).await {
            Err(leases::LeaseError::Stopping(_)) => record(c, leases::Fence::Hold).await,
            result => result,
        }
    };
    if check().is_err() {
        Err(leases::LeaseError::StaleClaim)
    } else {
        result
    }
}

fn approved_effects(
    pool: PgPool,
    store: Store,
    settings: leases::LeaseSettings,
) -> ApprovedEffects {
    store.attach(&pool);
    ApprovedEffects {
        policy: Arc::new(Registry),
        adapter: Arc::new(ArtifactReader {
            pool,
            store,
            settings,
        }),
    }
}
struct ArtifactReader {
    settings: leases::LeaseSettings,
    pool: PgPool,
    store: Store,
}
impl ApprovedAdapter for ArtifactReader {
    fn send<'a>(
        &'a self,
        run: &'a ActiveRun,
        operation: String,
        request: Vec<u8>,
        mut step: StepContext,
    ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
        Box::pin(async move {
            let lease = run.claim.lease();
            let Ok(env) = serde_json::from_slice::<Value>(&request) else {
                return StepResult::Failed(leases::FailReason::StepFailed);
            };
            let Some(key) = env["logical_key"].as_str() else {
                return StepResult::LeaseLost;
            };
            let Ok(proposal) = Registry.proposal(
                lease.scope_id,
                key,
                READ_RANGE,
                "1",
                env["arguments"].to_string().as_bytes(),
            ) else {
                return StepResult::LeaseLost;
            };
            let mut backoff = 250u64;
            let result = loop {
                let result = tokio::select! {
                    biased;
                    _=step.stop.wait_for(Option::is_some)=>return StepResult::Stopped,
                    result=tokio::time::timeout_at(step.deadline,range::read(&self.pool,&self.store,&env["arguments"],lease.scope_id))=>match result {
                        Ok(v)=>v, Err(_)=>return StepResult::Handoff,
                    },
                };
                if result != Err(ToolFault::Transient) {
                    break result;
                }
                use ring::rand::{SecureRandom, SystemRandom};
                let mut jitter = [0; 2];
                if SystemRandom::new().fill(&mut jitter).is_err() {
                    break result;
                }
                let delay = std::time::Duration::from_millis(
                    u64::from(u16::from_be_bytes(jitter)) % (backoff + 1),
                );
                backoff = 500;
                let wake = tokio::time::Instant::now() + delay;
                if wake >= step.deadline {
                    break result;
                }
                tokio::select! {
                    biased;
                    _=step.stop.wait_for(Option::is_some)=>return StepResult::Stopped,
                    _=tokio::time::sleep_until(wake)=>{}
                }
                let Ok(mut c) = self.pool.acquire().await else {
                    return StepResult::LeaseLost;
                };
                let permit = approvals::start_replayed_read(
                    &mut c,
                    &lease,
                    &operation,
                    &proposal,
                    &self.settings,
                    &Registry,
                )
                .await;
                if let Err(result) = crate::worker::start_permit(
                    &mut c,
                    &lease,
                    (&operation, &proposal),
                    &self.settings,
                    &Registry,
                    &mut step,
                    permit,
                )
                .await
                {
                    return result;
                }
            };
            StepResult::ToolResponse(result)
        })
    }
}

/// Execute an explicitly server-owned raw call. Route selection and the production
/// gateway's tool rollout are separate from this internal adapter.
pub struct ScopedAdapter {
    pool: PgPool,
    effects: ApprovedEffects,
    settings: leases::LeaseSettings,
}

impl ScopedAdapter {
    pub fn new(pool: PgPool, store: Store, settings: leases::LeaseSettings) -> Self {
        Self {
            effects: approved_effects(pool.clone(), store, settings),
            pool,
            settings,
        }
    }
    pub async fn call(
        &self,
        run: &ActiveRun,
        step: StepContext,
        key: &str,
        tool: &str,
        version: &str,
        raw: &[u8],
    ) -> StepResult {
        let refused = || StepResult::ToolOutput(ToolFault::TerminalRefusal.envelope());
        let Ok(p) = Registry.proposal(&run.claim.scope_id, key, tool, version, raw) else {
            return refused();
        };
        if let Some(stop) = *step.stop.borrow() {
            return crate::worker::stopped_step(stop);
        }
        let intent = {
            let Ok(mut c) = self.pool.acquire().await else {
                return StepResult::LeaseLost;
            };
            match approvals::record_fenced_intent(
                &mut c,
                &run.claim.lease(),
                &p,
                None,
                &Registry,
                &self.settings,
            )
            .await
            {
                Ok(intent) => intent,
                Err(leases::LeaseError::Store(
                    StoreError::Denied(_) | StoreError::InvalidInput(_),
                )) => return refused(),
                Err(e) => return crate::worker::turns::lease_step(e),
            }
        };
        crate::worker::EffectDispatch {
            pool: &self.pool,
            artifacts: None,
            effects: &self.effects,
            settings: &self.settings,
        }
        .send(run, &p, intent, step)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "00000000-0000-0000-0000-000000000001";

    #[test]
    fn registry_requires_exact_schema_and_closed_canonical_arguments() {
        let schema = Registry.read_range().parameters;
        assert!(
            Registry
                .verify_schema(READ_RANGE, "1", schema.to_string().as_bytes())
                .is_ok()
        );
        let mut drift = schema;
        drift["properties"]["artifact_id"]["x-mcp-header"] = json!("Authorization");
        assert!(
            Registry
                .verify_schema(READ_RANGE, "1", drift.to_string().as_bytes())
                .is_err()
        );
        let p = |bytes: &[u8]| Registry.proposal(ID, "call", READ_RANGE, "1", bytes);
        let base = format!(r#""artifact_id":"{ID}","revision_id":"{ID}""#);
        assert_eq!(
            p(format!("{{{base}}}").as_bytes()).unwrap().arguments()["max_bytes"],
            8192
        );
        for field in [
            r#""offset":1.0"#,
            r#""offset":-1"#,
            r#""max_bytes":3"#,
            r#""offset":0,"offset":1"#,
            r#""resource":"*""#,
            r#""max_bytes":16385"#,
            r#""x-mcp-header":true"#,
        ] {
            assert!(p(format!("{{{base},{field}}}").as_bytes()).is_err());
        }
        for extra in [
            "[".repeat(18) + &"]".repeat(18),
            json!("x".repeat(16385)).to_string(),
            json!(vec![0; 257]).to_string(),
        ] {
            assert!(p(format!("{{{base},\"offset\":{extra}}}").as_bytes()).is_err());
        }
        assert!(p(&vec![b' '; 65537]).is_err());
        assert!(p(format!(r#"{{"artifact_id":"*","revision_id":"{ID}"}}"#).as_bytes()).is_err());
    }
}
