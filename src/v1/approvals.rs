//! Actor-only approval requests and immutable decision receipts (ADR 0035).
use super::*;
use crate::authz::approvals::{
    self as store, DecisionInput, EffectPolicy, HumanDecision, Proposal, Review,
};

/// Router extension for server-reviewed tool schemas whose exact arguments and destination
/// can be displayed to the actor. A core-only installation has no registered tools.
#[derive(Clone)]
pub struct ApprovalDisplayPolicy(pub Arc<dyn EffectPolicy + Send + Sync>);

impl EffectPolicy for Option<&ApprovalDisplayPolicy> {
    fn review(
        &self,
        scope: &str,
        run: &str,
        proposal: &Proposal,
    ) -> Result<Option<Review>, StoreError> {
        match self {
            Some(policy) => policy.0.review(scope, run, proposal),
            None => Ok(None),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    #[serde(deserialize_with = "string_enum")]
    decision: HumanDecision,
    binding_digest: String,
}

impl Api {
    pub(super) async fn approval_operation(
        &self,
        op: Op,
        parts: &Parts,
        channel: &Session,
        run: &str,
        key: Option<&str>,
        body: &[u8],
    ) -> Result<Response, Problem> {
        if parts.uri.query().is_some() {
            return Err(INVALID);
        }
        let decision = if op == Op::DecideRunApproval {
            let approval = path_id(parts, 5)?;
            let decision: Decision = parse(body)?;
            if !store::valid_digest(&decision.binding_digest) {
                return Err(INVALID);
            }
            Some((approval, decision, key.ok_or(KEY_REQUIRED)?))
        } else {
            None
        };
        let session = self.authenticate(channel).await?;
        let policy = parts.extensions.get::<ApprovalDisplayPolicy>();
        self.with_connection(async |c| {
            crate::restore::require_open_gate(c).await?;
            let scope: String = sqlx::query_scalar(
                "SELECT scope_id::text FROM openmettle.runs WHERE id=$1::uuid AND actor_user_id=$2::uuid",
            )
            .bind(run)
            .bind(session.user_id())
            .fetch_optional(&mut *c)
            .await?
            .ok_or(NOT_FOUND)?;
            let result = match decision {
                Some((approval, decision, key)) => {
                    let input = DecisionInput {
                        scope: &scope,
                        run,
                        approval,
                        decision: decision.decision,
                        binding_digest: &decision.binding_digest,
                        idempotency_key: key,
                    };
                    let receipt = store::decide(c, &session, &input, &policy).await?;
                    json!({
                        "approval_id": receipt.approval_id,
                        "decision": receipt.decision,
                        "binding_digest": receipt.binding_digest,
                        "decided_at": timestamp(receipt.decided_us)?,
                    })
                }
                None => {
                    let mut items = Vec::new();
                    if let Some(p) = store::list_pending(c, &session, &scope, run, &policy).await? {
                        items.push(json!({
                            "approval_id": p.approval_id,
                            "tool_id": p.tool_id,
                            "tool_version": p.tool_version,
                            "arguments_json": p.arguments_json,
                            "destination": p.destination,
                            "binding_digest": p.binding_digest,
                            "approval_expires_at": timestamp(p.expires_us)?,
                        }));
                    }
                    json!({"items": items})
                }
            };
            Ok(reply(StatusCode::OK, result))
        }).await
    }
}
