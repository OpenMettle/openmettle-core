//! Worker execution-time recheck and live run invalidation (ADR 0027 PR5).
//!
//! [`recheck_run`] works as `openmettle_worker` or `openmettle_api`. In one READ COMMITTED
//! transaction it locks the run row, re-hydrates the run owner from the primary, decides with
//! [`super::authorize_run_continuation`] and, on a denial, moves the run to `cancelled`. It never
//! reads `account_admins`, `project_settings`, `authorization_audit` or any session or secret
//! column. Logging out never cancels a run: the originating session is not consulted.
//!
//! The worker cannot observe project archive or delete, because it has no `SELECT` on
//! `project_settings`. The API therefore cancels the affected non-terminal runs in the same
//! transaction as `archive_project`, `delete_project` and `disable_user`.
//!
//! # Lock order
//!
//! - [`recheck_run`] locks exactly one run row `FOR NO KEY UPDATE`. Afterwards it only reads
//!   without row locks and updates the row it already holds. It never waits while holding a
//!   run lock, so it cannot close a wait cycle.
//! - Bulk cancellation is the last statement of `archive_project` and `delete_project` (after
//!   the project row lock) and of `disable_user` (after `account_admin_lock` and the user row).
//!   It locks every affected run row in ascending `id` order before updating any. Overlapping
//!   bulk cancellations therefore acquire their shared rows in the same order.
//! - No path locks a run row and then waits on a project, user or `account_admin_lock` row.
use super::{
    CapabilityGate, DenialReason, PlatformPolicy, Principal, Resource, ResourceKind, RunAuthority,
    RunContinuation, Scope, projects,
    store::{self, StoreError, uuid},
};
use sqlx::PgConnection;

/// Run states after which no recheck or cancellation changes the row (ADR 0004 vocabulary).
pub const TERMINAL_STATES: [&str; 4] = ["succeeded", "failed", "cancelled", "interrupted"];

/// `queued`, `running`, `waiting`, `cancelling` and `reconciling` are not terminal.
pub fn is_terminal(state: &str) -> bool {
    TERMINAL_STATES.contains(&state)
}

// Keep in step with `TERMINAL_STATES`; the unit tests compare them.
macro_rules! non_terminal {
    () => {
        "state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')"
    };
}

const LOCK_RUN: &str = "SELECT actor_user_id::text, conversation_id::text, state
   FROM openmettle.runs WHERE scope_id = $1::uuid AND id = $2::uuid FOR NO KEY UPDATE";

const CANCEL_ONE: &str = concat!(
    "UPDATE openmettle.runs SET state = 'cancelled', wait_reason = NULL
      WHERE scope_id = $1::uuid AND id = $2::uuid AND ",
    non_terminal!()
);

// The materialized CTE locks every affected row in ascending ID order before any is updated.
const CANCEL_SCOPE: &str = concat!(
    "WITH doomed AS MATERIALIZED (
       SELECT id FROM openmettle.runs WHERE scope_id = $1::uuid AND ",
    non_terminal!(),
    " ORDER BY id FOR NO KEY UPDATE)
     UPDATE openmettle.runs r SET state = 'cancelled', wait_reason = NULL
       FROM doomed WHERE r.id = doomed.id AND r.",
    non_terminal!()
);

const CANCEL_USER: &str = concat!(
    "WITH doomed AS MATERIALIZED (
       SELECT id FROM openmettle.runs WHERE actor_user_id = $1::uuid AND ",
    non_terminal!(),
    " ORDER BY id FOR NO KEY UPDATE)
     UPDATE openmettle.runs r SET state = 'cancelled', wait_reason = NULL
       FROM doomed WHERE r.id = doomed.id AND r.",
    non_terminal!()
);

/// One capability the next run step uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityUse<'a> {
    pub name: &'a str,
    pub gate: CapabilityGate,
}

/// One execution-time recheck, before dispatch and before each tool or provider step.
#[derive(Clone, Copy, Debug)]
pub struct RunRecheckRequest<'a> {
    pub scope_id: &'a str,
    pub run_id: &'a str,
    /// The identity approval the run was admitted under. An approval that is not one of the
    /// run owner's reads as inactive and invalidates the run: it fails closed.
    pub actor_approval_id: &'a str,
    pub capabilities: &'a [CapabilityUse<'a>],
    /// A conversation or artifact the step writes besides the run's conversation. It needs the
    /// same `RunExecute` (write) access and must be in the run's scope.
    pub extra_target: Option<(ResourceKind, &'a str)>,
    pub now_ms: i64,
}

impl RunRecheckRequest<'_> {
    /// Input checks, made before any database work.
    pub fn validate(&self) -> Result<(), StoreError> {
        uuid(self.scope_id, "scope_id")?;
        uuid(self.run_id, "run_id")?;
        uuid(self.actor_approval_id, "actor_approval_id")?;
        if !self
            .capabilities
            .iter()
            .all(|c| super::valid_capability(c.name))
        {
            return Err(StoreError::InvalidInput("capability"));
        }
        if let Some((kind, id)) = self.extra_target {
            if !kind.shareable() {
                return Err(StoreError::InvalidInput("resource kind"));
            }
            uuid(id, "resource_id")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunRecheckOutcome {
    /// Authorized at this observation; the run row is unchanged. Recheck at the next step.
    Continue,
    /// This recheck moved the run to `cancelled` with no wait reason. It is not retried.
    Invalidated(DenialReason),
    /// The run was already terminal, for example cancelled by the API. Nothing changed.
    Terminal { state: String },
}

/// Recheck one run on the primary and cancel it when its owner no longer holds the authority
/// it needs. `NotFound` means no run with this ID exists in this scope.
pub async fn recheck_run(
    c: &mut PgConnection,
    request: &RunRecheckRequest<'_>,
) -> Result<RunRecheckOutcome, StoreError> {
    request.validate()?;
    let mut tx = store::begin(c).await?;
    let result = match tx.connection() {
        Ok(c) => recheck_locked(c, request).await,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(outcome) => {
            tx.commit().await?;
            Ok(outcome)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

async fn recheck_locked(
    c: &mut PgConnection,
    r: &RunRecheckRequest<'_>,
) -> Result<RunRecheckOutcome, StoreError> {
    let (owner, conversation, state): (String, String, String) = sqlx::query_as(LOCK_RUN)
        .bind(r.scope_id)
        .bind(r.run_id)
        .fetch_optional(&mut *c)
        .await?
        .ok_or(StoreError::NotFound)?;
    if is_terminal(&state) {
        return Ok(RunRecheckOutcome::Terminal { state });
    }
    let principal =
        store::hydrate_worker_principal(c, &owner, r.actor_approval_id, r.now_ms).await?;
    let platform = store::load_platform_capabilities(c).await?;
    let scope = run_scope(c, r.scope_id, r.now_ms).await?;
    let target =
        projects::hydrate_resource(c, ResourceKind::Conversation, &conversation, r.now_ms).await?;
    let extra = match r.extra_target {
        Some((kind, id)) => Some(projects::hydrate_resource(c, kind, id, r.now_ms).await?),
        None => None,
    };
    let capabilities = r
        .capabilities
        .iter()
        .map(|c| (c.name.to_owned(), c.gate))
        .collect();
    let decision = evaluate(
        principal.as_ref(),
        &platform,
        scope,
        target,
        extra,
        capabilities,
    );
    let RunContinuation::Invalidate(reason) = decision else {
        return Ok(RunRecheckOutcome::Continue);
    };
    // The row is locked and non-terminal, so exactly this run changes.
    sqlx::query(CANCEL_ONE)
        .bind(r.scope_id)
        .bind(r.run_id)
        .execute(c)
        .await?;
    Ok(RunRecheckOutcome::Invalidated(reason))
}

/// The run's own scope, hydrated independently of its target so that a target outside it is
/// concealed. `None` if the scope row is missing or names neither a user nor a project.
async fn run_scope(
    c: &mut PgConnection,
    scope_id: &str,
    now_ms: i64,
) -> Result<Option<Scope>, StoreError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT personal_user_id::text, project_id::text FROM openmettle.scopes
          WHERE id = $1::uuid",
    )
    .bind(scope_id)
    .fetch_optional(&mut *c)
    .await?;
    Ok(match row {
        Some((Some(owner_user_id), _)) => Some(Scope::Personal {
            scope_id: scope_id.to_owned(),
            owner_user_id,
        }),
        Some((None, Some(project))) => projects::hydrate_project(c, &project, now_ms)
            .await?
            .map(Scope::Project),
        _ => None,
    })
}

/// The pure decision. A missing principal, scope, conversation or requested extra target
/// invalidates; `extra` is `Some(None)` when a requested target does not exist. The
/// originating session is never consulted.
fn evaluate(
    principal: Option<&Principal>,
    platform: &PlatformPolicy,
    scope: Option<Scope>,
    target: Option<Resource>,
    extra: Option<Option<Resource>>,
    capabilities: Vec<(String, CapabilityGate)>,
) -> RunContinuation {
    let owner = match super::require(principal) {
        Ok(owner) => owner,
        Err(reason) => return RunContinuation::Invalidate(reason),
    };
    let (Some(scope), Some(target)) = (scope, target) else {
        return RunContinuation::Invalidate(DenialReason::NotFound);
    };
    let extra = match extra {
        Some(None) => return RunContinuation::Invalidate(DenialReason::NotFound),
        Some(Some(resource)) => Some(resource),
        None => None,
    };
    let mut run = RunAuthority {
        scope,
        target: Some(target),
        capabilities,
        originating_session_active: false,
    };
    let decision = super::authorize_run_continuation(owner, platform, &run);
    match (decision, extra) {
        (RunContinuation::Continue, Some(extra)) => {
            run.target = Some(extra);
            run.capabilities.clear();
            super::authorize_run_continuation(owner, platform, &run)
        }
        (decision, _) => decision,
    }
}

/// Cancel every non-terminal run in one scope, as `openmettle_api`. Call it as the last
/// statement of a project archive or delete, after the project row lock.
pub(super) async fn cancel_scope_runs(
    c: &mut PgConnection,
    scope_id: &str,
) -> Result<u64, StoreError> {
    Ok(sqlx::query(CANCEL_SCOPE)
        .bind(scope_id)
        .execute(c)
        .await?
        .rows_affected())
}

/// Cancel every non-terminal run the user owns, as `openmettle_api`. Call it as the last
/// statement of a user disablement, after `account_admin_lock` and the user row lock.
pub(super) async fn cancel_user_runs(
    c: &mut PgConnection,
    user_id: &str,
) -> Result<u64, StoreError> {
    Ok(sqlx::query(CANCEL_USER)
        .bind(user_id)
        .execute(c)
        .await?
        .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{
        Grant, Origin, PolicyReason, Project, ProjectRole, ResourceAccess, ResourceShare,
    };
    use std::collections::BTreeSet;

    const ID: &str = "00000000-0000-0000-0000-000000000001";
    const OWNER: &str = "00000000-0000-0000-0000-0000000000a1";
    const OTHER: &str = "00000000-0000-0000-0000-0000000000b2";
    const PERSONAL: &str = "00000000-0000-0000-0000-0000000000c1";
    const PROJECT: &str = "00000000-0000-0000-0000-0000000000d1";

    fn request<'a>(capabilities: &'a [CapabilityUse<'a>]) -> RunRecheckRequest<'a> {
        RunRecheckRequest {
            scope_id: ID,
            run_id: ID,
            actor_approval_id: ID,
            capabilities,
            extra_target: None,
            now_ms: 1,
        }
    }

    fn owner() -> Principal {
        Principal {
            user_id: OWNER.into(),
            personal_scope_id: PERSONAL.into(),
            account_active: true,
            approval_active: true,
            provider_active: true,
            ..Principal::default()
        }
    }

    fn personal() -> Scope {
        Scope::Personal {
            scope_id: PERSONAL.into(),
            owner_user_id: OWNER.into(),
        }
    }

    fn project(role: ProjectRole) -> Scope {
        Scope::Project(Project {
            id: PROJECT.into(),
            grants: vec![Grant {
                grantee: crate::authz::Grantee::User(OWNER.into()),
                permission: role,
                origin: Origin::Direct,
                recorded_active: true,
            }],
        })
    }

    fn resource(kind: ResourceKind, scope: Scope, creator: &str) -> Resource {
        Resource {
            kind,
            id: ID.into(),
            creator_user_id: creator.into(),
            scope,
            shares: Vec::new(),
        }
    }

    fn shared(mut r: Resource, access: ResourceAccess) -> Resource {
        let share: ResourceShare = Grant {
            grantee: crate::authz::Grantee::User(OWNER.into()),
            permission: access,
            origin: Origin::Direct,
            recorded_active: true,
        };
        r.shares.push(share);
        r
    }

    fn decide(
        principal: Option<&Principal>,
        scope: Option<Scope>,
        target: Option<Resource>,
        extra: Option<Option<Resource>>,
        capabilities: &[(&str, CapabilityGate)],
    ) -> RunContinuation {
        let platform = PlatformPolicy::default();
        let capabilities = capabilities
            .iter()
            .map(|(n, g)| ((*n).to_owned(), *g))
            .collect();
        evaluate(principal, &platform, scope, target, extra, capabilities)
    }

    fn invalid(reason: DenialReason) -> RunContinuation {
        RunContinuation::Invalidate(reason)
    }

    #[test]
    fn terminal_states_match_the_adr_0004_vocabulary_and_the_sql_predicate() {
        for state in ["succeeded", "failed", "cancelled", "interrupted"] {
            assert!(is_terminal(state), "{state}");
            assert!(non_terminal!().contains(&format!("'{state}'")), "{state}");
        }
        for state in ["queued", "running", "waiting", "cancelling", "reconciling"] {
            assert!(!is_terminal(state), "{state}");
            assert!(!non_terminal!().contains(&format!("'{state}'")), "{state}");
        }
        for state in ["", "Cancelled", "cancelled ", "done"] {
            assert!(!is_terminal(state), "{state:?}");
        }
        for sql in [CANCEL_ONE, CANCEL_SCOPE, CANCEL_USER] {
            assert!(
                sql.contains("state = 'cancelled', wait_reason = NULL"),
                "{sql}"
            );
        }
        for sql in [CANCEL_SCOPE, CANCEL_USER] {
            assert!(sql.contains("ORDER BY id FOR NO KEY UPDATE"), "{sql}");
            assert!(sql.contains("AS MATERIALIZED"), "{sql}");
        }
    }

    #[test]
    fn requests_are_validated_before_any_database_work() {
        let yolo = [CapabilityUse {
            name: "runs.use_yolo",
            gate: CapabilityGate::OptIn,
        }];
        assert!(request(&yolo).validate().is_ok());
        let artifact = RunRecheckRequest {
            extra_target: Some((ResourceKind::Artifact, ID)),
            ..request(&[])
        };
        assert!(artifact.validate().is_ok());
        for bad in ["", "not-a-uuid", "00000000-0000-0000-0000-00000000000A"] {
            for (field, r) in [
                (
                    "scope_id",
                    RunRecheckRequest {
                        scope_id: bad,
                        ..request(&[])
                    },
                ),
                (
                    "run_id",
                    RunRecheckRequest {
                        run_id: bad,
                        ..request(&[])
                    },
                ),
                (
                    "actor_approval_id",
                    RunRecheckRequest {
                        actor_approval_id: bad,
                        ..request(&[])
                    },
                ),
                (
                    "resource_id",
                    RunRecheckRequest {
                        extra_target: Some((ResourceKind::Artifact, bad)),
                        ..request(&[])
                    },
                ),
            ] {
                assert!(
                    matches!(r.validate(), Err(StoreError::InvalidInput(f)) if f == field),
                    "{field} {bad:?}"
                );
            }
        }
        let long = "a".repeat(129);
        for name in ["", "Web_search", "web search", "ü", long.as_str()] {
            let capabilities = [
                yolo[0],
                CapabilityUse {
                    name,
                    gate: CapabilityGate::OnByDefault,
                },
            ];
            assert!(
                matches!(
                    request(&capabilities).validate(),
                    Err(StoreError::InvalidInput("capability"))
                ),
                "{name:?}"
            );
        }
        for kind in [
            ResourceKind::Memory,
            ResourceKind::Tool,
            ResourceKind::Connection,
        ] {
            let r = RunRecheckRequest {
                extra_target: Some((kind, ID)),
                ..request(&[])
            };
            assert!(matches!(
                r.validate(),
                Err(StoreError::InvalidInput("resource kind"))
            ));
        }
    }

    #[test]
    fn missing_or_inactive_owner_invalidates_before_anything_else() {
        let chat = || Some(resource(ResourceKind::Conversation, personal(), OWNER));
        assert_eq!(
            decide(None, Some(personal()), chat(), None, &[]),
            invalid(DenialReason::Unauthenticated)
        );
        for inactive in [
            Principal {
                account_active: false,
                ..owner()
            },
            Principal {
                approval_active: false,
                ..owner()
            },
            Principal {
                provider_active: false,
                ..owner()
            },
        ] {
            assert_eq!(
                decide(Some(&inactive), None, None, Some(None), &[]),
                invalid(DenialReason::InactivePrincipal)
            );
        }
    }

    #[test]
    fn missing_scope_conversation_or_extra_target_is_concealed() {
        let p = owner();
        let chat = || Some(resource(ResourceKind::Conversation, personal(), OWNER));
        assert_eq!(
            decide(Some(&p), Some(personal()), chat(), None, &[]),
            RunContinuation::Continue
        );
        assert_eq!(
            decide(Some(&p), None, chat(), None, &[]),
            invalid(DenialReason::NotFound)
        );
        assert_eq!(
            decide(Some(&p), Some(personal()), None, None, &[]),
            invalid(DenialReason::NotFound)
        );
        assert_eq!(
            decide(Some(&p), Some(personal()), chat(), Some(None), &[]),
            invalid(DenialReason::NotFound)
        );
    }

    #[test]
    fn targets_outside_the_run_scope_are_concealed() {
        let p = owner();
        let in_project = || {
            Some(resource(
                ResourceKind::Conversation,
                project(ProjectRole::Editor),
                OWNER,
            ))
        };
        assert_eq!(
            decide(Some(&p), Some(personal()), in_project(), None, &[]),
            invalid(DenialReason::NotFound)
        );
        let artifact = resource(ResourceKind::Artifact, project(ProjectRole::Editor), OWNER);
        assert_eq!(
            decide(
                Some(&p),
                Some(personal()),
                Some(resource(ResourceKind::Conversation, personal(), OWNER)),
                Some(Some(artifact)),
                &[]
            ),
            invalid(DenialReason::NotFound)
        );
    }

    #[test]
    fn project_role_and_extra_target_access_are_both_required() {
        let p = owner();
        let chat = |role| Some(resource(ResourceKind::Conversation, project(role), OWNER));
        assert_eq!(
            decide(
                Some(&p),
                Some(project(ProjectRole::Editor)),
                chat(ProjectRole::Editor),
                None,
                &[]
            ),
            RunContinuation::Continue
        );
        assert_eq!(
            decide(
                Some(&p),
                Some(project(ProjectRole::Viewer)),
                chat(ProjectRole::Viewer),
                None,
                &[]
            ),
            invalid(DenialReason::Policy(PolicyReason::InsufficientRole))
        );
        let others = |access| {
            Some(Some(shared(
                resource(ResourceKind::Artifact, project(ProjectRole::Editor), OTHER),
                access,
            )))
        };
        let scope = || Some(project(ProjectRole::Editor));
        assert_eq!(
            decide(
                Some(&p),
                scope(),
                chat(ProjectRole::Editor),
                others(ResourceAccess::Write),
                &[]
            ),
            RunContinuation::Continue
        );
        assert_eq!(
            decide(
                Some(&p),
                scope(),
                chat(ProjectRole::Editor),
                others(ResourceAccess::Read),
                &[]
            ),
            invalid(DenialReason::Policy(PolicyReason::InsufficientAccess))
        );
        let unshared = resource(ResourceKind::Artifact, project(ProjectRole::Editor), OTHER);
        assert_eq!(
            decide(
                Some(&p),
                scope(),
                chat(ProjectRole::Editor),
                Some(Some(unshared)),
                &[]
            ),
            invalid(DenialReason::NotFound)
        );
    }

    #[test]
    fn capabilities_apply_to_the_run_and_a_deny_wins() {
        let chat = || Some(resource(ResourceKind::Conversation, personal(), OWNER));
        let yolo = [("runs.use_yolo", CapabilityGate::OptIn)];
        let p = owner();
        assert_eq!(
            decide(Some(&p), Some(personal()), chat(), None, &yolo),
            invalid(DenialReason::Policy(PolicyReason::CapabilityNotGranted))
        );
        let granted = Principal {
            granted_capabilities: BTreeSet::from(["runs.use_yolo".to_owned()]),
            ..owner()
        };
        assert_eq!(
            decide(Some(&granted), Some(personal()), chat(), None, &yolo),
            RunContinuation::Continue
        );
        let denied = Principal {
            denied_capabilities: BTreeSet::from(["runs.use_yolo".to_owned()]),
            ..granted
        };
        assert_eq!(
            decide(Some(&denied), Some(personal()), chat(), None, &yolo),
            invalid(DenialReason::Policy(PolicyReason::CapabilityDenied))
        );
    }
}
