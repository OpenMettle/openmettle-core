//! Bounded gateway-role sweeps. Discovery, claims and readback publication use
//! separate transactions; no database connection crosses an admin HTTP call.
use super::Error;
use crate::{
    authz::{CapabilityGate, Decision, authorize_capability, store},
    model_config::Catalog,
    provider_http::gateway::{Action, Admin, Error as AdminError, FamilyDirectory, Mutation},
    provider_keys::gateway::{Context, Envelope, GatewaySealer},
    runs::WriteTransaction,
    telemetry::{
        gateway_failure,
        metrics::{GatewayCause, GatewayStep as Step},
    },
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub struct Profile<'a> {
    pub installation: &'a str,
    pub report_source: &'a str,
    /// Monotonic deployment configuration revision. Older replicas cannot republish.
    pub revision: i64,
    pub rotation_epoch: i64,
    pub renew_before: Duration,
    pub catalog: &'a Catalog,
    /// Most recently authenticated snapshot for preflight or offline discovery. A sweep fetches its own.
    pub families: &'a FamilyDirectory,
}

#[derive(Serialize)]
struct Grant {
    scope: String,
    approval: String,
    cycle: Option<String>,
    model: String,
    provider_generation: i64,
    approval_generation: i64,
    user_generation: i64,
    capabilities: BTreeMap<String, bool>,
}
struct Desired {
    admitted: BTreeSet<String>,
    grants: Vec<Grant>,
    family_minute: Option<u16>,
    family_signature: String,
    family_member: bool,
    policy: Value,
    signature: String,
    configuration: String,
}

async fn desired(c: &mut PgConnection, p: &Profile<'_>, user: &str) -> Result<Desired, Error> {
    // Administration writers use these guards. Lock project rows before identity/user/binding.
    sqlx::query("SELECT id FROM openmettle.account_admin_lock FOR SHARE")
        .execute(&mut *c)
        .await?;
    sqlx::query("SELECT p.id FROM openmettle.projects p WHERE EXISTS (SELECT FROM openmettle.grant_assignments g
        WHERE g.target_id=p.id AND g.target_kind='project' AND g.assignment_format='openmettle.project-role'
        AND (g.grantee_user_id=$1::uuid OR EXISTS (
            SELECT FROM openmettle.local_group_memberships m WHERE m.user_id=$1::uuid AND m.group_id=g.grantee_local_group_id)
          OR EXISTS (SELECT FROM openmettle.membership_observations m JOIN openmettle.local_identity_approvals a ON a.id=m.approval_id
            JOIN openmettle.user_identities i ON i.id=a.identity_id JOIN openmettle.grant_mapping_revisions v
             ON v.rule_id=m.rule_id AND v.revision=m.rule_revision WHERE i.user_id=$1::uuid AND v.claim_value=g.grantee_oidc_group_id)))
        ORDER BY p.id FOR SHARE").bind(user).execute(&mut *c).await?;
    sqlx::query("SELECT p.id FROM openmettle.login_providers p WHERE EXISTS (SELECT FROM openmettle.local_identity_approvals a
        JOIN openmettle.user_identities i ON i.id=a.identity_id WHERE i.user_id=$1::uuid AND a.provider_id=p.id)
        ORDER BY p.id FOR SHARE").bind(user).execute(&mut *c).await?;
    sqlx::query("SELECT a.id FROM openmettle.local_identity_approvals a JOIN openmettle.user_identities i ON i.id=a.identity_id
        WHERE i.user_id=$1::uuid ORDER BY a.id FOR SHARE OF a").bind(user).execute(&mut *c).await?;
    sqlx::query("SELECT id FROM openmettle.users WHERE id=$1::uuid FOR SHARE")
        .bind(user)
        .execute(&mut *c)
        .await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(&mut *c)
            .await?;
    let approvals: Vec<(String,i64,i64,i64)> = sqlx::query_as("SELECT a.id::text,p.access_generation,a.access_generation,u.session_generation
        FROM openmettle.local_identity_approvals a JOIN openmettle.user_identities i ON i.id=a.identity_id
        JOIN openmettle.users u ON u.id=i.user_id JOIN openmettle.login_providers p ON p.id=a.provider_id
        WHERE u.id=$1::uuid AND u.disabled_at IS NULL AND a.active AND a.expires_ms>$2 ORDER BY a.id")
        .bind(user).bind(now).fetch_all(&mut *c).await?;
    let platform = store::load_platform_capabilities(c)
        .await
        .map_err(|_| Error::Database)?;
    let family = p.families.children.get(user);
    let family_minute = match family {
        Some(policy) => match policy.local_minute(c, Some(now)).await {
            Ok(minute) => Some(minute),
            Err(Error::Refused) => None,
            Err(error) => return Err(error),
        },
        None => None,
    };
    let invalid_child =
        p.families.invalid_children.contains(user) || family.is_some() && family_minute.is_none();
    if invalid_child {
        gateway_failure(Step::Policy, GatewayCause::Protocol);
    }
    let mut admitted = BTreeSet::new();
    let mut grants = Vec::new();
    let mut models = BTreeMap::new();
    for (approval, provider_generation, approval_generation, user_generation) in approvals {
        let Some(actor) = store::hydrate_worker_principal(c, user, &approval, now)
            .await
            .map_err(|_| Error::Database)?
        else {
            continue;
        };
        if !actor.is_active() {
            continue;
        }
        admitted.insert(approval.clone());
        if invalid_child {
            continue;
        }
        let groups = Vec::from_iter(actor.local_groups.iter().cloned());
        let oidc = Vec::from_iter(actor.oidc_groups.iter().cloned());
        let mut scopes:Vec<(String,Option<String>)>=sqlx::query_as("SELECT DISTINCT ON (p.scope_id) p.scope_id::text,h.cycle_id::text
            FROM openmettle.grant_assignments g JOIN openmettle.grant_changes h ON h.assignment_id=g.id AND h.revision=g.last_revision
            JOIN openmettle.projects p ON p.id=g.target_id AND p.scope_id=g.scope_id
            LEFT JOIN openmettle.project_settings ps ON ps.project_id=p.id
            WHERE g.source_kind='direct' AND g.assignment_format='openmettle.project-role' AND g.assignment_version=1
              AND g.target_kind='project' AND g.assignment_key IN ('editor','owner') AND h.decision='grant'
              AND ps.archived_at IS NULL AND ps.deleted_at IS NULL AND (g.grantee_user_id=$1::uuid
                 OR g.grantee_local_group_id::text=ANY($2) OR g.grantee_oidc_group_id=ANY($3))
            ORDER BY p.scope_id,h.cycle_id").bind(user).bind(groups).bind(oidc).fetch_all(&mut *c).await?;
        scopes.push((actor.personal_scope_id.clone(), None));
        for (model, profile) in p.catalog.models() {
            if family.is_some_and(|f| f.disabled_models.contains(model))
                || !profile.required_capabilities.iter().all(|(name, gate)| {
                    authorize_capability(&actor, &platform, name, *gate) == Decision::Allow
                })
            {
                continue;
            }
            models.insert(model, &profile.required_capabilities);
            for (scope, cycle) in &scopes {
                grants.push(Grant {
                    scope: scope.clone(),
                    cycle: cycle.clone(),
                    approval: approval.clone(),
                    model: model.clone(),
                    provider_generation,
                    approval_generation,
                    user_generation,
                    capabilities: profile
                        .required_capabilities
                        .iter()
                        .map(|(k, v)| (k.clone(), *v == CapabilityGate::OptIn))
                        .collect(),
                });
            }
        }
    }
    // Only this user's effective policy belongs in the authorization signature. An
    // installation directory revision and a key rotation are independent watermarks.
    let policy = json!({"models":models,"family":family});
    let bytes = serde_json::to_vec(&(&grants, &policy, invalid_child, p.report_source))
        .map_err(|_| Error::Conflict)?;
    let requirements: BTreeMap<_, _> = p
        .catalog
        .models()
        .iter()
        .map(|(name, m)| (name, &m.required_capabilities))
        .collect();
    let config =
        serde_json::to_vec(&(requirements, p.report_source)).map_err(|_| Error::Conflict)?;
    let family_config =
        serde_json::to_vec(&(family, invalid_child)).map_err(|_| Error::Conflict)?;
    Ok(Desired {
        admitted,
        family_minute,
        family_signature: format!("{:x}", Sha256::digest(family_config)),
        family_member: family.is_some() || invalid_child,
        grants,
        policy,
        configuration: format!("{:x}", Sha256::digest(config)),
        signature: format!("{:x}", Sha256::digest(bytes)),
    })
}

struct Binding {
    id: String,
    principal: String,
    budget: String,
    revision: i64,
}
struct Work {
    binding: Binding,
    user: String,
    claim: String,
    mutation: Mutation,
}
type Sealed = ([u8; 32], Envelope);

fn step(action: Action) -> Step {
    match action {
        Action::Principal => Step::Principal,
        Action::Budget | Action::Attach => Step::Budget,
        Action::Policy => Step::Policy,
        Action::Issue | Action::Renew | Action::Rotate => Step::Key,
        Action::Suspend | Action::Revoke => Step::Revoke,
    }
}

/// Identity of the immutable remote plan, validated against primary authority under
/// the binding lock. Unrelated directory edits can retain an older, identical plan.
struct Plan {
    revision: i64,
    profile: i64,
    directory: i64,
    desired: Desired,
}

enum Refresh {
    Current(Plan),
    Fenced,
    Idle,
}

impl Profile<'_> {
    async fn refresh(&self, c: &mut PgConnection, user: &str) -> Result<Refresh, Error> {
        let d = desired(c, self, user).await?;
        if !d.grants.is_empty() {
            sqlx::query("INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
                VALUES ($1::uuid,$2::uuid,gen_random_uuid(),gen_random_uuid()) ON CONFLICT DO NOTHING")
                .bind(self.installation).bind(user).execute(&mut *c).await?;
        }
        // Re-read the newest plan (including a staged successor) after acquiring the lock.
        sqlx::query("SELECT id FROM openmettle.gateway_bindings WHERE installation=$1::uuid AND user_id=$2::uuid FOR UPDATE")
            .bind(self.installation).bind(user).execute(&mut *c).await?;
        let row = sqlx::query("SELECT b.id::text,b.principal::text,b.budget::text,b.desired_revision,b.state,
            e.remote_key::text AS previous_key, e.expires_at>clock_timestamp() AS usable,
            e.expires_at<=clock_timestamp()+$3*interval '1 second' AS renew,
            old.desired_revision AS planned,old.operation_id::text,old.parameters->>'signature' AS signature,
            (old.parameters->>'family_member')::boolean AS family_member,old.parameters->>'family_signature' AS family_signature,old.parameters->>'configuration' AS configuration,(old.parameters->>'directory_revision')::bigint AS directory_revision,
            (old.parameters->>'profile_revision')::bigint AS profile_revision,(old.parameters->>'rotation_epoch')::bigint AS rotation_epoch,
            (SELECT max(a.remote_revision) FROM openmettle.gateway_audit a WHERE a.operation_id=old.operation_id
                AND a.step='policy' AND a.outcome='confirmed' AND a.remote_handle IS NULL) AS seen_directory,
            (SELECT i.parameters->>'signature' FROM openmettle.gateway_intents i WHERE i.binding_id=b.id
                AND i.desired_revision=b.observed_revision AND i.action='policy' AND i.complete LIMIT 1) AS active_signature
            FROM openmettle.gateway_bindings b LEFT JOIN openmettle.gateway_generations e ON (e.binding_id,e.generation)=(b.id,b.active_generation)
            LEFT JOIN LATERAL (SELECT operation_id,desired_revision,parameters FROM openmettle.gateway_intents i WHERE i.binding_id=b.id
                ORDER BY desired_revision DESC,generation,action LIMIT 1) old ON true
            WHERE b.installation=$1::uuid AND b.user_id=$2::uuid")
            .bind(self.installation).bind(user).bind(self.renew_before.as_secs_f64()).fetch_optional(&mut *c).await?;
        let Some(r) = row else {
            return Ok(Refresh::Idle);
        };
        let planned: Option<i64> = r.try_get("planned")?;
        let active: i64 = r.try_get("desired_revision")?;
        let prev = active.max(planned.unwrap_or(active));
        let state: &str = r.try_get("state")?;
        let id: String = r.try_get("id")?;
        let old_profile: Option<i64> = r.try_get("profile_revision")?;
        let directory: Option<i64> = r.try_get("directory_revision")?;
        let seen = directory.max(r.try_get("seen_directory")?);
        let old_epoch: Option<i64> = r.try_get("rotation_epoch")?;
        let member = r.try_get::<Option<bool>, _>("family_member")?;
        if old_profile.is_some_and(|v| v > self.revision)
            || old_epoch.is_some_and(|v| v > self.rotation_epoch)
            || (d.family_member || member != Some(false))
                && seen.is_some_and(|v| v > self.families.revision)
            || member.is_some()
                && old_profile == Some(self.revision)
                && r.try_get::<Option<&str>, _>("configuration")? != Some(&d.configuration)
            || seen == Some(self.families.revision)
                && r.try_get::<Option<&str>, _>("family_signature")?
                    .is_some_and(|v| v != d.family_signature)
        {
            return Ok(Refresh::Fenced);
        }
        let plan_directory = seen.unwrap_or_default().max(self.families.revision);
        let renew = state == "ready" && r.try_get::<Option<bool>, _>("renew")? == Some(true);
        let same_signature = r.try_get::<Option<&str>, _>("signature")? == Some(&d.signature);
        let same_epoch = old_epoch == Some(self.rotation_epoch);
        if same_signature
            && old_profile == Some(self.revision)
            && same_epoch
            && (!renew || prev > active)
        {
            // Remember that an unchanged plan was validated at the newer directory watermark.
            // This also fences a delayed snapshot in which an adult was still a child.
            if seen.is_some_and(|v| v < self.families.revision) {
                sqlx::query("INSERT INTO openmettle.gateway_audit(binding_id,desired_revision,operation_id,step,outcome,remote_revision)
                    VALUES ($1::uuid,$2,$3::uuid,'policy','confirmed',$4)")
                    .bind(&id).bind(prev).bind(r.try_get::<&str,_>("operation_id")?)
                    .bind(self.families.revision).execute(&mut *c).await?;
            }
            if state == "revoked" {
                return Ok(Refresh::Idle);
            }
            return Ok(Refresh::Current(Plan {
                revision: prev,
                profile: self.revision,
                directory: directory.ok_or(Error::Conflict)?,
                desired: d,
            }));
        }
        let previous_key: Option<String> = r.try_get("previous_key")?;
        let revision = if planned.is_none() && state == "provisioning" && previous_key.is_none() {
            prev
        } else {
            prev.checked_add(1).ok_or(Error::Conflict)?
        };
        let identity = json!({"signature":d.signature, "configuration":d.configuration,
            "profile_revision":self.revision, "rotation_epoch":self.rotation_epoch,
            "directory_revision":plan_directory, "family_signature":d.family_signature,
            "family_member":d.family_member});
        if state == "revoked" && d.grants.is_empty() {
            // The remote tombstone already satisfies this policy. Persist the new
            // identity under the binding lock so an older profile cannot regrant
            // after a disabled user returns. No remote revision advance is required.
            let operation: String = sqlx::query_scalar(
                "INSERT INTO openmettle.gateway_intents
                (binding_id,desired_revision,generation,action,expected_revision,parameters)
                VALUES ($1::uuid,$2,0,'policy',$3,$4::jsonb) RETURNING operation_id::text",
            )
            .bind(&id)
            .bind(revision)
            .bind(prev)
            .bind(identity.to_string())
            .fetch_one(&mut *c)
            .await?;
            sqlx::query(
                "UPDATE openmettle.gateway_intents SET complete=true WHERE operation_id=$1::uuid",
            )
            .bind(&operation)
            .execute(&mut *c)
            .await?;
            sqlx::query("INSERT INTO openmettle.gateway_audit(binding_id,desired_revision,operation_id,step,outcome,remote_revision)
                VALUES ($1::uuid,$2,$3::uuid,'policy','confirmed',$4)")
                .bind(&id).bind(revision).bind(operation).bind(plan_directory).execute(&mut *c).await?;
            return Ok(Refresh::Idle);
        }
        let enabled = !d.grants.is_empty();
        // A key-only successor has its own remote revision. Keep the published policy
        // and envelope paired until both successor policy and key are confirmed.
        let keep_ready = enabled
            && state == "ready"
            && r.try_get::<Option<bool>, _>("usable")? == Some(true)
            && r.try_get::<Option<&str>, _>("active_signature")? == Some(&d.signature);
        if !keep_ready {
            sqlx::query("UPDATE openmettle.gateway_bindings SET state=$2,desired_revision=$3 WHERE id=$1::uuid")
                .bind(&id).bind(if enabled { "provisioning" } else { "suspended" }).bind(revision).execute(&mut *c).await?;
        }
        // Superseded claims may still return evidence, but no longer own publication.
        sqlx::query("UPDATE openmettle.gateway_intents SET complete=true,claim=NULL WHERE binding_id=$1::uuid AND desired_revision<$2 AND NOT complete")
            .bind(&id).bind(revision).execute(&mut *c).await?;
        let principal: String = r.try_get("principal")?;
        let budget: String = r.try_get("budget")?;
        let key: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut *c)
            .await?;
        let mut steps = Vec::new();
        if enabled {
            // PR2 generations are independent of desired revisions. Include intents for
            // remotely issued keys that have not reached the envelope table.
            let generation: i64 = sqlx::query_scalar("SELECT greatest($2::bigint,1+greatest(
                (SELECT max(generation) FROM openmettle.gateway_generations WHERE binding_id=$1::uuid),
                (SELECT max(generation) FROM openmettle.gateway_intents WHERE binding_id=$1::uuid AND action IN ('issue','renew','rotate'))))")
                .bind(&id).bind(revision).fetch_one(&mut *c).await?;
            let action = if previous_key.is_none() {
                Action::Issue
            } else if renew
                && r.try_get::<Option<i64>, _>("rotation_epoch")? == Some(self.rotation_epoch)
            {
                Action::Renew
            } else {
                Action::Rotate
            };
            steps.extend([
                (Action::Principal, principal.clone(), revision),
                (Action::Budget, budget.clone(), revision),
                (Action::Attach, budget.clone(), revision),
                (Action::Policy, principal.clone(), revision),
                (action, key, generation),
            ]);
            // A previous remote issue may have committed before its response or before
            // local publication. Retire even those handles, by their original generation.
            let old_keys: Vec<(String,i64)> = sqlx::query_as("WITH keys AS (
                 SELECT remote_key AS target,generation FROM openmettle.gateway_generations WHERE binding_id=$1::uuid
                 UNION SELECT (parameters->>'target')::uuid,generation FROM openmettle.gateway_intents
                  WHERE binding_id=$1::uuid AND action IN ('issue','renew','rotate') AND parameters ? 'signature')
                SELECT target::text,generation FROM keys k WHERE NOT EXISTS
                 (SELECT FROM openmettle.gateway_audit a WHERE a.binding_id=$1::uuid AND a.step='revoke'
                    AND a.outcome='confirmed' AND (a.remote_handle=k.target OR (a.remote_handle=$2::uuid AND a.desired_revision>(SELECT max(issue.desired_revision) FROM openmettle.gateway_intents issue WHERE issue.binding_id=a.binding_id AND issue.parameters->>'target'=k.target::text AND issue.action IN ('issue','renew','rotate')))))
                ORDER BY generation").bind(&id).bind(&principal).fetch_all(&mut *c).await?;
            steps.extend(
                old_keys
                    .into_iter()
                    .map(|(target, generation)| (Action::Revoke, target, generation)),
            );
        } else {
            steps.extend([
                (Action::Suspend, principal.clone(), revision),
                (Action::Revoke, principal, revision),
            ]);
        }
        for (order, (action, target, generation)) in steps.into_iter().enumerate() {
            let mut params = identity.clone();
            params["order"] = json!(order);
            params["target"] = json!(target);
            if action == Action::Policy {
                params["policy"] = d.policy.clone();
            }
            let expected = if order == 0 { revision - 1 } else { revision };
            sqlx::query("INSERT INTO openmettle.gateway_intents (binding_id,desired_revision,generation,action,expected_revision,parameters)
                VALUES ($1::uuid,$2,$3,$4,$5,$6::jsonb)")
                .bind(&id)
                .bind(revision)
                .bind(generation)
                .bind(action.as_str())
                .bind(expected)
                .bind(params.to_string())
                .execute(&mut *c).await?;
        }
        Ok(Refresh::Current(Plan {
            revision,
            profile: self.revision,
            directory: plan_directory,
            desired: d,
        }))
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Sweep {
    after: Option<String>,
}
impl Sweep {
    /// Enqueue authority changes from one keyset page, without contacting the gateway.
    pub async fn discover(
        &mut self,
        pool: &PgPool,
        p: &Profile<'_>,
        limit: u16,
    ) -> Result<usize, Error> {
        if !(1..=64).contains(&limit)
            || !crate::runs::is_canonical_uuid(p.installation)
            || !crate::runs::is_canonical_uuid(p.report_source)
            || p.revision < 1
            || p.rotation_epoch < 0
            || p.renew_before > Duration::from_secs(86400 * 30)
        {
            return Err(Error::Refused);
        }
        let users: Vec<String> = sqlx::query_scalar(
            "SELECT id::text FROM openmettle.users WHERE ($1::uuid IS NULL OR id>$1::uuid)
                ORDER BY users.id LIMIT $2",
        )
        .bind(&self.after)
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await?;
        let count = users.len();
        for u in users {
            let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
            p.refresh(tx.connection()?, &u).await?;
            tx.commit().await?;
            self.after = Some(u);
        }
        if count < usize::from(limit) {
            self.after = None;
        }
        Ok(count)
    }

    /// Discover committed authority even when issuance and administration emitted no hint.
    /// The cursor wraps and may safely restart at the beginning. Process up to limit intents too.
    pub async fn page(
        &mut self,
        pool: &PgPool,
        admin: &Admin,
        sealer: &GatewaySealer,
        p: &Profile<'_>,
        limit: u16,
        deadline: Instant,
    ) -> Result<usize, Error> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        tokio::time::timeout_at(deadline, async {
            let directory = admin
                .family_directory(p.installation, deadline)
                .await
                .map_err(|e| {
                    gateway_failure(Step::Policy, e.cause());
                    Error::Refused
                })?;
            let current = Profile {
                families: &directory,
                ..*p
            };
            let p = &current;
            self.discover(pool, p, limit).await?;
            let mut visited = Vec::new();
            let mut executed = 0;
            while visited.len() < usize::from(limit) {
                let Some(w) = claim(pool, p, &mut visited, usize::from(limit)).await? else {
                    break;
                };
                execute(pool, admin, sealer, p, &w, deadline).await?;
                executed += 1;
            }
            Ok(executed)
        })
        .await
        .map_err(|_| Error::Database)?
    }
}

async fn claim(
    pool: &PgPool,
    p: &Profile<'_>,
    visited: &mut Vec<String>,
    limit: usize,
) -> Result<Option<Work>, Error> {
    // Pick without locking, then acquire authority and binding locks in writer order.
    // The conditional lease acquisition arbitrates contenders in the same transaction.
    while visited.len() < limit {
        let candidate: Option<(String,String)> = sqlx::query_as("SELECT i.operation_id::text,b.user_id::text FROM openmettle.gateway_intents i
            JOIN openmettle.gateway_bindings b ON b.id=i.binding_id
            WHERE NOT i.complete AND i.parameters ? 'order' AND i.due_at<=clock_timestamp() AND b.installation=$1::uuid
              AND (i.parameters->>'profile_revision')::bigint=$2 AND ((i.parameters->>'directory_revision')::bigint<=$3 OR i.parameters->>'family_member'='false')
              AND NOT (i.operation_id::text=ANY($4)) AND NOT EXISTS
              (SELECT FROM openmettle.gateway_intents pre WHERE pre.binding_id=i.binding_id AND pre.desired_revision=i.desired_revision
                AND NOT pre.complete AND (pre.parameters->>'order')::int<(i.parameters->>'order')::int)
            ORDER BY (b.state='suspended') DESC,i.due_at,i.operation_id LIMIT 1")
            .bind(p.installation).bind(p.revision).bind(p.families.revision).bind(&*visited).fetch_optional(pool).await?;
        let Some((operation, user)) = candidate else {
            break;
        };
        visited.push(operation.clone());
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
        let c = tx.connection()?;
        let Refresh::Current(plan) = p.refresh(c, &user).await? else {
            tx.commit().await?;
            continue;
        };
        let row = sqlx::query("WITH due AS (SELECT operation_id FROM openmettle.gateway_intents
            WHERE operation_id=$1::uuid AND NOT complete AND due_at<=clock_timestamp() FOR UPDATE SKIP LOCKED)
            UPDATE openmettle.gateway_intents i SET claim=gen_random_uuid(),due_at=clock_timestamp()+interval '45 seconds'
            FROM due,openmettle.gateway_bindings b WHERE i.operation_id=due.operation_id AND i.binding_id=b.id AND i.desired_revision=$2
            AND i.parameters->>'signature'=$3 AND (i.parameters->>'profile_revision')::bigint=$4
            AND (i.parameters->>'directory_revision')::bigint=$5 AND NOT i.complete AND i.due_at<=clock_timestamp()
            RETURNING i.binding_id::text,b.principal::text,b.budget::text,b.user_id::text,i.claim::text,
            i.operation_id::text,i.desired_revision,i.expected_revision,i.generation,i.action,i.parameters::text")
            .bind(operation).bind(plan.revision).bind(&plan.desired.signature).bind(plan.profile).bind(plan.directory)
            .fetch_optional(c).await?;
        tx.commit().await?;
        if let Some(row) = row {
            return work(row, p).map(Some);
        }
    }
    Ok(None)
}

fn work(r: sqlx::postgres::PgRow, p: &Profile<'_>) -> Result<Work, Error> {
    let params: Value =
        serde_json::from_str(r.try_get("parameters")?).map_err(|_| Error::Conflict)?;
    let binding = Binding {
        id: r.try_get("binding_id")?,
        principal: r.try_get("principal")?,
        budget: r.try_get("budget")?,
        revision: r.try_get("desired_revision")?,
    };
    let m = Mutation {
        installation: p.installation.into(),
        principal: binding.principal.clone(),
        budget: binding.budget.clone(),
        operation: r.try_get("operation_id")?,
        revision: binding.revision,
        expected_revision: r.try_get("expected_revision")?,
        generation: r.try_get("generation")?,
        target: params["target"].as_str().ok_or(Error::Conflict)?.into(),
        action: serde_json::from_value(Value::String(r.try_get("action")?))
            .map_err(|_| Error::Conflict)?,
        policy: params.get("policy").filter(|v| !v.is_null()).cloned(),
    };
    Ok(Work {
        binding,
        user: r.try_get("user_id")?,
        claim: r.try_get("claim")?,
        mutation: m,
    })
}

async fn audit(
    c: &mut PgConnection,
    w: &Work,
    step: Step,
    outcome: &str,
    observed: bool,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO openmettle.gateway_audit (binding_id,desired_revision,operation_id,step,outcome,remote_handle,remote_revision)
        VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6::uuid,$7)")
        .bind(&w.binding.id).bind(w.binding.revision).bind(&w.mutation.operation).bind(step.as_str()).bind(outcome)
        .bind(observed.then_some(&w.mutation.target)).bind(observed.then_some(w.binding.revision)).execute(c).await?;
    Ok(())
}
async fn live(c: &mut PgConnection, w: &Work, plan: &Plan) -> Result<bool, Error> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT FROM openmettle.gateway_intents i
        WHERE i.operation_id=$1::uuid AND i.claim=$2::uuid AND i.desired_revision=$3 AND i.parameters->>'signature'=$4
        AND (i.parameters->>'profile_revision')::bigint=$5 AND (i.parameters->>'directory_revision')::bigint=$6
        AND NOT i.complete AND i.due_at>clock_timestamp() FOR UPDATE OF i)")
        .bind(&w.mutation.operation).bind(&w.claim).bind(plan.revision).bind(&plan.desired.signature)
        .bind(plan.profile).bind(plan.directory).fetch_one(c).await?)
}

async fn failed(pool: &PgPool, w: &Work, step: Step, error: AdminError) -> Result<(), Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    record_failure(tx.connection()?, w, step, error).await?;
    tx.commit().await?;
    Ok(())
}

async fn record_failure(
    c: &mut PgConnection,
    w: &Work,
    step: Step,
    error: AdminError,
) -> Result<(), Error> {
    let cause = error.cause();
    gateway_failure(step, cause);
    let retry = match error {
        AdminError::Deferred(delay) => Some(delay),
        AdminError::Transport(crate::provider_http::Error::Protocol) => {
            Some(crate::provider_http::gateway::retry_backoff())
        }
        AdminError::Transport(_)
            if matches!(cause, GatewayCause::Transport | GatewayCause::Timeout) =>
        {
            Some(crate::provider_http::gateway::retry_backoff())
        }
        _ => None,
    };
    audit(
        c,
        w,
        step,
        if step != Step::Readiness && matches!(error, AdminError::Transport(_)) {
            "uncertain"
        } else if retry.is_some() {
            "deferred"
        } else {
            "refused"
        },
        false,
    )
    .await?;
    sqlx::query("UPDATE openmettle.gateway_intents SET claim=NULL,due_at=coalesce(clock_timestamp()+$3*interval '1 second','9999-12-31'::timestamptz)
        WHERE operation_id=$1::uuid AND claim=$2::uuid").bind(&w.mutation.operation).bind(&w.claim).bind(retry.map(|d|d.as_secs_f64().max(0.001))).execute(c).await?;
    Ok(())
}

async fn execute(
    pool: &PgPool,
    admin: &Admin,
    sealer: &GatewaySealer,
    p: &Profile<'_>,
    w: &Work,
    deadline: Instant,
) -> Result<(), Error> {
    let ready = match admin.ready(deadline).await {
        Ok(ready) => ready,
        Err(e) => return failed(pool, w, Step::Readiness, e).await,
    };
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let current = match p.refresh(tx.connection()?, &w.user).await? {
        Refresh::Current(plan) => live(tx.connection()?, w, &plan).await?,
        Refresh::Idle | Refresh::Fenced => false,
    };
    audit(tx.connection()?, w, Step::Readiness, "confirmed", false).await?;
    tx.commit().await?;
    if !current {
        return Ok(());
    }
    let action = w.mutation.action;
    let receipt = match ready.reconcile(&w.mutation).await {
        Ok(r) => r,
        Err(e) => return failed(pool, w, step(action), e).await,
    };
    let sealed = if let Some(key) = receipt.key {
        let unexpired: bool =
            sqlx::query_scalar("SELECT to_timestamp($1::bigint/1000.0)>clock_timestamp()")
                .bind(receipt.expires_ms.ok_or(Error::Conflict)?)
                .fetch_one(pool)
                .await?;
        if !unexpired {
            return failed(pool, w, Step::Key, AdminError::Protocol).await;
        }
        let ctx = Context {
            installation: p.installation,
            user_id: &w.user,
            binding_id: &w.binding.id,
            principal: &w.binding.principal,
            generation: w.mutation.generation,
        };
        Some(sealer.seal(&ctx, &key).await.map_err(|_| {
            gateway_failure(Step::Key, GatewayCause::Protection);
            Error::Protection
        })?)
    } else {
        None
    };
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let c = tx.connection()?;
    if let Refresh::Current(plan) = p.refresh(c, &w.user).await?
        && live(c, w, &plan).await?
    {
        if !publish(
            c,
            w,
            &plan.desired,
            p.report_source,
            sealed,
            receipt.expires_ms,
        )
        .await?
        {
            // It expired between the pre-seal clock check and the guarded INSERT.
            // Park the immutable receipt with its refusal in this transaction.
            record_failure(c, w, Step::Key, AdminError::Protocol).await?;
            tx.commit().await?;
            return Ok(());
        }
        sqlx::query("UPDATE openmettle.gateway_intents SET complete=true,claim=NULL WHERE operation_id=$1::uuid AND claim=$2::uuid")
            .bind(&w.mutation.operation).bind(&w.claim).execute(&mut *c).await?;
    }
    audit(c, w, step(action), "confirmed", true).await?;
    tx.commit().await?;
    Ok(())
}

async fn publish(
    c: &mut PgConnection,
    w: &Work,
    d: &Desired,
    source: &str,
    sealed: Option<Sealed>,
    expiry: Option<i64>,
) -> Result<bool, Error> {
    let b = &w.binding;
    match w.mutation.action {
        Action::Policy => {
            for g in &d.grants {
                sqlx::query("INSERT INTO openmettle.gateway_policy (binding_id,revision,scope_id,approval_id,model,report_source,
                provider_generation,approval_generation,user_generation,grant_cycle,capabilities)
                VALUES ($1::uuid,$2,$3::uuid,$4::uuid,$5,$6::uuid,$7,$8,$9,$10::uuid,$11::jsonb)")
                .bind(&b.id).bind(b.revision).bind(&g.scope).bind(&g.approval).bind(&g.model).bind(source)
                .bind(g.provider_generation).bind(g.approval_generation).bind(g.user_generation).bind(&g.cycle)
                .bind(json!(g.capabilities).to_string()).execute(&mut *c).await?;
            }
        }
        a if a.issues_key() => {
            let (fp, env) = sealed.ok_or(Error::Protection)?;
            let expiry = expiry.ok_or(Error::Conflict)?;
            let inserted = sqlx::query("INSERT INTO openmettle.gateway_generations (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
                SELECT $1::uuid,$2,$3::uuid,t,$5,$6,$7,$8 FROM (SELECT to_timestamp($4::bigint/1000.0) AS t) e WHERE t>clock_timestamp()")
                .bind(&b.id).bind(w.mutation.generation).bind(&w.mutation.target).bind(expiry).bind(env.key_id)
                .bind(fp.as_slice()).bind(env.nonce.as_slice()).bind(env.ciphertext).execute(&mut *c).await?;
            if inserted.rows_affected() != 1 {
                return Ok(false);
            }
            let activated=sqlx::query("UPDATE openmettle.gateway_bindings SET state='ready',observed_revision=$3,desired_revision=$3,active_generation=$2
                WHERE id=$1::uuid AND desired_revision<=$3 AND state IN ('ready','provisioning')")
                .bind(&b.id).bind(w.mutation.generation).bind(b.revision).execute(c).await?;
            if activated.rows_affected() != 1 {
                return Err(Error::Conflict);
            }
        }
        Action::Revoke if w.mutation.target == b.principal => {
            sqlx::query("UPDATE openmettle.gateway_bindings SET state='revoked',active_generation=NULL,observed_revision=desired_revision
                WHERE id=$1::uuid AND state='suspended'").bind(&b.id).execute(c).await?;
        }
        _ => {}
    }
    Ok(true)
}

/// A caller's already authenticated identity and visibility decision. The dedicated
/// gateway service checks its policy projection on the primary before selecting a default.
pub struct ModelRequest<'a> {
    pub access: crate::provider_http::gateway::problem::Access,
    pub user: &'a str,
    pub approval: &'a str,
    pub scope: &'a str,
    pub model: Option<&'a str>,
}
impl Profile<'_> {
    pub async fn select_model(
        &self,
        pool: &PgPool,
        r: ModelRequest<'_>,
        known: Option<crate::provider_http::gateway::problem::Problem>,
        default_model: impl FnOnce() -> String,
    ) -> Result<String, crate::provider_http::gateway::problem::Problem> {
        use crate::provider_http::gateway::problem::{Access, Problem, select};
        select(r.access, None, true, || ())?;
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false)
            .await
            .map_err(|_| Problem::Unavailable)?;
        let c = tx.connection().map_err(|_| Problem::Unavailable)?;
        let d = desired(c, self, r.user)
            .await
            .map_err(|_| Problem::Unavailable)?;
        if !d.admitted.contains(r.approval) {
            return Err(Problem::Unauthenticated);
        }
        let mut allowed: BTreeSet<&str> = d
            .grants
            .iter()
            .filter(|g| g.scope == r.scope && g.approval == r.approval)
            .map(|g| g.model.as_str())
            .collect();
        if let (Some(f), Some(minute)) = (self.families.children.get(r.user), d.family_minute) {
            allowed.retain(|model| f.permits_minute(model, minute));
        }
        if allowed.is_empty() || r.model.is_some_and(|m| !allowed.contains(m)) {
            return Err(Problem::Policy);
        }
        let ready: bool = sqlx::query_scalar("SELECT EXISTS (SELECT FROM openmettle.gateway_bindings b
            JOIN openmettle.gateway_generations k ON (k.binding_id,k.generation)=(b.id,b.active_generation)
            JOIN openmettle.gateway_intents i ON i.binding_id=b.id AND i.desired_revision=b.observed_revision AND i.action='policy' AND i.complete
            WHERE b.installation=$1::uuid AND b.user_id=$2::uuid AND b.state='ready' AND k.expires_at>clock_timestamp()
             AND i.parameters->>'signature'=$3)")
            .bind(self.installation)
            .bind(r.user)
            .bind(d.signature)
            .fetch_one(c).await.map_err(|_|Problem::Unavailable)?;
        tx.commit().await.map_err(|_| Problem::Unavailable)?;
        let model = select(Access::Entitled, known, ready, || {
            r.model.map(str::to_owned).unwrap_or_else(default_model)
        })?;
        if !allowed.contains(model.as_str()) {
            return Err(Problem::Policy);
        }
        Ok(model)
    }
}
