//! Effect authorization and ledger transactions (ADR 0035). Policy resolution is server-side.
//! Adapter I/O starts only after an applied intent commits and its stop point is checked.
use super::{
    CapabilityGate, DenialReason, PlatformPolicy, Principal, ResourceKind, RunContinuation,
    authorize_capability,
    leases::{self, CancelReason, Fence, Lease, LeaseError, LeaseSettings, Settled},
    projects,
    runs::{self, CapabilityUse, RunAdmission, RunRecheckRequest},
    store::{self, StoreError},
};
use crate::{
    membership::membership_state,
    provider_keys::documents::unique,
    runs::{self as durable, EffectAdmission, Intent, Payload, bounded, digest, identity},
    sessions,
    worker::StepContext,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{
    AssertSqlSafe, PgConnection, Postgres, Row,
    postgres::{PgArguments, PgRow},
    query::Query,
};
use std::time::Duration;
use tokio::time::Instant;

const INVALID: StoreError = StoreError::InvalidInput("effect proposal");
const CONFLICT: StoreError = StoreError::Conflict("approval");
const DENIED: StoreError =
    StoreError::Denied(DenialReason::Policy(super::PolicyReason::CapabilityDenied));
const HIDDEN: StoreError = StoreError::Denied(DenialReason::NotFound);
const YOLO: &str = "runs.use_yolo";

/// The locator and principal come from validating the same browser credential or native bearer.
pub struct EffectSession {
    context: sessions::Context,
    locator: String,
}
impl std::ops::Deref for EffectSession {
    type Target = sessions::Context;
    fn deref(&self) -> &Self::Target {
        self.context()
    }
}
impl EffectSession {
    pub(crate) fn into_context(self) -> sessions::Context {
        self.context
    }

    pub async fn validate(
        c: &mut PgConnection,
        credential: &str,
        policy: &sessions::Policy,
        native_audience: Option<[u8; 32]>,
    ) -> Result<Self, sessions::Error> {
        let channel = native_audience.map_or(
            sessions::Validation::Browser,
            sessions::Validation::NativeBearer,
        );
        let context = tokio::time::timeout(
            policy.deadline(),
            sessions::validate_inner(c, credential, channel),
        )
        .await
        .map_err(|_| sessions::Error::Timeout)??;
        let (locator, _) = credential
            .split_once('.')
            .ok_or(sessions::Error::Rejected)?;
        Ok(Self {
            context,
            locator: locator.to_owned(),
        })
    }
    pub fn context(&self) -> &sessions::Context {
        &self.context
    }
    pub fn locator(&self) -> &str {
        &self.locator
    }
}

/// The ADR 0035 compact integer-only JSON profile. Tool-specific schema validation and default
/// expansion belong to the reviewed adapter. Duplicate names are rejected before conversion.
pub fn canonical_arguments(bytes: &[u8]) -> Result<Value, StoreError> {
    fn valid(v: &Value) -> bool {
        match v {
            Value::Number(n) => n.is_i64(),
            Value::Array(a) => a.iter().all(valid),
            Value::Object(o) => o.values().all(valid),
            _ => true,
        }
    }
    if bytes.len() > 65536 {
        return Err(INVALID);
    }
    let mut value = unique(bytes).map_err(|_| INVALID)?;
    if !value.is_object() || !valid(&value) {
        return Err(INVALID);
    }
    value.sort_all_objects();
    Ok(value)
}

/// The adapter pins these four identifiers through send, including redirect handling.
#[derive(Clone, Serialize)]
pub struct Destination<'a> {
    pub connection: &'a str,
    pub account: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
}

#[derive(Clone)]
pub struct Proposal {
    pub logical_key: String,
    pub tool: String,
    pub version: String,
    arguments: Value,
    destination: String,
}
impl Proposal {
    pub fn new(
        key: &str,
        tool: &str,
        version: &str,
        args: &[u8],
        dst: Destination<'_>,
    ) -> Result<Self, StoreError> {
        if [key, tool, version].iter().any(|v| !bounded(v, 128))
            || [dst.connection, dst.account, dst.action, dst.resource]
                .iter()
                .any(|v| !bounded(v, 512) || v.contains('*'))
        {
            return Err(INVALID);
        }
        let destination =
            json!(["v1", dst.connection, dst.account, dst.action, dst.resource]).to_string();
        if destination.len() > 512 {
            return Err(INVALID);
        }
        Ok(Self {
            logical_key: key.into(),
            tool: tool.into(),
            version: version.into(),
            arguments: canonical_arguments(args)?,
            destination,
        })
    }
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }
    pub fn destination(&self) -> &str {
        &self.destination
    }

    fn binding(&self, subject: &Subject<'_>, expires_us: i64, evidence: &[u8]) -> Vec<u8> {
        digest(&identity(
            b"openmettle/effect-approval/1\0",
            &[
                subject.scope.as_bytes(),
                subject.run.unwrap_or_default().as_bytes(),
                self.logical_key.as_bytes(),
                subject.actor.as_bytes(),
                self.tool.as_bytes(),
                self.version.as_bytes(),
                &digest(self.arguments.to_string().as_bytes()),
                self.destination.as_bytes(),
                &expires_us.to_be_bytes(),
                &digest(evidence),
            ],
        ))
    }
}

/// Immutable server-reviewed policy classes. Account/platform changes, credential export,
/// self-grant and isolation escape all use Prohibited. Sharing always requires a human.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Prohibited,
    HumanRequired,
    Sharing,
    EligibleWrite,
    Read,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "support")]
pub enum EndpointKey {
    Supported {
        namespace: String,
        field: String,
        valid_from_us: i64,
        key: String,
        expires_us: i64,
    },
    Unsupported,
    Unknown,
}

/// Supplied by trusted server code for the exact tool, schema, destination and resource.
/// Unavailable policy, an unpinned destination, or an unsupported quota returns no review.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct Review {
    pub class: EffectClass,
    pub capability: String,
    pub gate: CapabilityGate,
    pub tool_policy: String,
    pub destination_policy: String,
    pub endpoint_id: String,
    pub endpoint_version: String,
    pub endpoint_key: EndpointKey,
    pub authoritative_lookup: bool,
    pub artifact: Option<String>,
    /// A required, run-bound storage reservation. Other quota units need V1-17 evidence.
    pub reservation: Option<StorageReservation>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageReservation {
    pub id: String,
    pub required_bytes: i64,
}

/// Resolve the current reviewed manifest for this exact call. Reject unknown argument fields
/// and out-of-schema values. Model output never implements this interface.
pub trait EffectPolicy {
    fn review(
        &self,
        scope: &str,
        run: &str,
        proposal: &Proposal,
    ) -> Result<Option<Review>, StoreError>;
}
impl Review {
    fn validate(&self) -> Result<(), StoreError> {
        if self.class == EffectClass::Prohibited
            || !super::valid_capability(&self.capability)
            || [
                &self.tool_policy,
                &self.destination_policy,
                &self.endpoint_id,
                &self.endpoint_version,
            ]
            .iter()
            .any(|v| !bounded(v, 128))
            || self.reservation.is_some() && self.artifact.is_none()
        {
            return Err(DENIED);
        }
        if self
            .reservation
            .as_ref()
            .is_some_and(|q| q.required_bytes <= 0)
        {
            return Err(INVALID);
        }
        for id in [
            self.artifact.as_ref(),
            self.reservation.as_ref().map(|q| &q.id),
        ]
        .into_iter()
        .flatten()
        {
            store::uuid(id, "effect resource")?;
        }
        if let EndpointKey::Supported {
            namespace,
            field,
            valid_from_us,
            key,
            expires_us,
        } = &self.endpoint_key
            && (!bounded(namespace, 128)
                || !bounded(key, 512)
                || !bounded(field, 128)
                || *valid_from_us < 0
                || expires_us <= valid_from_us)
        {
            return Err(INVALID);
        }
        Ok(())
    }
    fn capability_class(&self) -> &'static str {
        if self.class == EffectClass::Read {
            "repeatable_read"
        } else if matches!(self.endpoint_key, EndpointKey::Supported { .. }) {
            "idempotent"
        } else if self.authoritative_lookup {
            "lookup"
        } else {
            "non_repeatable"
        }
    }
}

struct Subject<'a> {
    scope: &'a str,
    run: Option<&'a str>,
    actor: &'a str,
    approval: &'a str,
    conversation: &'a str,
    session: &'a str,
}

// One primary snapshot covers the two bound sessions, grant cycles, membership validity,
// capability revisions (including absent rows), and any required reservation. The same
// expression guards the final INSERT. All reads after the run lock are non-locking.
const AUTH: &str = concat!(
    "WITH t AS MATERIALIZED (SELECT clock_timestamp() AS at),
     live AS MATERIALIZED (
       SELECT s.id, least(s.expires_ms,a.expires_ms) AS until_ms,
              jsonb_build_array(s.id,s.provider_id,s.approval_id,s.identity_id,s.issued_epoch,
                s.provider_generation,s.approval_generation,s.user_generation,e.epoch) AS proof
       FROM openmettle.local_sessions s JOIN openmettle.login_providers p ON p.id=s.provider_id
       JOIN openmettle.local_identity_approvals a ON a.id=s.approval_id AND a.provider_id=p.id
       JOIN openmettle.user_identities i ON i.id=s.identity_id AND i.id=a.identity_id AND i.issuer=p.issuer
       JOIN openmettle.users u ON u.id=s.user_id AND i.user_id=u.id
       JOIN LATERAL (SELECT epoch,revision FROM openmettle.login_provider_revisions
          WHERE provider_id=p.id ORDER BY epoch DESC LIMIT 1) e ON e.revision IS NOT NULL, t
       WHERE s.id IN ($2,$9) AND NOT s.revoked AND u.disabled_at IS NULL AND a.active
         AND s.user_id=$3::uuid AND a.id=$4::uuid AND s.issued_client=p.client_id
         AND s.created_ms <= extract(epoch FROM t.at)*1000
         AND least(s.expires_ms,a.expires_ms) > extract(epoch FROM t.at)*1000
         AND s.provider_generation=p.access_generation AND s.approval_generation=a.access_generation
         AND s.user_generation=u.session_generation AND NOT EXISTS (
           SELECT FROM openmettle.login_provider_revisions WHERE provider_id=p.id AND epoch>s.issued_epoch AND revision IS NULL)
     ), targets AS (
       SELECT g.target_id, g.target_kind, g.id, g.grantee_kind, g.grantee_user_id, g.grantee_local_group_id,
              g.grantee_oidc_group_id,g.mapping_rule_id,g.last_revision,h.cycle_id
       FROM openmettle.grant_assignments g JOIN openmettle.grant_changes h ON h.assignment_id=g.id AND h.revision=g.last_revision
       WHERE g.scope_id=$5::uuid AND h.decision='grant' AND (g.target_kind='project' OR g.target_id IN ($6::uuid,$7::uuid))
     ), groups AS (
       SELECT g.id,m.revision AS member_revision,g.revision FROM openmettle.local_group_memberships m
       JOIN openmettle.local_groups g ON g.id=m.group_id WHERE m.user_id=$3::uuid AND m.active AND g.disabled_at IS NULL
         AND g.id IN (SELECT grantee_local_group_id FROM targets)
     ), mapped AS (
       SELECT m.approval_id,m.config_revision,m.rule_revision,m.issued_ms,m.epoch,(m.observation).change_id,
              least(m.expires_ms,m.issued_ms+1000::bigint*m.max_age_seconds) AS until_ms,v.claim_value,m.rule_id,v.selector_kind
       FROM openmettle.membership_observations m JOIN openmettle.grant_mapping_revisions v ON
         (v.rule_id,v.revision)=(m.rule_id,m.rule_revision)
       JOIN openmettle.local_identity_approvals mref ON mref.id=m.approval_id
       JOIN openmettle.user_identities i ON i.id=mref.identity_id
       WHERE i.user_id=$3::uuid AND EXISTS (SELECT FROM targets g
          WHERE g.mapping_rule_id=m.rule_id AND g.cycle_id=(m.observation).change_id OR
          (m.approval_id=$4::uuid AND v.selector_kind='group' AND g.grantee_oidc_group_id=v.claim_value))
       AND EXISTS (SELECT FROM (",
    membership_state!(),
    " WHERE a.id=mref.id) fresh WHERE fresh.state='present')
     ), grants AS (
       SELECT g.* FROM targets g WHERE (g.mapping_rule_id IS NULL OR g.cycle_id IN (SELECT change_id FROM mapped))
       AND (g.grantee_user_id=$3::uuid OR g.grantee_kind='project' OR g.grantee_local_group_id IN (SELECT id FROM groups)
           OR g.grantee_oidc_group_id IN (SELECT claim_value FROM mapped WHERE approval_id=$4::uuid AND selector_kind='group'))
     ), caps AS (
       SELECT k, jsonb_build_array(k,p.revision,p.denied,d.revision,d.denied,g.revision,g.granted) AS proof,
           coalesce(g.granted,false) AND NOT coalesce(p.denied,false) AND NOT coalesce(d.denied,false) AS allowed
       FROM (SELECT DISTINCT unnest(ARRAY['runs.use_yolo',$8::text]) AS k) keys
       LEFT JOIN openmettle.platform_capability_denies p ON p.capability=k
       LEFT JOIN openmettle.user_capability_denies d ON d.capability=k AND d.user_id=$3::uuid
       LEFT JOIN openmettle.user_capability_grants g ON g.capability=k AND g.user_id=$3::uuid
     ), snap AS (
       SELECT (extract(epoch FROM t.at)*1000000)::bigint AS now_us,
           least(origin.until_ms,decider.until_ms,(SELECT min(until_ms) FROM mapped))*1000 AS until_us,
           jsonb_build_array('v1',origin.proof,
              ARRAY(SELECT jsonb_build_array(id,member_revision,revision) FROM groups WHERE id IN
                  (SELECT grantee_local_group_id FROM grants WHERE target_kind='project' OR target_id=$6::uuid) ORDER BY id),
              ARRAY(SELECT to_jsonb(m) - 'selector_kind' FROM mapped m WHERE EXISTS (SELECT FROM grants g
                  WHERE (g.target_kind='project' OR g.target_id=$6::uuid) AND (g.cycle_id=m.change_id OR (m.selector_kind='group' AND g.grantee_oidc_group_id=m.claim_value)))
                  ORDER BY approval_id),
              ARRAY(SELECT jsonb_build_array(id,cycle_id,last_revision) FROM grants WHERE target_kind='project' OR target_id=$6::uuid ORDER BY id))::text AS base,
           (SELECT proof::text FROM caps WHERE k='runs.use_yolo') AS yolo,
           (SELECT allowed FROM caps WHERE k='runs.use_yolo') AS eligible,
           quota.max_bytes AS reserved_bytes,
           jsonb_build_array((SELECT proof FROM caps WHERE k=$8),
              ARRAY(SELECT jsonb_build_array(id,cycle_id,last_revision) FROM grants WHERE target_id=$7::uuid ORDER BY id),
              ARRAY(SELECT jsonb_build_array(id,member_revision,revision) FROM groups WHERE id IN
                  (SELECT grantee_local_group_id FROM grants WHERE target_id=$7::uuid) ORDER BY id),
              ARRAY(SELECT to_jsonb(m) - 'selector_kind' FROM mapped m WHERE EXISTS (SELECT FROM grants g WHERE g.target_id=$7::uuid AND
                  (g.cycle_id=m.change_id OR (m.selector_kind='group' AND g.grantee_oidc_group_id=m.claim_value))) ORDER BY approval_id),
              quota.id,quota.max_bytes)::text AS tool
       FROM t JOIN live origin ON origin.id=$2 LEFT JOIN live decider ON decider.id=$9
       LEFT JOIN openmettle.storage_reservations quota ON quota.id=$10::uuid AND quota.state='reserved'
           AND quota.scope_id=$5::uuid AND quota.actor_user_id=$3::uuid AND quota.run_id=$11::uuid AND quota.artifact_id=$7::uuid
       WHERE ($9::text IS NULL OR decider.id IS NOT NULL) AND ($10::uuid IS NULL OR quota.id IS NOT NULL)
     )"
);
struct Proof<'a> {
    subject: &'a Subject<'a>,
    capability: &'a str,
    artifact: Option<&'a str>,
    reservation: Option<&'a str>,
    decider: Option<&'a str>,
}
impl<'a> Proof<'a> {
    fn query<'q>(&'q self, sql: &'q str) -> Query<'q, Postgres, PgArguments> {
        let s = self.subject;
        sqlx::query(AssertSqlSafe(sql))
            .bind(None::<i64>)
            .bind(s.session)
            .bind(s.actor)
            .bind(s.approval)
            .bind(s.scope)
            .bind(s.conversation)
            .bind(self.artifact)
            .bind(self.capability)
            .bind(self.decider)
            .bind(self.reservation)
            .bind(s.run)
    }
    async fn session_time(&self, c: &mut PgConnection) -> Result<i64, StoreError> {
        // Receipt replay depends only on this credential and current read visibility.
        let sql = format!(
            "{AUTH} SELECT floor(extract(epoch FROM t.at)*1000)::bigint AS ms
                            FROM live,t WHERE live.id=$2"
        );
        Ok(self
            .query(&sql)
            .fetch_optional(c)
            .await?
            .ok_or(StoreError::Denied(DenialReason::Unauthenticated))?
            .try_get("ms")?)
    }
    async fn snapshot(&self, c: &mut PgConnection) -> Result<Snapshot, StoreError> {
        let sql = format!(
            "{AUTH} SELECT * FROM snap WHERE octet_length(base)<=32768 AND octet_length(tool)<=32768"
        );
        let row = self.query(&sql).fetch_optional(c).await?.ok_or(DENIED)?;
        Ok(Snapshot {
            base: row.try_get("base")?,
            tool: row.try_get("tool")?,
            yolo: row.try_get("yolo")?,
            eligible: row.try_get("eligible")?,
            reserved_bytes: row.try_get("reserved_bytes")?,
            now: row.try_get("now_us")?,
            until: row.try_get("until_us")?,
        })
    }
}
struct Snapshot {
    base: String,
    tool: String,
    yolo: String,
    eligible: bool,
    reserved_bytes: Option<i64>,
    now: i64,
    until: i64,
}
impl Snapshot {
    fn admission(&self, mode: &str) -> Vec<u8> {
        identity(
            b"openmettle/effect-admission/1\0",
            &[
                self.base.as_bytes(),
                if mode == "yolo" {
                    self.yolo.as_bytes()
                } else {
                    b""
                },
            ],
        )
    }
    fn evidence(&self, review: &Review, auto: bool) -> Vec<u8> {
        let policy = serde_json::to_vec(review).expect("serializable review");
        identity(
            b"openmettle/effect-authority/1\0",
            &[
                self.base.as_bytes(),
                self.tool.as_bytes(),
                if auto { self.yolo.as_bytes() } else { b"" },
                &policy,
            ],
        )
    }
}

fn admission_subject<'a>(r: &'a RunAdmission<'_>, session: &'a str) -> Subject<'a> {
    Subject {
        scope: r.input.scope,
        run: None,
        actor: r.input.actor,
        approval: r.actor_approval_id,
        conversation: r.input.conversation,
        session,
    }
}
fn session_proof<'a>(subject: &'a Subject<'a>) -> Proof<'a> {
    Proof {
        subject,
        capability: YOLO,
        artifact: None,
        reservation: None,
        decider: None,
    }
}

pub(super) async fn admission_time(
    c: &mut PgConnection,
    r: &RunAdmission<'_>,
    session: &str,
) -> Result<i64, StoreError> {
    session_proof(&admission_subject(r, session))
        .session_time(c)
        .await
}

pub(super) async fn admission<'a>(
    c: &mut PgConnection,
    r: &RunAdmission<'_>,
    session: &'a str,
    principal: &Principal,
    platform: &PlatformPolicy,
) -> Result<EffectAdmission<'a>, StoreError> {
    let config = unique(r.input.config).map_err(|_| INVALID)?;
    let mode = match config.as_object().ok_or(INVALID)?.get("execution_mode") {
        None => "ordinary",
        Some(Value::String(s)) if s == "ordinary" || s == "standard" => "ordinary",
        Some(Value::String(s)) if s == "yolo" => "yolo",
        _ => return Err(INVALID),
    };
    let snap = session_proof(&admission_subject(r, session))
        .snapshot(c)
        .await?;
    if mode == "yolo" {
        store::check(authorize_capability(
            principal,
            platform,
            YOLO,
            CapabilityGate::OptIn,
        ))?;
        if !snap.eligible {
            return Err(DENIED);
        }
    }
    let evidence = snap.admission(mode);
    if evidence.len() > 16384 {
        return Err(INVALID);
    }
    Ok(EffectAdmission {
        mode,
        session,
        evidence,
    })
}

const RUN: &str = "SELECT actor_user_id::text, actor_approval_id::text, conversation_id::text,
    originating_session_id, execution_mode, admission_evidence, approval_wait_id::text,
    state, cancel_reason, (extract(epoch FROM execution_expires_at)*1000000)::bigint AS execution_us
    FROM openmettle.runs WHERE id=$1::uuid AND scope_id=$2::uuid FOR NO KEY UPDATE";

const REQUEST: &str = "SELECT a.id::text, a.logical_key,a.tool_id,a.tool_version,a.canonical_arguments,
    a.destination,a.authority_evidence,a.binding_digest,(extract(epoch FROM a.approval_expires_at)*1000000)::bigint AS expires,
    d.decision,d.binding_digest AS decision_digest,d.deciding_session_id, EXISTS(SELECT FROM openmettle.operations o
         WHERE o.run_id=a.run_id AND o.logical_key=a.logical_key) AS consumed
    FROM openmettle.run_approvals a LEFT JOIN openmettle.run_approval_decisions d ON d.approval_id=a.id
    WHERE a.run_id=$1::uuid AND a.id=$2::uuid";

fn subject<'a>(row: &'a PgRow, scope: &'a str, run: &'a str) -> Result<Subject<'a>, StoreError> {
    Ok(Subject {
        scope,
        run: Some(run),
        actor: row.try_get("actor_user_id")?,
        conversation: row.try_get("conversation_id")?,
        approval: row
            .try_get::<Option<&str>, _>("actor_approval_id")?
            .ok_or(DENIED)?,
        session: row
            .try_get::<Option<&str>, _>("originating_session_id")?
            .ok_or(DENIED)?,
    })
}

fn stored_proposal(row: &PgRow) -> Result<Proposal, StoreError> {
    let raw: &[u8] = row.try_get("canonical_arguments")?;
    let arguments = canonical_arguments(raw)?;
    if arguments.to_string().as_bytes() != raw {
        return Err(CONFLICT);
    }
    Ok(Proposal {
        logical_key: row.try_get("logical_key")?,
        tool: row.try_get("tool_id")?,
        version: row.try_get("tool_version")?,
        arguments,
        destination: row.try_get("destination")?,
    })
}
fn reviewed(
    policy: &impl EffectPolicy,
    s: &Subject<'_>,
    p: &Proposal,
) -> Result<Review, StoreError> {
    let review = policy
        .review(s.scope, s.run.ok_or(INVALID)?, p)?
        .ok_or(DENIED)?;
    review.validate()?;
    Ok(review)
}
fn proof<'a>(s: &'a Subject<'a>, review: &'a Review, decider: Option<&'a str>) -> Proof<'a> {
    Proof {
        subject: s,
        capability: &review.capability,
        artifact: review.artifact.as_deref(),
        reservation: review.reservation.as_ref().map(|q| q.id.as_str()),
        decider,
    }
}
async fn authorized(
    c: &mut PgConnection,
    p: &Proof<'_>,
    review: &Review,
) -> Result<Snapshot, StoreError> {
    let snap = p.snapshot(c).await?;
    if review
        .reservation
        .as_ref()
        .is_some_and(|q| snap.reserved_bytes.unwrap_or(0) < q.required_bytes)
        || matches!(review.endpoint_key,EndpointKey::Supported{valid_from_us,..} if snap.now<valid_from_us)
    {
        return Err(DENIED);
    }
    let s = p.subject;
    let request = RunRecheckRequest {
        scope_id: s.scope,
        run_id: s.run.ok_or(INVALID)?,
        actor_approval_id: s.approval,
        capabilities: &[CapabilityUse {
            name: &review.capability,
            gate: review.gate,
        }],
        extra_target: p
            .artifact
            .filter(|_| review.class != EffectClass::Read)
            .map(|id| (ResourceKind::Artifact, id)),
        now_ms: snap.now / 1000,
    };
    if let RunContinuation::Invalidate(reason) =
        runs::recheck_decision(c, &request, s.actor, s.conversation).await?
    {
        return Err(StoreError::Denied(reason));
    }
    if let Some(id) = p.artifact.filter(|_| review.class == EffectClass::Read) {
        readable_artifact(c, s, id, snap.now / 1000).await?;
    }
    Ok(snap)
}

async fn readable_artifact(
    c: &mut PgConnection,
    s: &Subject<'_>,
    id: &str,
    ms: i64,
) -> Result<(), StoreError> {
    let actor = store::hydrate_worker_principal(c, s.actor, s.approval, ms)
        .await?
        .ok_or(DENIED)?;
    let scope = runs::run_scope(c, s.scope, ms).await?.ok_or(HIDDEN)?;
    let artifact = projects::hydrate_resource(c, ResourceKind::Artifact, id, ms)
        .await?
        .ok_or(HIDDEN)?;
    if !super::same_scope(&artifact.scope, &scope) {
        return Err(HIDDEN);
    }
    store::check(super::authorize_resource(
        &actor,
        &artifact,
        super::Action::Read,
    ))
}

fn automatic(row: &PgRow, snap: &Snapshot) -> Result<bool, StoreError> {
    Ok(
        row.try_get::<Option<&str>, _>("execution_mode")? == Some("yolo")
            && snap.eligible
            && row.try_get::<Option<&[u8]>, _>("admission_evidence")?
                == Some(snap.admission("yolo").as_slice()),
    )
}
fn validity(s: &Snapshot, r: &Review) -> i64 {
    match &r.endpoint_key {
        EndpointKey::Supported { expires_us, .. } => s.until.min(*expires_us),
        _ => s.until,
    }
}

struct Binding {
    expires: i64,
    evidence: Vec<u8>,
    hash: Vec<u8>,
}
impl Binding {
    fn new(
        p: &Proposal,
        s: &Subject<'_>,
        snap: &Snapshot,
        review: &Review,
        expires: i64,
        auto: bool,
    ) -> Result<Self, StoreError> {
        let evidence = snap.evidence(review, auto);
        if evidence.len() > 32768 {
            return Err(INVALID);
        }
        let hash = p.binding(s, expires, &evidence);
        Ok(Self {
            expires,
            evidence,
            hash,
        })
    }
    fn matches(&self, p: &Proposal, row: &PgRow) -> Result<bool, StoreError> {
        Ok(row.try_get::<&str, _>("logical_key")? == p.logical_key
            && row.try_get::<&str, _>("tool_id")? == p.tool
            && row.try_get::<&str, _>("tool_version")? == p.version
            && row.try_get::<&str, _>("destination")? == p.destination
            && row.try_get::<&[u8], _>("canonical_arguments")?
                == p.arguments.to_string().as_bytes()
            && row.try_get::<&[u8], _>("authority_evidence")? == self.evidence
            && row.try_get::<&[u8], _>("binding_digest")? == self.hash)
    }
    fn envelope(
        &self,
        p: &Proposal,
        s: &Subject<'_>,
        review: &Review,
        approval: Option<&str>,
    ) -> Result<Vec<u8>, StoreError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let basis = if approval.is_some() {
            "human"
        } else if review.class == EffectClass::Read {
            "read"
        } else {
            "yolo"
        };
        let envelope = json!({
            "version": 1,
            "tool": p.tool,
            "tool_version": p.version,
            "arguments": p.arguments,
            "arguments_digest": projects::hex(&digest(p.arguments.to_string().as_bytes())),
            "destination": p.destination,
            "logical_key": p.logical_key,
            "actor": s.actor,
            "scope": s.scope,
            "run": s.run,
            "authorization": {
                "basis": basis,
                "approval_id": approval,
                "binding_digest": projects::hex(&self.hash),
                "expires_us": self.expires,
                "authority": STANDARD.encode(&self.evidence)
            },
            "endpoint": review
        });
        let bytes = serde_json::to_vec(&envelope).map_err(|_| INVALID)?;
        if bytes.len() > 65536 {
            return Err(INVALID);
        }
        Ok(bytes)
    }
}
fn event(format: &'static str, bytes: &'static [u8]) -> Payload<'static> {
    Payload {
        format,
        version: 1,
        bytes,
    }
}
const EXPIRED: Payload<'static> = Payload {
    format: "openmettle.run-approval-expired",
    version: 1,
    bytes: br#"{"reason":"approval_expired"}"#,
};
const INVALID_WAIT: Payload<'static> = Payload {
    format: "openmettle.run-invalid-wait",
    version: 1,
    bytes: br#"{"reason":"invalid_wait"}"#,
};

/// Readable identity of the durable proposal, including the original database deadline.
#[derive(Debug, PartialEq, Eq)]
pub struct Parked {
    pub approval_id: String,
    pub binding_digest: String,
    pub expires_us: i64,
}

const BLOCKS_PARK: &str = concat!(
    "SELECT EXISTS(SELECT FROM openmettle.operations WHERE run_id=$1::uuid
       AND (logical_key=$2 OR (", leases::unresolved!(), ")))
       OR EXISTS(SELECT FROM openmettle.run_approvals a WHERE id=$3::uuid
       AND NOT EXISTS(SELECT FROM openmettle.operations o WHERE o.run_id=a.run_id AND o.logical_key=a.logical_key))"
);

const INSERT_REQUEST: &str = "INSERT INTO openmettle.run_approvals
            (scope_id,run_id,actor_user_id,logical_key,tool_id,tool_version,canonical_arguments,destination,
             authority_evidence,binding_digest,approval_expires_at,resume_execution_expires_at)
            SELECT scope_id,id,actor_user_id,$3,$4,$5,$6,$7,$8,$9,
                timestamptz 'epoch'+($10::bigint::text || ' microseconds')::interval, execution_expires_at
            FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid RETURNING id::text";

const PARK_RUN: &str = "UPDATE openmettle.runs r SET state='waiting',wait_reason='approval',approval_wait_id=$12::uuid,
            claim_token=NULL,claimed_at=NULL,lease_expires_at=NULL,execution_expires_at=NULL FROM snap,t
            WHERE r.id=$11::uuid AND state='running' AND cancel_reason IS NULL AND claim_token=$13::uuid
            AND lease_expires_at>t.at AND execution_expires_at>t.at AND snap.now_us<$14
            AND snap.base=$15 AND snap.tool=$16";

pub async fn park(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    tasks: &crate::worker::TaskHandle,
    p: &Proposal,
    policy: &impl EffectPolicy,
    settings: &LeaseSettings,
    ttl: Duration,
) -> Result<Parked, LeaseError> {
    settings.validate()?;
    if ttl.as_micros() == 0 || ttl > settings.execution_timeout {
        return Err(StoreError::InvalidInput("approval TTL").into());
    }
    let guard = tasks
        .close_if_drained()
        .ok_or(StoreError::Conflict("owned child work"))?;
    leases::fenced(c, lease, Fence::Step, async move |tx, _| {
        let c = tx.connection()?;
        let run = sqlx::query(RUN)
            .bind(lease.run_id)
            .bind(lease.scope_id)
            .fetch_one(&mut *c)
            .await?;
        let s = subject(&run, lease.scope_id, lease.run_id)?;
        if sqlx::query_scalar::<_, bool>(BLOCKS_PARK)
            .bind(lease.run_id)
            .bind(&p.logical_key)
            .bind(run.try_get::<Option<&str>, _>("approval_wait_id")?)
            .fetch_one(&mut *c)
            .await?
        {
            return Err(StoreError::Conflict("unresolved operation"));
        }
        let review = reviewed(policy, &s, p)?;
        let proof = proof(&s, &review, None);
        let snap = authorized(c, &proof, &review).await?;
        if review.class == EffectClass::Read
            || review.class == EffectClass::EligibleWrite && automatic(&run, &snap)?
        {
            return Err(CONFLICT);
        }
        let execution: i64 = run.try_get("execution_us")?;
        let expires = execution
            .min(snap.now + ttl.as_micros() as i64)
            .min(validity(&snap, &review));
        if expires <= snap.now {
            return Err(CONFLICT);
        }
        let binding = Binding::new(p, &s, &snap, &review, expires, false)?;
        binding.envelope(p, &s, &review, Some("00000000-0000-0000-0000-000000000000"))?;
        let id: String = sqlx::query_scalar(INSERT_REQUEST)
            .bind(s.scope)
            .bind(lease.run_id)
            .bind(&p.logical_key)
            .bind(&p.tool)
            .bind(&p.version)
            .bind(p.arguments.to_string().as_bytes())
            .bind(&p.destination)
            .bind(&binding.evidence)
            .bind(&binding.hash)
            .bind(expires)
            .fetch_one(&mut *c)
            .await?;
        let sql = format!("{AUTH} {PARK_RUN}");
        if proof
            .query(&sql)
            .bind(&id)
            .bind(lease.claim_token)
            .bind(expires)
            .bind(&snap.base)
            .bind(&snap.tool)
            .execute(&mut *c)
            .await?
            .rows_affected()
            != 1
        {
            return Err(CONFLICT);
        }
        runs::append(
            c,
            s.scope,
            lease.run_id,
            &format!("approval-request:{id}"),
            event("openmettle.run-approval-requested", b"{}"),
        )
        .await?;
        runs::append(
            c,
            s.scope,
            lease.run_id,
            &format!("waiting:{id}"),
            event("openmettle.run-waiting", br#"{"reason":"approval"}"#),
        )
        .await?;
        // A lost commit reply requires recovery. Keep spawning closed from this point.
        guard.keep_closed();
        Ok(Parked {
            approval_id: id,
            binding_digest: projects::hex(&binding.hash),
            expires_us: expires,
        })
    })
    .await
}

/// Recover a lost park commit response by the logical key and exact proposal, without changing time or state.
pub async fn recover_park(
    c: &mut PgConnection,
    scope: &str,
    run: &str,
    p: &Proposal,
    policy: &impl EffectPolicy,
) -> Result<Parked, StoreError> {
    runs::transaction(c, async |c| {
        let r = sqlx::query(RUN)
            .bind(run)
            .bind(scope)
            .fetch_optional(&mut *c)
            .await?
            .ok_or(HIDDEN)?;
        let s = subject(&r, scope, run)?;
        let a = sqlx::query(REQUEST)
            .bind(run)
            .bind(r.try_get::<Option<&str>, _>("approval_wait_id")?)
            .fetch_optional(&mut *c)
            .await?
            .ok_or(CONFLICT)?;
        let review = reviewed(policy, &s, p)?;
        let snap = authorized(c, &proof(&s, &review, None), &review).await?;
        let expires = a.try_get("expires")?;
        let binding = Binding::new(p, &s, &snap, &review, expires, false)?;
        if r.try_get::<&str, _>("state")? != "waiting"
            || expires <= snap.now
            || !binding.matches(p, &a)?
        {
            return Err(CONFLICT);
        }
        Ok(Parked {
            approval_id: a.try_get("id")?,
            binding_digest: projects::hex(&binding.hash),
            expires_us: expires,
        })
    })
    .await
}

async fn fail(
    c: &mut PgConnection,
    scope: &str,
    run: &str,
    reason: Payload<'_>,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE openmettle.runs SET state='failed',wait_reason=NULL WHERE id=$1::uuid AND scope_id=$2::uuid")
        .bind(run).bind(scope).execute(&mut *c).await?;
    runs::append(c, scope, run, runs::TERMINAL_KEY, reason).await
}

// Probe each waiting row's single approval by primary key as the ordered sweep advances.
const LOCK_DUE_WAITS: &str = "WITH locked AS MATERIALIZED (
            SELECT r.id,r.scope_id,r.state,r.wait_reason,r.approval_wait_id,a.approval_expires_at FROM openmettle.runs r
            LEFT JOIN LATERAL (SELECT approval_expires_at FROM openmettle.run_approvals
                WHERE id=r.approval_wait_id LIMIT 1) a ON true
            WHERE r.state='waiting' AND (r.approval_wait_id IS NULL OR r.wait_reason IS DISTINCT FROM 'approval'
                OR a.approval_expires_at<=clock_timestamp()) ORDER BY r.id LIMIT $1 FOR NO KEY UPDATE OF r SKIP LOCKED)
            SELECT scope_id::text,id::text,approval_wait_id IS NOT NULL AND wait_reason IS NOT DISTINCT FROM 'approval'
            FROM locked WHERE state='waiting' AND (approval_wait_id IS NULL OR wait_reason IS DISTINCT FROM 'approval'
                OR approval_expires_at<=clock_timestamp()) ORDER BY locked.id";

/// Fail at most the requested number of due or legacy waits in ascending run ID order.
pub async fn expire_waits(c: &mut PgConnection, limit: u32) -> Result<Vec<String>, StoreError> {
    if !(1..=1000).contains(&limit) {
        return Err(StoreError::InvalidInput("limit"));
    }
    runs::transaction(c, async |c| {
        let rows: Vec<(String, String, bool)> = sqlx::query_as(LOCK_DUE_WAITS)
            .bind(i64::from(limit))
            .fetch_all(&mut *c)
            .await?;
        let mut ids = Vec::with_capacity(rows.len());
        for (scope, id, bound) in rows {
            fail(c, &scope, &id, if bound { EXPIRED } else { INVALID_WAIT }).await?;
            ids.push(id);
        }
        runs::release_terminal_runs(c, &ids).await?;
        Ok(ids)
    })
    .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanDecision {
    Approve,
    Deny,
}
impl HumanDecision {
    fn text(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}
pub struct DecisionInput<'a> {
    pub scope: &'a str,
    pub run: &'a str,
    pub approval: &'a str,
    pub decision: HumanDecision,
    pub binding_digest: &'a str,
    pub idempotency_key: &'a str,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Receipt {
    pub approval_id: String,
    pub decision: HumanDecision,
    pub binding_digest: String,
    pub decided_us: i64,
}

async fn db_time(c: &mut PgConnection) -> Result<i64, StoreError> {
    Ok(
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(c)
            .await?,
    )
}
async fn invalidate_wait(
    c: &mut PgConnection,
    scope: &str,
    run: &str,
    expires: i64,
) -> Result<(), StoreError> {
    if expires <= db_time(c).await? {
        fail(c, scope, run, EXPIRED).await
    } else {
        runs::cancel_one(c, scope, run, CancelReason::Revoked)
            .await
            .map(drop)
    }
}

const RECEIPT: &str = "SELECT request_key,decision,binding_digest,
            (extract(epoch FROM decided_at)*1000000)::bigint AS decided FROM openmettle.run_approval_decisions WHERE approval_id=$1::uuid";

const INSERT_DECISION: &str = "INSERT INTO openmettle.run_approval_decisions
                (approval_id,scope_id,run_id,actor_user_id,deciding_session_id,binding_digest,decision,request_key)
                SELECT $12::uuid,$5::uuid,$11::uuid,$3::uuid,$9,$13,$14,$15 FROM snap
                WHERE now_us<$16 AND base=$17 AND tool=$18
                RETURNING (extract(epoch FROM decided_at)*1000000)::bigint AS decided";

async fn locked_actor_run(
    c: &mut PgConnection,
    session: &EffectSession,
    scope: &str,
    run: &str,
) -> Result<PgRow, StoreError> {
    let r = sqlx::query(RUN)
        .bind(run)
        .bind(scope)
        .fetch_optional(c)
        .await?
        .ok_or(HIDDEN)?;
    if r.try_get::<&str, _>("actor_user_id")? != session.user_id() {
        return Err(HIDDEN);
    }
    Ok(r)
}

// The deciding session can differ from the originating one, including on a receipt replay.
async fn readable<'a>(
    c: &mut PgConnection,
    session: &'a EffectSession,
    scope: &'a str,
    run: &'a str,
    r: &'a PgRow,
) -> Result<(Subject<'a>, projects::ResourceView), StoreError> {
    let reader = Subject {
        scope,
        run: Some(run),
        actor: session.user_id(),
        approval: session.approval_id(),
        conversation: r.try_get("conversation_id")?,
        session: session.locator(),
    };
    let now = session_proof(&reader).session_time(c).await?;
    let principal = store::hydrate_api_principal(c, reader.actor, reader.approval, now)
        .await?
        .ok_or(HIDDEN)?;
    let current = runs::run_scope(c, scope, now).await?.ok_or(HIDDEN)?;
    if !super::authorize_scope(&principal, &current, super::Action::Read).is_allowed() {
        return Err(HIDDEN);
    }
    let view = projects::read_resource(
        c,
        &principal,
        ResourceKind::Conversation,
        reader.conversation,
        now,
    )
    .await?;
    if view.scope_id != scope {
        return Err(HIDDEN);
    }
    Ok((reader, view))
}

async fn current_binding(
    c: &mut PgConnection,
    s: &Subject<'_>,
    a: &PgRow,
    p: &Proposal,
    session: &EffectSession,
    view: &projects::ResourceView,
    policy: &impl EffectPolicy,
) -> Result<(Binding, Snapshot, Review), StoreError> {
    if view.project_id.is_some() && view.access != super::ResourceAccess::Write {
        return Err(DENIED);
    }
    let review = reviewed(policy, s, p)?;
    let snap = authorized(c, &proof(s, &review, Some(session.locator())), &review).await?;
    let binding = Binding::new(p, s, &snap, &review, a.try_get("expires")?, false)?;
    if !binding.matches(p, a)? || snap.now >= validity(&snap, &review) {
        return Err(DENIED);
    }
    Ok((binding, snap, review))
}

/// Actor-only fields of a current request approved by the display policy.
pub struct PendingApproval {
    pub approval_id: String,
    pub tool_id: String,
    pub tool_version: String,
    pub arguments_json: String,
    pub destination: String,
    pub binding_digest: String,
    pub expires_us: i64,
}

/// Observe the current wait under the same run lock as a decision. A read never settles it.
pub async fn list_pending(
    c: &mut PgConnection,
    session: &EffectSession,
    scope: &str,
    run: &str,
    policy: &impl EffectPolicy,
) -> Result<Option<PendingApproval>, StoreError> {
    runs::transaction(c, async |c| {
        let r = locked_actor_run(c, session, scope, run).await?;
        let (reader, view) = readable(c, session, scope, run, &r).await?;
        let Some(id) = r.try_get::<Option<&str>, _>("approval_wait_id")? else {
            return Ok(None);
        };
        if r.try_get::<&str, _>("state")? != "waiting"
            || r.try_get::<Option<&str>, _>("cancel_reason")?.is_some()
            || r.try_get::<Option<&str>, _>("actor_approval_id")? != Some(reader.approval)
        {
            return Ok(None);
        }
        let a = sqlx::query(REQUEST)
            .bind(run)
            .bind(id)
            .fetch_one(&mut *c)
            .await?;
        let expires: i64 = a.try_get("expires")?;
        if a.try_get::<Option<&str>, _>("decision")?.is_some() || expires <= db_time(c).await? {
            return Ok(None);
        }
        let s = subject(&r, scope, run)?;
        let p = stored_proposal(&a)?;
        let (binding, snap, review) =
            match current_binding(c, &s, &a, &p, session, &view, policy).await {
                Ok(current) => current,
                Err(StoreError::Denied(_)) => {
                    session_proof(&reader).session_time(c).await?;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
        if db_time(c).await? >= expires.min(validity(&snap, &review)) {
            return Ok(None);
        }
        Ok(Some(PendingApproval {
            approval_id: id.to_owned(),
            tool_id: p.tool,
            tool_version: p.version,
            arguments_json: p.arguments.to_string(),
            destination: p.destination,
            binding_digest: projects::hex(&binding.hash),
            expires_us: expires,
        }))
    })
    .await
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Replay requires current actor visibility. Only a new receipt consumes effect authority.
pub async fn decide(
    c: &mut PgConnection,
    session: &EffectSession,
    input: &DecisionInput<'_>,
    policy: &impl EffectPolicy,
) -> Result<Receipt, StoreError> {
    let i = input;
    for id in [i.scope, i.run, i.approval] {
        store::uuid(id, "approval target")?;
    }
    if !valid_digest(i.binding_digest)
        || !bounded(i.idempotency_key, 128)
        || !i
            .idempotency_key
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(INVALID);
    }
    let path = format!("/v1/runs/{}/approvals/{}/decision", i.run, i.approval);
    let key = projects::hex(&digest(&identity(
        b"openmettle/v1-idempotency/1\0",
        &[
            b"decideRunApproval",
            path.as_bytes(),
            i.idempotency_key.as_bytes(),
        ],
    )));
    runs::transaction(c, async |c| {
        let r = locked_actor_run(c, session, i.scope, i.run).await?;
        let (reader, view) = readable(c, session, i.scope, i.run, &r).await?;
        let a = sqlx::query(REQUEST)
            .bind(i.run)
            .bind(i.approval)
            .fetch_optional(&mut *c)
            .await?
            .ok_or(HIDDEN)?;
        if let Some(old) = sqlx::query(RECEIPT)
            .bind(i.approval)
            .fetch_optional(&mut *c)
            .await?
        {
            if old.try_get::<&str, _>("request_key")? != key {
                return Err(CONFLICT);
            }
            if old.try_get::<&str, _>("decision")? != i.decision.text()
                || projects::hex(old.try_get("binding_digest")?) != i.binding_digest
            {
                return Err(StoreError::Conflict(store::KEY_REUSED));
            }
            return Ok(Some(Receipt {
                approval_id: i.approval.into(),
                decision: i.decision,
                binding_digest: i.binding_digest.into(),
                decided_us: old.try_get("decided")?,
            }));
        }
        if r.try_get::<&str, _>("state")? != "waiting"
            || r.try_get::<Option<&str>, _>("approval_wait_id")? != Some(i.approval)
            || r.try_get::<Option<&str>, _>("cancel_reason")?.is_some()
        {
            return Err(CONFLICT);
        }
        let expires: i64 = a.try_get("expires")?;
        if db_time(c).await? >= expires {
            fail(c, i.scope, i.run, EXPIRED).await?;
            return Ok(None);
        }
        let s = subject(&r, i.scope, i.run)?;
        if session.context.approval_id() != s.approval {
            return Err(CONFLICT);
        }
        let p = stored_proposal(&a)?;
        let attempt = async {
            let (binding, snap, review) =
                current_binding(c, &s, &a, &p, session, &view, policy).await?;
            let proof = proof(&s, &review, Some(session.locator()));
            if projects::hex(&binding.hash) != i.binding_digest {
                return Err(CONFLICT);
            }
            let sql = format!("{AUTH} {INSERT_DECISION}");
            proof
                .query(&sql)
                .bind(i.approval)
                .bind(&binding.hash)
                .bind(i.decision.text())
                .bind(&key)
                .bind(expires.min(validity(&snap, &review)))
                .bind(&snap.base)
                .bind(&snap.tool)
                .fetch_optional(&mut *c)
                .await?
                .ok_or(DENIED)?
                .try_get::<i64, _>("decided")
                .map_err(StoreError::from)
        }
        .await;
        let decided_us = match attempt {
            Ok(time) => time,
            Err(StoreError::Denied(_)) => {
                session_proof(&reader).session_time(c).await?;
                invalidate_wait(c, i.scope, i.run, expires).await?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        runs::append(
            c,
            i.scope,
            i.run,
            &format!("approval-decision:{}", i.approval),
            event("openmettle.run-approval-decided", b"{}"),
        )
        .await?;
        if i.decision == HumanDecision::Deny {
            runs::cancel_one(c, i.scope, i.run, CancelReason::Requested).await?;
        }
        Ok(Some(Receipt {
            approval_id: i.approval.into(),
            decision: i.decision,
            binding_digest: i.binding_digest.into(),
            decided_us,
        }))
    })
    .await?
    .ok_or(CONFLICT)
}

/// Only an Applied result carries the exact committed outbound request and a one-use start check.
pub enum IntentResult {
    Applied(CommittedIntent),
    Replayed(String),
    ApprovalRequired,
    Invalidated(Settled),
}
pub struct CommittedIntent {
    pub operation_id: String,
    request: Vec<u8>,
    effect_deadline: Instant,
    lease_margin_deadline: Instant,
}

pub enum StartPermit {
    Stopped(crate::worker::Stop),
    AuthorityExpired {
        operation_id: String,
        request: Vec<u8>,
    },
    LeaseMarginExhausted,
    Ready {
        request: Vec<u8>,
        deadline: Instant,
    },
}

impl CommittedIntent {
    fn new(
        id: String,
        request: Vec<u8>,
        sent: Instant,
        remaining_us: i64,
        held: &leases::Held,
        settings: &LeaseSettings,
    ) -> Self {
        Self {
            operation_id: id,
            request,
            effect_deadline: sent + Duration::from_micros(remaining_us.max(0) as u64),
            lease_margin_deadline: sent
                + held
                    .lease_remaining
                    .min(held.execution_remaining)
                    .saturating_sub(settings.lease / 3),
        }
    }

    pub fn start(self, step: &StepContext) -> StartPermit {
        let now = Instant::now();
        if let Some(stop) = *step.stop.borrow() {
            StartPermit::Stopped(stop)
        } else if now >= self.effect_deadline {
            StartPermit::AuthorityExpired {
                operation_id: self.operation_id,
                request: self.request,
            }
        } else if now >= self.lease_margin_deadline.min(step.deadline) {
            StartPermit::LeaseMarginExhausted
        } else {
            StartPermit::Ready {
                request: self.request,
                deadline: self
                    .effect_deadline
                    .min(self.lease_margin_deadline)
                    .min(step.deadline),
            }
        }
    }
}

async fn invalidate_running(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    settings: &LeaseSettings,
    expires: i64,
) -> Result<IntentResult, StoreError> {
    // Recheck after policy I/O. A lapsed holder cannot settle the run.
    let live:bool=sqlx::query_scalar("SELECT state='running' AND claim_token=$2::uuid AND cancel_reason IS NULL
        AND least(lease_expires_at,execution_expires_at)>clock_timestamp() FROM openmettle.runs WHERE id=$1::uuid")
        .bind(lease.run_id).bind(lease.claim_token).fetch_one(&mut *c).await?;
    if !live {
        return Err(CONFLICT);
    }
    let settled = if db_time(c).await? >= expires {
        fail(c, lease.scope_id, lease.run_id, EXPIRED).await?;
        Settled::Terminal { state: "failed" }
    } else {
        sqlx::query("UPDATE openmettle.runs SET cancel_reason='revoked' WHERE id=$1::uuid")
            .bind(lease.run_id)
            .execute(&mut *c)
            .await?;
        leases::settle_locked(
            c,
            lease,
            leases::ExecState::Running,
            Some(CancelReason::Revoked),
            settings,
            leases::Settle::Stopped,
        )
        .await?
    };
    Ok(IntentResult::Invalidated(settled))
}

const PENDING_EFFECT: &str = "SELECT a.id::text,a.logical_key,a.tool_id,a.tool_version,a.canonical_arguments,a.destination
        FROM openmettle.runs r LEFT JOIN openmettle.run_approvals a ON a.id=r.approval_wait_id
          AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id=a.run_id AND o.logical_key=a.logical_key)
        WHERE r.id=$1::uuid AND r.scope_id=$2::uuid AND r.claim_token=$3::uuid AND r.state='running'
          AND r.cancel_reason IS NULL AND least(r.lease_expires_at,r.execution_expires_at)>clock_timestamp()";

pub(crate) async fn pending_effect(
    c: &mut PgConnection,
    lease: &Lease<'_>,
) -> Result<Option<(String, Proposal)>, StoreError> {
    let row = sqlx::query(PENDING_EFFECT)
        .bind(lease.run_id)
        .bind(lease.scope_id)
        .bind(lease.claim_token)
        .fetch_optional(c)
        .await?
        .ok_or(CONFLICT)?;
    row.try_get::<Option<String>, _>("id")?
        .map(|id| Ok((id, stored_proposal(&row)?)))
        .transpose()
}
const INSERT_INTENT: &str = "INSERT INTO openmettle.operations
                (scope_id,run_id,logical_key,target,capability,format,format_version,request,request_identity,request_digest,approval_id,dispatched_attempts,effective_expires_us)
                SELECT $5::uuid,$11::uuid,$12,$13,$14,'openmettle.effect',1,$15,$16,$17,$18::uuid,CASE WHEN $14='repeatable_read' THEN 0 END,$20 FROM snap,t,openmettle.runs r
                WHERE r.id=$11::uuid AND r.state='running' AND r.cancel_reason IS NULL AND r.claim_token=$19::uuid
                AND r.lease_expires_at>t.at AND r.execution_expires_at>t.at AND now_us<$20 AND base=$21 AND tool=$22
                AND (NOT $23 OR (eligible AND yolo=$24)) RETURNING id::text";

async fn committed_binding(
    c: &mut PgConnection,
    s: &Subject<'_>,
    p: &Proposal,
    approval: Option<&str>,
    old: &PgRow,
) -> Result<(String, Binding, Review), StoreError> {
    let bytes: &[u8] = old.try_get("request")?;
    let envelope: Value = unique(bytes).map_err(|_| CONFLICT)?;
    use base64::{Engine, engine::general_purpose::STANDARD};
    let basis = &envelope["authorization"];
    let evidence = STANDARD
        .decode(basis["authority"].as_str().ok_or(CONFLICT)?)
        .map_err(|_| CONFLICT)?;
    let expires = basis["expires_us"].as_i64().ok_or(CONFLICT)?;
    let binding = Binding {
        hash: p.binding(s, expires, &evidence),
        expires,
        evidence,
    };
    let review: Review =
        serde_json::from_value(envelope["endpoint"].clone()).map_err(|_| CONFLICT)?;
    let capability: &str = old.try_get("capability")?;
    if review.capability_class() != capability {
        return Err(CONFLICT);
    }
    let rebuilt = binding.envelope(p, s, &review, approval)?;
    let intent = Intent {
        scope: s.scope,
        run: s.run.ok_or(INVALID)?,
        key: &p.logical_key,
        target: &p.destination,
        capability,
        request: Payload {
            format: "openmettle.effect",
            version: 1,
            bytes: &rebuilt,
        },
    };
    let id = durable::intent_identity(&intent)?;
    let op = durable::existing_intent(c, &intent, approval, &id)
        .await?
        .ok_or(CONFLICT)?;
    Ok((op, binding, review))
}

/// Record or inspect one exact logical effect. A missing commit reply grants no send permit.
pub async fn record_fenced_intent(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    p: &Proposal,
    approval: Option<&str>,
    policy: &impl EffectPolicy,
    settings: &LeaseSettings,
) -> Result<IntentResult, LeaseError> {
    settings.validate()?;
    if let Some(id) = approval {
        store::uuid(id, "approval")?;
    }
    let sent = Instant::now();
    leases::fenced(c, lease, Fence::Step, async |tx, held| {
        let c = tx.connection()?;
        let r = sqlx::query(RUN)
            .bind(lease.run_id)
            .bind(lease.scope_id)
            .fetch_one(&mut *c)
            .await?;
        let s = subject(&r, lease.scope_id, lease.run_id)?;
        // Once an intent exists, compare against its original envelope. Expiry or revocation can
        // never convert the replay into a send or erase an observation.
        if let Some(old) = sqlx::query(
            "SELECT request,capability FROM openmettle.operations WHERE run_id=$1::uuid AND logical_key=$2",
        )
        .bind(lease.run_id)
        .bind(&p.logical_key)
        .fetch_optional(&mut *c)
        .await?
        {
            let (op, _, _) = committed_binding(c, &s, p, approval, &old).await?;
            return Ok(IntentResult::Replayed(op));
        }
        let pointer: Option<&str> = r.try_get("approval_wait_id")?;
        let pending = sqlx::query(REQUEST)
            .bind(lease.run_id)
            .bind(pointer)
            .fetch_optional(&mut *c)
            .await?
            .filter(|a| !a.get::<bool, _>("consumed"));
        let expiry = pending.as_ref().map(|a| a.get::<i64, _>("expires"));
        if let Some(end) = expiry
            && db_time(c).await? >= end
        {
            return invalidate_running(c, lease, settings, end).await;
        }
        if approval != pending.as_ref().map(|a| a.get::<&str, _>("id")) {
            if let Some(end) = expiry {
                return invalidate_running(c, lease, settings, end).await;
            }
            return Err(CONFLICT);
        }
        let attempt = async {
            let review = reviewed(policy, &s, p)?;
            let proof = proof(
                &s,
                &review,
                pending.as_ref().and_then(|a| a.get("deciding_session_id")),
            );
            let snap = authorized(c, &proof, &review).await?;
            let auto = approval.is_none() && review.class != EffectClass::Read;
            if auto {
                if review.class != EffectClass::EligibleWrite || !automatic(&r, &snap)? {
                    return Ok(IntentResult::ApprovalRequired);
                }
                let actor =
                    store::hydrate_worker_principal(c, s.actor, s.approval, snap.now / 1000)
                        .await?
                        .ok_or(DENIED)?;
                let platform = store::load_platform_capabilities(c).await?;
                if !authorize_capability(&actor, &platform, YOLO, CapabilityGate::OptIn)
                    .is_allowed()
                {
                    return Ok(IntentResult::ApprovalRequired);
                }
            }
            let expires = expiry.unwrap_or(
                r.try_get::<i64, _>("execution_us")?
                    .min(validity(&snap, &review)),
            );
            let effective_until = expires.min(validity(&snap, &review));
            if snap.now >= effective_until {
                return Err(DENIED);
            }
            let binding = Binding::new(p, &s, &snap, &review, expires, auto)?;
            if let Some(a) = &pending
                && (a.try_get::<Option<&str>, _>("decision")? != Some("approve")
                    || !binding.matches(p, a)?)
            {
                return Err(DENIED);
            }
            let bytes = binding.envelope(p, &s, &review, approval)?;
            let intent = Intent {
                scope: s.scope,
                run: lease.run_id,
                key: &p.logical_key,
                target: &p.destination,
                capability: review.capability_class(),
                request: Payload {
                    format: "openmettle.effect",
                    version: 1,
                    bytes: &bytes,
                },
            };
            let id = durable::intent_identity(&intent)?;
            let sql = format!("{AUTH} {INSERT_INTENT}");
            let row = proof
                .query(&sql)
                .bind(&p.logical_key)
                .bind(&p.destination)
                .bind(intent.capability)
                .bind(&bytes)
                .bind(&id)
                .bind(digest(&id))
                .bind(approval)
                .bind(lease.claim_token)
                .bind(effective_until)
                .bind(&snap.base)
                .bind(&snap.tool)
                .bind(auto)
                .bind(&snap.yolo)
                .fetch_optional(&mut *c)
                .await?
                .ok_or(DENIED)?;
            let op: String = row.try_get("id")?;
            durable::intent_event(c, &intent, &op, &id).await?;
            Ok(IntentResult::Applied(CommittedIntent::new(op, bytes, sent, effective_until - snap.now, held, settings)))
        }
        .await;
        match (attempt, expiry) {
            (Err(StoreError::Denied(_)), Some(expires)) => {
                invalidate_running(c, lease, settings, expires).await
            }
            (result, _) => result,
        }
    })
    .await
}

/// Only a separately committed read attempt can grant a replay dispatch permit.
pub enum ReplayEffect {
    Pending,
    Handoff,
    Ready(CommittedIntent),
    Observed {
        succeeded: bool,
        output: Option<String>,
    },
    Invalidated(Settled),
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum ReplayAction {
    Inspect,
    PrepareSpill,
    StartRead,
    RefreshUnstarted,
}

pub async fn recheck_replay_effect_authority(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    operation: &str,
    proposal: &Proposal,
    settings: &LeaseSettings,
    policy: &impl EffectPolicy,
) -> Result<ReplayEffect, LeaseError> {
    check_operation(
        c,
        lease,
        operation,
        proposal,
        settings,
        policy,
        ReplayAction::Inspect,
    )
    .await
}

pub async fn start_replayed_read(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    operation: &str,
    proposal: &Proposal,
    settings: &LeaseSettings,
    policy: &impl EffectPolicy,
) -> Result<ReplayEffect, LeaseError> {
    check_operation(
        c,
        lease,
        operation,
        proposal,
        settings,
        policy,
        ReplayAction::StartRead,
    )
    .await
}

pub(crate) async fn expire_unstarted_intent(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    operation: &str,
    proposal: &Proposal,
    settings: &LeaseSettings,
    policy: &impl EffectPolicy,
) -> Result<ReplayEffect, LeaseError> {
    check_operation(
        c,
        lease,
        operation,
        proposal,
        settings,
        policy,
        ReplayAction::RefreshUnstarted,
    )
    .await
}

async fn active_revision(
    c: &mut PgConnection,
    s: &Subject<'_>,
    artifact: &str,
    revision: &str,
) -> Result<(), StoreError> {
    if !crate::storage::read_revision(c, artifact, revision)
        .await?
        .is_some_and(|r| r.scope_id == s.scope && r.state == "active")
    {
        return Err(HIDDEN);
    }
    Ok(())
}

async fn invalidate_post_intent(
    tx: &mut durable::WriteTransaction<'_>,
    lease: &Lease<'_>,
    settings: &LeaseSettings,
    op: &PgRow,
    expires: i64,
) -> Result<ReplayEffect, StoreError> {
    let capability: &str = op.try_get("capability")?;
    let outcome: &str = op.try_get("outcome")?;
    let attempts: Option<i32> = op.try_get("dispatched_attempts")?;
    let ambiguous = capability != "repeatable_read"
        && (outcome == "outcome_unknown" || (outcome == "intent" && attempts != Some(0)));
    let id: &str = op.try_get("id")?;
    if outcome == "intent" && (!ambiguous || capability == "non_repeatable") {
        durable::record_observation(
            tx,
            &durable::Observation {
                scope: lease.scope_id,
                run: lease.run_id,
                operation: id,
                key: &format!("invalidated:{id}"),
                expected_revision: 0,
                outcome: if ambiguous {
                    "outcome_unknown"
                } else {
                    "failed"
                },
                handle: None,
                evidence: event(
                    "openmettle.effect-invalidated",
                    br#"{"reason":"authority_invalid"}"#,
                ),
            },
        )
        .await?;
    }
    let c = tx.connection()?;
    let now = sqlx::query_scalar::<_,i64>("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint
        FROM openmettle.runs WHERE id=$1::uuid AND scope_id=$2::uuid AND state='running'
        AND claim_token=$3::uuid AND cancel_reason IS NULL AND least(lease_expires_at,execution_expires_at)>clock_timestamp()")
        .bind(lease.run_id).bind(lease.scope_id).bind(lease.claim_token).fetch_optional(&mut *c).await?
        .ok_or(StoreError::Conflict("expired effect claim"))?;
    let expired = now >= expires;
    let (cancel, input) = if expired && !ambiguous {
        (
            None,
            leases::Settle::Failed(leases::FailReason::ApprovalExpired),
        )
    } else {
        if !expired {
            sqlx::query("UPDATE openmettle.runs SET cancel_reason='revoked' WHERE id=$1::uuid")
                .bind(lease.run_id)
                .execute(&mut *c)
                .await?;
        }
        (
            (!expired).then_some(CancelReason::Revoked),
            leases::Settle::Stopped,
        )
    };
    Ok(ReplayEffect::Invalidated(
        leases::settle_locked(
            c,
            lease,
            leases::ExecState::Running,
            cancel,
            settings,
            input,
        )
        .await?,
    ))
}

/// The base and tool components of ADR 0035 evidence contain the exact mapped
/// observations used at admission. Look up only these cycles when classifying expiry.
fn bound_observations(binding: &Binding) -> Result<Vec<String>, StoreError> {
    let mut bytes = binding
        .evidence
        .strip_prefix(b"openmettle/effect-authority/1\0")
        .ok_or(CONFLICT)?;
    let mut cycles = Vec::new();
    for _ in 0..2 {
        let (len, rest) = bytes.split_at_checked(8).ok_or(CONFLICT)?;
        let len = usize::try_from(u64::from_be_bytes(len.try_into().map_err(|_| CONFLICT)?))
            .map_err(|_| CONFLICT)?;
        let (field, rest) = rest.split_at_checked(len).ok_or(CONFLICT)?;
        bytes = rest;
        let field: Value = serde_json::from_slice(field).map_err(|_| CONFLICT)?;
        for observation in field[3].as_array().ok_or(CONFLICT)? {
            cycles.push(
                observation["change_id"]
                    .as_str()
                    .ok_or(CONFLICT)?
                    .to_owned(),
            );
        }
    }
    Ok(cycles)
}

async fn observed_output(
    c: &mut PgConnection,
    s: &Subject<'_>,
    op: &PgRow,
    ms: i64,
) -> Result<Option<String>, StoreError> {
    if op.try_get::<Option<&str>, _>("observation_format")? != Some(crate::mcp::RESULT_FORMAT) {
        return Ok(None);
    }
    let bytes: &[u8] = op.try_get("evidence")?;
    if bytes.len() > crate::mcp::INLINE_BYTES || op.try_get::<i32, _>("observation_version")? != 1 {
        return Err(CONFLICT);
    }
    let outcome: &str = op.try_get("outcome")?;
    let result = unique(bytes).map_err(|_| CONFLICT)?;
    if (outcome == "failed" && result["status"] != "tool_error")
        || (outcome == "succeeded" && result["status"] != "ok")
    {
        return Err(CONFLICT);
    }
    if result["storage"] == "spilled" {
        let provenance = &result["provenance"];
        let artifact = provenance["artifact_id"].as_str().ok_or(CONFLICT)?;
        let revision = provenance["revision_id"].as_str().ok_or(CONFLICT)?;
        let operation: &str = op.try_get("id")?;
        if provenance["operation_id"] != operation {
            return Err(CONFLICT);
        }
        readable_artifact(c, s, artifact, ms).await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM openmettle.artifact_revisions r
            JOIN openmettle.storage_reservations sr ON sr.id=r.reservation_id AND sr.scope_id=r.scope_id
            WHERE r.scope_id=$1::uuid AND r.artifact_id=$2::uuid AND r.id=$3::uuid AND r.state='active'
            AND sr.run_id=$4::uuid AND sr.operation_id=$5::uuid AND sr.state='settled'
            AND sr.idempotency_key LIKE 'tool-spill:%')").bind(s.scope).bind(artifact).bind(revision)
            .bind(s.run).bind(operation).fetch_one(c).await?;
        if !exists {
            return Err(HIDDEN);
        }
    }
    Ok(Some(
        std::str::from_utf8(bytes).map_err(|_| CONFLICT)?.to_owned(),
    ))
}

pub(crate) async fn check_operation(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    operation: &str,
    p: &Proposal,
    settings: &LeaseSettings,
    policy: &impl EffectPolicy,
    action: ReplayAction,
) -> Result<ReplayEffect, LeaseError> {
    settings.validate()?;
    let sent = Instant::now();
    leases::fenced(c, lease, Fence::Step, async |tx, held| {
        let c = tx.connection()?;
        let r = sqlx::query(RUN)
            .bind(lease.run_id)
            .bind(lease.scope_id)
            .fetch_one(&mut *c)
            .await?;
        let s = subject(&r, lease.scope_id, lease.run_id)?;
        let op = sqlx::query("SELECT id::text, request,capability,approval_id::text,dispatched_attempts,
                effective_expires_us,outcome,observation_format,observation_version,evidence
                FROM openmettle.operations WHERE scope_id=$1::uuid AND run_id=$2::uuid AND id=$3::uuid FOR UPDATE")
                .bind(s.scope).bind(lease.run_id).bind(operation).fetch_optional(&mut *c).await?.ok_or(CONFLICT)?;
        let approval: Option<&str> = op.try_get("approval_id")?;
        let (id, committed, endpoint) = committed_binding(c, &s, p, approval, &op).await?;
        if id != operation {
            return Err(CONFLICT);
        }
        let decision = sqlx::query(REQUEST)
            .bind(lease.run_id)
            .bind(approval)
            .fetch_optional(&mut *c)
            .await?;
        let decider = decision
            .as_ref()
            .and_then(|d| d.get::<Option<&str>, _>("deciding_session_id"));
        // Keep naturally expired sessions visible even when the live AUTH snapshot disappears.
        let mut bound: i64 = sqlx::query_scalar("SELECT least($1::bigint,$2::bigint,
                (SELECT min(least(ls.expires_ms,a.expires_ms))*1000 FROM openmettle.local_sessions ls
                 JOIN openmettle.local_identity_approvals a ON a.id=ls.approval_id
                 WHERE ls.id IN ($3,$4) AND NOT ls.revoked AND a.active),
                (SELECT min(least(m.expires_ms,m.issued_ms+1000::bigint*m.max_age_seconds))*1000
                 FROM openmettle.membership_observations m WHERE m.enabled AND (m.observation).state='present'
                 AND (m.observation).change_id::text=ANY($5::text[])))")
                .bind(committed.expires).bind(op.try_get::<Option<i64>,_>("effective_expires_us")?)
                .bind(s.session).bind(decider).bind(bound_observations(&committed)?).fetch_one(&mut *c).await?;
        let authority = async {
                let review = reviewed(policy, &s, p).map_err(|error| match error {
                    StoreError::Database(_) => error,
                    _ => DENIED,
                })?;
                if let EndpointKey::Supported { expires_us, .. } = review.endpoint_key {
                    bound = bound.min(expires_us);
                }
                if review != endpoint || review.reservation.is_some() {
                    return Err(DENIED);
                }
                if approval.is_some() {
                    let receipt = decision.as_ref().ok_or(DENIED)?;
                    if receipt.try_get::<Option<&str>, _>("decision")? != Some("approve")
                        || decider.is_none()
                        || !committed.matches(p, receipt)?
                        || receipt.try_get::<Option<&[u8]>, _>("decision_digest")? != Some(&committed.hash)
                    {
                        return Err(DENIED);
                    }
                }
                let proof = proof(&s, &review, decider);
                let snap = authorized(c, &proof, &review).await?;
                bound = bound.min(validity(&snap, &review));
                let auto = approval.is_none() && review.class != EffectClass::Read;
                if auto {
                    let actor = store::hydrate_worker_principal(c, s.actor, s.approval, snap.now / 1000)
                        .await?
                        .ok_or(DENIED)?;
                    if review.class != EffectClass::EligibleWrite
                        || !automatic(&r, &snap)?
                        || !authorize_capability(
                            &actor,
                            &store::load_platform_capabilities(c).await?,
                            YOLO,
                            CapabilityGate::OptIn,
                        )
                        .is_allowed()
                    {
                        return Err(DENIED);
                    }
                }
                let live = Binding::new(p, &s, &snap, &review, committed.expires, auto)?;
                if snap.now >= bound || live.hash != committed.hash || live.evidence != committed.evidence {
                    return Err(DENIED);
                }
                let outcome: &str = op.try_get("outcome")?;
                if outcome == "succeeded" && p.tool == crate::mcp::READ_RANGE {
                    active_revision(
                        c,
                        &s,
                        review.artifact.as_deref().ok_or(DENIED)?,
                        p.arguments["revision_id"].as_str().ok_or(DENIED)?,
                    )
                    .await?;
                }
                let observed = matches!(outcome, "succeeded" | "failed");
                let output = if observed {
                    observed_output(c, &s, &op, snap.now / 1000).await?
                } else {
                    None
                };
                let attempts: Option<i32> = op.try_get("dispatched_attempts")?;
                let start = action == ReplayAction::StartRead && !observed;
                if start && (review.class != EffectClass::Read || outcome != "intent") {
                    return Err(CONFLICT);
                }
                let increment = start && attempts.is_some_and(|n| n < 3);
                if increment
                    && sent
                        + held
                            .lease_remaining
                            .min(held.execution_remaining)
                            .saturating_sub(settings.lease / 3)
                        <= Instant::now()
                {
                    return Ok(Some(ReplayEffect::Handoff));
                }
                let guard = "FROM snap,t,openmettle.runs r WHERE r.id=$11::uuid AND r.state='running'
                            AND r.cancel_reason IS NULL AND r.claim_token=$12::uuid AND least(r.lease_expires_at,r.execution_expires_at)>t.at
                            AND snap.now_us<$13 AND snap.base=$14 AND snap.tool=$15 AND (NOT $16 OR (snap.eligible AND snap.yolo=$17))";
                let sql = if increment {
                    format!("{AUTH} UPDATE openmettle.operations o SET dispatched_attempts=o.dispatched_attempts+1 {guard}
                                AND o.id=$18::uuid AND o.run_id=r.id AND o.outcome='intent' AND o.capability='repeatable_read' AND o.dispatched_attempts<3 RETURNING snap.now_us")
                } else {
                    format!("{AUTH} SELECT snap.now_us {guard}")
                };
                let mut q = proof
                    .query(&sql)
                    .bind(lease.claim_token)
                    .bind(bound)
                    .bind(&snap.base)
                    .bind(&snap.tool)
                    .bind(auto)
                    .bind(&snap.yolo);
                if increment {
                    q = q.bind(operation);
                }
                let now: i64 = q
                    .fetch_optional(&mut *c)
                    .await?
                    .ok_or(DENIED)?
                    .try_get("now_us")?;
                if observed {
                    return Ok(Some(ReplayEffect::Observed {
                        succeeded: outcome == "succeeded",
                        output,
                    }));
                }
                if start && !increment {
                    return Ok(None);
                }
                if !increment && action != ReplayAction::RefreshUnstarted {
                    return Ok(Some(ReplayEffect::Pending));
                }
                Ok(Some(ReplayEffect::Ready(CommittedIntent::new(
                    id,
                    op.try_get("request")?,
                    sent,
                    bound - now,
                    held,
                    settings,
                ))))
            }.await;
        match authority {
            Ok(Some(result)) => Ok(result),
            Ok(None) => {
                let output = crate::mcp::ToolFault::Transient.envelope();
                crate::mcp::observe(tx, lease, operation, false, &output).await?;
                Ok(ReplayEffect::Observed {
                    succeeded: false,
                    output: Some(output),
                })
            }
            Err(StoreError::Denied(_) | StoreError::NotFound) => {
                // Publication has a known response in hand. Record that write before
                // settling the run, so revocation cannot turn success into uncertainty.
                if action == ReplayAction::PrepareSpill
                    && op.try_get::<&str, _>("outcome")? == "intent"
                    && op.try_get::<&str, _>("capability")? != "repeatable_read"
                {
                    return Err(DENIED);
                }
                invalidate_post_intent(tx, lease, settings, &op, bound).await
            }
            Err(error) => Err(error),
        }
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_class_requires_reviewed_endpoint_support() {
        let mut review = Review {
            class: EffectClass::EligibleWrite,
            capability: "tool.mail".into(),
            gate: CapabilityGate::OnByDefault,
            tool_policy: "1".into(),
            destination_policy: "1".into(),
            endpoint_id: "fixture".into(),
            endpoint_version: "1".into(),
            endpoint_key: EndpointKey::Unknown,
            authoritative_lookup: false,
            artifact: None,
            reservation: None,
        };
        for support in [EndpointKey::Unknown, EndpointKey::Unsupported] {
            review.endpoint_key = support;
            review.authoritative_lookup = false;
            assert_eq!(review.capability_class(), "non_repeatable");
            review.authoritative_lookup = true;
            assert_eq!(review.capability_class(), "lookup");
        }
        review.endpoint_key = EndpointKey::Supported {
            namespace: "account".into(),
            field: "Idempotency-Key".into(),
            key: "one-effect".into(),
            valid_from_us: 1,
            expires_us: 2,
        };
        assert_eq!(review.capability_class(), "idempotent");
        review.class = EffectClass::Read;
        assert_eq!(review.capability_class(), "repeatable_read");
    }

    #[test]
    fn canonical_integer_profile_and_binding_known_answer() {
        let make = |tool: &str, version: &str, recipient: &str, args: &[u8]| {
            Proposal::new(
                "k",
                tool,
                version,
                args,
                Destination {
                    connection: "c",
                    account: "acct",
                    action: "append",
                    resource: recipient,
                },
            )
        };
        let s = Subject {
            scope: "00000000-0000-0000-0000-000000000001",
            run: Some("00000000-0000-0000-0000-000000000002"),
            actor: "00000000-0000-0000-0000-000000000003",
            approval: "",
            conversation: "",
            session: "",
        };
        let bind =
            |p: Proposal| projects::hex(&p.binding(&s, 1_800_000_000_123_456, b"authority-v1"));
        let raw = br#"{"z":{"b":3,"a":4},"a":[1,2]}"#;
        let known = "4fd747fb9a29324f30d3192b3445ff6048fc4ebb74b9a1939753020320029c6c";
        assert_eq!(bind(make("mail", "v1", "alice", raw).unwrap()), known);
        assert_eq!(
            bind(make("mail", "v1", "alice", br#"{ "a":[1,2],"z":{"a":4,"b":3}}"#).unwrap()),
            known
        );
        for changed in [
            make("mail", "v2", "alice", raw),
            make("mail2", "v1", "alice", raw),
            make("mail", "v1", "bob", raw),
            make("mail", "v1", "alice", br#"{"a":[2,1],"z":{"a":4,"b":3}}"#),
        ] {
            assert_ne!(bind(changed.unwrap()), known);
        }
        for bad in [
            r#"{"a":1,"\u0061":2}"#,
            r#"{"a":[{"x":2,"x":2}]}"#,
            r#"{"v":1.0}"#,
            r#"{"v":1e2}"#,
            r#"{"v":-0}"#,
            r#"{"v":9223372036854775808}"#,
            r#"{"v":-9223372036854775809}"#,
            "[]",
            "{}{}",
        ] {
            assert!(canonical_arguments(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
