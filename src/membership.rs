//! Login-time reconciliation for owner-enrolled existing identities (ADR 0021).
use crate::{
    auth::VerifiedAssertion,
    grants::{self, Assignment, ChangeInput, Decision, Target},
    runs::WriteTransaction,
    sessions::Error,
};
use serde_json::Value;
use sqlx::{Connection, PgConnection, Row};
use std::collections::BTreeSet;

/// Evidence at one primary-database snapshot. This is not resource authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Present,
    Absent,
    Missing,
    Partial,
    Ambiguous,
    Stale,
    Failed,
}

use Observation::*;

impl Observation {
    fn label(self) -> &'static str {
        match self {
            Present => "present",
            Absent => "absent",
            Missing => "missing",
            Partial => "partial",
            Ambiguous => "ambiguous",
            Stale => "stale",
            Failed => "failed",
        }
    }
}

// Only these two direct, complete-array profiles are supported. The verified payload is
// bounded by MAX_ID_TOKEN_BYTES. Discard every unrelated claim and distributed destination.
pub(crate) struct Evidence {
    groups: Result<BTreeSet<String>, Observation>,
    roles: Result<BTreeSet<String>, Observation>,
}
impl Evidence {
    pub(crate) fn from_signed_payload(payload: Option<Value>) -> Self {
        let list = |name: &str| {
            let obj = payload
                .as_ref()
                .and_then(Value::as_object)
                .ok_or(Ambiguous)?;
            if ["hasgroups", "_claim_names", "_claim_sources"]
                .iter()
                .any(|key| obj.contains_key(*key))
                || obj
                    .keys()
                    .any(|key| key.starts_with("groups:") || key.starts_with("roles:"))
            {
                return Err(Partial);
            }
            let entries = obj.get(name).ok_or(Missing)?.as_array().ok_or(Ambiguous)?;
            if entries.len() > 128 {
                return Err(Partial);
            }
            let mut values = BTreeSet::new();
            for entry in entries {
                let value = entry.as_str().ok_or(Ambiguous)?;
                if value.is_empty()
                    || value.len() > 1024
                    || value.chars().any(char::is_control)
                    || !values.insert(value.to_owned())
                {
                    return Err(Ambiguous);
                }
            }
            Ok(values)
        };
        Self {
            groups: list("groups"),
            roles: list("roles"),
        }
    }
    pub(crate) fn select(&self, kind: &str, name: &str, value: &str) -> Observation {
        let values = match (kind, name) {
            ("group", "groups") => &self.groups,
            ("app_role", "roles") => &self.roles,
            _ => return Failed,
        };
        match values {
            Ok(set) if set.contains(value) => Present,
            Ok(_) => Absent,
            Err(reason) => *reason,
        }
    }
}

// A matching value has meaning only under the selected rule and provider.
struct Selector<'a> {
    provider: &'a str,
    issuer: &'a str,
    kind: &'a str,
    name: &'a str,
    value: &'a str,
}

impl Selector<'_> {
    fn observe(&self, proof: &VerifiedAssertion, age: i32, now_ms: i64) -> (i64, i64, Observation) {
        let (issued, expires) = proof.membership_window(age);
        let identity = proof.identity();
        let observation =
            if self.provider != identity.provider_config_id() || self.issuer != identity.issuer() {
                Failed
            } else if now_ms < issued || now_ms >= expires {
                Stale
            } else {
                proof.membership.select(self.kind, self.name, self.value)
            };
        (issued, expires, observation)
    }
}

pub(crate) struct Subject<'a> {
    pub approval: &'a str,
    pub user: &'a str,
    pub epoch: i64,
    pub membership_revision: i64,
    pub user_generation: i64,
    pub approval_generation: i64,
}

// Called inside session issuance with provider, approval and user locked, after exact
// identity, authority epoch, account status and consumed-login checks.
pub(crate) async fn reconcile(
    tx: &mut WriteTransaction<'_>,
    subject: Subject<'_>,
    assertion: &VerifiedAssertion,
    login: &str,
) -> Result<Option<i64>, Error> {
    let Some(enrollment) = sqlx::query(
        "SELECT rule_id::text,rule_revision,project_id::text,scope_id::text,max_age_seconds,
                issued_ms,expires_ms,(observation).state AS state,(observation).change_id::text AS change_id, floor_ms FROM openmettle.membership_observations
         WHERE approval_id=$1::uuid AND enabled AND config_revision <= $2 FOR UPDATE",
    )
    .bind(subject.approval)
    .bind(subject.membership_revision)
    .fetch_optional(tx.connection()?)
    .await?
    else {
        return Ok(None);
    };
    let rule: &str = enrollment.try_get("rule_id")?;
    let revision: i64 = enrollment.try_get("rule_revision")?;
    let project: &str = enrollment.try_get("project_id")?;
    let scope: &str = enrollment.try_get("scope_id")?;
    // Lock before reading the revision and the assignment, including when no change is needed.
    let config = sqlx::query(
        "SELECT r.last_revision,r.provider_config_id::text,r.issuer,v.enabled,v.selector_kind,
                v.claim_name,v.claim_value,v.binding_format,v.binding_version,v.binding
         FROM openmettle.grant_mapping_rules r JOIN openmettle.grant_mapping_revisions v
           ON v.rule_id=r.id AND v.revision=$2
         WHERE r.id=$1::uuid FOR NO KEY UPDATE OF r",
    )
    .bind(rule)
    .bind(revision)
    .fetch_one(tx.connection()?)
    .await?;
    let configured = config.try_get::<i64, _>("last_revision")? == revision
        && config.try_get::<bool, _>("enabled")?
        && config.try_get::<&str, _>("binding_format")? == "openmettle.project-member"
        && config.try_get::<i32, _>("binding_version")? == 1
        && config.try_get::<&[u8], _>("binding")? == project.as_bytes();
    let now_ms = crate::sessions::now(tx.connection()?).await?;
    let age = enrollment.try_get::<i32, _>("max_age_seconds")?;
    let selector = Selector {
        provider: config.try_get("provider_config_id")?,
        issuer: config.try_get("issuer")?,
        kind: config.try_get("selector_kind")?,
        name: config.try_get("claim_name")?,
        value: config.try_get("claim_value")?,
    };
    let (issued, mut expires, mut observation) = selector.observe(assertion, age, now_ms);
    if !configured {
        observation = Failed;
    }
    let previous = enrollment.try_get::<Option<i64>, _>("issued_ms")?;
    if enrollment
        .try_get::<Option<i64>, _>("floor_ms")?
        .is_some_and(|floor| issued <= floor)
        || previous.is_some_and(|v| issued < v)
    {
        return Ok(None);
    }
    if previous == Some(issued) {
        // One issue time cannot order two conflicting assertions. Require a newer time
        // to resolve that ambiguity. A replay can never extend the original expiry.
        let prior = enrollment.try_get::<&str, _>("state")?;
        if prior == observation.label() && enrollment.try_get::<i64, _>("expires_ms")? <= expires {
            return Ok(None);
        }
        // Even identical evidence with a shorter expiry may only shorten the old window.
        if prior == observation.label() {
            sqlx::query("UPDATE openmettle.membership_observations SET expires_ms=$2 WHERE approval_id=$1::uuid")
                .bind(subject.approval).bind(expires).execute(tx.connection()?).await?;
            return Ok(None);
        }
        observation = Ambiguous;
        expires = expires.min(enrollment.try_get("expires_ms")?);
    }
    let mut change: Option<String> = enrollment.try_get("change_id")?;
    if matches!(observation, Present | Absent) {
        let assignment = Assignment {
            scope,
            target: Target::Project(project),
            grantee: subject.user,
            format: "openmettle.project-member",
            version: 1,
            key: subject.approval,
            mapping_rule: Some(rule),
        };
        if !apply_assignment(
            tx,
            assignment,
            project,
            revision,
            observation == Present,
            login,
            &mut change,
        )
        .await?
        {
            observation = Failed;
        }
    }
    sqlx::query(
        "UPDATE openmettle.membership_observations SET issued_ms=$2,expires_ms=$3,observation=ROW($4::text,$8::uuid)::openmettle.membership_evidence,
                 epoch=$5,approval_generation=$6,user_generation=$7 WHERE approval_id=$1::uuid",
    )
    .bind(subject.approval)
    .bind(issued)
    .bind(expires)
    .bind(observation.label())
    .bind(subject.epoch)
    .bind(subject.approval_generation)
    .bind(subject.user_generation)
    .bind(change)
    .execute(tx.connection()?)
    .await?;
    Ok(matches!(observation, Present | Absent).then_some(expires))
}

// The locked rule serializes all mapped writers, including v5 callers.
async fn apply_assignment(
    tx: &mut WriteTransaction<'_>,
    assignment: Assignment<'_>,
    project: &str,
    revision: i64,
    present: bool,
    login: &str,
    confirmed: &mut Option<String>,
) -> Result<bool, Error> {
    let current = sqlx::query(
        "SELECT c.id::text AS change_id,a.last_revision,c.decision,c.cycle_id::text,c.mapping_revision
             FROM openmettle.grant_assignments a JOIN openmettle.grant_changes c
               ON c.assignment_id=a.id AND c.revision=a.last_revision
             WHERE a.scope_id=$1::uuid AND a.project_id=$2::uuid AND a.grantee_user_id=$3::uuid
               AND a.mapping_rule_id=$4::uuid AND a.assignment_format='openmettle.project-member'
               AND a.assignment_version=1 AND a.assignment_key=$5",
    )
    .bind(assignment.scope)
    .bind(project)
    .bind(assignment.grantee)
    .bind(assignment.mapping_rule)
    .bind(assignment.key)
    .fetch_optional(tx.connection()?)
    .await?;
    let latest = current
        .as_ref()
        .map(|row| row.try_get::<&str, _>("change_id"))
        .transpose()?;
    if latest != confirmed.as_deref() {
        // Independent v5 mutation. Never adopt this revision in a later login.
        return Ok(false);
    }
    let mut expected = 0;
    let mut active = false;
    if let Some(row) = current {
        expected = row.try_get("last_revision")?;
        active = row.try_get::<&str, _>("decision")? == "grant";
        if active && (!present || row.try_get::<i64, _>("mapping_revision")? != revision) {
            let change = ChangeInput {
                assignment,
                actor: assignment.grantee,
                key: &format!("membership-revoke/{login}"),
                expected_revision: expected,
                mapping_revision: Some(row.try_get("mapping_revision")?),
                decision: Decision::Revoke(Some(row.try_get("cycle_id")?)),
            };
            let receipt = grants::change_grant(tx, &change).await?;
            expected = receipt.revision;
            *confirmed = Some(receipt.change);
            active = false;
        }
    }
    if present && !active {
        let receipt = grants::change_grant(
            tx,
            &ChangeInput {
                assignment,
                actor: assignment.grantee,
                key: &format!("membership-grant/{login}"),
                expected_revision: expected,
                mapping_revision: Some(revision),
                decision: Decision::Grant,
            },
        )
        .await?;
        *confirmed = Some(receipt.change);
    }
    Ok(true)
}

/// Current mapped membership for one exact approval and project. Failure, expiry, rule
/// replacement and incomplete observations yield no positive decision. Use a primary connection.
pub async fn current(
    c: &mut PgConnection,
    approval: &str,
    project: &str,
    policy: &crate::sessions::Policy,
) -> Result<Observation, Error> {
    crate::runs::uuid(approval)
        .and_then(|()| crate::runs::uuid(project))
        .map_err(|_| Error::Rejected)?;
    if c.is_in_transaction() {
        return Err(Error::Rejected);
    }
    let query = sqlx::query_scalar::<_,String>(
        "SELECT CASE
          WHEN NOT m.enabled OR NOT a.active OR a.expires_ms <= t.ms OR u.disabled_at IS NOT NULL
            OR r.last_revision <> m.rule_revision OR NOT v.enabled
            OR v.binding_format <> 'openmettle.project-member' OR v.binding_version <> 1
            OR v.binding <> convert_to(m.project_id::text,'UTF8')
            OR e.revision IS NULL OR h.id IS DISTINCT FROM (m.observation).change_id THEN 'failed'
          WHEN m.issued_ms IS NULL THEN 'missing'
          WHEN m.epoch IS DISTINCT FROM e.epoch
            OR m.approval_generation IS DISTINCT FROM a.access_generation
            OR m.user_generation IS DISTINCT FROM u.session_generation THEN 'failed'
          WHEN t.ms < m.issued_ms OR t.ms >= least(m.expires_ms, m.issued_ms + 1000::bigint*m.max_age_seconds) THEN 'stale'
          WHEN (m.observation).state='present' AND
               (h.decision <> 'grant' OR h.cycle_id IS DISTINCT FROM h.id OR h.mapping_revision <> m.rule_revision) THEN 'failed'
          ELSE (m.observation).state END
         FROM openmettle.membership_observations m JOIN openmettle.local_identity_approvals a ON a.id=m.approval_id
         JOIN openmettle.user_identities i ON i.id=a.identity_id JOIN openmettle.users u ON u.id=i.user_id
         JOIN openmettle.grant_mapping_rules r ON r.id=m.rule_id AND r.provider_config_id=a.provider_id AND r.issuer=i.issuer
         JOIN openmettle.grant_mapping_revisions v ON v.rule_id=r.id AND v.revision=m.rule_revision
         LEFT JOIN openmettle.grant_assignments g ON g.scope_id=m.scope_id AND g.project_id=m.project_id
           AND g.grantee_user_id=u.id AND g.mapping_rule_id=r.id AND g.assignment_key=a.id::text
           AND g.assignment_format='openmettle.project-member' AND g.assignment_version=1
         LEFT JOIN openmettle.grant_changes h ON h.assignment_id=g.id AND h.revision=g.last_revision
         LEFT JOIN LATERAL (SELECT epoch,revision FROM openmettle.login_provider_revisions WHERE provider_id=a.provider_id
                            ORDER BY epoch DESC LIMIT 1) e ON true
         CROSS JOIN (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS ms) t
         WHERE a.id=$1::uuid AND m.project_id=$2::uuid"
    ).bind(approval).bind(project).fetch_optional(c);
    let result = tokio::time::timeout(policy.deadline(), query)
        .await
        .map_err(|_| Error::Timeout)??;
    Ok(match result.as_deref() {
        Some("present") => Present,
        Some("absent") => Absent,
        Some("partial") => Partial,
        Some("missing") => Missing,
        Some("ambiguous") => Ambiguous,
        Some("stale") => Stale,
        _ => Failed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{ExpectedNonce, ExpectedNonceDigest, Policy, TrustedProvider, UnverifiedIdToken},
        login::fixture,
    };
    use serde_json::json;

    #[test]
    fn signed_claims_feed_only_the_configured_selector() {
        let p = TrustedProvider::new(
            fixture::ID,
            fixture::ISSUER,
            fixture::CLIENT,
            &fixture::jwks(),
        )
        .unwrap();
        let nonce = "x".repeat(43);
        let expected = ExpectedNonceDigest::from_nonce(&ExpectedNonce::new(&nonce).unwrap());
        for (claims, groups, roles) in [
            (
                json!({"groups":["team"],"roles":["other"]}),
                Present,
                Absent,
            ),
            (json!({"groups":[],"roles":["team"]}), Absent, Present),
            (json!({"email":"team","hd":"team"}), Missing, Missing),
            (json!({"groups":null}), Ambiguous, Missing),
            (json!({"groups":["team",false]}), Ambiguous, Missing),
            (json!({"groups":["team","team"]}), Ambiguous, Missing),
            (
                json!({"groups":["team"],"roles":["team"],"hasgroups":true}),
                Partial,
                Partial,
            ),
            (
                json!({"groups":[],"_claim_names":{"groups":"src1"},"_claim_sources":{"src1":{"endpoint":"https://unused.example.test"}}}),
                Partial,
                Partial,
            ),
            (json!({"groups": vec!["team";129]}), Partial, Missing),
        ] {
            let raw = fixture::membership_token("synthetic-subject", &nonce, 1799999990, claims);
            let token = UnverifiedIdToken::new(&raw).unwrap();
            let proof = p
                .verify_assertion(&token, &expected, &Policy::default(), fixture::now())
                .unwrap();
            let mapping = Selector {
                provider: fixture::ID,
                issuer: fixture::ISSUER,
                kind: "group",
                name: "groups",
                value: "team",
            };
            let now_ms = 1800000000000;
            assert_eq!(mapping.observe(&proof, 20, now_ms).2, groups);
            assert_eq!(mapping.observe(&proof, 10, now_ms).2, Stale);
            assert_eq!(mapping.observe(&proof, 20, 1799999989999).2, Stale);
            assert_eq!(
                Selector {
                    provider: "00000000-0000-0000-0000-000000000099",
                    ..mapping
                }
                .observe(&proof, 20, now_ms)
                .2,
                Failed
            );
            assert_eq!(
                Selector {
                    issuer: "https://other.example.test",
                    ..mapping
                }
                .observe(&proof, 20, now_ms)
                .2,
                Failed
            );
            assert_eq!(proof.membership.select("group", "groups", "team"), groups);
            assert_eq!(proof.membership.select("app_role", "roles", "team"), roles);
            assert_eq!(proof.membership.select("group", "email", "team"), Failed);
            assert_eq!(proof.membership_window(20), (1799999990000, 1800000010000));
        }
        let wrong = fixture::membership_token(
            "synthetic-subject",
            &"z".repeat(43),
            1799999990,
            json!({"groups":["team"]}),
        );
        assert!(
            p.verify_assertion(
                &UnverifiedIdToken::new(&wrong).unwrap(),
                &expected,
                &Policy::default(),
                fixture::now()
            )
            .is_err()
        );
    }
}
