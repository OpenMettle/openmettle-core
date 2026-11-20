//! Grant persistence and provenance, never authorization. See ADRs 0006 and 0027.
use crate::runs::{Error, WriteTransaction, bounded, digest, finish, identity, uuid};
use sqlx::{Acquire, PgConnection, Row, postgres::PgRow};

#[derive(Clone, Copy)]
pub struct MappingInput<'a> {
    pub rule: &'a str,
    pub provider: &'a str,
    pub issuer: &'a str,
    pub actor: &'a str,
    pub key: &'a str,
    pub expected_revision: i64,
    pub enabled: bool,
    pub selector_kind: &'a str,
    pub claim_name: &'a str,
    pub claim_value: &'a str,
    pub binding_format: &'a str,
    pub binding_version: i32,
    pub binding: &'a [u8],
}
#[derive(Debug, PartialEq, Eq)]
pub struct MappingReceipt {
    pub rule: String,
    pub revision: i64,
}
#[derive(Clone, Copy)]
pub enum Target<'a> {
    Project(&'a str),
    Conversation(&'a str),
    Artifact(&'a str),
}
impl<'a> Target<'a> {
    fn parts(self) -> (&'static str, &'a str) {
        match self {
            Self::Project(id) => ("project", id),
            Self::Conversation(id) => ("conversation", id),
            Self::Artifact(id) => ("artifact", id),
        }
    }
}
/// A borrowed [`crate::authz::Grantee`]: the recipient of an assignment (migration 16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grantee<'a> {
    User(&'a str),
    LocalGroup(&'a str),
    /// The exact OIDC group claim value: 1 to 1024 bytes without control characters.
    OidcGroup(&'a str),
    /// Every member of the containing project; resource targets only.
    Project,
}
impl<'a> From<&'a crate::authz::Grantee> for Grantee<'a> {
    fn from(g: &'a crate::authz::Grantee) -> Self {
        use crate::authz::Grantee as G;
        match g {
            G::User(id) => Self::User(id),
            G::LocalGroup(id) => Self::LocalGroup(id),
            G::OidcGroup(id) => Self::OidcGroup(id),
            G::Project => Self::Project,
        }
    }
}
impl<'a> Grantee<'a> {
    /// The `grantee_kind` and the user, local group and OIDC group columns. Exactly the column
    /// of the kind is set.
    pub(crate) fn columns(
        self,
    ) -> (
        &'static str,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
    ) {
        match self {
            Self::User(id) => ("user", Some(id), None, None),
            Self::LocalGroup(id) => ("local_group", None, Some(id), None),
            Self::OidcGroup(id) => ("oidc_group", None, None, Some(id)),
            Self::Project => ("project", None, None, None),
        }
    }
    fn from_columns(row: &'a PgRow) -> Self {
        match row.get::<&str, _>("grantee_kind") {
            "user" => Self::User(row.get("grantee_user_id")),
            "local_group" => Self::LocalGroup(row.get("grantee_local_group_id")),
            "oidc_group" => Self::OidcGroup(row.get("grantee_oidc_group_id")),
            _ => Self::Project,
        }
    }
    /// Request-identity bytes. A user is its UUID, byte-identical to ADR 0006 version 1, so every
    /// earlier request still replays. Other kinds are `kind NUL id`; a UUID never holds NUL.
    fn identity(self) -> Vec<u8> {
        match self.columns() {
            ("user", Some(id), ..) => id.as_bytes().to_vec(),
            (kind, _, local, oidc) => [kind, "\0", local.or(oidc).unwrap_or("")]
                .concat()
                .into_bytes(),
        }
    }
}
#[derive(Clone, Copy)]
pub struct Assignment<'a> {
    pub scope: &'a str,
    pub target: Target<'a>,
    pub grantee: Grantee<'a>,
    pub format: &'a str,
    pub version: i32,
    pub key: &'a str,
    pub mapping_rule: Option<&'a str>,
}
impl<'a> Assignment<'a> {
    /// Identifier formats of the scope, target and grantee; returns the target kind and ID.
    fn validate(&self) -> Result<(&'static str, &'a str), Error> {
        let (kind, target) = self.target.parts();
        uuid(self.scope)?;
        uuid(target)?;
        match self.grantee {
            Grantee::User(id) | Grantee::LocalGroup(id) => uuid(id)?,
            Grantee::OidcGroup(id) if !bounded(id, 1024) || id.chars().any(char::is_control) => {
                return Err(Error::Invalid);
            }
            // A project-wide grantee is a resource share; it never targets the project itself.
            Grantee::Project if kind == "project" => return Err(Error::Invalid),
            _ => {}
        }
        Ok((kind, target))
    }
}
#[derive(Clone, Copy)]
pub enum Decision<'a> {
    Grant,
    /// None records an inactive tombstone; Some must name the current active cycle.
    Revoke(Option<&'a str>),
}
#[derive(Clone, Copy)]
pub struct ChangeInput<'a> {
    pub assignment: Assignment<'a>,
    pub actor: &'a str,
    pub key: &'a str,
    pub expected_revision: i64,
    pub mapping_revision: Option<i64>,
    pub decision: Decision<'a>,
}
/// Historical receipt. This is not current access or current persistence state.
#[derive(Debug, PartialEq, Eq)]
pub struct GrantReceipt {
    pub change: String,
    pub assignment: String,
    pub revision: i64,
    pub granted: bool,
    pub cycle: Option<String>,
}
#[derive(Debug)]
pub struct AssignmentSnapshot {
    pub assignment: String,
    pub revision: i64,
    pub recorded_active: bool,
    pub cycle: Option<String>,
    pub mapping_eligible: bool,
}
/// The migration 16 natural key of `grant_assignments a`, binding $1 scope, $2 target kind,
/// $3 target, $4 grantee kind, $5 user, $6 local group, $7 OIDC group, $8 format, $9 version,
/// $10 key and $11 mapping rule.
macro_rules! natural_key {
    () => {
        "a.scope_id=$1::uuid AND a.target_kind=$2 AND a.target_id=$3::uuid AND a.grantee_kind=$4 AND a.grantee_user_id IS NOT DISTINCT FROM $5::uuid AND a.grantee_local_group_id IS NOT DISTINCT FROM $6::uuid AND a.grantee_oidc_group_id IS NOT DISTINCT FROM $7 AND a.assignment_format=$8 AND a.assignment_version=$9 AND a.assignment_key=$10 AND a.mapping_rule_id IS NOT DISTINCT FROM $11::uuid"
    };
}
fn revision(v: i64) -> Result<i64, Error> {
    if !(0..i64::MAX).contains(&v) {
        return Err(Error::Invalid);
    }
    Ok(v + 1)
}
fn mapping_identity(r: &MappingInput<'_>) -> Vec<u8> {
    identity(
        b"openmettle/grant-mapping/1\0",
        &[
            r.rule.as_bytes(),
            r.provider.as_bytes(),
            r.issuer.as_bytes(),
            r.actor.as_bytes(),
            r.key.as_bytes(),
            &r.expected_revision.to_be_bytes(),
            &[u8::from(r.enabled)],
            r.selector_kind.as_bytes(),
            r.claim_name.as_bytes(),
            r.claim_value.as_bytes(),
            r.binding_format.as_bytes(),
            &r.binding_version.to_be_bytes(),
            r.binding,
        ],
    )
}
fn change_identity(r: &ChangeInput<'_>) -> Vec<u8> {
    let a = r.assignment;
    let (kind, target) = a.target.parts();
    let (decision, cycle) = match r.decision {
        Decision::Grant => ("grant", None),
        Decision::Revoke(c) => ("revoke", c),
    };
    identity(
        b"openmettle/grant-change/1\0",
        &[
            a.scope.as_bytes(),
            kind.as_bytes(),
            target.as_bytes(),
            &a.grantee.identity(),
            a.format.as_bytes(),
            &a.version.to_be_bytes(),
            a.key.as_bytes(),
            a.mapping_rule.unwrap_or("").as_bytes(),
            &r.mapping_revision.unwrap_or(0).to_be_bytes(),
            r.actor.as_bytes(),
            r.key.as_bytes(),
            &r.expected_revision.to_be_bytes(),
            decision.as_bytes(),
            cycle.unwrap_or("").as_bytes(),
        ],
    )
}
async fn mapping_replay(
    c: &mut PgConnection,
    r: &MappingInput<'_>,
    id: &[u8],
) -> Result<Option<MappingReceipt>, Error> {
    let row = sqlx::query("SELECT v.*,r.provider_config_id::text,r.issuer FROM openmettle.grant_mapping_revisions v JOIN openmettle.grant_mapping_rules r ON r.id=v.rule_id WHERE v.rule_id=$1::uuid AND v.actor_user_id=$2::uuid AND v.request_key=$3")
        .bind(r.rule).bind(r.actor).bind(r.key).fetch_optional(c).await?;
    let Some(row) = row else { return Ok(None) };
    let stored = MappingInput {
        rule: r.rule,
        provider: row.get("provider_config_id"),
        issuer: row.get("issuer"),
        actor: r.actor,
        key: r.key,
        expected_revision: row.get::<i64, _>("revision") - 1,
        enabled: row.get("enabled"),
        selector_kind: row.get("selector_kind"),
        claim_name: row.get("claim_name"),
        claim_value: row.get("claim_value"),
        binding_format: row.get("binding_format"),
        binding_version: row.get("binding_version"),
        binding: row.get("binding"),
    };
    if row.get::<Vec<u8>, _>("request_identity") != id
        || row.get::<Vec<u8>, _>("request_digest") != digest(id)
        || mapping_identity(&stored) != id
    {
        return Err(Error::Conflict);
    }
    Ok(Some(MappingReceipt {
        rule: r.rule.into(),
        revision: row.get("revision"),
    }))
}
/// Record an immutable configuration observation. Provider UUID is provenance, not trust.
pub async fn record_mapping_revision(
    tx: &mut WriteTransaction<'_>,
    r: &MappingInput<'_>,
) -> Result<MappingReceipt, Error> {
    for v in [r.rule, r.provider, r.actor] {
        uuid(v)?;
    }
    let next = revision(r.expected_revision)?;
    if !bounded(r.issuer, 2048)
        || !bounded(r.key, 128)
        || !matches!(r.selector_kind, "group" | "app_role")
        || !bounded(r.claim_name, 128)
        || !bounded(r.claim_value, 1024)
        || !bounded(r.binding_format, 128)
        || r.binding_version <= 0
        || r.binding.len() > 16384
    {
        return Err(Error::Invalid);
    }
    let id = mapping_identity(r);
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        if let Some(receipt) = mapping_replay(&mut sp,r,&id).await? { return Ok(receipt); }
        sqlx::query("INSERT INTO openmettle.grant_mapping_rules(id,provider_config_id,issuer,created_by_user_id) VALUES ($1::uuid,$2::uuid,$3,$4::uuid) ON CONFLICT DO NOTHING")
            .bind(r.rule).bind(r.provider).bind(r.issuer).bind(r.actor).execute(&mut *sp).await?;
        let row = sqlx::query("SELECT provider_config_id::text,issuer,last_revision FROM openmettle.grant_mapping_rules WHERE id=$1::uuid FOR NO KEY UPDATE")
            .bind(r.rule).fetch_one(&mut *sp).await?;
        if let Some(receipt) = mapping_replay(&mut sp,r,&id).await? { return Ok(receipt); }
        if row.get::<String,_>("provider_config_id")!=r.provider || row.get::<String,_>("issuer")!=r.issuer { return Err(Error::Conflict); }
        if row.get::<i64,_>("last_revision")!=r.expected_revision { return Err(Error::StaleRevision); }
        sqlx::query("INSERT INTO openmettle.grant_mapping_revisions(rule_id,revision,actor_user_id,request_key,enabled,selector_kind,claim_name,claim_value,binding_format,binding_version,binding,request_identity,request_digest) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(r.rule).bind(next).bind(r.actor).bind(r.key).bind(r.enabled).bind(r.selector_kind).bind(r.claim_name).bind(r.claim_value).bind(r.binding_format).bind(r.binding_version).bind(r.binding).bind(&id).bind(digest(&id)).execute(&mut *sp).await?;
        sqlx::query("UPDATE openmettle.grant_mapping_rules SET last_revision=$2 WHERE id=$1::uuid").bind(r.rule).bind(next).execute(&mut *sp).await?;
        Ok(MappingReceipt { rule:r.rule.into(),revision:next })
    }.await;
    let result = finish(sp, result).await?;
    tx.restore(outer);
    result
}
fn receipt(row: &PgRow) -> GrantReceipt {
    GrantReceipt {
        change: row.get("change_id"),
        assignment: row.get("assignment_id"),
        revision: row.get("revision"),
        granted: row.get::<String, _>("decision") == "grant",
        cycle: row.get("cycle_id"),
    }
}
async fn change_replay(
    c: &mut PgConnection,
    r: &ChangeInput<'_>,
    id: &[u8],
) -> Result<Option<GrantReceipt>, Error> {
    let row = sqlx::query("SELECT c.id::text AS change_id,c.assignment_id::text,c.revision,c.decision,c.cycle_id::text,c.mapping_revision,c.request_identity,c.request_digest,a.target_kind,a.target_id::text,a.grantee_kind,a.grantee_user_id::text,a.grantee_local_group_id::text,a.grantee_oidc_group_id,a.assignment_format,a.assignment_version,a.assignment_key,a.mapping_rule_id::text FROM openmettle.grant_changes c JOIN openmettle.grant_assignments a ON a.id=c.assignment_id WHERE c.scope_id=$1::uuid AND c.actor_user_id=$2::uuid AND c.request_key=$3")
        .bind(r.assignment.scope).bind(r.actor).bind(r.key).fetch_optional(c).await?;
    let Some(row) = row else { return Ok(None) };
    let target = match row.get::<&str, _>("target_kind") {
        "project" => Target::Project(row.get("target_id")),
        "conversation" => Target::Conversation(row.get("target_id")),
        _ => Target::Artifact(row.get("target_id")),
    };
    let stored = ChangeInput {
        assignment: Assignment {
            scope: r.assignment.scope,
            target,
            grantee: Grantee::from_columns(&row),
            format: row.get("assignment_format"),
            version: row.get("assignment_version"),
            key: row.get("assignment_key"),
            mapping_rule: row.get("mapping_rule_id"),
        },
        actor: r.actor,
        key: r.key,
        expected_revision: row.get::<i64, _>("revision") - 1,
        mapping_revision: row.get("mapping_revision"),
        decision: if row.get::<&str, _>("decision") == "grant" {
            Decision::Grant
        } else {
            Decision::Revoke(row.get("cycle_id"))
        },
    };
    if row.get::<Vec<u8>, _>("request_identity") != id
        || row.get::<Vec<u8>, _>("request_digest") != digest(id)
        || change_identity(&stored) != id
    {
        return Err(Error::Conflict);
    }
    Ok(Some(receipt(&row)))
}
/// Exact replay precedes current-state checks. New writes use revision CAS; never retry stale
/// directory observations with a fresh revision without establishing their freshness.
pub async fn change_grant(
    tx: &mut WriteTransaction<'_>,
    r: &ChangeInput<'_>,
) -> Result<GrantReceipt, Error> {
    let a = r.assignment;
    let (kind, target) = a.validate()?;
    uuid(r.actor)?;
    let (grantee_kind, user, local_group, oidc_group) = a.grantee.columns();
    if let Some(rule) = a.mapping_rule {
        uuid(rule)?;
    }
    let (decision, cycle) = match r.decision {
        Decision::Grant => ("grant", None),
        Decision::Revoke(c) => ("revoke", c),
    };
    if let Some(cycle) = cycle {
        uuid(cycle)?;
    }
    let next = revision(r.expected_revision)?;
    if !bounded(a.format, 128)
        || !bounded(a.key, 128)
        || !bounded(r.key, 128)
        || a.version <= 0
        || a.mapping_rule.is_some() != r.mapping_revision.is_some()
        || r.mapping_revision.is_some_and(|v| v <= 0)
    {
        return Err(Error::Invalid);
    }
    let source = if a.mapping_rule.is_some() {
        "mapped"
    } else {
        "direct"
    };
    let id = change_identity(r);
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        if let Some(receipt) = change_replay(&mut sp,r,&id).await? { return Ok(receipt); }
        if let Some(rule) = a.mapping_rule {
            let current = sqlx::query("SELECT last_revision FROM openmettle.grant_mapping_rules WHERE id=$1::uuid FOR NO KEY UPDATE")
                .bind(rule).fetch_optional(&mut *sp).await?.ok_or(Error::NotFound)?;
            if let Some(receipt) = change_replay(&mut sp, r, &id).await? { return Ok(receipt); }
            let enabled: Option<bool> = sqlx::query_scalar("SELECT enabled FROM openmettle.grant_mapping_revisions WHERE rule_id=$1::uuid AND revision=$2").bind(rule).bind(current.get::<i64,_>("last_revision")).fetch_optional(&mut *sp).await?;
            // Revokes may name an old immutable mapping revision after disable/replacement.
            if decision=="grant" && (Some(current.get::<i64,_>("last_revision"))!=r.mapping_revision || enabled!=Some(true)) { return Err(Error::StaleRevision); }
        }
        sqlx::query("INSERT INTO openmettle.grant_assignments(scope_id,target_kind,project_id,conversation_id,artifact_id,grantee_kind,grantee_user_id,grantee_local_group_id,grantee_oidc_group_id,assignment_format,assignment_version,assignment_key,source_kind,mapping_rule_id,created_by_user_id) VALUES($1::uuid,$2,CASE WHEN $2='project' THEN $3::uuid END,CASE WHEN $2='conversation' THEN $3::uuid END,CASE WHEN $2='artifact' THEN $3::uuid END,$4,$5::uuid,$6::uuid,$7,$8,$9,$10,$11,$12::uuid,$13::uuid) ON CONFLICT DO NOTHING")
            .bind(a.scope).bind(kind).bind(target).bind(grantee_kind).bind(user).bind(local_group).bind(oidc_group).bind(a.format).bind(a.version).bind(a.key).bind(source).bind(a.mapping_rule).bind(r.actor).execute(&mut *sp).await?;
        let row = sqlx::query(concat!("SELECT id::text,last_revision FROM openmettle.grant_assignments a WHERE ", natural_key!(), " FOR NO KEY UPDATE"))
            .bind(a.scope).bind(kind).bind(target).bind(grantee_kind).bind(user).bind(local_group).bind(oidc_group).bind(a.format).bind(a.version).bind(a.key).bind(a.mapping_rule).fetch_one(&mut *sp).await?;
        if let Some(receipt) = change_replay(&mut sp,r,&id).await? { return Ok(receipt); }
        let assignment: String = row.get("id");
        if row.get::<i64,_>("last_revision")!=r.expected_revision { return Err(Error::StaleRevision); }
        let active: Option<(String, Option<i64>)> = sqlx::query_as("SELECT cycle_id::text,mapping_revision FROM openmettle.grant_changes WHERE assignment_id=$1::uuid AND revision=$2 AND decision='grant'")
            .bind(&assignment).bind(r.expected_revision).fetch_optional(&mut *sp).await?;
        if decision=="grant" && active.is_some() { return Err(Error::Conflict); }
        if decision=="revoke" {
            if active.as_ref().map(|(id,_)| id.as_str())!=cycle { return Err(Error::StaleRevision); }
            if active.as_ref().is_some_and(|(_,revision)| *revision!=r.mapping_revision) { return Err(Error::Conflict); }
        }
        let change: String = sqlx::query_scalar("SELECT gen_random_uuid()::text").fetch_one(&mut *sp).await?;
        let new_cycle = if decision=="grant" { Some(change.as_str()) } else { cycle };
        // DO NOTHING avoids aborting the savepoint on a global request-key race. A separate
        // statement sees the winner. On conflict finish rolls back any provisional assignment.
        let inserted = sqlx::query("INSERT INTO openmettle.grant_changes(id,scope_id,assignment_id,revision,source_kind,mapping_rule_id,mapping_revision,actor_user_id,request_key,decision,cycle_id,request_identity,request_digest) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6::uuid,$7,$8::uuid,$9,$10,$11::uuid,$12,$13) ON CONFLICT (scope_id,actor_user_id,request_key) DO NOTHING")
            .bind(&change).bind(a.scope).bind(&assignment).bind(next).bind(source).bind(a.mapping_rule).bind(r.mapping_revision).bind(r.actor).bind(r.key).bind(decision).bind(new_cycle).bind(&id).bind(digest(&id)).execute(&mut *sp).await?;
        if inserted.rows_affected()==0 { return change_replay(&mut sp,r,&id).await?.ok_or(Error::Conflict); }
        sqlx::query("UPDATE openmettle.grant_assignments SET last_revision=$2 WHERE id=$1::uuid").bind(&assignment).bind(next).execute(&mut *sp).await?;
        Ok(GrantReceipt { cycle:new_cycle.map(str::to_owned),change,assignment,revision:next,granted:decision=="grant" })
    }.await;
    let result = finish(sp, result).await?;
    tx.restore(outer);
    result
}
/// Snapshot columns of `grant_assignments a`; callers append the WHERE clause.
macro_rules! snapshot_sql {
    () => {
        "SELECT a.id::text,a.last_revision,coalesce(c.decision='grant',false) AS active,c.cycle_id::text,CASE WHEN a.source_kind='direct' THEN true ELSE coalesce(m.enabled AND c.mapping_revision=m.revision,false) END AS eligible FROM openmettle.grant_assignments a LEFT JOIN openmettle.grant_changes c ON c.assignment_id=a.id AND c.revision=a.last_revision LEFT JOIN openmettle.grant_mapping_rules r ON r.id=a.mapping_rule_id LEFT JOIN openmettle.grant_mapping_revisions m ON m.rule_id=r.id AND m.revision=r.last_revision WHERE "
    };
}
fn snapshot(r: PgRow) -> AssignmentSnapshot {
    AssignmentSnapshot {
        assignment: r.get("id"),
        revision: r.get("last_revision"),
        recorded_active: r.get("active"),
        cycle: r.get("cycle_id"),
        mapping_eligible: r.get("eligible"),
    }
}
/// One statement snapshot; recorded state and current mapping eligibility stay separate.
/// Neither field checks user disablement, permissions, resource lifecycle or directory truth.
pub async fn read_assignment(
    c: &mut PgConnection,
    scope: &str,
    assignment: &str,
) -> Result<Option<AssignmentSnapshot>, Error> {
    uuid(scope)?;
    uuid(assignment)?;
    let row = sqlx::query(concat!(
        snapshot_sql!(),
        "a.scope_id=$1::uuid AND a.id=$2::uuid"
    ))
    .bind(scope)
    .bind(assignment)
    .fetch_optional(c)
    .await?;
    Ok(row.map(snapshot))
}
/// The same snapshot located by the assignment's natural key, or `None` if it was never written.
pub async fn find_assignment(
    c: &mut PgConnection,
    a: &Assignment<'_>,
) -> Result<Option<AssignmentSnapshot>, Error> {
    let (kind, target) = a.validate()?;
    let (grantee_kind, user, local_group, oidc_group) = a.grantee.columns();
    let row = sqlx::query(concat!(snapshot_sql!(), natural_key!()))
        .bind(a.scope)
        .bind(kind)
        .bind(target)
        .bind(grantee_kind)
        .bind(user)
        .bind(local_group)
        .bind(oidc_group)
        .bind(a.format)
        .bind(a.version)
        .bind(a.key)
        .bind(a.mapping_rule)
        .fetch_optional(c)
        .await?;
    Ok(row.map(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapping_identity_bound_covers_maximum_legal_input() {
        let u = "00000000-0000-0000-0000-000000000001";
        let s = "x".repeat(2048);
        let v = vec![0; 16384];
        let r = MappingInput {
            rule: u,
            provider: u,
            issuer: &s,
            actor: u,
            key: &s[..128],
            expected_revision: i64::MAX - 1,
            enabled: true,
            selector_kind: "app_role",
            claim_name: &s[..128],
            claim_value: &s[..1024],
            binding_format: &s[..128],
            binding_version: i32::MAX,
            binding: &v,
        };
        assert_eq!(mapping_identity(&r).len(), 20100);
        assert!(mapping_identity(&r).len() < 32768);
        let c = ChangeInput {
            assignment: Assignment {
                scope: u,
                target: Target::Conversation(u),
                grantee: Grantee::OidcGroup(&s[..1024]),
                format: &s[..128],
                version: i32::MAX,
                key: &s[..128],
                mapping_rule: Some(u),
            },
            actor: u,
            key: &s[..128],
            expected_revision: i64::MAX - 1,
            mapping_revision: Some(i64::MAX),
            decision: Decision::Revoke(Some(u)),
        };
        assert!(change_identity(&c).len() < 32768);
        assert!(matches!(revision(i64::MAX), Err(Error::Invalid)));
        assert!(matches!(revision(-1), Err(Error::Invalid)));
    }
}
