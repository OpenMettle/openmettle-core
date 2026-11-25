//! Wall-clock family schedules, per-user overrides and model switches (ADR 0044, increment 4).
//! Convert an instant to local time in PostgreSQL (`pg_timezone_names`): missing spring minutes
//! never occur and both autumn occurrences resolve to the same local minute.
use super::Error;
use crate::authz::store::{self, KEY_REUSED, StoreError, UNCHANGED, WriteOutcome, uuid};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use std::collections::BTreeSet;

/// A half-open local wall-clock window `[start_minute, end_minute)` in `0..1440` with
/// `start_minute != end_minute` (`start_minute > end_minute` wraps across midnight).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hours {
    pub start_minute: u16,
    pub end_minute: u16,
}

impl Hours {
    pub fn valid(&self) -> bool {
        self.start_minute < 1440 && self.end_minute < 1440 && self.start_minute != self.end_minute
    }

    /// Parse a strict `HH:MM-HH:MM` window (`00:00`..`23:59`, non-equal start and end).
    pub fn parse_window(raw: &str) -> Option<Self> {
        let b = raw.as_bytes();
        if b.len() != 11 || b[2] != b':' || b[5] != b'-' || b[8] != b':' {
            return None;
        }
        let pair = |hi: u8, lo: u8| -> Option<u16> {
            if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
                return None;
            }
            Some(u16::from(hi - b'0') * 10 + u16::from(lo - b'0'))
        };
        let sh = pair(b[0], b[1])?;
        let sm = pair(b[3], b[4])?;
        let eh = pair(b[6], b[7])?;
        let em = pair(b[9], b[10])?;
        if sh >= 24 || sm >= 60 || eh >= 24 || em >= 60 {
            return None;
        }
        let hours = Self {
            start_minute: sh * 60 + sm,
            end_minute: eh * 60 + em,
        };
        hours.valid().then_some(hours)
    }

    /// Format as canonical `HH:MM-HH:MM`.
    pub fn format_window(&self) -> String {
        format!(
            "{:02}:{:02}-{:02}:{:02}",
            self.start_minute / 60,
            self.start_minute % 60,
            self.end_minute / 60,
            self.end_minute % 60
        )
    }

    fn contains(&self, m: u16) -> bool {
        if self.start_minute < self.end_minute {
            (self.start_minute..self.end_minute).contains(&m)
        } else {
            m >= self.start_minute || m < self.end_minute
        }
    }
}

/// Timezone syntax rule, matching `openmettle.family_policies.zone`'s `CHECK` constraint.
pub fn valid_zone(zone: &str) -> bool {
    (1..=128).contains(&zone.len())
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'-' | b'_' | b'.'))
}

/// Model identifier syntax rule, matching `model_config::name` and `family_policy_models.model`.
pub fn valid_model(model: &str) -> bool {
    crate::model_config::name(model)
}

/// OIDC group claim rule, matching `openmettle.family_policies.grantee_oidc_group_id`'s `CHECK`.
pub fn valid_oidc_group_id(claim: &str) -> bool {
    (1..=1024).contains(&claim.len()) && !claim.chars().any(char::is_control)
}

/// Legacy ADR 0037 in-memory family policy structure retained until increment 6 removal.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FamilyPolicy {
    pub revision: i64,
    pub zone: String,
    pub quiet: Option<Hours>,
    pub study: Option<Hours>,
    pub study_models: BTreeSet<String>,
    pub disabled_models: BTreeSet<String>,
}

impl FamilyPolicy {
    pub fn valid(&self) -> bool {
        self.revision > 0
            && valid_zone(&self.zone)
            && [self.quiet.as_ref(), self.study.as_ref()]
                .into_iter()
                .flatten()
                .all(Hours::valid)
    }

    pub(super) async fn local_minute(
        &self,
        c: &mut PgConnection,
        instant_ms: Option<i64>,
    ) -> Result<u16, Error> {
        if !self.valid() {
            return Err(Error::Refused);
        }
        let minute: i32 = sqlx::query_scalar(
            "SELECT extract(hour FROM local_time)::int * 60 + extract(minute FROM local_time)::int
               FROM (
                   SELECT coalesce(
                       timestamptz 'epoch' + ($2::bigint * interval '1 millisecond'),
                       clock_timestamp()
                   ) AT TIME ZONE name AS local_time
                     FROM pg_catalog.pg_timezone_names
                    WHERE name = $1
               ) z",
        )
        .bind(&self.zone)
        .bind(instant_ms)
        .fetch_optional(c)
        .await?
        .ok_or(Error::Refused)?;
        Ok(minute as u16)
    }

    pub async fn permits(
        &self,
        c: &mut PgConnection,
        model: &str,
        instant_ms: Option<i64>,
    ) -> Result<bool, Error> {
        let minute = self.local_minute(c, instant_ms).await?;
        Ok(self.permits_minute(model, minute))
    }

    pub(super) fn permits_minute(&self, model: &str, minute: u16) -> bool {
        !self.disabled_models.contains(model)
            && !self.quiet.as_ref().is_some_and(|h| h.contains(minute))
            && (!self.study.as_ref().is_some_and(|h| h.contains(minute))
                || self.study_models.contains(model))
    }
}

// --- Increment 4: PostgreSQL family policy tables, evaluator & operator CLI ----------------------

/// Subject of one `openmettle.family_policies` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FamilyGrantee {
    User(String),
    LocalGroup(String),
    OidcGroup(String),
}

impl FamilyGrantee {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::LocalGroup(_) => "local_group",
            Self::OidcGroup(_) => "oidc_group",
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::User(id) | Self::LocalGroup(id) | Self::OidcGroup(id) => id,
        }
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        match self {
            Self::User(id) => uuid(id, "user_id"),
            Self::LocalGroup(id) => uuid(id, "group_id"),
            Self::OidcGroup(claim) => {
                if valid_oidc_group_id(claim) {
                    Ok(())
                } else {
                    Err(StoreError::InvalidInput("oidc_group"))
                }
            }
        }
    }

    fn columns(&self) -> (&'static str, Option<&str>, Option<&str>, Option<&str>) {
        match self {
            Self::User(id) => ("user", Some(id.as_str()), None, None),
            Self::LocalGroup(id) => ("local_group", None, Some(id.as_str()), None),
            Self::OidcGroup(claim) => ("oidc_group", None, None, Some(claim.as_str())),
        }
    }
}

/// Rule kind stored in `openmettle.family_policy_models.rule_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyPolicyRuleKind {
    StudyAllow,
    Disabled,
}

impl FamilyPolicyRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StudyAllow => "study_allow",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "study_allow" => Some(Self::StudyAllow),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }

    pub fn audit_action(self, active: bool) -> &'static str {
        match (self, active) {
            (Self::StudyAllow, true) => "family_policy.model_study_allow",
            (Self::StudyAllow, false) => "family_policy.model_study_revoke",
            (Self::Disabled, true) => "family_policy.model_disable",
            (Self::Disabled, false) => "family_policy.model_enable",
        }
    }
}

/// Desired schedule and override state for `set_family_policy` / `operator_set_family_policy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyPolicyInput {
    pub zone: String,
    pub quiet: Option<Hours>,
    pub study: Option<Hours>,
    pub override_group_schedules: bool,
}

impl FamilyPolicyInput {
    pub fn validate(&self, grantee: &FamilyGrantee) -> Result<(), StoreError> {
        grantee.validate()?;
        if !valid_zone(&self.zone) {
            return Err(StoreError::InvalidInput("zone"));
        }
        if self.quiet.is_some_and(|h| !h.valid()) {
            return Err(StoreError::InvalidInput("quiet"));
        }
        if self.study.is_some_and(|h| !h.valid()) {
            return Err(StoreError::InvalidInput("study"));
        }
        if self.override_group_schedules && !matches!(grantee, FamilyGrantee::User(_)) {
            return Err(StoreError::InvalidInput("override_group_schedules"));
        }
        Ok(())
    }
}

/// Current-state snapshot of one family policy and its active model rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyPolicyRecord {
    pub id: String,
    pub grantee: FamilyGrantee,
    pub active: bool,
    pub zone: String,
    pub quiet: Option<Hours>,
    pub study: Option<Hours>,
    pub override_group_schedules: bool,
    pub revision: i64,
    pub study_models: BTreeSet<String>,
    pub disabled_models: BTreeSet<String>,
}

/// Operator audit context for `openmettle_owner` (`openmettle-admin family`) mutations.
#[derive(Clone, Copy, Debug)]
pub struct OperatorContext<'a> {
    pub operator_id: &'a str,
    pub request_key: &'a str,
    pub reason: &'a str,
}

impl OperatorContext<'_> {
    pub fn validate(&self) -> Result<(), StoreError> {
        uuid(self.operator_id, "operator_id")?;
        if !crate::runs::bounded(self.request_key, 128) {
            return Err(StoreError::InvalidInput("request_key"));
        }
        if !crate::runs::bounded(self.reason, 512) {
            return Err(StoreError::InvalidInput("reason"));
        }
        Ok(())
    }
}

async fn has_permits_function(c: &mut PgConnection) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT to_regprocedure('openmettle.family_policy_permits(uuid,uuid,text,timestamptz)') IS NOT NULL",
    )
    .fetch_one(&mut *c)
    .await?)
}

/// Authoritative single-model evaluation against `openmettle.family_policy_permits` at `now_ms`.
/// Callable by `openmettle_api` and `openmettle_worker`; returns `true` on pre-35 schemas.
pub async fn permits_at(
    c: &mut PgConnection,
    user_id: &str,
    approval_id: &str,
    model: &str,
    now_ms: i64,
) -> Result<bool, StoreError> {
    uuid(user_id, "user_id")?;
    uuid(approval_id, "approval_id")?;
    if !has_permits_function(c).await? {
        return Ok(true);
    }
    let allowed: bool = sqlx::query_scalar(
        "SELECT openmettle.family_policy_permits(
             $1::uuid,
             $2::uuid,
             $3,
             timestamptz 'epoch' + ($4::bigint * interval '1 millisecond')
         )",
    )
    .bind(user_id)
    .bind(approval_id)
    .bind(model)
    .bind(now_ms)
    .fetch_one(c)
    .await?;
    Ok(allowed)
}

async fn has_filter_function(c: &mut PgConnection) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT to_regprocedure('openmettle.family_policy_filter_models(uuid,uuid,text[],timestamptz)') IS NOT NULL",
    )
    .fetch_one(&mut *c)
    .await?)
}

/// Evaluate `openmettle.family_policy_filter_models` across a slice of catalog models in one
/// round trip (converting each active policy's timezone once). On pre-35 schemas all models pass.
pub async fn permits_models(
    c: &mut PgConnection,
    user_id: &str,
    approval_id: &str,
    models: &[&str],
    now_ms: i64,
) -> Result<BTreeSet<String>, StoreError> {
    uuid(user_id, "user_id")?;
    uuid(approval_id, "approval_id")?;
    if models.is_empty() {
        return Ok(BTreeSet::new());
    }
    if !has_filter_function(c).await? {
        return Ok(models.iter().map(|m| (*m).to_owned()).collect());
    }
    let permitted: Vec<String> = sqlx::query_scalar(
        "SELECT openmettle.family_policy_filter_models(
             $1::uuid,
             $2::uuid,
             $3::text[],
             timestamptz 'epoch' + ($4::bigint * interval '1 millisecond')
         )",
    )
    .bind(user_id)
    .bind(approval_id)
    .bind(models)
    .bind(now_ms)
    .fetch_all(c)
    .await?;
    Ok(permitted.into_iter().collect())
}

/// Read the current-state family policy row and active model rules for `grantee`.
/// Callable by `openmettle_api` and `openmettle_owner`.
pub async fn load_family_policy(
    c: &mut PgConnection,
    grantee: &FamilyGrantee,
) -> Result<Option<FamilyPolicyRecord>, StoreError> {
    grantee.validate()?;
    let (kind, user_id, local_group_id, oidc_group_id) = grantee.columns();
    let Some(row) = sqlx::query(
        "SELECT id::text, active, zone,
                quiet_start_minute, quiet_end_minute,
                study_start_minute, study_end_minute,
                override_group_schedules, revision
           FROM openmettle.family_policies
          WHERE grantee_kind = $1
            AND grantee_user_id IS NOT DISTINCT FROM $2::uuid
            AND grantee_local_group_id IS NOT DISTINCT FROM $3::uuid
            AND grantee_oidc_group_id IS NOT DISTINCT FROM $4",
    )
    .bind(kind)
    .bind(user_id)
    .bind(local_group_id)
    .bind(oidc_group_id)
    .fetch_optional(&mut *c)
    .await?
    else {
        return Ok(None);
    };
    let id: String = row.try_get(0)?;
    let pair = |start: Option<i16>, end: Option<i16>| -> Option<Hours> {
        Some(Hours {
            start_minute: u16::try_from(start?).ok()?,
            end_minute: u16::try_from(end?).ok()?,
        })
    };
    let quiet = pair(row.try_get(3)?, row.try_get(4)?);
    let study = pair(row.try_get(5)?, row.try_get(6)?);
    let models: Vec<(String, String)> = sqlx::query_as(
        "SELECT rule_kind, model
           FROM openmettle.family_policy_models
          WHERE policy_id = $1::uuid AND active
          ORDER BY rule_kind, model",
    )
    .bind(&id)
    .fetch_all(&mut *c)
    .await?;
    let mut study_models = BTreeSet::new();
    let mut disabled_models = BTreeSet::new();
    for (rule_kind, model) in models {
        match rule_kind.as_str() {
            "study_allow" => {
                study_models.insert(model);
            }
            "disabled" => {
                disabled_models.insert(model);
            }
            _ => {}
        }
    }
    Ok(Some(FamilyPolicyRecord {
        id,
        grantee: grantee.clone(),
        active: row.try_get(1)?,
        zone: row.try_get(2)?,
        quiet,
        study,
        override_group_schedules: row.try_get(7)?,
        revision: row.try_get(8)?,
        study_models,
        disabled_models,
    }))
}

pub(crate) fn set_policy_details(grantee: &FamilyGrantee, input: &FamilyPolicyInput) -> Value {
    json!({
        "grantee_kind": grantee.kind(),
        "grantee_id": grantee.id(),
        "zone": input.zone,
        "quiet": input.quiet.map(|h| h.format_window()),
        "study": input.study.map(|h| h.format_window()),
        "override_group_schedules": input.override_group_schedules,
    })
}

pub(crate) fn clear_policy_details(grantee: &FamilyGrantee) -> Value {
    json!({
        "grantee_kind": grantee.kind(),
        "grantee_id": grantee.id(),
    })
}

pub(crate) fn set_model_details(
    grantee: &FamilyGrantee,
    kind: FamilyPolicyRuleKind,
    model: &str,
    active: bool,
) -> Value {
    json!({
        "grantee_kind": grantee.kind(),
        "grantee_id": grantee.id(),
        "rule_kind": kind.as_str(),
        "model": model,
        "active": active,
    })
}

pub(crate) async fn existing_policy_id(
    c: &mut PgConnection,
    grantee: &FamilyGrantee,
) -> Result<Option<String>, StoreError> {
    let (kind, user_id, local_group_id, oidc_group_id) = grantee.columns();
    Ok(sqlx::query_scalar(
        "SELECT id::text
           FROM openmettle.family_policies
          WHERE grantee_kind = $1
            AND grantee_user_id IS NOT DISTINCT FROM $2::uuid
            AND grantee_local_group_id IS NOT DISTINCT FROM $3::uuid
            AND grantee_oidc_group_id IS NOT DISTINCT FROM $4
            FOR UPDATE",
    )
    .bind(kind)
    .bind(user_id)
    .bind(local_group_id)
    .bind(oidc_group_id)
    .fetch_optional(c)
    .await?)
}

async fn lock_grantee(c: &mut PgConnection, grantee: &FamilyGrantee) -> Result<(), StoreError> {
    match grantee {
        FamilyGrantee::User(id) => {
            store::lock_user(c, id, false).await?;
            Ok(())
        }
        FamilyGrantee::LocalGroup(id) => {
            store::lock_group(c, id, false).await?;
            Ok(())
        }
        FamilyGrantee::OidcGroup(_) => Ok(()),
    }
}

async fn verify_timezone(c: &mut PgConnection, zone: &str) -> Result<(), StoreError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_timezone_names WHERE name = $1)",
    )
    .bind(zone)
    .fetch_one(c)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(StoreError::InvalidInput("zone"))
    }
}

pub(crate) async fn apply_set_policy(
    c: &mut PgConnection,
    policy_id: &str,
    grantee: &FamilyGrantee,
    input: &FamilyPolicyInput,
    updated_by_user_id: Option<&str>,
) -> Result<(), StoreError> {
    lock_grantee(c, grantee).await?;
    verify_timezone(c, &input.zone).await?;
    let q_start = input.quiet.map(|h| h.start_minute as i16);
    let q_end = input.quiet.map(|h| h.end_minute as i16);
    let s_start = input.study.map(|h| h.start_minute as i16);
    let s_end = input.study.map(|h| h.end_minute as i16);
    let current = sqlx::query(
        "SELECT active, zone, quiet_start_minute, quiet_end_minute,
                study_start_minute, study_end_minute, override_group_schedules
           FROM openmettle.family_policies
          WHERE id = $1::uuid
            FOR UPDATE",
    )
    .bind(policy_id)
    .fetch_optional(&mut *c)
    .await?;
    if let Some(row) = current {
        let active: bool = row.try_get(0)?;
        let zone: String = row.try_get(1)?;
        let cqs: Option<i16> = row.try_get(2)?;
        let cqe: Option<i16> = row.try_get(3)?;
        let css: Option<i16> = row.try_get(4)?;
        let cse: Option<i16> = row.try_get(5)?;
        let cov: bool = row.try_get(6)?;
        if active
            && zone == input.zone
            && (cqs, cqe, css, cse, cov)
                == (
                    q_start,
                    q_end,
                    s_start,
                    s_end,
                    input.override_group_schedules,
                )
        {
            return Err(UNCHANGED);
        }
        sqlx::query(
            "UPDATE openmettle.family_policies
                SET active = true,
                    zone = $2,
                    quiet_start_minute = $3,
                    quiet_end_minute = $4,
                    study_start_minute = $5,
                    study_end_minute = $6,
                    override_group_schedules = $7,
                    revision = revision + 1,
                    updated_at = clock_timestamp(),
                    updated_by_user_id = $8::uuid
              WHERE id = $1::uuid",
        )
        .bind(policy_id)
        .bind(&input.zone)
        .bind(q_start)
        .bind(q_end)
        .bind(s_start)
        .bind(s_end)
        .bind(input.override_group_schedules)
        .bind(updated_by_user_id)
        .execute(c)
        .await?;
    } else {
        let (kind, user_id, local_group_id, oidc_group_id) = grantee.columns();
        sqlx::query(
            "INSERT INTO openmettle.family_policies (
                 id, grantee_kind, grantee_user_id, grantee_local_group_id, grantee_oidc_group_id,
                 active, zone, quiet_start_minute, quiet_end_minute,
                 study_start_minute, study_end_minute, override_group_schedules, updated_by_user_id
             ) VALUES (
                 $1::uuid, $2, $3::uuid, $4::uuid, $5,
                 true, $6, $7, $8, $9, $10, $11, $12::uuid
             )",
        )
        .bind(policy_id)
        .bind(kind)
        .bind(user_id)
        .bind(local_group_id)
        .bind(oidc_group_id)
        .bind(&input.zone)
        .bind(q_start)
        .bind(q_end)
        .bind(s_start)
        .bind(s_end)
        .bind(input.override_group_schedules)
        .bind(updated_by_user_id)
        .execute(c)
        .await?;
    }
    Ok(())
}

pub(crate) async fn apply_clear_policy(
    c: &mut PgConnection,
    policy_id: &str,
    grantee: &FamilyGrantee,
    updated_by_user_id: Option<&str>,
) -> Result<(), StoreError> {
    lock_grantee(c, grantee).await?;
    let changed = sqlx::query(
        "UPDATE openmettle.family_policies
            SET active = false,
                revision = revision + 1,
                updated_at = clock_timestamp(),
                updated_by_user_id = $2::uuid
          WHERE id = $1::uuid AND active",
    )
    .bind(policy_id)
    .bind(updated_by_user_id)
    .execute(c)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(UNCHANGED);
    }
    Ok(())
}

pub(crate) async fn apply_set_model(
    c: &mut PgConnection,
    policy_id: &str,
    grantee: &FamilyGrantee,
    kind: FamilyPolicyRuleKind,
    model: &str,
    active: bool,
    updated_by_user_id: Option<&str>,
) -> Result<(), StoreError> {
    lock_grantee(c, grantee).await?;
    let policy_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM openmettle.family_policies WHERE id = $1::uuid)",
    )
    .bind(policy_id)
    .fetch_one(&mut *c)
    .await?;
    if !policy_exists {
        return Err(StoreError::NotFound);
    }
    let current: Option<bool> = sqlx::query_scalar(
        "SELECT active
           FROM openmettle.family_policy_models
          WHERE policy_id = $1::uuid AND rule_kind = $2 AND model = $3
            FOR UPDATE",
    )
    .bind(policy_id)
    .bind(kind.as_str())
    .bind(model)
    .fetch_optional(&mut *c)
    .await?;
    if current.unwrap_or(false) == active {
        return Err(UNCHANGED);
    }
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO openmettle.family_policy_models AS m
             (policy_id, rule_kind, model, active, updated_by_user_id)
         VALUES ($1::uuid, $2, $3, $4, $5::uuid)
         ON CONFLICT (policy_id, rule_kind, model) DO UPDATE
            SET active = $4,
                revision = m.revision + 1,
                updated_at = clock_timestamp(),
                updated_by_user_id = $5::uuid
          WHERE m.active <> $4
         RETURNING m.revision",
    )
    .bind(policy_id)
    .bind(kind.as_str())
    .bind(model)
    .bind(active)
    .bind(updated_by_user_id)
    .fetch_optional(c)
    .await?
    .ok_or(UNCHANGED)
    .map(drop)
}

async fn record_operator_audit(
    c: &mut PgConnection,
    op: &OperatorContext<'_>,
    action: &'static str,
    target_id: Option<String>,
    details: &Value,
) -> Result<WriteOutcome, StoreError> {
    let target = match &target_id {
        Some(id) => id.clone(),
        None => {
            sqlx::query_scalar("SELECT gen_random_uuid()::text")
                .fetch_one(&mut *c)
                .await?
        }
    };
    let details_str = details.to_string();
    let inserted = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
             (actor_kind, operator_id, action, target_kind, target_id, request_key, reason, details)
         VALUES ('operator', $1::uuid, $2, 'family_policy', $3, $4, $5, $6::jsonb)
         ON CONFLICT (operator_id, request_key) DO NOTHING",
    )
    .bind(op.operator_id)
    .bind(action)
    .bind(&target)
    .bind(op.request_key)
    .bind(op.reason)
    .bind(&details_str)
    .execute(&mut *c)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(WriteOutcome::Applied { target_id: target });
    }
    let row = sqlx::query(
        "SELECT action, target_kind, target_id, details = $3::jsonb
           FROM openmettle.authorization_audit
          WHERE operator_id = $1::uuid AND request_key = $2",
    )
    .bind(op.operator_id)
    .bind(op.request_key)
    .bind(&details_str)
    .fetch_one(&mut *c)
    .await?;
    let recorded: String = row.try_get(2)?;
    let same = row.try_get::<&str, _>(0)? == action
        && row.try_get::<&str, _>(1)? == "family_policy"
        && target_id.as_ref().is_none_or(|id| *id == recorded)
        && row.try_get::<bool, _>(3)?;
    if same {
        Ok(WriteOutcome::Replayed {
            target_id: recorded,
        })
    } else {
        Err(StoreError::Conflict(KEY_REUSED))
    }
}

async fn operator_write(
    c: &mut PgConnection,
    op: &OperatorContext<'_>,
    grantee: &FamilyGrantee,
    action: &'static str,
    details: Value,
    apply: impl AsyncFnOnce(&mut PgConnection, &str) -> Result<(), StoreError>,
) -> Result<WriteOutcome, StoreError> {
    op.validate()?;
    grantee.validate()?;
    let mut tx = store::begin(c).await?;
    let result = async {
        let c = tx.connection()?;
        sqlx::query("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
            .fetch_one(&mut *c)
            .await?;
        let existing = existing_policy_id(c, grantee).await?;
        let outcome = record_operator_audit(c, op, action, existing, &details).await?;
        if let WriteOutcome::Applied { target_id } = &outcome {
            apply(c, target_id).await?;
        }
        Ok(outcome)
    }
    .await;
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

/// Owner-operated (`openmettle_owner`) audited family-policy upsert.
pub async fn operator_set_family_policy(
    c: &mut PgConnection,
    op: &OperatorContext<'_>,
    grantee: &FamilyGrantee,
    input: &FamilyPolicyInput,
) -> Result<WriteOutcome, StoreError> {
    input.validate(grantee)?;
    let details = set_policy_details(grantee, input);
    operator_write(
        c,
        op,
        grantee,
        "family_policy.set",
        details,
        async |c, id| apply_set_policy(c, id, grantee, input, None).await,
    )
    .await
}

/// Owner-operated (`openmettle_owner`) audited family-policy deactivation (`active = false`).
pub async fn operator_clear_family_policy(
    c: &mut PgConnection,
    op: &OperatorContext<'_>,
    grantee: &FamilyGrantee,
) -> Result<WriteOutcome, StoreError> {
    let details = clear_policy_details(grantee);
    operator_write(
        c,
        op,
        grantee,
        "family_policy.clear",
        details,
        async |c, id| apply_clear_policy(c, id, grantee, None).await,
    )
    .await
}

/// Owner-operated (`openmettle_owner`) audited family-policy model rule mutation.
pub async fn operator_set_family_policy_model(
    c: &mut PgConnection,
    op: &OperatorContext<'_>,
    grantee: &FamilyGrantee,
    kind: FamilyPolicyRuleKind,
    model: &str,
    active: bool,
) -> Result<WriteOutcome, StoreError> {
    if !valid_model(model) {
        return Err(StoreError::InvalidInput("model"));
    }
    let action = kind.audit_action(active);
    let details = set_model_details(grantee, kind, model, active);
    operator_write(c, op, grantee, action, details, async |c, id| {
        apply_set_model(c, id, grantee, kind, model, active, None).await
    })
    .await
}

// --- `openmettle-admin family` CLI parsing and execution -----------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminOperatorArgs {
    pub operator_id: String,
    pub request_key: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminFamilyCommand {
    SetPolicy {
        grantee: FamilyGrantee,
        input: FamilyPolicyInput,
        operator: AdminOperatorArgs,
    },
    ClearPolicy {
        grantee: FamilyGrantee,
        operator: AdminOperatorArgs,
    },
    SetModel {
        grantee: FamilyGrantee,
        kind: FamilyPolicyRuleKind,
        model: String,
        active: bool,
        operator: AdminOperatorArgs,
    },
}

/// Parse arguments after `openmettle-admin family`.
pub fn parse_admin_args(args: &[String]) -> Result<AdminFamilyCommand, &'static str> {
    const USAGE: &str = "usage: openmettle-admin family set-policy (--user UUID | --local-group UUID | --oidc-group CLAIM) --zone TZ [--quiet HH:MM-HH:MM] [--study HH:MM-HH:MM] [--override-group-schedules] --operator-id UUID --request-key KEY --reason TEXT | clear-policy (...) | set-model (...) --kind (study_allow|disabled) --model MODEL (--enable|--disable) (...)";
    let Some((sub, rest)) = args.split_first() else {
        return Err(USAGE);
    };
    let is_set = sub == "set-policy";
    let is_clear = sub == "clear-policy";
    let is_model = sub == "set-model";
    if !is_set && !is_clear && !is_model {
        return Err(USAGE);
    }

    let mut grantee: Option<FamilyGrantee> = None;
    let mut zone: Option<String> = None;
    let mut quiet: Option<Hours> = None;
    let mut study: Option<Hours> = None;
    let mut override_group_schedules = false;
    let mut kind: Option<FamilyPolicyRuleKind> = None;
    let mut model: Option<String> = None;
    let mut active: Option<bool> = None;
    let mut operator_id: Option<String> = None;
    let mut request_key: Option<String> = None;
    let mut reason: Option<String> = None;

    let mut set_grantee = |g: FamilyGrantee| -> Result<(), &'static str> {
        if grantee.is_some() {
            return Err("specify exactly one of --user, --local-group, or --oidc-group");
        }
        grantee = Some(g);
        Ok(())
    };

    let mut i = 0;
    while i < rest.len() {
        let flag = rest[i].as_str();
        let next_val = |idx: &mut usize, missing: &'static str| -> Result<&str, &'static str> {
            *idx += 1;
            rest.get(*idx).map(String::as_str).ok_or(missing)
        };
        match flag {
            "--user" => {
                let v = next_val(&mut i, "missing --user UUID")?;
                set_grantee(FamilyGrantee::User(v.to_owned()))?;
            }
            "--local-group" => {
                let v = next_val(&mut i, "missing --local-group UUID")?;
                set_grantee(FamilyGrantee::LocalGroup(v.to_owned()))?;
            }
            "--oidc-group" => {
                let v = next_val(&mut i, "missing --oidc-group CLAIM")?;
                set_grantee(FamilyGrantee::OidcGroup(v.to_owned()))?;
            }
            "--operator-id" => {
                if operator_id.is_some() {
                    return Err("duplicate --operator-id");
                }
                operator_id = Some(next_val(&mut i, "missing --operator-id UUID")?.to_owned());
            }
            "--request-key" => {
                if request_key.is_some() {
                    return Err("duplicate --request-key");
                }
                request_key = Some(next_val(&mut i, "missing --request-key KEY")?.to_owned());
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("duplicate --reason");
                }
                reason = Some(next_val(&mut i, "missing --reason TEXT")?.to_owned());
            }
            "--zone" if is_set => {
                if zone.is_some() {
                    return Err("duplicate --zone");
                }
                zone = Some(next_val(&mut i, "missing --zone TZ")?.to_owned());
            }
            "--quiet" if is_set => {
                if quiet.is_some() {
                    return Err("duplicate --quiet");
                }
                let raw = next_val(&mut i, "missing --quiet HH:MM-HH:MM")?;
                quiet = Some(
                    Hours::parse_window(raw)
                        .ok_or("invalid --quiet window; expected HH:MM-HH:MM with start != end")?,
                );
            }
            "--study" if is_set => {
                if study.is_some() {
                    return Err("duplicate --study");
                }
                let raw = next_val(&mut i, "missing --study HH:MM-HH:MM")?;
                study = Some(
                    Hours::parse_window(raw)
                        .ok_or("invalid --study window; expected HH:MM-HH:MM with start != end")?,
                );
            }
            "--override-group-schedules" if is_set => {
                if override_group_schedules {
                    return Err("duplicate --override-group-schedules");
                }
                override_group_schedules = true;
            }
            "--kind" if is_model => {
                if kind.is_some() {
                    return Err("duplicate --kind");
                }
                let raw = next_val(&mut i, "missing --kind (study_allow|disabled)")?;
                kind = Some(
                    FamilyPolicyRuleKind::parse(raw)
                        .ok_or("invalid --kind; expected study_allow or disabled")?,
                );
            }
            "--model" if is_model => {
                if model.is_some() {
                    return Err("duplicate --model");
                }
                model = Some(next_val(&mut i, "missing --model MODEL")?.to_owned());
            }
            "--enable" if is_model => {
                if active.is_some() {
                    return Err("specify exactly one of --enable or --disable");
                }
                active = Some(true);
            }
            "--disable" if is_model => {
                if active.is_some() {
                    return Err("specify exactly one of --enable or --disable");
                }
                active = Some(false);
            }
            _ => return Err("unknown or misplaced family option"),
        }
        i += 1;
    }

    let grantee = grantee.ok_or("one of --user, --local-group, or --oidc-group is required")?;
    grantee.validate().map_err(|_| "invalid grantee")?;
    let operator = AdminOperatorArgs {
        operator_id: operator_id.ok_or("--operator-id is required")?,
        request_key: request_key.ok_or("--request-key is required")?,
        reason: reason.ok_or("--reason is required")?,
    };
    OperatorContext {
        operator_id: &operator.operator_id,
        request_key: &operator.request_key,
        reason: &operator.reason,
    }
    .validate()
    .map_err(|_| "invalid --operator-id, --request-key, or --reason")?;

    if is_set {
        let input = FamilyPolicyInput {
            zone: zone.ok_or("--zone is required")?,
            quiet,
            study,
            override_group_schedules,
        };
        input.validate(&grantee).map_err(|e| match e {
            StoreError::InvalidInput("override_group_schedules") => {
                "--override-group-schedules is only valid with --user"
            }
            StoreError::InvalidInput("zone") => "invalid --zone",
            _ => "invalid family policy arguments",
        })?;
        Ok(AdminFamilyCommand::SetPolicy {
            grantee,
            input,
            operator,
        })
    } else if is_clear {
        Ok(AdminFamilyCommand::ClearPolicy { grantee, operator })
    } else {
        let kind = kind.ok_or("--kind is required")?;
        let model = model.ok_or("--model is required")?;
        if !valid_model(&model) {
            return Err("invalid --model");
        }
        let active = active.ok_or("one of --enable or --disable is required")?;
        Ok(AdminFamilyCommand::SetModel {
            grantee,
            kind,
            model,
            active,
            operator,
        })
    }
}

/// Execute a parsed `openmettle-admin family` command against an `openmettle_owner` connection.
pub async fn execute_admin_command(
    c: &mut PgConnection,
    cmd: &AdminFamilyCommand,
) -> Result<(&'static str, WriteOutcome), StoreError> {
    match cmd {
        AdminFamilyCommand::SetPolicy {
            grantee,
            input,
            operator,
        } => {
            let op = OperatorContext {
                operator_id: &operator.operator_id,
                request_key: &operator.request_key,
                reason: &operator.reason,
            };
            let outcome = operator_set_family_policy(c, &op, grantee, input).await?;
            Ok(("family_policy.set", outcome))
        }
        AdminFamilyCommand::ClearPolicy { grantee, operator } => {
            let op = OperatorContext {
                operator_id: &operator.operator_id,
                request_key: &operator.request_key,
                reason: &operator.reason,
            };
            let outcome = operator_clear_family_policy(c, &op, grantee).await?;
            Ok(("family_policy.clear", outcome))
        }
        AdminFamilyCommand::SetModel {
            grantee,
            kind,
            model,
            active,
            operator,
        } => {
            let op = OperatorContext {
                operator_id: &operator.operator_id,
                request_key: &operator.request_key,
                reason: &operator.reason,
            };
            let outcome =
                operator_set_family_policy_model(c, &op, grantee, *kind, model, *active).await?;
            Ok((kind.audit_action(*active), outcome))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID1: &str = "00000000-0000-4000-8000-000000000001";
    const OP_UUID: &str = "00000000-0000-4000-8000-000000000002";

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn hours_window_parser_enforces_strict_hh_mm_bounds() {
        assert_eq!(
            Hours::parse_window("22:00-07:00"),
            Some(Hours {
                start_minute: 1320,
                end_minute: 420
            })
        );
        assert_eq!(
            Hours::parse_window("00:00-23:59").unwrap().format_window(),
            "00:00-23:59"
        );
        for bad in [
            "",
            "9:00-17:00",
            "09:00-17:0",
            "22:00-22:00",
            "24:00-07:00",
            "22:60-07:00",
            "22:00-24:00",
            "22:00-07:60",
            " 22:00-07:00",
            "22:00-07:00 ",
            "22:00/07:00",
            "aa:00-07:00",
        ] {
            assert_eq!(Hours::parse_window(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn parse_admin_args_accepts_valid_commands_and_rejects_invalid_combinations() {
        let cmd = parse_admin_args(&s(&[
            "set-policy",
            "--oidc-group",
            "Family",
            "--zone",
            "Europe/London",
            "--quiet",
            "22:00-07:00",
            "--study",
            "16:00-18:00",
            "--operator-id",
            OP_UUID,
            "--request-key",
            "req-1",
            "--reason",
            "household bedtime",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            AdminFamilyCommand::SetPolicy {
                grantee: FamilyGrantee::OidcGroup("Family".into()),
                input: FamilyPolicyInput {
                    zone: "Europe/London".into(),
                    quiet: Some(Hours {
                        start_minute: 1320,
                        end_minute: 420
                    }),
                    study: Some(Hours {
                        start_minute: 960,
                        end_minute: 1080
                    }),
                    override_group_schedules: false,
                },
                operator: AdminOperatorArgs {
                    operator_id: OP_UUID.into(),
                    request_key: "req-1".into(),
                    reason: "household bedtime".into(),
                },
            }
        );

        let user_override = parse_admin_args(&s(&[
            "set-policy",
            "--user",
            UUID1,
            "--zone",
            "UTC",
            "--override-group-schedules",
            "--operator-id",
            OP_UUID,
            "--request-key",
            "req-2",
            "--reason",
            "parent override",
        ]))
        .unwrap();
        assert!(matches!(
            user_override,
            AdminFamilyCommand::SetPolicy {
                input: FamilyPolicyInput {
                    override_group_schedules: true,
                    ..
                },
                ..
            }
        ));

        let model_cmd = parse_admin_args(&s(&[
            "set-model",
            "--local-group",
            UUID1,
            "--kind",
            "disabled",
            "--model",
            " heavy-model ",
            "--enable",
            "--operator-id",
            OP_UUID,
            "--request-key",
            "req-3",
            "--reason",
            "disable heavy model",
        ]))
        .unwrap();
        assert_eq!(
            model_cmd,
            AdminFamilyCommand::SetModel {
                grantee: FamilyGrantee::LocalGroup(UUID1.into()),
                kind: FamilyPolicyRuleKind::Disabled,
                model: " heavy-model ".into(),
                active: true,
                operator: AdminOperatorArgs {
                    operator_id: OP_UUID.into(),
                    request_key: "req-3".into(),
                    reason: "disable heavy model".into(),
                },
            }
        );
        assert!(valid_model(" padded-model "));
        assert!(!valid_model("bad\nmodel"));

        for bad in [
            // Missing subcommand / unknown subcommand
            &[][..],
            &["unknown"][..],
            // Mutually exclusive grantees
            &[
                "clear-policy",
                "--user",
                UUID1,
                "--oidc-group",
                "Family",
                "--operator-id",
                OP_UUID,
                "--request-key",
                "k",
                "--reason",
                "r",
            ][..],
            // Override on non-user grantee
            &[
                "set-policy",
                "--oidc-group",
                "Family",
                "--zone",
                "UTC",
                "--override-group-schedules",
                "--operator-id",
                OP_UUID,
                "--request-key",
                "k",
                "--reason",
                "r",
            ][..],
            // Both --enable and --disable
            &[
                "set-model",
                "--user",
                UUID1,
                "--kind",
                "study_allow",
                "--model",
                "a",
                "--enable",
                "--disable",
                "--operator-id",
                OP_UUID,
                "--request-key",
                "k",
                "--reason",
                "r",
            ][..],
            // Equal quiet window
            &[
                "set-policy",
                "--user",
                UUID1,
                "--zone",
                "UTC",
                "--quiet",
                "22:00-22:00",
                "--operator-id",
                OP_UUID,
                "--request-key",
                "k",
                "--reason",
                "r",
            ][..],
            // Unknown kind
            &[
                "set-model",
                "--user",
                UUID1,
                "--kind",
                "other",
                "--model",
                "a",
                "--enable",
                "--operator-id",
                OP_UUID,
                "--request-key",
                "k",
                "--reason",
                "r",
            ][..],
        ] {
            assert!(parse_admin_args(&s(bad)).is_err(), "{bad:?}");
        }
    }
}
