//! Artifact revision and storage-accounting persistence primitives (ADR 0005). Not a quota,
//! upload, retention or purge service. Helpers borrow the caller's `WriteTransaction`, work
//! inside a savepoint and never commit. They keep counters consistent only for writers that
//! use them; direct SQL by an application role can bypass that protocol.
//!
//! Lock order across helpers: run, reservation, artifact, revision, owner account, instance.
//! Each helper follows it. Callers composing several helpers or owners in one transaction can
//! still deadlock (SQLSTATE 40P01): abandon the whole transaction and retry it with the same
//! idempotency keys. Never infer success from a failed or interrupted commit.
use crate::runs::{Error, WriteTransaction, bounded, digest, finish, identity, lock_run, uuid};
use sqlx::{Acquire, Postgres, Row, Transaction};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationState {
    Reserved,
    Settled,
    Released,
}
impl ReservationState {
    fn parse(state: &str) -> Result<Self, Error> {
        match state {
            "reserved" => Ok(Self::Reserved),
            "settled" => Ok(Self::Settled),
            "released" => Ok(Self::Released),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Debug)]
pub struct Reservation {
    pub id: String,
    pub state: ReservationState,
}

/// A bounded allowance for writing one revision of `artifact` (a caller-chosen UUID for a new
/// artifact, or an existing artifact in the same scope).
pub struct ReservationInput<'a> {
    pub scope: &'a str,
    pub actor: &'a str,
    pub key: &'a str,
    pub artifact: &'a str,
    pub max_bytes: i64,
    pub run: Option<&'a str>,
    pub operation: Option<&'a str>,
}

fn optional(value: Option<&str>) -> [&[u8]; 2] {
    match value {
        Some(v) => [&[1], v.as_bytes()],
        None => [&[0], b""],
    }
}

/// Reserve before writing. The owner's charged bytes (active + retained + reserved) and the
/// instance totals must stay within the owner-configured limits read under the same row
/// locks. Unconfigured limits refuse. An exact replay of (scope, actor, key) returns the
/// original reservation and its current state without rechecking limits; changed input
/// conflicts.
pub async fn reserve(
    tx: &mut WriteTransaction<'_>,
    r: &ReservationInput<'_>,
) -> Result<Reservation, Error> {
    for id in [r.scope, r.actor, r.artifact] {
        uuid(id)?;
    }
    for id in [r.run, r.operation].into_iter().flatten() {
        uuid(id)?;
    }
    if !bounded(r.key, 128) || r.max_bytes <= 0 || (r.operation.is_some() && r.run.is_none()) {
        return Err(Error::Invalid);
    }
    let [run_present, run] = optional(r.run);
    let [operation_present, operation] = optional(r.operation);
    let id = identity(
        b"openmettle/reservation/1\0",
        &[
            r.scope.as_bytes(),
            r.actor.as_bytes(),
            r.key.as_bytes(),
            r.artifact.as_bytes(),
            &r.max_bytes.to_be_bytes(),
            run_present,
            run,
            operation_present,
            operation,
        ],
    );
    let hash = digest(&id);
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        let kind: String = sqlx::query_scalar("SELECT kind FROM openmettle.scopes WHERE id=$1::uuid")
            .bind(r.scope).fetch_optional(&mut *sp).await?.ok_or(Error::NotFound)?;
        sqlx::query("INSERT INTO openmettle.storage_accounts(scope_id) VALUES ($1::uuid) ON CONFLICT DO NOTHING")
            .bind(r.scope).execute(&mut *sp).await?;
        let account = sqlx::query("SELECT active_bytes,retained_bytes,reserved_bytes FROM openmettle.storage_accounts
             WHERE scope_id=$1::uuid FOR UPDATE")
            .bind(r.scope).fetch_one(&mut *sp).await?;
        // The owner lock serializes reservations of one scope, so a committed duplicate is visible.
        let existing = sqlx::query("SELECT id::text,state,request_identity,request_digest,artifact_id::text,max_bytes,
             run_id::text,operation_id::text FROM openmettle.storage_reservations
             WHERE scope_id=$1::uuid AND actor_user_id=$2::uuid AND idempotency_key=$3")
            .bind(r.scope).bind(r.actor).bind(r.key).fetch_optional(&mut *sp).await?;
        if let Some(row) = existing {
            if row.get::<Vec<u8>, _>("request_identity") != id
                || row.get::<Vec<u8>, _>("request_digest") != hash
                || row.get::<String, _>("artifact_id") != r.artifact
                || row.get::<i64, _>("max_bytes") != r.max_bytes
                || row.get::<Option<String>, _>("run_id").as_deref() != r.run
                || row.get::<Option<String>, _>("operation_id").as_deref() != r.operation
            {
                return Err(Error::Conflict);
            }
            return Ok(Reservation {
                id: row.get("id"),
                state: ReservationState::parse(row.get("state"))?,
            });
        }
        let owner: Option<String> = sqlx::query_scalar("SELECT scope_id::text FROM openmettle.artifacts WHERE id=$1::uuid")
            .bind(r.artifact).fetch_optional(&mut *sp).await?;
        if owner.is_some_and(|s| s != r.scope) {
            return Err(Error::Conflict);
        }
        let instance = sqlx::query("SELECT instance_budget_bytes,personal_limit_bytes,project_limit_bytes,
             active_bytes,retained_bytes,reserved_bytes FROM openmettle.storage_instance FOR UPDATE")
            .fetch_optional(&mut *sp).await?.ok_or(Error::LimitUnconfigured)?;
        let owner_limit: Option<i64> = instance.get(if kind == "personal" {
            "personal_limit_bytes"
        } else {
            "project_limit_bytes"
        });
        let budget: Option<i64> = instance.get("instance_budget_bytes");
        let (Some(owner_limit), Some(budget)) = (owner_limit, budget) else {
            return Err(Error::LimitUnconfigured);
        };
        let charged = |row: &sqlx::postgres::PgRow| {
            ["active_bytes", "retained_bytes", "reserved_bytes"]
                .iter()
                .map(|c| i128::from(row.get::<i64, _>(*c)))
                .sum::<i128>()
                + i128::from(r.max_bytes)
        };
        if charged(&account) > i128::from(owner_limit) {
            return Err(Error::OwnerLimit);
        }
        if charged(&instance) > i128::from(budget) {
            return Err(Error::InstanceLimit);
        }
        let reservation: String = sqlx::query_scalar("INSERT INTO openmettle.storage_reservations
             (scope_id,actor_user_id,idempotency_key,artifact_id,max_bytes,run_id,operation_id,request_identity,request_digest)
             VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5,$6::uuid,$7::uuid,$8,$9) RETURNING id::text")
            .bind(r.scope).bind(r.actor).bind(r.key).bind(r.artifact).bind(r.max_bytes).bind(r.run).bind(r.operation)
            .bind(&id).bind(&hash).fetch_one(&mut *sp).await?;
        adjust(&mut sp, r.scope, 0, 0, r.max_bytes).await?;
        Ok(Reservation { id: reservation, state: ReservationState::Reserved })
    }
    .await;
    let result = finish(sp, result).await?;
    tx.restore(outer);
    result
}

/// Adds signed deltas to the owner account and then the instance row (fixed lock order).
/// Counter overflow or a negative total fails the statement and so the savepoint.
async fn adjust(
    tx: &mut Transaction<'_, Postgres>,
    scope: &str,
    active: i64,
    retained: i64,
    reserved: i64,
) -> Result<(), Error> {
    let updated = sqlx::query(
        "UPDATE openmettle.storage_accounts SET active_bytes=active_bytes+$2,
         retained_bytes=retained_bytes+$3,reserved_bytes=reserved_bytes+$4 WHERE scope_id=$1::uuid",
    )
    .bind(scope)
    .bind(active)
    .bind(retained)
    .bind(reserved)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(Error::NotFound);
    }
    let updated = sqlx::query(
        "UPDATE openmettle.storage_instance SET active_bytes=active_bytes+$1,
         retained_bytes=retained_bytes+$2,reserved_bytes=reserved_bytes+$3",
    )
    .bind(active)
    .bind(retained)
    .bind(reserved)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Immutable metadata of the single revision a reservation settles into.
pub struct Settlement<'a> {
    pub scope: &'a str,
    pub reservation: &'a str,
    pub size_bytes: i64,
    pub content_digest: &'a [u8],
    pub media_type: &'a str,
}

/// Settle a reservation into exactly one revision: charge the actual size and release the
/// unused remainder. Creates the artifact (owned by the reservation actor) on first use. An
/// exact replay returns the same revision; different metadata or a released reservation
/// conflicts.
pub async fn settle(tx: &mut WriteTransaction<'_>, s: &Settlement<'_>) -> Result<String, Error> {
    uuid(s.scope)?;
    uuid(s.reservation)?;
    if s.size_bytes < 0 || s.content_digest.len() != 32 || !bounded(s.media_type, 255) {
        return Err(Error::Invalid);
    }
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        let row = sqlx::query("SELECT actor_user_id::text,artifact_id::text,max_bytes,state FROM openmettle.storage_reservations
             WHERE scope_id=$1::uuid AND id=$2::uuid FOR UPDATE")
            .bind(s.scope).bind(s.reservation).fetch_optional(&mut *sp).await?.ok_or(Error::NotFound)?;
        let actor: String = row.get("actor_user_id");
        let artifact: String = row.get("artifact_id");
        let max: i64 = row.get("max_bytes");
        match ReservationState::parse(row.get("state"))? {
            ReservationState::Released => return Err(Error::Conflict),
            ReservationState::Settled => {
                let rev = sqlx::query("SELECT id::text,artifact_id::text,size_bytes,content_digest,media_type,
                     created_by_user_id::text FROM openmettle.artifact_revisions
                     WHERE scope_id=$1::uuid AND reservation_id=$2::uuid")
                    .bind(s.scope).bind(s.reservation).fetch_one(&mut *sp).await?;
                if rev.get::<String, _>("artifact_id") != artifact
                    || rev.get::<i64, _>("size_bytes") != s.size_bytes
                    || rev.get::<Vec<u8>, _>("content_digest") != s.content_digest
                    || rev.get::<String, _>("media_type") != s.media_type
                    || rev.get::<String, _>("created_by_user_id") != actor
                {
                    return Err(Error::Conflict);
                }
                return Ok(rev.get("id"));
            }
            ReservationState::Reserved => {}
        }
        if s.size_bytes > max {
            return Err(Error::Invalid);
        }
        sqlx::query("INSERT INTO openmettle.artifacts(id,scope_id,scope_kind,owner_user_id)
             SELECT $1::uuid,id,kind,$3::uuid FROM openmettle.scopes WHERE id=$2::uuid ON CONFLICT (id) DO NOTHING")
            .bind(&artifact).bind(s.scope).bind(&actor).execute(&mut *sp).await?;
        let owner: String = sqlx::query_scalar("SELECT scope_id::text FROM openmettle.artifacts WHERE id=$1::uuid FOR UPDATE")
            .bind(&artifact).fetch_one(&mut *sp).await?;
        if owner != s.scope {
            return Err(Error::Conflict);
        }
        let number: i64 = sqlx::query_scalar("UPDATE openmettle.artifacts SET last_revision=last_revision+1
             WHERE id=$1::uuid RETURNING last_revision")
            .bind(&artifact).fetch_one(&mut *sp).await?;
        let revision: String = sqlx::query_scalar("INSERT INTO openmettle.artifact_revisions
             (scope_id,artifact_id,revision,reservation_id,size_bytes,content_digest,media_type,created_by_user_id)
             VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5,$6,$7,$8::uuid) RETURNING id::text")
            .bind(s.scope).bind(&artifact).bind(number).bind(s.reservation).bind(s.size_bytes)
            .bind(s.content_digest).bind(s.media_type).bind(&actor).fetch_one(&mut *sp).await?;
        sqlx::query("UPDATE openmettle.storage_reservations SET state='settled',settled_bytes=$3,closed_at=now()
             WHERE scope_id=$1::uuid AND id=$2::uuid")
            .bind(s.scope).bind(s.reservation).bind(s.size_bytes).execute(&mut *sp).await?;
        adjust(&mut sp, s.scope, s.size_bytes, 0, -max).await?;
        Ok(revision)
    }
    .await;
    let result = finish(sp, result).await?;
    tx.restore(outer);
    result
}

/// Release an unsettled reservation in full. Refused while the linked operation (or, for a
/// run-only link, any operation of the run) is `intent` or `outcome_unknown`, checked under
/// the run lock. A known outcome is necessary, not sufficient: the caller must first have
/// reconciled that no bytes from this reservation remain to be settled. Timeouts never
/// authorize release, and there is no automatic expiry. Repeating a release is a no-op.
pub async fn release(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    reservation: &str,
) -> Result<(), Error> {
    uuid(scope)?;
    uuid(reservation)?;
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        // run_id/operation_id are immutable, so reading them before locking is safe.
        let link = sqlx::query(
            "SELECT run_id::text,operation_id::text FROM openmettle.storage_reservations
             WHERE scope_id=$1::uuid AND id=$2::uuid",
        )
        .bind(scope)
        .bind(reservation)
        .fetch_optional(&mut *sp)
        .await?
        .ok_or(Error::NotFound)?;
        let run: Option<String> = link.get("run_id");
        let operation: Option<String> = link.get("operation_id");
        if let Some(run) = &run {
            lock_run(&mut sp, scope, run).await?;
        }
        let row = sqlx::query(
            "SELECT state,max_bytes FROM openmettle.storage_reservations
             WHERE scope_id=$1::uuid AND id=$2::uuid FOR UPDATE",
        )
        .bind(scope)
        .bind(reservation)
        .fetch_one(&mut *sp)
        .await?;
        match ReservationState::parse(row.get("state"))? {
            ReservationState::Released => return Ok(()),
            ReservationState::Settled => return Err(Error::Conflict),
            ReservationState::Reserved => {}
        }
        if let Some(run) = &run {
            let unresolved: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT FROM openmettle.operations
                 WHERE scope_id=$1::uuid AND run_id=$2::uuid AND ($3::uuid IS NULL OR id=$3::uuid)
                 AND outcome IN ('intent','outcome_unknown'))",
            )
            .bind(scope)
            .bind(run)
            .bind(&operation)
            .fetch_one(&mut *sp)
            .await?;
            if unresolved {
                return Err(Error::Unresolved);
            }
        }
        sqlx::query(
            "UPDATE openmettle.storage_reservations SET state='released',closed_at=now()
             WHERE scope_id=$1::uuid AND id=$2::uuid",
        )
        .bind(scope)
        .bind(reservation)
        .execute(&mut *sp)
        .await?;
        adjust(&mut sp, scope, 0, 0, -row.get::<i64, _>("max_bytes")).await
    }
    .await;
    let result = finish(sp, result).await?;
    tx.restore(outer);
    result
}

/// Locks a revision and returns (state, size, deadline text, now < deadline, now >= deadline,
/// purge claim committed before this transaction).
async fn lock_revision(
    tx: &mut Transaction<'_, Postgres>,
    scope: &str,
    revision: &str,
) -> Result<(String, i64, Option<String>, bool, bool, bool), Error> {
    let row = sqlx::query(
        "SELECT state,size_bytes,purge_after::text AS deadline,
         coalesce(now() < purge_after,false) AS before,coalesce(now() >= purge_after,false) AS due,
         coalesce(purging_at < now(),false) AS claimed
         FROM openmettle.artifact_revisions WHERE scope_id=$1::uuid AND id=$2::uuid FOR UPDATE",
    )
    .bind(scope)
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::NotFound)?;
    Ok((
        row.get("state"),
        row.get("size_bytes"),
        row.get("deadline"),
        row.get("before"),
        row.get("due"),
        row.get("claimed"),
    ))
}

async fn lifecycle<T>(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
    step: impl AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<T, Error>,
) -> Result<T, Error> {
    uuid(scope)?;
    uuid(revision)?;
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = step(&mut sp).await;
    let result = finish(sp, result).await?;
    tx.restore(outer);
    result
}

/// Move an active revision to retained with `purge_after = now() + grace`, keeping its bytes
/// charged. `grace_seconds` is the deployment's configured grace (30 days by default) and must
/// be positive. A retry, or a call in any later state, returns the stored deadline unchanged.
pub async fn retain_revision(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
    grace_seconds: u32,
) -> Result<String, Error> {
    if grace_seconds == 0 {
        return Err(Error::Invalid);
    }
    lifecycle(tx, scope, revision, async |sp| {
        let (state, size, deadline, ..) = lock_revision(sp, scope, revision).await?;
        if state != "active" {
            return deadline.ok_or(Error::Invalid);
        }
        let deadline: String = sqlx::query_scalar(
            "UPDATE openmettle.artifact_revisions SET state='retained',
             retained_at=now(),purge_after=now()+$3*interval '1 second'
             WHERE scope_id=$1::uuid AND id=$2::uuid RETURNING purge_after::text",
        )
        .bind(scope)
        .bind(revision)
        .bind(i64::from(grace_seconds))
        .fetch_one(&mut **sp)
        .await?;
        adjust(sp, scope, -size, size, 0).await?;
        Ok(deadline)
    })
    .await
}

/// Return a retained revision to active before its deadline. Active is a no-op; an expired,
/// purging or purged revision is not eligible.
pub async fn restore_revision(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
) -> Result<(), Error> {
    lifecycle(tx, scope, revision, async |sp| {
        let (state, size, _, before, ..) = lock_revision(sp, scope, revision).await?;
        match state.as_str() {
            "active" => return Ok(()),
            "retained" if before => {}
            _ => return Err(Error::NotEligible),
        }
        sqlx::query("UPDATE openmettle.artifact_revisions SET state='active',retained_at=NULL,purge_after=NULL
             WHERE scope_id=$1::uuid AND id=$2::uuid")
            .bind(scope).bind(revision).execute(&mut **sp).await?;
        adjust(sp, scope, size, -size, 0).await
    })
    .await
}

/// Claim an expired retained revision for purge. Bytes stay charged. Repeating the claim, or
/// claiming a purged revision, is a no-op; before the deadline it is not eligible.
pub async fn begin_purge(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
) -> Result<(), Error> {
    lifecycle(tx, scope, revision, async |sp| {
        let (state, _, _, _, due, _) = lock_revision(sp, scope, revision).await?;
        match state.as_str() {
            "purging" | "purged" => return Ok(()),
            "retained" if due => {}
            _ => return Err(Error::NotEligible),
        }
        sqlx::query(
            "UPDATE openmettle.artifact_revisions SET state='purging',purging_at=now()
             WHERE scope_id=$1::uuid AND id=$2::uuid",
        )
        .bind(scope)
        .bind(revision)
        .execute(&mut **sp)
        .await?;
        Ok(())
    })
    .await
}

/// Record that payload deletion succeeded and stop charging the bytes. Requires a purge claim
/// committed by an earlier transaction. Repeated confirmation is a no-op and never decrements
/// twice.
pub async fn confirm_purge(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
) -> Result<(), Error> {
    lifecycle(tx, scope, revision, async |sp| {
        let (state, size, _, _, _, claimed) = lock_revision(sp, scope, revision).await?;
        match state.as_str() {
            "purged" => return Ok(()),
            "purging" if claimed => {}
            _ => return Err(Error::NotEligible),
        }
        sqlx::query(
            "UPDATE openmettle.artifact_revisions SET state='purged',purged_at=now()
             WHERE scope_id=$1::uuid AND id=$2::uuid",
        )
        .bind(scope)
        .bind(revision)
        .execute(&mut **sp)
        .await?;
        adjust(sp, scope, 0, -size, 0).await
    })
    .await
}
