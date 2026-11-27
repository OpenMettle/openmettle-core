//! Artifact revision and storage-accounting persistence primitives (ADR 0005). Not a quota,
//! upload, retention or purge service. Helpers borrow the caller's `WriteTransaction`, work
//! inside a savepoint and never commit. They keep counters consistent only for writers that
//! use them; direct SQL by an application role can bypass that protocol.
//!
//! Lock order across helpers: run, reservation, artifact, revision, the restore gate (shared,
//! on a move into `purging` or `purged`), volume control, owner account, instance, then the
//! retention policy (shared, for a removal's deadline) and at commit the deletion journal head
//! (ADR 0040, ADR 0041). Each helper follows it. Callers composing several helpers or owners in one transaction can
//! still deadlock (SQLSTATE 40P01): abandon the whole transaction and retry it with the same
//! idempotency keys. Never infer success from a failed or interrupted commit.
use crate::{
    runs::{Error, WriteTransaction, bounded, digest, finish, identity, lock_run, uuid},
    telemetry::metrics::{self, StorageOperation, StorageOutcome},
};
use sqlx::{Acquire, PgConnection, Postgres, Row, Transaction};

fn record<T>(operation: StorageOperation, result: Result<T, Error>) -> Result<T, Error> {
    let outcome = match &result {
        Ok(_) => StorageOutcome::Ok,
        Err(
            Error::OwnerLimit
            | Error::InstanceLimit
            | Error::LimitUnconfigured
            | Error::InstanceLimitUnconfigured,
        ) => StorageOutcome::QuotaRefused,
        Err(Error::Conflict | Error::StaleRevision | Error::NotEligible | Error::Unresolved) => {
            StorageOutcome::Conflict
        }
        Err(Error::NotFound) => StorageOutcome::NotFound,
        Err(Error::Invalid) => StorageOutcome::Invalid,
        Err(Error::Database(_) | Error::TransactionUnavailable) => StorageOutcome::Error,
    };
    metrics::global().record_storage(operation, outcome);
    result
}

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
    record(StorageOperation::Reserve, reserve_inner(tx, r).await)
}

async fn reserve_inner(
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
        if !crate::restore::lock_open_gate(&mut sp).await? {
            return Err(Error::Database(sqlx::Error::Protocol(
                "restore reconciliation pending".into(),
            )));
        }
        // ADR 0046: close fresh client upload reservations during maintenance while allowing
        // in-flight draining worker runs (`r.run.is_some()`) to settle spill artifacts.
        if r.run.is_none() && !crate::backup::lock_open_maintenance(&mut sp).await? {
            return Err(Error::Database(sqlx::Error::Protocol(
                "service is in maintenance window".into(),
            )));
        }
        // On a pinned deployment serialize acquisition with adoption before locking counters.
        // Existing unpinned HTTP uploads can proceed while the fleet is being replaced.
        sqlx::query("SELECT openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
            WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL)").execute(&mut *sp).await?;
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
            .fetch_optional(&mut *sp).await?.ok_or(Error::InstanceLimitUnconfigured)?;
        let override_limit:Option<i64>=sqlx::query_scalar("SELECT hard_limit FROM openmettle.quota_overrides WHERE
            scope_id=$1::uuid AND resource_kind='storage_bytes' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())")
            .bind(r.scope).fetch_optional(&mut *sp).await?;
        let owner_limit: Option<i64> = override_limit.or(instance.get(if kind == "personal" {
            "personal_limit_bytes"
        } else {
            "project_limit_bytes"
        }));
        let Some(owner_limit) = owner_limit else {
            return Err(Error::LimitUnconfigured);
        };
        let Some(budget): Option<i64> = instance.get("instance_budget_bytes") else {
            return Err(Error::InstanceLimitUnconfigured);
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
             (scope_id,actor_user_id,idempotency_key,artifact_id,max_bytes,run_id,operation_id,request_identity,request_digest,lease_expires_at)
             VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5,$6::uuid,$7::uuid,$8,$9,
                 CASE WHEN $6::uuid IS NULL THEN clock_timestamp()+interval '900 seconds'
                      ELSE (SELECT greatest(clock_timestamp()+interval '1 second',coalesce(execution_expires_at,queue_expires_at)+interval '60 seconds')
                            FROM openmettle.runs WHERE id=$6::uuid) END) RETURNING id::text")
            .bind(r.scope).bind(r.actor).bind(r.key).bind(r.artifact).bind(r.max_bytes).bind(r.run).bind(r.operation)
            .bind(&id).bind(&hash).fetch_one(&mut *sp).await?;
        adjust(&mut sp, r.scope, 0, 0, r.max_bytes).await?;
        sqlx::query("SELECT openmettle.quota_record_storage_warning($1::uuid,$2)")
            .bind(r.scope).bind(r.max_bytes).execute(&mut *sp).await?;
        Ok(Reservation { id: reservation, state: ReservationState::Reserved })
    }
    .await;
    let result = finish(sp, result).await?;
    tx.restore(outer);
    result
}

/// The artifact an upload under `(scope, actor, key)` names: the one an earlier reservation
/// with that key chose, so an exact retry reserves the same identity again, or else a new random
/// UUID. Two first attempts racing on one key may choose different artifacts; `reserve` then
/// refuses the later one with `Conflict`.
pub async fn upload_artifact(
    c: &mut PgConnection,
    scope: &str,
    actor: &str,
    key: &str,
) -> Result<String, Error> {
    uuid(scope)?;
    uuid(actor)?;
    if !bounded(key, 128) {
        return Err(Error::Invalid);
    }
    Ok(sqlx::query_scalar(
        "SELECT coalesce((SELECT artifact_id::text FROM openmettle.storage_reservations
                           WHERE scope_id = $1::uuid AND actor_user_id = $2::uuid
                             AND idempotency_key = $3),
                         gen_random_uuid()::text)",
    )
    .bind(scope)
    .bind(actor)
    .bind(key)
    .fetch_one(c)
    .await?)
}

/// The stored metadata of one artifact revision and its scope. `reservation_id` names the
/// payload file (ADR 0031) and never leaves the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    pub id: String,
    pub artifact_id: String,
    pub revision: i64,
    pub scope_id: String,
    /// The containing project, or `None` in a personal scope.
    pub project_id: Option<String>,
    pub reservation_id: String,
    pub size_bytes: i64,
    pub content_digest: Vec<u8>,
    pub media_type: String,
    pub display_name: Option<String>,
    /// `active`, `retained`, `purging`, `purged` or `lost`.
    pub state: String,
    /// Creation time in Unix microseconds.
    pub created_us: i64,
    /// Disassociation time in Unix microseconds, or `None` while `active`.
    pub retained_us: Option<i64>,
    /// Earliest purge deadline in Unix microseconds, or `None` while `active`.
    pub purge_after_us: Option<i64>,
    /// Time the payload was declared permanently lost after a restore, or `None`.
    pub lost_us: Option<i64>,
}

/// Reads revision `revision_id` of `artifact_id`, or `None` when it does not exist or belongs
/// to another artifact. No authorization: the caller decides access to the artifact first.
pub async fn read_revision(
    c: &mut PgConnection,
    artifact_id: &str,
    revision_id: &str,
) -> Result<Option<Revision>, Error> {
    read_revision_locked(c, artifact_id, revision_id, false).await
}

/// Like [`read_revision`], acquiring `FOR SHARE` on `openmettle.artifact_revisions` so concurrent
/// disassociation cannot commit while download admission checks the restore gate and opens the
/// payload (preserving canonical lock order: `artifact_revisions` before
/// `restore_reconciliation_gate`).
pub(crate) async fn read_revision_for_share(
    c: &mut PgConnection,
    artifact_id: &str,
    revision_id: &str,
) -> Result<Option<Revision>, Error> {
    read_revision_locked(c, artifact_id, revision_id, true).await
}

async fn read_revision_locked(
    c: &mut PgConnection,
    artifact_id: &str,
    revision_id: &str,
    for_share: bool,
) -> Result<Option<Revision>, Error> {
    uuid(artifact_id)?;
    uuid(revision_id)?;
    let sql = if for_share {
        "SELECT r.id::text, r.artifact_id::text, r.revision, r.scope_id::text, s.project_id::text,
                r.reservation_id::text, r.size_bytes, r.content_digest, r.media_type,
                r.display_name, r.state,
                (extract(epoch FROM r.created_at) * 1000000)::bigint,
                (extract(epoch FROM r.retained_at) * 1000000)::bigint,
                (extract(epoch FROM r.purge_after) * 1000000)::bigint,
                (extract(epoch FROM r.lost_at) * 1000000)::bigint
           FROM openmettle.artifact_revisions r JOIN openmettle.scopes s ON s.id = r.scope_id
          WHERE r.artifact_id = $1::uuid AND r.id = $2::uuid
            FOR SHARE OF r"
    } else {
        "SELECT r.id::text, r.artifact_id::text, r.revision, r.scope_id::text, s.project_id::text,
                r.reservation_id::text, r.size_bytes, r.content_digest, r.media_type,
                r.display_name, r.state,
                (extract(epoch FROM r.created_at) * 1000000)::bigint,
                (extract(epoch FROM r.retained_at) * 1000000)::bigint,
                (extract(epoch FROM r.purge_after) * 1000000)::bigint,
                (extract(epoch FROM r.lost_at) * 1000000)::bigint
           FROM openmettle.artifact_revisions r JOIN openmettle.scopes s ON s.id = r.scope_id
          WHERE r.artifact_id = $1::uuid AND r.id = $2::uuid"
    };
    let row = sqlx::query(sql)
        .bind(artifact_id)
        .bind(revision_id)
        .fetch_optional(c)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(Revision {
        id: row.try_get(0)?,
        artifact_id: row.try_get(1)?,
        revision: row.try_get(2)?,
        scope_id: row.try_get(3)?,
        project_id: row.try_get(4)?,
        reservation_id: row.try_get(5)?,
        size_bytes: row.try_get(6)?,
        content_digest: row.try_get(7)?,
        media_type: row.try_get(8)?,
        display_name: row.try_get(9)?,
        state: row.try_get(10)?,
        created_us: row.try_get(11)?,
        retained_us: row.try_get(12)?,
        purge_after_us: row.try_get(13)?,
        lost_us: row.try_get(14)?,
    }))
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
    sqlx::query(
        "SELECT openmettle.storage_lock_pinned_volume() FROM openmettle.storage_volume_control
        WHERE id AND (volume_id IS NOT NULL OR adoption_run_id IS NOT NULL)",
    )
    .execute(&mut **tx)
    .await?;
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
    /// Optional client-supplied file name, display metadata only (ADR 0031). Never a path.
    pub display_name: Option<&'a str>,
}

/// A display name is 1 to 255 characters without control characters or surrounding white
/// space; at least as strict as migration 17, which checks only ASCII classes.
pub fn valid_display_name(name: &str) -> bool {
    let count = name.chars().count();
    (1..=255).contains(&count) && !name.chars().any(char::is_control) && name.trim() == name
}

/// Settle a reservation into exactly one revision: charge the actual size and release the
/// unused remainder. Creates the artifact (owned by the reservation actor) on first use. An
/// exact replay returns the same revision; different metadata (including the display name) or
/// a released reservation conflicts.
pub async fn settle(tx: &mut WriteTransaction<'_>, s: &Settlement<'_>) -> Result<String, Error> {
    record(StorageOperation::Settle, settle_inner(tx, s).await)
}

async fn settle_inner(tx: &mut WriteTransaction<'_>, s: &Settlement<'_>) -> Result<String, Error> {
    uuid(s.scope)?;
    uuid(s.reservation)?;
    if s.size_bytes < 0
        || s.content_digest.len() != 32
        || !bounded(s.media_type, 255)
        || s.display_name.is_some_and(|name| !valid_display_name(name))
    {
        return Err(Error::Invalid);
    }
    let mut outer = tx.take_active()?;
    let mut sp = outer.begin().await?;
    let result = async {
        let row = sqlx::query("SELECT actor_user_id::text,artifact_id::text,max_bytes,state,reclaim_state,adoption_unverified,
            payload_ino IS NOT NULL AS bound,publish_pending FROM openmettle.storage_reservations
             WHERE scope_id=$1::uuid AND id=$2::uuid FOR UPDATE")
            .bind(s.scope).bind(s.reservation).fetch_optional(&mut *sp).await?.ok_or(Error::NotFound)?;
        let actor: String = row.get("actor_user_id");
        let artifact: String = row.get("artifact_id");
        let max: i64 = row.get("max_bytes");
        match ReservationState::parse(row.get("state"))? {
            ReservationState::Released => return Err(Error::Conflict),
            ReservationState::Settled => {
                if !crate::restore::lock_open_gate(&mut sp).await? {
                    return Err(Error::Database(sqlx::Error::Protocol(
                        "restore reconciliation pending".into(),
                    )));
                }
                let rev = sqlx::query("SELECT id::text,artifact_id::text,size_bytes,content_digest,media_type,
                     display_name,created_by_user_id::text FROM openmettle.artifact_revisions
                     WHERE scope_id=$1::uuid AND reservation_id=$2::uuid")
                    .bind(s.scope).bind(s.reservation).fetch_one(&mut *sp).await?;
                if rev.get::<String, _>("artifact_id") != artifact
                    || rev.get::<i64, _>("size_bytes") != s.size_bytes
                    || rev.get::<Vec<u8>, _>("content_digest") != s.content_digest
                    || rev.get::<String, _>("media_type") != s.media_type
                    || rev.get::<Option<String>, _>("display_name").as_deref() != s.display_name
                    || rev.get::<String, _>("created_by_user_id") != actor
                {
                    return Err(Error::Conflict);
                }
                return Ok(rev.get("id"));
            }
            ReservationState::Reserved => {}
        }
        if row.get::<bool,_>("adoption_unverified") || row.get::<&str,_>("reclaim_state") != "none"
            || !row.get::<bool,_>("bound") || !row.get::<bool,_>("publish_pending") {
            return Err(Error::Conflict);
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
        if !crate::restore::lock_open_gate(&mut sp).await? {
            return Err(Error::Database(sqlx::Error::Protocol(
                "restore reconciliation pending".into(),
            )));
        }
        let number: i64 = sqlx::query_scalar("UPDATE openmettle.artifacts SET last_revision=last_revision+1
             WHERE id=$1::uuid RETURNING last_revision")
            .bind(&artifact).fetch_one(&mut *sp).await?;
        // Name `display_name` only when set, so an unnamed settle also runs on schemas 4-16.
        let sql = if s.display_name.is_some() {
            "INSERT INTO openmettle.artifact_revisions
             (scope_id,artifact_id,revision,reservation_id,size_bytes,content_digest,media_type,
              created_by_user_id,display_name)
             VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5,$6,$7,$8::uuid,$9) RETURNING id::text"
        } else {
            "INSERT INTO openmettle.artifact_revisions
             (scope_id,artifact_id,revision,reservation_id,size_bytes,content_digest,media_type,
              created_by_user_id)
             VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5,$6,$7,$8::uuid) RETURNING id::text"
        };
        let mut insert = sqlx::query_scalar(sql)
            .bind(s.scope).bind(&artifact).bind(number).bind(s.reservation).bind(s.size_bytes)
            .bind(s.content_digest).bind(s.media_type).bind(&actor);
        if let Some(name) = s.display_name {
            insert = insert.bind(name);
        }
        let revision: String = insert.fetch_one(&mut *sp).await?;
        sqlx::query("UPDATE openmettle.storage_reservations SET state='settled',publish_pending=false,settled_bytes=$3,closed_at=now()
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
    record(
        StorageOperation::Release,
        release_inner(tx, scope, reservation, None).await,
    )
}

pub(crate) async fn release_claimed(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    reservation: &str,
    claim: &str,
) -> Result<(), Error> {
    record(
        StorageOperation::Release,
        release_inner(tx, scope, reservation, Some(claim)).await,
    )
}

async fn release_inner(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    reservation: &str,
    claim: Option<&str>,
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
            "SELECT state,max_bytes,stage_claimed,payload_ino IS NOT NULL AS bound,adoption_unverified,
             publish_pending,reclaim_state,reclaim_claim_token::text AS token FROM openmettle.storage_reservations
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
        let reclaim: &str = row.get("reclaim_state");
        let bound: bool = row.get("bound");
        if row.get::<bool,_>("adoption_unverified") || row.get::<bool,_>("publish_pending")
            || row.get::<Option<&str>,_>("token") != claim
            || match claim {
                Some(_) => if bound { reclaim != "truncated" } else { reclaim != "claiming" },
                None => bound || row.get::<bool,_>("stage_claimed") || reclaim != "none",
            }
        {return Err(Error::NotEligible);}
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
            "UPDATE openmettle.storage_reservations SET state='released',closed_at=now(),
             reclaim_state=CASE WHEN reclaim_state='truncated' THEN 'anchor_pending_unlink' ELSE 'none' END,
             reclaim_claim_token=NULL,reclaim_lease_until=NULL
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

/// Locks a revision and returns (state, size, deadline text, purge claim committed before this
/// transaction began). Deadline comparisons are not made here: a value computed in the locking
/// statement can predate its lock wait. Each transition compares `clock_timestamp()` in its
/// own later statement, after its locks are held. `claimed` deliberately compares with the
/// transaction start: it only tells a claim made by this transaction from an earlier one.
async fn lock_revision(
    tx: &mut Transaction<'_, Postgres>,
    scope: &str,
    revision: &str,
) -> Result<(String, i64, Option<String>, bool), Error> {
    let row = sqlx::query(
        "SELECT state,size_bytes,purge_after::text AS deadline,coalesce(purging_at < now(),false) AS claimed
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
        row.get("claimed"),
    ))
}

async fn lifecycle<T>(
    operation: StorageOperation,
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
    step: impl AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<T, Error>,
) -> Result<T, Error> {
    let result = async {
        uuid(scope)?;
        uuid(revision)?;
        let mut outer = tx.take_active()?;
        let mut sp = outer.begin().await?;
        let result = step(&mut sp).await;
        let result = finish(sp, result).await?;
        tx.restore(outer);
        result
    }
    .await;
    record(operation, result)
}

/// Move an active revision to retained, keeping its bytes charged. Migration 28's trigger sets
/// `retained_at`, `purge_after` and the policy stamp from the installation's `retention_policy`
/// (30 days by default; 0 only when the operator's bounds allow it) and the wall clock, after
/// every storage lock is held. Under `READ COMMITTED` a policy change in flight is waited for
/// and applied; under `REPEATABLE READ` one committed after the snapshot fails with 40001. A
/// retry, or a call in any later state, returns the stored deadline unchanged.
pub async fn retain_revision(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
) -> Result<String, Error> {
    lifecycle(StorageOperation::Retain, tx, scope, revision, async |sp| {
        let (state, size, deadline, _) = lock_revision(sp, scope, revision).await?;
        let gate_open = crate::restore::lock_open_gate(sp).await?;
        if !crate::backup::lock_open_maintenance(sp).await? {
            return Err(Error::Database(sqlx::Error::Protocol(
                "service is in maintenance window".into(),
            )));
        }
        if state != "active" {
            if !gate_open {
                return Err(Error::Database(sqlx::Error::Protocol(
                    "restore reconciliation pending".into(),
                )));
            }
            return deadline.ok_or(Error::Invalid);
        }
        adjust(sp, scope, -size, size, 0).await?;
        // Naming the retention columns keeps their API-only grants deciding who may retain;
        // the trigger replaces these values (and refuses closed restore gates with OMR02).
        Ok(sqlx::query_scalar(
            "UPDATE openmettle.artifact_revisions SET state='retained',retained_at=NULL,purge_after=NULL,
             retention_policy_revision=NULL WHERE scope_id=$1::uuid AND id=$2::uuid RETURNING purge_after::text",
        )
        .bind(scope)
        .bind(revision)
        .fetch_one(&mut **sp)
        .await?)
    })
    .await
}

/// Return a retained revision to active strictly before its deadline, judged by the wall clock
/// once every lock of the transition is held. Active is a no-op; an expired, purging or purged
/// revision is not eligible.
pub async fn restore_revision(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
) -> Result<(), Error> {
    lifecycle(StorageOperation::Restore, tx, scope, revision, async |sp| {
        let (state, size, ..) = lock_revision(sp, scope, revision).await?;
        let gate_open = crate::restore::lock_open_gate(sp).await?;
        if !crate::backup::lock_open_maintenance(sp).await? {
            return Err(Error::Database(sqlx::Error::Protocol(
                "service is in maintenance window".into(),
            )));
        }
        match state.as_str() {
            "active" => {
                if !gate_open {
                    return Err(Error::Database(sqlx::Error::Protocol(
                        "restore reconciliation pending".into(),
                    )));
                }
                return Ok(());
            }
            "retained" => {}
            _ => return Err(Error::NotEligible),
        }
        // Counters first, so the deadline comparison follows the last lock; refusing rolls the
        // savepoint and the counter change back.
        adjust(sp, scope, size, -size, 0).await?;
        let restored = sqlx::query(
            "UPDATE openmettle.artifact_revisions SET state='active',retained_at=NULL,purge_after=NULL,
             retention_policy_revision=NULL WHERE scope_id=$1::uuid AND id=$2::uuid
             AND state='retained' AND clock_timestamp() < purge_after",
        )
        .bind(scope)
        .bind(revision)
        .execute(&mut **sp)
        .await?;
        if restored.rows_affected() != 1 {
            return Err(Error::NotEligible);
        }
        Ok(())
    })
    .await
}

/// Claim an expired retained revision for purge. Bytes stay charged. Repeating the claim, or
/// claiming a purged revision, is a no-op. It is not eligible before the deadline, while its
/// payload binding is unverified, or while `openmettle.artifact_revision_pinned` finds a
/// reference: a message attachment, an operator hold, or its writing run still unfinished.
///
/// Requires `READ COMMITTED`; migration 28's claim guard fails the claim with SQLSTATE 25000
/// under any other level, because the recheck must see references that other sessions commit
/// while this one waits for the revision lock. Lock order: the revision row `FOR UPDATE`, then
/// the restore gate `FOR SHARE` through migration 41's guard (OMR02 while a restore awaits
/// journal replay), then `storage_volume_control` `FOR SHARE` through migration 24's pin guard
/// on the claim (OMQ03 while unpinned or adopting). Every new attachment or hold first locks the revision row
/// `FOR SHARE`, so it either commits before this lock is granted and the recheck (a later
/// statement, with a newer snapshot) sees it, or it waits and then fails on `purging` (OMR01).
/// Runs only move towards an outcome. The guarantee holds while this transaction keeps the row
/// lock; once `purging` commits, no new reference or restore can succeed. The deadline is judged
/// by the wall clock in the claiming statement, after the row lock and the recheck; the pin
/// guard's later lock wait cannot undo it because a reached deadline stays reached. A claim
/// committed before migration 28 (already `purging`) is resumed without a recheck: it was valid
/// when made and its payload may already be gone (see the migration's upgrade note).
pub async fn begin_purge(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
) -> Result<(), Error> {
    lifecycle(
        StorageOperation::BeginPurge,
        tx,
        scope,
        revision,
        async |sp| {
            let (state, ..) = lock_revision(sp, scope, revision).await?;
            let retained = state == "retained";
            let eligible: bool = sqlx::query_scalar(
                "SELECT NOT s.adoption_unverified AND s.payload_ino IS NOT NULL
                    AND NOT ($3 AND openmettle.artifact_revision_pinned(r.scope_id, r.id))
                 FROM openmettle.artifact_revisions r JOIN openmettle.storage_reservations s
                 ON s.scope_id=r.scope_id AND s.id=r.reservation_id WHERE r.scope_id=$1::uuid AND r.id=$2::uuid",
            )
            .bind(scope)
            .bind(revision)
            .bind(retained)
            .fetch_one(&mut **sp)
            .await?;
            match state.as_str() {
                _ if !eligible => return Err(Error::NotEligible),
                "purging" | "purged" => return Ok(()),
                _ if retained => {
                    if !crate::backup::lock_open_maintenance(sp).await? {
                        return Err(Error::Database(sqlx::Error::Protocol(
                            "service is in maintenance window".into(),
                        )));
                    }
                }
                _ => return Err(Error::NotEligible),
            }
            let claimed = sqlx::query(
                "UPDATE openmettle.artifact_revisions SET state='purging',purging_at=clock_timestamp()
                 WHERE scope_id=$1::uuid AND id=$2::uuid AND purge_after <= clock_timestamp()",
            )
            .bind(scope)
            .bind(revision)
            .execute(&mut **sp)
            .await?;
            if claimed.rows_affected() != 1 {
                return Err(Error::NotEligible);
            }
            Ok(())
        },
    )
    .await
}

/// Record that payload deletion succeeded and stop charging the bytes. Requires a purge claim
/// committed by an earlier transaction. Repeated confirmation is a no-op and never decrements
/// twice. Migration 28's deferred trigger appends the revision's `deletion_journal` record when
/// the caller commits, taking the journal head lock after every storage lock; a confirmation
/// that rolls back (or whose commit fails) leaves neither the purge nor a record.
pub async fn confirm_purge(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    revision: &str,
) -> Result<(), Error> {
    lifecycle(
        StorageOperation::ConfirmPurge,
        tx,
        scope,
        revision,
        async |sp| {
            let (state, size, _, claimed) = lock_revision(sp, scope, revision).await?;
            match state.as_str() {
                "purged" => return Ok(()),
                "purging" if claimed => {}
                _ => return Err(Error::NotEligible),
            }
            sqlx::query(
                "UPDATE openmettle.artifact_revisions SET state='purged',purged_at=now(),purge_stage='anchor_pending_unlink'
                 WHERE scope_id=$1::uuid AND id=$2::uuid",
            )
            .bind(scope)
            .bind(revision)
            .execute(&mut **sp)
            .await?;
            adjust(sp, scope, 0, -size, 0).await
        },
    )
    .await
}
