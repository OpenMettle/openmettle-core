//! Gateway reservation, handoff and settlement store (ADRs 0037 and 0044). A run round is handed
//! off without a gateway binding, under a per-round bearer of which the database holds a hash.
//! The ADR 0037 provisioning and sealed-key code here has no caller and awaits removal.
use crate::{
    provider_keys::gateway::{Context, Envelope, GatewayKeys},
    runs::WriteTransaction,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::crypto::SharedSecret;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::fmt;

/// All failure classes are safe to display or log, including a failed commit.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Database,
    Refused,
    Retryable,
    Protection,
    Conflict,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database => "gateway store unavailable",
            Self::Refused => "gateway request refused",
            Self::Retryable => "gateway reservation retryable",
            Self::Protection => "gateway credential unavailable",
            Self::Conflict => "gateway intent conflict",
        })
    }
}
impl std::error::Error for Error {}
impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        match error.as_database_error().and_then(|e| e.code()).as_deref() {
            Some("OMQ01" | "OMQ02" | "OMQ05") => Self::Refused,
            Some("40001") => Self::Retryable,
            _ => Self::Database,
        }
    }
}

/// Map SQLSTATE `42501` (stale run lease) and `P0002` (run no longer live/running) to `Refused`.
pub(crate) fn map_stale_lease(err: sqlx::Error) -> Error {
    match err.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("42501" | "P0002") => Error::Refused,
        _ => Error::from(err),
    }
}
impl From<crate::runs::Error> for Error {
    fn from(error: crate::runs::Error) -> Self {
        match error {
            crate::runs::Error::Database(db) => Self::from(db),
            _ => Self::Database,
        }
    }
}

pub struct Reservation<'a> {
    pub id: &'a str,
    pub scope_id: &'a str,
    pub actor: &'a str,
    pub approval: &'a str,
}
/// Compose this with run admission under the API role. The same run cannot own two holds.
pub async fn hold(
    tx: &mut WriteTransaction<'_>,
    r: &Reservation<'_>,
    run: Option<&str>,
    units: i64,
) -> Result<(), Error> {
    hold_with_cost(tx, r, run, units, None).await
}
/// Reserve a run with an independently denominated maximum cost in deployment micro-units.
pub async fn hold_with_cost(
    tx: &mut WriteTransaction<'_>,
    r: &Reservation<'_>,
    run: Option<&str>,
    units: i64,
    cost_ceiling: Option<i64>,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO openmettle.gateway_reservations (id,scope_id,actor_user_id,approval_id,run_id,units)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6)")
        .bind(r.id)
        .bind(r.scope_id)
        .bind(r.actor)
        .bind(r.approval)
        .bind(run)
        .bind(units)
        .execute(tx.connection()?)
        .await?;
    if let Some(run) = run {
        let spec = match cost_ceiling {
            Some(c) => crate::quotas::CostBoundSpec::Profile(Some(u128::try_from(c).unwrap_or(0))),
            None => crate::quotas::CostBoundSpec::Legacy,
        };
        let cost = crate::quotas::cost_ceiling(tx, r, None, None, spec).await?;
        for (resource, amount) in [("usage_cost_micros", cost), ("usage_tokens", Some(units))] {
            if let Some(amount) = amount {
                sqlx::query("SELECT openmettle.quota_reserve($1::uuid,$2::uuid,$3,$4,$5,$6::uuid,NULL,NULL,
                    (SELECT coalesce(queue_expires_at,clock_timestamp())+interval '60 seconds' FROM openmettle.runs WHERE id=$6::uuid))")
                    .bind(r.scope_id).bind(r.actor).bind(resource).bind(amount).bind(format!("run:{run}")).bind(run)
                    .execute(tx.connection()?).await?;
            }
        }
    }
    Ok(())
}
pub enum Authority<'a> {
    Session {
        credential: &'a str,
        native_audience: Option<&'a [u8; 32]>,
    },
    Lease {
        run: &'a str,
        round: i32,
        token: &'a str,
    },
}
pub struct Call<'a> {
    pub reservation: Reservation<'a>,
    pub installation: &'a str,
    pub model: &'a str,
    pub units: i64,
    pub authority: Authority<'a>,
}

/// Possession of this handle proves the allocating caller owns the unsent request.
/// A failed/ambiguous commit never constructs one. It has no Clone or serialization.
pub struct Pending<'a> {
    pub id: String,
    secret: [u8; 32],
    call: Call<'a>,
    explicit_cost: Option<u128>,
    bound_cost: Option<u128>,
}
pub async fn reserve<'a>(pool: &PgPool, call: Call<'a>) -> Result<Pending<'a>, Error> {
    reserve_with_cost(pool, call, None).await
}
/// Reserve a dispatch with a qualified ceiling independent of its token envelope.
pub async fn reserve_with_cost<'a>(
    pool: &PgPool,
    call: Call<'a>,
    cost_ceiling: Option<i64>,
) -> Result<Pending<'a>, Error> {
    let explicit_cost = match cost_ceiling {
        Some(c) if c > 0 => Some(u128::try_from(c).map_err(|_| Error::Refused)?),
        Some(_) => return Err(Error::Refused),
        None => None,
    };
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let res = async {
        crate::quotas::prepare_round(&mut tx, &call, cost_ceiling).await?;
        let mut pending = reserve_in(&mut tx, call).await?;
        let spec = match explicit_cost {
            Some(c) => crate::quotas::CostBoundSpec::Profile(Some(c)),
            None => crate::quotas::CostBoundSpec::Legacy,
        };
        let bound_cost = match crate::quotas::bind_request(
            &mut tx,
            &pending.call,
            &pending.id,
            &pending.secret,
            spec,
            false,
        )
        .await?
        {
            crate::quotas::BindOutcome::NeedsParentHolds => return Err(Error::Refused),
            crate::quotas::BindOutcome::Bound { bound_cost, .. } => bound_cost,
        };
        pending.explicit_cost = explicit_cost;
        pending.bound_cost = bound_cost;
        Ok(pending)
    }
    .await;
    match res {
        Ok(pending) => {
            tx.commit().await?;
            Ok(pending)
        }
        Err(err) => {
            let _ = tx.rollback().await;
            Err(err)
        }
    }
}
/// Inputs for reserving one leased worker turn round with qualified cost and device bounds.
pub struct TurnRound<'a> {
    pub scope_id: &'a str,
    pub actor: &'a str,
    pub approval: &'a str,
    pub run_id: &'a str,
    pub round: i32,
    pub claim_token: &'a str,
    pub installation: &'a str,
    pub model: &'a str,
    pub round_tokens: i64,
    pub round_cost: Option<u128>,
    pub requires_device_slot: bool,
}

pub use crate::provider_http::{BillableDispatch, CallerDispatch, TurnDispatch};

/// Owned unsent turn-round reservation handle. Never cloned or serialized.
pub struct TurnPending {
    pub id: String,
    secret: [u8; 32],
    reservation_id: String,
    scope_id: String,
    actor: String,
    approval: String,
    run_id: String,
    round: i32,
    claim_token: String,
    installation: String,
    model: String,
    units: i64,
    round_cost: Option<u128>,
    requires_device_slot: bool,
    pub(crate) enforced_at_bind: bool,
    pub(crate) cost_bound_at_bind: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TurnHandoffError {
    /// Deferred `OMQ04` rolled back `handoff` pre-dispatch because enforcement or the first
    /// applicable cost limit activated after `reserve_turn_round` bound without the required hold.
    MissingHold,
    Other(Error),
}

impl TurnPending {
    fn as_pending(&self) -> Pending<'_> {
        Pending {
            id: self.id.clone(),
            secret: self.secret,
            call: Call {
                reservation: Reservation {
                    id: &self.reservation_id,
                    scope_id: &self.scope_id,
                    actor: &self.actor,
                    approval: &self.approval,
                },
                installation: &self.installation,
                model: &self.model,
                units: self.units,
                authority: Authority::Lease {
                    run: &self.run_id,
                    round: self.round,
                    token: &self.claim_token,
                },
            },
            explicit_cost: self.round_cost,
            bound_cost: self.cost_bound_at_bind.then_some(self.round_cost).flatten(),
        }
    }

    pub async fn release(&self, pool: &PgPool) -> Result<bool, Error> {
        self.as_pending().release(pool).await
    }

    /// Atomically commit gateway handoff, optional device-slot handoff, and round usage child
    /// holds in a single write transaction following strict ADR 0040 lock order:
    /// `account_admin_lock..users..runs -> gateway_requests -> quota_reservations (resource_kind, id)
    /// -> quota_gateway_handoffs -> quota_enforcement`. Verifies reserved `(units, round_cost,
    /// requires_device_slot)` bounds, route binding, and complete outbound headers against
    /// `billable` and `prepared` before committing, returning a single-use [`TurnDispatch`] bound
    /// to `prepared`'s originating [`crate::provider_http::inference::Gateway`]. Any pre-commit or
    /// deferred OMQ04 failure rolls back `gateway_requests` to `'reserved'` so `release()` can
    /// immediately unwind the round.
    ///
    /// The round is authorized without a gateway binding, and the dispatch carries a bearer
    /// credential made for this handoff, independent of the dispatch secret (ADR 0044).
    pub async fn handoff<'a>(
        &self,
        pool: &PgPool,
        device_grant_id: Option<&str>,
        billable: &crate::provider_http::BillableInferenceRef<'_>,
        prepared: crate::provider_http::inference::PreparedRequest<'a>,
    ) -> Result<TurnDispatch<'a>, Error> {
        self.handoff_turn(pool, device_grant_id, billable, prepared)
            .await
            .map_err(|err| match err.0 {
                TurnHandoffError::MissingHold => Error::Refused,
                TurnHandoffError::Other(err) => err,
            })
    }

    pub(crate) async fn handoff_turn<'a>(
        &self,
        pool: &PgPool,
        device_grant_id: Option<&str>,
        billable: &crate::provider_http::BillableInferenceRef<'_>,
        prepared: crate::provider_http::inference::PreparedRequest<'a>,
    ) -> Result<
        TurnDispatch<'a>,
        Box<(
            TurnHandoffError,
            crate::provider_http::inference::PreparedRequest<'a>,
        )>,
    > {
        match self
            .handoff_turn_inner(pool, device_grant_id, billable, &prepared)
            .await
        {
            Ok(dispatch) => Ok(TurnDispatch::new(dispatch, prepared)),
            Err(err) => Err(Box::new((err, prepared))),
        }
    }

    async fn handoff_turn_inner(
        &self,
        pool: &PgPool,
        device_grant_id: Option<&str>,
        billable: &crate::provider_http::BillableInferenceRef<'_>,
        prepared: &crate::provider_http::inference::PreparedRequest<'_>,
    ) -> Result<Dispatch, TurnHandoffError> {
        if (self.requires_device_slot
            && device_grant_id.is_some_and(|g| !crate::runs::is_canonical_uuid(g)))
            || !prepared.is_server()
            || !round_fits(prepared, self.units)
            || prepared.round_cost() != self.round_cost
            || prepared.requires_device_slot() != self.requires_device_slot
        {
            return Err(TurnHandoffError::Other(Error::Refused));
        }
        let pending = self.as_pending();
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false)
            .await
            .map_err(|err| TurnHandoffError::Other(Error::from(err)))?;
        let prefix = sqlx::query(
            "SELECT openmettle.quota_lock_turn_handoff_prefix(
                 $1::uuid, $2::bytea, $3::uuid, $4::uuid, $5::uuid
             )",
        )
        .bind(&pending.id)
        .bind(pending.secret.as_slice())
        .bind(&self.scope_id)
        .bind(&self.run_id)
        .bind(&self.claim_token)
        .execute(
            tx.connection()
                .map_err(|err| TurnHandoffError::Other(Error::from(err)))?,
        )
        .await;
        if let Err(err) = prefix {
            let _ = tx.rollback().await;
            return Err(TurnHandoffError::Other(
                match err.as_database_error().and_then(|e| e.code()).as_deref() {
                    Some("42501") => Error::Refused,
                    _ => Error::from(err),
                },
            ));
        }
        let dispatch = match self.authorize_in(&mut tx).await {
            Ok(dispatch) => dispatch,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(TurnHandoffError::Other(err));
            }
        };
        if let Err(err) = validate_bound(billable, &dispatch, prepared) {
            let _ = tx.rollback().await;
            return Err(TurnHandoffError::Other(err));
        }
        let res = sqlx::query(
            "SELECT openmettle.quota_commit_turn_handoff(
                 $1::uuid, $2::bytea, $3::uuid, $4::uuid, $5::uuid, $6, $7::uuid, $8
             )",
        )
        .bind(&pending.id)
        .bind(pending.secret.as_slice())
        .bind(&self.scope_id)
        .bind(&self.run_id)
        .bind(&self.claim_token)
        .bind(self.requires_device_slot)
        .bind(device_grant_id)
        .bind(self.round_cost.is_none())
        .execute(
            tx.connection()
                .map_err(|err| TurnHandoffError::Other(Error::from(err)))?,
        )
        .await;
        if let Err(err) = res {
            let _ = tx.rollback().await;
            return Err(TurnHandoffError::Other(
                match err.as_database_error().and_then(|e| e.code()).as_deref() {
                    Some("42501" | "23505" | "OMQ04") => Error::Refused,
                    _ => Error::from(err),
                },
            ));
        }
        // A deferred `OMQ04` means a hold the round needs is missing. It is retryable when
        // enforcement or the first cost limit activated after the round was reserved.
        let missing_hold = || {
            let retryable = (!self.enforced_at_bind
                || (!self.cost_bound_at_bind && self.round_cost.is_some()))
                && (!self.requires_device_slot || device_grant_id.is_some());
            if retryable {
                TurnHandoffError::MissingHold
            } else {
                TurnHandoffError::Other(Error::Refused)
            }
        };
        // The last statement: it runs the deferred handoff checks, which can wait on quota
        // locks, and then reads the authority again on a new clock reading. Nothing that can
        // wait on a lock follows it, so no approval, lease or membership observation that
        // lapsed during a wait is committed (`openmettle.gateway_handoff_round_confirm`).
        let confirmed =
            sqlx::query("SELECT openmettle.gateway_handoff_round_confirm($1::uuid,$2,$3::uuid)")
                .bind(&pending.id)
                .bind(pending.secret.as_slice())
                .bind(&self.claim_token)
                .execute(
                    tx.connection()
                        .map_err(|err| TurnHandoffError::Other(Error::from(err)))?,
                )
                .await;
        if let Err(err) = confirmed {
            let _ = tx.rollback().await;
            return Err(
                match err.as_database_error().and_then(|e| e.code()).as_deref() {
                    Some("OMQ04") => missing_hold(),
                    Some("42501") => TurnHandoffError::Other(Error::Refused),
                    _ => TurnHandoffError::Other(Error::from(err)),
                },
            );
        }
        if let Err(err) = tx.commit().await {
            if let crate::runs::Error::Database(ref db) = err
                && db.as_database_error().and_then(|e| e.code()).as_deref() == Some("OMQ04")
            {
                return Err(missing_hold());
            }
            let mut recovery = WriteTransaction::begin_bounded_pool(pool, false)
                .await
                .map_err(|err| TurnHandoffError::Other(Error::from(err)))?;
            pending
                .recover_in(&mut recovery)
                .await
                .map_err(TurnHandoffError::Other)?;
            recovery
                .commit()
                .await
                .map_err(|err| TurnHandoffError::Other(Error::from(err)))?;
            return Err(TurnHandoffError::Other(Error::Database));
        }
        Ok(dispatch)
    }

    /// Recheck the round's authorization without a gateway binding and mark it handed off
    /// (`openmettle.gateway_handoff_round`, ADR 0044). The transaction must end with
    /// `openmettle.gateway_handoff_round_confirm`.
    ///
    /// The bearer the worker presents to the proxy is a new random value, independent of the
    /// dispatch secret. Only its SHA-256 is sent to the database, which stores it for the proxy
    /// to compare. The bearer itself is kept in the returned [`Dispatch`], is sent to the proxy
    /// over HTTP, and never crosses a database connection. The dispatch secret stays this
    /// caller's proof to the database and is never sent over HTTP.
    async fn authorize_in(&self, tx: &mut WriteTransaction<'_>) -> Result<Dispatch, Error> {
        let mut bearer = [0; 32];
        SystemRandom::new()
            .fill(&mut bearer)
            .map_err(|_| Error::Protection)?;
        // `id` is caller-visible; dispatch the database-canonical spelling so the wire
        // `x-request-id` always correlates with the stored request.
        let id: String = sqlx::query_scalar(
            "SELECT $1::uuid::text \
              WHERE openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid,$4)",
        )
        .bind(&self.id)
        .bind(self.secret.as_slice())
        .bind(&self.claim_token)
        .bind(Sha256::digest(bearer).as_slice())
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Refused)?;
        let mut authorization = hyper::header::HeaderValue::try_from(format!(
            "Bearer {}",
            URL_SAFE_NO_PAD.encode(bearer)
        ))
        .map_err(|_| Error::Protection)?;
        authorization.set_sensitive(true);
        Ok(Dispatch {
            id,
            installation: self.installation.clone(),
            model: self.model.clone(),
            server: true,
            authorization,
        })
    }
}

/// Reserve one leased worker turn round in a single write transaction: unwind any superseded
/// round hold, recover missing legacy/pre-PR3 gateway or quota parent holds (enforcing profile
/// `cost_bound` and `requires_device_slot`), insert the round `gateway_requests` row, and bind
/// its metered quota slice.
pub async fn reserve_turn_round(pool: &PgPool, round: TurnRound<'_>) -> Result<TurnPending, Error> {
    let round_cost_i64 = round.round_cost.and_then(|c| i64::try_from(c).ok());
    let round_cost_overflow = round.round_cost.is_some_and(|c| i64::try_from(c).is_err());
    for force_holds in [false, true] {
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
        let attempt: Result<Option<TurnPending>, Error> = async {
            sqlx::query("SELECT openmettle.quota_lock_run_actor_prefix($1::uuid, $2::uuid)")
                .bind(round.scope_id)
                .bind(round.run_id)
                .execute(tx.connection()?)
                .await?;
            sqlx::query(
                "SELECT openmettle.quota_unwind_superseded_round($1::uuid, $2::uuid, $3::uuid, $4)",
            )
            .bind(round.scope_id)
            .bind(round.run_id)
            .bind(round.claim_token)
            .bind(round.round)
            .execute(tx.connection()?)
            .await
            .map_err(map_stale_lease)?;
            let reservation_id: String = sqlx::query_scalar(
                "SELECT openmettle.quota_prepare_turn_round(
                     $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9
                 )::text",
            )
            .bind(round.scope_id)
            .bind(round.run_id)
            .bind(round.claim_token)
            .bind(round.round_tokens)
            .bind(round_cost_i64)
            .bind(round.round_cost.is_none())
            .bind(round_cost_overflow)
            .bind(round.requires_device_slot)
            .bind(force_holds)
            .fetch_one(tx.connection()?)
            .await
            .map_err(map_stale_lease)?;
            let call = Call {
                reservation: Reservation {
                    id: &reservation_id,
                    scope_id: round.scope_id,
                    actor: round.actor,
                    approval: round.approval,
                },
                installation: round.installation,
                model: round.model,
                units: round.round_tokens,
                authority: Authority::Lease {
                    run: round.run_id,
                    round: round.round,
                    token: round.claim_token,
                },
            };
            let pending = reserve_in(&mut tx, call).await?;
            match crate::quotas::bind_request(
                &mut tx,
                &pending.call,
                &pending.id,
                &pending.secret,
                crate::quotas::CostBoundSpec::Profile(round.round_cost),
                round.requires_device_slot,
            )
            .await?
            {
                crate::quotas::BindOutcome::NeedsParentHolds => Ok(None),
                crate::quotas::BindOutcome::Bound {
                    enforced_at_bind,
                    cost_bound_at_bind,
                    ..
                } => Ok(Some(TurnPending {
                    id: pending.id,
                    secret: pending.secret,
                    reservation_id,
                    scope_id: round.scope_id.to_owned(),
                    actor: round.actor.to_owned(),
                    approval: round.approval.to_owned(),
                    run_id: round.run_id.to_owned(),
                    round: round.round,
                    claim_token: round.claim_token.to_owned(),
                    installation: round.installation.to_owned(),
                    model: round.model.to_owned(),
                    units: round.round_tokens,
                    round_cost: round.round_cost,
                    requires_device_slot: round.requires_device_slot,
                    enforced_at_bind,
                    cost_bound_at_bind,
                })),
            }
        }
        .await;
        match attempt {
            Ok(None) => {
                tx.rollback().await?;
                if force_holds {
                    return Err(Error::Refused);
                }
            }
            Ok(Some(pending)) => {
                tx.commit().await?;
                return Ok(pending);
            }
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err);
            }
        }
    }
    Err(Error::Refused)
}

async fn reserve_in<'a>(
    tx: &mut WriteTransaction<'_>,
    call: Call<'a>,
) -> Result<Pending<'a>, Error> {
    if let Authority::Session { credential, .. } = call.authority {
        crate::sessions::well_formed(credential).map_err(|_| Error::Refused)?;
    }
    let mut secret = [0; 32];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| Error::Protection)?;
    let id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(tx.connection()?)
        .await?;
    let r = &call.reservation;
    let sql = match call.authority {
        Authority::Session { .. } => {
            hold(tx, r, None, call.units).await?;
            "INSERT INTO openmettle.gateway_requests (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,session_id)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7,$8,$9,$10)"
        }
        Authority::Lease { .. } =>
            "INSERT INTO openmettle.gateway_requests (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7,$8,$9,$10::uuid,$11)"
    };
    let q = sqlx::query(sql)
        .bind(&id)
        .bind(r.id)
        .bind(r.scope_id)
        .bind(r.actor)
        .bind(r.approval)
        .bind(call.installation)
        .bind(call.model)
        .bind(call.units)
        .bind(Sha256::digest(secret).to_vec());
    match call.authority {
        Authority::Session { credential, .. } => q.bind(&credential[..43]),
        Authority::Lease { run, round, .. } => q.bind(run).bind(round),
    }
    .execute(tx.connection()?)
    .await?;
    Ok(Pending {
        id,
        secret,
        call,
        explicit_cost: None,
        bound_cost: None,
    })
}
/// The prepared wire round equals the reserved token units and carries a positive output cap
/// within them, so the funded hold bounds what the provider may generate.
fn round_fits(prepared: &crate::provider_http::inference::PreparedRequest<'_>, units: i64) -> bool {
    prepared.round_tokens() == Some(units)
        && prepared
            .output_reserve()
            .is_some_and(|out| out > 0 && out <= units)
}

/// Validate the opened dispatch against the prepared route and outbound headers before commit.
fn validate_bound(
    billable: &crate::provider_http::BillableInferenceRef<'_>,
    dispatch: &Dispatch,
    prepared: &crate::provider_http::inference::PreparedRequest<'_>,
) -> Result<(), Error> {
    billable
        .validate_dispatch(dispatch, prepared)
        .map_err(|err| match err {
            crate::provider_http::inference::Error::Validation => Error::Refused,
            _ => Error::Protection,
        })
}

/// Single-use credential for the pinned inference client. The caller cannot construct it.
pub struct Dispatch {
    pub(crate) id: String,
    pub(crate) installation: String,
    pub(crate) model: String,
    pub(crate) server: bool,
    pub(crate) authorization: hyper::header::HeaderValue,
}
impl Pending<'_> {
    pub async fn release(&self, pool: &PgPool) -> Result<bool, Error> {
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
        let released = self.release_in(&mut tx).await?;
        tx.commit().await?;
        Ok(released)
    }
    async fn release_in(&self, tx: &mut WriteTransaction<'_>) -> Result<bool, Error> {
        if let Authority::Lease { run, .. } = self.call.authority {
            sqlx::query("SELECT FROM openmettle.runs WHERE id=$1::uuid FOR NO KEY UPDATE")
                .bind(run)
                .execute(tx.connection()?)
                .await?;
        }
        let released = sqlx::query_scalar("SELECT openmettle.gateway_release($1::uuid,$2)")
            .bind(&self.id)
            .bind(self.secret.as_slice())
            .fetch_one(tx.connection()?)
            .await?;
        if released {
            self.recover_in(tx).await?;
        }
        Ok(released)
    }
    /// Commit the gateway handoff and quota holds only after `prepared` is proven to fit them:
    /// the request mode matches the authority, the wire round equals the reserved units with a
    /// positive output cap inside it, a caller session never needs a device slot, and the round
    /// cost matches the explicit ceiling or fits the cost hold bound at reservation. The route
    /// binding and complete outbound headers are validated inside the transaction; cost-unqualified
    /// and device-slot requests are marked so the deferred `enforce_gateway_handoff_holds` trigger
    /// raises `OMQ04` when a cost limit or required device hold is missing at commit. Every refusal
    /// rolls back and leaves the request `reserved` for [`Self::release`]. Returns a single-use
    /// [`BillableDispatch`] bound to `prepared`'s originating gateway: `Server` for a lease,
    /// `Caller` for a session. Markers carry the database-canonical request id so a rewritten
    /// spelling of [`Self::id`] cannot evade the trigger.
    pub async fn handoff<'p>(
        &self,
        pool: &PgPool,
        keys: &GatewayKeys,
        billable: &crate::provider_http::BillableInferenceRef<'_>,
        prepared: crate::provider_http::inference::PreparedRequest<'p>,
    ) -> Result<BillableDispatch<'p>, Error> {
        let server = matches!(self.call.authority, Authority::Lease { .. });
        let cost_ok = match (self.explicit_cost, self.bound_cost, prepared.round_cost()) {
            (Some(explicit), _, cost) => cost == Some(explicit),
            (None, Some(held), cost) => cost.is_some_and(|c| c > 0 && c <= held),
            (None, None, _) => true,
        };
        if prepared.is_server() != server
            || !round_fits(&prepared, self.call.units)
            || (!server && prepared.requires_device_slot())
            || !cost_ok
        {
            return Err(Error::Refused);
        }
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
        let res = async {
            let dispatch = self.handoff_in(&mut tx, keys).await?;
            validate_bound(billable, &dispatch, &prepared)?;
            for (setting, mark) in [
                (
                    "openmettle.turn_cost_unqualified_requests",
                    prepared.round_cost().is_none(),
                ),
                (
                    "openmettle.turn_device_required_requests",
                    prepared.requires_device_slot(),
                ),
            ] {
                if mark {
                    sqlx::query(
                        "SELECT set_config($1, coalesce(current_setting($1, true), '') || ',' || $2::uuid::text || ',', true)",
                    )
                    .bind(setting)
                    .bind(&self.id)
                    .execute(tx.connection()?)
                    .await?;
                }
            }
            sqlx::query("SELECT openmettle.quota_commit_handoff($1::uuid,$2::bytea)")
                .bind(&self.id)
                .bind(self.secret.as_slice())
                .execute(tx.connection()?)
                .await?;
            Ok::<_, Error>(dispatch)
        }
        .await;
        let dispatch = match res {
            Ok(dispatch) => dispatch,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err);
            }
        };
        if let Err(err) = tx.commit().await {
            if let crate::runs::Error::Database(ref db) = err
                && db.as_database_error().and_then(|e| e.code()).as_deref() == Some("OMQ04")
            {
                return Err(Error::Refused);
            }
            let mut recovery = WriteTransaction::begin_bounded_pool(pool, false).await?;
            self.recover_in(&mut recovery).await?;
            recovery.commit().await?;
            return Err(Error::Database);
        }
        Ok(BillableDispatch::new(dispatch, prepared))
    }
    async fn recover_in(&self, tx: &mut WriteTransaction<'_>) -> Result<String, Error> {
        let run = match self.call.authority {
            Authority::Lease { run, .. } => Some(run),
            _ => None,
        };
        Ok(sqlx::query_scalar(
            "SELECT openmettle.quota_recover_lost_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)",
        )
        .bind(&self.id)
        .bind(self.secret.as_slice())
        .bind(self.call.reservation.scope_id)
        .bind(self.call.reservation.actor)
        .bind(run)
        .fetch_one(tx.connection()?)
        .await?)
    }
    async fn handoff_in(
        &self,
        tx: &mut WriteTransaction<'_>,
        keys: &GatewayKeys,
    ) -> Result<Dispatch, Error> {
        let (proof, audience, lease) = match self.call.authority {
            Authority::Session {
                credential,
                native_audience,
            } => (
                Some(SharedSecret::from(
                    URL_SAFE_NO_PAD
                        .decode(&credential[44..])
                        .map_err(|_| Error::Refused)?,
                )),
                native_audience,
                None,
            ),
            Authority::Lease { token, .. } => (None, None, Some(token)),
        };
        // `id` is caller-visible; dispatch the database-canonical spelling so the wire
        // `x-request-id` always correlates with gateway usage reports.
        let row = sqlx::query(
            "SELECT h.*,$1::uuid::text AS request \
             FROM openmettle.gateway_handoff($1::uuid,$2,$3,$4,$5::uuid) h",
        )
        .bind(&self.id)
        .bind(self.secret.as_slice())
        .bind(proof.as_ref().map(SharedSecret::secret_bytes))
        .bind(audience.map(|a| a.as_slice()))
        .bind(lease)
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Refused)?;
        let ctx = Context {
            installation: row.try_get("installation")?,
            user_id: row.try_get("actor")?,
            binding_id: row.try_get("binding")?,
            principal: row.try_get("principal")?,
            generation: row.try_get("generation")?,
        };
        let envelope = Envelope {
            key_id: row.try_get("key_id")?,
            nonce: row
                .try_get::<&[u8], _>("nonce")?
                .try_into()
                .map_err(|_| Error::Protection)?,
            ciphertext: row.try_get("ciphertext")?,
        };
        let authorization = keys
            .open(&ctx, &envelope)
            .map_err(|_| Error::Protection)?
            .authorization();
        Ok(Dispatch {
            id: row.try_get("request")?,
            installation: self.call.installation.into(),
            model: self.call.model.into(),
            server: lease.is_some(),
            authorization,
        })
    }
}

/// Coalesce a logical mutation under its immutable parameters. A conflict cannot
/// replace the original operation ID. Read after INSERT in a fresh statement snapshot.
pub struct Intent<'a> {
    pub binding: &'a str,
    pub revision: i64,
    pub generation: i64,
    pub action: &'a str,
    pub expected_revision: i64,
    pub parameters: &'a serde_json::Value,
}
pub async fn intent(pool: &PgPool, i: &Intent<'_>) -> Result<String, Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT desired_revision FROM openmettle.gateway_bindings WHERE id=$1::uuid FOR SHARE",
    )
    .bind(i.binding)
    .fetch_optional(tx.connection()?)
    .await?;
    if current != Some(i.revision) {
        return Err(Error::Conflict);
    }
    let params = i.parameters.to_string();
    sqlx::query("INSERT INTO openmettle.gateway_intents (binding_id,desired_revision,generation,action,expected_revision,parameters)
        VALUES ($1::uuid,$2,$3,$4,$5,$6::jsonb) ON CONFLICT DO NOTHING")
        .bind(i.binding)
        .bind(i.revision)
        .bind(i.generation)
        .bind(i.action)
        .bind(i.expected_revision)
        .bind(&params)
        .execute(tx.connection()?)
        .await?;
    let id = sqlx::query_scalar("SELECT operation_id::text FROM openmettle.gateway_intents WHERE
        binding_id=$1::uuid AND desired_revision=$2 AND generation=$3 AND action=$4 AND expected_revision=$5 AND parameters=$6::jsonb")
        .bind(i.binding)
        .bind(i.revision)
        .bind(i.generation)
        .bind(i.action)
        .bind(i.expected_revision)
        .bind(params)
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Conflict)?;
    tx.commit().await?;
    Ok(id)
}

/// Publish a confirmed issue/rotation only for the live claim, revision and predecessor.
/// A delayed observation belongs in the intent audit even if this guard refuses it.
pub async fn publish_generation(
    pool: &PgPool,
    binding: &str,
    operation: &str,
    claim: &str,
    previous: Option<i64>,
) -> Result<bool, Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    sqlx::query("SELECT id FROM openmettle.gateway_bindings WHERE id=$1::uuid FOR UPDATE")
        .bind(binding)
        .execute(tx.connection()?)
        .await?;
    let row = sqlx::query("SELECT generation,desired_revision FROM openmettle.gateway_intents WHERE binding_id=$1::uuid
        AND operation_id=$2::uuid AND claim=$3::uuid AND due_at>clock_timestamp() AND NOT complete AND action IN ('issue','rotate') AND NOT (parameters ? 'signature') FOR UPDATE")
        .bind(binding)
        .bind(operation)
        .bind(claim)
        .fetch_optional(tx.connection()?)
        .await?;
    let Some(row) = row else { return Ok(false) };
    let generation: i64 = row.try_get(0)?;
    let changed = sqlx::query("UPDATE openmettle.gateway_bindings b SET state='ready',observed_revision=desired_revision,
        active_generation=$2 WHERE id=$1::uuid AND desired_revision=$3 AND active_generation IS NOT DISTINCT FROM $4::bigint
        AND $2>coalesce(active_generation,0) AND state IN ('provisioning','ready')
        AND EXISTS (SELECT FROM openmettle.gateway_generations e JOIN openmettle.gateway_audit a
                ON a.binding_id=e.binding_id AND a.remote_handle=e.remote_key
                WHERE e.binding_id=b.id AND e.generation=$2 AND e.expires_at>clock_timestamp()
                  AND a.operation_id=$5::uuid AND a.step='key' AND a.outcome='confirmed')")
        .bind(binding)
        .bind(generation)
        .bind(row.try_get::<i64, _>(1)?)
        .bind(previous)
        .bind(operation)
        .execute(tx.connection()?)
        .await?
        .rows_affected() == 1;
    if changed {
        sqlx::query(
            "UPDATE openmettle.gateway_intents SET complete=true,claim=NULL WHERE operation_id=$1::uuid",
        )
        .bind(operation)
        .execute(tx.connection()?)
        .await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// Fixed caller-facing classification shared by preflight and the pinned inference decoder.
pub use crate::provider_http::gateway::problem;
pub mod family;
pub mod reconcile;
pub mod settlement;
