//! Gateway reservation, credential handoff and reconciliation store (ADR 0037).
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
    Protection,
    Conflict,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database => "gateway store unavailable",
            Self::Refused => "gateway request refused",
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
            _ => Self::Database,
        }
    }
}
impl From<crate::runs::Error> for Error {
    fn from(_: crate::runs::Error) -> Self {
        Self::Database
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
        let cost = crate::quotas::cost_ceiling(tx, r, None, cost_ceiling).await?;
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
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    crate::quotas::prepare_round(&mut tx, &call).await?;
    let pending = reserve_in(&mut tx, call).await?;
    crate::quotas::bind_request(
        &mut tx,
        &pending.call,
        &pending.id,
        &pending.secret,
        cost_ceiling,
    )
    .await?;
    tx.commit().await?;
    Ok(pending)
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
    pub round_cost: Option<i64>,
    pub requires_device_slot: bool,
}

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
        }
    }

    pub async fn release(&self, pool: &PgPool) -> Result<bool, Error> {
        self.as_pending().release(pool).await
    }

    pub async fn handoff(&self, pool: &PgPool, keys: &GatewayKeys) -> Result<Dispatch, Error> {
        self.as_pending().handoff(pool, keys).await
    }
}

/// Reserve one leased worker turn round in a single write transaction: unwind any superseded
/// round hold, recover missing legacy/pre-PR3 gateway or quota parent holds (enforcing profile
/// `cost_bound` and `requires_device_slot`), insert the round `gateway_requests` row, and bind
/// its metered quota slice.
pub async fn reserve_turn_round(pool: &PgPool, round: TurnRound<'_>) -> Result<TurnPending, Error> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    sqlx::query(
        "SELECT openmettle.quota_unwind_superseded_round($1::uuid, $2::uuid, $3::uuid, $4)",
    )
    .bind(round.scope_id)
    .bind(round.run_id)
    .bind(round.claim_token)
    .bind(round.round)
    .execute(tx.connection()?)
    .await?;
    let reservation_id: String = sqlx::query_scalar(
        "SELECT openmettle.quota_ensure_legacy_run_holds(
             $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7
         )::text",
    )
    .bind(round.scope_id)
    .bind(round.run_id)
    .bind(round.claim_token)
    .bind(round.round_tokens)
    .bind(round.round_cost)
    .bind(round.round_cost.is_none())
    .bind(round.requires_device_slot)
    .fetch_one(tx.connection()?)
    .await?;
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
    crate::quotas::bind_request(
        &mut tx,
        &pending.call,
        &pending.id,
        &pending.secret,
        round.round_cost,
    )
    .await?;
    let id = pending.id;
    let secret = pending.secret;
    tx.commit().await?;
    Ok(TurnPending {
        id,
        secret,
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
    })
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
    Ok(Pending { id, secret, call })
}
/// Single-use credential for the pinned inference client. The caller cannot construct it.
pub struct Dispatch {
    pub(crate) id: String,
    pub(crate) installation: String,
    pub(crate) model: String,
    pub(crate) server: bool,
    pub(crate) authorization: hyper::header::HeaderValue,
}
impl Dispatch {
    /// Returns the sensitive `Authorization` header only when this handoff matches `server` and
    /// `model`, preserving binding between reservation handoff and inference dispatch.
    pub fn authorization_for(
        &self,
        server: bool,
        model: &str,
    ) -> Option<hyper::header::HeaderValue> {
        (self.server == server && self.model == model).then(|| self.authorization.clone())
    }
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
    pub async fn handoff(&self, pool: &PgPool, keys: &GatewayKeys) -> Result<Dispatch, Error> {
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
        let dispatch = self.handoff_in(&mut tx, keys).await?;
        sqlx::query("SELECT openmettle.quota_commit_handoff($1::uuid,$2::bytea)")
            .bind(&self.id)
            .bind(self.secret.as_slice())
            .execute(tx.connection()?)
            .await?;
        if tx.commit().await.is_err() {
            let mut recovery = WriteTransaction::begin_bounded_pool(pool, false).await?;
            self.recover_in(&mut recovery).await?;
            recovery.commit().await?;
            return Err(Error::Database);
        }
        Ok(dispatch)
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
        let row =
            sqlx::query("SELECT * FROM openmettle.gateway_handoff($1::uuid,$2,$3,$4,$5::uuid)")
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
            id: self.id.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn dispatch_authorization_checks_server_and_model() {
        let mut auth = HeaderValue::from_static("Bearer handed-off");
        auth.set_sensitive(true);
        let dispatch = Dispatch {
            id: "00000000-0000-4000-8000-000000000001".into(),
            installation: "00000000-0000-4000-8000-000000000002".into(),
            model: "a".into(),
            server: true,
            authorization: auth,
        };
        assert_eq!(
            dispatch.authorization_for(true, "a").as_ref(),
            Some(&HeaderValue::from_static("Bearer handed-off"))
        );
        assert!(dispatch.authorization_for(false, "a").is_none());
        assert!(dispatch.authorization_for(true, "b").is_none());
    }
}
