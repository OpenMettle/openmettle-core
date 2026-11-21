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
    fn from(_: sqlx::Error) -> Self {
        Self::Database
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
    if let Authority::Session { credential, .. } = call.authority {
        crate::sessions::well_formed(credential).map_err(|_| Error::Refused)?;
    }
    let mut secret = [0; 32];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| Error::Protection)?;
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(tx.connection()?)
        .await?;
    let r = &call.reservation;
    let sql = match call.authority {
        Authority::Session { .. } => {
            hold(&mut tx, r, None, call.units).await?;
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
    tx.commit().await?;
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
impl Pending<'_> {
    pub async fn release(&self, pool: &PgPool) -> Result<bool, Error> {
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
        let released = sqlx::query_scalar("SELECT openmettle.gateway_release($1::uuid,$2)")
            .bind(&self.id)
            .bind(self.secret.as_slice())
            .fetch_one(tx.connection()?)
            .await?;
        tx.commit().await?;
        Ok(released)
    }
    pub async fn handoff(&self, pool: &PgPool, keys: &GatewayKeys) -> Result<Dispatch, Error> {
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
        let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
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
        tx.commit().await?;
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
        AND operation_id=$2::uuid AND claim=$3::uuid AND due_at>clock_timestamp() AND NOT complete AND action IN ('issue','rotate') FOR UPDATE")
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
