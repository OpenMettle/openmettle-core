//! A bounded, single-use delivery of a local session already issued from a managed proof.
use super::{Credential, Error, Validation};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

pub(super) const MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) struct Attempt {
    pub(crate) callback: String,
    pub(crate) binding: [u8; 32],
    pub(crate) registration: [u8; 32],
    pub(crate) audience: [u8; 32],
    pub(crate) challenge: [u8; 32],
}
fn cipher(code: &[u8; 32]) -> Result<aead::LessSafeKey, Error> {
    Ok(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, code).map_err(|_| Error::Rejected)?,
    ))
}
impl Attempt {
    pub(crate) async fn store(
        &self,
        c: &mut PgConnection,
        session: &str,
        bearer: &Credential,
        expiry: i64,
    ) -> Result<String, Error> {
        // A fresh 256-bit key seals exactly one credential, inside its issuing transaction.
        // Only the code holder has the key. Only the API database holds the ciphertext.
        let mut code = [0; 32];
        SystemRandom::new()
            .fill(&mut code)
            .map_err(|_| Error::Random)?;
        let mut sealed = bearer.expose().as_bytes().to_vec();
        cipher(&code)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(session.as_bytes()),
                &mut sealed,
            )
            .map_err(|_| Error::Rejected)?;
        // `registration` fences the pending code to the exact configuration. `audience` names
        // the downstream registration that the delivered bearer belongs to.
        sqlx::query("INSERT INTO openmettle.native_handoffs(session_id,code_hash,registration,audience,challenge,sealed,expires_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(session).bind(Sha256::digest(code).as_slice()).bind(self.registration.as_slice())
            .bind(self.audience.as_slice()).bind(self.challenge.as_slice()).bind(sealed).bind(expiry)
            .execute(c).await?;
        Ok(B64.encode(code))
    }
}

async fn claim(
    registration: &[u8; 32],
    db: &mut PgConnection,
    code: &[u8; 32],
    challenge: &[u8],
) -> Result<(Credential, tokio::time::Instant), Error> {
    let mut tx = super::transaction(db).await?;
    let result = async {
        let start = tokio::time::Instant::now();
        let row = sqlx::query(
            "SELECT session_id, sealed,
                    expires_ms - floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS remaining
             FROM openmettle.native_handoffs
             WHERE code_hash=$1 AND challenge=$2 AND registration=$3
               AND sealed IS NOT NULL
             FOR UPDATE"
        )
        .bind(Sha256::digest(code).as_slice())
        .bind(challenge)
        .bind(registration.as_slice())
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Rejected)?;
        let id: String = row.try_get("session_id")?;
        let mut sealed: Vec<u8> = row.try_get("sealed")?;
        let remaining: i64 = row.try_get("remaining")?;
        let deadline = start + std::time::Duration::from_millis(remaining.clamp(0, MAX_LIFETIME.as_millis() as i64) as u64);
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Rejected);
        }
        let plain = cipher(code)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(id.as_bytes()),
                &mut sealed,
            )
            .map_err(|_| Error::Rejected)?;
        let bearer = Credential(String::from_utf8(plain.to_vec()).map_err(|_| Error::Rejected)?);
        // Erase the envelope before release. An unknown commit requires a new login.
        sqlx::query("UPDATE openmettle.native_handoffs SET sealed=NULL WHERE session_id=$1")
            .bind(id)
            .execute(tx.connection()?)
            .await?;
        Ok((bearer, deadline))
    }.await;
    super::finish(tx, result).await
}

/// The only success path out of the claim transaction revalidates on the primary after commit.
pub(crate) async fn redeem(
    db: &mut PgConnection,
    code: &[u8; 32],
    registration: &[u8; 32],
    challenge: &[u8],
) -> Result<Credential, Error> {
    let (bearer, deadline) = claim(registration, db, code, challenge).await?;
    super::validate_inner(db, bearer.expose(), Validation::NativeExchange).await?;
    if tokio::time::Instant::now() >= deadline {
        return Err(Error::Rejected);
    }
    Ok(bearer)
}
