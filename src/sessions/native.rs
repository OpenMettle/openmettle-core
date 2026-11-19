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

/// Converts a primary-clock remainder to the monotonic clock. `sample` is taken before the
/// clock query is sent, and the query floors to a millisecond, so one millisecond is
/// discarded. Primary time cannot reach the stored expiry before the returned instant
/// unless the primary clock runs faster than the local monotonic clock.
pub(super) fn primary_deadline(
    sample: tokio::time::Instant,
    remaining_ms: i64,
) -> tokio::time::Instant {
    sample + std::time::Duration::from_millis(remaining_ms.saturating_sub(1).max(0) as u64)
}

/// A handoff code with its conservative monotonic release deadline. The code is available
/// only through `release`, which refuses once the deadline has passed. No `Debug`.
pub(crate) struct Release {
    code: String,
    by: tokio::time::Instant,
}
impl Release {
    pub(super) fn live(&self) -> bool {
        tokio::time::Instant::now() < self.by
    }
    /// Call immediately before the code leaves the process. No await may follow.
    pub(crate) fn release(self) -> Option<String> {
        self.live().then_some(self.code)
    }
}

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
        release_by: tokio::time::Instant,
    ) -> Result<Release, Error> {
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
        // `registration` fences the pending code to the exact configuration. `audience` stays
        // with the delivered bearer for validation and logout.
        sqlx::query("INSERT INTO openmettle.native_handoffs(session_id,code_hash,registration,audience,challenge,sealed,expires_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(session).bind(Sha256::digest(code).as_slice()).bind(self.registration.as_slice())
            .bind(self.audience.as_slice()).bind(self.challenge.as_slice()).bind(sealed).bind(expiry)
            .execute(c).await?;
        Ok(Release {
            code: B64.encode(code),
            by: release_by,
        })
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
        // Sampled before the query is sent. The clock in the target list can be read before
        // a row-lock wait, so the wait is charged to the grant, never added to it.
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
        let deadline = primary_deadline(start, remaining.min(MAX_LIFETIME.as_millis() as i64));
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
    audience: &[u8; 32],
    challenge: &[u8],
) -> Result<Credential, Error> {
    let (bearer, deadline) = claim(registration, db, code, challenge).await?;
    super::validate_inner(db, bearer.expose(), Validation::NativeExchange(*audience)).await?;
    if tokio::time::Instant::now() >= deadline {
        return Err(Error::Rejected);
    }
    Ok(bearer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn primary_remainder_converts_to_a_conservative_monotonic_deadline() {
        let sample = Instant::now();
        // One millisecond is discarded for the floored primary clock, and nothing is added
        // for a remainder that is already spent.
        for (remaining_ms, after) in [
            (i64::MIN, 0),
            (-5, 0),
            (0, 0),
            (1, 0),
            (2, 1),
            (30_000, 29_999),
        ] {
            assert_eq!(
                primary_deadline(sample, remaining_ms),
                sample + Duration::from_millis(after),
                "{remaining_ms}"
            );
        }
    }

    #[test]
    fn code_is_released_only_before_its_deadline() {
        let held = |by| Release {
            code: "synthetic-handoff-code".into(),
            by,
        };
        let now = Instant::now();
        let live = held(now + Duration::from_secs(60));
        assert!(live.live());
        assert_eq!(live.release().as_deref(), Some("synthetic-handoff-code"));
        // The deadline itself is already too late.
        let late = held(now);
        assert!(!late.live());
        assert!(late.release().is_none());
    }
}
