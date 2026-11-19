//! A bounded, single-use delivery of a local session already issued from a managed proof.
use super::{Credential, Error, Validation};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};

/// Longest life of a handoff code, counted from the final primary-clock read of its issuing
/// transaction (ADR 0023).
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

/// One primary-clock read, paired with the monotonic sample taken before its query was sent.
#[derive(Clone, Copy)]
pub(super) struct Sample {
    pub(super) at: tokio::time::Instant,
    pub(super) ms: i64,
}

/// The two lifetimes of one handoff: the stored grant expiry in primary milliseconds, and the
/// monotonic deadline for releasing its code from the issuing process.
pub(super) struct Window {
    pub(super) until: i64,
    pub(super) release_by: tokio::time::Instant,
}

/// The lifetime rule of ADR 0023.
///
/// The stored expiry is what the app redeems against, on any replica. It is the earliest of
/// the login expiry, the session expiry and `last` plus the smaller of `MAX_LIFETIME` and
/// `assertion`, the remaining age of the ID token. `proof_deadline` is deliberately not a
/// term: key freshness, the provider HTTP deadline and the session operation deadline bound
/// the work of the issuing process, not the grant. The app needs its window for the
/// redirect, the operating system's link delivery, its own launch and the token request.
///
/// The release deadline applies to the issuing process only. It converts the stored expiry
/// to the monotonic clock from both paired samples, so a lock wait, a rollback or wall-clock
/// skew after a sample cannot extend it, and it never passes `proof_deadline`.
///
/// `None` when the grant would already be spent at `last`.
pub(super) fn window(
    issued: Sample,
    last: Sample,
    login_expiry: i64,
    session_expiry: i64,
    assertion: std::time::Duration,
    proof_deadline: tokio::time::Instant,
) -> Option<Window> {
    let budget = assertion.min(MAX_LIFETIME).as_millis() as i64;
    let until = login_expiry
        .min(session_expiry)
        .min(last.ms.saturating_add(budget));
    if until <= last.ms {
        return None;
    }
    let release_by = primary_deadline(issued.at, until.saturating_sub(issued.ms))
        .min(primary_deadline(last.at, until - last.ms))
        .min(proof_deadline);
    Some(Window { until, release_by })
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
    /// The authoritative deadline check, and the only way to the code. Call immediately
    /// before the code leaves the process. No await may follow.
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

    // A synthetic primary time, and an issuing transaction whose two clock reads are 40 ms
    // apart on both clocks.
    const T: i64 = 1_800_000_000_000;
    fn reads(now: Instant) -> (Sample, Sample) {
        let issued = Sample { at: now, ms: T };
        let last = Sample {
            at: now + Duration::from_millis(40),
            ms: T + 40,
        };
        (issued, last)
    }
    fn held(by: Instant) -> Release {
        Release {
            code: "synthetic-handoff-code".into(),
            by,
        }
    }

    #[test]
    fn stored_grant_has_exactly_four_clips_and_the_process_deadline_is_not_one() {
        let now = Instant::now();
        let (issued, last) = reads(now);
        let far = now + Duration::from_secs(3600);
        let (login, session, age) = (T + 300_000, T + 60_000, Duration::from_secs(290));
        // 3.5 s left of a 5 s provider deadline after a slow exchange, one second of key
        // reuse, and a process deadline that is already spent: the app still gets 30 s.
        for process in [3500, 1000, 0] {
            let proof_deadline = now + Duration::from_millis(process);
            let w = window(issued, last, login, session, age, proof_deadline).unwrap();
            assert_eq!(w.until, T + 40 + 30_000, "{process}");
            assert_eq!(w.release_by, proof_deadline, "{process}");
        }
        // Each remaining term clips on its own. A sub-millisecond remainder is discarded.
        for (login, session, age, until) in [
            (login, session, age, T + 30_040),
            (T + 10_040, session, age, T + 10_040),
            (login, T + 5_040, age, T + 5_040),
            (login, session, Duration::from_secs(2), T + 2_040),
            (login, session, Duration::from_micros(2_000_900), T + 2_040),
        ] {
            let w = window(issued, last, login, session, age, far).unwrap();
            assert_eq!(w.until, until);
            // Both samples agree here, and one millisecond is discarded.
            assert_eq!(
                w.release_by,
                now + Duration::from_millis((until - T - 1) as u64)
            );
        }
        // Nothing is stored for a grant that is already spent at the final read.
        for (login, session, age) in [
            (T + 40, session, age),
            (login, T + 40, age),
            (login, session, Duration::ZERO),
            (login, session, Duration::from_micros(999)),
        ] {
            assert!(window(issued, last, login, session, age, far).is_none());
        }
    }

    #[test]
    fn release_deadline_takes_the_earlier_sample_and_never_passes_the_process_deadline() {
        let now = Instant::now();
        let (issued, last) = reads(now);
        let far = now + Duration::from_secs(3600);
        let (login, session, age) = (T + 300_000, T + 60_000, Duration::from_secs(290));
        // The first read's reply waited 200 ms, so its sample is the earlier bound.
        let slow_first = Sample {
            at: now,
            ms: T + 200,
        };
        let later = Sample {
            at: now + Duration::from_millis(240),
            ms: T + 240,
        };
        let w = window(slow_first, later, login, session, age, far).unwrap();
        assert_eq!(w.until, T + 30_240);
        assert_eq!(w.release_by, now + Duration::from_millis(30_039));
        // The final read's reply waited instead: its sample is the earlier bound.
        let slow_last = Sample {
            at: now + Duration::from_millis(40),
            ms: T + 500,
        };
        let w = window(issued, slow_last, login, session, age, far).unwrap();
        assert_eq!(w.until, T + 30_500);
        assert_eq!(w.release_by, now + Duration::from_millis(30_039));
        // The process deadline is earlier than both and leaves the stored grant alone. A
        // code held to it is not released, although the app's window has 30 s left.
        let w = window(issued, last, login, session, age, now).unwrap();
        assert_eq!((w.until, w.release_by), (T + 30_040, now));
        assert!(held(w.release_by).release().is_none());
    }

    #[test]
    fn issuance_refuses_a_code_that_is_past_its_release_deadline() {
        use super::super::Delivery;
        let settle = |code| Delivery::settled(Credential("synthetic-bearer".into()), code);
        let now = Instant::now();
        let live = settle(Some(held(now + Duration::from_secs(60))));
        assert!(matches!(live, Ok(Delivery::NativeCode(_))));
        // The deadline itself is already too late.
        assert!(matches!(settle(Some(held(now))), Err(Error::Rejected)));
        assert!(matches!(settle(None), Ok(Delivery::Browser(_))));
    }

    #[test]
    fn code_is_released_only_before_its_deadline() {
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
