//! Offline OIDC ID-token verification (ADR 0008, first V1-04 increment).
//!
//! Untrusted ID-token bytes are verified against explicitly trusted provider inputs. Every
//! signature, JOSE-header, issuer, audience, expiry and nonce check uses `openidconnect`; this
//! module adds the checks that library leaves to the relying party (`azp`, multiple audiences,
//! `iat` age and future skew, `nbf`) and bounds the inputs. It performs no network I/O,
//! discovery, key refresh, state/PKCE handling, account lookup or admission. A verified identity
//! proves only that a trusted provider asserted this issuer/subject pair for this client and nonce;
//! it is not authentication of a session, an admission decision or an access grant.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use openidconnect::{
    AdditionalClaims, ClaimsVerificationError, ClientId, IdToken, IssuerUrl, Nonce,
    SignatureVerificationError,
    core::{
        CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

/// Maximum accepted compact ID-token length in bytes.
pub const MAX_ID_TOKEN_BYTES: usize = 16 * 1024;
/// Maximum trusted JWKS document length in bytes.
pub const MAX_JWKS_BYTES: usize = 64 * 1024;
/// Maximum number of usable keys in a trusted JWKS.
pub const MAX_JWKS_KEYS: usize = 16;
/// Issuer bound, matching `user_identities.issuer`.
pub const MAX_ISSUER_BYTES: usize = 2048;
/// Subject bound, matching `user_identities.subject` and OIDC Core's 255 ASCII characters.
pub const MAX_SUBJECT_BYTES: usize = 255;
/// Client-identifier bound.
pub const MAX_CLIENT_ID_BYTES: usize = 255;
/// Expected-nonce bounds: at least 22 characters (128 bits of base64url) up to 512.
pub const MIN_NONCE_BYTES: usize = 22;
pub const MAX_NONCE_BYTES: usize = 512;
/// Upper bounds for [`Policy`] durations.
pub const MAX_ISSUED_AT_AGE: Duration = Duration::from_secs(3600);
pub const MAX_FUTURE_SKEW: Duration = Duration::from_secs(300);

/// Invalid trusted configuration or policy. Carries no configuration values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    ProviderConfigId,
    Issuer,
    ClientId,
    Jwks,
    Nonce,
    Policy,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProviderConfigId => "invalid provider configuration identifier",
            Self::Issuer => "invalid trusted issuer",
            Self::ClientId => "invalid trusted client identifier",
            Self::Jwks => "invalid trusted key set",
            Self::Nonce => "invalid expected nonce",
            Self::Policy => "invalid verification policy",
        })
    }
}

impl std::error::Error for ConfigError {}

/// Fixed verification failure categories. No variant carries token, claim, key or library text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Empty, oversized or structurally invalid token or claims.
    Malformed,
    /// Encrypted, nested or otherwise unsupported token form.
    Unsupported,
    /// Algorithm outside the allowlist, including `none` and HMAC.
    DisallowedAlgorithm,
    /// No trusted key, or several, matches the token's key identifier and algorithm.
    UnknownKey,
    /// The signature does not verify with the selected trusted key.
    InvalidSignature,
    Issuer,
    Audience,
    AuthorizedParty,
    Nonce,
    Expired,
    IssuedInFuture,
    IssuedTooLongAgo,
    NotYetValid,
    /// Subject missing from bounds accepted by persistence.
    Subject,
    /// The trusted clock is outside the representable range.
    Clock,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "ID token is malformed",
            Self::Unsupported => "ID token form is unsupported",
            Self::DisallowedAlgorithm => "ID token algorithm is not allowed",
            Self::UnknownKey => "no unique trusted key matches the ID token",
            Self::InvalidSignature => "ID token signature is invalid",
            Self::Issuer => "ID token issuer does not match",
            Self::Audience => "ID token audience does not match",
            Self::AuthorizedParty => "ID token authorized party does not match",
            Self::Nonce => "ID token nonce does not match",
            Self::Expired => "ID token has expired",
            Self::IssuedInFuture => "ID token issue time is in the future",
            Self::IssuedTooLongAgo => "ID token issue time is too old",
            Self::NotYetValid => "ID token is not yet valid",
            Self::Subject => "ID token subject is invalid",
            Self::Clock => "trusted clock is out of range",
        })
    }
}

impl std::error::Error for VerifyError {}

/// Implementation policy for issue-time checks. These are not owner-approved product values.
/// Expiry is always enforced strictly against the trusted clock, without leeway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    max_issued_at_age: Duration,
    future_skew: Duration,
}

impl Policy {
    /// `max_issued_at_age` in 1 s..=1 h; `future_skew` in 0..=5 min and below the age.
    pub fn new(max_issued_at_age: Duration, future_skew: Duration) -> Result<Self, ConfigError> {
        if max_issued_at_age < Duration::from_secs(1)
            || max_issued_at_age > MAX_ISSUED_AT_AGE
            || future_skew > MAX_FUTURE_SKEW
            || future_skew >= max_issued_at_age
        {
            return Err(ConfigError::Policy);
        }
        Ok(Self {
            max_issued_at_age,
            future_skew,
        })
    }
}

impl Default for Policy {
    /// Five minutes' issue-time age and 60 s future skew.
    fn default() -> Self {
        Self {
            max_issued_at_age: Duration::from_secs(300),
            future_skew: Duration::from_secs(60),
        }
    }
}

/// Validated deployment identity, independent of fetched signing keys.
#[derive(Clone)]
pub struct ProviderIdentity {
    provider_config_id: String,
    issuer: IssuerUrl,
    client_id: ClientId,
}
impl fmt::Debug for ProviderIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderIdentity(..)")
    }
}
impl ProviderIdentity {
    pub fn new(id: &str, issuer: &str, client: &str) -> Result<Self, ConfigError> {
        if !canonical_uuid(id) {
            return Err(ConfigError::ProviderConfigId);
        }
        let issuer = trusted_issuer(issuer).ok_or(ConfigError::Issuer)?;
        if client.is_empty()
            || client.len() > MAX_CLIENT_ID_BYTES
            || !client.bytes().all(|b| (0x20..0x7f).contains(&b))
        {
            return Err(ConfigError::ClientId);
        }
        Ok(Self {
            provider_config_id: id.into(),
            issuer,
            client_id: ClientId::new(client.into()),
        })
    }
    pub(crate) fn binding(&self) -> (&str, &str, &str) {
        (
            &self.provider_config_id,
            self.issuer.as_str(),
            self.client_id.as_str(),
        )
    }
    pub(crate) fn with_keys(&self, keys: CoreJsonWebKeySet) -> TrustedProvider {
        TrustedProvider {
            provider_config_id: self.provider_config_id.clone(),
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            keys,
        }
    }
}

/// Trusted provider inputs. The issuer, client and keys come only from deployment configuration;
/// nothing in a token selects them.
#[derive(Clone)]
pub struct TrustedProvider {
    provider_config_id: String,
    issuer: IssuerUrl,
    client_id: ClientId,
    keys: CoreJsonWebKeySet,
}

impl fmt::Debug for TrustedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedProvider")
            .field("provider_config_id", &self.provider_config_id)
            .finish_non_exhaustive()
    }
}

impl TrustedProvider {
    /// `provider_config_id` is a canonical lowercase UUID. `issuer` is an exact HTTPS URL with a
    /// host and no user information, query or fragment, compared byte for byte. `jwks` is a JSON
    /// Web Key Set document; keys the library cannot use are skipped, and at least one must remain.
    pub fn new(
        provider_config_id: &str,
        issuer: &str,
        client_id: &str,
        jwks: &[u8],
    ) -> Result<Self, ConfigError> {
        if !canonical_uuid(provider_config_id) {
            return Err(ConfigError::ProviderConfigId);
        }
        let issuer = trusted_issuer(issuer).ok_or(ConfigError::Issuer)?;
        if client_id.is_empty()
            || client_id.len() > MAX_CLIENT_ID_BYTES
            || !client_id.bytes().all(|b| (0x20..0x7f).contains(&b))
        {
            return Err(ConfigError::ClientId);
        }
        if jwks.is_empty() || jwks.len() > MAX_JWKS_BYTES {
            return Err(ConfigError::Jwks);
        }
        let keys: CoreJsonWebKeySet =
            serde_json::from_slice(jwks).map_err(|_| ConfigError::Jwks)?;
        if keys.keys().is_empty() || keys.keys().len() > MAX_JWKS_KEYS {
            return Err(ConfigError::Jwks);
        }
        // Inspect the keys the verifier actually parsed, not a separate raw-JWKS view.
        // CoreJsonWebKey exposes its RSA modulus through serialization only.
        for key in keys.keys() {
            let key = serde_json::to_value(key).map_err(|_| ConfigError::Jwks)?;
            if key["kty"] == "RSA" {
                let modulus = key["n"].as_str().ok_or(ConfigError::Jwks)?;
                let bytes = URL_SAFE_NO_PAD
                    .decode(modulus)
                    .map_err(|_| ConfigError::Jwks)?;
                let significant = bytes
                    .iter()
                    .position(|b| *b != 0)
                    .ok_or(ConfigError::Jwks)?;
                let bits =
                    (bytes.len() - significant) * 8 - bytes[significant].leading_zeros() as usize;
                if bits < 2048 {
                    return Err(ConfigError::Jwks);
                }
            }
        }
        Ok(Self {
            provider_config_id: provider_config_id.to_owned(),
            issuer,
            client_id: ClientId::new(client_id.to_owned()),
            keys,
        })
    }

    /// Verifies `token` for this provider, the expected nonce and the trusted clock `now`.
    /// Only RS256 is accepted. Tokens with more than one audience are rejected.
    pub fn verify(
        &self,
        token: &UnverifiedIdToken,
        nonce: &ExpectedNonce,
        policy: &Policy,
        now: SystemTime,
    ) -> Result<VerifiedIdentity, VerifyError> {
        self.verify_digest(token, &ExpectedNonceDigest::from_nonce(nonce), policy, now)
    }

    /// Verify against a digest owned by the committed login transaction.
    pub fn verify_digest(
        &self,
        token: &UnverifiedIdToken,
        nonce: &ExpectedNonceDigest,
        policy: &Policy,
        now: SystemTime,
    ) -> Result<VerifiedIdentity, VerifyError> {
        self.verify_assertion(token, nonce, policy, now)
            .map(|v| v.identity)
    }
    pub(crate) fn verify_assertion(
        &self,
        token: &UnverifiedIdToken,
        nonce: &ExpectedNonceDigest,
        policy: &Policy,
        now: SystemTime,
    ) -> Result<VerifiedAssertion, VerifyError> {
        let now = utc(now)?;
        let parsed = IdToken::<
            TimeClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >::from_str(&token.0)
        .map_err(|_| VerifyError::Malformed)?;
        // Public-client mode: no client secret, so HMAC algorithms can never verify.
        let verifier = CoreIdTokenVerifier::new_public_client(
            self.client_id.clone(),
            self.issuer.clone(),
            self.keys.clone(),
        )
        .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256])
        .set_time_fn(move || now);
        let claims = parsed
            .into_claims(&verifier, |claim: Option<&Nonce>| nonce.check(claim))
            .map_err(classify)?;

        // Checks on signature-verified claims that the library leaves to the relying party.
        if claims.audiences().len() != 1 {
            return Err(VerifyError::Audience);
        }
        if let Some(azp) = claims.authorized_party()
            && **azp != *self.client_id
        {
            return Err(VerifyError::AuthorizedParty);
        }
        let skew = delta(policy.future_skew)?;
        let latest = now.checked_add_signed(skew).ok_or(VerifyError::Clock)?;
        let issued = claims.issue_time();
        if issued > latest {
            return Err(VerifyError::IssuedInFuture);
        }
        let earliest = now
            .checked_sub_signed(delta(policy.max_issued_at_age)?)
            .ok_or(VerifyError::Clock)?;
        if issued < earliest {
            return Err(VerifyError::IssuedTooLongAgo);
        }
        if let Some(nbf) = claims.additional_claims().nbf {
            let nbf = DateTime::<Utc>::from_timestamp(nbf, 0).ok_or(VerifyError::Malformed)?;
            if nbf > latest {
                return Err(VerifyError::NotYetValid);
            }
        }
        let subject = claims.subject().as_str();
        if subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || !subject.is_ascii()
            || subject.contains('\0')
        {
            return Err(VerifyError::Subject);
        }
        // Inspect only the payload of the exact compact token that passed every check above.
        // A duplicate anywhere makes membership ambiguous without changing exact-identity login.
        let payload = token
            .0
            .split('.')
            .nth(1)
            .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
            .and_then(|bytes| crate::provider_keys::documents::unique(&bytes).ok());
        Ok(VerifiedAssertion {
            membership: crate::membership::Evidence::from_signed_payload(payload),
            identity: VerifiedIdentity {
                provider_config_id: self.provider_config_id.clone(),
                issuer: self.issuer.as_str().to_owned(),
                subject: subject.to_owned(),
            },
            checked_at: now,
            expires: claims.expiration(),
            issued,
            max_age: delta(policy.max_issued_at_age)?,
        })
    }
}

/// Signature-verified evidence kept private until the managed generation check.
pub(crate) struct VerifiedAssertion {
    pub(crate) membership: crate::membership::Evidence,
    identity: VerifiedIdentity,
    checked_at: DateTime<Utc>,
    expires: DateTime<Utc>,
    issued: DateTime<Utc>,
    max_age: TimeDelta,
}
impl VerifiedAssertion {
    pub(crate) fn membership_window(&self, max_age_seconds: i32) -> (i64, i64) {
        let issued = self.issued.timestamp_millis();
        let age = self
            .max_age
            .num_milliseconds()
            .min(i64::from(max_age_seconds) * 1000);
        (
            issued,
            self.expires
                .timestamp_millis()
                .min(issued.saturating_add(age)),
        )
    }
    pub(crate) fn release(self, now: SystemTime) -> Result<VerifiedIdentity, VerifyError> {
        self.check(now)?;
        Ok(self.identity)
    }
    pub(crate) fn remaining(&self, now: SystemTime) -> Result<Duration, VerifyError> {
        let age_limit = self
            .issued
            .checked_add_signed(self.max_age)
            .ok_or(VerifyError::Clock)?;
        (self.expires.min(age_limit) - utc(now)?)
            .to_std()
            .map_err(|_| VerifyError::Expired)
    }
    pub(crate) fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }
    pub(crate) fn check(&self, now: SystemTime) -> Result<(), VerifyError> {
        let now = utc(now)?;
        if now < self.checked_at {
            return Err(VerifyError::Clock);
        }
        if now >= self.expires {
            return Err(VerifyError::Expired);
        }
        if self.issued
            < now
                .checked_sub_signed(self.max_age)
                .ok_or(VerifyError::Clock)?
        {
            return Err(VerifyError::IssuedTooLongAgo);
        }
        Ok(())
    }
}

/// SHA-256 of the exact authorization nonce. Not a substitute for transaction consumption.
pub struct ExpectedNonceDigest([u8; 32]);
impl fmt::Debug for ExpectedNonceDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExpectedNonceDigest(..)")
    }
}
impl ExpectedNonceDigest {
    pub fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }
    pub fn from_nonce(nonce: &ExpectedNonce) -> Self {
        Self(Sha256::digest(nonce.0.secret().as_bytes()).into())
    }
    fn check(&self, claim: Option<&Nonce>) -> Result<(), String> {
        let value = claim.ok_or_else(|| "invalid nonce".to_owned())?.secret();
        ExpectedNonce::new(value).map_err(|_| "invalid nonce".to_owned())?;
        let actual: [u8; 32] = Sha256::digest(value.as_bytes()).into();
        if bool::from(self.0.ct_eq(&actual)) {
            Ok(())
        } else {
            Err("invalid nonce".to_owned())
        }
    }
}

impl TrustedProvider {
    pub(crate) fn binding(&self) -> (&str, &str, &str) {
        (
            &self.provider_config_id,
            self.issuer.as_str(),
            self.client_id.as_str(),
        )
    }
}

/// Untrusted compact ID-token bytes. Never displayed or debug-printed.
pub struct UnverifiedIdToken(String);

impl fmt::Debug for UnverifiedIdToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnverifiedIdToken(..)")
    }
}

impl UnverifiedIdToken {
    pub(crate) fn header(&self) -> Result<serde_json::Value, VerifyError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(self.0.split('.').next().ok_or(VerifyError::Malformed)?)
            .map_err(|_| VerifyError::Malformed)?;
        crate::provider_keys::documents::json(&bytes).map_err(|_| VerifyError::Malformed)
    }
    /// Bounds the input and checks the compact-serialization alphabet before any parsing.
    pub fn new(token: &str) -> Result<Self, VerifyError> {
        if token.is_empty()
            || token.len() > MAX_ID_TOKEN_BYTES
            || token.bytes().filter(|&b| b == b'.').count() != 2
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(VerifyError::Malformed);
        }
        Ok(Self(token.to_owned()))
    }
}

/// The nonce a future login-transaction owner sent in the authorization request. Supplying it
/// is trusted context; this module does not generate, store or consume nonces.
pub struct ExpectedNonce(Nonce);

impl fmt::Debug for ExpectedNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExpectedNonce(..)")
    }
}

impl ExpectedNonce {
    /// 22–512 visible ASCII characters. Callers must generate at least 128 random bits.
    pub fn new(nonce: &str) -> Result<Self, ConfigError> {
        if nonce.len() < MIN_NONCE_BYTES
            || nonce.len() > MAX_NONCE_BYTES
            || !nonce.bytes().all(|b| (0x21..0x7f).contains(&b))
        {
            return Err(ConfigError::Nonce);
        }
        Ok(Self(Nonce::new(nonce.to_owned())))
    }
}

/// A provider-asserted identity that passed verification. It grants nothing by itself.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    provider_config_id: String,
    issuer: String,
    subject: String,
}

impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedIdentity")
            .field("provider_config_id", &self.provider_config_id)
            .finish_non_exhaustive()
    }
}

impl VerifiedIdentity {
    pub fn provider_config_id(&self) -> &str {
        &self.provider_config_id
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// The only claim read beyond OIDC Core's ID-token claims: RFC 7519 `nbf`, when present.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct TimeClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
}

impl AdditionalClaims for TimeClaims {}

/// Drops every library message: they can quote issuers, audiences and key identifiers.
fn classify(error: ClaimsVerificationError) -> VerifyError {
    use ClaimsVerificationError as C;
    use SignatureVerificationError as S;
    match error {
        C::Expired(_) => VerifyError::Expired,
        C::InvalidAudience(_) => VerifyError::Audience,
        C::InvalidIssuer(_) => VerifyError::Issuer,
        C::InvalidNonce(_) => VerifyError::Nonce,
        C::InvalidSubject(_) => VerifyError::Subject,
        C::Unsupported(_) => VerifyError::Unsupported,
        // `alg: none` surfaces as NoSignature: an unsigned token is a disallowed algorithm.
        C::SignatureVerification(S::DisallowedAlg(_) | S::UnsupportedAlg(_) | S::NoSignature) => {
            VerifyError::DisallowedAlgorithm
        }
        C::SignatureVerification(S::NoMatchingKey | S::AmbiguousKeyId(_)) => {
            VerifyError::UnknownKey
        }
        C::SignatureVerification(_) => VerifyError::InvalidSignature,
        _ => VerifyError::Malformed,
    }
}

fn trusted_issuer(issuer: &str) -> Option<IssuerUrl> {
    if issuer.is_empty() || issuer.len() > MAX_ISSUER_BYTES {
        return None;
    }
    let parsed = IssuerUrl::new(issuer.to_owned()).ok()?;
    let url = parsed.url();
    let exact = url.scheme() == "https"
        && url.host_str().is_some_and(|h| !h.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !issuer.contains(['?', '#']);
    exact.then_some(parsed)
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

fn utc(now: SystemTime) -> Result<DateTime<Utc>, VerifyError> {
    let since = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VerifyError::Clock)?;
    let seconds = i64::try_from(since.as_secs()).map_err(|_| VerifyError::Clock)?;
    DateTime::<Utc>::from_timestamp(seconds, since.subsec_nanos()).ok_or(VerifyError::Clock)
}

fn delta(duration: Duration) -> Result<TimeDelta, VerifyError> {
    TimeDelta::from_std(duration).map_err(|_| VerifyError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_bounds() {
        let s = Duration::from_secs;
        assert!(Policy::new(s(300), s(60)).is_ok());
        assert!(Policy::new(s(3600), s(300)).is_ok());
        assert_eq!(Policy::new(Duration::ZERO, s(0)), Err(ConfigError::Policy));
        assert_eq!(Policy::new(s(3601), s(0)), Err(ConfigError::Policy));
        assert_eq!(Policy::new(s(600), s(301)), Err(ConfigError::Policy));
        assert_eq!(Policy::new(s(60), s(60)), Err(ConfigError::Policy));
        assert_eq!(Policy::new(Duration::MAX, s(0)), Err(ConfigError::Policy));
    }

    #[test]
    fn issuer_must_be_exact_https() {
        assert!(trusted_issuer("https://login.example.test/realm").is_some());
        for bad in [
            "",
            "http://login.example.test",
            "https://user@login.example.test",
            "https://login.example.test/?a=b",
            "https://login.example.test/#f",
            "https://login.example.test/?",
            "file:///etc/issuer",
            "not a url",
        ] {
            assert!(trusted_issuer(bad).is_none(), "{bad}");
        }
        assert!(trusted_issuer(&format!("https://a.test/{}", "x".repeat(2048))).is_none());
    }

    #[test]
    fn clock_out_of_range_is_rejected() {
        assert_eq!(
            utc(UNIX_EPOCH - Duration::from_secs(1)),
            Err(VerifyError::Clock)
        );
        assert!(utc(UNIX_EPOCH + Duration::from_secs(1_800_000_000)).is_ok());
    }
}
