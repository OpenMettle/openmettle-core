//! Internal local identity approval and sessions (ADR 0013). No resource authorization.
pub(crate) mod native;
use crate::runs::WriteTransaction;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::{fmt, time::Duration};
use subtle::ConstantTimeEq;
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Rejected,
    Capacity,
    Random,
    Database,
    Timeout,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid session policy",
            Self::Rejected => "session rejected",
            Self::Capacity => "session storage limit reached",
            Self::Random => "session randomness unavailable",
            Self::Database => "session persistence failed; discard uncertain connection",
            Self::Timeout => "session deadline exceeded; discard uncertain connection",
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

/// Explicit implementation bounds, not deployment defaults. No renewal or sliding expiry.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    lifetime_ms: i64,
    retained_limit: i64,
    deadline: Duration,
}
impl Policy {
    pub fn new(lifetime: Duration, retained_limit: u32, deadline: Duration) -> Result<Self, Error> {
        if !(Duration::from_secs(1)..=Duration::from_secs(86400)).contains(&lifetime)
            || !(1..=1024).contains(&retained_limit)
            || !(Duration::from_millis(10)..=Duration::from_secs(60)).contains(&deadline)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            lifetime_ms: lifetime.as_millis() as i64,
            retained_limit: retained_limit.into(),
            deadline,
        })
    }
    /// Bound on one session operation, including any wait for a pooled connection (ADR 0016).
    pub(crate) fn deadline(&self) -> Duration {
        self.deadline
    }
}
/// Returned only after acknowledged issuance and fresh local validation. Never log expose().
pub struct Credential(String);
impl Credential {
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(..)")
    }
}
/// Identity at a local database observation, not a grant or a durable permission capability.
pub struct Context {
    user: String,
    personal_scope: String,
    approval: String,
    observed_ms: i64,
}
impl Context {
    pub fn user_id(&self) -> &str {
        &self.user
    }
    pub fn personal_scope_id(&self) -> &str {
        &self.personal_scope
    }
    /// The approval the session was issued under, verified active and unexpired under its
    /// `FOR SHARE` lock in the validating transaction (ADR 0029). Pass it with
    /// [`Self::observed_ms`] to `authz::store::hydrate_api_principal`.
    pub fn approval_id(&self) -> &str {
        &self.approval
    }
    /// The primary database's clock, in Unix milliseconds, at which eligibility was observed
    /// (ADR 0029). It lies in the session's `[created_ms, expires_ms)` window.
    pub fn observed_ms(&self) -> i64 {
        self.observed_ms
    }
}
impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionContext(..)")
    }
}
/// Native variants carry the session audience of the serving registration (ADR 0023). The
/// bearer's stored audience must equal it in the same transaction as validation or logout.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Channel {
    Browser,
    Native([u8; 32]),
}
#[derive(Clone, Copy)]
pub(crate) enum Validation {
    Browser,
    NativePending([u8; 32]),
    NativeExchange([u8; 32]),
    NativeBearer([u8; 32]),
}
impl Validation {
    fn channel(self) -> Channel {
        match self {
            Self::Browser => Channel::Browser,
            Self::NativePending(audience)
            | Self::NativeExchange(audience)
            | Self::NativeBearer(audience) => Channel::Native(audience),
        }
    }
}
fn digest(channel: Channel, id: &str, secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(crate::runs::identity(
        match channel {
            Channel::Browser => b"openmettle/session-secret/1\0",
            Channel::Native(_) => b"openmettle/native-session-secret/1\0",
        },
        &[id.as_bytes(), secret],
    ))
    .into()
}
fn create_with(
    channel: Channel,
    fill: impl FnOnce(&mut [u8]) -> Result<(), Error>,
) -> Result<(String, Credential, [u8; 32]), Error> {
    let mut random = [0; 64];
    fill(&mut random)?;
    let id = URL_SAFE_NO_PAD.encode(&random[..32]);
    let secret: [u8; 32] = random[32..].try_into().map_err(|_| Error::Random)?;
    let hash = digest(channel, &id, &secret);
    let credential = Credential(format!("{id}.{}", URL_SAFE_NO_PAD.encode(secret)));
    Ok((id, credential, hash))
}
fn parse(channel: Channel, value: &str) -> Result<(&str, [u8; 32]), Error> {
    if value.len() != 87 {
        return Err(Error::Rejected);
    }
    let (id, secret) = value.split_once('.').ok_or(Error::Rejected)?;
    for part in [id, secret] {
        let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| Error::Rejected)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != part {
            return Err(Error::Rejected);
        }
    }
    let secret: [u8; 32] = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| Error::Rejected)?
        .try_into()
        .map_err(|_| Error::Rejected)?;
    Ok((id, digest(channel, id, &secret)))
}
/// Shape check alone, so a malformed credential never costs a pooled connection (ADR 0016).
pub(crate) fn well_formed(value: &str) -> Result<(), Error> {
    parse(Channel::Browser, value).map(|_| ())
}
fn matches(stored: Option<&[u8]>, supplied: &[u8; 32]) -> bool {
    let expected: [u8; 32] = stored.and_then(|v| v.try_into().ok()).unwrap_or([0; 32]);
    let equal = bool::from(expected.ct_eq(supplied));
    stored.is_some_and(|v| v.len() == 32) & equal
}
async fn transaction(c: &mut PgConnection) -> Result<WriteTransaction<'_>, Error> {
    use sqlx::Connection;
    if c.is_in_transaction() {
        return Err(Error::Rejected);
    }
    let mut tx = WriteTransaction::begin(c).await?;
    let setup: Result<(), Error> = async {
        for sql in [
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "SET LOCAL synchronous_commit = on",
            "SET LOCAL lock_timeout = '2s'",
            "SET LOCAL statement_timeout = '3s'",
        ] {
            sqlx::query(sql).execute(tx.connection()?).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = setup {
        tx.rollback().await?;
        return Err(error);
    }
    Ok(tx)
}
// Deferred home-invitation cutoff (home_redemption_session). The server reported the error for COMMIT
// and rolled the transaction back, so the refusal is definite.
const INVITATION_CUTOFF: &str = "OMH01";
// Only that known server refusal is Rejected. Connection loss, a lost acknowledgement and
// every other commit failure stay Database: discard the uncertain connection.
fn committed(result: Result<(), crate::runs::Error>) -> Result<(), Error> {
    match result {
        Ok(()) => Ok(()),
        Err(crate::runs::Error::Database(sqlx::Error::Database(e)))
            if e.code().as_deref() == Some(INVITATION_CUTOFF) =>
        {
            Err(Error::Rejected)
        }
        Err(_) => Err(Error::Database),
    }
}
// Returned errors must release locks before the caller gets its connection back. Drop
// only queues SQLx rollback; cancellation/timeout remains an uncertain-discard boundary.
async fn finish<T>(tx: WriteTransaction<'_>, result: Result<T, Error>) -> Result<T, Error> {
    match result {
        Ok(value) => {
            committed(tx.commit().await)?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}
pub(crate) async fn now(c: &mut PgConnection) -> Result<i64, Error> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(c)
            .await?,
    )
}
/// What remains of a managed proof at one in-memory check (ADR 0023).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProofBudget {
    /// Until the ID token expires or passes its maximum age. This alone bounds a stored
    /// native grant, which the app redeems on any replica.
    pub(crate) assertion: Duration,
    /// Until the checking process must stop acting on the proof: `assertion`, the freshness
    /// of its key snapshot and its exchange deadline. It bounds in-process work only.
    pub(crate) process: Duration,
}
// Only the managed proof consumer constructs this input. No public mint/identity bypass.
pub(crate) struct Issuance<'a> {
    pub provider: &'a str,
    pub issuer: &'a str,
    pub client: &'a str,
    pub revision: &'a str,
    pub assertion: &'a crate::auth::VerifiedAssertion,
    pub epoch: i64,
    pub login: &'a str,
    pub native: Option<&'a native::Attempt>,
    pub login_expiry: i64,
    pub membership_revision: i64,
    pub binding: Vec<u8>,
    pub deadline: Instant,
    /// The invitation code presented when this login started, if any (ADR 0022).
    pub invitation: Option<&'a crate::invitation::InvitationCode>,
}
// Only a missing identity can enter the first-account path. A missing or withdrawn
// approval on an existing identity is always handled by the ordinary eligibility checks,
// and a code presented for an existing identity is dropped here without being evaluated.
// A missing identity without a code is refused without calling the redemption function.
async fn resolve_identity(
    c: &mut PgConnection,
    input: &Issuance<'_>,
) -> Result<(String, String, Option<i64>), Error> {
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT id::text, user_id::text FROM openmettle.user_identities
         WHERE issuer=$1 AND subject=$2 AND issuer COLLATE \"C\"=$1 AND subject COLLATE \"C\"=$2",
    )
    .bind(input.issuer)
    .bind(input.assertion.identity().subject())
    .fetch_optional(&mut *c)
    .await?;
    if let Some((identity, user)) = existing {
        return Ok((identity, user, None));
    }
    let code = input.invitation.ok_or(Error::Rejected)?;
    sqlx::query_as(
        "SELECT identity_id, user_id, redeem_before_ms FROM
         openmettle.redeem_home_invitation($1::uuid,$2,$3,$4,$5,$6)",
    )
    .bind(input.provider)
    .bind(input.issuer)
    .bind(input.assertion.identity().subject())
    .bind(input.login)
    .bind(input.epoch)
    .bind(code.bytes().as_slice())
    .fetch_optional(c)
    .await?
    .ok_or(Error::Rejected)
}
pub(crate) enum Delivery {
    Browser(Credential),
    NativeCode(native::Release),
}
impl Delivery {
    /// The last step of issuance. A native code whose release deadline has already passed,
    /// for example during the final validation, is refused here. That refusal is defence in
    /// depth: `native::Release::release` repeats the check when the code leaves the process,
    /// and nothing else yields the code.
    fn settled(credential: Credential, code: Option<native::Release>) -> Result<Self, Error> {
        match code {
            Some(code) if code.live() => Ok(Self::NativeCode(code)),
            Some(_) => Err(Error::Rejected),
            None => Ok(Self::Browser(credential)),
        }
    }
    pub(crate) fn browser(self) -> Result<Credential, Error> {
        match self {
            Self::Browser(credential) => Ok(credential),
            Self::NativeCode(_) => Err(Error::Rejected),
        }
    }
}

/// A committed session whose credential has not been released. Only [`Issued::release`]
/// yields it, after a fresh validation on the primary; dropping this releases nothing.
pub(crate) struct Issued {
    credential: Credential,
    code: Option<native::Release>,
    validation: Validation,
    deadline: Instant,
}
impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Issued(..)")
    }
}
impl Issued {
    /// The acknowledgement can be delayed past revocation or local expiry. A new primary
    /// transaction observes that; the issued row/marker may remain without a credential.
    /// `c` is an `openmettle_api` connection, never the issuance one: the issuance role
    /// cannot run validation (ADR 0030). The issuance deadline still bounds this step.
    pub(crate) async fn release(
        self,
        c: &mut PgConnection,
        check: impl Fn() -> Result<ProofBudget, Error>,
    ) -> Result<Delivery, Error> {
        let deadline = self.deadline;
        tokio::time::timeout_at(deadline, async move {
            validate_inner(c, self.credential.expose(), self.validation).await?;
            check()?;
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            Delivery::settled(self.credential, self.code)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

/// The issuance transaction on `c`, an `openmettle_issuance` connection (ADR 0030). It ends
/// committed or rolled back; the caller settles `c` before releasing the result.
pub(crate) async fn issue(
    c: &mut PgConnection,
    input: Issuance<'_>,
    policy: &Policy,
    check: impl Fn() -> Result<ProofBudget, Error>,
) -> Result<Issued, Error> {
    let validation = if let Some(native) = input.native {
        Validation::NativePending(native.audience)
    } else {
        Validation::Browser
    };
    let deadline = input.deadline.min(Instant::now() + policy.deadline);
    tokio::time::timeout_at(deadline, async {
        // Both proof budgets become monotonic bounds before the first await. Later wall-clock
        // changes cannot extend them, and each later check() can only shorten what remains.
        // `proof_deadline` bounds this process. `assertion_deadline` also bounds a stored
        // native grant. It is None only for a remainder too large to represent.
        let started = Instant::now();
        let proof = check()?;
        let proof_deadline = (started + proof.process).min(deadline);
        let assertion_deadline = started.checked_add(proof.assertion);
        let mut tx = transaction(c).await?;
        let result: Result<(Credential, Option<native::Release>), Error> = async {
        let gate = sqlx::query("SELECT binding,expires_ms,consumed,session_issued FROM openmettle.login_transactions WHERE id=$1 FOR UPDATE")
            .bind(input.login).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        if !gate.try_get::<bool,_>("consumed")? || gate.try_get::<bool,_>("session_issued")?
            || gate.try_get::<Vec<u8>,_>("binding")? != input.binding
            || gate.try_get::<i64,_>("expires_ms")? != input.login_expiry { return Err(Error::Rejected); }
        sqlx::query("SELECT id FROM openmettle.login_providers WHERE id=$1::uuid FOR SHARE")
            .bind(input.provider).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        let epoch = crate::provider_keys::authority(tx.connection()?, input.provider, input.issuer, input.client, input.revision).await.map_err(|_| Error::Rejected)?;
        if epoch != input.epoch { return Err(Error::Rejected); }
        let provider_generation: i64 = sqlx::query_scalar("SELECT access_generation FROM openmettle.login_providers WHERE id=$1::uuid")
            .bind(input.provider).fetch_one(tx.connection()?).await?;
        let (identity_id, user, invitation_cutoff) = resolve_identity(tx.connection()?, &input).await?;
        let approval: String = sqlx::query_scalar("SELECT id::text FROM openmettle.local_identity_approvals WHERE provider_id=$1::uuid AND identity_id=$2::uuid FOR SHARE")
            .bind(input.provider).bind(&identity_id).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        let a = sqlx::query("SELECT active,expires_ms,revision,access_generation FROM openmettle.local_identity_approvals WHERE id=$1::uuid")
            .bind(&approval).fetch_one(tx.connection()?).await?;
        let u = sqlx::query("SELECT disabled_at IS NOT NULL AS disabled,session_generation FROM openmettle.users WHERE id=$1::uuid FOR NO KEY UPDATE")
            .bind(&user).fetch_one(tx.connection()?).await?;
        // Each monotonic sample is taken before its primary clock query is sent.
        let issued_at = Instant::now();
        let timestamp = now(tx.connection()?).await?;
        let approval_expiry: i64 = a.try_get("expires_ms")?;
        if !a.try_get::<bool,_>("active")? || u.try_get::<bool,_>("disabled")?
            || timestamp >= approval_expiry || timestamp >= input.login_expiry { return Err(Error::Rejected); }
        sqlx::query("SELECT id FROM openmettle.scopes WHERE personal_user_id=$1::uuid AND kind='personal'")
            .bind(&user).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions WHERE user_id=$1::uuid")
            .bind(&user).fetch_one(tx.connection()?).await?;
        if count >= policy.retained_limit { return Err(Error::Capacity); }
        let membership_expiry = crate::membership::reconcile(&mut tx, crate::membership::Subject {
            approval: &approval, user: &user, epoch, membership_revision: input.membership_revision,
            approval_generation: a.try_get("access_generation")?,
            user_generation: u.try_get("session_generation")?,
        }, input.assertion, input.login).await?;
        let expiry = timestamp.checked_add(policy.lifetime_ms).ok_or(Error::Configuration)?.min(approval_expiry);
        let (id, credential, hash) = create_with(validation.channel(), |bytes| SystemRandom::new().fill(bytes).map_err(|_| Error::Random))?;
        sqlx::query("INSERT INTO openmettle.local_sessions (id,secret_hash,login_id,provider_id,identity_id,approval_id,user_id,issued_client,issued_epoch,issued_revision,provider_generation,approval_generation,user_generation,created_ms,expires_ms) VALUES ($1,$2,$3,$4::uuid,$5::uuid,$6::uuid,$7::uuid,$8,$9,$10,$11,$12,$13,$14,$15)")
            .bind(&id).bind(hash.as_slice()).bind(input.login).bind(input.provider).bind(&identity_id).bind(&approval).bind(&user)
            .bind(input.client).bind(input.epoch).bind(a.try_get::<i64,_>("revision")?).bind(provider_generation)
            .bind(a.try_get::<i64,_>("access_generation")?).bind(u.try_get::<i64,_>("session_generation")?)
            .bind(timestamp).bind(expiry).execute(tx.connection()?).await?;
        sqlx::query("UPDATE openmettle.login_transactions SET session_issued=true WHERE id=$1")
            .bind(input.login).execute(tx.connection()?).await?;
        let mut final_at = Instant::now();
        let mut final_time = now(tx.connection()?).await?;
        if membership_expiry.is_some_and(|expiry| final_time >= expiry) {
            // Keep both the newer signed high-water and any completed removal. Only
            // the mapped evidence expired while issuing this exact-approval session.
            sqlx::query("UPDATE openmettle.membership_observations SET observation.state='stale' WHERE approval_id=$1::uuid")
                .bind(&approval).execute(tx.connection()?).await?;
            final_at = Instant::now();
            final_time = now(tx.connection()?).await?;
        }
        if invitation_cutoff.is_some_and(|cutoff| final_time >= cutoff)
            || final_time < timestamp || final_time >= expiry
            || final_time >= approval_expiry || final_time >= input.login_expiry
        {
            return Err(Error::Rejected);
        }
        let remaining = check()?;
        let code = if let Some(native) = input.native {
            // The stored grant ends with the login, the session and the assertion's age, and
            // never with `proof_deadline`: that bounds only the release from this process
            // (`native::window`, ADR 0023).
            let assertion = assertion_deadline.map_or(remaining.assertion, |at| {
                remaining.assertion.min(at.saturating_duration_since(Instant::now()))
            });
            let window = native::window(
                native::Sample { at: issued_at, ms: timestamp },
                native::Sample { at: final_at, ms: final_time },
                input.login_expiry, expiry, assertion, proof_deadline,
            ).ok_or(Error::Rejected)?;
            let code = native.store(tx.connection()?, &id, &credential, window.until, window.release_by).await?;
            check()?;
            Some(code)
        } else { None };
        Ok((credential, code))
        }.await;
        let (credential, code) = finish(tx, result).await?;
        check()?;
        Ok(Issued { credential, code, validation, deadline })
    }).await.map_err(|_| Error::Timeout)?
}

/// Primary database only. Context is not authorization for a later protected write.
pub async fn validate(
    c: &mut PgConnection,
    credential: &str,
    policy: &Policy,
) -> Result<Context, Error> {
    tokio::time::timeout(
        policy.deadline,
        validate_inner(c, credential, Validation::Browser),
    )
    .await
    .map_err(|_| Error::Timeout)?
}
pub(crate) async fn validate_inner(
    c: &mut PgConnection,
    credential: &str,
    validation: Validation,
) -> Result<Context, Error> {
    let (id, hash) = parse(validation.channel(), credential)?;
    let mut tx = transaction(c).await?;
    let result: Result<Context, Error> = async {
    let row = sqlx::query("SELECT secret_hash,provider_id::text,approval_id::text,user_id::text FROM openmettle.local_sessions WHERE id=$1")
        .bind(id).fetch_optional(tx.connection()?).await?;
    let stored = row
        .as_ref()
        .map(|r| r.try_get::<Vec<u8>, _>("secret_hash"))
        .transpose()?;
    if !matches(stored.as_deref(), &hash) {
        return Err(Error::Rejected);
    }
    let row = row.ok_or(Error::Rejected)?;
    // Immutable references from the preliminary lookup only select lock targets. Every
    // eligibility field is read again after all locks, including the session itself.
    sqlx::query("SELECT id FROM openmettle.login_providers WHERE id=$1::uuid FOR SHARE")
        .bind(row.try_get::<String, _>("provider_id")?)
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Rejected)?;
    sqlx::query("SELECT id FROM openmettle.local_identity_approvals WHERE id=$1::uuid FOR SHARE")
        .bind(row.try_get::<String, _>("approval_id")?)
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Rejected)?;
    sqlx::query("SELECT id FROM openmettle.users WHERE id=$1::uuid FOR SHARE")
        .bind(row.try_get::<String, _>("user_id")?)
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Rejected)?;
    sqlx::query("SELECT id FROM openmettle.local_sessions WHERE id=$1 FOR SHARE")
        .bind(id)
        .fetch_optional(tx.connection()?)
        .await?
        .ok_or(Error::Rejected)?;
    let timestamp = now(tx.connection()?).await?;
    let current = sqlx::query("SELECT s.user_id::text,s.approval_id::text AS approval_id,sc.id::text AS scope_id FROM openmettle.local_sessions s JOIN openmettle.login_providers p ON p.id=s.provider_id JOIN LATERAL (SELECT revision FROM openmettle.login_provider_revisions WHERE provider_id=p.id ORDER BY epoch DESC LIMIT 1) r ON true JOIN openmettle.local_identity_approvals a ON a.id=s.approval_id JOIN openmettle.user_identities i ON i.id=s.identity_id JOIN openmettle.users u ON u.id=s.user_id JOIN openmettle.scopes sc ON sc.personal_user_id=u.id AND sc.kind='personal' WHERE s.id=$1 AND s.secret_hash=$2 AND NOT s.revoked AND s.created_ms <= $3 AND s.expires_ms > $3 AND r.revision IS NOT NULL AND NOT EXISTS (SELECT FROM openmettle.login_provider_revisions retired WHERE retired.provider_id=p.id AND retired.epoch>s.issued_epoch AND retired.revision IS NULL) AND p.issuer=i.issuer AND p.client_id=s.issued_client AND i.user_id=u.id AND a.provider_id=p.id AND a.identity_id=i.id AND a.active AND a.expires_ms > $3 AND u.disabled_at IS NULL AND s.provider_generation=p.access_generation AND s.approval_generation=a.access_generation AND s.user_generation=u.session_generation")
        .bind(id).bind(hash.as_slice()).bind(timestamp).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
    match validation {
        Validation::Browser => {}
        Validation::NativeBearer(audience) => {
            // A delivered bearer is usable only through its own audience. Routine upstream
            // changes keep the audience, and another registration never matches it.
            sqlx::query("SELECT session_id FROM openmettle.native_handoffs WHERE session_id=$1 AND audience=$2 AND sealed IS NULL")
                .bind(id).bind(audience.as_slice()).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        }
        Validation::NativePending(audience) | Validation::NativeExchange(audience) => {
            // Pending grants require the original provider epoch, including across replicas.
            // The first observation precedes code delivery, the second follows the claim commit.
            sqlx::query("SELECT g.session_id FROM openmettle.native_handoffs g
                         JOIN openmettle.local_sessions s ON s.id=g.session_id
                         WHERE s.id=$1 AND (g.sealed IS NULL)=$2 AND g.expires_ms > $3 AND g.audience=$4
                         AND s.issued_epoch=(SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id=s.provider_id)")
                .bind(id).bind(matches!(validation, Validation::NativeExchange(_))).bind(timestamp).bind(audience.as_slice())
                .fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        }
    }
    let context = Context {
        user: current.try_get("user_id")?,
        personal_scope: current.try_get("scope_id")?,
        approval: current.try_get("approval_id")?,
        observed_ms: timestamp,
    };
    Ok(context)
    }.await;
    finish(tx, result).await
}
/// Revokes by possession of the credential even when all current eligibility has been lost.
pub async fn logout(c: &mut PgConnection, credential: &str, policy: &Policy) -> Result<(), Error> {
    logout_channel(c, credential, policy, Channel::Browser).await
}
pub(crate) async fn logout_channel(
    c: &mut PgConnection,
    credential: &str,
    policy: &Policy,
    channel: Channel,
) -> Result<(), Error> {
    tokio::time::timeout(policy.deadline, async {
        let (id, hash) = parse(channel, credential)?;
        let mut tx = transaction(c).await?;
        let result: Result<(), Error> = async {
            let stored: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT secret_hash FROM openmettle.local_sessions WHERE id=$1 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(tx.connection()?)
            .await?;
            if !matches(stored.as_deref(), &hash) {
                return Err(Error::Rejected);
            }
            // Possession and the serving audience. Current eligibility is not required.
            if let Channel::Native(audience) = channel {
                sqlx::query("SELECT session_id FROM openmettle.native_handoffs WHERE session_id=$1 AND audience=$2 AND sealed IS NULL")
                    .bind(id).bind(audience.as_slice()).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
            }
            sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=$1")
                .bind(id)
                .execute(tx.connection()?)
                .await?;
            Ok(())
        }
        .await;
        finish(tx, result).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}
/// Internal administrative operation, not an authorized product route. Expected generation
/// prevents stale administrative observations. Re-enable is owner-only in this increment.
pub async fn disable_user(
    c: &mut PgConnection,
    user: &str,
    expected_generation: i64,
    policy: &Policy,
) -> Result<(), Error> {
    crate::runs::uuid(user).map_err(|_| Error::Rejected)?;
    tokio::time::timeout(policy.deadline, async {
        let next = expected_generation.checked_add(1).filter(|_| expected_generation >= 0).ok_or(Error::Rejected)?;
        let mut tx = transaction(c).await?;
        let result: Result<(), Error> = async {
        let generation: i64 = sqlx::query_scalar("SELECT session_generation FROM openmettle.users WHERE id=$1::uuid FOR UPDATE")
            .bind(user).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        if generation != expected_generation { return Err(Error::Rejected); }
        sqlx::query("UPDATE openmettle.users SET disabled_at=GREATEST(created_at,clock_timestamp()),session_generation=$2 WHERE id=$1::uuid")
            .bind(user).bind(next).execute(tx.connection()?).await?;
        Ok(())
        }.await;
        finish(tx, result).await
    }).await.map_err(|_| Error::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_bounds_hashes_and_redaction() {
        let (id, value, hash) = create_with(Channel::Browser, |b| {
            b.fill(17);
            Ok(())
        })
        .unwrap();
        assert_eq!(value.expose().len(), 87);
        assert_eq!(
            parse(Channel::Browser, value.expose()).unwrap(),
            (id.as_str(), hash)
        );
        let (_, native_digest) = parse(Channel::Native([0; 32]), value.expose()).unwrap();
        assert!(!matches(Some(&hash), &native_digest));
        assert!(matches(Some(&hash), &hash));
        assert!(!matches(None, &[0; 32]));
        assert!(!matches(Some(&[0; 31]), &hash));
        assert!(!matches(Some(&[0; 32]), &hash));
        for bad in [
            String::new(),
            "x".repeat(4096),
            format!("{}=", value.expose()),
            value.expose().replace('.', "/"),
        ] {
            assert!(parse(Channel::Browser, &bad).is_err());
        }
        assert_eq!(format!("{value:?}"), "Credential(..)");
        assert!(matches!(
            create_with(Channel::Browser, |_| Err(Error::Random)),
            Err(Error::Random)
        ));
    }
    #[test]
    fn explicit_policy_bounds() {
        assert!(Policy::new(Duration::from_secs(1), 1, Duration::from_millis(10)).is_ok());
        for (life, cap, time) in [
            (0, 1, 10),
            (86401, 1, 10),
            (1, 0, 10),
            (1, 1025, 10),
            (1, 1, 0),
            (1, 1, 60001),
        ] {
            assert!(
                Policy::new(Duration::from_secs(life), cap, Duration::from_millis(time)).is_err()
            );
        }
    }
    #[derive(Debug)]
    struct Server(&'static str);
    impl fmt::Display for Server {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("synthetic server error")
        }
    }
    impl std::error::Error for Server {}
    impl sqlx::error::DatabaseError for Server {
        fn message(&self) -> &str {
            "synthetic server error"
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(self.0.into())
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }
    #[test]
    fn only_a_reported_invitation_cutoff_is_a_definite_commit_refusal() {
        let server =
            |code| crate::runs::Error::Database(sqlx::Error::Database(Box::new(Server(code))));
        assert_eq!(committed(Ok(())), Ok(()));
        assert_eq!(committed(Err(server("OMH01"))), Err(Error::Rejected));
        // The detached-redemption gate, serialization failures and lost connections stay uncertain.
        for code in ["P0001", "40001", "23514"] {
            assert_eq!(committed(Err(server(code))), Err(Error::Database));
        }
        let lost = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        for error in [
            crate::runs::Error::Database(sqlx::Error::Io(lost)),
            crate::runs::Error::Database(sqlx::Error::PoolTimedOut),
            crate::runs::Error::TransactionUnavailable,
        ] {
            assert_eq!(committed(Err(error)), Err(Error::Database));
        }
    }
}
