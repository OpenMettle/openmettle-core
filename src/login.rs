//! Internal browser login transactions (ADR 0009). No route, session or admission decision.
use crate::auth::{
    ExpectedNonceDigest, Policy, TrustedProvider, UnverifiedIdToken, VerifiedIdentity,
};
use crate::invitation::InvitationCode;
use crate::runs::{WriteTransaction, identity};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AsyncHttpClient, AuthUrl, AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken,
    HttpRequest, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenUrl,
    core::{CoreClient, CoreJsonWebKeySet, CoreResponseType},
};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime},
};
use subtle::ConstantTimeEq;

pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_CODE_BYTES: usize = 4096;
const DEADLINE: Duration = Duration::from_secs(10);
/// Login transaction lifetime bounds (ADR 0009), shared with the deployment loader.
pub const MIN_LOGIN_LIFETIME: Duration = Duration::from_secs(1);
pub const MAX_LOGIN_LIFETIME: Duration = Duration::from_secs(600);
/// Key ring capacity: one active key and up to three decrypt-only keys.
pub const MAX_KEYS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Random,
    Database,
    Rejected,
    Protection,
    Exchange,
    Verification,
    /// The owner-configured outstanding-login limit is reached (ADR 0014).
    Capacity,
    /// No outstanding-login limit is configured; initiation fails closed (ADR 0014).
    Unconfigured,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Capacity => "outstanding login limit reached",
            Self::Unconfigured => "login admission limit not configured",
            Self::Configuration => "invalid login configuration",
            Self::Random => "login randomness unavailable",
            Self::Database => "login persistence failed; restart login",
            Self::Rejected => "login transaction rejected",
            Self::Protection => "login protection failed",
            Self::Exchange => "login exchange failed; restart login",
            Self::Verification => "login identity verification failed",
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

/// Secret bytes are not displayed. No zeroization guarantee is made.
pub struct Secret(String);
impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Random)?;
    Ok(bytes)
}
fn secret() -> Result<Secret, Error> {
    Ok(Secret(URL_SAFE_NO_PAD.encode(random::<32>()?)))
}
fn hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == 32 && right.len() == 32 && bool::from(left.ct_eq(right))
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn https(value: &str) -> bool {
    if value.len() > 2048 || value.bytes().any(|b| b <= 32 || b >= 127) {
        return false;
    }
    let Ok(parsed) = IssuerUrl::new(value.to_owned()) else {
        return false;
    };
    let u = parsed.url();
    u.scheme() == "https"
        && u.host_str().is_some()
        && u.username().is_empty()
        && u.password().is_none()
        && !value.contains(['?', '#', '\\'])
}

/// Deployment inputs only. This initial exchange profile is a public PKCE client.
/// Confidential-client authentication requires its own secret-lifecycle contract.
pub struct ProviderDefinition<'a> {
    pub revision: &'a str,
    pub authorization_endpoint: &'a str,
    pub token_endpoint: &'a str,
    pub callback: &'a str,
    pub destination: &'a str,
    pub enabled: bool,
}
pub(crate) fn validate_definition(
    identity: &crate::auth::ProviderIdentity,
    d: &ProviderDefinition<'_>,
) -> Result<(), Error> {
    if !name(d.revision)
        || !name(d.destination)
        || !https(identity.binding().1)
        || !https(d.authorization_endpoint)
        || !https(d.token_endpoint)
        || !https(d.callback)
    {
        return Err(Error::Configuration);
    }
    Ok(())
}
pub struct Provider {
    // Managed only: canonical full configuration binding before the durable authority epoch.
    managed: Option<Vec<u8>>,
    trusted: TrustedProvider,
    revision: String,
    authorization: String,
    token: String,
    callback: String,
    destination: String,
    enabled: bool,
}
impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginProvider(..)")
    }
}
impl Provider {
    pub fn new(trusted: TrustedProvider, d: ProviderDefinition<'_>) -> Result<Self, Error> {
        if !name(d.revision)
            || !name(d.destination)
            || !https(trusted.binding().1)
            || !https(d.authorization_endpoint)
            || !https(d.token_endpoint)
            || !https(d.callback)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            managed: None,
            trusted,
            revision: d.revision.into(),
            authorization: d.authorization_endpoint.into(),
            token: d.token_endpoint.into(),
            callback: d.callback.into(),
            destination: d.destination.into(),
            enabled: d.enabled,
        })
    }
    pub(crate) fn set_managed(&mut self, config_binding: Vec<u8>) {
        self.managed = Some(config_binding);
    }
    /// The stored transaction binding. Managed providers read the committed provider authority
    /// inside the caller's transaction (ADR 0012); offline providers keep the ADR 0009 binding.
    async fn persisted_binding(
        &self,
        connection: &mut PgConnection,
    ) -> Result<(Vec<u8>, Option<i64>), Error> {
        let Some(config) = &self.managed else {
            return Ok((self.binding(), None));
        };
        let (id, issuer, client) = self.trusted.binding();
        let epoch =
            crate::provider_keys::authority(connection, id, issuer, client, &self.revision).await?;
        Ok((crate::provider_keys::persisted(config, epoch), Some(epoch)))
    }
    fn binding(&self) -> Vec<u8> {
        let (id, issuer, client) = self.trusted.binding();
        identity(
            b"openmettle/login-provider/1\0",
            &[
                id.as_bytes(),
                self.revision.as_bytes(),
                issuer.as_bytes(),
                client.as_bytes(),
                self.authorization.as_bytes(),
                self.token.as_bytes(),
                self.callback.as_bytes(),
                b"browser",
                self.destination.as_bytes(),
                b"public-pkce",
            ],
        )
    }
}

/// One active key followed by up to three decrypt-only keys, injected by a future loader.
/// Material and IDs must remain exclusive to this purpose across rotations and replicas.
pub struct KeyRing {
    keys: Vec<(String, [u8; 32])>,
}
impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyRing(..)")
    }
}
impl KeyRing {
    pub fn new(keys: Vec<(String, [u8; 32])>) -> Result<Self, Error> {
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(Error::Configuration);
        }
        for (i, (id, material)) in keys.iter().enumerate() {
            if !name(id)
                || keys[..i]
                    .iter()
                    .any(|(old, bytes)| old == id || bool::from(bytes.ct_eq(material)))
            {
                return Err(Error::Configuration);
            }
        }
        Ok(Self { keys })
    }
    fn key(&self, id: &str) -> Result<aead::LessSafeKey, Error> {
        let (_, bytes) = self
            .keys
            .iter()
            .find(|(key, _)| key == id)
            .ok_or(Error::Protection)?;
        Ok(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, bytes).map_err(|_| Error::Protection)?,
        ))
    }
}

async fn transaction(connection: &mut PgConnection) -> Result<WriteTransaction<'_>, Error> {
    open(connection, false).await
}
async fn open(
    connection: &mut PgConnection,
    read_only: bool,
) -> Result<WriteTransaction<'_>, Error> {
    let mut tx = WriteTransaction::begin(connection).await?;
    let setup: Result<(), Error> = async {
        for sql in [
            "SET LOCAL synchronous_commit = on",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "SET LOCAL lock_timeout = '2s'",
            "SET LOCAL statement_timeout = '3s'",
        ] {
            sqlx::query(sql).execute(tx.connection()?).await?;
        }
        if read_only {
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(tx.connection()?)
                .await?;
        }
        Ok(())
    }
    .await;
    match setup {
        Ok(()) => Ok(tx),
        Err(error) => finish(tx, Err(error)).await,
    }
}
// Every ordinary returned error awaits ROLLBACK, so an idle caller connection never keeps
// row or admission locks (dropping a SQLx transaction only queues the rollback). The original
// error survives successful cleanup; a failed cleanup is Database: discard the connection.
// Cancellation and timeouts remain uncertain-discard boundaries.
async fn finish<T>(tx: WriteTransaction<'_>, result: Result<T, Error>) -> Result<T, Error> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await.map_err(|_| Error::Database)?;
            Err(error)
        }
    }
}

// Its own root commit: never seal before this succeeds. Reservations have no delete privilege.
async fn reserve(connection: &mut PgConnection, key: &str, iv: &[u8; 12]) -> Result<bool, Error> {
    let mut tx = transaction(connection).await?;
    let result: Result<bool, Error> = async {
        Ok(sqlx::query("INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ($1,$2) ON CONFLICT DO NOTHING")
            .bind(key).bind(iv.as_slice()).execute(tx.connection()?).await?.rows_affected() == 1)
    }
    .await;
    finish(tx, result).await
}

/// Implementation ceiling for the owner-configured limit (migration 9); not a deployment value.
pub const MAX_OUTSTANDING_LOGINS: i32 = 65536;
// The singleton limit. NULL, a missing row or an out-of-range value refuses initiation.
async fn admission_limit(c: &mut PgConnection, lock: bool) -> Result<i64, Error> {
    let sql = if lock {
        "SELECT outstanding_limit FROM openmettle.login_admission WHERE id FOR UPDATE"
    } else {
        "SELECT outstanding_limit FROM openmettle.login_admission WHERE id"
    };
    match sqlx::query_scalar::<_, Option<i32>>(sql)
        .fetch_optional(c)
        .await?
        .flatten()
    {
        Some(limit) if (1..=MAX_OUTSTANDING_LOGINS).contains(&limit) => Ok(limit.into()),
        _ => Err(Error::Unconfigured),
    }
}
async fn database_ms(c: &mut PgConnection) -> Result<i64, Error> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(c)
            .await?,
    )
}
// Unexpired rows without an issued session, consumed or not, counted up to the limit.
// A consumed row whose exchange failed keeps its slot until its original expiry.
async fn below_limit(c: &mut PgConnection, now: i64, limit: i64) -> Result<(), Error> {
    let outstanding: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT 1 FROM openmettle.login_transactions
         WHERE NOT session_issued AND expires_ms > $1 LIMIT $2) AS outstanding",
    )
    .bind(now)
    .bind(limit)
    .fetch_one(c)
    .await?;
    if outstanding >= limit {
        return Err(Error::Capacity);
    }
    Ok(())
}
// Advisory read before any nonce reservation: refuses obvious unconfigured, full or
// stale-authority attempts without spending a reservation. It always rolls back. Concurrent,
// cancelled or later-refused attempts can still spend a permanent reservation each; the
// locked recheck in the insert transaction is authoritative.
async fn precheck(connection: &mut PgConnection, p: &Provider) -> Result<(), Error> {
    let mut tx = open(connection, true).await?;
    let result: Result<(), Error> = async {
        let limit = admission_limit(tx.connection()?, false).await?;
        p.persisted_binding(tx.connection()?).await?;
        let now = database_ms(tx.connection()?).await?;
        below_limit(tx.connection()?, now, limit).await
    }
    .await;
    tx.rollback().await.map_err(|_| Error::Database)?;
    result
}
async fn reserve_random(connection: &mut PgConnection, key: &str) -> Result<[u8; 12], Error> {
    for _ in 0..3 {
        let iv = random()?;
        if reserve(connection, key, &iv).await? {
            return Ok(iv);
        }
    }
    Err(Error::Protection)
}
const VERIFIER_BYTES: usize = 43;
const TAG_BYTES: usize = 16;
/// The two sealed formats, told apart by ciphertext length and bound by distinct
/// authenticated data, so neither opens as the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sealing {
    /// `aes256gcm-v1`: the PKCE verifier alone, 59 bytes. Opened for logins that started
    /// before migration 13 and never written. Such a login carries no invitation code.
    V1,
    /// `aes256gcm-v2`: verifier, one flag byte and 16 code bytes that are zero when the
    /// flag is zero. Always 76 bytes, so the length does not show whether a code was sent.
    V2,
}
impl Sealing {
    fn of(ciphertext: usize) -> Option<Self> {
        [Self::V1, Self::V2]
            .into_iter()
            .find(|sealing| sealing.ciphertext() == ciphertext)
    }
    fn ciphertext(self) -> usize {
        TAG_BYTES
            + match self {
                Self::V1 => VERIFIER_BYTES,
                Self::V2 => VERIFIER_BYTES + 1 + 16,
            }
    }
    /// The authenticated-data domain and the format label inside it.
    fn labels(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::V1 => (b"openmettle/login/1\0", b"aes256gcm-v1"),
            Self::V2 => (b"openmettle/login/2\0", b"aes256gcm-v2"),
        }
    }
}
/// The row fields that authenticate one sealed login (ADR 0009).
struct Envelope<'a> {
    id: &'a str,
    binding: &'a [u8],
    expiry: i64,
    state: &'a [u8],
    nonce: &'a [u8],
    caller: &'a [u8],
    key: &'a str,
}
impl Envelope<'_> {
    fn aad(&self, sealing: Sealing) -> Vec<u8> {
        let (domain, format) = sealing.labels();
        identity(
            domain,
            &[
                format,
                self.id.as_bytes(),
                self.binding,
                &self.expiry.to_be_bytes(),
                self.state,
                self.nonce,
                self.caller,
                self.key.as_bytes(),
            ],
        )
    }
    /// Seals under the envelope's key. `iv` must be a committed reservation for that key.
    fn seal(
        &self,
        sealing: Sealing,
        keys: &KeyRing,
        iv: [u8; 12],
        verifier: &str,
        invitation: Option<&InvitationCode>,
    ) -> Result<Vec<u8>, Error> {
        let mut sealed = verifier.as_bytes().to_vec();
        match sealing {
            // No code can be stored in this format.
            Sealing::V1 if invitation.is_some() => return Err(Error::Protection),
            Sealing::V1 => {}
            Sealing::V2 => {
                sealed.push(u8::from(invitation.is_some()));
                sealed.extend_from_slice(invitation.map_or(&[0; 16], |code| code.bytes()));
            }
        }
        keys.key(self.key)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(&self.aad(sealing)),
                &mut sealed,
            )
            .map_err(|_| Error::Protection)?;
        Ok(sealed)
    }
    /// Opens either format. Any other length, a failed tag, a malformed verifier, an unknown
    /// flag or code bytes without the flag are `Protection`.
    fn open(
        &self,
        keys: &KeyRing,
        iv: [u8; 12],
        mut sealed: Vec<u8>,
    ) -> Result<(Secret, Option<InvitationCode>), Error> {
        let sealing = Sealing::of(sealed.len()).ok_or(Error::Protection)?;
        let plain = keys
            .key(self.key)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(&self.aad(sealing)),
                &mut sealed,
            )
            .map_err(|_| Error::Protection)?;
        let (verifier, rest) = plain
            .split_at_checked(VERIFIER_BYTES)
            .ok_or(Error::Protection)?;
        let verifier = std::str::from_utf8(verifier).map_err(|_| Error::Protection)?;
        if !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(Error::Protection);
        }
        let invitation = match (sealing, rest) {
            (Sealing::V1, []) => None,
            (Sealing::V2, [flag, code @ ..]) => {
                let code: [u8; 16] = code.try_into().map_err(|_| Error::Protection)?;
                match *flag {
                    0 if code == [0; 16] => None,
                    1 => Some(InvitationCode::from_bytes(code)),
                    _ => return Err(Error::Protection),
                }
            }
            _ => return Err(Error::Protection),
        };
        Ok((Secret(verifier.into()), invitation))
    }
}

/// URL and caller secret must be delivered only to the initiating browser, after this operation.
/// They must never enter ordinary logs. Cookie transport is not implemented here.
#[derive(Debug)]
pub struct Started {
    pub authorization_url: Secret,
    pub state: Secret,
    pub caller_binding: Secret,
}

/// `invitation` is the code the person entered when starting this login, if any. It is
/// sealed with the PKCE verifier and reaches only the redemption function (ADR 0022).
pub async fn begin(
    connection: &mut PgConnection,
    provider: &Provider,
    keys: &KeyRing,
    lifetime: Duration,
    invitation: Option<&InvitationCode>,
) -> Result<Started, Error> {
    let start = begin_inner(
        connection,
        provider,
        keys,
        lifetime,
        invitation,
        Sealing::V2,
    );
    tokio::time::timeout(DEADLINE, start)
        .await
        .map_err(|_| Error::Database)?
}
/// A login as the release before migration 13 sealed it, for upgrade tests.
#[cfg(test)]
pub(crate) async fn begin_v1(
    connection: &mut PgConnection,
    provider: &Provider,
    keys: &KeyRing,
    lifetime: Duration,
) -> Result<Started, Error> {
    begin_inner(connection, provider, keys, lifetime, None, Sealing::V1).await
}
async fn begin_inner(
    connection: &mut PgConnection,
    p: &Provider,
    keys: &KeyRing,
    lifetime: Duration,
    invitation: Option<&InvitationCode>,
    sealing: Sealing,
) -> Result<Started, Error> {
    if !p.enabled || !(MIN_LOGIN_LIFETIME..=MAX_LOGIN_LIFETIME).contains(&lifetime) {
        return Err(Error::Configuration);
    }
    let id = secret()?;
    let state = Secret(format!("{}.{}", id.0, secret()?.0));
    let nonce = secret()?;
    let caller = secret()?;
    let verifier = secret()?;
    let key = &keys.keys[0].0;
    // Advisory: avoid spending a permanent reservation on obviously refused attempts.
    precheck(connection, p).await?;
    let iv = reserve_random(connection, key).await?;
    let mut tx = transaction(connection).await?;
    let result: Result<Started, Error> = async {
        // Authoritative admission: serialize on the singleton, then sample the primary clock
        // only after any lock wait, and count outstanding rows against the limit just read.
        let limit = admission_limit(tx.connection()?, true).await?;
        let now = database_ms(tx.connection()?).await?;
        below_limit(tx.connection()?, now, limit).await?;
        let expiry = now
            .checked_add(lifetime.as_millis() as i64)
            .ok_or(Error::Configuration)?;
        // Managed authority is read in this transaction, after the clock statement.
        let (binding, _) = p.persisted_binding(tx.connection()?).await?;
        let (state_hash, nonce_hash, caller_hash) =
            (hash(&state.0), hash(&nonce.0), hash(&caller.0));
        let envelope = Envelope {
            id: &id.0,
            binding: &binding,
            expiry,
            state: &state_hash,
            nonce: &nonce_hash,
            caller: &caller_hash,
            key,
        };
        let encrypted = envelope.seal(sealing, keys, iv, &verifier.0, invitation)?;
        sqlx::query("INSERT INTO openmettle.login_transactions (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(&id.0).bind(&binding).bind(expiry).bind(state_hash.as_slice()).bind(nonce_hash.as_slice())
            .bind(caller_hash.as_slice()).bind(key).bind(iv.as_slice()).bind(encrypted).execute(tx.connection()?).await?;
        let (_, issuer, client) = p.trusted.binding();
        let client = CoreClient::new(
            ClientId::new(client.into()),
            IssuerUrl::new(issuer.into()).map_err(|_| Error::Configuration)?,
            CoreJsonWebKeySet::new(vec![]),
        )
        .set_auth_uri(AuthUrl::new(p.authorization.clone()).map_err(|_| Error::Configuration)?)
        .set_redirect_uri(
            RedirectUrl::new(p.callback.clone()).map_err(|_| Error::Configuration)?,
        );
        let challenge =
            PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.0));
        let state_copy = state.0.clone();
        let (url, _, _) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                move || CsrfToken::new(state_copy),
                move || Nonce::new(nonce.0),
            )
            .set_pkce_challenge(challenge)
            .url();
        Ok(Started {
            authorization_url: Secret(url.to_string()),
            state,
            caller_binding: caller,
        })
    }
    .await;
    finish(tx, result).await
}

#[derive(Clone)]
pub(crate) struct LoginOrigin {
    pub login: String,
    pub expiry: i64,
    pub membership_revision: i64,
}

/// Parsed callback inputs, still untrusted. No Debug implementation.
pub struct Callback<'a> {
    pub state: &'a str,
    pub caller_binding: &'a str,
    pub issuer: &'a str,
    pub callback: &'a str,
    pub code: &'a str,
}
/// Created only after acknowledged consumption commit. Owns the code and exact provider.
pub struct ExchangePermit {
    pub(crate) origin: Option<LoginOrigin>,
    // The invitation code sealed with this login, for first-account redemption only.
    pub(crate) invitation: Option<InvitationCode>,
    provider: Arc<Provider>,
    // Managed only: the durable authority epoch committed with this consumption.
    epoch: Option<i64>,
    code: Secret,
    verifier: Secret,
    nonce: ExpectedNonceDigest,
}
impl fmt::Debug for ExchangePermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExchangePermit(..)")
    }
}
pub async fn consume(
    connection: &mut PgConnection,
    provider: Arc<Provider>,
    keys: &KeyRing,
    callback: Callback<'_>,
) -> Result<ExchangePermit, Error> {
    tokio::time::timeout(
        DEADLINE,
        consume_inner(connection, provider, keys, callback),
    )
    .await
    .map_err(|_| Error::Database)?
}
async fn consume_inner(
    connection: &mut PgConnection,
    p: Arc<Provider>,
    keys: &KeyRing,
    c: Callback<'_>,
) -> Result<ExchangePermit, Error> {
    if !p.enabled
        || c.issuer != p.trusted.binding().1
        || c.callback != p.callback
        || c.code.is_empty()
        || c.code.len() > MAX_CODE_BYTES
        || !c.code.bytes().all(|b| (0x21..0x7f).contains(&b))
        || c.state.len() != 87
        || c.caller_binding.len() != 43
    {
        return Err(Error::Rejected);
    }
    let (id, state_secret) = c.state.split_once('.').ok_or(Error::Rejected)?;
    if id.len() != 43
        || state_secret.len() != 43
        || !id
            .bytes()
            .chain(state_secret.bytes())
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(Error::Rejected);
    }
    let mut tx = transaction(connection).await?;
    // Rejections after the row lock await rollback; the permit escapes only after COMMIT.
    let result: Result<ExchangePermit, Error> = async {
        let row = sqlx::query("SELECT binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext,consumed FROM openmettle.login_transactions WHERE id=$1 FOR UPDATE")
            .bind(id).fetch_optional(tx.connection()?).await?.ok_or(Error::Rejected)?;
        // A separate statement AFTER the lock: neither the transaction-start time nor pre-wait snapshot.
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
                .fetch_one(tx.connection()?)
                .await?;
        let binding: Vec<u8> = row.try_get("binding")?;
        let expiry: i64 = row.try_get("expires_ms")?;
        let state: Vec<u8> = row.try_get("state_hash")?;
        let nonce: Vec<u8> = row.try_get("nonce_hash")?;
        let caller: Vec<u8> = row.try_get("caller_hash")?;
        // Managed authority is read only after the row lock, so a waiting consumer observes
        // provider revisions committed while it waited (ADR 0012).
        let (expected, epoch) = p.persisted_binding(tx.connection()?).await?;
        if row.try_get::<bool, _>("consumed")?
            || now >= expiry
            || binding != expected
            || !equal(&state, &hash(c.state))
            || !equal(&caller, &hash(c.caller_binding))
        {
            return Err(Error::Rejected);
        }
        let key: String = row.try_get("key_id")?;
        let iv: Vec<u8> = row.try_get("nonce")?;
        let encrypted: Vec<u8> = row
            .try_get::<Option<Vec<u8>>, _>("ciphertext")?
            .ok_or(Error::Protection)?;
        let envelope = Envelope {
            id,
            binding: &binding,
            expiry,
            state: &state,
            nonce: &nonce,
            caller: &caller,
            key: &key,
        };
        let iv: [u8; 12] = iv.try_into().map_err(|_| Error::Protection)?;
        let (verifier, invitation) = envelope.open(keys, iv, encrypted)?;
        // Owner edits serialize revision allocation and commit. This snapshot precedes
        // the one permitted token POST, so the sealed proof cannot cross a later reset.
        let membership_revision = if epoch.is_some() {
            sqlx::query_scalar("SELECT coalesce(max(config_revision),0) FROM openmettle.membership_observations")
                .fetch_one(tx.connection()?).await?
        } else { 0 };
        let permit = ExchangePermit {
            origin: Some(LoginOrigin {login:id.to_owned(),expiry,membership_revision}),
            invitation,
            provider: p,
            epoch,
            code: Secret(c.code.into()),
            verifier,
            nonce: ExpectedNonceDigest::new(nonce.try_into().map_err(|_| Error::Protection)?),
        };
        sqlx::query(
            "UPDATE openmettle.login_transactions SET consumed=true,ciphertext=NULL WHERE id=$1",
        )
        .bind(id)
        .execute(tx.connection()?)
        .await?;
        Ok(permit)
    }
    .await;
    finish(tx, result).await
}

type TokenClient = CoreClient<
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointSet,
>;
fn token_client(p: &Provider) -> Result<TokenClient, Error> {
    let (_, issuer, client) = p.trusted.binding();
    Ok(CoreClient::new(
        ClientId::new(client.into()),
        IssuerUrl::new(issuer.into()).map_err(|_| Error::Configuration)?,
        CoreJsonWebKeySet::new(vec![]),
    )
    .set_token_uri(TokenUrl::new(p.token.clone()).map_err(|_| Error::Configuration)?)
    .set_redirect_uri(RedirectUrl::new(p.callback.clone()).map_err(|_| Error::Configuration)?))
}
fn exchanged_token(
    response: openidconnect::core::CoreTokenResponse,
    nonce: ExpectedNonceDigest,
) -> Result<(UnverifiedIdToken, ExpectedNonceDigest), Error> {
    let token = response
        .extra_fields()
        .id_token()
        .ok_or(Error::Verification)?;
    // Serialization retains the original signing input, including additional nbf claims.
    Ok((
        UnverifiedIdToken::new(&token.to_string()).map_err(|_| Error::Verification)?,
        nonce,
    ))
}

impl ExchangePermit {
    /// Exactly one library request through a caller-supplied transport. The transport must not
    /// retry, spawn detached work or allocate unbounded bodies. Managed permits use exchange_with_keys.
    pub async fn exchange<'c, C>(
        self,
        http: &'c C,
        policy: &Policy,
        now: impl FnOnce() -> SystemTime,
    ) -> Result<VerifiedIdentity, Error>
    where
        C: AsyncHttpClient<'c>,
    {
        if self.provider.managed.is_some() {
            return Err(Error::Rejected);
        }
        let provider = self.provider.clone();
        let (token, nonce) = self.exchange_token(http).await?;
        provider
            .trusted
            .verify_digest(&token, &nonce, policy, now())
            .map_err(|_| Error::Verification)
    }
    /// Managed exchange. The result is sealed until `ManagedProvider::release` rechecks the
    /// committed provider authority and the in-memory configuration/key generation.
    pub async fn exchange_with_keys(
        self,
        provider: &crate::provider_keys::ManagedProvider,
        policy: &Policy,
    ) -> Result<crate::provider_keys::ExchangedIdentity, Error> {
        provider.exchange(self, policy).await
    }
    pub(crate) fn managed_config(&self) -> Option<&[u8]> {
        self.provider.managed.as_deref()
    }
    pub(crate) fn epoch(&self) -> Option<i64> {
        self.epoch
    }
    pub(crate) async fn exchange_token<'c, C>(
        self,
        http: &'c C,
    ) -> Result<(UnverifiedIdToken, ExpectedNonceDigest), Error>
    where
        C: AsyncHttpClient<'c>,
    {
        let client = token_client(&self.provider)?;
        let bounded = |request: HttpRequest| async move {
            let response = http.call(request).await.map_err(|_| Error::Exchange)?;
            if response.body().len() > MAX_RESPONSE_BYTES
                || response.headers().len() > 32
                || response
                    .headers()
                    .iter()
                    .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
                    .sum::<usize>()
                    > 8192
            {
                return Err(Error::Exchange);
            }
            Ok(response)
        };
        let response = tokio::time::timeout(
            DEADLINE,
            client
                .exchange_code(AuthorizationCode::new(self.code.0))
                .set_pkce_verifier(PkceCodeVerifier::new(self.verifier.0))
                .request_async(&bounded),
        )
        .await
        .map_err(|_| Error::Exchange)?
        .map_err(|_| Error::Exchange)?;
        exchanged_token(response, self.nonce)
    }
    // The concrete production transport enforces all bounds before library parsing. Keep this
    // path separate from the legacy injected-client adapter so its future remains Send.
    pub(crate) async fn request_token(
        self,
        http: &crate::provider_http::ProviderTransport,
    ) -> Result<(UnverifiedIdToken, ExpectedNonceDigest), Error> {
        let client = token_client(&self.provider)?;
        let response = tokio::time::timeout(
            DEADLINE,
            client
                .exchange_code(AuthorizationCode::new(self.code.0))
                .set_pkce_verifier(PkceCodeVerifier::new(self.verifier.0))
                .request_async(http),
        )
        .await
        .map_err(|_| Error::Exchange)?
        .map_err(|_| Error::Exchange)?;
        exchanged_token(response, self.nonce)
    }
}

#[cfg(test)]
#[path = "../tests/login_support/mod.rs"]
pub(crate) mod fixture;
#[cfg(test)]
pub(crate) fn fixture_permit(provider: Arc<Provider>, epoch: Option<i64>) -> ExchangePermit {
    ExchangePermit {
        origin: None,
        invitation: None,
        provider,
        epoch,
        code: Secret("synthetic-code".into()),
        verifier: Secret("v".repeat(43)),
        nonce: ExpectedNonceDigest::new(hash(&"n".repeat(43))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provider() -> Arc<Provider> {
        Arc::new(
            Provider::new(
                TrustedProvider::new(
                    fixture::ID,
                    fixture::ISSUER,
                    fixture::CLIENT,
                    &fixture::jwks(),
                )
                .unwrap(),
                ProviderDefinition {
                    revision: "v1",
                    authorization_endpoint: fixture::AUTH,
                    token_endpoint: fixture::TOKEN,
                    callback: fixture::CALLBACK,
                    destination: "home",
                    enabled: true,
                },
            )
            .unwrap(),
        )
    }
    fn permit() -> ExchangePermit {
        ExchangePermit {
            origin: None,
            invitation: None,
            provider: provider(),
            epoch: None,
            code: Secret("code".into()),
            verifier: Secret("v".repeat(43)),
            nonce: ExpectedNonceDigest::new(hash(&"n".repeat(43))),
        }
    }
    #[tokio::test]
    async fn exchange_preserves_all_verification_and_redacts_provider_errors() {
        for (issuer, aud, nonce, nbf, valid) in [
            (
                fixture::ISSUER,
                fixture::CLIENT,
                "n".repeat(43),
                1799999990,
                true,
            ),
            (
                "https://wrong.example.test",
                fixture::CLIENT,
                "n".repeat(43),
                1799999990,
                false,
            ),
            (fixture::ISSUER, "wrong", "n".repeat(43), 1799999990, false),
            (
                fixture::ISSUER,
                fixture::CLIENT,
                "x".repeat(43),
                1799999990,
                false,
            ),
            (
                fixture::ISSUER,
                fixture::CLIENT,
                "n".repeat(43),
                1800001000,
                false,
            ),
        ] {
            let token = fixture::signed(&nonce, issuer, aud, nbf);
            let http = |_: HttpRequest| {
                let token = token.clone();
                async move {
                    Ok::<_,Error>(openidconnect::http::Response::builder().status(200).header("content-type","application/json")
                    .body(serde_json::to_vec(&serde_json::json!({"access_token":"secret","token_type":"Bearer","id_token":token})).unwrap()).unwrap())
                }
            };
            assert_eq!(
                permit()
                    .exchange(&http, &Policy::default(), fixture::now)
                    .await
                    .is_ok(),
                valid
            );
        }
        for body in [
            br#"{"error":"invalid_grant","error_description":"SECRET-marker"}"#.to_vec(),
            vec![b'x'; MAX_RESPONSE_BYTES + 1],
        ] {
            let http = |_: HttpRequest| {
                let body = body.clone();
                async move {
                    Ok::<_, Error>(
                        openidconnect::http::Response::builder()
                            .status(400)
                            .body(body)
                            .unwrap(),
                    )
                }
            };
            let err = permit()
                .exchange(&http, &Policy::default(), fixture::now)
                .await
                .unwrap_err();
            assert_eq!(err, Error::Exchange);
            assert!(!format!("{err:?} {err}").contains("SECRET"));
        }
    }
    #[tokio::test]
    async fn fake_provider_enforces_challenge_and_callback() {
        let p = provider();
        let fake = fixture::FakeProvider::new();
        let verifier = "v".repeat(43);
        let nonce = "n".repeat(43);
        let challenge =
            PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.clone()));
        let mut url = openidconnect::url::Url::parse(fixture::AUTH).unwrap();
        url.query_pairs_mut().extend_pairs([
            ("client_id", fixture::CLIENT),
            ("redirect_uri", fixture::CALLBACK),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", "synthetic-state"),
            ("nonce", &nonce),
            ("code_challenge_method", "S256"),
            ("code_challenge", challenge.as_str()),
        ]);
        let code = fake.authorize(url.as_str(), "synthetic-state");
        let http = |request| std::future::ready(fake.exchange(request));
        let permit = ExchangePermit {
            origin: None,
            invitation: None,
            provider: p,
            epoch: None,
            code: Secret(code),
            verifier: Secret(verifier),
            nonce: ExpectedNonceDigest::new(hash(&nonce)),
        };
        assert!(
            permit
                .exchange(&http, &Policy::default(), fixture::now)
                .await
                .is_ok()
        );
        for mismatch in 0..3 {
            let code = fake.authorize(url.as_str(), "synthetic-state");
            let mut p = Arc::try_unwrap(provider()).unwrap();
            if mismatch == 1 {
                p.trusted = TrustedProvider::new(
                    fixture::ID,
                    fixture::ISSUER,
                    "wrong-client",
                    &fixture::jwks(),
                )
                .unwrap();
            }
            if mismatch == 2 {
                p.callback = "https://app.example.test/wrong".into();
            }
            let permit = ExchangePermit {
                origin: None,
                invitation: None,
                provider: Arc::new(p),
                epoch: None,
                code: Secret(code),
                verifier: Secret(if mismatch == 0 {
                    "x".repeat(43)
                } else {
                    "v".repeat(43)
                }),
                nonce: ExpectedNonceDigest::new(hash(&nonce)),
            };
            assert_eq!(
                permit
                    .exchange(&http, &Policy::default(), fixture::now)
                    .await
                    .unwrap_err(),
                Error::Exchange
            );
        }
    }
    #[tokio::test]
    async fn exchange_cancellation_does_not_retry_or_detach() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let entered = tokio::sync::Notify::new();
        let http = |_: HttpRequest| async {
            calls.fetch_add(1, Ordering::SeqCst);
            entered.notify_one();
            std::future::pending::<Result<openidconnect::HttpResponse, Error>>().await
        };
        let policy = Policy::default();
        let mut exchange = Box::pin(permit().exchange(&http, &policy, fixture::now));
        tokio::select! {
            _ = entered.notified() => (),
            _ = &mut exchange => panic!("pending transport completed"),
        }
        drop(exchange);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// The real TLS transport (ADR 0010) carries the library exchange to the fake provider.
    #[tokio::test]
    async fn real_tls_transport_exchanges_once_and_never_follows_redirects() {
        use crate::provider_http::fixture as tls;
        let ca = tls::Ca::new();
        let fake = Arc::new(fixture::FakeProvider::new());
        let relay = fake.clone();
        let server = tls::Server::start(ca.leaf(tls::HOST, false), move |received| {
            let request = openidconnect::http::Request::builder()
                .method("POST")
                .uri(fixture::TOKEN)
                .body(received.body.clone())
                .unwrap();
            match relay.exchange(request) {
                Ok(response) => tls::Reply::Bytes(tls::json(response.body())),
                Err(_) => tls::Reply::Bytes(tls::response(
                    400,
                    &[("content-type", "application/json")],
                    br#"{"error":"invalid_grant"}"#,
                )),
            }
        })
        .await;
        let verifier = "v".repeat(43);
        let nonce = "n".repeat(43);
        let challenge =
            PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.clone()));
        let mut url = openidconnect::url::Url::parse(fixture::AUTH).unwrap();
        url.query_pairs_mut().extend_pairs([
            ("client_id", fixture::CLIENT),
            ("redirect_uri", fixture::CALLBACK),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", "synthetic-state"),
            ("nonce", &nonce),
            ("code_challenge_method", "S256"),
            ("code_challenge", challenge.as_str()),
        ]);
        let permit = |token: String| {
            let mut p = Arc::try_unwrap(provider()).unwrap();
            p.token = token;
            ExchangePermit {
                origin: None,
                invitation: None,
                provider: Arc::new(p),
                epoch: None,
                code: Secret(fake.authorize(url.as_str(), "synthetic-state")),
                verifier: Secret(verifier.clone()),
                nonce: ExpectedNonceDigest::new(hash(&nonce)),
            }
        };
        let http = tls::transport(server.port, &ca);
        let identity = permit(tls::url(server.port))
            .exchange(&http, &Policy::default(), fixture::now)
            .await
            .unwrap();
        assert_eq!(identity.subject(), "synthetic-subject");
        assert_eq!(server.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        let target = tls::url(server.port);
        let redirect = tls::Server::start(ca.leaf(tls::HOST, false), move |_| {
            tls::Reply::Bytes(tls::response(307, &[("location", &target)], b""))
        })
        .await;
        let http = tls::transport(redirect.port, &ca);
        assert_eq!(
            permit(tls::url(redirect.port))
                .exchange(&http, &Policy::default(), fixture::now)
                .await
                .unwrap_err(),
            Error::Exchange
        );
        assert_eq!(
            redirect.requests.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            server.connections.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn provider_configuration_rejects_unsafe_urls_and_unbounded_names() {
        for bad in [
            "http://issuer.example.test",
            "https://user@issuer.example.test",
            "https://issuer.example.test/?q=x",
            "https://issuer.example.test/#x",
            "https://issuer.example.test/\\escape",
        ] {
            assert!(!https(bad));
        }
        assert!(!name(&"x".repeat(65)));
        assert!(!name(""));
        assert!(https(fixture::AUTH));
    }

    fn envelope() -> Envelope<'static> {
        Envelope {
            id: "id",
            binding: b"binding",
            expiry: 123,
            state: &[1; 32],
            nonce: &[2; 32],
            caller: &[3; 32],
            key: "active",
        }
    }
    /// Any plaintext sealed validly under one format's authenticated data.
    fn sealed_raw(sealing: Sealing, keys: &KeyRing, iv: [u8; 12], plain: &[u8]) -> Vec<u8> {
        let mut sealed = plain.to_vec();
        keys.key("active")
            .unwrap()
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(&envelope().aad(sealing)),
                &mut sealed,
            )
            .unwrap();
        sealed
    }

    #[test]
    fn sealed_login_carries_an_optional_invitation_code_at_one_length() {
        let keys = KeyRing::new(vec![("active".into(), [7; 32])]).unwrap();
        let (envelope, iv) = (envelope(), [9; 12]);
        let verifier = "v".repeat(43);
        let code = InvitationCode::parse(&"5a".repeat(16)).unwrap();
        let seal = |sealing, invitation| envelope.seal(sealing, &keys, iv, &verifier, invitation);
        let with = seal(Sealing::V2, Some(&code)).unwrap();
        let without = seal(Sealing::V2, None).unwrap();
        // One length either way: a stored row does not show whether a code was sent.
        assert_eq!((with.len(), without.len()), (76, 76));
        let (opened, invitation) = envelope.open(&keys, iv, with.clone()).unwrap();
        assert_eq!(opened.expose(), verifier);
        assert_eq!(invitation.unwrap().bytes(), code.bytes());
        let (opened, invitation) = envelope.open(&keys, iv, without.clone()).unwrap();
        assert_eq!(opened.expose(), verifier);
        assert!(invitation.is_none());

        // The previous format still opens, as a login without a code. It cannot hold one.
        let legacy = seal(Sealing::V1, None).unwrap();
        assert_eq!(legacy.len(), 59);
        let (opened, invitation) = envelope.open(&keys, iv, legacy.clone()).unwrap();
        assert_eq!(opened.expose(), verifier);
        assert!(invitation.is_none());
        assert_eq!(
            seal(Sealing::V1, Some(&code)).unwrap_err(),
            Error::Protection
        );

        let refused = |sealed: Vec<u8>| {
            assert_eq!(
                envelope.open(&keys, iv, sealed).unwrap_err(),
                Error::Protection
            );
        };
        // Every byte of every ciphertext is authenticated, and no other length is opened.
        for sealed in [&with, &without, &legacy] {
            for index in 0..sealed.len() {
                let mut tampered = sealed.clone();
                tampered[index] ^= 1;
                refused(tampered);
            }
            for length in [0, 16, 58, 60, 75, 77] {
                let mut resized = sealed.clone();
                resized.resize(length, 0);
                refused(resized);
            }
        }
        // Neither format opens as the other: the length selects the authenticated data, so
        // a v2 plaintext sealed under the v1 domain, or the reverse, fails its tag.
        let mut plain = verifier.clone().into_bytes();
        refused(sealed_raw(Sealing::V2, &keys, iv, &plain));
        plain.extend_from_slice(&[1; 17]);
        refused(sealed_raw(Sealing::V1, &keys, iv, &plain));
        // Control for the cases below: this helper's v2 output opens.
        let opened = envelope.open(&keys, iv, sealed_raw(Sealing::V2, &keys, iv, &plain));
        assert_eq!(opened.unwrap().1.unwrap().bytes(), &[1; 16]);
        // Authentic but malformed contents: an unknown flag, code bytes without the flag
        // and a verifier outside the base64url alphabet.
        for (index, byte) in [(43, 2), (43, 0), (0, b'!')] {
            let mut malformed = plain.clone();
            malformed[index] = byte;
            refused(sealed_raw(Sealing::V2, &keys, iv, &malformed));
        }
        // Another key ID or any other envelope field is not this login.
        let other = Envelope {
            expiry: 124,
            ..self::envelope()
        };
        assert_eq!(other.open(&keys, iv, with).unwrap_err(), Error::Protection);
    }

    /// A login sealed by the schema-12 release (c2c71f3) must still open after the upgrade.
    /// These bytes are AES-256-GCM over 43 `v` bytes with key `[7; 32]`, IV `[9; 12]` and
    /// c2c71f3's `aad()` for `envelope()`. They were computed outside this crate (Python
    /// `cryptography`), so a change to the v1 labels or field order fails here, even though
    /// sealing and opening would still agree with each other.
    #[test]
    fn a_login_sealed_by_the_schema_12_release_still_opens() {
        const SEALED_BY_V12: [u8; 59] = [
            0x51, 0xf3, 0xf2, 0xe2, 0xc8, 0x86, 0xb7, 0x17, 0xd6, 0x14, 0xbd, 0x4e, 0x90, 0x9c,
            0xd5, 0xa9, 0xa2, 0xc6, 0x15, 0x85, 0x42, 0x98, 0x81, 0xb6, 0x19, 0xd8, 0x30, 0xd0,
            0xa3, 0x02, 0x77, 0x0c, 0xa5, 0x93, 0x91, 0xb5, 0x94, 0x24, 0x5c, 0x66, 0x09, 0xc5,
            0xd3, 0x92, 0x44, 0x92, 0x0b, 0x36, 0x2c, 0x4b, 0x47, 0x71, 0x73, 0x21, 0xa9, 0x0f,
            0x74, 0x6f, 0x00,
        ];
        let keys = KeyRing::new(vec![("active".into(), [7; 32])]).unwrap();
        let verifier = "v".repeat(43);
        let (opened, invitation) = envelope()
            .open(&keys, [9; 12], SEALED_BY_V12.to_vec())
            .unwrap();
        assert_eq!(opened.expose(), verifier);
        assert!(invitation.is_none());
        // The test-only v1 writer used by the upgrade fixtures produces the same bytes.
        assert_eq!(
            envelope()
                .seal(Sealing::V1, &keys, [9; 12], &verifier, None)
                .unwrap(),
            SEALED_BY_V12
        );
    }

    #[test]
    fn secrets_carried_by_a_permit_stay_out_of_debug_output() {
        let mut permit = permit();
        permit.invitation = InvitationCode::parse(&"5a".repeat(16));
        assert!(permit.invitation.is_some());
        assert_eq!(format!("{permit:?}"), "ExchangePermit(..)");
    }

    #[test]
    fn aead_binds_every_field_and_keys() {
        let keys = KeyRing::new(vec![("active".into(), [7; 32])]).unwrap();
        for sealing in [Sealing::V1, Sealing::V2] {
            aead_binds(&keys, &envelope().aad(sealing));
        }
        // The two formats never share authenticated data.
        assert_ne!(envelope().aad(Sealing::V1), envelope().aad(Sealing::V2));
    }
    fn aead_binds(keys: &KeyRing, context: &[u8]) {
        let key = keys.key("active").unwrap();
        let iv = random::<12>().unwrap();
        let mut cipher = b"secret verifier".to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(context),
            &mut cipher,
        )
        .unwrap();
        for index in 0..context.len() {
            let mut wrong = context.to_vec();
            wrong[index] ^= 1;
            assert!(
                key.open_in_place(
                    aead::Nonce::assume_unique_for_key(iv),
                    aead::Aad::from(&wrong),
                    &mut cipher.clone()
                )
                .is_err()
            );
        }
        let mut bad = cipher.clone();
        bad[0] ^= 1;
        assert!(
            key.open_in_place(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(context),
                &mut bad
            )
            .is_err()
        );
        let rotated =
            KeyRing::new(vec![("new".into(), [8; 32]), ("active".into(), [7; 32])]).unwrap();
        assert!(
            rotated
                .key("active")
                .unwrap()
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(iv),
                    aead::Aad::from(context),
                    &mut cipher.clone()
                )
                .is_ok()
        );
        assert!(
            rotated
                .key("new")
                .unwrap()
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(iv),
                    aead::Aad::from(context),
                    &mut cipher
                )
                .is_err()
        );
        assert!(rotated.key("missing").is_err());
    }
}
