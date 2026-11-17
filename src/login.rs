//! Internal browser login transactions (ADR 0009). No route, session or admission decision.
use crate::auth::{
    ExpectedNonceDigest, Policy, TrustedProvider, UnverifiedIdToken, VerifiedIdentity,
};
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

const FORMAT: &[u8] = b"aes256gcm-v1";
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_CODE_BYTES: usize = 4096;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Random,
    Database,
    Rejected,
    Protection,
    Exchange,
    Verification,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
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
pub struct Provider {
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
            trusted,
            revision: d.revision.into(),
            authorization: d.authorization_endpoint.into(),
            token: d.token_endpoint.into(),
            callback: d.callback.into(),
            destination: d.destination.into(),
            enabled: d.enabled,
        })
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
        if keys.is_empty() || keys.len() > 4 {
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
    let mut tx = WriteTransaction::begin(connection).await?;
    sqlx::query("SET LOCAL synchronous_commit = on")
        .execute(tx.connection()?)
        .await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(tx.connection()?)
        .await?;
    sqlx::query("SET LOCAL lock_timeout = '2s'")
        .execute(tx.connection()?)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '3s'")
        .execute(tx.connection()?)
        .await?;
    Ok(tx)
}

// Its own root commit: never seal before this succeeds. Reservations have no delete privilege.
async fn reserve(connection: &mut PgConnection, key: &str, iv: &[u8; 12]) -> Result<bool, Error> {
    let mut tx = transaction(connection).await?;
    let inserted = sqlx::query("INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ($1,$2) ON CONFLICT DO NOTHING")
        .bind(key).bind(iv.as_slice()).execute(tx.connection()?).await?.rows_affected() == 1;
    tx.commit().await?;
    Ok(inserted)
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
fn aad(
    id: &str,
    binding: &[u8],
    expiry: i64,
    state: &[u8],
    nonce: &[u8],
    caller: &[u8],
    key: &str,
) -> Vec<u8> {
    identity(
        b"openmettle/login/1\0",
        &[
            FORMAT,
            id.as_bytes(),
            binding,
            &expiry.to_be_bytes(),
            state,
            nonce,
            caller,
            key.as_bytes(),
        ],
    )
}

/// URL and caller secret must be delivered only to the initiating browser, after this operation.
/// They must never enter ordinary logs. Cookie transport is not implemented here.
#[derive(Debug)]
pub struct Started {
    pub authorization_url: Secret,
    pub state: Secret,
    pub caller_binding: Secret,
}

pub async fn begin(
    connection: &mut PgConnection,
    provider: &Provider,
    keys: &KeyRing,
    lifetime: Duration,
) -> Result<Started, Error> {
    tokio::time::timeout(DEADLINE, begin_inner(connection, provider, keys, lifetime))
        .await
        .map_err(|_| Error::Database)?
}
async fn begin_inner(
    connection: &mut PgConnection,
    p: &Provider,
    keys: &KeyRing,
    lifetime: Duration,
) -> Result<Started, Error> {
    if !p.enabled || lifetime < Duration::from_secs(1) || lifetime > Duration::from_secs(600) {
        return Err(Error::Configuration);
    }
    let id = secret()?;
    let state = Secret(format!("{}.{}", id.0, secret()?.0));
    let nonce = secret()?;
    let caller = secret()?;
    let verifier = secret()?;
    let key = &keys.keys[0].0;
    let iv = reserve_random(connection, key).await?;
    let mut tx = transaction(connection).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(tx.connection()?)
            .await?;
    let expiry = now
        .checked_add(lifetime.as_millis() as i64)
        .ok_or(Error::Configuration)?;
    let binding = p.binding();
    let (state_hash, nonce_hash, caller_hash) = (hash(&state.0), hash(&nonce.0), hash(&caller.0));
    let context = aad(
        &id.0,
        &binding,
        expiry,
        &state_hash,
        &nonce_hash,
        &caller_hash,
        key,
    );
    let mut encrypted = verifier.0.as_bytes().to_vec();
    keys.key(key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(&context),
            &mut encrypted,
        )
        .map_err(|_| Error::Protection)?;
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
    .set_redirect_uri(RedirectUrl::new(p.callback.clone()).map_err(|_| Error::Configuration)?);
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
    tx.commit().await?;
    Ok(Started {
        authorization_url: Secret(url.to_string()),
        state,
        caller_binding: caller,
    })
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
    provider: Arc<Provider>,
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
    if row.try_get::<bool, _>("consumed")?
        || now >= expiry
        || binding != p.binding()
        || !equal(&state, &hash(c.state))
        || !equal(&caller, &hash(c.caller_binding))
    {
        return Err(Error::Rejected);
    }
    let key: String = row.try_get("key_id")?;
    let iv: Vec<u8> = row.try_get("nonce")?;
    let mut encrypted: Vec<u8> = row
        .try_get::<Option<Vec<u8>>, _>("ciphertext")?
        .ok_or(Error::Protection)?;
    if encrypted.len() != 59 {
        return Err(Error::Protection);
    }
    let context = aad(id, &binding, expiry, &state, &nonce, &caller, &key);
    let iv: [u8; 12] = iv.try_into().map_err(|_| Error::Protection)?;
    let decrypt_key = keys.key(&key)?;
    let plain = decrypt_key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(&context),
            &mut encrypted,
        )
        .map_err(|_| Error::Protection)?;
    let verifier = std::str::from_utf8(plain).map_err(|_| Error::Protection)?;
    if verifier.len() != 43
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(Error::Protection);
    }
    let permit = ExchangePermit {
        provider: p,
        code: Secret(c.code.into()),
        verifier: Secret(verifier.into()),
        nonce: ExpectedNonceDigest::new(nonce.try_into().map_err(|_| Error::Protection)?),
    };
    sqlx::query(
        "UPDATE openmettle.login_transactions SET consumed=true,ciphertext=NULL WHERE id=$1",
    )
    .bind(id)
    .execute(tx.connection()?)
    .await?;
    tx.commit().await?;
    Ok(permit)
}

impl ExchangePermit {
    /// Exactly one library request through a caller-supplied transport. The transport must not
    /// retry, spawn detached work or allocate unbounded bodies. No production adapter exists.
    pub async fn exchange<'c, C>(
        self,
        http: &'c C,
        policy: &Policy,
        now: impl FnOnce() -> SystemTime,
    ) -> Result<VerifiedIdentity, Error>
    where
        C: AsyncHttpClient<'c>,
    {
        let p = self.provider;
        let (_, issuer, client) = p.trusted.binding();
        let client = CoreClient::new(
            ClientId::new(client.into()),
            IssuerUrl::new(issuer.into()).map_err(|_| Error::Configuration)?,
            CoreJsonWebKeySet::new(vec![]),
        )
        .set_token_uri(TokenUrl::new(p.token.clone()).map_err(|_| Error::Configuration)?)
        .set_redirect_uri(RedirectUrl::new(p.callback.clone()).map_err(|_| Error::Configuration)?);
        let bounded = |request: HttpRequest| async {
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
        let token = response
            .extra_fields()
            .id_token()
            .ok_or(Error::Verification)?;
        // Library serialization retains original signing_input, including unrecognized nbf.
        let token = UnverifiedIdToken::new(&token.to_string()).map_err(|_| Error::Verification)?;
        p.trusted
            .verify_digest(&token, &self.nonce, policy, now())
            .map_err(|_| Error::Verification)
    }
}

#[cfg(test)]
#[path = "../tests/login_support/mod.rs"]
mod fixture;
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
            provider: provider(),
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
            provider: p,
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
                provider: Arc::new(p),
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

    #[test]
    fn aead_binds_every_field_and_keys() {
        let keys = KeyRing::new(vec![("active".into(), [7; 32])]).unwrap();
        let context = aad(
            "id", b"binding", 123, &[1; 32], &[2; 32], &[3; 32], "active",
        );
        let key = keys.key("active").unwrap();
        let iv = random::<12>().unwrap();
        let mut cipher = b"secret verifier".to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(&context),
            &mut cipher,
        )
        .unwrap();
        for index in 0..context.len() {
            let mut wrong = context.clone();
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
                aead::Aad::from(&context),
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
                    aead::Aad::from(&context),
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
                    aead::Aad::from(&context),
                    &mut cipher
                )
                .is_err()
        );
        assert!(rotated.key("missing").is_err());
    }
}
