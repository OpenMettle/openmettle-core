//! Managed OIDC documents and key generations (ADR 0011). No routes, sessions or admission.
pub(crate) mod documents;
pub mod gateway;
use crate::{
    auth::{self, ExpectedNonceDigest, ProviderIdentity, UnverifiedIdToken, VerifiedIdentity},
    invitation::InvitationCode,
    login,
    provider_http::{ProviderDocuments, ProviderTransport, Trust},
    sessions::native::Attempt,
};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::Instant,
};

// Persisted managed binding: canonical configuration plus durable authority epoch (ADR 0012).
// Process registration generations never enter stored bytes.
const MANAGED_DOMAIN: &[u8] = b"openmettle/managed-login/2\0";
// Persisted native binding (ADR 0023): the same configuration and epoch with the native
// attempt digest between them, under its own domain. Migration 14 checks both layouts.
const NATIVE_DOMAIN: &[u8] = b"openmettle/native-managed-login/1\0";
const MAX_BINDING_BYTES: usize = 12 * 1024; // Existing migration 6 bytea constraint.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Capacity,
    Retired,
    Cooldown,
    Cancelled,
    Timeout,
    Fetch,
    Document,
    Mismatch,
    Unavailable,
    Verification,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid managed provider configuration",
            Self::Capacity => "provider capacity exhausted",
            Self::Retired => "provider configuration retired",
            Self::Cooldown => "provider refresh cooling down",
            Self::Cancelled => "provider refresh cancelled",
            Self::Timeout => "provider operation timed out",
            Self::Fetch => "provider document fetch failed",
            Self::Document => "provider document invalid",
            Self::Mismatch => "provider metadata inconsistent",
            Self::Unavailable => "fresh provider keys unavailable",
            Self::Verification => "provider token verification failed",
        })
    }
}
impl std::error::Error for Error {}
/// Default reuse window for a document that refuses caching (owner decision, #5, 19 November
/// 2026; ADR 0011 amendment).
pub const DEFAULT_UNCACHEABLE_REUSE: Duration = Duration::from_secs(60);
/// Largest reuse window an operator may set for a document that refuses caching.
pub const MAX_UNCACHEABLE_REUSE: Duration = Duration::from_secs(300);
/// Explicit deployment policy, with finite implementation ceilings. The only operational
/// default is the reuse window for documents that refuse caching.
#[derive(Clone, Copy, Debug)]
pub struct RefreshPolicy {
    freshness: Duration,
    cooldown: Duration,
    deadline: Duration,
    providers: usize,
    callers: usize,
    gets: usize,
    // Reuse window for `no-store`/`no-cache` documents, from the request, under `freshness`.
    uncacheable_reuse: Duration,
}
impl RefreshPolicy {
    /// The reuse window starts at [`DEFAULT_UNCACHEABLE_REUSE`], capped by `freshness` when
    /// the documents are fetched; [`Self::with_uncacheable_reuse`] sets it explicitly.
    pub fn new(
        freshness: Duration,
        cooldown: Duration,
        deadline: Duration,
        providers: usize,
        callers: usize,
        gets: usize,
    ) -> Result<Self, Error> {
        if !(Duration::from_secs(1)..=Duration::from_secs(86400)).contains(&freshness)
            || !(Duration::from_secs(1)..=Duration::from_secs(3600)).contains(&cooldown)
            || !(Duration::from_millis(10)..=Duration::from_secs(60)).contains(&deadline)
            || !(1..=64).contains(&providers)
            || !(1..=1024).contains(&callers)
            || !(1..=64).contains(&gets)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            freshness,
            cooldown,
            deadline,
            providers,
            callers,
            gets,
            uncacheable_reuse: DEFAULT_UNCACHEABLE_REUSE,
        })
    }
    /// An explicit reuse window for documents that refuse caching: 1 s to
    /// [`MAX_UNCACHEABLE_REUSE`], no shorter than the cooldown and no longer than freshness.
    /// A shorter window would leave the documents expired while cooldown still blocks the
    /// refresh, refusing sign-ins in between. A longer one would trust keys past the
    /// operator's freshness cap for every other document.
    pub fn with_uncacheable_reuse(self, reuse: Duration) -> Result<Self, Error> {
        // Cooldown is at least 1 s, so the lower bound also enforces the 1 s minimum.
        if !(self.cooldown..=self.freshness.min(MAX_UNCACHEABLE_REUSE)).contains(&reuse) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            uncacheable_reuse: reuse,
            ..self
        })
    }
}
/// Fully configured identity and endpoints. Construction performs no provider network requests.
pub struct ProviderConfig {
    identity: ProviderIdentity,
    revision: String,
    authorization: String,
    token_url: String,
    discovery_url: String,
    jwks_url: String,
    callback: String,
    destination: String,
    token: ProviderTransport,
    documents: ProviderDocuments,
    binding: Vec<u8>,
}
impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderConfig(..)")
    }
}
impl ProviderConfig {
    pub fn new(
        identity: ProviderIdentity,
        definition: login::ProviderDefinition<'_>,
        discovery: &str,
        jwks: &str,
        trust: Trust<'_>,
        private_ranges: &[&str],
    ) -> Result<Self, Error> {
        login::validate_definition(identity.binding().1, &definition)
            .map_err(|_| Error::Configuration)?;
        if !definition.enabled {
            return Err(Error::Configuration);
        }
        let token = ProviderTransport::new(definition.token_endpoint, trust, private_ranges)
            .map_err(|_| Error::Configuration)?;
        let documents = ProviderDocuments::configured(&token, discovery, jwks)
            .map_err(|_| Error::Configuration)?;
        let mut c = Self {
            identity,
            revision: definition.revision.into(),
            authorization: definition.authorization_endpoint.into(),
            token_url: definition.token_endpoint.into(),
            discovery_url: discovery.into(),
            jwks_url: jwks.into(),
            callback: definition.callback.into(),
            destination: definition.destination.into(),
            token,
            documents,
            binding: vec![],
        };
        c.binding = c.canonical_binding();
        if c.binding.len() + MANAGED_DOMAIN.len() + 24 > MAX_BINDING_BYTES {
            return Err(Error::Configuration);
        }
        Ok(c)
    }
    // Every deployment-authoritative input, without process generation or durable epoch.
    fn canonical_binding(&self) -> Vec<u8> {
        let (id, issuer, client) = self.identity.binding();
        crate::runs::identity(
            b"openmettle/login-provider/2\0",
            &[
                id.as_bytes(),
                issuer.as_bytes(),
                client.as_bytes(),
                self.revision.as_bytes(),
                self.authorization.as_bytes(),
                self.token_url.as_bytes(),
                self.discovery_url.as_bytes(),
                self.jwks_url.as_bytes(),
                self.callback.as_bytes(),
                self.destination.as_bytes(),
                b"browser",
                b"public-pkce",
                &self.token.policy_binding(),
            ],
        )
    }
    fn login(
        &self,
        snapshot: &Snapshot,
        native: Option<&Attempt>,
    ) -> Result<Arc<login::Provider>, Error> {
        let mut p = login::Provider::new(
            snapshot.trusted.clone(),
            login::ProviderDefinition {
                revision: &self.revision,
                authorization_endpoint: &self.authorization,
                token_endpoint: &self.token_url,
                callback: native.map_or(&self.callback, |n| &n.callback),
                destination: &self.destination,
                enabled: true,
            },
        )
        .map_err(|_| Error::Configuration)?;
        p.set_managed(self.binding.clone(), native.map(|n| n.binding));
        Ok(Arc::new(p))
    }
}
#[derive(Clone, Copy)]
struct Sample {
    wall: SystemTime,
    mono: Instant,
}
// Test-only release barrier: (point, reached, resume).
#[cfg(test)]
type Pause = (
    &'static str,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
);
struct Manager {
    policy: RefreshPolicy,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
    callers: Arc<Semaphore>,
    gets: Arc<Semaphore>,
    #[cfg(test)]
    release_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    pause: Mutex<Option<Pause>>,
    #[cfg(test)]
    clock: Mutex<Option<Arc<dyn Fn() -> Sample + Send + Sync>>>,
}
impl Manager {
    fn now(&self) -> Sample {
        #[cfg(test)]
        if let Some(clock) = self.clock.lock().unwrap().as_ref() {
            return clock();
        }
        Sample {
            wall: SystemTime::now(),
            mono: Instant::now(),
        }
    }
}
/// One owner per process deployment. Registration is bounded, including retired tombstones.
/// Re-registering a UUID preserves its refresh cooldown and outstanding flight; identical
/// configuration also preserves keys and handles. Durable authority is checked separately.
pub struct ProviderManager {
    inner: Arc<Manager>,
}
impl ProviderManager {
    pub fn new(policy: RefreshPolicy) -> Self {
        Self {
            inner: Arc::new(Manager {
                policy,
                entries: Mutex::new(HashMap::new()),
                callers: Arc::new(Semaphore::new(policy.callers)),
                gets: Arc::new(Semaphore::new(policy.gets)),
                #[cfg(test)]
                release_hook: Mutex::new(None),
                #[cfg(test)]
                pause: Mutex::new(None),
                #[cfg(test)]
                clock: Mutex::new(None),
            }),
        }
    }
    #[cfg(test)]
    pub(crate) fn policy(&self) -> RefreshPolicy {
        self.inner.policy
    }
    pub fn register(&self, config: ProviderConfig) -> Result<ManagedProvider, Error> {
        let mut entries = self.inner.entries.lock().unwrap();
        let id = config.identity.binding().0.to_owned();
        if !entries.contains_key(&id) && entries.len() >= self.inner.policy.providers {
            return Err(Error::Capacity);
        }
        let entry = entries
            .entry(id.clone())
            .or_insert_with(|| {
                Arc::new(Entry {
                    id,
                    issuer: config.identity.binding().1.to_owned(),
                    client: config.identity.binding().2.to_owned(),
                    state: Mutex::new(State {
                        generation: 0,
                        config: None,
                        snapshot: None,
                        key_generation: 0,
                        next: None,
                        flight: None,
                        last_wall: None,
                    }),
                })
            })
            .clone();
        if entry.issuer != config.identity.binding().1
            || entry.client != config.identity.binding().2
        {
            return Err(Error::Configuration);
        }
        let mut s = entry.state.lock().unwrap();
        // Identical canonical configuration is a no-op: keys, cooldown, any in-flight refresh
        // and existing handles survive. A change, or restoring after retirement, invalidates.
        if !s
            .config
            .as_ref()
            .is_some_and(|c| c.binding == config.binding)
        {
            s.generation = s.generation.checked_add(1).ok_or(Error::Configuration)?;
            s.config = Some(Arc::new(config));
            s.snapshot = None;
        }
        let generation = s.generation;
        drop(s);
        Ok(ManagedProvider {
            manager: self.inner.clone(),
            entry,
            generation,
            native: None,
        })
    }
    pub fn retire(&self, provider: &ManagedProvider) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.inner, &provider.manager) {
            return Err(Error::Retired);
        }
        let mut s = provider.entry.state.lock().unwrap();
        provider.active(&s)?;
        s.config = None;
        s.snapshot = None;
        Ok(())
    }
}
struct Entry {
    id: String,
    issuer: String,
    client: String,
    state: Mutex<State>,
}
struct State {
    generation: u64,
    config: Option<Arc<ProviderConfig>>,
    snapshot: Option<Arc<Snapshot>>,
    key_generation: u64,
    next: Option<Instant>,
    flight: Option<Arc<Flight>>,
    last_wall: Option<SystemTime>,
}
struct Snapshot {
    trusted: auth::TrustedProvider,
    kids: Vec<Option<String>>,
    known_kids: Vec<String>,
    expires: Instant,
    generation: u64,
}
struct Flight {
    result: watch::Sender<Option<Result<(), Error>>>,
}
// Sender remains alive in waiters; this guard must publish on every cancellation path.
struct Leader {
    entry: Arc<Entry>,
    flight: Arc<Flight>,
    done: bool,
}
impl Leader {
    fn finish(&mut self, result: Result<(), Error>) {
        let mut s = self.entry.state.lock().unwrap();
        if s.flight
            .as_ref()
            .is_some_and(|f| Arc::ptr_eq(f, &self.flight))
        {
            s.flight = None;
        }
        self.flight.result.send_replace(Some(result));
        self.done = true;
    }
}
impl Drop for Leader {
    fn drop(&mut self) {
        if !self.done {
            self.finish(Err(Error::Cancelled));
        }
    }
}
/// Generation-bound handle. Old handles cannot fetch, publish or release identity after replacement.
#[derive(Clone)]
pub struct ManagedProvider {
    native: Option<Arc<Attempt>>,
    manager: Arc<Manager>,
    entry: Arc<Entry>,
    generation: u64,
}
impl fmt::Debug for ManagedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedProvider(..)")
    }
}
impl ManagedProvider {
    /// This provider for one native attempt. Its logins use the attempt's upstream callback
    /// and store the native binding, so no other handle can consume or exchange them.
    pub(crate) fn native_handle(&self, attempt: Attempt) -> Self {
        Self {
            native: Some(Arc::new(attempt)),
            ..self.clone()
        }
    }
    pub(crate) fn check_active(&self) -> Result<(), Error> {
        self.active(&self.entry.state.lock().unwrap()).map(|_| ())
    }
    /// The canonical configuration binding, for a native registration digest. Refused when
    /// the stored native binding built from it would exceed the login row's limit.
    pub(crate) fn registration_binding(&self) -> Result<Vec<u8>, Error> {
        let binding = self.config()?.binding.clone();
        if persisted(&binding, Some(&[0; 32]), 0).len() > MAX_BINDING_BYTES {
            return Err(Error::Configuration);
        }
        Ok(binding)
    }
    fn attempt(&self) -> Option<&[u8; 32]> {
        self.native.as_ref().map(|n| &n.binding)
    }

    fn active<'a>(&self, s: &'a State) -> Result<&'a Arc<ProviderConfig>, Error> {
        if s.generation != self.generation {
            return Err(Error::Retired);
        }
        s.config.as_ref().ok_or(Error::Retired)
    }
    fn admission(&self) -> Result<OwnedSemaphorePermit, Error> {
        self.manager
            .callers
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)
    }
    fn snapshot(&self) -> Result<Arc<Snapshot>, Error> {
        let mut s = self.entry.state.lock().unwrap();
        self.active(&s)?;
        let now = self.manager.now();
        if s.last_wall.is_some_and(|last| now.wall < last) {
            return Err(Error::Unavailable);
        }
        s.last_wall = Some(now.wall);
        s.snapshot
            .as_ref()
            .filter(|v| now.mono < v.expires && !v.kids.is_empty())
            .cloned()
            .ok_or(Error::Unavailable)
    }
    fn config(&self) -> Result<Arc<ProviderConfig>, Error> {
        Ok(self.active(&self.entry.state.lock().unwrap())?.clone())
    }
    pub async fn preflight(&self) -> Result<(), Error> {
        let _admission = self.admission()?;
        let deadline = Instant::now() + self.manager.policy.deadline;
        tokio::time::timeout_at(deadline, self.ensure())
            .await
            .map_err(|_| Error::Timeout)??;
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    async fn ensure(&self) -> Result<Arc<Snapshot>, Error> {
        if let Ok(s) = self.snapshot() {
            return Ok(s);
        }
        self.refresh(None).await?;
        self.snapshot()
    }
    async fn refresh(&self, observed: Option<u64>) -> Result<(), Error> {
        let (config, flight, leader) = {
            let mut s = self.entry.state.lock().unwrap();
            let config = self.active(&s)?.clone();
            // A completed concurrent replacement is enough; never fetch again for this token.
            if observed.is_some_and(|g| g != s.key_generation) {
                return Ok(());
            }
            if let Some(f) = &s.flight {
                (config, f.clone(), false)
            } else {
                let now = self.manager.now().mono;
                if s.next.is_some_and(|n| now < n) {
                    return Err(Error::Cooldown);
                }
                s.next = Some(now + self.manager.policy.cooldown);
                let (tx, _) = watch::channel(None);
                let f = Arc::new(Flight { result: tx });
                s.flight = Some(f.clone());
                (config, f, true)
            }
        };
        if !leader {
            let mut rx = flight.result.subscribe();
            loop {
                if let Some(result) = *rx.borrow_and_update() {
                    return result;
                }
                rx.changed().await.map_err(|_| Error::Cancelled)?;
            }
        }
        let mut guard = Leader {
            entry: self.entry.clone(),
            flight,
            done: false,
        };
        let result = self.fetch(&config).await;
        guard.finish(result);
        result
    }
    async fn document(
        &self,
        c: &ProviderConfig,
        jwks: bool,
    ) -> Result<(openidconnect::HttpResponse, Option<Instant>), Error> {
        self.config()?;
        let _slot = self
            .manager
            .gets
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)?;
        let start = self.manager.now();
        let response = if jwks {
            c.documents.fetch_jwks().await
        } else {
            c.documents.fetch_discovery().await
        }
        .map_err(|_| Error::Fetch)?;
        let end = self.manager.now();
        documents::media(&response, jwks)?;
        let delay = end
            .mono
            .checked_duration_since(start.mono)
            .ok_or(Error::Unavailable)?;
        let policy = self.manager.policy;
        let fresh = documents::freshness(
            &response,
            start.wall,
            end.wall,
            delay,
            policy.freshness,
            policy.uncacheable_reuse,
        )
        .and_then(|v| end.mono.checked_add(v));
        Ok((response, fresh))
    }
    async fn fetch(&self, c: &ProviderConfig) -> Result<(), Error> {
        let (metadata, metadata_expiry) = self.document(c, false).await?;
        if let Err(e) = documents::metadata(metadata.body(), c) {
            if e == Error::Mismatch {
                let mut s = self.entry.state.lock().unwrap();
                self.active(&s)?;
                s.snapshot = None;
            }
            return Err(e);
        }
        if metadata_expiry.is_none() {
            let mut s = self.entry.state.lock().unwrap();
            self.active(&s)?;
            s.snapshot = None;
            return Err(Error::Unavailable);
        }
        let (jwks, key_expiry) = self.document(c, true).await?;
        let keys = documents::keys(jwks.body())?;
        let mut s = self.entry.state.lock().unwrap();
        self.active(&s)?;
        s.key_generation = s
            .key_generation
            .checked_add(1)
            .ok_or(Error::Configuration)?;
        // A valid replacement always retires old keys, even if it cannot be cached.
        s.snapshot = match metadata_expiry.zip(key_expiry) {
            Some((m, k)) => Some(Arc::new(Snapshot {
                trusted: c.identity.with_keys(keys.keys),
                kids: keys.kids,
                known_kids: keys.known_kids,
                expires: m.min(k),
                generation: s.key_generation,
            })),
            None => None,
        };
        Ok(())
    }
    async fn verify(
        &self,
        token: &UnverifiedIdToken,
        nonce: &ExpectedNonceDigest,
        policy: &auth::Policy,
    ) -> Result<(u64, auth::VerifiedAssertion), Error> {
        let first = self.ensure().await?;
        let header = token.header().map_err(|_| Error::Verification)?;
        let kid = match header.get("kid") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .filter(|v| v.len() <= 256 && !v.contains('\0'))
                    .ok_or(Error::Verification)?,
            ),
        };
        let result = first
            .trusted
            .verify_assertion(token, nonce, policy, self.manager.now().wall);
        if matches!(result, Err(auth::VerifyError::UnknownKey))
            && kid.is_some_and(|k| !first.known_kids.iter().any(|known| known == k))
        {
            self.refresh(Some(first.generation)).await?;
            let snapshot = self.snapshot()?;
            let verified = snapshot
                .trusted
                .verify_assertion(token, nonce, policy, self.manager.now().wall)
                .map_err(|_| Error::Verification)?;
            Ok((snapshot.generation, verified))
        } else {
            Ok((first.generation, result.map_err(|_| Error::Verification)?))
        }
    }
    /// In-memory linearization: no stale config, removed key generation, expired qualification,
    /// spent deadline or expired token escapes. Callers perform every await before this.
    fn finish(
        &self,
        key_generation: u64,
        assertion: auth::VerifiedAssertion,
        deadline: Instant,
    ) -> Result<VerifiedIdentity, Error> {
        self.check_assertion(key_generation, &assertion, deadline)?;
        assertion
            .release(self.manager.now().wall)
            .map_err(|_| Error::Verification)
    }
    fn check_assertion(
        &self,
        key_generation: u64,
        assertion: &auth::VerifiedAssertion,
        deadline: Instant,
    ) -> Result<crate::sessions::ProofBudget, Error> {
        #[cfg(test)]
        self.before_release();
        let mut s = self.entry.state.lock().unwrap();
        self.active(&s)?;
        let now = self.manager.now();
        if s.last_wall.is_some_and(|last| now.wall < last) {
            return Err(Error::Unavailable);
        }
        s.last_wall = Some(now.wall);
        let snapshot = s
            .snapshot
            .as_ref()
            .filter(|v| v.generation == key_generation && now.mono < v.expires)
            .ok_or(Error::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        assertion.check(now.wall).map_err(|_| Error::Verification)?;
        let remaining = assertion
            .remaining(now.wall)
            .map_err(|_| Error::Verification)?;
        // The assertion's own age is reported apart from this process's key freshness and
        // operation deadline, which never bound a stored native grant (ADR 0023).
        Ok(crate::sessions::ProofBudget {
            assertion: remaining,
            process: remaining
                .min(snapshot.expires - now.mono)
                .min(deadline.saturating_duration_since(Instant::now())),
        })
    }
    /// The configured provider UUID this handle was registered under.
    pub(crate) fn id(&self) -> &str {
        &self.entry.id
    }
    /// The issuer this provider UUID is fixed to.
    pub(crate) fn issuer(&self) -> &str {
        &self.entry.issuer
    }
    /// The exact registered callback of the active configuration. A retired or replaced
    /// handle refuses.
    pub(crate) fn callback(&self) -> Result<String, Error> {
        Ok(self.config()?.callback.clone())
    }
    // Begin and consume share four phases with the pooled service (ADR 0016), so neither path
    // repeats a check. The caller-owned connection API below runs them back to back; the
    // pooled service waits for a connection between `fresh` and `login_provider`.
    /// Manager admission and the deadline that bounds the whole phase: preflight, any wait
    /// for a pooled connection and the database work.
    pub(crate) fn login_phase(&self) -> Result<(OwnedSemaphorePermit, Instant), login::Error> {
        let admission = self.admission().map_err(|_| login::Error::Rejected)?;
        Ok((admission, Instant::now() + self.manager.policy.deadline))
    }
    /// Managed preflight. It may fetch provider documents and needs no database connection.
    pub(crate) async fn fresh(&self) -> Result<(), login::Error> {
        self.ensure().await.map_err(|_| login::Error::Rejected)?;
        Ok(())
    }
    /// Active configuration with unexpired keys inside the phase deadline. No network or
    /// database work, so it is also the validity check after a wait and before any write.
    pub(crate) fn login_provider(
        &self,
        deadline: Instant,
    ) -> Result<Arc<login::Provider>, login::Error> {
        let snapshot = self.snapshot().map_err(|_| login::Error::Rejected)?;
        let config = self.config().map_err(|_| login::Error::Rejected)?;
        if Instant::now() >= deadline {
            return Err(login::Error::Rejected);
        }
        config
            .login(&snapshot, self.native.as_deref())
            .map_err(|_| login::Error::Configuration)
    }
    /// After the database work: keys still fresh and the phase deadline unspent.
    pub(crate) fn confirm(&self, deadline: Instant) -> Result<(), login::Error> {
        self.snapshot().map_err(|_| login::Error::Rejected)?;
        if Instant::now() >= deadline {
            return Err(login::Error::Rejected);
        }
        Ok(())
    }
    /// `invitation` is the code the person entered for a first sign-in, if any (ADR 0022).
    pub async fn begin(
        &self,
        connection: &mut sqlx::PgConnection,
        keys: &login::KeyRing,
        lifetime: Duration,
        invitation: Option<&InvitationCode>,
    ) -> Result<login::Started, login::Error> {
        let (_admission, deadline) = self.login_phase()?;
        tokio::time::timeout_at(deadline, async {
            self.fresh().await?;
            let p = self.login_provider(deadline)?;
            let started = login::begin(connection, &p, keys, lifetime, invitation).await?;
            self.confirm(deadline)?;
            Ok(started)
        })
        .await
        .map_err(|_| login::Error::Rejected)?
    }
    pub async fn consume(
        &self,
        connection: &mut sqlx::PgConnection,
        keys: &login::KeyRing,
        callback: login::Callback<'_>,
    ) -> Result<login::ExchangePermit, login::Error> {
        let (_admission, deadline) = self.login_phase()?;
        tokio::time::timeout_at(deadline, async {
            self.fresh().await?;
            let p = self.login_provider(deadline)?;
            let permit = login::consume(connection, p, keys, callback).await?;
            self.confirm(deadline)?;
            Ok(permit)
        })
        .await
        .map_err(|_| login::Error::Rejected)?
    }
    /// One code POST and signature verification. No database connection is held during the
    /// POST; the sealed result keeps the original deadline and cannot yield an identity until
    /// `release` rechecks committed authority and in-memory generations.
    pub(crate) async fn exchange(
        &self,
        mut permit: login::ExchangePermit,
        policy: &auth::Policy,
    ) -> Result<ExchangedIdentity, login::Error> {
        let _admission = self.admission().map_err(|_| login::Error::Rejected)?;
        let deadline = Instant::now() + self.manager.policy.deadline;
        tokio::time::timeout_at(deadline, async {
            self.ensure()
                .await
                .map_err(|_| login::Error::Verification)?;
            let c = self.config().map_err(|_| login::Error::Rejected)?;
            let epoch = permit.epoch().ok_or(login::Error::Rejected)?;
            if permit.managed_config() != Some(c.binding.as_slice())
                || permit.native_attempt() != self.attempt()
            {
                return Err(login::Error::Rejected);
            }
            // No await between active-config check and starting the one permitted token POST.
            let origin = permit.origin.clone();
            let invitation = permit.invitation.take();
            let (token, nonce) = permit.request_token(&c.token).await?;
            let (key_generation, assertion) = self
                .verify(&token, &nonce, policy)
                .await
                .map_err(|_| login::Error::Verification)?;
            Ok(ExchangedIdentity {
                native_binding: self.attempt().copied(),
                origin,
                invitation,
                entry: self.entry.clone(),
                generation: self.generation,
                key_generation,
                epoch,
                deadline,
                assertion,
            })
        })
        .await
        .map_err(|_| login::Error::Exchange)?
    }
    /// Release a verified identity. Authority linearizes at the snapshot of its single
    /// READ COMMITTED read: a retirement or revision committed before that snapshot refuses;
    /// one committed afterward, even before this returns, is ordered after the release.
    /// Future session creation must recheck and serialize authority inside its own transaction.
    pub async fn release(
        &self,
        connection: &mut sqlx::PgConnection,
        exchanged: ExchangedIdentity,
    ) -> Result<VerifiedIdentity, login::Error> {
        if !Arc::ptr_eq(&self.entry, &exchanged.entry)
            || self.generation != exchanged.generation
            || self.attempt() != exchanged.native_binding.as_ref()
        {
            return Err(login::Error::Rejected);
        }
        let _admission = self.admission().map_err(|_| login::Error::Rejected)?;
        let deadline = exchanged.deadline;
        tokio::time::timeout_at(deadline, async {
            let config = self.config().map_err(|_| login::Error::Rejected)?;
            #[cfg(test)]
            self.pause("before-authority").await;
            let epoch = read_authority(connection, &config).await?;
            #[cfg(test)]
            self.pause("after-authority").await;
            if epoch != exchanged.epoch {
                return Err(login::Error::Rejected);
            }
            self.finish(exchanged.key_generation, exchanged.assertion, deadline)
                .map_err(|e| match e {
                    Error::Timeout => login::Error::Exchange,
                    _ => login::Error::Verification,
                })
        })
        .await
        .map_err(|_| login::Error::Exchange)?
    }
    /// Consume a managed online proof for an approved identity or an invited new account.
    /// Offline VerifiedIdentity values cannot reach this operation. Issuance commits on
    /// `issuance`, an `openmettle_issuance` connection; the credential is released only after
    /// a fresh validation on `primary`, an `openmettle_api` connection (ADR 0030).
    pub async fn issue_session(
        &self,
        issuance: &mut sqlx::PgConnection,
        primary: &mut sqlx::PgConnection,
        exchanged: ExchangedIdentity,
        policy: &crate::sessions::Policy,
    ) -> Result<crate::sessions::Credential, crate::sessions::Error> {
        let (_admission, deadline) = self.session_phase(&exchanged, policy)?;
        let issued = self
            .issue_admitted(issuance, &exchanged, policy, deadline)
            .await?;
        self.release_issued(primary, &exchanged, issued)
            .await?
            .browser()
    }
    /// Handle binding, manager admission and the issuance deadline: the proof's original
    /// exchange deadline, further limited by the session operation deadline from now. The
    /// pooled service (ADR 0016) computes it before waiting for a connection, so a wait
    /// never starts a new window.
    pub(crate) fn session_phase(
        &self,
        exchanged: &ExchangedIdentity,
        policy: &crate::sessions::Policy,
    ) -> Result<(OwnedSemaphorePermit, Instant), crate::sessions::Error> {
        use crate::sessions::Error as SessionError;
        if !Arc::ptr_eq(&self.entry, &exchanged.entry)
            || self.generation != exchanged.generation
            || self.attempt() != exchanged.native_binding.as_ref()
        {
            return Err(SessionError::Rejected);
        }
        let admission = self.admission().map_err(|_| SessionError::Rejected)?;
        let deadline = exchanged.deadline.min(Instant::now() + policy.deadline());
        Ok((admission, deadline))
    }
    /// Issuance under a held `session_phase` admission, on an issuance connection.
    /// `deadline` bounds the transaction and, through the result, the postcommit
    /// validation of [`Self::release_issued`]; the proof keeps its own original deadline in
    /// every in-memory check.
    pub(crate) async fn issue_admitted(
        &self,
        connection: &mut sqlx::PgConnection,
        exchanged: &ExchangedIdentity,
        policy: &crate::sessions::Policy,
        deadline: Instant,
    ) -> Result<crate::sessions::Issued, crate::sessions::Error> {
        use crate::sessions::{self, Error as SessionError};
        let config = self.config().map_err(|_| SessionError::Rejected)?;
        let origin = exchanged.origin.as_ref().ok_or(SessionError::Rejected)?;
        let identity = exchanged.assertion.identity();
        let (provider, issuer, client) = config.identity.binding();
        if identity.provider_config_id() != provider || identity.issuer() != issuer {
            return Err(SessionError::Rejected);
        }
        sessions::issue(
            connection,
            sessions::Issuance {
                provider,
                issuer,
                client,
                revision: &config.revision,
                assertion: &exchanged.assertion,
                epoch: exchanged.epoch,
                login: &origin.login,
                login_expiry: origin.expiry,
                membership_revision: origin.membership_revision,
                binding: persisted(&config.binding, self.attempt(), exchanged.epoch),
                native: self.native.as_deref(),
                deadline,
                invitation: exchanged.invitation.as_ref(),
            },
            policy,
            || self.proof_budget(exchanged),
        )
        .await
    }
    /// The postcommit validation that gates a committed issuance, on a primary connection
    /// acquired after the issuance connection was settled (ADR 0030).
    pub(crate) async fn release_issued(
        &self,
        primary: &mut sqlx::PgConnection,
        exchanged: &ExchangedIdentity,
        issued: crate::sessions::Issued,
    ) -> Result<crate::sessions::Delivery, crate::sessions::Error> {
        issued
            .release(primary, || self.proof_budget(exchanged))
            .await
    }
    fn proof_budget(
        &self,
        exchanged: &ExchangedIdentity,
    ) -> Result<crate::sessions::ProofBudget, crate::sessions::Error> {
        self.check_assertion(
            exchanged.key_generation,
            &exchanged.assertion,
            exchanged.deadline,
        )
        .map_err(|_| crate::sessions::Error::Rejected)
    }
    #[cfg(test)]
    async fn pause(&self, point: &'static str) {
        let barrier = self
            .manager
            .pause
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(at, _, _)| *at == point)
            .map(|(_, reached, resume)| (reached.clone(), resume.clone()));
        if let Some((reached, resume)) = barrier {
            reached.notify_one();
            resume.notified().await;
        }
    }
    #[cfg(test)]
    fn before_release(&self) {
        let hook = self.manager.release_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}

/// Sealed managed exchange result. Not cloneable, no public identity accessor. `release`
/// converts it after authority checks; `issue_session` consumes it under local approval.
pub struct ExchangedIdentity {
    // The native attempt of the handle that exchanged this proof, if any (ADR 0023).
    native_binding: Option<[u8; 32]>,
    origin: Option<login::LoginOrigin>,
    // The invitation code sealed with the originating login, if the person entered one. It
    // is passed only to first-account redemption (ADR 0022).
    invitation: Option<InvitationCode>,
    entry: Arc<Entry>,
    generation: u64,
    key_generation: u64,
    epoch: i64,
    deadline: Instant,
    assertion: auth::VerifiedAssertion,
}
impl fmt::Debug for ExchangedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExchangedIdentity(..)")
    }
}

/// Stored managed transaction binding: canonical configuration bytes plus durable epoch. A
/// native login also carries its 32-byte attempt digest, under a separate domain, so neither
/// layout reads as the other. `redeem_home_invitation` (migration 14) checks these exact bytes.
pub(crate) fn persisted(config: &[u8], attempt: Option<&[u8; 32]>, epoch: i64) -> Vec<u8> {
    let epoch = epoch.to_be_bytes();
    match attempt {
        None => crate::runs::identity(MANAGED_DOMAIN, &[config, &epoch]),
        Some(attempt) => crate::runs::identity(NATIVE_DOMAIN, &[config, attempt, &epoch]),
    }
}

// One statement: the latest committed revision row for this provider and its stable identity.
const AUTHORITY: &str = "SELECT r.epoch, r.revision, p.issuer, p.client_id
    FROM openmettle.login_providers AS p
    JOIN LATERAL (SELECT epoch, revision FROM openmettle.login_provider_revisions
                  WHERE provider_id = p.id ORDER BY epoch DESC LIMIT 1) AS r ON true
    WHERE p.id = $1::uuid";

/// Current committed authority epoch for exactly this provider identity and revision.
/// Missing, retired (NULL), different revision, issuer or client all refuse. The caller owns
/// the transaction; the epoch is the latest committed under the statement's snapshot. The
/// database records revisions, not the full configuration binding, which stays deployment-owned.
pub(crate) async fn authority(
    connection: &mut sqlx::PgConnection,
    id: &str,
    issuer: &str,
    client: &str,
    revision: &str,
) -> Result<i64, login::Error> {
    let row: Option<(i64, Option<String>, String, String)> = sqlx::query_as(AUTHORITY)
        .bind(id)
        .fetch_optional(connection)
        .await?;
    match row {
        Some((epoch, Some(r), i, c))
            if epoch > 0 && r == revision && i == issuer && c == client =>
        {
            Ok(epoch)
        }
        _ => Err(login::Error::Rejected),
    }
}

// A fresh root, read-only READ COMMITTED transaction with bounded lock/statement time. It never
// joins a caller's transaction or snapshot. Drop on cancellation hands rollback to SQLx.
async fn read_authority(
    connection: &mut sqlx::PgConnection,
    c: &ProviderConfig,
) -> Result<i64, login::Error> {
    let mut tx = crate::runs::WriteTransaction::begin_bounded(connection, true)
        .await
        .map_err(|error| match error {
            crate::runs::Error::Invalid => login::Error::Rejected,
            other => other.into(),
        })?;
    let (id, issuer, client) = c.identity.binding();
    let epoch = authority(tx.connection()?, id, issuer, client, &c.revision).await;
    match epoch {
        Ok(epoch) => {
            tx.commit().await?;
            Ok(epoch)
        }
        Err(e) => {
            tx.rollback().await?;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests;
