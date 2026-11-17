//! Managed OIDC documents and key generations (ADR 0011). No routes, sessions or admission.
pub(crate) mod documents;
use crate::{
    auth::{self, ExpectedNonceDigest, ProviderIdentity, UnverifiedIdToken, VerifiedIdentity},
    login,
    provider_http::{ProviderDocuments, ProviderTransport, Trust},
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

const REGISTRATION_DOMAIN: &[u8] = b"openmettle/managed-registration/1\0";
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
/// Explicit deployment policy, with finite implementation ceilings and no operational defaults.
#[derive(Clone, Copy, Debug)]
pub struct RefreshPolicy {
    freshness: Duration,
    cooldown: Duration,
    deadline: Duration,
    providers: usize,
    callers: usize,
    gets: usize,
}
impl RefreshPolicy {
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
        login::validate_definition(&identity, &definition).map_err(|_| Error::Configuration)?;
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
        let (id, issuer, client) = c.identity.binding();
        c.binding = crate::runs::identity(
            b"openmettle/login-provider/2\0",
            &[
                id.as_bytes(),
                issuer.as_bytes(),
                client.as_bytes(),
                c.revision.as_bytes(),
                c.authorization.as_bytes(),
                c.token_url.as_bytes(),
                c.discovery_url.as_bytes(),
                c.jwks_url.as_bytes(),
                c.callback.as_bytes(),
                c.destination.as_bytes(),
                b"browser",
                b"public-pkce",
                &c.token.policy_binding(),
            ],
        );
        if c.binding.len() + REGISTRATION_DOMAIN.len() + 24 > MAX_BINDING_BYTES {
            return Err(Error::Configuration);
        }
        Ok(c)
    }
    fn login(&self, snapshot: &Snapshot) -> Result<Arc<login::Provider>, Error> {
        let mut p = login::Provider::new(
            snapshot.trusted.clone(),
            login::ProviderDefinition {
                revision: &self.revision,
                authorization_endpoint: &self.authorization,
                token_endpoint: &self.token_url,
                callback: &self.callback,
                destination: &self.destination,
                enabled: true,
            },
        )
        .map_err(|_| Error::Configuration)?;
        p.set_managed_binding(self.binding.clone());
        Ok(Arc::new(p))
    }
}
#[derive(Clone, Copy)]
struct Sample {
    wall: SystemTime,
    mono: Instant,
}
struct Manager {
    policy: RefreshPolicy,
    entries: Mutex<HashMap<String, Arc<Entry>>>,
    callers: Arc<Semaphore>,
    gets: Arc<Semaphore>,
    #[cfg(test)]
    release_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
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
/// Re-registering a UUID preserves its refresh cooldown and outstanding flight.
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
                clock: Mutex::new(None),
            }),
        }
    }
    pub fn register(&self, config: ProviderConfig) -> Result<ManagedProvider, Error> {
        let mut entries = self.inner.entries.lock().unwrap();
        let id = config.identity.binding().0.to_owned();
        if !entries.contains_key(&id) && entries.len() >= self.inner.policy.providers {
            return Err(Error::Capacity);
        }
        let entry = entries
            .entry(id)
            .or_insert_with(|| {
                Arc::new(Entry {
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
        s.generation = s.generation.checked_add(1).ok_or(Error::Configuration)?;
        let mut config = config;
        config.binding = crate::runs::identity(
            REGISTRATION_DOMAIN,
            &[&config.binding, &s.generation.to_be_bytes()],
        );
        s.config = Some(Arc::new(config));
        s.snapshot = None;
        let generation = s.generation;
        drop(s);
        Ok(ManagedProvider {
            manager: self.inner.clone(),
            entry,
            generation,
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
        let fresh = documents::freshness(
            &response,
            start.wall,
            end.wall,
            delay,
            self.manager.policy.freshness,
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
        deadline: Instant,
    ) -> Result<VerifiedIdentity, Error> {
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
        let (snapshot, identity) = if matches!(result, Err(auth::VerifyError::UnknownKey))
            && kid.is_some_and(|k| !first.known_kids.iter().any(|known| known == k))
        {
            self.refresh(Some(first.generation)).await?;
            let snapshot = self.snapshot()?;
            let verified = snapshot
                .trusted
                .verify_assertion(token, nonce, policy, self.manager.now().wall)
                .map_err(|_| Error::Verification)?;
            (snapshot, verified)
        } else {
            (first, result.map_err(|_| Error::Verification)?)
        };
        #[cfg(test)]
        self.before_release();
        // Linearization point: no stale config, removed generation or expired qualification escapes.
        let mut s = self.entry.state.lock().unwrap();
        self.active(&s)?;
        let now = self.manager.now();
        if s.last_wall.is_some_and(|last| now.wall < last) {
            return Err(Error::Unavailable);
        }
        s.last_wall = Some(now.wall);
        if s.snapshot
            .as_ref()
            .is_none_or(|v| v.generation != snapshot.generation || now.mono >= v.expires)
        {
            return Err(Error::Unavailable);
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        identity.release(now.wall).map_err(|_| Error::Verification)
    }
    pub async fn begin(
        &self,
        connection: &mut sqlx::PgConnection,
        keys: &login::KeyRing,
        lifetime: Duration,
    ) -> Result<login::Started, login::Error> {
        let _admission = self.admission().map_err(|_| login::Error::Rejected)?;
        let deadline = Instant::now() + self.manager.policy.deadline;
        tokio::time::timeout_at(deadline, async {
            let snapshot = self.ensure().await.map_err(|_| login::Error::Rejected)?;
            let config = self.config().map_err(|_| login::Error::Rejected)?;
            let p = config
                .login(&snapshot)
                .map_err(|_| login::Error::Configuration)?;
            let started = login::begin(connection, &p, keys, lifetime).await?;
            self.snapshot().map_err(|_| login::Error::Rejected)?;
            if Instant::now() >= deadline {
                return Err(login::Error::Rejected);
            }
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
        let _admission = self.admission().map_err(|_| login::Error::Rejected)?;
        let deadline = Instant::now() + self.manager.policy.deadline;
        tokio::time::timeout_at(deadline, async {
            let snapshot = self.ensure().await.map_err(|_| login::Error::Rejected)?;
            let config = self.config().map_err(|_| login::Error::Rejected)?;
            let p = config
                .login(&snapshot)
                .map_err(|_| login::Error::Configuration)?;
            let permit = login::consume(connection, p, keys, callback).await?;
            self.snapshot().map_err(|_| login::Error::Rejected)?;
            if Instant::now() >= deadline {
                return Err(login::Error::Rejected);
            }
            Ok(permit)
        })
        .await
        .map_err(|_| login::Error::Rejected)?
    }
    pub(crate) async fn exchange(
        &self,
        permit: login::ExchangePermit,
        policy: &auth::Policy,
    ) -> Result<VerifiedIdentity, login::Error> {
        let _admission = self.admission().map_err(|_| login::Error::Rejected)?;
        let deadline = Instant::now() + self.manager.policy.deadline;
        tokio::time::timeout_at(deadline, async {
            self.ensure()
                .await
                .map_err(|_| login::Error::Verification)?;
            let c = self.config().map_err(|_| login::Error::Rejected)?;
            if permit.managed_binding() != Some(c.binding.as_slice()) {
                return Err(login::Error::Rejected);
            }
            // No await between active-config check and starting the one permitted token POST.
            let (token, nonce) = permit.request_token(&c.token).await?;
            self.verify(&token, &nonce, policy, deadline)
                .await
                .map_err(|_| login::Error::Verification)
        })
        .await
        .map_err(|_| login::Error::Exchange)?
    }
    #[cfg(test)]
    fn before_release(&self) {
        let hook = self.manager.release_hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}

#[cfg(test)]
mod tests;
