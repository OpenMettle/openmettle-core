//! Internal managed browser-auth service over the API's primary PostgreSQL pool (ADR 0016)
//! and its separate session issuance pool (ADR 0030).
//!
//! It joins validated settings ([`AuthConfig`], ADR 0015) to the existing managed login and
//! session operations and owns every pooled connection those operations use. The service
//! itself has no cookie or request handling; [`handoff`] holds the browser adapter
//! (ADR 0017) and [`router`] its bounded Axum router (ADRs 0018 and 0019). The API constructs
//! the service and mounts that router only when `OPENMETTLE_API_AUTH_CONFIG` names a
//! version-2 settings document (ADR 0025); by default nothing constructs either.
//! [`native`] provides the separate native code handoff. The API mounts it over the same
//! service only when that document also names a native profile (ADR 0029).
pub mod handoff;
pub mod native;
pub mod router;
use crate::{
    auth_config::AuthConfig,
    invitation::InvitationCode,
    login,
    provider_keys::{ExchangedIdentity, ManagedProvider},
    sessions,
};
use sqlx::{Connection, PgConnection, PgPool, Postgres, pool::PoolConnection};
use std::fmt;

/// The existing fixed, redacted categories, unchanged. An identifier that is not configured
/// is `Login(Rejected)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Login(login::Error),
    Session(sessions::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login(error) => error.fmt(f),
            Self::Session(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<login::Error> for Error {
    fn from(error: login::Error) -> Self {
        Self::Login(error)
    }
}
impl From<sessions::Error> for Error {
    fn from(error: sessions::Error) -> Self {
        Self::Session(error)
    }
}

/// One pooled connection owned by one database phase. An unused checkout returns to the
/// pool. From the first [`Checkout::lend`] the connection is closed when the guard drops,
/// unless [`Checkout::settle`] recorded a completed transaction or an acknowledged rollback.
/// Cancellation, a timeout, a panic and every early return therefore discard a connection
/// whose protocol or transaction state is unknown.
///
/// The guard is always created inside the future that the phase deadline wraps, so an
/// elapsed deadline drops it together with the cancelled borrow. The `/v1` routes use the
/// same guard for their authorization reads and writes (ADR 0027 PR4b).
pub(crate) struct Checkout {
    connection: PoolConnection<Postgres>,
    in_doubt: bool,
}
impl Checkout {
    pub(crate) async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        Ok(Self {
            connection: pool.acquire().await?,
            in_doubt: false,
        })
    }
    /// Lends the connection to database work. It stays in doubt until settled.
    pub(crate) fn lend(&mut self) -> &mut PgConnection {
        self.in_doubt = true;
        &mut self.connection
    }
    /// Ends the phase. `reusable` requires an acknowledgement for every transaction the helper
    /// opened. The depth check rejects a tracked open transaction. SQLx can clear its tracked
    /// depth while a rollback is still queued, so safe reuse depends on the helper's outcome.
    pub(crate) fn settle(mut self, reusable: bool) {
        self.in_doubt = !reusable || self.connection.is_in_transaction();
    }
}
impl Drop for Checkout {
    fn drop(&mut self) {
        if self.in_doubt {
            // SQLx sends Terminate from a task on its own runtime and keeps this pool slot
            // counted until that close ends (5 s limit). `detach` would free the slot at
            // once and let the pool exceed its configured size.
            self.connection.close_on_drop();
        }
    }
}

// Reuse is decided from the returned category alone. Each arm was checked against the
// helper it classifies; a new variant must be classified here before it compiles.
fn login_settled<T>(result: &Result<T, login::Error>) -> bool {
    use login::Error::{
        Capacity, Configuration, Database, Exchange, Protection, Random, Rejected, Unconfigured,
        Verification,
    };
    match result {
        // Every transaction the helper opened committed and was acknowledged.
        Ok(_) => true,
        // Returned before any statement, between transactions, or after an awaited ROLLBACK
        // whose failure would have been reported as `Database` instead.
        Err(Configuration | Random | Rejected | Protection | Capacity | Unconfigured) => true,
        // Statement, commit or cleanup failure, or the helper's own timeout: state unknown.
        Err(Database) => false,
        // Never produced by begin or consume; an unexpected category is not trusted.
        Err(Exchange | Verification) => false,
    }
}
fn session_settled<T>(result: &Result<T, sessions::Error>) -> bool {
    use sessions::Error::{Capacity, Configuration, Database, Random, Rejected, Timeout};
    match result {
        Ok(_) => true,
        // As above: no statement sent, or an awaited ROLLBACK or COMMIT was acknowledged.
        Err(Configuration | Rejected | Capacity | Random) => true,
        // `Timeout` also covers a cancelled statement; `Database` covers failed cleanup.
        Err(Database | Timeout) => false,
    }
}

/// One byte of a plain URL path: RFC 3986 unreserved characters and `/`.
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"/-._~".contains(&b)
}

/// Exact match against configured provider UUIDs. Nothing else selects a provider. The
/// service and the handoff's settings check (also run offline, ADR 0020) share this lookup.
fn configured<'a>(providers: &'a [ManagedProvider], id: &str) -> Option<&'a ManagedProvider> {
    providers.iter().find(|provider| provider.id() == id)
}

/// Managed browser login and local sessions for the configured providers.
///
/// Construct it once per process with the loaded settings, a handle to the API's existing
/// primary pool and one to its issuance pool. It opens no pool of its own and holds a pooled
/// connection only while database work runs: never across a provider document fetch or the
/// token request, and never one from each pool at once.
pub struct BrowserAuth {
    config: AuthConfig,
    pool: PgPool,
    issuance: PgPool,
}
impl fmt::Debug for BrowserAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrowserAuth(..)")
    }
}
impl BrowserAuth {
    /// `pool` must connect to the primary (ADR 0012) as `openmettle_api`, and `issuance` to
    /// the same primary as a login role of `openmettle_issuance` (ADR 0030). The issuance
    /// pool runs only session issuance; everything else, including the validation that
    /// releases a new credential, uses `pool`. The settings keep their single
    /// process-lifetime provider manager (ADR 0011).
    pub fn new(config: AuthConfig, pool: PgPool, issuance: PgPool) -> Self {
        Self {
            config,
            pool,
            issuance,
        }
    }
    fn provider(&self, id: &str) -> Result<&ManagedProvider, login::Error> {
        configured(self.config.providers(), id).ok_or(login::Error::Rejected)
    }

    /// Starts a login for one configured provider. Deliver the result only to the
    /// initiating browser (ADR 0009). `invitation` is the code the person entered for a first
    /// sign-in, if any. It is sealed with the login and never returned (ADR 0022).
    pub async fn begin(
        &self,
        provider: &str,
        invitation: Option<InvitationCode>,
    ) -> Result<login::Started, Error> {
        Ok(self.start(self.provider(provider)?, invitation).await?)
    }
    /// Completes a callback: committed single-use consumption, then exactly one token
    /// request, then session issuance from the sealed proof. No step is retried; after any
    /// failure, cancellation or uncertain commit the login must be restarted.
    pub async fn complete(
        &self,
        provider: &str,
        callback: login::Callback<'_>,
    ) -> Result<sessions::Credential, Error> {
        let provider = self.provider(provider)?;
        let permit = self.consume(provider, callback).await?;
        // The consumption checkout is already settled and dropped: no pooled connection is
        // held during the token request or a following key refresh.
        let exchanged = permit
            .exchange_with_keys(provider, self.config.token_policy())
            .await?;
        Ok(self.issue(provider, exchanged).await?)
    }
    /// Local validation on the primary. No provider is contacted.
    pub async fn validate(&self, credential: &str) -> Result<sessions::Context, Error> {
        Ok(self.validate_effect(credential, None).await?.into_context())
    }

    pub(crate) async fn validate_effect(
        &self,
        credential: &str,
        native_audience: Option<[u8; 32]>,
    ) -> Result<crate::authz::approvals::EffectSession, sessions::Error> {
        let policy = self.config.session_policy();
        sessions::well_formed(credential)?;
        tokio::time::timeout(policy.deadline(), async {
            let mut db = Checkout::acquire(&self.pool).await?;
            let result = crate::authz::approvals::EffectSession::validate(
                db.lend(),
                credential,
                policy,
                native_audience,
            )
            .await;
            db.settle(session_settled(&result));
            result
        })
        .await
        .map_err(|_| sessions::Error::Timeout)?
    }
    /// Local revocation by possession of the credential. No provider is contacted.
    pub async fn logout(&self, credential: &str) -> Result<(), Error> {
        let policy = self.config.session_policy();
        sessions::well_formed(credential)?;
        let result = tokio::time::timeout(policy.deadline(), async {
            let mut db = Checkout::acquire(&self.pool).await?;
            let result = sessions::logout(db.lend(), credential, policy).await;
            db.settle(session_settled(&result));
            result
        })
        .await
        .map_err(|_| sessions::Error::Timeout)?;
        Ok(result?)
    }

    // Stages. Each takes the manager admission first, so waiters for a pooled connection
    // are bounded by the configured caller capacity, and creates its checkout inside the
    // future its deadline wraps.
    // Every login start takes the optional invitation code, so a new start path (the native
    // one, block C) must decide where the person enters it.
    pub(crate) async fn start(
        &self,
        provider: &ManagedProvider,
        invitation: Option<InvitationCode>,
    ) -> Result<login::Started, login::Error> {
        let (_admission, deadline) = provider.login_phase()?;
        tokio::time::timeout_at(deadline, async {
            provider.fresh().await?;
            let mut db = Checkout::acquire(&self.pool).await?;
            // Checked after the wait for a connection and before any write.
            let login = provider.login_provider(deadline)?;
            let result = login::begin(
                db.lend(),
                &login,
                self.config.keys(),
                self.config.login_lifetime(),
                invitation.as_ref(),
            )
            .await;
            db.settle(login_settled(&result));
            let started = result?;
            provider.confirm(deadline)?;
            Ok(started)
        })
        .await
        .map_err(|_| login::Error::Rejected)?
    }
    pub(crate) async fn consume(
        &self,
        provider: &ManagedProvider,
        callback: login::Callback<'_>,
    ) -> Result<login::ExchangePermit, login::Error> {
        let (_admission, deadline) = provider.login_phase()?;
        tokio::time::timeout_at(deadline, async {
            provider.fresh().await?;
            let mut db = Checkout::acquire(&self.pool).await?;
            let login = provider.login_provider(deadline)?;
            let result = login::consume(db.lend(), login, self.config.keys(), callback).await;
            db.settle(login_settled(&result));
            let permit = result?;
            provider.confirm(deadline)?;
            Ok(permit)
        })
        .await
        .map_err(|_| login::Error::Rejected)?
    }
    pub(crate) async fn issue(
        &self,
        provider: &ManagedProvider,
        exchanged: ExchangedIdentity,
    ) -> Result<sessions::Credential, sessions::Error> {
        self.issue_delivery(provider, exchanged).await?.browser()
    }
    pub(crate) async fn issue_delivery(
        &self,
        provider: &ManagedProvider,
        exchanged: ExchangedIdentity,
    ) -> Result<sessions::Delivery, sessions::Error> {
        let policy = self.config.session_policy();
        // Fixed before the wait: pool pressure never opens a new window for the proof.
        let (_admission, deadline) = provider.session_phase(&exchanged, policy)?;
        tokio::time::timeout_at(deadline, async {
            // The issuance checkout is settled, and so returned or closed, before the primary
            // checkout is requested: no phase waits on one pool while holding the other.
            let mut db = Checkout::acquire(&self.issuance).await?;
            let result = provider
                .issue_admitted(db.lend(), &exchanged, policy, deadline)
                .await;
            db.settle(session_settled(&result));
            let issued = result?;
            let mut db = Checkout::acquire(&self.pool).await?;
            let result = provider.release_issued(db.lend(), &exchanged, issued).await;
            db.settle(session_settled(&result));
            result
        })
        .await
        .map_err(|_| sessions::Error::Timeout)?
    }
}

#[cfg(test)]
mod tests;
