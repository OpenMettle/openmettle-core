//! The pooled browser-auth service (ADR 0016) without PostgreSQL: provider selection and the
//! order of provider work and pool checkout. A local listener that never speaks the PostgreSQL
//! protocol stands in for the database, so a checkout attempt is observable as a connection.
use super::*;
use crate::{
    auth_config::AuthConfig,
    browser_auth::{BrowserAuth, Error},
    sessions,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

/// The service over this harness's manager and fixture provider. Test trust only.
pub(super) fn browser_auth(
    h: &Harness,
    pool: sqlx::PgPool,
    login_lifetime: Duration,
    session_policy: sessions::Policy,
) -> BrowserAuth {
    BrowserAuth::new(
        AuthConfig::fixture(
            login::KeyRing::new(vec![("active".into(), [7; 32])]).unwrap(),
            login_lifetime,
            session_policy,
            ProviderManager {
                inner: h.manager.inner.clone(),
            },
            vec![h.provider.clone()],
        ),
        pool,
    )
}
fn assert_send<T: Send>(_: &T) {}

#[tokio::test]
async fn provider_work_precedes_checkout_and_refusals_never_check_out() {
    let database = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    database.set_nonblocking(true).unwrap();
    let attempted = || database.accept().is_ok();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(300))
        .connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(database.local_addr().unwrap().port())
                .username("fixture")
                .database("fixture")
                .ssl_mode(PgSslMode::Disable),
        );
    let h = Harness::new().await;
    let policy = sessions::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(5));
    let auth = browser_auth(&h, pool, Duration::from_secs(300), policy.unwrap());
    let callback = || login::Callback {
        state: "synthetic-state",
        caller_binding: "synthetic-binding",
        issuer: signing::ISSUER,
        callback: signing::CALLBACK,
        code: "synthetic-code",
    };
    // Route handlers need Send futures.
    assert_send(&auth.begin(signing::ID));
    assert_send(&auth.complete(signing::ID, callback()));
    assert_send(&auth.validate("synthetic"));
    assert_send(&auth.logout("synthetic"));
    // Only configured identifiers select a provider: no provider request and no checkout.
    let unknown = "00000000-0000-4000-8000-000000000000";
    for id in [unknown, signing::ISSUER, ""] {
        assert_eq!(
            auth.begin(id).await.unwrap_err(),
            Error::Login(login::Error::Rejected)
        );
        assert!(matches!(
            auth.complete(id, callback()).await,
            Err(Error::Login(login::Error::Rejected))
        ));
    }
    // A malformed credential is refused before any checkout.
    assert!(matches!(
        auth.validate("malformed").await,
        Err(Error::Session(sessions::Error::Rejected))
    ));
    assert_eq!(
        auth.logout("malformed").await.unwrap_err(),
        Error::Session(sessions::Error::Rejected)
    );
    assert_eq!(h.count(), 0);
    assert!(!attempted());
    // A failed preflight ends the phase before any checkout.
    h.script.lock().unwrap().mode = "failure";
    assert_eq!(
        auth.begin(signing::ID).await.unwrap_err(),
        Error::Login(login::Error::Rejected)
    );
    assert_eq!(h.count(), 1);
    assert!(!attempted());
    // After a successful preflight (both documents fetched) the checkout is attempted. The
    // stand-in never answers, so pool acquisition fails as a database error, not a retry.
    h.script.lock().unwrap().mode = "ok";
    h.advance(2);
    assert_eq!(
        auth.begin(signing::ID).await.unwrap_err(),
        Error::Login(login::Error::Database)
    );
    assert_eq!(h.count(), 3);
    assert!(attempted());
}
