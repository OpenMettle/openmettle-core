//! Session check and logout routes (ADR 0019) through actual Axum dispatch on a loopback
//! listener, without PostgreSQL. The fixture provider's request count and the silent database
//! stand-in show which requests reached the service: a pooled checkout attempt is one
//! accepted connection, and it fails as a database error.
use super::handoff::{ORIGIN, settings};
use super::router::{Reply, head, limits, send, serve};
use super::*;
use crate::{
    browser_auth::{
        handoff::{LOGIN_COOKIE, LoginHandoff, MAX_COOKIE_BYTES, SESSION_COOKIE},
        router::{
            MAX_HEADER_BYTES, MAX_TARGET_BYTES, Rate, SessionSettings, Settings, SettingsError,
            router, router_with_sessions,
        },
    },
    sessions,
};
use tokio::{io::AsyncWriteExt, net::TcpStream};

const INVALID: &str = "session not valid\n";
const UNAVAILABLE: &str = "session unavailable; try again later\n";
const ORIGIN_REFUSED: &str = "logout origin refused\n";
const SESSION_RATE: &str = "session rate limit reached; try again later\n";
const SESSION_BUSY: &str = "session busy; try again later\n";
const LOGIN_RATE: &str = "login rate limit reached; try again later\n";
const HOUR: Duration = Duration::from_secs(3600);

/// Well-formed for the session parser: two canonical 43-character base64url tokens.
fn credential() -> String {
    format!("{}.{}", "A".repeat(43), "A".repeat(43))
}
fn session_cookie() -> String {
    format!("{SESSION_COOKIE}={}", credential())
}
fn sessions_at(checks: u32, logouts: u32) -> SessionSettings<'static> {
    SessionSettings {
        session: "/session",
        logout: "/logout",
        checks: Rate {
            burst: checks,
            interval: HOUR,
        },
        logouts: Rate {
            burst: logouts,
            interval: HOUR,
        },
    }
}
fn handoff(h: &Harness, pool: sqlx::PgPool) -> LoginHandoff {
    let policy = sessions::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(5));
    let auth = service::browser_auth(h, pool, Duration::from_secs(300), policy.unwrap());
    LoginHandoff::new(Arc::new(auth), settings()).unwrap()
}
/// A session check from the application, with the given `Cookie` fields.
fn check(cookies: &[&str]) -> String {
    let mut headers = vec![("sec-fetch-site", "same-origin")];
    headers.extend(cookies.iter().map(|cookie| ("cookie", *cookie)));
    head("GET", "/session", &headers)
}
/// A logout form `POST` with the given `Origin` fields and `Cookie` fields, empty body.
fn logout(origins: &[&str], cookies: &[&str]) -> String {
    let mut headers: Vec<_> = origins.iter().map(|origin| ("origin", *origin)).collect();
    headers.extend(cookies.iter().map(|cookie| ("cookie", *cookie)));
    headers.push(("content-type", "application/x-www-form-urlencoded"));
    headers.push(("content-length", "0"));
    head("POST", "/logout", &headers)
}
fn form() -> String {
    head(
        "POST",
        "/login",
        &[("origin", ORIGIN), ("content-length", "0")],
    )
}
/// No session-route response deletes or sets a cookie unless the revocation committed.
fn refused(reply: &Reply, status: u16, line: &str) {
    reply.refused(status, line);
    assert_eq!(reply.one("content-type"), "text/plain; charset=utf-8");
}

#[tokio::test]
async fn session_settings_join_the_login_rules_and_the_login_router_is_unchanged() {
    let (database, pool) = service::silent_database();
    let h = Harness::new().await;
    let build = |sessions: SessionSettings<'_>| {
        router_with_sessions(handoff(&h, pool.clone()), limits(), sessions).map(|_| ())
    };
    assert_eq!(build(sessions_at(1, 1)), Ok(()));
    // The registered callback is /callback and the initiation path is /login.
    for (path, error) in [
        ("/{id}", SettingsError::Pattern),
        ("/session/{*rest}", SettingsError::Pattern),
        ("", SettingsError::Path),
        ("session", SettingsError::Path),
        ("//session", SettingsError::Path),
        ("/session?x=1", SettingsError::Path),
        ("/login", SettingsError::Collision),
        ("/callback", SettingsError::Collision),
        ("/healthz", SettingsError::Collision),
        ("/readyz", SettingsError::Collision),
    ] {
        let session = SessionSettings {
            session: path,
            ..sessions_at(1, 1)
        };
        assert_eq!(build(session), Err(error), "session {path}");
        let logout = SessionSettings {
            logout: path,
            ..sessions_at(1, 1)
        };
        assert_eq!(build(logout), Err(error), "logout {path}");
    }
    let same = SessionSettings {
        logout: "/session",
        ..sessions_at(1, 1)
    };
    assert_eq!(build(same), Err(SettingsError::Collision));
    for (checks, logouts) in [(0, 1), (1, 0), (65_537, 1)] {
        assert_eq!(
            build(sessions_at(checks, logouts)),
            Err(SettingsError::Rate)
        );
    }
    let slow = SessionSettings {
        logouts: Rate {
            burst: 1,
            interval: HOUR + Duration::from_millis(1),
        },
        ..sessions_at(1, 1)
    };
    assert_eq!(build(slow), Err(SettingsError::Rate));
    let settings = Settings {
        in_flight: 0,
        ..limits()
    };
    let capped = router_with_sessions(handoff(&h, pool.clone()), settings, sessions_at(1, 1));
    assert_eq!(capped.map(|_| ()), Err(SettingsError::InFlight));
    assert_eq!(h.count(), 0);
    assert!(database.accept().is_err());

    // The login-only entry point routes neither session path.
    let address = serve(router(handoff(&h, pool), limits()).unwrap()).await;
    for request in [
        check(&[&session_cookie()]),
        logout(&[ORIGIN], &[&session_cookie()]),
    ] {
        let reply = send(address, &request).await;
        assert_eq!(reply.status, 404);
        assert!(reply.all("set-cookie").is_empty() && reply.all("location").is_empty());
    }
    assert!(database.accept().is_err());
}

#[tokio::test]
async fn routes_methods_bounds_and_cookies_are_decided_before_any_checkout() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let routes = router_with_sessions(handoff(&h, pool), limits(), sessions_at(1000, 1000));
    let address = serve(routes.unwrap()).await;
    let cookie = session_cookie();

    // One method per route. HEAD is refused like any other method.
    for (path, allow, methods) in [
        (
            "/session",
            "GET",
            &["HEAD", "POST", "PUT", "DELETE", "OPTIONS"][..],
        ),
        (
            "/logout",
            "POST",
            &["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "PATCH"][..],
        ),
    ] {
        for method in methods {
            let headers = [
                ("origin", ORIGIN),
                ("cookie", &cookie),
                ("content-length", "0"),
            ];
            let reply = send(address, &head(method, path, &headers)).await;
            assert_eq!(reply.status, 405, "{method} {path}");
            assert_eq!(reply.one("allow"), allow);
            if *method != "HEAD" {
                reply.refused(405, "method not allowed\n");
            }
        }
    }
    // Only the literal paths are routed.
    for path in [
        "/Session",
        "/session/",
        "/session/x",
        "//session",
        "/%73ession",
        "/logout/",
        "/Logout",
        "/logout/x",
    ] {
        for request in [
            check(&[&cookie]).replacen("/session", path, 1),
            logout(&[ORIGIN], &[&cookie]).replacen("/logout", path, 1),
        ] {
            let reply = send(address, &request).await;
            assert_eq!(reply.status, 404, "{path}");
            assert!(reply.all("set-cookie").is_empty() && reply.all("location").is_empty());
        }
    }
    // The login bounds, with the session lines.
    let long = format!("/session?{}", "p".repeat(MAX_TARGET_BYTES));
    refused(
        &send(address, &head("GET", &long, &[("cookie", &cookie)])).await,
        414,
        "session request target too long\n",
    );
    let pad = "v".repeat(MAX_HEADER_BYTES);
    for path in ["/session", "/logout"] {
        let method = if path == "/session" { "GET" } else { "POST" };
        let headers = [("origin", ORIGIN), ("cookie", &cookie), ("x-pad", &pad)];
        refused(
            &send(address, &head(method, path, &headers)).await,
            431,
            "session request headers too large\n",
        );
        for body in [("content-length", "1"), ("transfer-encoding", "chunked")] {
            let headers = [("origin", ORIGIN), ("cookie", &cookie), body];
            refused(
                &send(address, &head(method, path, &headers)).await,
                413,
                "session request body not accepted\n",
            );
        }
    }
    // Only same-origin browser checks inspect the cookie. A rejected check never connects.
    refused(
        &send(address, &head("GET", "/session", &[])).await,
        403,
        "session origin refused\n",
    );
    for sites in [
        &[][..],
        &["same-site"][..],
        &["cross-site"][..],
        &["none"][..],
        &["same-origin, same-origin"][..],
        &["same-origin", "same-origin"][..],
    ] {
        let mut headers = vec![("cookie", cookie.as_str())];
        headers.extend(sites.iter().map(|site| ("sec-fetch-site", *site)));
        refused(
            &send(address, &head("GET", "/session", &headers)).await,
            403,
            "session origin refused\n",
        );
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // Missing, repeated, malformed and oversized session cookies, on both routes.
    let noncanonical = format!("{SESSION_COOKIE}={}.{}", "A".repeat(43), "B".repeat(43));
    let caller = format!("{LOGIN_COOKIE}={}", credential());
    let both = format!("{cookie}; {cookie}");
    let misnamed = format!("{SESSION_COOKIE}2={}", credential());
    let truncated = format!("{SESSION_COOKIE}={}", &credential()[1..]);
    let oversized = format!("{cookie}; pad={}", "p".repeat(MAX_COOKIE_BYTES));
    for cookies in [
        &[][..],
        &["theme=dark"][..],
        &[caller.as_str()][..],
        &[both.as_str()][..],
        &[cookie.as_str(), cookie.as_str()][..],
        &[misnamed.as_str()][..],
        &[truncated.as_str()][..],
        &[noncanonical.as_str()][..],
        &[oversized.as_str()][..],
    ] {
        refused(&send(address, &check(cookies)).await, 403, INVALID);
        refused(
            &send(address, &logout(&[ORIGIN], cookies)).await,
            403,
            INVALID,
        );
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // One well-formed cookie reaches the service, among other cookies and with the caller
    // cookie present. The stand-in fails the checkout: a fixed 503 without any cookie.
    for cookies in [
        &[cookie.as_str()][..],
        &["theme=dark", cookie.as_str(), caller.as_str()][..],
    ] {
        refused(&send(address, &check(cookies)).await, 503, UNAVAILABLE);
        assert!(attempted());
        // A database failure during logout deletes nothing.
        refused(
            &send(address, &logout(&[ORIGIN], cookies)).await,
            503,
            UNAVAILABLE,
        );
        assert!(attempted());
    }
    assert_eq!(h.count(), 0);
}

#[tokio::test]
async fn logout_origin_is_exact_and_refused_before_the_cookie_or_database() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let routes = router_with_sessions(handoff(&h, pool), limits(), sessions_at(1000, 1000));
    let address = serve(routes.unwrap()).await;
    let cookie = session_cookie();
    let listed = format!("{ORIGIN}, {ORIGIN}");
    for origins in [
        &[][..],
        &["null"][..],
        &[ORIGIN, ORIGIN][..],
        &[listed.as_str()][..],
        &["http://app.example.test"][..],
        &["https://app.example.test:443"][..],
        &["https://app.example.test:8443"][..],
        &["https://APP.example.test"][..],
        &["https://app.example.test/"][..],
        &["https://other.example.test"][..],
        &["https://other.example.test", ORIGIN][..],
    ] {
        // With a well-formed cookie, and with cookies the cookie rule would also refuse:
        // the Origin refusal comes first either way.
        for cookies in [
            &[cookie.as_str()][..],
            &[][..],
            &[cookie.as_str(), cookie.as_str()][..],
        ] {
            refused(
                &send(address, &logout(origins, cookies)).await,
                403,
                ORIGIN_REFUSED,
            );
        }
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());
    // The same-origin session GET uses Fetch Metadata and needs no Origin field.
    refused(&send(address, &check(&[&cookie])).await, 503, UNAVAILABLE);
    assert!(attempted());
}

#[tokio::test]
async fn session_logout_and_login_budgets_are_independent_and_shared_by_clones() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let settings = Settings {
        begin: Rate {
            burst: 1,
            interval: HOUR,
        },
        ..limits()
    };
    let routes = router_with_sessions(handoff(&h, pool), settings, sessions_at(2, 2)).unwrap();
    let (first, second) = (serve(routes.clone()).await, serve(routes).await);
    let cookie = session_cookie();

    // Method and bound refusals spend no rate.
    for _ in 0..5 {
        send(first, &head("HEAD", "/session", &[])).await;
        send(second, &head("GET", "/logout", &[])).await;
        let body = [("cookie", cookie.as_str()), ("content-length", "1")];
        refused(
            &send(first, &head("GET", "/session", &body)).await,
            413,
            "session request body not accepted\n",
        );
    }
    // Session polling spends only the check budget, across both clones. Refusals by the
    // handoff spend it too.
    refused(&send(first, &check(&[])).await, 403, INVALID);
    refused(&send(second, &check(&[])).await, 403, INVALID);
    for address in [first, second] {
        refused(&send(address, &check(&[])).await, 429, SESSION_RATE);
        refused(&send(address, &check(&[&cookie])).await, 429, SESSION_RATE);
    }
    // Logout and login budgets are untouched: each still admits.
    refused(
        &send(first, &logout(&[], &[&cookie])).await,
        403,
        ORIGIN_REFUSED,
    );
    refused(&send(second, &logout(&[ORIGIN], &[])).await, 403, INVALID);
    for address in [first, second] {
        let reply = send(address, &logout(&[ORIGIN], &[&cookie])).await;
        refused(&reply, 429, SESSION_RATE);
    }
    send(first, &head("POST", "/login", &[("content-length", "0")]))
        .await
        .refused(403, "login origin refused\n");
    send(second, &form()).await.refused(429, LOGIN_RATE);
    // Exhausted logout and login budgets leave the check budget as it was: still spent.
    refused(&send(first, &check(&[])).await, 429, SESSION_RATE);
    assert_eq!(h.count(), 0);
    assert!(!attempted());
}

#[tokio::test]
async fn one_in_flight_cap_covers_session_routes_and_releases_on_disconnect() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let settings = Settings {
        in_flight: 1,
        ..limits()
    };
    let routes = router_with_sessions(handoff(&h, pool), settings, sessions_at(1, 1)).unwrap();
    let (first, second) = (serve(routes.clone()).await, serve(routes).await);
    let cookie = session_cookie();

    // A stalled initiation holds the only permit.
    h.script.lock().unwrap().mode = "stall";
    let mut held = TcpStream::connect(first).await.unwrap();
    held.write_all(form().as_bytes()).await.unwrap();
    h.entered(1).await;
    for address in [first, second] {
        refused(&send(address, &check(&[&cookie])).await, 503, SESSION_BUSY);
        let reply = send(address, &logout(&[ORIGIN], &[&cookie])).await;
        refused(&reply, 503, SESSION_BUSY);
    }
    assert_eq!(h.count(), 1);
    assert!(!attempted());

    // Disconnecting releases the permit. Busy refusals spent no session rate: the single
    // unit of each budget is still available and reaches the service.
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), h.server.closed.notified())
        .await
        .expect("cancelled provider request did not close");
    refused(&send(second, &check(&[&cookie])).await, 503, UNAVAILABLE);
    assert!(attempted());
    let reply = send(first, &logout(&[ORIGIN], &[&cookie])).await;
    refused(&reply, 503, UNAVAILABLE);
    assert!(attempted());
    refused(&send(first, &check(&[&cookie])).await, 429, SESSION_RATE);
    let reply = send(second, &logout(&[ORIGIN], &[&cookie])).await;
    refused(&reply, 429, SESSION_RATE);
    assert!(!attempted());
}
