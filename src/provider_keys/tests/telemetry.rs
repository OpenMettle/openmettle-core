//! Telemetry redaction canary (ADR 0024) for the login routes that ADRs 0017, 0019 and 0022
//! require to be redacted before mounting. The unmounted login and session router is merged
//! with the served health routes, observed by the production request middleware and driven
//! under the production subscriber stack, whose stderr is replaced by a capture. Synthetic
//! canaries are planted in the database password, the login key, both cookies, the callback
//! query, an invitation code, a run payload and other headers; none may reach the sink.
use super::handoff::{ORIGIN, settings};
use super::router::{FORM_TYPE, head, limits, send, serve};
use super::*;
use crate::{
    auth_config::AuthConfig,
    browser_auth::{
        BrowserAuth,
        handoff::{LOGIN_COOKIE, LoginHandoff, SESSION_COOKIE},
        router::{Rate, SessionSettings, router_with_sessions},
    },
    sessions,
    telemetry::{
        Format, Verbosity,
        tests::{Capture, is_v4},
    },
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

const DB_PASSWORD: &str = "CANARY-db-password-8d21";
/// Exactly 32 bytes, used as the active login key.
const LOGIN_KEY: &[u8; 32] = b"CANARY-login-key-0123456789abcde";
/// A well-formed invitation code no invitation has; hexadecimal, so it cannot say CANARY.
const INVITATION: &str = "omh1-ca4a-21e5-0dd5-c0de-feed-face-b0a7-d00d";
const RUN_PAYLOAD: &str = "CANARY-run-payload-{\"prompt\":\"synthetic\"}";
const HEADER: &str = "CANARY-authorization-header-3f9e";
const CLIENT_REQUEST_ID: &str = "5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a";

/// A canonical 43-character base64url token that starts with `prefix`.
fn token(prefix: &str) -> String {
    format!("{prefix}{}", "A".repeat(43 - prefix.len()))
}

/// The pooled service with the canary login key, over a database that never answers and
/// whose configured password is a canary. Test trust only.
fn handoff(h: &Harness) -> (std::net::TcpListener, sqlx::PgPool, LoginHandoff) {
    let database = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    database.set_nonblocking(true).unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(300))
        .connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(database.local_addr().unwrap().port())
                .username("fixture")
                .password(DB_PASSWORD)
                .database("fixture")
                .ssl_mode(PgSslMode::Disable),
        );
    let policy = sessions::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(5));
    let config = AuthConfig::fixture(
        login::KeyRing::new(vec![("active".into(), *LOGIN_KEY)]).unwrap(),
        Duration::from_secs(300),
        policy.unwrap(),
        ProviderManager {
            inner: h.manager.inner.clone(),
        },
        vec![h.provider.clone()],
    );
    let auth = BrowserAuth::new(config, pool.clone());
    let handoff = LoginHandoff::new(Arc::new(auth), settings()).unwrap();
    (database, pool, handoff)
}

fn sessions() -> SessionSettings<'static> {
    let rate = Rate {
        burst: 1000,
        interval: Duration::from_secs(3600),
    };
    SessionSettings {
        session: "/session",
        logout: "/logout",
        checks: rate,
        logouts: rate,
    }
}

#[tokio::test]
async fn no_planted_canary_reaches_the_production_sink() {
    let locator = token("CANARYloginLocator");
    let login_secret = token("CANARYloginSecret");
    let callback_code = "CANARY-callback-code-71b0";
    let callback_state = token("CANARYcallbackState");
    let session = format!("{}.{}", token("CANARYsessionId"), token("CANARYsessionKey"));
    let login_cookie = format!("{LOGIN_COOKIE}={locator}.{login_secret}");
    let session_cookie = format!("{SESSION_COOKIE}={session}");
    let form = format!("invitation_code={INVITATION}");
    let form_length = form.len().to_string();
    let run_length = RUN_PAYLOAD.len().to_string();
    let extra = [
        ("authorization", HEADER),
        ("x-request-id", CLIENT_REQUEST_ID),
    ];
    let with = |headers: &[(&'static str, &str)]| -> Vec<(&'static str, String)> {
        let all = headers.iter().chain(extra.iter());
        all.map(|(n, v)| (*n, v.to_string())).collect()
    };
    let request = |method: &str, target: &str, headers: Vec<(&'static str, String)>| {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        head(method, target, &headers)
    };
    let callback = format!(
        "/callback?code={callback_code}&state={locator}.{callback_state}&iss=https%3A%2F%2Fissuer.example.test%2Frealm"
    );
    // (request, status, route template, method)
    let cases = [
        (
            request(
                "POST",
                "/login",
                with(&[
                    ("origin", ORIGIN),
                    FORM_TYPE,
                    ("content-length", &form_length),
                ]),
            ) + &form,
            503,
            "/login",
            "POST",
        ),
        (
            request("GET", &callback, with(&[("cookie", &login_cookie)])),
            503,
            "/callback",
            "GET",
        ),
        (
            request(
                "GET",
                "/session",
                with(&[
                    ("sec-fetch-site", "same-origin"),
                    ("cookie", &session_cookie),
                ]),
            ),
            503,
            "/session",
            "GET",
        ),
        (
            request(
                "POST",
                "/logout",
                with(&[
                    ("origin", ORIGIN),
                    ("cookie", &session_cookie),
                    FORM_TYPE,
                    ("content-length", "0"),
                ]),
            ),
            503,
            "/logout",
            "POST",
        ),
        (
            request(
                "POST",
                "/v1/runs",
                with(&[
                    ("content-type", "application/json"),
                    ("content-length", &run_length),
                ]),
            ) + RUN_PAYLOAD,
            404,
            "unmatched",
            "POST",
        ),
        (
            request("GET", &format!("/healthz?{callback_code}"), with(&[])),
            200,
            "/healthz",
            "GET",
        ),
        (
            request("GET", "/readyz", with(&[("cookie", &session_cookie)])),
            503,
            "/readyz",
            "GET",
        ),
    ];
    let canaries: Vec<&[u8]> = vec![
        b"CANARY",
        DB_PASSWORD.as_bytes(),
        LOGIN_KEY,
        INVITATION.as_bytes(),
        RUN_PAYLOAD.as_bytes(),
        b"synthetic",
        HEADER.as_bytes(),
        CLIENT_REQUEST_ID.as_bytes(),
        locator.as_bytes(),
        login_secret.as_bytes(),
        callback_code.as_bytes(),
        callback_state.as_bytes(),
        session.as_bytes(),
        LOGIN_COOKIE.as_bytes(),
        SESSION_COOKIE.as_bytes(),
        b"/v1/runs",
        b"?code",
        b"&state",
    ];

    let h = Harness::new().await;
    for format in [Format::Json, Format::Text] {
        let (capture, _guard) = Capture::install(format, Verbosity::Debug);
        let (database, pool, handoff) = handoff(&h);
        let login = router_with_sessions(handoff, limits(), sessions()).unwrap();
        let health = crate::routes(crate::Health {
            pool,
            timeout: Duration::from_millis(300),
        });
        let address = serve(crate::telemetry::observe(health.merge(login))).await;
        for (request, status, route, _) in &cases {
            let reply = send(address, request).await;
            assert_eq!(reply.status, *status, "{route}");
        }
        // The planted inputs reached the work they guard: the form used the provider (its
        // metadata stays cached for the second format) and the canary login key, and the
        // database with the canary password was dialled.
        assert!(h.count() > 0);
        assert!(database.accept().is_ok());

        // Positive control: the sink is live and saw one event per request.
        let text = capture.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), cases.len(), "{format:?}:\n{text}");
        if format == Format::Json {
            let events = capture.events("http.request.completed");
            assert_eq!(events.len(), cases.len());
            for (event, (_, status, route, method)) in events.iter().zip(&cases) {
                assert_eq!(event["http.route"], *route);
                assert_eq!(event["http.request.method"], *method);
                assert_eq!(event["http.response.status_code"], *status);
                assert!(is_v4(event["request_id"].as_str().unwrap()));
            }
        } else {
            for (line, (_, _, route, _)) in lines.iter().zip(&cases) {
                assert!(line.contains("http.request.completed"), "{line}");
                assert!(line.contains(&format!("http.route=\"{route}\"")), "{line}");
            }
        }
        capture.assert_absent(&canaries);
    }
}
