//! Runtime mounting of the browser sign-in routes (ADR 0025). No PostgreSQL, provider or
//! network: the database address never answers, and no request here reaches a provider.
use super::*;
use crate::{
    auth_config::tests::support::{self, Dir},
    provider_http::fixture::Ca,
    telemetry::{
        Format, Verbosity,
        tests::{Capture, is_v4},
    },
};
use std::{cell::RefCell, net::TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const URL: (&str, &str) = ("DATABASE_URL", "postgres://localhost/test");

fn parse(role: Role, pairs: &[(&str, &str)]) -> Result<Config, &'static str> {
    Config::parse(role, |key| {
        let found = pairs.iter().find(|(k, _)| *k == key);
        Ok(found.map(|(_, v)| v.to_string()))
    })
}

#[test]
fn auth_config_is_optional_and_must_be_an_absolute_path() {
    assert_eq!(parse(Role::Api, &[URL]).ok().unwrap().auth_config, None);
    let config = parse(
        Role::Api,
        &[URL, ("AUTH_CONFIG", "/etc/openmettle/auth.json")],
    );
    assert_eq!(
        config.ok().unwrap().auth_config.as_deref(),
        Some(std::path::Path::new("/etc/openmettle/auth.json"))
    );
    // A set value is never read as unset, and the refusal names the key alone.
    for value in [
        "",
        " ",
        "auth.json",
        "./auth.json",
        "../etc/auth.json",
        "~/a",
    ] {
        let refused = parse(Role::Api, &[URL, ("AUTH_CONFIG", value)]);
        assert_eq!(refused.err(), Some("invalid AUTH_CONFIG"), "{value:?}");
    }
    // Read after the existing keys, so their refusals are reported as before.
    let refused = parse(
        Role::Api,
        &[URL, ("LOG_LEVEL", "trace"), ("AUTH_CONFIG", "relative")],
    );
    assert_eq!(refused.err(), Some("invalid LOG_LEVEL"));
}

/// The worker asks for every key the API does except `AUTH_CONFIG`, so no value of it, valid
/// or not, can change the worker.
#[test]
fn worker_never_reads_auth_config() {
    let keys = |role| {
        let asked = RefCell::new(Vec::new());
        let config = Config::parse(role, |key| {
            asked.borrow_mut().push(key.to_owned());
            Ok(match key {
                "DATABASE_URL" => Some(URL.1.to_owned()),
                "AUTH_CONFIG" => Some("relative".to_owned()),
                _ => None,
            })
        });
        (config.map(|config| config.auth_config), asked.into_inner())
    };
    let (api, mut api_keys) = keys(Role::Api);
    assert_eq!(api.err(), Some("invalid AUTH_CONFIG"));
    assert_eq!(api_keys.pop().as_deref(), Some("AUTH_CONFIG"));
    let (worker, worker_keys) = keys(Role::Worker);
    assert_eq!(worker.ok(), Some(None));
    assert_eq!(worker_keys, api_keys);
}

/// A serving configuration over a database address that accepts and never answers.
fn config(database: &TcpListener, auth: Option<&str>) -> Config {
    let url = format!(
        "postgres://fixture:CANARY-db-password@{}/fixture?sslmode=disable",
        database.local_addr().unwrap()
    );
    let mut pairs = vec![("DATABASE_URL", url.as_str()), ("DB_TIMEOUT_MS", "200")];
    pairs.extend(auth.map(|path| ("AUTH_CONFIG", path)));
    parse(Role::Api, &pairs).ok().unwrap()
}

/// Serves `app` observed as in `serve` and returns its address.
async fn serve_observed(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, telemetry::observe(app)).await });
    address
}

/// One request on a new connection: the status, the lowercase head and the body.
async fn send(
    address: SocketAddr,
    method: &str,
    target: &str,
    extra: &str,
) -> (u16, String, String) {
    // `extra` is further header lines, optionally followed by a blank line and a body.
    let end = if extra.contains("\r\n\r\n") {
        ""
    } else {
        "\r\n"
    };
    let request = format!(
        "{method} {target} HTTP/1.1\r\nhost: app.example.test\r\nconnection: close\r\n{extra}{end}"
    );
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    };
    let response = tokio::time::timeout(Duration::from_secs(10), exchange)
        .await
        .expect("no response within ten seconds");
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head["HTTP/1.1 ".len()..][..3].parse().unwrap();
    (status, head.to_ascii_lowercase(), body.to_owned())
}

/// Without `AUTH_CONFIG` nothing is loaded and the sign-in paths are unknown routes.
#[tokio::test]
async fn unset_auth_config_serves_the_operational_routes_only() {
    let database = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = config(&database, None);
    let address = serve_observed(app(&config, &pool(&config)).unwrap()).await;
    assert_eq!(send(address, "GET", "/healthz", "").await.0, 200);
    for (method, path) in [
        ("POST", "/auth/login"),
        ("GET", "/callback"),
        ("GET", "/auth/session"),
        ("POST", "/auth/logout"),
    ] {
        let (status, head, _) = send(address, method, path, "content-length: 0\r\n").await;
        assert_eq!(status, 404, "{method} {path}");
        assert!(!head.contains("set-cookie") && !head.contains("location"));
    }
}

/// A refused document builds no router. Each category is the offline check's fixed text;
/// version 1 passes that check and is refused here.
#[tokio::test]
async fn refused_settings_mount_nothing() {
    let database = TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = Dir::new();
    let bundle = Ca::new().pem();
    let v1 = support::document(&dir, &bundle);
    let mut collision = support::document_v2(&dir, &bundle);
    let mut cases = vec![(dir.path("absent.json"), auth_config::Error::ConfigFile)];
    cases.push((
        dir.write("v1.json", v1.to_string().as_bytes()),
        auth_config::Error::BrowserProfileRequired,
    ));
    for (probe, path) in [("/healthz", "session_check"), ("/readyz", "logout")] {
        collision["browser"]["paths"][path] = probe.into();
        cases.push((
            dir.write("collision.json", collision.to_string().as_bytes()),
            auth_config::Error::BrowserRouter(browser_auth::router::SettingsError::Collision),
        ));
        let config = config(&database, Some(&cases.last().unwrap().0));
        // Checked here because the next iteration rewrites the file.
        assert_eq!(
            app(&config, &pool(&config)).err(),
            Some(cases.pop().unwrap().1)
        );
        collision = support::document_v2(&dir, &bundle);
    }
    for (path, error) in cases {
        let config = config(&database, Some(&path));
        assert_eq!(app(&config, &pool(&config)).err(), Some(error));
    }
    assert_eq!(
        auth_config::Error::BrowserProfileRequired.to_string(),
        "serving requires a version 2 browser profile"
    );
    // Nothing above dialled the database.
    database.set_nonblocking(true).unwrap();
    assert!(database.accept().is_err());
}

/// A version-2 document mounts its four routes beside the probes, on the primary pool, and
/// each request is recorded by route template, method and status alone.
#[tokio::test]
async fn version_2_settings_mount_the_sign_in_routes_under_observation() {
    const SESSION: &str = concat!(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ".",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    let database = TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = Dir::new();
    let document = support::document_v2(&dir, &Ca::new().pem());
    // A textual login key, so its bytes can be searched for.
    dir.write("login-key-b", b"CANARY-login-key-32-bytes-000000");
    let path = dir.write("auth.json", document.to_string().as_bytes());
    let config = config(&database, Some(&path));
    let (capture, _guard) = Capture::install(Format::Json, Verbosity::Debug);
    let address = serve_observed(app(&config, &pool(&config)).unwrap()).await;

    let state = format!("{}.{}", "s".repeat(43), "t".repeat(43));
    let bound = format!(
        "/callback?code=CANARY-code&state={state}&iss=https%3A%2F%2Fissuer.example.test%2Frealm"
    );
    let session =
        format!("sec-fetch-site: same-origin\r\ncookie: __Host-openmettle-session={SESSION}\r\n");
    let form = "origin: https://other.example.test\r\ncontent-length: 39\r\n\
                content-type: application/x-www-form-urlencoded\r\n\r\n\
                invitation_code=CANARY-invitation-00000";
    let cases: [(&str, &str, &str, u16, &str, &str); 12] = [
        (
            "GET",
            "/healthz",
            "x-request-id: CANARY-id\r\n",
            200,
            "ok\n",
            "/healthz",
        ),
        ("GET", "/readyz", "", 503, "not ready\n", "/readyz"),
        (
            "POST",
            "/auth/login",
            "content-length: 0\r\n",
            403,
            "login origin refused\n",
            "/auth/login",
        ),
        (
            "POST",
            "/auth/login",
            form,
            403,
            "login origin refused\n",
            "/auth/login",
        ),
        (
            "GET",
            "/auth/login",
            "",
            405,
            "method not allowed\n",
            "/auth/login",
        ),
        (
            "GET",
            "/callback?code=CANARY-code&state=CANARY-state&iss=CANARY-iss",
            "",
            400,
            "login response refused; restart login\n",
            "/callback",
        ),
        (
            "GET",
            &bound,
            "",
            400,
            "login browser binding missing or superseded; restart login\n",
            "/callback",
        ),
        (
            "GET",
            "/auth/session",
            "",
            403,
            "session origin refused\n",
            "/auth/session",
        ),
        (
            "GET",
            "/auth/session",
            "sec-fetch-site: same-origin\r\n",
            403,
            "session not valid\n",
            "/auth/session",
        ),
        // A well-formed credential reaches the primary pool, which cannot connect.
        (
            "GET",
            "/auth/session",
            &session,
            503,
            "session unavailable; try again later\n",
            "/auth/session",
        ),
        (
            "POST",
            "/auth/logout",
            "content-length: 0\r\n",
            403,
            "logout origin refused\n",
            "/auth/logout",
        ),
        ("GET", "/auth/CANARY-path", "", 404, "", "unmatched"),
    ];
    for (method, target, extra, status, line, route) in cases {
        let (got, head, body) = send(address, method, target, extra).await;
        assert_eq!((got, body.as_str()), (status, line), "{method} {target}");
        assert!(!head.contains("set-cookie") && !head.contains("location"));
        assert!(!head.contains("request-id"), "{head}");
        // Every sign-in response is uncacheable; the probes and the fallback are unchanged.
        assert_eq!(
            head.contains("cache-control: no-store"),
            !matches!(route, "/healthz" | "/readyz" | "unmatched"),
            "{method} {target}"
        );
    }
    // The session check dialled the database with the canary password.
    database.set_nonblocking(true).unwrap();
    assert!(database.accept().is_ok());

    let events = capture.events("http.request.completed");
    assert_eq!(capture.json().len(), cases.len());
    assert_eq!(events.len(), cases.len());
    for (event, (method, _, _, status, _, route)) in events.iter().zip(&cases) {
        assert_eq!(event["http.route"], *route);
        assert_eq!(event["http.request.method"], *method);
        assert_eq!(event["http.response.status_code"], *status);
        assert!(is_v4(event["request_id"].as_str().unwrap()));
    }
    capture.assert_absent(&[
        b"CANARY",
        SESSION.as_bytes(),
        state.as_bytes(),
        b"__Host-",
        b"issuer.example.test",
        dir.path("").as_bytes(),
    ]);
}
