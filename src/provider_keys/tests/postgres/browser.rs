//! Full-page Chrome navigation across two HTTPS sites. The browser owns both cookies.
use super::*;
use crate::browser_auth::{
    BrowserAuth,
    handoff::{LOGIN_COOKIE, LoginHandoff, SESSION_COOKIE, Settings as HandoffSettings},
    router::{SessionSettings, router_with_sessions},
};
use axum::{
    Router,
    extract::{RawQuery, Request},
    http::header,
    middleware::{Next, from_fn},
    response::Html,
    routing::get,
    serve::Listener,
};
use std::{
    io::Write,
    net::SocketAddr,
    process::{Command, Stdio},
};
use tokio::net::{TcpListener, TcpStream};

const APP: &str = "app.relying.test";
const ISSUER: &str = "issuer.example.test";

struct Https(TcpListener, tokio_rustls::TlsAcceptor);

impl Listener for Https {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = self.0.accept().await.unwrap();
            if let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(3), self.1.accept(tcp)).await
            {
                return (tls, addr);
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

fn serve(listener: TcpListener, host: &str, ca: &tls::Ca, routes: Router) {
    let https = Https(listener, tls::acceptor(ca.leaf(host, false)));
    tokio::spawn(axum::serve(https, routes).into_future());
}

// The form carries the invitation code field (ADR 0022), filled with a synthetic well-formed
// code that no invitation has. The seeded identity already exists, so the code is ignored.
// The journey shows that the body a real browser sends for this form passes the router's form
// profile and the handoff's parser.
const LOGIN: &str = r#"<form method="post" action="/login"><input name="invitation_code" value="omh1-0123-4567-89ab-cdef-fedc-ba98-7654-3210"><button id="login">Sign in</button></form>"#;
/// `invitation_code=` and the 44-character display form, which needs no escaping.
const LOGIN_FORM_BYTES: &str = "60";
const LANDING: &str = r#"<form method="post" action="/logout"><button id="logout">Sign out</button></form>
<script>
document.forms[0].onsubmit = async event => {
    event.preventDefault();
    const form = event.target;
    const response = await fetch(form.action, {
        method: form.method, body: new URLSearchParams(new FormData(form))
    });
    form.dataset.status = response.status;
};
</script>"#;

#[derive(Default)]
struct Observations {
    wrong_form_refused: bool,
    login_form_declared: bool,
    callback_navigation: bool,
    session_cookies: Vec<bool>,
}

// Record only navigation context, the refusal status and session cookie presence.
fn observe(routes: Router, wrong_origin: String, observed: Arc<Mutex<Observations>>) -> Router {
    routes.layer(from_fn(move |req: Request, next: Next| {
        let observed = observed.clone();
        let wrong_origin = wrong_origin.clone();
        async move {
            let headers = req.headers();
            let wrong_form = req.uri().path() == "/login"
                && req.method() == axum::http::Method::POST
                && headers
                    .get(header::ORIGIN)
                    .is_some_and(|v| v == wrong_origin.as_str())
                && headers
                    .get("sec-fetch-site")
                    .is_some_and(|v| v == "cross-site");
            // The application's own form: one URL-encoded body of the field's exact length.
            if req.uri().path() == "/login"
                && req.method() == axum::http::Method::POST
                && headers
                    .get("sec-fetch-site")
                    .is_some_and(|v| v == "same-origin")
            {
                observed.lock().unwrap().login_form_declared = headers
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|v| v == "application/x-www-form-urlencoded")
                    && headers
                        .get(header::CONTENT_LENGTH)
                        .is_some_and(|v| v == LOGIN_FORM_BYTES);
            }
            if req.uri().path() == "/callback" {
                observed.lock().unwrap().callback_navigation = req.method()
                    == axum::http::Method::GET
                    && headers
                        .get("sec-fetch-site")
                        .is_some_and(|v| v == "cross-site")
                    && headers
                        .get("sec-fetch-mode")
                        .is_some_and(|v| v == "navigate")
                    && headers
                        .get("sec-fetch-dest")
                        .is_some_and(|v| v == "document");
            }
            if req.uri().path() == "/session" {
                let present = headers
                    .get_all(header::COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|v| v.split(';'))
                    .filter_map(|v| v.trim().split_once('='))
                    .any(|(name, _)| name == SESSION_COOKIE);
                observed.lock().unwrap().session_cookies.push(present);
            }
            let response = next.run(req).await;
            if wrong_form {
                observed.lock().unwrap().wrong_form_refused =
                    response.status() == axum::http::StatusCode::FORBIDDEN;
            }
            response
        }
    }))
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and sandboxed Chrome required"]
async fn cross_site_session_lifecycle() {
    let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = format!(
        "https://{APP}:{}",
        app_listener.local_addr().unwrap().port()
    );
    let issuer = format!(
        "https://{ISSUER}:{}",
        issuer_listener.local_addr().unwrap().port()
    );
    let callback = format!("{app}/callback");
    let harness =
        Harness::with_endpoints(policy(), &format!("{issuer}/authorize"), &callback).await;
    let mut f = Flow::with(harness).await;
    let user = sessions::seed(&mut f, true, true).await;
    let pool = pooled::one_slot(f.db.options(API));
    let service = Arc::new(pooled::service_over(&f, &pool));
    let handoff = LoginHandoff::new(
        service,
        HandoffSettings {
            origin: &app,
            landing: "/app",
            provider: signing::ID,
        },
    )
    .unwrap();
    let limits = super::super::router::limits();
    let routes = router_with_sessions(
        handoff,
        limits,
        SessionSettings {
            session: "/session",
            logout: "/logout",
            checks: limits.begin,
            logouts: limits.begin,
        },
    )
    .unwrap();

    let observed = Arc::new(Mutex::new(Observations::default()));
    let routes = observe(routes, issuer.clone(), observed.clone())
        .route("/", get(|| async { Html(LOGIN) }))
        .route("/app", get(|| async { Html(LANDING) }));
    serve(app_listener, APP, &f.h.ca, routes);

    let wrong = format!(
        r#"<form action="{app}/login" method="post"><button id="wrong">Sign in</button></form>"#
    );
    let script = f.h.script.clone();
    let provider = Router::new()
        .route("/wrong", get(|| async move { Html(wrong) }))
        .route(
            "/authorize",
            get(move |RawQuery(query): RawQuery| async move {
                let params: HashMap<_, _> = openidconnect::url::form_urlencoded::parse(
                    query.as_deref().unwrap_or_default().as_bytes(),
                )
                .into_owned()
                .collect();
                assert!(
                    params["redirect_uri"] == callback
                        && params["client_id"] == signing::CLIENT
                        && params["response_type"] == "code"
                        && params["code_challenge_method"] == "S256",
                    "authorization request binding"
                );
                script.lock().unwrap().authorize(&params);
                let query = openidconnect::url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("code", "synthetic-code")
                    .append_pair("state", &params["state"])
                    .append_pair("iss", signing::ISSUER)
                    .finish()
                    .replace('&', "&amp;");
                Html(format!(
                    r#"<a id="approve" href="{callback}?{query}">Continue</a>"#
                ))
            }),
        );
    serve(issuer_listener, ISSUER, &f.h.ca, provider);

    let public_ca = f.h.ca.pem();
    let status = tokio::task::spawn_blocking(move || {
        let mut child = Command::new("python3")
            .args(["tests/browser/qualify.py", &app, &issuer])
            .stdin(Stdio::piped())
            .spawn()
            .expect("start browser harness");
        child.stdin.take().unwrap().write_all(&public_ca).unwrap();
        child.wait().expect("reap browser harness")
    })
    .await
    .unwrap();
    assert!(status.success(), "browser journey failed");
    {
        let observed = observed.lock().unwrap();
        assert!(
            observed.callback_navigation,
            "cross-site top-level callback GET"
        );
        assert!(
            observed.wrong_form_refused,
            "wrong-origin form POST refusal"
        );
        assert!(
            observed.login_form_declared,
            "application form POST with the invitation code field"
        );
        assert_eq!(observed.session_cookies, [true, false]);
    }
    assert_eq!(pooled::posts(&f), 1);
    assert_eq!(f.rows().await, 1);
    let sessions: Vec<bool> = sqlx::query_scalar(
        "SELECT s.revoked AND s.user_id = $1::uuid AND t.consumed AND t.session_issued
         FROM openmettle.local_sessions s JOIN openmettle.login_transactions t ON t.id = s.login_id",
    ).bind(user).fetch_all(&mut f.owner).await.unwrap();
    assert_eq!(sessions, [true]);
}

// Login form for hosted Keycloak qualification: empty by default for approved identities and
// filled by tests/browser/keycloak.py when redeeming a home invitation code (ADR 0022).
const KEYCLOAK_LOGIN: &str = r#"<form method="post" action="/login"><input id="invitation" name="invitation_code"><button id="login">Sign in</button></form>"#;

// Never derive Debug: holds per-run synthetic credentials loaded from accounts.json.
#[derive(serde::Deserialize)]
struct FixtureAccount {
    username: String,
    subject: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct FixtureAccounts {
    approved: FixtureAccount,
    invited: FixtureAccount,
}

#[derive(Default)]
struct KeycloakObservations {
    initiation_redirect_ok: bool,
    key_gen_after_begin: Option<u64>,
    callback_ok: bool,
    key_gen_after_callback: Option<u64>,
    session_checks: Vec<(bool, u16)>,
    logouts: Vec<u16>,
}

struct KeycloakObserverConfig {
    authorization_endpoint: String,
    client_id: String,
    callback_url: String,
    issuer: String,
    provider: ManagedProvider,
}

fn has_cookie(headers: &axum::http::HeaderMap, name: &str) -> bool {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .any(|(cookie, _)| cookie == name)
}

fn sets_cookie(headers: &axum::http::HeaderMap, name: &str) -> bool {
    let prefix = format!("{name}=");
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|value| value.starts_with(&prefix))
}

fn provider_cache_state(provider: &ManagedProvider) -> (u64, bool, bool) {
    let state = provider.entry.state.lock().unwrap();
    let now = Instant::now();
    let has_valid_snapshot = state.snapshot.as_ref().is_some_and(|snapshot| {
        snapshot.generation == state.key_generation && snapshot.expires > now
    });
    let cooldown_recorded = state.next.is_some();
    (state.key_generation, has_valid_snapshot, cooldown_recorded)
}

fn authorization_redirect_valid(
    location: &str,
    expected_endpoint: &str,
    expected_client: &str,
    expected_callback: &str,
) -> bool {
    let Ok(url) = openidconnect::url::Url::parse(location) else {
        return false;
    };
    let Ok(endpoint) = openidconnect::url::Url::parse(expected_endpoint) else {
        return false;
    };
    if url.scheme() != endpoint.scheme()
        || url.host_str() != endpoint.host_str()
        || url.port_or_known_default() != endpoint.port_or_known_default()
        || url.path() != endpoint.path()
    {
        return false;
    }
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    params.get("response_type").map(String::as_str) == Some("code")
        && params.get("client_id").map(String::as_str) == Some(expected_client)
        && params.get("redirect_uri").map(String::as_str) == Some(expected_callback)
        && params.get("code_challenge_method").map(String::as_str) == Some("S256")
        && params.get("code_challenge").is_some_and(|v| !v.is_empty())
        && params.get("state").is_some_and(|v| !v.is_empty())
        && params.get("nonce").is_some_and(|v| !v.is_empty())
}

// Records only protocol invariants, status codes, cookie presence, and provider key generation.
// Never records or logs tokens, authorization codes, cookies, or secrets.
fn observe_keycloak(
    routes: Router,
    expected: Arc<KeycloakObserverConfig>,
    observed: Arc<Mutex<KeycloakObservations>>,
) -> Router {
    routes.layer(from_fn(move |req: Request, next: Next| {
        let expected = expected.clone();
        let observed = observed.clone();
        async move {
            let path = req.uri().path().to_owned();
            let method = req.method().clone();
            let headers = req.headers();
            let session_cookie_present = has_cookie(headers, SESSION_COOKIE);
            let callback_request_ok = path == "/callback"
                && method == axum::http::Method::GET
                && headers
                    .get("sec-fetch-site")
                    .is_some_and(|v| v == "cross-site")
                && headers
                    .get("sec-fetch-mode")
                    .is_some_and(|v| v == "navigate")
                && headers
                    .get("sec-fetch-dest")
                    .is_some_and(|v| v == "document")
                && {
                    let params: HashMap<String, String> =
                        openidconnect::url::form_urlencoded::parse(
                            req.uri().query().unwrap_or_default().as_bytes(),
                        )
                        .into_owned()
                        .collect();
                    params.get("iss").map(String::as_str) == Some(expected.issuer.as_str())
                        && params.get("code").is_some_and(|v| !v.is_empty())
                        && params.get("state").is_some_and(|v| !v.is_empty())
                };

            let response = next.run(req).await;
            let status = response.status();
            let resp_headers = response.headers();

            if path == "/login" && method == axum::http::Method::POST {
                let redirect_ok = status == axum::http::StatusCode::SEE_OTHER
                    && resp_headers
                        .get(header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|loc| {
                            authorization_redirect_valid(
                                loc,
                                &expected.authorization_endpoint,
                                &expected.client_id,
                                &expected.callback_url,
                            )
                        })
                    && sets_cookie(resp_headers, LOGIN_COOKIE);
                let (key_gen, _, _) = provider_cache_state(&expected.provider);
                let mut obs = observed.lock().unwrap();
                obs.initiation_redirect_ok = redirect_ok;
                obs.key_gen_after_begin = Some(key_gen);
            } else if path == "/callback" {
                let response_ok = status == axum::http::StatusCode::SEE_OTHER
                    && resp_headers
                        .get(header::LOCATION)
                        .is_some_and(|v| v == "/app")
                    && sets_cookie(resp_headers, SESSION_COOKIE);
                let (key_gen, _, _) = provider_cache_state(&expected.provider);
                let mut obs = observed.lock().unwrap();
                obs.callback_ok = callback_request_ok && response_ok;
                obs.key_gen_after_callback = Some(key_gen);
            } else if path == "/session" && method == axum::http::Method::GET {
                observed
                    .lock()
                    .unwrap()
                    .session_checks
                    .push((session_cookie_present, status.as_u16()));
            } else if path == "/logout" && method == axum::http::Method::POST {
                observed.lock().unwrap().logouts.push(status.as_u16());
            }

            response
        }
    }))
}

async fn register_provider(
    owner: &mut PgConnection,
    provider_id: &str,
    issuer: &str,
    client_id: &str,
    revision: &str,
) {
    owner.execute(PROTOCOL).await.unwrap();
    sqlx::query(
        "INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason)
         VALUES ($1::uuid, $2, $3, 'fixture-owner', 'keycloak qualification provider')",
    )
    .bind(provider_id)
    .bind(issuer)
    .bind(client_id)
    .execute(&mut *owner)
    .await
    .unwrap();
    sqlx::query(APPEND)
        .bind(provider_id)
        .bind(revision)
        .execute(&mut *owner)
        .await
        .unwrap();
    owner.execute("COMMIT").await.unwrap();
}

async fn seed_unapproved_user(owner: &mut PgConnection, issuer: &str, subject: &str) -> String {
    let user: String =
        sqlx::query_scalar("INSERT INTO openmettle.users DEFAULT VALUES RETURNING id::text")
            .fetch_one(&mut *owner)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.user_identities (user_id, issuer, subject)
         VALUES ($1::uuid, $2, $3)",
    )
    .bind(&user)
    .bind(issuer)
    .bind(subject)
    .execute(&mut *owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.scopes (kind, personal_user_id) VALUES ('personal', $1::uuid)",
    )
    .bind(&user)
    .execute(&mut *owner)
    .await
    .unwrap();
    user
}

async fn approve_identity_via_script(
    owner: &mut PgConnection,
    db_name: &str,
    provider_id: &str,
    issuer: &str,
    subject: &str,
) {
    const SCRIPT: &str = include_str!("../../../../docs/operator/first-identity-approval.psql");
    let expires_ms: i64 = sqlx::query_scalar(
        "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 600000",
    )
    .fetch_one(owner)
    .await
    .unwrap();
    let expires = expires_ms.to_string();
    let vars = [
        ("provider", provider_id),
        ("issuer", issuer),
        ("subject", subject),
        ("expires_ms", expires.as_str()),
        ("actor", "fixture-operator"),
        ("reason", "keycloak qualification first approval"),
    ];
    let mut child = psql::start(db_name, OWNER, PASSWORD, &vars);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(SCRIPT.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "first approval script failed: {stderr}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "first approval committed
"
    );
    assert!(out.stderr.is_empty(), "first approval stderr: {stderr}");
}

fn create_home_invitation_via_script(
    db_name: &str,
    provider_id: &str,
    issuer: &str,
    subject: &str,
) -> String {
    const SCRIPT: &str = include_str!("../../../../docs/operator/home-invitation-create.psql");
    const CODE_PREFIX: &str = "invitation code (shown once; deliver privately): ";
    let vars = [
        ("invitation", "00000000-0000-4000-8000-000000000201"),
        ("provider", provider_id),
        ("issuer", issuer),
        ("subject", subject),
        ("expected_generation", "0"),
        ("operator", "00000000-0000-4000-8000-000000000202"),
    ];
    let mut child = psql::start(db_name, OWNER, PASSWORD, &vars);
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 600000 AS redeem_before_ms,              floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 900000 AS approval_until_ms \\gset"
        )
        .unwrap();
        stdin.write_all(SCRIPT.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "home invitation script failed: {stderr}"
    );
    assert!(out.stderr.is_empty(), "home invitation stderr: {stderr}");
    // Never format stdout into an assertion message: it carries the one-time code.
    let stdout = String::from_utf8(out.stdout).expect("utf-8 invitation output");
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("home invitation created"));
    let code = lines
        .next()
        .and_then(|line| line.strip_prefix(CODE_PREFIX))
        .expect("missing invitation code line")
        .to_owned();
    assert!(
        lines.next().is_none(),
        "unexpected trailing invitation output"
    );
    assert!(!code.is_empty(), "empty invitation code");
    code
}

async fn run_keycloak_browser(
    app_origin: String,
    issuer: String,
    authorities: Vec<String>,
    account: &FixtureAccount,
    invitation_code: Option<String>,
) {
    let payload = serde_json::json!({
        "authorities": authorities,
        "username": account.username,
        "password": account.password,
        "invitation_code": invitation_code,
    })
    .to_string();
    let output = tokio::task::spawn_blocking(move || {
        let mut child = Command::new("python3")
            .args(["tests/browser/keycloak.py", &app_origin, &issuer])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start keycloak browser harness");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        child
            .wait_with_output()
            .expect("reap keycloak browser harness")
    })
    .await
    .unwrap();
    // tests/browser/keycloak.py writes only fixed phrases or phase names to stderr.
    assert!(
        output.status.success(),
        "keycloak browser journey failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18, pinned Keycloak 26.8.2, POSTGRES_CONTAINER and sandboxed Chrome required"]
async fn keycloak_browser_sign_in_qualification() {
    println!("Qualification phase: load fixture and auth settings");
    let fixture_dir = std::path::PathBuf::from(
        std::env::var("KEYCLOAK_FIXTURE_DIR").expect("KEYCLOAK_FIXTURE_DIR required"),
    );
    let settings_path = fixture_dir.join("auth-settings.json");
    let raw_settings: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&settings_path).expect("read fixture auth-settings.json"),
    )
    .expect("parse fixture auth-settings.json");
    let revision = raw_settings["providers"][0]["revision"]
        .as_str()
        .expect("provider revision")
        .to_owned();
    let authorization_endpoint = raw_settings["providers"][0]["authorization_endpoint"]
        .as_str()
        .expect("authorization_endpoint")
        .to_owned();

    let config = crate::auth_config::load(&settings_path).expect("load fixture auth settings");
    assert_eq!(config.providers().len(), 1, "single qualification provider");
    let refresh_policy = config.manager().policy();
    assert!(
        refresh_policy.uncacheable_reuse >= refresh_policy.cooldown
            && refresh_policy.uncacheable_reuse <= MAX_UNCACHEABLE_REUSE
            && refresh_policy.uncacheable_reuse <= refresh_policy.freshness,
        "explicit uncacheable_reuse_seconds policy bounds"
    );

    let provider = config.providers()[0].clone();
    let browser_profile = config.browser().expect("browser profile").clone();
    let app_origin = browser_profile.handoff().origin.to_owned();
    let app_url = openidconnect::url::Url::parse(&app_origin).expect("valid application origin");
    let app_port = app_url
        .port_or_known_default()
        .expect("application origin port");
    let provider_id = provider.id().to_owned();
    let issuer = provider.issuer().to_owned();
    let client_id = provider.entry.client.clone();
    let callback_url = provider.callback().expect("provider callback");

    let provider_ca_pem =
        std::fs::read_to_string(fixture_dir.join("provider-ca.pem")).expect("read provider-ca.pem");
    let accounts: FixtureAccounts = serde_json::from_slice(
        &std::fs::read(fixture_dir.join("accounts.json")).expect("read accounts.json"),
    )
    .expect("parse accounts.json");

    println!("Qualification phase: prepare database authority and operator approvals");
    let db = Db::new().await;
    let mut owner = db.connect(OWNER).await;
    register_provider(&mut owner, &provider_id, &issuer, &client_id, &revision).await;

    let approved_user = seed_unapproved_user(&mut owner, &issuer, &accounts.approved.subject).await;
    approve_identity_via_script(
        &mut owner,
        &db.name,
        &provider_id,
        &issuer,
        &accounts.approved.subject,
    )
    .await;
    let invitation_code = create_home_invitation_via_script(
        &db.name,
        &provider_id,
        &issuer,
        &accounts.invited.subject,
    );

    let app_listener = TcpListener::bind(("127.0.0.1", app_port))
        .await
        .expect("bind application loopback listener");
    let pool = pooled::one_slot(db.options(API));
    let service = Arc::new(BrowserAuth::new(config, pool));
    let handoff = LoginHandoff::new(service, browser_profile.handoff()).unwrap();
    let routes = router_with_sessions(
        handoff,
        browser_profile.router(),
        browser_profile.sessions(),
    )
    .unwrap();

    let observed = Arc::new(Mutex::new(KeycloakObservations::default()));
    let observer_config = Arc::new(KeycloakObserverConfig {
        authorization_endpoint,
        client_id,
        callback_url,
        issuer: issuer.clone(),
        provider: provider.clone(),
    });
    let routes = observe_keycloak(routes, observer_config, observed.clone())
        .route("/", get(|| async { Html(KEYCLOAK_LOGIN) }))
        .route("/app", get(|| async { Html(LANDING) }));

    let app_ca = tls::Ca::new();
    let app_ca_pem = String::from_utf8(app_ca.pem()).expect("utf-8 app CA PEM");
    serve(app_listener, APP, &app_ca, routes);

    assert_eq!(
        provider_cache_state(&provider),
        (0, false, false),
        "no provider fetches before first sign-in"
    );

    let authorities = vec![app_ca_pem, provider_ca_pem];

    println!("Qualification phase: approved identity browser sign-in");
    run_keycloak_browser(
        app_origin.clone(),
        issuer.clone(),
        authorities.clone(),
        &accounts.approved,
        None,
    )
    .await;
    {
        let obs = observed.lock().unwrap();
        assert!(
            obs.initiation_redirect_ok,
            "approved sign-in initiation redirect (PKCE S256, exact redirect_uri, login cookie)"
        );
        assert!(
            obs.callback_ok,
            "approved sign-in callback (cross-site navigation, RFC 9207 iss, session cookie)"
        );
        assert_eq!(
            obs.session_checks,
            [(true, 204), (false, 403)],
            "approved sign-in session check before and after logout"
        );
        assert_eq!(
            obs.logouts,
            [204],
            "approved sign-in logout acknowledgement"
        );
        assert_eq!(
            obs.key_gen_after_begin,
            Some(1),
            "discovery and JWKS fetched once at login begin"
        );
        assert_eq!(
            obs.key_gen_after_callback,
            Some(1),
            "callback reused cached documents within uncacheable_reuse_seconds"
        );
    }
    let (key_gen, has_valid_snapshot, cooldown_recorded) = provider_cache_state(&provider);
    assert_eq!(
        key_gen, 1,
        "single provider fetch generation after approved sign-in"
    );
    assert!(
        has_valid_snapshot,
        "cached snapshot remains valid inside reuse window"
    );
    assert!(
        cooldown_recorded,
        "refresh cooldown recorded on initial fetch"
    );

    println!("Qualification phase: home invitation one-time code browser sign-in");
    *observed.lock().unwrap() = KeycloakObservations::default();
    run_keycloak_browser(
        app_origin,
        issuer.clone(),
        authorities,
        &accounts.invited,
        Some(invitation_code),
    )
    .await;
    {
        let obs = observed.lock().unwrap();
        assert!(
            obs.initiation_redirect_ok,
            "invited sign-in initiation redirect (PKCE S256, exact redirect_uri, login cookie)"
        );
        assert!(
            obs.callback_ok,
            "invited sign-in callback (cross-site navigation, RFC 9207 iss, session cookie)"
        );
        assert_eq!(
            obs.session_checks,
            [(true, 204), (false, 403)],
            "invited sign-in session check before and after logout"
        );
        assert_eq!(obs.logouts, [204], "invited sign-in logout acknowledgement");
        assert_eq!(
            obs.key_gen_after_begin,
            Some(1),
            "second sign-in begin reused cached documents within uncacheable_reuse_seconds"
        );
        assert_eq!(
            obs.key_gen_after_callback,
            Some(1),
            "second sign-in callback reused cached documents within uncacheable_reuse_seconds"
        );
    }

    println!("Qualification phase: verify database state and provider cache reuse");
    assert_eq!(
        provider_cache_state(&provider).0,
        1,
        "provider documents stayed within single reuse window across both sign-ins"
    );

    let invited_user: String = sqlx::query_scalar(
        "SELECT i.user_id::text
         FROM openmettle.user_identities i
         JOIN openmettle.users u ON u.id = i.user_id AND u.disabled_at IS NULL
         JOIN openmettle.scopes s ON s.personal_user_id = u.id AND s.kind = 'personal'
         WHERE i.issuer = $1 AND i.subject = $2",
    )
    .bind(&issuer)
    .bind(&accounts.invited.subject)
    .fetch_one(&mut owner)
    .await
    .expect("invited user, identity, and personal scope created by redemption");
    assert_ne!(invited_user, approved_user, "distinct local users");

    let redeemed: bool = sqlx::query_scalar(
        "SELECT h.redeemed_at IS NOT NULL
                AND h.login_id IS NOT NULL
                AND a.active
                AND i.user_id = $1::uuid
         FROM openmettle.home_invitations h
         JOIN openmettle.local_identity_approvals a ON a.id = h.approval_id
         JOIN openmettle.user_identities i ON i.id = a.identity_id
         WHERE h.id = '00000000-0000-4000-8000-000000000201'::uuid",
    )
    .bind(&invited_user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(redeemed, "home invitation marked redeemed");

    let session_rows: Vec<(String, bool, bool, bool)> = sqlx::query_as(
        "SELECT s.user_id::text, s.revoked, t.consumed, t.session_issued
         FROM openmettle.local_sessions s
         JOIN openmettle.login_transactions t ON t.id = s.login_id
         ORDER BY s.created_ms ASC",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        session_rows,
        vec![
            (approved_user, true, true, true),
            (invited_user, true, true, true),
        ],
        "two consumed logins with revoked sessions for both synthetic users"
    );
}
