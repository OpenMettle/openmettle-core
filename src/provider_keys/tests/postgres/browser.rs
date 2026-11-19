//! Full-page Chrome navigation across two HTTPS sites. The browser owns both cookies.
use super::*;
use crate::browser_auth::{
    handoff::{LoginHandoff, SESSION_COOKIE, Settings as HandoffSettings},
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
        .merge(authorization_site(callback, script));
    serve(issuer_listener, ISSUER, &f.h.ca, provider);

    run_browser(app, issuer, None, f.h.ca.pem()).await;
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

async fn run_browser(app: String, issuer: String, link: Option<String>, public_ca: Vec<u8>) {
    let status = tokio::task::spawn_blocking(move || {
        let mut command = Command::new("python3");
        command.args(["tests/browser/qualify.py", &app, &issuer]);
        if let Some(link) = link {
            command.arg(link);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .spawn()
            .expect("start browser harness");
        child.stdin.take().unwrap().write_all(&public_ca).unwrap();
        child.wait().expect("reap browser harness")
    })
    .await
    .unwrap();
    assert!(status.success(), "browser journey failed");
}

/// Redacted facts from the native journey. Only booleans are kept, never a header value.
#[derive(Default)]
struct NativeObservations {
    provider_reached: bool,
    link_reached: bool,
    /// A Referer reached the provider authorization or app-link endpoint.
    third_party_referer: bool,
    /// A Cookie reached the provider authorization or app-link endpoint.
    third_party_cookie: bool,
    /// The callback carried exactly one temporary native binding cookie.
    callback_binding: bool,
    callback_redirect: bool,
    /// The callback response set or deleted any cookie.
    callback_set_cookie: bool,
    /// Any app response set the browser session cookie.
    session_cookie_issued: bool,
    /// A Referer or Cookie reached the token, session or logout endpoint.
    backchannel_ambient: bool,
    /// The confirmation form was one URL-encoded body holding its empty field alone.
    confirmation_form: bool,
}

fn observe_native(
    routes: Router,
    callback: &'static str,
    observed: Arc<Mutex<NativeObservations>>,
) -> Router {
    routes.layer(from_fn(move |req: Request, next: Next| {
        let observed = observed.clone();
        async move {
            let path = req.uri().path().to_owned();
            let headers = req.headers();
            let ambient =
                headers.contains_key(header::REFERER) || headers.contains_key(header::COOKIE);
            // `invitation_code=` is 16 bytes: the page's one field, left empty.
            let form = req.method() == axum::http::Method::POST
                && headers
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|v| v == "application/x-www-form-urlencoded")
                && headers
                    .get(header::CONTENT_LENGTH)
                    .is_some_and(|v| v == "16");
            let bindings = headers
                .get_all(header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(';'))
                .filter(|v| v.trim().starts_with("__Host-openmettle-native-login="))
                .count();
            let response = next.run(req).await;
            let set_cookies = response.headers().get_all(header::SET_COOKIE);
            let session = set_cookies.iter().any(|v| {
                v.as_bytes()
                    .starts_with(format!("{SESSION_COOKIE}=").as_bytes())
            });
            let mut o = observed.lock().unwrap();
            o.session_cookie_issued |= session;
            if path == "/auth/native/authorize" && form {
                o.confirmation_form = response.status() == axum::http::StatusCode::SEE_OTHER;
            }
            if path == callback {
                o.callback_binding = bindings == 1;
                o.callback_redirect = response.status() == axum::http::StatusCode::SEE_OTHER;
                o.callback_set_cookie = set_cookies.iter().next().is_some();
            }
            if [
                "/auth/native/token",
                "/auth/native/session",
                "/auth/native/logout",
            ]
            .contains(&path.as_str())
            {
                o.backchannel_ambient |= ambient;
            }
            response
        }
    }))
}
// The provider authorization page and the app link see neither Referer nor Cookie.
fn observe_site(
    routes: Router,
    endpoint: &'static str,
    observed: Arc<Mutex<NativeObservations>>,
) -> Router {
    routes.layer(from_fn(move |req: Request, next: Next| {
        let observed = observed.clone();
        async move {
            if req.uri().path() == endpoint {
                let headers = req.headers();
                let mut o = observed.lock().unwrap();
                match endpoint {
                    "/authorize" => o.provider_reached = true,
                    _ => o.link_reached = true,
                }
                o.third_party_referer |= headers.contains_key(header::REFERER);
                o.third_party_cookie |= headers.contains_key(header::COOKIE);
            }
            next.run(req).await
        }
    }))
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and sandboxed Chrome required"]
async fn cross_site_native_code_delivery() {
    use crate::browser_auth::native::NativeAuth;
    let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let link_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = format!(
        "https://{APP}:{}",
        app_listener.local_addr().unwrap().port()
    );
    let issuer = format!(
        "https://{ISSUER}:{}",
        issuer_listener.local_addr().unwrap().port()
    );
    let link = format!(
        "https://links.relying.test:{}/app-link",
        link_listener.local_addr().unwrap().port()
    );
    let callback = format!("{app}/native/callback");
    let h = Harness::with_endpoints(
        policy(),
        &format!("{issuer}/authorize"),
        &format!("{app}/browser/callback"),
    )
    .await;
    let mut f = Flow::with(h).await;
    sessions::seed(&mut f, true, true).await;
    let pool = pooled::one_slot(f.db.options(API));
    let service = Arc::new(pooled::service_over(&f, &pool));
    let native = NativeAuth::new(
        service,
        signing::ID,
        &app,
        &callback,
        "synthetic.mobile",
        &link,
        8,
    )
    .unwrap();
    let observed = Arc::new(Mutex::new(NativeObservations::default()));
    let routes = native.router(super::super::router::limits().begin).unwrap();
    let routes = observe_native(routes, "/native/callback", observed.clone());
    serve(app_listener, APP, &f.h.ca, routes);

    // Ordinary HTTPS destination in the harness. No mobile OS link association is involved.
    let routes = Router::new().route("/app-link", get(|| async { "synthetic app link" }));
    let routes = observe_site(routes, "/app-link", observed.clone());
    serve(link_listener, "links.relying.test", &f.h.ca, routes);
    let routes = authorization_site(callback, f.h.script.clone());
    let routes = observe_site(routes, "/authorize", observed.clone());
    serve(issuer_listener, ISSUER, &f.h.ca, routes);
    run_browser(app, issuer, Some(link), f.h.ca.pem()).await;
    {
        let o = observed.lock().unwrap();
        assert!(o.provider_reached && o.link_reached, "observed endpoints");
        assert!(!o.third_party_referer, "Referer at provider or app link");
        assert!(!o.third_party_cookie, "Cookie at provider or app link");
        assert!(o.callback_binding && o.callback_redirect, "native callback");
        assert!(!o.callback_set_cookie, "native callback cookie change");
        assert!(!o.session_cookie_issued, "browser session cookie");
        assert!(o.confirmation_form, "confirmation form POST");
        assert!(!o.backchannel_ambient, "ambient back-channel credentials");
    }
    assert_eq!(pooled::posts(&f), 1);
    let result:(bool,bool)=sqlx::query_as("SELECT s.revoked, g.sealed IS NULL FROM openmettle.local_sessions s JOIN openmettle.native_handoffs g ON g.session_id=s.id").fetch_one(&mut f.owner).await.unwrap();
    assert_eq!(result, (true, true));
}

fn authorization_site(callback: String, script: Arc<Mutex<Script>>) -> Router {
    Router::new().route(
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
    )
}
