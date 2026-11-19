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
