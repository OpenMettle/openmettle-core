//! Two independent provider managers and primary pools run the unmounted native router
//! (ADR 0023). The schema is the migrated one, including migration 14.
use super::super::{
    handoff::{ORIGIN, request},
    router::{CODE, FORM_TYPE, Reply, head, limits, send, serve},
};
use super::*;
use crate::{
    auth_config::AuthConfig,
    browser_auth::{BrowserAuth, handoff::SESSION_COOKIE, native::NativeAuth, router::Rate},
    response_barrier::ResponseBarrier,
};
use openidconnect::url::Url;
use sqlx::PgPool;
use std::net::SocketAddr;

const CALLBACK: &str = "https://app.example.test/native/callback";
const LINK: &str = "https://links.example.test/app";
const CLIENT: &str = "synthetic.mobile";
const VERIFIER: &str = "0123456789abcdefghijklmnopqrstuvwxyz-._~ABCDEFGHIJK";
const REFUSED: &str = "native sign-in refused\n";
const NOW_MS: &str = "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint";

/// One downstream native registration on the shared deployment issuer.
#[derive(Clone, Copy)]
struct Registration {
    client: &'static str,
    link: &'static str,
    callback: &'static str,
}
const A: Registration = Registration {
    client: CLIENT,
    link: LINK,
    callback: CALLBACK,
};
// A second app on the same deployment, provider and primary database. Its upstream callback
// is separately registered with the synthetic provider.
const B: Registration = Registration {
    client: "synthetic.tablet",
    link: "https://links.example.test/tablet",
    callback: "https://app.example.test/native/tablet/callback",
};

/// The app's own attempt values. They never reach the provider.
struct App {
    registration: Registration,
    verifier: String,
    state: String,
}
impl App {
    fn new(registration: Registration, seed: u8) -> Self {
        Self {
            registration,
            verifier: format!("{VERIFIER}{seed:03}"),
            state: URL_SAFE_NO_PAD.encode([seed; 32]),
        }
    }
    fn challenge_bytes(&self) -> [u8; 32] {
        Sha256::digest(self.verifier.as_bytes()).into()
    }
    fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.challenge_bytes())
    }
    fn target(&self) -> String {
        let r = self.registration;
        format!(
            "/auth/native/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge_method=S256&state={}&code_challenge={}",
            r.client,
            r.link,
            self.state,
            self.challenge()
        )
    }
    fn callback(&self, upstream_state: &str) -> String {
        format!(
            "{}?iss={}&state={upstream_state}&code=synthetic-code",
            &self.registration.callback[ORIGIN.len()..],
            signing::ISSUER
        )
    }
    fn redeem(&self, code: &str) -> Value {
        let r = self.registration;
        json!({"grant_type":"authorization_code","iss":ORIGIN,"client_id":r.client,"redirect_uri":r.link,"code_verifier":self.verifier,"code":code})
    }
}
fn code_hash(code: &str) -> [u8; 32] {
    Sha256::digest(URL_SAFE_NO_PAD.decode(code).unwrap()).into()
}
/// Upstream values of one managed login, as the browser saw them.
struct Started {
    location: String,
    cookie: String,
    state: String,
    challenge: String,
}

const FORM_REFUSED: &str = "native sign-in request refused\n";
const BODY_REFUSED: &str = "native sign-in request body not accepted\n";
const BODY_NOT_RECEIVED: &str = "native sign-in request body not received\n";
/// Migration 14's role boundary as the roles meet it: the worker reads nothing, and the API
/// role can neither extend a grant, rebind it nor remove it.
async fn role_boundaries(f: &mut Flow) {
    let mut worker = f.db.connect(WORKER).await;
    let denied = |err: sqlx::Error| {
        assert_eq!(
            err.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("42501")
        );
    };
    denied(
        worker
            .execute("SELECT * FROM openmettle.native_handoffs")
            .await
            .unwrap_err(),
    );
    for sql in [
        "UPDATE openmettle.native_handoffs SET expires_ms=1",
        "UPDATE openmettle.native_handoffs SET challenge=code_hash",
        "UPDATE openmettle.native_handoffs SET audience=registration",
        "DELETE FROM openmettle.native_handoffs",
    ] {
        denied(f.api.execute(sql).await.unwrap_err());
    }
}
fn native(auth: Arc<BrowserAuth>, r: Registration) -> NativeAuth {
    NativeAuth::new(auth, signing::ID, ORIGIN, r.callback, r.client, r.link, 8).unwrap()
}
fn profile(auth: Arc<BrowserAuth>) -> NativeAuth {
    native(auth, A)
}
async fn mount(auth: Arc<BrowserAuth>, r: Registration) -> SocketAddr {
    serve(native(auth, r).router(limits().begin).unwrap()).await
}
/// Another process: its own provider manager, the fixture clock and `pool`.
fn replica(f: &Flow, pool: PgPool, login_lifetime: Duration) -> Arc<BrowserAuth> {
    replica_with(
        f,
        pool,
        login_lifetime,
        policy(),
        sessions::session_policy(),
    )
    .0
}
/// Another process with explicit provider-refresh and session policies, returning both the
/// service and its provider handle so timed tests can warm its key snapshot first.
fn replica_with(
    f: &Flow,
    pool: PgPool,
    login_lifetime: Duration,
    refresh: RefreshPolicy,
    session_policy: crate::sessions::Policy,
) -> (Arc<BrowserAuth>, ManagedProvider) {
    let manager = ProviderManager::new(refresh);
    let clock = f.h.manager.inner.clock.lock().unwrap().clone();
    *manager.inner.clock.lock().unwrap() = clock;
    let p = manager
        .register(Harness::config(&f.h.server, &f.h.ca, "v2"))
        .unwrap();
    manager.retire(&p).unwrap();
    let provider = manager
        .register(Harness::config(&f.h.server, &f.h.ca, "v1"))
        .unwrap();
    assert!(provider.generation > 1);
    let auth = Arc::new(BrowserAuth::new(
        AuthConfig::fixture(
            keys(),
            login_lifetime,
            session_policy,
            manager,
            vec![provider.clone()],
        ),
        pool,
    ));
    (auth, provider)
}
/// A one-slot pool whose only backend runs through `barrier`. The backend is opened before
/// any counted reply. A replacement after a discarded connection bypasses the barrier.
async fn proxied(f: &Flow, barrier: &ResponseBarrier) -> PgPool {
    let pool = pooled::one_slot(
        f.db.options(API)
            .host("127.0.0.1")
            .port(barrier.port)
            .ssl_mode(sqlx::postgres::PgSslMode::Disable),
    );
    sqlx::query("SELECT 1").execute(&pool).await.unwrap();
    pool.set_connect_options(f.db.options(API));
    pool
}
fn exchanged(f: &Flow) -> Vec<String> {
    f.h.script.lock().unwrap().exchanged.clone()
}
async fn primary_ms(owner: &mut PgConnection) -> i64 {
    sqlx::query_scalar(NOW_MS).fetch_one(owner).await.unwrap()
}
async fn wait_past(owner: &mut PgConnection, expiry: i64) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while primary_ms(owner).await <= expiry {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("primary clock did not pass the grant expiry");
}
/// No code, bearer, redirect or cookie of any kind.
fn nothing_released(reply: &Reply) {
    assert_eq!((reply.status, reply.body.as_str()), (403, REFUSED));
    assert!(reply.all("set-cookie").is_empty());
    assert!(reply.all("location").is_empty());
}
/// The confirmed `POST` from a page on `origin`. A non-empty `body` is declared and carried
/// as the confirmation form.
fn confirm(target: &str, origin: &str, body: &str) -> String {
    if body.is_empty() {
        return head("POST", target, &[("origin", origin)]);
    }
    let length = body.len().to_string();
    let headers = [("origin", origin), FORM_TYPE, ("content-length", &length)];
    head("POST", target, &headers) + body
}
async fn start(address: SocketAddr, app: &App) -> Started {
    start_with(address, app, "").await.1
}
/// One confirmed start whose form is `body`: the reply and the upstream values in it.
async fn start_with(address: SocketAddr, app: &App, body: &str) -> (Reply, Started) {
    let response = send(address, &confirm(&app.target(), ORIGIN, body)).await;
    assert_eq!(response.status, 303);
    let location = response.one("location").to_owned();
    let params: HashMap<_, _> = Url::parse(&location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(params["redirect_uri"], app.registration.callback);
    assert_eq!(params["code_challenge_method"], "S256");
    // Upstream state and PKCE are fresh per login and independent of the app's values.
    assert_ne!(params["code_challenge"], app.challenge());
    assert_ne!(params["state"], app.state);
    let (cookie, attributes) = response.one("set-cookie").split_once(';').unwrap();
    assert!(attributes.starts_with(" Max-Age="));
    assert!(attributes.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax"));
    let value = cookie
        .strip_prefix("__Host-openmettle-native-login=")
        .unwrap();
    let parts: Vec<&str> = value.split('.').collect();
    let (locator, _) = params["state"].split_once('.').unwrap();
    assert_eq!(
        (parts.len(), parts[0], parts[2], parts[3]),
        (4, locator, app.challenge().as_str(), app.state.as_str())
    );
    assert!(!location.contains(parts[1]));
    let started = Started {
        cookie: cookie.to_owned(),
        state: params["state"].clone(),
        challenge: params["code_challenge"].clone(),
        location,
    };
    (response, started)
}
async fn complete(f: &Flow, app: &App, start_at: SocketAddr, finish_at: SocketAddr) -> Reply {
    let started = start(start_at, app).await;
    f.arm_url(&started.location);
    let upstream = exchanged(f);
    let target = app.callback(&started.state);
    let send_callback = |cookie: &str| head("GET", &target, &[("cookie", cookie)]);
    let wrong_issuer = target.replace(signing::ISSUER, "https://other.example.test");
    nothing_released(
        &send(
            finish_at,
            &head("GET", &wrong_issuer, &[("cookie", &started.cookie)]),
        )
        .await,
    );
    // The app's own state is not the upstream state.
    nothing_released(
        &send(
            finish_at,
            &send_callback(&started.cookie).replace(&started.state, &app.state),
        )
        .await,
    );
    // Attempt substitution changes the managed login's authenticated transaction binding.
    let (prefix, _) = started.cookie.rsplit_once('.').unwrap();
    let tampered = format!("{prefix}.{}", URL_SAFE_NO_PAD.encode([4; 32]));
    assert_eq!(send(finish_at, &send_callback(&tampered)).await.status, 403);
    assert_eq!(exchanged(f), upstream);
    let reply = send(finish_at, &send_callback(&started.cookie)).await;
    let replay = send(start_at, &send_callback(&started.cookie)).await;
    assert_eq!(replay.status, 403);
    assert!(replay.all("set-cookie").is_empty() && replay.all("location").is_empty());
    // The callback never sets or deletes a cookie, whatever its outcome.
    assert!(reply.all("set-cookie").is_empty());
    let after = exchanged(f);
    if reply.status == 303 {
        // One token POST, bound to this login's upstream challenge and exact callback.
        assert_eq!(after[..upstream.len()], upstream[..]);
        assert_eq!(after[upstream.len()..], [started.challenge]);
    } else {
        assert!(after.len() <= upstream.len() + 1);
    }
    reply
}
/// The app-link redirect: exactly code, the app's state and the deployment issuer.
fn link_code(reply: &Reply, app: &App) -> String {
    assert_eq!(reply.status, 303);
    assert!(reply.all("set-cookie").is_empty());
    let url = Url::parse(reply.one("location")).unwrap();
    assert!(
        url.as_str()
            .starts_with(&format!("{}?", app.registration.link))
    );
    assert_eq!(url.query_pairs().count(), 3);
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(params["state"], app.state);
    assert_eq!(params["iss"], ORIGIN);
    assert_eq!(params["code"].len(), 43);
    params["code"].clone()
}
async fn code(f: &Flow, app: &App, start_at: SocketAddr, finish_at: SocketAddr) -> String {
    link_code(&complete(f, app, start_at, finish_at).await, app)
}
fn post(input: &Value) -> String {
    // Native serializers can escape slashes in JSON URL strings.
    let body = input.to_string().replace('/', r"\/");
    head(
        "POST",
        "/auth/native/token",
        &[
            ("content-type", "application/json"),
            ("content-length", &body.len().to_string()),
        ],
    ) + &body
}
fn bearer(reply: &Reply) -> String {
    assert_eq!(reply.status, 200);
    assert_eq!(reply.one("cache-control"), "no-store");
    assert!(reply.all("set-cookie").is_empty());
    let json: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 2);
    assert_eq!(json["token_type"], "Bearer");
    json["access_token"].as_str().unwrap().to_owned()
}
async fn status(address: SocketAddr, method: &str, route: &str, bearer: &str) -> u16 {
    let target = format!("/auth/native/{route}");
    let authorization = format!("Bearer {bearer}");
    send(
        address,
        &head(method, &target, &[("authorization", &authorization)]),
    )
    .await
    .status
}
/// Valid through each listed replica of its own registration. Refused for validation and
/// logout through `foreign`, and that refused logout leaves it valid.
async fn isolated(own: &[SocketAddr], foreign: SocketAddr, bearer: &str) {
    assert_eq!(status(foreign, "GET", "session", bearer).await, 403);
    assert_eq!(status(foreign, "POST", "logout", bearer).await, 403);
    for at in own {
        assert_eq!(status(*at, "GET", "session", bearer).await, 204);
    }
}
async fn services(f: &Flow) -> (Arc<BrowserAuth>, SocketAddr, SocketAddr) {
    let pool = pooled::one_slot(f.db.options(API));
    let auth = Arc::new(pooled::service_over(f, &pool));
    let replica = replica(
        f,
        pooled::one_slot(f.db.options(API)),
        Duration::from_secs(300),
    );
    let a = mount(auth.clone(), A).await;
    let b = mount(replica, A).await;
    (auth, a, b)
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn two_replicas_deliver_once_with_exact_pkce_registration_and_channel() {
    let mut f = Flow::new().await;
    role_boundaries(&mut f).await;
    sessions::seed(&mut f, true, true).await;
    let (auth, a, b) = services(&f).await;
    let app = App::new(A, 3);
    let request = app.redeem(&code(&f, &app, a, b).await);
    // The downstream verifier never reaches the provider.
    assert!(
        !f.h.script
            .lock()
            .unwrap()
            .authorizations
            .contains_key(&app.challenge())
    );
    for (field, value) in [
        ("client_id", "other"),
        ("redirect_uri", "https://other.example.test/app"),
        ("iss", "https://other.example.test"),
        ("code_verifier", &"x".repeat(43)),
    ] {
        let mut wrong = request.clone();
        wrong[field] = value.into();
        nothing_released(&send(a, &post(&wrong)).await);
    }
    let req = post(&request);
    let (one, two) = tokio::join!(send(a, &req), send(b, &req));
    // Exactly one cross-replica claimant receives the bearer. The other gets no cookie,
    // redirect or token.
    let (ok, lost) = match (one.status, two.status) {
        (200, 403) => (one, two),
        (403, 200) => (two, one),
        _ => panic!("exactly one redemption must win"),
    };
    nothing_released(&lost);
    let bearer = bearer(&ok);
    nothing_released(&send(b, &req).await);
    assert!(auth.validate(&bearer).await.is_err());
    assert!(auth.logout(&bearer).await.is_err());
    let browser = sessions::issue(&mut f).await;
    for (route, method) in [("session", "GET"), ("logout", "POST")] {
        let target = format!("/auth/native/{route}");
        assert_eq!(status(a, method, route, browser.expose()).await, 403);
        assert_eq!(
            send(
                a,
                &head(
                    method,
                    &target,
                    &[("cookie", &format!("__Host-openmettle-session={bearer}"))]
                )
            )
            .await
            .status,
            403
        );
        assert_eq!(status(a, method, route, &bearer).await, 204);
    }
    assert_eq!(status(b, "GET", "session", &bearer).await, 403);
    auth.validate(browser.expose()).await.unwrap();
    let empty: bool = sqlx::query_scalar("SELECT sealed IS NULL FROM openmettle.native_handoffs")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert!(empty);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn registrations_isolate_codes_bearers_and_logout_across_revisions() {
    let mut f = Flow::new().await;
    let user = sessions::seed(&mut f, true, true).await;
    let (auth, a1, a2) = services(&f).await;
    let b = mount(auth, B).await;
    let (mobile, tablet) = (App::new(A, 7), App::new(B, 8));
    let mobile_code = code(&f, &mobile, a1, a2).await;
    let tablet_code = code(&f, &tablet, b, b).await;
    // Replicas of one registration store one audience. Registrations differ in both values.
    let distinct: (i64, i64) = sqlx::query_as(
        "SELECT count(DISTINCT audience), count(DISTINCT registration) FROM openmettle.native_handoffs",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(distinct, (2, 2));
    // Neither registration redeems the other's code: with the code's own registration fields,
    // or with the serving registration's fields and the original verifier.
    for (owner, code, serving, at) in [
        (&mobile, &mobile_code, &tablet, b),
        (&tablet, &tablet_code, &mobile, a1),
    ] {
        nothing_released(&send(at, &post(&owner.redeem(code))).await);
        let mut substituted = serving.redeem(code);
        substituted["code_verifier"] = owner.verifier.clone().into();
        nothing_released(&send(at, &post(&substituted)).await);
    }
    let mobile_bearer = bearer(&send(a2, &post(&mobile.redeem(&mobile_code))).await);
    let tablet_bearer = bearer(&send(b, &post(&tablet.redeem(&tablet_code))).await);
    isolated(&[a1, a2], b, &mobile_bearer).await;
    isolated(&[b], a1, &tablet_bearer).await;
    isolated(&[b], a2, &tablet_bearer).await;

    // Routine provider and approval revisions fence a pending code but keep delivered sessions
    // in their own audience only.
    let pending = App::new(A, 9);
    let pending_code = code(&f, &pending, a1, a2).await;
    write(&mut f.owner, Some("v2")).await;
    f.owner
        .execute("UPDATE openmettle.local_identity_approvals SET revision=revision+1,change_reason='routine extension',expires_ms=expires_ms+1000")
        .await
        .unwrap();
    write(&mut f.owner, Some("v1")).await;
    nothing_released(&send(a1, &post(&pending.redeem(&pending_code))).await);
    isolated(&[a1, a2], b, &mobile_bearer).await;
    isolated(&[b], a1, &tablet_bearer).await;

    // A second redemption attempt on the fenced code still releases nothing.
    nothing_released(&send(a1, &post(&pending.redeem(&pending_code))).await);

    // New logins after the revisions, then sign-out through the owning registration.
    let (mobile_late_app, tablet_late_app) = (App::new(A, 10), App::new(B, 11));
    let mobile_late_code = code(&f, &mobile_late_app, a2, a1).await;
    let mobile_late = bearer(&send(a1, &post(&mobile_late_app.redeem(&mobile_late_code))).await);
    let tablet_late_code = code(&f, &tablet_late_app, b, b).await;
    let tablet_late = bearer(&send(b, &post(&tablet_late_app.redeem(&tablet_late_code))).await);
    assert_eq!(status(a2, "POST", "logout", &mobile_bearer).await, 204);
    for at in [a1, a2] {
        assert_eq!(status(at, "GET", "session", &mobile_bearer).await, 403);
    }
    assert_eq!(status(b, "GET", "session", &tablet_bearer).await, 204);
    assert_eq!(status(b, "POST", "logout", &tablet_bearer).await, 204);
    assert_eq!(status(b, "GET", "session", &tablet_bearer).await, 403);

    // Owner sign-out still works for a disabled user, and for a retired, unreachable provider.
    // A foreign registration still cannot sign either bearer out.
    crate::sessions::disable_user(&mut f.api, &user, 0, &sessions::session_policy())
        .await
        .unwrap();
    assert_eq!(status(a1, "GET", "session", &mobile_late).await, 403);
    assert_eq!(status(b, "POST", "logout", &mobile_late).await, 403);
    assert_eq!(status(a1, "POST", "logout", &mobile_late).await, 204);
    write(&mut f.owner, None).await;
    f.h.script.lock().unwrap().mode = "failure";
    let requests = f.h.count();
    assert_eq!(status(a1, "POST", "logout", &tablet_late).await, 403);
    assert_eq!(status(b, "POST", "logout", &tablet_late).await, 204);
    assert_eq!(f.h.count(), requests);
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.native_handoffs")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(total, 5);
    // Every grant was claimed once (clearing `sealed`), including the fenced pending code
    // whose post-claim validation refused the stale provider epoch without releasing a
    // bearer. Only the four delivered bearers were revoked, each by its own registration.
    for (name, app, handoff_code, expected) in [
        ("mobile", &mobile, &mobile_code, (true, true)),
        ("tablet", &tablet, &tablet_code, (true, true)),
        ("pending", &pending, &pending_code, (true, false)),
        (
            "mobile_late",
            &mobile_late_app,
            &mobile_late_code,
            (true, true),
        ),
        (
            "tablet_late",
            &tablet_late_app,
            &tablet_late_code,
            (true, true),
        ),
    ] {
        let state: (bool, bool) = sqlx::query_as(
            "SELECT g.sealed IS NULL, s.revoked
             FROM openmettle.native_handoffs g
             JOIN openmettle.local_sessions s ON s.id=g.session_id
             WHERE g.code_hash=$1 AND g.challenge=$2",
        )
        .bind(code_hash(handoff_code).as_slice())
        .bind(app.challenge_bytes().as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
        assert_eq!(state, expected, "{name}");
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn overlapping_attempt_keeps_its_binding_cookie_and_completes() {
    let mut f = Flow::new().await;
    sessions::seed(&mut f, true, true).await;
    let (_, a, b) = services(&f).await;
    let (first, second) = (App::new(A, 5), App::new(A, 6));
    let older = start(a, &first).await;
    f.arm_url(&older.location);
    let posts = pooled::posts(&f);
    let gate = f.h.script.lock().unwrap().gate.clone();
    f.h.script.lock().unwrap().mode = "gate-post";
    // An unrelated browser session credential travels with the callback. It must stay untouched.
    let cookies = format!(
        "{}; {SESSION_COOKIE}=synthetic-browser-session",
        older.cookie
    );
    let request = head(
        "GET",
        &first.callback(&older.state),
        &[("cookie", &cookies)],
    );
    let callback = send(b, &request);
    tokio::pin!(callback);
    let newer = tokio::select! {
        reply = &mut callback => panic!("callback ended before its token response: {}", reply.status),
        newer = async {
            // Callback A is held at its token response while initiation B replaces the cookie.
            tokio::time::timeout(Duration::from_secs(10), async {
                while pooled::posts(&f) == posts {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("token POST not received");
            let newer = start(a, &second).await;
            f.arm_url(&newer.location);
            f.h.script.lock().unwrap().mode = "ok";
            gate.notify_one();
            newer
        } => newer,
    };
    let older_code = link_code(&callback.await, &first);
    // Replays of A, with its own cookie and with the newer cookie the browser now holds,
    // release nothing and set or delete no cookie.
    for cookie in [cookies.as_str(), newer.cookie.as_str()] {
        let replay = send(
            b,
            &head("GET", &first.callback(&older.state), &[("cookie", cookie)]),
        )
        .await;
        assert_eq!(replay.status, 403);
        assert!(replay.all("set-cookie").is_empty() && replay.all("location").is_empty());
    }
    let reply = send(
        a,
        &head(
            "GET",
            &second.callback(&newer.state),
            &[("cookie", &newer.cookie)],
        ),
    )
    .await;
    let newer_code = link_code(&reply, &second);
    bearer(&send(a, &post(&first.redeem(&older_code))).await);
    bearer(&send(b, &post(&second.redeem(&newer_code))).await);
    assert_eq!(exchanged(&f), [older.challenge, newer.challenge]);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn grant_expiry_during_final_validation_acknowledgement_releases_no_code() {
    // An eight-second login lifetime clips the grant. The session (60 s), assertion (about
    // 290 s on the fixture clock) and the 30 s exchange and 20 s session deadlines outlast it.
    // Both replicas warm their key snapshots before the login starts so CI load does not spend
    // the login lifetime on discovery or JWKS fetches before reaching the validation barrier.
    let secs = Duration::from_secs;
    let refresh = RefreshPolicy::new(secs(600), secs(2), secs(30), 2, 32, 2).unwrap();
    let session_policy = crate::sessions::Policy::new(secs(60), 16, secs(20)).unwrap();
    let mut f = Flow::with(Harness::with_policy(refresh).await).await;
    sessions::seed(&mut f, true, true).await;
    let lifetime = secs(8);
    let initiating = Arc::new(service::browser_auth(
        &f.h,
        pooled::one_slot(f.db.options(API)),
        lifetime,
        session_policy,
    ));
    let a = mount(initiating, A).await;
    // On the callback replica's only backend: consume, issuance, then final validation commit.
    let mut barrier = ResponseBarrier::nth(b"COMMIT\0", 3);
    let pool = proxied(&f, &barrier).await;
    let (replica_auth, replica_provider) =
        replica_with(&f, pool.clone(), lifetime, refresh, session_policy);
    f.h.provider.ensure().await.unwrap();
    replica_provider.ensure().await.unwrap();
    let b = mount(replica_auth, A).await;
    let app = App::new(A, 14);
    let started = start(a, &app).await;
    f.arm_url(&started.location);
    let request = callback_request(&app, &started);
    let callback = send(b, &request);
    tokio::pin!(callback);
    tokio::select! {
        () = barrier.wait_reached() => {},
        reply = &mut callback => panic!("callback ended before the validation barrier: {}", reply.status),
    }
    let (grant, login, session): (i64, i64, i64) = sqlx::query_as(
        "SELECT g.expires_ms, l.expires_ms, s.expires_ms
         FROM openmettle.native_handoffs g
         JOIN openmettle.local_sessions s ON s.id=g.session_id
         JOIN openmettle.login_transactions l ON l.id=s.login_id
         WHERE g.challenge=$1",
    )
    .bind(app.challenge_bytes().as_slice())
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(grant, login);
    wait_past(&mut f.owner, grant).await;
    assert!(session > primary_ms(&mut f.owner).await + 10_000);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut callback)
            .await
            .is_err()
    );
    barrier.resume();
    nothing_released(&callback.await);
    let row: (bool, bool) = sqlx::query_as(
        "SELECT g.sealed IS NOT NULL, s.revoked
         FROM openmettle.native_handoffs g
         JOIN openmettle.local_sessions s ON s.id=g.session_id
         WHERE g.challenge=$1",
    )
    .bind(app.challenge_bytes().as_slice())
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(row, (true, false));
    assert_eq!(exchanged(&f), [started.challenge]);
    pool.close().await;
    drop(barrier);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn pending_grant_expiry_alone_refuses_while_session_is_unexpired() {
    let mut f = Flow::new().await;
    sessions::seed(&mut f, true, true).await;
    let (_, a, _) = services(&f).await;
    // Issuance: only the grant expires while the issuance COMMIT acknowledgement is held.
    let mut barrier = ResponseBarrier::nth(b"COMMIT\0", 2);
    let pool = proxied(&f, &barrier).await;
    let b = mount(replica(&f, pool.clone(), Duration::from_secs(300)), A).await;
    let app = App::new(A, 15);
    let started = start(a, &app).await;
    f.arm_url(&started.location);
    let request = head(
        "GET",
        &app.callback(&started.state),
        &[("cookie", &started.cookie)],
    );
    let callback = send(b, &request);
    tokio::pin!(callback);
    tokio::select! {
        () = barrier.wait_reached() => {},
        reply = &mut callback => panic!("callback ended before the issuance barrier: {}", reply.status),
    }
    f.owner
        .execute(AssertSqlSafe(format!(
            "UPDATE openmettle.native_handoffs SET expires_ms=({NOW_MS})"
        )))
        .await
        .unwrap();
    barrier.resume();
    nothing_released(&callback.await);
    pool.close().await;
    drop(barrier);
    // Redemption: a delivered code whose grant alone has expired.
    let app = App::new(A, 16);
    let code = code(&f, &app, a, a).await;
    f.owner
        .execute(AssertSqlSafe(format!(
            "UPDATE openmettle.native_handoffs SET expires_ms=({NOW_MS})"
        )))
        .await
        .unwrap();
    nothing_released(&send(a, &post(&app.redeem(&code))).await);
    let rows: Vec<(bool, bool, bool)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT g.sealed IS NOT NULL, NOT s.revoked, s.expires_ms > ({NOW_MS})
         FROM openmettle.native_handoffs g JOIN openmettle.local_sessions s ON s.id=g.session_id"
    )))
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(rows, [(true, true, true); 2]);
}

/// One callback request of `app`'s attempt, as the browser sends it.
fn callback_request(app: &App, started: &Started) -> String {
    head(
        "GET",
        &app.callback(&started.state),
        &[("cookie", &started.cookie)],
    )
}
/// The grant for `app`: its stored window from the session's creation, what remains of it now,
/// whether its code is still unclaimed and whether its session is unrevoked.
async fn grant_state(owner: &mut PgConnection, app: &App) -> (i64, i64, bool, bool) {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT g.expires_ms - s.created_ms, g.expires_ms - ({NOW_MS}), g.sealed IS NOT NULL,
                NOT s.revoked
         FROM openmettle.native_handoffs g JOIN openmettle.local_sessions s ON s.id=g.session_id
         WHERE g.challenge=$1"
    )))
    .bind(app.challenge_bytes().as_slice())
    .fetch_one(owner)
    .await
    .unwrap()
}
/// The full 30 s from the final clock read of issuance, which follows the session's creation
/// inside one transaction.
fn full_window(window: i64) {
    assert!((30_000..40_000).contains(&window), "{window}");
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn slow_exchange_under_the_provider_deadline_leaves_the_app_its_window() {
    let mut f = Flow::new().await;
    sessions::seed(&mut f, true, true).await;
    let (_, a, b) = services(&f).await;
    let app = App::new(A, 30);
    let started = start(a, &app).await;
    f.arm_url(&started.location);
    // The provider answers the token request after 1.5 s of the 5 s provider deadline.
    let provider_deadline = policy().deadline;
    assert_eq!(provider_deadline, Duration::from_secs(5));
    let posts = pooled::posts(&f);
    let gate = f.h.script.lock().unwrap().gate.clone();
    f.h.script.lock().unwrap().mode = "gate-post";
    let sent = Instant::now();
    let request = callback_request(&app, &started);
    let callback = send(b, &request);
    tokio::pin!(callback);
    tokio::select! {
        reply = &mut callback => panic!("callback ended before its token response: {}", reply.status),
        () = async {
            tokio::time::timeout(Duration::from_secs(10), async {
                while pooled::posts(&f) == posts {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("token POST not received");
            tokio::time::sleep(Duration::from_millis(1500)).await;
            f.h.script.lock().unwrap().mode = "ok";
            gate.notify_one();
        } => {},
    }
    let code = link_code(&callback.await, &app);
    // The stored grant is not clipped to what the exchange left of the provider deadline.
    let (window, _, pending, _) = grant_state(&mut f.owner, &app).await;
    full_window(window);
    assert!(pending);
    // The app redeems after that deadline has passed, as after a slow launch.
    tokio::time::sleep_until(sent + provider_deadline + Duration::from_millis(500)).await;
    let token = bearer(&send(a, &post(&app.redeem(&code))).await);
    assert_eq!(status(b, "GET", "session", &token).await, 204);
    assert_eq!(exchanged(&f), [started.challenge]);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn short_key_reuse_window_bounds_the_release_and_not_the_stored_grant() {
    // The provider documents refuse caching, so a key snapshot lives for the ten-second
    // reuse window. A 30 s provider deadline keeps the operation deadlines out of the way.
    let secs = Duration::from_secs;
    let refresh = RefreshPolicy::new(secs(600), secs(2), secs(30), 2, 32, 2)
        .unwrap()
        .with_uncacheable_reuse(secs(10))
        .unwrap();
    let mut f = Flow::with(Harness::with_policy(refresh).await).await;
    {
        let mut script = f.h.script.lock().unwrap();
        script.cache = "no-store".into();
        script.metadata_cache = "no-store".into();
    }
    sessions::seed(&mut f, true, true).await;
    // Both services use the harness manager, and so one key snapshot on the fixture clock.
    let pool = pooled::one_slot(f.db.options(API));
    let a = mount(Arc::new(pooled::service_over(&f, &pool)), A).await;

    // Stored grant: issued with two seconds of key freshness left, and redeemed after the
    // snapshot has expired.
    let app = App::new(A, 32);
    let started = start(a, &app).await;
    f.arm_url(&started.location);
    let fetched = f.h.count();
    f.h.advance(8);
    let code = link_code(&send(a, &callback_request(&app, &started)).await, &app);
    // The callback reused the snapshot: its one provider request is the token POST.
    assert_eq!(f.h.count(), fetched + 1);
    let (window, _, pending, _) = grant_state(&mut f.owner, &app).await;
    full_window(window);
    assert!(pending);
    f.h.advance(3);
    let token = bearer(&send(a, &post(&app.redeem(&code))).await);
    assert_eq!(status(a, "GET", "session", &token).await, 204);
    assert_eq!(f.h.count(), fetched + 1);

    // Release: the same two seconds bound the issuing process. The final validation's
    // acknowledgement is withheld past them on the callback service's only backend, after
    // the consume and issuance commits. The fixture clock stands still, so every later
    // proof check passes and only the code's release deadline refuses.
    let mut barrier = ResponseBarrier::nth(b"COMMIT\0", 3);
    let held_pool = proxied(&f, &barrier).await;
    let b = mount(Arc::new(pooled::service_over(&f, &held_pool)), A).await;
    let app = App::new(A, 33);
    let started = start(a, &app).await;
    f.arm_url(&started.location);
    let fetched = f.h.count();
    f.h.advance(8);
    let request = callback_request(&app, &started);
    let callback = send(b, &request);
    tokio::pin!(callback);
    tokio::select! {
        () = barrier.wait_reached() => {},
        reply = &mut callback => panic!("callback ended before the validation barrier: {}", reply.status),
    }
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut callback)
            .await
            .is_err()
    );
    barrier.resume();
    nothing_released(&callback.await);
    assert_eq!(f.h.count(), fetched + 1);
    // The stored grant is whole and unexpired. Its code never left the process.
    let (window, remaining, pending, unrevoked) = grant_state(&mut f.owner, &app).await;
    full_window(window);
    assert!(remaining > 20_000, "{remaining}");
    assert!(pending && unrevoked);
    assert_eq!(exchanged(&f).len(), 2);
    held_pool.close().await;
    drop(barrier);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn stored_audience_alone_refuses_a_pending_code_and_its_redemption() {
    let mut f = Flow::new().await;
    sessions::seed(&mut f, true, true).await;
    let (_, a, _) = services(&f).await;
    // Another audience under an unchanged registration, challenge, code and expiry. Only the
    // owner can write it (`role_boundaries`).
    const REBIND: &str = "UPDATE openmettle.native_handoffs SET audience=sha256(audience)
        WHERE challenge=$1
        RETURNING registration, audience";
    const GRANT: &str = "SELECT g.registration, g.audience, g.sealed IS NOT NULL, NOT s.revoked,
            g.expires_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 20000
        FROM openmettle.native_handoffs g JOIN openmettle.local_sessions s ON s.id=g.session_id
        WHERE g.challenge=$1";
    type Grant = (Vec<u8>, Vec<u8>, bool, bool, bool);

    // Issuance: the audience changes while the issuance COMMIT acknowledgement is held, so
    // the final validation meets a grant that differs in its audience only.
    let mut barrier = ResponseBarrier::nth(b"COMMIT\0", 2);
    let pool = proxied(&f, &barrier).await;
    let b = mount(replica(&f, pool.clone(), Duration::from_secs(300)), A).await;
    let app = App::new(A, 34);
    let started = start(a, &app).await;
    f.arm_url(&started.location);
    let request = callback_request(&app, &started);
    let callback = send(b, &request);
    tokio::pin!(callback);
    tokio::select! {
        () = barrier.wait_reached() => {},
        reply = &mut callback => panic!("callback ended before the issuance barrier: {}", reply.status),
    }
    let challenge = app.challenge_bytes();
    let issued: Grant = sqlx::query_as(GRANT)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    let rebound: (Vec<u8>, Vec<u8>) = sqlx::query_as(REBIND)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(rebound.0, issued.0);
    assert_ne!(rebound.1, issued.1);
    barrier.resume();
    nothing_released(&callback.await);
    let after: Grant = sqlx::query_as(GRANT)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    // Unclaimed, unrevoked and unexpired, with the registration it was issued under.
    assert_eq!(after, (issued.0, rebound.1, true, true, true));
    pool.close().await;
    drop(barrier);

    // Redemption: a delivered code whose grant differs in its audience only. The claim
    // matches the code, the challenge and the registration and commits. The validation
    // after it refuses, and no bearer is released then or later.
    let app = App::new(A, 35);
    let delivered = code(&f, &app, a, a).await;
    let challenge = app.challenge_bytes();
    let issued: Grant = sqlx::query_as(GRANT)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    let rebound: (Vec<u8>, Vec<u8>) = sqlx::query_as(REBIND)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(rebound.0, issued.0);
    assert_ne!(rebound.1, issued.1);
    let request = post(&app.redeem(&delivered));
    nothing_released(&send(a, &request).await);
    let after: Grant = sqlx::query_as(GRANT)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(after, (issued.0, rebound.1, false, true, true));
    nothing_released(&send(a, &request).await);

    // Control: the same steps without the change deliver and redeem.
    let app = App::new(A, 36);
    let delivered = code(&f, &app, a, a).await;
    let token = bearer(&send(a, &post(&app.redeem(&delivered))).await);
    assert_eq!(status(a, "GET", "session", &token).await, 204);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn withheld_claim_acknowledgement_releases_once_and_never_retries() {
    let mut f = Flow::new().await;
    sessions::seed(&mut f, true, true).await;
    let (_, a, _) = services(&f).await;
    // The claim commits on replica C, whose acknowledgement is withheld. A concurrent claimant
    // on A receives nothing. C then delivers the bearer once.
    let mut barrier = ResponseBarrier::new(b"COMMIT\0");
    let pool = proxied(&f, &barrier).await;
    let c = mount(replica(&f, pool.clone(), Duration::from_secs(300)), A).await;
    let app = App::new(A, 12);
    let request = post(&app.redeem(&code(&f, &app, a, a).await));
    let held = send(c, &request);
    tokio::pin!(held);
    tokio::select! {
        () = barrier.wait_reached() => {},
        reply = &mut held => panic!("redemption ended before the claim barrier: {}", reply.status),
    }
    let claimed: bool = sqlx::query_scalar("SELECT sealed IS NULL FROM openmettle.native_handoffs")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert!(claimed);
    nothing_released(&send(a, &request).await);
    barrier.resume();
    let token = bearer(&held.await);
    assert_eq!(status(a, "GET", "session", &token).await, 204);
    nothing_released(&send(a, &request).await);
    pool.close().await;
    drop(barrier);

    // The grant passes its expiry while the claim acknowledgement is withheld. Nothing is
    // released, the claim is not retried and no new upstream exchange starts.
    let secs = Duration::from_secs;
    let session_policy = crate::sessions::Policy::new(secs(60), 16, secs(20)).unwrap();
    let short = Arc::new(service::browser_auth(
        &f.h,
        pooled::one_slot(f.db.options(API)),
        secs(8),
        session_policy,
    ));
    let short = mount(short, A).await;
    let mut barrier = ResponseBarrier::new(b"COMMIT\0");
    let pool = proxied(&f, &barrier).await;
    let (replica_auth, _) = replica_with(&f, pool.clone(), secs(300), policy(), session_policy);
    let c = mount(replica_auth, A).await;
    let app = App::new(A, 13);
    let started = start(short, &app).await;
    f.arm_url(&started.location);
    let delivered = link_code(&send(short, &callback_request(&app, &started)).await, &app);
    let request = post(&app.redeem(&delivered));
    let (posts, upstream) = (pooled::posts(&f), exchanged(&f));
    let held = send(c, &request);
    tokio::pin!(held);
    tokio::select! {
        () = barrier.wait_reached() => {},
        reply = &mut held => panic!("redemption ended before the claim barrier: {}", reply.status),
    }
    const GRANT: &str =
        "SELECT g.expires_ms, l.expires_ms, s.expires_ms, g.sealed IS NULL, s.revoked
        FROM openmettle.native_handoffs g
        JOIN openmettle.local_sessions s ON s.id=g.session_id
        JOIN openmettle.login_transactions l ON l.id=s.login_id
        WHERE g.challenge=$1";
    let challenge = app.challenge_bytes();
    let (grant, login, session, _, _): (i64, i64, i64, bool, bool) = sqlx::query_as(GRANT)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(grant, login);
    wait_past(&mut f.owner, grant).await;
    assert!(session > primary_ms(&mut f.owner).await + 10_000);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut held)
            .await
            .is_err()
    );
    barrier.resume();
    nothing_released(&held.await);
    nothing_released(&send(a, &request).await);
    assert_eq!((pooled::posts(&f), exchanged(&f)), (posts, upstream));
    let (_, _, _, claimed, revoked): (i64, i64, i64, bool, bool) = sqlx::query_as(GRANT)
        .bind(challenge.as_slice())
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!((claimed, revoked), (true, false));
    pool.close().await;
    drop(barrier);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn grant_expiry_withdrawal_disablement_and_retirement_prevent_delivery() {
    let mut f = Flow::new().await;
    let (_, a, b) = services(&f).await;
    assert_eq!(complete(&f, &App::new(A, 3), a, b).await.status, 403);
    let user = sessions::seed(&mut f, true, true).await;
    for (seed, event) in [
        (20, "expiry"),
        (22, "withdraw"),
        (24, "disable"),
        (26, "retire"),
    ] {
        let delivered = App::new(A, seed);
        let delivered = post(&delivered.redeem(&code(&f, &delivered, a, b).await));
        let token = bearer(&send(a, &delivered).await);
        let pending = App::new(A, seed + 1);
        let pending = post(&pending.redeem(&code(&f, &pending, b, a).await));
        match event {
            "expiry" => {
                f.owner.execute("UPDATE openmettle.native_handoffs SET expires_ms=1 WHERE sealed IS NOT NULL").await.unwrap();
                f.owner
                    .execute("UPDATE openmettle.local_sessions SET expires_ms=created_ms+1")
                    .await
                    .unwrap();
            }
            "withdraw" => {
                f.owner.execute("UPDATE openmettle.local_identity_approvals SET active=false,access_generation=access_generation+1,revision=revision+1").await.unwrap();
                f.owner.execute("UPDATE openmettle.local_identity_approvals SET active=true,revision=revision+1").await.unwrap();
            }
            "disable" => {
                crate::sessions::disable_user(&mut f.api, &user, 0, &sessions::session_policy())
                    .await
                    .unwrap();
                f.owner
                    .execute("UPDATE openmettle.users SET disabled_at=NULL")
                    .await
                    .unwrap();
            }
            _ => {
                write(&mut f.owner, None).await;
                write(&mut f.owner, Some("v1")).await;
            }
        }
        nothing_released(&send(a, &pending).await);
        assert_eq!(status(b, "GET", "session", &token).await, 403);
    }
}

#[tokio::test]
async fn confirmation_and_invalid_registrations_need_no_database_or_provider_request() {
    let h = Harness::new().await;
    let (listener, pool) = service::silent_database();
    let auth = Arc::new(service::browser_auth(
        &h,
        pool,
        Duration::from_secs(60),
        sessions::session_policy(),
    ));
    // Production app links are HTTPS only. A private scheme is never accepted here.
    for link in [
        "synthetic-app:/callback",
        "http://example.test/link",
        "https://example.test/a/../link",
        "https://example.test/link?",
        "https://user@example.test/link",
        "https://app.example.test/healthz",
        "https://app.example.test/readyz",
        CALLBACK,
    ] {
        assert!(
            NativeAuth::new(auth.clone(), signing::ID, ORIGIN, CALLBACK, CLIENT, link, 4).is_err()
        );
    }
    assert!(
        NativeAuth::new(
            auth.clone(),
            signing::ID,
            ORIGIN,
            signing::CALLBACK,
            CLIENT,
            LINK,
            4
        )
        .is_err()
    );
    let native = profile(auth);
    let target = App::new(A, 3).target();
    let response = native.authorize(&request("GET", &target, &[]), &[]).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["referrer-policy"], "same-origin");
    assert!(response.headers().get("set-cookie").is_none());
    // The page posts back exactly one field, the optional invitation code (ADR 0022). A
    // named control or a hidden field would be refused as an unknown form field.
    let page = *response.body();
    assert_eq!(page.matches(" name=").count(), 1);
    assert!(page.contains("<form method=post>") && page.contains(" name=invitation_code "));
    let line = |response: axum::http::Response<&'static str>| {
        (response.status().as_u16(), *response.body())
    };
    let coded = format!("invitation_code={CODE}");
    for modified in [
        target.replace(CLIENT, "unregistered"),
        target.replace(LINK, "https://other.example.test/app"),
        target.replace("S256", "plain"),
        format!("{target}&state=repeated"),
        // An invitation code is never accepted in the query, with or without a form.
        format!("{target}&{coded}"),
    ] {
        for body in ["", coded.as_str()] {
            for method in ["GET", "POST"] {
                let request = request(method, &modified, &[("origin", ORIGIN)]);
                let response = native.authorize(&request, body.as_bytes()).await;
                assert_eq!(line(response), (403, REFUSED), "{method}");
            }
        }
    }
    // Origin is decided before the form: a foreign page gets the origin refusal whatever
    // its form holds, and only the deployment's own page gets the form refusal.
    for body in ["", coded.as_str(), "invitation_code=not-a-code"] {
        for origins in [
            &[][..],
            &[("origin", "null")],
            &[("origin", "https://other.example.test")],
        ] {
            let request = request("POST", &target, origins);
            let response = native.authorize(&request, body.as_bytes()).await;
            assert_eq!(line(response), (403, REFUSED));
        }
    }
    let repeated = format!("{coded}&{coded}");
    let named_button = format!("{coded}&confirm=");
    for (case, body) in [
        "x=1",
        "invitation_code",
        "invitation_code=not-a-code",
        "invitation_code=omh1-0123",
        "invitation_code=%zz",
        repeated.as_str(),
        named_button.as_str(),
    ]
    .into_iter()
    .enumerate()
    {
        let request = request("POST", &target, &[("origin", ORIGIN)]);
        let response = native.authorize(&request, body.as_bytes()).await;
        assert!(response.headers().get("set-cookie").is_none(), "{case}");
        assert_eq!(line(response), (400, FORM_REFUSED), "{case}");
    }
    assert_eq!(h.count(), 0);
    assert!(listener.accept().is_err());
}

#[tokio::test]
async fn preview_and_start_spend_separate_budgets_and_other_methods_spend_none() {
    let h = Harness::new().await;
    let (_listener, pool) = service::silent_database();
    let auth = Arc::new(service::browser_auth(
        &h,
        pool,
        Duration::from_secs(60),
        sessions::session_policy(),
    ));
    let one = Rate {
        burst: 1,
        interval: Duration::from_secs(3600),
    };
    let address = serve(profile(auth.clone()).router(one).unwrap()).await;
    let target = App::new(A, 3).target();
    let callback = &CALLBACK[ORIGIN.len()..];
    let routes: [(&str, &[&str]); 5] = [
        (&target, &["GET", "POST"]),
        (callback, &["GET"]),
        ("/auth/native/token", &["POST"]),
        ("/auth/native/session", &["GET"]),
        ("/auth/native/logout", &["POST"]),
    ];
    // Unsupported methods are refused first, and spend no unit of any budget.
    for (path, allowed) in routes {
        for method in ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"] {
            if !allowed.contains(&method) {
                let reply = send(address, &head(method, path, &[])).await;
                assert_eq!((reply.status, reply.body.as_str()), (403, REFUSED));
            }
        }
    }
    // With burst 1, the confirmation preview and its POST are both admitted. The silent
    // database then refuses the started login.
    assert_eq!(send(address, &head("GET", &target, &[])).await.status, 200);
    let started = send(address, &head("POST", &target, &[("origin", ORIGIN)])).await;
    assert_eq!(started.status, 503);
    let limited = |reply: Reply| {
        assert_eq!(
            (reply.status, reply.body.as_str()),
            (429, "native request rate exceeded\n")
        );
    };
    limited(send(address, &head("GET", &target, &[])).await);
    limited(send(address, &head("POST", &target, &[("origin", ORIGIN)])).await);
    for (path, method) in [
        (callback, "GET"),
        ("/auth/native/token", "POST"),
        ("/auth/native/session", "GET"),
        ("/auth/native/logout", "POST"),
    ] {
        assert_eq!(send(address, &head(method, path, &[])).await.status, 403);
        limited(send(address, &head(method, path, &[])).await);
    }

    // An unsupported method takes no request slot. One slot is held by a token body that
    // never arrives, so a supported request is busy while an unsupported one is refused.
    let native = NativeAuth::new(auth, signing::ID, ORIGIN, CALLBACK, CLIENT, LINK, 1).unwrap();
    let address = serve(native.router(limits().begin).unwrap()).await;
    let stalled = head(
        "POST",
        "/auth/native/token",
        &[
            ("content-type", "application/json"),
            ("content-length", "64"),
        ],
    );
    let stalled = tokio::spawn(async move { send(address, &stalled).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while send(address, &head("GET", "/auth/native/session", &[]))
            .await
            .status
            != 503
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("body slot was not taken");
    let reply = send(address, &head("PUT", "/auth/native/session", &[])).await;
    assert_eq!((reply.status, reply.body.as_str()), (403, REFUSED));
    assert_eq!(stalled.await.unwrap().status, 403);
    assert_eq!(h.count(), 2);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn handoff_cannot_outlive_remaining_assertion_age_on_another_replica() {
    let mut f = Flow::new().await;
    sessions::seed(&mut f, true, true).await;
    // Fixture ID token issued at T-10, maximum age 300s. Four seconds remain.
    {
        let mut script = f.h.script.lock().unwrap();
        script.cache = "max-age=600".into();
        script.metadata_cache = "max-age=600".into();
    }
    f.h.advance(286);
    let (_, a, b) = services(&f).await;
    let app = App::new(A, 3);
    let pending = app.redeem(&code(&f, &app, a, b).await);
    let (grant, clipped): (i64, bool) = sqlx::query_as(
        "SELECT g.expires_ms,
                g.expires_ms <= floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 4000
                    AND g.expires_ms < s.expires_ms AND g.expires_ms < l.expires_ms
         FROM openmettle.native_handoffs g JOIN openmettle.local_sessions s ON s.id=g.session_id
         JOIN openmettle.login_transactions l ON l.id=s.login_id
         WHERE g.challenge=$1",
    )
    .bind(app.challenge_bytes().as_slice())
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(clipped);
    wait_past(&mut f.owner, grant).await;
    nothing_released(&send(a, &post(&pending)).await);
    assert_eq!(pooled::posts(&f), 1);
}

#[tokio::test]
async fn native_http_refusals_do_not_checkout_or_exchange() {
    let h = Harness::new().await;
    let (listener, pool) = service::silent_database();
    let auth = Arc::new(service::browser_auth(
        &h,
        pool,
        Duration::from_secs(60),
        sessions::session_policy(),
    ));
    let address = serve(profile(auth).router(limits().begin).unwrap()).await;
    let app = App::new(A, 3);
    let mut input = app.redeem(&URL_SAFE_NO_PAD.encode([9; 32]));
    let fields = [
        "grant_type",
        "iss",
        "client_id",
        "redirect_uri",
        "code",
        "code_verifier",
    ];
    // The six members are named. A positional array of the same values and an object that
    // lacks any one member are refused.
    let positional = Value::Array(fields.iter().map(|field| input[*field].clone()).collect());
    assert_eq!(send(address, &post(&positional)).await.status, 403);
    for field in fields {
        let mut incomplete = input.clone();
        incomplete.as_object_mut().unwrap().remove(field);
        assert_eq!(send(address, &post(&incomplete)).await.status, 403);
    }
    // A provider code outside the one syntax rule is refused by the callback parser, with a
    // well-formed cookie and state, before the service is called.
    let locator = URL_SAFE_NO_PAD.encode([2; 32]);
    let secret = URL_SAFE_NO_PAD.encode([3; 32]);
    let cookie = format!("__Host-openmettle-native-login={locator}.{secret}.{secret}.{secret}");
    for code in ["", "%20", "%C3%A9", &"x".repeat(login::MAX_CODE_BYTES + 1)] {
        let callback = format!(
            "/native/callback?iss={}&state={locator}.{secret}&code={code}",
            signing::ISSUER
        );
        assert_eq!(
            send(address, &head("GET", &callback, &[("cookie", &cookie)]))
                .await
                .status,
            403
        );
    }
    for (name, value) in [
        ("iss", "https://foreign.example.test"),
        ("client_id", "another"),
        ("redirect_uri", "synthetic-app:/callback"),
        ("code_verifier", "short"),
        ("grant_type", "refresh_token"),
    ] {
        let old = input[name].clone();
        input[name] = value.into();
        assert_eq!(send(address, &post(&input)).await.status, 403);
        input[name] = old;
    }
    let cookie_only = head(
        "GET",
        "/auth/native/session",
        &[("cookie", "__Host-openmettle-session=synthetic")],
    );
    assert_eq!(send(address, &cookie_only).await.status, 403);
    for body in [r#"{"code":"a","code":"b"}"#, r#"{}"#, &"a".repeat(8193)] {
        let req = head(
            "POST",
            "/auth/native/token",
            &[
                ("content-type", "application/json"),
                ("content-length", &body.len().to_string()),
            ],
        ) + body;
        assert_eq!(send(address, &req).await.status, 403);
    }
    assert_eq!(h.count(), 0);
    assert!(listener.accept().is_err());
}

/// The confirmed start follows the browser initiation body rules (ADR 0022), through actual
/// Axum dispatch. Metadata alone refuses a body outside both profiles, before a rate unit is
/// spent. An admitted form is read with a bound and a timeout, and decided after `Origin`
/// and before any provider or database work.
#[tokio::test]
async fn confirmed_start_takes_one_bounded_invitation_form_before_any_service_work() {
    let h = Harness::new().await;
    let (listener, pool) = service::silent_database();
    let attempted = || listener.accept().is_ok();
    let auth = Arc::new(service::browser_auth(
        &h,
        pool,
        Duration::from_secs(60),
        sessions::session_policy(),
    ));
    // Exactly the nine requests admitted below, and no refill within the test.
    let rate = Rate {
        burst: 9,
        interval: Duration::from_secs(3600),
    };
    let address = serve(profile(auth).router(rate).unwrap()).await;
    let target = App::new(A, 3).target();
    let coded = format!("invitation_code={CODE}");
    let declared = |headers: &[(&str, &str)]| {
        let mut all = vec![("origin", ORIGIN)];
        all.extend_from_slice(headers);
        head("POST", &target, &all)
    };

    // 1. Outside both body profiles. Only the head is sent: the refusal reads no body.
    for headers in [
        &[FORM_TYPE, ("transfer-encoding", "chunked")][..],
        &[FORM_TYPE, ("content-length", "257")],
        &[FORM_TYPE, ("content-length", "060")],
        &[("content-length", "60")],
        &[("content-type", "text/plain"), ("content-length", "60")],
        &[
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            ),
            ("content-length", "60"),
        ],
        &[FORM_TYPE, FORM_TYPE, ("content-length", "60")],
    ] {
        send(address, &declared(headers))
            .await
            .refused(413, BODY_REFUSED);
    }

    // 2. Admitted, and refused without service work. A foreign page gets the origin
    // refusal for a valid and for a malformed form alike (two units).
    let foreign = "https://other.example.test";
    for body in [coded.as_str(), "invitation_code=not-a-code"] {
        send(address, &confirm(&target, foreign, body))
            .await
            .refused(403, REFUSED);
    }
    // A code in the query is refused even with a valid form (one unit).
    let queried = format!("{target}&{coded}");
    send(address, &confirm(&queried, ORIGIN, &coded))
        .await
        .refused(403, REFUSED);
    // A malformed form from the deployment's own page is the fixed form refusal (two units).
    for body in ["x=1", "invitation_code=omh1-0123"] {
        send(address, &confirm(&target, ORIGIN, body))
            .await
            .refused(400, FORM_REFUSED);
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // 3. A declared form that stalls after five bytes is given up after the read timeout
    // (one unit). It reached neither the provider nor the database.
    let length = coded.len().to_string();
    let stalled = declared(&[FORM_TYPE, ("content-length", &length)]) + &coded[..5];
    let begun = Instant::now();
    send(address, &stalled)
        .await
        .refused(408, BODY_NOT_RECEIVED);
    assert!(begun.elapsed() >= crate::browser_auth::router::FORM_READ_TIMEOUT);
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // 4. A well-formed code, an empty value and an empty body all reach the service with
    // the same reply (three units). The code is not checked against any invitation here.
    let mut replies = Vec::new();
    for body in [coded.as_str(), "invitation_code=", ""] {
        let reply = send(address, &confirm(&target, ORIGIN, body)).await;
        assert!(attempted(), "the service did not reach the database");
        assert_eq!(reply.status, 503);
        let headers = reply.headers.iter().filter(|(name, _)| name != "date");
        replies.push((headers.cloned().collect::<Vec<_>>(), reply.body));
    }
    assert!(replies.iter().all(|reply| *reply == replies[0]));
    assert_eq!(h.count(), 2);

    // 5. The budget is spent by exactly the nine admitted requests. None of the metadata
    // refusals above took a unit, and one more does not either.
    let over = send(address, &confirm(&target, ORIGIN, &coded)).await;
    assert_eq!(over.status, 429);
    send(address, &declared(&[FORM_TYPE, ("content-length", "257")]))
        .await
        .refused(413, BODY_REFUSED);
    assert_eq!(h.count(), 2);
    assert!(!attempted());
}

/// One complete native sign-in whose confirmation form is `body`.
struct SignIn {
    app: App,
    /// The login's public locator.
    login: String,
    start: Reply,
    callback: Reply,
}
/// `(ciphertext bytes, native binding layout)` of a stored login.
async fn stored_login(f: &mut Flow, login: &str) -> (i32, bool) {
    sqlx::query_as(
        "SELECT octet_length(ciphertext),
                substring(binding FROM 1 FOR 34)
                    = convert_to('openmettle/native-managed-login/1', 'SQL_ASCII') || '\\x00'::bytea
           FROM openmettle.login_transactions WHERE id = $1",
    )
    .bind(login)
    .fetch_one(&mut f.owner)
    .await
    .unwrap()
}
async fn sign_in(f: &mut Flow, address: SocketAddr, seed: u8, body: &str) -> SignIn {
    let app = App::new(A, seed);
    let (start, started) = start_with(address, &app, body).await;
    let login = started.state.split_once('.').unwrap().0.to_owned();
    // The stored login is sealed at one length whatever the form carried, and it carries
    // the native binding layout that migration 14 admits.
    assert_eq!(stored_login(f, &login).await, (76, true));
    f.arm_url(&started.location);
    let request = head(
        "GET",
        &app.callback(&started.state),
        &[("cookie", &started.cookie)],
    );
    let callback = send(address, &request).await;
    SignIn {
        app,
        login,
        start,
        callback,
    }
}
/// Redeems a delivered code and validates the bearer through `native`: the signed-in user.
async fn delivered_user(
    native: &NativeAuth,
    address: SocketAddr,
    app: &App,
    reply: &Reply,
) -> String {
    let code = link_code(reply, app);
    let token = bearer(&send(address, &post(&app.redeem(&code))).await);
    let context = native.validate(&token).await.unwrap();
    context.user_id().to_owned()
}
/// `(pending, redeemed by this login)` over every invitation.
async fn invitations(f: &mut Flow, login: &str) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE approval_id IS NULL AND withdrawn_at IS NULL
                    AND redeemed_at IS NULL AND login_id IS NULL),
                count(*) FILTER (WHERE approval_id IS NOT NULL AND redeemed_at IS NOT NULL
                    AND login_id = $1)
           FROM openmettle.home_invitations",
    )
    .bind(login)
    .fetch_one(&mut f.owner)
    .await
    .unwrap()
}

// ADR 0022 through the native flow (ADR 0023): the code a person enters in the system
// browser's confirmation form is the only thing that lets their first native sign-in create
// the account. Every sign-in below is a complete flow through the router: confirmation
// form POST, provider, upstream callback and, where a code is delivered, redemption.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn first_native_sign_in_needs_the_invitation_code_entered_in_the_confirmation_form() {
    use super::handoff::{entered, login_state, observable, start_shape};
    use super::invitations::{OTHER, create, created, empty, invite, pending};
    let mut f = Flow::new().await;
    let (auth, a, b) = services(&f).await;
    // The same registration as both routers, for direct validation of a delivered bearer.
    let native = profile(auth);

    // Nobody is invited. A person who enters a well-formed code completes the provider
    // sign-in and is refused at the callback. This is the reference refusal.
    let uninvited = sign_in(&mut f, a, 30, &format!("invitation_code={CODE}")).await;
    uninvited.callback.refused(403, REFUSED);
    assert_eq!(
        login_state(&mut f, &uninvited.login).await,
        (true, true, false)
    );
    empty(&mut f).await;

    // The operator invites the person, and someone else. Only the create command ever
    // shows a code.
    let code = invite(&f);
    let other = created(&create(&f, OTHER, signing::ID, "other-subject"));
    let correct = entered(code.bytes());
    let mut near = *code.bytes();
    near[15] ^= 1;
    let wrong = entered(&near);
    let another = entered(other.bytes());
    let unassigned = format!("invitation_code={CODE}");

    // No form body, an empty field, a code that differs in one bit, the other invitation's
    // code and a code no invitation has. Each sign-in starts like any other, is refused with
    // exactly the reply an uninvited person gets, spends its login and leaves both
    // invitations pending.
    for (seed, body) in [
        (31, ""),
        (32, "invitation_code="),
        (33, wrong.as_str()),
        (34, another.as_str()),
        (35, unassigned.as_str()),
    ] {
        let refused = sign_in(&mut f, a, seed, body).await;
        assert_eq!(
            start_shape(&refused.start),
            start_shape(&uninvited.start),
            "{seed}"
        );
        assert_eq!(
            observable(&refused.callback),
            observable(&uninvited.callback),
            "{seed}"
        );
        assert_eq!(
            login_state(&mut f, &refused.login).await,
            (true, true, false),
            "{seed}"
        );
        empty(&mut f).await;
        pending(&mut f, 2).await;
    }
    // Each of the six refused sign-ins reached the provider once: none was refused early.
    assert_eq!(pooled::posts(&f), 6);

    // A malformed code and a code in the query are refused at the start: no login row and
    // no provider request.
    let (rows, requests) = (f.rows().await, f.h.count());
    let target = App::new(A, 39).target();
    for body in ["invitation_code=omh1-0123", "code=0123"] {
        send(a, &confirm(&target, ORIGIN, body))
            .await
            .refused(400, FORM_REFUSED);
    }
    let queried = format!("{target}&{correct}");
    send(a, &confirm(&queried, ORIGIN, ""))
        .await
        .refused(403, REFUSED);
    assert_eq!(send(a, &head("GET", &queried, &[])).await.status, 403);
    assert_eq!((f.rows().await, f.h.count()), (rows, requests));

    // A new sign-in with the correct code, typed as displayed, creates the account. The
    // callback finishes on the other replica.
    let app = App::new(A, 40);
    let (start, started) = start_with(a, &app, &correct).await;
    assert_eq!(start_shape(&start), start_shape(&uninvited.start));
    let login = started.state.split_once('.').unwrap().0.to_owned();
    assert_eq!(stored_login(&mut f, &login).await, (76, true));
    // The stored login holds the code only inside its ciphertext.
    let visible: bool = sqlx::query_scalar(
        "SELECT position(encode($1, 'hex') IN to_jsonb(t)::text) > 0
           FROM openmettle.login_transactions t WHERE id = $2",
    )
    .bind(code.bytes().as_slice())
    .bind(&login)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(
        !visible,
        "the login row shows the code outside its ciphertext"
    );
    f.arm_url(&started.location);
    let request = head(
        "GET",
        &app.callback(&started.state),
        &[("cookie", &started.cookie)],
    );
    let reply = send(b, &request).await;
    // The app link carries the handoff code, the app state and the issuer, and nothing of
    // the invitation code.
    let hex: String = code.bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !reply.one("location").contains(&hex),
        "the app link repeats the invitation code"
    );
    let user = delivered_user(&native, b, &app, &reply).await;
    assert_eq!(login_state(&mut f, &login).await, (true, true, true));
    let accounts = sessions::account_state(&mut f).await;
    assert_eq!(accounts.len(), 3); // one user, one identity, one private scope
    assert_eq!(invitations(&mut f, &login).await, (1, 1));

    // The identity now exists, so a code is ignored: the spent code, a wrong code, the other
    // pending invitation's code and no code all sign in to that one account through its
    // ordinary approval. The other invitation stays pending.
    for (seed, body) in [
        (41, correct.as_str()),
        (42, wrong.as_str()),
        (43, another.as_str()),
        (44, ""),
    ] {
        let again = sign_in(&mut f, a, seed, body).await;
        assert_eq!(
            delivered_user(&native, a, &again.app, &again.callback).await,
            user,
            "{seed}"
        );
    }
    assert_eq!(sessions::account_state(&mut f).await, accounts);
    assert_eq!(invitations(&mut f, &login).await, (1, 1));

    // A disabled account stays refused with the correct code, and no account is created.
    crate::sessions::disable_user(&mut f.api, &user, 0, &sessions::session_policy())
        .await
        .unwrap();
    let disabled = sessions::account_state(&mut f).await;
    let refused = sign_in(&mut f, a, 45, &correct).await;
    assert_eq!(
        observable(&refused.callback),
        observable(&uninvited.callback)
    );
    assert_eq!(sessions::account_state(&mut f).await, disabled);
    assert_eq!(disabled.len(), accounts.len());
}

/// A consumed login that the API role writes with plain SQL, holding exactly `binding`.
async fn consumed_login(f: &mut Flow, mark: u8, binding: &[u8]) -> String {
    let login = format!("{mark:n>43}");
    sqlx::query(
        "INSERT INTO openmettle.login_nonce_reservations (key_id, nonce) VALUES ('layout', $1)",
    )
    .bind(vec![mark; 12])
    .execute(&mut f.api)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.login_transactions
            (id,binding,expires_ms,state_hash,nonce_hash,caller_hash,key_id,nonce,ciphertext)
         VALUES ($1,$2,floor(extract(epoch FROM clock_timestamp())*1000)::bigint+60000,
                 $3,$3,$3,'layout',$4,decode(repeat('00',76),'hex'))",
    )
    .bind(&login)
    .bind(binding)
    .bind(vec![mark; 32])
    .bind(vec![mark; 12])
    .execute(&mut f.api)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.login_transactions SET consumed=true,ciphertext=NULL WHERE id=$1",
    )
    .bind(&login)
    .execute(&mut f.api)
    .await
    .unwrap();
    login
}

// Migration 14's binding check, called directly with the correct code. The function admits
// the managed layout and the native layout of the exact provider configuration and epoch,
// and no other bytes. Each refused binding differs from an admitted one in one respect.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn redemption_admits_exactly_the_managed_and_native_binding_layouts() {
    use super::invitations::{empty, invite, pending, redeem_direct};
    let mut f = Flow::new().await;
    let code = invite(&f);
    let epoch: i64 = sqlx::query_scalar(
        "SELECT max(epoch) FROM openmettle.login_provider_revisions WHERE provider_id=$1::uuid",
    )
    .bind(signing::ID)
    .fetch_one(&mut f.api)
    .await
    .unwrap();
    let config = f.h.provider.config().unwrap().binding.clone();
    let revised = Harness::config(&f.h.server, &f.h.ca, "v2").binding;
    let attempt = [0x5a; 32];
    let field = |bytes: &[u8]| [&(bytes.len() as u64).to_be_bytes()[..], bytes].concat();
    let layout = |domain: &[u8], fields: &[&[u8]]| {
        let mut binding = domain.to_vec();
        for bytes in fields {
            binding.extend(field(bytes));
        }
        binding
    };
    let stored_epoch = epoch.to_be_bytes();
    let native = persisted(&config, Some(&attempt), epoch);
    let managed = persisted(&config, None, epoch);
    assert_eq!(
        native,
        layout(NATIVE_DOMAIN, &[&config, &attempt, &stored_epoch])
    );
    // The attempt's length field says 31 while 32 bytes follow, so every other offset holds.
    let mut mislabelled = native.clone();
    let length_field = NATIVE_DOMAIN.len() + 8 + config.len();
    mislabelled[length_field..length_field + 8].copy_from_slice(&31_u64.to_be_bytes());
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        ("the native binding", native.clone(), true),
        ("the managed binding", managed.clone(), true),
        (
            "a native binding of another epoch",
            persisted(&config, Some(&attempt), epoch + 1),
            false,
        ),
        (
            "a managed binding of another epoch",
            persisted(&config, None, epoch + 1),
            false,
        ),
        (
            "a native binding of another revision",
            persisted(&revised, Some(&attempt), epoch),
            false,
        ),
        (
            "the native domain without an attempt",
            layout(NATIVE_DOMAIN, &[&config, &stored_epoch]),
            false,
        ),
        (
            "the managed domain with an attempt",
            layout(MANAGED_DOMAIN, &[&config, &attempt, &stored_epoch]),
            false,
        ),
        (
            "a 31-byte attempt",
            layout(NATIVE_DOMAIN, &[&config, &attempt[..31], &stored_epoch]),
            false,
        ),
        (
            "a 33-byte attempt",
            layout(NATIVE_DOMAIN, &[&config, &[0x5a; 33], &stored_epoch]),
            false,
        ),
        ("an attempt labelled 31 bytes", mislabelled, false),
        ("a trailing byte", [native.as_slice(), &[0]].concat(), false),
        (
            "a missing last byte",
            native[..native.len() - 1].to_vec(),
            false,
        ),
        (
            "another native domain version",
            layout(
                b"openmettle/native-managed-login/2\0",
                &[&config, &attempt, &stored_epoch],
            ),
            false,
        ),
    ];
    for (mark, (case, binding, admitted)) in cases.iter().enumerate() {
        let login = consumed_login(&mut f, b'a' + mark as u8, binding).await;
        let mut tx = f.api.begin().await.unwrap();
        let row = redeem_direct(&mut tx, signing::ID, &login, epoch, &code).await;
        assert_eq!(row.is_some(), *admitted, "{case}");
        // An admitted redemption is discarded: this test decides the binding check alone.
        tx.rollback().await.unwrap();
    }
    empty(&mut f).await;
    pending(&mut f, 1).await;
}
