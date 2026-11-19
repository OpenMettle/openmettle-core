//! The browser login handoff (ADR 0017) through the pooled service: one form POST to one
//! session cookie, with the fixture TLS provider, called directly and then through the
//! bounded router over loopback HTTP (ADR 0018), and the session check and logout routes
//! over issued cookies (ADR 0019). Isolated CI PostgreSQL 18 only.
use super::super::handoff::{
    BINDING_REFUSED, LOGIN_REFUSED, ORIGIN, RESPONSE_REFUSED, refused, request, settings,
};
use super::super::router::{CODE, FORM_REFUSED, Reply, form_with, head, limits, send, serve};
use super::pooled::{one_slot, posts, service_over};
use super::sessions::{account_state, issue, seed, session_policy};
use super::*;
use crate::browser_auth::{
    handoff::{LOGIN_COOKIE, LoginHandoff, SESSION_COOKIE},
    router::{Rate, SessionSettings, Settings, router, router_with_sessions},
};
use axum::http::{Response, StatusCode, header};
use std::net::SocketAddr;

const ATTRIBUTES: &str = "; Path=/; Secure; HttpOnly; SameSite=Lax";

/// A handoff redirect: `303`, no body, never stored, one `Location` and one `Set-Cookie`,
/// both sensitive and absent from the response's debug output.
fn redirected(response: &Response<&'static str>) -> (String, String) {
    assert_eq!(
        (response.status(), *response.body()),
        (StatusCode::SEE_OTHER, "")
    );
    let headers = response.headers();
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    let debug = format!("{response:?}");
    let single = |name: header::HeaderName| {
        let mut values = headers.get_all(&name).iter();
        let value = values.next().unwrap();
        assert!(values.next().is_none(), "{name} repeated");
        assert!(value.is_sensitive(), "{name} not sensitive");
        let value = value.to_str().unwrap().to_owned();
        assert!(!debug.contains(&value), "{name} in debug output");
        value
    };
    (single(header::LOCATION), single(header::SET_COOKIE))
}
struct Attempt {
    authorization_url: String,
    state: String,
    /// `name=value`, as the browser returns it.
    cookie: String,
}
/// An initiation response: the provider's authorization URL and the caller cookie bound to
/// that login's public locator, expiring with the configured login lifetime.
fn started(response: &Response<&'static str>) -> Attempt {
    let (authorization_url, set_cookie) = redirected(response);
    let url = openidconnect::url::Url::parse(&authorization_url).unwrap();
    assert_eq!(
        url.origin().ascii_serialization() + url.path(),
        signing::AUTH
    );
    let parameters: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(parameters["redirect_uri"], signing::CALLBACK);
    let state = parameters["state"].clone();
    let cookie = set_cookie
        .strip_suffix(&format!("; Max-Age=300{ATTRIBUTES}"))
        .expect("caller cookie attributes")
        .to_owned();
    let (locator, caller) = cookie
        .strip_prefix(&format!("{LOGIN_COOKIE}="))
        .and_then(|value| value.split_once('.'))
        .expect("caller cookie name and shape");
    assert_eq!(Some(locator), state.split_once('.').map(|(id, _)| id));
    assert_eq!((locator.len(), caller.len()), (43, 43));
    // The caller secret appears in the cookie alone.
    assert!(!authorization_url.contains(caller));
    Attempt {
        authorization_url,
        state,
        cookie,
    }
}
async fn consumed(f: &mut Flow, attempt: &Attempt) -> bool {
    sqlx::query_scalar("SELECT consumed FROM openmettle.login_transactions WHERE id = $1")
        .bind(attempt.state.split_once('.').unwrap().0)
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn form_post_becomes_one_session_cookie_and_stale_or_replayed_callbacks_set_nothing() {
    let mut f = Flow::new().await;
    let user = seed(&mut f, true, true).await;
    let pool = one_slot(f.db.options(API));
    let auth = Arc::new(service_over(&f, &pool));
    let handoff = LoginHandoff::new(auth.clone(), settings()).unwrap();
    let form = request("POST", "/login", &[("origin", ORIGIN)]);
    let callback = |attempt: &Attempt, cookies: &str| {
        let target = format!(
            "/callback?code=synthetic-code&state={}&iss=https%3A%2F%2Fissuer.example.test%2Frealm&session_state=synthetic",
            attempt.state
        );
        request("GET", &target, &[("cookie", cookies)])
    };

    // Two initiations from one browser: the cookie slot now holds the second login.
    let older = started(&handoff.initiate(&form, b"").await);
    let current = started(&handoff.initiate(&form, b"").await);
    assert_ne!(older.cookie, current.cookie);
    assert_eq!(f.rows().await, 2);

    // The binding refusal identifies the adapter's locator check. The request count and
    // row state also confirm that no further provider request or consumption occurred.
    let requests = f.h.count();
    let stale = handoff.callback(&callback(&older, &current.cookie)).await;
    refused(&stale, StatusCode::BAD_REQUEST, BINDING_REFUSED);
    assert_eq!(f.h.count(), requests);
    assert!(!consumed(&mut f, &older).await);

    // The response refusal identifies the adapter's provider-error check. The login
    // remains unconsumed and the provider has received no token POST.
    let target = format!(
        "/callback?error=access_denied&error_description=SECRET-provider-text&state={}",
        current.state
    );
    let headers = [("cookie", current.cookie.as_str())];
    let denied = handoff.callback(&request("GET", &target, &headers)).await;
    refused(&denied, StatusCode::BAD_REQUEST, RESPONSE_REFUSED);
    assert!(!consumed(&mut f, &current).await);
    assert_eq!(posts(&f), 0);

    // The current login completes: one token request, then the landing and the session
    // cookie. An earlier session cookie on the request is neither read nor required.
    f.arm_url(&current.authorization_url);
    let cookies = format!(
        "theme=dark; {}; {SESSION_COOKIE}=synthetic-earlier",
        current.cookie
    );
    let complete = handoff.callback(&callback(&current, &cookies)).await;
    let (landing, set_cookie) = redirected(&complete);
    assert_eq!(landing, "https://app.example.test/app");
    let credential = set_cookie
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .and_then(|rest| rest.strip_suffix(ATTRIBUTES))
        .expect("session cookie name and attributes");
    assert_eq!(credential.len(), 87);
    assert_eq!(posts(&f), 1);
    let context = auth.validate(credential).await.unwrap();
    assert_eq!(context.user_id(), user);

    // Replay of the same callback: refused under the login row lock, no second token
    // request and no cookie, so the session the browser holds is neither replaced nor
    // cleared and still validates.
    let replay = handoff.callback(&callback(&current, &cookies)).await;
    refused(&replay, StatusCode::FORBIDDEN, LOGIN_REFUSED);
    assert_eq!(posts(&f), 1);
    auth.validate(credential).await.unwrap();
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(sessions, 1);

    // The same handoff through the bounded router and actual Axum dispatch over loopback
    // HTTP. The budgets admit one initiation and two callbacks (the login and its replay),
    // so the next request on each route is refused before any provider or database work.
    let hour = Duration::from_secs(3600);
    let bounded = Settings {
        begin: Rate {
            burst: 1,
            interval: hour,
        },
        callback: Rate {
            burst: 2,
            interval: hour,
        },
        in_flight: 1,
        ..limits()
    };
    let handoff = LoginHandoff::new(auth.clone(), settings()).unwrap();
    let address = serve(router(handoff, bounded).unwrap()).await;
    let form = head(
        "POST",
        "/login",
        &[
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", "0"),
        ],
    );
    let redirect = |reply: &super::super::router::Reply| {
        assert_eq!((reply.status, reply.body.as_str()), (303, ""));
        assert_eq!(reply.one("cache-control"), "no-store");
        assert_eq!(reply.one("referrer-policy"), "no-referrer");
        (
            reply.one("location").to_owned(),
            reply.one("set-cookie").to_owned(),
        )
    };
    let (authorization_url, set_cookie) = redirect(&send(address, &form).await);
    let url = openidconnect::url::Url::parse(&authorization_url).unwrap();
    let parameters: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(parameters["redirect_uri"], signing::CALLBACK);
    let cookie = set_cookie
        .strip_suffix(&format!("; Max-Age=300{ATTRIBUTES}"))
        .expect("caller cookie attributes")
        .to_owned();
    let routed = Attempt {
        authorization_url,
        state: parameters["state"].clone(),
        cookie,
    };
    assert!(routed.cookie.starts_with(&format!("{LOGIN_COOKIE}=")));
    assert_eq!(f.rows().await, 3);
    send(address, &form)
        .await
        .refused(429, "login rate limit reached; try again later\n");
    assert_eq!(f.rows().await, 3);

    f.arm_url(&routed.authorization_url);
    let target = format!(
        "/callback?code=synthetic-code&state={}&iss=https%3A%2F%2Fissuer.example.test%2Frealm",
        routed.state
    );
    let navigation = head("GET", &target, &[("cookie", &routed.cookie)]);
    let (landing, set_cookie) = redirect(&send(address, &navigation).await);
    assert_eq!(landing, "https://app.example.test/app");
    let routed_credential = set_cookie
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .and_then(|rest| rest.strip_suffix(ATTRIBUTES))
        .expect("session cookie name and attributes");
    assert_eq!(posts(&f), 2);
    assert_eq!(
        auth.validate(routed_credential).await.unwrap().user_id(),
        user
    );
    assert!(consumed(&mut f, &routed).await);
    // Replay through the router: the handoff's refusal, no token request, no cookie.
    send(address, &navigation).await.refused(403, LOGIN_REFUSED);
    // The callback budget is spent: refused before the handoff.
    send(address, &navigation)
        .await
        .refused(429, "login rate limit reached; try again later\n");
    assert_eq!(posts(&f), 2);
    auth.validate(credential).await.unwrap();
    auth.validate(routed_credential).await.unwrap();
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(sessions, 2);
}

/// `revoked` on the row named by the credential's public identifier.
async fn revoked(f: &mut Flow, credential: &str) -> bool {
    sqlx::query_scalar("SELECT revoked FROM openmettle.local_sessions WHERE id = $1")
        .bind(credential.split_once('.').unwrap().0)
        .fetch_one(&mut f.owner)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn issued_cookies_validate_and_logout_revokes_without_current_eligibility() {
    use super::super::router::Reply;
    const DELETION: &str =
        "__Host-openmettle-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax";
    let mut f = Flow::new().await;
    seed(&mut f, true, true).await;
    let pool = one_slot(f.db.options(API));
    let auth = Arc::new(service_over(&f, &pool));
    let handoff = LoginHandoff::new(auth.clone(), settings()).unwrap();
    let hour = Duration::from_secs(3600);
    let rate = |burst| Rate {
        burst,
        interval: hour,
    };
    let sessions = SessionSettings {
        session: "/session",
        logout: "/logout",
        checks: rate(16),
        logouts: rate(16),
    };
    let routes = router_with_sessions(handoff, limits(), sessions).unwrap();
    let address = serve(routes).await;
    let check = |cookie: &str| {
        head(
            "GET",
            "/session",
            &[("sec-fetch-site", "same-origin"), ("cookie", cookie)],
        )
    };
    let logout = |origin: &str, cookie: &str| {
        head(
            "POST",
            "/logout",
            &[
                ("origin", origin),
                ("cookie", cookie),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", "0"),
            ],
        )
    };
    let valid = |reply: &Reply| {
        assert_eq!((reply.status, reply.body.as_str()), (204, ""));
        assert_eq!(reply.one("cache-control"), "no-store");
        assert_eq!(reply.one("referrer-policy"), "no-referrer");
        assert!(reply.all("set-cookie").is_empty() && reply.all("location").is_empty());
    };
    let deleted = |reply: &Reply| {
        assert_eq!((reply.status, reply.body.as_str()), (204, ""));
        assert_eq!(reply.one("cache-control"), "no-store");
        assert_eq!(reply.one("referrer-policy"), "no-referrer");
        assert_eq!(reply.one("set-cookie"), DELETION);
        assert!(reply.all("location").is_empty());
    };

    // A session cookie issued by a routed login.
    let form = head(
        "POST",
        "/login",
        &[("origin", ORIGIN), ("content-length", "0")],
    );
    let reply = send(address, &form).await;
    assert_eq!(reply.status, 303);
    let url = openidconnect::url::Url::parse(reply.one("location")).unwrap();
    let parameters: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let caller = reply
        .one("set-cookie")
        .strip_suffix(&format!("; Max-Age=300{ATTRIBUTES}"))
        .expect("caller cookie attributes")
        .to_owned();
    f.arm_url(url.as_str());
    let target = format!(
        "/callback?code=synthetic-code&state={}&iss=https%3A%2F%2Fissuer.example.test%2Frealm",
        parameters["state"]
    );
    let reply = send(address, &head("GET", &target, &[("cookie", &caller)])).await;
    assert_eq!(reply.status, 303);
    let issued = reply
        .one("set-cookie")
        .strip_suffix(ATTRIBUTES)
        .expect("session cookie attributes")
        .to_owned();
    let credential = issued
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .unwrap()
        .to_owned();
    assert_eq!(posts(&f), 1);
    // Validation and logout never contact the provider.
    let mut requests = f.h.count();

    // The issued cookie validates, beside the caller cookie and other cookies.
    let cookies = format!("theme=dark; {issued}; {caller}");
    valid(&send(address, &check(&cookies)).await);
    valid(&send(address, &check(&issued)).await);
    // A wrong Origin is refused before the cookie or database: still valid, not revoked.
    let reply = send(address, &logout("https://other.example.test", &issued)).await;
    reply.refused(403, "logout origin refused\n");
    assert!(!revoked(&mut f, &credential).await);
    valid(&send(address, &check(&issued)).await);

    // Logout is acknowledged before the one deletion. The caller cookie is not touched.
    deleted(&send(address, &logout(ORIGIN, &cookies)).await);
    assert!(revoked(&mut f, &credential).await);
    send(address, &check(&issued))
        .await
        .refused(403, "session not valid\n");
    assert!(auth.validate(&credential).await.is_err());
    // A repeated logout by the same retained credential is acknowledged again.
    deleted(&send(address, &logout(ORIGIN, &issued)).await);
    send(address, &check(&issued))
        .await
        .refused(403, "session not valid\n");

    // A second issued session loses eligibility. The check refuses it, and logout still
    // revokes it by possession alone.
    assert_eq!(f.h.count(), requests);
    let second = issue(&mut f).await;
    requests = f.h.count();
    let second_cookie = format!("{SESSION_COOKIE}={}", second.expose());
    valid(&send(address, &check(&second_cookie)).await);
    f.owner
        .execute("UPDATE openmettle.local_identity_approvals SET active=false,revision=revision+1,access_generation=access_generation+1")
        .await
        .unwrap();
    send(address, &check(&second_cookie))
        .await
        .refused(403, "session not valid\n");
    assert!(!revoked(&mut f, second.expose()).await);
    deleted(&send(address, &logout(ORIGIN, &second_cookie)).await);
    assert!(revoked(&mut f, second.expose()).await);
    // Restored eligibility never revives either revoked session.
    f.owner
        .execute("UPDATE openmettle.local_identity_approvals SET active=true,revision=revision+1,access_generation=access_generation+1")
        .await
        .unwrap();
    for cookie in [&second_cookie, &issued] {
        send(address, &check(cookie))
            .await
            .refused(403, "session not valid\n");
    }

    // An unknown well-formed credential is refused without a deletion.
    let unknown = format!("{SESSION_COOKIE}={}.{}", "A".repeat(43), "A".repeat(43));
    send(address, &logout(ORIGIN, &unknown))
        .await
        .refused(403, "session not valid\n");
    assert_eq!(f.h.count(), requests);
    assert_eq!(posts(&f), 2);
}

/// One initiation through the bounded router over loopback HTTP.
struct Routed {
    /// The login's public locator.
    login: String,
    state: String,
    /// `name=value`, as the browser returns it.
    cookie: String,
    authorization_url: String,
    reply: Reply,
}
/// A form `POST` whose body is `form`, answered by the redirect to the provider. The stored
/// login is sealed at one length whatever the form carried.
async fn routed_start(f: &mut Flow, address: SocketAddr, form: &str) -> Routed {
    let reply = send(address, &form_with(form)).await;
    assert_eq!((reply.status, reply.body.as_str()), (303, ""));
    let authorization_url = reply.one("location").to_owned();
    let url = openidconnect::url::Url::parse(&authorization_url).unwrap();
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .expect("state parameter")
        .1
        .into_owned();
    let cookie = reply
        .one("set-cookie")
        .strip_suffix(&format!("; Max-Age=300{ATTRIBUTES}"))
        .expect("caller cookie attributes")
        .to_owned();
    let login = state.split_once('.').expect("state shape").0.to_owned();
    let sealed: i32 = sqlx::query_scalar(
        "SELECT octet_length(ciphertext) FROM openmettle.login_transactions WHERE id = $1",
    )
    .bind(&login)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(sealed, 76);
    Routed {
        login,
        state,
        cookie,
        authorization_url,
        reply,
    }
}
/// The provider approves and the browser follows the callback with its caller cookie.
async fn routed_finish(f: &mut Flow, address: SocketAddr, start: &Routed) -> Reply {
    f.arm_url(&start.authorization_url);
    let target = format!(
        "/callback?code=synthetic-code&state={}&iss=https%3A%2F%2Fissuer.example.test%2Frealm",
        start.state
    );
    send(address, &head("GET", &target, &[("cookie", &start.cookie)])).await
}
/// What an initiation reply shows apart from its random values: the status, the header
/// names, the authorization parameter names and the lengths of the redirect and the cookie.
fn start_shape(reply: &Reply) -> (u16, Vec<String>, Vec<String>, usize, usize) {
    let names = |pairs: Vec<String>| {
        let mut names = pairs;
        names.sort();
        names
    };
    let headers = reply.headers.iter().filter(|(name, _)| name != "date");
    let url = openidconnect::url::Url::parse(reply.one("location")).unwrap();
    (
        reply.status,
        names(headers.map(|(name, _)| name.clone()).collect()),
        names(
            url.query_pairs()
                .map(|(name, _)| name.into_owned())
                .collect(),
        ),
        reply.one("location").len(),
        reply.one("set-cookie").len(),
    )
}
/// Everything a client can observe in a reply except its `Date` field.
fn observable(reply: &Reply) -> (u16, Vec<(String, String)>, String) {
    let headers = reply.headers.iter().filter(|(name, _)| name != "date");
    (reply.status, headers.cloned().collect(), reply.body.clone())
}
/// The session credential of a completed sign-in: the landing redirect and the one cookie.
fn signed_in(reply: &Reply) -> String {
    assert_eq!((reply.status, reply.body.as_str()), (303, ""));
    assert_eq!(reply.one("location"), "https://app.example.test/app");
    reply
        .one("set-cookie")
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .and_then(|rest| rest.strip_suffix(ATTRIBUTES))
        .expect("session cookie name and attributes")
        .to_owned()
}
/// `(consumed, ciphertext cleared, session issued)` of one login.
async fn login_state(f: &mut Flow, login: &str) -> (bool, bool, bool) {
    sqlx::query_as(
        "SELECT consumed, ciphertext IS NULL, session_issued
           FROM openmettle.login_transactions WHERE id = $1",
    )
    .bind(login)
    .fetch_one(&mut f.owner)
    .await
    .unwrap()
}
/// The form field a person submits after typing `code` as the create command displays it.
/// Test output never includes this value.
fn entered(code: &[u8; 16]) -> String {
    let hex: String = code.iter().map(|byte| format!("{byte:02x}")).collect();
    let groups: Vec<&str> = (0..8).map(|group| &hex[4 * group..4 * group + 4]).collect();
    format!("invitation_code=omh1-{}", groups.join("-"))
}

// ADR 0022 end to end: the code a person enters in the initiation form is the only thing that
// lets their first sign-in create the account. Every sign-in below is a complete browser
// flow through the router: form POST, provider, callback.
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 and POSTGRES_CONTAINER required"]
async fn first_sign_in_needs_the_invitation_code_entered_in_the_initiation_form() {
    use super::invitations::{empty, invite, pending};
    let mut f = Flow::new().await;
    let pool = one_slot(f.db.options(API));
    let auth = Arc::new(service_over(&f, &pool));
    let handoff = LoginHandoff::new(auth.clone(), settings()).unwrap();
    let address = serve(router(handoff, limits()).unwrap()).await;

    // Nobody is invited. A person who enters a well-formed code completes the provider
    // sign-in and is refused at the callback. This is the reference refusal.
    let start = routed_start(&mut f, address, &format!("invitation_code={CODE}")).await;
    let uninvited = routed_finish(&mut f, address, &start).await;
    uninvited.refused(403, LOGIN_REFUSED);
    assert_eq!(login_state(&mut f, &start.login).await, (true, true, false));
    let reference = start.reply;
    empty(&mut f).await;

    // The operator invites the person. Only the create command ever shows the code.
    let code = invite(&f);
    let correct = entered(code.bytes());
    let mut near = *code.bytes();
    near[15] ^= 1;
    let wrong = entered(&near);

    // No form body, an empty field, a code that differs in one bit and another well-formed
    // code. Each sign-in starts like any other, is refused with exactly the reply an
    // uninvited person gets, spends its login and leaves the invitation pending.
    let other = format!("invitation_code={CODE}");
    for (attempt, form) in ["", "invitation_code=", wrong.as_str(), other.as_str()]
        .into_iter()
        .enumerate()
    {
        let start = routed_start(&mut f, address, form).await;
        assert_eq!(
            start_shape(&start.reply),
            start_shape(&reference),
            "{attempt}"
        );
        let reply = routed_finish(&mut f, address, &start).await;
        assert_eq!(observable(&reply), observable(&uninvited), "{attempt}");
        assert_eq!(
            login_state(&mut f, &start.login).await,
            (true, true, false),
            "{attempt}"
        );
        empty(&mut f).await;
        pending(&mut f, 1).await;
    }
    // Each of the five refused sign-ins reached the provider once: none was refused early.
    assert_eq!(posts(&f), 5);

    // A malformed code is refused by the form rule: no login and no provider request.
    let (rows, requests) = (f.rows().await, f.h.count());
    for form in [
        "invitation_code=omh1-0123",
        "code=0123",
        "invitation_code=x",
    ] {
        send(address, &form_with(form))
            .await
            .refused(400, FORM_REFUSED);
    }
    assert_eq!((f.rows().await, f.h.count()), (rows, requests));

    // A new sign-in with the correct code, typed as displayed, creates the account. The
    // earlier wrong attempts locked nothing and counted against nothing.
    let start = routed_start(&mut f, address, &correct).await;
    assert_eq!(start_shape(&start.reply), start_shape(&reference));
    // The stored login holds the code only inside its ciphertext.
    let visible: bool = sqlx::query_scalar(
        "SELECT position(encode($1, 'hex') IN to_jsonb(t)::text) > 0
           FROM openmettle.login_transactions t WHERE id = $2",
    )
    .bind(code.bytes().as_slice())
    .bind(&start.login)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(
        !visible,
        "the login row shows the code outside its ciphertext"
    );
    let credential = signed_in(&routed_finish(&mut f, address, &start).await);
    assert_eq!(login_state(&mut f, &start.login).await, (true, true, true));
    let user = auth
        .validate(&credential)
        .await
        .unwrap()
        .user_id()
        .to_owned();
    let accounts = account_state(&mut f).await;
    assert_eq!(accounts.len(), 3); // one user, one identity, one private scope
    let redeemed: Vec<(String, bool)> = sqlx::query_as(
        "SELECT login_id, approval_id IS NOT NULL AND redeemed_at IS NOT NULL
           FROM openmettle.home_invitations",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(redeemed, [(start.login.clone(), true)]);

    // The identity now exists, so a code is ignored: the spent code, a wrong code and no
    // code all sign in to that one account through its ordinary approval.
    for (attempt, form) in [correct.as_str(), wrong.as_str(), ""]
        .into_iter()
        .enumerate()
    {
        let start = routed_start(&mut f, address, form).await;
        let credential = signed_in(&routed_finish(&mut f, address, &start).await);
        let context = auth.validate(&credential).await.unwrap();
        assert_eq!(context.user_id(), user, "{attempt}");
    }
    assert_eq!(account_state(&mut f).await, accounts);

    // A disabled account stays refused with the correct code, and no account is created.
    crate::sessions::disable_user(&mut f.api, &user, 0, &session_policy())
        .await
        .unwrap();
    let disabled = account_state(&mut f).await;
    let start = routed_start(&mut f, address, &correct).await;
    let reply = routed_finish(&mut f, address, &start).await;
    assert_eq!(observable(&reply), observable(&uninvited));
    assert_eq!(account_state(&mut f).await, disabled);
    assert_eq!(disabled.len(), accounts.len());
}
