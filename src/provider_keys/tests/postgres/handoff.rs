//! The browser login handoff (ADR 0017) through the pooled service: one form POST to one
//! session cookie, with the fixture TLS provider. Isolated CI PostgreSQL 18 only.
use super::super::handoff::{
    BINDING_REFUSED, DENIED, ORIGIN, RESPONSE_REFUSED, refused, request, settings,
};
use super::pooled::{one_slot, posts, service_over};
use super::sessions::seed;
use super::*;
use crate::browser_auth::handoff::{LOGIN_COOKIE, LoginHandoff, SESSION_COOKIE};
use axum::http::{Response, StatusCode, header};

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
    let older = started(&handoff.initiate(&form).await);
    let current = started(&handoff.initiate(&form).await);
    assert_ne!(older.cookie, current.cookie);
    assert_eq!(f.rows().await, 2);

    // The older login's callback arrives with the newer cookie. It is refused on the
    // locator before any service call: no provider request and nothing consumed.
    let requests = f.h.count();
    let stale = handoff.callback(&callback(&older, &current.cookie)).await;
    refused(&stale, StatusCode::BAD_REQUEST, BINDING_REFUSED);
    assert_eq!(f.h.count(), requests);
    assert!(!consumed(&mut f, &older).await);

    // A provider error for the current login is refused without spending it.
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
    refused(&replay, StatusCode::FORBIDDEN, DENIED);
    assert_eq!(posts(&f), 1);
    auth.validate(credential).await.unwrap();
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(sessions, 1);
}
