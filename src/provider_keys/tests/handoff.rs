//! The unmounted browser login handoff (ADR 0017) without PostgreSQL: its settings, and every
//! request decision it makes before the service is called. The silent database stand-in and
//! the fixture provider's request count show that a refusal reached neither.
use super::*;
use crate::{
    browser_auth::{
        BrowserAuth,
        handoff::{
            LOGIN_COOKIE, LoginHandoff, MAX_COOKIE_BYTES, MAX_QUERY_BYTES, MAX_QUERY_PARAMETERS,
            SESSION_COOKIE, Settings, SettingsError,
        },
    },
    sessions,
};
use axum::http::{Request, Response, StatusCode, header, request::Parts};

pub(super) const ORIGIN: &str = "https://app.example.test";
pub(super) const RESPONSE_REFUSED: &str = "login response refused; restart login\n";
pub(super) const BINDING_REFUSED: &str =
    "login browser binding missing or superseded; restart login\n";
pub(super) const LOGIN_REFUSED: &str = "login refused. Start a new login.\n";
const UNAVAILABLE: &str = "login unavailable; restart login\n";

pub(super) fn settings() -> Settings<'static> {
    Settings {
        origin: ORIGIN,
        landing: "/app",
        provider: signing::ID,
    }
}
pub(super) fn request(method: &str, target: &str, headers: &[(&str, &str)]) -> Parts {
    let mut request = Request::builder().method(method).uri(target);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(()).unwrap().into_parts().0
}
/// A refusal is one fixed line. It is never stored, sets or deletes no cookie and redirects
/// nowhere.
pub(super) fn refused(response: &Response<&'static str>, status: StatusCode, line: &str) {
    assert_eq!((response.status(), *response.body()), (status, line));
    let headers = response.headers();
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
    assert!(!headers.contains_key(header::SET_COOKIE));
    assert!(!headers.contains_key(header::LOCATION));
}
fn service(h: &Harness, pool: sqlx::PgPool) -> Arc<BrowserAuth> {
    let policy = sessions::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(5));
    Arc::new(service::browser_auth(
        h,
        pool,
        Duration::from_secs(300),
        policy.unwrap(),
    ))
}
fn percent_encoded(value: &str) -> String {
    value.bytes().map(|b| format!("%{b:02X}")).collect()
}

#[tokio::test]
async fn settings_are_exact_and_take_the_callback_from_the_configured_provider() {
    let (_database, pool) = service::silent_database();
    let h = Harness::new().await;
    let auth = service(&h, pool);
    let build = |origin, landing, provider| {
        let settings = Settings {
            origin,
            landing,
            provider,
        };
        LoginHandoff::new(auth.clone(), settings).map(|handoff| format!("{handoff:?}"))
    };
    for landing in ["/app", "/", "/app/home.html"] {
        assert_eq!(
            build(ORIGIN, landing, signing::ID).unwrap(),
            "LoginHandoff(..)"
        );
    }
    for origin in [
        "",
        "null",
        "app.example.test",
        "http://app.example.test",
        "https://app.example.test/",
        "https://app.example.test:443",
        "https://APP.example.test",
        "https://user@app.example.test",
        "https://app.example.test/app",
        "https://app.example.test?x",
        "https://app.example.test ",
    ] {
        assert_eq!(
            build(origin, "/app", signing::ID).unwrap_err(),
            SettingsError::Origin,
            "{origin}"
        );
    }
    for landing in [
        "",
        "app",
        "//other.example.test",
        "/\\other.example.test",
        "https://other.example.test/",
        "/app?next=x",
        "/app#x",
        "/app%2F",
        "/app page",
        "/a/../b",
        "/./app",
    ] {
        assert_eq!(
            build(ORIGIN, landing, signing::ID).unwrap_err(),
            SettingsError::Landing,
            "{landing}"
        );
    }
    // Only an exactly configured provider UUID selects the callback and issuer.
    for provider in [
        "",
        "00000000-0000-4000-8000-000000000000",
        "0B5C6F4E-2A1D-4C3B-9E8F-7A6B5C4D3E2F",
        signing::ISSUER,
    ] {
        assert_eq!(
            build(ORIGIN, "/app", provider).unwrap_err(),
            SettingsError::Provider,
            "{provider}"
        );
    }
    // The fixture's registered callback is https://app.example.test/callback.
    for origin in [
        "https://other.example.test",
        "https://app.example.tes",
        "https://app.example.test:8443",
    ] {
        assert_eq!(
            build(origin, "/app", signing::ID).unwrap_err(),
            SettingsError::Callback,
            "{origin}"
        );
    }
    assert_eq!(
        SettingsError::Callback.to_string(),
        "registered callback is not a plain path on the application origin"
    );
    h.manager.retire(&h.provider).unwrap();
    assert_eq!(
        build(ORIGIN, "/app", signing::ID).unwrap_err(),
        SettingsError::Provider
    );
    assert_eq!(h.count(), 0);
}

#[tokio::test]
async fn initiation_decides_method_and_origin_before_the_service() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let handoff = LoginHandoff::new(service(&h, pool), settings()).unwrap();
    let form = request("POST", "/login", &[("origin", ORIGIN)]);
    // Route handlers need Send futures.
    service::assert_send(&handoff.initiate(&form, b""));
    service::assert_send(&handoff.callback(&form));

    for method in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"] {
        let response = handoff
            .initiate(&request(method, "/login", &[("origin", ORIGIN)]), b"")
            .await;
        refused(
            &response,
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed\n",
        );
        assert_eq!(response.headers()[header::ALLOW], "POST");
    }
    for origins in [
        &[][..],
        &["null"],
        &[ORIGIN, ORIGIN],
        &[ORIGIN, "null"],
        &["https://app.example.test, https://app.example.test"],
        &["http://app.example.test"],
        &["https://app.example.test:443"],
        &["https://app.example.test/"],
        &["https://APP.example.test"],
        &["https://other.example.test"],
        &["https://app.example.test.other.example.test"],
    ] {
        // Nothing else in the request stands in for the Origin field.
        let mut headers = vec![
            ("host", "app.example.test"),
            ("x-forwarded-host", "app.example.test"),
            ("forwarded", "host=app.example.test;proto=https"),
            ("referer", "https://app.example.test/"),
        ];
        headers.extend(origins.iter().map(|origin| ("origin", *origin)));
        let response = handoff
            .initiate(&request("POST", "/login", &headers), b"")
            .await;
        refused(&response, StatusCode::FORBIDDEN, "login origin refused\n");
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // The admissible form POST is the one request that reaches the service: both provider
    // documents, then a checkout. The stand-in never answers, so nothing is delivered.
    let response = handoff.initiate(&form, b"").await;
    refused(&response, StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE);
    assert_eq!(h.count(), 2);
    assert!(attempted());
}

/// The initiation form (ADR 0022) is decided after `Origin` and before the service. A
/// malformed form reaches neither the provider nor the database.
#[tokio::test]
async fn initiation_decides_the_form_after_origin_and_before_the_service() {
    use super::router::{CODE, FORM_REFUSED};
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let handoff = LoginHandoff::new(service(&h, pool), settings()).unwrap();
    let form = request("POST", "/login", &[("origin", ORIGIN)]);
    let valid = format!("invitation_code={CODE}");
    let malformed: [&[u8]; 7] = [
        b"x=1",
        b"invitation_code",
        b"invitation_code=not-a-code",
        b"invitation_code=0123",
        b"invitation_code=%zz",
        b"invitation_code=\xff",
        &[valid.as_bytes(), b"&", valid.as_bytes()].concat(),
    ];

    // Method, then Origin, whatever the body holds: a foreign page gets the origin refusal
    // for a valid and for a malformed form alike.
    for body in malformed.into_iter().chain([valid.as_bytes()]) {
        let response = handoff
            .initiate(&request("GET", "/login", &[("origin", ORIGIN)]), body)
            .await;
        refused(
            &response,
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed\n",
        );
        for origins in [&[][..], &[("origin", "https://other.example.test")]] {
            let response = handoff
                .initiate(&request("POST", "/login", origins), body)
                .await;
            refused(&response, StatusCode::FORBIDDEN, "login origin refused\n");
        }
    }
    // From the application origin, every malformed form is the one fixed refusal.
    for body in malformed {
        let response = handoff.initiate(&form, body).await;
        refused(&response, StatusCode::BAD_REQUEST, FORM_REFUSED);
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // A well-formed code is not checked against any invitation here. It reaches the service
    // exactly as an empty value and an empty body do, with the same response.
    for body in [valid.as_bytes(), b"invitation_code=", b""] {
        let response = handoff.initiate(&form, body).await;
        refused(&response, StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE);
        assert!(attempted());
    }
    assert_eq!(h.count(), 2);
}

#[tokio::test]
async fn callback_decides_the_response_and_binding_before_the_service() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let handoff = LoginHandoff::new(service(&h, pool), settings()).unwrap();

    let locator = "L".repeat(43);
    let state = format!("{locator}.{}", "s".repeat(43));
    let cookie = format!("{LOGIN_COOKIE}={locator}.{}", "c".repeat(43));
    let issuer = "https%3A%2F%2Fissuer.example.test%2Frealm";
    let success = format!("code=synthetic-code&state={state}&iss={issuer}");
    let get = |target: &str, cookies: &[&str]| {
        let headers: Vec<_> = cookies.iter().map(|cookie| ("cookie", *cookie)).collect();
        request("GET", target, &headers)
    };

    // Path, then method. Neither depends on the query or the cookie.
    for target in [
        "/",
        "/login",
        "/Callback",
        "/callback/",
        "/callback/x",
        "//callback",
        "/./callback",
    ] {
        for method in ["GET", "POST"] {
            let target = format!("{target}?{success}");
            let headers = [("cookie", cookie.as_str())];
            let response = handoff.callback(&request(method, &target, &headers)).await;
            refused(&response, StatusCode::NOT_FOUND, "not found\n");
        }
    }
    for method in ["POST", "HEAD", "PUT"] {
        let target = format!("/callback?{success}");
        let headers = [("cookie", cookie.as_str())];
        let response = handoff.callback(&request(method, &target, &headers)).await;
        refused(
            &response,
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed\n",
        );
        assert_eq!(response.headers()[header::ALLOW], "GET");
    }

    // The authorization response, with the right cookie present.
    let long_code = "c".repeat(crate::login::MAX_CODE_BYTES + 1);
    let padding = "p".repeat(MAX_QUERY_BYTES - success.len() - "&pad=".len() + 1);
    // The three success members and thirty more: one over the parameter ceiling.
    let unknown: String = (4..=MAX_QUERY_PARAMETERS + 1)
        .map(|n| format!("&p{n}="))
        .collect();
    let refused_queries = [
        // Empty or malformed.
        String::new(),
        format!("{success}&"),
        format!("&{success}"),
        format!("{success}&&x=1"),
        format!("{success}&=x"),
        format!("{success}&x=%zz"),
        format!("{success}&x=%z0"),
        format!("{success}&x=%0z"),
        format!("{success}&x=%2"),
        format!("{success}&x=%"),
        format!("{success}&%zz=x"),
        format!("{success}&x=%FF"),
        format!("{success}&x=%C3%28"),
        // Repeated members, including names that only differ before decoding.
        format!("{success}&code=synthetic-other"),
        format!("{success}&%63ode=synthetic-other"),
        format!("{success}&state={state}"),
        format!("{success}&iss={issuer}"),
        format!("{success}&x=1&x=2"),
        format!("{success}&x=1&%78=2"),
        format!("{success}&a+b=1&a%20b=2"),
        // Incomplete success.
        format!("state={state}&iss={issuer}"),
        format!("code=synthetic-code&iss={issuer}"),
        format!("code=synthetic-code&state={state}"),
        format!("code&state={state}&iss={issuer}"),
        format!("code=&state={state}&iss={issuer}"),
        format!("Code=synthetic-code&state={state}&iss={issuer}"),
        // Another issuer, compared as an exact string.
        format!("code=synthetic-code&state={state}&iss="),
        format!("code=synthetic-code&state={state}&iss={issuer}%2F"),
        format!("code=synthetic-code&state={state}&iss=https%3A%2F%2FISSUER.example.test%2Frealm"),
        format!("code=synthetic-code&state={state}&iss=https%3A%2F%2Fother.example.test%2Frealm"),
        // Provider errors and error detail beside a code. The text is never reflected.
        format!(
            "error=access_denied&error_description=SECRET-provider-text&state={state}&iss={issuer}"
        ),
        format!("error=&state={state}&iss={issuer}"),
        format!("{success}&error=access_denied"),
        format!("{success}&error_description=SECRET-provider-text"),
        format!("{success}&error_uri=https%3A%2F%2Fother.example.test%2FSECRET"),
        // Unsafe code and state shapes.
        format!("code=two+words&state={state}&iss={issuer}"),
        format!("code=two%20words&state={state}&iss={issuer}"),
        format!("code=nul%00&state={state}&iss={issuer}"),
        format!("code=caf%C3%A9&state={state}&iss={issuer}"),
        format!("code={long_code}&state={state}&iss={issuer}"),
        format!("code=synthetic-code&state={}&iss={issuer}", &state[1..]),
        format!("code=synthetic-code&state={state}s&iss={issuer}"),
        format!("code=synthetic-code&state={}&iss={issuer}", "s".repeat(87)),
        format!(
            "code=synthetic-code&state={}&iss={issuer}",
            state.replace('s', "!")
        ),
        // One parameter and one byte over the ceilings.
        format!("{success}{unknown}"),
        format!("{success}&pad={padding}"),
    ];
    assert_eq!(refused_queries.last().unwrap().len(), MAX_QUERY_BYTES + 1);
    for query in &refused_queries {
        let target = format!("/callback?{query}");
        let response = handoff.callback(&get(&target, &[&cookie])).await;
        refused(&response, StatusCode::BAD_REQUEST, RESPONSE_REFUSED);
    }
    let response = handoff.callback(&get("/callback", &[&cookie])).await;
    refused(&response, StatusCode::BAD_REQUEST, RESPONSE_REFUSED);

    // The caller cookie, with a well-formed response present.
    let value = &cookie[LOGIN_COOKIE.len() + 1..];
    let other_login = format!("{LOGIN_COOKIE}={}.{}", "M".repeat(43), "c".repeat(43));
    let oversized = format!("{cookie}; pad={}", "p".repeat(MAX_COOKIE_BYTES));
    let refused_cookies: [&[&str]; 14] = [
        &[],
        &["theme=dark"],
        &[&format!("{SESSION_COOKIE}={value}")],
        &[&format!("openmettle-login={value}")],
        &[&format!("__host-openmettle-login={value}")],
        &[&format!("{LOGIN_COOKIE} ={value}")],
        // Malformed values.
        &[&format!("{LOGIN_COOKIE}=")],
        &[&format!("{LOGIN_COOKIE}=\"{value}\"")],
        &[&format!("{cookie}c")],
        // Repeated in one field, with another value, and across fields.
        &[&format!("{cookie}; {cookie}")],
        &[&format!("{cookie}; {other_login}")],
        &[&cookie, &cookie],
        &[&oversized],
        // A cookie from a later initiation: the locator names another login.
        &[&other_login],
    ];
    for cookies in refused_cookies {
        let target = format!("/callback?{success}");
        let response = handoff.callback(&get(&target, cookies)).await;
        refused(&response, StatusCode::BAD_REQUEST, BINDING_REFUSED);
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // Admitted: unknown well-formed parameters and unrelated cookies beside the one binding.
    // The pool acquisition times out at the silent database before the phase deadline.
    // That database error maps to unavailable.
    let target = format!("/callback?{success}&session_state=synthetic&scope=openid+profile&x=&y");
    let cookies = format!("theme=dark;{cookie};\t{SESSION_COOKIE}=synthetic-earlier");
    let response = handoff.callback(&get(&target, &[&cookies])).await;
    refused(&response, StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE);
    assert_eq!(h.count(), 2);
    assert!(attempted());

    // Admitted at the ceilings: a maximal code with every byte of code, state and issuer
    // percent-encoded, the last allowed parameter, the last allowed query byte and the last
    // allowed cookie byte.
    let mut query = format!(
        "code={}&state={}&iss={}",
        percent_encoded(&"c".repeat(crate::login::MAX_CODE_BYTES)),
        percent_encoded(&state),
        percent_encoded(signing::ISSUER)
    );
    for n in 4..MAX_QUERY_PARAMETERS {
        query.push_str(&format!("&p{n}="));
    }
    query.push_str("&pad=");
    query.push_str(&"p".repeat(MAX_QUERY_BYTES - query.len()));
    assert_eq!(query.len(), MAX_QUERY_BYTES);
    assert_eq!(query.matches('&').count() + 1, MAX_QUERY_PARAMETERS);
    let mut cookies = format!("{cookie}; pad=");
    cookies.push_str(&"p".repeat(MAX_COOKIE_BYTES - cookies.len()));
    let target = format!("/callback?{query}");
    let response = handoff.callback(&get(&target, &[&cookies])).await;
    refused(&response, StatusCode::SERVICE_UNAVAILABLE, UNAVAILABLE);
    assert!(attempted());
}
