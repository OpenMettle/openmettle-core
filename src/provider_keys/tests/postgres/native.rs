//! Two independent provider managers and primary pools run the unmounted native router
//! (ADR 0023). The schema is the migrated one, including migration 14.
use super::super::{
    handoff::{ORIGIN, request},
    router::{CODE, FORM_TYPE, Reply, head, limits, send, serve},
};
use super::*;
use crate::{
    auth_config::AuthConfig,
    browser_auth::{BrowserAuth, native::NativeAuth, router::Rate},
};
use openidconnect::url::Url;
use std::net::SocketAddr;

const CALLBACK: &str = "https://app.example.test/native/callback";
const LINK: &str = "https://links.example.test/app";
const CLIENT: &str = "synthetic.mobile";
const VERIFIER: &str = "0123456789abcdefghijklmnopqrstuvwxyz-._~ABCDEFGHIJK";
const REFUSED: &str = "native sign-in refused\n";
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
fn profile(auth: Arc<BrowserAuth>) -> NativeAuth {
    NativeAuth::new(auth, signing::ID, ORIGIN, CALLBACK, CLIENT, LINK, 8).unwrap()
}
fn form(verifier: &str) -> String {
    let state = URL_SAFE_NO_PAD.encode([3; 32]);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    format!(
        "/auth/native/authorize?response_type=code&client_id={CLIENT}&redirect_uri={LINK}&code_challenge_method=S256&state={state}&code_challenge={challenge}"
    )
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
async fn start(address: SocketAddr) -> (String, String) {
    let (_, location, cookie) = start_with(address, "").await;
    (location, cookie)
}
/// One confirmed start whose form is `body`: the reply, the provider URL and the cookie pair.
async fn start_with(address: SocketAddr, body: &str) -> (Reply, String, String) {
    let target = form(VERIFIER);
    let response = send(address, &confirm(&target, ORIGIN, body)).await;
    assert_eq!(response.status, 303);
    let location = response.one("location");
    let params: HashMap<_, _> = Url::parse(location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(params["redirect_uri"], CALLBACK);
    assert_ne!(
        params["code_challenge"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
    );
    let cookie = response
        .one("set-cookie")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(!location.contains(cookie.split('.').nth(1).unwrap()));
    let location = location.to_owned();
    (response, location, cookie)
}
/// The provider approves and the system browser follows the upstream callback.
async fn finish(f: &Flow, address: SocketAddr, location: &str, cookie: &str) -> Reply {
    f.arm_url(location);
    let state = Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == "state")
        .expect("state parameter")
        .1
        .into_owned();
    let target = format!(
        "/native/callback?iss={}&state={state}&code=synthetic-code",
        signing::ISSUER
    );
    send(address, &head("GET", &target, &[("cookie", cookie)])).await
}
/// The handoff code in a completed callback: the app link with exactly its three parameters.
fn delivered(reply: &Reply) -> String {
    assert_eq!(reply.status, 303);
    let url = Url::parse(reply.one("location")).unwrap();
    assert!(url.as_str().starts_with(&format!("{LINK}?")));
    assert_eq!(url.query_pairs().count(), 3);
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(params["state"], URL_SAFE_NO_PAD.encode([3; 32]));
    assert_eq!(params["iss"], ORIGIN);
    assert_eq!(params["code"].len(), 43);
    params["code"].clone()
}
async fn complete(
    f: &Flow,
    start_at: SocketAddr,
    finish_at: SocketAddr,
) -> super::super::router::Reply {
    let (location, cookie) = start(start_at).await;
    f.arm_url(&location);
    let params: HashMap<_, _> = Url::parse(&location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    let target = format!(
        "/native/callback?iss={}&state={}&code=synthetic-code",
        signing::ISSUER,
        params["state"]
    );
    let send_callback = |cookie: &str| head("GET", &target, &[("cookie", cookie)]);
    let wrong_issuer = target.replace(signing::ISSUER, "https://other.example.test");
    assert_eq!(
        send(
            finish_at,
            &head("GET", &wrong_issuer, &[("cookie", &cookie)])
        )
        .await
        .status,
        403
    );
    // Attempt substitution changes the managed login's authenticated transaction binding.
    let (prefix, _) = cookie.rsplit_once('.').unwrap();
    let tampered = format!("{prefix}.{}", URL_SAFE_NO_PAD.encode([4; 32]));
    assert_eq!(send(finish_at, &send_callback(&tampered)).await.status, 403);
    let reply = send(finish_at, &send_callback(&cookie)).await;
    assert_eq!(send(start_at, &send_callback(&cookie)).await.status, 403);
    reply
}
async fn code(f: &Flow, start_at: SocketAddr, finish_at: SocketAddr) -> String {
    delivered(&complete(f, start_at, finish_at).await)
}
fn redeem(code: &str) -> Value {
    json!({"grant_type":"authorization_code","iss":ORIGIN,"client_id":CLIENT,"redirect_uri":LINK,"code_verifier":VERIFIER,"code":code})
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
async fn services(f: &Flow) -> (Arc<BrowserAuth>, SocketAddr, SocketAddr) {
    f.h.script.lock().unwrap().native_callback = Some(CALLBACK.into());
    let pool = pooled::one_slot(f.db.options(API));
    let auth = Arc::new(pooled::service_over(f, &pool));
    let (manager, provider) = f.restart();
    let replica = Arc::new(BrowserAuth::new(
        AuthConfig::fixture(
            keys(),
            Duration::from_secs(300),
            sessions::session_policy(),
            manager,
            vec![provider],
        ),
        pooled::one_slot(f.db.options(API)),
    ));
    let a = serve(profile(auth.clone()).router(limits().begin).unwrap()).await;
    let b = serve(profile(replica).router(limits().begin).unwrap()).await;
    (auth, a, b)
}
#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn two_replicas_deliver_once_with_exact_pkce_registration_and_channel() {
    let mut f = Flow::new().await;
    role_boundaries(&mut f).await;
    sessions::seed(&mut f, true, true).await;
    let (auth, a, b) = services(&f).await;
    let request = redeem(&code(&f, a, b).await);
    for (field, value) in [
        ("client_id", "other"),
        ("redirect_uri", "https://other.example.test/app"),
        ("iss", "https://other.example.test"),
        ("code_verifier", &"x".repeat(43)),
    ] {
        let mut wrong = request.clone();
        wrong[field] = value.into();
        assert_eq!(send(a, &post(&wrong)).await.status, 403);
    }
    let req = post(&request);
    let (one, two) = tokio::join!(send(a, &req), send(b, &req));
    let ok = match (one.status, two.status) {
        (200, 403) => one,
        (403, 200) => two,
        _ => panic!("exactly one redemption must win"),
    };
    assert_eq!(ok.one("cache-control"), "no-store");
    assert!(ok.all("set-cookie").is_empty());
    let json: Value = serde_json::from_str(&ok.body).unwrap();
    assert_eq!(json.as_object().unwrap().len(), 2);
    let bearer = json["access_token"].as_str().unwrap();
    assert_eq!(send(b, &req).await.status, 403);
    assert!(auth.validate(bearer).await.is_err());
    assert!(auth.logout(bearer).await.is_err());
    let browser = sessions::issue(&mut f).await;
    for (route, method) in [("session", "GET"), ("logout", "POST")] {
        let target = format!("/auth/native/{route}");
        assert_eq!(
            send(
                a,
                &head(
                    method,
                    &target,
                    &[("authorization", &format!("Bearer {}", browser.expose()))]
                )
            )
            .await
            .status,
            403
        );
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
        assert_eq!(
            send(
                a,
                &head(
                    method,
                    &target,
                    &[("authorization", &format!("Bearer {bearer}"))]
                )
            )
            .await
            .status,
            204
        );
    }
    assert_eq!(
        send(
            b,
            &head(
                "GET",
                "/auth/native/session",
                &[("authorization", &format!("Bearer {bearer}"))]
            )
        )
        .await
        .status,
        403
    );
    auth.validate(browser.expose()).await.unwrap();
    let empty: bool = sqlx::query_scalar("SELECT sealed IS NULL FROM openmettle.native_handoffs")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert!(empty);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn grant_expiry_withdrawal_disablement_and_retirement_prevent_delivery() {
    let mut f = Flow::new().await;
    let (_, a, b) = services(&f).await;
    assert_eq!(complete(&f, a, b).await.status, 403);
    let user = sessions::seed(&mut f, true, true).await;
    for event in ["expiry", "withdraw", "disable", "retire"] {
        let delivered = post(&redeem(&code(&f, a, b).await));
        let ok = send(a, &delivered).await;
        assert_eq!(ok.status, 200);
        let token: Value = serde_json::from_str(&ok.body).unwrap();
        let pending = post(&redeem(&code(&f, b, a).await));
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
        assert_eq!(send(a, &pending).await.status, 403);
        assert_eq!(
            send(
                b,
                &head(
                    "GET",
                    "/auth/native/session",
                    &[(
                        "authorization",
                        &format!("Bearer {}", token["access_token"].as_str().unwrap())
                    )]
                )
            )
            .await
            .status,
            403
        );
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
    for link in [
        "synthetic-app:/callback",
        "http://example.test/link",
        "https://example.test/a/../link",
        "https://example.test/link?",
        "https://user@example.test/link",
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
    let target = form(VERIFIER);
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
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn handoff_cannot_outlive_remaining_assertion_age_on_another_replica() {
    let mut f = Flow::new().await;
    sessions::seed(&mut f, true, true).await;
    // Fixture ID token issued at T-10, maximum age 300s. Two seconds remain.
    {
        let mut script = f.h.script.lock().unwrap();
        script.cache = "max-age=600".into();
        script.metadata_cache = "max-age=600".into();
    }
    f.h.advance(288);
    let (_, a, b) = services(&f).await;
    let pending = redeem(&code(&f, a, b).await);
    let clipped: bool = sqlx::query_scalar(
        "SELECT g.expires_ms <= floor(extract(epoch FROM clock_timestamp())*1000)::bigint + 2000
            AND g.expires_ms < s.expires_ms AND g.expires_ms < l.expires_ms
         FROM openmettle.native_handoffs g JOIN openmettle.local_sessions s ON s.id=g.session_id
         JOIN openmettle.login_transactions l ON l.id=s.login_id",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(clipped);
    tokio::time::sleep(Duration::from_millis(2050)).await;
    assert_eq!(send(a, &post(&pending)).await.status, 403);
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
    let mut input = redeem(&URL_SAFE_NO_PAD.encode([9; 32]));
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
    let target = form(VERIFIER);
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
    /// The login's public locator.
    login: String,
    start: Reply,
    callback: Reply,
}
async fn sign_in(f: &mut Flow, address: SocketAddr, body: &str) -> SignIn {
    let (start, location, cookie) = start_with(address, body).await;
    let login = cookie
        .split_once('=')
        .and_then(|(_, value)| value.split('.').next())
        .expect("cookie locator")
        .to_owned();
    // The stored login is sealed at one length whatever the form carried, and it carries
    // the native binding layout that migration 14 admits.
    let stored: (i32, bool) = sqlx::query_as(
        "SELECT octet_length(ciphertext),
                substring(binding FROM 1 FOR 34)
                    = convert_to('openmettle/native-managed-login/1', 'SQL_ASCII') || '\\x00'::bytea
           FROM openmettle.login_transactions WHERE id = $1",
    )
    .bind(&login)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(stored, (76, true));
    let callback = finish(f, address, &location, &cookie).await;
    SignIn {
        login,
        start,
        callback,
    }
}
/// Redeems a delivered code and validates the bearer through `native`: the signed-in user.
async fn delivered_user(native: &NativeAuth, address: SocketAddr, reply: &Reply) -> String {
    let token = send(address, &post(&redeem(&delivered(reply)))).await;
    assert_eq!(token.status, 200);
    let token: Value = serde_json::from_str(&token.body).unwrap();
    let bearer = token["access_token"].as_str().expect("bearer");
    let context = native.validate(bearer).await.unwrap();
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
    let uninvited = sign_in(&mut f, a, &format!("invitation_code={CODE}")).await;
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
    for (attempt, body) in [
        "",
        "invitation_code=",
        wrong.as_str(),
        another.as_str(),
        unassigned.as_str(),
    ]
    .into_iter()
    .enumerate()
    {
        let refused = sign_in(&mut f, a, body).await;
        assert_eq!(
            start_shape(&refused.start),
            start_shape(&uninvited.start),
            "{attempt}"
        );
        assert_eq!(
            observable(&refused.callback),
            observable(&uninvited.callback),
            "{attempt}"
        );
        assert_eq!(
            login_state(&mut f, &refused.login).await,
            (true, true, false),
            "{attempt}"
        );
        empty(&mut f).await;
        pending(&mut f, 2).await;
    }
    // Each of the six refused sign-ins reached the provider once: none was refused early.
    assert_eq!(pooled::posts(&f), 6);

    // A malformed code and a code in the query are refused at the start: no login row and
    // no provider request.
    let (rows, requests) = (f.rows().await, f.h.count());
    let target = form(VERIFIER);
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
    let (start, location, cookie) = start_with(a, &correct).await;
    assert_eq!(start_shape(&start), start_shape(&uninvited.start));
    let login = cookie
        .split_once('=')
        .and_then(|(_, value)| value.split('.').next())
        .expect("cookie locator")
        .to_owned();
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
    let reply = finish(&f, b, &location, &cookie).await;
    // The app link carries the handoff code, the app state and the issuer, and nothing of
    // the invitation code.
    let hex: String = code.bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        !reply.one("location").contains(&hex),
        "the app link repeats the invitation code"
    );
    let user = delivered_user(&native, b, &reply).await;
    assert_eq!(login_state(&mut f, &login).await, (true, true, true));
    let accounts = sessions::account_state(&mut f).await;
    assert_eq!(accounts.len(), 3); // one user, one identity, one private scope
    assert_eq!(invitations(&mut f, &login).await, (1, 1));

    // The identity now exists, so a code is ignored: the spent code, a wrong code, the other
    // pending invitation's code and no code all sign in to that one account through its
    // ordinary approval. The other invitation stays pending.
    for (attempt, body) in [correct.as_str(), wrong.as_str(), another.as_str(), ""]
        .into_iter()
        .enumerate()
    {
        let again = sign_in(&mut f, a, body).await;
        assert_eq!(
            delivered_user(&native, a, &again.callback).await,
            user,
            "{attempt}"
        );
    }
    assert_eq!(sessions::account_state(&mut f).await, accounts);
    assert_eq!(invitations(&mut f, &login).await, (1, 1));

    // A disabled account stays refused with the correct code, and no account is created.
    crate::sessions::disable_user(&mut f.api, &user, 0, &sessions::session_policy())
        .await
        .unwrap();
    let disabled = sessions::account_state(&mut f).await;
    let refused = sign_in(&mut f, a, &correct).await;
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
