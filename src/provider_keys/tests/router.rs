//! The bounded login router (ADR 0018) through actual Axum dispatch on a loopback listener,
//! without PostgreSQL. Requests are raw HTTP/1.1 bytes. The fixture provider's request count
//! and the silent database stand-in show which requests reached the service.
use super::handoff::{BINDING_REFUSED, ORIGIN, settings};
use super::*;
use crate::{
    browser_auth::{
        handoff::{LOGIN_COOKIE, LoginHandoff, MAX_COOKIE_BYTES, MAX_QUERY_BYTES},
        router::{
            MAX_HEADER_BYTES, MAX_HEADER_FIELDS, MAX_TARGET_BYTES, Rate, Settings, SettingsError,
            router,
        },
    },
    sessions,
};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const UNAVAILABLE: &str = "login unavailable; restart login\n";
const RATE_REFUSED: &str = "login rate limit reached; try again later\n";
const BUSY_REFUSED: &str = "login busy; try again later\n";
const HOUR: Duration = Duration::from_secs(3600);

/// Generous limits that no test reaches unless it sets its own.
pub(super) fn limits() -> Settings<'static> {
    Settings {
        initiation: "/login",
        begin: Rate {
            burst: 1000,
            interval: HOUR,
        },
        callback: Rate {
            burst: 1000,
            interval: HOUR,
        },
        in_flight: 16,
    }
}
/// Serves `router` on a fresh loopback port for the rest of the test.
pub(super) async fn serve(router: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    address
}
/// One HTTP/1.1 request head with `Host` first. `Content-Length` only when given.
pub(super) fn head(method: &str, target: &str, headers: &[(&str, &str)]) -> String {
    let mut head = format!("{method} {target} HTTP/1.1\r\nhost: app.example.test\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head + "\r\n"
}
pub(super) struct Reply {
    pub(super) status: u16,
    /// Lowercase names, in order.
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: String,
}
impl Reply {
    pub(super) fn all(&self, name: &str) -> Vec<&str> {
        let values = self.headers.iter().filter(|(n, _)| n == name);
        values.map(|(_, value)| value.as_str()).collect()
    }
    pub(super) fn one(&self, name: &str) -> &str {
        match self.all(name)[..] {
            [value] => value,
            _ => panic!("expected exactly one {name} header"),
        }
    }
    /// A fixed refusal line: never stored, no referrer, no cookie and no redirect.
    pub(super) fn refused(&self, status: u16, line: &str) {
        assert_eq!((self.status, self.body.as_str()), (status, line));
        assert_eq!(self.one("cache-control"), "no-store");
        assert_eq!(self.one("referrer-policy"), "no-referrer");
        assert!(self.all("set-cookie").is_empty() && self.all("location").is_empty());
    }
}
/// Reads one response on `stream`: the head, then `Content-Length` bytes unless the request
/// was `HEAD`. It does not wait for the server to close the connection.
async fn read_reply(stream: &mut TcpStream, head_only: bool) -> Reply {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let end = loop {
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "connection closed before a response head");
        bytes.extend_from_slice(&buffer[..read]);
    };
    let text = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap()["HTTP/1.1 ".len()..][..3]
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    let length = match headers.iter().find(|(name, _)| name == "content-length") {
        Some(_) if head_only => 0,
        Some((_, length)) => length.parse().unwrap(),
        None => 0,
    };
    let mut body = bytes[end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "connection closed inside a response body");
        body.extend_from_slice(&buffer[..read]);
    }
    let body = String::from_utf8(body).unwrap();
    Reply {
        status,
        headers,
        body,
    }
}
/// Sends `request` bytes on a new connection and reads one response within ten seconds.
pub(super) async fn send(address: SocketAddr, request: &str) -> Reply {
    let head_only = request.starts_with("HEAD ");
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        read_reply(&mut stream, head_only).await
    })
    .await
    .expect("no response within ten seconds")
}
fn handoff(h: &Harness, pool: sqlx::PgPool) -> LoginHandoff {
    let policy = sessions::Policy::new(Duration::from_secs(60), 16, Duration::from_secs(5));
    let auth = service::browser_auth(h, pool, Duration::from_secs(300), policy.unwrap());
    LoginHandoff::new(Arc::new(auth), settings()).unwrap()
}
/// A form `POST` from the application page: one exact `Origin` and an empty body.
fn form() -> String {
    head(
        "POST",
        "/login",
        &[
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", "0"),
        ],
    )
}
/// A well-formed callback with a matching caller cookie, as a top-level navigation.
fn navigation(extra: &[(&str, &str)]) -> String {
    let locator = "L".repeat(43);
    let target = format!(
        "/callback?code=synthetic-code&state={locator}.{}&iss=https%3A%2F%2Fissuer.example.test%2Frealm",
        "s".repeat(43)
    );
    let cookie = format!("{LOGIN_COOKIE}={locator}.{}", "c".repeat(43));
    let mut headers = vec![("cookie", cookie.as_str())];
    headers.extend_from_slice(extra);
    head("GET", &target, &headers)
}

#[tokio::test]
async fn settings_are_validated_before_any_route_is_built() {
    let (database, pool) = service::silent_database();
    let h = Harness::new().await;
    let build = |settings: Settings<'_>| router(handoff(&h, pool.clone()), settings).map(|_| ());
    assert_eq!(build(limits()), Ok(()));
    let rate = |burst, interval| Rate { burst, interval };
    // The registered callback is /callback. None of these panics inside Axum.
    for (initiation, error) in [
        ("/{id}", SettingsError::Pattern),
        ("/login/{*rest}", SettingsError::Pattern),
        ("/:id", SettingsError::Pattern),
        ("", SettingsError::Path),
        ("login", SettingsError::Path),
        ("//login", SettingsError::Path),
        ("/login?next=x", SettingsError::Path),
        ("/callback", SettingsError::Collision),
        ("/healthz", SettingsError::Collision),
        ("/readyz", SettingsError::Collision),
    ] {
        let settings = Settings {
            initiation,
            ..limits()
        };
        assert_eq!(build(settings), Err(error), "{initiation}");
    }
    for (begin, callback) in [
        (rate(0, HOUR), rate(1, HOUR)),
        (rate(1, HOUR), rate(1, Duration::ZERO)),
        (rate(1, HOUR + Duration::from_secs(1)), rate(1, HOUR)),
    ] {
        let settings = Settings {
            begin,
            callback,
            ..limits()
        };
        assert_eq!(build(settings), Err(SettingsError::Rate));
    }
    for in_flight in [0, 4097] {
        let settings = Settings {
            in_flight,
            ..limits()
        };
        assert_eq!(build(settings), Err(SettingsError::InFlight));
    }
    assert_eq!(h.count(), 0);
    assert!(database.accept().is_err());
}

#[tokio::test]
async fn routes_are_exact_and_other_methods_do_no_auth_work() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let address = serve(router(handoff(&h, pool), limits()).unwrap()).await;

    // HEAD on either route is refused like any other method, before admission.
    for (path, allow, methods) in [
        (
            "/login",
            "POST",
            &["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "PATCH"][..],
        ),
        (
            "/callback",
            "GET",
            &["HEAD", "POST", "PUT", "DELETE", "OPTIONS"][..],
        ),
    ] {
        for method in methods {
            let request = head(method, path, &[("origin", ORIGIN), ("content-length", "0")]);
            let reply = send(address, &request).await;
            assert_eq!(reply.status, 405, "{method} {path}");
            assert_eq!(reply.one("allow"), allow);
            if *method != "HEAD" {
                reply.refused(405, "method not allowed\n");
            }
        }
    }
    // Only the two literal paths are routed. Others get Axum's fallback, without a cookie or
    // redirect. The router does not serve the operational routes.
    for path in [
        "/",
        "/Login",
        "/login/",
        "/login/x",
        "//login",
        "/callback/",
        "/Callback",
        "/callback/x",
        "/%63allback",
        "/healthz",
        "/readyz",
    ] {
        for request in [
            form().replacen("/login", path, 1),
            navigation(&[]).replacen("/callback", path, 1),
        ] {
            let reply = send(address, &request).await;
            assert_eq!(reply.status, 404, "{path}");
            assert!(reply.all("set-cookie").is_empty() && reply.all("location").is_empty());
        }
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // The admissible form POST and callback reach the service through dispatch. The original
    // callback path reaches the handoff, which compares it again.
    send(address, &form()).await.refused(503, UNAVAILABLE);
    assert_eq!(h.count(), 2);
    assert!(attempted());
    send(address, &navigation(&[]))
        .await
        .refused(503, UNAVAILABLE);
    assert!(attempted());
}

#[tokio::test]
async fn request_bounds_precede_parsing_and_never_wait_for_a_body() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let address = serve(router(handoff(&h, pool), limits()).unwrap()).await;

    // Target: one byte over is refused on either route before the handoff reads the query.
    for (method, path) in [("POST", "/login"), ("GET", "/callback")] {
        let target = format!("{path}?pad=");
        let target = target.clone() + &"p".repeat(MAX_TARGET_BYTES + 1 - target.len());
        let request = head(
            method,
            &target,
            &[("origin", ORIGIN), ("content-length", "0")],
        );
        send(address, &request)
            .await
            .refused(414, "login request target too long\n");
    }
    // Header fields and header bytes, one over each ceiling.
    let fields: Vec<_> = (1..MAX_HEADER_FIELDS)
        .map(|n| format!("x-field-{n}"))
        .collect();
    let mut many: Vec<(&str, &str)> = fields.iter().map(|name| (name.as_str(), "1")).collect();
    // Host and cookie, then a field that fills the byte ceiling exactly.
    let base: usize = navigation(&[])
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| name.len() + value.len())
        .sum();
    let at_bytes = "v".repeat(MAX_HEADER_BYTES - base - "x-pad".len());
    for request in [
        // Host, cookie and 63 more fields.
        navigation(&many),
        navigation(&[("x-pad", &(at_bytes.clone() + "v"))]),
    ] {
        send(address, &request)
            .await
            .refused(431, "login request headers too large\n");
    }
    // Bodies: declared, chunked or present. The server never receives body bytes for the
    // first two, so a reply proves the guard did not wait for them.
    for (method, path, extra) in [
        ("POST", "/login", &[("content-length", "1")][..]),
        ("POST", "/login", &[("content-length", "1000000000")][..]),
        ("POST", "/login", &[("transfer-encoding", "chunked")][..]),
        ("GET", "/callback", &[("content-length", "1")][..]),
        ("GET", "/callback", &[("transfer-encoding", "chunked")][..]),
    ] {
        let mut headers = vec![("origin", ORIGIN)];
        headers.extend_from_slice(extra);
        let request = head(method, path, &headers);
        send(address, &request)
            .await
            .refused(413, "login request body not accepted\n");
    }
    let request = head(
        "POST",
        "/login",
        &[("origin", ORIGIN), ("content-length", "5")],
    ) + "x=1&y";
    send(address, &request)
        .await
        .refused(413, "login request body not accepted\n");
    assert_eq!(h.count(), 0);
    assert!(!attempted());

    // At the ceilings each request passes the guard. A target query over the handoff's own
    // ceiling is still refused by the handoff, and the remaining field and byte budgets are
    // left for the handoff's cookie rule.
    let target = "/callback?pad=".to_owned();
    let target = target.clone() + &"p".repeat(MAX_TARGET_BYTES - target.len());
    let reply = send(address, &head("GET", &target, &[])).await;
    reply.refused(400, "login response refused; restart login\n");
    many.pop();
    send(address, &navigation(&many))
        .await
        .refused(503, UNAVAILABLE);
    assert_eq!(h.count(), 2);
    assert!(attempted());
    send(address, &navigation(&[("x-pad", &at_bytes)]))
        .await
        .refused(503, UNAVAILABLE);
    assert!(attempted());

    // The handoff's query and cookie ceilings are reachable through the router: a maximal
    // query and a maximal cookie field reach the service.
    let locator = "L".repeat(43);
    let mut query = format!(
        "code=synthetic-code&state={locator}.{}&iss=https%3A%2F%2Fissuer.example.test%2Frealm&pad=",
        "s".repeat(43)
    );
    query.push_str(&"p".repeat(MAX_QUERY_BYTES - query.len()));
    let mut cookie = format!("{LOGIN_COOKIE}={locator}.{}; pad=", "c".repeat(43));
    cookie.push_str(&"p".repeat(MAX_COOKIE_BYTES - cookie.len()));
    let request = head("GET", &format!("/callback?{query}"), &[("cookie", &cookie)]);
    send(address, &request).await.refused(503, UNAVAILABLE);
    assert!(attempted());
}

#[tokio::test]
async fn rate_budgets_are_separate_shared_by_clones_and_spent_before_work() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let settings = Settings {
        begin: Rate {
            burst: 2,
            interval: HOUR,
        },
        callback: Rate {
            burst: 3,
            interval: HOUR,
        },
        ..limits()
    };
    let router = router(handoff(&h, pool), settings).unwrap();
    // Two listeners serve clones of one router value.
    let (first, second) = (serve(router.clone()).await, serve(router).await);

    // Method and bound refusals spend no rate.
    for _ in 0..10 {
        send(first, &head("HEAD", "/login", &[])).await;
        send(second, &head("GET", "/login", &[])).await;
        let body = head(
            "POST",
            "/login",
            &[("origin", ORIGIN), ("content-length", "1")],
        );
        send(first, &body)
            .await
            .refused(413, "login request body not accepted\n");
    }
    // Admitted requests spend rate even when the handoff then refuses them: an initiation
    // without Origin on each listener exhausts the shared begin budget.
    let foreign = head("POST", "/login", &[("content-length", "0")]);
    send(first, &foreign)
        .await
        .refused(403, "login origin refused\n");
    send(second, &foreign)
        .await
        .refused(403, "login origin refused\n");
    for address in [first, second] {
        send(address, &foreign).await.refused(429, RATE_REFUSED);
        // A valid form POST is refused before any provider or database work.
        send(address, &form()).await.refused(429, RATE_REFUSED);
    }
    // The callback budget is separate and also shared: callbacks without a binding cookie.
    let unbound = navigation(&[]).replace(LOGIN_COOKIE, "theme");
    for address in [first, second, first] {
        send(address, &unbound).await.refused(400, BINDING_REFUSED);
    }
    for address in [first, second] {
        send(address, &unbound).await.refused(429, RATE_REFUSED);
        send(address, &navigation(&[]))
            .await
            .refused(429, RATE_REFUSED);
        send(address, &form()).await.refused(429, RATE_REFUSED);
    }
    assert_eq!(h.count(), 0);
    assert!(!attempted());
}

#[tokio::test]
async fn in_flight_cap_refuses_without_work_and_disconnect_releases_the_permit() {
    let (database, pool) = service::silent_database();
    let attempted = || database.accept().is_ok();
    let h = Harness::new().await;
    let settings = Settings {
        begin: Rate {
            burst: 3,
            interval: HOUR,
        },
        in_flight: 1,
        ..limits()
    };
    let router = router(handoff(&h, pool), settings).unwrap();
    let (first, second) = (serve(router.clone()).await, serve(router).await);

    // One initiation holds the only permit while its discovery request stalls. The
    // keep-alive connection lets the server notice the client leaving.
    h.script.lock().unwrap().mode = "stall";
    let mut held = TcpStream::connect(first).await.unwrap();
    held.write_all(form().as_bytes()).await.unwrap();
    h.entered(1).await;

    // Both routes on both clones are busy: no rate spent, no provider or database work.
    for address in [first, second] {
        send(address, &form()).await.refused(503, BUSY_REFUSED);
        send(address, &navigation(&[]))
            .await
            .refused(503, BUSY_REFUSED);
    }
    assert_eq!(h.count(), 1);
    assert!(!attempted());

    // The client leaves. Axum drops the handler future, which releases the permit and
    // cancels the provider request.
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), h.server.closed.notified())
        .await
        .expect("cancelled provider request did not close");
    // Admitted again. The cancelled refresh left the provider in cooldown, so the handoff
    // refuses without another provider request. Busy refusals spent no begin rate: two
    // units remain after the cancelled initiation.
    h.script.lock().unwrap().mode = "ok";
    send(second, &form()).await.refused(503, UNAVAILABLE);
    send(first, &form()).await.refused(503, UNAVAILABLE);
    send(first, &form()).await.refused(429, RATE_REFUSED);
    assert_eq!(h.count(), 1);
    assert!(!attempted());
}
