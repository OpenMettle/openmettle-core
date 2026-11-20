//! Bounded Axum router for one [`LoginHandoff`] (ADRs 0018 and 0019).
//!
//! **Off by default.** The API mounts [`router_with_sessions`] only when
//! `OPENMETTLE_API_AUTH_CONFIG` names a version-2 settings document (ADR 0025). Otherwise the
//! API, like the worker always, serves `/healthz` and `/readyz` only. [`router`] validates
//! every setting first and then returns an ordinary [`Router`] with exactly two literal routes:
//!
//! - the explicit initiation path, dispatched to [`LoginHandoff::initiate`] for `POST` only;
//! - the provider's registered callback path, dispatched to [`LoginHandoff::callback`] for
//!   `GET` only. `HEAD` is refused like any other method and never reaches the handoff.
//!
//! [`router_with_sessions`] adds two more explicit literal routes with their own budgets:
//!
//! - the session check path, dispatched to [`LoginHandoff::session`] for `GET` only;
//! - the logout path, dispatched to [`LoginHandoff::logout`] for `POST` only.
//!
//! Each request on any route is decided in this order by one implementation. Steps 1–4 do no
//! provider, pool or database work.
//!
//! 1. Method. A wrong method is `405` and spends nothing.
//! 2. Request bounds on the head that HTTP parsing produced: target length, header count,
//!    header bytes and the body profile. Every route requires an empty body, except that an
//!    initiation may declare one small form body (ADR 0022). A refusal spends nothing and
//!    never polls the body.
//! 3. One in-flight permit, shared by every route. None free is `503` and spends no rate.
//! 4. One unit of that route's own rate budget. None left is `429`; the permit is released.
//! 5. The handoff, holding the permit until it returns or its future is dropped. A declared
//!    initiation form is read first, under the permit: at most [`handoff::MAX_FORM_BYTES`]
//!    within [`FORM_READ_TIMEOUT`], or `408`.
//!
//! The rate unit spent in step 4 is never refunded, whatever the handoff then decides or
//! however the form read ends.
//! Admission state is per router value and shared by its clones. It is not keyed by client,
//! trusts no forwarded header, never queues and spawns nothing.
use super::handoff::{self, LoginHandoff};
use super::path_byte;
use axum::{
    Router,
    body::{Body, Bytes, HttpBody, to_bytes},
    extract::Request,
    http::{HeaderMap, HeaderName, Method, Response, StatusCode, Uri, header, request::Parts},
    routing::any,
};
use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

// Implementation ceilings, not deployment values. Requests at the handoff's own query and
// cookie ceilings (ADR 0017) still pass these bounds.
/// Bytes of a route path.
pub const MAX_PATH_BYTES: usize = 256;
/// Bytes of the parsed request target: path and query, plus scheme and authority for an
/// absolute-form target. Room for a maximal path and a query at the handoff's ceiling.
pub const MAX_TARGET_BYTES: usize = handoff::MAX_QUERY_BYTES + 1024;
/// Header fields, counting each repeated field.
pub const MAX_HEADER_FIELDS: usize = 64;
/// Header name and value bytes, excluding delimiters. Room for the handoff's cookie ceiling.
pub const MAX_HEADER_BYTES: usize = handoff::MAX_COOKIE_BYTES + 8 * 1024;
/// Largest burst of a rate budget.
pub const MAX_BURST: u32 = 65_536;
/// Shortest and longest refill interval of a rate budget.
pub const MIN_INTERVAL: Duration = Duration::from_millis(1);
pub const MAX_INTERVAL: Duration = Duration::from_secs(3600);
/// Largest in-flight cap.
pub const MAX_IN_FLIGHT: u32 = 4096;
/// Longest wait for a declared initiation form body, counted while its permit is held.
pub const FORM_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// The only media type of an initiation form body, as an HTML form sends it.
const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
const FORM_NOT_RECEIVED: &str = "login request body not received\n";
/// Operational routes in `crate::routes`. A login path never shadows them when `crate::app`
/// merges the two routers.
const CORE_PATHS: [&str; 2] = ["/healthz", "/readyz"];

/// A path no sign-in route may take: an operational route, or `/v1` and everything under it,
/// which the application API serves (ADR 0027 PR4b). `crate::app` merges every router, so a
/// reserved path is refused here, and offline, rather than by a panic in `Router::merge`.
pub(super) fn reserved(path: &str) -> bool {
    CORE_PATHS.contains(&path) || path == "/v1" || path.starts_with("/v1/")
}

/// One rate budget: at most `burst` admissions at once, refilled by one every `interval`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    pub burst: u32,
    pub interval: Duration,
}

/// Explicit router settings. None has a default and none is taken from a request.
#[derive(Clone, Copy, Debug)]
pub struct Settings<'a> {
    /// Exact literal path of the initiation form `POST`.
    pub initiation: &'a str,
    /// Budget for initiations.
    pub begin: Rate,
    /// Budget for callbacks, separate from `begin`.
    pub callback: Rate,
    /// Requests inside the handoff at once, across both routes.
    pub in_flight: u32,
}

/// Explicit settings for the session routes of [`router_with_sessions`]. None has a default
/// and none is taken from a request.
#[derive(Clone, Copy, Debug)]
pub struct SessionSettings<'a> {
    /// Exact literal path of the session check `GET`.
    pub session: &'a str,
    /// Exact literal path of the logout form `POST`.
    pub logout: &'a str,
    /// Budget for session checks, separate from every other budget.
    pub checks: Rate,
    /// Budget for logouts, separate from every other budget.
    pub logouts: Rate,
}

/// Fixed refusals of [`Settings`] and [`SessionSettings`]. No variant carries a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    /// A path contains route syntax (`{`, `}`, `*` or `:`).
    Pattern,
    /// A path is not a plain literal path of the accepted shape.
    Path,
    /// Two paths are equal, or one is an operational route.
    Collision,
    /// A burst or interval is outside its range.
    Rate,
    /// The in-flight cap is outside its range.
    InFlight,
}
impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pattern => "login path contains route syntax",
            Self::Path => "login path is not a plain literal path",
            Self::Collision => "login paths collide",
            Self::Rate => "login rate is outside its allowed range",
            Self::InFlight => "login in-flight cap is outside its allowed range",
        })
    }
}
impl std::error::Error for SettingsError {}

/// `/`, then segments of ASCII letters, digits and `- . _ ~`: no empty inner segment, dot
/// segment, escape, query or fragment. A trailing `/` is allowed. Axum matches it literally.
fn check_path(path: &str) -> Result<(), SettingsError> {
    if path.len() > MAX_PATH_BYTES {
        return Err(SettingsError::Path);
    }
    if path.bytes().any(|b| b"{}*:".contains(&b)) {
        return Err(SettingsError::Pattern);
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(SettingsError::Path);
    };
    let plain = rest.bytes().all(path_byte)
        && rest
            .split_terminator('/')
            .all(|segment| !matches!(segment, "" | "." | ".."));
    plain.then_some(()).ok_or(SettingsError::Path)
}
/// Every path is valid, no two are equal and none is [`reserved`]. Checked before a route is
/// added, so `Router::route` cannot panic on them.
pub(super) fn check_paths(paths: &[&str]) -> Result<(), SettingsError> {
    for path in paths {
        check_path(path)?;
    }
    for (index, path) in paths.iter().enumerate() {
        if reserved(path) || paths[index + 1..].contains(path) {
            return Err(SettingsError::Collision);
        }
    }
    Ok(())
}

/// A generic cell rate budget over monotonic time: one `Instant`, the earliest time at
/// which the budget would be full again if nothing else were admitted.
pub(super) struct Budget {
    interval: Duration,
    /// `interval × (burst − 1)`: how far that time may run ahead of now.
    tolerance: Duration,
    full_at: Mutex<Instant>,
}
impl Budget {
    pub(super) fn new(rate: Rate, now: Instant) -> Result<Self, SettingsError> {
        if !(1..=MAX_BURST).contains(&rate.burst)
            || !(MIN_INTERVAL..=MAX_INTERVAL).contains(&rate.interval)
        {
            return Err(SettingsError::Rate);
        }
        Ok(Self {
            interval: rate.interval,
            tolerance: rate
                .interval
                .checked_mul(rate.burst - 1)
                .ok_or(SettingsError::Rate)?,
            full_at: Mutex::new(now),
        })
    }
    /// Spends one unit at `now`, or refuses and changes nothing.
    pub(super) fn admit(&self, now: Instant) -> bool {
        // Only this arithmetic runs under the lock, so a poisoned value is still consistent.
        let mut full_at = self.full_at.lock().unwrap_or_else(PoisonError::into_inner);
        let from = (*full_at).max(now);
        if from.duration_since(now) > self.tolerance {
            return false;
        }
        match from.checked_add(self.interval) {
            Some(next) => {
                *full_at = next;
                true
            }
            None => false,
        }
    }
}

#[derive(Clone, Copy)]
enum Route {
    Begin,
    Callback,
    Session,
    Logout,
}
impl Route {
    /// The one accepted method, its `Allow` value and the route family's fixed lines.
    fn profile(self) -> (Method, &'static str, &'static Lines) {
        match self {
            Self::Begin => (Method::POST, "POST", &LOGIN_LINES),
            Self::Callback => (Method::GET, "GET", &LOGIN_LINES),
            Self::Session => (Method::GET, "GET", &SESSION_LINES),
            Self::Logout => (Method::POST, "POST", &SESSION_LINES),
        }
    }
}

/// Fixed lines through the handoff's builder: `no-store`, `no-referrer`, no cookie and no
/// `Location`. The login lines are unchanged from ADR 0018.
struct Lines {
    target: &'static str,
    headers: &'static str,
    body: &'static str,
    busy: &'static str,
    rate: &'static str,
}
const LOGIN_LINES: Lines = Lines {
    target: "login request target too long\n",
    headers: "login request headers too large\n",
    body: "login request body not accepted\n",
    busy: "login busy; try again later\n",
    rate: "login rate limit reached; try again later\n",
};
const SESSION_LINES: Lines = Lines {
    target: "session request target too long\n",
    headers: "session request headers too large\n",
    body: "session request body not accepted\n",
    busy: "session busy; try again later\n",
    rate: "session rate limit reached; try again later\n",
};

pub(crate) fn target_bytes(uri: &Uri) -> usize {
    uri.scheme_str()
        .map_or(0, |scheme| scheme.len() + "://".len())
        + uri
            .authority()
            .map_or(0, |authority| authority.as_str().len())
        + uri
            .path_and_query()
            .map_or(0, |target| target.as_str().len())
}
pub(crate) fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len())
        .sum()
}
/// The empty form and navigation profile: no `Transfer-Encoding`, every `Content-Length` is
/// `0`, and the parsed body is known to be empty. Decided from metadata alone.
pub(crate) fn empty_body(headers: &HeaderMap, body: &Body) -> bool {
    !headers.contains_key(header::TRANSFER_ENCODING)
        && headers
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .all(|value| value.as_bytes() == b"0")
        && body.size_hint().exact() == Some(0)
}
/// The initiation form profile (ADR 0022), decided from metadata alone. `Some(0)` is the
/// empty profile above. Otherwise there is no `Transfer-Encoding`, exactly one `Content-Type`
/// that is the form media type, and exactly one `Content-Length` of 1 to
/// [`handoff::MAX_FORM_BYTES`] in plain decimal that the parsed body agrees with. `None`
/// refuses, including a chunked body, whose length is not declared.
pub(super) fn form_body(headers: &HeaderMap, body: &Body) -> Option<usize> {
    if empty_body(headers, body) {
        return Some(0);
    }
    let single = |name: HeaderName| {
        let mut values = headers.get_all(name).iter();
        values.next().filter(|_| values.next().is_none())
    };
    let media_type = single(header::CONTENT_TYPE)?.as_bytes();
    let length = single(header::CONTENT_LENGTH)?.as_bytes();
    if headers.contains_key(header::TRANSFER_ENCODING)
        || !media_type.eq_ignore_ascii_case(FORM_MEDIA_TYPE.as_bytes())
        || length.len() > 3
        || length.first() == Some(&b'0')
        || !length.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let length: usize = std::str::from_utf8(length).ok()?.parse().ok()?;
    (length <= handoff::MAX_FORM_BYTES && body.size_hint().exact() == Some(length as u64))
        .then_some(length)
}
/// Bounds decided on what HTTP parsing already produced, before the handoff parses its query,
/// cookies or form. They do not limit how much the server reads to parse a head. A refusal is
/// a fixed status and line. Success is the declared body length: zero, or the length of an
/// initiation form that has not been read yet.
fn bounds(
    route: Route,
    request: &Parts,
    body: &Body,
    lines: &Lines,
) -> Result<usize, (StatusCode, &'static str)> {
    if target_bytes(&request.uri) > MAX_TARGET_BYTES {
        return Err((StatusCode::URI_TOO_LONG, lines.target));
    }
    if request.headers.len() > MAX_HEADER_FIELDS
        || header_bytes(&request.headers) > MAX_HEADER_BYTES
    {
        return Err((StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, lines.headers));
    }
    let declared = match route {
        Route::Begin => form_body(&request.headers, body),
        Route::Callback | Route::Session | Route::Logout => {
            empty_body(&request.headers, body).then_some(0)
        }
    };
    declared.ok_or((StatusCode::PAYLOAD_TOO_LARGE, lines.body))
}

/// State behind one router value and every clone of it. Constant size.
struct Shared {
    handoff: LoginHandoff,
    /// One cap across every route.
    in_flight: Semaphore,
}
impl Shared {
    /// The single route implementation. `budget` belongs to `route` alone.
    async fn dispatch(
        &self,
        route: Route,
        budget: &Budget,
        request: Request,
    ) -> Response<&'static str> {
        let (request, body) = request.into_parts();
        let (method, allow, lines) = route.profile();
        if request.method != method {
            return handoff::wrong_method(allow);
        }
        // Inspect body metadata only. An empty body is dropped here without polling it. A
        // declared initiation form is kept unread until the request is admitted.
        let declared = match bounds(route, &request, &body, lines) {
            Ok(declared) => declared,
            Err((status, line)) => return handoff::respond(status, line),
        };
        let body = (declared > 0).then_some(body);
        // `try_acquire` never waits. The permit is released when this future completes or is
        // dropped, including on client disconnect.
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return handoff::respond(StatusCode::SERVICE_UNAVAILABLE, lines.busy);
        };
        if !budget.admit(Instant::now()) {
            return handoff::respond(StatusCode::TOO_MANY_REQUESTS, lines.rate);
        }
        // The declared length bounds the read, and the timeout bounds a client that stalls.
        let form = match body {
            None => Bytes::new(),
            Some(body) => {
                let read = to_bytes(body, handoff::MAX_FORM_BYTES);
                match tokio::time::timeout(FORM_READ_TIMEOUT, read).await {
                    Ok(Ok(form)) if form.len() == declared => form,
                    _ => return handoff::respond(StatusCode::REQUEST_TIMEOUT, FORM_NOT_RECEIVED),
                }
            }
        };
        match route {
            Route::Begin => self.handoff.initiate(&request, &form).await,
            Route::Callback => self.handoff.callback(&request).await,
            Route::Session => self.handoff.session(&request).await,
            Route::Logout => self.handoff.logout(&request).await,
        }
    }
}

/// Validates `settings` against the handoff's registered callback, then builds the login
/// router: the initiation and callback routes only. The original request path reaches the
/// handoff unchanged: mount the result with `Router::merge`, never under a prefix with
/// `Router::nest`. It has no fallback, so an unrouted path gets the host router's fallback.
pub fn router(handoff: LoginHandoff, settings: Settings<'_>) -> Result<Router, SettingsError> {
    build(handoff, settings, None)
}

/// [`router`] plus the session check and logout routes (ADR 0019). All four paths obey the
/// same shape and collision rules, every route has its own budget and all four share the
/// one in-flight cap. The same mounting rules apply.
pub fn router_with_sessions(
    handoff: LoginHandoff,
    settings: Settings<'_>,
    sessions: SessionSettings<'_>,
) -> Result<Router, SettingsError> {
    build(handoff, settings, Some(sessions))
}

/// Every [`router_with_sessions`] settings check, without a handoff or any route: path shape,
/// collisions among the four paths and with the operational routes, each budget and the
/// in-flight cap. `callback_path` is the selected provider's registered callback path. It
/// needs no runtime, listener, pool or network, so the offline configuration check
/// (ADR 0020) runs the same rules.
pub(crate) fn check(
    callback_path: &str,
    settings: Settings<'_>,
    sessions: SessionSettings<'_>,
) -> Result<(), SettingsError> {
    plan(callback_path, settings, Some(sessions)).map(drop)
}

/// Validated routes with fresh budgets, in the order they are added, and the in-flight cap.
type Plan<'a> = (Vec<(&'a str, Route, Arc<Budget>)>, u32);
/// The single settings validation behind [`build`] and [`check`]. Paths first, then each
/// budget in route order, then the in-flight cap.
fn plan<'a>(
    callback_path: &'a str,
    settings: Settings<'a>,
    sessions: Option<SessionSettings<'a>>,
) -> Result<Plan<'a>, SettingsError> {
    let Settings {
        initiation,
        begin,
        callback,
        in_flight,
    } = settings;
    let mut routes = vec![(initiation, Route::Begin, begin)];
    routes.push((callback_path, Route::Callback, callback));
    if let Some(sessions) = sessions {
        routes.push((sessions.session, Route::Session, sessions.checks));
        routes.push((sessions.logout, Route::Logout, sessions.logouts));
    }
    let paths: Vec<&str> = routes.iter().map(|(path, _, _)| *path).collect();
    check_paths(&paths)?;
    let now = Instant::now();
    let mut budgets = Vec::with_capacity(routes.len());
    for (path, route, rate) in routes {
        budgets.push((path, route, Arc::new(Budget::new(rate, now)?)));
    }
    if !(1..=MAX_IN_FLIGHT).contains(&in_flight) {
        return Err(SettingsError::InFlight);
    }
    Ok((budgets, in_flight))
}

fn build(
    handoff: LoginHandoff,
    settings: Settings<'_>,
    sessions: Option<SessionSettings<'_>>,
) -> Result<Router, SettingsError> {
    let callback_path = handoff.callback_path().to_owned();
    let (budgets, in_flight) = plan(&callback_path, settings, sessions)?;
    let shared = Arc::new(Shared {
        handoff,
        in_flight: Semaphore::new(in_flight as usize),
    });
    let mut router = Router::new();
    for (path, route, budget) in budgets {
        let shared = shared.clone();
        // `any`, not `get`: Axum also runs `get` handlers for HEAD.
        let handler = any(move |request: Request| async move {
            shared
                .dispatch(route, &budget, request)
                .await
                .map(Body::from)
        });
        router = router.route(path, handler);
    }
    Ok(router)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_plain_distinct_literals() {
        for (initiation, callback) in [
            ("/login", "/callback"),
            ("/", "/callback"),
            ("/auth/login/", "/auth/callback"),
            ("/a-b.c_d~e", "/x/y/z"),
            ("/healthz/login", "/readyz2"),
            // Only `/v1` itself and paths under it are reserved, not a shared prefix.
            ("/v10", "/v1x/callback"),
            ("/auth/v1", "/api/v1/callback"),
        ] {
            assert_eq!(check_paths(&[initiation, callback]), Ok(()), "{initiation}");
        }
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        let longest = &long[..MAX_PATH_BYTES];
        assert_eq!(check_paths(&[longest, "/callback"]), Ok(()));
        for (path, error) in [
            ("/{id}", SettingsError::Pattern),
            ("/login/{*rest}", SettingsError::Pattern),
            ("/*rest", SettingsError::Pattern),
            ("/:id", SettingsError::Pattern),
            ("/login}", SettingsError::Pattern),
            ("", SettingsError::Path),
            ("login", SettingsError::Path),
            ("//", SettingsError::Path),
            ("//login", SettingsError::Path),
            ("/a//", SettingsError::Path),
            ("/a//b", SettingsError::Path),
            ("/./login", SettingsError::Path),
            ("/login/..", SettingsError::Path),
            ("/login?next=x", SettingsError::Path),
            ("/login#x", SettingsError::Path),
            ("/log%69n", SettingsError::Path),
            ("/log in", SettingsError::Path),
            ("/lögin", SettingsError::Path),
            ("/login\\x", SettingsError::Path),
            (long.as_str(), SettingsError::Path),
        ] {
            // Either path; the callback comes from the provider configuration.
            assert_eq!(check_paths(&[path, "/callback"]), Err(error), "{path}");
            assert_eq!(check_paths(&["/login", path]), Err(error), "{path}");
        }
        for (initiation, callback) in [
            ("/callback", "/callback"),
            ("/healthz", "/callback"),
            ("/readyz", "/callback"),
            ("/login", "/healthz"),
            ("/login", "/readyz"),
            // The application API prefix and everything under it (ADR 0027 PR4b).
            ("/v1", "/callback"),
            ("/v1/", "/callback"),
            ("/v1/projects", "/callback"),
            ("/login", "/v1/capabilities"),
            ("/login", "/v1/auth/callback"),
        ] {
            assert_eq!(
                check_paths(&[initiation, callback]),
                Err(SettingsError::Collision),
                "{initiation} {callback}"
            );
        }
    }

    /// Session paths join the same rules: every shape refusal applies in any position, and
    /// any two equal paths or an operational path collide.
    #[test]
    fn session_paths_obey_the_same_rules() {
        let four = |session, logout| check_paths(&["/login", "/callback", session, logout]);
        assert_eq!(four("/session", "/logout"), Ok(()));
        assert_eq!(four("/auth/session/", "/auth/logout"), Ok(()));
        for (path, error) in [
            ("/{id}", SettingsError::Pattern),
            ("/session:x", SettingsError::Pattern),
            ("", SettingsError::Path),
            ("session", SettingsError::Path),
            ("//session", SettingsError::Path),
            ("/a/../session", SettingsError::Path),
            ("/session?x", SettingsError::Path),
            ("/s%65ssion", SettingsError::Path),
            ("/login", SettingsError::Collision),
            ("/callback", SettingsError::Collision),
            ("/healthz", SettingsError::Collision),
            ("/readyz", SettingsError::Collision),
        ] {
            assert_eq!(four(path, "/logout"), Err(error), "{path}");
            assert_eq!(four("/session", path), Err(error), "{path}");
        }
        assert_eq!(four("/same", "/same"), Err(SettingsError::Collision));
    }

    #[test]
    fn rates_are_bounded_and_have_no_default() {
        let now = Instant::now();
        let rate = |burst, interval| Budget::new(Rate { burst, interval }, now).map(|_| ());
        for (burst, interval) in [
            (1, MIN_INTERVAL),
            (MAX_BURST, MAX_INTERVAL),
            (10, Duration::from_secs(1)),
        ] {
            assert_eq!(rate(burst, interval), Ok(()));
        }
        for (burst, interval) in [
            (0, Duration::from_secs(1)),
            (MAX_BURST + 1, Duration::from_secs(1)),
            (1, Duration::ZERO),
            (1, MIN_INTERVAL - Duration::from_nanos(1)),
            (1, MAX_INTERVAL + Duration::from_nanos(1)),
        ] {
            assert_eq!(rate(burst, interval), Err(SettingsError::Rate));
        }
        assert_eq!(SettingsError::Collision.to_string(), "login paths collide");
    }

    /// Refill depends only on the supplied monotonic instants.
    #[test]
    fn budget_refills_one_unit_per_interval_up_to_the_burst() {
        let start = Instant::now();
        let at = |millis| start + Duration::from_millis(millis);
        let interval = Duration::from_secs(10);
        let budget = Budget::new(Rate { burst: 3, interval }, start).unwrap();
        let admitted = |now| budget.admit(now);
        // A full burst, then nothing until one interval has passed.
        assert!(admitted(at(0)) && admitted(at(0)) && admitted(at(0)));
        assert!(!admitted(at(0)));
        assert!(!admitted(at(9_999)));
        assert!(admitted(at(10_000)));
        assert!(!admitted(at(10_000)));
        // Refusals spend nothing: the next unit still arrives on schedule.
        for _ in 0..100 {
            assert!(!admitted(at(15_000)));
        }
        assert!(admitted(at(20_000)));
        // A long idle period refills to the burst and no further.
        assert!(admitted(at(1_000_000)) && admitted(at(1_000_000)) && admitted(at(1_000_000)));
        assert!(!admitted(at(1_000_000)));
        // An instant earlier than one already seen is not a refill.
        assert!(!admitted(at(0)));

        let single = Budget::new(
            Rate {
                burst: 1,
                interval: MIN_INTERVAL,
            },
            start,
        )
        .unwrap();
        assert!(single.admit(start));
        assert!(!single.admit(start));
        assert!(single.admit(start + MIN_INTERVAL));
    }

    #[test]
    fn bounds_measure_the_parsed_target_and_header_map() {
        let uri: Uri = "https://app.example.test/callback?x=1".parse().unwrap();
        assert_eq!(target_bytes(&uri), uri.to_string().len());
        let uri: Uri = "/callback?x=1".parse().unwrap();
        assert_eq!(target_bytes(&uri), "/callback?x=1".len());
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, "a=1".parse().unwrap());
        headers.append(header::COOKIE, "b=22".parse().unwrap());
        assert_eq!(header_bytes(&headers), 2 * "cookie".len() + 3 + 4);
        assert_eq!(headers.len(), 2);

        let empty = |pairs: &[(&str, &str)], body: Body| {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.append(
                    header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            empty_body(&headers, &body)
        };
        assert!(empty(&[], Body::empty()));
        assert!(empty(&[("content-length", "0")], Body::empty()));
        assert!(!empty(&[("content-length", "1")], Body::empty()));
        assert!(!empty(&[("content-length", "00")], Body::empty()));
        assert!(!empty(&[("transfer-encoding", "chunked")], Body::empty()));
        assert!(!empty(&[], Body::from("x")));
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }
    const FORM: (&str, &str) = ("content-type", FORM_MEDIA_TYPE);

    /// The initiation form profile, from metadata alone: nothing here polls a body.
    #[test]
    fn initiation_form_profile_is_one_declared_small_urlencoded_body() {
        let form = |pairs: &[(&str, &str)], body: Body| form_body(&headers(pairs), &body);
        let bytes = |length: usize| Body::from(vec![b'a'; length]);
        // The empty profile is unchanged, with or without a media type.
        assert_eq!(form(&[], Body::empty()), Some(0));
        assert_eq!(
            form(&[FORM, ("content-length", "0")], Body::empty()),
            Some(0)
        );
        // One declared form body, up to the ceiling.
        assert_eq!(form(&[FORM, ("content-length", "16")], bytes(16)), Some(16));
        assert_eq!(form(&[FORM, ("content-length", "1")], bytes(1)), Some(1));
        assert_eq!(handoff::MAX_FORM_BYTES, 256);
        assert_eq!(
            form(&[FORM, ("content-length", "256")], bytes(256)),
            Some(256)
        );
        let mixed_case = ("content-type", "Application/X-WWW-Form-URLEncoded");
        assert_eq!(
            form(&[mixed_case, ("content-length", "16")], bytes(16)),
            Some(16)
        );

        let length = ("content-length", "16");
        let refused: [(&[(&str, &str)], Body); 17] = [
            // One byte over the ceiling, and far over it.
            (&[FORM, ("content-length", "257")], bytes(257)),
            (&[FORM, ("content-length", "1000000000")], Body::empty()),
            // No media type, another one, a parameter, a list and a repeated field.
            (&[length], bytes(16)),
            (&[("content-type", "text/plain"), length], bytes(16)),
            (
                &[("content-type", "multipart/form-data"), length],
                bytes(16),
            ),
            (&[("content-type", "application/json"), length], bytes(16)),
            (
                &[
                    (
                        "content-type",
                        "application/x-www-form-urlencoded; charset=UTF-8",
                    ),
                    length,
                ],
                bytes(16),
            ),
            (
                &[
                    (
                        "content-type",
                        "application/x-www-form-urlencoded, text/plain",
                    ),
                    length,
                ],
                bytes(16),
            ),
            (&[FORM, FORM, length], bytes(16)),
            // No declared length, a repeated one, and lengths that are not plain decimal.
            (&[FORM], bytes(16)),
            (&[FORM, length, length], bytes(16)),
            (&[FORM, ("content-length", "016")], bytes(16)),
            (&[FORM, ("content-length", "+16")], bytes(16)),
            (&[FORM, ("content-length", "16, 16")], bytes(16)),
            // A chunked body, with or without a declared length.
            (&[FORM, ("transfer-encoding", "chunked")], bytes(16)),
            (&[FORM, length, ("transfer-encoding", "chunked")], bytes(16)),
            // A parsed body that disagrees with the declared length.
            (&[FORM, length], bytes(15)),
        ];
        for (index, (pairs, body)) in refused.into_iter().enumerate() {
            assert_eq!(form(pairs, body), None, "case {index}: {pairs:?}");
        }
    }

    /// Only the initiation route takes the form profile. The same request is refused on
    /// every other route, where the body must still be empty.
    #[test]
    fn only_the_initiation_route_admits_a_form_body() {
        let request = |pairs: &[(&str, &str)]| {
            let mut request = Request::builder().method("POST").uri("/path");
            for (name, value) in pairs {
                request = request.header(*name, *value);
            }
            request.body(Body::empty()).unwrap().into_parts().0
        };
        let form = request(&[FORM, ("content-length", "16")]);
        let body = || Body::from(vec![b'a'; 16]);
        assert_eq!(bounds(Route::Begin, &form, &body(), &LOGIN_LINES), Ok(16));
        for (route, lines) in [
            (Route::Callback, &LOGIN_LINES),
            (Route::Session, &SESSION_LINES),
            (Route::Logout, &SESSION_LINES),
        ] {
            assert_eq!(
                bounds(route, &form, &body(), lines),
                Err((StatusCode::PAYLOAD_TOO_LARGE, lines.body))
            );
            // Control: the empty profile still passes there.
            assert_eq!(bounds(route, &request(&[]), &Body::empty(), lines), Ok(0));
        }
        // A form the initiation route refuses is the same fixed refusal.
        let chunked = request(&[FORM, ("transfer-encoding", "chunked")]);
        assert_eq!(
            bounds(Route::Begin, &chunked, &body(), &LOGIN_LINES),
            Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "login request body not accepted\n"
            ))
        );
    }
}
