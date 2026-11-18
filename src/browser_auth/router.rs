//! Bounded Axum router for one [`LoginHandoff`] (ADR 0018).
//!
//! **Not mounted.** No listener or running process constructs it: the API and worker still
//! serve `/healthz` and `/readyz` only. [`router`] validates every setting first and then
//! returns an ordinary [`Router`] with exactly two literal routes:
//!
//! - the explicit initiation path, dispatched to [`LoginHandoff::initiate`] for `POST` only;
//! - the provider's registered callback path, dispatched to [`LoginHandoff::callback`] for
//!   `GET` only. `HEAD` is refused like any other method and never reaches the handoff.
//!
//! Each request is decided in this order. Steps 1–4 do no provider, pool or database work.
//!
//! 1. Method. A wrong method is `405` and spends nothing.
//! 2. Request bounds on the head that HTTP parsing produced: target length, header count,
//!    header bytes and an empty body. A refusal spends nothing and never polls the body.
//! 3. One in-flight permit, shared by both routes. None free is `503` and spends no rate.
//! 4. One unit of that route's rate budget. None left is `429`; the permit is released.
//! 5. The handoff, holding the permit until it returns or its future is dropped.
//!
//! The rate unit spent in step 4 is never refunded, whatever the handoff then decides.
//! Admission state is per router value and shared by its clones. It is not keyed by client,
//! trusts no forwarded header, never queues and spawns nothing.
use super::handoff::{self, LoginHandoff};
use axum::{
    Router,
    body::{Body, HttpBody},
    extract::Request,
    http::{HeaderMap, Method, Response, StatusCode, Uri, header, request::Parts},
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
/// Operational routes in `crate::serve`. A login path never shadows them when merged.
const CORE_PATHS: [&str; 2] = ["/healthz", "/readyz"];

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

/// Fixed refusals of [`Settings`]. No variant carries a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    /// A path contains route syntax (`{`, `}`, `*` or `:`).
    Pattern,
    /// A path is not a plain literal path of the accepted shape.
    Path,
    /// The two paths are equal, or one is an operational route.
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
    let plain = rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
        && rest
            .split_terminator('/')
            .all(|segment| !matches!(segment, "" | "." | ".."));
    plain.then_some(()).ok_or(SettingsError::Path)
}
/// Both paths are valid and distinct, and neither is an operational route. Checked before a
/// route is added, so `Router::route` cannot panic on them.
fn check_paths(initiation: &str, callback: &str) -> Result<(), SettingsError> {
    check_path(initiation)?;
    check_path(callback)?;
    if initiation == callback || CORE_PATHS.contains(&initiation) || CORE_PATHS.contains(&callback)
    {
        return Err(SettingsError::Collision);
    }
    Ok(())
}

/// A generic cell rate budget over monotonic time: one `Instant`, the earliest time at
/// which the budget would be full again if nothing else were admitted.
struct Budget {
    interval: Duration,
    /// `interval × (burst − 1)`: how far that time may run ahead of now.
    tolerance: Duration,
    full_at: Mutex<Instant>,
}
impl Budget {
    fn new(rate: Rate, now: Instant) -> Result<Self, SettingsError> {
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
    fn admit(&self, now: Instant) -> bool {
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
}

/// Fixed lines through the handoff's builder: `no-store`, `no-referrer`, no cookie and no
/// `Location`.
const TARGET_REFUSED: &str = "login request target too long\n";
const HEADERS_REFUSED: &str = "login request headers too large\n";
const BODY_REFUSED: &str = "login request body not accepted\n";
const RATE_REFUSED: &str = "login rate limit reached; try again later\n";
const BUSY_REFUSED: &str = "login busy; try again later\n";

fn target_bytes(uri: &Uri) -> usize {
    uri.scheme_str()
        .map_or(0, |scheme| scheme.len() + "://".len())
        + uri
            .authority()
            .map_or(0, |authority| authority.as_str().len())
        + uri
            .path_and_query()
            .map_or(0, |target| target.as_str().len())
}
fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len())
        .sum()
}
/// The empty form and navigation profile: no `Transfer-Encoding`, every `Content-Length` is
/// `0`, and the parsed body is known to be empty. Decided from metadata alone.
fn empty_body(headers: &HeaderMap, body: &Body) -> bool {
    !headers.contains_key(header::TRANSFER_ENCODING)
        && headers
            .get_all(header::CONTENT_LENGTH)
            .iter()
            .all(|value| value.as_bytes() == b"0")
        && body.size_hint().exact() == Some(0)
}
/// Bounds decided on what HTTP parsing already produced, before the handoff parses its query
/// or cookies. They do not limit how much the server reads to parse a head. A refusal is a
/// fixed status and line.
fn bounds(request: &Parts, body: &Body) -> Result<(), (StatusCode, &'static str)> {
    if target_bytes(&request.uri) > MAX_TARGET_BYTES {
        return Err((StatusCode::URI_TOO_LONG, TARGET_REFUSED));
    }
    if request.headers.len() > MAX_HEADER_FIELDS
        || header_bytes(&request.headers) > MAX_HEADER_BYTES
    {
        return Err((StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, HEADERS_REFUSED));
    }
    if !empty_body(&request.headers, body) {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, BODY_REFUSED));
    }
    Ok(())
}

/// State behind one router value and every clone of it. Constant size.
struct Routes {
    handoff: LoginHandoff,
    begin: Budget,
    callback: Budget,
    in_flight: Semaphore,
}
impl Routes {
    async fn dispatch(&self, route: Route, request: Request) -> Response<&'static str> {
        let (request, body) = request.into_parts();
        let (method, allow, budget) = match route {
            Route::Begin => (Method::POST, "POST", &self.begin),
            Route::Callback => (Method::GET, "GET", &self.callback),
        };
        if request.method != method {
            return handoff::wrong_method(allow);
        }
        // Inspect body metadata only, then drop the body without polling it.
        if let Err((status, line)) = bounds(&request, &body) {
            return handoff::respond(status, line);
        }
        drop(body);
        // `try_acquire` never waits. The permit is released when this future completes or is
        // dropped, including on client disconnect.
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return handoff::respond(StatusCode::SERVICE_UNAVAILABLE, BUSY_REFUSED);
        };
        if !budget.admit(Instant::now()) {
            return handoff::respond(StatusCode::TOO_MANY_REQUESTS, RATE_REFUSED);
        }
        match route {
            Route::Begin => self.handoff.initiate(&request).await,
            Route::Callback => self.handoff.callback(&request).await,
        }
    }
}

/// Validates `settings` against the handoff's registered callback, then builds the router.
/// The original request path reaches the handoff unchanged: mount the result with
/// `Router::merge`, never under a prefix with `Router::nest`. It has no fallback, so an
/// unrouted path gets the host router's fallback.
pub fn router(handoff: LoginHandoff, settings: Settings<'_>) -> Result<Router, SettingsError> {
    let Settings {
        initiation,
        begin,
        callback,
        in_flight,
    } = settings;
    let callback_path = handoff.callback_path().to_owned();
    check_paths(initiation, &callback_path)?;
    let now = Instant::now();
    let (begin, callback) = (Budget::new(begin, now)?, Budget::new(callback, now)?);
    if !(1..=MAX_IN_FLIGHT).contains(&in_flight) {
        return Err(SettingsError::InFlight);
    }
    let routes = Arc::new(Routes {
        handoff,
        begin,
        callback,
        in_flight: Semaphore::new(in_flight as usize),
    });
    // `any`, not `get`: Axum also runs `get` handlers for HEAD.
    let route = |route: Route| {
        let routes = routes.clone();
        any(
            move |request: Request| async move { routes.dispatch(route, request).await.map(Body::from) },
        )
    };
    Ok(Router::new()
        .route(initiation, route(Route::Begin))
        .route(&callback_path, route(Route::Callback)))
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
        ] {
            assert_eq!(check_paths(initiation, callback), Ok(()), "{initiation}");
        }
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        let longest = &long[..MAX_PATH_BYTES];
        assert_eq!(check_paths(longest, "/callback"), Ok(()));
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
            assert_eq!(check_paths(path, "/callback"), Err(error), "{path}");
            assert_eq!(check_paths("/login", path), Err(error), "{path}");
        }
        for (initiation, callback) in [
            ("/callback", "/callback"),
            ("/healthz", "/callback"),
            ("/readyz", "/callback"),
            ("/login", "/healthz"),
            ("/login", "/readyz"),
        ] {
            assert_eq!(
                check_paths(initiation, callback),
                Err(SettingsError::Collision),
                "{initiation} {callback}"
            );
        }
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
}
