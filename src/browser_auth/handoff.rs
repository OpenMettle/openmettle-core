//! Same-origin browser login handoff over [`BrowserAuth`] (ADR 0017).
//!
//! **Not mounted.** No router, listener or running process constructs this adapter. It turns
//! one HTTP request head into one response:
//!
//! - [`LoginHandoff::initiate`]: a top-level form `POST` whose single `Origin` equals the
//!   configured application origin becomes a `303` to the provider with the caller cookie.
//! - [`LoginHandoff::callback`]: a top-level `GET` on the exact registered callback path
//!   becomes a `303` to the configured landing with the session cookie.
//!
//! Anything else is a fixed refusal. The adapter reads no request body, `Host`, forwarded
//! header or return URL, logs nothing, and never deletes a cookie.
use super::{BrowserAuth, Error};
use crate::{login, sessions};
use axum::http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header, request::Parts};
use openidconnect::url::Url;
use std::{fmt, sync::Arc};

/// Caller cookie: `<public transaction locator>.<caller secret>`. One slot per browser.
pub const LOGIN_COOKIE: &str = "__Host-openmettle-login";
/// The opaque local session credential (ADR 0013).
pub const SESSION_COOKIE: &str = "__Host-openmettle-session";
/// Implementation ceilings applied to raw bytes before any decoding; not deployment values.
/// The query ceiling admits a maximal code, issuer and state with every byte percent-encoded.
pub const MAX_QUERY_BYTES: usize = 32 * 1024;
/// Parameters in one query, recognized or not.
pub const MAX_QUERY_PARAMETERS: usize = 32;
/// Total bytes of every `Cookie` field value on one request.
pub const MAX_COOKIE_BYTES: usize = 16 * 1024;
const COOKIE_ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Lax";

/// Host-only (`__Host-`, no `Domain`) and gone with the login it names.
fn caller_cookie(locator: &str, caller_secret: &str, login_seconds: u64) -> String {
    format!(
        "{LOGIN_COOKIE}={locator}.{caller_secret}; Max-Age={login_seconds}; {COOKIE_ATTRIBUTES}"
    )
}
/// No `Max-Age` or `Expires`: expiry in the primary database is authoritative (ADR 0013).
fn session_cookie(credential: &str) -> String {
    format!("{SESSION_COOKIE}={credential}; {COOKIE_ATTRIBUTES}")
}

/// Explicit adapter settings. None has a default and none is taken from a request.
pub struct Settings<'a> {
    /// The application origin exactly as browsers serialize it in `Origin`: `https`, a
    /// lowercase ASCII host, a port only when it is not 443, and nothing after it.
    pub origin: &'a str,
    /// Absolute path on that origin that a completed login redirects to.
    pub landing: &'a str,
    /// The configured provider UUID this adapter serves.
    pub provider: &'a str,
}

/// Fixed refusals of [`Settings`]. No variant carries a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    Origin,
    Landing,
    /// Not an exactly configured, active provider UUID.
    Provider,
    /// The provider's registered callback is not a plain path on the application origin.
    Callback,
}
impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Origin => "application origin is not a canonical HTTPS origin",
            Self::Landing => "landing is not a plain absolute path",
            Self::Provider => "provider is not configured",
            Self::Callback => "registered callback is not a plain path on the application origin",
        })
    }
}
impl std::error::Error for SettingsError {}

/// A fixed status and line. No request, provider or database value reaches a response.
#[derive(Clone, Copy)]
enum Refusal {
    Origin,
    Path,
    /// The authorization response is malformed, repeated, incomplete, from another issuer
    /// or a provider error.
    Response,
    /// The caller cookie is absent, repeated, malformed or bound to another login.
    Binding,
    Denied,
    Unavailable,
}
impl Refusal {
    fn response(self) -> Response<&'static str> {
        let (status, line) = match self {
            Self::Origin => (StatusCode::FORBIDDEN, "login origin refused\n"),
            Self::Path => (StatusCode::NOT_FOUND, "not found\n"),
            Self::Response => (
                StatusCode::BAD_REQUEST,
                "login response refused; restart login\n",
            ),
            Self::Binding => (
                StatusCode::BAD_REQUEST,
                "login browser binding missing or superseded; restart login\n",
            ),
            Self::Denied => (StatusCode::FORBIDDEN, "login denied\n"),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "login unavailable; restart login\n",
            ),
        };
        respond(status, line)
    }
}
/// Every handoff response: never stored, never a referrer source.
fn respond(status: StatusCode, line: &'static str) -> Response<&'static str> {
    let mut response = Response::new(line);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if !line.is_empty() {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    response
}
fn wrong_method(allow: &'static str) -> Response<&'static str> {
    let mut response = respond(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}
/// `303` with one cookie. Both header values are marked sensitive: they stay out of `Debug`
/// output, and an HTTP/2 encoder that honors the mark does not index them.
fn redirect(location: &str, cookie: &str) -> Response<&'static str> {
    let sensitive = |value: &str| {
        let mut value = HeaderValue::from_str(value).ok()?;
        value.set_sensitive(true);
        Some(value)
    };
    let (Some(location), Some(cookie)) = (sensitive(location), sensitive(cookie)) else {
        return Refusal::Unavailable.response();
    };
    let mut response = respond(StatusCode::SEE_OTHER, "");
    response.headers_mut().insert(header::LOCATION, location);
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response
}
// Exhaustive, so a new service category must be classified before the crate compiles.
fn completion_refusal(error: Error) -> Refusal {
    use login::Error as L;
    use sessions::Error as S;
    match error {
        // The transaction, the provider's assertion or the local approval said no.
        Error::Login(L::Rejected | L::Verification) | Error::Session(S::Rejected) => {
            Refusal::Denied
        }
        Error::Login(
            L::Configuration
            | L::Random
            | L::Database
            | L::Protection
            | L::Exchange
            | L::Capacity
            | L::Unconfigured,
        )
        | Error::Session(S::Configuration | S::Capacity | S::Random | S::Database | S::Timeout) => {
            Refusal::Unavailable
        }
    }
}

/// `https://host[:port]` in the ASCII serialization browsers send, and nothing else.
fn canonical_origin(value: &str) -> bool {
    Url::parse(value)
        .is_ok_and(|url| url.scheme() == "https" && url.origin().ascii_serialization() == value)
}
/// `path` is absolute and is exactly what a browser requests for `url`: no query, fragment,
/// dot segment or rewritten character.
fn plain_path(url: &str, path: &str) -> bool {
    path.starts_with('/')
        && Url::parse(url).is_ok_and(|url| {
            url.path() == path && url.query().is_none() && url.fragment().is_none()
        })
}
/// Two 43-character base64url tokens joined by a dot: `state` and the caller cookie value.
fn token_pair(value: &str) -> Option<(&str, &str)> {
    let (first, second) = value.split_once('.')?;
    let token = |part: &str| {
        part.len() == 43
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    };
    (token(first) && token(second)).then_some((first, second))
}
/// One strict `application/x-www-form-urlencoded` component: visible ASCII only, `+` is a
/// space, every `%` starts two hexadecimal digits and the decoded bytes are UTF-8.
fn decode(raw: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                (high * 16 + low) as u8
            }
            byte if byte.is_ascii_graphic() => byte,
            _ => return None,
        });
    }
    String::from_utf8(decoded).ok()
}

/// A complete authorization success response, still untrusted.
struct Authorization {
    code: String,
    state: String,
    issuer: String,
}
/// `None` unless the query is one well-formed success response: bounded before decoding, no
/// decoded name twice (RFC 6749 §3.1), no error member, and `code`, `state` and `iss` present.
/// Other well-formed parameters are ignored.
fn authorization(query: &str) -> Option<Authorization> {
    if query.len() > MAX_QUERY_BYTES
        || query.bytes().filter(|b| *b == b'&').count() >= MAX_QUERY_PARAMETERS
    {
        return None;
    }
    let mut names: Vec<String> = Vec::new();
    let (mut code, mut state, mut issuer) = (None, None, None);
    for parameter in query.split('&') {
        let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        let name = decode(name).filter(|name| !name.is_empty())?;
        let value = decode(value)?;
        if names.contains(&name) {
            return None;
        }
        match name.as_str() {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "iss" => issuer = Some(value),
            // A provider error, or error detail beside a code. Never reflected or exchanged.
            "error" | "error_description" | "error_uri" => return None,
            _ => {}
        }
        names.push(name);
    }
    Some(Authorization {
        code: code?,
        state: state?,
        issuer: issuer?,
    })
}
/// The caller cookie's value when it occurs exactly once across every `Cookie` field and
/// those fields are within [`MAX_COOKIE_BYTES`].
fn login_cookie(headers: &HeaderMap) -> Option<&str> {
    let fields = || headers.get_all(header::COOKIE).iter();
    if fields().map(HeaderValue::len).sum::<usize>() > MAX_COOKIE_BYTES {
        return None;
    }
    let mut found = None;
    for field in fields() {
        for pair in field.as_bytes().split(|b| *b == b';') {
            let value = pair
                .trim_ascii()
                .strip_prefix(LOGIN_COOKIE.as_bytes())
                .and_then(|rest| rest.strip_prefix(b"="));
            if let Some(value) = value
                && found.replace(value).is_some()
            {
                return None;
            }
        }
    }
    std::str::from_utf8(found?).ok()
}

/// The handoff for one configured provider at one application origin.
pub struct LoginHandoff {
    auth: Arc<BrowserAuth>,
    provider: String,
    origin: String,
    issuer: String,
    /// The exact registered callback; its path is everything after the origin.
    callback: String,
    /// `origin` followed by the landing path.
    landing: String,
    login_seconds: u64,
}
impl fmt::Debug for LoginHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginHandoff(..)")
    }
}
impl LoginHandoff {
    /// Validates the settings against the service's configuration. The issuer and the exact
    /// callback come from the provider registered under that UUID, never from a request.
    pub fn new(auth: Arc<BrowserAuth>, settings: Settings<'_>) -> Result<Self, SettingsError> {
        let Settings {
            origin,
            landing,
            provider,
        } = settings;
        if !canonical_origin(origin) {
            return Err(SettingsError::Origin);
        }
        let landing_url = format!("{origin}{landing}");
        if landing.starts_with("//")
            || !landing
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
            || !plain_path(&landing_url, landing)
        {
            return Err(SettingsError::Landing);
        }
        let registered = auth
            .provider(provider)
            .map_err(|_| SettingsError::Provider)?;
        let callback = registered.callback().map_err(|_| SettingsError::Provider)?;
        if !callback
            .strip_prefix(origin)
            .is_some_and(|path| plain_path(&callback, path))
        {
            return Err(SettingsError::Callback);
        }
        Ok(Self {
            provider: provider.to_owned(),
            origin: origin.to_owned(),
            issuer: registered.issuer().to_owned(),
            callback,
            landing: landing_url,
            login_seconds: auth.config.login_lifetime().as_secs(),
            auth,
        })
    }

    /// Starts a login. Method and `Origin` are decided before the service is called; the
    /// path, query and body are not read. The `Location` is exactly the authorization URL
    /// returned by [`BrowserAuth::begin`].
    pub async fn initiate(&self, request: &Parts) -> Response<&'static str> {
        if request.method != Method::POST {
            return wrong_method("POST");
        }
        // Exactly one field with exactly the configured bytes: `null`, a list, another
        // scheme, host or port and a repeated field all fail here.
        let mut origins = request.headers.get_all(header::ORIGIN).iter();
        if !matches!(
            (origins.next(), origins.next()),
            (Some(origin), None) if origin.as_bytes() == self.origin.as_bytes()
        ) {
            return Refusal::Origin.response();
        }
        let Ok(started) = self.auth.begin(&self.provider).await else {
            return Refusal::Unavailable.response();
        };
        let Some((locator, _)) = started.state.expose().split_once('.') else {
            return Refusal::Unavailable.response();
        };
        redirect(
            started.authorization_url.expose(),
            &caller_cookie(locator, started.caller_binding.expose(), self.login_seconds),
        )
    }

    /// Completes a login. Path, method, the authorization response, its issuer and the
    /// caller cookie's locator are decided before [`BrowserAuth::complete`] is called once.
    /// Only its acknowledged, freshly validated credential sets the session cookie; no
    /// refusal sets or deletes any cookie.
    pub async fn callback(&self, request: &Parts) -> Response<&'static str> {
        let registered_path = &self.callback[self.origin.len()..];
        if request.uri.path() != registered_path {
            return Refusal::Path.response();
        }
        if request.method != Method::GET {
            return wrong_method("GET");
        }
        let Some(response) = authorization(request.uri.query().unwrap_or_default()) else {
            return Refusal::Response.response();
        };
        let Authorization {
            code,
            state,
            issuer,
        } = &response;
        let code_is_safe = !code.is_empty()
            && code.len() <= login::MAX_CODE_BYTES
            && code.bytes().all(|b| b.is_ascii_graphic());
        let locator = match token_pair(state) {
            Some((locator, _)) if code_is_safe && *issuer == self.issuer => locator,
            _ => return Refusal::Response.response(),
        };
        // The cookie names the login it belongs to, so a cookie from a later initiation
        // refuses an earlier login's callback here, without consuming either.
        let Some((bound, caller_binding)) = login_cookie(&request.headers).and_then(token_pair)
        else {
            return Refusal::Binding.response();
        };
        if bound != locator {
            return Refusal::Binding.response();
        }
        let callback = login::Callback {
            state,
            caller_binding,
            issuer,
            callback: &self.callback,
            code,
        };
        match self.auth.complete(&self.provider, callback).await {
            Ok(credential) => redirect(&self.landing, &session_cookie(credential.expose())),
            Err(error) => completion_refusal(error).response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No login can start without PostgreSQL, so the two success responses are checked
    /// through the builders the entry points use. The managed PostgreSQL test (ADR 0017)
    /// checks the same properties end to end.
    #[test]
    fn redirects_carry_one_protected_cookie_and_stay_out_of_debug_output() {
        let (locator, caller) = ("L".repeat(43), "c".repeat(43));
        let authorization = format!("https://issuer.example.test/authorize?state={locator}.s");
        let credential = format!("{}.{}", "i".repeat(43), "k".repeat(43));
        for (location, cookie, expected) in [
            (
                authorization.as_str(),
                caller_cookie(&locator, &caller, 300),
                format!(
                    "__Host-openmettle-login={locator}.{caller}; Max-Age=300; Path=/; Secure; HttpOnly; SameSite=Lax"
                ),
            ),
            (
                "https://app.example.test/app",
                session_cookie(&credential),
                format!(
                    "__Host-openmettle-session={credential}; Path=/; Secure; HttpOnly; SameSite=Lax"
                ),
            ),
        ] {
            let response = redirect(location, &cookie);
            assert_eq!(
                (response.status(), *response.body()),
                (StatusCode::SEE_OTHER, "")
            );
            let headers = response.headers();
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
            assert_eq!(headers.len(), 4);
            for (name, value) in [
                (header::LOCATION, location),
                (header::SET_COOKIE, expected.as_str()),
            ] {
                let mut values = headers.get_all(&name).iter();
                let only = values.next().unwrap();
                assert!(values.next().is_none(), "{name} repeated");
                assert_eq!(only, value);
                assert!(only.is_sensitive(), "{name} not sensitive");
            }
            let debug = format!("{response:?}");
            for secret in [&locator[..], &caller, &credential, "app.example.test"] {
                assert!(!debug.contains(secret));
            }
        }
        // A value that cannot be a header never becomes a partial redirect.
        let broken = redirect("https://app.example.test/app", "name=line\nbreak");
        assert_eq!(broken.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!broken.headers().contains_key(header::LOCATION));
        assert!(!broken.headers().contains_key(header::SET_COOKIE));
    }

    #[test]
    fn service_errors_map_to_two_fixed_lines() {
        use login::Error as L;
        use sessions::Error as S;
        let line = |error| {
            let response = completion_refusal(error).response();
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            (response.status(), *response.body())
        };
        for denied in [
            Error::Login(L::Rejected),
            Error::Login(L::Verification),
            Error::Session(S::Rejected),
        ] {
            assert_eq!(
                line(denied),
                (StatusCode::FORBIDDEN, "login denied\n"),
                "{denied:?}"
            );
        }
        for unavailable in [
            Error::Login(L::Configuration),
            Error::Login(L::Random),
            Error::Login(L::Database),
            Error::Login(L::Protection),
            Error::Login(L::Exchange),
            Error::Login(L::Capacity),
            Error::Login(L::Unconfigured),
            Error::Session(S::Configuration),
            Error::Session(S::Capacity),
            Error::Session(S::Random),
            Error::Session(S::Database),
            Error::Session(S::Timeout),
        ] {
            assert_eq!(
                line(unavailable),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "login unavailable; restart login\n"
                ),
                "{unavailable:?}"
            );
        }
    }
}
