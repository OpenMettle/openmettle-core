//! Same-origin browser login handoff over [`BrowserAuth`] (ADR 0017), with session checks and
//! local logout (ADR 0019).
//!
//! **Not mounted.** No listener or running process constructs this adapter; the unmounted
//! [`super::router`] composes it (ADRs 0018 and 0019). It turns one HTTP request head into one
//! response:
//!
//! - [`LoginHandoff::initiate`]: a top-level form `POST` whose single `Origin` equals the
//!   configured application origin becomes a `303` to the provider with the caller cookie.
//!   Its form may carry one `invitation_code` field for a first sign-in (ADR 0022).
//! - [`LoginHandoff::callback`]: a top-level `GET` on the exact registered callback path
//!   becomes a `303` to the configured landing with the session cookie.
//! - [`LoginHandoff::session`]: a same-origin `GET` with one valid session cookie becomes
//!   an empty `204`.
//! - [`LoginHandoff::logout`]: a form `POST` with the initiation `Origin` rule and one
//!   well-formed session cookie becomes a `204` that deletes the session cookie, only after
//!   the revocation commit is acknowledged.
//!
//! Anything else is a fixed refusal. The adapter reads no `Host`, forwarded header or return
//! URL, no request body except the initiation form, and logs nothing. Only an acknowledged
//! logout deletes a cookie.
use super::{BrowserAuth, Error};
use crate::{invitation::InvitationCode, login, provider_keys::ManagedProvider, sessions};
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
/// Bytes of the initiation form body. Room for the one field with a maximal code and every
/// byte of it percent-encoded.
pub const MAX_FORM_BYTES: usize = 256;
/// The one field an initiation form may carry (ADR 0022).
pub const INVITATION_FIELD: &str = "invitation_code";
const COOKIE_ATTRIBUTES: &str = "Path=/; Secure; HttpOnly; SameSite=Lax";
/// Deletes the session cookie: the same name and attributes, an empty value and `Max-Age=0`.
/// It names no credential, so it is the same for every browser.
const SESSION_DELETION: &str =
    "__Host-openmettle-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax";

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
    /// The initiation form has an unknown, repeated or malformed field, or a malformed code.
    Form,
    Path,
    /// The authorization response is malformed, repeated, incomplete, from another issuer
    /// or a provider error.
    Response,
    /// The caller cookie is absent, repeated, malformed or bound to another login.
    Binding,
    CompletionRejected,
    Unavailable,
    /// Logout `Origin` rule, the same rule as initiation.
    LogoutOrigin,
    /// Session check without exactly one `Sec-Fetch-Site: same-origin` field.
    SessionOrigin,
    /// The session cookie is absent, repeated or malformed, or its credential is unknown,
    /// revoked, expired or no longer eligible.
    SessionInvalid,
    /// Validation or logout failed or its outcome is uncertain.
    SessionUnavailable,
}
impl Refusal {
    fn response(self) -> Response<&'static str> {
        let (status, line) = match self {
            Self::Origin => (StatusCode::FORBIDDEN, "login origin refused\n"),
            Self::Form => (StatusCode::BAD_REQUEST, "login request refused\n"),
            Self::Path => (StatusCode::NOT_FOUND, "not found\n"),
            Self::Response => (
                StatusCode::BAD_REQUEST,
                "login response refused; restart login\n",
            ),
            Self::Binding => (
                StatusCode::BAD_REQUEST,
                "login browser binding missing or superseded; restart login\n",
            ),
            Self::CompletionRejected => {
                (StatusCode::FORBIDDEN, "login refused. Start a new login.\n")
            }
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "login unavailable; restart login\n",
            ),
            Self::LogoutOrigin => (StatusCode::FORBIDDEN, "logout origin refused\n"),
            Self::SessionOrigin => (StatusCode::FORBIDDEN, "session origin refused\n"),
            Self::SessionInvalid => (StatusCode::FORBIDDEN, "session not valid\n"),
            Self::SessionUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "session unavailable; try again later\n",
            ),
        };
        respond(status, line)
    }
}
/// Every handoff response: never stored, never a referrer source. The router reuses it.
pub(super) fn respond(status: StatusCode, line: &'static str) -> Response<&'static str> {
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
pub(super) fn wrong_method(allow: &'static str) -> Response<&'static str> {
    let mut response = respond(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n");
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}
/// `303` with one cookie. Both header values are marked sensitive: they stay out of `Debug`
/// output, and an HTTP/2 encoder that honors the mark does not index them.
pub(super) fn redirect(location: &str, cookie: &str) -> Response<&'static str> {
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
pub(super) fn login_failure(error: Error) -> Response<&'static str> {
    use login::Error as L;
    use sessions::Error as S;
    match error {
        // The consume phase also reports provider preflight, admission and deadline
        // failures as Rejected. Use one neutral message for these outcomes.
        Error::Login(L::Rejected | L::Verification) | Error::Session(S::Rejected) => {
            Refusal::CompletionRejected
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
    .response()
}

/// Validation and logout outcomes. Exhaustive, like [`login_failure`]. Only a credential
/// the database refused is `SessionInvalid`; every other category, including the login
/// categories these operations never return, is an operational failure.
fn session_refusal(error: Error) -> Refusal {
    use login::Error as L;
    use sessions::Error as S;
    match error {
        Error::Session(S::Rejected) => Refusal::SessionInvalid,
        Error::Session(S::Configuration | S::Capacity | S::Random | S::Database | S::Timeout)
        | Error::Login(
            L::Configuration
            | L::Random
            | L::Rejected
            | L::Database
            | L::Protection
            | L::Exchange
            | L::Verification
            | L::Capacity
            | L::Unconfigured,
        ) => Refusal::SessionUnavailable,
    }
}
/// `204` after an acknowledged revocation, with the one session-cookie deletion.
fn logged_out() -> Response<&'static str> {
    let mut response = respond(StatusCode::NO_CONTENT, "");
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(SESSION_DELETION),
    );
    response
}

/// `https://host[:port]` in the ASCII serialization browsers send, and nothing else.
pub(super) fn canonical_origin(value: &str) -> bool {
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
pub(super) fn token_pair(value: &str) -> Option<(&str, &str)> {
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
pub(super) fn decode(raw: &str) -> Option<String> {
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
pub(super) struct Authorization {
    pub(super) code: String,
    pub(super) state: String,
    pub(super) issuer: String,
}
/// `None` unless the query is one well-formed success response: bounded before decoding, no
/// decoded name twice (RFC 6749 §3.1), no error member, and `code`, `state` and `iss` present.
/// Other well-formed parameters are ignored.
pub(super) fn authorization(query: &str) -> Option<Authorization> {
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
/// The invitation code in an initiation form. The outer `None` refuses the form. An empty
/// body and an empty value both mean that no code was entered. Anything else must be exactly
/// one `invitation_code` field whose strictly decoded value is a well-formed code. Syntax
/// only: whether the code belongs to an invitation is decided at redemption, so a
/// well-formed wrong code and no code get the same response here.
pub(super) fn invitation(form: &[u8]) -> Option<Option<InvitationCode>> {
    if form.is_empty() {
        return Some(None);
    }
    if form.len() > MAX_FORM_BYTES {
        return None;
    }
    let (name, value) = std::str::from_utf8(form).ok()?.split_once('=')?;
    // One field only: a second `=` or any `&` is another or a malformed field.
    if value.contains(['=', '&']) || decode(name)? != INVITATION_FIELD {
        return None;
    }
    let value = decode(value)?;
    if value.is_empty() {
        return Some(None);
    }
    InvitationCode::parse(&value).map(Some)
}
/// The value of cookie `name` when it occurs exactly once across every `Cookie` field and
/// those fields are within [`MAX_COOKIE_BYTES`]. Names compare exactly.
pub(super) fn single_cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let fields = || headers.get_all(header::COOKIE).iter();
    if fields().map(HeaderValue::len).sum::<usize>() > MAX_COOKIE_BYTES {
        return None;
    }
    let mut found = None;
    for field in fields() {
        for pair in field.as_bytes().split(|b| *b == b';') {
            let value = pair
                .trim_ascii()
                .strip_prefix(name.as_bytes())
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
/// The caller cookie, found by the rule above.
fn login_cookie(headers: &HeaderMap) -> Option<&str> {
    single_cookie(headers, LOGIN_COOKIE)
}
/// The session cookie's value, found by the same rule. [`BrowserAuth::validate`] and
/// [`BrowserAuth::logout`] apply the session parser before requesting a pooled connection.
fn session_credential(headers: &HeaderMap) -> Option<&str> {
    single_cookie(headers, SESSION_COOKIE)
}

/// The handoff for one configured provider at one application origin.
pub struct LoginHandoff {
    auth: Arc<BrowserAuth>,
    settings: Checked,
    login_seconds: u64,
}
impl fmt::Debug for LoginHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginHandoff(..)")
    }
}
/// [`Settings`] that passed [`check`], with the provider's issuer and exact callback.
pub(crate) struct Checked {
    provider: String,
    origin: String,
    issuer: String,
    /// The exact registered callback; its path is everything after the origin.
    callback: String,
    /// `origin` followed by the landing path.
    landing: String,
}
impl Checked {
    /// The registered callback's path: everything after the application origin.
    pub(crate) fn callback_path(&self) -> &str {
        &self.callback[self.origin.len()..]
    }
}

/// Every settings check of [`LoginHandoff::new`], against the configured providers alone. It
/// needs no service, pool, runtime or network, so the offline configuration check (ADR 0020)
/// runs the same rules. The issuer and the exact callback come from the provider registered
/// under that UUID, never from a request.
pub(crate) fn check(
    providers: &[ManagedProvider],
    settings: Settings<'_>,
) -> Result<Checked, SettingsError> {
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
    let registered = super::configured(providers, provider).ok_or(SettingsError::Provider)?;
    let callback = registered.callback().map_err(|_| SettingsError::Provider)?;
    if !callback
        .strip_prefix(origin)
        .is_some_and(|path| plain_path(&callback, path))
    {
        return Err(SettingsError::Callback);
    }
    Ok(Checked {
        provider: provider.to_owned(),
        origin: origin.to_owned(),
        issuer: registered.issuer().to_owned(),
        callback,
        landing: landing_url,
    })
}

impl LoginHandoff {
    /// Validates the settings against the service's configuration using the offline checks.
    pub fn new(auth: Arc<BrowserAuth>, settings: Settings<'_>) -> Result<Self, SettingsError> {
        Ok(Self {
            settings: check(auth.config.providers(), settings)?,
            login_seconds: auth.config.login_lifetime().as_secs(),
            auth,
        })
    }

    /// The registered callback's path: everything after the application origin.
    pub(super) fn callback_path(&self) -> &str {
        self.settings.callback_path()
    }
    /// Exactly one field with exactly the configured bytes: `null`, a list, another scheme,
    /// host or port and a repeated field all fail. Initiation and logout share this rule.
    fn same_origin(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        matches!(
            (origins.next(), origins.next()),
            (Some(origin), None) if origin.as_bytes() == self.settings.origin.as_bytes()
        )
    }

    /// Starts a login. Method, `Origin` and then the form are decided before the service is
    /// called; the path and query are not read. `form` is the request body, which the
    /// caller has already bounded: empty, or one `invitation_code` field (ADR 0022). The
    /// `Location` is exactly the authorization URL returned by [`BrowserAuth::begin`], and
    /// the response is the same with or without a code.
    pub async fn initiate(&self, request: &Parts, form: &[u8]) -> Response<&'static str> {
        if request.method != Method::POST {
            return wrong_method("POST");
        }
        if !self.same_origin(&request.headers) {
            return Refusal::Origin.response();
        }
        let Some(invitation) = invitation(form) else {
            return Refusal::Form.response();
        };
        let Ok(started) = self.auth.begin(&self.settings.provider, invitation).await else {
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
        if request.uri.path() != self.callback_path() {
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
            Some((locator, _)) if code_is_safe && *issuer == self.settings.issuer => locator,
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
            callback: &self.settings.callback,
            code,
        };
        match self.auth.complete(&self.settings.provider, callback).await {
            Ok(credential) => {
                redirect(&self.settings.landing, &session_cookie(credential.expose()))
            }
            Err(error) => login_failure(error),
        }
    }

    /// Session check. Require exactly one `Sec-Fetch-Site: same-origin` before reading the
    /// session cookie. [`BrowserAuth::validate`] refuses a malformed credential before checkout.
    /// A valid session gets an empty `204` with no identity, permission, credential, cookie
    /// or redirect.
    pub async fn session(&self, request: &Parts) -> Response<&'static str> {
        if request.method != Method::GET {
            return wrong_method("GET");
        }
        let mut sites = request.headers.get_all("sec-fetch-site").iter();
        if !matches!(
            (sites.next(), sites.next()),
            (Some(site), None) if site.as_bytes() == b"same-origin"
        ) {
            return Refusal::SessionOrigin.response();
        }
        let Some(credential) = session_credential(&request.headers) else {
            return Refusal::SessionInvalid.response();
        };
        match self.auth.validate(credential).await {
            // The context is dropped unread.
            Ok(_) => respond(StatusCode::NO_CONTENT, ""),
            Err(error) => session_refusal(error).response(),
        }
    }

    /// Local logout of the presented session. The `Origin` rule is decided before any cookie
    /// is read, and the single session cookie before [`BrowserAuth::logout`] is called once;
    /// its parser refuses a malformed credential before any checkout. No eligibility check
    /// precedes it: possession revokes an issued session after expiry, disablement or lost
    /// approval. Only an acknowledged commit returns `204` with
    /// the session-cookie deletion; every refusal or uncertain outcome deletes nothing.
    /// Other sessions of the same user are not revoked, and the caller cookie is untouched.
    pub async fn logout(&self, request: &Parts) -> Response<&'static str> {
        if request.method != Method::POST {
            return wrong_method("POST");
        }
        if !self.same_origin(&request.headers) {
            return Refusal::LogoutOrigin.response();
        }
        let Some(credential) = session_credential(&request.headers) else {
            return Refusal::SessionInvalid.response();
        };
        match self.auth.logout(credential).await {
            Ok(()) => logged_out(),
            Err(error) => session_refusal(error).response(),
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

    const CODE: &str = "omh1-0123-4567-89ab-cdef-fedc-ba98-7654-3210";
    const CODE_BYTES: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    fn percent_encoded(value: &str) -> String {
        value.bytes().map(|b| format!("%{b:02X}")).collect()
    }

    #[test]
    fn initiation_form_is_empty_or_exactly_one_invitation_code_field() {
        // No code: an empty body, as a form without the field sends, or an empty value.
        for form in ["", "invitation_code=", "%69nvitation_code="] {
            assert!(matches!(invitation(form.as_bytes()), Some(None)), "{form}");
        }
        // One code, in every form a browser can send what the person typed or pasted.
        let longest = format!(
            "invitation_code={}",
            percent_encoded(&format!("{CODE:<64}"))
        );
        assert!(longest.len() <= MAX_FORM_BYTES);
        for form in [
            format!("invitation_code={CODE}"),
            format!("invitation_code={}", CODE.to_ascii_uppercase()),
            format!("invitation_code={}", CODE.replace('-', "+")),
            format!("invitation_code={}", CODE.replace('-', "%20")),
            format!(
                "invitation_code=+{}+",
                &CODE.replace('-', "")["omh1".len()..]
            ),
            format!("invitation_code={}", percent_encoded(CODE)),
            format!("{}={CODE}", percent_encoded(INVITATION_FIELD)),
            longest,
        ] {
            let code = invitation(form.as_bytes())
                .flatten()
                .expect("accepted form");
            assert_eq!(code.bytes(), &CODE_BYTES);
        }
    }

    #[test]
    fn initiation_form_with_any_other_content_is_refused() {
        let hex = &CODE.replace('-', "")["omh1".len()..];
        let oversized = format!("invitation_code={}", "+".repeat(MAX_FORM_BYTES));
        let refused: Vec<Vec<u8>> = [
            // Another field, alone, before or after the code, and the field twice.
            "x=1".to_owned(),
            format!("code={CODE}"),
            format!("Invitation_Code={CODE}"),
            format!("invitation_code2={CODE}"),
            format!("x=1&invitation_code={CODE}"),
            format!("invitation_code={CODE}&x=1"),
            format!("invitation_code={CODE}&invitation_code={CODE}"),
            "invitation_code=&invitation_code=".to_owned(),
            // Not one `name=value` pair.
            "invitation_code".to_owned(),
            "=".to_owned(),
            format!("={CODE}"),
            format!("invitation_code={CODE}&"),
            format!("&invitation_code={CODE}"),
            format!("invitation_code=={CODE}"),
            format!("invitation_code={CODE}="),
            // Malformed escapes, and bytes a form never sends unescaped.
            "invitation_code=%zz".to_owned(),
            "invitation_code=%2".to_owned(),
            "invitation_code=%".to_owned(),
            format!("invitation_code={CODE}\r\n"),
            format!("invitation_code={CODE} "),
            format!("invitation_code={}", CODE.replace('-', " ")),
            // A malformed code: wrong length, not hexadecimal, only separators, not ASCII,
            // and more than 64 bytes once decoded.
            format!("invitation_code={}", &hex[..31]),
            format!("invitation_code={hex}0"),
            format!("invitation_code={}g", &hex[..31]),
            "invitation_code=+".to_owned(),
            "invitation_code=-".to_owned(),
            format!("invitation_code={}%C3%A9", &hex[..31]),
            format!("invitation_code={CODE}{}", "+".repeat(65 - CODE.len())),
            oversized,
        ]
        .into_iter()
        .map(String::into_bytes)
        // Bytes that are not UTF-8, raw and percent-encoded.
        .chain([
            b"invitation_code=\xff".to_vec(),
            b"\xffinvitation_code=".to_vec(),
        ])
        .chain(["invitation_code=%FF".as_bytes().to_vec()])
        .collect();
        for form in &refused {
            assert!(
                invitation(form).is_none(),
                "accepted {:?}",
                String::from_utf8_lossy(form)
            );
        }
        // Controls: each refusal above is one change away from an accepted form.
        assert!(invitation(format!("invitation_code={CODE}").as_bytes()).is_some());
        let padded = format!("invitation_code={CODE}{}", "+".repeat(64 - CODE.len()));
        assert!(invitation(padded.as_bytes()).is_some());

        // One fixed refusal, whatever was wrong, with no cookie and no redirect.
        let response = Refusal::Form.response();
        assert_eq!(
            (response.status(), *response.body()),
            (StatusCode::BAD_REQUEST, "login request refused\n")
        );
        let headers = response.headers();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert!(!headers.contains_key(header::SET_COOKIE));
        assert!(!headers.contains_key(header::LOCATION));
    }

    #[test]
    fn logout_deletes_only_the_session_cookie_with_matching_attributes() {
        assert_eq!(
            SESSION_DELETION,
            format!("{SESSION_COOKIE}=; Max-Age=0; {COOKIE_ATTRIBUTES}")
        );
        let response = logged_out();
        assert_eq!(
            (response.status(), *response.body()),
            (StatusCode::NO_CONTENT, "")
        );
        let headers = response.headers();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert!(!headers.contains_key(header::LOCATION));
        assert!(!headers.contains_key(header::CONTENT_TYPE));
        let cookies: Vec<_> = headers.get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(cookies, [SESSION_DELETION]);
        assert_eq!(headers.len(), 3);
    }

    #[test]
    fn session_errors_map_to_one_refusal_and_one_failure() {
        use login::Error as L;
        use sessions::Error as S;
        let line = |error| {
            let response = session_refusal(error).response();
            let headers = response.headers();
            assert!(!headers.contains_key(header::SET_COOKIE));
            assert!(!headers.contains_key(header::LOCATION));
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
            (response.status(), *response.body())
        };
        assert_eq!(
            line(Error::Session(S::Rejected)),
            (StatusCode::FORBIDDEN, "session not valid\n")
        );
        for failure in [
            Error::Session(S::Configuration),
            Error::Session(S::Capacity),
            Error::Session(S::Random),
            Error::Session(S::Database),
            Error::Session(S::Timeout),
            Error::Login(L::Configuration),
            Error::Login(L::Random),
            Error::Login(L::Rejected),
            Error::Login(L::Database),
            Error::Login(L::Protection),
            Error::Login(L::Exchange),
            Error::Login(L::Verification),
            Error::Login(L::Capacity),
            Error::Login(L::Unconfigured),
        ] {
            assert_eq!(
                line(failure),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "session unavailable; try again later\n"
                ),
                "{failure:?}"
            );
        }
    }

    /// The session cookie is found by the caller-cookie rule, which still finds the caller
    /// cookie. Credential shape is the session parser's decision, inside the service.
    #[test]
    fn session_credential_is_one_exactly_named_cookie() {
        let valid = format!("{}.{}", "A".repeat(43), "A".repeat(43));
        let headers = |fields: &[&str]| {
            let mut headers = HeaderMap::new();
            for field in fields {
                headers.append(header::COOKIE, HeaderValue::from_str(field).unwrap());
            }
            headers
        };
        let session = format!("{SESSION_COOKIE}={valid}");
        let caller = format!("{LOGIN_COOKIE}={valid}");
        for fields in [
            vec![session.as_str()],
            vec!["theme=dark", session.as_str(), caller.as_str()],
            vec![format!("a=1; {session}; b=2").as_str()],
        ] {
            let headers = headers(&fields);
            assert_eq!(session_credential(&headers), Some(valid.as_str()));
            if fields.len() == 3 {
                assert_eq!(login_cookie(&headers), Some(valid.as_str()));
            }
        }
        let oversized = format!("{session}; pad={}", "p".repeat(MAX_COOKIE_BYTES));
        for fields in [
            vec![],
            vec!["theme=dark"],
            vec![caller.as_str()],
            vec![format!("{session}; {session}").as_str()],
            vec![session.as_str(), session.as_str()],
            vec![format!("{SESSION_COOKIE}2={valid}").as_str()],
            vec![format!("__host-openmettle-session={valid}").as_str()],
            vec![oversized.as_str()],
        ] {
            assert_eq!(session_credential(&headers(&fields)), None, "{fields:?}");
        }
    }

    #[test]
    fn service_errors_map_to_two_fixed_lines() {
        use login::Error as L;
        use sessions::Error as S;
        let line = |error| {
            let response = login_failure(error);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            (response.status(), *response.body())
        };
        for rejected in [
            Error::Login(L::Rejected),
            Error::Login(L::Verification),
            Error::Session(S::Rejected),
        ] {
            assert_eq!(
                line(rejected),
                (StatusCode::FORBIDDEN, "login refused. Start a new login.\n"),
                "{rejected:?}"
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
