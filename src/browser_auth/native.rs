//! API-brokered native login (ADR 0023). The app supplies its own S256 challenge. The API
//! mounts it beside the browser routes when the version-2 settings name a `native` profile
//! (ADR 0029); otherwise nothing constructs it.
//! The person confirms the sign-in in the system browser, where a first sign-in also enters
//! its invitation code (ADR 0022). The app never handles that code.
mod routes;
use super::{BrowserAuth, Checkout, handoff, path_byte, router::Rate, session_settled};
use crate::sessions::native::{self, Attempt};
use crate::{
    auth_config::BrowserProfile,
    provider_keys::ManagedProvider,
    sessions::{self, Channel, Credential, Error},
};
use axum::http::{Method, Response, StatusCode, header, request::Parts};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openidconnect::url::Url;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Semaphore;

const START: &str = "/auth/native/authorize";
const TOKEN: &str = "/auth/native/token";
const SESSION: &str = "/auth/native/session";
const LOGOUT: &str = "/auth/native/logout";
const COOKIE: &str = "__Host-openmettle-native-login";

fn token(value: &str) -> Option<[u8; 32]> {
    if value.len() != 43 {
        return None;
    }
    B64.decode(value).ok()?.try_into().ok()
}
fn hash(fields: &[&[u8]]) -> [u8; 32] {
    Sha256::digest(crate::runs::identity(
        b"openmettle/native-login/1\0",
        fields,
    ))
    .into()
}
/// Downstream session audience, separate from the pending-code registration. It names the
/// deployment issuer, native client, exact app link and the provider UUID and issuer. It
/// omits the provider configuration binding and upstream callback, so routine upstream
/// epoch and trust maintenance keep delivered sessions (ADR 0013). Replicas with the same
/// inputs share it. Version 1 of a domain-separated, length-prefixed SHA-256 digest.
fn audience(provider: &ManagedProvider, issuer: &str, client: &str, redirect: &Url) -> [u8; 32] {
    Sha256::digest(crate::runs::identity(
        b"openmettle/native-session-audience/1\0",
        &[
            issuer.as_bytes(),
            client.as_bytes(),
            redirect.as_str().as_bytes(),
            provider.id().as_bytes(),
            provider.issuer().as_bytes(),
        ],
    ))
    .into()
}
/// The confirmation page. Its form posts back to the same URL with one optional field, so the
/// button has no name: any other field is refused (ADR 0022).
const CONFIRMATION: &str = "<!doctype html><title>OpenMettle sign-in</title><form method=post><p><label>Invitation code, for a first sign-in only <input name=invitation_code autocomplete=off autocapitalize=none spellcheck=false maxlength=64></label><p><button id=confirm>Continue to sign in to the native app</button></form>";

pub struct NativeAuth {
    auth: Arc<BrowserAuth>,
    provider: ManagedProvider,
    issuer: String,
    client: String,
    callback: String,
    redirect: Url,
    registration: [u8; 32],
    audience: [u8; 32],
    /// The configured cap of `operations`, which also sizes the router's request slots.
    in_flight: usize,
    operations: Semaphore,
}
impl std::fmt::Debug for NativeAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeAuth(..)")
    }
}
/// Inputs of the app's back-channel HTTPS POST. No cookie participates.
pub struct Redemption<'a> {
    pub issuer: &'a str,
    pub client: &'a str,
    pub redirect: &'a str,
    pub code: &'a str,
    pub verifier: &'a str,
}

fn exact_link(value: &str) -> Option<Url> {
    if value.len() > 2048 {
        return None;
    }
    let url = Url::parse(value).ok()?;
    (url.scheme() == "https"
        && value == url.as_str()
        && url.username().is_empty()
        && url.password().is_none()
        && url.has_host()
        && value == format!("{}{}", url.origin().ascii_serialization(), url.path())
        && url.path().len() > 1
        && !url.path().starts_with("//")
        && url.path().bytes().all(path_byte))
    .then_some(url)
}
/// Largest native in-flight cap.
pub const MAX_IN_FLIGHT: u32 = 1024;

/// Explicit native deployment settings (ADRs 0023 and 0029). None has a default and none is
/// taken from a request. The route rate is supplied separately, to the check and the router.
#[derive(Clone, Copy)]
pub struct Settings<'a> {
    /// The configured provider UUID, matched exactly.
    pub provider: &'a str,
    /// The deployment issuer: a canonical HTTPS origin that serves the native routes.
    pub issuer: &'a str,
    /// The exact upstream callback, a plain path on the issuer origin.
    pub callback: &'a str,
    /// The native client identifier.
    pub client: &'a str,
    /// The exact app link that receives the code.
    pub redirect: &'a str,
    /// Native operations at once, and the router's request slots.
    pub max_in_flight: u32,
}
impl std::fmt::Debug for Settings<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeSettings(..)")
    }
}

/// Fixed refusals of [`Settings`] and the route rate, in the order [`check`] decides them.
/// No variant carries a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError {
    /// Not an exactly configured provider UUID, or its registration cannot be bound.
    Provider,
    Issuer,
    /// Not an exact HTTPS link with a plain path on the issuer origin.
    Callback,
    Client,
    Redirect,
    /// The callback path is not a plain literal route path.
    Route,
    /// A native route or the app link collides with an operational, browser or provider
    /// callback route.
    Collision,
    Rate,
    InFlight,
}
impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Provider => "native provider is not configured",
            Self::Issuer => "native issuer is not a canonical HTTPS origin",
            Self::Callback => "native callback is not a plain HTTPS path on the issuer origin",
            Self::Client => "native client identifier is not acceptable",
            Self::Redirect => "native app link is not a canonical HTTPS URL",
            Self::Route => "native callback path is not a plain literal path",
            Self::Collision => "native routes or app link collide with another route",
            Self::Rate => "native rate is outside its allowed range",
            Self::InFlight => "native in-flight cap is outside its allowed range",
        })
    }
}
impl std::error::Error for SettingsError {}

/// [`Settings`] that passed the check: the selected provider, the parsed app link and the
/// provider's configuration binding.
struct Checked<'a> {
    provider: &'a ManagedProvider,
    redirect: Url,
    binding: Vec<u8>,
}

/// Every settings check of [`NativeAuth::new`] and [`NativeAuth::router_shared`], against the
/// configured providers and the checked browser profile alone (ADR 0029). It needs no
/// service, pool, runtime, listener or network, so the offline configuration check runs the
/// same rules, in the order of [`SettingsError`].
pub(crate) fn check(
    providers: &[ManagedProvider],
    browser: Option<&BrowserProfile>,
    settings: Settings<'_>,
    rate: Rate,
) -> Result<(), SettingsError> {
    plan(providers, browser, settings, Some(rate)).map(drop)
}

/// The single implementation behind [`check`] and [`NativeAuth::new`], which has no rate.
fn plan<'a>(
    providers: &'a [ManagedProvider],
    browser: Option<&BrowserProfile>,
    settings: Settings<'_>,
    rate: Option<Rate>,
) -> Result<Checked<'a>, SettingsError> {
    let Settings {
        provider,
        issuer,
        callback,
        client,
        redirect,
        max_in_flight,
    } = settings;
    let provider = super::configured(providers, provider).ok_or(SettingsError::Provider)?;
    let binding = provider
        .registration_binding()
        .map_err(|_| SettingsError::Provider)?;
    if !handoff::canonical_origin(issuer) || issuer.len() > 2048 {
        return Err(SettingsError::Issuer);
    }
    let callback_url = exact_link(callback)
        .filter(|url| url.origin().ascii_serialization() == issuer)
        .ok_or(SettingsError::Callback)?;
    if client.is_empty()
        || client.len() > 128
        || !client
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    {
        return Err(SettingsError::Client);
    }
    let redirect = exact_link(redirect).ok_or(SettingsError::Redirect)?;
    let redirect_origin = redirect.origin().ascii_serialization();
    let routes = [START, TOKEN, SESSION, LOGOUT, callback_url.path()];
    super::router::check_paths(&routes).map_err(|error| match error {
        super::router::SettingsError::Collision => SettingsError::Collision,
        _ => SettingsError::Route,
    })?;
    // Operational routes and the application API under `/v1` (ADR 0027 PR4b).
    let core = super::router::reserved;
    // The app link never lands on a native, operational or API route of the issuer.
    if redirect_origin == issuer && (routes.contains(&redirect.path()) || core(redirect.path())) {
        return Err(SettingsError::Collision);
    }
    if let Some(profile) = browser {
        let browser_origin = profile.handoff().origin;
        let browser_paths = [
            profile.router().initiation,
            profile.sessions().session,
            profile.sessions().logout,
            profile.handoff().landing,
        ];
        // The native routes never shadow a browser route on a shared origin, and the app
        // link never lands on a browser or operational route of the browser origin,
        // whichever origin the native deployment itself uses.
        if (browser_origin == issuer && browser_paths.iter().any(|path| routes.contains(path)))
            || (redirect_origin == browser_origin
                && (browser_paths.contains(&redirect.path()) || core(redirect.path())))
        {
            return Err(SettingsError::Collision);
        }
        // The API serves both route sets from one router, which matches paths without the
        // host (ADR 0029). A native route therefore never repeats a mounted browser route,
        // on any origin: the three literal paths and the selected provider's callback.
        let mounted_callback = super::configured(providers, profile.handoff().provider)
            .and_then(|selected| selected.callback().ok())
            .and_then(|callback| Url::parse(&callback).ok())
            .ok_or(SettingsError::Collision)?;
        if browser_paths[..3]
            .iter()
            .chain([&mounted_callback.path()])
            .any(|path| routes.contains(path))
        {
            return Err(SettingsError::Collision);
        }
    }
    for other in providers {
        // A registered callback that cannot be read cannot be shown not to collide.
        let browser_url = other
            .callback()
            .ok()
            .and_then(|callback| Url::parse(&callback).ok())
            .ok_or(SettingsError::Collision)?;
        if (browser_url.origin().ascii_serialization() == issuer
            && routes.contains(&browser_url.path()))
            || browser_url == redirect
        {
            return Err(SettingsError::Collision);
        }
    }
    if let Some(rate) = rate {
        super::router::Budget::new(rate, std::time::Instant::now())
            .map_err(|_| SettingsError::Rate)?;
    }
    if !(1..=MAX_IN_FLIGHT).contains(&max_in_flight) {
        return Err(SettingsError::InFlight);
    }
    Ok(Checked {
        provider,
        redirect,
        binding,
    })
}
fn refused() -> Response<&'static str> {
    handoff::respond(StatusCode::FORBIDDEN, "native sign-in refused\n")
}
/// The confirmation form has an unknown, repeated or malformed field, or a malformed code.
fn form_refused() -> Response<&'static str> {
    handoff::respond(StatusCode::BAD_REQUEST, "native sign-in request refused\n")
}
fn session_failure(error: Error) -> Response<&'static str> {
    match error {
        Error::Rejected => refused(),
        Error::Configuration
        | Error::Capacity
        | Error::Random
        | Error::Database
        | Error::Timeout => handoff::respond(
            StatusCode::SERVICE_UNAVAILABLE,
            "native sign-in unavailable\n",
        ),
    }
}
impl NativeAuth {
    /// Deployment inputs. The issuer is a canonical HTTPS origin and owns the upstream callback.
    /// The app link must be a canonical HTTPS URL registered for this client. Every refusal is
    /// `Configuration`; [`check`] decides it, with its fixed category, without this service.
    pub fn new(
        auth: Arc<BrowserAuth>,
        provider: &str,
        issuer: &str,
        callback: &str,
        client: &str,
        redirect: &str,
        max_in_flight: u32,
    ) -> Result<Self, Error> {
        let settings = Settings {
            provider,
            issuer,
            callback,
            client,
            redirect,
            max_in_flight,
        };
        Self::build(auth, settings, None).map_err(|_| Error::Configuration)
    }
    /// [`Self::new`] for a loaded profile (ADR 0029): the same checks plus the route rate,
    /// refused with the offline check's fixed category.
    pub(crate) fn checked(
        auth: Arc<BrowserAuth>,
        settings: Settings<'_>,
        rate: Rate,
    ) -> Result<Self, SettingsError> {
        Self::build(auth, settings, Some(rate))
    }
    fn build(
        auth: Arc<BrowserAuth>,
        settings: Settings<'_>,
        rate: Option<Rate>,
    ) -> Result<Self, SettingsError> {
        let checked = plan(
            auth.config.providers(),
            auth.config.browser(),
            settings,
            rate,
        )?;
        let provider = checked.provider.clone();
        let redirect = checked.redirect;
        let Settings {
            issuer,
            callback,
            client,
            max_in_flight,
            ..
        } = settings;
        let registration = hash(&[
            &checked.binding,
            issuer.as_bytes(),
            callback.as_bytes(),
            client.as_bytes(),
            redirect.as_str().as_bytes(),
        ]);
        let audience = audience(&provider, issuer, client, &redirect);
        Ok(Self {
            auth,
            provider,
            issuer: issuer.into(),
            callback: callback.into(),
            client: client.into(),
            redirect,
            registration,
            audience,
            in_flight: max_in_flight as usize,
            operations: Semaphore::new(max_in_flight as usize),
        })
    }
    fn attempt(&self, challenge: &str, state: &str) -> Option<ManagedProvider> {
        let challenge = token(challenge)?;
        token(state)?;
        let attempt = Attempt {
            binding: hash(&[&self.registration, &challenge, state.as_bytes()]),
            registration: self.registration,
            audience: self.audience,
            callback: self.callback.clone(),
            challenge,
        };
        Some(self.provider.native_handle(attempt))
    }
    /// The bounded authorization query is repeated unchanged in the confirmed POST. It has
    /// exactly the six protocol parameters, so an invitation code in a query is refused.
    fn request(&self, request: &Parts) -> Option<(String, String)> {
        if request.uri.path() != START {
            return None;
        }
        let query = request.uri.query()?;
        if query.len() > 4096 {
            return None;
        }
        let mut values = std::collections::HashMap::new();
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=')?;
            if ![
                "client_id",
                "redirect_uri",
                "response_type",
                "state",
                "code_challenge_method",
                "code_challenge",
            ]
            .contains(&name)
                || values.insert(name, handoff::decode(value)?).is_some()
            {
                return None;
            }
        }
        if values.get("client_id")? != &self.client
            || values.get("redirect_uri")? != self.redirect.as_str()
            || values.get("code_challenge_method")? != "S256"
            || values.get("response_type")? != "code"
        {
            return None;
        }
        let challenge = values.remove("code_challenge")?;
        let state = values.remove("state")?;
        token(&challenge)?;
        token(&state)?;
        Some((challenge, state))
    }
    /// GET shows a static form. Only a POST from the configured deployment origin can write.
    /// `form` is the POST body, which the caller has already bounded: empty, or the one
    /// `invitation_code` field of the confirmation form (ADR 0022). The query, the method,
    /// `Origin` and then the form are decided before the service is called, and the redirect
    /// has the same shape with or without a code.
    pub async fn authorize(&self, request: &Parts, form: &[u8]) -> Response<&'static str> {
        let Some((challenge, state)) = self.request(request) else {
            return refused();
        };
        if request.method == Method::GET {
            let mut response = handoff::respond(StatusCode::OK, CONFIRMATION);
            for (name, value) in [
                (header::REFERRER_POLICY, "same-origin"),
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
                ),
            ] {
                response
                    .headers_mut()
                    .insert(name, header::HeaderValue::from_static(value));
            }
            return response;
        }
        let mut origins = request.headers.get_all(header::ORIGIN).iter();
        if request.method != Method::POST
            || !origins
                .next()
                .is_some_and(|v| v.as_bytes() == self.issuer.as_bytes())
            || origins.next().is_some()
        {
            return refused();
        }
        // Syntax only. Whether the code belongs to an invitation is decided at redemption.
        let Some(invitation) = handoff::invitation(form) else {
            return form_refused();
        };
        let Ok(_slot) = self.operations.try_acquire() else {
            return refused();
        };
        let Some(provider) = self.attempt(&challenge, &state) else {
            return refused();
        };
        let started = match self.auth.start(&provider, invitation).await {
            Ok(started) => started,
            Err(error) => return handoff::login_failure(error.into()),
        };
        let Some((locator, _)) = handoff::token_pair(started.state.expose()) else {
            return refused();
        };
        let cookie = format!(
            "{COOKIE}={locator}.{}.{challenge}.{state}; Max-Age={}; Path=/; Secure; HttpOnly; SameSite=Lax",
            started.caller_binding.expose(),
            self.auth.config.login_lifetime().as_secs()
        );
        handoff::redirect(started.authorization_url.expose(), Some(&cookie))
    }
    pub async fn callback(&self, request: &Parts) -> Response<&'static str> {
        if request.method != Method::GET
            || request.uri.path() != &self.callback[self.issuer.len()..]
        {
            return refused();
        }
        let Some(response) = handoff::authorization(request.uri.query().unwrap_or_default()) else {
            return refused();
        };
        let Some(cookie) = handoff::single_cookie(&request.headers, COOKIE) else {
            return refused();
        };
        let mut parts = cookie.split('.');
        let (Some(locator), Some(caller), Some(challenge), Some(state), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return refused();
        };
        if token(caller).is_none()
            || handoff::token_pair(&response.state).map(|p| p.0) != Some(locator)
            || response.issuer != self.provider.issuer()
        {
            return refused();
        }
        let Ok(_slot) = self.operations.try_acquire() else {
            return refused();
        };
        let Some(provider) = self.attempt(challenge, state) else {
            return refused();
        };
        let callback = crate::login::Callback {
            state: &response.state,
            caller_binding: caller,
            issuer: &response.issuer,
            callback: &self.callback,
            code: &response.code,
        };
        let permit = match self.auth.consume(&provider, callback).await {
            Ok(permit) => permit,
            Err(error) => return handoff::login_failure(error.into()),
        };
        let proof = match permit
            .exchange_with_keys(&provider, self.auth.config.token_policy())
            .await
        {
            Ok(proof) => proof,
            Err(error) => return handoff::login_failure(error.into()),
        };
        let pending = match self.auth.issue_delivery(&provider, proof).await {
            Ok(sessions::Delivery::NativeCode(pending)) => pending,
            Ok(sessions::Delivery::Browser(_)) => return refused(),
            Err(error) => return session_failure(error),
        };
        // Last monotonic check of the grant deadline. Nothing below awaits.
        let Some(code) = pending.release() else {
            return refused();
        };
        let mut link = self.redirect.clone();
        link.query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", state)
            .append_pair("iss", &self.issuer);
        // No Set-Cookie. Deleting the single temporary cookie here could erase the binding
        // of a newer overlapping attempt. It expires with the login lifetime.
        handoff::redirect(link.as_str(), None)
    }

    pub async fn redeem(&self, request: Redemption<'_>) -> Result<Credential, Error> {
        if request.issuer != self.issuer
            || request.client != self.client
            || request.redirect != self.redirect.as_str()
            || !(43..=128).contains(&request.verifier.len())
            || !request
                .verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(Error::Rejected);
        }
        let code = token(request.code).ok_or(Error::Rejected)?;
        let challenge = Sha256::digest(request.verifier.as_bytes());
        let _slot = self.operations.try_acquire().map_err(|_| Error::Capacity)?;
        let policy = self.auth.config.session_policy();
        tokio::time::timeout(policy.deadline(), async {
            self.provider.check_active().map_err(|_| Error::Rejected)?;
            let mut db = Checkout::acquire(&self.auth.pool).await?;
            let result = native::redeem(
                db.lend(),
                &code,
                &self.registration,
                &self.audience,
                &challenge,
            )
            .await;
            db.settle(session_settled(&result));
            let bearer = result?;
            self.provider.check_active().map_err(|_| Error::Rejected)?;
            Ok(bearer)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn validate(&self, bearer: &str) -> Result<sessions::Context, Error> {
        sessions::well_formed(bearer)?;
        let _slot = self.operations.try_acquire().map_err(|_| Error::Capacity)?;
        Ok(self.validate_effect(bearer).await?.into_context())
    }
    /// `/v1` bounds its own concurrency (`MAX_IN_FLIGHT` and `SSE_MAX_IN_FLIGHT`) and validates
    /// browser cookies through `BrowserAuth::validate_effect` without taking the sign-in router's
    /// in-flight cap; native bearers follow the same rule here so `SSE_MAX_IN_FLIGHT` streams are
    /// not evicted when `native.max_in_flight` is smaller.
    pub(crate) async fn validate_effect(
        &self,
        bearer: &str,
    ) -> Result<crate::authz::approvals::EffectSession, Error> {
        self.auth.validate_effect(bearer, Some(self.audience)).await
    }
    pub async fn logout(&self, bearer: &str) -> Result<(), Error> {
        sessions::well_formed(bearer)?;
        let _slot = self.operations.try_acquire().map_err(|_| Error::Capacity)?;
        let policy = self.auth.config.session_policy();
        tokio::time::timeout(policy.deadline(), async {
            let mut db = Checkout::acquire(&self.auth.pool).await?;
            let result =
                sessions::logout_channel(db.lend(), bearer, policy, Channel::Native(self.audience))
                    .await;
            db.settle(session_settled(&result));
            result
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{auth_config, auth_config::tests::support, provider_http::fixture::Ca};
    use sqlx::postgres::PgPoolOptions;
    use std::{net::TcpListener, time::Duration};

    #[tokio::test]
    async fn validate_effect_is_not_gated_by_native_signin_max_in_flight() {
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let dir = support::Dir::new();
        let mut doc = support::document_v2_native(&dir, &Ca::new().pem());
        doc["native"]["max_in_flight"] = serde_json::json!(1);
        doc["session"]["deadline_milliseconds"] = serde_json::json!(200);
        let path = dir.write("auth.json", doc.to_string().as_bytes());
        let settings = auth_config::load(std::path::Path::new(&path)).unwrap();
        let profile = settings.native().unwrap().clone();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(100))
            .connect_lazy(&format!(
                "postgres://fixture:fixture@127.0.0.1:{port}/fixture?sslmode=disable"
            ))
            .unwrap();
        let browser = Arc::new(BrowserAuth::new(settings, pool.clone(), pool));
        let native = NativeAuth::checked(browser, profile.settings(), profile.rate()).unwrap();

        let _occupied = native.operations.try_acquire().unwrap();
        let bearer = format!("{}.{}", B64.encode([1u8; 32]), B64.encode([2u8; 32]));

        // Direct native session validation still enforces `native.max_in_flight`.
        assert_eq!(native.validate(&bearer).await.err(), Some(Error::Capacity));
        // `/v1` effect validation uses `/v1`'s own permits and must not fail with `Capacity`.
        let effect_error = native.validate_effect(&bearer).await.err();
        assert!(
            matches!(effect_error, Some(Error::Database | Error::Timeout)),
            "expected database/timeout against closed port, got {effect_error:?}"
        );
    }
}
