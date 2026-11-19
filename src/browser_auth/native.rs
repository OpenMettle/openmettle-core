//! Unmounted API-brokered native login (ADR 0023). The app supplies its own S256 challenge.
//! The person confirms the sign-in in the system browser, where a first sign-in also enters
//! its invitation code (ADR 0022). The app never handles that code.
mod routes;
use super::{BrowserAuth, Checkout, handoff, session_settled};
use crate::sessions::native::{self, Attempt};
use crate::{
    provider_keys::ManagedProvider,
    sessions::{self, Channel, Credential, Error, Validation},
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
    operations: Semaphore,
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
        && url
            .path()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b)))
    .then_some(url)
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
    /// The app link must be a canonical HTTPS URL registered for this client.
    pub fn new(
        auth: Arc<BrowserAuth>,
        provider: &str,
        issuer: &str,
        callback: &str,
        client: &str,
        redirect: &str,
        max_in_flight: u32,
    ) -> Result<Self, Error> {
        let provider = auth
            .provider(provider)
            .map_err(|_| Error::Configuration)?
            .clone();
        let callback_url = exact_link(callback).ok_or(Error::Configuration)?;
        let redirect = exact_link(redirect).ok_or(Error::Configuration)?;
        let redirect_origin = redirect.origin().ascii_serialization();
        let routes = [START, TOKEN, SESSION, LOGOUT, callback_url.path()];
        super::router::check_paths(&routes).map_err(|_| Error::Configuration)?;
        if let Some(profile) = auth.config.browser() {
            let browser_origin = profile.handoff().origin;
            let settings = profile.router();
            let sessions = profile.sessions();
            let browser_paths = [
                settings.initiation,
                sessions.session,
                sessions.logout,
                profile.handoff().landing,
            ];
            // The native routes never shadow a browser route on a shared origin, and the
            // app link never lands on a browser or operational route of the browser origin,
            // whichever origin the native deployment itself uses.
            if (browser_origin == issuer && browser_paths.iter().any(|path| routes.contains(path)))
                || (redirect_origin == browser_origin
                    && (browser_paths.contains(&redirect.path())
                        || super::router::CORE_PATHS.contains(&redirect.path())))
            {
                return Err(Error::Configuration);
            }
        }
        for other in auth.config.providers() {
            let browser_callback = other.callback().map_err(|_| Error::Configuration)?;
            let browser_url = Url::parse(&browser_callback).map_err(|_| Error::Configuration)?;
            if (browser_url.origin().ascii_serialization() == issuer
                && routes.contains(&browser_url.path()))
                || browser_url == redirect
            {
                return Err(Error::Configuration);
            }
        }
        if !handoff::canonical_origin(issuer)
            || issuer.len() > 2048
            || callback_url.origin().ascii_serialization() != issuer
            || (redirect_origin == issuer
                && (routes.contains(&redirect.path())
                    || super::router::CORE_PATHS.contains(&redirect.path())))
            || client.is_empty()
            || client.len() > 128
            || !client
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
            || !(1..=1024).contains(&max_in_flight)
        {
            return Err(Error::Configuration);
        }
        let registration = hash(&[
            &provider
                .registration_binding()
                .map_err(|_| Error::Configuration)?,
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
        tokio::time::timeout(self.auth.config.session_policy().deadline(), async {
            let mut db = Checkout::acquire(&self.auth.pool).await?;
            let result = sessions::validate_inner(
                db.lend(),
                bearer,
                Validation::NativeBearer(self.audience),
            )
            .await;
            db.settle(session_settled(&result));
            result
        })
        .await
        .map_err(|_| Error::Timeout)?
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
