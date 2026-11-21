//! Offline loader for mounted browser-auth settings (ADRs 0015 and 0020).
//!
//! One strict, versioned JSON document and the files it names become validated in-memory state
//! through the existing constructors. Version 2 adds one browser-routing profile, judged by
//! the same settings checks as the handoff and router. Loading performs no network, DNS,
//! database or listener work, enters no async runtime and mounts nothing. The API loads a
//! version-2 document at startup through [`load_browser`] when `OPENMETTLE_API_AUTH_CONFIG`
//! names one (ADR 0025). Version 2 may also carry one optional native sign-in profile, judged
//! by the native service's own settings check and mounted beside the browser routes
//! (ADR 0029). Settings and
//! login secrets come from the deployment files. Native trust follows ADR 0010 and honors
//! `SSL_CERT_FILE` and `SSL_CERT_DIR`. Success validates local inputs for this build.
//! Provider reachability, durable authority (ADR 0012) and agreement between replicas require
//! separate checks.
use crate::{
    auth::{self, ProviderIdentity},
    browser_auth::{
        handoff, native,
        router::{self, Rate},
    },
    login::{self, KeyRing},
    provider_http::{MAX_TRUST_BUNDLE_BYTES, Trust},
    provider_keys::{self, ManagedProvider, ProviderConfig, ProviderManager, RefreshPolicy},
    sessions,
};
use ring::hmac;
use serde_json::{Map, Value, error::Category};
use std::{
    collections::HashSet,
    ffi::OsString,
    fmt, fs,
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use subtle::ConstantTimeEq;

/// The original document: login, token, refresh, session and provider settings.
pub const VERSION: u64 = 1;
/// [`VERSION`] plus one required browser-routing profile (ADR 0020) and one optional native
/// sign-in profile (ADR 0029).
pub const VERSION_2: u64 = 2;
/// Maximum serialized document size, applied before parsing.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// Exact length of each raw login key file.
pub const KEY_BYTES: usize = 32;
/// Fixed success line of `openmettle-api --check-auth-config PATH`.
pub const VALID: &str = "auth configuration valid (local files only)";

/// Fixed refusal categories. No variant carries a path, URL, identifier, key byte, parser
/// message or filesystem error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A path is not absolute.
    Path,
    /// The document is not a readable regular file within [`MAX_CONFIG_BYTES`].
    ConfigFile,
    Json,
    DuplicateField,
    Version,
    MissingField,
    UnknownField,
    /// Wrong JSON type, a non-integer or negative number, or an unrecognized keyword.
    Field,
    LoginLifetime,
    TokenPolicy,
    RefreshPolicy,
    SessionPolicy,
    /// A key file is not a readable regular file of exactly [`KEY_BYTES`] bytes.
    KeyFile,
    /// Key count, identifiers or repeated material refused by [`KeyRing`].
    KeyRing,
    /// An unreadable cursor key file or a key with an incorrect length.
    CursorKeyFile,
    /// Invalid cursor key count, identifier or key separation.
    CursorKeyRing,
    /// No provider, or more than the configured manager capacity.
    ProviderCount,
    ProviderIdentity,
    DuplicateProvider,
    /// A bundle is not a readable regular file within the transport's ceiling.
    TrustBundleFile,
    /// Definition, endpoint, trust anchors or address policy refused by [`ProviderConfig`].
    Provider,
    /// The browser profile's origin, landing, provider or that provider's callback, refused
    /// by the handoff's own settings check with its fixed category.
    BrowserHandoff(handoff::SettingsError),
    /// The browser profile's paths, rate budgets or in-flight cap, refused by the router's
    /// own settings check with its fixed category.
    BrowserRouter(router::SettingsError),
    /// The native profile's provider, issuer, callback, client, app link, route collisions,
    /// rate or in-flight cap, refused by the native service's own settings check with its
    /// fixed category (ADR 0029).
    Native(native::SettingsError),
    /// A valid version-1 document where serving needs the version-2 browser profile. Only
    /// [`load_browser`] returns it; the offline check still accepts version 1.
    BrowserProfileRequired,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Path => "a path is not absolute",
            Self::ConfigFile => "configuration is not a readable regular file within bounds",
            Self::Json => "configuration is not valid JSON",
            Self::DuplicateField => "configuration repeats a field",
            Self::Version => "configuration version is missing or unsupported",
            Self::MissingField => "configuration lacks a required field",
            Self::UnknownField => "configuration has an unknown field",
            Self::Field => "a configuration field has the wrong type or keyword",
            Self::LoginLifetime => "login lifetime is out of range",
            Self::TokenPolicy => "ID-token age or skew is out of range",
            Self::RefreshPolicy => "provider refresh policy is out of range",
            Self::SessionPolicy => "session policy is out of range",
            Self::KeyFile => "a login key is not a readable regular file of exactly 32 bytes",
            Self::KeyRing => "login key count, identifiers or material are not acceptable",
            Self::CursorKeyFile => {
                "a cursor key is not a readable regular file of exactly 32 bytes"
            }
            Self::CursorKeyRing => "cursor key count, identifiers or key separation are invalid",
            Self::ProviderCount => "provider count is outside the configured capacity",
            Self::ProviderIdentity => "a provider identity is invalid",
            Self::DuplicateProvider => "provider identifiers are not unique",
            Self::TrustBundleFile => "a trust bundle is not a readable regular file within bounds",
            Self::Provider => "a provider definition, endpoint, trust or address policy is invalid",
            // The wrapped categories are fixed lines too; neither carries a value.
            Self::BrowserHandoff(error) => return write!(f, "browser profile refused: {error}"),
            Self::BrowserRouter(error) => return write!(f, "browser profile refused: {error}"),
            Self::Native(error) => return write!(f, "native profile refused: {error}"),
            Self::BrowserProfileRequired => "serving requires a version 2 browser profile",
        })
    }
}
impl std::error::Error for Error {}

/// One JSON object. Members are taken by name; whatever remains is an unknown field. Derived
/// Serde structs are deliberately not used: they also accept positional arrays and `null`,
/// which would give the document more than one accepted shape.
struct Object(Map<String, Value>);
impl Object {
    fn new(value: Value) -> Result<Self, Error> {
        match value {
            Value::Object(members) => Ok(Self(members)),
            _ => Err(Error::Field),
        }
    }
    fn take(&mut self, name: &str) -> Result<Value, Error> {
        self.0.remove(name).ok_or(Error::MissingField)
    }
    fn object(&mut self, name: &str) -> Result<Self, Error> {
        Self::new(self.take(name)?)
    }
    fn string(&mut self, name: &str) -> Result<String, Error> {
        match self.take(name)? {
            Value::String(value) => Ok(value),
            _ => Err(Error::Field),
        }
    }
    /// A non-negative JSON integer; fractions, exponents and strings are refused.
    fn integer(&mut self, name: &str) -> Result<u64, Error> {
        self.take(name)?.as_u64().ok_or(Error::Field)
    }
    /// [`Self::integer`] for a member that may be absent. A present `null` is refused, so the
    /// member has exactly two accepted shapes: absent, or a plain integer.
    fn optional_integer(&mut self, name: &str) -> Result<Option<u64>, Error> {
        if self.0.contains_key(name) {
            self.integer(name).map(Some)
        } else {
            Ok(None)
        }
    }
    /// An object member that may be absent. A present `null` or other type is refused, so the
    /// member has exactly two accepted shapes: absent, or an object.
    fn optional_object(&mut self, name: &str) -> Result<Option<Self>, Error> {
        if self.0.contains_key(name) {
            self.object(name).map(Some)
        } else {
            Ok(None)
        }
    }
    fn array(&mut self, name: &str) -> Result<Vec<Value>, Error> {
        match self.take(name)? {
            Value::Array(values) => Ok(values),
            _ => Err(Error::Field),
        }
    }
    fn end(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::UnknownField)
        }
    }
}

struct KeyFile {
    id: String,
    path: String,
}
impl KeyFile {
    fn parse(value: Value) -> Result<Self, Error> {
        let mut key = Object::new(value)?;
        let parsed = Self {
            id: key.string("id")?,
            path: key.string("path")?,
        };
        key.end()?;
        Ok(parsed)
    }
}

/// Dedicated HMAC keys in signing order, active first (ADR 0034).
pub(crate) struct CursorKeys {
    pub(crate) active: (String, hmac::Key),
    pub(crate) verify_only: Vec<(String, hmac::Key)>,
}

impl CursorKeys {
    pub(crate) fn valid_id(id: &str) -> bool {
        (1..=64).contains(&id.len()) && id.bytes().all(login::url_safe_byte)
    }
}

struct CursorFiles {
    active: KeyFile,
    verify_only: Vec<KeyFile>,
}
impl CursorFiles {
    fn parse(mut keys: Object) -> Result<Self, Error> {
        let active = KeyFile::parse(keys.take("active")?)?;
        let verify_only = keys
            .array("verify_only")?
            .into_iter()
            .map(KeyFile::parse)
            .collect::<Result<_, _>>()?;
        keys.end()?;
        Ok(Self {
            active,
            verify_only,
        })
    }

    fn load(&self, login: &[(String, [u8; KEY_BYTES])]) -> Result<CursorKeys, Error> {
        let keys = key_material(&self.active, &self.verify_only).map_err(|error| match error {
            Error::KeyRing => Error::CursorKeyRing,
            Error::KeyFile => Error::CursorKeyFile,
            other => other,
        })?;
        for (i, (id, material)) in keys.iter().enumerate() {
            if !CursorKeys::valid_id(id)
                || keys[..i].iter().any(|(other, _)| other == id)
                || login
                    .iter()
                    .chain(&keys[..i])
                    .any(|(_, other)| bool::from(material.ct_eq(other)))
            {
                return Err(Error::CursorKeyRing);
            }
        }
        let mut keys = keys
            .into_iter()
            .map(|(id, bytes)| (id, hmac::Key::new(hmac::HMAC_SHA256, &bytes)));
        Ok(CursorKeys {
            active: keys.next().ok_or(Error::CursorKeyRing)?,
            verify_only: keys.collect(),
        })
    }
}

struct Provider {
    id: String,
    issuer: String,
    client_id: String,
    revision: String,
    authorization_endpoint: String,
    token_endpoint: String,
    discovery_url: String,
    jwks_url: String,
    callback: String,
    destination: String,
    private_cidrs: Vec<String>,
    /// `None` selects the native roots; a path selects exactly one PEM bundle.
    bundle_path: Option<String>,
}
impl Provider {
    fn parse(value: Value) -> Result<Self, Error> {
        let mut provider = Object::new(value)?;
        let mut trust = provider.object("trust")?;
        let bundle_path = match trust.string("roots")?.as_str() {
            "native" => None,
            "bundle" => Some(trust.string("bundle_path")?),
            _ => return Err(Error::Field),
        };
        trust.end()?;
        let private_cidrs = provider
            .array("private_cidrs")?
            .into_iter()
            .map(|range| match range {
                Value::String(range) => Ok(range),
                _ => Err(Error::Field),
            })
            .collect::<Result<_, _>>()?;
        let parsed = Self {
            id: provider.string("id")?,
            issuer: provider.string("issuer")?,
            client_id: provider.string("client_id")?,
            revision: provider.string("revision")?,
            authorization_endpoint: provider.string("authorization_endpoint")?,
            token_endpoint: provider.string("token_endpoint")?,
            discovery_url: provider.string("discovery_url")?,
            jwks_url: provider.string("jwks_url")?,
            callback: provider.string("callback")?,
            destination: provider.string("destination")?,
            private_cidrs,
            bundle_path,
        };
        provider.end()?;
        Ok(parsed)
    }
}

/// The version-2 browser-routing profile (ADR 0020): one selected provider, the application
/// origin and landing, three literal route paths, four rate budgets and one in-flight cap.
/// The callback path is the selected provider's registered callback; nothing here supplies it.
///
/// Only [`load`] returns one, inside [`AuthConfig`], after the handoff's and router's own
/// settings checks accepted it. It holds settings only: no route, listener or admission state.
#[derive(Clone)]
pub struct BrowserProfile {
    provider_id: String,
    origin: String,
    landing_path: String,
    initiation_path: String,
    session_check_path: String,
    logout_path: String,
    initiation: Rate,
    callback: Rate,
    session_check: Rate,
    logout: Rate,
    max_in_flight: u32,
}
impl fmt::Debug for BrowserProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrowserProfile(..)")
    }
}
impl BrowserProfile {
    /// Settings for `LoginHandoff::new`.
    pub fn handoff(&self) -> handoff::Settings<'_> {
        handoff::Settings {
            origin: &self.origin,
            landing: &self.landing_path,
            provider: &self.provider_id,
        }
    }
    /// Login-route settings for `router_with_sessions`.
    pub fn router(&self) -> router::Settings<'_> {
        router::Settings {
            initiation: &self.initiation_path,
            begin: self.initiation,
            callback: self.callback,
            in_flight: self.max_in_flight,
        }
    }
    /// Session-route settings for `router_with_sessions`.
    pub fn sessions(&self) -> router::SessionSettings<'_> {
        router::SessionSettings {
            session: &self.session_check_path,
            logout: &self.logout_path,
            checks: self.session_check,
            logouts: self.logout,
        }
    }

    /// Shape only. Integers too large for the router's types saturate, so the router's own
    /// range check refuses them in its usual order; no bound is added here.
    fn parse(value: Value) -> Result<Self, Error> {
        let mut browser = Object::new(value)?;
        let mut paths = browser.object("paths")?;
        let mut rates = browser.object("rates")?;
        let parsed = Self {
            provider_id: browser.string("provider_id")?,
            origin: browser.string("origin")?,
            landing_path: browser.string("landing_path")?,
            initiation_path: paths.string("initiation")?,
            session_check_path: paths.string("session_check")?,
            logout_path: paths.string("logout")?,
            initiation: rate(rates.take("initiation")?)?,
            callback: rate(rates.take("callback")?)?,
            session_check: rate(rates.take("session_check")?)?,
            logout: rate(rates.take("logout")?)?,
            max_in_flight: saturate(browser.integer("max_in_flight")?),
        };
        for object in [paths, rates, browser] {
            object.end()?;
        }
        Ok(parsed)
    }
    /// The handoff's settings check against the registered providers (origin, landing,
    /// selected provider and its exact callback), then the router's over all four paths,
    /// the four budgets and the in-flight cap. Neither builds a service, route or task.
    fn check(self, providers: &[ManagedProvider]) -> Result<Self, Error> {
        let checked = handoff::check(providers, self.handoff()).map_err(Error::BrowserHandoff)?;
        router::check(checked.callback_path(), self.router(), self.sessions())
            .map_err(Error::BrowserRouter)?;
        Ok(self)
    }
}

/// A JSON integer for a `u32` setting. Too large saturates, so the owning range check
/// refuses it in its usual order rather than accepting a clamped value.
fn saturate(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
/// One `{"burst", "interval_milliseconds"}` rate object, shape only.
fn rate(value: Value) -> Result<Rate, Error> {
    let mut rate = Object::new(value)?;
    let parsed = Rate {
        burst: saturate(rate.integer("burst")?),
        interval: Duration::from_millis(rate.integer("interval_milliseconds")?),
    };
    rate.end()?;
    Ok(parsed)
}

/// The optional version-2 native sign-in profile (ADR 0029): one selected provider, the
/// deployment issuer and its upstream callback, the native client and its exact app link,
/// one rate for each native route and method, and one in-flight cap.
///
/// Only [`load`] returns one, inside [`AuthConfig`], after the native service's own settings
/// check accepted it. It holds settings only: no route, listener or admission state.
#[derive(Clone)]
pub struct NativeProfile {
    provider_id: String,
    issuer: String,
    callback: String,
    client_id: String,
    redirect_uri: String,
    rate: Rate,
    max_in_flight: u32,
}
impl fmt::Debug for NativeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeProfile(..)")
    }
}
impl NativeProfile {
    /// Settings for the native service.
    pub fn settings(&self) -> native::Settings<'_> {
        native::Settings {
            provider: &self.provider_id,
            issuer: &self.issuer,
            callback: &self.callback,
            client: &self.client_id,
            redirect: &self.redirect_uri,
            max_in_flight: self.max_in_flight,
        }
    }
    /// The rate of each native route and accepted method, for `NativeAuth::router_shared`.
    pub fn rate(&self) -> Rate {
        self.rate
    }
    /// Shape only, as for [`BrowserProfile::parse`].
    fn parse(mut native: Object) -> Result<Self, Error> {
        let parsed = Self {
            provider_id: native.string("provider_id")?,
            issuer: native.string("issuer")?,
            callback: native.string("callback")?,
            client_id: native.string("client_id")?,
            redirect_uri: native.string("redirect_uri")?,
            rate: rate(native.take("rate")?)?,
            max_in_flight: saturate(native.integer("max_in_flight")?),
        };
        native.end()?;
        Ok(parsed)
    }
    /// The native service's settings check against the registered providers and the checked
    /// browser profile. It builds no service, route or task.
    fn check(
        self,
        providers: &[ManagedProvider],
        browser: Option<&BrowserProfile>,
    ) -> Result<Self, Error> {
        native::check(providers, browser, self.settings(), self.rate).map_err(Error::Native)?;
        Ok(self)
    }
}

/// The complete shape of either version, checked before any policy is evaluated or other file
/// is read.
struct Document {
    login_lifetime_seconds: u64,
    active_key: KeyFile,
    cursor_keys: Option<CursorFiles>,
    decrypt_only_keys: Vec<KeyFile>,
    max_issued_at_age_seconds: u64,
    future_skew_seconds: u64,
    freshness_seconds: u64,
    cooldown_seconds: u64,
    /// Optional; absent selects the 60-second default (ADR 0011 amendment, 19 November 2026).
    uncacheable_reuse_seconds: Option<u64>,
    refresh_deadline_milliseconds: u64,
    max_providers: u64,
    max_callers: u64,
    max_document_gets: u64,
    session_lifetime_seconds: u64,
    retained_per_user: u64,
    session_deadline_milliseconds: u64,
    providers: Vec<Provider>,
    /// Required in version 2. Version 1 has no such member, so there it is an unknown field.
    browser: Option<BrowserProfile>,
    /// Optional in version 2, and an unknown field in version 1.
    native: Option<NativeProfile>,
}
impl Document {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let value = provider_keys::documents::unique(bytes).map_err(|e| match e.classify() {
            Category::Data => Error::DuplicateField,
            _ => Error::Json,
        })?;
        // Version first: another version's fields must not be reported as shape errors.
        let mut root = Object::new(value).map_err(|_| Error::Version)?;
        let version = match root.take("version").ok().and_then(|v| v.as_u64()) {
            Some(version @ (VERSION | VERSION_2)) => version,
            _ => return Err(Error::Version),
        };
        let mut login = root.object("login")?;
        let mut keys = login.object("keys")?;
        let mut id_token = root.object("id_token")?;
        let mut refresh = root.object("provider_refresh")?;
        let mut session = root.object("session")?;
        let parsed = Self {
            login_lifetime_seconds: login.integer("lifetime_seconds")?,
            active_key: KeyFile::parse(keys.take("active")?)?,
            decrypt_only_keys: keys
                .array("decrypt_only")?
                .into_iter()
                .map(KeyFile::parse)
                .collect::<Result<_, _>>()?,
            max_issued_at_age_seconds: id_token.integer("max_issued_at_age_seconds")?,
            future_skew_seconds: id_token.integer("future_skew_seconds")?,
            freshness_seconds: refresh.integer("freshness_seconds")?,
            cooldown_seconds: refresh.integer("cooldown_seconds")?,
            uncacheable_reuse_seconds: refresh.optional_integer("uncacheable_reuse_seconds")?,
            refresh_deadline_milliseconds: refresh.integer("deadline_milliseconds")?,
            max_providers: refresh.integer("max_providers")?,
            max_callers: refresh.integer("max_callers")?,
            max_document_gets: refresh.integer("max_document_gets")?,
            session_lifetime_seconds: session.integer("lifetime_seconds")?,
            retained_per_user: session.integer("retained_per_user")?,
            session_deadline_milliseconds: session.integer("deadline_milliseconds")?,
            providers: root
                .array("providers")?
                .into_iter()
                .map(Provider::parse)
                .collect::<Result<_, _>>()?,
            browser: match version {
                VERSION_2 => Some(BrowserProfile::parse(root.take("browser")?)?),
                _ => None,
            },
            cursor_keys: match version {
                VERSION_2 => root
                    .optional_object("cursor_keys")?
                    .map(CursorFiles::parse)
                    .transpose()?,
                _ => None,
            },
            native: match version {
                VERSION_2 => root
                    .optional_object("native")?
                    .map(NativeProfile::parse)
                    .transpose()?,
                _ => None,
            },
        };
        for object in [keys, login, id_token, refresh, session, root] {
            object.end()?;
        }
        Ok(parsed)
    }
}

/// [`read`] for another loader with its own fixed refusal: OTLP's CA file (ADR 0026).
pub(crate) fn read_bounded(path: &Path, limit: usize) -> Option<Vec<u8>> {
    read(path, limit, Error::TrustBundleFile).ok()
}

/// Reads one file named by an absolute path, at most `limit` bytes. Symbolic links are
/// followed, so Kubernetes projected-volume entries work; what they resolve to must be a
/// regular file. Type and length are checked before opening (a FIFO, device, socket or
/// directory is never opened), checked again on the opened handle, and the read is capped.
/// Ownership and mode are not inspected, and a writer racing in the same directory is not
/// defended against: the directories must be deployment-owned.
fn read(path: &Path, limit: usize, refusal: Error) -> Result<Vec<u8>, Error> {
    if !path.is_absolute() {
        return Err(Error::Path);
    }
    let bounded = |m: fs::Metadata| m.is_file() && m.len() <= limit as u64;
    if !fs::metadata(path).is_ok_and(bounded) {
        return Err(refusal);
    }
    let file = fs::File::open(path).map_err(|_| refusal)?;
    if !file.metadata().is_ok_and(bounded) {
        return Err(refusal);
    }
    let mut bytes = Vec::new();
    match file.take(limit as u64 + 1).read_to_end(&mut bytes) {
        Ok(length) if length <= limit => Ok(bytes),
        _ => Err(refusal),
    }
}

/// The active key first, then decrypt-only keys in document order. The count is bounded
/// before any key file is read; [`KeyRing::new`] checks identifiers and repeated material.
fn key_material(
    active: &KeyFile,
    decrypt_only: &[KeyFile],
) -> Result<Vec<(String, [u8; KEY_BYTES])>, Error> {
    if decrypt_only.len() >= login::MAX_KEYS {
        return Err(Error::KeyRing);
    }
    std::iter::once(active)
        .chain(decrypt_only)
        .map(|key| {
            let bytes = read(Path::new(&key.path), KEY_BYTES, Error::KeyFile)?;
            let material = bytes.try_into().map_err(|_| Error::KeyFile)?;
            Ok((key.id.clone(), material))
        })
        .collect()
}

/// Everything the browser-auth runtime needs, constructed together or not at all. The manager
/// is the single process-lifetime owner required by ADR 0011; providers are in document order.
pub struct AuthConfig {
    pub(crate) cursor_keys: Option<CursorKeys>,
    keys: KeyRing,
    login_lifetime: Duration,
    token_policy: auth::Policy,
    session_policy: sessions::Policy,
    manager: ProviderManager,
    providers: Vec<ManagedProvider>,
    browser: Option<BrowserProfile>,
    native: Option<NativeProfile>,
}
impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthConfig(..)")
    }
}
impl AuthConfig {
    pub fn keys(&self) -> &KeyRing {
        &self.keys
    }
    pub fn login_lifetime(&self) -> Duration {
        self.login_lifetime
    }
    pub fn token_policy(&self) -> &auth::Policy {
        &self.token_policy
    }
    pub fn session_policy(&self) -> &sessions::Policy {
        &self.session_policy
    }
    pub fn manager(&self) -> &ProviderManager {
        &self.manager
    }
    pub fn providers(&self) -> &[ManagedProvider] {
        &self.providers
    }
    /// The validated browser-routing profile of a version-2 document; `None` for version 1.
    /// The API mounts its routes only from [`load_browser`] (ADR 0025).
    pub fn browser(&self) -> Option<&BrowserProfile> {
        self.browser.as_ref()
    }
    /// The validated native sign-in profile of a version-2 document that has one (ADR 0029).
    pub fn native(&self) -> Option<&NativeProfile> {
        self.native.as_ref()
    }
    /// Test-only assembly from parts built with fixture trust. Production state comes from
    /// [`load`] alone.
    #[cfg(test)]
    pub(crate) fn fixture(
        keys: KeyRing,
        login_lifetime: Duration,
        session_policy: sessions::Policy,
        manager: ProviderManager,
        providers: Vec<ManagedProvider>,
    ) -> Self {
        Self {
            keys,
            login_lifetime,
            token_policy: auth::Policy::default(),
            session_policy,
            manager,
            providers,
            cursor_keys: None,
            browser: None,
            native: None,
        }
    }
}

/// Loads and validates the document at `path` and every file it names. Offline and read-only.
pub fn load(path: &Path) -> Result<AuthConfig, Error> {
    let document = Document::parse(&read(path, MAX_CONFIG_BYTES, Error::ConfigFile)?)?;

    let login_lifetime = Duration::from_secs(document.login_lifetime_seconds);
    if !(login::MIN_LOGIN_LIFETIME..=login::MAX_LOGIN_LIFETIME).contains(&login_lifetime) {
        return Err(Error::LoginLifetime);
    }
    let token_policy = auth::Policy::new(
        Duration::from_secs(document.max_issued_at_age_seconds),
        Duration::from_secs(document.future_skew_seconds),
    )
    .map_err(|_| Error::TokenPolicy)?;
    let count = |value: u64| usize::try_from(value).map_err(|_| Error::RefreshPolicy);
    let max_providers = count(document.max_providers)?;
    let mut refresh_policy = RefreshPolicy::new(
        Duration::from_secs(document.freshness_seconds),
        Duration::from_secs(document.cooldown_seconds),
        Duration::from_millis(document.refresh_deadline_milliseconds),
        max_providers,
        count(document.max_callers)?,
        count(document.max_document_gets)?,
    )
    .map_err(|_| Error::RefreshPolicy)?;
    // Only an explicit window is checked against cooldown and freshness. The default applies
    // under the freshness cap, so documents written before the member existed still load.
    if let Some(seconds) = document.uncacheable_reuse_seconds {
        refresh_policy = refresh_policy
            .with_uncacheable_reuse(Duration::from_secs(seconds))
            .map_err(|_| Error::RefreshPolicy)?;
    }
    let session_policy = sessions::Policy::new(
        Duration::from_secs(document.session_lifetime_seconds),
        u32::try_from(document.retained_per_user).map_err(|_| Error::SessionPolicy)?,
        Duration::from_millis(document.session_deadline_milliseconds),
    )
    .map_err(|_| Error::SessionPolicy)?;

    if !(1..=max_providers).contains(&document.providers.len()) {
        return Err(Error::ProviderCount);
    }

    let material = key_material(&document.active_key, &document.decrypt_only_keys)?;
    let cursor_keys = document
        .cursor_keys
        .as_ref()
        .map(|files| files.load(&material))
        .transpose()?;
    let keys = KeyRing::new(material).map_err(|_| Error::KeyRing)?;

    let manager = ProviderManager::new(refresh_policy);
    let mut seen = HashSet::new();
    let mut providers = Vec::with_capacity(document.providers.len());
    for provider in &document.providers {
        let identity = ProviderIdentity::new(&provider.id, &provider.issuer, &provider.client_id)
            .map_err(|_| Error::ProviderIdentity)?;
        // Canonical lowercase text, so string equality is UUID equality. Registration would
        // otherwise treat a repeated identifier as a replacement.
        if !seen.insert(provider.id.as_str()) {
            return Err(Error::DuplicateProvider);
        }
        let bundle = provider
            .bundle_path
            .as_deref()
            .map(|path| {
                read(
                    Path::new(path),
                    MAX_TRUST_BUNDLE_BYTES,
                    Error::TrustBundleFile,
                )
            })
            .transpose()?;
        let ranges: Vec<&str> = provider.private_cidrs.iter().map(String::as_str).collect();
        let config = ProviderConfig::new(
            identity,
            login::ProviderDefinition {
                revision: &provider.revision,
                authorization_endpoint: &provider.authorization_endpoint,
                token_endpoint: &provider.token_endpoint,
                callback: &provider.callback,
                destination: &provider.destination,
                enabled: true,
            },
            &provider.discovery_url,
            &provider.jwks_url,
            bundle.as_deref().map_or(Trust::Native, Trust::Bundle),
            &ranges,
        )
        .map_err(|_| Error::Provider)?;
        providers.push(manager.register(config).map_err(|_| Error::Provider)?);
    }
    // Last: the profile names a registered provider and is judged against its callback.
    let browser = document
        .browser
        .map(|profile| profile.check(&providers))
        .transpose()?;
    // Then the native profile, judged against the checked browser routes it must not shadow.
    let native = document
        .native
        .map(|profile| profile.check(&providers, browser.as_ref()))
        .transpose()?;
    Ok(AuthConfig {
        cursor_keys,
        keys,
        login_lifetime,
        token_policy,
        session_policy,
        manager,
        providers,
        browser,
        native,
    })
}

/// [`load`] for serving (ADR 0025): the settings and the browser-routing profile the API
/// mounts. A version-1 document passes every version-1 check and is then refused, because it
/// names no origin, route or budget to serve.
pub fn load_browser(path: &Path) -> Result<(AuthConfig, BrowserProfile), Error> {
    let config = load(path)?;
    let profile = config
        .browser
        .clone()
        .ok_or(Error::BrowserProfileRequired)?;
    Ok((config, profile))
}

/// `openmettle-api` with arguments accepts exactly `--check-auth-config PATH`.
/// Returns 0 after writing [`VALID`], 1 if that write fails, or 78 with a fixed diagnostic
/// for invalid settings or arguments.
pub fn check_command(arguments: &[OsString]) -> u8 {
    let path = match arguments {
        [flag, path] if flag == "--check-auth-config" => path,
        _ => {
            eprintln!("usage error: expected no arguments or --check-auth-config PATH");
            return 78;
        }
    };
    match load(Path::new(path)) {
        Ok(_) => match writeln!(std::io::stdout(), "{VALID}") {
            Ok(()) => 0,
            Err(_) => 1,
        },
        Err(error) => {
            eprintln!("auth configuration error: {error}");
            78
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
