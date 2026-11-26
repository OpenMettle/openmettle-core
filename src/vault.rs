//! V1-28 credential vault and external connection lifecycle (ADR 0045).
//!
//! Stores scope-owned external connection metadata and versioned-key encrypted credentials in
//! PostgreSQL (`openmettle.external_connections`, `openmettle.external_connection_shares`).
//!
//! Security invariants:
//! - Envelope encryption uses HKDF-SHA256 (`b"openmettle.vault.dek/1"`) per-seal key derivation
//!   with a fresh 32-byte CSPRNG salt and 12-byte nonce under `ring::aead::AES_256_GCM`, binding
//!   canonical length-prefixed AAD (`connection_id`, `scope_id`, `account_id`, `secret_kind`,
//!   `key_id`, `credential_generation`, `allowed_scopes`).
//! - Master keys live outside PostgreSQL in a separate Kubernetes Secret / mounted-file keyring
//!   (`VaultKeyRing`), checked with `subtle::ConstantTimeEq` and zeroed on drop via
//!   `rustls::crypto::SharedSecret` under `unsafe_code = "forbid"`.
//! - `granted_scopes` can never widen beyond `allowed_scopes` (enforced in Rust and SQL `<@`).
//! - `openmettle_api` has column-scoped read grants excluding all secret/ciphertext/key_id/lease
//!   columns and never returns tokens or secrets on any response.
//! - `openmettle_worker` resolves credentials at execution time after verifying live primary
//!   principal, scope lifecycle, explicit shares, destination origin, required scope, and the open
//!   `restore_reconciliation_gate`, using DB-backed single-flight refresh leasing fenced against
//!   concurrent disconnects and revocations.

use crate::{
    authz::{
        self, DenialReason, Grantee, PolicyReason, Principal, Project, ProjectRole, Scope,
        projects::{
            ARCHIVED, CONCEALED, grantee_details, grantee_input, lock_project, project_in,
            recipient_enabled, recipient_principal,
        },
        store::{
            self, AuditContext, Change, StoreError, UNCHANGED, WriteOutcome, lock_actor_approval,
            lock_actor_authority, post_lock_acting, post_lock_clock_ms, record, transact, uuid,
        },
    },
    grants,
    mcp::external::{
        CredentialOutcome, CredentialRequest, DestinationAuthorizer, McpCredential,
        McpCredentialProvider, ReconcileTarget,
    },
    provider_http::{self, MAX_PRIVATE_RANGES, Trust, transport},
    provider_keys::documents::unique,
    runs,
};
use hyper::{Method, StatusCode, header};
use ring::{
    aead, hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use rustls::crypto::SharedSecret;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, PgPool, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    future::Future,
    io::Read,
    path::Path,
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    sync::Semaphore,
    time::{Instant, sleep},
};

/// Maximum configured master keys in one [`VaultKeyRing`] (active plus historical decrypt keys).
pub const MAX_KEYS: usize = 16;
/// Byte length of every master encryption key (256-bit).
pub const KEY_BYTES: usize = 32;
/// Byte length of the per-seal HKDF-SHA256 salt.
pub const SALT_BYTES: usize = 32;
/// Byte length of the per-seal AES-256-GCM nonce.
pub const NONCE_BYTES: usize = 12;
/// Maximum plaintext access-token size (4 KiB; ciphertext plus 16-byte GCM tag <= 4,112 bytes;
/// aligns with MCP `MAX_REQUEST_HEADER_BYTES = 8 KiB` for `Authorization: Bearer <token>`).
pub const MAX_ACCESS_TOKEN_BYTES: usize = 4 * 1024;
/// Maximum plaintext refresh-token size (16 KiB; ciphertext plus 16-byte GCM tag <= 16,400 bytes).
pub const MAX_REFRESH_TOKEN_BYTES: usize = 16 * 1024;
/// Maximum plaintext credential size across secret kinds (alias for [`MAX_REFRESH_TOKEN_BYTES`]).
pub const MAX_SECRET_BYTES: usize = MAX_REFRESH_TOKEN_BYTES;
/// Maximum number of scopes on a single external connection.
pub const MAX_SCOPES: usize = 64;
/// Maximum size of a vault keyring JSON configuration document.
const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// Maximum HTTP response body accepted from an upstream OAuth token refresh endpoint.
const MAX_REFRESH_RESPONSE_BYTES: usize = 64 * 1024;
/// Maximum HTTP request body sent to an upstream OAuth token refresh endpoint.
/// Sized for worst-case `%XX` percent-encoding of a 16 KiB refresh token, up to 64 scopes,
/// and form framing.
const MAX_REFRESH_REQUEST_BYTES: usize = 96 * 1024;
/// Maximum `expires_in` seconds accepted from an upstream refresh response (1 year).
const MAX_EXPIRES_IN_SECS: u64 = 31_536_000;

const HKDF_INFO: &[u8] = b"openmettle.vault.dek/1";
const IDEMPOTENCY_SALT: &[u8] = b"openmettle.vault.idempotency.salt/1";
const IDEMPOTENCY_INFO: &[u8] = b"openmettle.vault.idempotency/1";
const AAD_DOMAIN: &[u8] = b"openmettle.vault.aad/1\0";

/// Dedicated process-wide DNS lookup slot pool isolated from OIDC, gateway inference, and MCP.
static VAULT_REFRESH_DNS_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(provider_http::DNS_LOOKUP_SLOTS)));

// --- errors & redacted secret types ------------------------------------------------------------

/// Redacted vault error. `Display` and `Debug` never emit secret bytes, keys, paths, or payloads.
pub enum VaultError {
    Configuration(&'static str),
    Random,
    UnknownKey,
    Crypto,
    InvalidSecret,
    ScopeWidening,
    Store(StoreError),
    RefreshRefused,
    RefreshTransient,
}

impl fmt::Debug for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(msg) => write!(f, "VaultError::Configuration({msg})"),
            Self::Random => f.write_str("VaultError::Random"),
            Self::UnknownKey => f.write_str("VaultError::UnknownKey"),
            Self::Crypto => f.write_str("VaultError::Crypto"),
            Self::InvalidSecret => f.write_str("VaultError::InvalidSecret"),
            Self::ScopeWidening => f.write_str("VaultError::ScopeWidening"),
            Self::Store(err) => write!(f, "VaultError::Store({err})"),
            Self::RefreshRefused => f.write_str("VaultError::RefreshRefused"),
            Self::RefreshTransient => f.write_str("VaultError::RefreshTransient"),
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(msg) => write!(f, "{msg}"),
            Self::Random => f.write_str("vault randomness unavailable"),
            Self::UnknownKey => f.write_str("vault encryption key version unavailable"),
            Self::Crypto => f.write_str("vault cryptographic operation failed"),
            Self::InvalidSecret => f.write_str("invalid credential material"),
            Self::ScopeWidening => f.write_str("granted scopes exceed allowed scopes"),
            Self::Store(err) => write!(f, "{err}"),
            Self::RefreshRefused => f.write_str("upstream credential refresh refused"),
            Self::RefreshTransient => f.write_str("upstream credential refresh unavailable"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<StoreError> for VaultError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

impl From<sqlx::Error> for VaultError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(StoreError::Database(err))
    }
}

/// Validated non-empty visible-ASCII credential string backed by a zeroizing [`SharedSecret`].
/// `Debug` is redacted and `Display` is intentionally omitted.
pub struct SecretText(SharedSecret);

impl SecretText {
    /// Validate and copy visible ASCII token bytes (`0x21..=0x7E`, `1..=max_bytes`).
    fn with_limit(raw: &str, max_bytes: usize) -> Result<Self, VaultError> {
        let bytes = raw.as_bytes();
        if bytes.is_empty()
            || bytes.len() > max_bytes
            || !bytes.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            return Err(VaultError::InvalidSecret);
        }
        Ok(Self(SharedSecret::from(bytes)))
    }

    /// Validate and copy visible ASCII token bytes (`1..=MAX_REFRESH_TOKEN_BYTES`).
    pub fn new(raw: &str) -> Result<Self, VaultError> {
        Self::with_limit(raw, MAX_REFRESH_TOKEN_BYTES)
    }

    /// Validate an access token (`1..=MAX_ACCESS_TOKEN_BYTES`, aligned with MCP 8 KiB request headers).
    pub fn new_access(raw: &str) -> Result<Self, VaultError> {
        Self::with_limit(raw, MAX_ACCESS_TOKEN_BYTES)
    }

    /// Validate a refresh token (`1..=MAX_REFRESH_TOKEN_BYTES`).
    pub fn new_refresh(raw: &str) -> Result<Self, VaultError> {
        Self::with_limit(raw, MAX_REFRESH_TOKEN_BYTES)
    }

    /// Validate a token according to its [`SecretKind`] ceiling.
    pub fn new_for_kind(kind: SecretKind, raw: &str) -> Result<Self, VaultError> {
        Self::with_limit(raw, kind.max_plaintext_bytes())
    }

    pub fn expose(&self) -> &str {
        // Every byte was verified in 0x21..=0x7E, which is always valid UTF-8.
        std::str::from_utf8(self.0.secret_bytes()).expect("validated ASCII secret")
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(..)")
    }
}

/// Which secret slot inside a connection row an envelope protects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    Access,
    Refresh,
}

impl SecretKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
        }
    }

    pub const fn max_plaintext_bytes(self) -> usize {
        match self {
            Self::Access => MAX_ACCESS_TOKEN_BYTES,
            Self::Refresh => MAX_REFRESH_TOKEN_BYTES,
        }
    }
}

/// Metadata cryptographically bound into every sealed secret's AAD.
#[derive(Clone, Copy, Debug)]
pub struct SecretBinding<'a> {
    pub connection_id: &'a str,
    pub scope_id: &'a str,
    pub account_id: &'a str,
    pub secret_kind: SecretKind,
    pub credential_generation: i64,
    pub allowed_scopes: &'a [String],
}

/// Versioned HKDF-SHA256 + AES-256-GCM ciphertext envelope. `Debug` never prints raw bytes.
#[derive(Clone)]
pub struct SealedSecret {
    pub key_id: String,
    pub salt: [u8; SALT_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSecret")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

// --- versioned keyring & HKDF + AES-256-GCM envelope -------------------------------------------

fn valid_key_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(crate::login::url_safe_byte)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingDocument {
    version: u32,
    active_key_id: String,
    keys: Vec<KeyEntryDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntryDocument {
    id: String,
    file: String,
}

/// Versioned master key ring loaded from separate filesystem / Kubernetes-mounted secret files.
pub struct VaultKeyRing {
    active_key_id: String,
    keys: Vec<(String, SharedSecret)>,
}

impl fmt::Debug for VaultKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<&str> = self.keys.iter().map(|(id, _)| id.as_str()).collect();
        f.debug_struct("VaultKeyRing")
            .field("active_key_id", &self.active_key_id)
            .field("key_ids", &ids)
            .finish()
    }
}

impl VaultKeyRing {
    /// Construct a validated key ring from in-memory `(key_id, key_bytes)` pairs.
    pub fn new(
        active_key_id: String,
        keys: Vec<(String, [u8; KEY_BYTES])>,
    ) -> Result<Self, VaultError> {
        let wrapped = keys
            .into_iter()
            .map(|(id, bytes)| (id, SharedSecret::from(bytes.as_slice())))
            .collect();
        Self::from_shared(active_key_id, wrapped)
    }

    fn from_shared(
        active_key_id: String,
        keys: Vec<(String, SharedSecret)>,
    ) -> Result<Self, VaultError> {
        if keys.is_empty() || keys.len() > MAX_KEYS || !valid_key_id(&active_key_id) {
            return Err(VaultError::Configuration("invalid vault keyring"));
        }
        let zeros = [0u8; KEY_BYTES];
        let mut seen_ids = BTreeSet::new();
        for (idx, (id, secret)) in keys.iter().enumerate() {
            if !valid_key_id(id) || !seen_ids.insert(id.as_str()) {
                return Err(VaultError::Configuration("invalid vault key identifier"));
            }
            let bytes = secret.secret_bytes();
            if bytes.len() != KEY_BYTES || bool::from(bytes.ct_eq(&zeros)) {
                return Err(VaultError::Configuration("invalid vault key material"));
            }
            for (_, other) in &keys[idx + 1..] {
                if bool::from(bytes.ct_eq(other.secret_bytes())) {
                    return Err(VaultError::Configuration("duplicate vault key material"));
                }
            }
        }
        if !seen_ids.contains(active_key_id.as_str()) {
            return Err(VaultError::Configuration("active vault key missing"));
        }
        Ok(Self {
            active_key_id,
            keys,
        })
    }

    /// Load a version-1 vault keyring configuration file referencing owner-only 32-byte key files.
    pub fn load_from_config(path: &Path) -> Result<Self, VaultError> {
        let doc_bytes = read_bounded_file(path, MAX_CONFIG_BYTES, false)?;
        let value = unique(&doc_bytes)
            .map_err(|_| VaultError::Configuration("invalid vault keyring document"))?;
        if !value.is_object() {
            return Err(VaultError::Configuration("invalid vault keyring document"));
        }
        let doc: KeyRingDocument = serde_json::from_value(value)
            .map_err(|_| VaultError::Configuration("invalid vault keyring document"))?;
        if doc.version != 1 || doc.keys.is_empty() || doc.keys.len() > MAX_KEYS {
            return Err(VaultError::Configuration("invalid vault keyring document"));
        }
        let mut loaded = Vec::with_capacity(doc.keys.len());
        for entry in doc.keys {
            if !valid_key_id(&entry.id) {
                return Err(VaultError::Configuration("invalid vault key identifier"));
            }
            let raw = read_bounded_file(Path::new(&entry.file), KEY_BYTES, true)?;
            let secret = SharedSecret::from(raw);
            if secret.secret_bytes().len() != KEY_BYTES {
                return Err(VaultError::Configuration("invalid vault key file"));
            }
            loaded.push((entry.id, secret));
        }
        Self::from_shared(doc.active_key_id, loaded)
    }

    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.iter().any(|(id, _)| id == key_id)
    }

    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.iter().map(|(id, _)| id.as_str()).collect()
    }

    fn key_bytes(&self, key_id: &str) -> Result<&[u8], VaultError> {
        self.keys
            .iter()
            .find(|(id, _)| id == key_id)
            .map(|(_, secret)| secret.secret_bytes())
            .ok_or(VaultError::UnknownKey)
    }

    /// Seal `plaintext` under the ring's `active_key_id` using HKDF-SHA256 + AES-256-GCM.
    pub fn seal(
        &self,
        binding: &SecretBinding<'_>,
        plaintext: &SecretText,
    ) -> Result<SealedSecret, VaultError> {
        if binding.credential_generation < 1 {
            return Err(VaultError::Crypto);
        }
        if plaintext.expose().len() > binding.secret_kind.max_plaintext_bytes() {
            return Err(VaultError::InvalidSecret);
        }
        let master = self.key_bytes(&self.active_key_id)?;
        let rng = SystemRandom::new();
        let mut salt = [0u8; SALT_BYTES];
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        rng.fill(&mut salt).map_err(|_| VaultError::Random)?;
        rng.fill(&mut nonce_bytes).map_err(|_| VaultError::Random)?;
        let dek = derive_dek(master, &salt)?;
        let aad_bytes = build_aad(binding, &self.active_key_id);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf = Vec::with_capacity(plaintext.expose().len() + aead::AES_256_GCM.tag_len());
        buf.extend_from_slice(plaintext.expose().as_bytes());
        let res = dek.seal_in_place_append_tag(nonce, aead::Aad::from(&aad_bytes), &mut buf);
        if res.is_err() {
            buf.fill(0);
            return Err(VaultError::Crypto);
        }
        Ok(SealedSecret {
            key_id: self.active_key_id.clone(),
            salt,
            nonce: nonce_bytes,
            ciphertext: buf,
        })
    }

    /// Authenticate and decrypt `sealed` using the key matching `sealed.key_id` and exact `binding`.
    pub fn open(
        &self,
        binding: &SecretBinding<'_>,
        sealed: &SealedSecret,
    ) -> Result<SecretText, VaultError> {
        let max_ct_len = binding.secret_kind.max_plaintext_bytes() + aead::AES_256_GCM.tag_len();
        if binding.credential_generation < 1
            || !(17..=max_ct_len).contains(&sealed.ciphertext.len())
        {
            return Err(VaultError::Crypto);
        }
        let master = self.key_bytes(&sealed.key_id)?;
        let dek = derive_dek(master, &sealed.salt)?;
        let aad_bytes = build_aad(binding, &sealed.key_id);
        let nonce = aead::Nonce::assume_unique_for_key(sealed.nonce);
        let mut buf = sealed.ciphertext.clone();
        let opened = match dek.open_in_place(nonce, aead::Aad::from(&aad_bytes), &mut buf) {
            Ok(plain) => plain,
            Err(_) => {
                buf.fill(0);
                return Err(VaultError::Crypto);
            }
        };
        let result = std::str::from_utf8(opened)
            .map_err(|_| VaultError::Crypto)
            .and_then(|s| SecretText::new_for_kind(binding.secret_kind, s));
        buf.fill(0);
        result
    }

    /// Derive a keyed HMAC-SHA256 digest binding secret authorization inputs for
    /// `authorizeConnection` idempotency replay detection without storing plaintext or
    /// reversible token material in `authorization_audit`, using the ring's `active_key_id`.
    pub fn idempotency_mac_hex(
        &self,
        connection_id: &str,
        scope_id: &str,
        access_token: &SecretText,
        refresh_token: Option<&SecretText>,
        granted_scopes: &[String],
        expires_at: Option<&str>,
    ) -> Result<String, VaultError> {
        self.idempotency_mac_hex_with_key(
            &self.active_key_id,
            connection_id,
            scope_id,
            access_token,
            refresh_token,
            granted_scopes,
            expires_at,
        )
    }

    /// Derive a keyed HMAC-SHA256 digest binding secret authorization inputs under an explicit
    /// `key_id` in this ring (returning [`VaultError::UnknownKey`] if `key_id` is not mounted).
    #[allow(clippy::too_many_arguments)]
    pub fn idempotency_mac_hex_with_key(
        &self,
        key_id: &str,
        connection_id: &str,
        scope_id: &str,
        access_token: &SecretText,
        refresh_token: Option<&SecretText>,
        granted_scopes: &[String],
        expires_at: Option<&str>,
    ) -> Result<String, VaultError> {
        let master = self.key_bytes(key_id)?;
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, IDEMPOTENCY_SALT).extract(master);
        let okm = prk
            .expand(&[IDEMPOTENCY_INFO], hmac::HMAC_SHA256)
            .map_err(|_| VaultError::Crypto)?;
        let mac_key = hmac::Key::from(okm);
        let mut ctx = hmac::Context::with_key(&mac_key);
        let push = |ctx: &mut hmac::Context, bytes: &[u8]| {
            ctx.update(&(bytes.len() as u64).to_be_bytes());
            ctx.update(bytes);
        };
        push(&mut ctx, connection_id.as_bytes());
        push(&mut ctx, scope_id.as_bytes());
        push(&mut ctx, access_token.expose().as_bytes());
        match refresh_token {
            Some(tok) => {
                ctx.update(&[1u8]);
                push(&mut ctx, tok.expose().as_bytes());
            }
            None => ctx.update(&[0u8]),
        }
        ctx.update(&(granted_scopes.len() as u64).to_be_bytes());
        for scope in granted_scopes {
            push(&mut ctx, scope.as_bytes());
        }
        match expires_at {
            Some(exp) => {
                ctx.update(&[1u8]);
                push(&mut ctx, exp.as_bytes());
            }
            None => ctx.update(&[0u8]),
        }
        let tag = ctx.sign();
        Ok(crate::authz::projects::hex(tag.as_ref()))
    }
}

fn derive_dek(master: &[u8], salt: &[u8; SALT_BYTES]) -> Result<aead::LessSafeKey, VaultError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(master);
    let okm = prk
        .expand(&[HKDF_INFO], &aead::AES_256_GCM)
        .map_err(|_| VaultError::Crypto)?;
    Ok(aead::LessSafeKey::new(aead::UnboundKey::from(okm)))
}

fn build_aad(binding: &SecretBinding<'_>, key_id: &str) -> Vec<u8> {
    let gen_bytes = binding.credential_generation.to_be_bytes();
    let count_bytes = (binding.allowed_scopes.len() as u64).to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(7 + binding.allowed_scopes.len());
    parts.push(binding.connection_id.as_bytes());
    parts.push(binding.scope_id.as_bytes());
    parts.push(binding.account_id.as_bytes());
    parts.push(binding.secret_kind.as_str().as_bytes());
    parts.push(key_id.as_bytes());
    parts.push(&gen_bytes);
    parts.push(&count_bytes);
    for scope in binding.allowed_scopes {
        parts.push(scope.as_bytes());
    }
    runs::identity(AAD_DOMAIN, &parts)
}

fn read_bounded_file(
    path: &Path,
    limit: usize,
    require_owner_only: bool,
) -> Result<Vec<u8>, VaultError> {
    if !path.is_absolute() {
        return Err(VaultError::Configuration("vault path must be absolute"));
    }
    let check_meta = |m: &fs::Metadata| -> Result<(), VaultError> {
        if !m.is_file() || m.len() > limit as u64 {
            return Err(VaultError::Configuration("invalid vault file"));
        }
        #[cfg(unix)]
        if require_owner_only {
            use std::os::unix::fs::PermissionsExt;
            if (m.permissions().mode() & 0o077) != 0 {
                return Err(VaultError::Configuration(
                    "vault key file must restrict group and world permissions",
                ));
            }
        }
        #[cfg(not(unix))]
        let _ = require_owner_only;
        Ok(())
    };
    let meta =
        fs::metadata(path).map_err(|_| VaultError::Configuration("vault file unreadable"))?;
    check_meta(&meta)?;
    let file =
        fs::File::open(path).map_err(|_| VaultError::Configuration("vault file unreadable"))?;
    let opened_meta = file
        .metadata()
        .map_err(|_| VaultError::Configuration("vault file unreadable"))?;
    check_meta(&opened_meta)?;
    let mut bytes = Vec::with_capacity(limit.min(KEY_BYTES) + 1);
    match file.take(limit as u64 + 1).read_to_end(&mut bytes) {
        Ok(len) if len <= limit => Ok(bytes),
        _ => {
            drop(SharedSecret::from(bytes));
            Err(VaultError::Configuration("invalid vault file"))
        }
    }
}

// --- input validation --------------------------------------------------------------------------

/// Valid `provider_kind`: 1..=64 ASCII bytes matching `^[a-z][a-z0-9._-]{0,63}$`.
pub fn validate_provider_kind(value: &str) -> Result<(), StoreError> {
    let b = value.as_bytes();
    if !(1..=64).contains(&b.len())
        || !b[0].is_ascii_lowercase()
        || !b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
    {
        return Err(StoreError::InvalidInput("provider_kind"));
    }
    Ok(())
}

/// Valid `account_id`: 1..=256 bytes, trimmed, no control characters, no `'*'`.
pub fn validate_account_id(value: &str) -> Result<(), StoreError> {
    if !(1..=256).contains(&value.len())
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('*')
    {
        return Err(StoreError::InvalidInput("account_id"));
    }
    Ok(())
}

/// Valid canonical `https://host[:port]` origin (DNS host only; no IP literal, path, query,
/// fragment, userinfo, trailing slash, uppercase, or default `:443`).
pub fn validate_endpoint_origin(value: &str) -> Result<(), StoreError> {
    if !(9..=256).contains(&value.len()) || !value.starts_with("https://") || value.ends_with('/') {
        return Err(StoreError::InvalidInput("origin"));
    }
    let with_slash = format!("{value}/");
    let ep = transport::endpoint(&with_slash).map_err(|_| StoreError::InvalidInput("origin"))?;
    if ep.path != "/" || format!("https://{}", ep.authority) != value {
        return Err(StoreError::InvalidInput("origin"));
    }
    Ok(())
}

/// Valid canonical scope token: 1..=128 ASCII bytes matching `^[a-z0-9][a-z0-9._:/-]{0,127}$`.
pub fn validate_scope_token(value: &str) -> Result<(), StoreError> {
    let b = value.as_bytes();
    if !(1..=128).contains(&b.len())
        || !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        || !b.iter().all(|&c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || matches!(c, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(StoreError::InvalidInput("scope"));
    }
    Ok(())
}

/// Returns `true` when `value` is a valid canonical lowercase ASCII scope token.
pub fn is_valid_scope_token(value: &str) -> bool {
    validate_scope_token(value).is_ok()
}

/// Validate, sort canonically, and reject duplicates on a scope array.
pub fn normalize_scopes(raw: &[String], allow_empty: bool) -> Result<Vec<String>, StoreError> {
    if raw.is_empty() {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(StoreError::InvalidInput("scopes"))
        };
    }
    if raw.len() > MAX_SCOPES {
        return Err(StoreError::InvalidInput("scopes"));
    }
    let mut set = BTreeSet::new();
    for s in raw {
        validate_scope_token(s)?;
        if !set.insert(s.clone()) {
            return Err(StoreError::InvalidInput("scopes"));
        }
    }
    Ok(set.into_iter().collect())
}

fn scopes_are_subset(granted: &[String], allowed: &[String]) -> bool {
    granted.iter().all(|g| allowed.binary_search(g).is_ok())
}

/// Canonical SHA-256 digest of a sorted scope slice so `authorization_audit.details` stays
/// strictly within its 4,096-byte JSONB ceiling even with 64 maximum-length scopes.
fn scopes_sha256_hex(scopes: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"openmettle.vault.scopes/1\0");
    hasher.update((scopes.len() as u64).to_be_bytes());
    for scope in scopes {
        hasher.update((scope.len() as u64).to_be_bytes());
        hasher.update(scope.as_bytes());
    }
    crate::authz::projects::hex(&hasher.finalize())
}

// --- connection metadata & authorization model -------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    PendingAuth,
    Authorized,
    ReauthRequired,
    Disconnected,
}

impl ConnectionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingAuth => "pending_auth",
            Self::Authorized => "authorized",
            Self::ReauthRequired => "reauth_required",
            Self::Disconnected => "disconnected",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "pending_auth" => Some(Self::PendingAuth),
            "authorized" => Some(Self::Authorized),
            "reauth_required" => Some(Self::ReauthRequired),
            "disconnected" => Some(Self::Disconnected),
            _ => None,
        }
    }
}

/// Non-secret metadata view returned to authorized callers on `/v1/connections*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionView {
    pub connection_id: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub project_id: Option<String>,
    pub provider_kind: String,
    pub account_id: String,
    pub origin: String,
    pub allowed_scopes: Vec<String>,
    pub granted_scopes: Vec<String>,
    pub state: ConnectionState,
    pub expires_at_us: Option<i64>,
    pub has_refresh: bool,
    pub credential_generation: i64,
    pub revocation_generation: i64,
    pub share_revision: i64,
    pub created_at_us: i64,
    pub updated_at_us: i64,
    pub disconnected_at_us: Option<i64>,
    pub can_manage: bool,
}

#[derive(Clone, Debug)]
pub struct CreateConnectionInput<'a> {
    pub scope_id: &'a str,
    pub provider_kind: &'a str,
    pub account_id: &'a str,
    pub origin: &'a str,
    pub allowed_scopes: &'a [String],
}

pub struct AuthorizeConnectionInput<'a> {
    pub access_token: &'a str,
    pub refresh_token: Option<&'a str>,
    pub granted_scopes: &'a [String],
    pub expires_at: Option<&'a str>,
}

impl fmt::Debug for AuthorizeConnectionInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizeConnectionInput")
            .field("granted_scopes", &self.granted_scopes)
            .field("has_refresh", &self.refresh_token.is_some())
            .field("has_expires_at", &self.expires_at.is_some())
            .finish()
    }
}

async fn load_active_shares(
    c: &mut PgConnection,
    connection_id: &str,
) -> Result<Vec<Grantee>, StoreError> {
    let rows = sqlx::query(
        "SELECT s.grantee_kind,
                coalesce(s.grantee_user_id::text, s.grantee_local_group_id::text, s.grantee_oidc_group_id)
           FROM openmettle.external_connection_shares s
           LEFT JOIN openmettle.users gu ON gu.id = s.grantee_user_id
           LEFT JOIN openmettle.local_groups gg ON gg.id = s.grantee_local_group_id
          WHERE s.connection_id = $1::uuid
            AND s.active
            AND gu.disabled_at IS NULL
            AND gg.disabled_at IS NULL
          ORDER BY s.id",
    )
    .bind(connection_id)
    .fetch_all(c)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let kind: &str = row.try_get(0)?;
        let id: Option<String> = row.try_get(1)?;
        match (kind, id) {
            ("user", Some(id)) => out.push(Grantee::User(id)),
            ("local_group", Some(id)) => out.push(Grantee::LocalGroup(id)),
            ("oidc_group", Some(id)) => out.push(Grantee::OidcGroup(id)),
            ("project", None) => out.push(Grantee::Project),
            _ => {}
        }
    }
    Ok(out)
}

fn principal_matches_shares(principal: &Principal, scope: &Scope, shares: &[Grantee]) -> bool {
    shares.iter().any(|grantee| match (scope, grantee) {
        (Scope::Project(_), Grantee::Project) => true,
        (Scope::Personal { .. }, Grantee::Project) => false,
        (Scope::Project(project), g @ (Grantee::LocalGroup(_) | Grantee::OidcGroup(_))) => {
            project.group_is_member(g) && principal.matches(g)
        }
        (_, g) => principal.matches(g),
    })
}

/// Returns `Some(can_manage)` if `principal` may read the connection's metadata, or `None` to
/// conceal it (`404 not_found`). Never consults `account_admin`.
fn evaluate_read_access(principal: &Principal, scope: &Scope, shares: &[Grantee]) -> Option<bool> {
    if !principal.is_active() {
        return None;
    }
    match scope {
        Scope::Personal {
            scope_id,
            owner_user_id,
        } => {
            if *scope_id == principal.personal_scope_id && *owner_user_id == principal.user_id {
                Some(true)
            } else if principal_matches_shares(principal, scope, shares) {
                Some(false)
            } else {
                None
            }
        }
        Scope::Project(project) => {
            let role = project.role_of(principal)?;
            if role == ProjectRole::Owner {
                Some(true)
            } else if principal_matches_shares(principal, scope, shares) {
                Some(false)
            } else {
                None
            }
        }
    }
}

/// Require scope-level management authority for creating a new connection:
/// personal scope owner (`404` otherwise), or project `Owner` (`403` for visible non-owner
/// project members, `404` for non-members).
fn require_scope_manager(principal: &Principal, scope: &Scope) -> Result<(), StoreError> {
    authz::require(Some(principal)).map_err(StoreError::Denied)?;
    match scope {
        Scope::Personal {
            scope_id,
            owner_user_id,
        } => {
            if *scope_id == principal.personal_scope_id && *owner_user_id == principal.user_id {
                Ok(())
            } else {
                Err(CONCEALED)
            }
        }
        Scope::Project(project) => match project.role_of(principal) {
            Some(ProjectRole::Owner) => Ok(()),
            Some(_) => Err(StoreError::Denied(DenialReason::Policy(
                PolicyReason::InsufficientRole,
            ))),
            None => Err(CONCEALED),
        },
    }
}

/// Require management authority on an existing connection. Mirrors [`evaluate_read_access`] so
/// unshared project connections are concealed (`404 not_found`) even from project `Editor` and
/// `Viewer` members, while visible non-managers (active `'use'` share holders) receive `403`.
fn require_connection_manager(
    principal: &Principal,
    scope: &Scope,
    shares: &[Grantee],
) -> Result<(), StoreError> {
    authz::require(Some(principal)).map_err(StoreError::Denied)?;
    match evaluate_read_access(principal, scope, shares) {
        Some(true) => Ok(()),
        Some(false) => Err(StoreError::Denied(DenialReason::Policy(
            PolicyReason::NotShareManager,
        ))),
        None => Err(CONCEALED),
    }
}

/// Execution-time credential / reconcile authority check.
/// - Personal scope: personal owner OR active share recipient.
/// - Project scope: active project member with role `>= Editor` AND (`Owner` OR active share).
fn can_execute_connection(principal: &Principal, scope: &Scope, shares: &[Grantee]) -> bool {
    if !principal.is_active() {
        return false;
    }
    match scope {
        Scope::Personal {
            scope_id,
            owner_user_id,
        } => {
            (*scope_id == principal.personal_scope_id && *owner_user_id == principal.user_id)
                || principal_matches_shares(principal, scope, shares)
        }
        Scope::Project(project) => match project.role_of(principal) {
            Some(ProjectRole::Owner) => true,
            Some(ProjectRole::Editor) => principal_matches_shares(principal, scope, shares),
            _ => false,
        },
    }
}

// --- API store operations (openmettle_api) -----------------------------------------------------

#[derive(Clone)]
struct LocatedConnection {
    scope_id: String,
    personal_owner: Option<String>,
    project_id: Option<String>,
}

async fn locate_connection(
    c: &mut PgConnection,
    connection_id: &str,
) -> Result<Option<LocatedConnection>, StoreError> {
    let row = sqlx::query(
        "SELECT c.scope_id::text, s.personal_user_id::text, s.project_id::text
           FROM openmettle.external_connections c
           JOIN openmettle.scopes s ON s.id = c.scope_id
          WHERE c.id = $1::uuid",
    )
    .bind(connection_id)
    .fetch_optional(c)
    .await?;
    row.map(|r| {
        Ok(LocatedConnection {
            scope_id: r.try_get(0)?,
            personal_owner: r.try_get(1)?,
            project_id: r.try_get(2)?,
        })
    })
    .transpose()
}

/// Lock scope + actor authority in canonical order
/// (`projects -> login_providers -> local_identity_approvals -> users`), returning
/// `Ok(archived)` or concealing missing/deleted scopes after verifying actor is active.
async fn lock_scope_and_actor(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    personal_owner: Option<&str>,
    project_id: Option<&str>,
) -> Result<bool, StoreError> {
    match (personal_owner, project_id) {
        (_, Some(project)) => match lock_project(c, project).await? {
            Some(locked) if !locked.deleted => {
                lock_actor_authority(c, ctx).await?;
                Ok(locked.archived)
            }
            _ => {
                lock_actor_authority(c, ctx).await?;
                post_lock_acting(c, ctx).await?;
                Err(CONCEALED)
            }
        },
        (Some(owner), None) => {
            lock_actor_approval(c, ctx.actor_approval_id).await?;
            if owner == ctx.actor_user_id {
                sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE")
                    .bind(owner)
                    .fetch_one(&mut *c)
                    .await?;
            } else {
                sqlx::query("SELECT FROM openmettle.users WHERE id = $1::uuid FOR SHARE")
                    .bind(ctx.actor_user_id)
                    .execute(&mut *c)
                    .await?;
            }
            Ok(false)
        }
        (None, None) => {
            lock_actor_authority(c, ctx).await?;
            post_lock_acting(c, ctx).await?;
            Err(CONCEALED)
        }
    }
}

async fn hydrate_scope(
    c: &mut PgConnection,
    scope_id: &str,
    personal_owner: Option<&str>,
    project_id: Option<&str>,
    now_ms: i64,
) -> Result<Scope, StoreError> {
    match (personal_owner, project_id) {
        (Some(owner), _) => Ok(Scope::Personal {
            scope_id: scope_id.to_owned(),
            owner_user_id: owner.to_owned(),
        }),
        (None, Some(project)) => Ok(Scope::Project(
            project_in(c, project, scope_id, now_ms).await?,
        )),
        (None, None) => Err(CONCEALED),
    }
}

/// Register a new external connection in `pending_auth` state (no credentials stored yet).
/// Personal connections require the personal scope owner; project connections require a project
/// `Owner` and refuse archived or deleted projects.
pub async fn create_connection(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    input: &CreateConnectionInput<'_>,
) -> Result<WriteOutcome, StoreError> {
    uuid(input.scope_id, "scope_id")?;
    validate_provider_kind(input.provider_kind)?;
    validate_account_id(input.account_id)?;
    validate_endpoint_origin(input.origin)?;
    let allowed_scopes = normalize_scopes(input.allowed_scopes, false)?;

    let change = Change {
        action: "connection.created",
        target_kind: "external_connection",
        target_id: None,
        details: json!({
            "scope_id": input.scope_id,
            "provider_kind": input.provider_kind,
            "account_id": input.account_id,
            "origin": input.origin,
            "allowed_scope_count": allowed_scopes.len(),
            "allowed_scopes_sha256": scopes_sha256_hex(&allowed_scopes),
        }),
    };

    transact(c, ctx, async |tx| {
        let c = tx.connection()?;
        let scope_row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT kind, personal_user_id::text, project_id::text
               FROM openmettle.scopes
              WHERE id = $1::uuid",
        )
        .bind(input.scope_id)
        .fetch_optional(&mut *c)
        .await?;
        let Some((scope_kind, personal_owner, project_id)) = scope_row else {
            lock_actor_authority(c, ctx).await?;
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        let archived =
            lock_scope_and_actor(c, ctx, personal_owner.as_deref(), project_id.as_deref()).await?;
        let (actor, post_lock_ctx) = post_lock_acting(c, ctx).await?;
        let scope = hydrate_scope(
            c,
            input.scope_id,
            personal_owner.as_deref(),
            project_id.as_deref(),
            post_lock_ctx.now_ms,
        )
        .await?;
        require_scope_manager(&actor, &scope)?;
        if archived {
            return Err(ARCHIVED);
        }
        let outcome = record(c, &post_lock_ctx, &change).await?;
        if let WriteOutcome::Applied { target_id } = &outcome {
            sqlx::query(
                "INSERT INTO openmettle.external_connections
                     (id, scope_id, scope_kind, owner_user_id, provider_kind, account_id,
                      endpoint_origin, allowed_scopes)
                 VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, $7, $8)",
            )
            .bind(target_id)
            .bind(input.scope_id)
            .bind(&scope_kind)
            .bind(&actor.user_id)
            .bind(input.provider_kind)
            .bind(input.account_id)
            .bind(input.origin)
            .bind(&allowed_scopes)
            .execute(&mut *c)
            .await?;
        }
        let (fresh_actor, fresh_ctx) = post_lock_acting(c, &post_lock_ctx).await?;
        let fresh_scope = hydrate_scope(
            c,
            input.scope_id,
            personal_owner.as_deref(),
            project_id.as_deref(),
            fresh_ctx.now_ms,
        )
        .await?;
        require_scope_manager(&fresh_actor, &fresh_scope)?;
        Ok(outcome)
    })
    .await
}

/// Read one external connection's non-secret metadata for an authorized principal (`openmettle_api`).
/// Conceals unauthorized, missing, or deleted-project connections with `NotFound`.
pub async fn read_connection(
    c: &mut PgConnection,
    principal: &Principal,
    connection_id: &str,
    now_ms: i64,
) -> Result<ConnectionView, StoreError> {
    authz::require(Some(principal)).map_err(StoreError::Denied)?;
    uuid(connection_id, "connection_id")?;
    let Some(row) = sqlx::query(
        "SELECT c.id::text, c.scope_kind, c.scope_id::text, s.personal_user_id::text,
                s.project_id::text, coalesce(ps.deleted_at IS NOT NULL, false),
                c.provider_kind, c.account_id, c.endpoint_origin,
                c.allowed_scopes, c.granted_scopes, c.state,
                CASE WHEN c.expires_at IS NOT NULL
                     THEN (extract(epoch FROM c.expires_at) * 1000000)::bigint END,
                c.has_refresh, c.credential_generation, c.revocation_generation, c.share_revision,
                (extract(epoch FROM c.created_at) * 1000000)::bigint,
                (extract(epoch FROM c.updated_at) * 1000000)::bigint,
                CASE WHEN c.disconnected_at IS NOT NULL
                     THEN (extract(epoch FROM c.disconnected_at) * 1000000)::bigint END
           FROM openmettle.external_connections c
           JOIN openmettle.scopes s ON s.id = c.scope_id
           LEFT JOIN openmettle.project_settings ps ON ps.project_id = s.project_id
          WHERE c.id = $1::uuid",
    )
    .bind(connection_id)
    .fetch_optional(&mut *c)
    .await?
    else {
        return Err(CONCEALED);
    };
    let deleted: bool = row.try_get(5)?;
    if deleted {
        return Err(CONCEALED);
    }
    let scope_id: String = row.try_get(2)?;
    let personal_owner: Option<String> = row.try_get(3)?;
    let project_id: Option<String> = row.try_get(4)?;
    let scope = hydrate_scope(
        c,
        &scope_id,
        personal_owner.as_deref(),
        project_id.as_deref(),
        now_ms,
    )
    .await?;
    let shares = load_active_shares(c, connection_id).await?;
    let Some(can_manage) = evaluate_read_access(principal, &scope, &shares) else {
        return Err(CONCEALED);
    };
    let state_raw: String = row.try_get(11)?;
    let state = ConnectionState::parse(&state_raw).ok_or_else(|| {
        StoreError::Database(sqlx::Error::Protocol("unknown connection state".into()))
    })?;
    Ok(ConnectionView {
        connection_id: row.try_get(0)?,
        scope_kind: row.try_get(1)?,
        scope_id,
        project_id,
        provider_kind: row.try_get(6)?,
        account_id: row.try_get(7)?,
        origin: row.try_get(8)?,
        allowed_scopes: row.try_get(9)?,
        granted_scopes: row.try_get(10)?,
        state,
        expires_at_us: row.try_get(12)?,
        has_refresh: row.try_get(13)?,
        credential_generation: row.try_get(14)?,
        revocation_generation: row.try_get(15)?,
        share_revision: row.try_get(16)?,
        created_at_us: row.try_get(17)?,
        updated_at_us: row.try_get(18)?,
        disconnected_at_us: row.try_get(19)?,
        can_manage,
    })
}

/// Write-only encrypted storage of access and optional refresh credentials on an existing
/// connection (`pending_auth`, `reauth_required`, or `authorized` -> `authorized`).
/// Refuses scope widening (`granted_scopes` must be a subset of `allowed_scopes`), disconnected
/// connections (`409`), archived projects (`409`), and closed restore gates (`503`).
pub async fn authorize_connection(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    keyring: &VaultKeyRing,
    connection_id: &str,
    input: &AuthorizeConnectionInput<'_>,
) -> Result<WriteOutcome, VaultError> {
    uuid(connection_id, "connection_id")?;
    let access_secret = SecretText::new_access(input.access_token)?;
    let refresh_secret = input
        .refresh_token
        .map(SecretText::new_refresh)
        .transpose()?;
    let granted_scopes = normalize_scopes(input.granted_scopes, false)?;
    if let Some(exp) = input.expires_at
        && (exp.is_empty() || exp.len() > 64 || !exp.is_ascii())
    {
        return Err(StoreError::InvalidInput("expires_at").into());
    }

    let result: Result<WriteOutcome, VaultError> = async {
        ctx.validate()?;
        let mut tx = store::begin(c).await?;
        let gate = match tx.connection() {
            Ok(conn) => crate::restore::require_open_gate(conn).await,
            Err(err) => Err(err.into()),
        };
        if let Err(err) = gate {
            tx.rollback().await.map_err(StoreError::from)?;
            return Err(err.into());
        }
        let body: Result<WriteOutcome, VaultError> = async {
            let conn = tx.connection().map_err(StoreError::from)?;
            let Some(located) = locate_connection(conn, connection_id).await? else {
                lock_actor_authority(conn, ctx).await?;
                post_lock_acting(conn, ctx).await?;
                return Err(CONCEALED.into());
            };
            let archived = lock_scope_and_actor(
                conn,
                ctx,
                located.personal_owner.as_deref(),
                located.project_id.as_deref(),
            )
            .await?;
            // Lock the connection row after scope/actor in canonical order.
            let locked_row = sqlx::query(
                "SELECT account_id, allowed_scopes, state, credential_generation
                   FROM openmettle.external_connections
                  WHERE id = $1::uuid
                    FOR NO KEY UPDATE",
            )
            .bind(connection_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(StoreError::from)?;
            let Some(locked_row) = locked_row else {
                post_lock_acting(conn, ctx).await?;
                return Err(CONCEALED.into());
            };
            let (actor, post_lock_ctx) = post_lock_acting(conn, ctx).await?;
            let scope = hydrate_scope(
                conn,
                &located.scope_id,
                located.personal_owner.as_deref(),
                located.project_id.as_deref(),
                post_lock_ctx.now_ms,
            )
            .await?;
            let shares = load_active_shares(conn, connection_id).await?;
            require_connection_manager(&actor, &scope, &shares)?;
            if archived {
                return Err(ARCHIVED.into());
            }
            let account_id: String = locked_row.try_get(0)?;
            let allowed_scopes: Vec<String> = locked_row.try_get(1)?;
            let state: String = locked_row.try_get(2)?;
            let cred_gen: i64 = locked_row.try_get(3)?;
            if !scopes_are_subset(&granted_scopes, &allowed_scopes) {
                return Err(VaultError::ScopeWidening);
            }
            // If an audit row already exists for `(actor, request_key)` on this connection,
            // verify the candidate MAC under the stored `mac_key_id` in constant time so
            // retries remain idempotent across `active_key_id` rotations while failing closed
            // (`VaultError::UnknownKey` -> `503 provisioning`) if that historical key was retired.
            let existing_audit: Option<(String, String, String, String)> = sqlx::query_as(
                "SELECT action, target_kind, target_id, details::text
                   FROM openmettle.authorization_audit
                  WHERE actor_user_id = $1::uuid AND request_key = $2",
            )
            .bind(post_lock_ctx.actor_user_id)
            .bind(post_lock_ctx.request_key)
            .fetch_optional(&mut *conn)
            .await
            .map_err(StoreError::from)?;
            let (mac_key_id, credentials_mac) = match existing_audit {
                Some((action, target_kind, target_id, details_raw))
                    if action == "connection.authorized"
                        && target_kind == "external_connection"
                        && target_id == connection_id =>
                {
                    let existing_details: Value =
                        serde_json::from_str(&details_raw).unwrap_or(Value::Null);
                    let stored_key_id = existing_details
                        .get("mac_key_id")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| keyring.active_key_id());
                    let stored_mac = existing_details
                        .get("credentials_mac")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let candidate_mac = keyring.idempotency_mac_hex_with_key(
                        stored_key_id,
                        connection_id,
                        &located.scope_id,
                        &access_secret,
                        refresh_secret.as_ref(),
                        &granted_scopes,
                        input.expires_at,
                    )?;
                    if !bool::from(candidate_mac.as_bytes().ct_eq(stored_mac.as_bytes())) {
                        return Err(StoreError::Conflict(store::KEY_REUSED).into());
                    }
                    (stored_key_id.to_owned(), candidate_mac)
                }
                _ => {
                    let active_key_id = keyring.active_key_id().to_owned();
                    let mac = keyring.idempotency_mac_hex_with_key(
                        &active_key_id,
                        connection_id,
                        &located.scope_id,
                        &access_secret,
                        refresh_secret.as_ref(),
                        &granted_scopes,
                        input.expires_at,
                    )?;
                    (active_key_id, mac)
                }
            };
            let change = Change {
                action: "connection.authorized",
                target_kind: "external_connection",
                target_id: Some(connection_id.to_owned()),
                details: json!({
                    "granted_scope_count": granted_scopes.len(),
                    "granted_scopes_sha256": scopes_sha256_hex(&granted_scopes),
                    "has_refresh": refresh_secret.is_some(),
                    "expires_at": input.expires_at,
                    "mac_key_id": mac_key_id,
                    "credentials_mac": credentials_mac,
                }),
            };
            let outcome = record(conn, &post_lock_ctx, &change).await?;
            if matches!(outcome, WriteOutcome::Applied { .. }) {
                if state == ConnectionState::Disconnected.as_str() {
                    return Err(StoreError::Conflict("connection is disconnected").into());
                }
                let next_gen = cred_gen + 1;
                let access_sealed = keyring.seal(
                    &SecretBinding {
                        connection_id,
                        scope_id: &located.scope_id,
                        account_id: &account_id,
                        secret_kind: SecretKind::Access,
                        credential_generation: next_gen,
                        allowed_scopes: &allowed_scopes,
                    },
                    &access_secret,
                )?;
                let refresh_sealed = refresh_secret
                    .as_ref()
                    .map(|secret| {
                        keyring.seal(
                            &SecretBinding {
                                connection_id,
                                scope_id: &located.scope_id,
                                account_id: &account_id,
                                secret_kind: SecretKind::Refresh,
                                credential_generation: next_gen,
                                allowed_scopes: &allowed_scopes,
                            },
                            secret,
                        )
                    })
                    .transpose()?;
                sqlx::query(
                    "UPDATE openmettle.external_connections
                        SET granted_scopes = $2,
                            state = 'authorized',
                            expires_at = $3::timestamptz,
                            encryption_key_id = $4,
                            access_salt = $5,
                            access_nonce = $6,
                            access_ciphertext = $7,
                            refresh_salt = $8,
                            refresh_nonce = $9,
                            refresh_ciphertext = $10,
                            credential_generation = $11,
                            refresh_claim_token = NULL,
                            refresh_lease_until = NULL,
                            updated_at = clock_timestamp()
                      WHERE id = $1::uuid",
                )
                .bind(connection_id)
                .bind(&granted_scopes)
                .bind(input.expires_at)
                .bind(&access_sealed.key_id)
                .bind(access_sealed.salt.as_slice())
                .bind(access_sealed.nonce.as_slice())
                .bind(access_sealed.ciphertext.as_slice())
                .bind(refresh_sealed.as_ref().map(|s| s.salt.as_slice()))
                .bind(refresh_sealed.as_ref().map(|s| s.nonce.as_slice()))
                .bind(refresh_sealed.as_ref().map(|s| s.ciphertext.as_slice()))
                .bind(next_gen)
                .execute(&mut *conn)
                .await?;
            }
            let (fresh_actor, fresh_ctx) = post_lock_acting(conn, &post_lock_ctx).await?;
            let fresh_scope = hydrate_scope(
                conn,
                &located.scope_id,
                located.personal_owner.as_deref(),
                located.project_id.as_deref(),
                fresh_ctx.now_ms,
            )
            .await?;
            let fresh_shares = load_active_shares(conn, connection_id).await?;
            require_connection_manager(&fresh_actor, &fresh_scope, &fresh_shares)?;
            Ok(outcome)
        }
        .await;
        match body {
            Ok(outcome) => {
                tx.commit().await.map_err(StoreError::from)?;
                Ok(outcome)
            }
            Err(err) => {
                tx.rollback().await.map_err(StoreError::from)?;
                Err(err)
            }
        }
    }
    .await;
    result
}

/// Immediately disconnect a connection, wiping all encrypted credential columns and advancing
/// `revocation_generation` to fence any concurrent worker refresh. Allowed on archived projects.
pub async fn disconnect_connection(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    connection_id: &str,
) -> Result<WriteOutcome, StoreError> {
    uuid(connection_id, "connection_id")?;
    let change = Change {
        action: "connection.disconnected",
        target_kind: "external_connection",
        target_id: Some(connection_id.to_owned()),
        details: json!({}),
    };
    transact(c, ctx, async |tx| {
        let c = tx.connection()?;
        let Some(located) = locate_connection(c, connection_id).await? else {
            lock_actor_authority(c, ctx).await?;
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        let _archived = lock_scope_and_actor(
            c,
            ctx,
            located.personal_owner.as_deref(),
            located.project_id.as_deref(),
        )
        .await?;
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM openmettle.external_connections WHERE id = $1::uuid FOR NO KEY UPDATE",
        )
        .bind(connection_id)
        .fetch_optional(&mut *c)
        .await?;
        let Some(state) = state else {
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        let (actor, post_lock_ctx) = post_lock_acting(c, ctx).await?;
        let scope = hydrate_scope(
            c,
            &located.scope_id,
            located.personal_owner.as_deref(),
            located.project_id.as_deref(),
            post_lock_ctx.now_ms,
        )
        .await?;
        let shares = load_active_shares(c, connection_id).await?;
        require_connection_manager(&actor, &scope, &shares)?;
        let outcome = record(c, &post_lock_ctx, &change).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            if state == ConnectionState::Disconnected.as_str() {
                return Err(UNCHANGED);
            }
            sqlx::query(
                "UPDATE openmettle.external_connections
                    SET granted_scopes = ARRAY[]::text[],
                        state = 'disconnected',
                        expires_at = NULL,
                        encryption_key_id = NULL,
                        access_salt = NULL,
                        access_nonce = NULL,
                        access_ciphertext = NULL,
                        refresh_salt = NULL,
                        refresh_nonce = NULL,
                        refresh_ciphertext = NULL,
                        revocation_generation = revocation_generation + 1,
                        refresh_claim_token = NULL,
                        refresh_lease_until = NULL,
                        updated_at = clock_timestamp(),
                        disconnected_at = clock_timestamp()
                  WHERE id = $1::uuid",
            )
            .bind(connection_id)
            .execute(&mut *c)
            .await?;
        }
        let (fresh_actor, fresh_ctx) = post_lock_acting(c, &post_lock_ctx).await?;
        let fresh_scope = hydrate_scope(
            c,
            &located.scope_id,
            located.personal_owner.as_deref(),
            located.project_id.as_deref(),
            fresh_ctx.now_ms,
        )
        .await?;
        let fresh_shares = load_active_shares(c, connection_id).await?;
        require_connection_manager(&fresh_actor, &fresh_scope, &fresh_shares)?;
        Ok(outcome)
    })
    .await
}

async fn validate_share_recipient(
    c: &mut PgConnection,
    scope: &Scope,
    grantee: &Grantee,
    now_ms: i64,
) -> Result<(), StoreError> {
    let invalid = || StoreError::Denied(DenialReason::Policy(PolicyReason::InvalidGrantee));
    let not_member = || StoreError::Denied(DenialReason::Policy(PolicyReason::GranteeNotMember));
    match (scope, grantee) {
        (Scope::Personal { .. }, Grantee::Project) => Err(invalid()),
        (Scope::Personal { owner_user_id, .. }, Grantee::User(id)) if id == owner_user_id => {
            Err(invalid())
        }
        (Scope::Personal { .. }, Grantee::User(id)) => {
            let recipient = recipient_principal(c, id, None, now_ms).await?;
            if recipient.is_active() {
                Ok(())
            } else {
                Err(invalid())
            }
        }
        (Scope::Personal { .. }, Grantee::LocalGroup(_)) => recipient_enabled(c, grantee).await,
        (Scope::Personal { .. }, Grantee::OidcGroup(_)) => Ok(()),
        (Scope::Project(_), Grantee::Project) => Ok(()),
        (Scope::Project(project), Grantee::User(id)) => {
            let recipient = recipient_principal(c, id, Some(project), now_ms).await?;
            if recipient.is_active() && project.role_of(&recipient).is_some() {
                Ok(())
            } else {
                Err(not_member())
            }
        }
        (Scope::Project(project), Grantee::LocalGroup(_)) => {
            recipient_enabled(c, grantee).await?;
            if project.group_is_member(grantee) {
                Ok(())
            } else {
                Err(not_member())
            }
        }
        (Scope::Project(project), Grantee::OidcGroup(_)) => {
            if project.group_is_member(grantee) {
                Ok(())
            } else {
                Err(not_member())
            }
        }
    }
}

/// Explicitly grant execution `'use'` access on an external connection without exposing credentials.
pub async fn share_connection(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    connection_id: &str,
    grantee: &Grantee,
) -> Result<WriteOutcome, StoreError> {
    connection_share_change(c, ctx, connection_id, grantee, true).await
}

/// Immediately revoke a connection share, cutting off subsequent execution and reconciliation.
pub async fn revoke_connection_share(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    connection_id: &str,
    grantee: &Grantee,
) -> Result<WriteOutcome, StoreError> {
    connection_share_change(c, ctx, connection_id, grantee, false).await
}

async fn connection_share_change(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    connection_id: &str,
    grantee: &Grantee,
    grant: bool,
) -> Result<WriteOutcome, StoreError> {
    uuid(connection_id, "connection_id")?;
    grantee_input(grantee)?;
    let change = Change {
        action: if grant {
            "connection.shared"
        } else {
            "connection.share_revoked"
        },
        target_kind: "external_connection",
        target_id: Some(connection_id.to_owned()),
        details: grantee_details(grantee, "access", grant.then_some("use")),
    };
    let (kind, user_id, local_group_id, oidc_group_id) = grants::Grantee::from(grantee).columns();
    transact(c, ctx, async |tx| {
        let c = tx.connection()?;
        let Some(located) = locate_connection(c, connection_id).await? else {
            lock_actor_authority(c, ctx).await?;
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        let archived = lock_scope_and_actor(
            c,
            ctx,
            located.personal_owner.as_deref(),
            located.project_id.as_deref(),
        )
        .await?;
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM openmettle.external_connections WHERE id = $1::uuid FOR NO KEY UPDATE",
        )
        .bind(connection_id)
        .fetch_optional(&mut *c)
        .await?;
        let Some(state) = state else {
            post_lock_acting(c, ctx).await?;
            return Err(CONCEALED);
        };
        let (actor, post_lock_ctx) = post_lock_acting(c, ctx).await?;
        let scope = hydrate_scope(
            c,
            &located.scope_id,
            located.personal_owner.as_deref(),
            located.project_id.as_deref(),
            post_lock_ctx.now_ms,
        )
        .await?;
        let shares = load_active_shares(c, connection_id).await?;
        require_connection_manager(&actor, &scope, &shares)?;
        if grant {
            if archived {
                return Err(ARCHIVED);
            }
            if state == ConnectionState::Disconnected.as_str() {
                return Err(StoreError::Conflict("connection is disconnected"));
            }
            validate_share_recipient(c, &scope, grantee, post_lock_ctx.now_ms).await?;
        }
        let outcome = record(c, &post_lock_ctx, &change).await?;
        if matches!(outcome, WriteOutcome::Applied { .. }) {
            if grant {
                let changed = sqlx::query(
                    "INSERT INTO openmettle.external_connection_shares AS s
                         (connection_id, scope_id, grantee_kind, grantee_user_id,
                          grantee_local_group_id, grantee_oidc_group_id,
                          access, active, updated_by_user_id)
                     VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5::uuid, $6, 'use', true, $7::uuid)
                     ON CONFLICT ON CONSTRAINT external_connection_shares_unique_key DO UPDATE
                        SET active = true,
                            revision = s.revision + 1,
                            updated_at = clock_timestamp(),
                            updated_by_user_id = $7::uuid
                      WHERE NOT s.active",
                )
                .bind(connection_id)
                .bind(&located.scope_id)
                .bind(kind)
                .bind(user_id)
                .bind(local_group_id)
                .bind(oidc_group_id)
                .bind(&actor.user_id)
                .execute(&mut *c)
                .await?
                .rows_affected();
                if changed == 0 {
                    return Err(UNCHANGED);
                }
                sqlx::query(
                    "UPDATE openmettle.external_connections
                        SET share_revision = share_revision + 1,
                            updated_at = clock_timestamp()
                      WHERE id = $1::uuid",
                )
                .bind(connection_id)
                .execute(&mut *c)
                .await?;
            } else {
                let changed = sqlx::query(
                    "UPDATE openmettle.external_connection_shares
                        SET active = false,
                            revision = revision + 1,
                            updated_at = clock_timestamp(),
                            updated_by_user_id = $6::uuid
                      WHERE connection_id = $1::uuid
                        AND grantee_kind = $2
                        AND grantee_user_id IS NOT DISTINCT FROM $3::uuid
                        AND grantee_local_group_id IS NOT DISTINCT FROM $4::uuid
                        AND grantee_oidc_group_id IS NOT DISTINCT FROM $5
                        AND active",
                )
                .bind(connection_id)
                .bind(kind)
                .bind(user_id)
                .bind(local_group_id)
                .bind(oidc_group_id)
                .bind(&actor.user_id)
                .execute(&mut *c)
                .await?
                .rows_affected();
                if changed == 0 {
                    return Err(UNCHANGED);
                }
                sqlx::query(
                    "UPDATE openmettle.external_connections
                        SET share_revision = share_revision + 1,
                            revocation_generation = revocation_generation + 1,
                            updated_at = clock_timestamp()
                      WHERE id = $1::uuid",
                )
                .bind(connection_id)
                .execute(&mut *c)
                .await?;
            }
        }
        let (fresh_actor, fresh_ctx) = post_lock_acting(c, &post_lock_ctx).await?;
        let fresh_scope = hydrate_scope(
            c,
            &located.scope_id,
            located.personal_owner.as_deref(),
            located.project_id.as_deref(),
            fresh_ctx.now_ms,
        )
        .await?;
        let fresh_shares = load_active_shares(c, connection_id).await?;
        require_connection_manager(&fresh_actor, &fresh_scope, &fresh_shares)?;
        if grant {
            validate_share_recipient(c, &fresh_scope, grantee, fresh_ctx.now_ms).await?;
        }
        Ok(outcome)
    })
    .await
}

// --- owner-operated vault status & online batch rotation (openmettle-admin) --------------------

/// Redacted summary of connection states and encryption key versions (zero secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStatusReport {
    pub by_state: BTreeMap<String, i64>,
    pub by_key_id: BTreeMap<String, i64>,
    pub total_connections: i64,
    pub total_encrypted: i64,
}

/// Summary of one `openmettle-admin vault rotate` run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRotateReport {
    pub target_key_id: String,
    pub rotated_rows: i64,
    pub skipped_rows: i64,
    pub deferred_active_refresh: i64,
    pub replayed: bool,
}

/// Aggregate connection states and encryption key versions (`openmettle_owner`).
pub async fn vault_status(pool: &PgPool) -> Result<VaultStatusReport, VaultError> {
    let state_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT state, count(*) FROM openmettle.external_connections GROUP BY state ORDER BY state",
    )
    .fetch_all(pool)
    .await?;
    let key_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT encryption_key_id, count(*)
           FROM openmettle.external_connections
          WHERE encryption_key_id IS NOT NULL
          GROUP BY encryption_key_id
          ORDER BY encryption_key_id",
    )
    .fetch_all(pool)
    .await?;
    let mut by_state = BTreeMap::new();
    let mut total_connections = 0i64;
    for (state, count) in state_rows {
        total_connections += count;
        by_state.insert(state, count);
    }
    let mut by_key_id = BTreeMap::new();
    let mut total_encrypted = 0i64;
    for (key_id, count) in key_rows {
        total_encrypted += count;
        by_key_id.insert(key_id, count);
    }
    Ok(VaultStatusReport {
        by_state,
        by_key_id,
        total_connections,
        total_encrypted,
    })
}

/// Re-encrypt authorized connection credentials from historical `key_id`s to
/// `keyring.active_key_id()` in bounded `READ COMMITTED` `FOR UPDATE SKIP LOCKED` batches with
/// `credential_generation` compare-and-set, deferring rows with an active worker refresh claim
/// so in-flight refreshes are not invalidated mid-flight. Refuses fail-closed if any stored
/// source `key_id` is missing from `keyring`, and records an audited `vault.rotated` operator
/// event only once all old-key rows have been rotated (`skipped_rows == 0`).
pub async fn vault_rotate(
    pool: &PgPool,
    keyring: &VaultKeyRing,
    operator_id: &str,
    request_key: &str,
    reason: &str,
    batch_size: usize,
) -> Result<VaultRotateReport, VaultError> {
    vault_rotate_with_wait(
        pool,
        keyring,
        operator_id,
        request_key,
        reason,
        batch_size,
        Duration::from_secs(2),
    )
    .await
}

/// Like [`vault_rotate`], with an explicit bounded retry window for rows deferred by active
/// worker refresh claims.
pub async fn vault_rotate_with_wait(
    pool: &PgPool,
    keyring: &VaultKeyRing,
    operator_id: &str,
    request_key: &str,
    reason: &str,
    batch_size: usize,
    defer_wait: Duration,
) -> Result<VaultRotateReport, VaultError> {
    uuid(operator_id, "operator_id")?;
    if !runs::bounded(request_key, 128) {
        return Err(StoreError::InvalidInput("request_key").into());
    }
    if !runs::bounded(reason, 512) {
        return Err(StoreError::InvalidInput("reason").into());
    }
    if !(1..=1000).contains(&batch_size) {
        return Err(StoreError::InvalidInput("batch_size").into());
    }
    let target_key_id = keyring.active_key_id().to_owned();

    // Check operator idempotency before rotating any rows.
    if let Some(row) = sqlx::query(
        "SELECT action, target_kind, target_id, details::text
           FROM openmettle.authorization_audit
          WHERE operator_id = $1::uuid AND request_key = $2",
    )
    .bind(operator_id)
    .bind(request_key)
    .fetch_optional(pool)
    .await?
    {
        let action: String = row.try_get(0)?;
        let target_kind: String = row.try_get(1)?;
        let target_id: String = row.try_get(2)?;
        let details_raw: String = row.try_get(3)?;
        let details: Value = serde_json::from_str(&details_raw).unwrap_or(Value::Null);
        if action == "vault.rotated"
            && target_kind == "vault"
            && target_id == "external_connections"
            && details.get("target_key_id").and_then(Value::as_str) == Some(&target_key_id)
        {
            return Ok(VaultRotateReport {
                target_key_id,
                rotated_rows: details
                    .get("rotated_rows")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
                skipped_rows: details
                    .get("skipped_rows")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
                deferred_active_refresh: details
                    .get("deferred_active_refresh")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
                replayed: true,
            });
        }
        return Err(StoreError::Conflict(store::KEY_REUSED).into());
    }

    // Pre-check that every historical key currently in use is present in the keyring.
    let existing_keys: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT encryption_key_id
           FROM openmettle.external_connections
          WHERE encryption_key_id IS NOT NULL
            AND encryption_key_id <> $1",
    )
    .bind(&target_key_id)
    .fetch_all(pool)
    .await?;
    for key_id in &existing_keys {
        if !keyring.has_key(key_id) {
            return Err(VaultError::UnknownKey);
        }
    }

    let mut rotated_rows = 0i64;
    let wait_deadline = Instant::now() + defer_wait;
    loop {
        let mut tx = pool.begin().await?;
        let rows = sqlx::query(
            "SELECT id::text, scope_id::text, account_id, allowed_scopes,
                    encryption_key_id, credential_generation,
                    access_salt, access_nonce, access_ciphertext,
                    refresh_salt, refresh_nonce, refresh_ciphertext
               FROM openmettle.external_connections
              WHERE state = 'authorized'
                AND encryption_key_id IS NOT NULL
                AND encryption_key_id <> $1
                AND (refresh_claim_token IS NULL OR refresh_lease_until <= clock_timestamp())
              ORDER BY id
              LIMIT $2
                FOR UPDATE SKIP LOCKED",
        )
        .bind(&target_key_id)
        .bind(batch_size as i64)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            tx.rollback().await?;
            let remaining: i64 = sqlx::query_scalar(
                "SELECT count(*)
                   FROM openmettle.external_connections
                  WHERE state = 'authorized'
                    AND encryption_key_id IS NOT NULL
                    AND encryption_key_id <> $1",
            )
            .bind(&target_key_id)
            .fetch_one(pool)
            .await?;
            if remaining > 0 && Instant::now() < wait_deadline {
                let pause = Duration::from_millis(50)
                    .min(wait_deadline.saturating_duration_since(Instant::now()));
                sleep(pause).await;
                continue;
            }
            break;
        }
        for row in rows {
            let conn_id: String = row.try_get(0)?;
            let scope_id: String = row.try_get(1)?;
            let account_id: String = row.try_get(2)?;
            let allowed_scopes: Vec<String> = row.try_get(3)?;
            let old_key_id: String = row.try_get(4)?;
            let old_gen: i64 = row.try_get(5)?;
            let access_sealed = decode_sealed(
                &old_key_id,
                row.try_get::<Vec<u8>, _>(6)?,
                row.try_get::<Vec<u8>, _>(7)?,
                row.try_get::<Vec<u8>, _>(8)?,
            )?;
            let access_plain = keyring.open(
                &SecretBinding {
                    connection_id: &conn_id,
                    scope_id: &scope_id,
                    account_id: &account_id,
                    secret_kind: SecretKind::Access,
                    credential_generation: old_gen,
                    allowed_scopes: &allowed_scopes,
                },
                &access_sealed,
            )?;
            let refresh_plain = match (
                row.try_get::<Option<Vec<u8>>, _>(9)?,
                row.try_get::<Option<Vec<u8>>, _>(10)?,
                row.try_get::<Option<Vec<u8>>, _>(11)?,
            ) {
                (Some(s), Some(n), Some(ct)) => {
                    let sealed = decode_sealed(&old_key_id, s, n, ct)?;
                    Some(keyring.open(
                        &SecretBinding {
                            connection_id: &conn_id,
                            scope_id: &scope_id,
                            account_id: &account_id,
                            secret_kind: SecretKind::Refresh,
                            credential_generation: old_gen,
                            allowed_scopes: &allowed_scopes,
                        },
                        &sealed,
                    )?)
                }
                (None, None, None) => None,
                _ => return Err(VaultError::Crypto),
            };
            // Re-wrap the existing upstream credential under `target_key_id` without advancing
            // `credential_generation` so online key rotation does not emit false
            // `external_connection.credential_superseded` journal events against pre-rotation
            // backups (AAD already binds `key_id` alongside `credential_generation`).
            let new_access = keyring.seal(
                &SecretBinding {
                    connection_id: &conn_id,
                    scope_id: &scope_id,
                    account_id: &account_id,
                    secret_kind: SecretKind::Access,
                    credential_generation: old_gen,
                    allowed_scopes: &allowed_scopes,
                },
                &access_plain,
            )?;
            let new_refresh = refresh_plain
                .as_ref()
                .map(|plain| {
                    keyring.seal(
                        &SecretBinding {
                            connection_id: &conn_id,
                            scope_id: &scope_id,
                            account_id: &account_id,
                            secret_kind: SecretKind::Refresh,
                            credential_generation: old_gen,
                            allowed_scopes: &allowed_scopes,
                        },
                        plain,
                    )
                })
                .transpose()?;
            let updated = sqlx::query(
                "UPDATE openmettle.external_connections
                    SET encryption_key_id = $2,
                        access_salt = $3,
                        access_nonce = $4,
                        access_ciphertext = $5,
                        refresh_salt = $6,
                        refresh_nonce = $7,
                        refresh_ciphertext = $8,
                        updated_at = clock_timestamp()
                  WHERE id = $1::uuid
                    AND state = 'authorized'
                    AND encryption_key_id = $9
                    AND credential_generation = $10
                    AND (refresh_claim_token IS NULL OR refresh_lease_until <= clock_timestamp())",
            )
            .bind(&conn_id)
            .bind(&new_access.key_id)
            .bind(new_access.salt.as_slice())
            .bind(new_access.nonce.as_slice())
            .bind(new_access.ciphertext.as_slice())
            .bind(new_refresh.as_ref().map(|s| s.salt.as_slice()))
            .bind(new_refresh.as_ref().map(|s| s.nonce.as_slice()))
            .bind(new_refresh.as_ref().map(|s| s.ciphertext.as_slice()))
            .bind(&old_key_id)
            .bind(old_gen)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            rotated_rows += updated as i64;
        }
        tx.commit().await?;
    }

    let (skipped_rows, deferred_active_refresh): (i64, i64) = sqlx::query_as(
        "SELECT count(*),
                count(*) FILTER (
                    WHERE refresh_claim_token IS NOT NULL
                      AND refresh_lease_until > clock_timestamp()
                )
           FROM openmettle.external_connections
          WHERE state = 'authorized'
            AND encryption_key_id IS NOT NULL
            AND encryption_key_id <> $1",
    )
    .bind(&target_key_id)
    .fetch_one(pool)
    .await?;

    if skipped_rows > 0 {
        return Ok(VaultRotateReport {
            target_key_id,
            rotated_rows,
            skipped_rows,
            deferred_active_refresh,
            replayed: false,
        });
    }

    let details = json!({
        "target_key_id": target_key_id,
        "rotated_rows": rotated_rows,
        "skipped_rows": skipped_rows,
        "deferred_active_refresh": deferred_active_refresh,
    });
    let inserted = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
             (actor_kind, operator_id, action, target_kind, target_id, request_key, reason, details)
         VALUES ('operator', $1::uuid, 'vault.rotated', 'vault', 'external_connections',
                 $2, $3, $4::jsonb)
         ON CONFLICT (operator_id, request_key) DO NOTHING",
    )
    .bind(operator_id)
    .bind(request_key)
    .bind(reason)
    .bind(details.to_string())
    .execute(pool)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Err(StoreError::Conflict(store::KEY_REUSED).into());
    }
    Ok(VaultRotateReport {
        target_key_id,
        rotated_rows,
        skipped_rows,
        deferred_active_refresh,
        replayed: false,
    })
}

fn decode_sealed(
    key_id: &str,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<SealedSecret, VaultError> {
    let salt: [u8; SALT_BYTES] = salt.try_into().map_err(|_| VaultError::Crypto)?;
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| VaultError::Crypto)?;
    Ok(SealedSecret {
        key_id: key_id.to_owned(),
        salt,
        nonce,
        ciphertext,
    })
}

// --- upstream OAuth token refresh client -------------------------------------------------------

/// Inputs for one upstream refresh-token exchange. `Debug` is redacted.
pub struct RefreshRequest<'a> {
    pub connection_id: &'a str,
    pub provider_kind: &'a str,
    pub account_id: &'a str,
    pub endpoint_origin: &'a str,
    pub refresh_token: &'a SecretText,
    pub allowed_scopes: &'a [String],
    pub current_granted_scopes: &'a [String],
}

impl fmt::Debug for RefreshRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("connection_id", &self.connection_id)
            .field("provider_kind", &self.provider_kind)
            .finish_non_exhaustive()
    }
}

/// Decoded successful upstream refresh payload. `Debug` is redacted.
pub struct RefreshedCredential {
    pub access_token: SecretText,
    pub refresh_token: Option<SecretText>,
    pub granted_scopes: Option<Vec<String>>,
    pub expires_in_secs: Option<u64>,
}

impl fmt::Debug for RefreshedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshedCredential(..)")
    }
}

/// Classified outcome of one upstream refresh exchange.
#[derive(Debug)]
pub enum RefreshOutcome {
    Refreshed(RefreshedCredential),
    /// Confirmed OAuth rejection (`401`/`403`, `400` with permanent OAuth `error`, or malformed
    /// `200` token/scope payload). Transitions the connection to `reauth_required`.
    Refused,
    /// Transient fault (`408`/`429`/`5xx`, non-OAuth `400`, TLS/network/timeout/framing).
    /// Preserves stored credentials.
    Transient,
    /// No provider- and origin-bound refresh route matches the connection. Non-destructive.
    Unconfigured,
}

/// Pluggable upstream refresh seam used by [`VaultCredentialProvider`].
pub trait RefreshClient: Send + Sync {
    fn refresh<'a>(
        &'a self,
        request: RefreshRequest<'a>,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = RefreshOutcome> + Send + 'a>>;
}

/// Bounded timeouts for [`HttpsRefreshClient`].
#[derive(Clone, Copy, Debug)]
pub struct RefreshTimeouts {
    pub setup: Duration,
    pub total: Duration,
}

impl Default for RefreshTimeouts {
    fn default() -> Self {
        Self {
            setup: Duration::from_secs(5),
            total: Duration::from_secs(10),
        }
    }
}

/// Bounded HTTPS/1.1 OAuth2 `refresh_token` client built over [`crate::provider_http::transport`],
/// strictly bound to one `provider_kind` and explicit allowlist of MCP `endpoint_origin`s so a
/// refresh token can never be dispatched to a mismatched provider's authorization server.
/// Enforces canonical HTTPS URLs, SSRF address policy, explicit `rustls` (ring) TLS 1.2/1.3,
/// isolated DNS lookup slots, zero redirects/retries/pooling, and fully redacted error handling.
#[derive(Clone)]
pub struct HttpsRefreshClient {
    provider_kind: String,
    allowed_origins: BTreeSet<String>,
    endpoint: transport::Endpoint,
    allowed: Vec<transport::Range>,
    tls: Arc<rustls::ClientConfig>,
    lookup: transport::Lookup,
    slots: Arc<Semaphore>,
    client_id: Option<String>,
    timeouts: RefreshTimeouts,
    #[cfg(test)]
    loopback: bool,
}

impl fmt::Debug for HttpsRefreshClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpsRefreshClient(..)")
    }
}

impl HttpsRefreshClient {
    pub fn new(
        provider_kind: &str,
        allowed_origins: &[&str],
        token_endpoint_url: &str,
        trust: Trust<'_>,
        private_ranges: &[&str],
        client_id: Option<String>,
        timeouts: RefreshTimeouts,
    ) -> Result<Self, provider_http::Error> {
        if validate_provider_kind(provider_kind).is_err()
            || allowed_origins.is_empty()
            || allowed_origins.len() > 64
            || private_ranges.len() > MAX_PRIVATE_RANGES
            || timeouts.setup.is_zero()
            || timeouts.total.is_zero()
            || timeouts.total > Duration::from_secs(60)
        {
            return Err(provider_http::Error::Configuration);
        }
        if let Some(id) = client_id.as_deref()
            && (id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(provider_http::Error::Configuration);
        }
        let mut origins = BTreeSet::new();
        for origin in allowed_origins {
            if validate_endpoint_origin(origin).is_err() || !origins.insert((*origin).to_owned()) {
                return Err(provider_http::Error::Configuration);
            }
        }
        let endpoint = transport::endpoint(token_endpoint_url)?;
        let allowed = private_ranges
            .iter()
            .map(|r| transport::private_range(r))
            .collect::<Result<Vec<_>, _>>()?;
        let roots = transport::roots(trust)?;
        let tls = transport::client_config(roots)?;
        Ok(Self {
            provider_kind: provider_kind.to_owned(),
            allowed_origins: origins,
            endpoint,
            allowed,
            tls,
            lookup: Arc::new(transport::system_lookup),
            slots: VAULT_REFRESH_DNS_SLOTS.clone(),
            client_id,
            timeouts,
            #[cfg(test)]
            loopback: false,
        })
    }

    pub fn provider_kind(&self) -> &str {
        &self.provider_kind
    }

    pub fn allowed_origins(&self) -> &BTreeSet<String> {
        &self.allowed_origins
    }

    fn route(&self) -> transport::Route<'_> {
        transport::Route {
            endpoint: &self.endpoint,
            allowed: &self.allowed,
            tls: Some(&self.tls),
            lookup: &self.lookup,
            slots: &self.slots,
            #[cfg(test)]
            loopback: self.loopback,
        }
    }
}

/// Provider- and origin-bound registry of trusted OAuth token refresh clients.
///
/// Keys each configured [`HttpsRefreshClient`] by `(provider_kind, mcp_endpoint_origin)` so
/// connections for one provider or MCP origin can never dispatch refresh tokens to another
/// provider's authorization server. Connections without a matching route receive
/// [`RefreshOutcome::Unconfigured`] without contacting any remote host or wiping stored tokens.
#[derive(Clone, Default)]
pub struct VaultRefreshRegistry {
    routes: BTreeMap<(String, String), Arc<HttpsRefreshClient>>,
}

impl fmt::Debug for VaultRefreshRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultRefreshRegistry(..)")
    }
}

impl VaultRefreshRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, client: Arc<HttpsRefreshClient>) -> Result<(), VaultError> {
        for origin in client.allowed_origins() {
            let key = (client.provider_kind().to_owned(), origin.clone());
            if self.routes.contains_key(&key) {
                return Err(VaultError::Configuration("duplicate vault refresh route"));
            }
        }
        for origin in client.allowed_origins() {
            let key = (client.provider_kind().to_owned(), origin.clone());
            self.routes.insert(key, Arc::clone(&client));
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl RefreshClient for VaultRefreshRegistry {
    fn refresh<'a>(
        &'a self,
        request: RefreshRequest<'a>,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = RefreshOutcome> + Send + 'a>> {
        let key = (
            request.provider_kind.to_owned(),
            request.endpoint_origin.to_owned(),
        );
        match self.routes.get(&key) {
            Some(client) => client.refresh(request, deadline),
            None => Box::pin(async { RefreshOutcome::Unconfigured }),
        }
    }
}

fn form_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            use fmt::Write;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[derive(Deserialize)]
struct OAuthTokenReply {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

fn parse_oauth_refresh_reply(body: &[u8]) -> Result<RefreshedCredential, VaultError> {
    let value = unique(body).map_err(|_| VaultError::RefreshRefused)?;
    if !value.is_object() {
        return Err(VaultError::RefreshRefused);
    }
    let parsed: OAuthTokenReply =
        serde_json::from_value(value).map_err(|_| VaultError::RefreshRefused)?;
    let access_token = SecretText::new_access(&parsed.access_token)?;
    let refresh_token = parsed
        .refresh_token
        .as_deref()
        .map(SecretText::new_refresh)
        .transpose()?;
    let granted_scopes = match parsed.scope {
        Some(raw) => {
            let tokens: Vec<String> = raw
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            Some(normalize_scopes(&tokens, false).map_err(|_| VaultError::RefreshRefused)?)
        }
        None => None,
    };
    let expires_in_secs = match parsed.expires_in {
        Some(secs) if (1..=MAX_EXPIRES_IN_SECS).contains(&secs) => Some(secs),
        Some(_) => return Err(VaultError::RefreshRefused),
        None => None,
    };
    Ok(RefreshedCredential {
        access_token,
        refresh_token,
        granted_scopes,
        expires_in_secs,
    })
}

fn is_permanent_oauth_400(body: &[u8]) -> bool {
    let Ok(Value::Object(map)) = unique(body) else {
        return false;
    };
    matches!(
        map.get("error").and_then(Value::as_str),
        Some("invalid_grant" | "invalid_client" | "unauthorized_client" | "invalid_scope")
    )
}

impl RefreshClient for HttpsRefreshClient {
    fn refresh<'a>(
        &'a self,
        request: RefreshRequest<'a>,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = RefreshOutcome> + Send + 'a>> {
        Box::pin(async move {
            if request.provider_kind != self.provider_kind
                || !self.allowed_origins.contains(request.endpoint_origin)
            {
                return RefreshOutcome::Unconfigured;
            }
            let now = Instant::now();
            if now >= deadline {
                return RefreshOutcome::Transient;
            }
            let remaining = deadline.saturating_duration_since(now);
            let total = self.timeouts.total.min(remaining);
            let setup = self.timeouts.setup.min(total);
            let mut form = format!(
                "grant_type=refresh_token&refresh_token={}",
                form_encode(request.refresh_token.expose())
            );
            if !request.current_granted_scopes.is_empty() {
                let joined = request.current_granted_scopes.join(" ");
                form.push_str("&scope=");
                form.push_str(&form_encode(&joined));
            }
            if let Some(client_id) = &self.client_id {
                form.push_str("&client_id=");
                form.push_str(&form_encode(client_id));
            }
            let mut body_bytes = form.into_bytes();
            let mut headers = hyper::HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            headers.insert(
                header::ACCEPT,
                header::HeaderValue::from_static("application/json"),
            );
            let limits = transport::Limits {
                request_body: MAX_REFRESH_REQUEST_BYTES,
                response_body: MAX_REFRESH_RESPONSE_BYTES,
                response_headers: provider_http::MAX_RESPONSE_HEADERS,
                response_header_bytes: provider_http::MAX_RESPONSE_HEADER_BYTES,
                setup,
                total,
            };
            let send_buf = std::mem::take(&mut body_bytes);
            let reply = self
                .route()
                .send(Method::POST, &headers, send_buf, &limits)
                .await;
            match reply {
                Ok(response) => match response.status() {
                    StatusCode::OK => match parse_oauth_refresh_reply(response.body()) {
                        Ok(cred) => RefreshOutcome::Refreshed(cred),
                        Err(_) => RefreshOutcome::Refused,
                    },
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => RefreshOutcome::Refused,
                    StatusCode::BAD_REQUEST => {
                        if is_permanent_oauth_400(response.body()) {
                            RefreshOutcome::Refused
                        } else {
                            RefreshOutcome::Transient
                        }
                    }
                    _ => RefreshOutcome::Transient,
                },
                Err(_) => RefreshOutcome::Transient,
            }
        })
    }
}

// --- worker execution-time credential provider & destination authorizer ------------------------

/// Timing parameters for [`VaultCredentialProvider`] single-flight refresh coordination.
#[derive(Clone, Copy, Debug)]
pub struct VaultConfig {
    /// Proactive refresh window before `expires_at`.
    pub refresh_skew: Duration,
    /// Duration of the DB-backed single-flight refresh lease.
    pub refresh_lease: Duration,
    /// Poll interval while waiting for another worker's in-flight refresh.
    pub waiter_poll: Duration,
    /// Maximum total time spent resolving or waiting for a credential.
    pub max_wait: Duration,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            refresh_skew: Duration::from_secs(60),
            refresh_lease: Duration::from_secs(30),
            waiter_poll: Duration::from_millis(50),
            max_wait: Duration::from_secs(10),
        }
    }
}

type ScopeLifecycleRow = (String, Option<String>, Option<String>, bool, bool);

async fn load_worker_scope_and_actor(
    c: &mut PgConnection,
    scope_id: &str,
    actor_user_id: &str,
    actor_approval_id: Option<&str>,
    now_ms: i64,
) -> Result<Option<(Scope, Principal)>, StoreError> {
    let lifecycle: Option<ScopeLifecycleRow> = sqlx::query_as(
        "SELECT scope_kind, project_id::text, personal_user_id::text, archived, deleted
           FROM openmettle.external_connection_scope_lifecycle($1::uuid)",
    )
    .bind(scope_id)
    .fetch_optional(&mut *c)
    .await?;
    let Some((_kind, project_id, personal_user_id, archived, deleted)) = lifecycle else {
        return Ok(None);
    };
    if deleted || archived {
        return Ok(None);
    }
    let scope = match (personal_user_id, project_id) {
        (Some(owner), None) => Scope::Personal {
            scope_id: scope_id.to_owned(),
            owner_user_id: owner,
        },
        (None, Some(project)) => Scope::Project(project_in(c, &project, scope_id, now_ms).await?),
        _ => return Ok(None),
    };
    let project_ref = match &scope {
        Scope::Project(p) => Some(p),
        Scope::Personal { .. } => None,
    };
    let actor = match actor_approval_id {
        Some(approval_id) => {
            store::hydrate_worker_principal(c, actor_user_id, approval_id, now_ms).await?
        }
        None => hydrate_any_active_worker_principal(c, actor_user_id, project_ref, now_ms).await?,
    };
    Ok(actor.filter(Principal::is_active).map(|p| (scope, p)))
}

/// Verify worker-side execution authority across the run's scope (`run_scope_id`) and the target
/// connection's owning scope (`conn_scope_id`, `conn_scope_kind`, `conn_owner_user_id`):
/// - `actor` must be active and authorized to execute in `run_scope_id` (personal owner, or
///   project `Owner`/`Editor` on a non-archived, non-deleted project).
/// - `project` connections require exact scope equality (`conn_scope_id == run_scope_id`) and
///   [`can_execute_connection`] (`Owner` or `Editor` with active matching share).
/// - `personal` connections may only be used from a `personal` run scope (never from a project
///   run scope): either by the personal owner in their own personal scope, or by an active
///   recipient in their own personal scope via a live active share while the owner remains active.
#[allow(clippy::too_many_arguments)]
async fn verify_worker_connection_authority(
    c: &mut PgConnection,
    run_scope_id: &str,
    conn_scope_id: &str,
    conn_scope_kind: &str,
    conn_owner_user_id: &str,
    connection_id: &str,
    actor_user_id: &str,
    actor_approval_id: Option<&str>,
    now_ms: i64,
) -> Result<bool, StoreError> {
    let Some((run_scope, actor)) =
        load_worker_scope_and_actor(c, run_scope_id, actor_user_id, actor_approval_id, now_ms)
            .await?
    else {
        return Ok(false);
    };
    let can_act_in_run_scope = match &run_scope {
        Scope::Personal {
            scope_id,
            owner_user_id,
        } => *scope_id == actor.personal_scope_id && *owner_user_id == actor.user_id,
        Scope::Project(project) => matches!(
            project.role_of(&actor),
            Some(ProjectRole::Owner | ProjectRole::Editor)
        ),
    };
    if !can_act_in_run_scope {
        return Ok(false);
    }
    match conn_scope_kind {
        "project" => {
            if conn_scope_id != run_scope_id || !matches!(run_scope, Scope::Project(_)) {
                return Ok(false);
            }
            let shares = load_active_shares(c, connection_id).await?;
            Ok(can_execute_connection(&actor, &run_scope, &shares))
        }
        "personal" => {
            if !matches!(run_scope, Scope::Personal { .. }) {
                return Ok(false);
            }
            if conn_scope_id == run_scope_id {
                return Ok(conn_owner_user_id == actor.user_id);
            }
            let conn_lifecycle: Option<ScopeLifecycleRow> = sqlx::query_as(
                "SELECT scope_kind, project_id::text, personal_user_id::text, archived, deleted
                   FROM openmettle.external_connection_scope_lifecycle($1::uuid)",
            )
            .bind(conn_scope_id)
            .fetch_optional(&mut *c)
            .await?;
            let Some((kind, None, Some(owner), false, false)) = conn_lifecycle else {
                return Ok(false);
            };
            if kind != "personal" || owner != conn_owner_user_id {
                return Ok(false);
            }
            let owner_active: bool = sqlx::query_scalar(
                "SELECT disabled_at IS NULL FROM openmettle.users WHERE id = $1::uuid",
            )
            .bind(&owner)
            .fetch_optional(&mut *c)
            .await?
            .unwrap_or(false);
            if !owner_active {
                return Ok(false);
            }
            let conn_scope = Scope::Personal {
                scope_id: conn_scope_id.to_owned(),
                owner_user_id: owner,
            };
            let shares = load_active_shares(c, connection_id).await?;
            Ok(can_execute_connection(&actor, &conn_scope, &shares))
        }
        _ => Ok(false),
    }
}

async fn hydrate_any_active_worker_principal(
    c: &mut PgConnection,
    user_id: &str,
    project: Option<&Project>,
    now_ms: i64,
) -> Result<Option<Principal>, StoreError> {
    let approvals: Vec<String> = sqlx::query_scalar(
        "SELECT a.id::text
           FROM openmettle.local_identity_approvals a
           JOIN openmettle.user_identities i ON i.id = a.identity_id
          WHERE i.user_id = $1::uuid
          ORDER BY a.id",
    )
    .bind(user_id)
    .fetch_all(&mut *c)
    .await?;
    for approval in approvals {
        let Some(p) = store::hydrate(c, user_id, &approval, now_ms, false).await? else {
            continue;
        };
        if p.is_active() && project.is_none_or(|proj| proj.role_of(&p).is_some()) {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

async fn worker_audit_connection(
    c: &mut PgConnection,
    actor_user_id: &str,
    action: &str,
    connection_id: &str,
    request_key: &str,
    reason: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT openmettle.external_connection_audit_worker(
             $1::uuid, $2, $3::uuid, $4, $5, $6::jsonb
         )",
    )
    .bind(actor_user_id)
    .bind(action)
    .bind(connection_id)
    .bind(request_key)
    .bind(reason)
    .bind(details.to_string())
    .execute(c)
    .await?;
    Ok(())
}

/// Worker-side execution credential resolver (`impl McpCredentialProvider`) with live primary
/// authority checks, destination/scope validation, and DB-backed single-flight refresh.
pub struct VaultCredentialProvider {
    pool: PgPool,
    keyring: Arc<VaultKeyRing>,
    refresher: Option<Arc<dyn RefreshClient>>,
    config: VaultConfig,
}

impl fmt::Debug for VaultCredentialProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultCredentialProvider")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl VaultCredentialProvider {
    pub fn new(
        pool: PgPool,
        keyring: Arc<VaultKeyRing>,
        refresher: Option<Arc<dyn RefreshClient>>,
        config: VaultConfig,
    ) -> Self {
        Self {
            pool,
            keyring,
            refresher,
            config,
        }
    }

    async fn resolve_inner(&self, request: CredentialRequest<'_>) -> CredentialOutcome {
        if runs::uuid(request.connection_id).is_err()
            || runs::uuid(request.scope_id).is_err()
            || runs::uuid(request.actor_user_id).is_err()
            || request
                .actor_approval_id
                .is_some_and(|id| runs::uuid(id).is_err())
        {
            return CredentialOutcome::Unavailable;
        }
        let deadline = Instant::now() + self.config.max_wait;
        let skew_ms = i64::try_from(self.config.refresh_skew.as_millis()).unwrap_or(60_000);
        let lease_ms = i64::try_from(self.config.refresh_lease.as_millis()).unwrap_or(30_000);

        loop {
            if Instant::now() >= deadline {
                return CredentialOutcome::Transient;
            }
            let Ok(mut conn) = self.pool.acquire().await else {
                return CredentialOutcome::Unavailable;
            };
            let Ok(mut tx) = conn.begin().await else {
                return CredentialOutcome::Unavailable;
            };
            // Consistent single MVCC snapshot across restore gate, scope/actor authority, shares,
            // and encrypted connection metadata with zero row locks on projects/users/connections.
            if sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *tx)
                .await
                .is_err()
            {
                let _ = tx.rollback().await;
                return CredentialOutcome::Unavailable;
            }
            if crate::restore::require_open_gate(&mut tx).await.is_err() {
                let _ = tx.rollback().await;
                return CredentialOutcome::Unavailable;
            }
            let Ok(now_ms) = post_lock_clock_ms(&mut tx, 0).await else {
                let _ = tx.rollback().await;
                return CredentialOutcome::Unavailable;
            };
            let row = sqlx::query(
                "SELECT scope_id::text, scope_kind, owner_user_id::text,
                        provider_kind, endpoint_origin, allowed_scopes, granted_scopes, state,
                        CASE WHEN expires_at IS NOT NULL
                             THEN floor(extract(epoch FROM expires_at) * 1000)::bigint END,
                        encryption_key_id,
                        access_salt, access_nonce, access_ciphertext,
                        has_refresh, credential_generation, revocation_generation
                   FROM openmettle.external_connections
                  WHERE id = $1::uuid AND account_id = $2",
            )
            .bind(request.connection_id)
            .bind(request.account_id)
            .fetch_optional(&mut *tx)
            .await;
            let Ok(Some(row)) = row else {
                let _ = tx.rollback().await;
                return CredentialOutcome::Unavailable;
            };

            let conn_scope_id: String = match row.try_get(0) {
                Ok(v) => v,
                Err(_) => return CredentialOutcome::Unavailable,
            };
            let conn_scope_kind: String = match row.try_get(1) {
                Ok(v) => v,
                Err(_) => return CredentialOutcome::Unavailable,
            };
            let conn_owner_user_id: String = match row.try_get(2) {
                Ok(v) => v,
                Err(_) => return CredentialOutcome::Unavailable,
            };
            let authorized = verify_worker_connection_authority(
                &mut tx,
                request.scope_id,
                &conn_scope_id,
                &conn_scope_kind,
                &conn_owner_user_id,
                request.connection_id,
                request.actor_user_id,
                request.actor_approval_id,
                now_ms,
            )
            .await
            .unwrap_or(false);
            if !authorized {
                let _ = tx.rollback().await;
                return CredentialOutcome::Unavailable;
            }

            let state: String = match row.try_get(7) {
                Ok(v) => v,
                Err(_) => return CredentialOutcome::Unavailable,
            };
            let origin: String = match row.try_get(4) {
                Ok(v) => v,
                Err(_) => return CredentialOutcome::Unavailable,
            };
            let allowed_scopes: Vec<String> = match row.try_get(5) {
                Ok(v) => v,
                Err(_) => return CredentialOutcome::Unavailable,
            };
            let granted_scopes: Vec<String> = match row.try_get(6) {
                Ok(v) => v,
                Err(_) => return CredentialOutcome::Unavailable,
            };
            if state != ConnectionState::Authorized.as_str()
                || request.expected_origin.is_some_and(|exp| exp != origin)
                || request.required_scope.is_some_and(|req| {
                    !granted_scopes.iter().any(|s| s == req)
                        || !allowed_scopes.iter().any(|s| s == req)
                })
            {
                let _ = tx.rollback().await;
                return CredentialOutcome::Unavailable;
            }

            let expires_ms: Option<i64> = row.try_get(8).unwrap_or(None);
            let has_refresh: bool = row.try_get(13).unwrap_or(false);
            let cred_gen: i64 = row.try_get(14).unwrap_or(0);
            let expired = expires_ms.is_some_and(|exp| exp <= now_ms);
            let needs_refresh = expires_ms.is_some_and(|exp| exp <= now_ms.saturating_add(skew_ms));

            if !needs_refresh || (!expired && (!has_refresh || self.refresher.is_none())) {
                let key_id: Option<String> = row.try_get(9).unwrap_or(None);
                let salt: Option<Vec<u8>> = row.try_get(10).unwrap_or(None);
                let nonce: Option<Vec<u8>> = row.try_get(11).unwrap_or(None);
                let ct: Option<Vec<u8>> = row.try_get(12).unwrap_or(None);
                let _ = tx.rollback().await;
                let (Some(key_id), Some(salt), Some(nonce), Some(ct)) = (key_id, salt, nonce, ct)
                else {
                    return CredentialOutcome::Unavailable;
                };
                let Ok(sealed) = decode_sealed(&key_id, salt, nonce, ct) else {
                    return CredentialOutcome::Unavailable;
                };
                let binding = SecretBinding {
                    connection_id: request.connection_id,
                    scope_id: &conn_scope_id,
                    account_id: request.account_id,
                    secret_kind: SecretKind::Access,
                    credential_generation: cred_gen,
                    allowed_scopes: &allowed_scopes,
                };
                return match self.keyring.open(&binding, &sealed) {
                    Ok(plain) => CredentialOutcome::Ready(McpCredential::bearer(plain.expose())),
                    Err(_) => CredentialOutcome::Unavailable,
                };
            }

            // Release the read transaction before entering the locked refresh/reauth phase.
            let _ = tx.rollback().await;
            drop(conn);

            // Expired with no refresh secret -> transition to reauth_required.
            if !has_refresh {
                self.mark_expired_reauth_required(&request).await;
                return CredentialOutcome::Unavailable;
            }
            // Expired with a valid refresh secret but no refresher configured -> non-destructive
            // transient refusal; preserve stored credentials.
            if self.refresher.is_none() {
                return CredentialOutcome::Transient;
            }

            // Single-flight refresh attempt (claim lease or wait behind active leader).
            match self
                .attempt_single_flight_refresh(&request, skew_ms, lease_ms, deadline)
                .await
            {
                RefreshStep::Ready(cred) => return CredentialOutcome::Ready(cred),
                RefreshStep::Wait => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return CredentialOutcome::Transient;
                    }
                    sleep(self.config.waiter_poll.min(remaining)).await;
                }
                RefreshStep::RetryRead => continue,
                RefreshStep::Transient => return CredentialOutcome::Transient,
                RefreshStep::Unavailable => return CredentialOutcome::Unavailable,
            }
        }
    }

    async fn mark_expired_reauth_required(&self, request: &CredentialRequest<'_>) {
        let Ok(mut conn) = self.pool.acquire().await else {
            return;
        };
        let Ok(mut tx) = conn.begin().await else {
            return;
        };
        if crate::restore::require_open_gate(&mut tx).await.is_err() {
            let _ = tx.rollback().await;
            return;
        }
        let row = sqlx::query(
            "SELECT scope_id::text, scope_kind, owner_user_id::text,
                    state, revocation_generation,
                    CASE WHEN expires_at IS NOT NULL
                         THEN floor(extract(epoch FROM expires_at) * 1000)::bigint END,
                    has_refresh, endpoint_origin, allowed_scopes, granted_scopes
               FROM openmettle.external_connections
              WHERE id = $1::uuid AND account_id = $2
                FOR UPDATE",
        )
        .bind(request.connection_id)
        .bind(request.account_id)
        .fetch_optional(&mut *tx)
        .await;
        let Ok(Some(row)) = row else {
            let _ = tx.rollback().await;
            return;
        };
        let conn_scope_id: String = row.try_get(0).unwrap_or_default();
        let conn_scope_kind: String = row.try_get(1).unwrap_or_default();
        let conn_owner_user_id: String = row.try_get(2).unwrap_or_default();
        // Re-verify live caller authority AFTER holding the connection row lock.
        let Ok(now_ms) = post_lock_clock_ms(&mut tx, 0).await else {
            let _ = tx.rollback().await;
            return;
        };
        if !verify_worker_connection_authority(
            &mut tx,
            request.scope_id,
            &conn_scope_id,
            &conn_scope_kind,
            &conn_owner_user_id,
            request.connection_id,
            request.actor_user_id,
            request.actor_approval_id,
            now_ms,
        )
        .await
        .unwrap_or(false)
        {
            let _ = tx.rollback().await;
            return;
        }
        let state: String = row.try_get(3).unwrap_or_default();
        let rev_gen: i64 = row.try_get(4).unwrap_or(0);
        let exp_ms: Option<i64> = row.try_get(5).unwrap_or(None);
        let has_refresh: bool = row.try_get(6).unwrap_or(false);
        let endpoint_origin: String = row.try_get(7).unwrap_or_default();
        let allowed_scopes: Vec<String> = row.try_get(8).unwrap_or_default();
        let granted_scopes: Vec<String> = row.try_get(9).unwrap_or_default();
        if state != ConnectionState::Authorized.as_str()
            || !exp_ms.is_some_and(|exp| exp <= now_ms)
            || has_refresh
            || request
                .expected_origin
                .is_some_and(|exp| exp != endpoint_origin)
            || request.required_scope.is_some_and(|req| {
                !granted_scopes.iter().any(|s| s == req) || !allowed_scopes.iter().any(|s| s == req)
            })
        {
            let _ = tx.rollback().await;
            return;
        }
        let next_rev = rev_gen + 1;
        let updated = sqlx::query(
            "UPDATE openmettle.external_connections
                SET granted_scopes = ARRAY[]::text[],
                    state = 'reauth_required',
                    expires_at = NULL,
                    encryption_key_id = NULL,
                    access_salt = NULL,
                    access_nonce = NULL,
                    access_ciphertext = NULL,
                    refresh_salt = NULL,
                    refresh_nonce = NULL,
                    refresh_ciphertext = NULL,
                    revocation_generation = $2,
                    refresh_claim_token = NULL,
                    refresh_lease_until = NULL,
                    updated_at = clock_timestamp()
              WHERE id = $1::uuid AND state = 'authorized' AND revocation_generation = $3",
        )
        .bind(request.connection_id)
        .bind(next_rev)
        .bind(rev_gen)
        .execute(&mut *tx)
        .await;
        if let Ok(done) = updated
            && done.rows_affected() == 1
        {
            let audit_key = format!("vault-expired/{}/{next_rev}", request.connection_id);
            let _ = worker_audit_connection(
                &mut tx,
                request.actor_user_id,
                "connection.reauth_required",
                request.connection_id,
                &audit_key,
                "access credential expired without refresh",
                json!({
                    "revocation_generation": next_rev,
                    "reason": "expired_without_refresh",
                }),
            )
            .await;
            let _ = tx.commit().await;
        } else {
            let _ = tx.rollback().await;
        }
    }

    async fn attempt_single_flight_refresh(
        &self,
        request: &CredentialRequest<'_>,
        skew_ms: i64,
        lease_ms: i64,
        deadline: Instant,
    ) -> RefreshStep {
        let Some(refresher) = self.refresher.as_ref() else {
            return RefreshStep::Transient;
        };

        // Phase 1: lock gate (FOR SHARE) then connection row (FOR UPDATE) FIRST, re-verify live
        // caller authority + state + expiry AFTER holding the row lock, and claim the single-flight
        // refresh lease before releasing DB locks.
        let claim = {
            let Ok(mut conn) = self.pool.acquire().await else {
                return RefreshStep::Unavailable;
            };
            let Ok(mut tx) = conn.begin().await else {
                return RefreshStep::Unavailable;
            };
            if crate::restore::require_open_gate(&mut tx).await.is_err() {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            }
            let row = sqlx::query(
                "SELECT scope_id::text, scope_kind, owner_user_id::text,
                        provider_kind, endpoint_origin, allowed_scopes, granted_scopes, state,
                        CASE WHEN expires_at IS NOT NULL
                             THEN floor(extract(epoch FROM expires_at) * 1000)::bigint END,
                        encryption_key_id,
                        refresh_salt, refresh_nonce, refresh_ciphertext,
                        credential_generation, revocation_generation,
                        refresh_claim_token::text,
                        CASE WHEN refresh_lease_until IS NOT NULL
                             THEN floor(extract(epoch FROM refresh_lease_until) * 1000)::bigint END
                   FROM openmettle.external_connections
                  WHERE id = $1::uuid AND account_id = $2
                    FOR UPDATE",
            )
            .bind(request.connection_id)
            .bind(request.account_id)
            .fetch_optional(&mut *tx)
            .await;
            let Ok(Some(row)) = row else {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            };
            let conn_scope_id: String = match row.try_get(0) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let conn_scope_kind: String = match row.try_get(1) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let conn_owner_user_id: String = match row.try_get(2) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let Ok(now_ms) = post_lock_clock_ms(&mut tx, 0).await else {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            };
            if !verify_worker_connection_authority(
                &mut tx,
                request.scope_id,
                &conn_scope_id,
                &conn_scope_kind,
                &conn_owner_user_id,
                request.connection_id,
                request.actor_user_id,
                request.actor_approval_id,
                now_ms,
            )
            .await
            .unwrap_or(false)
            {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            }

            let provider_kind: String = match row.try_get(3) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let endpoint_origin: String = match row.try_get(4) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let allowed_scopes: Vec<String> = match row.try_get(5) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let granted_scopes: Vec<String> = match row.try_get(6) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let state: String = match row.try_get(7) {
                Ok(v) => v,
                Err(_) => return RefreshStep::Unavailable,
            };
            let expires_ms: Option<i64> = row.try_get(8).unwrap_or(None);
            if state != ConnectionState::Authorized.as_str()
                || request
                    .expected_origin
                    .is_some_and(|exp| exp != endpoint_origin)
                || request.required_scope.is_some_and(|req| {
                    !granted_scopes.iter().any(|s| s == req)
                        || !allowed_scopes.iter().any(|s| s == req)
                })
            {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            }
            if !expires_ms.is_some_and(|exp| exp <= now_ms.saturating_add(skew_ms)) {
                // Another worker already committed a fresh token!
                let _ = tx.rollback().await;
                return RefreshStep::RetryRead;
            }
            let existing_claim: Option<String> = row.try_get(15).unwrap_or(None);
            let existing_lease_ms: Option<i64> = row.try_get(16).unwrap_or(None);
            if existing_claim.is_some() && existing_lease_ms.is_some_and(|until| until > now_ms) {
                let _ = tx.rollback().await;
                return RefreshStep::Wait;
            }
            let key_id: Option<String> = row.try_get(9).unwrap_or(None);
            let r_salt: Option<Vec<u8>> = row.try_get(10).unwrap_or(None);
            let r_nonce: Option<Vec<u8>> = row.try_get(11).unwrap_or(None);
            let r_ct: Option<Vec<u8>> = row.try_get(12).unwrap_or(None);
            let cred_gen: i64 = row.try_get(13).unwrap_or(0);
            let rev_gen: i64 = row.try_get(14).unwrap_or(0);
            let (Some(key_id), Some(r_salt), Some(r_nonce), Some(r_ct)) =
                (key_id, r_salt, r_nonce, r_ct)
            else {
                let _ = tx.rollback().await;
                return RefreshStep::RetryRead;
            };
            let Ok(sealed_refresh) = decode_sealed(&key_id, r_salt, r_nonce, r_ct) else {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            };
            let Ok(refresh_secret) = self.keyring.open(
                &SecretBinding {
                    connection_id: request.connection_id,
                    scope_id: &conn_scope_id,
                    account_id: request.account_id,
                    secret_kind: SecretKind::Refresh,
                    credential_generation: cred_gen,
                    allowed_scopes: &allowed_scopes,
                },
                &sealed_refresh,
            ) else {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            };
            let Ok(claim_token) = sqlx::query_scalar::<_, String>(
                "UPDATE openmettle.external_connections
                    SET refresh_claim_token = gen_random_uuid(),
                        refresh_lease_until = clock_timestamp() + ($2 * interval '1 millisecond'),
                        updated_at = clock_timestamp()
                  WHERE id = $1::uuid
                    AND state = 'authorized'
                    AND credential_generation = $3
                    AND revocation_generation = $4
                 RETURNING refresh_claim_token::text",
            )
            .bind(request.connection_id)
            .bind(lease_ms)
            .bind(cred_gen)
            .bind(rev_gen)
            .fetch_one(&mut *tx)
            .await
            else {
                let _ = tx.rollback().await;
                return RefreshStep::Unavailable;
            };
            if tx.commit().await.is_err() {
                return RefreshStep::Unavailable;
            }
            ClaimedRefresh {
                conn_scope_id,
                conn_scope_kind,
                conn_owner_user_id,
                claim_token,
                cred_gen,
                rev_gen,
                provider_kind,
                endpoint_origin,
                allowed_scopes,
                granted_scopes,
                refresh_secret,
            }
        };

        // Phase 2: perform bounded upstream HTTPS refresh with ZERO DB connections or locks held.
        let outcome = refresher
            .refresh(
                RefreshRequest {
                    connection_id: request.connection_id,
                    provider_kind: &claim.provider_kind,
                    account_id: request.account_id,
                    endpoint_origin: &claim.endpoint_origin,
                    refresh_token: &claim.refresh_secret,
                    allowed_scopes: &claim.allowed_scopes,
                    current_granted_scopes: &claim.granted_scopes,
                },
                deadline,
            )
            .await;

        // Phase 3: re-lock gate (FOR SHARE) then connection row (FOR UPDATE) and fence commit
        // against concurrent disconnect/reauth/rotation.
        let Ok(mut conn) = self.pool.acquire().await else {
            return RefreshStep::Transient;
        };
        let Ok(mut tx) = conn.begin().await else {
            return RefreshStep::Transient;
        };
        if crate::restore::require_open_gate(&mut tx).await.is_err() {
            let _ = tx.rollback().await;
            return RefreshStep::Unavailable;
        }
        let fenced = sqlx::query(
            "SELECT state, credential_generation, revocation_generation,
                    refresh_claim_token::text, allowed_scopes, granted_scopes,
                    CASE WHEN expires_at IS NOT NULL
                         THEN floor(extract(epoch FROM expires_at) * 1000)::bigint END,
                    encryption_key_id, access_salt, access_nonce, access_ciphertext
               FROM openmettle.external_connections
              WHERE id = $1::uuid AND scope_id = $2::uuid AND account_id = $3
                FOR UPDATE",
        )
        .bind(request.connection_id)
        .bind(&claim.conn_scope_id)
        .bind(request.account_id)
        .fetch_optional(&mut *tx)
        .await;
        let Ok(Some(fenced)) = fenced else {
            let _ = tx.rollback().await;
            return RefreshStep::Unavailable;
        };
        let state: String = fenced.try_get(0).unwrap_or_default();
        let cur_cred_gen: i64 = fenced.try_get(1).unwrap_or(-1);
        let cur_rev_gen: i64 = fenced.try_get(2).unwrap_or(-1);
        let cur_claim: Option<String> = fenced.try_get(3).unwrap_or(None);
        let allowed_scopes: Vec<String> = fenced.try_get(4).unwrap_or_default();
        let existing_granted: Vec<String> = fenced.try_get(5).unwrap_or_default();
        let cur_expires_ms: Option<i64> = fenced.try_get(6).unwrap_or(None);

        // Disconnect, revocation, concurrent re-authorize, or lease takeover wins!
        if state != ConnectionState::Authorized.as_str()
            || cur_cred_gen != claim.cred_gen
            || cur_rev_gen != claim.rev_gen
            || cur_claim.as_deref() != Some(claim.claim_token.as_str())
        {
            let _ = tx.rollback().await;
            return RefreshStep::Unavailable;
        }

        match outcome {
            RefreshOutcome::Refreshed(refreshed) => {
                // RFC 6749 §6: refresh cannot widen beyond prior `granted_scopes` (or `allowed_scopes`).
                // Omitting `scope` preserves `existing_granted`.
                let next_granted = match refreshed.granted_scopes {
                    Some(scopes) => {
                        let within_granted = scopes_are_subset(&scopes, &existing_granted);
                        let within_allowed = scopes_are_subset(&scopes, &allowed_scopes);
                        let required_ok = request
                            .required_scope
                            .is_none_or(|req| scopes.iter().any(|s| s == req));
                        if !within_granted || !within_allowed || !required_ok {
                            self.commit_reauth_required(
                                tx,
                                request,
                                &claim,
                                "scope_policy_refused",
                            )
                            .await;
                            return RefreshStep::Unavailable;
                        }
                        scopes
                    }
                    None => {
                        let required_ok = request
                            .required_scope
                            .is_none_or(|req| existing_granted.iter().any(|s| s == req));
                        if existing_granted.is_empty()
                            || !scopes_are_subset(&existing_granted, &allowed_scopes)
                            || !required_ok
                        {
                            self.commit_reauth_required(
                                tx,
                                request,
                                &claim,
                                "scope_policy_refused",
                            )
                            .await;
                            return RefreshStep::Unavailable;
                        }
                        existing_granted
                    }
                };
                let next_gen = claim.cred_gen + 1;
                let Ok(new_access) = self.keyring.seal(
                    &SecretBinding {
                        connection_id: request.connection_id,
                        scope_id: &claim.conn_scope_id,
                        account_id: request.account_id,
                        secret_kind: SecretKind::Access,
                        credential_generation: next_gen,
                        allowed_scopes: &allowed_scopes,
                    },
                    &refreshed.access_token,
                ) else {
                    let _ = tx.rollback().await;
                    return RefreshStep::Unavailable;
                };
                let next_refresh_plain = refreshed
                    .refresh_token
                    .as_ref()
                    .unwrap_or(&claim.refresh_secret);
                let Ok(new_refresh) = self.keyring.seal(
                    &SecretBinding {
                        connection_id: request.connection_id,
                        scope_id: &claim.conn_scope_id,
                        account_id: request.account_id,
                        secret_kind: SecretKind::Refresh,
                        credential_generation: next_gen,
                        allowed_scopes: &allowed_scopes,
                    },
                    next_refresh_plain,
                ) else {
                    let _ = tx.rollback().await;
                    return RefreshStep::Unavailable;
                };
                let expires_secs = refreshed.expires_in_secs.map(|s| s as i64);
                let updated = sqlx::query(
                    "UPDATE openmettle.external_connections
                        SET granted_scopes = $2,
                            expires_at = CASE WHEN $3::bigint IS NOT NULL
                                              THEN clock_timestamp() + ($3::bigint * interval '1 second')
                                              ELSE NULL END,
                            encryption_key_id = $4,
                            access_salt = $5,
                            access_nonce = $6,
                            access_ciphertext = $7,
                            refresh_salt = $8,
                            refresh_nonce = $9,
                            refresh_ciphertext = $10,
                            credential_generation = $11,
                            refresh_claim_token = NULL,
                            refresh_lease_until = NULL,
                            updated_at = clock_timestamp()
                      WHERE id = $1::uuid
                        AND state = 'authorized'
                        AND refresh_claim_token = $12::uuid
                        AND credential_generation = $13
                        AND revocation_generation = $14",
                )
                .bind(request.connection_id)
                .bind(&next_granted)
                .bind(expires_secs)
                .bind(&new_access.key_id)
                .bind(new_access.salt.as_slice())
                .bind(new_access.nonce.as_slice())
                .bind(new_access.ciphertext.as_slice())
                .bind(new_refresh.salt.as_slice())
                .bind(new_refresh.nonce.as_slice())
                .bind(new_refresh.ciphertext.as_slice())
                .bind(next_gen)
                .bind(&claim.claim_token)
                .bind(claim.cred_gen)
                .bind(claim.rev_gen)
                .execute(&mut *tx)
                .await;
                if !matches!(updated, Ok(done) if done.rows_affected() == 1) {
                    let _ = tx.rollback().await;
                    return RefreshStep::Unavailable;
                }
                let audit_key = format!(
                    "vault-refresh/{}/{}/{}",
                    request.connection_id, next_gen, claim.claim_token
                );
                if worker_audit_connection(
                    &mut tx,
                    request.actor_user_id,
                    "connection.refreshed",
                    request.connection_id,
                    &audit_key,
                    "worker refreshed external connection credential",
                    json!({
                        "credential_generation": next_gen,
                        "encryption_key_id": new_access.key_id,
                        "granted_scope_count": next_granted.len(),
                    }),
                )
                .await
                .is_err()
                {
                    let _ = tx.rollback().await;
                    return RefreshStep::Unavailable;
                }
                // Re-verify live actor authority before returning the refreshed bearer token.
                let Ok(now_ms) = post_lock_clock_ms(&mut tx, 0).await else {
                    let _ = tx.rollback().await;
                    return RefreshStep::Unavailable;
                };
                let live_ok = verify_worker_connection_authority(
                    &mut tx,
                    request.scope_id,
                    &claim.conn_scope_id,
                    &claim.conn_scope_kind,
                    &claim.conn_owner_user_id,
                    request.connection_id,
                    request.actor_user_id,
                    request.actor_approval_id,
                    now_ms,
                )
                .await
                .unwrap_or(false);
                if tx.commit().await.is_err() || !live_ok {
                    return RefreshStep::Unavailable;
                }
                RefreshStep::Ready(McpCredential::bearer(refreshed.access_token.expose()))
            }
            RefreshOutcome::Refused => {
                self.commit_reauth_required(tx, request, &claim, "upstream_refused")
                    .await;
                RefreshStep::Unavailable
            }
            RefreshOutcome::Transient | RefreshOutcome::Unconfigured => {
                let _ = sqlx::query(
                    "UPDATE openmettle.external_connections
                        SET refresh_claim_token = NULL,
                            refresh_lease_until = NULL,
                            updated_at = clock_timestamp()
                      WHERE id = $1::uuid
                        AND state = 'authorized'
                        AND refresh_claim_token = $2::uuid
                        AND credential_generation = $3
                        AND revocation_generation = $4",
                )
                .bind(request.connection_id)
                .bind(&claim.claim_token)
                .bind(claim.cred_gen)
                .bind(claim.rev_gen)
                .execute(&mut *tx)
                .await;
                let now_ms = post_lock_clock_ms(&mut tx, 0).await.ok();
                let live_ok = match now_ms {
                    Some(ms) => verify_worker_connection_authority(
                        &mut tx,
                        request.scope_id,
                        &claim.conn_scope_id,
                        &claim.conn_scope_kind,
                        &claim.conn_owner_user_id,
                        request.connection_id,
                        request.actor_user_id,
                        request.actor_approval_id,
                        ms,
                    )
                    .await
                    .unwrap_or(false),
                    None => false,
                };
                let _ = tx.commit().await;
                if !live_ok {
                    return RefreshStep::Unavailable;
                }
                // If this was a proactive refresh while the stored access token is still
                // unexpired, continue serving the existing unexpired token; otherwise surface
                // `Transient` so callers can retry without wiping valid credentials.
                if let Some(ms) = now_ms
                    && cur_expires_ms.is_none_or(|exp| exp > ms)
                {
                    let key_id: Option<String> = fenced.try_get(7).unwrap_or(None);
                    let salt: Option<Vec<u8>> = fenced.try_get(8).unwrap_or(None);
                    let nonce: Option<Vec<u8>> = fenced.try_get(9).unwrap_or(None);
                    let ct: Option<Vec<u8>> = fenced.try_get(10).unwrap_or(None);
                    if let (Some(key_id), Some(salt), Some(nonce), Some(ct)) =
                        (key_id, salt, nonce, ct)
                        && let Ok(sealed) = decode_sealed(&key_id, salt, nonce, ct)
                        && let Ok(plain) = self.keyring.open(
                            &SecretBinding {
                                connection_id: request.connection_id,
                                scope_id: &claim.conn_scope_id,
                                account_id: request.account_id,
                                secret_kind: SecretKind::Access,
                                credential_generation: claim.cred_gen,
                                allowed_scopes: &allowed_scopes,
                            },
                            &sealed,
                        )
                    {
                        return RefreshStep::Ready(McpCredential::bearer(plain.expose()));
                    }
                }
                RefreshStep::Transient
            }
        }
    }

    async fn commit_reauth_required(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
        request: &CredentialRequest<'_>,
        claim: &ClaimedRefresh,
        reason_code: &'static str,
    ) {
        let next_rev = claim.rev_gen + 1;
        let updated = sqlx::query(
            "UPDATE openmettle.external_connections
                SET granted_scopes = ARRAY[]::text[],
                    state = 'reauth_required',
                    expires_at = NULL,
                    encryption_key_id = NULL,
                    access_salt = NULL,
                    access_nonce = NULL,
                    access_ciphertext = NULL,
                    refresh_salt = NULL,
                    refresh_nonce = NULL,
                    refresh_ciphertext = NULL,
                    revocation_generation = $2,
                    refresh_claim_token = NULL,
                    refresh_lease_until = NULL,
                    updated_at = clock_timestamp()
              WHERE id = $1::uuid
                AND state = 'authorized'
                AND refresh_claim_token = $3::uuid
                AND credential_generation = $4
                AND revocation_generation = $5",
        )
        .bind(request.connection_id)
        .bind(next_rev)
        .bind(&claim.claim_token)
        .bind(claim.cred_gen)
        .bind(claim.rev_gen)
        .execute(&mut *tx)
        .await;
        if let Ok(done) = updated
            && done.rows_affected() == 1
        {
            let audit_key = format!(
                "vault-reauth/{}/{}/{}",
                request.connection_id, next_rev, claim.claim_token
            );
            let _ = worker_audit_connection(
                &mut tx,
                request.actor_user_id,
                "connection.reauth_required",
                request.connection_id,
                &audit_key,
                "external connection requires re-authorization",
                json!({
                    "revocation_generation": next_rev,
                    "reason": reason_code,
                }),
            )
            .await;
            let _ = tx.commit().await;
        } else {
            let _ = tx.rollback().await;
        }
    }
}

struct ClaimedRefresh {
    conn_scope_id: String,
    conn_scope_kind: String,
    conn_owner_user_id: String,
    claim_token: String,
    cred_gen: i64,
    rev_gen: i64,
    provider_kind: String,
    endpoint_origin: String,
    allowed_scopes: Vec<String>,
    granted_scopes: Vec<String>,
    refresh_secret: SecretText,
}

enum RefreshStep {
    Ready(McpCredential),
    Wait,
    RetryRead,
    Transient,
    Unavailable,
}

impl McpCredentialProvider for VaultCredentialProvider {
    fn resolve<'a>(
        &'a self,
        request: CredentialRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = CredentialOutcome> + Send + 'a>> {
        Box::pin(async move { self.resolve_inner(request).await })
    }
}

/// Worker-side destination authorizer (`impl DestinationAuthorizer`) verifying live connection
/// state, destination tuple, pinned HTTPS origin, contract `lookup_scope`, actor/share authority,
/// and `restore_reconciliation_gate` directly on the caller's existing `Fence::Hold` connection
/// strictly before reconciliation credential lookups.
#[derive(Clone, Copy, Debug, Default)]
pub struct VaultDestinationAuthorizer;

impl VaultDestinationAuthorizer {
    pub fn new() -> Self {
        Self
    }

    async fn authorize_inner(&self, conn: &mut PgConnection, target: ReconcileTarget<'_>) -> bool {
        if runs::uuid(target.connection_id).is_err()
            || runs::uuid(target.scope_id).is_err()
            || runs::uuid(target.actor_user_id).is_err()
            || target
                .actor_approval_id
                .is_some_and(|id| runs::uuid(id).is_err())
            || !is_valid_scope_token(target.lookup_scope)
        {
            return false;
        }
        let Some((dest_conn, dest_acct, _dest_action)) =
            parse_destination_tuple(target.destination)
        else {
            return false;
        };
        if dest_conn != target.connection_id || dest_acct != target.account_id {
            return false;
        }
        if crate::restore::require_open_gate(&mut *conn).await.is_err() {
            return false;
        }
        let Ok(now_ms) = post_lock_clock_ms(&mut *conn, 0).await else {
            return false;
        };
        let row = sqlx::query(
            "SELECT scope_id::text, scope_kind, owner_user_id::text,
                    endpoint_origin, allowed_scopes, granted_scopes, state,
                    CASE WHEN expires_at IS NOT NULL
                         THEN floor(extract(epoch FROM expires_at) * 1000)::bigint END,
                    has_refresh
               FROM openmettle.external_connections
              WHERE id = $1::uuid AND account_id = $2",
        )
        .bind(target.connection_id)
        .bind(target.account_id)
        .fetch_optional(&mut *conn)
        .await;
        let Ok(Some(row)) = row else {
            return false;
        };
        let conn_scope_id: String = row.try_get(0).unwrap_or_default();
        let conn_scope_kind: String = row.try_get(1).unwrap_or_default();
        let conn_owner_user_id: String = row.try_get(2).unwrap_or_default();
        if !verify_worker_connection_authority(
            &mut *conn,
            target.scope_id,
            &conn_scope_id,
            &conn_scope_kind,
            &conn_owner_user_id,
            target.connection_id,
            target.actor_user_id,
            target.actor_approval_id,
            now_ms,
        )
        .await
        .unwrap_or(false)
        {
            return false;
        }
        let origin: String = row.try_get(3).unwrap_or_default();
        let allowed_scopes: Vec<String> = row.try_get(4).unwrap_or_default();
        let granted_scopes: Vec<String> = row.try_get(5).unwrap_or_default();
        let state: String = row.try_get(6).unwrap_or_default();
        let expires_ms: Option<i64> = row.try_get(7).unwrap_or(None);
        let has_refresh: bool = row.try_get(8).unwrap_or(false);
        if state != ConnectionState::Authorized.as_str() {
            return false;
        }
        if target.expected_origin.is_some_and(|exp| exp != origin) {
            return false;
        }
        if !granted_scopes.iter().any(|s| s == target.lookup_scope)
            || !allowed_scopes.iter().any(|s| s == target.lookup_scope)
        {
            return false;
        }
        expires_ms.is_none_or(|exp| exp > now_ms) || has_refresh
    }
}

fn parse_destination_tuple(destination: &str) -> Option<(String, String, String)> {
    let Value::Array(items) = serde_json::from_str(destination).ok()? else {
        return None;
    };
    if items.len() != 5 || items[0].as_str() != Some("v1") {
        return None;
    }
    Some((
        items[1].as_str()?.to_owned(),
        items[2].as_str()?.to_owned(),
        items[3].as_str()?.to_owned(),
    ))
}

impl DestinationAuthorizer for VaultDestinationAuthorizer {
    fn authorize_reconcile<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        target: ReconcileTarget<'a>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { self.authorize_inner(conn, target).await })
    }
}

// --- unit tests --------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ring() -> VaultKeyRing {
        VaultKeyRing::new(
            "k2".into(),
            vec![
                ("k1".into(), [0x11; KEY_BYTES]),
                ("k2".into(), [0x22; KEY_BYTES]),
            ],
        )
        .unwrap()
    }

    #[test]
    fn envelope_round_trips_and_rejects_every_aad_or_key_tamper() {
        let ring = test_ring();
        let scopes = vec!["issues.read".to_owned(), "issues.write".to_owned()];
        let binding = SecretBinding {
            connection_id: "00000000-0000-4000-8000-000000000001",
            scope_id: "00000000-0000-4000-8000-000000000002",
            account_id: "acct-alpha",
            secret_kind: SecretKind::Access,
            credential_generation: 1,
            allowed_scopes: &scopes,
        };
        let secret = SecretText::new("CANARY-ACCESS-TOKEN-98765").unwrap();
        let sealed = ring.seal(&binding, &secret).unwrap();
        assert_eq!(sealed.key_id, "k2");
        assert_ne!(sealed.ciphertext, secret.expose().as_bytes());

        // Redacted Debug never leaks secret or key material.
        let dbg_secret = format!("{secret:?}");
        let dbg_sealed = format!("{sealed:?}");
        let dbg_ring = format!("{ring:?}");
        assert!(!dbg_secret.contains("CANARY-ACCESS-TOKEN-98765"));
        assert!(!dbg_sealed.contains("CANARY"));
        assert!(!dbg_ring.contains("17") && dbg_ring.contains("k2"));

        let opened = ring.open(&binding, &sealed).unwrap();
        assert_eq!(opened.expose(), "CANARY-ACCESS-TOKEN-98765");

        // Fresh seal generates distinct salt and nonce.
        let sealed2 = ring.seal(&binding, &secret).unwrap();
        assert_ne!(sealed.salt, sealed2.salt);
        assert_ne!(sealed.nonce, sealed2.nonce);
        assert_ne!(sealed.ciphertext, sealed2.ciphertext);

        // Every AAD tamper fails closed.
        let wrong_conn = SecretBinding {
            connection_id: "00000000-0000-4000-8000-000000000099",
            ..binding
        };
        assert!(matches!(
            ring.open(&wrong_conn, &sealed),
            Err(VaultError::Crypto)
        ));

        let wrong_scope = SecretBinding {
            scope_id: "00000000-0000-4000-8000-000000000099",
            ..binding
        };
        assert!(matches!(
            ring.open(&wrong_scope, &sealed),
            Err(VaultError::Crypto)
        ));

        let wrong_acct = SecretBinding {
            account_id: "acct-beta",
            ..binding
        };
        assert!(matches!(
            ring.open(&wrong_acct, &sealed),
            Err(VaultError::Crypto)
        ));

        let wrong_kind = SecretBinding {
            secret_kind: SecretKind::Refresh,
            ..binding
        };
        assert!(matches!(
            ring.open(&wrong_kind, &sealed),
            Err(VaultError::Crypto)
        ));

        let wrong_gen = SecretBinding {
            credential_generation: 2,
            ..binding
        };
        assert!(matches!(
            ring.open(&wrong_gen, &sealed),
            Err(VaultError::Crypto)
        ));

        let widened_scopes = vec![
            "issues.admin".to_owned(),
            "issues.read".to_owned(),
            "issues.write".to_owned(),
        ];
        let wrong_scopes = SecretBinding {
            allowed_scopes: &widened_scopes,
            ..binding
        };
        assert!(matches!(
            ring.open(&wrong_scopes, &sealed),
            Err(VaultError::Crypto)
        ));

        // Swapping key_id fails closed.
        let mut wrong_key_sealed = sealed.clone();
        wrong_key_sealed.key_id = "k1".into();
        assert!(matches!(
            ring.open(&binding, &wrong_key_sealed),
            Err(VaultError::Crypto)
        ));

        // Missing key fails with UnknownKey.
        let mut missing_key = sealed.clone();
        missing_key.key_id = "k99".into();
        assert!(matches!(
            ring.open(&binding, &missing_key),
            Err(VaultError::UnknownKey)
        ));

        // Bit-flipped ciphertext fails closed.
        let mut flipped = sealed.clone();
        flipped.ciphertext[0] ^= 0x01;
        assert!(matches!(
            ring.open(&binding, &flipped),
            Err(VaultError::Crypto)
        ));
    }

    #[test]
    fn keyring_validation_and_file_loading_enforce_strict_invariants() {
        // Duplicate key ID, duplicate key bytes, all-zero key, missing active key all fail.
        assert!(VaultKeyRing::new("k1".into(), vec![]).is_err());
        assert!(VaultKeyRing::new("k1".into(), vec![("k1".into(), [0; 32])]).is_err());
        assert!(
            VaultKeyRing::new(
                "k1".into(),
                vec![("k1".into(), [1; 32]), ("k1".into(), [2; 32])]
            )
            .is_err()
        );
        assert!(
            VaultKeyRing::new(
                "k1".into(),
                vec![("k1".into(), [1; 32]), ("k2".into(), [1; 32])]
            )
            .is_err()
        );
        assert!(VaultKeyRing::new("missing".into(), vec![("k1".into(), [1; 32])]).is_err());

        // File-based loading enforces owner-only permissions on Unix.
        let dir = std::env::temp_dir().join(format!("om-vault-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("k1.key");
        let cfg_path = dir.join("vault.json");
        fs::write(&key_path, [0x42u8; 32]).unwrap();
        fs::write(
            &cfg_path,
            json!({
                "version": 1,
                "active_key_id": "k1",
                "keys": [{ "id": "k1", "file": key_path.to_str().unwrap() }]
            })
            .to_string(),
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(VaultKeyRing::load_from_config(&cfg_path).is_err());
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let ring = VaultKeyRing::load_from_config(&cfg_path).unwrap();
        assert_eq!(ring.active_key_id(), "k1");
        assert!(ring.has_key("k1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn validators_enforce_canonical_origins_scopes_and_secrets() {
        for ok in [
            "https://api.example.test",
            "https://mcp-1.sub.example.test:8443",
        ] {
            assert!(validate_endpoint_origin(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://api.example.test",
            "https://api.example.test/",
            "https://api.example.test/v1",
            "https://api.example.test:443",
            "https://API.example.test",
            "https://127.0.0.1:8443",
            "https://user:pass@api.example.test",
            "https://api.example.test?x=1",
            "https://api.example.test#frag",
        ] {
            assert!(validate_endpoint_origin(bad).is_err(), "{bad}");
        }

        let normalized = normalize_scopes(
            &["z.write".into(), "a.read".into(), "m:sync/1".into()],
            false,
        )
        .unwrap();
        assert_eq!(normalized, vec!["a.read", "m:sync/1", "z.write"]);
        assert!(normalize_scopes(&["a".into(), "a".into()], false).is_err());
        assert!(normalize_scopes(&["UPPER".into()], false).is_err());
        assert!(normalize_scopes(&[], false).is_err());
        assert!(scopes_are_subset(&["a.read".into()], &normalized));
        assert!(!scopes_are_subset(
            &["a.read".into(), "extra".into()],
            &normalized
        ));

        assert!(SecretText::new("tok_abc123.XYZ-_/=+").is_ok());
        assert!(SecretText::new("").is_err());
        assert!(SecretText::new("has space").is_err());
        assert!(SecretText::new("line\nbreak").is_err());
        assert!(SecretText::new_access(&"a".repeat(MAX_ACCESS_TOKEN_BYTES)).is_ok());
        assert!(SecretText::new_access(&"a".repeat(MAX_ACCESS_TOKEN_BYTES + 1)).is_err());
        assert!(SecretText::new_refresh(&"r".repeat(MAX_REFRESH_TOKEN_BYTES)).is_ok());
        assert!(SecretText::new_refresh(&"r".repeat(MAX_REFRESH_TOKEN_BYTES + 1)).is_err());

        // Idempotency MAC binds secret tokens and non-secret parameters without leaking plaintext.
        let ring = test_ring();
        let a1 = SecretText::new_access("CANARY-ACCESS-ONE").unwrap();
        let a2 = SecretText::new_access("CANARY-ACCESS-TWO").unwrap();
        let r1 = SecretText::new_refresh("CANARY-REFRESH-ONE").unwrap();
        let scopes = vec!["issues.read".to_owned()];
        let mac1 = ring
            .idempotency_mac_hex("c1", "s1", &a1, Some(&r1), &scopes, None)
            .unwrap();
        let mac1_again = ring
            .idempotency_mac_hex("c1", "s1", &a1, Some(&r1), &scopes, None)
            .unwrap();
        let mac2 = ring
            .idempotency_mac_hex("c1", "s1", &a2, Some(&r1), &scopes, None)
            .unwrap();
        let mac_no_ref = ring
            .idempotency_mac_hex("c1", "s1", &a1, None, &scopes, None)
            .unwrap();
        assert_eq!(mac1.len(), 64);
        assert_eq!(mac1, mac1_again);
        assert_ne!(mac1, mac2);
        assert_ne!(mac1, mac_no_ref);
        assert!(!mac1.contains("CANARY"));

        // Permanent OAuth 400 classification preserves non-OAuth 400s as transient.
        assert!(is_permanent_oauth_400(br#"{"error":"invalid_grant"}"#));
        assert!(is_permanent_oauth_400(br#"{"error":"invalid_client"}"#));
        assert!(is_permanent_oauth_400(
            br#"{"error":"unauthorized_client"}"#
        ));
        assert!(is_permanent_oauth_400(br#"{"error":"invalid_scope"}"#));
        assert!(!is_permanent_oauth_400(br#"{"error":"server_error"}"#));
        assert!(!is_permanent_oauth_400(b"Bad Request from proxy"));
    }

    #[tokio::test]
    async fn refresh_registry_binds_provider_and_origin_non_destructively() {
        let ca = crate::provider_http::fixture::Ca::new();
        let client = Arc::new(
            HttpsRefreshClient::new(
                "github",
                &["https://mcp.vendor.example.test"],
                "https://oauth.vendor.example.test/token",
                Trust::Bundle(&ca.pem()),
                &[],
                Some("synthetic-client".into()),
                RefreshTimeouts::default(),
            )
            .unwrap(),
        );
        let mut reg = VaultRefreshRegistry::new();
        reg.register(Arc::clone(&client)).unwrap();
        // Duplicate (provider_kind, origin) is refused.
        assert!(reg.register(client).is_err());

        let refresh_tok = SecretText::new_refresh("CANARY-UNROUTED-REFRESH").unwrap();
        let scopes = vec!["issues.read".to_owned()];
        // Wrong provider_kind or wrong MCP origin returns Unconfigured without network I/O.
        for (provider_kind, origin) in [
            ("gitlab", "https://mcp.vendor.example.test"),
            ("github", "https://other.vendor.example.test"),
        ] {
            let outcome = reg
                .refresh(
                    RefreshRequest {
                        connection_id: "00000000-0000-4000-8000-000000000001",
                        provider_kind,
                        account_id: "acct-1",
                        endpoint_origin: origin,
                        refresh_token: &refresh_tok,
                        allowed_scopes: &scopes,
                        current_granted_scopes: &scopes,
                    },
                    Instant::now() + Duration::from_secs(5),
                )
                .await;
            assert!(
                matches!(outcome, RefreshOutcome::Unconfigured),
                "expected Unconfigured for ({provider_kind}, {origin}), got {outcome:?}"
            );
        }
    }
}
