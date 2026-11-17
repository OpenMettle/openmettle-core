//! Synthetic auth-config files for the loader and process tests (ADR 0015). Every file lives in
//! a per-test temporary directory that is removed on drop; nothing is written elsewhere.
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Dir(PathBuf);
impl Dir {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "openmettle-auth-config-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        );
        // Canonical, so the absolute paths handed to the loader contain no symbolic link.
        let path = fs::canonicalize(std::env::temp_dir()).unwrap().join(unique);
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    /// Absolute path of `name` inside this directory.
    pub fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }
    pub fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.path(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A valid version-1 document. Writes two raw 32-byte key files and the given PEM bundle into
/// `dir`. Every numeric value is distinct so tests can address one member in the JSON text.
pub fn document(dir: &Dir, bundle: &[u8]) -> Value {
    json!({
        "version": 1,
        "login": {
            "lifetime_seconds": 300,
            "keys": {
                "active": {"id": "login-b", "path": dir.write("login-key-b", &[0xb1; 32])},
                "decrypt_only": [
                    {"id": "login-a", "path": dir.write("login-key-a", &[0xa0; 32])}
                ]
            }
        },
        "id_token": {"max_issued_at_age_seconds": 301, "future_skew_seconds": 60},
        "provider_refresh": {
            "freshness_seconds": 3600,
            "cooldown_seconds": 61,
            "deadline_milliseconds": 5000,
            "max_providers": 2,
            "max_callers": 32,
            "max_document_gets": 3
        },
        "session": {
            "lifetime_seconds": 28800,
            "retained_per_user": 16,
            "deadline_milliseconds": 5001
        },
        "providers": [{
            "id": "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
            "issuer": "https://issuer.example.test/realm",
            "client_id": "synthetic-client",
            "revision": "r1",
            "authorization_endpoint": "https://issuer.example.test/authorize",
            "token_endpoint": "https://issuer.example.test/token",
            "discovery_url": "https://issuer.example.test/realm/.well-known/openid-configuration",
            "jwks_url": "https://issuer.example.test/jwks",
            "callback": "https://app.example.test/callback",
            "destination": "web",
            "private_cidrs": ["10.20.0.0/16"],
            "trust": {"roots": "bundle", "bundle_path": dir.write("provider-ca", bundle)}
        }]
    })
}
