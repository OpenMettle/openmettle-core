//! Synthetic provider, with real code/challenge/client/callback binding. No network.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    Audience, IdToken, IdTokenClaims, IssuerUrl, JsonWebKeyId, Nonce, PrivateSigningKey,
    StandardClaims, SubjectIdentifier,
    core::{
        CoreGenderClaim, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
    },
};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub const ID: &str = "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f";
pub const ISSUER: &str = "https://issuer.example.test/realm";
pub const CLIENT: &str = "synthetic-client";
pub const CALLBACK: &str = "https://app.example.test/callback";
pub const AUTH: &str = "https://issuer.example.test/authorize";
pub const TOKEN: &str = "https://issuer.example.test/token";
pub fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1800000000)
}
fn key() -> &'static CoreRsaPrivateSigningKey {
    static KEY: OnceLock<CoreRsaPrivateSigningKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let k = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        CoreRsaPrivateSigningKey::from_pem(
            &k.to_pkcs1_pem(LineEnding::LF).unwrap(),
            Some(JsonWebKeyId::new("test".into())),
        )
        .unwrap()
    })
}
pub fn jwks() -> Vec<u8> {
    serde_json::to_vec(&CoreJsonWebKeySet::new(vec![key().as_verification_key()])).unwrap()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Extra {
    nbf: i64,
}
impl openidconnect::AdditionalClaims for Extra {}
pub fn signed(nonce: &str, issuer: &str, audience: &str, nbf: i64) -> String {
    let claims = IdTokenClaims::<Extra, CoreGenderClaim>::new(
        IssuerUrl::new(issuer.into()).unwrap(),
        vec![Audience::new(audience.into())],
        chrono::DateTime::from_timestamp(1800000300, 0).unwrap(),
        chrono::DateTime::from_timestamp(1799999990, 0).unwrap(),
        StandardClaims::new(SubjectIdentifier::new("synthetic-subject".into())),
        Extra { nbf },
    )
    .set_nonce(Some(Nonce::new(nonce.into())));
    IdToken::<_, _, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>::new(
        claims,
        key(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap()
    .to_string()
}
pub struct FakeProvider {
    issued: Mutex<HashMap<String, HashMap<String, String>>>,
}
impl FakeProvider {
    pub fn new() -> Self {
        Self {
            issued: Mutex::new(HashMap::new()),
        }
    }
    pub fn authorize(&self, url: &str) -> String {
        let url = openidconnect::url::Url::parse(url).unwrap();
        assert_eq!(url.origin().ascii_serialization() + url.path(), AUTH);
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(params["client_id"], CLIENT);
        assert_eq!(params["redirect_uri"], CALLBACK);
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["scope"], "openid");
        assert_eq!(params["nonce"].len(), 43);
        let code = format!("synthetic-code-{}", self.issued.lock().unwrap().len());
        self.issued.lock().unwrap().insert(code.clone(), params);
        code
    }
    pub fn exchange(
        &self,
        request: openidconnect::HttpRequest,
    ) -> Result<openidconnect::HttpResponse, std::io::Error> {
        let bad = || std::io::Error::other("SECRET-provider-marker");
        if request.uri() != TOKEN || request.method() != "POST" {
            return Err(bad());
        }
        let p: HashMap<String, String> = openidconnect::url::form_urlencoded::parse(request.body())
            .into_owned()
            .collect();
        let code = p.get("code").ok_or_else(bad)?;
        let issued = self.issued.lock().unwrap().remove(code).ok_or_else(bad)?;
        if p.get("grant_type").map(String::as_str) != Some("authorization_code")
            || p.get("client_id") != issued.get("client_id")
            || p.get("redirect_uri") != issued.get("redirect_uri")
        {
            return Err(bad());
        }
        let verifier = p.get("code_verifier").ok_or_else(bad)?;
        if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != issued["code_challenge"] {
            return Err(bad());
        }
        let token = signed(&issued["nonce"], ISSUER, CLIENT, 1799999990);
        Ok(openidconnect::http::Response::builder().status(200).header("content-type","application/json")
            .body(serde_json::to_vec(&serde_json::json!({"access_token":"SECRET-access","token_type":"Bearer","refresh_token":"SECRET-refresh","id_token":token})).unwrap()).unwrap())
    }
}
