//! Offline ID-token verification tests (ADR 0008). Keys are generated in memory for each test
//! process and never written to disk. All issuers, clients, subjects and nonces are synthetic.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AdditionalClaims, Audience, ClientId, EndUserEmail, IdToken, IdTokenClaims, IssuerUrl,
    JsonWebKeyId, Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
    core::{
        CoreGenderClaim, CoreHmacKey, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
    },
};
use openmettle_core::auth::{
    ConfigError, ExpectedNonce, MAX_ID_TOKEN_BYTES, MAX_JWKS_BYTES, Policy, TrustedProvider,
    UnverifiedIdToken, VerifyError,
};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use std::{
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const PROVIDER: &str = "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f";
const ISSUER: &str = "https://issuer.example.test/realms/synthetic";
const CLIENT: &str = "openmettle-synthetic-client";
const SUBJECT: &str = "synthetic-subject-0001";
const NONCE: &str = "synthetic-nonce-0123456789abcdef";
/// Fixed trusted clock: 2027-01-15T08:00:00Z.
const NOW_SECS: i64 = 1_800_000_000;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS as u64)
}

fn at(offset_secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(NOW_SECS + offset_secs, 0).unwrap()
}

/// In-memory RSA signing key; generation is slow in debug builds, so keys are shared.
fn rsa_key(kid: &'static str) -> &'static CoreRsaPrivateSigningKey {
    static K1: OnceLock<CoreRsaPrivateSigningKey> = OnceLock::new();
    static K2: OnceLock<CoreRsaPrivateSigningKey> = OnceLock::new();
    static ATTACKER: OnceLock<CoreRsaPrivateSigningKey> = OnceLock::new();
    let (cell, id) = match kid {
        "k1" => (&K1, "k1"),
        "k2" => (&K2, "k2"),
        // A different key that claims the trusted key's identifier.
        _ => (&ATTACKER, "k1"),
    };
    cell.get_or_init(|| {
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let pem = private.to_pkcs1_pem(LineEnding::LF).unwrap();
        CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new(id.into()))).unwrap()
    })
}

fn jwks(kids: &[&'static str]) -> Vec<u8> {
    let keys = kids
        .iter()
        .map(|kid| rsa_key(kid).as_verification_key())
        .collect();
    serde_json::to_vec(&CoreJsonWebKeySet::new(keys)).unwrap()
}

fn provider() -> TrustedProvider {
    TrustedProvider::new(PROVIDER, ISSUER, CLIENT, &jwks(&["k1"])).unwrap()
}

fn nonce() -> ExpectedNonce {
    ExpectedNonce::new(NONCE).unwrap()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Extra {
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<i64>,
}
impl AdditionalClaims for Extra {}

type Claims = IdTokenClaims<Extra, CoreGenderClaim>;
type Token =
    IdToken<Extra, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;

fn claims() -> Claims {
    IdTokenClaims::new(
        IssuerUrl::new(ISSUER.into()).unwrap(),
        vec![Audience::new(CLIENT.into())],
        at(300),
        at(-10),
        StandardClaims::new(SubjectIdentifier::new(SUBJECT.into())),
        Extra::default(),
    )
    .set_nonce(Some(Nonce::new(NONCE.into())))
}

fn sign_with<S>(claims: Claims, key: &S, alg: CoreJwsSigningAlgorithm) -> String
where
    S: PrivateSigningKey<VerificationKey = openidconnect::core::CoreJsonWebKey>,
{
    let token = Token::new(claims, key, alg, None, None).unwrap();
    serde_json::to_value(&token)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn sign(claims: Claims, kid: &'static str) -> String {
    sign_with(
        claims,
        rsa_key(kid),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    )
}

fn verify_with(
    provider: &TrustedProvider,
    token: &str,
) -> Result<openmettle_core::auth::VerifiedIdentity, VerifyError> {
    provider.verify(
        &UnverifiedIdToken::new(token)?,
        &nonce(),
        &Policy::default(),
        now(),
    )
}

fn verify(token: &str) -> Result<openmettle_core::auth::VerifiedIdentity, VerifyError> {
    verify_with(&provider(), token)
}

/// A compact token from raw JSON parts with an arbitrary signature segment.
fn raw(header: &str, payload: &str, signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

fn payload_json(c: &Claims) -> String {
    serde_json::to_string(c).unwrap()
}

#[test]
fn valid_token_yields_only_provider_issuer_subject() {
    let identity = verify(&sign(claims(), "k1")).unwrap();
    assert_eq!(identity.provider_config_id(), PROVIDER);
    assert_eq!(identity.issuer(), ISSUER);
    assert_eq!(identity.subject(), SUBJECT);
}

#[test]
fn email_and_name_claims_do_not_affect_identity() {
    let mut standard = StandardClaims::new(SubjectIdentifier::new(SUBJECT.into()));
    standard = standard.set_email(Some(EndUserEmail::new("someone@example.test".into())));
    let c = IdTokenClaims::new(
        IssuerUrl::new(ISSUER.into()).unwrap(),
        vec![Audience::new(CLIENT.into())],
        at(300),
        at(-10),
        standard,
        Extra::default(),
    )
    .set_nonce(Some(Nonce::new(NONCE.into())));
    let identity = verify(&sign(c, "k1")).unwrap();
    assert_eq!(identity.subject(), SUBJECT);
}

#[test]
fn issuer_must_match_exactly() {
    for issuer in [
        "https://attacker.example.test/realms/synthetic",
        "https://issuer.example.test/realms/synthetic/",
        "https://ISSUER.example.test/realms/synthetic",
    ] {
        let c = claims().set_issuer(IssuerUrl::new(issuer.into()).unwrap());
        assert_eq!(verify(&sign(c, "k1")), Err(VerifyError::Issuer), "{issuer}");
    }
}

#[test]
fn audience_policy_is_exact_single_client() {
    let wrong = claims().set_audiences(vec![Audience::new("other-client".into())]);
    assert_eq!(verify(&sign(wrong, "k1")), Err(VerifyError::Audience));
    // The library rejects untrusted additional audiences.
    let extra = claims().set_audiences(vec![
        Audience::new(CLIENT.into()),
        Audience::new("other-client".into()),
    ]);
    assert_eq!(verify(&sign(extra, "k1")), Err(VerifyError::Audience));
    // Multiple audiences are rejected even with a matching azp (initial provider limit).
    let duplicate = claims()
        .set_audiences(vec![
            Audience::new(CLIENT.into()),
            Audience::new(CLIENT.into()),
        ])
        .set_authorized_party(Some(ClientId::new(CLIENT.into())));
    assert_eq!(verify(&sign(duplicate, "k1")), Err(VerifyError::Audience));
}

#[test]
fn authorized_party_must_match_when_present() {
    let ok = claims().set_authorized_party(Some(ClientId::new(CLIENT.into())));
    assert!(verify(&sign(ok, "k1")).is_ok());
    let wrong = claims().set_authorized_party(Some(ClientId::new("other-client".into())));
    assert_eq!(
        verify(&sign(wrong, "k1")),
        Err(VerifyError::AuthorizedParty)
    );
}

#[test]
fn nonce_is_mandatory_and_must_match() {
    let missing = claims().set_nonce(None);
    assert_eq!(verify(&sign(missing, "k1")), Err(VerifyError::Nonce));
    let wrong = claims().set_nonce(Some(Nonce::new("synthetic-nonce-other-value-000".into())));
    assert_eq!(verify(&sign(wrong, "k1")), Err(VerifyError::Nonce));
    for bad in [
        "",
        "short",
        &"n".repeat(513),
        "contains space 0123456789abc",
    ] {
        assert_eq!(ExpectedNonce::new(bad).err(), Some(ConfigError::Nonce));
    }
}

#[test]
fn expiry_is_strict() {
    let expired = claims().set_expiration(at(0));
    assert_eq!(verify(&sign(expired, "k1")), Err(VerifyError::Expired));
    let past = claims().set_expiration(at(-1));
    assert_eq!(verify(&sign(past, "k1")), Err(VerifyError::Expired));
    let next = claims().set_expiration(at(1));
    assert!(verify(&sign(next, "k1")).is_ok());
}

#[test]
fn issue_time_is_bounded() {
    let future = claims().set_issue_time(at(61));
    assert_eq!(
        verify(&sign(future, "k1")),
        Err(VerifyError::IssuedInFuture)
    );
    let skewed = claims().set_issue_time(at(60));
    assert!(verify(&sign(skewed, "k1")).is_ok());
    let stale = claims().set_issue_time(at(-301));
    assert_eq!(
        verify(&sign(stale, "k1")),
        Err(VerifyError::IssuedTooLongAgo)
    );
    let oldest = claims().set_issue_time(at(-300));
    assert!(verify(&sign(oldest, "k1")).is_ok());
    // A stricter injected policy applies to the same token.
    let token = sign(claims().set_issue_time(at(-120)), "k1");
    let strict = Policy::new(Duration::from_secs(60), Duration::from_secs(5)).unwrap();
    let result = provider().verify(
        &UnverifiedIdToken::new(&token).unwrap(),
        &nonce(),
        &strict,
        now(),
    );
    assert_eq!(result, Err(VerifyError::IssuedTooLongAgo));
}

#[test]
fn not_before_is_enforced_when_present() {
    let mut c = claims();
    c.additional_claims_mut().nbf = Some(NOW_SECS + 61);
    assert_eq!(verify(&sign(c, "k1")), Err(VerifyError::NotYetValid));
    let mut c = claims();
    c.additional_claims_mut().nbf = Some(NOW_SECS + 60);
    assert!(verify(&sign(c, "k1")).is_ok());
}

#[test]
fn subject_is_bounded() {
    let long = claims().set_subject(SubjectIdentifier::new("s".repeat(256)));
    assert_eq!(verify(&sign(long, "k1")), Err(VerifyError::Subject));
    let empty = claims().set_subject(SubjectIdentifier::new(String::new()));
    assert_eq!(verify(&sign(empty, "k1")), Err(VerifyError::Subject));
}

#[test]
fn malformed_tokens_and_claims_are_rejected() {
    for bad in [
        "",
        "a.b",
        "a.b.c.d",
        "a b.c.d",
        "a.b.c=",
        &"a".repeat(MAX_ID_TOKEN_BYTES + 1),
    ] {
        assert_eq!(
            UnverifiedIdToken::new(bad).err(),
            Some(VerifyError::Malformed),
            "{}",
            bad.len()
        );
    }
    let header = r#"{"alg":"RS256","kid":"k1"}"#;
    for payload in [
        "not json",
        r#"{"iss":"https://issuer.example.test/realms/synthetic"}"#,
        &payload_json(&claims()).replace(r#""sub":"#, r#""sub_":"#),
        &payload_json(&claims()).replacen('{', r#"{"nbf":"soon","#, 1),
    ] {
        assert_eq!(
            verify(&raw(header, payload, b"sig")),
            Err(VerifyError::Malformed)
        );
    }
    assert_eq!(
        verify(&raw("not json", &payload_json(&claims()), b"sig")),
        Err(VerifyError::Malformed)
    );
}

#[test]
fn unsigned_and_hmac_tokens_are_rejected() {
    let payload = payload_json(&claims());
    let none = raw(r#"{"alg":"none"}"#, &payload, b"");
    assert_eq!(verify(&none), Err(VerifyError::DisallowedAlgorithm));
    let none_kid = raw(r#"{"alg":"none","kid":"k1"}"#, &payload, b"sig");
    assert_eq!(verify(&none_kid), Err(VerifyError::DisallowedAlgorithm));
    // Key confusion: an HMAC keyed with the trusted public key material.
    for secret in [jwks(&["k1"]), CLIENT.as_bytes().to_vec()] {
        let hmac = sign_with(
            claims(),
            &CoreHmacKey::new(secret),
            CoreJwsSigningAlgorithm::HmacSha256,
        );
        assert_eq!(verify(&hmac), Err(VerifyError::DisallowedAlgorithm));
    }
}

#[test]
fn disallowed_rsa_algorithm_is_rejected() {
    let rs384 = sign_with(
        claims(),
        rsa_key("k1"),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
    );
    assert_eq!(verify(&rs384), Err(VerifyError::DisallowedAlgorithm));
}

#[test]
fn forged_and_tampered_signatures_are_rejected() {
    // Different key presenting the trusted key identifier.
    assert_eq!(
        verify(&sign(claims(), "attacker")),
        Err(VerifyError::InvalidSignature)
    );
    // Valid signature over different claims, spliced onto a modified payload.
    let token = sign(claims(), "k1");
    let parts: Vec<&str> = token.split('.').collect();
    let other = claims().set_subject(SubjectIdentifier::new("synthetic-subject-0002".into()));
    let spliced = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(payload_json(&other)),
        parts[2]
    );
    assert_eq!(verify(&spliced), Err(VerifyError::InvalidSignature));
    let truncated = format!("{}.{}.{}", parts[0], parts[1], &parts[2][..8]);
    assert_eq!(verify(&truncated), Err(VerifyError::InvalidSignature));
}

#[test]
fn unknown_key_and_replacement_key_set() {
    assert_eq!(verify(&sign(claims(), "k2")), Err(VerifyError::UnknownKey));
    // Replacing the trusted key set is an explicit caller input, not automatic rotation.
    let replaced = TrustedProvider::new(PROVIDER, ISSUER, CLIENT, &jwks(&["k2"])).unwrap();
    assert!(verify_with(&replaced, &sign(claims(), "k2")).is_ok());
    assert_eq!(
        verify_with(&replaced, &sign(claims(), "k1")),
        Err(VerifyError::UnknownKey)
    );
    let both = TrustedProvider::new(PROVIDER, ISSUER, CLIENT, &jwks(&["k1", "k2"])).unwrap();
    assert!(verify_with(&both, &sign(claims(), "k1")).is_ok());
    assert!(verify_with(&both, &sign(claims(), "k2")).is_ok());
}

#[test]
fn trusted_inputs_are_validated() {
    let keys = jwks(&["k1"]);
    let new = |id: &str, iss: &str, client: &str, jwks: &[u8]| {
        TrustedProvider::new(id, iss, client, jwks).err()
    };
    assert_eq!(
        new("not-a-uuid", ISSUER, CLIENT, &keys),
        Some(ConfigError::ProviderConfigId)
    );
    assert_eq!(
        new(&PROVIDER.to_uppercase(), ISSUER, CLIENT, &keys),
        Some(ConfigError::ProviderConfigId)
    );
    assert_eq!(
        new(PROVIDER, "http://issuer.example.test", CLIENT, &keys),
        Some(ConfigError::Issuer)
    );
    assert_eq!(
        new(PROVIDER, ISSUER, "", &keys),
        Some(ConfigError::ClientId)
    );
    assert_eq!(
        new(PROVIDER, ISSUER, "tab\tclient", &keys),
        Some(ConfigError::ClientId)
    );
    for bad in [
        b"".to_vec(),
        b"not json".to_vec(),
        br#"{"keys":[]}"#.to_vec(),
        br#"{"keys":[{"kty":"unknown"}]}"#.to_vec(),
        vec![b' '; MAX_JWKS_BYTES + 1],
    ] {
        assert_eq!(new(PROVIDER, ISSUER, CLIENT, &bad), Some(ConfigError::Jwks));
    }
    let key = serde_json::to_value(rsa_key("k1").as_verification_key()).unwrap();
    let many = serde_json::to_vec(&serde_json::json!({ "keys": vec![key; 17] })).unwrap();
    assert_eq!(
        new(PROVIDER, ISSUER, CLIENT, &many),
        Some(ConfigError::Jwks)
    );
    assert!(
        TrustedProvider::new(PROVIDER, ISSUER, CLIENT, &keys).is_ok(),
        "baseline"
    );
}

#[test]
fn diagnostics_never_echo_token_or_identity_values() {
    const MARK: &str = "MARKERX7Q";
    let provider = TrustedProvider::new(
        PROVIDER,
        &format!("https://{MARK}.example.test"),
        &format!("{MARK}-client"),
        &jwks(&["k1"]),
    )
    .unwrap();
    let marked = |c: Claims| {
        c.set_issuer(IssuerUrl::new(format!("https://{MARK}.example.test")).unwrap())
            .set_audiences(vec![Audience::new(format!("{MARK}-client"))])
            .set_subject(SubjectIdentifier::new(format!("{MARK}-subject")))
            .set_authorized_party(Some(ClientId::new(format!("{MARK}-client"))))
            .set_nonce(Some(Nonce::new(format!("{MARK}-nonce-0123456789abcdef"))))
    };
    let expected = ExpectedNonce::new(&format!("{MARK}-nonce-0123456789abcdef")).unwrap();
    let cases = [
        marked(claims())
            .set_issuer(IssuerUrl::new(format!("https://{MARK}2.example.test")).unwrap()),
        marked(claims()).set_audiences(vec![Audience::new(format!("{MARK}-other"))]),
        marked(claims()).set_authorized_party(Some(ClientId::new(format!("{MARK}-azp")))),
        marked(claims()).set_nonce(Some(Nonce::new(format!("{MARK}-wrong-nonce-0123456789")))),
        marked(claims()).set_expiration(at(-1)),
    ];
    let mut seen = Vec::new();
    for c in cases {
        let token = sign(c, "k1");
        let unverified = UnverifiedIdToken::new(&token).unwrap();
        let error = provider
            .verify(&unverified, &expected, &Policy::default(), now())
            .unwrap_err();
        seen.push(error);
        for text in [
            error.to_string(),
            format!("{error:?}"),
            format!("{unverified:?}"),
            format!("{expected:?}"),
            format!("{provider:?}"),
        ] {
            assert!(!text.contains(MARK), "{text}");
            assert!(!text.contains(&token[..20]), "{text}");
        }
    }
    assert_eq!(
        seen,
        [
            VerifyError::Issuer,
            VerifyError::Audience,
            VerifyError::AuthorizedParty,
            VerifyError::Nonce,
            VerifyError::Expired
        ]
    );
    let identity = provider
        .verify(
            &UnverifiedIdToken::new(&sign(marked(claims()), "k1")).unwrap(),
            &expected,
            &Policy::default(),
            now(),
        )
        .unwrap();
    assert!(!format!("{identity:?}").contains(MARK));
}

#[test]
fn weak_rsa_moduli_are_rejected_even_with_zero_padding() {
    for bits in [512, 1024] {
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, bits).unwrap();
        let pem = private.to_pkcs1_pem(LineEnding::LF).unwrap();
        let signing =
            CoreRsaPrivateSigningKey::from_pem(&pem, Some(JsonWebKeyId::new("weak".into())))
                .unwrap();
        let token = sign_with(
            claims(),
            &signing,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        );
        assert!(UnverifiedIdToken::new(&token).is_ok());
        let mut keys =
            serde_json::to_value(CoreJsonWebKeySet::new(vec![signing.as_verification_key()]))
                .unwrap();
        let original = URL_SAFE_NO_PAD
            .decode(keys["keys"][0]["n"].as_str().unwrap())
            .unwrap();
        for padding in [0, 256] {
            let mut modulus = vec![0; padding];
            modulus.extend_from_slice(&original);
            keys["keys"][0]["n"] = URL_SAFE_NO_PAD.encode(modulus).into();
            assert_eq!(
                TrustedProvider::new(
                    PROVIDER,
                    ISSUER,
                    CLIENT,
                    &serde_json::to_vec(&keys).unwrap()
                )
                .err(),
                Some(ConfigError::Jwks)
            );
        }
    }
    // A real 2048-bit signature remains valid with a zero-prefixed public modulus.
    let mut keys: serde_json::Value = serde_json::from_slice(&jwks(&["k1"])).unwrap();
    let mut modulus = vec![0; 8];
    modulus.extend(
        URL_SAFE_NO_PAD
            .decode(keys["keys"][0]["n"].as_str().unwrap())
            .unwrap(),
    );
    keys["keys"][0]["n"] = URL_SAFE_NO_PAD.encode(modulus).into();
    let trusted = TrustedProvider::new(
        PROVIDER,
        ISSUER,
        CLIENT,
        &serde_json::to_vec(&keys).unwrap(),
    )
    .unwrap();
    assert!(verify_with(&trusted, &sign(claims(), "k1")).is_ok());
    // Byte length alone must not accept a 2047-bit or all-zero modulus.
    for leading in [0x7f, 0] {
        let mut bytes = vec![0; 256];
        bytes[0] = leading;
        keys["keys"][0]["n"] = URL_SAFE_NO_PAD.encode(bytes).into();
        assert_eq!(
            TrustedProvider::new(
                PROVIDER,
                ISSUER,
                CLIENT,
                &serde_json::to_vec(&keys).unwrap()
            )
            .err(),
            Some(ConfigError::Jwks)
        );
    }
}

#[test]
fn subjects_must_be_ascii_and_nul_free_without_normalization() {
    for subject in ["user\0suffix", "usér", "用户"] {
        let token = sign(
            claims().set_subject(SubjectIdentifier::new(subject.into())),
            "k1",
        );
        assert_eq!(verify(&token).err(), Some(VerifyError::Subject));
    }
    for subject in ["x".into(), "s".repeat(255), " leading and trailing ".into()] {
        let token = sign(
            claims().set_subject(SubjectIdentifier::new(subject.clone())),
            "k1",
        );
        assert_eq!(verify(&token).unwrap().subject(), subject);
    }
}

#[test]
fn digest_nonce_uses_same_verification_and_bounds() {
    use openmettle_core::auth::ExpectedNonceDigest;
    let p = provider();
    let expected = ExpectedNonceDigest::from_nonce(&nonce());
    let token = UnverifiedIdToken::new(&sign(claims(), "k1")).unwrap();
    assert!(
        p.verify_digest(&token, &expected, &Policy::default(), now())
            .is_ok()
    );
    assert_eq!(
        p.verify_digest(
            &token,
            &ExpectedNonceDigest::new([0; 32]),
            &Policy::default(),
            now()
        ),
        Err(VerifyError::Nonce)
    );
    for value in ["x".repeat(513), "x".repeat(21), "x\0".repeat(22)] {
        let c = claims().set_nonce(Some(Nonce::new(value)));
        let token = UnverifiedIdToken::new(&sign(c, "k1")).unwrap();
        assert_eq!(
            p.verify_digest(&token, &expected, &Policy::default(), now()),
            Err(VerifyError::Nonce)
        );
    }
}
