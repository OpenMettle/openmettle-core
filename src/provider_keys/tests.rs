use super::*;
use crate::{login::fixture as signing, provider_http::fixture as tls};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{JsonWebKeyId, PrivateSigningKey, core::CoreRsaPrivateSigningKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{
    OnceLock,
    atomic::{AtomicI64, AtomicU64, Ordering},
};

fn policy() -> RefreshPolicy {
    RefreshPolicy::new(
        Duration::from_secs(600),
        Duration::from_secs(2),
        Duration::from_secs(5),
        2,
        32,
        2,
    )
    .unwrap()
}
fn key() -> &'static CoreRsaPrivateSigningKey {
    static KEY: OnceLock<CoreRsaPrivateSigningKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let k = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        CoreRsaPrivateSigningKey::from_pem(
            &k.to_pkcs1_pem(LineEnding::LF).unwrap(),
            Some(JsonWebKeyId::new("rotated".into())),
        )
        .unwrap()
    })
}
fn rotated() -> Vec<u8> {
    serde_json::to_vec(&json!({"keys":[key().as_verification_key()]})).unwrap()
}
fn token(new: bool) -> UnverifiedIdToken {
    let raw = if new {
        signing::signed_using(
            key(),
            &"n".repeat(43),
            signing::ISSUER,
            signing::CLIENT,
            1799999990,
        )
    } else {
        signing::signed(
            &"n".repeat(43),
            signing::ISSUER,
            signing::CLIENT,
            1799999990,
        )
    };
    UnverifiedIdToken::new(&raw).unwrap()
}
fn nonce() -> ExpectedNonceDigest {
    ExpectedNonceDigest::new(Sha256::digest("n".repeat(43).as_bytes()).into())
}
/// One armed upstream authorization: its exact `redirect_uri` and the ID token for its nonce.
struct Authorization {
    callback: String,
    token: String,
}
struct Script {
    metadata: Value,
    keys: Vec<u8>,
    cache: String,
    metadata_cache: String,
    date: std::time::SystemTime,
    // False omits Date, as stock Keycloak 26.8.2 does (PR #72).
    dated: bool,
    mode: &'static str,
    token: String,
    // Armed authorizations by upstream PKCE challenge. Empty keeps the fixed fixture verifier,
    // the registered callback and `token`.
    authorizations: HashMap<String, Authorization>,
    // Upstream challenges whose token POST was accepted, in arrival order.
    exchanged: Vec<String>,
    gate: Arc<tokio::sync::Notify>,
}
struct Harness {
    manager: ProviderManager,
    provider: ManagedProvider,
    server: tls::Server,
    ca: tls::Ca,
    script: Arc<Mutex<Script>>,
    ticks: Arc<AtomicU64>,
    wall: Arc<AtomicI64>,
}
impl Harness {
    async fn new() -> Self {
        Self::with_policy(policy()).await
    }
    async fn with_policy(policy: RefreshPolicy) -> Self {
        Self::with_endpoints(policy, signing::AUTH, signing::CALLBACK).await
    }
    async fn with_endpoints(policy: RefreshPolicy, authorization: &str, callback: &str) -> Self {
        let ca = tls::Ca::new();
        let script = Arc::new(Mutex::new(Script {
            gate: Arc::default(),
            metadata: Value::Null,
            keys: signing::jwks(),
            cache: "max-age=100".into(),
            metadata_cache: "max-age=100".into(),
            date: signing::now(),
            dated: true,
            mode: "ok",
            authorizations: HashMap::new(),
            exchanged: Vec::new(),
            token: signing::signed(
                &"n".repeat(43),
                signing::ISSUER,
                signing::CLIENT,
                1799999990,
            ),
        }));
        let data = script.clone();
        let registered_callback = callback.to_owned();
        let server=tls::Server::start(ca.leaf(tls::HOST,false),move |request|{
            let mut s=data.lock().unwrap();
            let discovery=request.head.starts_with("GET /discovery ");let jwks=request.head.starts_with("GET /jwks ");
            if s.mode=="stall" || s.mode=="post-stall" && !discovery && !jwks {return tls::Reply::Stall(vec![]);}
            if s.mode=="redirect" {return tls::Reply::Bytes(tls::response(302,&[("location","https://unconfigured.example.test/jwks")],b""));}
            if s.mode=="failure" {return tls::Reply::Bytes(tls::response(503,&[],b""));}
            if !discovery && !jwks {
                assert!(request.head.starts_with("POST /token "));
                let params:HashMap<String,String>=openidconnect::url::form_urlencoded::parse(&request.body).into_owned().collect();
                assert!(params["code"] == "synthetic-code", "authorization code mismatch");
                assert!(params["client_id"] == signing::CLIENT, "client binding mismatch");
                let verifier = &params["code_verifier"];
                // The verifier selects exactly one armed authorization. Its recorded callback is
                // the only accepted redirect_uri; another configured callback is refused.
                let token = if s.authorizations.is_empty() {
                    assert!(*verifier == "v".repeat(43), "fixture verifier mismatch");
                    assert!(params["redirect_uri"] == registered_callback, "callback binding mismatch");
                    s.token.clone()
                } else {
                    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
                    let armed = s.authorizations.get(&challenge).expect("PKCE mismatch");
                    assert!(params["redirect_uri"] == armed.callback, "callback binding mismatch");
                    let token = armed.token.clone();
                    s.exchanged.push(challenge);
                    token
                };
                let bytes=tls::json(&serde_json::to_vec(&json!({"access_token":"synthetic-access","token_type":"Bearer","id_token":token})).unwrap());
                return if s.mode=="gate-post" {tls::Reply::Gate(s.gate.clone(),bytes)} else {tls::Reply::Bytes(bytes)};
            }
            assert!(request.body.is_empty());
            let body=if discovery {serde_json::to_vec(&s.metadata).unwrap()}else{s.keys.clone()};
            let date=httpdate::fmt_http_date(s.date);
            let mut headers=vec![("content-type","application/json"),("cache-control",if discovery {s.metadata_cache.as_str()}else{s.cache.as_str()})];
            if s.dated {headers.push(("date",&date));}
            let bytes=tls::response(200,&headers,&body);
            if jwks && s.mode=="gate-jwks" {tls::Reply::Gate(s.gate.clone(),bytes)} else {tls::Reply::Bytes(bytes)}
        }).await;
        let manager = ProviderManager::new(policy);
        let ticks = Arc::new(AtomicU64::new(0));
        let wall = Arc::new(AtomicI64::new(0));
        let start = Instant::now();
        let t = ticks.clone();
        let w = wall.clone();
        *manager.inner.clock.lock().unwrap() = Some(Arc::new(move || {
            let t = t.load(Ordering::SeqCst);
            let w = w.load(Ordering::SeqCst);
            Sample {
                mono: start + Duration::from_secs(t),
                wall: signing::now() + Duration::from_secs(t)
                    - Duration::from_secs(w.unsigned_abs()),
            }
        }));
        let config =
            Self::endpoint_config(&server, &ca, signing::ID, "v1", authorization, callback);
        script.lock().unwrap().metadata = metadata(&config);
        let provider = manager.register(config).unwrap();
        Self {
            manager,
            provider,
            server,
            ca,
            script,
            ticks,
            wall,
        }
    }
    fn config(server: &tls::Server, ca: &tls::Ca, revision: &str) -> ProviderConfig {
        Self::endpoint_config(
            server,
            ca,
            signing::ID,
            revision,
            signing::AUTH,
            signing::CALLBACK,
        )
    }
    fn endpoint_config(
        server: &tls::Server,
        ca: &tls::Ca,
        provider_id: &str,
        revision: &str,
        authorization: &str,
        callback: &str,
    ) -> ProviderConfig {
        let base = format!("https://{}:{}", tls::HOST, server.port);
        let mut c = ProviderConfig::new(
            ProviderIdentity::new(provider_id, signing::ISSUER, signing::CLIENT).unwrap(),
            login::ProviderDefinition {
                revision,
                authorization_endpoint: authorization,
                token_endpoint: &format!("{base}/token"),
                callback,
                destination: "home",
                enabled: true,
            },
            &format!("{base}/discovery"),
            &format!("{base}/jwks"),
            Trust::Bundle(&ca.pem()),
            &[],
        )
        .unwrap();
        c.token = c.token.with_lookup(tls::loopback).allow_loopback_fixture();
        c.documents =
            ProviderDocuments::configured(&c.token, &c.discovery_url, &c.jwks_url).unwrap();
        c
    }
    fn advance(&self, seconds: u64) {
        self.ticks.fetch_add(seconds, Ordering::SeqCst);
    }
    async fn verify(&self, new: bool) -> Result<VerifiedIdentity, Error> {
        verify(&self.provider, token(new)).await
    }
    fn count(&self) -> usize {
        self.server.requests.load(Ordering::SeqCst)
    }
    async fn entered(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.count() < count {
                self.server.entered.notified().await;
            }
        })
        .await
        .expect("fixture request barrier timed out");
    }
    fn permit(&self) -> login::ExchangePermit {
        let c = self.provider.config().unwrap();
        let s = self.provider.snapshot().unwrap();
        login::fixture_permit(c.login(&s, None).unwrap(), Some(1))
    }
}
async fn verify(p: &ManagedProvider, token: UnverifiedIdToken) -> Result<VerifiedIdentity, Error> {
    let _slot = p.admission()?;
    let deadline = Instant::now() + p.manager.policy.deadline;
    let (generation, assertion) = tokio::time::timeout_at(
        deadline,
        p.verify(&token, &nonce(), &auth::Policy::default()),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    p.finish(generation, assertion, deadline)
}
/// In-memory release only. The committed-authority read is exercised by the PostgreSQL suite.
fn finish_in_memory(p: &ManagedProvider, e: ExchangedIdentity) -> Result<VerifiedIdentity, Error> {
    assert!(Arc::ptr_eq(&p.entry, &e.entry) && p.generation == e.generation);
    p.finish(e.key_generation, e.assertion, e.deadline)
}
fn metadata(c: &ProviderConfig) -> Value {
    json!({"issuer":c.identity.binding().1,"authorization_endpoint":c.authorization,"token_endpoint":c.token_url,"jwks_uri":c.jwks_url,"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"authorization_response_iss_parameter_supported":true})
}

#[tokio::test]
async fn cold_start_and_one_post_with_unknown_key_refresh() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 2);
    let permit = h.permit();
    h.advance(2);
    {
        let mut s = h.script.lock().unwrap();
        s.keys = rotated();
        s.token = signing::signed_using(
            key(),
            &"n".repeat(43),
            signing::ISSUER,
            signing::CLIENT,
            1799999990,
        );
    }
    let exchanged = permit
        .exchange_with_keys(&h.provider, &auth::Policy::default())
        .await
        .unwrap();
    assert_eq!(format!("{exchanged:?}"), "ExchangedIdentity(..)");
    // A login that sealed no invitation code yields a proof without one.
    assert!(exchanged.invitation.is_none());
    let identity = finish_in_memory(&h.provider, exchanged).unwrap();
    assert_eq!(identity.subject(), "synthetic-subject");
    assert_eq!(h.count(), 5);
    {
        let heads = h.server.heads.lock().unwrap();
        assert_eq!(heads.iter().filter(|s| s.starts_with("POST")).count(), 1);
        assert_eq!(heads.iter().filter(|s| s.starts_with("GET")).count(), 4);
    }
    assert!(h.verify(false).await.is_err());
    assert_eq!(h.count(), 5);
    assert!(h.verify(true).await.is_ok());
}
#[tokio::test]
async fn managed_exchange_preserves_signed_membership_and_never_resolves_overage() {
    use crate::membership::Observation::{Partial, Present};
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    for (claims, decision) in [
        (json!({"groups":["team"]}), Present),
        (
            json!({"groups":["team"],"_claim_sources":{"src1":{"endpoint":"https://unused.example.test"}}}),
            Partial,
        ),
    ] {
        h.script.lock().unwrap().token =
            signing::membership_token("synthetic-subject", &"n".repeat(43), 1799999990, claims);
        let proof = h
            .permit()
            .exchange_with_keys(&h.provider, &auth::Policy::default())
            .await
            .unwrap();
        assert_eq!(
            proof.assertion.membership.select("group", "groups", "team"),
            decision
        );
        assert_eq!(
            finish_in_memory(&h.provider, proof).unwrap().subject(),
            "synthetic-subject"
        );
    }
    assert_eq!(h.count(), 4); // Discovery, JWKS, and one token POST per permit.
}
/// The invitation code sealed with a login travels from its permit to the sealed proof
/// (ADR 0022). Neither value shows it in debug output.
#[tokio::test]
async fn managed_exchange_carries_the_sealed_invitation_code_to_the_proof() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    h.script.lock().unwrap().token = signing::signed(
        &"n".repeat(43),
        signing::ISSUER,
        signing::CLIENT,
        1799999990,
    );
    let mut permit = h.permit();
    permit.invitation = crate::invitation::InvitationCode::parse(&"5a".repeat(16));
    assert_eq!(format!("{permit:?}"), "ExchangePermit(..)");
    let proof = permit
        .exchange_with_keys(&h.provider, &auth::Policy::default())
        .await
        .unwrap();
    let carried = proof.invitation.as_ref().map(|code| *code.bytes());
    assert_eq!(carried, Some([0x5a; 16]));
    assert_eq!(format!("{proof:?}"), "ExchangedIdentity(..)");
}
#[tokio::test]
async fn successful_replacements_retire_removed_and_noncacheable_keys() {
    for (cache, usable) in [
        ("max-age=100", true),
        ("no-store", true),
        ("no-cache", true),
        ("max-age=0", false),
        ("max-age=bogus", false),
        ("no-cache, bogus", false),
    ] {
        let h = Harness::new().await;
        h.provider.preflight().await.unwrap();
        h.advance(2);
        {
            let mut s = h.script.lock().unwrap();
            s.keys = rotated();
            s.cache = cache.into();
        }
        h.provider.refresh(None).await.unwrap();
        assert!(h.verify(false).await.is_err());
        assert_eq!(h.verify(true).await.is_ok(), usable, "{cache}");
        assert_eq!(h.count(), 4);
    }
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    h.advance(2);
    h.script.lock().unwrap().keys = b"{\"keys\":[]}".to_vec();
    h.provider.refresh(None).await.unwrap();
    assert!(h.verify(false).await.is_err());
    assert_eq!(h.count(), 4);
}
#[tokio::test]
async fn malformed_refresh_and_outage_never_extend_joint_expiry() {
    let h = Harness::new().await;
    h.script.lock().unwrap().metadata_cache = "max-age=10".into();
    h.provider.preflight().await.unwrap();
    h.advance(2);
    h.script.lock().unwrap().keys = b"{broken".to_vec();
    assert_eq!(h.provider.refresh(None).await, Err(Error::Document));
    assert!(h.verify(false).await.is_ok());
    h.advance(8);
    h.script.lock().unwrap().mode = "failure";
    assert!(h.verify(false).await.is_err());
    assert!(h.provider.snapshot().is_err());
    let n = h.count();
    assert!(h.verify(false).await.is_err());
    assert_eq!(h.count(), n);
}
#[tokio::test]
async fn metadata_defaults_profile_and_exact_destinations() {
    let h = Harness::new().await;
    let c = h.provider.config().unwrap();
    let original = metadata(&c);
    assert!(documents::metadata(&serde_json::to_vec(&original).unwrap(), &c).is_ok());
    for name in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    ] {
        let mut v = original.clone();
        v[name] = "https://unconfigured.example.test/".into();
        assert_eq!(
            documents::metadata(&serde_json::to_vec(&v).unwrap(), &c),
            Err(Error::Mismatch)
        );
    }
    for name in [
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
        "code_challenge_methods_supported",
        "authorization_response_iss_parameter_supported",
    ] {
        let mut v = original.clone();
        v.as_object_mut().unwrap().remove(name);
        assert!(documents::metadata(&serde_json::to_vec(&v).unwrap(), &c).is_err());
    }
    for (name, value) in [
        ("grant_types_supported", json!(["implicit"])),
        ("response_modes_supported", json!(["fragment"])),
        ("code_challenge_methods_supported", json!(["plain"])),
        (
            "authorization_response_iss_parameter_supported",
            json!(false),
        ),
    ] {
        let mut v = original.clone();
        v[name] = value;
        assert_eq!(
            documents::metadata(&serde_json::to_vec(&v).unwrap(), &c),
            Err(Error::Mismatch)
        );
    }
    h.provider.preflight().await.unwrap();
    h.advance(2);
    h.script.lock().unwrap().metadata["jwks_uri"] = "https://unconfigured.example.test/keys".into();
    assert_eq!(h.provider.refresh(None).await, Err(Error::Mismatch));
    assert!(h.provider.snapshot().is_err());
    assert_eq!(h.count(), 3);
    // A separate redirect target is never contacted.
    h.script.lock().unwrap().mode = "redirect";
    h.advance(2);
    assert!(h.provider.refresh(None).await.is_err());
    assert_eq!(h.count(), 4);
}
#[tokio::test]
async fn cancellation_coalesces_waiters_and_preserves_cooldown() {
    let h = Harness::new().await;
    h.script.lock().unwrap().mode = "stall";
    let p = h.provider.clone();
    let leader = tokio::spawn(async move { p.preflight().await });
    h.entered(1).await;
    let mut waiters = Vec::new();
    for _ in 0..12 {
        let p = h.provider.clone();
        waiters.push(tokio::spawn(async move { p.preflight().await }));
    }
    // Each waiter holds admission and has subscribed before cancellation.
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.manager.inner.callers.available_permits() != 19 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());
    for w in waiters {
        assert_eq!(w.await.unwrap(), Err(Error::Cancelled));
    }
    assert_eq!(h.count(), 1);
    assert_eq!(h.provider.preflight().await, Err(Error::Cooldown));
    assert_eq!(h.manager.inner.callers.available_permits(), 32);
    assert_eq!(h.manager.inner.gets.available_permits(), 2);
    tokio::time::timeout(Duration::from_secs(5), h.server.closed.notified())
        .await
        .expect("cancelled connection did not close");
    h.script.lock().unwrap().mode = "ok";
    h.advance(2);
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 3);
}
#[tokio::test]
async fn unknown_kid_flood_and_known_signature_failure_are_bounded() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    h.advance(2);
    h.script.lock().unwrap().mode = "stall";
    let mut workers = Vec::new();
    for i in 0..20 {
        let p = h.provider.clone();
        let token = unknown(&format!("unknown-{i}"));
        workers.push(tokio::spawn(async move { verify(&p, token).await }));
    }
    h.entered(3).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.manager.inner.callers.available_permits() != 12 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    workers[0].abort(); // Which task led is scheduler dependent; abort all, with no detached HTTP.
    for w in workers {
        w.abort();
        let _ = w.await;
    }
    assert_eq!(h.count(), 3);
    assert_eq!(
        verify(&h.provider, unknown("next")).await,
        Err(Error::Cooldown)
    );
    let mut forged = signing::signed_using(
        key(),
        &"n".repeat(43),
        signing::ISSUER,
        signing::CLIENT,
        1799999990,
    )
    .split('.')
    .map(str::to_owned)
    .collect::<Vec<_>>();
    forged[0] = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test"}"#);
    assert_eq!(
        verify(
            &h.provider,
            UnverifiedIdToken::new(&forged.join(".")).unwrap()
        )
        .await,
        Err(Error::Verification)
    );
    assert_eq!(h.count(), 3);
}
#[tokio::test]
async fn known_ineligible_kids_do_not_spend_refresh_budget() {
    for kind in ["algorithm", "use", "curve", "size"] {
        let h = Harness::new().await;
        let mut document: Value = serde_json::from_slice(&signing::jwks()).unwrap();
        let mut filtered = document["keys"][0].clone();
        match kind {
            "algorithm" => filtered["alg"] = "RS384".into(),
            "use" => filtered["use"] = "enc".into(),
            "curve" => {
                filtered = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode([1;32]),"y":URL_SAFE_NO_PAD.encode([2;32]),"alg":"ES256"})
            }
            "size" => {
                let mut modulus = vec![0; 1024];
                modulus[0] = 0x80;
                modulus[1023] = 1;
                filtered["n"] = URL_SAFE_NO_PAD.encode(modulus).into();
            }
            _ => unreachable!(),
        }
        filtered["kid"] = "filtered".into();
        document["keys"].as_array_mut().unwrap().push(filtered);
        h.script.lock().unwrap().keys = serde_json::to_vec(&document).unwrap();
        h.provider.preflight().await.unwrap();
        h.advance(2); // Refresh is permitted, so a missing-key misclassification sends GETs.
        assert_eq!(
            verify(&h.provider, unknown("filtered")).await,
            Err(Error::Verification),
            "{kind}"
        );
        assert_eq!(h.count(), 2, "{kind}");
        assert!(h.verify(false).await.is_ok());
        verify(&h.provider, unknown("actually-absent"))
            .await
            .unwrap_err();
        assert_eq!(h.count(), 4, "unused refresh budget: {kind}");
    }
}

#[tokio::test]
async fn expiry_inside_cooldown_is_an_outage() {
    let h = Harness::new().await;
    h.script.lock().unwrap().cache = "max-age=1".into();
    h.provider.preflight().await.unwrap();
    h.advance(1);
    assert_eq!(h.provider.preflight().await, Err(Error::Cooldown));
    assert_eq!(h.count(), 2);
    assert!(h.provider.snapshot().is_err());
    h.ticks.store(2, Ordering::SeqCst);
    h.script.lock().unwrap().cache = "max-age=100".into();
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 4);
}
#[tokio::test]
async fn identical_registration_is_noop_and_changes_or_restores_invalidate() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    let permit = h.permit();
    // Identical reload keeps keys, handles and budget; no outage and no fetch.
    let same = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v1"))
        .unwrap();
    assert_eq!(same.generation, h.provider.generation);
    same.preflight().await.unwrap();
    h.provider.preflight().await.unwrap();
    assert!(h.verify(false).await.is_ok());
    assert_eq!(h.count(), 2);
    // A permit issued before the identical reload still exchanges once.
    let exchanged = permit
        .exchange_with_keys(&same, &auth::Policy::default())
        .await
        .unwrap();
    assert!(finish_in_memory(&h.provider, exchanged).is_ok());
    assert_eq!(h.count(), 3);
    // Every canonical binding input change invalidates handles and keys, keeping cooldown.
    let ca = tls::Ca::new();
    let base = format!("https://{}:{}", tls::HOST, h.server.port);
    let variants: Vec<Box<dyn Fn() -> ProviderConfig>> = vec![
        Box::new(|| Harness::config(&h.server, &h.ca, "v2")),
        Box::new(|| Harness::config(&h.server, &ca, "v1")),
        Box::new(|| {
            let mut c = Harness::config(&h.server, &h.ca, "v1");
            c.discovery_url = format!("{base}/other-discovery");
            rebind(&mut c);
            c
        }),
        Box::new(|| {
            let mut c = Harness::config(&h.server, &h.ca, "v1");
            c.callback = "https://app.example.test/other".into();
            rebind(&mut c);
            c
        }),
        Box::new(|| {
            let mut c = Harness::config(&h.server, &h.ca, "v1");
            c.destination = "other".into();
            rebind(&mut c);
            c
        }),
    ];
    let mut current = h.provider.clone();
    for variant in variants {
        let next = h.manager.register(variant()).unwrap();
        assert!(next.generation > current.generation);
        assert_eq!(current.preflight().await, Err(Error::Retired));
        assert!(next.snapshot().is_err());
        assert_eq!(next.preflight().await, Err(Error::Cooldown));
        current = next;
    }
    // Retire then restore identical configuration is a new generation, still within budget.
    let restored_from = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v1"))
        .unwrap();
    h.manager.retire(&restored_from).unwrap();
    let restored = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v1"))
        .unwrap();
    assert!(restored.generation > restored_from.generation);
    assert_eq!(restored_from.preflight().await, Err(Error::Retired));
    assert_eq!(restored.preflight().await, Err(Error::Cooldown));
    assert_eq!(h.count(), 3);
}
// Recompute the canonical binding after a test edits one input field directly.
fn rebind(c: &mut ProviderConfig) {
    c.binding = c.canonical_binding();
}
// The invitation redemption function compares these exact bytes of the stored login binding
// with the provider, issuer, client, current revision and epoch it is given.
#[tokio::test]
async fn stored_managed_binding_layout_matches_invitation_redemption() {
    let h = Harness::new().await;
    let c = Harness::config(&h.server, &h.ca, "v1");
    let field = |b: &[u8]| [&(b.len() as u64).to_be_bytes()[..], b].concat();
    let head = [
        b"openmettle/login-provider/2\0".as_slice(),
        &field(signing::ID.as_bytes()),
        &field(signing::ISSUER.as_bytes()),
        &field(signing::CLIENT.as_bytes()),
        &field(b"v1"),
    ]
    .concat();
    assert!(c.binding.starts_with(&head));
    let expected = [
        b"openmettle/managed-login/2\0".as_slice(),
        &field(&c.binding),
        &field(&42_i64.to_be_bytes()),
    ]
    .concat();
    assert_eq!(persisted(&c.binding, None, 42), expected);
    // A native login (ADR 0023) stores the same configuration and epoch with its 32-byte
    // attempt digest between them, under its own domain. Migration 14 reads these offsets.
    let attempt = [0xa5; 32];
    let native = [
        b"openmettle/native-managed-login/1\0".as_slice(),
        &field(&c.binding),
        &field(&attempt),
        &field(&42_i64.to_be_bytes()),
    ]
    .concat();
    assert_eq!(persisted(&c.binding, Some(&attempt), 42), native);
    assert_eq!(native.len(), 34 + 8 + c.binding.len() + 40 + 16);
    assert_eq!(expected.len(), 27 + 8 + c.binding.len() + 16);
}
// A login belongs to the handle kind that started it: the browser handle, or the native
// handle of one exact attempt. Any other handle refuses the permit before a token request.
#[tokio::test]
async fn permit_is_exchanged_only_by_the_handle_of_its_own_attempt() {
    use crate::sessions::native::Attempt;
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    let requests = h.count();
    let attempt = |binding: u8| Attempt {
        callback: signing::CALLBACK.into(),
        binding: [binding; 32],
        registration: [1; 32],
        audience: [2; 32],
        challenge: [3; 32],
    };
    let native = h.provider.native_handle(attempt(4));
    let other = h.provider.native_handle(attempt(5));
    let permit = |from: &ManagedProvider| {
        let c = from.config().unwrap();
        let s = from.snapshot().unwrap();
        login::fixture_permit(c.login(&s, from.native.as_deref()).unwrap(), Some(1))
    };
    let policy = auth::Policy::default();
    for (started, finishing) in [
        (&h.provider, &native),
        (&native, &h.provider),
        (&native, &other),
    ] {
        let refused = permit(started).exchange_with_keys(finishing, &policy).await;
        assert!(matches!(refused, Err(login::Error::Rejected)));
    }
    assert_eq!(h.count(), requests);
    // Control: the handle of the same attempt reaches the provider's token endpoint.
    let control = permit(&native).exchange_with_keys(&native, &policy).await;
    assert!(!matches!(control, Err(login::Error::Rejected)));
    assert!(h.count() > requests);
}
fn unknown(kid: &str) -> UnverifiedIdToken {
    let t = signing::signed(
        &"n".repeat(43),
        signing::ISSUER,
        signing::CLIENT,
        1799999990,
    );
    let mut parts = t.split('.').map(str::to_owned).collect::<Vec<_>>();
    parts[0] =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg":"RS256","kid":kid})).unwrap());
    UnverifiedIdToken::new(&parts.join(".")).unwrap()
}
#[tokio::test]
async fn retirement_blocks_late_fetch_post_and_identity_release() {
    let h = Harness::new().await;
    h.script.lock().unwrap().mode = "stall";
    let p = h.provider.clone();
    let leader = tokio::spawn(async move { p.preflight().await });
    h.entered(1).await;
    h.manager.retire(&h.provider).unwrap();
    leader.abort();
    let _ = leader.await;
    assert!(h.provider.snapshot().is_err());
    let replacement = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v2"))
        .unwrap();
    assert_eq!(replacement.preflight().await, Err(Error::Cooldown));
    assert_eq!(h.provider.preflight().await, Err(Error::Retired));
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    let permit = h.permit();
    h.script.lock().unwrap().mode = "post-stall";
    let p = h.provider.clone();
    let exchange = tokio::spawn(async move {
        permit
            .exchange_with_keys(&p, &auth::Policy::default())
            .await
    });
    h.entered(3).await;
    h.manager.retire(&h.provider).unwrap();
    exchange.abort();
    let _ = exchange.await;
    assert_eq!(h.count(), 3);
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    let entry = h.provider.entry.clone();
    *h.manager.inner.release_hook.lock().unwrap() = Some(Arc::new(move || {
        entry.state.lock().unwrap().config = None;
    }));
    assert_eq!(h.verify(false).await, Err(Error::Retired));
}
#[tokio::test]
async fn release_rechecks_generation_expiry_token_time_and_clock_rollback() {
    for kind in ["generation", "keys-expire", "token-expire", "rollback"] {
        let h = Harness::new().await;
        h.script.lock().unwrap().cache = if kind == "keys-expire" {
            "max-age=10"
        } else {
            "max-age=600"
        }
        .into();
        h.script.lock().unwrap().metadata_cache = "max-age=600".into();
        h.provider.preflight().await.unwrap();
        let entry = h.provider.entry.clone();
        let ticks = h.ticks.clone();
        let wall = h.wall.clone();
        *h.manager.inner.release_hook.lock().unwrap() = Some(Arc::new(move || match kind {
            "generation" => {
                let mut state = entry.state.lock().unwrap();
                let previous = state.snapshot.as_ref().unwrap();
                state.snapshot = Some(Arc::new(Snapshot {
                    trusted: previous.trusted.clone(),
                    kids: previous.kids.clone(),
                    known_kids: previous.known_kids.clone(),
                    expires: previous.expires,
                    generation: previous.generation + 1,
                }));
            }
            "keys-expire" => {
                // Token exp/iat remain valid; only the key snapshot has expired.
                ticks.store(10, Ordering::SeqCst);
            }
            "token-expire" => {
                ticks.store(300, Ordering::SeqCst);
            }
            _ => {
                wall.store(1, Ordering::SeqCst);
            }
        }));
        assert_eq!(
            h.verify(false).await,
            Err(if kind == "token-expire" {
                Error::Verification
            } else {
                Error::Unavailable
            }),
            "{kind}"
        );
    }
}
#[tokio::test]
async fn capacities_and_managed_offline_bypass_are_closed() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    let slots = (0..32)
        .map(|_| h.provider.admission().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(h.provider.preflight().await, Err(Error::Capacity));
    drop(slots);
    let c = h.provider.config().unwrap();
    let permit = h.permit();
    assert_eq!(
        permit
            .exchange(&c.token, &auth::Policy::default(), signing::now)
            .await,
        Err(login::Error::Rejected)
    );
    assert_eq!(h.count(), 2);
    let old = h.permit();
    let p = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v2"))
        .unwrap();
    h.advance(2);
    p.preflight().await.unwrap();
    assert!(matches!(
        old.exchange_with_keys(&p, &auth::Policy::default()).await,
        Err(login::Error::Rejected)
    ));
    assert_eq!(h.count(), 4);
}

#[test]
fn duplicate_json_depth_and_raw_key_bounds() {
    for bytes in [
        br#"{"keys":[],"keys":[]}"#.as_slice(),
        br#"{"keys":[],"extension":{"same":1,"same":2}}"#,
        br#"{"keys":[{"kty":"RSA","kty":"RSA"}]}"#,
    ] {
        assert!(documents::keys(bytes).is_err());
    }
    let deep = format!("{}0{}", "[".repeat(130), "]".repeat(130));
    assert!(documents::json(deep.as_bytes()).is_err());
    assert!(documents::json(&vec![b' '; 65537]).is_err());
    let raw: Value = serde_json::from_slice(&signing::jwks()).unwrap();
    let key = raw["keys"][0].clone();
    let keys = (0..16)
        .map(|i| {
            let mut k = key.clone();
            k["kid"] = format!("key-{i}").into();
            k
        })
        .collect::<Vec<_>>();
    assert!(documents::keys(&serde_json::to_vec(&json!({"keys":keys})).unwrap()).is_ok());
    let mut many = keys;
    let mut ignored = key.clone();
    ignored["alg"] = "RS384".into();
    many.push(ignored);
    assert!(documents::keys(&serde_json::to_vec(&json!({"keys":many})).unwrap()).is_err());
    assert!(
        documents::keys(&serde_json::to_vec(&json!({"keys":[key.clone(),key]})).unwrap()).is_err()
    );
}
#[test]
fn online_keys_reject_malformed_private_usage_and_strength() {
    let raw: Value = serde_json::from_slice(&signing::jwks()).unwrap();
    let original = raw["keys"][0].clone();
    for (field, value) in [
        ("kid", json!("x".repeat(257))),
        ("kid", json!("null\0kid")),
        ("kid", json!(5)),
        ("alg", json!(3)),
        ("use", json!([])),
        ("key_ops", json!(["verify", "verify"])),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!(["verify", "sign"])),
        ("key_ops", json!(["verify", "encrypt"])),
        ("key_ops", json!(null)),
        ("n", json!("!")),
        ("e", json!("AA")),
        ("e", json!("Ag")),
        ("x5c", json!(["!"])),
        ("d", json!("AA")),
        ("k", json!("AA")),
        ("oth", json!([])),
        ("kty", json!("oct")),
    ] {
        let mut k = original.clone();
        k[field] = value;
        assert!(
            documents::keys(&serde_json::to_vec(&json!({"keys":[k]})).unwrap()).is_err(),
            "{field}"
        );
    }
    for (bits, valid) in [
        (2047usize, false),
        (2048, true),
        (8192, true),
        (8193, false),
    ] {
        let mut bytes = vec![0u8; bits.div_ceil(8)];
        bytes[0] = 1 << ((bits - 1) % 8);
        *bytes.last_mut().unwrap() |= 1;
        let mut k = original.clone();
        k["n"] = URL_SAFE_NO_PAD.encode(&bytes).into();
        assert_eq!(
            documents::keys(&serde_json::to_vec(&json!({"keys":[k.clone()]})).unwrap()).is_ok(),
            valid
        );
        bytes.insert(0, 0);
        k["n"] = URL_SAFE_NO_PAD.encode(&bytes).into();
        assert_eq!(
            documents::keys(&serde_json::to_vec(&json!({"keys":[k]})).unwrap()).is_ok(),
            valid
        );
    }
    let mut k = original.clone();
    for field in ["kid", "alg", "use"] {
        k.as_object_mut().unwrap().remove(field);
    }
    k["key_ops"] = json!(["verify"]);
    assert!(documents::keys(&serde_json::to_vec(&json!({"keys":[k]})).unwrap()).is_ok());
    let mut k = original;
    k["alg"] = "RS384".into();
    assert!(
        documents::keys(&serde_json::to_vec(&json!({"keys":[k.clone()]})).unwrap())
            .unwrap()
            .kids
            .is_empty()
    );
    k["n"] = "broken!".into();
    assert!(documents::keys(&serde_json::to_vec(&json!({"keys":[k]})).unwrap()).is_err());
}
#[test]
fn freshness_obeys_age_delay_caps_headers_and_directives() {
    let now = signing::now();
    let response = |cache: &str, date: SystemTime, age: Option<&str>| {
        let mut r = openidconnect::http::Response::builder()
            .header("cache-control", cache)
            .header("date", httpdate::fmt_http_date(date));
        if let Some(a) = age {
            r = r.header("age", a);
        }
        r.body(vec![]).unwrap()
    };
    let fresh = |r: &openidconnect::HttpResponse| {
        documents::freshness(
            r,
            now - Duration::from_secs(2),
            now,
            Duration::from_secs(2),
            Duration::from_secs(20),
            Duration::from_secs(60),
        )
    };
    assert_eq!(
        fresh(&response("max-age=100", now, Some("3"))),
        Some(Duration::from_secs(15))
    );
    assert_eq!(
        fresh(&response(
            "max-age=\"20\"",
            now - Duration::from_secs(7),
            Some("3")
        )),
        Some(Duration::from_secs(13))
    );
    for cc in [
        "max-age=0",
        "max-age=20, max-age=30",
        "max-age=20, MAX-AGE=30",
        "max-age=-1",
        "max-age=18446744073709551616",
        "max-age=20, unknown",
        "max-age=\"20",
        "max-age=20,",
        "public",
    ] {
        assert_eq!(fresh(&response(cc, now, None)), None, "{cc}");
    }
    for age in ["20", "-1", "x", "18446744073709551615"] {
        assert_eq!(fresh(&response("max-age=20", now, Some(age))), None);
    }
    assert_eq!(
        fresh(&response("max-age=20", now + Duration::from_secs(1), None)),
        None
    );
    assert_eq!(
        documents::freshness(
            &response("max-age=20", now, None),
            now + Duration::from_secs(1),
            now,
            Duration::ZERO,
            Duration::from_secs(20),
            Duration::from_secs(60)
        ),
        None
    );
    for header in ["date", "age", "cache-control"] {
        let mut r = response("max-age=20", now, Some("0"));
        let v = r.headers()[header].clone();
        r.headers_mut().append(
            openidconnect::http::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            v,
        );
        assert_eq!(fresh(&r), None);
    }
    let mut r = response("max-age=20", now, None);
    r.headers_mut().remove("date");
    assert_eq!(fresh(&r), None);
    assert_eq!(
        fresh(&response(
            "max-age=20, stale-if-error=999, stale-while-revalidate=999",
            now,
            Some("20")
        )),
        None
    );
}
#[test]
fn supported_media_and_unsolicited_304() {
    for (media, valid) in [
        ("application/json", true),
        ("application/jwk-set+json", true),
        ("application/json; charset=utf-8", true),
        ("application/json; charset=\"UTF-8\"", true),
        ("text/json", false),
        ("application/json; charset=latin1", false),
        ("application/json; charset=utf-8; charset=utf-8", false),
    ] {
        let r = openidconnect::http::Response::builder()
            .header("content-type", media)
            .body(vec![])
            .unwrap();
        assert_eq!(documents::media(&r, true).is_ok(), valid);
    }
    let r = openidconnect::http::Response::builder()
        .status(304)
        .header("content-type", "application/json")
        .body(vec![])
        .unwrap();
    assert!(documents::media(&r, true).is_err());
    let r = openidconnect::http::Response::builder()
        .header("content-type", "application/json")
        .header("content-type", "application/json")
        .body(vec![])
        .unwrap();
    assert!(documents::media(&r, true).is_err());
}
#[tokio::test]
async fn late_responses_never_publish_after_replacement_or_retirement() {
    let h = Harness::new().await;
    h.script.lock().unwrap().mode = "gate-jwks";
    let p = h.provider.clone();
    let leader = tokio::spawn(async move { p.preflight().await });
    h.entered(2).await;
    let new = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v2"))
        .unwrap();
    h.script.lock().unwrap().gate.notify_one();
    assert_eq!(leader.await.unwrap(), Err(Error::Retired));
    assert!(new.snapshot().is_err());
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    let permit = h.permit();
    h.script.lock().unwrap().mode = "gate-post";
    // Poll the exchange in this task too: it must reject an otherwise valid completed POST.
    let policy = auth::Policy::default();
    let exchange = permit.exchange_with_keys(&h.provider, &policy);
    let control = async {
        h.entered(3).await;
        h.manager.retire(&h.provider).unwrap();
        h.script.lock().unwrap().gate.notify_one();
    };
    let (result, ()) = tokio::join!(exchange, control);
    assert!(result.is_err());
    assert_eq!(h.count(), 3);
}
#[tokio::test]
async fn token_expiring_during_refresh_is_rejected_after_wait() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    h.advance(2);
    {
        let mut s = h.script.lock().unwrap();
        s.keys = rotated();
        s.mode = "gate-jwks";
        s.cache = "max-age=600".into();
        s.metadata_cache = "max-age=600".into();
    }
    let verification = h.verify(true);
    let control = async {
        h.entered(4).await;
        h.advance(298);
        h.script.lock().unwrap().gate.notify_one();
    };
    let (result, ()) = tokio::join!(verification, control);
    assert_eq!(result, Err(Error::Verification));
    assert_eq!(h.count(), 4);
}

#[tokio::test]
async fn unknown_ids_share_completed_refresh_and_cannot_reset_budget() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    h.advance(2);
    h.script.lock().unwrap().mode = "gate-jwks";
    let mut tasks = Vec::new();
    for i in 0..20 {
        let p = h.provider.clone();
        tasks.push(tokio::spawn(async move {
            verify(&p, unknown(&format!("attack-{i}"))).await
        }));
    }
    h.entered(4).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.manager.inner.callers.available_permits() != 12 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    h.script.lock().unwrap().gate.notify_one();
    for task in tasks {
        assert_eq!(task.await.unwrap(), Err(Error::Verification));
    }
    for i in 0..50 {
        assert_eq!(
            verify(&h.provider, unknown(&format!("later-{i}"))).await,
            Err(Error::Cooldown)
        );
    }
    assert_eq!(h.count(), 4);
    h.manager.retire(&h.provider).unwrap();
    let replacement = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v2"))
        .unwrap();
    assert_eq!(replacement.preflight().await, Err(Error::Cooldown));
    assert_eq!(h.count(), 4);
}
#[tokio::test]
async fn same_kid_rotation_and_missing_kid_ambiguity() {
    let h = Harness::new().await;
    h.provider.preflight().await.unwrap();
    let mut changed: Value = serde_json::from_slice(&rotated()).unwrap();
    changed["keys"][0]["kid"] = "test".into();
    h.script.lock().unwrap().keys = serde_json::to_vec(&changed).unwrap();
    h.advance(2);
    h.provider.refresh(None).await.unwrap();
    assert_eq!(h.verify(false).await, Err(Error::Verification));
    assert_eq!(h.count(), 4);
    let mut mixed: Value = serde_json::from_slice(&signing::jwks()).unwrap();
    mixed["keys"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::from_slice::<Value>(&rotated()).unwrap()["keys"][0].clone());
    h.script.lock().unwrap().keys = serde_json::to_vec(&mixed).unwrap();
    h.advance(2);
    h.provider.refresh(None).await.unwrap();
    let raw = signing::signed(
        &"n".repeat(43),
        signing::ISSUER,
        signing::CLIENT,
        1799999990,
    );
    let mut parts = raw.split('.').map(str::to_owned).collect::<Vec<_>>();
    parts[0] = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    h.advance(2);
    assert_eq!(
        verify(
            &h.provider,
            UnverifiedIdToken::new(&parts.join(".")).unwrap()
        )
        .await,
        Err(Error::Verification)
    );
    assert_eq!(h.count(), 6);
}
#[tokio::test]
async fn manager_registration_network_capacity_and_effective_policy_binding() {
    let h = Harness::new().await;
    let slots = (0..2)
        .map(|_| h.manager.inner.gets.clone().try_acquire_owned().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(h.provider.preflight().await, Err(Error::Capacity));
    assert_eq!(h.count(), 0);
    drop(slots);
    h.advance(2);
    h.provider.preflight().await.unwrap();
    let old = h.provider.config().unwrap();
    let other_ca = tls::Ca::new();
    let different = Harness::config(&h.server, &other_ca, "v1");
    assert_ne!(old.token.policy_binding(), different.token.policy_binding());
    let raw = Harness::config(&h.server, &h.ca, "v1");
    let old_binding = raw.binding.clone();
    let mut other = Harness::config(&h.server, &h.ca, "v1");
    other.identity =
        ProviderIdentity::new(signing::ID, "https://other.example.test", signing::CLIENT).unwrap();
    assert!(matches!(
        h.manager.register(other),
        Err(Error::Configuration)
    ));
    let mut second = Harness::config(&h.server, &h.ca, "v1");
    second.identity = ProviderIdentity::new(
        "1b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
        signing::ISSUER,
        signing::CLIENT,
    )
    .unwrap();
    let second = h.manager.register(second).unwrap();
    h.manager.retire(&second).unwrap();
    let mut third = Harness::config(&h.server, &h.ca, "v1");
    third.identity = ProviderIdentity::new(
        "2b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
        signing::ISSUER,
        signing::CLIENT,
    )
    .unwrap();
    assert!(matches!(h.manager.register(third), Err(Error::Capacity)));
    // Identical canonical configuration (no process generation in it) is a no-op.
    assert_eq!(old.binding, old_binding);
    let replacement = h.manager.register(raw).unwrap();
    assert_eq!(replacement.generation, h.provider.generation);
    assert!(Arc::ptr_eq(&old, &replacement.config().unwrap()));
    assert!(h.provider.config().is_ok() && h.provider.snapshot().is_ok());
    let changed = h.manager.register(different).unwrap();
    assert_ne!(changed.config().unwrap().binding, old_binding);
    assert!(h.provider.config().is_err());
}
#[tokio::test]
async fn overall_deadline_cancels_http_and_releases_capacity() {
    let mut h = Harness::new().await;
    // Only the explicit policy changes; real transport and real cancellation remain in use.
    let mut p = policy();
    p.deadline = Duration::from_millis(100);
    h.manager = ProviderManager::new(p);
    h.provider = h
        .manager
        .register(Harness::config(&h.server, &h.ca, "v1"))
        .unwrap();
    h.script.lock().unwrap().mode = "stall";
    assert_eq!(h.provider.preflight().await, Err(Error::Timeout));
    assert_eq!(h.count(), 1);
    assert_eq!(h.manager.inner.gets.available_permits(), 2);
    assert_eq!(h.manager.inner.callers.available_permits(), 32);
    assert_eq!(h.provider.preflight().await, Err(Error::Cooldown));
}
#[test]
fn policy_bounds_and_diagnostics_are_fixed() {
    for (fresh, cool, deadline, providers, callers, gets) in [
        (0, 1, 1, 1, 1, 1),
        (86401, 1, 1, 1, 1, 1),
        (1, 0, 1, 1, 1, 1),
        (1, 3601, 1, 1, 1, 1),
        (1, 1, 0, 1, 1, 1),
        (1, 1, 61, 1, 1, 1),
        (1, 1, 1, 65, 1, 1),
        (1, 1, 1, 1, 1025, 1),
        (1, 1, 1, 1, 1, 65),
    ] {
        assert!(
            RefreshPolicy::new(
                Duration::from_secs(fresh),
                Duration::from_secs(cool),
                Duration::from_secs(deadline),
                providers,
                callers,
                gets
            )
            .is_err()
        );
    }
    for e in [
        Error::Configuration,
        Error::Capacity,
        Error::Retired,
        Error::Cooldown,
        Error::Cancelled,
        Error::Timeout,
        Error::Fetch,
        Error::Document,
        Error::Mismatch,
        Error::Unavailable,
        Error::Verification,
    ] {
        let text = format!("{e:?} {e}");
        assert!(!text.contains(signing::ISSUER));
        assert!(!text.contains(signing::CLIENT));
    }
}

#[tokio::test]
async fn lost_metadata_qualification_retires_old_snapshot_without_key_fetch() {
    for absent in [false, true] {
        let h = Harness::new().await;
        h.provider.preflight().await.unwrap();
        h.advance(2);
        {
            let mut s = h.script.lock().unwrap();
            if absent {
                s.metadata
                    .as_object_mut()
                    .unwrap()
                    .remove("code_challenge_methods_supported");
            } else {
                s.metadata_cache = "no-store, unknown".into();
            }
        }
        assert_eq!(
            h.provider.refresh(None).await,
            Err(if absent {
                Error::Mismatch
            } else {
                Error::Unavailable
            })
        );
        assert!(h.provider.snapshot().is_err());
        assert_eq!(h.count(), 3);
    }
}
/// ADR 0011 amendment: the token-endpoint authentication list is not required, in any form;
/// S256 and every other capability check still are.
#[tokio::test]
async fn metadata_ignores_client_authentication_advertising_but_requires_s256() {
    let h = Harness::new().await;
    let c = h.provider.config().unwrap();
    let check = |v: &Value| documents::metadata(&serde_json::to_vec(v).unwrap(), &c);
    let mut keycloak = metadata(&c);
    keycloak["token_endpoint_auth_methods_supported"] = json!([
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
    ]);
    keycloak["code_challenge_methods_supported"] = json!(["plain", "S256"]);
    assert_eq!(check(&keycloak), Ok(()));
    for methods in [json!(["client_secret_basic"]), json!([])] {
        let mut v = metadata(&c);
        v["token_endpoint_auth_methods_supported"] = methods;
        assert_eq!(check(&v), Ok(()));
    }
    let mut v = metadata(&c);
    v.as_object_mut()
        .unwrap()
        .remove("token_endpoint_auth_methods_supported");
    assert_eq!(check(&v), Ok(()));
    // The member stays typed: a non-array is still a malformed document.
    v["token_endpoint_auth_methods_supported"] = json!("none");
    assert_eq!(check(&v), Err(Error::Document));
    for (name, value) in [
        ("code_challenge_methods_supported", Some(json!(["plain"]))),
        ("code_challenge_methods_supported", Some(json!([]))),
        ("code_challenge_methods_supported", None),
        ("authorization_response_iss_parameter_supported", None),
        ("response_types_supported", Some(json!(["id_token"]))),
    ] {
        let mut v = keycloak.clone();
        match value {
            Some(value) => v[name] = value,
            None => {
                v.as_object_mut().unwrap().remove(name);
            }
        }
        assert!(check(&v).is_err(), "{name}");
    }
    for name in ["issuer", "token_endpoint", "jwks_uri"] {
        let mut v = keycloak.clone();
        v[name] = "https://unconfigured.example.test/".into();
        assert_eq!(check(&v), Err(Error::Mismatch), "{name}");
    }
}
/// Refusal directives give the operator's window from the request: Date never ages it, Age
/// and request delay do, and maximum freshness caps it. A malformed header or directive still
/// fails, whatever its position relative to the refusal.
#[test]
fn freshness_refusals_give_the_window_and_malformed_headers_still_fail() {
    let now = signing::now();
    let at = |cache: Option<&str>, date: Option<&str>, age: Option<&str>, window: u64| {
        let mut r = openidconnect::http::Response::builder();
        for (name, value) in [("cache-control", cache), ("date", date), ("age", age)] {
            if let Some(v) = value {
                r = r.header(name, v);
            }
        }
        documents::freshness(
            &r.body(vec![]).unwrap(),
            now - Duration::from_secs(2),
            now,
            Duration::from_secs(2),
            Duration::from_secs(20),
            Duration::from_secs(window),
        )
    };
    let fresh = |cache, date, age| at(cache, date, age, 10);
    let secs = |v| Some(Duration::from_secs(v));
    let date = httpdate::fmt_http_date(now);
    let old = httpdate::fmt_http_date(now - Duration::from_secs(30));
    // Keycloak 26.8.2 discovery and JWKS as observed in PR #72: no Date and no Age.
    for cc in [
        "no-cache, no-store, must-revalidate, no-transform",
        "no-cache",
        "no-store",
        "NO-STORE",
        "no-transform, must-revalidate, no-store, no-cache",
        "max-age=20, no-store",
        "no-cache, max-age=20",
        "max-age=5, no-cache",
        "public, no-cache",
    ] {
        // The 10 s window less the 2 s request delay.
        assert_eq!(fresh(Some(cc), None, None), secs(8), "{cc}");
        assert_eq!(fresh(Some(cc), Some(&old), Some("3")), secs(5), "{cc}");
    }
    assert_eq!(at(Some("no-store"), None, None, 30), secs(18));
    assert_eq!(fresh(Some("no-store"), None, Some("7")), secs(1));
    assert_eq!(fresh(Some("no-store"), None, Some("8")), None);
    // max-age keeps its lifetime whatever the window, and still needs Date.
    for window in [1, 10, 300] {
        assert_eq!(at(Some("max-age=20"), Some(&date), None, window), secs(18));
        assert_eq!(at(Some("max-age=20"), Some(&old), None, window), None);
    }
    assert_eq!(fresh(Some("max-age=20"), None, None), None);
    for cc in [
        "no-store, bogus",
        "bogus, no-store",
        "no-cache, no-cache",
        "no-store, NO-STORE",
        "no-store=1",
        "no-cache=\"set-cookie\"",
        "no-cache, max-age=x",
        "no-cache, max-age",
        "no-store,",
        ",no-store",
        "no-store, s-maxage=-1",
        "no-store, public=1",
    ] {
        assert_eq!(fresh(Some(cc), None, None), None, "{cc}");
    }
    assert_eq!(fresh(None, None, None), None);
    // When present, Date and Age must still be valid; future Date still fails.
    let future = httpdate::fmt_http_date(now + Duration::from_secs(1));
    assert_eq!(fresh(Some("no-store"), Some("yesterday"), None), None);
    assert_eq!(fresh(Some("no-store"), Some(&future), None), None);
    assert_eq!(fresh(Some("no-store"), None, Some("-1")), None);
    // A repeated header fails even when both copies are identical and valid.
    for (header, value) in [
        ("date", date.as_str()),
        ("age", "0"),
        ("cache-control", "no-store"),
    ] {
        let r = openidconnect::http::Response::builder()
            .header("cache-control", "no-store")
            .header("date", &date)
            .header("age", "0")
            .header(header, value)
            .body(vec![])
            .unwrap();
        assert_eq!(
            documents::freshness(
                &r,
                now,
                now,
                Duration::ZERO,
                Duration::from_secs(20),
                Duration::from_secs(10)
            ),
            None,
            "duplicate {header}"
        );
    }
    // Local wall-clock rollback during the request still fails.
    let r = openidconnect::http::Response::builder()
        .header("cache-control", "no-store")
        .body(vec![])
        .unwrap();
    assert_eq!(
        documents::freshness(
            &r,
            now + Duration::from_secs(1),
            now,
            Duration::ZERO,
            Duration::from_secs(20),
            Duration::from_secs(10)
        ),
        None
    );
}
fn keycloak(h: &Harness) {
    let mut s = h.script.lock().unwrap();
    s.metadata_cache = "no-cache, no-store, must-revalidate, no-transform".into();
    s.cache = "no-cache".into();
    s.dated = false;
    s.metadata["token_endpoint_auth_methods_supported"] = json!([
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post"
    ]);
}
/// With Keycloak's headers, begin and a callback inside cooldown share one fetch. The snapshot
/// is reused, even while the provider is unreachable, until the window ends; then it is
/// fetched again and an outage gets no grace.
#[tokio::test]
async fn refused_caching_is_reused_for_the_window_then_fetched_again() {
    let h = Harness::new().await;
    keycloak(&h);
    assert_eq!(
        h.manager.policy().uncacheable_reuse,
        DEFAULT_UNCACHEABLE_REUSE
    );
    // Begin: one discovery and one JWKS fetch, then the checks after the database work.
    let (_admission, deadline) = h.provider.login_phase().unwrap();
    h.provider.fresh().await.unwrap();
    h.provider.login_provider(deadline).unwrap();
    h.provider.confirm(deadline).unwrap();
    assert_eq!(h.count(), 2);
    // Callback 1 s later, inside the 2 s cooldown: consume, exchange and release reuse the
    // snapshot, so the only further request is the code POST.
    h.advance(1);
    let (_admission, deadline) = h.provider.login_phase().unwrap();
    h.provider.fresh().await.unwrap();
    h.provider.login_provider(deadline).unwrap();
    h.provider.confirm(deadline).unwrap();
    let proof = h
        .permit()
        .exchange_with_keys(&h.provider, &auth::Policy::default())
        .await
        .unwrap();
    assert_eq!(h.count(), 3);
    assert_eq!(
        finish_in_memory(&h.provider, proof).unwrap().subject(),
        "synthetic-subject"
    );
    // The fixture clock adds no request delay, so the window ends exactly 60 s after fetch.
    h.advance(58);
    h.script.lock().unwrap().mode = "failure";
    h.provider.preflight().await.unwrap();
    assert!(h.verify(false).await.is_ok());
    assert_eq!(h.count(), 3);
    h.advance(1);
    assert_eq!(h.provider.preflight().await, Err(Error::Fetch));
    assert!(h.provider.snapshot().is_err());
    assert!(h.verify(false).await.is_err());
    assert_eq!(h.count(), 4);
    h.script.lock().unwrap().mode = "ok";
    h.advance(2);
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 6);
}
/// The documented gap: without an explicit window, the 60 s default is not checked against a
/// longer cooldown. A provider that refuses caching is then refused from the end of each
/// window until the cooldown ends, without a fetch, and recovers once a refresh is allowed.
#[tokio::test]
async fn default_window_shorter_than_cooldown_refuses_until_the_cooldown_ends() {
    let h = Harness::with_policy(
        RefreshPolicy::new(
            Duration::from_secs(600),
            Duration::from_secs(120),
            Duration::from_secs(5),
            2,
            32,
            2,
        )
        .unwrap(),
    )
    .await;
    keycloak(&h);
    assert_eq!(
        h.manager.policy().uncacheable_reuse,
        DEFAULT_UNCACHEABLE_REUSE
    );
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 2);
    // Inside the window the snapshot is reused.
    h.advance(59);
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 2);
    // The window has ended but the 120 s cooldown has not: refused, and nothing is fetched.
    h.advance(1);
    assert_eq!(h.provider.preflight().await, Err(Error::Cooldown));
    assert!(h.provider.snapshot().is_err());
    h.advance(59);
    assert_eq!(h.provider.preflight().await, Err(Error::Cooldown));
    assert_eq!(h.count(), 2);
    // When the cooldown ends a refresh is allowed again and sign-in recovers.
    h.advance(1);
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 4);
}
/// Rotation inside the window behaves as for cached documents. A removed key stays trusted
/// (the accepted trade-off) and an unknown kid waits for cooldown; the unknown-kid refresh
/// then retires the old key and starts a new window.
#[tokio::test]
async fn refused_caching_rotation_uses_the_unknown_key_refresh() {
    let h = Harness::new().await;
    keycloak(&h);
    h.provider.preflight().await.unwrap();
    h.script.lock().unwrap().keys = rotated();
    assert_eq!(h.verify(true).await.err(), Some(Error::Cooldown));
    assert!(h.verify(false).await.is_ok());
    assert_eq!(h.count(), 2);
    h.advance(2);
    assert!(h.verify(true).await.is_ok());
    assert_eq!(h.count(), 4);
    assert!(h.verify(false).await.is_err());
    // The replacement fetched at 2 s is reused until 62 s.
    h.advance(59);
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 4);
    h.advance(1);
    h.provider.preflight().await.unwrap();
    assert_eq!(h.count(), 6);
}
/// Concurrent starts share one fetch, and starts after it, inside cooldown, reuse its result
/// instead of being refused.
#[tokio::test]
async fn concurrent_refused_caching_starts_share_one_fetch() {
    let h = Harness::new().await;
    keycloak(&h);
    h.script.lock().unwrap().mode = "gate-jwks";
    let mut starts = Vec::new();
    for _ in 0..8 {
        let p = h.provider.clone();
        starts.push(tokio::spawn(async move { p.preflight().await }));
    }
    h.entered(2).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while h.manager.inner.callers.available_permits() != 24 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    h.script.lock().unwrap().gate.notify_one();
    for start in starts {
        assert_eq!(start.await.unwrap(), Ok(()));
    }
    h.script.lock().unwrap().mode = "ok";
    h.advance(1);
    for _ in 0..8 {
        h.provider.preflight().await.unwrap();
        h.provider.fresh().await.unwrap();
    }
    assert_eq!(h.count(), 2);
}
/// The snapshot lives until the earlier of its documents' lifetimes: explicit max-age as
/// before, the window for a refusal, and maximum freshness over both. A malformed refusal
/// still makes the provider unavailable.
#[tokio::test]
async fn max_age_keeps_its_lifetime_and_refusals_use_the_window() {
    let refresh = |freshness| {
        RefreshPolicy::new(
            Duration::from_secs(freshness),
            Duration::from_secs(2),
            Duration::from_secs(5),
            2,
            32,
            2,
        )
        .unwrap()
    };
    let short = refresh(600)
        .with_uncacheable_reuse(Duration::from_secs(10))
        .unwrap();
    let keycloak = "no-cache, no-store, must-revalidate, no-transform";
    for (policy, metadata_cache, cache, lifetime) in [
        (policy(), "max-age=100", "max-age=100", 100),
        (policy(), "no-store", "max-age=100", 60),
        (policy(), "max-age=100", "no-cache", 60),
        (policy(), "max-age=30", "no-cache", 30),
        (short, "max-age=100", "max-age=100", 100),
        (short, keycloak, "no-cache", 10),
        // The 60 s default stays under a shorter freshness cap.
        (refresh(30), "no-store", "no-cache", 30),
    ] {
        let h = Harness::with_policy(policy).await;
        {
            let mut s = h.script.lock().unwrap();
            s.metadata_cache = metadata_cache.into();
            s.cache = cache.into();
        }
        h.provider.preflight().await.unwrap();
        h.advance(lifetime - 1);
        h.provider.preflight().await.unwrap();
        assert_eq!(h.count(), 2, "{metadata_cache} {cache}");
        h.advance(1);
        h.script.lock().unwrap().date = signing::now() + Duration::from_secs(lifetime);
        h.provider.preflight().await.unwrap();
        assert_eq!(h.count(), 4, "{metadata_cache} {cache}");
    }
    for (metadata_cache, cache, count) in [
        ("no-store, bogus", "no-cache", 1),
        ("no-store", "no-cache, no-cache", 2),
    ] {
        let h = Harness::new().await;
        {
            let mut s = h.script.lock().unwrap();
            s.metadata_cache = metadata_cache.into();
            s.cache = cache.into();
        }
        assert_eq!(h.provider.preflight().await, Err(Error::Unavailable));
        assert!(h.provider.snapshot().is_err());
        assert_eq!(h.count(), count);
    }
}
/// The window is 60 s unless set. An explicit window is 1–300 s, no shorter than cooldown
/// and no longer than maximum freshness.
#[test]
fn uncacheable_reuse_window_is_bounded_by_cooldown_freshness_and_ceiling() {
    let secs = Duration::from_secs;
    let base = |freshness, cooldown| {
        RefreshPolicy::new(secs(freshness), secs(cooldown), secs(5), 1, 1, 1).unwrap()
    };
    assert_eq!(base(600, 2).uncacheable_reuse, secs(60));
    assert_eq!(MAX_UNCACHEABLE_REUSE, secs(300));
    for (freshness, cooldown, reuse, accepted) in [
        (600, 1, 1, true),
        (600, 1, 0, false),
        (600, 1, 300, true),
        (600, 1, 301, false),
        (600, 1, u64::MAX, false),
        (600, 60, 60, true),
        (600, 61, 60, false),
        (120, 1, 120, true),
        (120, 1, 121, false),
        (1, 1, 1, true),
        (1, 1, 2, false),
        // A cooldown above the ceiling leaves no explicit window.
        (3600, 300, 300, true),
        (3600, 301, 301, false),
    ] {
        assert_eq!(
            base(freshness, cooldown)
                .with_uncacheable_reuse(secs(reuse))
                .map(|p| p.uncacheable_reuse),
            if accepted {
                Ok(secs(reuse))
            } else {
                Err(Error::Configuration)
            },
            "{freshness} {cooldown} {reuse}"
        );
    }
}
#[test]
fn malformed_filtered_keys_do_not_disappear() {
    let mut rsa: Value = serde_json::from_slice(&signing::jwks()).unwrap();
    rsa["keys"][0]["alg"] = "RS384".into();
    rsa["keys"][0]["e"] = "AA".into();
    assert!(documents::keys(&serde_json::to_vec(&rsa).unwrap()).is_err());
    let mut ec = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode([1;32]),"y":URL_SAFE_NO_PAD.encode([2;32]),"alg":"ES256"});
    assert!(
        documents::keys(&serde_json::to_vec(&json!({"keys":[ec.clone()]})).unwrap())
            .unwrap()
            .kids
            .is_empty()
    );
    ec["x"] = "AA".into();
    assert!(documents::keys(&serde_json::to_vec(&json!({"keys":[ec]})).unwrap()).is_err());
}

#[test]
fn rsa_document_ceiling_does_not_claim_unsupported_library_sizes() {
    let mut v: Value = serde_json::from_slice(&signing::jwks()).unwrap();
    let mut n = vec![0; 1024];
    n[0] = 0x80;
    n[1023] = 1;
    v["keys"][0]["n"] = URL_SAFE_NO_PAD.encode(&n).into();
    let validated = documents::keys(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(validated.kids.is_empty());
    n[1023] = 0;
    v["keys"][0]["n"] = URL_SAFE_NO_PAD.encode(&n).into();
    assert!(documents::keys(&serde_json::to_vec(&v).unwrap()).is_err());
}

#[test]
fn complete_managed_binding_respects_existing_schema_limit() {
    let ca = tls::Ca::new();
    let url = format!("https://long.example.test/{}", "x".repeat(2010));
    assert!(url.len() <= 2048);
    let identity = ProviderIdentity::new(signing::ID, &url, &"c".repeat(255)).unwrap();
    let result = ProviderConfig::new(
        identity,
        login::ProviderDefinition {
            revision: &"r".repeat(64),
            authorization_endpoint: &url,
            token_endpoint: &url,
            callback: &url,
            destination: &"d".repeat(64),
            enabled: true,
        },
        &url,
        &url,
        Trust::Bundle(&ca.pem()),
        &[],
    );
    assert!(matches!(result, Err(Error::Configuration)));
}

#[tokio::test]
async fn exchange_deadline_is_shared_by_post_and_following_document_wait() {
    // Real timer is needed for caller-owned HTTP cancellation; barriers fix stage ordering.
    let mut p = policy();
    p.deadline = Duration::from_millis(600);
    let h = Harness::with_policy(p).await;
    h.provider.preflight().await.unwrap();
    h.advance(2);
    {
        let mut s = h.script.lock().unwrap();
        s.mode = "gate-post";
        s.token = signing::signed_using(
            key(),
            &"n".repeat(43),
            signing::ISSUER,
            signing::CLIENT,
            1799999990,
        );
    }
    let permit = h.permit();
    let policy = auth::Policy::default();
    let control = async {
        h.entered(3).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut s = h.script.lock().unwrap();
        s.mode = "stall";
        s.gate.notify_one();
    };
    let exchange = tokio::time::timeout(
        Duration::from_millis(800),
        permit.exchange_with_keys(&h.provider, &policy),
    );
    let (result, ()) = tokio::join!(exchange, control);
    assert!(matches!(result.unwrap(), Err(login::Error::Exchange)));
    assert_eq!(h.count(), 4);
    assert_eq!(h.manager.inner.callers.available_permits(), 32);
    assert_eq!(h.manager.inner.gets.available_permits(), 2);
    assert_eq!(
        h.server
            .heads
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.starts_with("POST"))
            .count(),
        1
    );
}

// Managed begin -> consume -> POST -> release against isolated CI PostgreSQL (ADR 0012).
mod handoff;
mod postgres;
mod router;
mod service;
mod session_routes;
