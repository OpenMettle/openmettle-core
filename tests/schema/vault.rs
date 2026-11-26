//! V1-28 (ADR 0045) integration tests on isolated PostgreSQL 18.1, real `openmettle-api` and
//! `openmettle-admin` binaries, and synthetic `rcgen` TLS (`TEST_GATEWAY_HOST`):
//! 1. Personal and project ownership, `404` concealment, `account_admin` non-escalation,
//!    explicit `user` / `local_group` / `oidc_group` / `project` sharing and immediate revocation,
//!    archived/deleted project rules, closed `restore_reconciliation_gate`, and zero plaintext
//!    leakage across HTTP responses, PostgreSQL tables, audit rows, and debug stderr logs.
//! 2. Versioned `key_id` HKDF-SHA256 + AES-256-GCM encryption, AAD tamper refusal,
//!    `openmettle-admin vault status` & online batched `vault rotate`, missing-key refusal, and
//!    key-loss recovery.
//! 3. Full state machine (`pending_auth -> authorized -> single-flight refresh across N concurrent
//!    callers hitting synthetic TLS server once -> 401 refusal -> reauth_required -> re-authorize
//!    -> disconnect`), concurrent `disconnect` winning over in-flight refresh, upstream scope
//!    widening refusal, transient `503` refresh preserving refresh secret, and expiry without
//!    refresh.
//! 4. End-to-end `ExternalMcpAdapter` over synthetic TLS (`rcgen`) injecting only the required
//!    bearer token, enforcing origin and `granted_scopes`, cache invalidation on disconnect, and
//!    PostgreSQL least-privilege role boundaries.

use super::authz_http::{As, browser, native};
use super::authz_runs::{personal_of, seeded_session};
use super::authz_store::{Account, FUTURE, PROVIDER, account, ctx, make_admin, providers};
use super::*;
use openmettle_core::{
    artifact_fs,
    authz::{
        CapabilityGate, Grantee, ProjectRole,
        approvals::{
            self, EffectClass, IntentResult, ReplayEffect, record_fenced_intent,
            start_write_attempt,
        },
        branches::{
            self, Conversation, Operation, Part, UserInput,
            snapshot::{Intent as TurnIntent, Snapshots},
        },
        leases::{self, LeaseSettings, Settle},
        projects::{self, ProjectSettingsInput},
        runs::{self as run_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        store,
    },
    build_worker_turn_executor,
    mcp::{
        contract::{ExternalRegistry, ExternalToolContract, ReconcileSpec},
        external::{
            CredentialOutcome, CredentialRequest, DestinationAuthorizer, ExternalCall,
            ExternalMcpAdapter, McpCredentialProvider, ReconcileTarget,
        },
    },
    model_config::{ConfigSnapshot, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection},
    provider_http::{
        Trust,
        mcp::{McpTimeouts, McpTransport},
    },
    restore::{self, GateLockRequest},
    runs::{RunInput, WriteTransaction},
    vault::{
        self, AuthorizeConnectionInput, CreateConnectionInput, HttpsRefreshClient, RefreshClient,
        RefreshOutcome, RefreshRequest, RefreshTimeouts, RefreshedCredential, SecretText,
        VaultConfig, VaultCredentialProvider, VaultDestinationAuthorizer, VaultKeyRing,
        VaultRefreshRegistry,
    },
    worker::{
        ActiveRun, ApprovedAdapter, Executor, StepContext, StepResult, StepTasks, Stop,
        config as worker_config,
    },
};
use serde_json::{Value, json};
use sqlx::{Executor as SqlxExecutor, PgPool, postgres::PgPoolOptions};
use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    net::IpAddr,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Barrier, Notify, watch},
    time::Instant,
};

const ORIGIN: &str = "https://app.example.test";
const OIDC_GROUP: &str = "synthetic-vault-group";

fn admin_cli(db_url: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_openmettle-admin"));
    scrub_env(&mut cmd);
    cmd.env("OPENMETTLE_ADMIN_DATABASE_URL", db_url)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_cli(&mut cmd, "openmettle-admin vault")
}

/// Write a version-1 keyring config + owner-only 32-byte key files under `dir`.
fn write_keyring_files(
    dir: &auth_config_support::Dir,
    name: &str,
    active_key_id: &str,
    keys: &[(&str, [u8; 32])],
) -> String {
    let mut entries = Vec::new();
    for (id, bytes) in keys {
        let key_file = dir.write(&format!("{name}-{id}.key"), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        entries.push(json!({ "id": id, "file": key_file }));
    }
    dir.write(
        &format!("{name}.json"),
        json!({
            "version": 1,
            "active_key_id": active_key_id,
            "keys": entries,
        })
        .to_string()
        .as_bytes(),
    )
}

struct VaultApi {
    _process: Process,
    _dir: auth_config_support::Dir,
    bind: String,
    log_path: PathBuf,
}

impl VaultApi {
    fn start(db: &TestDb, dir: auth_config_support::Dir, vault_keys_path: Option<&str>) -> Self {
        let mut document = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
        document["cursor_keys"] = json!({
            "active": {
                "id": "cursor-k1",
                "path": dir.write("cursor-k1.key", &[0x55u8; 32])
            },
            "verify_only": []
        });
        let auth = dir.write("auth.json", document.to_string().as_bytes());
        let log_path = PathBuf::from(dir.path("api.stderr.log"));
        let log_file = fs::File::create(&log_path).unwrap();
        let bind = address();
        let mut cmd = binary("api");
        cmd.env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", db.url(API))
            .env("OPENMETTLE_API_DB_MAX_CONNECTIONS", "4")
            .env("OPENMETTLE_API_DB_TIMEOUT_MS", "2000")
            .env("OPENMETTLE_API_AUTH_CONFIG", &auth)
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", db.url(ISSUANCE))
            .env("OPENMETTLE_API_LOG_LEVEL", "debug")
            .stdout(Stdio::null())
            .stderr(log_file);
        if let Some(vault_path) = vault_keys_path {
            cmd.env("OPENMETTLE_API_VAULT_KEYS_CONFIG", vault_path);
        }
        let mut process = Process(cmd.spawn().unwrap());
        wait_ready(&mut process, &bind);
        Self {
            _process: process,
            _dir: dir,
            bind,
            log_path,
        }
    }

    fn call(
        &self,
        who: As<'_>,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let body_text = body.map(Value::to_string).unwrap_or_default();
        let mut req = format!("{method} {path} HTTP/1.1\r\nhost: app.example.test\r\n");
        match who {
            As::Browser(cookie) => {
                req.push_str(&format!(
                    "cookie: __Host-openmettle-session={cookie}\r\norigin: {ORIGIN}\r\n"
                ));
            }
            As::Native(bearer) => {
                req.push_str(&format!("authorization: Bearer {bearer}\r\n"));
            }
        }
        if let Some(k) = key {
            req.push_str(&format!("idempotency-key: {k}\r\n"));
        }
        if !body_text.is_empty() {
            req.push_str("content-type: application/json\r\n");
        }
        req.push_str(&format!(
            "content-length: {}\r\nconnection: close\r\n\r\n{body_text}",
            body_text.len()
        ));
        let mut stream = TcpStream::connect(&self.bind).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream.write_all(req.as_bytes()).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let response = String::from_utf8(response).unwrap();
        let (head, raw_body) = response.split_once("\r\n\r\n").unwrap();
        let status: u16 = head[9..12].parse().unwrap();
        let head_lower = head.to_ascii_lowercase();
        assert!(head_lower.contains("openmettle-api-version: 1.0"), "{head}");
        assert!(head_lower.contains("cache-control: no-store"), "{head}");
        if raw_body.is_empty() {
            return (status, Value::Null);
        }
        let parsed: Value = serde_json::from_str(raw_body)
            .unwrap_or_else(|e| panic!("invalid JSON ({status}): {e}: {raw_body}"));
        if status >= 400 {
            consumer::decode_problem(&parsed).unwrap();
        }
        (status, parsed)
    }

    fn stderr_text(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

/// Seed a current `present` ADR 0021 OIDC group membership observation for `user_account` on `group_name`.
async fn grant_oidc_group_evidence(
    db: &TestDb,
    owner: &mut PgConnection,
    user_account: &Account,
    group_name: &str,
    expires_ms: i64,
) {
    use openmettle_core::grants::{
        self, Assignment, ChangeInput, Decision, Grantee as GrantGrantee, MappingInput, Target,
    };
    const ISSUER: &str = "https://authz-store.example.test";
    const RULE_ID: &str = "00000000-0000-4000-8000-000000004501";
    let (project_id, scope_id) = project(owner, &user_account.user).await;
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut *owner)
            .await
            .unwrap();
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    grants::record_mapping_revision(
        &mut tx,
        &MappingInput {
            rule: RULE_ID,
            provider: PROVIDER,
            issuer: ISSUER,
            actor: &user_account.user,
            key: "vault-oidc-rule",
            expected_revision: 0,
            enabled: true,
            selector_kind: "group",
            claim_name: "groups",
            claim_value: group_name,
            binding_format: "openmettle.project-member",
            binding_version: 1,
            binding: project_id.as_bytes(),
        },
    )
    .await
    .unwrap();
    let receipt = grants::change_grant(
        &mut tx,
        &ChangeInput {
            assignment: Assignment {
                scope: &scope_id,
                target: Target::Project(&project_id),
                grantee: GrantGrantee::User(&user_account.user),
                format: "openmettle.project-member",
                version: 1,
                key: &user_account.approval,
                mapping_rule: Some(RULE_ID),
            },
            actor: &user_account.user,
            key: "vault-oidc-grant",
            expected_revision: 0,
            mapping_revision: Some(1),
            decision: Decision::Grant,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    sqlx::query(
        "WITH c AS (
           INSERT INTO openmettle.membership_configuration_changes
               (request_id, approval_id, previous_revision, rule_id, rule_revision, project_id,
                scope_id, max_age_seconds, enabled, baseline_change, floor_ms, actor, reason)
           VALUES (gen_random_uuid(), $1::uuid, 0, $2::uuid, 1, $3::uuid, $4::uuid, 3600, true,
                   NULL, NULL, gen_random_uuid(), 'synthetic vault oidc group enrollment')
           RETURNING revision)
         INSERT INTO openmettle.membership_observations
             (approval_id, config_revision, enabled, floor_ms, rule_id, rule_revision, project_id,
              scope_id, max_age_seconds, issued_ms, expires_ms, observation, epoch,
              approval_generation, user_generation)
         SELECT $1::uuid, c.revision, true, NULL, $2::uuid, 1, $3::uuid, $4::uuid, 3600,
                $6 - 60000, $7, ROW('present', $5::uuid)::openmettle.membership_evidence,
                (SELECT max(epoch) FROM openmettle.login_provider_revisions
                  WHERE provider_id = $8::uuid), 0, 0
           FROM c",
    )
    .bind(&user_account.approval)
    .bind(RULE_ID)
    .bind(&project_id)
    .bind(&scope_id)
    .bind(&receipt.change)
    .bind(now_ms)
    .bind(expires_ms)
    .bind(PROVIDER)
    .execute(&mut *owner)
    .await
    .unwrap();
}

/// Synthetic `rcgen` HTTPS server bound on `TEST_GATEWAY_HOST`.
struct SyntheticTlsServer {
    host: String,
    ip: IpAddr,
    port: u16,
    ca_pem: Vec<u8>,
    requests: Arc<AtomicUsize>,
    captured: Arc<Mutex<Vec<(String, String)>>>,
}

impl SyntheticTlsServer {
    async fn start(script: impl Fn(&str, &str) -> Vec<u8> + Send + Sync + 'static) -> Self {
        let host = std::env::var("TEST_GATEWAY_HOST")
            .expect("TEST_GATEWAY_HOST must name a private address of this host");
        let mut ips: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(&*host, 0))
            .expect("TEST_GATEWAY_HOST resolves")
            .map(|a| a.ip())
            .collect();
        ips.sort();
        ips.dedup();
        let [ip] = ips[..] else {
            panic!("TEST_GATEWAY_HOST must resolve to one address");
        };
        let ca = ca::Ca::new();
        let identity = ca.leaf(&host, false);
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(identity.chain, identity.key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let req_count = requests.clone();
        let cap_log = captured.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let script = script.clone();
                let req_count = req_count.clone();
                let cap_log = cap_log.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut data = Vec::new();
                    let mut buf = [0u8; 4096];
                    let end = loop {
                        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        let Ok(n) = tls.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 || data.len() > 256 * 1024 {
                            return;
                        }
                        data.extend_from_slice(&buf[..n]);
                    };
                    let head = String::from_utf8_lossy(&data[..end]).into_owned();
                    let length = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    let mut body = data[end..].to_vec();
                    while body.len() < length {
                        let Ok(n) = tls.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        body.extend_from_slice(&buf[..n]);
                    }
                    let body_str = String::from_utf8_lossy(&body).into_owned();
                    req_count.fetch_add(1, Ordering::SeqCst);
                    let reply = script(&head, &body_str);
                    cap_log.lock().unwrap().push((head, body_str));
                    let _ = tls.write_all(&reply).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            host,
            ip,
            port,
            ca_pem: ca.pem(),
            requests,
            captured,
        }
    }

    fn private_cidr(&self) -> String {
        let prefix = if self.ip.is_ipv4() { 32 } else { 128 };
        format!("{}/{prefix}", self.ip)
    }

    fn origin(&self) -> String {
        format!("https://{}:{}", self.host, self.port)
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}:{}{path}", self.host, self.port)
    }

    fn refresh_client(
        &self,
        provider_kind: &str,
        allowed_origins: &[&str],
    ) -> Arc<HttpsRefreshClient> {
        let range = self.private_cidr();
        Arc::new(
            HttpsRefreshClient::new(
                provider_kind,
                allowed_origins,
                &self.url("/oauth/token"),
                Trust::Bundle(&self.ca_pem),
                &[&range],
                Some("synthetic-client".into()),
                RefreshTimeouts::default(),
            )
            .unwrap(),
        )
    }

    fn mcp_transport(&self) -> Arc<McpTransport> {
        let range = self.private_cidr();
        Arc::new(
            McpTransport::new(
                &self.url("/mcp"),
                Trust::Bundle(&self.ca_pem),
                &[&range],
                McpTimeouts {
                    setup: Duration::from_secs(5),
                    idle_read: Duration::from_secs(5),
                    call: Duration::from_secs(10),
                },
            )
            .unwrap(),
        )
    }
}

fn http_json(status: u16, body: &Value) -> Vec<u8> {
    let text = body.to_string();
    format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        text.len()
    )
    .into_bytes()
}

async fn make_pool(db: &TestDb, role: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(8)
        .connect_with(role_options(&db.0, role))
        .await
        .unwrap()
}

// ============================================================================================
// 1. Personal/project ownership, sharing, immediate revocation, HTTP routes & redaction
// ============================================================================================

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn vault_personal_project_ownership_sharing_revocation_and_http_routes() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let carol_admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    let dave = account(&mut owner, PROVIDER, true, FUTURE).await;
    let eve = account(&mut owner, PROVIDER, true, FUTURE).await;
    let viewer = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &carol_admin).await;
    grant_oidc_group_evidence(&db, &mut owner, &eve, OIDC_GROUP, FUTURE).await;

    // Create local group containing Dave.
    let mut api_conn = connect(&db.0, API).await;
    let group_id =
        store::create_local_group(&mut api_conn, &ctx(&carol_admin, "grp-1"), "vault-team")
            .await
            .unwrap()
            .target_id()
            .to_owned();
    store::add_local_group_member(
        &mut api_conn,
        &ctx(&carol_admin, "grp-add-1"),
        &group_id,
        &dave.user,
    )
    .await
    .unwrap();

    // Verify invalid VAULT_KEYS_CONFIG refuses startup with exit 78 and redacted stderr.
    {
        let bad_dir = auth_config_support::Dir::new();
        let bad_key = bad_dir.write("loose.key", &[0x11u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bad_key, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let bad_cfg = bad_dir.write(
            "bad-vault.json",
            json!({"version": 1, "active_key_id": "k1", "keys": [{"id": "k1", "file": bad_key}]})
                .to_string()
                .as_bytes(),
        );
        let mut cmd = binary("api");
        cmd.env("OPENMETTLE_API_BIND", address())
            .env("OPENMETTLE_API_DATABASE_URL", db.url(API))
            .env("OPENMETTLE_API_VAULT_KEYS_CONFIG", &bad_cfg);
        let out = run_refusal(&mut cmd, "api loose vault key file");
        assert_eq!(out.status.code(), Some(78));
        let err = stderr(&out);
        assert!(err.starts_with("vault configuration error: "), "{err}");
        assert!(!err.contains(&bad_key), "{err}");
    }

    let alice_s = browser(&db, &alice, 1).await;
    let bob_s = native(&db, &bob, 2).await;
    let admin_s = browser(&db, &carol_admin, 3).await;
    let dave_s = native(&db, &dave, 4).await;
    let eve_s = native(&db, &eve, 5).await;
    let viewer_s = native(&db, &viewer, 6).await;

    // Boot API WITHOUT VAULT_KEYS_CONFIG first to verify 503 provisioning on /authorize.
    let unprovisioned_api = VaultApi::start(&db, auth_config_support::Dir::new(), None);
    let create_body = json!({
        "provider_kind": "github",
        "account_id": "acct-alice",
        "origin": "https://api.example.test",
        "allowed_scopes": ["issues.write", "issues.read"],
        "reason": "register personal connection"
    });
    let (status, created) = unprovisioned_api.call(
        As::Browser(&alice_s),
        "POST",
        "/v1/connections",
        Some("conn-create-1"),
        Some(&create_body),
    );
    assert_eq!(status, 201, "{created}");
    let decoded_created = consumer::decode_connection(&created).unwrap();
    assert_eq!(
        decoded_created.state,
        consumer::ConnectionState::PendingAuth
    );
    assert_eq!(
        decoded_created.allowed_scopes,
        vec!["issues.read", "issues.write"]
    );
    assert!(decoded_created.granted_scopes.is_empty());
    assert!(!decoded_created.has_refresh);
    assert!(decoded_created.can_manage);
    let conn_id = decoded_created.connection_id.clone();

    // Idempotent replay returns 200 with same connection_id; different body with same key is 409.
    let (status, replayed) = unprovisioned_api.call(
        As::Browser(&alice_s),
        "POST",
        "/v1/connections",
        Some("conn-create-1"),
        Some(&create_body),
    );
    assert_eq!(status, 200);
    assert_eq!(replayed["connection_id"], conn_id);
    let (status, conflict) = unprovisioned_api.call(
        As::Browser(&alice_s),
        "POST",
        "/v1/connections",
        Some("conn-create-1"),
        Some(&json!({
            "provider_kind": "gitlab",
            "account_id": "acct-alice",
            "origin": "https://api.example.test",
            "allowed_scopes": ["issues.read"]
        })),
    );
    assert_eq!(status, 409);
    assert_eq!(conflict["code"], "idempotency_conflict");

    // Without VAULT_KEYS_CONFIG, /authorize answers 503 provisioning.
    let (status, prov) = unprovisioned_api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{conn_id}/authorize"),
        Some("auth-unprov"),
        Some(&json!({
            "access_token": "CANARY-UNPROV-TOKEN",
            "granted_scopes": ["issues.read"]
        })),
    );
    assert_eq!(status, 503);
    assert_eq!(prov["code"], "provisioning");
    drop(unprovisioned_api);

    // Boot API WITH VAULT_KEYS_CONFIG (key k1).
    let dir = auth_config_support::Dir::new();
    let k1 = [0x31u8; 32];
    let keyring_path = write_keyring_files(&dir, "vault-k1", "k1", &[("k1", k1)]);
    let api = VaultApi::start(&db, dir, Some(&keyring_path));
    let worker_pool = make_pool(&db, WORKER).await;
    let ring = Arc::new(VaultKeyRing::new("k1".into(), vec![("k1".into(), k1)]).unwrap());
    let provider =
        VaultCredentialProvider::new(worker_pool.clone(), ring, None, VaultConfig::default());
    let authorizer = VaultDestinationAuthorizer::new();
    let mut worker_conn = connect(&db.0, WORKER).await;

    // Non-owner Bob and account_admin Carol are concealed (404).
    for (label, who) in [
        ("bob", As::Native(&bob_s)),
        ("admin", As::Browser(&admin_s)),
    ] {
        let (st, body) = api.call(
            who,
            "GET",
            &format!("/v1/connections/{conn_id}"),
            None,
            None,
        );
        assert_eq!(st, 404, "{label}: {body}");
        assert_eq!(body["code"], "not_found");
        let (st, _) = api.call(
            who,
            "POST",
            &format!("/v1/connections/{conn_id}/disconnect"),
            Some(&format!("disc-{label}")),
            None,
        );
        assert_eq!(st, 404, "{label}");
    }

    // Scope widening on /authorize is refused (400 validation).
    let (st, wide_err) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{conn_id}/authorize"),
        Some("auth-wide"),
        Some(&json!({
            "access_token": "CANARY-WIDENED-TOKEN",
            "granted_scopes": ["issues.read", "issues.admin"]
        })),
    );
    assert_eq!(st, 400, "{wide_err}");
    assert_eq!(wide_err["code"], "validation");

    // Valid authorization stores encrypted credentials and returns non-secret metadata only.
    let access_canary = "CANARY-ACCESS-SECRET-ALPHA";
    let refresh_canary = "CANARY-REFRESH-SECRET-BETA";
    let auth_ok_body = json!({
        "access_token": access_canary,
        "refresh_token": refresh_canary,
        "granted_scopes": ["issues.read"],
        "expires_at": "2030-01-01T00:00:00.000000Z",
        "reason": "store synthetic credentials"
    });
    let (st, authorized_json) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{conn_id}/authorize"),
        Some("auth-ok-1"),
        Some(&auth_ok_body),
    );
    assert_eq!(st, 200, "{authorized_json}");
    let auth_view = consumer::decode_connection(&authorized_json).unwrap();
    assert_eq!(auth_view.state, consumer::ConnectionState::Authorized);
    assert!(auth_view.has_refresh);
    assert_eq!(auth_view.generation, 1);
    assert_eq!(auth_view.granted_scopes, vec!["issues.read"]);
    assert!(!authorized_json.to_string().contains(access_canary));
    assert!(!authorized_json.to_string().contains(refresh_canary));

    // P2 #11: Exact Idempotency-Key replay succeeds (200); reusing key with different tokens -> 409!
    let (st, replay_auth) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{conn_id}/authorize"),
        Some("auth-ok-1"),
        Some(&auth_ok_body),
    );
    assert_eq!(st, 200, "{replay_auth}");
    assert_eq!(
        consumer::decode_connection(&replay_auth)
            .unwrap()
            .generation,
        1
    );
    for (label, mutated) in [
        (
            "different access_token",
            json!({
                "access_token": "CANARY-DIFFERENT-ACCESS",
                "refresh_token": refresh_canary,
                "granted_scopes": ["issues.read"],
                "expires_at": "2030-01-01T00:00:00.000000Z",
                "reason": "store synthetic credentials"
            }),
        ),
        (
            "different refresh_token",
            json!({
                "access_token": access_canary,
                "refresh_token": "CANARY-DIFFERENT-REFRESH",
                "granted_scopes": ["issues.read"],
                "expires_at": "2030-01-01T00:00:00.000000Z",
                "reason": "store synthetic credentials"
            }),
        ),
    ] {
        let (st, conflict) = api.call(
            As::Browser(&alice_s),
            "POST",
            &format!("/v1/connections/{conn_id}/authorize"),
            Some("auth-ok-1"),
            Some(&mutated),
        );
        assert_eq!(st, 409, "{label}: {conflict}");
        assert_eq!(conflict["code"], "idempotency_conflict", "{label}");
    }

    // P2 #14 & P2 #15: 64 distinct 128-byte scopes fit within 4,096-byte audit details,
    // 4,097-byte access token is refused (400), and 4,096-byte access token succeeds (200).
    let max_scopes: Vec<String> = (0..64)
        .map(|i| format!("s{i:02}-{}", "a".repeat(124)))
        .collect();
    assert!(max_scopes.iter().all(|s| s.len() == 128));
    let (st, max_conn_json) = api.call(
        As::Browser(&alice_s),
        "POST",
        "/v1/connections",
        Some("conn-64-scopes"),
        Some(&json!({
            "provider_kind": "github",
            "account_id": "acct-64-scopes",
            "origin": "https://api.example.test",
            "allowed_scopes": max_scopes,
        })),
    );
    assert_eq!(st, 201, "{max_conn_json}");
    let max_conn_id = consumer::decode_connection(&max_conn_json)
        .unwrap()
        .connection_id;
    let (st, too_long_err) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{max_conn_id}/authorize"),
        Some("auth-4097"),
        Some(&json!({
            "access_token": "x".repeat(4097),
            "granted_scopes": max_scopes,
        })),
    );
    assert_eq!(st, 400, "{too_long_err}");
    assert_eq!(too_long_err["code"], "validation");
    let (st, ok_4096) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{max_conn_id}/authorize"),
        Some("auth-64-scopes-4096"),
        Some(&json!({
            "access_token": "x".repeat(4096),
            "granted_scopes": max_scopes,
        })),
    );
    assert_eq!(st, 200, "{ok_4096}");
    let max_audit_bytes: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(octet_length(details::text)), 0)::bigint
           FROM openmettle.authorization_audit",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(
        max_audit_bytes <= 4096,
        "audit details exceeded 4096 bytes: {max_audit_bytes}"
    );

    // Verify ZERO plaintext secret substrings anywhere in PostgreSQL tables or debug logs.
    let conn_dump: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(to_jsonb(c)::text, '\n'), '') FROM openmettle.external_connections c",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let audit_dump: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(to_jsonb(a)::text, '\n'), '') FROM openmettle.authorization_audit a",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let logs = api.stderr_text();
    for needle in [access_canary, refresh_canary, "CANARY-WIDENED-TOKEN"] {
        assert!(
            !conn_dump.contains(needle),
            "secret leaked in external_connections"
        );
        assert!(
            !audit_dump.contains(needle),
            "secret leaked in authorization_audit"
        );
        assert!(!logs.contains(needle), "secret leaked in api debug logs");
    }

    // List personal connections with cursor pagination.
    let (st, page_json) = api.call(
        As::Browser(&alice_s),
        "GET",
        "/v1/connections?limit=1",
        None,
        None,
    );
    assert_eq!(st, 200);
    let page = consumer::decode_connection_page(&page_json).unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].connection_id, conn_id);

    // Explicit sharing on personal connection: user Bob, local_group (Dave), oidc_group (Eve).
    // Whole-project grantee is refused on personal connections (403 policy).
    let (st, err) = api.call(
        As::Browser(&alice_s),
        "PUT",
        &format!("/v1/connections/{conn_id}/shares"),
        Some("share-proj-personal"),
        Some(&json!({"grantee": {"kind": "project"}, "access": "use"})),
    );
    assert_eq!(st, 403, "{err}");

    for (key, grantee) in [
        ("share-bob", json!({"kind": "user", "grantee_id": bob.user})),
        (
            "share-grp",
            json!({"kind": "local_group", "grantee_id": group_id}),
        ),
        (
            "share-oidc",
            json!({"kind": "oidc_group", "grantee_id": OIDC_GROUP}),
        ),
    ] {
        let (st, body) = api.call(
            As::Browser(&alice_s),
            "PUT",
            &format!("/v1/connections/{conn_id}/shares"),
            Some(key),
            Some(&json!({"grantee": grantee, "access": "use"})),
        );
        assert_eq!(st, 200, "{key}: {body}");
        consumer::decode_connection_share(&body).unwrap();
    }

    let alice_scope = personal_of(&db, &alice).await;
    let dest = json!(["v1", conn_id, "acct-alice", "issues.read", "repo/1"]).to_string();
    // Bob, Dave (via local_group), and Eve (via oidc_group) can read metadata & execute, but cannot manage.
    for (label, who, acct) in [
        ("bob", As::Native(&bob_s), &bob),
        ("dave", As::Native(&dave_s), &dave),
        ("eve", As::Native(&eve_s), &eve),
    ] {
        let (st, meta) = api.call(
            who,
            "GET",
            &format!("/v1/connections/{conn_id}"),
            None,
            None,
        );
        assert_eq!(st, 200, "{label}: {meta}");
        assert!(!consumer::decode_connection(&meta).unwrap().can_manage);
        let (st, _) = api.call(
            who,
            "POST",
            &format!("/v1/connections/{conn_id}/disconnect"),
            Some(&format!("disc-shared-{label}")),
            None,
        );
        assert_eq!(st, 403, "{label}");

        let resolved = provider
            .resolve(CredentialRequest {
                connection_id: &conn_id,
                account_id: "acct-alice",
                scope_id: &alice_scope,
                actor_user_id: &acct.user,
                actor_approval_id: Some(&acct.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await;
        match resolved {
            CredentialOutcome::Ready(cred) => assert_eq!(cred.bearer_token(), Some(access_canary)),
            other => panic!("expected Ready for shared user {label}, got {other:?}"),
        }
        assert!(
            authorizer
                .authorize_reconcile(
                    &mut worker_conn,
                    ReconcileTarget {
                        scope_id: &alice_scope,
                        run_id: "00000000-0000-4000-8000-000000000001",
                        actor_user_id: &acct.user,
                        actor_approval_id: Some(&acct.approval),
                        connection_id: &conn_id,
                        account_id: "acct-alice",
                        tool_id: "gh.issue",
                        tool_version: "1",
                        destination: &dest,
                        capability: "lookup",
                        lookup_scope: "issues.read",
                        expected_origin: Some("https://api.example.test"),
                    }
                )
                .await,
            "expected authorize_reconcile=true for {label}"
        );
    }

    // Immediate revocation of Bob's share cuts off GET, resolve, and authorize_reconcile.
    let (st, _) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{conn_id}/shares/revoke"),
        Some("revoke-bob"),
        Some(&json!({"grantee": {"kind": "user", "grantee_id": bob.user}})),
    );
    assert_eq!(st, 204);
    let (st, _) = api.call(
        As::Native(&bob_s),
        "GET",
        &format!("/v1/connections/{conn_id}"),
        None,
        None,
    );
    assert_eq!(st, 404);
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &conn_id,
                account_id: "acct-alice",
                scope_id: &alice_scope,
                actor_user_id: &bob.user,
                actor_approval_id: Some(&bob.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));
    assert!(
        !authorizer
            .authorize_reconcile(
                &mut worker_conn,
                ReconcileTarget {
                    scope_id: &alice_scope,
                    run_id: "00000000-0000-4000-8000-000000000001",
                    actor_user_id: &bob.user,
                    actor_approval_id: Some(&bob.approval),
                    connection_id: &conn_id,
                    account_id: "acct-alice",
                    tool_id: "gh.issue",
                    tool_version: "1",
                    destination: &dest,
                    capability: "lookup",
                    lookup_scope: "issues.read",
                    expected_origin: Some("https://api.example.test"),
                }
            )
            .await
    );

    // Lapsed OIDC group evidence immediately cuts off Eve's OIDC-group-shared access.
    sqlx::query(
        "UPDATE openmettle.membership_observations
            SET expires_ms = issued_ms
          WHERE approval_id = $1::uuid",
    )
    .bind(&eve.approval)
    .execute(&mut owner)
    .await
    .unwrap();
    let (st, _) = api.call(
        As::Native(&eve_s),
        "GET",
        &format!("/v1/connections/{conn_id}"),
        None,
        None,
    );
    assert_eq!(st, 404);
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &conn_id,
                account_id: "acct-alice",
                scope_id: &alice_scope,
                actor_user_id: &eve.user,
                actor_approval_id: Some(&eve.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));

    // Project connection ownership, Gate 2b sharing, Viewer non-execution, Archive/Delete & Restore gate.
    let defaults = json!({});
    let proj_id = projects::create_project(
        &mut api_conn,
        &ctx(&alice, "proj-1"),
        &ProjectSettingsInput {
            name: "Vault Project",
            instructions: "",
            defaults: &defaults,
        },
    )
    .await
    .unwrap()
    .target_id()
    .to_owned();
    let proj_scope: String =
        sqlx::query_scalar("SELECT scope_id::text FROM openmettle.projects WHERE id = $1::uuid")
            .bind(&proj_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    projects::set_project_member_role(
        &mut api_conn,
        &ctx(&alice, "pm-bob"),
        &proj_id,
        &Grantee::User(bob.user.clone()),
        ProjectRole::Editor,
    )
    .await
    .unwrap();
    projects::set_project_member_role(
        &mut api_conn,
        &ctx(&alice, "pm-viewer"),
        &proj_id,
        &Grantee::User(viewer.user.clone()),
        ProjectRole::Viewer,
    )
    .await
    .unwrap();

    // Project Editor Bob cannot create project connections (403 policy).
    let proj_create = json!({
        "scope_id": proj_scope,
        "provider_kind": "github",
        "account_id": "acct-proj",
        "origin": "https://proj.example.test",
        "allowed_scopes": ["issues.read", "issues.write"]
    });
    let (st, _) = api.call(
        As::Native(&bob_s),
        "POST",
        "/v1/connections",
        Some("pconn-bob"),
        Some(&proj_create),
    );
    assert_eq!(st, 403);

    // Project Owner Alice creates & authorizes project connection.
    let (st, pconn_json) = api.call(
        As::Browser(&alice_s),
        "POST",
        "/v1/connections",
        Some("pconn-alice"),
        Some(&proj_create),
    );
    assert_eq!(st, 201, "{pconn_json}");
    let pconn_id = consumer::decode_connection(&pconn_json)
        .unwrap()
        .connection_id;
    let (st, _) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{pconn_id}/authorize"),
        Some("pconn-auth"),
        Some(&json!({
            "access_token": "CANARY-PROJ-TOKEN",
            "granted_scopes": ["issues.read"]
        })),
    );
    assert_eq!(st, 200);

    // P2 #13: Before explicit share, project Editor Bob, Viewer, and account_admin Carol are
    // concealed (`404 not_found`) across BOTH GET and every management mutation!
    for who in [
        As::Native(&bob_s),
        As::Native(&viewer_s),
        As::Browser(&admin_s),
    ] {
        let (st, _) = api.call(
            who,
            "GET",
            &format!("/v1/connections/{pconn_id}"),
            None,
            None,
        );
        assert_eq!(st, 404);
    }
    for (method, suffix, key, body) in [
        (
            "POST",
            "/authorize",
            "bob-unshared-auth",
            Some(json!({"access_token": "CANARY-UNSHARED", "granted_scopes": ["issues.read"]})),
        ),
        ("POST", "/disconnect", "bob-unshared-disc", None),
        (
            "PUT",
            "/shares",
            "bob-unshared-share",
            Some(json!({"grantee": {"kind": "project"}, "access": "use"})),
        ),
        (
            "POST",
            "/shares/revoke",
            "bob-unshared-revoke",
            Some(json!({"grantee": {"kind": "project"}})),
        ),
    ] {
        let (st, err) = api.call(
            As::Native(&bob_s),
            method,
            &format!("/v1/connections/{pconn_id}{suffix}"),
            Some(key),
            body.as_ref(),
        );
        assert_eq!(st, 404, "unshared Editor {method} {suffix}: {err}");
        assert_eq!(err["code"], "not_found");
    }
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &pconn_id,
                account_id: "acct-proj",
                scope_id: &proj_scope,
                actor_user_id: &bob.user,
                actor_approval_id: Some(&bob.approval),
                expected_origin: Some("https://proj.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));

    // Whole-project share grants Editor Bob execution, allows Viewer metadata read, STILL denies
    // Viewer execution, and returns `403 policy` (not 404) when visible non-owners attempt management!
    let (st, _) = api.call(
        As::Browser(&alice_s),
        "PUT",
        &format!("/v1/connections/{pconn_id}/shares"),
        Some("pshare-all"),
        Some(&json!({"grantee": {"kind": "project"}, "access": "use"})),
    );
    assert_eq!(st, 200);
    for (method, suffix, key, body) in [
        (
            "POST",
            "/authorize",
            "bob-shared-auth",
            Some(json!({"access_token": "CANARY-SHARED", "granted_scopes": ["issues.read"]})),
        ),
        ("POST", "/disconnect", "bob-shared-disc", None),
        (
            "PUT",
            "/shares",
            "bob-shared-share",
            Some(json!({"grantee": {"kind": "user", "grantee_id": bob.user}, "access": "use"})),
        ),
        (
            "POST",
            "/shares/revoke",
            "bob-shared-revoke",
            Some(json!({"grantee": {"kind": "project"}})),
        ),
    ] {
        let (st, err) = api.call(
            As::Native(&bob_s),
            method,
            &format!("/v1/connections/{pconn_id}{suffix}"),
            Some(key),
            body.as_ref(),
        );
        assert_eq!(st, 403, "shared Editor {method} {suffix}: {err}");
        assert_eq!(err["code"], "policy");
    }
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &pconn_id,
                account_id: "acct-proj",
                scope_id: &proj_scope,
                actor_user_id: &bob.user,
                actor_approval_id: Some(&bob.approval),
                expected_origin: Some("https://proj.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Ready(_)
    ));
    let (st, _) = api.call(
        As::Native(&viewer_s),
        "GET",
        &format!("/v1/connections/{pconn_id}"),
        None,
        None,
    );
    assert_eq!(st, 200);
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &pconn_id,
                account_id: "acct-proj",
                scope_id: &proj_scope,
                actor_user_id: &viewer.user,
                actor_approval_id: Some(&viewer.approval),
                expected_origin: Some("https://proj.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));

    // Archived project blocks execution and /authorize (409), while permitting GET and /shares/revoke & /disconnect.
    projects::archive_project(&mut api_conn, &ctx(&alice, "arch-1"), &proj_id)
        .await
        .unwrap();
    let (st, _) = api.call(
        As::Browser(&alice_s),
        "GET",
        &format!("/v1/connections/{pconn_id}"),
        None,
        None,
    );
    assert_eq!(st, 200);
    let (st, _) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{pconn_id}/authorize"),
        Some("arch-auth"),
        Some(&json!({"access_token": "CANARY-ARCH", "granted_scopes": ["issues.read"]})),
    );
    assert_eq!(st, 409);
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &pconn_id,
                account_id: "acct-proj",
                scope_id: &proj_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some("https://proj.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));
    let (st, _) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{pconn_id}/shares/revoke"),
        Some("arch-revoke"),
        Some(&json!({"grantee": {"kind": "project"}})),
    );
    assert_eq!(st, 204);
    let (st, disc_body) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{pconn_id}/disconnect"),
        Some("arch-disc"),
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(
        consumer::decode_connection(&disc_body).unwrap().state,
        consumer::ConnectionState::Disconnected
    );

    // Deleted project conceals its connections completely (404).
    projects::delete_project(&mut api_conn, &ctx(&alice, "del-1"), &proj_id)
        .await
        .unwrap();
    let (st, _) = api.call(
        As::Browser(&alice_s),
        "GET",
        &format!("/v1/connections/{pconn_id}"),
        None,
        None,
    );
    assert_eq!(st, 404);

    // Closed restore_reconciliation_gate fails closed on API mutations (503) and worker resolve.
    let (
        origin_us,
        lifecycle_origin_us,
        lifecycle_baseline_digest,
        connection_origin_us,
        head_seq,
        head_digest,
    ): (i64, i64, String, i64, i64, String) = sqlx::query_as(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint,
                (extract(epoch FROM lifecycle_coverage_started_at) * 1000000)::bigint,
                encode(lifecycle_baseline_digest, 'hex'),
                (extract(epoch FROM connection_coverage_started_at) * 1000000)::bigint,
                journal_seq,
                encode(chain_digest, 'hex')
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, $2, decode($3, 'hex'), true, NULL, true, $4, decode($5, 'hex'), $6)",
    )
    .bind(origin_us)
    .bind(head_seq)
    .bind(&head_digest)
    .bind(lifecycle_origin_us)
    .bind(&lifecycle_baseline_digest)
    .bind(connection_origin_us)
    .execute(&mut owner)
    .await
    .unwrap();
    let (st, gate_err) = api.call(
        As::Browser(&alice_s),
        "POST",
        &format!("/v1/connections/{conn_id}/disconnect"),
        Some("disc-gated"),
        None,
    );
    assert_eq!(st, 503, "{gate_err}");
    assert_eq!(gate_err["code"], "unavailable");
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &conn_id,
                account_id: "acct-alice",
                scope_id: &alice_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));
}

// ============================================================================================
// 2. Versioned encryption, AAD tamper refusal, admin status/rotate, and key-loss recovery
// ============================================================================================

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn vault_versioned_encryption_aad_tamper_and_admin_rotation() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_scope = personal_of(&db, &alice).await;
    let mut api_conn = connect(&db.0, API).await;

    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    let k3 = [0x33u8; 32];
    let ring_k1 = Arc::new(VaultKeyRing::new("k1".into(), vec![("k1".into(), k1)]).unwrap());
    let ring_k2_only = Arc::new(VaultKeyRing::new("k2".into(), vec![("k2".into(), k2)]).unwrap());
    let ring_k3_only = Arc::new(VaultKeyRing::new("k3".into(), vec![("k3".into(), k3)]).unwrap());

    let mut conn_ids = Vec::new();
    for i in 0..2 {
        let id = vault::create_connection(
            &mut api_conn,
            &ctx(&alice, &format!("rot-c-{i}")),
            &CreateConnectionInput {
                scope_id: &alice_scope,
                provider_kind: "github",
                account_id: &format!("acct-{i}"),
                origin: "https://api.example.test",
                allowed_scopes: &["issues.read".into()],
            },
        )
        .await
        .unwrap()
        .target_id()
        .to_owned();
        vault::authorize_connection(
            &mut api_conn,
            &ctx(&alice, &format!("rot-a-{i}")),
            &ring_k1,
            &id,
            &AuthorizeConnectionInput {
                access_token: &format!("CANARY-ROT-ACCESS-{i}"),
                refresh_token: Some(&format!("CANARY-ROT-REFRESH-{i}")),
                granted_scopes: &["issues.read".into()],
                expires_at: None,
            },
        )
        .await
        .unwrap();
        conn_ids.push(id);
    }

    // `openmettle-admin vault status` reports k1 without leaking secrets.
    let status_out = admin_cli(&db.url(OWNER), &["vault", "status"]);
    assert!(status_out.status.success(), "{}", stderr(&status_out));
    let stdout_s = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        stdout_s.contains("connections 2, encrypted 2"),
        "{stdout_s}"
    );
    assert!(stdout_s.contains("key_id k1 2"), "{stdout_s}");
    assert!(!stdout_s.contains("CANARY-ROT"));

    // Missing historical key k1 fails closed before modifying any row.
    let dir = auth_config_support::Dir::new();
    let cfg_k2_only = write_keyring_files(&dir, "k2-only", "k2", &[("k2", k2)]);
    let op_id = "00000000-0000-4000-8000-000000000901";
    let missing_out = admin_cli(
        &db.url(OWNER),
        &[
            "vault",
            "rotate",
            "--vault-keys",
            &cfg_k2_only,
            "--operator-id",
            op_id,
            "--request-key",
            "rot-missing",
            "--reason",
            "should fail missing k1",
        ],
    );
    assert!(!missing_out.status.success());
    assert!(stderr(&missing_out).contains("stored key version missing"));

    // P2 #7: Hold an active worker refresh lease on conn_ids[0] during `vault rotate`:
    // rotate must defer conn_ids[0], rotate conn_ids[1], preserve the in-flight claim,
    // exit non-zero, and NOT consume `rot-to-k2` so retrying after lease release completes cleanly!
    let cfg_k1_k2 = write_keyring_files(&dir, "k1-k2", "k2", &[("k1", k1), ("k2", k2)]);
    let active_claim: String = sqlx::query_scalar(
        "UPDATE openmettle.external_connections
            SET refresh_claim_token = gen_random_uuid(),
                refresh_lease_until = clock_timestamp() + interval '5 minutes'
          WHERE id = $1::uuid
         RETURNING refresh_claim_token::text",
    )
    .bind(&conn_ids[0])
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let deferred_out = admin_cli(
        &db.url(OWNER),
        &[
            "vault",
            "rotate",
            "--vault-keys",
            &cfg_k1_k2,
            "--operator-id",
            op_id,
            "--request-key",
            "rot-to-k2",
            "--reason",
            "rotate to k2",
            "--batch-size",
            "1",
        ],
    );
    assert!(
        !deferred_out.status.success(),
        "rotate with deferred active refresh must exit non-zero"
    );
    let deferred_stdout = String::from_utf8_lossy(&deferred_out.stdout);
    assert!(
        deferred_stdout.contains(
            "applied vault.rotated target_key_id=k2 rotated=1 skipped=1 deferred_active_refresh=1"
        ),
        "{deferred_stdout}"
    );
    let (still_key, still_gen, still_claim): (String, i64, Option<String>) = sqlx::query_as(
        "SELECT encryption_key_id, credential_generation, refresh_claim_token::text
           FROM openmettle.external_connections WHERE id = $1::uuid",
    )
    .bind(&conn_ids[0])
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(still_key, "k1");
    assert_eq!(still_gen, 1);
    assert_eq!(still_claim.as_deref(), Some(active_claim.as_str()));

    // Clear the active refresh lease and retry with the EXACT SAME `--request-key rot-to-k2`.
    sqlx::query(
        "UPDATE openmettle.external_connections
            SET refresh_claim_token = NULL, refresh_lease_until = NULL
          WHERE id = $1::uuid",
    )
    .bind(&conn_ids[0])
    .execute(&mut owner)
    .await
    .unwrap();
    let rot_out = admin_cli(
        &db.url(OWNER),
        &[
            "vault",
            "rotate",
            "--vault-keys",
            &cfg_k1_k2,
            "--operator-id",
            op_id,
            "--request-key",
            "rot-to-k2",
            "--reason",
            "rotate to k2",
            "--batch-size",
            "1",
        ],
    );
    assert!(rot_out.status.success(), "{}", stderr(&rot_out));
    let rot_stdout = String::from_utf8_lossy(&rot_out.stdout);
    assert!(
        rot_stdout.contains(
            "applied vault.rotated target_key_id=k2 rotated=1 skipped=0 deferred_active_refresh=0"
        ),
        "{rot_stdout}"
    );

    // Replay with same operator_id & request_key succeeds idempotently.
    let replay_out = admin_cli(
        &db.url(OWNER),
        &[
            "vault",
            "rotate",
            "--vault-keys",
            &cfg_k1_k2,
            "--operator-id",
            op_id,
            "--request-key",
            "rot-to-k2",
            "--reason",
            "rotate to k2",
        ],
    );
    assert!(replay_out.status.success(), "{}", stderr(&replay_out));
    assert!(String::from_utf8_lossy(&replay_out.stdout).contains("replayed vault.rotated"));

    // After rotation, a worker with ONLY k2 decrypts both connections cleanly.
    let worker_pool = make_pool(&db, WORKER).await;
    let prov_k2 = VaultCredentialProvider::new(
        worker_pool.clone(),
        ring_k2_only.clone(),
        None,
        VaultConfig::default(),
    );
    for (i, id) in conn_ids.iter().enumerate() {
        let got = prov_k2
            .resolve(CredentialRequest {
                connection_id: id,
                account_id: &format!("acct-{i}"),
                scope_id: &alice_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await;
        match got {
            CredentialOutcome::Ready(c) => {
                assert_eq!(
                    c.bearer_token(),
                    Some(format!("CANARY-ROT-ACCESS-{i}").as_str())
                );
            }
            other => panic!("expected k2 decryption for conn {i}, got {other:?}"),
        }
    }

    // Cross-row ciphertext swap fails AAD verification fail-closed!
    sqlx::query(
        "UPDATE openmettle.external_connections AS dst
            SET access_salt = src.access_salt,
                access_nonce = src.access_nonce,
                access_ciphertext = src.access_ciphertext,
                credential_generation = dst.credential_generation + 1
           FROM openmettle.external_connections AS src
          WHERE dst.id = $1::uuid AND src.id = $2::uuid",
    )
    .bind(&conn_ids[1])
    .bind(&conn_ids[0])
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(matches!(
        prov_k2
            .resolve(CredentialRequest {
                connection_id: &conn_ids[1],
                account_id: "acct-1",
                scope_id: &alice_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));

    // Key-loss recovery: keyring with only k3 refuses k2 row cleanly, then owner recovers via re-authorize.
    let prov_k3 = VaultCredentialProvider::new(
        worker_pool,
        ring_k3_only.clone(),
        None,
        VaultConfig::default(),
    );
    assert!(matches!(
        prov_k3
            .resolve(CredentialRequest {
                connection_id: &conn_ids[0],
                account_id: "acct-0",
                scope_id: &alice_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));
    vault::authorize_connection(
        &mut api_conn,
        &ctx(&alice, "recover-k3"),
        &ring_k3_only,
        &conn_ids[0],
        &AuthorizeConnectionInput {
            access_token: "CANARY-RECOVERED-K3",
            refresh_token: None,
            granted_scopes: &["issues.read".into()],
            expires_at: None,
        },
    )
    .await
    .unwrap();
    match prov_k3
        .resolve(CredentialRequest {
            connection_id: &conn_ids[0],
            account_id: "acct-0",
            scope_id: &alice_scope,
            actor_user_id: &alice.user,
            actor_approval_id: Some(&alice.approval),
            expected_origin: Some("https://api.example.test"),
            required_scope: Some("issues.read"),
        })
        .await
    {
        CredentialOutcome::Ready(c) => assert_eq!(c.bearer_token(), Some("CANARY-RECOVERED-K3")),
        other => panic!("expected recovery under k3, got {other:?}"),
    }
}

// ============================================================================================
// 3. Single-flight refresh, disconnect race fencing, scope widening, 401/503, and expiry
// ============================================================================================

struct BarrierRefresher {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    calls: Arc<AtomicUsize>,
}

impl RefreshClient for BarrierRefresher {
    fn refresh<'a>(
        &'a self,
        _request: RefreshRequest<'a>,
        _deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = RefreshOutcome> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            RefreshOutcome::Refreshed(RefreshedCredential {
                access_token: SecretText::new("CANARY-RACING-TOKEN").unwrap(),
                refresh_token: Some(SecretText::new("CANARY-RACING-REFRESH").unwrap()),
                granted_scopes: Some(vec!["issues.read".into()]),
                expires_in_secs: Some(3600),
            })
        })
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and TEST_GATEWAY_HOST"]
async fn vault_single_flight_refresh_disconnect_race_scope_widening_and_transient_faults() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_scope = personal_of(&db, &alice).await;
    let mut api_conn = connect(&db.0, API).await;
    let ring = Arc::new(VaultKeyRing::new("k1".into(), vec![("k1".into(), [0x44u8; 32])]).unwrap());
    let worker_pool = make_pool(&db, WORKER).await;

    // (a) P1 #1: Provider-bound VaultRefreshRegistry routing an MCP origin to a SEPARATE trusted
    // OAuth AS origin over synthetic rcgen TLS: 8 concurrent callers -> 1 HTTP call!
    let mode = Arc::new(Mutex::new("ok"));
    let mode_for_srv = mode.clone();
    let oauth_as_srv = SyntheticTlsServer::start(move |_head, body| {
        assert!(body.contains("grant_type=refresh_token"), "{body}");
        let m = *mode_for_srv.lock().unwrap();
        match m {
            "ok" => http_json(
                200,
                &json!({
                    "access_token": "CANARY-REFRESHED-ACCESS-1",
                    "refresh_token": "CANARY-REFRESHED-NEXT-1",
                    "scope": "issues.read",
                    "expires_in": 3600
                }),
            ),
            // P1 #4: Widen within allowed_scopes (`issues.write` is allowed on the connection,
            // NOT in prior `granted_scopes = ["issues.read"]`)!
            "widen_within_allowed" => http_json(
                200,
                &json!({
                    "access_token": "CANARY-WIDENED-WITHIN-ALLOWED",
                    "scope": "issues.read issues.write",
                    "expires_in": 3600
                }),
            ),
            "400_proxy" => b"HTTP/1.1 400 Bad Request\r\ncontent-type: text/plain\r\ncontent-length: 22\r\nconnection: close\r\n\r\nBad Request from proxy".to_vec(),
            "400_oauth" => http_json(
                400,
                &json!({"error": "invalid_grant", "error_description": "revoked"}),
            ),
            "401" => http_json(
                401,
                &json!({"error": "invalid_grant", "detail": "CANARY-UPSTREAM-BODY"}),
            ),
            "503" => http_json(503, &json!({"error": "temporarily_unavailable"})),
            _ => unreachable!(),
        }
    })
    .await;

    // Distinct MCP resource server origin (different port/host from oauth_as_srv.origin()!).
    let mcp_origin = "https://mcp-resource.example.test";
    assert_ne!(mcp_origin, oauth_as_srv.origin());
    let mut refresh_registry = VaultRefreshRegistry::new();
    refresh_registry
        .register(oauth_as_srv.refresh_client("github", &[mcp_origin]))
        .unwrap();
    let refresh_registry = Arc::new(refresh_registry);

    let conn_id = vault::create_connection(
        &mut api_conn,
        &ctx(&alice, "sf-create"),
        &CreateConnectionInput {
            scope_id: &alice_scope,
            provider_kind: "github",
            account_id: "acct-sf",
            origin: mcp_origin,
            allowed_scopes: &["issues.read".into(), "issues.write".into()],
        },
    )
    .await
    .unwrap()
    .target_id()
    .to_owned();
    vault::authorize_connection(
        &mut api_conn,
        &ctx(&alice, "sf-auth"),
        &ring,
        &conn_id,
        &AuthorizeConnectionInput {
            access_token: "CANARY-EXPIRING-ACCESS",
            refresh_token: Some("CANARY-INITIAL-REFRESH"),
            granted_scopes: &["issues.read".into()],
            expires_at: Some("2020-01-01T00:00:00.000000Z"),
        },
    )
    .await
    .unwrap();

    let provider = Arc::new(VaultCredentialProvider::new(
        worker_pool.clone(),
        ring.clone(),
        Some(refresh_registry.clone()),
        VaultConfig {
            refresh_skew: Duration::from_secs(60),
            refresh_lease: Duration::from_secs(10),
            waiter_poll: Duration::from_millis(20),
            max_wait: Duration::from_secs(10),
        },
    ));

    let n_callers = 8;
    let barrier = Arc::new(Barrier::new(n_callers));
    let mut tasks = Vec::new();
    for _ in 0..n_callers {
        let p = provider.clone();
        let b = barrier.clone();
        let cid = conn_id.clone();
        let sc = alice_scope.clone();
        let uid = alice.user.clone();
        let aid = alice.approval.clone();
        tasks.push(tokio::spawn(async move {
            b.wait().await;
            p.resolve(CredentialRequest {
                connection_id: &cid,
                account_id: "acct-sf",
                scope_id: &sc,
                actor_user_id: &uid,
                actor_approval_id: Some(&aid),
                expected_origin: Some(mcp_origin),
                required_scope: Some("issues.read"),
            })
            .await
        }));
    }
    for task in tasks {
        match task.await.unwrap() {
            CredentialOutcome::Ready(cred) => {
                assert_eq!(cred.bearer_token(), Some("CANARY-REFRESHED-ACCESS-1"));
            }
            other => panic!("expected refreshed credential, got {other:?}"),
        }
    }
    assert_eq!(
        oauth_as_srv.requests.load(Ordering::SeqCst),
        1,
        "single-flight refresh must issue exactly ONE upstream HTTPS request"
    );
    let refreshed_audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.authorization_audit
          WHERE action = 'connection.refreshed' AND target_id = $1",
    )
    .bind(&conn_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(refreshed_audit, 1);

    // P1 #1: Mismatched provider_kind (`gitlab`) or unconfigured origin returns Transient with
    // ZERO HTTP calls to oauth_as_srv and preserves stored credentials!
    let reqs_before_mismatch = oauth_as_srv.requests.load(Ordering::SeqCst);
    for (idx, (prov_kind, orig)) in [
        ("gitlab", mcp_origin),
        ("github", "https://other-mcp.example.test"),
    ]
    .into_iter()
    .enumerate()
    {
        let mismatch_id = vault::create_connection(
            &mut api_conn,
            &ctx(&alice, &format!("mis-c-{idx}")),
            &CreateConnectionInput {
                scope_id: &alice_scope,
                provider_kind: prov_kind,
                account_id: &format!("acct-mis-{idx}"),
                origin: orig,
                allowed_scopes: &["issues.read".into()],
            },
        )
        .await
        .unwrap()
        .target_id()
        .to_owned();
        vault::authorize_connection(
            &mut api_conn,
            &ctx(&alice, &format!("mis-a-{idx}")),
            &ring,
            &mismatch_id,
            &AuthorizeConnectionInput {
                access_token: "CANARY-MIS-ACCESS",
                refresh_token: Some("CANARY-MIS-REFRESH"),
                granted_scopes: &["issues.read".into()],
                expires_at: Some("2020-01-01T00:00:00.000000Z"),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            provider
                .resolve(CredentialRequest {
                    connection_id: &mismatch_id,
                    account_id: &format!("acct-mis-{idx}"),
                    scope_id: &alice_scope,
                    actor_user_id: &alice.user,
                    actor_approval_id: Some(&alice.approval),
                    expected_origin: Some(orig),
                    required_scope: Some("issues.read"),
                })
                .await,
            CredentialOutcome::Transient
        ));
        let (st, has_ref): (String, bool) = sqlx::query_as(
            "SELECT state, has_refresh FROM openmettle.external_connections WHERE id = $1::uuid",
        )
        .bind(&mismatch_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((st.as_str(), has_ref), ("authorized", true));
    }
    assert_eq!(
        oauth_as_srv.requests.load(Ordering::SeqCst),
        reqs_before_mismatch,
        "unmatched provider/origin must send zero requests to oauth_as_srv"
    );

    // (b) P2 #8: Transient 503, non-OAuth 400, and unconfigured refresher (`None`) all return
    // `CredentialOutcome::Transient` and preserve `state = 'authorized'` & `refresh_ciphertext`!
    sqlx::query("UPDATE openmettle.external_connections SET expires_at = now() - interval '10 seconds' WHERE id = $1::uuid")
        .bind(&conn_id)
        .execute(&mut owner)
        .await
        .unwrap();
    for transient_mode in ["503", "400_proxy"] {
        *mode.lock().unwrap() = transient_mode;
        assert!(
            matches!(
                provider
                    .resolve(CredentialRequest {
                        connection_id: &conn_id,
                        account_id: "acct-sf",
                        scope_id: &alice_scope,
                        actor_user_id: &alice.user,
                        actor_approval_id: Some(&alice.approval),
                        expected_origin: Some(mcp_origin),
                        required_scope: Some("issues.read"),
                    })
                    .await,
                CredentialOutcome::Transient
            ),
            "expected Transient for {transient_mode}"
        );
        let (state, has_refresh, claim_null): (String, bool, bool) = sqlx::query_as(
            "SELECT state, has_refresh, refresh_claim_token IS NULL
               FROM openmettle.external_connections WHERE id = $1::uuid",
        )
        .bind(&conn_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            (state.as_str(), has_refresh, claim_null),
            ("authorized", true, true),
            "{transient_mode} must preserve valid credentials"
        );
    }
    let no_refresher_provider = VaultCredentialProvider::new(
        worker_pool.clone(),
        ring.clone(),
        None,
        VaultConfig::default(),
    );
    assert!(matches!(
        no_refresher_provider
            .resolve(CredentialRequest {
                connection_id: &conn_id,
                account_id: "acct-sf",
                scope_id: &alice_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some(mcp_origin),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Transient
    ));
    let (st_no_ref, hr_no_ref): (String, bool) = sqlx::query_as(
        "SELECT state, has_refresh FROM openmettle.external_connections WHERE id = $1::uuid",
    )
    .bind(&conn_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!((st_no_ref.as_str(), hr_no_ref), ("authorized", true));

    // P1 #2: Post-FOR UPDATE authority recheck when Bob's share is revoked while refresh waits
    // on the connection row lock -> 0 HTTP requests sent to oauth_as_srv!
    vault::share_connection(
        &mut api_conn,
        &ctx(&alice, "sf-share-bob"),
        &conn_id,
        &Grantee::User(bob.user.clone()),
    )
    .await
    .unwrap();
    let reqs_before_lock_race = oauth_as_srv.requests.load(Ordering::SeqCst);
    *mode.lock().unwrap() = "ok";
    {
        let mut blocker = connect(&db.0, OWNER).await;
        let mut lock_tx = blocker.begin().await.unwrap();
        sqlx::query("SELECT 1 FROM openmettle.external_connections WHERE id = $1::uuid FOR UPDATE")
            .bind(&conn_id)
            .fetch_one(&mut *lock_tx)
            .await
            .unwrap();
        let p_bob = provider.clone();
        let cid_bob = conn_id.clone();
        let sc_bob = alice_scope.clone();
        let uid_bob = bob.user.clone();
        let aid_bob = bob.approval.clone();
        let bob_task = tokio::spawn(async move {
            p_bob
                .resolve(CredentialRequest {
                    connection_id: &cid_bob,
                    account_id: "acct-sf",
                    scope_id: &sc_bob,
                    actor_user_id: &uid_bob,
                    actor_approval_id: Some(&aid_bob),
                    expected_origin: Some(mcp_origin),
                    required_scope: Some("issues.read"),
                })
                .await
        });
        // Wait briefly so bob_task passes the REPEATABLE READ snapshot and blocks on Phase 1 FOR UPDATE.
        tokio::time::sleep(Duration::from_millis(120)).await;
        // Revoke Bob's share inside the same transaction holding the row lock and commit.
        sqlx::query(
            "UPDATE openmettle.external_connection_shares
                SET active = false, revision = revision + 1, updated_at = clock_timestamp()
              WHERE connection_id = $1::uuid AND grantee_user_id = $2::uuid AND active",
        )
        .bind(&conn_id)
        .bind(&bob.user)
        .execute(&mut *lock_tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.external_connections
                SET share_revision = share_revision + 1,
                    revocation_generation = revocation_generation + 1
              WHERE id = $1::uuid",
        )
        .bind(&conn_id)
        .execute(&mut *lock_tx)
        .await
        .unwrap();
        lock_tx.commit().await.unwrap();
        assert!(matches!(
            bob_task.await.unwrap(),
            CredentialOutcome::Unavailable
        ));
    }
    assert_eq!(
        oauth_as_srv.requests.load(Ordering::SeqCst),
        reqs_before_lock_race,
        "revoked caller blocked on FOR UPDATE must never dispatch an upstream refresh"
    );

    // (c) P1 #4: Direct worker SQL UPDATE attempting to widen granted_scopes within allowed_scopes
    // fails with SQLSTATE 23514, AND upstream refresh widening within allowed_scopes transitions
    // the connection to `reauth_required` & wipes secrets!
    {
        let mut worker_conn = connect(&db.0, WORKER).await;
        expect_state(
            &mut worker_conn,
            &format!(
                "UPDATE openmettle.external_connections
                    SET granted_scopes = ARRAY['issues.read', 'issues.write']
                  WHERE id = '{conn_id}'::uuid"
            ),
            "23514",
        )
        .await;
    }
    *mode.lock().unwrap() = "widen_within_allowed";
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &conn_id,
                account_id: "acct-sf",
                scope_id: &alice_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some(mcp_origin),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));
    let (state, access_null, refresh_null): (String, bool, bool) = sqlx::query_as(
        "SELECT state, access_ciphertext IS NULL, refresh_ciphertext IS NULL
           FROM openmettle.external_connections WHERE id = $1::uuid",
    )
    .bind(&conn_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        (state.as_str(), access_null, refresh_null),
        ("reauth_required", true, true)
    );

    // (d) Re-authorize -> permanent OAuth 400 (`invalid_grant`) AND 401 wipe to `reauth_required`!
    for (idx, refused_mode) in ["400_oauth", "401"].into_iter().enumerate() {
        vault::authorize_connection(
            &mut api_conn,
            &ctx(&alice, &format!("reauth-{idx}")),
            &ring,
            &conn_id,
            &AuthorizeConnectionInput {
                access_token: "CANARY-REAUTHED",
                refresh_token: Some("CANARY-REAUTHED-REF"),
                granted_scopes: &["issues.read".into()],
                expires_at: Some("2020-01-01T00:00:00.000000Z"),
            },
        )
        .await
        .unwrap();
        *mode.lock().unwrap() = refused_mode;
        assert!(matches!(
            provider
                .resolve(CredentialRequest {
                    connection_id: &conn_id,
                    account_id: "acct-sf",
                    scope_id: &alice_scope,
                    actor_user_id: &alice.user,
                    actor_approval_id: Some(&alice.approval),
                    expected_origin: Some(mcp_origin),
                    required_scope: Some("issues.read"),
                })
                .await,
            CredentialOutcome::Unavailable
        ));
        let st_after: String = sqlx::query_scalar(
            "SELECT state FROM openmettle.external_connections WHERE id = $1::uuid",
        )
        .bind(&conn_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(st_after, "reauth_required", "{refused_mode}");
    }

    // (e) Concurrent disconnect wins over an in-flight refresh!
    vault::authorize_connection(
        &mut api_conn,
        &ctx(&alice, "race-auth"),
        &ring,
        &conn_id,
        &AuthorizeConnectionInput {
            access_token: "CANARY-RACE-OLD",
            refresh_token: Some("CANARY-RACE-REF"),
            granted_scopes: &["issues.read".into()],
            expires_at: Some("2020-01-01T00:00:00.000000Z"),
        },
    )
    .await
    .unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let racing_provider = Arc::new(VaultCredentialProvider::new(
        worker_pool.clone(),
        ring.clone(),
        Some(Arc::new(BarrierRefresher {
            entered: entered.clone(),
            release: release.clone(),
            calls: calls.clone(),
        })),
        VaultConfig::default(),
    ));
    let cid_clone = conn_id.clone();
    let sc_clone = alice_scope.clone();
    let uid_clone = alice.user.clone();
    let aid_clone = alice.approval.clone();
    let refresh_task = tokio::spawn(async move {
        racing_provider
            .resolve(CredentialRequest {
                connection_id: &cid_clone,
                account_id: "acct-sf",
                scope_id: &sc_clone,
                actor_user_id: &uid_clone,
                actor_approval_id: Some(&aid_clone),
                expected_origin: Some(mcp_origin),
                required_scope: Some("issues.read"),
            })
            .await
    });
    entered.notified().await;
    vault::disconnect_connection(&mut api_conn, &ctx(&alice, "race-disconnect"), &conn_id)
        .await
        .unwrap();
    release.notify_one();
    assert!(matches!(
        refresh_task.await.unwrap(),
        CredentialOutcome::Unavailable
    ));
    let (disc_state, a_null, r_null, k_null): (String, bool, bool, bool) = sqlx::query_as(
        "SELECT state, access_ciphertext IS NULL, refresh_ciphertext IS NULL, encryption_key_id IS NULL
           FROM openmettle.external_connections WHERE id = $1::uuid",
    )
    .bind(&conn_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        (disc_state.as_str(), a_null, r_null, k_null),
        ("disconnected", true, true, true)
    );

    // (f) Expired token with no refresh secret transitions cleanly to reauth_required.
    let no_ref_id = vault::create_connection(
        &mut api_conn,
        &ctx(&alice, "noref-c"),
        &CreateConnectionInput {
            scope_id: &alice_scope,
            provider_kind: "github",
            account_id: "acct-noref",
            origin: "https://api.example.test",
            allowed_scopes: &["issues.read".into()],
        },
    )
    .await
    .unwrap()
    .target_id()
    .to_owned();
    vault::authorize_connection(
        &mut api_conn,
        &ctx(&alice, "noref-a"),
        &ring,
        &no_ref_id,
        &AuthorizeConnectionInput {
            access_token: "CANARY-NOREF-EXPIRED",
            refresh_token: None,
            granted_scopes: &["issues.read".into()],
            expires_at: Some("2020-01-01T00:00:00.000000Z"),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        provider
            .resolve(CredentialRequest {
                connection_id: &no_ref_id,
                account_id: "acct-noref",
                scope_id: &alice_scope,
                actor_user_id: &alice.user,
                actor_approval_id: Some(&alice.approval),
                expected_origin: Some("https://api.example.test"),
                required_scope: Some("issues.read"),
            })
            .await,
        CredentialOutcome::Unavailable
    ));
    let noref_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.external_connections WHERE id = $1::uuid")
            .bind(&no_ref_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(noref_state, "reauth_required");
}

// ============================================================================================
// 4. End-to-end ExternalMcpAdapter injection + destination/scope checks + role boundaries
// ============================================================================================

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and TEST_GATEWAY_HOST"]
async fn vault_external_mcp_adapter_end_to_end_and_role_boundaries() {
    let db = TestDb::migrated().await;
    super::run_admission::seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_scope = personal_of(&db, &alice).await;
    let mut api_conn = connect(&db.0, API).await;

    // Activate two-phase effect intents for ExternalMcpAdapter.
    let act = admin_cli(&db.url(OWNER), &["runtime", "activate-two-phase-intents"]);
    assert!(act.status.success(), "{}", stderr(&act));

    // Synthetic rcgen TLS MCP server returning tools/list + tools/call (including reflected-bearer
    // inline, spilled >20 KiB, and poisoned-handle scenarios plus read-only reconcile lookup).
    let mcp_mode = Arc::new(Mutex::new("ok"));
    let mcp_mode_srv = mcp_mode.clone();
    let mcp_srv = SyntheticTlsServer::start(move |head, body| {
        let req: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let id = req["id"].as_str().unwrap_or("1");
        let method = req["method"].as_str().unwrap_or("");
        let bearer = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("authorization")
                    .then(|| v.trim().strip_prefix("Bearer ").map(str::to_owned))?
            })
            .unwrap_or_default();
        if method == "tools/list" {
            let repo_schema = json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["repo"],
                "properties": {
                    "repo": {"type": "string", "minLength": 1, "maxLength": 64}
                }
            });
            http_json(
                200,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [
                            {"name": "list_issues", "inputSchema": repo_schema},
                            {"name": "echo_bearer", "inputSchema": repo_schema},
                            {"name": "create_issue", "inputSchema": repo_schema}
                        ]
                    }
                }),
            )
        } else {
            let tool_name = req["params"]["name"].as_str().unwrap_or("");
            if tool_name == "lookup_issue" {
                return http_json(
                    200,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{"type": "text", "text": "{\"status\":\"succeeded\"}"}],
                            "structuredContent": {"status": "succeeded"}
                        }
                    }),
                );
            }
            if tool_name == "echo_bearer" {
                let mode = *mcp_mode_srv.lock().unwrap();
                return match mode {
                    "echo_inline" => http_json(
                        200,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{"type": "text", "text": format!("reflected={bearer}")}],
                                "structuredContent": {"echo": bearer}
                            }
                        }),
                    ),
                    "echo_spill" => {
                        let big = format!("prefix-{bearer}-{}", "z".repeat(20 * 1024));
                        http_json(
                            200,
                            &json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [{"type": "text", "text": big}]
                                }
                            }),
                        )
                    }
                    "echo_handle" => http_json(
                        200,
                        &json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{"type": "text", "text": "ok"}],
                                "structuredContent": {"op_handle": format!("h-{bearer}")}
                            }
                        }),
                    ),
                    _ => unreachable!(),
                };
            }
            http_json(
                200,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{"type": "text", "text": "ok-from-mcp"}]
                    }
                }),
            )
        }
    })
    .await;

    let ring = Arc::new(VaultKeyRing::new("k1".into(), vec![("k1".into(), [0x77u8; 32])]).unwrap());
    let conn_id = vault::create_connection(
        &mut api_conn,
        &ctx(&alice, "mcp-c1"),
        &CreateConnectionInput {
            scope_id: &alice_scope,
            provider_kind: "github",
            account_id: "acct-mcp",
            origin: &mcp_srv.origin(),
            allowed_scopes: &[
                "issues.read".into(),
                "issues.write".into(),
                "status.read".into(),
            ],
        },
    )
    .await
    .unwrap()
    .target_id()
    .to_owned();
    // P2 #15: Exercise exact 4,096-byte boundary access token end-to-end over MCP tools/list & tools/call!
    let mcp_access = format!("CANARY-MCP-4K-{}", "t".repeat(4096 - 14));
    assert_eq!(mcp_access.len(), 4096);
    let mcp_refresh = "CANARY-MCP-REFRESH-NEVER-SENT";
    vault::authorize_connection(
        &mut api_conn,
        &ctx(&alice, "mcp-a1"),
        &ring,
        &conn_id,
        &AuthorizeConnectionInput {
            access_token: &mcp_access,
            refresh_token: Some(mcp_refresh),
            granted_scopes: &["issues.read".into()],
            expires_at: None,
        },
    )
    .await
    .unwrap();

    // Seed a claimed ActiveRun for Alice.
    let conv = conversation(&mut api_conn, &alice_scope, "personal", &alice.user)
        .await
        .unwrap();
    let msg = message(&mut api_conn, &alice_scope, &conv, None)
        .await
        .unwrap();
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&alice_scope)
    .bind(&conv)
    .fetch_one(&mut api_conn)
    .await
    .unwrap();
    let sess_token = seeded_session(&db, &alice, 10, None).await;
    let sess_policy =
        openmettle_core::sessions::Policy::new(Duration::from_secs(60), 10, Duration::from_secs(3))
            .unwrap();
    let effect_session = openmettle_core::authz::approvals::EffectSession::validate(
        &mut api_conn,
        &sess_token,
        &sess_policy,
        None,
    )
    .await
    .unwrap();
    let limits = AdmissionLimits {
        live_per_actor: 4,
        live_per_scope: 4,
        queued_in_instance: 16,
        queue_timeout: Duration::from_secs(600),
        round_cap: 10,
    };
    let config_bytes = json!({"execution_mode": "ordinary"}).to_string();
    let mut tx = WriteTransaction::begin(&mut api_conn).await.unwrap();
    let admitted = run_queue::admit_run_with_mode(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &alice_scope,
                actor: &alice.user,
                conversation: &conv,
                branch: &branch,
                message: &msg,
                key: "mcp-run-1",
                format: "openmettle.synthetic-run",
                version: 1,
                input: b"{}",
                config: config_bytes.as_bytes(),
            },
            actor_approval_id: &alice.approval,
            now_ms: effect_session.context().observed_ms(),
            capabilities: &[],
            requested_rounds: Some(5),
            cost_qualified: None,
        },
        &limits,
        &effect_session,
    )
    .await
    .unwrap();
    assert!(
        matches!(admitted, Admission::Admitted { .. }),
        "unexpected admission: {admitted:?}"
    );
    tx.commit().await.unwrap();

    let leases = LeaseSettings {
        lease: Duration::from_secs(30),
        execution_timeout: Duration::from_secs(120),
    };
    let mut worker_conn = connect(&db.0, WORKER).await;
    let claimed = run_queue::claim_next(
        &mut worker_conn,
        &ClaimLimits {
            executing_per_actor: 4,
            executing_per_scope: 4,
        },
        &leases,
    )
    .await
    .unwrap()
    .expect("claimed run");

    let mut reg = ExternalRegistry::new();
    let make_tool = |tool_id: &str, remote_name: &str, action: &str| ExternalToolContract {
        tool_id: tool_id.into(),
        remote_name: remote_name.into(),
        version: "1".into(),
        description: "Synthetic MCP tool".into(),
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["repo"],
            "properties": {
                "repo": {"type": "string", "minLength": 1, "maxLength": 64}
            }
        }),
        schema_digest: [0; 32],
        connection_id: conn_id.clone(),
        account_id: "acct-mcp".into(),
        action: action.into(),
        resource_field: Some("repo".into()),
        fixed_resource: "default".into(),
        class: EffectClass::Read,
        capability: "tool.github".into(),
        gate: CapabilityGate::OnByDefault,
        tool_policy: "mcp.v1".into(),
        destination_policy: "synth.v1".into(),
        endpoint_id: "gh-mcp".into(),
        endpoint_version: "1".into(),
        idempotency: None,
        authoritative_lookup: false,
        semantic_errors_are_side_effect_free: true,
        handle_field: None,
        reconcile: None,
        call_timeout: Duration::from_secs(10),
    };
    reg.register(make_tool("gh.list_issues", "list_issues", "issues.read"))
        .unwrap();
    let mut write_tool = make_tool("gh.write_issue", "create_issue", "issues.write");
    write_tool.class = EffectClass::EligibleWrite;
    write_tool.authoritative_lookup = true;
    write_tool.reconcile = Some(ReconcileSpec {
        lookup_tool: "lookup_issue".into(),
        lookup_scope: "status.read".into(),
        handle_argument: None,
        deterministic_key_argument: Some("key".into()),
        status_field: "status".into(),
    });
    reg.register(write_tool).unwrap();
    let mut echo_tool = make_tool("gh.echo", "echo_bearer", "issues.read");
    echo_tool.handle_field = Some("op_handle".into());
    reg.register(echo_tool).unwrap();
    let reg = Arc::new(reg);

    // Prepare real artifact store and storage quota limits for P1 #3 spilled-output redaction.
    let art_dir = auth_config_support::Dir::new();
    let art_root = PathBuf::from(art_dir.path("artifacts"));
    fs::create_dir_all(&art_root).unwrap();
    let art_store = artifact_fs::Store::open(&art_root).unwrap();
    let api_pool = make_pool(&db, API).await;
    art_store.initialize_api(&api_pool).await.unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_instance
            SET personal_limit_bytes = 4000000, instance_budget_bytes = 4000000",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let worker_pool = make_pool(&db, WORKER).await;
    let mut transports = BTreeMap::new();
    transports.insert(conn_id.clone(), mcp_srv.mcp_transport());
    let adapter = Arc::new(
        ExternalMcpAdapter::new(
            worker_pool.clone(),
            leases,
            reg.clone(),
            transports.clone(),
            Arc::new(VaultCredentialProvider::new(
                worker_pool.clone(),
                ring.clone(),
                None,
                VaultConfig::default(),
            )),
            Arc::new(VaultDestinationAuthorizer::new()),
        )
        .with_artifacts(art_store),
    );

    let (_stop_tx, stop_rx) = watch::channel(None::<Stop>);
    let step = StepContext {
        stop: stop_rx,
        deadline: Instant::now() + Duration::from_secs(20),
        tasks: StepTasks::default().handle(),
    };
    let active = ActiveRun {
        claim: claimed,
        state: leases::ExecState::Running,
        execution_deadline: step.deadline,
    };

    // P2 #12: `filter_turn_tools` caches by `(connection_id, account_id, action)`, so mixed
    // granted (`issues.read`) and ungranted (`issues.write`) tools keep ONLY `gh.list_issues`
    // regardless of declaration order!
    let d_read = reg.get("gh.list_issues", "1").unwrap().declared_tool();
    let d_write = reg.get("gh.write_issue", "1").unwrap().declared_tool();
    for (order, list) in [
        ("read_first", vec![d_read.clone(), d_write.clone()]),
        ("write_first", vec![d_write, d_read]),
    ] {
        let filtered = adapter
            .filter_turn_tools(&active, list, &step)
            .await
            .ok()
            .expect("filter_turn_tools succeeded");
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["gh.list_issues"], "order={order}");
    }

    // Allowed action (`issues.read`) succeeds and injects ONLY the 4,096-byte access bearer token.
    let res = adapter
        .call(
            &active,
            step.clone(),
            ExternalCall {
                key: "call-1",
                tool: "gh.list_issues",
                version: "1",
                raw_args: br#"{"repo":"openmettle-core"}"#,
                approval: None,
            },
        )
        .await;
    match res {
        StepResult::ToolOutput(env) => assert!(env.contains("ok-from-mcp"), "{env}"),
        _ => panic!("expected ToolOutput success"),
    }
    let captured = mcp_srv.captured.lock().unwrap().clone();
    assert!(!captured.is_empty());
    for (head, body) in &captured {
        assert!(
            head.contains(&format!("authorization: Bearer {mcp_access}"))
                || head.contains(&format!("Authorization: Bearer {mcp_access}")),
            "missing expected 4096-byte bearer token in request head"
        );
        assert!(!head.contains(mcp_refresh) && !body.contains(mcp_refresh));
    }

    // P1 #3: Reflected bearer credential redaction (inline, >20 KiB spilled artifact, poisoned handle).
    *mcp_mode.lock().unwrap() = "echo_inline";
    match adapter
        .call(
            &active,
            step.clone(),
            ExternalCall {
                key: "call-echo-inline",
                tool: "gh.echo",
                version: "1",
                raw_args: br#"{"repo":"openmettle-core"}"#,
                approval: None,
            },
        )
        .await
    {
        StepResult::ToolOutput(env) => {
            assert!(env.contains("[REDACTED_CREDENTIAL]"), "{env}");
            assert!(
                !env.contains(&mcp_access),
                "inline observation leaked bearer"
            );
        }
        _ => panic!("expected redacted inline ToolOutput"),
    }
    *mcp_mode.lock().unwrap() = "echo_spill";
    match adapter
        .call(
            &active,
            step.clone(),
            ExternalCall {
                key: "call-echo-spill",
                tool: "gh.echo",
                version: "1",
                raw_args: br#"{"repo":"openmettle-core"}"#,
                approval: None,
            },
        )
        .await
    {
        StepResult::ToolOutput(env) => {
            let env_val: Value = serde_json::from_str(&env).unwrap();
            assert_eq!(
                env_val["storage"], "spilled",
                "expected spilled artifact: {env}"
            );
            assert!(env_val["provenance"]["artifact_id"].is_string(), "{env}");
            assert!(!env.contains(&mcp_access), "spill envelope leaked bearer");
        }
        _ => panic!("expected redacted spilled ToolOutput"),
    }
    // Check EVERY file on disk under art_root/revisions contains zero bytes of mcp_access and has marker!
    let mut found_redacted_spill = false;
    for entry in fs::read_dir(art_root.join("revisions")).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains(&mcp_access),
            "spilled artifact leaked bearer"
        );
        if text.contains("[REDACTED_CREDENTIAL]") {
            found_redacted_spill = true;
        }
    }
    assert!(
        found_redacted_spill,
        "expected redacted spilled artifact on disk"
    );

    // Poisoned handle_field containing bearer secret -> terminal_refusal & zero leaked bytes!
    *mcp_mode.lock().unwrap() = "echo_handle";
    match adapter
        .call(
            &active,
            step.clone(),
            ExternalCall {
                key: "call-echo-handle",
                tool: "gh.echo",
                version: "1",
                raw_args: br#"{"repo":"openmettle-core"}"#,
                approval: None,
            },
        )
        .await
    {
        StepResult::ToolOutput(env) => {
            assert!(env.contains("terminal_refusal"), "{env}");
            assert!(!env.contains(&mcp_access), "refusal leaked bearer");
        }
        _ => panic!("expected terminal_refusal on poisoned handle"),
    }

    // Ungranted action (`issues.write` is allowed on connection but NOT in granted_scopes) is refused with 0 HTTP calls!
    let reqs_before = mcp_srv.requests.load(Ordering::SeqCst);
    let refused_scope = adapter
        .call(
            &active,
            step.clone(),
            ExternalCall {
                key: "call-2",
                tool: "gh.write_issue",
                version: "1",
                raw_args: br#"{"repo":"openmettle-core"}"#,
                approval: None,
            },
        )
        .await;
    match refused_scope {
        StepResult::ToolOutput(env) => assert!(env.contains("terminal_refusal"), "{env}"),
        _ => panic!("expected terminal_refusal for ungranted scope"),
    }
    assert_eq!(mcp_srv.requests.load(Ordering::SeqCst), reqs_before);

    // P2 #9 & P2 #10: `reconcile_operation` on a `max_connections(1)` pool enforces
    // `ReconcileSpec.lookup_scope` (`status.read`, distinct from write `action = issues.write`)
    // without pool exhaustion deadlock!
    {
        // Grant `runs.use_yolo` to Alice and admit + claim a dedicated YOLO run so we create a
        // real two-phase write intent (`record_fenced_intent` -> `start_write_attempt` ->
        // `Settle::Stopped` -> `ExecState::Reconciling`).
        sqlx::query(
            "INSERT INTO openmettle.user_capability_grants AS g
                 (user_id, capability, granted, updated_by_user_id)
             VALUES ($1::uuid, 'runs.use_yolo', true, $1::uuid)
             ON CONFLICT (user_id, capability) DO UPDATE
                SET granted = true, revision = g.revision + 1",
        )
        .bind(&alice.user)
        .execute(&mut owner)
        .await
        .unwrap();
        let yolo_cfg = json!({"execution_mode": "yolo"}).to_string();
        let mut tx_y = WriteTransaction::begin(&mut api_conn).await.unwrap();
        let admitted_y = run_queue::admit_run_with_mode(
            &mut tx_y,
            &RunAdmission {
                input: RunInput {
                    scope: &alice_scope,
                    actor: &alice.user,
                    conversation: &conv,
                    branch: &branch,
                    message: &msg,
                    key: "mcp-yolo-reconcile-run",
                    format: "openmettle.synthetic-run",
                    version: 1,
                    input: b"{}",
                    config: yolo_cfg.as_bytes(),
                },
                actor_approval_id: &alice.approval,
                now_ms: effect_session.context().observed_ms(),
                capabilities: &[],
                requested_rounds: Some(5),
                cost_qualified: None,
            },
            &limits,
            &effect_session,
        )
        .await
        .unwrap();
        assert!(matches!(admitted_y, Admission::Admitted { .. }));
        tx_y.commit().await.unwrap();
        let mut w_conn = connect(&db.0, WORKER).await;
        let rec_claim = run_queue::claim_next(
            &mut w_conn,
            &ClaimLimits {
                executing_per_actor: 4,
                executing_per_scope: 4,
            },
            &leases,
        )
        .await
        .unwrap()
        .expect("claimed yolo reconcile run");

        // Authorize with ONLY `issues.write` (missing `status.read`) first.
        vault::authorize_connection(
            &mut api_conn,
            &ctx(&alice, "mcp-a-write-only"),
            &ring,
            &conn_id,
            &AuthorizeConnectionInput {
                access_token: "CANARY-RECONCILE-BEARER",
                refresh_token: None,
                granted_scopes: &["issues.write".into()],
                expires_at: None,
            },
        )
        .await
        .unwrap();
        let proposal = reg
            .get("gh.write_issue", "1")
            .unwrap()
            .proposal("reconcile-key-1", br#"{"repo":"openmettle-core"}"#)
            .unwrap();
        let IntentResult::Applied(tx1) = record_fenced_intent(
            &mut w_conn,
            &rec_claim.lease(),
            &proposal,
            None,
            reg.as_ref(),
            &leases,
        )
        .await
        .unwrap() else {
            panic!("expected Tx1 for reconcile write");
        };
        assert!(matches!(
            start_write_attempt(
                &mut w_conn,
                &rec_claim.lease(),
                &tx1.operation_id,
                &proposal,
                &leases,
                reg.as_ref(),
            )
            .await
            .unwrap(),
            ReplayEffect::Ready(_)
        ));
        assert_eq!(
            leases::settle(&mut w_conn, &rec_claim.lease(), &leases, Settle::Stopped)
                .await
                .unwrap(),
            leases::Settled::Reconciling { unresolved: 1 }
        );
        let capability: String =
            sqlx::query_scalar("SELECT capability FROM openmettle.operations WHERE id = $1::uuid")
                .bind(&tx1.operation_id)
                .fetch_one(&mut owner)
                .await
                .unwrap();
        let unres = leases::UnresolvedOperation {
            id: tx1.operation_id,
            logical_key: proposal.logical_key.clone(),
            target: proposal.destination().to_owned(),
            capability,
            outcome: "intent".into(),
            revision: 0,
            downstream_handle: None,
            dispatched_attempts: Some(1),
        };
        let rec_active = ActiveRun {
            claim: rec_claim,
            state: leases::ExecState::Reconciling,
            execution_deadline: step.deadline,
        };
        let single_conn_pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect_with(role_options(&db.0, WORKER))
            .await
            .unwrap();
        let single_adapter = ExternalMcpAdapter::new(
            single_conn_pool.clone(),
            leases,
            reg.clone(),
            transports,
            Arc::new(VaultCredentialProvider::new(
                single_conn_pool,
                ring.clone(),
                None,
                VaultConfig::default(),
            )),
            Arc::new(VaultDestinationAuthorizer::new()),
        );
        let reqs_pre_rec = mcp_srv.requests.load(Ordering::SeqCst);
        let denied_rec = single_adapter
            .reconcile_operation(&rec_active, &unres, step.clone())
            .await;
        assert!(
            denied_rec.is_none(),
            "missing lookup_scope must deny reconciliation"
        );
        assert_eq!(mcp_srv.requests.load(Ordering::SeqCst), reqs_pre_rec);

        // Now grant `status.read` alongside `issues.write`: single-connection pool reconciles cleanly!
        vault::authorize_connection(
            &mut api_conn,
            &ctx(&alice, "mcp-a-write-and-status"),
            &ring,
            &conn_id,
            &AuthorizeConnectionInput {
                access_token: "CANARY-RECONCILE-BEARER",
                refresh_token: None,
                granted_scopes: &["issues.write".into(), "status.read".into()],
                expires_at: None,
            },
        )
        .await
        .unwrap();
        let ok_rec = single_adapter
            .reconcile_operation(&rec_active, &unres, step.clone())
            .await
            .expect("reconcile_operation must succeed on max_connections(1) pool when lookup_scope is granted");
        assert_eq!(ok_rec.outcome, "succeeded");
        // Restore issues.read grant for disconnect test below.
        vault::authorize_connection(
            &mut api_conn,
            &ctx(&alice, "mcp-a-restore-read"),
            &ring,
            &conn_id,
            &AuthorizeConnectionInput {
                access_token: &mcp_access,
                refresh_token: Some(mcp_refresh),
                granted_scopes: &["issues.read".into()],
                expires_at: None,
            },
        )
        .await
        .unwrap();
    }

    // Disconnect evicts catalog cache and immediately blocks the next call with 0 HTTP calls!
    let reqs_before_disc = mcp_srv.requests.load(Ordering::SeqCst);
    vault::disconnect_connection(&mut api_conn, &ctx(&alice, "mcp-disc"), &conn_id)
        .await
        .unwrap();
    let refused_disc = adapter
        .call(
            &active,
            step,
            ExternalCall {
                key: "call-3",
                tool: "gh.list_issues",
                version: "1",
                raw_args: br#"{"repo":"openmettle-core"}"#,
                approval: None,
            },
        )
        .await;
    match refused_disc {
        StepResult::ToolOutput(env) => assert!(env.contains("terminal_refusal"), "{env}"),
        _ => panic!("expected terminal_refusal after disconnect"),
    }
    assert_eq!(mcp_srv.requests.load(Ordering::SeqCst), reqs_before_disc);

    // Verify zero plaintext secret substrings in operations or run_events.
    let ops_dump: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(to_jsonb(o)::text, '\n'), '') FROM openmettle.operations o",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let ev_dump: String = sqlx::query_scalar(
        "SELECT coalesce(string_agg(to_jsonb(e)::text, '\n'), '') FROM openmettle.run_events e",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    for needle in [mcp_access.as_str(), mcp_refresh, "CANARY-RECONCILE-BEARER"] {
        assert!(!ops_dump.contains(needle));
        assert!(!ev_dump.contains(needle));
    }

    // Verify PostgreSQL least-privilege role boundaries.
    for sql in [
        "SELECT access_ciphertext FROM openmettle.external_connections",
        "SELECT refresh_ciphertext FROM openmettle.external_connections",
        "SELECT encryption_key_id FROM openmettle.external_connections",
        "SELECT refresh_claim_token FROM openmettle.external_connections",
        "DELETE FROM openmettle.external_connections",
        "DELETE FROM openmettle.external_connection_shares",
    ] {
        expect_state(&mut api_conn, sql, "42501").await;
    }
    for sql in [
        "INSERT INTO openmettle.external_connections (scope_id, scope_kind, owner_user_id, provider_kind, account_id, endpoint_origin, allowed_scopes) VALUES (gen_random_uuid(), 'personal', gen_random_uuid(), 'github', 'a', 'https://a.example.test', ARRAY['r'])",
        "DELETE FROM openmettle.external_connections",
        "SELECT * FROM openmettle.project_settings",
        "SELECT * FROM openmettle.authorization_audit",
    ] {
        expect_state(&mut worker_conn, sql, "42501").await;
    }
    for role in [ISSUANCE, "openmettle_gateway"] {
        let mut c = connect(&db.0, role).await;
        for sql in [
            "SELECT id FROM openmettle.external_connections",
            "SELECT id FROM openmettle.external_connection_shares",
            "SELECT * FROM openmettle.external_connection_scope_lifecycle(gen_random_uuid())",
        ] {
            expect_state(&mut c, sql, "42501").await;
        }
    }
}

// ============================================================================================
// 5. P1 #5: Packaged worker startup wiring (`worker::config::load` + `build_worker_turn_executor`)
// ============================================================================================

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL and TEST_GATEWAY_HOST"]
async fn vault_packaged_worker_startup_wiring_executes_credentialed_mcp_tool() {
    let db = TestDb::migrated().await;
    super::run_admission::seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_scope = personal_of(&db, &alice).await;
    let mut api_conn = connect(&db.0, API).await;

    let act = admin_cli(&db.url(OWNER), &["runtime", "activate-two-phase-intents"]);
    assert!(act.status.success(), "{}", stderr(&act));

    // Synthetic TLS MCP server expecting the vaulted bearer token.
    let mcp_srv = SyntheticTlsServer::start(|_head, body| {
        let req: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let id = req["id"].as_str().unwrap_or("1");
        let method = req["method"].as_str().unwrap_or("");
        if method == "tools/list" {
            http_json(
                200,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [{
                            "name": "list_issues",
                            "inputSchema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["repo"],
                                "properties": {
                                    "repo": {"type": "string", "minLength": 1, "maxLength": 64}
                                }
                            }
                        }]
                    }
                }),
            )
        } else {
            http_json(
                200,
                &json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{"type": "text", "text": "packaged-worker-mcp-ok"}]
                    }
                }),
            )
        }
    })
    .await;

    // Synthetic TLS metered gateway returning a tool call on round 1 and final answer on round 2.
    let gw_round = Arc::new(AtomicUsize::new(0));
    let gw_round_srv = gw_round.clone();
    let gw_seen_mcp_result = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let gw_seen_srv = gw_seen_mcp_result.clone();
    let gw_srv = SyntheticTlsServer::start(move |_head, body| {
        let r = gw_round_srv.fetch_add(1, Ordering::SeqCst);
        if r == 0 {
            http_json(
                200,
                &json!({
                    "id": "chatcmpl-w1",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_pkg_1",
                                "type": "function",
                                "function": {
                                    "name": "gh_list_issues",
                                    "arguments": "{\"repo\":\"openmettle-core\"}"
                                }
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 6}
                }),
            )
        } else {
            if body.contains("packaged-worker-mcp-ok") {
                gw_seen_srv.store(true, Ordering::SeqCst);
            }
            http_json(
                200,
                &json!({
                    "id": "chatcmpl-w2",
                    "object": "chat.completion",
                    "model": "a",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Packaged worker turn completed."
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 6}
                }),
            )
        }
    })
    .await;

    let ring = Arc::new(VaultKeyRing::new("k1".into(), vec![("k1".into(), [0x88u8; 32])]).unwrap());
    let conn_id = vault::create_connection(
        &mut api_conn,
        &ctx(&alice, "pkg-c1"),
        &CreateConnectionInput {
            scope_id: &alice_scope,
            provider_kind: "github",
            account_id: "acct-pkg",
            origin: &mcp_srv.origin(),
            allowed_scopes: &["issues.read".into()],
        },
    )
    .await
    .unwrap()
    .target_id()
    .to_owned();
    let bearer_secret = "CANARY-PACKAGED-WORKER-BEARER";
    vault::authorize_connection(
        &mut api_conn,
        &ctx(&alice, "pkg-a1"),
        &ring,
        &conn_id,
        &AuthorizeConnectionInput {
            access_token: bearer_secret,
            refresh_token: None,
            granted_scopes: &["issues.read".into()],
            expires_at: None,
        },
    )
    .await
    .unwrap();

    // Write a real OPENMETTLE_WORKER_INFERENCE_CONFIG file referencing gw_srv + mcp_srv!
    let dir = auth_config_support::Dir::new();
    let catalog_bytes = include_bytes!("../fixtures/conversation-catalog-v1.json");
    let catalog_val: Value = serde_json::from_slice(catalog_bytes).unwrap();
    let mut inf_doc = auth_config_support::inference_document(
        &dir,
        &catalog_val,
        &gw_srv.ca_pem,
        &format!("{}:{}", gw_srv.host, gw_srv.port),
    );
    let gw_cidr = gw_srv.private_cidr();
    let mcp_cidr = mcp_srv.private_cidr();
    let mcp_ca = dir.write("mcp-ca.pem", &mcp_srv.ca_pem);
    for model_key in ["a", "b"] {
        inf_doc["routes"][model_key]["private_cidrs"] = json!([gw_cidr]);
        inf_doc["routes"][model_key]["functions"] = json!("flat");
    }
    inf_doc["external_mcp"] = json!({
        "connections": {
            &conn_id: {
                "endpoint": mcp_srv.url("/mcp"),
                "trust": { "roots": "bundle", "bundle_path": mcp_ca },
                "private_cidrs": [mcp_cidr],
                "setup_timeout_milliseconds": 5000,
                "idle_read_timeout_milliseconds": 5000,
                "call_timeout_milliseconds": 10000
            }
        },
        "tools": [{
            "tool_id": "gh_list_issues",
            "remote_name": "list_issues",
            "version": "1",
            "description": "List repository issues",
            "input_schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["repo"],
                "properties": {
                    "repo": {"type": "string", "minLength": 1, "maxLength": 64}
                }
            },
            "connection_id": &conn_id,
            "account_id": "acct-pkg",
            "action": "issues.read",
            "resource_field": "repo",
            "fixed_resource": "default",
            "class": "read",
            "capability": "tool.github",
            "gate": "on_by_default",
            "tool_policy": "mcp.v1",
            "destination_policy": "synth.v1",
            "endpoint_id": "gh-mcp",
            "endpoint_version": "1",
            "authoritative_lookup": false,
            "semantic_errors_are_side_effect_free": true,
            "call_timeout_milliseconds": 10000
        }]
    });
    let inf_path = dir.write("worker-inference.json", inf_doc.to_string().as_bytes());
    let loaded = worker_config::load(std::path::Path::new(&inf_path)).unwrap();
    let catalog = loaded.catalog.clone();

    // Admit a real conversation turn run on model "a".
    let conv_outcome =
        branches::create_conversation(&mut api_conn, &ctx(&alice, "pkg-conv"), &alice_scope)
            .await
            .unwrap();
    let conv = match conv_outcome {
        store::WriteOutcome::Applied { target_id }
        | store::WriteOutcome::Replayed { target_id } => target_id,
    };
    let msg_id = "00000000-0000-4000-8000-000000004559";
    let chat = Conversation {
        scope: &alice_scope,
        id: &conv.conversation_id,
    };
    let parts = [Part::Text("list open issues".into())];
    let turn_op = Operation::Append(UserInput {
        id: msg_id,
        parts: &parts,
    });
    let selection: Selection = serde_json::from_value(
        json!({"model": "a", "layer": {"controls": {"output_reserve": 256}}}),
    )
    .unwrap();
    let snapshot = ConfigSnapshot {
        effective: catalog
            .resolve(&Selection::default(), &selection, None, |_, _| true)
            .unwrap(),
        required_capabilities: catalog.model("a").unwrap().required_capabilities.clone(),
        policy_revision: "openmettle.authz/1".into(),
        cost_bound: catalog.model("a").unwrap().cost_bound,
    };
    let turn_intent = TurnIntent {
        source_branch_id: &conv.branch_id,
        expected_head_message_id: None,
        operation: turn_op,
        selection: &selection,
        requested_rounds: Some(3),
    };
    let sess_token = seeded_session(&db, &alice, 10, None).await;
    let sess_policy =
        openmettle_core::sessions::Policy::new(Duration::from_secs(60), 10, Duration::from_secs(3))
            .unwrap();
    let effect_session =
        approvals::EffectSession::validate(&mut api_conn, &sess_token, &sess_policy, None)
            .await
            .unwrap();
    let actor_principal = super::authz_store::principal(&db, &alice).await;
    let mut tx = WriteTransaction::begin(&mut api_conn).await.unwrap();
    branches::prepare_turn(
        &mut tx,
        &ctx(&alice, "pkg-msg"),
        chat,
        &conv.branch_id,
        None,
        turn_op,
    )
    .await
    .unwrap();
    let history = branches::history(
        tx.connection().unwrap(),
        &actor_principal,
        chat,
        &conv.branch_id,
        effect_session.context().observed_ms(),
    )
    .await
    .unwrap()
    .unwrap();
    let pins = Snapshots::encode(&turn_intent, &history, &catalog, &snapshot).unwrap();
    let limits = AdmissionLimits {
        live_per_actor: 4,
        live_per_scope: 4,
        queued_in_instance: 16,
        queue_timeout: Duration::from_secs(600),
        round_cap: 10,
    };
    let admitted = run_queue::admit_run_with_mode(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &alice_scope,
                actor: &alice.user,
                conversation: &conv.conversation_id,
                branch: &conv.branch_id,
                message: msg_id,
                key: "pkg-turn-run-1",
                format: SNAPSHOT_FORMAT,
                version: SNAPSHOT_VERSION,
                input: &pins.input,
                config: &pins.config,
            },
            actor_approval_id: &alice.approval,
            now_ms: effect_session.context().observed_ms(),
            capabilities: &[],
            requested_rounds: Some(3),
            cost_qualified: None,
        },
        &limits,
        &effect_session,
    )
    .await
    .unwrap();
    assert!(matches!(admitted, Admission::Admitted { .. }));
    tx.commit().await.unwrap();

    let leases = LeaseSettings {
        lease: Duration::from_secs(30),
        execution_timeout: Duration::from_secs(120),
    };
    let mut worker_conn = connect(&db.0, WORKER).await;
    let claimed = run_queue::claim_next(
        &mut worker_conn,
        &ClaimLimits {
            executing_per_actor: 4,
            executing_per_scope: 4,
        },
        &leases,
    )
    .await
    .unwrap()
    .expect("claimed packaged-worker run");

    let worker_pool = make_pool(&db, WORKER).await;
    let executor =
        build_worker_turn_executor(worker_pool.clone(), loaded, leases, None, Some(ring));
    let (_stop_tx, stop_rx) = watch::channel(None::<Stop>);
    let step = StepContext {
        stop: stop_rx,
        deadline: Instant::now() + Duration::from_secs(20),
        tasks: StepTasks::default().handle(),
    };
    let active = ActiveRun {
        claim: claimed,
        state: leases::ExecState::Running,
        execution_deadline: step.deadline,
    };
    let result = executor.step(&active, step).await;
    assert!(
        matches!(result, StepResult::Answer(_)),
        "expected TurnExecutor Answer through packaged worker wiring"
    );
    assert!(
        gw_seen_mcp_result.load(Ordering::SeqCst),
        "model round 2 must observe external MCP tool output"
    );
    let mcp_captured = mcp_srv.captured.lock().unwrap().clone();
    assert!(!mcp_captured.is_empty());
    assert!(
        mcp_captured
            .iter()
            .any(|(head, _)| head.contains(&format!("Bearer {bearer_secret}"))),
        "packaged worker must inject vaulted bearer token into outbound MCP requests"
    );

    // Without VAULT_KEYS_CONFIG (`vault_keys = None`), packaged worker wiring stays fail-closed
    // (`GatedCredentialProvider`): filter_turn_tools omits the tool and 0 MCP calls occur!
    let reqs_before_gated = mcp_srv.requests.load(Ordering::SeqCst);
    let conv_2 = match branches::create_conversation(
        &mut api_conn,
        &ctx(&alice, "pkg-conv-2"),
        &alice_scope,
    )
    .await
    .unwrap()
    {
        store::WriteOutcome::Applied { target_id }
        | store::WriteOutcome::Replayed { target_id } => target_id,
    };
    let chat_2 = Conversation {
        scope: &alice_scope,
        id: &conv_2.conversation_id,
    };
    let msg_id_2 = "00000000-0000-4000-8000-000000004560";
    let parts_2 = [Part::Text("second run without vault keys".into())];
    let turn_op_2 = Operation::Append(UserInput {
        id: msg_id_2,
        parts: &parts_2,
    });
    let turn_intent_2 = TurnIntent {
        source_branch_id: &conv_2.branch_id,
        expected_head_message_id: None,
        operation: turn_op_2,
        selection: &selection,
        requested_rounds: Some(2),
    };
    let mut tx2 = WriteTransaction::begin(&mut api_conn).await.unwrap();
    branches::prepare_turn(
        &mut tx2,
        &ctx(&alice, "pkg-msg-2"),
        chat_2,
        &conv_2.branch_id,
        None,
        turn_op_2,
    )
    .await
    .unwrap();
    let history_2 = branches::history(
        tx2.connection().unwrap(),
        &actor_principal,
        chat_2,
        &conv_2.branch_id,
        effect_session.context().observed_ms(),
    )
    .await
    .unwrap()
    .unwrap();
    let pins_2 = Snapshots::encode(&turn_intent_2, &history_2, &catalog, &snapshot).unwrap();
    let admitted_2 = run_queue::admit_run_with_mode(
        &mut tx2,
        &RunAdmission {
            input: RunInput {
                scope: &alice_scope,
                actor: &alice.user,
                conversation: &conv_2.conversation_id,
                branch: &conv_2.branch_id,
                message: msg_id_2,
                key: "pkg-turn-run-2",
                format: SNAPSHOT_FORMAT,
                version: SNAPSHOT_VERSION,
                input: &pins_2.input,
                config: &pins_2.config,
            },
            actor_approval_id: &alice.approval,
            now_ms: effect_session.context().observed_ms(),
            capabilities: &[],
            requested_rounds: Some(2),
            cost_qualified: None,
        },
        &limits,
        &effect_session,
    )
    .await
    .unwrap();
    assert!(matches!(admitted_2, Admission::Admitted { .. }));
    tx2.commit().await.unwrap();
    let claimed_2 = run_queue::claim_next(
        &mut worker_conn,
        &ClaimLimits {
            executing_per_actor: 4,
            executing_per_scope: 4,
        },
        &leases,
    )
    .await
    .unwrap()
    .expect("claimed gated run");
    let loaded_gated = worker_config::load(std::path::Path::new(&inf_path)).unwrap();
    let gated_exec = build_worker_turn_executor(worker_pool, loaded_gated, leases, None, None);
    let (_stop_tx2, stop_rx2) = watch::channel(None::<Stop>);
    let step2 = StepContext {
        stop: stop_rx2,
        deadline: Instant::now() + Duration::from_secs(20),
        tasks: StepTasks::default().handle(),
    };
    let active2 = ActiveRun {
        claim: claimed_2,
        state: leases::ExecState::Running,
        execution_deadline: step2.deadline,
    };
    let gated_result = gated_exec.step(&active2, step2).await;
    assert!(
        matches!(gated_result, StepResult::Answer(_)),
        "gated worker run should settle without invoking unconfigured external MCP tool"
    );
    assert_eq!(
        mcp_srv.requests.load(Ordering::SeqCst),
        reqs_before_gated,
        "worker without VAULT_KEYS_CONFIG must send 0 HTTP requests to MCP server"
    );
    let gw_last_body = gw_srv.captured.lock().unwrap().last().unwrap().1.clone();
    assert!(
        !gw_last_body.contains("gh_list_issues"),
        "gated worker must omit external MCP tool declaration when VAULT_KEYS_CONFIG is absent: {gw_last_body}"
    );
}

// ============================================================================================
// 6. P1 #6: Deletion-journal replay & coverage-gap connection reconciliation across restore
// ============================================================================================

async fn backup_db(db: &TestDb) -> TestDb {
    let copy = TestDb::with_options(false, &format!("TEMPLATE {}", db.0)).await;
    let roles = "openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway";
    for sql in [
        format!("REVOKE ALL ON DATABASE {} FROM PUBLIC", copy.0),
        format!("GRANT CONNECT ON DATABASE {} TO {roles}", copy.0),
    ] {
        SqlxExecutor::execute(&mut copy.admin().await, AssertSqlSafe(sql))
            .await
            .unwrap();
    }
    copy
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn vault_restore_journal_replay_and_coverage_gap_reconciliation() {
    let db = TestDb::migrated().await;
    let (conn_disc, conn_rot, conn_shared, bob_user) = {
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
        let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
        let alice_scope = personal_of(&db, &alice).await;
        let mut api_conn = connect(&db.0, API).await;
        let ring = VaultKeyRing::new("k1".into(), vec![("k1".into(), [0x5au8; 32])]).unwrap();

        let make_auth = |suffix: &str| {
            let scope = alice_scope.clone();
            let acct = format!("acct-rst-{suffix}");
            (scope, acct)
        };
        let mut ids = Vec::new();
        for suffix in ["disc", "rot", "shared"] {
            let (scope, acct) = make_auth(suffix);
            let id = vault::create_connection(
                &mut api_conn,
                &ctx(&alice, &format!("rst-c-{suffix}")),
                &CreateConnectionInput {
                    scope_id: &scope,
                    provider_kind: "github",
                    account_id: &acct,
                    origin: "https://api.example.test",
                    allowed_scopes: &["issues.read".into()],
                },
            )
            .await
            .unwrap()
            .target_id()
            .to_owned();
            vault::authorize_connection(
                &mut api_conn,
                &ctx(&alice, &format!("rst-a-{suffix}")),
                &ring,
                &id,
                &AuthorizeConnectionInput {
                    access_token: &format!("CANARY-PREBACKUP-{suffix}"),
                    refresh_token: Some(&format!("CANARY-PREBACKUP-REF-{suffix}")),
                    granted_scopes: &["issues.read".into()],
                    expires_at: None,
                },
            )
            .await
            .unwrap();
            ids.push(id);
        }
        vault::share_connection(
            &mut api_conn,
            &ctx(&alice, "rst-share-bob"),
            &ids[2],
            &Grantee::User(bob.user.clone()),
        )
        .await
        .unwrap();
        // Drop all connections to `db` before `CREATE DATABASE ... TEMPLATE`.
        drop(api_conn);
        drop(owner);
        (ids[0].clone(), ids[1].clone(), ids[2].clone(), bob.user)
    };

    // Simulate two restored copies of the pre-revocation backup taken at T0.
    let restored_replay = backup_db(&db).await;
    let restored_gap = backup_db(&db).await;

    // On LIVE after backup T0: disconnect conn_disc, supersede conn_rot, revoke Bob's share on conn_shared!
    let export_text = {
        let mut owner = connect(&db.0, OWNER).await;
        let alice_user: String = sqlx::query_scalar(
            "SELECT owner_user_id::text FROM openmettle.external_connections WHERE id = $1::uuid",
        )
        .bind(&conn_disc)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let alice_approval: String = sqlx::query_scalar(
            "SELECT a.id::text FROM openmettle.local_identity_approvals a
               JOIN openmettle.user_identities i ON i.id = a.identity_id
              WHERE i.user_id = $1::uuid LIMIT 1",
        )
        .bind(&alice_user)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let alice_acct = Account {
            user: alice_user,
            approval: alice_approval,
        };
        let mut api_conn = connect(&db.0, API).await;
        let ring = VaultKeyRing::new("k1".into(), vec![("k1".into(), [0x5au8; 32])]).unwrap();

        vault::disconnect_connection(&mut api_conn, &ctx(&alice_acct, "post-disc"), &conn_disc)
            .await
            .unwrap();
        vault::authorize_connection(
            &mut api_conn,
            &ctx(&alice_acct, "post-supersede"),
            &ring,
            &conn_rot,
            &AuthorizeConnectionInput {
                access_token: "CANARY-POSTBACKUP-ROTATED",
                refresh_token: Some("CANARY-POSTBACKUP-ROTATED-REF"),
                granted_scopes: &["issues.read".into()],
                expires_at: None,
            },
        )
        .await
        .unwrap();
        vault::revoke_connection_share(
            &mut api_conn,
            &ctx(&alice_acct, "post-revoke-bob"),
            &conn_shared,
            &Grantee::User(bob_user.clone()),
        )
        .await
        .unwrap();

        let live_pool = make_pool(&db, OWNER).await;
        restore::export(&live_pool).await.unwrap()
    };
    let parsed_export = restore::Export::parse(&export_text).unwrap();
    assert!(parsed_export.connection_origin_us.is_some());
    assert!(export_text.contains("external_connection.disconnected"));
    assert!(export_text.contains("external_connection.credential_superseded"));
    assert!(export_text.contains("external_connection.share_revoked"));

    // (a) Complete journal replay onto `restored_replay`: enforces all 3 post-backup events!
    {
        let pool = make_pool(&restored_replay, OWNER).await;
        restore::lock_gate_with_connection_origin(
            &pool,
            &GateLockRequest {
                origin_us: parsed_export.origin_us,
                lifecycle_origin_us: parsed_export.lifecycle_origin_us,
                lifecycle_baseline_digest: parsed_export.lifecycle_baseline_digest.as_deref(),
                required_seq: parsed_export.seq,
                required_digest: &parsed_export.digest,
                coverage_complete: true,
                replace_restore_run: None,
                new_restore: true,
            },
            parsed_export.connection_origin_us,
        )
        .await
        .unwrap();
        let applied = restore::apply(&pool, &parsed_export).await.unwrap();
        assert!(
            applied >= 3,
            "expected >=3 replayed connection events, got {applied}"
        );
        restore::finish(&pool, None, &parsed_export).await.unwrap();

        let mut owner = connect(&restored_replay.0, OWNER).await;
        assert!(restore::gate_open(&mut owner).await.unwrap());
        let (disc_st, disc_ct_null): (String, bool) = sqlx::query_as(
            "SELECT state, access_ciphertext IS NULL AND refresh_ciphertext IS NULL
               FROM openmettle.external_connections WHERE id = $1::uuid",
        )
        .bind(&conn_disc)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((disc_st.as_str(), disc_ct_null), ("disconnected", true));

        let (rot_st, rot_ct_null): (String, bool) = sqlx::query_as(
            "SELECT state, access_ciphertext IS NULL AND refresh_ciphertext IS NULL
               FROM openmettle.external_connections WHERE id = $1::uuid",
        )
        .bind(&conn_rot)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((rot_st.as_str(), rot_ct_null), ("reauth_required", true));

        let (shared_st, bob_active): (String, bool) = sqlx::query_as(
            "SELECT c.state,
                    EXISTS(SELECT 1 FROM openmettle.external_connection_shares s
                            WHERE s.connection_id = c.id AND s.grantee_user_id = $2::uuid AND s.active)
               FROM openmettle.external_connections c WHERE c.id = $1::uuid",
        )
        .bind(&conn_shared)
        .bind(&bob_user)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((shared_st.as_str(), bob_active), ("authorized", false));
    }

    // (b) Incomplete journal / coverage gap onto `restored_gap`:
    // Direct gate open refuses (`OMR04`) while authorized connections/shares survive;
    // `openmettle-admin restore accept-coverage-gap` wipes ALL authorized connections to
    // `reauth_required` and deactivates ALL active shares so nothing revives across the gap!
    {
        let pool = make_pool(&restored_gap, OWNER).await;
        let pre_export_text = restore::export(&pool).await.unwrap();
        let pre_export = restore::Export::parse(&pre_export_text).unwrap();
        let locked = restore::lock_gate_with_connection_origin(
            &pool,
            &GateLockRequest {
                origin_us: pre_export.origin_us,
                lifecycle_origin_us: pre_export.lifecycle_origin_us,
                lifecycle_baseline_digest: pre_export.lifecycle_baseline_digest.as_deref(),
                required_seq: pre_export.seq,
                required_digest: &pre_export.digest,
                coverage_complete: false,
                replace_restore_run: None,
                new_restore: true,
            },
            pre_export.connection_origin_us,
        )
        .await
        .unwrap();

        // Direct finish without accept-coverage-gap must fail with OMR04!
        restore::apply(&pool, &pre_export).await.unwrap();
        let premature = restore::finish(&pool, None, &pre_export).await;
        assert!(
            matches!(
                premature,
                Err(restore::Error::Database(sqlx::Error::Database(ref d)))
                    if d.code().as_deref() == Some("OMR04")
            ),
            "expected OMR04 without accept-coverage-gap, got {premature:?}"
        );

        let gap_out = admin_cli(
            &restored_gap.url(OWNER),
            &[
                "restore",
                "accept-coverage-gap",
                "--restore-run",
                &locked.restore_run_id,
                "--operator-id",
                "00000000-0000-4000-8000-000000000902",
                "--request-key",
                "vault-gap-1",
                "--reason",
                "synthetic coverage gap test",
            ],
        );
        assert!(gap_out.status.success(), "{}", stderr(&gap_out));

        restore::finish(&pool, None, &pre_export).await.unwrap();

        let mut owner = connect(&restored_gap.0, OWNER).await;
        let (still_auth, still_active_shares, gate_open): (i64, i64, bool) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM openmettle.external_connections WHERE state = 'authorized'),
                    (SELECT count(*) FROM openmettle.external_connection_shares WHERE active),
                    (SELECT open FROM openmettle.restore_reconciliation_gate WHERE id)",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            still_auth, 0,
            "all authorized connections must be wiped to reauth_required"
        );
        assert_eq!(
            still_active_shares, 0,
            "all active shares must be deactivated"
        );
        assert!(gate_open, "gate must open after accept-coverage-gap");
    }
}
