//! ADR 0027 PR4b and ADR 0031 PR2: the authenticated `/v1` routes through the real API binary,
//! mounted with a version-2 settings document, its native profile and an artifacts directory,
//! over PostgreSQL 18 as `openmettle_api`. Sessions are seeded as issuance stores them, for the
//! browser cookie channel (with the configured `Origin`) and the native bearer channel. Every
//! response is decoded by the independent contract consumer. The owner role seeds fixtures and
//! reads results. Every value is synthetic.
use super::authz_runs::{
    artifact, chat, framed_digest, personal_of, project_run, seeded_session, state_of,
};
use super::authz_store::{
    Account, FUTURE, PROVIDER, account, ctx, make_admin, present_membership_at, providers,
};
use super::*;
use openmettle_core::{
    artifact_fs::{self, Store},
    authz::store,
    runs::WriteTransaction,
    storage,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::{fs, net::Shutdown, path::Path};

/// The browser origin and native registration of `document_v2_native`.
const ORIGIN: &str = "https://app.example.test";

/// The native session audience of that registration (ADR 0023), encoded independently of
/// `src/browser_auth/native.rs`.
fn audience() -> Vec<u8> {
    framed_digest(
        b"openmettle/native-session-audience/1\0",
        &[
            ORIGIN.as_bytes(),
            b"openmettle-desktop",
            b"https://app.example.test/native/complete",
            b"0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
            b"https://issuer.example.test/realm",
        ],
    )
}

pub(super) async fn browser(db: &TestDb, account: &Account, n: u8) -> String {
    seeded_session(db, account, n, None).await
}

async fn native(db: &TestDb, account: &Account, n: u8) -> String {
    seeded_session(db, account, n, Some(&audience())).await
}

/// A session credential on its channel.
#[derive(Clone, Copy)]
pub(super) enum As<'a> {
    Browser(&'a str),
    Native(&'a str),
}

/// The API binary with `AUTH_CONFIG` and `ARTIFACTS_DIR`, connected as `openmettle_api` and,
/// for session issuance, as `openmettle_issuance` (ADR 0030). Killed on drop.
pub(super) struct Api {
    process: Process,
    dir: auth_config_support::Dir,
    bind: String,
}

impl Api {
    fn start(db: &TestDb) -> Self {
        let dir = auth_config_support::Dir::new();
        fs::create_dir(dir.path("artifacts")).unwrap();
        Self::start_in(db, dir)
    }

    /// Starts the binary over `dir`, whose `artifacts` directory an earlier process may have
    /// left files in.
    fn start_in(db: &TestDb, dir: auth_config_support::Dir) -> Self {
        let document = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
        Self::configured(db, dir, document, 4)
    }

    pub(super) fn configured(
        db: &TestDb,
        dir: auth_config_support::Dir,
        document: Value,
        connections: u32,
    ) -> Self {
        let auth = dir.write("auth.json", document.to_string().as_bytes());
        let bind = address();
        let mut cmd = binary("api");
        if Path::new(&dir.path("artifacts")).is_dir() {
            cmd.env("OPENMETTLE_API_ARTIFACTS_DIR", dir.path("artifacts"));
        }
        let child = cmd
            .env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", db.url(API))
            .env("OPENMETTLE_API_DB_MAX_CONNECTIONS", connections.to_string())
            .env("OPENMETTLE_API_DB_TIMEOUT_MS", "2000")
            .env("OPENMETTLE_API_AUTH_CONFIG", &auth)
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", db.url(ISSUANCE))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut process = Process(child);
        wait_ready(&mut process, &bind);
        Self { process, dir, bind }
    }

    /// Kills the process as a crash would, keeping its directory.
    fn kill(self) -> auth_config_support::Dir {
        drop(self.process);
        self.dir
    }

    /// The sorted file names in `staging` or `revisions`.
    fn files(&self, sub: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(Path::new(&self.dir.path("artifacts")).join(sub))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != ".openmettle-volume-id")
            .collect();
        names.sort();
        names
    }

    /// One raw request on a new connection: the status, the lowercase head and the body.
    fn raw(&self, request: &str) -> (u16, String, String) {
        let mut stream = TcpStream::connect(&self.bind).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        // An upload refused before its body is read may be reset after the response arrives.
        let mut response = Vec::new();
        if let Err(error) = stream.read_to_end(&mut response) {
            assert!(!response.is_empty(), "{error}");
        }
        let response = String::from_utf8(response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        (
            head[9..12].parse().unwrap(),
            head.to_ascii_lowercase(),
            body.to_owned(),
        )
    }

    /// A `/v1` request head on `who`'s channel with the extra `headers` lines, announcing a
    /// body of `len` bytes.
    fn head(who: As<'_>, method: &str, path: &str, headers: &str, len: usize) -> String {
        let mut request = format!("{method} {path} HTTP/1.1\r\nhost: app.example.test\r\n");
        match who {
            As::Browser(cookie) => request.push_str(&format!(
                "cookie: __Host-openmettle-session={cookie}\r\norigin: {ORIGIN}\r\n"
            )),
            As::Native(bearer) => {
                request.push_str(&format!("authorization: Bearer {bearer}\r\n"));
            }
        }
        request.push_str(headers);
        request.push_str(&format!(
            "content-length: {len}\r\nconnection: close\r\n\r\n"
        ));
        request
    }

    /// One `/v1` request: the status, the lowercase head and the body. Every response is
    /// versioned and uncacheable.
    fn send(
        &self,
        who: As<'_>,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> (u16, String, String) {
        let request = Self::head(who, method, path, headers, body.len()) + body;
        let (status, head, body) = self.raw(&request);
        assert!(head.contains("openmettle-api-version: 1.0"), "{head}");
        assert!(head.contains("cache-control: no-store"), "{head}");
        (status, head, body)
    }

    /// One `/v1` request: the status and the JSON body (`null` when empty). Every problem
    /// decodes with the contract consumer.
    pub(super) fn call(
        &self,
        who: As<'_>,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut headers = String::new();
        if let Some(key) = key {
            headers.push_str(&format!("idempotency-key: {key}\r\n"));
        }
        let body = body.map(Value::to_string).unwrap_or_default();
        if !body.is_empty() {
            headers.push_str("content-type: application/json\r\n");
        }
        let (status, _, body) = self.send(who, method, path, &headers, &body);
        decoded(status, &body)
    }

    /// One multipart upload under `key`; the boundary is the one `body` opens with. A created
    /// revision decodes with the contract consumer.
    fn upload(&self, who: As<'_>, path: &str, key: &str, body: &str) -> (u16, Value) {
        let (status, _, body) = self.send(who, "POST", path, &upload_headers(key, body), body);
        let response = decoded(status, &body);
        if status == 201 {
            consumer::decode_revision(&response.1).unwrap();
        }
        response
    }

    /// Sends an upload's head and its first `sent` body bytes, and leaves the request open.
    fn begin_upload(
        &self,
        who: As<'_>,
        path: &str,
        key: &str,
        body: &str,
        sent: usize,
    ) -> TcpStream {
        let head = Self::head(who, "POST", path, &upload_headers(key, body), body.len());
        let mut stream = TcpStream::connect(&self.bind).unwrap();
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body.as_bytes()[..sent]).unwrap();
        stream
    }

    /// A `GET` or `HEAD` of revision content with an optional `Range`: the status, the
    /// lowercase head and the body. A `GET` problem decodes with the contract consumer.
    fn download(
        &self,
        who: As<'_>,
        method: &str,
        path: &str,
        range: Option<&str>,
    ) -> (u16, String, String) {
        let range = range.map(|r| format!("range: {r}\r\n")).unwrap_or_default();
        let (status, head, body) = self.send(who, method, path, &range, "");
        if status >= 400 && method == "GET" {
            assert!(
                head.contains("content-type: application/problem+json"),
                "{head}"
            );
            decoded(status, &body);
        }
        (status, head, body)
    }
}

/// The JSON body of a response (`null` when empty); a problem decodes with the consumer.
fn decoded(status: u16, body: &str) -> (u16, Value) {
    let json = match body.is_empty() {
        true => Value::Null,
        false => serde_json::from_str(body).unwrap(),
    };
    if status >= 400 {
        let problem = consumer::decode_problem(&json).unwrap();
        assert_eq!(problem.status, status);
    }
    (status, json)
}

fn upload_headers(key: &str, body: &str) -> String {
    let boundary = body.lines().next().unwrap().strip_prefix("--").unwrap();
    format!("idempotency-key: {key}\r\ncontent-type: multipart/form-data; boundary={boundary}\r\n")
}

/// A migrated database with the synthetic providers, and the mounted API over it.
async fn mounted() -> (TestDb, Api) {
    let db = TestDb::migrated().await;
    providers(&mut connect(&db.0, OWNER).await).await;
    let api = Api::start(&db);
    (db, api)
}

#[track_caller]
pub(super) fn success(response: (u16, Value), status: u16) -> Value {
    assert_eq!(response.0, status, "{}", response.1);
    response.1
}

#[track_caller]
fn refused(response: (u16, Value), status: u16, code: &str) {
    assert_eq!(
        (response.0, response.1["code"].as_str()),
        (status, Some(code)),
        "{}",
        response.1
    );
}

fn member(grantee: (&str, &str), role: &str) -> Value {
    json!({ "grantee": { "kind": grantee.0, "grantee_id": grantee.1 }, "role": role })
}

fn grantee(kind: &str, id: Option<&str>) -> Value {
    match id {
        Some(id) => json!({ "grantee": { "kind": kind, "grantee_id": id } }),
        None => json!({ "grantee": { "kind": kind } }),
    }
}

fn shared(kind: &str, id: Option<&str>, access: &str) -> Value {
    let mut body = grantee(kind, id);
    body["access"] = access.into();
    body
}

/// The primary's clock in Unix milliseconds, which the API also hydrates at.
async fn db_now(db: &TestDb) -> i64 {
    sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn capabilities_follow_current_primary_state_on_both_channels() {
    let (db, api) = mounted().await;
    let mut owner = connect(&db.0, OWNER).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let withdrawn = account(&mut owner, PROVIDER, false, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let (cookie, bearer) = (browser(&db, &alice, 1).await, native(&db, &alice, 2).await);
    let capabilities = |who| api.call(who, "GET", "/v1/capabilities", None, None);

    for who in [As::Browser(&cookie), As::Native(&bearer)] {
        let list = success(capabilities(who), 200);
        assert!(consumer::decode_capabilities(&list).unwrap().is_empty());
        let generated = list["generated_at"].as_str().unwrap();
        assert_eq!((generated.len(), &generated[26..]), (27, "Z"));
    }
    // A browser session is not a bearer, and a bearer is not a browser session.
    refused(capabilities(As::Native(&cookie)), 401, "unauthenticated");
    refused(capabilities(As::Browser(&bearer)), 401, "unauthenticated");
    // A withdrawn approval is refused at validation.
    let withdrawn = browser(&db, &withdrawn, 3).await;
    refused(
        capabilities(As::Browser(&withdrawn)),
        401,
        "unauthenticated",
    );

    // Logging out through the mounted sign-in routes revokes the next `/v1` request.
    let (status, _, _) = api.raw(&format!(
        "POST /auth/logout HTTP/1.1\r\nhost: app.example.test\r\norigin: {ORIGIN}\r\n\
         cookie: __Host-openmettle-session={cookie}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    ));
    assert_eq!(status, 204);
    refused(capabilities(As::Browser(&cookie)), 401, "unauthenticated");
    success(capabilities(As::Native(&bearer)), 200);
    let (status, _, _) = api.raw(&format!(
        "POST /auth/native/logout HTTP/1.1\r\nhost: app.example.test\r\n\
         authorization: Bearer {bearer}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    ));
    assert_eq!(status, 204);
    refused(capabilities(As::Native(&bearer)), 401, "unauthenticated");

    // Disabling the account revokes both channels on the next request.
    let (cookie, bearer) = (browser(&db, &bob, 4).await, native(&db, &bob, 5).await);
    success(capabilities(As::Browser(&cookie)), 200);
    let mut c = connect(&db.0, API).await;
    store::disable_user(&mut c, &ctx(&admin, "disable-bob"), &bob.user)
        .await
        .unwrap();
    for who in [As::Browser(&cookie), As::Native(&bearer)] {
        refused(capabilities(who), 401, "unauthenticated");
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn project_lifecycle_is_enforced_over_both_channels() {
    let (db, api) = mounted().await;
    let mut owner = connect(&db.0, OWNER).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let a = browser(&db, &alice, 1).await;
    let a_native = native(&db, &alice, 2).await;
    let b = native(&db, &bob, 3).await;
    let ad = browser(&db, &admin, 4).await;
    let (alice_b, alice_n, bob_n) = (As::Browser(&a), As::Native(&a_native), As::Native(&b));

    // Create, replay on the other channel, and reuse a key for another body.
    let body = json!({"name": "Alpha", "instructions": "Be brief.", "defaults": {"model": "m"}});
    let created = success(
        api.call(alice_b, "POST", "/v1/projects", Some("create"), Some(&body)),
        201,
    );
    let project = consumer::decode_project(&created).unwrap();
    assert_eq!(
        (project.name.as_str(), project.revision, project.archived),
        ("Alpha", 1, false)
    );
    assert!(project.role.manages_project());
    let p = project.id;
    let replay = api.call(alice_n, "POST", "/v1/projects", Some("create"), Some(&body));
    assert_eq!(success(replay, 201)["project_id"], p.as_str());
    let other = json!({"name": "Beta"});
    let reused = api.call(
        alice_n,
        "POST",
        "/v1/projects",
        Some("create"),
        Some(&other),
    );
    refused(reused, 409, "idempotency_conflict");
    for invalid in [
        json!({"name": "A", "defaults": {"folder_id": "f"}}),
        json!({"name": "A", "collection_id": "c"}),
        json!({"name": " padded"}),
    ] {
        let response = api.call(alice_b, "POST", "/v1/projects", Some("bad"), Some(&invalid));
        refused(response, 400, "validation");
    }

    // Members read it; non-members, the administrator included, do not learn it exists.
    let base = format!("/v1/projects/{p}");
    let read = |who| api.call(who, "GET", &base, None, None);
    assert_eq!(success(read(alice_n), 200)["role"], "owner");
    refused(read(bob_n), 404, "not_found");
    refused(read(As::Browser(&ad)), 404, "not_found");

    // Settings: owner only, an unchanged value is a conflict, legacy defaults are refused.
    let settings = json!({"name": "Gamma", "instructions": "", "defaults": {"temperature": 1}});
    let updated = success(
        api.call(alice_b, "PUT", &base, Some("update"), Some(&settings)),
        200,
    );
    assert_eq!(
        (updated["name"].as_str(), updated["revision"].as_str()),
        (Some("Gamma"), Some("2"))
    );
    let unchanged = api.call(alice_b, "PUT", &base, Some("update-2"), Some(&settings));
    refused(unchanged, 409, "conflict");
    let legacy = json!({"name": "G", "instructions": "", "defaults": {"folder_ids": []}});
    refused(
        api.call(alice_b, "PUT", &base, Some("legacy"), Some(&legacy)),
        400,
        "validation",
    );

    // A viewer reads, but may not change, the project.
    let members = format!("{base}/members");
    let grant = success(
        api.call(
            alice_b,
            "PUT",
            &members,
            Some("bob"),
            Some(&member(("user", &bob.user), "viewer")),
        ),
        200,
    );
    let grant = consumer::decode_member_grant(&grant).unwrap();
    assert_eq!(grant.grantee, consumer::Grantee::User(bob.user.clone()));
    assert_eq!(success(read(bob_n), 200)["role"], "viewer");
    refused(
        api.call(bob_n, "PUT", &base, Some("b1"), Some(&settings)),
        403,
        "policy",
    );
    refused(
        api.call(bob_n, "POST", &format!("{base}/archive"), Some("b2"), None),
        403,
        "policy",
    );

    // Archive cancels live runs, freezes settings, roles and new shares, and keeps reads,
    // revocations, restore and delete.
    let scope = created["scope_id"].as_str().unwrap();
    let run = project_run(&db, scope, &alice).await;
    let conversation = chat(&db, scope, "project", &alice).await;
    let item = format!("/v1/conversations/{conversation}");
    let whole = shared("project", None, "read");
    success(
        api.call(
            alice_b,
            "PUT",
            &format!("{item}/shares"),
            Some("s1"),
            Some(&whole),
        ),
        200,
    );
    let archived = success(
        api.call(
            alice_b,
            "POST",
            &format!("{base}/archive"),
            Some("a1"),
            None,
        ),
        200,
    );
    assert_eq!(archived["archived"], true);
    assert_eq!(state_of(&db, &run).await, ("cancelled".into(), None));
    refused(
        api.call(alice_b, "PUT", &base, Some("f1"), Some(&legacy_free())),
        409,
        "conflict",
    );
    let editor = member(("user", &bob.user), "editor");
    refused(
        api.call(alice_b, "PUT", &members, Some("f2"), Some(&editor)),
        409,
        "conflict",
    );
    let write = shared("project", None, "write");
    refused(
        api.call(
            alice_b,
            "PUT",
            &format!("{item}/shares"),
            Some("f3"),
            Some(&write),
        ),
        409,
        "conflict",
    );
    assert_eq!(success(read(bob_n), 200)["archived"], true);
    let access = success(api.call(alice_n, "GET", &item, None, None), 200);
    let access = consumer::decode_item_access(&access, false).unwrap();
    assert_eq!(access.access, consumer::Access::Read);
    assert!(access.can_manage_shares && access.project_id.as_deref() == Some(p.as_str()));
    let revoke = grantee("project", None);
    let response = api.call(
        alice_b,
        "POST",
        &format!("{item}/shares/revoke"),
        Some("r1"),
        Some(&revoke),
    );
    assert_eq!(success(response, 204), Value::Null);
    let bob_out = grantee("user", Some(&bob.user));
    let response = api.call(
        alice_b,
        "POST",
        &format!("{members}/revoke"),
        Some("r2"),
        Some(&bob_out),
    );
    success(response, 204);
    refused(read(bob_n), 404, "not_found");
    let restored = success(
        api.call(
            alice_b,
            "POST",
            &format!("{base}/restore"),
            Some("u1"),
            None,
        ),
        200,
    );
    assert_eq!(restored["archived"], false);
    success(
        api.call(
            alice_b,
            "PUT",
            &base,
            Some("f1-again"),
            Some(&legacy_free()),
        ),
        200,
    );

    // Soft delete: the exact replay answers again, any other key and every read is concealed.
    success(
        api.call(alice_b, "DELETE", &base, Some("delete"), None),
        204,
    );
    success(
        api.call(alice_n, "DELETE", &base, Some("delete"), None),
        204,
    );
    refused(
        api.call(alice_b, "DELETE", &base, Some("delete-2"), None),
        404,
        "not_found",
    );
    refused(read(alice_b), 404, "not_found");
    refused(
        api.call(alice_b, "GET", &item, None, None),
        404,
        "not_found",
    );
    refused(
        api.call(
            alice_b,
            "POST",
            &format!("{base}/restore"),
            Some("u2"),
            None,
        ),
        404,
        "not_found",
    );
}

fn legacy_free() -> Value {
    json!({"name": "Delta", "instructions": "x", "defaults": {}})
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn roles_groups_and_private_items_are_enforced_on_every_request() {
    let (db, api) = mounted().await;
    let mut owner = connect(&db.0, OWNER).await;
    let mut accounts = Vec::new();
    for _ in 0..7 {
        accounts.push(account(&mut owner, PROVIDER, true, FUTURE).await);
    }
    let [alice, eddie, vic, gail, olive, bob, admin]: [Account; 7] =
        accounts.try_into().ok().unwrap();
    make_admin(&mut owner, &admin).await;
    let mut sessions = Vec::new();
    for (n, account) in [&alice, &eddie, &vic, &gail, &olive, &bob, &admin]
        .into_iter()
        .enumerate()
    {
        // Alice and the administrator use the browser channel, everyone else a bearer.
        let n = u8::try_from(n).unwrap() + 1;
        sessions.push(match n {
            1 | 7 => browser(&db, account, n).await,
            _ => native(&db, account, n).await,
        });
    }
    let who = |n: usize| match n {
        0 | 6 => As::Browser(&sessions[n]),
        _ => As::Native(&sessions[n]),
    };
    let (alice_s, eddie_s, vic_s, gail_s, olive_s, bob_s, admin_s) =
        (who(0), who(1), who(2), who(3), who(4), who(5), who(6));

    let created = success(
        api.call(
            alice_s,
            "POST",
            "/v1/projects",
            Some("create"),
            Some(&json!({"name": "P"})),
        ),
        201,
    );
    let p = created["project_id"].as_str().unwrap().to_owned();
    let scope = created["scope_id"].as_str().unwrap().to_owned();
    let base = format!("/v1/projects/{p}");
    let members = format!("{base}/members");
    let role_of = |who| api.call(who, "GET", &base, None, None);

    // Direct, local-group and OIDC-group grants, through the API.
    let mut c = connect(&db.0, API).await;
    let group = store::create_local_group(&mut c, &ctx(&admin, "group"), "Synthetic group")
        .await
        .unwrap()
        .target_id()
        .to_owned();
    store::add_local_group_member(&mut c, &ctx(&admin, "group-add"), &group, &gail.user)
        .await
        .unwrap();
    let mut observations = present_membership_at(&db, &olive, db_now(&db).await).await;
    for (key, body) in [
        ("eddie", member(("user", &eddie.user), "editor")),
        ("vic", member(("user", &vic.user), "viewer")),
        ("group", member(("local_group", &group), "editor")),
        ("team", member(("oidc_group", "synthetic-team"), "viewer")),
        // The highest role wins across a direct and a group grant.
        ("gail", member(("user", &gail.user), "viewer")),
    ] {
        success(
            api.call(alice_s, "PUT", &members, Some(key), Some(&body)),
            200,
        );
    }
    for (who, role) in [
        (eddie_s, "editor"),
        (vic_s, "viewer"),
        (gail_s, "editor"),
        (olive_s, "viewer"),
    ] {
        assert_eq!(success(role_of(who), 200)["role"], role);
    }
    refused(role_of(bob_s), 404, "not_found");
    // The last direct owner can neither leave nor step down.
    let alice_grantee = grantee("user", Some(&alice.user));
    let leave = api.call(
        alice_s,
        "POST",
        &format!("{members}/revoke"),
        Some("leave"),
        Some(&alice_grantee),
    );
    refused(leave, 403, "policy");
    let step_down = member(("user", &alice.user), "editor");
    refused(
        api.call(alice_s, "PUT", &members, Some("down"), Some(&step_down)),
        403,
        "policy",
    );

    // Items are private to their creator until shared, even from the project owner.
    let c1 = chat(&db, &scope, "project", &alice).await;
    let item = format!("/v1/conversations/{c1}");
    let shares = format!("{item}/shares");
    let access = |who| api.call(who, "GET", &item, None, None);
    for who in [eddie_s, vic_s, gail_s, olive_s, bob_s, admin_s] {
        refused(access(who), 404, "not_found");
    }
    let mine = consumer::decode_item_access(&success(access(alice_s), 200), false).unwrap();
    assert_eq!(
        (mine.access, mine.can_manage_shares),
        (consumer::Access::Write, true)
    );
    let to_vic = shared("user", Some(&vic.user), "read");
    refused(
        api.call(vic_s, "PUT", &shares, Some("v"), Some(&to_vic)),
        404,
        "not_found",
    );
    let to_eddie = shared("user", Some(&eddie.user), "read");
    let share = success(
        api.call(alice_s, "PUT", &shares, Some("e"), Some(&to_eddie)),
        200,
    );
    let share = consumer::decode_share(&share).unwrap();
    assert_eq!(
        (share.resource_kind.as_str(), share.access),
        ("conversation", consumer::Access::Read)
    );
    let seen = consumer::decode_item_access(&success(access(eddie_s), 200), false).unwrap();
    assert_eq!(
        (seen.access, seen.can_manage_shares),
        (consumer::Access::Read, false)
    );
    // An editor who can see another member's item may not reshare it.
    refused(
        api.call(eddie_s, "PUT", &shares, Some("e2"), Some(&to_vic)),
        403,
        "policy",
    );
    // A non-member is not a valid grantee.
    let to_bob = shared("user", Some(&bob.user), "read");
    refused(
        api.call(alice_s, "PUT", &shares, Some("b"), Some(&to_bob)),
        403,
        "policy",
    );
    let whole = shared("project", None, "write");
    success(
        api.call(alice_s, "PUT", &shares, Some("p"), Some(&whole)),
        200,
    );
    // A viewer's access is capped at read; the group editor writes.
    assert_eq!(success(access(vic_s), 200)["access"], "read");
    assert_eq!(success(access(gail_s), 200)["access"], "write");
    // A viewer cannot share its own item; an editor shares its own.
    let c2 = chat(&db, &scope, "project", &vic).await;
    let vic_shares = format!("/v1/conversations/{c2}/shares");
    let to_alice = shared("user", Some(&alice.user), "read");
    refused(
        api.call(vic_s, "PUT", &vic_shares, Some("v2"), Some(&to_alice)),
        403,
        "policy",
    );
    let c3 = chat(&db, &scope, "project", &eddie).await;
    let to_vic_write = shared("user", Some(&vic.user), "write");
    let eddie_shares = format!("/v1/conversations/{c3}/shares");
    success(
        api.call(
            eddie_s,
            "PUT",
            &eddie_shares,
            Some("e3"),
            Some(&to_vic_write),
        ),
        200,
    );
    let vic_view = api.call(vic_s, "GET", &format!("/v1/conversations/{c3}"), None, None);
    assert_eq!(success(vic_view, 200)["access"], "read");

    // Personal artifacts: private to their owner, shared and unshared directly.
    let a1 = artifact(&db, &personal_of(&db, &alice).await, "personal", &alice).await;
    let art = format!("/v1/artifacts/{a1}");
    let art_access = |who| api.call(who, "GET", &art, None, None);
    let own = success(art_access(alice_s), 200);
    let decoded = consumer::decode_item_access(&own, true).unwrap();
    assert_eq!((decoded.project_id, decoded.last_revision), (None, Some(0)));
    assert_eq!(
        (own["scope_kind"].as_str(), decoded.access),
        (Some("personal"), consumer::Access::Write)
    );
    refused(art_access(bob_s), 404, "not_found");
    let art_shares = format!("{art}/shares");
    let whole_read = shared("project", None, "read");
    refused(
        api.call(alice_s, "PUT", &art_shares, Some("ap"), Some(&whole_read)),
        403,
        "policy",
    );
    success(
        api.call(alice_s, "PUT", &art_shares, Some("ab"), Some(&to_bob)),
        200,
    );
    assert_eq!(success(art_access(bob_s), 200)["access"], "read");
    let bob_revoke = grantee("user", Some(&bob.user));
    success(
        api.call(
            alice_s,
            "POST",
            &format!("{art_shares}/revoke"),
            Some("ab-r"),
            Some(&bob_revoke),
        ),
        204,
    );
    refused(art_access(bob_s), 404, "not_found");

    // An account administrator gains nothing on any route.
    let settings = legacy_free();
    let editor = member(("user", &admin.user), "editor");
    let self_share = shared("user", Some(&admin.user), "read");
    let admin_self = grantee("user", Some(&admin.user));
    let routes: [(&str, String, Option<&Value>); 13] = [
        ("GET", base.clone(), None),
        ("PUT", base.clone(), Some(&settings)),
        ("DELETE", base.clone(), None),
        ("POST", format!("{base}/archive"), None),
        ("POST", format!("{base}/restore"), None),
        ("PUT", members.clone(), Some(&editor)),
        ("POST", format!("{members}/revoke"), Some(&alice_grantee)),
        ("GET", item.clone(), None),
        ("PUT", shares.clone(), Some(&self_share)),
        ("POST", format!("{shares}/revoke"), Some(&admin_self)),
        ("GET", art.clone(), None),
        ("PUT", art_shares.clone(), Some(&self_share)),
        ("POST", format!("{art_shares}/revoke"), Some(&admin_self)),
    ];
    for (n, (method, path, body)) in routes.iter().enumerate() {
        let key = (*method != "GET").then(|| format!("admin-{n}"));
        let response = api.call(admin_s, method, path, key.as_deref(), *body);
        refused(response, 404, "not_found");
    }

    // Revocations apply on the very next request.
    let eddie_out = grantee("user", Some(&eddie.user));
    success(
        api.call(
            alice_s,
            "POST",
            &format!("{members}/revoke"),
            Some("e-out"),
            Some(&eddie_out),
        ),
        204,
    );
    refused(role_of(eddie_s), 404, "not_found");
    refused(access(eddie_s), 404, "not_found");
    // A disabled group grants nothing: only Gail's direct viewer grant remains, so the
    // project share is capped at read.
    store::disable_local_group(&mut c, &ctx(&admin, "group-off"), &group)
        .await
        .unwrap();
    assert_eq!(success(role_of(gail_s), 200)["role"], "viewer");
    assert_eq!(success(access(gail_s), 200)["access"], "read");
    sqlx::query(
        "UPDATE openmettle.membership_observations SET observation.state = 'stale'
          WHERE approval_id = $1::uuid",
    )
    .bind(&olive.approval)
    .execute(&mut observations)
    .await
    .unwrap();
    refused(role_of(olive_s), 404, "not_found");
    let (status, _, _) = api.raw(&format!(
        "POST /auth/native/logout HTTP/1.1\r\nhost: app.example.test\r\n\
         authorization: Bearer {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        sessions[2]
    ));
    assert_eq!(status, 204);
    refused(role_of(vic_s), 401, "unauthenticated");
}

// --- artifact uploads and downloads (ADR 0031 PR2) --------------------------------------------

const GIB: i64 = 1 << 30;

/// Storage limits: a large instance budget and the given owner limits (`None` unconfigured).
async fn limits(db: &TestDb, personal: Option<i64>, project: Option<i64>) {
    sqlx::query(
        "UPDATE openmettle.storage_instance
            SET instance_budget_bytes = $1, personal_limit_bytes = $2, project_limit_bytes = $3",
    )
    .bind(1_i64 << 40)
    .bind(personal)
    .bind(project)
    .execute(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap();
}

/// Reservations in `state`.
async fn reservations(db: &TestDb, state: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM openmettle.storage_reservations WHERE state = $1")
        .bind(state)
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

/// The (active, retained, reserved) bytes charged to `scope`.
async fn charged(db: &TestDb, scope: &str) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT coalesce(sum(active_bytes), 0)::bigint, coalesce(sum(retained_bytes), 0)::bigint,
                coalesce(sum(reserved_bytes), 0)::bigint
           FROM openmettle.storage_accounts WHERE scope_id = $1::uuid",
    )
    .bind(scope)
    .fetch_one(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}

/// Polls `done` for up to ten seconds.
async fn eventually(mut done: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done().await {
        assert!(Instant::now() < deadline, "condition not reached");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The file part, with an optional file name and the given media type.
fn file_part(filename: Option<&str>, media: &str, bytes: &str) -> String {
    let filename = filename
        .map(|f| format!("; filename=\"{f}\""))
        .unwrap_or_default();
    format!(
        "Content-Disposition: form-data; name=\"file\"{filename}\r\nContent-Type: {media}\r\n\r\n{bytes}"
    )
}

fn metadata_part(json: &str) -> String {
    format!(
        "Content-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{json}"
    )
}

/// A form of `parts` under `boundary`, with or without its closing delimiter.
fn form(boundary: &str, parts: &[String], close: bool) -> String {
    let mut out: String = parts
        .iter()
        .map(|part| format!("--{boundary}\r\n{part}\r\n"))
        .collect();
    if close {
        out.push_str(&format!("--{boundary}--\r\n"));
    }
    out
}

fn sha256(bytes: &str) -> String {
    format!("{:x}", Sha256::digest(bytes.as_bytes()))
}

/// The value of header `name` in a lowercase head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn artifact_uploads_are_authorized_before_staging_and_replay_once() {
    let (db, api) = mounted().await;
    limits(&db, Some(GIB), Some(GIB)).await;
    let mut owner = connect(&db.0, OWNER).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let vic = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (a_b, a_n) = (browser(&db, &alice, 1).await, native(&db, &alice, 2).await);
    let (v, b) = (native(&db, &vic, 3).await, native(&db, &bob, 4).await);
    let (alice_b, alice_n) = (As::Browser(&a_b), As::Native(&a_n));
    let (vic_n, bob_n) = (As::Native(&v), As::Native(&b));
    let personal = personal_of(&db, &alice).await;
    let created = success(
        api.call(
            alice_b,
            "POST",
            "/v1/projects",
            Some("p"),
            Some(&json!({"name": "P"})),
        ),
        201,
    );
    let p = created["project_id"].as_str().unwrap().to_owned();
    let scope = created["scope_id"].as_str().unwrap().to_owned();
    let members = format!("/v1/projects/{p}/members");
    let viewer = member(("user", &vic.user), "viewer");
    success(
        api.call(alice_b, "PUT", &members, Some("vic"), Some(&viewer)),
        200,
    );

    let text = "hello, world";
    let file = file_part(Some("notes.txt"), "text/plain", text);
    let meta = metadata_part("{}");
    let note = form("a", &[file.clone(), meta.clone()], true);

    // Each refusal is decided on the primary before anything is reserved or staged.
    let into_project = format!("/v1/artifacts?scope_id={scope}");
    refused(api.upload(vic_n, &into_project, "v", &note), 403, "policy");
    refused(
        api.upload(bob_n, &into_project, "b", &note),
        404,
        "not_found",
    );
    let into_alice = format!("/v1/artifacts?scope_id={personal}");
    refused(api.upload(bob_n, &into_alice, "b", &note), 404, "not_found");
    let unknown = "/v1/artifacts/0f0e0d0c-0b0a-4908-8706-050403020100/revisions";
    refused(api.upload(alice_n, unknown, "u", &note), 404, "not_found");
    for state in ["reserved", "settled", "released"] {
        assert_eq!(reservations(&db, state).await, 0, "{state}");
    }
    assert!(api.files("staging").is_empty() && api.files("revisions").is_empty());

    // Created in the personal scope by default. The exact retry, on the other channel with
    // another boundary and the parts reversed, returns the same revision and charges once.
    let first = success(
        api.upload(alice_b, "/v1/artifacts?max_bytes=1000", "up", &note),
        201,
    );
    let revision = consumer::decode_revision(&first).unwrap();
    assert_eq!(
        (
            revision.revision,
            revision.size_bytes,
            revision.project_id.as_deref()
        ),
        (1, 12, None)
    );
    assert_eq!(revision.display_name.as_deref(), Some("notes.txt"));
    assert_eq!(
        (revision.media_type.as_str(), revision.sha256),
        ("text/plain", sha256(text))
    );
    assert_eq!(
        (first["scope_kind"].as_str(), first["scope_id"].as_str()),
        (Some("personal"), Some(personal.as_str()))
    );
    let reversed = form("retry-boundary", &[meta.clone(), file.clone()], true);
    let again = api.upload(alice_n, "/v1/artifacts?max_bytes=1000", "up", &reversed);
    assert_eq!(success(again, 201), first);
    assert_eq!(charged(&db, &personal).await, (12, 0, 0));
    assert_eq!(reservations(&db, "settled").await, 1);
    assert_eq!(api.files("revisions").len(), 1);
    let access = success(
        api.call(
            alice_n,
            "GET",
            &format!("/v1/artifacts/{}", revision.artifact_id),
            None,
            None,
        ),
        200,
    );
    assert_eq!(access["last_revision"], "1");

    // A changed file, name, media type or ceiling under that key is a different request.
    for (path, body) in [
        (
            "/v1/artifacts?max_bytes=1000",
            form(
                "c",
                &[
                    file_part(Some("notes.txt"), "text/plain", "hello, World"),
                    meta.clone(),
                ],
                true,
            ),
        ),
        (
            "/v1/artifacts?max_bytes=1000",
            form(
                "c",
                &[
                    file_part(Some("other.txt"), "text/plain", text),
                    meta.clone(),
                ],
                true,
            ),
        ),
        (
            "/v1/artifacts?max_bytes=1000",
            form(
                "c",
                &[
                    file_part(Some("notes.txt"), "text/markdown", text),
                    meta.clone(),
                ],
                true,
            ),
        ),
        ("/v1/artifacts?max_bytes=999", note.clone()),
    ] {
        refused(
            api.upload(alice_b, path, "up", &body),
            409,
            "idempotency_conflict",
        );
    }
    assert_eq!(charged(&db, &personal).await, (12, 0, 0));

    // Malformed bodies are refused after streaming starts: each staging file is unlinked and its
    // reservation released, and the spent key cannot be reused.
    let other =
        "Content-Disposition: form-data; name=\"extra\"\r\nContent-Type: text/plain\r\n\r\nx"
            .to_owned();
    for (path, key, body) in [
        (
            "/v1/artifacts",
            "truncated",
            form("t", &[file.clone(), meta.clone()], false),
        ),
        (
            "/v1/artifacts",
            "duplicate",
            form("d", &[file.clone(), file.clone(), meta.clone()], true),
        ),
        (
            "/v1/artifacts",
            "unknown-part",
            form("u", &[file.clone(), meta.clone(), other], true),
        ),
        (
            "/v1/artifacts",
            "metadata",
            form(
                "m",
                &[file.clone(), metadata_part("{\"scope_id\":\"x\"}")],
                true,
            ),
        ),
        ("/v1/artifacts?max_bytes=5", "too-large", note.clone()),
    ] {
        refused(api.upload(alice_b, path, key, &body), 400, "validation");
    }
    assert_eq!(reservations(&db, "released").await, 5);
    assert_eq!(reservations(&db, "reserved").await, 0);
    assert!(api.files("staging").is_empty());
    refused(
        api.upload(alice_b, "/v1/artifacts", "truncated", &note),
        409,
        "idempotency_conflict",
    );
    assert_eq!(charged(&db, &personal).await, (12, 0, 0));

    // A project artifact and its next revision, replayed on the other channel.
    let in_project = success(api.upload(alice_n, &into_project, "proj", &note), 201);
    assert_eq!(
        (
            in_project["scope_kind"].as_str(),
            in_project["project_id"].as_str()
        ),
        (Some("project"), Some(p.as_str()))
    );
    let artifact = in_project["artifact_id"].as_str().unwrap().to_owned();
    let revisions = format!("/v1/artifacts/{artifact}/revisions");
    let next = form(
        "n",
        &[
            meta.clone(),
            file_part(None, "application/json", "{\"v\":2}"),
        ],
        true,
    );
    let second = success(api.upload(alice_b, &revisions, "rev-2", &next), 201);
    assert_eq!(
        (
            second["revision"].as_str(),
            second["artifact_id"].as_str(),
            &second["display_name"]
        ),
        (Some("2"), Some(artifact.as_str()), &Value::Null)
    );
    let next_again = next.replace("--n", "--n2");
    assert_eq!(
        success(api.upload(alice_n, &revisions, "rev-2", &next_again), 201),
        second
    );
    // One key on two operations or targets is two requests.
    let elsewhere = success(api.upload(alice_n, "/v1/artifacts", "rev-2", &note), 201);
    assert_ne!(elsewhere["artifact_id"], second["artifact_id"]);

    // Writing a revision needs write access: concealed before a share, policy for a reader,
    // and conflict in an archived project, all before anything is reserved.
    let before = reservations(&db, "settled").await + reservations(&db, "released").await;
    refused(
        api.upload(vic_n, &revisions, "v-rev", &note),
        404,
        "not_found",
    );
    let read = shared("project", None, "read");
    let shares = format!("/v1/artifacts/{artifact}/shares");
    success(
        api.call(alice_b, "PUT", &shares, Some("share"), Some(&read)),
        200,
    );
    refused(api.upload(vic_n, &revisions, "v-rev", &note), 403, "policy");
    let archive = format!("/v1/projects/{p}/archive");
    success(
        api.call(alice_b, "POST", &archive, Some("archive"), None),
        200,
    );
    refused(
        api.upload(alice_b, &revisions, "rev-3", &note),
        409,
        "conflict",
    );
    refused(
        api.upload(alice_b, &into_project, "proj-2", &note),
        409,
        "conflict",
    );
    let after = reservations(&db, "settled").await + reservations(&db, "released").await;
    assert_eq!((after, reservations(&db, "reserved").await), (before, 0));
    let restore = format!("/v1/projects/{p}/restore");
    success(
        api.call(alice_b, "POST", &restore, Some("restore"), None),
        200,
    );
    success(api.upload(alice_b, &revisions, "rev-3", &note), 201);

    // Quota refusals reserve nothing: an owner limit too small for the ceiling, then
    // unconfigured limits.
    limits(&db, Some(100), Some(GIB)).await;
    let ceiling = "/v1/artifacts?max_bytes=1000";
    refused(api.upload(alice_b, ceiling, "q1", &note), 429, "quota");
    limits(&db, None, Some(GIB)).await;
    refused(
        api.upload(alice_b, ceiling, "q2", &note),
        503,
        "provisioning",
    );
    assert_eq!(reservations(&db, "reserved").await, 0);
    assert!(api.files("staging").is_empty());
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn artifact_downloads_check_current_grants_and_serve_byte_ranges() {
    let (db, api) = mounted().await;
    limits(&db, Some(GIB), Some(GIB)).await;
    let mut owner = connect(&db.0, OWNER).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let vic = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (a_b, a_n) = (browser(&db, &alice, 1).await, native(&db, &alice, 2).await);
    let (v, b) = (native(&db, &vic, 3).await, browser(&db, &bob, 4).await);
    let (alice_b, alice_n) = (As::Browser(&a_b), As::Native(&a_n));
    let (vic_n, bob_b) = (As::Native(&v), As::Browser(&b));
    let meta = metadata_part("{}");

    let digits = "0123456789";
    let body = form(
        "a",
        &[
            file_part(Some("report v1.txt"), "text/plain", digits),
            meta.clone(),
        ],
        true,
    );
    let created = success(
        api.upload(alice_b, "/v1/artifacts?max_bytes=100", "doc", &body),
        201,
    );
    let artifact = created["artifact_id"].as_str().unwrap().to_owned();
    let revision = created["revision_id"].as_str().unwrap().to_owned();
    let metadata = format!("/v1/artifacts/{artifact}/revisions/{revision}");
    let content = format!("{metadata}/content");
    assert_eq!(
        success(api.call(alice_n, "GET", &metadata, None, None), 200),
        created
    );

    // The whole content, with its stored media type and a safe attachment name.
    let (status, head, bytes) = api.download(alice_b, "GET", &content, None);
    assert_eq!((status, bytes.as_str()), (200, digits));
    for (name, value) in [
        ("content-type", "text/plain"),
        ("content-length", "10"),
        ("accept-ranges", "bytes"),
        ("x-content-type-options", "nosniff"),
        (
            "content-disposition",
            "attachment; filename*=utf-8''report%20v1.txt",
        ),
    ] {
        assert_eq!(header(&head, name), Some(value), "{head}");
    }
    assert_eq!(header(&head, "content-range"), None);
    // Single byte ranges, and HEAD with the same headers and no body.
    for (range, part, content_range) in [
        ("bytes=2-5", "2345", "bytes 2-5/10"),
        ("bytes=7-", "789", "bytes 7-9/10"),
        ("bytes=-3", "789", "bytes 7-9/10"),
        ("bytes=0-99", digits, "bytes 0-9/10"),
    ] {
        let (status, head, bytes) = api.download(alice_n, "GET", &content, Some(range));
        assert_eq!((status, bytes.as_str()), (206, part), "{range}");
        assert_eq!(header(&head, "content-range"), Some(content_range));
        assert_eq!(
            header(&head, "content-length"),
            Some(part.len().to_string().as_str())
        );
    }
    let (status, head, bytes) = api.download(alice_n, "HEAD", &content, None);
    assert_eq!(
        (status, bytes.as_str(), header(&head, "content-length")),
        (200, "", Some("10"))
    );
    let (status, head, bytes) = api.download(alice_n, "HEAD", &content, Some("bytes=2-5"));
    assert_eq!((status, bytes.as_str()), (206, ""));
    assert_eq!(header(&head, "content-range"), Some("bytes 2-5/10"));
    assert_eq!(header(&head, "content-length"), Some("4"));
    let (status, head, bytes) = api.download(alice_n, "GET", &content, Some("bytes=10-"));
    assert_eq!(
        (status, header(&head, "content-range")),
        (416, Some("bytes */10"))
    );
    assert_eq!(decoded(status, &bytes).1["code"], "range_not_satisfiable");
    let (status, _, bytes) = api.download(alice_n, "GET", &content, Some("bytes=0-1,4-5"));
    assert_eq!(
        (status, decoded(status, &bytes).1["code"].as_str()),
        (400, Some("validation"))
    );

    // Current grants decide every request: nothing before a share, bytes while it lasts,
    // nothing again the moment it is revoked.
    let concealed = |who| {
        refused(
            api.call(who, "GET", &metadata, None, None),
            404,
            "not_found",
        );
        let (status, _, bytes) = api.download(who, "GET", &content, Some("bytes=0-3"));
        assert!(status == 404 && !bytes.contains("0123"), "{status} {bytes}");
    };
    concealed(bob_b);
    let to_bob = shared("user", Some(&bob.user), "read");
    let shares = format!("/v1/artifacts/{artifact}/shares");
    success(
        api.call(alice_b, "PUT", &shares, Some("bob"), Some(&to_bob)),
        200,
    );
    let (status, _, bytes) = api.download(bob_b, "GET", &content, Some("bytes=0-3"));
    assert_eq!((status, bytes.as_str()), (206, "0123"));
    let revoke = grantee("user", Some(&bob.user));
    let revoked = api.call(
        alice_b,
        "POST",
        &format!("{shares}/revoke"),
        Some("bob-r"),
        Some(&revoke),
    );
    success(revoked, 204);
    concealed(bob_b);

    // A project member reads through a whole-project share until the membership is revoked.
    let project = success(
        api.call(
            alice_b,
            "POST",
            "/v1/projects",
            Some("p"),
            Some(&json!({"name": "P"})),
        ),
        201,
    );
    let (p, scope) = (
        project["project_id"].as_str().unwrap(),
        project["scope_id"].as_str().unwrap(),
    );
    let members = format!("/v1/projects/{p}/members");
    let viewer = member(("user", &vic.user), "viewer");
    success(
        api.call(alice_b, "PUT", &members, Some("vic"), Some(&viewer)),
        200,
    );
    let in_project = success(
        api.upload(
            alice_n,
            &format!("/v1/artifacts?scope_id={scope}"),
            "proj",
            &body,
        ),
        201,
    );
    let project_artifact = in_project["artifact_id"].as_str().unwrap();
    let project_content = format!(
        "/v1/artifacts/{project_artifact}/revisions/{}/content",
        in_project["revision_id"].as_str().unwrap()
    );
    let (status, _, _) = api.download(vic_n, "GET", &project_content, None);
    assert_eq!(status, 404);
    let whole = shared("project", None, "read");
    let project_shares = format!("/v1/artifacts/{project_artifact}/shares");
    success(
        api.call(alice_b, "PUT", &project_shares, Some("whole"), Some(&whole)),
        200,
    );
    let (status, _, bytes) = api.download(vic_n, "GET", &project_content, None);
    assert_eq!((status, bytes.as_str()), (200, digits));
    let vic_out = grantee("user", Some(&vic.user));
    let out = api.call(
        alice_b,
        "POST",
        &format!("{members}/revoke"),
        Some("vic-r"),
        Some(&vic_out),
    );
    success(out, 204);
    let (status, _, bytes) = api.download(vic_n, "GET", &project_content, None);
    assert!(status == 404 && !bytes.contains(digits));
    // A revision of another artifact is concealed.
    let foreign = format!("/v1/artifacts/{project_artifact}/revisions/{revision}");
    refused(
        api.call(alice_n, "GET", &foreign, None, None),
        404,
        "not_found",
    );

    // An empty file: the whole (empty) content, and no satisfiable range.
    let empty = form(
        "e",
        &[
            file_part(None, "application/octet-stream", ""),
            meta.clone(),
        ],
        true,
    );
    let created = success(
        api.upload(alice_b, "/v1/artifacts?max_bytes=1", "empty", &empty),
        201,
    );
    assert_eq!(created["size_bytes"], "0");
    let empty_content = format!(
        "/v1/artifacts/{}/revisions/{}/content",
        created["artifact_id"].as_str().unwrap(),
        created["revision_id"].as_str().unwrap()
    );
    let (status, head, bytes) = api.download(alice_b, "GET", &empty_content, None);
    assert_eq!(
        (status, bytes.as_str(), header(&head, "content-length")),
        (200, "", Some("0"))
    );
    let (status, head, _) = api.download(alice_b, "GET", &empty_content, Some("bytes=0-0"));
    assert_eq!(
        (status, header(&head, "content-range")),
        (416, Some("bytes */0"))
    );

    // A retained revision keeps its metadata and serves no content.
    let personal = personal_of(&db, &alice).await;
    let mut c = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    storage::retain_revision(&mut tx, &personal, &revision, 3600)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let retained = success(api.call(alice_n, "GET", &metadata, None, None), 200);
    assert_eq!(retained["state"], "retained");
    let (status, _, bytes) = api.download(alice_n, "GET", &content, None);
    assert_eq!(
        (status, decoded(status, &bytes).1["code"].as_str()),
        (409, Some("conflict"))
    );

    // A payload missing from the volume is an internal error that names no path.
    let reservation: String = sqlx::query_scalar(
        "SELECT reservation_id::text FROM openmettle.artifact_revisions WHERE id = $1::uuid",
    )
    .bind(in_project["revision_id"].as_str().unwrap())
    .fetch_one(&mut owner)
    .await
    .unwrap();
    fs::remove_file(
        Path::new(&api.dir.path("artifacts"))
            .join("revisions")
            .join(&reservation),
    )
    .unwrap();
    let (status, _, bytes) = api.download(alice_n, "GET", &project_content, None);
    assert_eq!(
        (status, decoded(status, &bytes).1["code"].as_str()),
        (500, Some("internal"))
    );
    assert!(!bytes.contains(&reservation) && !bytes.contains("revisions/"));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn interrupted_uploads_leave_nothing_after_reconciliation() {
    let (db, api) = mounted().await;
    limits(&db, Some(GIB), Some(GIB)).await;
    let mut owner = connect(&db.0, OWNER).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (a_b, a_n) = (browser(&db, &alice, 1).await, native(&db, &alice, 2).await);
    let (alice_b, alice_n) = (As::Browser(&a_b), As::Native(&a_n));
    let personal = personal_of(&db, &alice).await;
    let large = "x".repeat(4096);
    let body = form(
        "s",
        &[
            file_part(Some("big.txt"), "text/plain", &large),
            metadata_part("{}"),
        ],
        true,
    );

    // A client that stops sending mid-body: its staging file is unlinked.
    let mut gone = api.begin_upload(alice_n, "/v1/artifacts", "gone", &body, 1024);
    gone.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    eventually(async || api.files("staging").len() == 1).await;
    gone.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    let _ = gone.read_to_end(&mut rest);
    eventually(async || api.files("staging").is_empty()).await;

    // An upload still streaming holds its key: a retry is a conflict and touches nothing.
    let slow = api.begin_upload(alice_n, "/v1/artifacts", "slow", &body, 1024);
    eventually(async || api.files("staging").len() == 1).await;
    refused(
        api.upload(alice_b, "/v1/artifacts", "slow", &body),
        409,
        "conflict",
    );
    assert_eq!(api.files("staging").len(), 1);

    // A crash leaves the staging file and its reservation; the reconciler removes both.
    let dir = api.kill();
    drop(slow);
    let staging = Path::new(&dir.path("artifacts")).join("staging");
    assert_eq!(
        fs::read_dir(&staging)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name() != ".openmettle-volume-id")
            .count(),
        1
    );
    assert!(reservations(&db, "reserved").await >= 1);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db.url(API))
        .await
        .unwrap();
    let store = Store::open(Path::new(&dir.path("artifacts"))).unwrap();
    db.admin()
        .await
        .execute(
            "UPDATE openmettle.storage_reservations SET created_at=now()-interval '901 seconds',
        lease_expires_at=now()-interval '1 second' WHERE state='reserved'",
        )
        .await
        .unwrap();
    let released = artifact_fs::reconcile_expired(&pool, &store, Duration::ZERO, 10)
        .await
        .unwrap();
    assert!(released >= 1);
    assert_eq!(
        fs::read_dir(&staging)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name() != ".openmettle-volume-id")
            .count(),
        0
    );
    assert_eq!(reservations(&db, "reserved").await, 0);
    assert_eq!(charged(&db, &personal).await, (0, 0, 0));

    // The reconciled key is spent; a new key uploads normally.
    let api = Api::start_in(&db, dir);
    refused(
        api.upload(alice_n, "/v1/artifacts", "slow", &body),
        409,
        "idempotency_conflict",
    );
    let stored = success(api.upload(alice_n, "/v1/artifacts", "fresh", &body), 201);
    assert_eq!(stored["size_bytes"], "4096");
    assert_eq!(charged(&db, &personal).await, (4096, 0, 0));
}

fn validate_openapi_schema(pointer: &str, instance: &Value) -> bool {
    let mut doc: Value =
        serde_json::from_str(include_str!("../../contracts/openapi/openmettle-v1.json")).unwrap();
    doc["$ref"] = json!(pointer);
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&doc)
        .unwrap();
    validator.is_valid(instance)
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn quota_summary_wide_counters_privacy_warnings_and_hard_limit_reads_work_on_both_channels() {
    let (db, api) = mounted().await;
    let mut owner = connect(&db.0, OWNER).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;

    let (a_b, a_n) = (browser(&db, &alice, 1).await, native(&db, &alice, 2).await);
    let (b_b, b_n) = (browser(&db, &bob, 3).await, native(&db, &bob, 4).await);
    let (adm_b, adm_n) = (browser(&db, &admin, 5).await, native(&db, &admin, 6).await);
    let (alice_b, alice_n) = (As::Browser(&a_b), As::Native(&a_n));
    let (bob_b, bob_n) = (As::Browser(&b_b), As::Native(&b_n));
    let (admin_b, admin_n) = (As::Browser(&adm_b), As::Native(&adm_n));

    let alice_scope = personal_of(&db, &alice).await;
    let proj = success(
        api.call(
            alice_b,
            "POST",
            "/v1/projects",
            Some("quota-proj"),
            Some(&json!({"name": "Alpha Quotas"})),
        ),
        201,
    );
    let proj_id = proj["project_id"].as_str().unwrap();
    let proj_path = format!("/v1/projects/{proj_id}/quotas");

    // 1. Project quota concealment: non-member and non-member account_admin receive 404 not_found.
    for who in [bob_b, bob_n, admin_b, admin_n] {
        refused(
            api.call(who, "GET", &proj_path, None, None),
            404,
            "not_found",
        );
    }

    // 2. Oversized > i64::MAX 3-column token settlement read via GET /v1/quotas/personal.
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 1000), ('instance', 'usage_tokens', 10000000000)",
        )
        .await
        .unwrap();
    super::quotas::settle_oversized_three_column_tokens(&db, &alice, &alice_scope, &a_b).await;

    for who in [alice_b, alice_n] {
        let summary = success(api.call(who, "GET", "/v1/quotas/personal", None, None), 200);
        assert!(
            validate_openapi_schema("#/components/schemas/QuotaSummary", &summary),
            "QuotaSummary schema rejected wide counter response: {summary}"
        );
        let wide_val = &summary["usage"][0]["active_used"];
        assert_eq!(wide_val, "27670116110564327421");
        assert!(validate_openapi_schema(
            "#/components/schemas/WideNonNegativeDecimal",
            wide_val
        ));
        assert!(!validate_openapi_schema(
            "#/components/schemas/NonNegativeDecimal",
            wide_val
        ));
        let decoded = consumer::decode_quota_summary(&summary).unwrap();
        assert_eq!(decoded.usage[0].active_used, 27_670_116_110_564_327_421u128);
        assert_eq!(decoded.usage[0].remaining, Some(0));
        assert_eq!(decoded.usage[0].status, consumer::QuotaStatus::HardLimit);
        assert!(decoded.has_actor_execution);
    }

    // Project summary never leaks member's personal usage or per-actor execution fields.
    let proj_summary = success(api.call(alice_n, "GET", &proj_path, None, None), 200);
    assert!(validate_openapi_schema(
        "#/components/schemas/QuotaSummary",
        &proj_summary
    ));
    let decoded_proj = consumer::decode_quota_summary(&proj_summary).unwrap();
    assert_eq!(decoded_proj.scope_kind, "project");
    assert!(!decoded_proj.has_actor_execution);
    assert_eq!(decoded_proj.usage[0].active_used, 0);

    // Deleted project becomes 404 even for its owner.
    let del_proj = success(
        api.call(
            alice_b,
            "POST",
            "/v1/projects",
            Some("quota-del-proj"),
            Some(&json!({"name": "Soon Deleted"})),
        ),
        201,
    );
    let del_id = del_proj["project_id"].as_str().unwrap();
    success(
        api.call(
            alice_b,
            "DELETE",
            &format!("/v1/projects/{del_id}"),
            Some("del-now"),
            None,
        ),
        204,
    );
    refused(
        api.call(
            alice_n,
            "GET",
            &format!("/v1/projects/{del_id}/quotas"),
            None,
            None,
        ),
        404,
        "not_found",
    );

    // 3. Unconfigured instance storage budget on a configured project reports scope_kind = "instance".
    let proj_scope = proj["scope_id"].as_str().unwrap();
    owner
        .execute(
            "UPDATE openmettle.storage_instance
                SET instance_budget_bytes = NULL, personal_limit_bytes = 10000, project_limit_bytes = 10000",
        )
        .await
        .unwrap();
    let probe_up = form(
        "instunconf",
        &[
            file_part(Some("p.txt"), "text/plain", "hello"),
            metadata_part("{}"),
        ],
        true,
    );
    let (status, inst_unconf) = api.upload(
        alice_b,
        &format!("/v1/artifacts?scope_id={proj_scope}&max_bytes=5"),
        "proj-inst-unconf",
        &probe_up,
    );
    assert_eq!(status, 503, "{inst_unconf}");
    assert_eq!(inst_unconf["code"], "provisioning");
    assert_eq!(
        inst_unconf["quota"],
        json!({"resource_kind": "storage_bytes", "scope_kind": "instance"})
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/Problem",
        &inst_unconf
    ));

    // Cross-tenant privacy: remaining_bytes never leaks instance headroom consumed by bob.
    owner
        .execute(
            "UPDATE openmettle.storage_instance
                SET instance_budget_bytes = 12000, personal_limit_bytes = 10000, project_limit_bytes = 10000",
        )
        .await
        .unwrap();
    let payload_9k = "b".repeat(9_000);
    let bob_up = form(
        "bob9k",
        &[
            file_part(Some("bob.bin"), "application/octet-stream", &payload_9k),
            metadata_part("{}"),
        ],
        true,
    );
    success(
        api.upload(bob_n, "/v1/artifacts?max_bytes=9000", "bob-9k", &bob_up),
        201,
    );
    let payload_1k = "a".repeat(1_000);
    let alice_up = form(
        "alice1k",
        &[
            file_part(Some("alice.txt"), "text/plain", &payload_1k),
            metadata_part("{}"),
        ],
        true,
    );
    let alice_rev = success(
        api.upload(
            alice_b,
            "/v1/artifacts?max_bytes=1000",
            "alice-1k",
            &alice_up,
        ),
        201,
    );
    let alice_summary = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    // Instance only has 2000 bytes left, yet alice sees 9000 = max(0, 10000 - 1000).
    assert_eq!(alice_summary["storage"]["charged_bytes"], "1000");
    assert_eq!(alice_summary["storage"]["remaining_bytes"], "9000");

    // Exceeding instance headroom yields 429 quota with closed quota:{storage_bytes,instance} and no counts.
    let payload_4k = "x".repeat(4_000);
    let too_much = form(
        "alice4k",
        &[
            file_part(Some("big.txt"), "text/plain", &payload_4k),
            metadata_part("{}"),
        ],
        true,
    );
    let (status, prob) = api.upload(
        alice_n,
        "/v1/artifacts?max_bytes=4000",
        "alice-4k",
        &too_much,
    );
    assert_eq!(status, 429, "{prob}");
    assert_eq!(prob["code"], "quota");
    assert_eq!(
        prob["quota"],
        json!({"resource_kind": "storage_bytes", "scope_kind": "instance"})
    );
    let prob_text = prob.to_string();
    assert!(
        !prob_text.contains("9000")
            && !prob_text.contains("12000")
            && !prob_text.contains(&bob.user)
    );

    // 4. Warning deduplication & re-arming across override edit/revoke and config edit.
    limits(&db, Some(2_000), Some(100_000)).await;
    // Alice already has 1000 bytes; upload 700 -> 1700/2000 = 85% -> crosses 80% once.
    let payload_700 = "w".repeat(700);
    let warn_up = form(
        "warn700",
        &[
            file_part(Some("w.txt"), "text/plain", &payload_700),
            metadata_part("{}"),
        ],
        true,
    );
    success(
        api.upload(
            alice_b,
            "/v1/artifacts?max_bytes=700",
            "alice-warn-1",
            &warn_up,
        ),
        201,
    );
    let s1 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    let storage_warns = |s: &Value| -> Vec<i64> {
        s["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["resource_kind"] == "storage_bytes")
            .map(|w| w["threshold_pct"].as_i64().unwrap())
            .collect()
    };
    assert_eq!(storage_warns(&s1), vec![80]);
    // Bob's summary must not show Alice's warnings or instance warnings.
    let bob_s = success(
        api.call(bob_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert!(
        bob_s["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|w| w["resource_kind"] != "usage_tokens")
    );
    // Edit Alice's storage_bytes override -> bumps limit_revision -> clears old 80% warning & re-arms.
    let ov_path = format!("/v1/admin/scopes/{alice_scope}/quotas/storage_bytes");
    success(
        api.call(
            admin_b,
            "PUT",
            &ov_path,
            Some("ov-rearm-1"),
            Some(&json!({"hard_limit": "2200", "reason": "CANARY-override-reason"})),
        ),
        200,
    );
    let s2 = success(
        api.call(alice_n, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert!(storage_warns(&s2).is_empty());
    assert!(!s2.to_string().contains("CANARY-override-reason"));

    // Cross 80% under the new override revision (1700 + 200 = 1900 / 2200 = 86%).
    let payload_200 = "z".repeat(200);
    let warn_up2 = form(
        "warn200",
        &[
            file_part(Some("z.txt"), "text/plain", &payload_200),
            metadata_part("{}"),
        ],
        true,
    );
    success(
        api.upload(
            alice_b,
            "/v1/artifacts?max_bytes=200",
            "alice-warn-2",
            &warn_up2,
        ),
        201,
    );
    let s3 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(storage_warns(&s3), vec![80]);

    // Revoke override -> retains o.revision (2) as limit_revision while restoring the default
    // 2000-byte limit, re-arming default-level threshold warnings in the same bucket (ADR 0040).
    // Alice is still at 1900/2000 (95% >= 80%), so status remains "warning" with no warning
    // emitted yet at the new limit_revision.
    success(
        api.call(
            admin_n,
            "POST",
            &format!("{ov_path}/revoke"),
            Some("ov-rearm-rev"),
            Some(&json!({"reason": "re-arm check"})),
        ),
        200,
    );
    let s4 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(s4["storage"]["status"], "warning");
    assert!(storage_warns(&s4).is_empty());

    // Config edit (storage_instance.config_revision bump) re-arms warnings for the new threshold.
    limits(&db, Some(2_500), Some(100_000)).await;
    // Alice currently has 1900 bytes; upload 200 -> 2100/2500 = 84% -> triggers 80% under current config_revision.
    success(
        api.upload(
            alice_b,
            "/v1/artifacts?max_bytes=200",
            "alice-warn-cfg-1",
            &warn_up2,
        ),
        201,
    );
    let s_cfg1 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(storage_warns(&s_cfg1), vec![80]);
    // Flapping another small upload within the same UTC day deduplicates the 80% warning (no duplicate entry).
    let tiny = form(
        "tiny10",
        &[
            file_part(Some("t.txt"), "text/plain", "1234567890"),
            metadata_part("{}"),
        ],
        true,
    );
    success(
        api.upload(
            alice_b,
            "/v1/artifacts?max_bytes=10",
            "alice-warn-flap",
            &tiny,
        ),
        201,
    );
    let s_flap = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(storage_warns(&s_flap), vec![80]);
    owner
        .execute("UPDATE openmettle.storage_instance SET warn_pct_1 = 75 WHERE id")
        .await
        .unwrap();
    let s_cfg2 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert!(storage_warns(&s_cfg2).is_empty());

    // Expiring a temporary low storage override clears its warning once the higher default resumes.
    limits(&db, Some(20_000), Some(100_000)).await;
    success(
        api.call(
            admin_b,
            "PUT",
            &ov_path,
            Some("ov-temp-exp"),
            Some(&json!({
                "hard_limit": "2500",
                "expires_at": "2028-01-01T00:00:00.000000Z",
                "reason": "temporary cap"
            })),
        ),
        200,
    );
    success(
        api.upload(
            alice_b,
            "/v1/artifacts?max_bytes=200",
            "alice-warn-temp-exp",
            &warn_up2,
        ),
        201,
    );
    let s_temp_warn = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(s_temp_warn["storage"]["status"], "warning");
    assert_eq!(storage_warns(&s_temp_warn), vec![90]);
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = clock_timestamp() - interval '1 second'
          WHERE scope_id = $1::uuid AND resource_kind = 'storage_bytes'",
    )
    .bind(&alice_scope)
    .execute(&mut owner)
    .await
    .unwrap();
    let s_after_exp = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(s_after_exp["storage"]["limit_source"], "default");
    assert_eq!(s_after_exp["storage"]["status"], "ok");
    assert!(storage_warns(&s_after_exp).is_empty());

    // 5. Hard limit = 0: new upload fails 429 quota, while reads, downloads, retention & quota reads succeed!
    success(
        api.call(
            admin_b,
            "PUT",
            &ov_path,
            Some("ov-zero"),
            Some(&json!({"hard_limit": "0", "reason": "freeze"})),
        ),
        200,
    );
    let (status, prob) = api.upload(
        alice_b,
        "/v1/artifacts?max_bytes=10",
        "blocked-zero",
        &warn_up2,
    );
    assert_eq!(status, 429, "{prob}");
    assert_eq!(
        prob["quota"],
        json!({"resource_kind": "storage_bytes", "scope_kind": "personal"})
    );

    // Quota summary read, artifact read, revision metadata, and content download all stay allowed.
    let s_zero = success(
        api.call(alice_n, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(s_zero["storage"]["status"], "hard_limit");
    assert_eq!(s_zero["storage"]["remaining_bytes"], "0");

    let art_id = alice_rev["artifact_id"].as_str().unwrap();
    let rev_id = alice_rev["revision_id"].as_str().unwrap();
    success(
        api.call(
            alice_b,
            "GET",
            &format!("/v1/artifacts/{art_id}"),
            None,
            None,
        ),
        200,
    );
    success(
        api.call(
            alice_n,
            "GET",
            &format!("/v1/artifacts/{art_id}/revisions/{rev_id}"),
            None,
            None,
        ),
        200,
    );
    let (dl_status, _, dl_bytes) = api.download(
        alice_b,
        "GET",
        &format!("/v1/artifacts/{art_id}/revisions/{rev_id}/content"),
        None,
    );
    assert_eq!((dl_status, dl_bytes.len()), (200, 1000));

    // Retention remains permitted at hard_limit = 0.
    let mut c = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    storage::retain_revision(&mut tx, &alice_scope, rev_id, 3600)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Run cancellation remains permitted even when usage_tokens is over limit and live_runs_per_actor = 0.
    let live_ov = format!("/v1/admin/scopes/{alice_scope}/quotas/live_runs_per_actor");
    success(
        api.call(
            admin_b,
            "PUT",
            &live_ov,
            Some("live-zero"),
            Some(&json!({"hard_limit": "0", "reason": "freeze runs"})),
        ),
        200,
    );
    let conv_id = chat(&db, &alice_scope, "personal", &alice).await;
    let msg_id = message(&mut c, &alice_scope, &conv_id, None).await.unwrap();
    let branch_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&alice_scope)
    .bind(&conv_id)
    .fetch_one(&mut c)
    .await
    .unwrap();
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let run_id = openmettle_core::runs::create_run(
        &mut tx,
        &openmettle_core::runs::RunInput {
            scope: &alice_scope,
            actor: &alice.user,
            conversation: &conv_id,
            branch: &branch_id,
            message: &msg_id,
            key: "cancel-at-hard-limit",
            format: "openmettle.synthetic-run",
            version: 1,
            input: b"{}",
            config: b"{}",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // Restart API with cursor_keys and claim_limits so cancelRun works and QuotaSummary exposes claim defaults.
    let dir = auth_config_support::Dir::new();
    let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    doc["claim_limits"] = json!({
        "executing_per_actor": 3,
        "executing_per_scope": 7
    });
    let api_with_keys = Api::configured(&db, dir, doc, 4);
    let personal_claim = success(
        api_with_keys.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/QuotaSummary",
        &personal_claim
    ));
    assert_eq!(
        personal_claim["execution"]["executing_runs_per_actor"]["limit"],
        "3"
    );
    assert_eq!(
        personal_claim["execution"]["executing_runs_per_actor"]["limit_source"],
        "default"
    );
    assert_eq!(
        personal_claim["execution"]["executing_runs_per_scope"]["limit"],
        "7"
    );
    assert_eq!(
        personal_claim["execution"]["executing_runs_per_scope"]["limit_source"],
        "default"
    );
    let proj_claim = success(
        api_with_keys.call(alice_n, "GET", &proj_path, None, None),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/QuotaSummary",
        &proj_claim
    ));
    assert_eq!(
        proj_claim["execution"]["executing_runs_per_scope"]["limit"],
        "7"
    );
    assert_eq!(
        proj_claim["execution"]["executing_runs_per_scope"]["limit_source"],
        "default"
    );
    assert!(
        proj_claim["execution"]
            .get("executing_runs_per_actor")
            .is_none()
    );
    let cancelled = success(
        api_with_keys.call(
            alice_b,
            "POST",
            &format!("/v1/runs/{run_id}/cancel"),
            Some("cancel-ok"),
            None,
        ),
        200,
    );
    assert_eq!(cancelled["state"], "cancelled");
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn create_run_distinguishes_rate_limited_quota_and_provisioning_refusals_over_http() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (a_b, adm_n) = (browser(&db, &alice, 1).await, native(&db, &admin, 2).await);
    let (alice_b, admin_n) = (As::Browser(&a_b), As::Native(&adm_n));
    let alice_scope = personal_of(&db, &alice).await;

    let dir = auth_config_support::Dir::new();
    let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    let mut catalog: Value =
        serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    let prompt_bound = json!({
        "fixed_tokens": 4,
        "tokens_per_turn": 4,
        "tokens_per_part": 2,
        "tokens_per_byte": 1,
        "tokens_per_attachment": 10
    });
    catalog["models"]["a"]["prompt_bound"] = prompt_bound.clone();
    catalog["models"]["a"]["cost_bound"] = json!({
        "fixed_micros": 0,
        "micros_per_token": 1
    });
    // Model `b` has a qualified prompt bound but intentionally omits `cost_bound`.
    catalog["models"]["b"]["prompt_bound"] = prompt_bound;
    let mut gpu = catalog["models"]["a"].clone();
    gpu["pin"]["revision"] = json!("profile-gpu/1");
    gpu["requires_device_slot"] = json!(true);
    catalog["models"]["gpu"] = gpu;
    doc["catalog_file"] = json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
    doc["admission_limits"] = json!({
        "live_per_actor": 4,
        "live_per_scope": 8,
        "queued_in_instance": 32,
        "queue_timeout_seconds": 300,
        "round_cap": 10
    });
    let api = Api::configured(&db, dir, doc, 4);

    let conv = |key: &str| {
        let root = success(
            api.call(
                alice_b,
                "POST",
                "/v1/conversations",
                Some(key),
                Some(&json!({})),
            ),
            201,
        );
        (
            root["conversation_id"].as_str().unwrap().to_owned(),
            root["branch_id"].as_str().unwrap().to_owned(),
        )
    };
    let (conv_id, branch_id) = conv("conv-q");
    let run_body = |c_id: &str, b_id: &str, msg_id: &str, rounds: i64| {
        json!({
            "conversation_id": c_id,
            "branch_id": b_id,
            "proposal": {
                "expected_head_message_id": null,
                "turn": {
                    "mode": "append",
                    "input_message_id": msg_id,
                    "parts": [{"text": "hello"}]
                },
                "selection": {"preset": "study"},
                "requested_rounds": rounds
            }
        })
    };

    // 0. Fresh DB (metering_enforced = true, zero usage_tokens rows) fails closed with 503 provisioning.
    let (status, fresh_prov) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("run-fresh-unconf"),
        Some(&run_body(
            &conv_id,
            &branch_id,
            "00000000-0000-4000-8000-00000000a000",
            2,
        )),
    );
    assert_eq!(status, 503, "{fresh_prov}");
    assert_eq!(fresh_prov["code"], "provisioning");
    assert_eq!(
        fresh_prov["quota"],
        json!({"resource_kind": "usage_tokens", "scope_kind": "personal"})
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/Problem",
        &fresh_prov
    ));

    // 1. Overridden live_runs_per_actor = 0 -> 429 rate_limited (distinct from quota).
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/live_runs_per_actor"),
            Some("rl-zero"),
            Some(&json!({"hard_limit": "0", "reason": "test rate limit"})),
        ),
        200,
    );
    let (status, rl) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("run-rl"),
        Some(&run_body(
            &conv_id,
            &branch_id,
            "00000000-0000-4000-8000-00000000a001",
            2,
        )),
    );
    assert_eq!(status, 429, "{rl}");
    assert_eq!(rl["code"], "rate_limited");
    assert!(rl.get("quota").is_none());

    // Revoke live_runs_per_actor override, set usage_tokens override to 0 -> 429 quota with closed metadata.
    success(
        api.call(
            admin_n,
            "POST",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/live_runs_per_actor/revoke"),
            Some("rl-rev"),
            Some(&json!({"reason": "restore"})),
        ),
        200,
    );
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens"),
            Some("tok-zero"),
            Some(&json!({"hard_limit": "0", "reason": "CANARY-secret-reason"})),
        ),
        200,
    );
    let (status, q) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("run-q"),
        Some(&run_body(
            &conv_id,
            &branch_id,
            "00000000-0000-4000-8000-00000000a002",
            2,
        )),
    );
    assert_eq!(status, 429, "{q}");
    assert_eq!(q["code"], "quota");
    assert_eq!(
        q["quota"],
        json!({"resource_kind": "usage_tokens", "scope_kind": "personal"})
    );
    assert!(!q.to_string().contains("CANARY-secret-reason"));
    assert!(validate_openapi_schema("#/components/schemas/Problem", &q));

    // 2. Positive headroom smaller than the run's token envelope (8192 * 2 = 16384 > 10000)
    //    must refuse with 429 quota and roll back the run, branch message, and gateway/quota holds.
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens"),
            Some("tok-10k"),
            Some(&json!({"hard_limit": "10000", "reason": "smaller than envelope"})),
        ),
        200,
    );
    let (status, env_ref) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("run-too-big-envelope"),
        Some(&run_body(
            &conv_id,
            &branch_id,
            "00000000-0000-4000-8000-00000000a003",
            2,
        )),
    );
    assert_eq!(status, 429, "{env_ref}");
    assert_eq!(env_ref["code"], "quota");
    assert_eq!(
        env_ref["quota"],
        json!({"resource_kind": "usage_tokens", "scope_kind": "personal"})
    );
    let (runs_n, msgs_n, gw_n, qr_n): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM openmettle.runs),
                (SELECT count(*) FROM openmettle.messages),
                (SELECT count(*) FROM openmettle.gateway_reservations),
                (SELECT count(*) FROM openmettle.quota_reservations)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!((runs_n, msgs_n, gw_n, qr_n), (0, 0, 0, 0));

    // 3. Unconfigured (hard_limit = NULL) usage_cost_micros default must NOT block runs;
    //    two concurrent POST /v1/runs competing for headroom sufficient for 1 (20000 vs 16384 each)
    //    admit at most 1, refuse the other with 429 quota, and exact replay never double-charges.
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_cost_micros', NULL)",
        )
        .await
        .unwrap();
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens"),
            Some("tok-20k"),
            Some(&json!({"hard_limit": "20000", "reason": "headroom for one run"})),
        ),
        200,
    );
    let (conv2_id, branch2_id) = conv("conv-q-2");
    let body_a = run_body(
        &conv_id,
        &branch_id,
        "00000000-0000-4000-8000-00000000a004",
        2,
    );
    let body_b = run_body(
        &conv2_id,
        &branch2_id,
        "00000000-0000-4000-8000-00000000a005",
        2,
    );
    let barrier = std::sync::Barrier::new(2);
    let (res_a, res_b) = std::thread::scope(|s| {
        let b_ref = &barrier;
        let api_ref = &api;
        let ba = &body_a;
        let bb = &body_b;
        let t = s.spawn(move || {
            b_ref.wait();
            api_ref.call(alice_b, "POST", "/v1/runs", Some("race-a"), Some(ba))
        });
        barrier.wait();
        let rb = api.call(alice_b, "POST", "/v1/runs", Some("race-b"), Some(bb));
        (t.join().unwrap(), rb)
    });
    let mut statuses = [res_a.0, res_b.0];
    statuses.sort();
    assert_eq!(statuses, [201, 429], "a={res_a:?} b={res_b:?}");
    let (winner_key, winner_body, winner_val, loser_val) = if res_a.0 == 201 {
        ("race-a", &body_a, &res_a.1, &res_b.1)
    } else {
        ("race-b", &body_b, &res_b.1, &res_a.1)
    };
    assert_eq!(loser_val["code"], "quota");
    assert_eq!(
        loser_val["quota"],
        json!({"resource_kind": "usage_tokens", "scope_kind": "personal"})
    );
    let summary_held = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(summary_held["usage"][0]["reserved_held"], "16384");
    assert_eq!(summary_held["usage"][0]["remaining"], "3616");

    // Exact replay returns 200 OK with the same run_id and does not double-charge reserved_held.
    let replayed = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some(winner_key),
            Some(winner_body),
        ),
        200,
    );
    assert_eq!(replayed["run_id"], winner_val["run_id"]);
    let summary_after_replay = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(summary_after_replay["usage"][0]["reserved_held"], "16384");

    // 3b. Cancelling the queued winning run immediately releases its token hold without a worker
    //     sweep so a fresh 2-round run succeeds immediately.
    let winner_run_id = winner_val["run_id"].as_str().unwrap();
    let cancelled = success(
        api.call(
            alice_b,
            "POST",
            &format!("/v1/runs/{winner_run_id}/cancel"),
            Some("cancel-winner"),
            None,
        ),
        200,
    );
    assert_eq!(cancelled["state"], "cancelled");
    let summary_after_cancel = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(summary_after_cancel["usage"][0]["reserved_held"], "0");
    assert_eq!(summary_after_cancel["usage"][0]["remaining"], "20000");
    let (conv_retry_id, branch_retry_id) = conv("conv-q-retry");
    let retried = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("run-after-cancel"),
            Some(&run_body(
                &conv_retry_id,
                &branch_retry_id,
                "00000000-0000-4000-8000-00000000a015",
                2,
            )),
        ),
        201,
    );
    success(
        api.call(
            alice_b,
            "POST",
            &format!("/v1/runs/{}/cancel", retried["run_id"].as_str().unwrap()),
            Some("cancel-retried"),
            None,
        ),
        200,
    );

    // 4. Configured usage_cost_micros reserves the profile's qualified cost_bound (450 micros per
    //    450-token round, NOT hard_limit=1000), allowing two concurrent 450-micro runs (900 <= 1000)
    //    and refusing a third (900 + 450 > 1000) with 429 quota, while a profile without cost_bound
    //    fails closed with 503 provisioning.
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens"),
            Some("tok-1m"),
            Some(&json!({"hard_limit": "1000000", "reason": "ample tokens"})),
        ),
        200,
    );
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_cost_micros"),
            Some("cost-1000"),
            Some(&json!({"hard_limit": "1000", "reason": "cost ceiling"})),
        ),
        200,
    );
    let cost_body = |c_id: &str, b_id: &str, msg_id: &str, selection: Value| {
        json!({
            "conversation_id": c_id,
            "branch_id": b_id,
            "proposal": {
                "expected_head_message_id": null,
                "turn": {
                    "mode": "append",
                    "input_message_id": msg_id,
                    "parts": [{"text": "hello"}]
                },
                "selection": selection,
                "requested_rounds": 1
            }
        })
    };
    let small_a = json!({
        "model": "a",
        "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
    });
    let (conv3_id, branch3_id) = conv("conv-q-3");
    let (conv4_id, branch4_id) = conv("conv-q-4");
    let (conv5_id, branch5_id) = conv("conv-q-5");
    let cost_run_1 = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("cost-run-1"),
            Some(&cost_body(
                &conv3_id,
                &branch3_id,
                "00000000-0000-4000-8000-00000000a006",
                small_a.clone(),
            )),
        ),
        201,
    );
    let summary_cost_1 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(summary_cost_1["usage"][1]["reserved_held"], "450");
    assert_eq!(summary_cost_1["usage"][1]["remaining"], "550");
    let cost_run_2 = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("cost-run-2"),
            Some(&cost_body(
                &conv4_id,
                &branch4_id,
                "00000000-0000-4000-8000-00000000a007",
                small_a.clone(),
            )),
        ),
        201,
    );
    let summary_cost_2 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(summary_cost_2["usage"][1]["reserved_held"], "900");
    assert_eq!(summary_cost_2["usage"][1]["remaining"], "100");
    let (status, cost_ref) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("cost-run-3"),
        Some(&cost_body(
            &conv5_id,
            &branch5_id,
            "00000000-0000-4000-8000-00000000a016",
            small_a,
        )),
    );
    assert_eq!(status, 429, "{cost_ref}");
    assert_eq!(cost_ref["code"], "quota");
    assert_eq!(
        cost_ref["quota"],
        json!({"resource_kind": "usage_cost_micros", "scope_kind": "personal"})
    );
    // Profile `b` lacks `cost_bound` while usage_cost_micros is configured -> 503 provisioning.
    let (status, unbound_cost) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("cost-unbound-b"),
        Some(&cost_body(
            &conv5_id,
            &branch5_id,
            "00000000-0000-4000-8000-00000000a017",
            json!({"model": "b", "layer": {"controls": {"output_reserve": "256"}}}),
        )),
    );
    assert_eq!(status, 503, "{unbound_cost}");
    assert_eq!(unbound_cost["code"], "provisioning");
    assert_eq!(
        unbound_cost["quota"],
        json!({"resource_kind": "usage_cost_micros", "scope_kind": "instance"})
    );
    // Even when personal usage_cost_micros hard_limit = 0, missing profile cost_bound must still
    // fail closed with 503 provisioning (NOT 429 quota) because qualification precedes capacity.
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_cost_micros"),
            Some("cost-zero-qual"),
            Some(&json!({"hard_limit": "0", "reason": "zero cost ceiling"})),
        ),
        200,
    );
    let (status, unbound_zero) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("cost-unbound-b-zero"),
        Some(&cost_body(
            &conv5_id,
            &branch5_id,
            "00000000-0000-4000-8000-00000000a023",
            json!({"model": "b", "layer": {"controls": {"output_reserve": "256"}}}),
        )),
    );
    assert_eq!(status, 503, "{unbound_zero}");
    assert_eq!(unbound_zero["code"], "provisioning");
    assert_eq!(
        unbound_zero["quota"],
        json!({"resource_kind": "usage_cost_micros", "scope_kind": "instance"})
    );
    for (idx, run) in [cost_run_1, cost_run_2].into_iter().enumerate() {
        success(
            api.call(
                alice_b,
                "POST",
                &format!("/v1/runs/{}/cancel", run["run_id"].as_str().unwrap()),
                Some(&format!("cancel-cost-{idx}")),
                None,
            ),
            200,
        );
    }

    // 4a. Exact HTTP Idempotency-Key replay of a pre-PR3 queued run (missing gateway_reservations
    //     and quota_reservations) backfills both rows cleanly and keeps subsequent replays read-only.
    success(
        api.call(
            admin_n,
            "POST",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_cost_micros/revoke"),
            Some("cost-rev"),
            Some(&json!({"reason": "remove cost override"})),
        ),
        200,
    );
    {
        let (legacy_conv, legacy_branch) = conv("conv-legacy-replay");
        let legacy_msg = "00000000-0000-4000-8000-00000000a024";
        let legacy_body = run_body(&legacy_conv, &legacy_branch, legacy_msg, 1);
        let seed_run = success(
            api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some("legacy-seed-src"),
                Some(&legacy_body),
            ),
            201,
        );
        let seed_id = seed_run["run_id"].as_str().unwrap();
        success(
            api.call(
                alice_b,
                "POST",
                &format!("/v1/runs/{seed_id}/cancel"),
                Some("legacy-seed-cancel"),
                None,
            ),
            200,
        );
        let (input_snap, config_snap): (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT input_snapshot, config_snapshot FROM openmettle.runs WHERE id = $1::uuid",
        )
        .bind(seed_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let replay_client_key = "legacy-http-replay-1";
        let hashed_key: String = framed_digest(
            b"openmettle/v1-idempotency/1\0",
            &[
                b"createRun",
                legacy_conv.as_bytes(),
                replay_client_key.as_bytes(),
            ],
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
        let mut api_c = connect(&db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
        let openmettle_core::authz::runs::Admission::Admitted {
            run_id: legacy_run_id,
            ..
        } = openmettle_core::authz::runs::admit_run(
            &mut tx,
            &openmettle_core::authz::runs::RunAdmission {
                input: openmettle_core::runs::RunInput {
                    scope: &alice_scope,
                    actor: &alice.user,
                    conversation: &legacy_conv,
                    branch: &legacy_branch,
                    message: legacy_msg,
                    key: &hashed_key,
                    format: openmettle_core::model_config::SNAPSHOT_FORMAT,
                    version: openmettle_core::model_config::SNAPSHOT_VERSION,
                    input: &input_snap,
                    config: &config_snap,
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: None,
            },
            &openmettle_core::authz::runs::AdmissionLimits {
                live_per_actor: 4,
                live_per_scope: 8,
                queued_in_instance: 32,
                queue_timeout: Duration::from_secs(300),
                round_cap: 10,
            },
        )
        .await
        .unwrap()
        else {
            panic!("expected legacy queued admission");
        };
        tx.commit().await.unwrap();
        // Verify pre-replay state has no gateway_reservations or quota_reservations for this run.
        let (pre_gw, pre_qr): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM openmettle.gateway_reservations WHERE run_id = $1::uuid),
                    (SELECT count(*) FROM openmettle.quota_reservations WHERE run_id = $1::uuid)",
        )
        .bind(&legacy_run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((pre_gw, pre_qr), (0, 0));
        // Exact replay backfills both gateway_reservations and quota_reservations and returns 200 OK.
        let replayed_legacy = success(
            api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some(replay_client_key),
                Some(&legacy_body),
            ),
            200,
        );
        assert_eq!(replayed_legacy["run_id"], legacy_run_id);
        let (post_gw, post_qr): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM openmettle.gateway_reservations WHERE run_id = $1::uuid),
                    (SELECT count(*) FROM openmettle.quota_reservations WHERE run_id = $1::uuid AND state = 'held')",
        )
        .bind(&legacy_run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((post_gw, post_qr), (1, 1));
        // Second exact replay stays read-only even if personal usage_tokens is lowered to 0.
        success(
            api.call(
                admin_n,
                "PUT",
                &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens"),
                Some("tok-zero-after-backfill"),
                Some(&json!({"hard_limit": "0", "reason": "test read-only replay"})),
            ),
            200,
        );
        let replayed_again = success(
            api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some(replay_client_key),
                Some(&legacy_body),
            ),
            200,
        );
        assert_eq!(replayed_again["run_id"], legacy_run_id);
        success(
            api.call(
                alice_b,
                "POST",
                &format!("/v1/runs/{legacy_run_id}/cancel"),
                Some("cancel-legacy-replayed"),
                None,
            ),
            200,
        );
        success(
            api.call(
                admin_n,
                "PUT",
                &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens"),
                Some("tok-1m-restore"),
                Some(&json!({"hard_limit": "1000000", "reason": "restore tokens"})),
            ),
            200,
        );
    }

    // 4b. Device-slot profiles enforce device_reservations (unconfigured -> 503 provisioning,
    //     0 -> 429 quota, 1 -> admits first, refuses second, cancel frees the slot immediately).
    let gpu_sel = json!({"model": "gpu", "layer": {"controls": {"output_reserve": "256"}}});
    let (status, dev_unconf) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("gpu-unconf"),
        Some(&cost_body(
            &conv5_id,
            &branch5_id,
            "00000000-0000-4000-8000-00000000a018",
            gpu_sel.clone(),
        )),
    );
    assert_eq!(status, 503, "{dev_unconf}");
    assert_eq!(dev_unconf["code"], "provisioning");
    assert_eq!(
        dev_unconf["quota"],
        json!({"resource_kind": "device_reservations", "scope_kind": "personal"})
    );
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/device_reservations"),
            Some("dev-0"),
            Some(&json!({"hard_limit": "0", "reason": "no gpu slots"})),
        ),
        200,
    );
    let (status, dev_zero) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("gpu-zero"),
        Some(&cost_body(
            &conv5_id,
            &branch5_id,
            "00000000-0000-4000-8000-00000000a019",
            gpu_sel.clone(),
        )),
    );
    assert_eq!(status, 429, "{dev_zero}");
    assert_eq!(dev_zero["code"], "quota");
    assert_eq!(
        dev_zero["detail"],
        "The device reservation quota does not allow this request."
    );
    assert_eq!(
        dev_zero["quota"],
        json!({"resource_kind": "device_reservations", "scope_kind": "personal"})
    );
    success(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/device_reservations"),
            Some("dev-1"),
            Some(&json!({"hard_limit": "1", "reason": "one gpu slot"})),
        ),
        200,
    );
    let gpu_run_1 = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("gpu-run-1"),
            Some(&cost_body(
                &conv5_id,
                &branch5_id,
                "00000000-0000-4000-8000-00000000a020",
                gpu_sel.clone(),
            )),
        ),
        201,
    );
    let dev_summary = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(
        dev_summary["device_capacity"]["active_reservations"]["reserved_held"],
        "1"
    );
    let (conv6_id, branch6_id) = conv("conv-q-6");
    let (status, dev_full) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("gpu-run-2-full"),
        Some(&cost_body(
            &conv6_id,
            &branch6_id,
            "00000000-0000-4000-8000-00000000a021",
            gpu_sel.clone(),
        )),
    );
    assert_eq!(status, 429, "{dev_full}");
    assert_eq!(dev_full["code"], "quota");
    assert_eq!(
        dev_full["detail"],
        "The device reservation quota does not allow this request."
    );
    assert_eq!(
        dev_full["quota"],
        json!({"resource_kind": "device_reservations", "scope_kind": "personal"})
    );
    success(
        api.call(
            alice_b,
            "POST",
            &format!("/v1/runs/{}/cancel", gpu_run_1["run_id"].as_str().unwrap()),
            Some("cancel-gpu-1"),
            None,
        ),
        200,
    );
    let dev_after_cancel = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(
        dev_after_cancel["device_capacity"]["active_reservations"]["reserved_held"],
        "0"
    );
    let gpu_run_2 = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("gpu-run-2-ok"),
            Some(&cost_body(
                &conv6_id,
                &branch6_id,
                "00000000-0000-4000-8000-00000000a022",
                gpu_sel,
            )),
        ),
        201,
    );
    success(
        api.call(
            alice_b,
            "POST",
            &format!("/v1/runs/{}/cancel", gpu_run_2["run_id"].as_str().unwrap()),
            Some("cancel-gpu-2"),
            None,
        ),
        200,
    );

    // 5. Revoke personal usage_tokens override while keeping instance default -> 503 provisioning.
    success(
        api.call(
            admin_n,
            "POST",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens/revoke"),
            Some("tok-rev"),
            Some(&json!({"reason": "remove override"})),
        ),
        200,
    );
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('instance', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();
    let (conv7_id, branch7_id) = conv("conv-q-7");
    let (status, prov) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("run-prov"),
        Some(&run_body(
            &conv7_id,
            &branch7_id,
            "00000000-0000-4000-8000-00000000a008",
            1,
        )),
    );
    assert_eq!(status, 503, "{prov}");
    assert_eq!(prov["code"], "provisioning");
    assert_eq!(
        prov["quota"],
        json!({"resource_kind": "usage_tokens", "scope_kind": "personal"})
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/Problem",
        &prov
    ));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn manage_quotas_overrides_enforce_admin_upgrade_gate_idempotency_and_validation() {
    let (db, api) = mounted().await;
    let mut owner = connect(&db.0, OWNER).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (adm_b, adm_n) = (browser(&db, &admin, 1).await, native(&db, &admin, 2).await);
    let (a_b, a_n) = (browser(&db, &alice, 3).await, native(&db, &alice, 4).await);
    let (admin_b, admin_n) = (As::Browser(&adm_b), As::Native(&adm_n));
    let (alice_b, alice_n) = (As::Browser(&a_b), As::Native(&a_n));
    let alice_scope = personal_of(&db, &alice).await;
    let proj = success(
        api.call(
            alice_b,
            "POST",
            "/v1/projects",
            Some("proj-for-admin"),
            Some(&json!({"name": "Admin Quota Target"})),
        ),
        201,
    );
    let proj_scope = proj["scope_id"].as_str().unwrap();

    let tok_path = format!("/v1/admin/scopes/{alice_scope}/quotas/usage_tokens");
    let cost_path = format!("/v1/admin/scopes/{alice_scope}/quotas/usage_cost_micros");
    let missing_path = "/v1/admin/scopes/00000000-0000-4000-8000-000000009999/quotas/usage_tokens";

    // Non-admin refused with 403 policy on both channels.
    for who in [alice_b, alice_n] {
        refused(
            api.call(
                who,
                "PUT",
                &tok_path,
                Some("non-admin-set"),
                Some(&json!({"hard_limit": "100", "reason": "nope"})),
            ),
            403,
            "policy",
        );
        refused(
            api.call(
                who,
                "POST",
                &format!("{tok_path}/revoke"),
                Some("non-admin-rev"),
                Some(&json!({"reason": "nope"})),
            ),
            403,
            "policy",
        );
    }

    // Missing scope -> 404; per-actor on project scope -> 400; OMQ02 -> 503 provisioning.
    refused(
        api.call(
            admin_b,
            "PUT",
            missing_path,
            Some("missing-1"),
            Some(&json!({"hard_limit": "100", "reason": "missing"})),
        ),
        404,
        "not_found",
    );
    refused(
        api.call(
            admin_n,
            "PUT",
            &format!("/v1/admin/scopes/{proj_scope}/quotas/live_runs_per_actor"),
            Some("bad-per-actor"),
            Some(&json!({"hard_limit": "2", "reason": "invalid target"})),
        ),
        400,
        "validation",
    );
    let (status, omq02) = api.call(
        admin_b,
        "PUT",
        &cost_path,
        Some("omq02-1"),
        Some(&json!({"hard_limit": "1000", "reason": "no denom"})),
    );
    assert_eq!(status, 503, "{omq02}");
    assert_eq!(omq02["code"], "provisioning");
    assert_eq!(
        omq02["quota"],
        json!({"resource_kind": "usage_cost_micros", "scope_kind": "instance"})
    );

    // Adoption in progress gates override writes with 503 unavailable.
    owner
        .execute("UPDATE openmettle.storage_volume_control SET adoption_run_id = gen_random_uuid() WHERE id")
        .await
        .unwrap();
    refused(
        api.call(
            admin_b,
            "PUT",
            &tok_path,
            Some("during-adoption"),
            Some(&json!({"hard_limit": "50000", "reason": "blocked"})),
        ),
        503,
        "unavailable",
    );
    owner
        .execute("UPDATE openmettle.storage_volume_control SET adoption_run_id = NULL WHERE id")
        .await
        .unwrap();

    // Audited set, exact replay preserving recorded revision even after a later update, and 409 conflict.
    let body1 = json!({
        "hard_limit": "50000",
        "expires_at": "2028-01-01T00:00:00.000000Z",
        "reason": "CANARY-secret-admin-note"
    });
    let r1 = success(
        api.call(admin_b, "PUT", &tok_path, Some("set-k1"), Some(&body1)),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/QuotaOverride",
        &r1
    ));
    let dec1 = consumer::decode_quota_override(&r1).unwrap();
    assert_eq!((dec1.hard_limit, dec1.revision), (50_000, 1));
    assert!(dec1.revoked_at.is_none());
    assert!(!r1.to_string().contains("CANARY-secret-admin-note"));

    // Exact replay returns identical revision 1 without bumping revision.
    let r1_replay = success(
        api.call(admin_n, "PUT", &tok_path, Some("set-k1"), Some(&body1)),
        200,
    );
    assert_eq!(r1_replay, r1);

    // Second write advances revision to 2; replaying set-k1 still returns original revision 1.
    let body2 = json!({"hard_limit": "75000", "reason": "second bump"});
    let r2 = success(
        api.call(admin_n, "PUT", &tok_path, Some("set-k2"), Some(&body2)),
        200,
    );
    assert_eq!(r2["revision"], "2");
    assert_eq!(
        success(
            api.call(admin_b, "PUT", &tok_path, Some("set-k1"), Some(&body1)),
            200,
        ),
        r1
    );

    // Mismatched payload on set-k1 -> 409 idempotency_conflict.
    refused(
        api.call(
            admin_b,
            "PUT",
            &tok_path,
            Some("set-k1"),
            Some(&json!({"hard_limit": "99999", "reason": "CANARY-secret-admin-note"})),
        ),
        409,
        "idempotency_conflict",
    );

    // Reusing set-k1 on revoke is a distinct operation (ADR 0007 key scoping).
    let rev_body = json!({"reason": "return to defaults"});
    let rev = success(
        api.call(
            admin_b,
            "POST",
            &format!("{tok_path}/revoke"),
            Some("set-k1"),
            Some(&rev_body),
        ),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/QuotaOverride",
        &rev
    ));
    let dec_rev = consumer::decode_quota_override(&rev).unwrap();
    assert_eq!(dec_rev.revision, 3);
    assert!(dec_rev.revoked_at.is_some());

    // Exact replay of revoke returns identical revision 3; changed reason conflicts; new key returns 409 conflict.
    assert_eq!(
        success(
            api.call(
                admin_n,
                "POST",
                &format!("{tok_path}/revoke"),
                Some("set-k1"),
                Some(&rev_body),
            ),
            200,
        ),
        rev
    );
    refused(
        api.call(
            admin_n,
            "POST",
            &format!("{tok_path}/revoke"),
            Some("set-k1"),
            Some(&json!({"reason": "different"})),
        ),
        409,
        "idempotency_conflict",
    );
    refused(
        api.call(
            admin_n,
            "POST",
            &format!("{tok_path}/revoke"),
            Some("rev-again"),
            Some(&rev_body),
        ),
        409,
        "conflict",
    );
    // Revoking a resource with no override row returns 404 not_found.
    refused(
        api.call(
            admin_n,
            "POST",
            &format!("/v1/admin/scopes/{alice_scope}/quotas/device_reservations/revoke"),
            Some("rev-none"),
            Some(&rev_body),
        ),
        404,
        "not_found",
    );
    // Replaying set-k1 AFTER later set AND revoke still returns original recorded revision 1.
    assert_eq!(
        success(
            api.call(admin_b, "PUT", &tok_path, Some("set-k1"), Some(&body1)),
            200,
        ),
        r1
    );
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.authorization_audit
          WHERE actor_user_id = $1::uuid
            AND action IN ('quota.override.set', 'quota.override.revoke')",
    )
    .bind(&admin.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(audit_count, 3);

    // Multibyte UTF-8 reason boundary: 256 UTF-8 bytes accepted, 258 UTF-8 bytes rejected with 400 validation.
    let ok_utf8 = "é".repeat(128);
    let over_utf8 = "é".repeat(129);
    assert_eq!((ok_utf8.len(), over_utf8.len()), (256, 258));
    refused(
        api.call(
            admin_b,
            "PUT",
            &tok_path,
            Some("utf8-over-set"),
            Some(&json!({"hard_limit": "12345", "reason": over_utf8})),
        ),
        400,
        "validation",
    );
    refused(
        api.call(
            admin_b,
            "POST",
            &format!("{tok_path}/revoke"),
            Some("utf8-over-rev"),
            Some(&json!({"reason": over_utf8})),
        ),
        400,
        "validation",
    );
    let utf8_ok = success(
        api.call(
            admin_b,
            "PUT",
            &tok_path,
            Some("utf8-exact-set"),
            Some(&json!({"hard_limit": "12345", "reason": ok_utf8})),
        ),
        200,
    );
    assert_eq!(utf8_ok["revision"], "4");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn extreme_per_round_cost_bound_admits_on_token_only_and_returns_429_when_cost_limited() {
    use crate::{auth_config_support::Dir, ca::Ca};

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice = authz_store::account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_cookie = browser(&db, &alice, 1).await;
    let alice_b = As::Browser(&alice_cookie);

    // Token-only deployment: cost_denomination stays NULL and all usage_cost_micros limits are NULL.
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();

    let dir = Dir::new();
    std::fs::create_dir(dir.path("artifacts")).unwrap();
    let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
    doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    let mut catalog: Value =
        serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    catalog["models"]["a"]["prompt_bound"] = json!({
        "fixed_tokens": 4,
        "tokens_per_turn": 4,
        "tokens_per_part": 2,
        "tokens_per_byte": 1,
        "tokens_per_attachment": 10
    });
    catalog["models"]["a"]["cost_bound"] = json!({
        "fixed_micros": i64::MAX,
        "micros_per_token": 1
    });
    doc["catalog_file"] = json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
    doc["admission_limits"] = json!({
        "live_per_actor": 4,
        "live_per_scope": 8,
        "queued_in_instance": 32,
        "queue_timeout_seconds": 300,
        "round_cap": 10
    });
    let api = Api::configured(&db, dir, doc, 4);

    let conv = success(
        api.call(
            alice_b,
            "POST",
            "/v1/conversations",
            Some("extreme-conv-1"),
            Some(&json!({})),
        ),
        201,
    );
    let make_run = |conv_id: &str, branch_id: &str, msg_id: &str| {
        json!({
            "conversation_id": conv_id,
            "branch_id": branch_id,
            "proposal": {
                "expected_head_message_id": null,
                "turn": {
                    "mode": "append",
                    "input_message_id": msg_id,
                    "parts": [{"text": "extreme per-round cost bound"}]
                },
                "selection": {
                    "model": "a",
                    "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                },
                "requested_rounds": 2
            }
        })
    };

    // 1. Token-only deployment must admit a 2-round fixed_micros=i64::MAX run with 201 Created.
    let admitted = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("extreme-run-token-only"),
            Some(&make_run(
                conv["conversation_id"].as_str().unwrap(),
                conv["branch_id"].as_str().unwrap(),
                "00000000-0000-4000-8000-00000000e001",
            )),
        ),
        201,
    );
    assert!(admitted["run_id"].is_string());

    // 2. Once cost limits are configured, 2 * i64::MAX overflows i64 and must fail with 429 quota
    //    (not 400 validation).
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_cost_micros', 1000000)",
        )
        .await
        .unwrap();
    let conv2 = success(
        api.call(
            alice_b,
            "POST",
            "/v1/conversations",
            Some("extreme-conv-2"),
            Some(&json!({})),
        ),
        201,
    );
    let (status, body) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("extreme-run-cost-limited"),
        Some(&make_run(
            conv2["conversation_id"].as_str().unwrap(),
            conv2["branch_id"].as_str().unwrap(),
            "00000000-0000-4000-8000-00000000e002",
        )),
    );
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["code"], "quota");
    assert_eq!(
        body["detail"],
        "The usage budget does not allow this request."
    );
    assert_eq!(
        body["quota"],
        json!({"resource_kind": "usage_cost_micros", "scope_kind": "personal"})
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn revoked_override_rearms_default_threshold_warnings_over_http() {
    use openmettle_core::{
        runs::WriteTransaction,
        storage::{self, ReservationInput},
    };

    let (db, api) = mounted().await;
    let mut owner = connect(&db.0, OWNER).await;
    let mut api_conn = connect(&db.0, API).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;

    let a_b = browser(&db, &alice, 1).await;
    let adm_b = browser(&db, &admin, 2).await;
    let (alice_b, admin_b) = (As::Browser(&a_b), As::Browser(&adm_b));
    let scope = personal_of(&db, &alice).await;

    // Seed personal defaults: storage_bytes = 1000, usage_tokens = 1000, device_reservations = 10.
    limits(&db, Some(1_000), Some(100_000)).await;
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 1000),
                    ('personal', 'device_reservations', 10)",
        )
        .await
        .unwrap();

    let warnings_for = |summary: &Value, resource: &str| -> Vec<i64> {
        summary["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["resource_kind"] == resource)
            .map(|w| w["threshold_pct"].as_i64().unwrap())
            .collect()
    };

    // 1. Cross default 80% threshold for all three resources -> warnings emitted at limit_revision = 0.
    let mut tx = WriteTransaction::begin(&mut api_conn).await.unwrap();
    let s_res1 = storage::reserve(
        &mut tx,
        &ReservationInput {
            scope: &scope,
            actor: &alice.user,
            key: "rearm-s-1",
            artifact: "00000000-0000-4000-8000-00000000a101",
            max_bytes: 850,
            run: None,
            operation: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let tok_res1: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'usage_tokens', 850, 'rearm-tok-1',
             NULL, NULL, NULL, clock_timestamp() + interval '10 minutes'
         )::text",
    )
    .bind(&scope)
    .bind(&alice.user)
    .fetch_one(&mut api_conn)
    .await
    .unwrap();
    let dev_res1: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'device_reservations', 8, 'rearm-dev-1',
             NULL, NULL, NULL, clock_timestamp() + interval '10 minutes'
         )::text",
    )
    .bind(&scope)
    .bind(&alice.user)
    .fetch_one(&mut api_conn)
    .await
    .unwrap();

    let summary1 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    for resource in ["storage_bytes", "usage_tokens", "device_reservations"] {
        assert_eq!(warnings_for(&summary1, resource), vec![80], "{resource}");
        let revs: Vec<i64> = sqlx::query_scalar(
            "SELECT limit_revision
               FROM openmettle.quota_warning_events
              WHERE scope_id = $1::uuid AND resource_kind = $2 AND threshold_pct = 80
              ORDER BY limit_revision ASC",
        )
        .bind(&scope)
        .bind(resource)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(revs, vec![0], "{resource}");
    }

    // 2. Release holds below 80%, apply higher overrides (revision = 1), then revoke (revision = 2).
    let mut tx_rel = WriteTransaction::begin(&mut api_conn).await.unwrap();
    storage::release(&mut tx_rel, &scope, &s_res1.id)
        .await
        .unwrap();
    tx_rel.commit().await.unwrap();
    for hold_id in [&tok_res1, &dev_res1] {
        let released: bool = sqlx::query_scalar("SELECT openmettle.quota_release_unsent($1::uuid)")
            .bind(hold_id)
            .fetch_one(&mut api_conn)
            .await
            .unwrap();
        assert!(released);
    }

    for (resource, high_limit) in [
        ("storage_bytes", "2000"),
        ("usage_tokens", "2000"),
        ("device_reservations", "20"),
    ] {
        let ov_path = format!("/v1/admin/scopes/{scope}/quotas/{resource}");
        success(
            api.call(
                admin_b,
                "PUT",
                &ov_path,
                Some(&format!("rearm-put-{resource}")),
                Some(&json!({"hard_limit": high_limit, "reason": "temporary bump"})),
            ),
            200,
        );
        success(
            api.call(
                admin_b,
                "POST",
                &format!("{ov_path}/revoke"),
                Some(&format!("rearm-rev-{resource}")),
                Some(&json!({"reason": "restore default"})),
            ),
            200,
        );
        let active_rev: i64 = sqlx::query_scalar(
            "SELECT limit_revision FROM openmettle.quota_limit($1::uuid, 'personal', $2)",
        )
        .bind(&scope)
        .bind(resource)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            active_rev, 2,
            "{resource} revoked override must retain o.revision = 2"
        );
    }

    let summary_between = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert_eq!(summary_between["storage"]["limit_source"], "default");
    assert_eq!(summary_between["storage"]["limit_bytes"], "1000");
    assert!(summary_between["warnings"].as_array().unwrap().is_empty());

    // 3. Cross default 80% threshold again in the SAME bucket -> new quota_warning_events row at
    // limit_revision = 2 for every resource, surfaced by GET /v1/quotas/personal.
    let mut tx2 = WriteTransaction::begin(&mut api_conn).await.unwrap();
    let _s_res2 = storage::reserve(
        &mut tx2,
        &ReservationInput {
            scope: &scope,
            actor: &alice.user,
            key: "rearm-s-2",
            artifact: "00000000-0000-4000-8000-00000000a102",
            max_bytes: 850,
            run: None,
            operation: None,
        },
    )
    .await
    .unwrap();
    tx2.commit().await.unwrap();
    let _: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'usage_tokens', 850, 'rearm-tok-2',
             NULL, NULL, NULL, clock_timestamp() + interval '10 minutes'
         )::text",
    )
    .bind(&scope)
    .bind(&alice.user)
    .fetch_one(&mut api_conn)
    .await
    .unwrap();
    let _: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'device_reservations', 8, 'rearm-dev-2',
             NULL, NULL, NULL, clock_timestamp() + interval '10 minutes'
         )::text",
    )
    .bind(&scope)
    .bind(&alice.user)
    .fetch_one(&mut api_conn)
    .await
    .unwrap();

    let summary2 = success(
        api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
        200,
    );
    assert!(validate_openapi_schema(
        "#/components/schemas/QuotaSummary",
        &summary2
    ));
    for resource in ["storage_bytes", "usage_tokens", "device_reservations"] {
        assert_eq!(
            warnings_for(&summary2, resource),
            vec![80],
            "revoked override must re-arm default 80% warning for {resource}: {summary2}"
        );
        let revs: Vec<i64> = sqlx::query_scalar(
            "SELECT limit_revision
               FROM openmettle.quota_warning_events
              WHERE scope_id = $1::uuid AND resource_kind = $2 AND threshold_pct = 80
              ORDER BY limit_revision ASC",
        )
        .bind(&scope)
        .bind(resource)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            revs,
            vec![0, 2],
            "{resource} must emit a fresh warning row at limit_revision = 2 in the same bucket"
        );
    }
}

#[path = "run_events_http.rs"]
mod run_events_http;
