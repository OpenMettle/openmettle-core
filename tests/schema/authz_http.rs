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

async fn browser(db: &TestDb, account: &Account, n: u8) -> String {
    seeded_session(db, account, n, None).await
}

async fn native(db: &TestDb, account: &Account, n: u8) -> String {
    seeded_session(db, account, n, Some(&audience())).await
}

/// A session credential on its channel.
#[derive(Clone, Copy)]
enum As<'a> {
    Browser(&'a str),
    Native(&'a str),
}

/// The API binary with `AUTH_CONFIG` and `ARTIFACTS_DIR`, connected as `openmettle_api` and,
/// for session issuance, as `openmettle_issuance` (ADR 0030). Killed on drop.
struct Api {
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

    fn configured(
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
    fn call(
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
fn success(response: (u16, Value), status: u16) -> Value {
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

#[path = "run_events_http.rs"]
mod run_events_http;
