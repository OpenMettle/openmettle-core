//! ADR 0027 PR4b: the authenticated `/v1` routes through the real API binary, mounted with a
//! version-2 settings document and its native profile, over PostgreSQL 18 as
//! `openmettle_api`. Sessions are seeded as issuance stores them, for the browser cookie
//! channel (with the configured `Origin`) and the native bearer channel. Every response is
//! decoded by the independent contract consumer. The owner role seeds fixtures and reads
//! results. Every value is synthetic.
use super::authz_runs::{
    artifact, chat, framed_digest, personal_of, project_run, seeded_session, state_of,
};
use super::authz_store::{
    Account, FUTURE, PROVIDER, account, ctx, make_admin, present_membership_at, providers,
};
use super::*;
use openmettle_core::authz::store;
use serde_json::{Value, json};

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

/// The API binary with `AUTH_CONFIG`, connected as `openmettle_api` and, for session
/// issuance, as `openmettle_issuance` (ADR 0030). Killed on drop.
struct Api {
    _process: Process,
    _dir: auth_config_support::Dir,
    bind: String,
}

impl Api {
    fn start(db: &TestDb) -> Self {
        let dir = auth_config_support::Dir::new();
        let document = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
        let auth = dir.write("auth.json", document.to_string().as_bytes());
        let bind = address();
        let child = binary("api")
            .env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", db.url(API))
            .env("OPENMETTLE_API_DB_TIMEOUT_MS", "2000")
            .env("OPENMETTLE_API_AUTH_CONFIG", &auth)
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", db.url(ISSUANCE))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut process = Process(child);
        wait_ready(&mut process, &bind);
        Self {
            _process: process,
            _dir: dir,
            bind,
        }
    }

    /// One raw request on a new connection: the status, the lowercase head and the body.
    fn raw(&self, request: &str) -> (u16, String, String) {
        let mut stream = TcpStream::connect(&self.bind).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        (
            head[9..12].parse().unwrap(),
            head.to_ascii_lowercase(),
            body.to_owned(),
        )
    }

    /// One `/v1` request: the status and the JSON body (`null` when empty). Every response
    /// is versioned and uncacheable, and every problem decodes with the contract consumer.
    fn call(
        &self,
        who: As<'_>,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let mut request = format!("{method} {path} HTTP/1.1\r\nhost: app.example.test\r\n");
        match who {
            As::Browser(cookie) => request.push_str(&format!(
                "cookie: __Host-openmettle-session={cookie}\r\norigin: {ORIGIN}\r\n"
            )),
            As::Native(bearer) => {
                request.push_str(&format!("authorization: Bearer {bearer}\r\n"));
            }
        }
        if let Some(key) = key {
            request.push_str(&format!("idempotency-key: {key}\r\n"));
        }
        let body = body.map(Value::to_string).unwrap_or_default();
        if !body.is_empty() {
            request.push_str("content-type: application/json\r\n");
        }
        request.push_str(&format!(
            "content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        ));
        let (status, head, body) = self.raw(&request);
        assert!(head.contains("openmettle-api-version: 1.0"), "{head}");
        assert!(head.contains("cache-control: no-store"), "{head}");
        let json = match body.is_empty() {
            true => Value::Null,
            false => serde_json::from_str(&body).unwrap(),
        };
        if status >= 400 {
            let problem = consumer::decode_problem(&json).unwrap();
            assert_eq!(problem.status, status);
        }
        (status, json)
    }
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
