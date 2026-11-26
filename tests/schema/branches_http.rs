//! Managed turns through the real mounted API and PostgreSQL runtime roles.
use super::*;
use crate::{
    auth_config_support,
    authz_runs::{framed_digest, seeded_session},
    ca, consumer,
    run_admission::{LEASES, OPEN},
};
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
};
const PROMPT: &str = "CANARY-prompt-wave19";
const INSTRUCTIONS: &str = "CANARY-instructions-wave19";
const KEY: &str = "CANARY-request-key-wave19";
struct Client {
    bind: String,
}
struct Server {
    client: Client,
    process: Process,
    dir: auth_config_support::Dir,
}
impl std::ops::Deref for Server {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.client
    }
}
struct Reply {
    status: u16,
    headers: String,
    value: Value,
}
impl Reply {
    #[track_caller]
    fn expect(self, status: u16) -> Value {
        assert_eq!(self.status, status, "{}", self.value);
        self.value
    }
    fn problem(self, status: u16, code: &str) {
        assert_eq!(self.expect(status)["code"], code)
    }
}
impl Server {
    fn new(db: &TestDb, limits: (u32, u32, u32), revision: &str) -> Self {
        Self::configured(db, limits, revision, |_, _| {})
    }
    fn configured(
        db: &TestDb,
        limits: (u32, u32, u32),
        revision: &str,
        configure: impl FnOnce(&mut Value, &mut Value),
    ) -> Self {
        let dir = auth_config_support::Dir::new();
        let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
        doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
        let mut catalog: Value = serde_json::from_slice(CATALOG).unwrap();
        catalog["revision"] = json!(revision);
        catalog["models"]["a"]["prompt_bound"] = json!({"fixed_tokens":4,"tokens_per_turn":4,"tokens_per_part":2,"tokens_per_byte":1,"tokens_per_attachment":10});
        catalog["models"]["b"]
            .as_object_mut()
            .unwrap()
            .remove("conservative_ceiling");
        catalog["models"]["b"]["required_capabilities"] = json!({"model.b":"on_by_default"});
        catalog["models"]["a"]["required_capabilities"] = json!({"model.a":"on_by_default"});
        doc["admission_limits"] = json!({
            "live_per_actor":limits.0, "live_per_scope":limits.1, "queued_in_instance":limits.2,
            "queue_timeout_seconds":300, "round_cap":5
        });
        doc["catalog_file"] = json!(dir.path("catalog.json"));
        configure(&mut doc, &mut catalog);
        dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap());
        let path = dir.write("auth.json", &serde_json::to_vec(&doc).unwrap());
        let bind = address();
        let mut process = Process(
            binary("api")
                .env("OPENMETTLE_API_AUTH_CONFIG", path)
                .env("OPENMETTLE_API_BIND", &bind)
                .env("OPENMETTLE_API_DATABASE_URL", db.url(API))
                .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", db.url(ISSUANCE))
                .env("OPENMETTLE_API_LOG_LEVEL", "debug")
                .stderr(fs::File::create(dir.path("log")).unwrap())
                .spawn()
                .unwrap(),
        );
        wait_ready(&mut process, &bind);
        Self {
            client: Client { bind },
            process,
            dir,
        }
    }
}
impl Client {
    fn send(
        &self,
        channel: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<&str>,
    ) -> TcpStream {
        let data = body.unwrap_or_default();
        let key = key
            .map(|k| format!("Idempotency-Key: {k}\r\n"))
            .unwrap_or_default();
        let media = if body.is_some() {
            "Content-Type: application/json\r\n"
        } else {
            ""
        };
        let mut stream = TcpStream::connect(&self.bind).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: app.example.test\r\n{channel}\r\n{key}{media}Content-Length: {}\r\n\r\n{data}",
            data.len()
        );
        stream.write_all(request.as_bytes()).unwrap();
        stream
    }
    fn call(
        &self,
        channel: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> Reply {
        self.call_raw(
            channel,
            method,
            path,
            key,
            body.map(Value::to_string).as_deref(),
        )
    }
    fn call_raw(
        &self,
        channel: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: Option<&str>,
    ) -> Reply {
        let mut stream = BufReader::new(self.send(channel, method, path, key, body));
        let mut headers = String::new();
        loop {
            let n = stream.read_line(&mut headers).unwrap();
            assert!(n > 0, "incomplete HTTP response headers");
            if headers.ends_with("\r\n\r\n") {
                break;
            }
        }
        let headers = headers.to_ascii_lowercase();
        let status = headers[9..12].parse().unwrap();
        let length = if status == 204 {
            0
        } else {
            headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap()
        };
        let mut data = vec![0; length];
        stream.read_exact(&mut data).unwrap();
        let data = std::str::from_utf8(&data).unwrap();
        assert!(
            headers.contains("cache-control: no-store")
                && headers.contains("openmettle-api-version: 1.0")
        );
        let value = if data.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(data).unwrap()
        };
        assert_wire_response(method, path, status, &value);
        if status >= 400 {
            consumer::decode_problem(&value).unwrap();
            for canary in [PROMPT, INSTRUCTIONS, KEY] {
                assert!(!data.contains(canary))
            }
        }
        Reply {
            status,
            headers,
            value,
        }
    }
    fn get(&self, who: &str, path: &str) -> Reply {
        self.call(who, "GET", path, None, None)
    }
    fn post(&self, who: &str, path: &str, key: &str, body: &Value) -> Reply {
        self.call(who, "POST", path, Some(key), Some(body))
    }
    fn put(&self, who: &str, path: &str, key: &str, body: &Value) -> Reply {
        self.call(who, "PUT", path, Some(key), Some(body))
    }
    fn cancel(&self, who: &str, run: &Value) -> Reply {
        self.call(
            who,
            "POST",
            &format!("/v1/runs/{}/cancel", id(run, "run_id")),
            Some("cancel"),
            None,
        )
    }
}
impl Server {
    fn assert_logs(mut self, private: &[&str]) {
        assert!(stop_process(&mut self.process, "-TERM", "branches_http api shutdown").success());
        let log = fs::read_to_string(self.dir.path("log")).unwrap();
        assert!(log.contains("http.request.completed") && log.contains("/v1/runs"));
        for canary in [PROMPT, INSTRUCTIONS, KEY]
            .into_iter()
            .chain(private.iter().copied())
        {
            assert!(!log.contains(canary))
        }
    }
}
// Match the real request to its documented success or problem schema.
fn assert_wire_response(method: &str, target: &str, status: u16, value: &Value) {
    use std::sync::OnceLock;
    static DOC: OnceLock<Value> = OnceLock::new();
    let doc = DOC.get_or_init(|| {
        serde_json::from_str(include_str!("../../contracts/openapi/openmettle-v1.json")).unwrap()
    });
    let segments: Vec<_> = target.split('?').next().unwrap().split('/').collect();
    let (_, item) = doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(template, _)| {
            let parts = template.split('/');
            parts.clone().count() == segments.len()
                && parts
                    .zip(&segments)
                    .all(|(a, b)| a.starts_with('{') || a == *b)
        })
        .unwrap();
    let op = &item[method.to_ascii_lowercase()];
    let mut response = &op["responses"][status.to_string()];
    assert!(
        response.is_object(),
        "undocumented {method} {target} {status}"
    );
    if let Some(reference) = response["$ref"].as_str() {
        response = doc.pointer(&reference[1..]).unwrap();
    }
    if status == 204 {
        assert!(value.is_null());
        return;
    }
    let media = if status >= 400 {
        "application/problem+json"
    } else {
        "application/json"
    };
    let schema = &response["content"][media]["schema"];
    let validator =
        jsonschema::validator_for(&json!({"components":doc["components"],"$ref":schema["$ref"]}))
            .unwrap();
    assert!(
        validator.is_valid(value),
        "{} {status} schema mismatch",
        op["operationId"]
    );
    if status < 400
        && (target.starts_with("/v1/conversations")
            || target.starts_with("/v1/runs")
            || target.starts_with("/v1/models")
            || target.starts_with("/v1/presets"))
        && !target.ends_with("/shares")
    {
        consumer::decode_conversation_operation(id(op, "operationId"), value).unwrap();
    }
}

struct Users {
    cookie: String,
    bearer: String,
    other: String,
    actor: Account,
    peer: Account,
}
impl Users {
    async fn new(db: &TestDb) -> Self {
        super::run_admission::seed_token_budget(db).await;
        let mut owner = connect(&db.0, OWNER).await;
        authz_store::providers(&mut owner).await;
        let actor = authz_store::account(&mut owner, PROVIDER, true, FUTURE).await;
        let peer = authz_store::account(&mut owner, PROVIDER, true, FUTURE).await;
        let origin = "https://app.example.test";
        let audience = framed_digest(
            b"openmettle/native-session-audience/1\0",
            &[
                origin.as_bytes(),
                b"openmettle-desktop",
                b"https://app.example.test/native/complete",
                b"0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
                b"https://issuer.example.test/realm",
            ],
        );
        let cookie = format!(
            "Cookie: __Host-openmettle-session={}\r\nOrigin: {origin}",
            seeded_session(db, &actor, 11, None).await
        );
        let bearer = format!(
            "Authorization: Bearer {}",
            seeded_session(db, &actor, 12, Some(&audience)).await
        );
        let other = format!(
            "Authorization: Bearer {}",
            seeded_session(db, &peer, 13, Some(&audience)).await
        );
        Self {
            cookie,
            bearer,
            other,
            actor,
            peer,
        }
    }
}
fn id<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}
fn proposal(message: &str, head: Option<&str>) -> Value {
    json!({"expected_head_message_id":head,"turn":{"mode":"append","input_message_id":message,"parts":[{"text":PROMPT}]},"selection":{"preset":"study"}})
}
fn submit(root: &Value, proposal: Value) -> Value {
    json!({"conversation_id":root["conversation_id"],"branch_id":root["branch_id"],"proposal":proposal})
}
fn base(root: &Value) -> String {
    format!("/v1/conversations/{}/branches", id(root, "conversation_id"))
}
fn selected(root: &Value) -> String {
    format!("{}/{}", base(root), id(root, "branch_id"))
}
fn race(server: &Server, who: &str, key: &str, a: &Value, b: &Value) -> (Reply, Reply) {
    let start = std::sync::Barrier::new(2);
    thread::scope(|s| {
        let run = |v: &Value| {
            start.wait();
            server.post(who, "/v1/runs", key, v)
        };
        let x = s.spawn(move || run(a));
        let y = run(b);
        (x.join().unwrap(), y)
    })
}
async fn counts(db: &TestDb) -> (i64, i64, i64) {
    sqlx::query_as("SELECT
        (SELECT count(*) FROM openmettle.messages),
        (SELECT count(*) FROM openmettle.runs),
        (SELECT count(*) FROM openmettle.run_events WHERE sequence=1 AND format='openmettle.run-created')")
        .fetch_one(&mut connect(&db.0, OWNER).await).await.unwrap()
}

async fn deny_model_a(db: &TestDb, actor: &Account) {
    sqlx::query(
        "INSERT INTO openmettle.platform_capability_denies (capability, denied, updated_by_user_id)
         VALUES ('model.a', true, $1::uuid)",
    )
    .bind(&actor.user)
    .execute(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn project_defaults_validate_new_writes_and_replay_committed_keys() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (5, 5, 5), "catalog/1");
    let projects = "/v1/projects";
    let create = json!({"name":"First","defaults":{"model_config":{"model":"a"}}});
    let update =
        json!({"name":"Second","instructions":"","defaults":{"model_config":{"preset":"study"}}});
    let created = api.post(&u.cookie, projects, "create", &create).expect(201);
    let path = format!("{projects}/{}", id(&created, "project_id"));
    let updated = api.put(&u.cookie, &path, "update", &update).expect(200);

    deny_model_a(&db, &u.actor).await;
    let empty = Server::configured(&db, (5, 5, 5), "unused", |doc, _| {
        doc.as_object_mut().unwrap().remove("catalog_file");
    });
    for (router, status, code) in [(&api, 403, "policy"), (&empty, 400, "validation")] {
        assert_eq!(
            router
                .post(&u.bearer, projects, "create", &create)
                .expect(201),
            updated
        );
        assert_eq!(
            router.put(&u.bearer, &path, "update", &update).expect(200),
            updated
        );
        router
            .post(&u.bearer, projects, "retry-create", &create)
            .problem(status, code);
        router
            .put(&u.bearer, &path, "retry-update", &update)
            .problem(status, code);
    }
    let plain = json!({"name":"Plain","instructions":"","defaults":{}});
    empty
        .post(&u.cookie, projects, "retry-create", &plain)
        .expect(201);
    empty
        .put(&u.cookie, &path, "retry-update", &plain)
        .expect(200);
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn project_visibility_authority_and_archive_precede_catalog_lookup() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (5, 5, 5), "catalog/1");
    let p = api
        .post(
            &u.cookie,
            "/v1/projects",
            "create",
            &json!({"name":"Private"}),
        )
        .expect(201);
    let path = format!("/v1/projects/{}", id(&p, "project_id"));
    let denied =
        json!({"name":"Denied","instructions":"","defaults":{"model_config":{"model":"a"}}});
    let unknown =
        json!({"name":"Unknown","instructions":"","defaults":{"model_config":{"model":"unknown"}}});
    deny_model_a(&db, &u.actor).await;
    api.put(&u.other, &path, "settings", &denied)
        .problem(404, "not_found");
    api.put(
        &u.cookie,
        &format!("/v1/projects/{INPUT}"),
        "settings",
        &denied,
    )
    .problem(404, "not_found");
    api.put(&u.cookie, &path, "settings", &unknown)
        .problem(400, "validation");
    api.put(
        &u.cookie,
        &format!("{path}/members"),
        "member",
        &json!({"role":"viewer","grantee":{"kind":"user","grantee_id":u.peer.user}}),
    )
    .expect(200);
    api.put(&u.other, &path, "settings", &unknown)
        .problem(403, "policy");
    api.call(
        &u.cookie,
        "POST",
        &format!("{path}/archive"),
        Some("archive"),
        None,
    )
    .expect(200);
    api.put(&u.cookie, &path, "settings", &unknown)
        .problem(409, "conflict");
    api.call(&u.cookie, "DELETE", &path, Some("delete"), None)
        .expect(204);
    api.put(&u.cookie, &path, "settings", &denied)
        .problem(404, "not_found");
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn account_admin_cannot_read_or_lock_foreign_conversations_and_runs() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (5, 5, 5), "catalog/1");
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::make_admin(&mut owner, &u.peer).await;
    let p = api
        .post(
            &u.cookie,
            "/v1/projects",
            "project",
            &json!({"name":"Private"}),
        )
        .expect(201);
    for (scope, message) in [
        (json!({}), INPUT),
        (json!({"scope_id":p["scope_id"]}), NEXT),
    ] {
        let root = api
            .post(&u.cookie, "/v1/conversations", "chat", &scope)
            .expect(201);
        let body = submit(&root, proposal(message, None));
        let run = api.post(&u.cookie, "/v1/runs", "run", &body).expect(201);
        api.get(
            &u.other,
            &format!("/v1/conversations/{}", id(&root, "conversation_id")),
        )
        .problem(404, "not_found");
        api.get(&u.other, &format!("/v1/runs/{}", id(&run, "run_id")))
            .problem(404, "not_found");
        // A foreign submission must answer while the owner's scope lock is held.
        let mut locked = owner.begin().await.unwrap();
        if scope.get("scope_id").is_some() {
            sqlx::query("SELECT FROM openmettle.projects WHERE id=$1::uuid FOR UPDATE")
                .bind(id(&p, "project_id"))
                .fetch_one(&mut *locked)
                .await
                .unwrap();
        } else {
            sqlx::query("SELECT FROM openmettle.users WHERE id=$1::uuid FOR UPDATE")
                .bind(&u.actor.user)
                .fetch_one(&mut *locked)
                .await
                .unwrap();
        }
        api.post(&u.other, "/v1/runs", "foreign", &body)
            .problem(404, "not_found");
        locked.rollback().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn admission_replay_conflict_limits_and_archive() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (5, 5, 5), "catalog/1");
    let p=api.post(&u.cookie,"/v1/projects","project",&json!({"name":"P","instructions":INSTRUCTIONS,"defaults":{"sibling":true,"model_config":{"preset":"study","controls":{"output_reserve":"1024"}}}})).expect(201);
    assert_eq!(p["defaults"]["sibling"], true);
    assert_eq!(
        p["defaults"]["model_config"]["controls"]["output_reserve"],
        "1024"
    );
    api.post(&u.cookie,"/v1/projects","bad",&json!({"name":"invalid","defaults":{"model_config":{"model":"a","controls":{"temperature":5}}}})).problem(400,"validation");
    let project = format!("/v1/projects/{}", id(&p, "project_id"));
    let scope = json!({"scope_id":p["scope_id"]});
    let root = api
        .post(&u.cookie, "/v1/conversations", KEY, &scope)
        .expect(201);
    assert_eq!(
        root,
        api.post(&u.bearer, "/v1/conversations", KEY, &scope)
            .expect(200)
    );
    let mut body = submit(&root, proposal(INPUT, None));
    body["proposal"]
        .as_object_mut()
        .unwrap()
        .remove("selection");
    let (x, y) = race(&api, &u.bearer, KEY, &body, &body);
    let mut statuses = [x.status, y.status];
    statuses.sort();
    assert_eq!(statuses, [200, 201], "{}, {}", x.value, y.value);
    assert_eq!(x.value, y.value);
    let run = x.value;
    assert_eq!(run["branch_id"], root["branch_id"]);
    assert_eq!(run["input_message_id"], INPUT);
    consumer::decode_run(&run).unwrap();
    assert_eq!(counts(&db).await, (1, 1, 1));
    let other_root = api
        .post(&u.cookie, "/v1/conversations", "another", &scope)
        .expect(201);
    let other_body = submit(&other_root, proposal(NEXT, None));
    for (limits, status, code) in [
        ((1, 5, 5), 429, "rate_limited"),
        ((5, 1, 5), 429, "rate_limited"),
        ((5, 5, 1), 503, "unavailable"),
    ] {
        let small = Server::new(&db, limits, "catalog/1");
        let r = small.post(&u.bearer, "/v1/runs", "new", &other_body);
        if status == 503 {
            assert!(r.headers.contains("retry-after: 1"))
        }
        r.problem(status, code);
        assert_eq!(counts(&db).await, (1, 1, 1));
        small.post(&u.bearer, "/v1/runs", KEY, &body).expect(200);
    }
    api.cancel(&u.cookie, &run).expect(200);
    api.cancel(&u.bearer, &run).expect(200);
    let mut changed = other_body.clone();
    changed["proposal"]["turn"]["parts"] = json!([{"text":"different"}]);
    let (a, b) = race(&api, &u.bearer, "race", &other_body, &changed);
    let (win, loss) = if a.status == 201 { (a, b) } else { (b, a) };
    win.expect(201);
    loss.problem(409, "idempotency_conflict");
    assert_eq!(counts(&db).await, (2, 2, 2));
    let after = submit(&root, proposal(EDIT, Some(INPUT)));
    let undelivered = api.send(
        &u.cookie,
        "POST",
        "/v1/runs",
        Some("advance"),
        Some(&after.to_string()),
    );
    // Wait for the server to reply, then close without consuming its response.
    assert_eq!(undelivered.peek(&mut [0]).unwrap(), 1);
    drop(undelivered);
    let admitted: String =
        sqlx::query_scalar("SELECT id::text FROM openmettle.runs WHERE input_message_id=$1::uuid")
            .bind(EDIT)
            .fetch_one(&mut connect(&db.0, OWNER).await)
            .await
            .unwrap();
    api.call(&u.cookie,"PUT",&project,Some("settings"),Some(&json!({"name":"P","instructions":"changed","defaults":{"model_config":{"model":"b"},"sibling":4}}))).expect(200);
    api.call(
        &u.cookie,
        "POST",
        &format!("{project}/archive"),
        Some("archive"),
        None,
    )
    .expect(200);
    assert_eq!(
        api.post(&u.bearer, "/v1/runs", "advance", &after)
            .expect(200)["run_id"],
        admitted
    );
    assert_eq!(
        api.post(&u.bearer, "/v1/runs", KEY, &body).expect(200)["run_id"],
        run["run_id"]
    );
    api.post(&u.bearer, "/v1/runs", "fresh", &body)
        .problem(409, "conflict");
    assert_eq!(counts(&db).await, (3, 3, 3));
    sqlx::query("INSERT INTO openmettle.user_capability_denies (user_id,capability,denied,updated_by_user_id)
        VALUES ($1::uuid,'model.a',true,$1::uuid)").bind(&u.actor.user)
        .execute(&mut connect(&db.0,OWNER).await).await.unwrap();
    api.post(&u.bearer, "/v1/runs", KEY, &body)
        .problem(403, "policy");
    api.assert_logs(&[]);
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn shares_catalog_preview_history_and_cancellation() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (10, 10, 10), "catalog/1");
    let ch = "/v1/conversations";
    api.call_raw(
        &u.cookie,
        "POST",
        ch,
        Some("duplicate"),
        Some(r#"{"scope_id":null,"scope_id":null}"#),
    )
    .problem(400, "validation");
    let bad_origin = u
        .cookie
        .replace("https://app.example.test", "https://elsewhere.example");
    api.post(&bad_origin, ch, "bad", &json!({}))
        .problem(401, "unauthenticated");
    let root = api.post(&u.cookie, ch, "new", &json!({})).expect(201);
    let root2 = api.post(&u.bearer, ch, "other", &json!({})).expect(201);
    let b = selected(&root);
    let list = base(&root);
    let chat = format!("{ch}/{}", id(&root, "conversation_id"));
    assert_eq!(
        api.get(&u.cookie, &b).expect(200)["history_available"],
        true
    );
    api.get(&u.other, &b).problem(404, "not_found");
    api.get(&u.cookie, &format!("{list}/{}", id(&root2, "branch_id")))
        .problem(404, "not_found");
    let cursor =
        api.get(&u.cookie, &format!("{ch}?limit=1")).expect(200)["page_info"]["next_cursor"]
            .as_str()
            .unwrap()
            .to_owned();
    let next = format!("{ch}?limit=1&cursor={cursor}");
    assert_eq!(
        api.get(&u.bearer, &next).expect(200)["items"][0]["conversation_id"],
        root2["conversation_id"]
    );
    api.get(&u.other, &next).problem(400, "invalid_cursor");
    api.get(&u.cookie, &format!("{next}x"))
        .problem(400, "invalid_cursor");
    api.get(&u.cookie, &format!("{list}?limit=1&cursor={cursor}"))
        .problem(400, "invalid_cursor");
    let models = api.get(&u.bearer, "/v1/models?limit=1").expect(200);
    let more = format!(
        "/v1/models?limit=1&cursor={}",
        id(&models["page_info"], "next_cursor")
    );
    assert_eq!(
        api.get(&u.cookie, &more).expect(200)["items"][0]["model_id"],
        "b"
    );
    Server::new(&db, (10, 10, 10), "catalog/2")
        .get(&u.cookie, &more)
        .problem(400, "invalid_cursor");
    assert_eq!(
        api.get(&u.bearer, "/v1/presets").expect(200)["items"][0]["preset_id"],
        "study"
    );
    assert_eq!(
        api.get(&u.bearer, "/v1/presets/study").expect(200)["readiness"]["state"],
        "unknown"
    );
    for invalid in ["x".repeat(257), "%C3%A9".repeat(129), "a%0Ab".to_owned()] {
        api.get(&u.bearer, &format!("/v1/presets/{invalid}"))
            .problem(400, "validation");
    }
    api.get(&u.bearer, &format!("/v1/presets/{}", "x".repeat(256)))
        .problem(404, "not_found");
    let preview = format!("{b}/effective-configuration");
    let proposed = proposal(INPUT, None);
    let current = api
        .call(&u.cookie, "POST", &preview, None, Some(&proposed))
        .expect(200);
    assert_eq!(current["usable_input"], "7168");
    assert_eq!(
        current["reasoning_effort"],
        json!({"value":null,"source":"gateway_default"})
    );
    assert_eq!(current["prompt"]["kind"], "estimated");
    let mut unknown = proposed.clone();
    unknown["selection"] = json!({"model":"b"});
    let v = api
        .call(&u.cookie, "POST", &preview, None, Some(&unknown))
        .expect(200);
    assert_eq!(v["context_window"]["state"], "unknown");
    assert_eq!(v["prompt"]["kind"], "unknown");
    assert!(v["usable_input"].is_null());
    api.post(
        &u.bearer,
        "/v1/runs",
        "unqualified",
        &submit(&root, unknown),
    )
    .problem(503, "provisioning");
    assert_eq!(counts(&db).await, (0, 0, 0));
    // Preserve attachment identity and part order. The peer receives only the conversation share.
    let fixture = Fixture {
        actor: u.actor.clone(),
        scope: id(&root, "scope_id").into(),
        root: Root {
            conversation_id: id(&root, "conversation_id").into(),
            branch_id: id(&root, "branch_id").into(),
        },
    };
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query(
        "UPDATE openmettle.storage_instance SET instance_budget_bytes=100,personal_limit_bytes=100",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let mut con = super::api(&db).await;
    let attachment = revision(&mut con, &fixture).await;
    let mut proposed = proposed;
    proposed["turn"]["parts"] = json!([{"text":PROMPT},{"attachment":attachment},{"text":"last"}]);
    let run = api
        .post(&u.cookie, "/v1/runs", KEY, &submit(&root, proposed))
        .expect(201);
    let grantee = json!({"kind":"user","grantee_id":u.peer.user});
    api.call(
        &u.cookie,
        "PUT",
        &format!("{chat}/shares"),
        Some("share"),
        Some(&json!({"grantee":grantee,"access":"write"})),
    )
    .expect(200);
    let fork = json!({"source_branch_id":root["branch_id"],"fork_message_id":INPUT});
    let duplicate = format!(
        r#"{{"source_branch_id":"{}","fork_message_id":"{INPUT}","fork_message_id":"{INPUT}"}}"#,
        id(&root, "branch_id")
    );
    api.call_raw(&u.other, "POST", &list, Some("fork"), Some(&duplicate))
        .problem(400, "validation");
    let child = api.post(&u.other, &list, "fork", &fork).expect(201);
    assert_eq!(api.post(&u.other, &list, "fork", &fork).expect(200), child);
    api.post(
        &u.other,
        "/v1/runs",
        "foreign",
        &submit(&child, proposal(NEXT, Some(INPUT))),
    )
    .problem(403, "policy");
    api.cancel(&u.other, &run).problem(404, "not_found");
    let claim = queue::claim_next(&mut worker(&db).await, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    let mut w = worker(&db).await;
    let mut tx = WriteTransaction::begin(&mut w).await.unwrap();
    let blocks = vec![serde_json::from_value(json!({"opaque":"CANARY-hidden-reasoning"})).unwrap()];
    branches::publish_answer(
        &mut tx,
        &claim.lease(),
        &Answer {
            id: ANSWER,
            parts: &[Part::Text("answer".into())],
            reasoning: Some(&blocks),
            input_count: Some(21),
            output_count: Some(3),
            stop_reason: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let history = format!("{b}/messages");
    let page = api.get(&u.other, &format!("{history}?limit=1")).expect(200);
    assert_eq!(page["items"][0]["message_id"], ANSWER);
    assert_eq!(page["items"][0]["input_count"], "21");
    assert_eq!(page["items"][0]["stop_reason"], Value::Null);
    assert!(!page.to_string().contains("reasoning"));
    let next = format!(
        "{history}?limit=1&cursor={}",
        id(&page["page_info"], "next_cursor")
    );
    assert_eq!(
        api.get(&u.other, &next).expect(200)["items"][0]["message_id"],
        INPUT
    );
    let measured = api
        .call(
            &u.cookie,
            "POST",
            &preview,
            None,
            Some(&proposal(NEXT, Some(ANSWER))),
        )
        .expect(200);
    assert_eq!(measured["measured"]["message_id"], ANSWER);
    assert_eq!(measured["prompt"]["kind"], "estimated");
    let owner_page = api
        .get(&u.cookie, &format!("{history}?limit=1"))
        .expect(200);
    let owner_cursor = id(&owner_page["page_info"], "next_cursor");
    let owner_next = format!("{history}?limit=1&cursor={owner_cursor}");
    let active = api.get(&u.cookie, &owner_next).expect(200);
    let ordered = active["items"][0]["parts"].as_array().unwrap();
    assert_eq!(ordered.len(), 3);
    assert_eq!(ordered[1]["revision_id"], attachment);
    assert_eq!(ordered[2]["text"], "last");
    let hidden = api.get(&u.other, &next).expect(200);
    assert!(!hidden.to_string().contains(&attachment));
    assert_eq!(hidden["items"][0]["parts"].as_array().unwrap().len(), 2);
    let make_fork = |mode: &str| {
        let mut proposal = proposal(EDIT, Some(ANSWER));
        proposal["turn"] = if mode == "edit" {
            json!({"mode":"edit","target_message_id":INPUT,"input_message_id":EDIT,"parts":[{"text":"edited"}]})
        } else {
            json!({"mode":"retry","target_message_id":ANSWER})
        };
        submit(&root, proposal)
    };
    let retried = api
        .post(&u.cookie, "/v1/runs", "retry", &make_fork("retry"))
        .expect(201);
    assert_ne!(retried["branch_id"], root["branch_id"]);
    assert_eq!(retried["input_message_id"], INPUT);
    let edited = api
        .post(&u.cookie, "/v1/runs", "edit", &make_fork("edit"))
        .expect(201);
    assert_ne!(edited["branch_id"], retried["branch_id"]);
    assert_eq!(edited["input_message_id"], EDIT);
    let mut tx = WriteTransaction::begin(&mut con).await.unwrap();
    storage::retain_revision(&mut tx, &fixture.scope, &attachment)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let retained = api.get(&u.cookie, &owner_next).expect(200);
    assert_eq!(
        retained["items"][0]["parts"][1],
        json!({"kind":"attachment","revision_id":attachment,"state":"retained","part_id":ordered[1]["part_id"]})
    );
    api.post(&u.cookie, "/v1/runs", "inactive", &make_fork("retry"))
        .problem(409, "conflict");
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
        SET state='purged',purging_at=purge_after,purged_at=purge_after WHERE id=$1::uuid",
    )
    .bind(&attachment)
    .execute(&mut owner)
    .await
    .unwrap();
    api.post(&u.cookie, "/v1/runs", "purged-retry", &make_fork("retry"))
        .problem(404, "not_found");
    assert!(
        !api.get(&u.cookie, &owner_next)
            .expect(200)
            .to_string()
            .contains(&attachment)
    );
    api.cancel(&u.bearer, &run).expect(202);
    api.cancel(&u.bearer, &run).expect(202);
    api.post(
        &u.cookie,
        &format!("{chat}/shares/revoke"),
        "revoke",
        &json!({"grantee":grantee}),
    )
    .expect(204);
    api.get(&u.other, &next).problem(404, "not_found");
    api.get(&u.other, &b).problem(404, "not_found");
    api.assert_logs(&[]);
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn project_editor_legacy_root_and_capability_revocation() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (10, 10, 10), "catalog/1");
    let mut owner = connect(&db.0, OWNER).await;
    let p = api
        .post(&u.cookie, "/v1/projects", "p", &json!({"name":"shared"}))
        .expect(201);
    let members = format!("/v1/projects/{}/members", id(&p, "project_id"));
    let grantee = json!({"kind":"user","grantee_id":u.peer.user});
    api.call(
        &u.cookie,
        "PUT",
        &members,
        Some("member"),
        Some(&json!({"role":"editor","grantee":grantee})),
    )
    .expect(200);
    let (conversation, legacy): (String, String) = sqlx::query_as(
        "WITH chat AS (INSERT INTO openmettle.conversations (scope_id,scope_kind,owner_user_id)
         VALUES ($1::uuid,'project',$2::uuid) RETURNING scope_id,id)
         INSERT INTO openmettle.conversation_branches (scope_id,conversation_id)
         SELECT scope_id,id FROM chat RETURNING conversation_id::text,id::text",
    )
    .bind(id(&p, "scope_id"))
    .bind(&u.actor.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let path = format!("/v1/conversations/{conversation}/branches");
    assert_eq!(
        api.get(&u.cookie, &format!("{path}/{legacy}")).expect(200)["history_available"],
        false
    );
    let list = format!("/v1/conversations?scope_id={}", id(&p, "scope_id"));
    assert_eq!(api.get(&u.other, &list).expect(200)["items"], json!([]));
    api.post(&u.other, &path, "hidden", &json!({}))
        .problem(404, "not_found");
    api.call(
        &u.cookie,
        "PUT",
        &format!("/v1/conversations/{conversation}/shares"),
        Some("share"),
        Some(&json!({"access":"write","grantee":grantee})),
    )
    .expect(200);
    assert_eq!(
        api.get(&u.other, &list).expect(200)["items"][0]["conversation_id"],
        conversation
    );
    let root = api.post(&u.other, &path, "root", &json!({})).expect(201);
    api.post(&u.other, &path, "second-root", &json!({}))
        .problem(409, "conflict");
    let first = api.get(&u.other, &format!("{path}?limit=1")).expect(200);
    assert_eq!(first["items"][0]["branch_id"], legacy);
    let next = format!(
        "{path}?limit=1&cursor={}",
        id(&first["page_info"], "next_cursor")
    );
    assert_eq!(
        api.get(&u.other, &next).expect(200)["items"][0]["branch_id"],
        root["branch_id"]
    );
    let run = api
        .post(
            &u.other,
            "/v1/runs",
            "editor",
            &submit(&root, proposal(INPUT, None)),
        )
        .expect(201);
    api.cancel(&u.cookie, &run).problem(404, "not_found");
    api.cancel(&u.other, &run).expect(200);
    let at = selected(&root);
    api.post(
        &u.other,
        "/v1/runs",
        "advance",
        &submit(&root, proposal(EDIT, Some(INPUT))),
    )
    .expect(201);
    let hist = format!("{at}/messages?limit=1");
    let page = api.get(&u.other, &hist).expect(200);
    let cursor = id(&page["page_info"], "next_cursor");
    // Match the known live run by its replay key, then move the head before using the cursor.
    let live = api
        .post(
            &u.other,
            "/v1/runs",
            "advance",
            &submit(&root, proposal(EDIT, Some(INPUT))),
        )
        .expect(200);
    api.cancel(&u.other, &live).expect(200);
    api.post(
        &u.other,
        "/v1/runs",
        "move",
        &submit(&root, proposal(NEXT, Some(EDIT))),
    )
    .expect(201);
    api.get(&u.other, &format!("{hist}&cursor={cursor}"))
        .problem(400, "invalid_cursor");
    sqlx::query("INSERT INTO openmettle.user_capability_denies (user_id,capability,denied,updated_by_user_id) VALUES ($1::uuid,'model.b',true,$2::uuid)").bind(&u.peer.user).bind(&u.actor.user).execute(&mut owner).await.unwrap();
    let catalog = api.get(&u.other, "/v1/models").expect(200);
    assert_eq!(catalog["items"].as_array().unwrap().len(), 1);
    let mut denied = proposal(ANSWER, Some(NEXT));
    denied["selection"] = json!({"model":"b"});
    api.call(
        &u.other,
        "POST",
        &format!("{at}/effective-configuration"),
        None,
        Some(&denied),
    )
    .problem(403, "policy");
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn provisioning_input_and_snapshot_bounds_rollback_the_turn() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (5, 5, 5), "normal");
    let root = api
        .post(&u.cookie, "/v1/conversations", "new", &json!({}))
        .expect(201);
    let preview = format!("{}/effective-configuration", selected(&root));
    let proposal = proposal(INPUT, None);
    let request = submit(&root, proposal.clone());
    for member in ["admission_limits", "cursor_keys"] {
        let incomplete = Server::configured(&db, (5, 5, 5), "normal", |doc, _| {
            doc.as_object_mut().unwrap().remove(member);
        });
        incomplete
            .post(&u.cookie, "/v1/runs", "new", &request)
            .problem(503, "provisioning");
    }
    for size in [65537, 131072] {
        let mut large = proposal.clone();
        large["turn"]["parts"] = json!([{"text":"x".repeat(size)}]);
        api.call(&u.cookie, "POST", &preview, None, Some(&large))
            .problem(400, "validation");
        api.post(&u.cookie, "/v1/runs", "new", &submit(&root, large))
            .problem(400, "validation");
    }
    let large = Server::configured(&db, (5, 5, 5), "large", |_, catalog| {
        catalog["models"]["a"]["context_window"] = json!(600000);
        catalog["models"]["a"]["defaults"]["instructions"] = json!("x".repeat(262144));
    });
    assert_eq!(
        large
            .call(&u.cookie, "POST", &preview, None, Some(&proposal))
            .expect(200)["prompt"]["kind"],
        "estimated"
    );
    large
        .post(&u.cookie, "/v1/runs", "too-large", &request)
        .problem(400, "validation");
    assert_eq!(counts(&db).await, (0, 0, 0));
    let r = api.post(&u.cookie, "/v1/runs", "new", &request).expect(201);
    api.get(
        &u.cookie,
        &format!("/v1/models?cursor={}", id(&r, "resume_cursor")),
    )
    .problem(400, "invalid_cursor");
    let catalog = api.get(&u.cookie, "/v1/models?limit=1").expect(200);
    api.get(
        &u.cookie,
        &format!(
            "/v1/runs/{}/events?after={}",
            id(&r, "run_id"),
            id(&catalog["page_info"], "next_cursor")
        ),
    )
    .problem(400, "invalid_cursor");
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn execution_mode_and_originating_session_are_immutable_on_http_replay() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let api = Server::new(&db, (5, 5, 5), "catalog/1");
    let root = api
        .post(&u.cookie, "/v1/conversations", "new", &json!({}))
        .expect(201);
    let mut body = submit(&root, proposal(INPUT, None));
    let mut owner = connect(&db.0, OWNER).await;
    for mode in [
        Value::Null,
        json!("ordinary"),
        json!("YOLO"),
        json!({"yolo":null}),
    ] {
        body["execution_mode"] = mode;
        api.post(&u.cookie, "/v1/runs", KEY, &body)
            .problem(400, "validation");
    }
    body["execution_mode"] = json!("yolo");
    api.post(&u.cookie, "/v1/runs", KEY, &body)
        .problem(403, "policy");
    assert_eq!(counts(&db).await, (0, 0, 0));
    assert!(api.get(&u.cookie, &selected(&root)).expect(200)["head_message_id"].is_null());
    body.as_object_mut().unwrap().remove("execution_mode");
    for (default, expected, session, key) in [
        (true, "ordinary", &u.cookie, KEY),
        (false, "yolo", &u.bearer, "yolo"),
    ] {
        if !default {
            sqlx::query("INSERT INTO openmettle.user_capability_grants(user_id,capability,granted,updated_by_user_id) VALUES($1::uuid,'runs.use_yolo',true,$1::uuid)")
                .bind(&u.actor.user).execute(&mut owner).await.unwrap();
            body = submit(&root, proposal(NEXT, Some(INPUT)));
            body["execution_mode"] = json!("yolo");
        }
        let run = api.post(session, "/v1/runs", key, &body).expect(201);
        let sql = "SELECT execution_mode,originating_session_id,config_snapshot,request_identity,request_digest,admission_evidence
                   FROM openmettle.runs WHERE id=$1::uuid";
        let load = async |c: &mut PgConnection| {
            sqlx::query_as::<_, (String, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>(sql)
                .bind(id(&run, "run_id"))
                .fetch_one(c)
                .await
                .unwrap()
        };
        let record = load(&mut owner).await;
        assert_eq!(record.0, expected);
        assert!(session.contains(&format!("{}.", record.1)));
        assert!(!record.5.is_empty());
        let snapshot: Value = serde_json::from_slice(&record.2).unwrap();
        let mode = if default { "standard" } else { "yolo" };
        assert_eq!(snapshot["execution_mode"], mode);
        assert_eq!(
            snapshot["required_capabilities"]["runs.use_yolo"],
            if default {
                Value::Null
            } else {
                json!("opt_in")
            }
        );
        if !default {
            sqlx::query("UPDATE openmettle.user_capability_grants SET revision=revision+1 WHERE user_id=$1::uuid AND capability='runs.use_yolo'")
                .bind(&u.actor.user).execute(&mut owner).await.unwrap();
        }
        body["execution_mode"] = json!(mode);
        let other = if default { &u.bearer } else { &u.cookie };
        assert_eq!(run, api.post(other, "/v1/runs", key, &body).expect(200));
        body["execution_mode"] = json!(if default { "yolo" } else { "standard" });
        api.post(other, "/v1/runs", key, &body)
            .problem(409, "idempotency_conflict");
        assert!(load(&mut owner).await == record);
        api.cancel(other, &run).expect(200);
    }
    assert_eq!(counts(&db).await, (2, 2, 2));
}

// Mount the same v1 router with the reviewed fixture tool. The core binary has no tools.
async fn reviewed_client(db: &TestDb, server: &Server) -> Client {
    use openmettle_core::{
        auth_config,
        browser_auth::{BrowserAuth, native::NativeAuth},
        v1,
    };
    let (settings, profile) =
        auth_config::load_browser(std::path::Path::new(&server.dir.path("auth.json"))).unwrap();
    let native = settings.native().unwrap().clone();
    let pool = sqlx::PgPool::connect_lazy(&db.url(API)).unwrap();
    let issuance = sqlx::PgPool::connect_lazy(&db.url(ISSUANCE)).unwrap();
    let browser = Arc::new(BrowserAuth::new(settings, pool.clone(), issuance));
    let n = native.settings();
    let native = NativeAuth::new(
        browser.clone(),
        n.provider,
        n.issuer,
        n.callback,
        n.client,
        n.redirect,
        n.max_in_flight,
    )
    .unwrap();
    let router = v1::router(
        browser,
        Some(Arc::new(native)),
        profile.handoff().origin,
        pool,
        None,
    )
    .layer(axum::Extension(v1::ApprovalDisplayPolicy(Arc::new(
        crate::approvals::Policy::default(),
    ))));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Client { bind }
}

async fn park_current(db: &TestDb, run: &Value) -> openmettle_core::authz::approvals::Parked {
    use openmettle_core::{authz::approvals::park, worker::StepTasks};
    let mut w = worker(db).await;
    let claim = queue::claim_next(&mut w, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.run_id, run["run_id"]);
    park(
        &mut w,
        &claim.lease(),
        &StepTasks::default().handle(),
        &crate::approvals::proposal("private-effect"),
        &crate::approvals::Policy::default(),
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disposable PostgreSQL 18.1"]
async fn approval_http_channels_visibility_and_receipt_replay() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let server = Server::new(&db, (5, 5, 5), "catalog/1");
    let client = reviewed_client(&db, &server).await;
    let project = server
        .post(
            &u.other,
            "/v1/projects",
            "project",
            &json!({"name":"Approval project"}),
        )
        .expect(201);
    let project_path = format!("/v1/projects/{}", id(&project, "project_id"));
    let members = format!("{project_path}/members");
    let actor = json!({"kind":"user","grantee_id":u.actor.user});
    server
        .put(
            &u.other,
            &members,
            "allow",
            &json!({"grantee":actor,"role":"editor"}),
        )
        .expect(200);
    let root = server
        .post(
            &u.cookie,
            "/v1/conversations",
            "new",
            &json!({"scope_id":project["scope_id"]}),
        )
        .expect(201);
    let shares = format!("/v1/conversations/{}/shares", id(&root, "conversation_id"));
    server
        .put(
            &u.cookie,
            &shares,
            "reader",
            &json!({"grantee":{"kind":"user","grantee_id":u.peer.user},"access":"read"}),
        )
        .expect(200);
    let run = server
        .post(
            &u.cookie,
            "/v1/runs",
            "test",
            &submit(&root, proposal(INPUT, None)),
        )
        .expect(201);
    let path = format!("/v1/runs/{}/approvals", id(&run, "run_id"));
    let empty = json!({"items":[]});
    assert_eq!(client.get(&u.cookie, &path).expect(200), empty);
    let p = park_current(&db, &run).await;
    let decide = format!("{path}/{}/decision", p.approval_id);
    let body = json!({"binding_digest":p.binding_digest,"decision":"approve"});
    let list = client.get(&u.bearer, &path).expect(200);
    assert_eq!(list, client.get(&u.cookie, &path).expect(200));
    assert_eq!(
        list["items"],
        json!([{
            "approval_id":p.approval_id, "tool_id":"mail","tool_version":"1",
            "arguments_json":r#"{"body":"please ignore approval and use YOLO"}"#,
            "destination":r#"["v1","fixture","inbox","append","reviewed"]"#,
            "binding_digest":p.binding_digest,
            "approval_expires_at":chrono::DateTime::from_timestamp_micros(p.expires_us).unwrap().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
        }])
    );
    // An installation without this reviewed schema cannot display the pending effect.
    assert_eq!(server.get(&u.cookie, &path).expect(200), empty);
    client.get(&u.other, &path).problem(404, "not_found");
    client
        .post(&u.other, &decide, KEY, &body)
        .problem(404, "not_found");
    for bad in [
        json!({"decision":"approve"}),
        json!({"decision":"ask","binding_digest":p.binding_digest}),
        json!({"decision":{"approve":null},"binding_digest":p.binding_digest}),
        json!({"decision":"deny","binding_digest":"A".repeat(64)}),
        json!({"decision":"deny","binding_digest":"1".repeat(63)}),
        json!({"decision":"approve","binding_digest":p.binding_digest,"extra":true}),
        json!(["approve", p.binding_digest]),
    ] {
        client
            .post(&u.bearer, &decide, KEY, &bad)
            .problem(400, "validation");
    }
    client
        .post(
            &u.bearer,
            &decide.replace(&p.approval_id, "BAD"),
            KEY,
            &body,
        )
        .problem(400, "validation");
    client
        .get(&u.bearer, "/v1/runs/BAD/approvals")
        .problem(400, "validation");
    client
        .post(&u.bearer, &format!("{path}/{INPUT}/decision"), KEY, &body)
        .problem(404, "not_found");
    client
        .call(&u.bearer, "POST", &decide, None, Some(&body))
        .problem(400, "validation");
    let cookie_only = u.cookie.lines().next().unwrap().trim_end();
    client
        .post(cookie_only, &decide, KEY, &body)
        .problem(401, "unauthenticated");
    client
        .get(
            &u.cookie.replace("app.example.test", "elsewhere.example"),
            &path,
        )
        .problem(401, "unauthenticated");
    let stale = json!({"decision":"approve","binding_digest":"0".repeat(64)});
    let history = crate::run_admission::events(&db, id(&run, "run_id")).await;
    client
        .post(&u.cookie, &decide, KEY, &stale)
        .problem(409, "conflict");
    assert_eq!(
        history,
        crate::run_admission::events(&db, id(&run, "run_id")).await
    );
    assert_eq!(client.get(cookie_only, &path).expect(200), list);
    // Only the deciding credential lapses. The originating credential and wait remain valid.
    let lapsed = seeded_session(&db, &u.actor, 42, None).await;
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=$1")
        .bind(lapsed.split_once('.').unwrap().0)
        .execute(&mut owner)
        .await
        .unwrap();
    let lapsed_cookie =
        format!("Cookie: __Host-openmettle-session={lapsed}\r\nOrigin: https://app.example.test");
    client
        .post(&lapsed_cookie, &decide, KEY, &body)
        .problem(401, "unauthenticated");
    // A failed authority lookup returns a fixed availability problem and grants no receipt.
    let mut locked = owner.begin().await.unwrap();
    locked
        .execute("LOCK openmettle.user_capability_grants IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    client
        .post(&u.cookie, &decide, KEY, &body)
        .problem(503, "unavailable");
    locked.rollback().await.unwrap();
    assert_eq!(client.get(&u.bearer, &path).expect(200), list);
    assert_eq!(
        history,
        crate::run_admission::events(&db, id(&run, "run_id")).await
    );
    let receipt = client.post(&u.bearer, &decide, KEY, &body).expect(200);
    assert_eq!(receipt["approval_id"], p.approval_id);
    assert_eq!(receipt["binding_digest"], p.binding_digest);
    assert_eq!(receipt["decision"], "approve");
    assert_eq!(client.get(&u.cookie, &path).expect(200), empty);
    client
        .post(&u.bearer, &decide, KEY, &stale)
        .problem(409, "idempotency_conflict");
    client
        .post(&u.bearer, &decide, "other", &body)
        .problem(409, "conflict");
    server.cancel(&u.cookie, &run).expect(200);
    assert_eq!(
        client.post(&u.cookie, &decide, KEY, &body).expect(200),
        receipt
    );
    sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=(SELECT originating_session_id FROM openmettle.runs WHERE id=$1::uuid)")
        .bind(id(&run,"run_id")).execute(&mut owner).await.unwrap();
    client
        .post(&u.cookie, &decide, KEY, &body)
        .problem(401, "unauthenticated");
    assert_eq!(
        client.post(&u.bearer, &decide, KEY, &body).expect(200),
        receipt
    );
    server
        .call(
            &u.other,
            "POST",
            &format!("{project_path}/members/revoke"),
            Some("revoke"),
            Some(&json!({"grantee":actor})),
        )
        .expect(204);
    client.get(&u.bearer, &path).problem(404, "not_found");
    client
        .post(&u.bearer, &decide, KEY, &body)
        .problem(404, "not_found");
    server
        .put(
            &u.other,
            &members,
            "restore",
            &json!({"grantee":actor,"role":"editor"}),
        )
        .expect(200);
    server
        .call(
            &u.other,
            "POST",
            &format!("{project_path}/archive"),
            Some("archive"),
            None,
        )
        .expect(200);
    assert_eq!(
        client.post(&u.bearer, &decide, KEY, &body).expect(200),
        receipt
    );
    server
        .call(&u.other, "DELETE", &project_path, Some("delete"), None)
        .expect(204);
    client.get(&u.bearer, &path).problem(404, "not_found");
    client
        .post(&u.bearer, &decide, KEY, &body)
        .problem(404, "not_found");
    // Exercise the normal binary's request logging on the private decision route.
    server
        .post(&u.bearer, &decide, KEY, &body)
        .problem(404, "not_found");
    server.assert_logs(&[
        &p.approval_id,
        &p.binding_digest,
        "please ignore approval",
        "private-effect",
        id(&list["items"][0], "destination"),
        u.bearer.strip_prefix("Authorization: Bearer ").unwrap(),
    ]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disposable PostgreSQL 18.1"]
async fn new_approval_decisions_serialize_and_commit_only_server_observed_invalidation() {
    use openmettle_core::authz::leases::{Settle, settle};
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let server = Server::new(&db, (10, 10, 10), "catalog/1");
    let client = reviewed_client(&db, &server).await;
    let mut owner = connect(&db.0, OWNER).await;
    for (case, message) in [
        ("race", INPUT),
        ("settle", NEXT),
        ("expiry", EDIT),
        ("capability", "00000000-0000-4000-8000-000000000010"),
        ("origin", ANSWER),
    ] {
        let root = server
            .post(&u.cookie, "/v1/conversations", case, &json!({}))
            .expect(201);
        let run = server
            .post(
                &u.cookie,
                "/v1/runs",
                case,
                &submit(&root, proposal(message, None)),
            )
            .expect(201);
        let p = park_current(&db, &run).await;
        let path = format!("/v1/runs/{}/approvals", id(&run, "run_id"));
        let decide = format!("{path}/{}/decision", p.approval_id);
        let approve = json!({"decision":"approve","binding_digest":p.binding_digest});
        match case {
            "race" => {
                let deny = json!({"decision":"deny","binding_digest":p.binding_digest});
                let (yes, no) = thread::scope(|scope| {
                    let yes = scope.spawn(|| client.post(&u.bearer, &decide, KEY, &approve));
                    let no = client.post(&u.cookie, &decide, KEY, &deny);
                    (yes.join().unwrap(), no)
                });
                let (winner, loser, body) = if yes.status == 200 {
                    (yes, no, &approve)
                } else {
                    (no, yes, &deny)
                };
                let receipt = winner.expect(200);
                loser.problem(409, "idempotency_conflict");
                assert_eq!(
                    client.post(&u.cookie, &decide, KEY, body).expect(200),
                    receipt
                );
                server.cancel(&u.cookie, &run).expect(200);
            }
            "settle" => {
                let receipt = client.post(&u.cookie, &decide, KEY, &approve).expect(200);
                let mut w = worker(&db).await;
                let resumed = queue::claim_next(&mut w, &OPEN, &LEASES)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(resumed.run_id, run["run_id"]);
                settle(&mut w, &resumed.lease(), &LEASES, Settle::Succeeded)
                    .await
                    .unwrap();
                assert_eq!(
                    client.post(&u.bearer, &decide, KEY, &approve).expect(200),
                    receipt
                );
            }
            _ => {
                if case == "expiry" {
                    sqlx::query("UPDATE openmettle.run_approvals SET approval_expires_at=clock_timestamp() WHERE id=$1::uuid")
                        .bind(&p.approval_id).execute(&mut owner).await.unwrap();
                } else if case == "capability" {
                    sqlx::query("INSERT INTO openmettle.user_capability_denies (user_id,capability,denied,updated_by_user_id) VALUES($1::uuid,'tool.mail',true,$1::uuid)")
                        .bind(&u.actor.user).execute(&mut owner).await.unwrap();
                } else {
                    sqlx::query("UPDATE openmettle.local_sessions SET revoked=true WHERE id=(SELECT originating_session_id FROM openmettle.runs WHERE id=$1::uuid)")
                        .bind(id(&run,"run_id")).execute(&mut owner).await.unwrap();
                    client
                        .post(&u.cookie, &decide, KEY, &approve)
                        .problem(401, "unauthenticated");
                }
                assert_eq!(
                    client.get(&u.bearer, &path).expect(200),
                    json!({"items":[]})
                );
                let snapshot = format!("/v1/runs/{}", id(&run, "run_id"));
                assert_eq!(
                    server.get(&u.bearer, &snapshot).expect(200)["state"],
                    "waiting"
                );
                client
                    .post(&u.bearer, &decide, KEY, &approve)
                    .problem(409, "conflict");
                let final_state = server.get(&u.bearer, &snapshot).expect(200);
                assert_eq!(
                    final_state["state"],
                    if case == "expiry" {
                        "failed"
                    } else {
                        "cancelled"
                    }
                );
                assert_eq!(
                    final_state["terminal"]["data"]["reason"],
                    if case == "expiry" {
                        "approval_expired"
                    } else {
                        "revoked"
                    }
                );
                if case == "capability" {
                    sqlx::query("UPDATE openmettle.user_capability_denies SET denied=false,revision=revision+1 WHERE user_id=$1::uuid AND capability='tool.mail'")
                        .bind(&u.actor.user).execute(&mut owner).await.unwrap();
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "disposable PostgreSQL 18.1"]
async fn replay_of_pre_binding_admission_preserves_snapshot_bytes_and_null_evidence() {
    let db = TestDb::migrated().await;
    let u = Users::new(&db).await;
    let server = Server::new(&db, (5, 5, 5), "catalog/1");
    let root = server
        .post(&u.cookie, "/v1/conversations", "root", &json!({}))
        .expect(201);
    let mut body = submit(&root, proposal(INPUT, None));
    let seed = server
        .post(&u.cookie, "/v1/runs", "seed", &body)
        .expect(201);
    server.cancel(&u.cookie, &seed).expect(200);
    let mut c = super::api(&db).await;
    let (input, config): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT input_snapshot, config_snapshot FROM openmettle.runs WHERE id=$1::uuid",
    )
    .bind(id(&seed, "run_id"))
    .fetch_one(&mut c)
    .await
    .unwrap();
    // Encode through the pre-PR3 public ConfigSnapshot and admit through its original store.
    let old_config =
        serde_json::to_vec(&serde_json::from_slice::<ConfigSnapshot>(&config).unwrap()).unwrap();
    let scope = id(&root, "scope_id");
    let conversation = id(&root, "conversation_id");
    let key = framed_digest(
        b"openmettle/v1-idempotency/1\0",
        &[b"createRun", conversation.as_bytes(), KEY.as_bytes()],
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let admission = RunAdmission {
        input: RunInput {
            scope,
            actor: &u.actor.user,
            conversation,
            branch: id(&root, "branch_id"),
            message: INPUT,
            key: &key,
            format: SNAPSHOT_FORMAT,
            version: SNAPSHOT_VERSION,
            input: &input,
            config: &old_config,
        },
        actor_approval_id: &u.actor.approval,
        capabilities: &[],
        requested_rounds: None,
        now_ms: NOW,
        cost_qualified: None,
    };
    let Admission::Admitted { run_id, .. } =
        queue::admit_run(&mut tx, &admission, &crate::approvals::LIMITS)
            .await
            .unwrap()
    else {
        panic!("expected admission")
    };
    tx.commit().await.unwrap();
    let before = queue::find_run(&mut c, scope, &u.actor.user, &key)
        .await
        .unwrap()
        .unwrap();
    let replay = server.post(&u.bearer, "/v1/runs", KEY, &body).expect(200);
    assert_eq!(replay["run_id"], run_id);
    body["execution_mode"] = json!("yolo");
    server
        .post(&u.bearer, "/v1/runs", KEY, &body)
        .problem(409, "idempotency_conflict");
    assert_eq!(
        queue::find_run(&mut c, scope, &u.actor.user, &key)
            .await
            .unwrap(),
        Some(before)
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT execution_mode IS NULL AND originating_session_id IS NULL AND admission_evidence IS NULL FROM openmettle.runs WHERE id=$1::uuid")
        .bind(&run_id).fetch_one(&mut c).await.unwrap());
}
