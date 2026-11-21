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
struct Server {
    bind: String,
    process: Process,
    dir: auth_config_support::Dir,
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
        Self { bind, process, dir }
    }
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
    fn assert_logs(mut self) {
        signal(&self.process.0, "-TERM");
        assert!(self.process.0.wait().unwrap().success());
        let log = fs::read_to_string(self.dir.path("log")).unwrap();
        assert!(log.contains("http.request.completed") && log.contains("/v1/runs"));
        for canary in [PROMPT, INSTRUCTIONS, KEY] {
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
    api.assert_logs();
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
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let history = format!("{b}/messages");
    let page = api.get(&u.other, &format!("{history}?limit=1")).expect(200);
    assert_eq!(page["items"][0]["message_id"], ANSWER);
    assert_eq!(page["items"][0]["input_count"], "21");
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
    storage::retain_revision(&mut tx, &fixture.scope, &attachment, 60)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let retained = api.get(&u.cookie, &owner_next).expect(200);
    assert_eq!(
        retained["items"][0]["parts"][1],
        json!({"kind":"attachment","revision_id":attachment,"state":"retained","part_id":ordered[1]["part_id"]})
    );
    api.post(&u.cookie, "/v1/runs", "inactive", &make_fork("retry"))
        .problem(404, "not_found");
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
        SET state='purged',purging_at=purge_after,purged_at=purge_after WHERE id=$1::uuid",
    )
    .bind(&attachment)
    .execute(&mut owner)
    .await
    .unwrap();
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
    api.assert_logs();
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
