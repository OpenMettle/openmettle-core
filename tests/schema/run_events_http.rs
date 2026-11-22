//! ADR 0034 PR2. Each fixture starts the real API with one primary pool connection.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request,
    body::{Bytes, Incoming},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use openmettle_core::{
    authz::runs as queue,
    runs::{self, Payload},
};
use tokio::net::TcpSocket;

fn replica(db: &TestDb, configure: impl FnOnce(&mut Value)) -> Api {
    let dir = auth_config_support::Dir::new();
    // Event-stream replicas do not serve artifact payloads.
    let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    configure(&mut doc["cursor_keys"]);
    Api::configured(db, dir, doc, 1)
}

struct Fixture {
    api: Api,
    account: Account,
    cookie: String,
    bearer: String,
    project: String,
    scope: String,
    run: String,
    conversation: String,
    db: TestDb,
}
impl Fixture {
    async fn new() -> Self {
        let db = TestDb::migrated().await;
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let account = account(&mut owner, PROVIDER, true, FUTURE).await;
        let cookie = browser(&db, &account, 1).await;
        let bearer = native(&db, &account, 2).await;
        let api = replica(&db, |_| {});
        let p = success(
            api.call(
                As::Browser(&cookie),
                "POST",
                "/v1/projects",
                Some("new"),
                Some(&json!({"name":"Replay"})),
            ),
            201,
        );
        let project = p["project_id"].as_str().unwrap().to_owned();
        let scope = p["scope_id"].as_str().unwrap().to_owned();
        project_run(&db, &scope, &account).await;
        let (run, conversation) = sqlx::query_as(
            "SELECT id::text, conversation_id::text FROM openmettle.runs WHERE scope_id=$1::uuid",
        )
        .bind(&scope)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        Self {
            api,
            account,
            cookie,
            bearer,
            project,
            scope,
            run,
            conversation,
            db,
        }
    }
    fn browser(&self) -> As<'_> {
        As::Browser(&self.cookie)
    }
    fn native(&self) -> As<'_> {
        As::Native(&self.bearer)
    }
    fn path(&self) -> String {
        format!("/v1/runs/{}", self.run)
    }
    fn events(&self) -> String {
        format!("{}/events", self.path())
    }
    fn snapshot(&self) -> Value {
        let value = success(
            self.api
                .call(self.native(), "GET", &self.path(), None, None),
            200,
        );
        consumer::decode_run(&value).unwrap();
        value
    }
    async fn deadline(&self, ms: i64) {
        sqlx::query("UPDATE openmettle.runs SET created_at=clock_timestamp()-interval '1 minute', actor_approval_id=$2::uuid, round_limit=1, queue_expires_at=clock_timestamp()+$3::bigint*interval '1 millisecond' WHERE id=$1::uuid")
            .bind(&self.run).bind(&self.account.approval).bind(ms).execute(&mut connect(&self.db.0, OWNER).await).await.unwrap();
    }
    async fn expire(&self) {
        assert_eq!(
            queue::expire_queued(&mut connect(&self.db.0, WORKER).await, 1)
                .await
                .unwrap(),
            std::slice::from_ref(&self.run)
        );
    }
    async fn start_run(&self) {
        // Both schema versions allow a running fixture without a claim token. Keep the
        // state transition and its event under the same worker transaction and row lock.
        let mut c = connect(&self.db.0, WORKER).await;
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        let token: String = sqlx::query_scalar("UPDATE openmettle.runs SET state='running' WHERE scope_id=$1::uuid AND id=$2::uuid AND state='queued' RETURNING gen_random_uuid()::text")
            .bind(&self.scope).bind(&self.run).fetch_one(tx.connection().unwrap()).await.unwrap();
        runs::append_event(
            &mut tx,
            &self.scope,
            &self.run,
            &format!("claim:{token}"),
            Payload {
                format: "openmettle.run-claimed",
                version: 1,
                bytes: b"{}",
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    async fn hidden(&self) {
        let mut c = connect(&self.db.0, WORKER).await;
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        runs::append_event(
            &mut tx,
            &self.scope,
            &self.run,
            "private",
            Payload {
                format: "openmettle.observation",
                version: 1,
                bytes: b"synthetic private evidence",
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    async fn share(&self, reader: &Account) {
        for (path, data) in [
            (
                format!("/v1/projects/{}/members", self.project),
                member(("user", &reader.user), "viewer"),
            ),
            (
                format!("/v1/conversations/{}/shares", self.conversation),
                shared("user", Some(&reader.user), "read"),
            ),
        ] {
            success(
                self.api
                    .call(self.browser(), "PUT", &path, Some("allow"), Some(&data)),
                200,
            );
        }
    }
}

/// Decode chunked transport with Hyper. SSE blocks may cross transport frames.
struct Stream {
    body: Incoming,
    buffered: Vec<u8>,
}
impl Stream {
    async fn open(api: &Api, who: As<'_>, path: &str, last: Option<&str>) -> Self {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(8192).unwrap();
        let tcp = socket.connect(api.bind.parse().unwrap()).await.unwrap();
        let (mut sender, connection) = http1::handshake(TokioIo::new(tcp)).await.unwrap();
        tokio::spawn(connection);
        let mut req = Request::get(path).header("host", "app.example.test");
        req = match who {
            As::Browser(cookie) => {
                req.header("cookie", format!("__Host-openmettle-session={cookie}"))
            }
            As::Native(bearer) => req.header("authorization", format!("Bearer {bearer}")),
        };
        if let Some(id) = last {
            req = req.header("last-event-id", id);
        }
        let response = sender
            .send_request(req.body(Empty::<Bytes>::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        for (key, value) in [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-store"),
            ("x-accel-buffering", "no"),
            ("openmettle-api-version", "1.0"),
            ("transfer-encoding", "chunked"),
        ] {
            assert_eq!(response.headers()[key], value);
        }
        assert!(!response.headers().contains_key("content-length"));
        let mut stream = Self {
            body: response.into_body(),
            buffered: vec![],
        };
        assert_eq!(stream.block().await.as_deref(), Some(": heartbeat"));
        stream
    }
    async fn block(&mut self) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if let Some(i) = self.buffered.windows(2).position(|b| b == b"\n\n") {
                    let bytes: Vec<_> = self.buffered.drain(..i + 2).collect();
                    return Some(String::from_utf8(bytes[..i].to_vec()).unwrap());
                }
                match self.body.frame().await {
                    Some(part) => self
                        .buffered
                        .extend_from_slice(&part.unwrap().into_data().unwrap()),
                    None => {
                        assert!(self.buffered.is_empty());
                        return None;
                    }
                }
            }
        })
        .await
        .expect("stream did not send a frame or finish")
    }
    async fn next(&mut self) -> Option<(String, Value)> {
        while let Some(block) = self.block().await {
            if let Some(item) = consumer::sse_item(&block) {
                let lines: Vec<_> = block.lines().collect();
                assert_eq!(lines.len(), 2);
                assert!(lines[0].starts_with("id: ") && lines[1].starts_with("data: "));
                consumer::EventCursor::default().apply(&item).unwrap();
                let data = serde_json::from_str(item["data"].as_str().unwrap()).unwrap();
                return Some((item["id"].as_str().unwrap().to_owned(), data));
            }
            assert_eq!(block, ": heartbeat");
        }
        None
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn disconnect_resume_header_precedence_and_repeated_cursor() {
    let f = Fixture::new().await;
    let path = f.events();
    let mut a = Stream::open(&f.api, f.browser(), &path, None).await;
    let (id, created) = a.next().await.unwrap();
    assert_eq!(
        (created["type"].as_str(), created["sequence"].as_str()),
        (Some("run.created"), Some("1"))
    );
    drop(a);
    f.hidden().await;
    f.start_run().await;
    let query = format!("{path}?after={id}");
    let (mut a, mut b) = tokio::join!(
        Stream::open(&f.api, f.native(), &path, Some(&id)),
        Stream::open(&f.api, f.browser(), &query, None)
    );
    let next = a.next().await.unwrap();
    assert_eq!(Some(next.clone()), b.next().await);
    assert_eq!(next.1["sequence"], "3");
    assert_eq!(next.1["type"], "run.started");
    assert_eq!(next.1["data"], json!({}));
    let latest = f.snapshot();
    assert_eq!(latest["resume_cursor"], next.0);
    let newer_url = format!("{path}?after={}", next.0);
    let mut both = Stream::open(&f.api, f.native(), &newer_url, Some(&id)).await;
    assert_eq!(both.next().await.unwrap(), next);
    // All three idle streams leave the only primary connection free for unary traffic.
    assert_eq!(
        success(
            f.api
                .call(f.browser(), "GET", "/v1/capabilities", None, None),
            200
        )["capabilities"],
        json!([])
    );
    for (path, headers) in [
        (format!("{query}&after={}", next.0), String::new()),
        (
            path.clone(),
            format!("last-event-id: {id}\r\nlast-event-id: {}\r\n", next.0),
        ),
    ] {
        let (status, _, body) = f.api.send(f.browser(), "GET", &path, &headers, "");
        refused(decoded(status, &body), 400, "validation");
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn replacement_drains_live_bodies_and_resumes_on_another_replica() {
    let mut f = Fixture::new().await;
    let b = replica(&f.db, |_| {});
    let path = f.events();
    let mut queued = Stream::open(&f.api, f.browser(), &path, None).await;
    let (first, _) = queued.next().await.unwrap();
    f.start_run().await;
    let started = queued.next().await.unwrap();
    let mut running = Stream::open(&f.api, f.native(), &path, Some(&started.0)).await;
    signal(&f.api.process.0, "-TERM");
    assert_eq!(queued.next().await, None);
    assert_eq!(running.next().await, None);
    assert!(f.api.process.0.wait().unwrap().success());
    let mut resumed = Stream::open(&b, f.native(), &path, Some(&first)).await;
    assert_eq!(resumed.next().await.unwrap(), started);
    let snapshot = success(b.call(f.browser(), "GET", &f.path(), None, None), 200);
    assert_eq!(snapshot["state"], "running");
    assert_eq!(snapshot["resume_cursor"], started.0);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn heartbeat_leaves_deadline_untouched_and_terminal_snapshot_matches_replay() {
    let f = Fixture::new().await;
    f.deadline(500).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let version = "SELECT xmin::text FROM openmettle.runs WHERE id=$1::uuid";
    let unchanged: String = sqlx::query_scalar(version)
        .bind(&f.run)
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let before = f.snapshot();
    assert_eq!(before["state"], "queued");
    assert!(before["terminal"].is_null());
    let mut a = Stream::open(
        &f.api,
        f.native(),
        &f.events(),
        before["resume_cursor"].as_str(),
    )
    .await;
    assert_eq!(a.block().await.as_deref(), Some(": heartbeat"));
    assert_eq!(
        sqlx::query_scalar::<_, String>(version)
            .bind(&f.run)
            .fetch_one(&mut owner)
            .await
            .unwrap(),
        unchanged
    );
    f.expire().await;
    let (id, event) = a.next().await.unwrap();
    assert_eq!(event["type"], "run.failed");
    assert_eq!(event["data"], json!({"reason":"queue_expired"}));
    assert!(a.next().await.is_none());
    let snapshot = f.snapshot();
    assert_eq!(snapshot["state"], "failed");
    assert_eq!(snapshot["terminal"], event);
    assert_eq!(snapshot["resume_cursor"], id);
    let mut replay = Stream::open(&f.api, f.browser(), &f.events(), None).await;
    assert_eq!(replay.next().await.unwrap().1["type"], "run.created");
    assert_eq!(replay.next().await, Some((id.clone(), event)));
    assert!(replay.next().await.is_none());
    for method in ["GET", "HEAD"] {
        let (status, _, body) = f.api.send(
            f.browser(),
            method,
            &format!("{}?after={id}", f.events()),
            "",
            "",
        );
        assert_eq!((status, body.as_str()), (204, ""));
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn competing_expiry_and_cancellation_commit_one_terminal_event() {
    let f = Fixture::new().await;
    f.deadline(-1).await;
    let mut api = connect(&f.db.0, API).await;
    let mut worker = connect(&f.db.0, WORKER).await;
    let principal = store::hydrate_api_principal(
        &mut api,
        &f.account.user,
        &f.account.approval,
        db_now(&f.db).await,
    )
    .await
    .unwrap()
    .unwrap();
    let mut stream = Stream::open(
        &f.api,
        f.browser(),
        &f.events(),
        f.snapshot()["resume_cursor"].as_str(),
    )
    .await;
    let (cancel, expired) = tokio::join!(
        queue::cancel_run(&mut api, &principal, &f.scope, &f.run),
        queue::expire_queued(&mut worker, 1)
    );
    let cancelled = matches!(cancel.unwrap(), queue::CancelOutcome::Cancelled);
    assert_ne!(cancelled, expired.unwrap().contains(&f.run));
    let (_, terminal) = stream.next().await.unwrap();
    assert_eq!(
        terminal["type"],
        if cancelled {
            "run.cancelled"
        } else {
            "run.failed"
        }
    );
    let snapshot = f.snapshot();
    assert_eq!(snapshot["terminal"], terminal);
    assert_eq!(snapshot["last_sequence"], "2");
    assert!(stream.next().await.is_none());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn each_revocation_ends_delivery_and_conceals_the_reconnect() {
    for cause in [
        "share",
        "membership",
        "project",
        "disabled",
        "approval",
        "logout",
    ] {
        let f = Fixture::new().await;
        let mut owner = connect(&f.db.0, OWNER).await;
        let reader = account(&mut owner, PROVIDER, true, FUTURE).await;
        let bearer = native(&f.db, &reader, 3).await;
        let who = As::Native(&bearer);
        f.share(&reader).await;
        let path = f.events();
        let mut stream = Stream::open(&f.api, who, &path, None).await;
        let (id, _) = stream.next().await.unwrap();
        match cause {
            "share" => {
                success(
                    f.api.call(
                        f.browser(),
                        "POST",
                        &format!("/v1/conversations/{}/shares/revoke", f.conversation),
                        Some("remove"),
                        Some(&grantee("user", Some(&reader.user))),
                    ),
                    204,
                );
            }
            "membership" => {
                success(
                    f.api.call(
                        f.browser(),
                        "POST",
                        &format!("/v1/projects/{}/members/revoke", f.project),
                        Some("remove"),
                        Some(&grantee("user", Some(&reader.user))),
                    ),
                    204,
                );
            }
            "project" => {
                success(
                    f.api.call(
                        f.browser(),
                        "DELETE",
                        &format!("/v1/projects/{}", f.project),
                        Some("delete"),
                        None,
                    ),
                    204,
                );
            }
            "disabled" => {
                make_admin(&mut owner, &f.account).await;
                store::disable_user(
                    &mut connect(&f.db.0, API).await,
                    &ctx(&f.account, "disable"),
                    &reader.user,
                )
                .await
                .unwrap();
            }
            "approval" => {
                sqlx::query("UPDATE openmettle.local_identity_approvals SET active=false, access_generation=access_generation+1 WHERE id=$1::uuid").bind(&reader.approval).execute(&mut owner).await.unwrap();
            }
            "logout" => {
                assert_eq!(
                    f.api
                        .raw(&Api::head(who, "POST", "/auth/native/logout", "", 0))
                        .0,
                    204
                );
            }
            _ => unreachable!(),
        }
        // Delete already wrote a terminal event with the revocation. Logout also
        // exercises the idle check, without any new row to trigger reauthorization.
        if !matches!(cause, "project" | "logout") {
            f.start_run().await;
        }
        assert_eq!(stream.next().await, None, "{cause}");
        let (status, code) = if matches!(cause, "share" | "membership" | "project") {
            (404, "not_found")
        } else {
            (401, "unauthenticated")
        };
        refused(
            f.api
                .call(who, "GET", &format!("{path}?after={id}"), None, None),
            status,
            code,
        );
        // A malformed cursor cannot confirm that this run exists.
        refused(
            f.api
                .call(who, "GET", &format!("{path}?after=bad!"), None, None),
            status,
            code,
        );
        refused(f.api.call(who, "GET", &f.path(), None, None), status, code);
    }
}

/// Independently sign a synthetic cursor for fields the API would never issue together.
fn signed(scope: &str, run: &str, user: &str, sequence: i64, kind: &[u8]) -> String {
    let kid = b"cursor-b";
    let mut message = b"openmettle/v1-cursor/1\0".to_vec();
    for bytes in [
        kind,
        kid.as_slice(),
        scope.as_bytes(),
        run.as_bytes(),
        user.as_bytes(),
        &sequence.to_be_bytes(),
    ] {
        message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        message.extend_from_slice(bytes);
    }
    let mut raw = vec![1, kid.len() as u8];
    raw.extend_from_slice(kid);
    raw.extend_from_slice(&sequence.to_be_bytes());
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[2; 32]);
    raw.extend_from_slice(ring::hmac::sign(&key, &message).as_ref());
    URL_SAFE_NO_PAD.encode(raw)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn cursors_bind_every_field_and_rotate_between_replicas() {
    let f = Fixture::new().await;
    let id = f.snapshot()["resume_cursor"].as_str().unwrap().to_owned();
    let kind = b"run-events";
    assert_eq!(signed(&f.scope, &f.run, &f.account.user, 1, kind), id);
    let other = account(&mut connect(&f.db.0, OWNER).await, PROVIDER, true, FUTURE).await;
    let cookie = browser(&f.db, &other, 3).await;
    let who = As::Browser(&cookie);
    let path = f.events();
    refused(
        f.api
            .call(who, "GET", &format!("{path}?after={id}"), None, None),
        404,
        "not_found",
    );
    f.share(&other).await;
    refused(
        f.api
            .call(who, "GET", &format!("{path}?after={id}"), None, None),
        400,
        "invalid_cursor",
    );
    for token in [
        signed(&f.project, &f.run, &f.account.user, 1, kind),
        signed(&f.scope, &f.project, &f.account.user, 1, kind),
        signed(&f.scope, &f.run, &f.account.user, 1, b"other"),
        signed(&f.scope, &f.run, &f.account.user, 10, kind),
        signed(&f.scope, &f.run, &f.account.user, -1, kind),
    ] {
        refused(
            f.api.call(
                f.native(),
                "GET",
                &format!("{path}?after={token}"),
                None,
                None,
            ),
            400,
            "invalid_cursor",
        );
    }
    let rotated = |keys: &mut Value| {
        let previous = keys["active"].take();
        keys["active"] = keys["verify_only"][0].take();
        keys["verify_only"] = json!([previous]);
    };
    let new = replica(&f.db, rotated);
    f.start_run().await;
    let mut stream = Stream::open(&new, f.native(), &path, Some(&id)).await;
    let (new_id, started) = stream.next().await.unwrap();
    assert_eq!(started["sequence"], "2");
    assert_eq!(
        success(new.call(f.browser(), "GET", &f.path(), None, None), 200)["resume_cursor"],
        new_id
    );
    let retired = replica(&f.db, |keys| {
        rotated(keys);
        keys["verify_only"] = json!([]);
    });
    refused(
        retired.call(
            f.browser(),
            "GET",
            &format!("{path}?after={id}"),
            None,
            None,
        ),
        400,
        "invalid_cursor",
    );
    assert_eq!(
        retired
            .send(
                f.native(),
                "HEAD",
                &format!("{path}?after={new_id}"),
                "",
                ""
            )
            .0,
        200
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn indexed_batch_seeks_in_a_many_run_history_without_a_sort() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("INSERT INTO openmettle.runs (scope_id,actor_user_id,conversation_id,branch_id,input_message_id,idempotency_key,snapshot_format,snapshot_version,input_snapshot,config_snapshot,request_identity,request_digest,last_event_sequence)
        SELECT r.scope_id,r.actor_user_id,r.conversation_id,r.branch_id,r.input_message_id,'history-'||n,r.snapshot_format,1,r.input_snapshot,r.config_snapshot,r.request_identity,r.request_digest,32
        FROM openmettle.runs r CROSS JOIN generate_series(1,1024) n WHERE r.id=$1::uuid").bind(&f.run).execute(&mut owner).await.unwrap();
    sqlx::query("INSERT INTO openmettle.run_events (scope_id,run_id,sequence,append_key,format,format_version,payload,identity,digest)
        SELECT r.scope_id,r.id,n,'history-'||n,'openmettle.synthetic',1,''::bytea,''::bytea,sha256(''::bytea)
        FROM openmettle.runs r CROSS JOIN generate_series(1,32) n WHERE r.id<>$1::uuid").bind(&f.run).execute(&mut owner).await.unwrap();
    sqlx::query("ANALYZE openmettle.runs")
        .execute(&mut owner)
        .await
        .unwrap();
    sqlx::query("ANALYZE openmettle.run_events")
        .execute(&mut owner)
        .await
        .unwrap();
    // Observe the exact SQL of an idle live stream after its first empty poll.
    // The one primary backend last ran the batch query. Read it as that same role.
    let snapshot = f.snapshot();
    let _stream = Stream::open(
        &f.api,
        f.browser(),
        &f.events(),
        snapshot["resume_cursor"].as_str(),
    )
    .await;
    let mut observer = connect(&f.db.0, API).await;
    let sql: String = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let query = sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid<>pg_backend_pid()
                AND datname=current_database() AND usename=current_user AND state='idle' AND query LIKE 'SELECT r.scope_id%AS events%'")
                .fetch_optional(&mut observer).await.unwrap();
            if let Some(query) = query { break query; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.unwrap();
    assert!(include_str!("../../src/v1/runs.rs").contains(sql.as_str()));
    let explain = AssertSqlSafe(format!("EXPLAIN (FORMAT JSON) {sql}"));
    let row = sqlx::query(explain)
        .bind(&f.run)
        .bind(10_i64)
        .bind(16_i64)
        .fetch_one(&mut connect(&f.db.0, API).await)
        .await
        .unwrap();
    let plan = row.try_get_unchecked::<String, _>(0).unwrap();
    assert!(
        plan.contains("run_events_scope_run_idx") || plan.contains("run_events_pkey"),
        "{plan}"
    );
    assert!(!plan.contains("\"Sort\""), "{plan}");
    assert_eq!(f.snapshot()["last_sequence"], "1");
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn slow_reader_times_out_releases_capacity_and_resumes_without_loss() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let path = f.events();
    let mut stalled = Stream::open(&f.api, f.browser(), &path, None).await;
    let (mut cursor, _) = stalled.next().await.unwrap();
    // Hold the other 127 slots with quiet streams on a separate run. HEAD exercises
    // admission without creating another task or consuming the remaining socket data.
    project_run(&f.db, &f.scope, &f.account).await;
    let idle_run: String =
        sqlx::query_scalar("SELECT id::text FROM openmettle.runs WHERE id<>$1::uuid")
            .bind(&f.run)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let idle_path = format!("/v1/runs/{idle_run}/events");
    let mut idle = Vec::new();
    for _ in 1..128 {
        idle.push(Stream::open(&f.api, f.native(), &idle_path, None).await);
    }
    assert_eq!(f.api.send(f.browser(), "HEAD", &path, "", "").0, 503);
    // Enough compact synthetic claim rows to fill both TCP windows and the eight-frame
    // channel. Insert atomically, leaving the run live so EOF proves a write timeout.
    let total = 50_000_i64;
    let mut tx = owner.begin().await.unwrap();
    sqlx::query(
        "UPDATE openmettle.runs SET state='running', last_event_sequence=$2 WHERE id=$1::uuid",
    )
    .bind(&f.run)
    .bind(total)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("INSERT INTO openmettle.run_events (scope_id,run_id,sequence,append_key,format,format_version,payload,identity,digest)
        SELECT $1::uuid,$2::uuid,n,'claim:'||gen_random_uuid(),'openmettle.run-claimed',1,'{}'::bytea,''::bytea,sha256(''::bytea)
        FROM generate_series(2,$3::bigint) n").bind(&f.scope).bind(&f.run).bind(total).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    // No application reads on the stalled response. A freed permit and successful
    // authorization on the one-connection pool must precede its next read.
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if f.api.send(f.native(), "HEAD", &path, "", "").0 == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "slow reader retained the stream permit"
        );
    }
    assert_eq!(f.snapshot()["last_sequence"], total.to_string());
    drop(idle);
    let mut observer = admin(Some(&f.db.0)).await;
    // On quiet HTTP/1.1 streams, the first Linux TCP write after FIN can elicit RST.
    // EPIPE may surface on the second heartbeat, over 30s after disconnect.
    tokio::time::timeout(Duration::from_secs(45), async {
        let mut empty_since: Option<Instant> = None;
        loop {
            let (total_count, stale_idle_count): (i64, i64) = sqlx::query_as(
                "SELECT count(*),
                        count(*) FILTER (WHERE state='idle' AND state_change <= now() - interval '1 second')
                 FROM pg_stat_activity WHERE datname=current_database() AND usename=$1",
            )
            .bind(API)
            .fetch_one(&mut observer)
            .await
            .unwrap();
            if (total_count, stale_idle_count) == (1, 1) {
                break;
            }
            // Cancellation can close the sole connection. Wait through two 500ms polls
            // so a surviving stream has time to reconnect.
            if total_count == 0 {
                if empty_since.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(1) {
                    break;
                }
            } else {
                empty_since = None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("API pool did not stay idle after the quiet streams disconnected");

    let mut sequence = 1;
    while let Some((id, event)) = stalled.next().await {
        sequence += 1;
        assert_eq!(event["sequence"], sequence.to_string());
        cursor = id;
    }
    assert!(
        sequence < total,
        "expected backpressure before the end of the backlog"
    );
    let mut resumed = Stream::open(&f.api, f.native(), &path, Some(&cursor)).await;
    while sequence < total {
        sequence += 1;
        assert_eq!(
            resumed.next().await.unwrap().1["sequence"],
            sequence.to_string()
        );
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn legacy_terminal_and_malformed_terminal_payload_fail_closed() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.runs SET state='cancelled' WHERE id=$1::uuid")
        .bind(&f.run)
        .execute(&mut owner)
        .await
        .unwrap();
    let legacy = f.snapshot();
    assert_eq!(legacy["state"], "cancelled");
    assert!(legacy["terminal"].is_null());
    let mut replay = Stream::open(&f.api, f.browser(), &f.events(), None).await;
    assert_eq!(replay.next().await.unwrap().1["type"], "run.created");
    assert!(replay.next().await.is_none());

    let mut tx = WriteTransaction::begin(&mut owner).await.unwrap();
    runs::append_event(
        &mut tx,
        &f.scope,
        &f.run,
        "run-terminal",
        Payload {
            format: "openmettle.run-cancelled",
            version: 1,
            bytes: br#"{"reason":"private synthetic detail"}"#,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    refused(
        f.api.call(f.native(), "GET", &f.path(), None, None),
        500,
        "internal",
    );
    let mut corrupt = Stream::open(
        &f.api,
        f.browser(),
        &f.events(),
        legacy["resume_cursor"].as_str(),
    )
    .await;
    assert!(corrupt.next().await.is_none());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn shared_reader_replays_only_public_approval_transitions_and_terminal_reasons() {
    use crate::{
        approvals::{Policy, proposal},
        run_admission::{LEASES, OPEN},
    };
    use openmettle_core::{
        authz::approvals::{self, DecisionInput, EffectSession, HumanDecision},
        sessions,
        worker::StepTasks,
    };

    let mut f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let reader = account(&mut owner, PROVIDER, true, FUTURE).await;
    f.share(&reader).await;
    let token = browser(&f.db, &reader, 3).await;
    let channel = As::Browser(&token);
    let mut api = connect(&f.db.0, API).await;
    let session = EffectSession::validate(
        &mut api,
        &f.cookie,
        &sessions::Policy::new(Duration::from_secs(60), 10, Duration::from_secs(3)).unwrap(),
        None,
    )
    .await
    .unwrap();

    // Admit a session-bound run on the shared conversation. The original fixture row
    // predates the queue deadline and cannot be claimed.
    let (branch, message): (String, String) = sqlx::query_as(
        "SELECT branch_id::text,input_message_id::text FROM openmettle.runs WHERE id=$1::uuid",
    )
    .bind(&f.run)
    .fetch_one(&mut api)
    .await
    .unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let admission = queue::admit_run_with_mode(
        &mut tx,
        &queue::RunAdmission {
            input: runs::RunInput {
                scope: &f.scope,
                actor: session.user_id(),
                conversation: &f.conversation,
                branch: &branch,
                message: &message,
                key: "approval-events",
                format: "fixture.run",
                version: 1,
                input: b"fixture",
                config: br#"{"execution_mode":"standard"}"#,
            },
            actor_approval_id: session.approval_id(),
            capabilities: &[],
            requested_rounds: None,
            now_ms: session.observed_ms(),
        },
        &crate::approvals::LIMITS,
        &session,
    )
    .await
    .unwrap();
    let queue::Admission::Admitted { run_id, .. } = admission else {
        panic!("expected admission")
    };
    tx.commit().await.unwrap();
    f.run = run_id;
    let mut w = connect(&f.db.0, WORKER).await;
    let policy = Policy::default();
    let r = queue::claim_next(&mut w, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    let p = approvals::park(
        &mut w,
        &r.lease(),
        &StepTasks::default().handle(),
        &proposal("private-operation"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let path = f.events();
    let mut first = Stream::open(&f.api, channel, &path, None).await;
    let mut cursor = String::new();
    for (i, kind) in [
        "run.created",
        "run.started",
        "run.approval_requested",
        "run.waiting",
    ]
    .iter()
    .enumerate()
    {
        let (id, event) = first.next().await.unwrap();
        assert_eq!(event["type"], *kind);
        assert_eq!(event["sequence"], (i + 1).to_string());
        assert_eq!(
            event["data"],
            if *kind == "run.waiting" {
                json!({"reason":"approval"})
            } else {
                json!({})
            }
        );
        assert_eq!(event.as_object().unwrap().len(), 6);
        cursor = id;
    }
    drop(first);
    let hidden = f.api.call(
        channel,
        "GET",
        &format!("{}/approvals", f.path()),
        None,
        None,
    );
    refused(hidden, 404, "not_found");
    f.hidden().await;
    approvals::decide(
        &mut api,
        &session,
        &DecisionInput {
            scope: &f.scope,
            run: &f.run,
            approval: &p.approval_id,
            decision: HumanDecision::Approve,
            binding_digest: &p.binding_digest,
            idempotency_key: "private-decision-key",
        },
        &policy,
    )
    .await
    .unwrap();
    let resumed = queue::claim_next(&mut w, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    let mut stream = Stream::open(&f.api, channel, &path, Some(&cursor)).await;
    for (seq, kind) in [("6", "run.approval_decided"), ("7", "run.resumed")] {
        let (id, event) = stream.next().await.unwrap();
        assert_eq!(event["type"], kind);
        assert_eq!(event["sequence"], seq);
        assert_eq!(event["data"], json!({}));
        for private in [
            &p.approval_id,
            &p.binding_digest,
            session.locator(),
            &resumed.claim_token,
            "private-operation",
            "please ignore",
            "inbox",
            "private-decision-key",
        ] {
            assert!(!event.to_string().contains(private));
        }
        cursor = id;
    }
    drop(stream);
    // An approved call that has not started its intent expires under the resumed step fence.
    sqlx::query("UPDATE openmettle.run_approvals SET approval_expires_at=clock_timestamp() WHERE id=$1::uuid")
        .bind(&p.approval_id).execute(&mut owner).await.unwrap();
    approvals::record_fenced_intent(
        &mut w,
        &resumed.lease(),
        &proposal("private-operation"),
        Some(&p.approval_id),
        &policy,
        &LEASES,
    )
    .await
    .unwrap();
    let mut replay = Stream::open(&f.api, channel, &path, Some(&cursor)).await;
    let (_, terminal) = replay.next().await.unwrap();
    assert_eq!(terminal["type"], "run.failed");
    assert_eq!(terminal["data"], json!({"reason":"approval_expired"}));
    assert_eq!(f.snapshot()["terminal"], terminal);
    assert!(replay.next().await.is_none());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for disposable PostgreSQL 18"]
async fn invalid_wait_failure_snapshot_matches_reconnected_stream() {
    let f = Fixture::new().await;
    let cursor = f.snapshot()["resume_cursor"].as_str().unwrap().to_owned();
    sqlx::query("UPDATE openmettle.runs SET state='waiting' WHERE id=$1::uuid")
        .bind(&f.run)
        .execute(&mut connect(&f.db.0, OWNER).await)
        .await
        .unwrap();
    openmettle_core::authz::approvals::expire_waits(&mut connect(&f.db.0, WORKER).await, 1)
        .await
        .unwrap();
    let mut replay = Stream::open(&f.api, f.native(), &f.events(), Some(&cursor)).await;
    let (last, event) = replay.next().await.unwrap();
    assert!(replay.next().await.is_none());
    let snapshot = f.snapshot();
    assert_eq!(snapshot["state"], "failed");
    assert_eq!(snapshot["resume_cursor"], last);
    assert_eq!(snapshot["terminal"], event);
    assert_eq!(event["type"], "run.failed");
    assert_eq!(event["data"], json!({"reason":"invalid_wait"}));
}
