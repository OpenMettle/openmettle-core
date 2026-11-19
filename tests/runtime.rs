//! Black-box process tests. Real PostgreSQL is required only by the ignored test.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "auth_config_support/mod.rs"]
mod auth_config_support;
// The transport fixture's synthetic CA; its leaf certificates are not needed here.
#[allow(dead_code)]
#[path = "provider_http_support/ca.rs"]
mod ca;

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn command(worker: bool) -> Command {
    let mut command = Command::new(if worker {
        env!("CARGO_BIN_EXE_openmettle-worker")
    } else {
        env!("CARGO_BIN_EXE_openmettle-api")
    });
    // Do not inherit deployment configuration or libpq defaults.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("OPENMETTLE_") || name.starts_with("PG") {
            command.env_remove(key);
        }
    }
    command
}
fn start(worker: bool, address: &str, url: &str) -> Process {
    // Healthy-service checks use the application's normal database deadline.
    start_with_timeout(worker, address, url, 2000)
}
fn start_with_timeout(worker: bool, address: &str, url: &str, timeout_ms: u64) -> Process {
    let prefix = if worker {
        "OPENMETTLE_WORKER"
    } else {
        "OPENMETTLE_API"
    };
    Process(
        command(worker)
            .env(format!("{prefix}_BIND"), address)
            .env(format!("{prefix}_DATABASE_URL"), url)
            .env(format!("{prefix}_DB_TIMEOUT_MS"), timeout_ms.to_string())
            .env(format!("{prefix}_SHUTDOWN_TIMEOUT_MS"), "1000")
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn response(address: &str, path: &str) -> std::io::Result<String> {
    send(
        address,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
}
fn send(address: &str, request: &str) -> std::io::Result<String> {
    let mut stream =
        TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(300))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}
fn wait_status(process: &mut Process, address: &str, path: &str, code: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "process exited before health check"
        );
        if response(address, path).is_ok_and(|r| r.starts_with(&format!("HTTP/1.1 {code}"))) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "health check deadline: {path} expected {code}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
fn stop(process: &mut Process, signal: &str) {
    assert!(
        Command::new("kill")
            .args([signal, &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        assert!(Instant::now() < deadline, "shutdown did not finish");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn rejects_invalid_config_without_disclosing_values() {
    for worker in [false, true] {
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        for (key, value) in [
            ("DATABASE_URL", "invalid://synthetic-secret"),
            ("BIND", "synthetic-secret"),
            ("DB_MAX_CONNECTIONS", "0"),
            ("DB_TIMEOUT_MS", "30001"),
            ("SHUTDOWN_TIMEOUT_MS", "-1"),
        ] {
            let output = command(worker)
                .env(
                    format!("{prefix}_DATABASE_URL"),
                    "postgres://localhost/test",
                )
                .env(format!("{prefix}_{key}"), value)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(78));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-secret"));
        }
        assert_eq!(command(worker).output().unwrap().status.code(), Some(78));
    }
}

/// ADR 0024: telemetry settings are configuration. An invalid value exits 78 with one fixed
/// line naming the key, before any listener opens or any event is written.
#[test]
fn rejects_invalid_telemetry_settings_with_a_fixed_line() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    for worker in [false, true] {
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        for (key, value) in [
            ("LOG_FORMAT", "synthetic-secret"),
            ("LOG_FORMAT", "JSON"),
            ("LOG_LEVEL", "trace"),
            ("LOG_LEVEL", "info,synthetic-secret=debug"),
        ] {
            let output = command(worker)
                .env(
                    format!("{prefix}_DATABASE_URL"),
                    "postgres://localhost/test",
                )
                // Serving would exit 1 on this occupied address instead.
                .env(
                    format!("{prefix}_BIND"),
                    occupied.local_addr().unwrap().to_string(),
                )
                .env(format!("{prefix}_{key}"), value)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(78), "{key}={value}");
            assert!(output.stdout.is_empty());
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                format!("configuration error: invalid {key}\n")
            );
        }
    }
}

/// Starts a process with piped stderr and the given telemetry settings.
fn start_logging(worker: bool, address: &str, url: &str, settings: &[(&str, &str)]) -> Process {
    let prefix = if worker {
        "OPENMETTLE_WORKER"
    } else {
        "OPENMETTLE_API"
    };
    let mut command = command(worker);
    command
        .env(format!("{prefix}_BIND"), address)
        .env(format!("{prefix}_DATABASE_URL"), url)
        .env(format!("{prefix}_DB_TIMEOUT_MS"), "150")
        .env(format!("{prefix}_SHUTDOWN_TIMEOUT_MS"), "1000");
    for (key, value) in settings {
        command.env(format!("{prefix}_{key}"), value);
    }
    Process(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}
fn drain(process: &mut Process) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    process
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (stdout, stderr)
}

/// ADR 0024 through the real binaries: lifecycle and request events on stderr only, in the
/// selected format and level, with none of the planted canaries.
#[test]
fn serving_writes_redacted_lifecycle_and_request_events_to_stderr() {
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "postgres://fixture:CANARY-db-password@{}/fixture?sslmode=disable",
        unavailable.local_addr().unwrap()
    );
    let requests = [
        "GET /healthz?code=CANARY-query&state=CANARY-state HTTP/1.1\r\nHost: localhost\r\n\
         Cookie: __Host-openmettle-session=CANARY-cookie\r\nX-Request-Id: CANARY-id\r\n\
         Connection: close\r\n\r\n",
        "GET /readyz HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer CANARY-bearer\r\n\
         Connection: close\r\n\r\n",
        "POST /CANARY-path HTTP/1.1\r\nHost: localhost\r\nContent-Length: 14\r\n\
         Connection: close\r\n\r\nCANARY-payload",
    ];
    // The API in JSON at debug sees everything; the worker in text at warn sees only the
    // failed readiness check.
    for (worker, settings) in [
        (false, &[("LOG_LEVEL", "debug")][..]),
        (true, &[("LOG_FORMAT", "text"), ("LOG_LEVEL", "warn")][..]),
    ] {
        let bind = address();
        let mut process = start_logging(worker, &bind, &url, settings);
        wait_status(&mut process, &bind, "/healthz", 200);
        for request in requests {
            send(&bind, request).unwrap();
        }
        stop(&mut process, "-TERM");
        let (stdout, stderr) = drain(&mut process);
        assert!(stdout.is_empty(), "{stdout}");
        assert!(!stderr.contains("CANARY"), "{stderr}");
        let lines: Vec<&str> = stderr.lines().collect();
        if worker {
            assert_eq!(lines.len(), 1, "{stderr}");
            assert!(
                lines[0].contains(" WARN event=\"http.request.completed\""),
                "{stderr}"
            );
            assert!(lines[0].contains("http.route=\"/readyz\""), "{stderr}");
            assert!(
                lines[0].contains("http.response.status_code=503"),
                "{stderr}"
            );
            continue;
        }
        let events: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let names: Vec<&str> = events
            .iter()
            .map(|e| e["event"].as_str().unwrap())
            .collect();
        // Health polling adds request events before the planted requests.
        assert_eq!(names.first(), Some(&"process.started"), "{stderr}");
        assert_eq!(
            names[names.len() - 2..],
            ["process.stopping", "process.stopped"]
        );
        assert_eq!(events[0]["role"], "api");
        assert_eq!(events[names.len() - 2]["signal"], "SIGTERM");
        let planted: Vec<_> = events[events.len() - 5..events.len() - 2]
            .iter()
            .map(|e| {
                (
                    e["http.route"].as_str().unwrap(),
                    e["http.request.method"].as_str().unwrap(),
                    e["http.response.status_code"].as_u64().unwrap(),
                    e["level"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            planted,
            [
                ("/healthz", "GET", 200, "DEBUG"),
                ("/readyz", "GET", 503, "WARN"),
                ("unmatched", "POST", 404, "DEBUG"),
            ]
        );
    }
}

const USAGE: &str = "usage error: expected no arguments or --check-auth-config PATH\n";

/// ADRs 0015 and 0020: the check needs no database setting and opens no listener, for
/// version 1 and for version 2 with its browser-routing profile.
#[test]
fn auth_config_check_succeeds_offline_without_serving_settings() {
    assert_eq!(openmettle_core::auth_config::VERSION, 1);
    let dir = auth_config_support::Dir::new();
    let bundle = ca::Ca::new().pem();
    let v1 = auth_config_support::document(&dir, &bundle);
    let v2 = auth_config_support::document_v2(&dir, &bundle);
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    for (document, serving_settings) in [(&v1, false), (&v1, true), (&v2, false), (&v2, true)] {
        let path = dir.write("auth.json", document.to_string().as_bytes());
        let mut command = command(false);
        if serving_settings {
            // Serving with these would exit 78 (database URL) or 1 (occupied listener).
            command
                .env("OPENMETTLE_API_DATABASE_URL", "invalid://synthetic-secret")
                .env(
                    "OPENMETTLE_API_BIND",
                    occupied.local_addr().unwrap().to_string(),
                );
        }
        let output = command
            .args(["--check-auth-config", &path])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "auth configuration valid (local files only)\n"
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn auth_config_check_rejects_with_fixed_redacted_categories() {
    let dir = auth_config_support::Dir::new();
    let valid = auth_config_support::document(&dir, &ca::Ca::new().pem());
    let short_key = dir.write("synthetic-secret-key", &[0xd3; 31]);
    let mut cases = Vec::new();
    let mut case = |pointer: &str, value: serde_json::Value, category: &'static str| {
        let mut document = valid.clone();
        match document.pointer_mut(pointer) {
            Some(slot) => *slot = value,
            None => document["synthetic-secret"] = value,
        }
        cases.push((document.to_string().into_bytes(), category));
    };
    case(
        "/synthetic-secret",
        "synthetic-secret".into(),
        "configuration has an unknown field",
    );
    case(
        "/version",
        3.into(),
        "configuration version is missing or unsupported",
    );
    // Version 1 has no browser profile, and version 2 requires one.
    case("/version", 2.into(), "configuration lacks a required field");
    case(
        "/login/lifetime_seconds",
        601.into(),
        "login lifetime is out of range",
    );
    case(
        "/login/keys/active/path",
        short_key.into(),
        "a login key is not a readable regular file of exactly 32 bytes",
    );
    case(
        "/providers/0/issuer",
        "http://synthetic-secret.example.test".into(),
        "a provider identity is invalid",
    );
    case(
        "/providers/0/token_endpoint",
        "https://synthetic-secret/token".into(),
        "a provider definition, endpoint, trust or address policy is invalid",
    );
    cases.push((
        br#"{"synthetic-secret":"#.to_vec(),
        "configuration is not valid JSON",
    ));
    let v2 = auth_config_support::document_v2(&dir, &ca::Ca::new().pem());
    let mut browser = valid.clone();
    browser["browser"] = v2["browser"].clone();
    cases.push((
        browser.to_string().into_bytes(),
        "configuration has an unknown field",
    ));
    for (pointer, value, category) in [
        (
            "/browser/provider_id",
            "1c6d7a5f-3b2e-4d4c-8f9a-8b7c6d5e4f30",
            "browser profile refused: provider is not configured",
        ),
        (
            "/browser/origin",
            "https://synthetic-secret.example.test",
            "browser profile refused: registered callback is not a plain path on the application origin",
        ),
        (
            "/browser/landing_path",
            "/synthetic-secret?x",
            "browser profile refused: landing is not a plain absolute path",
        ),
        (
            "/browser/paths/logout",
            "/callback",
            "browser profile refused: login paths collide",
        ),
        (
            "/browser/paths/initiation",
            "/synthetic-secret/{x}",
            "browser profile refused: login path contains route syntax",
        ),
    ] {
        let mut document = v2.clone();
        *document.pointer_mut(pointer).unwrap() = value.into();
        cases.push((document.to_string().into_bytes(), category));
    }
    let mut document = v2.clone();
    document["browser"]["rates"]["callback"]["burst"] = 0.into();
    cases.push((
        document.to_string().into_bytes(),
        "browser profile refused: login rate is outside its allowed range",
    ));
    for (bytes, category) in cases {
        let path = dir.write("synthetic-secret.json", &bytes);
        let output = command(false)
            .args(["--check-auth-config", &path])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78));
        assert!(output.stdout.is_empty());
        // The whole diagnostic is one fixed line: no path, value or parser text.
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("auth configuration error: {category}\n")
        );
    }
    let output = command(false)
        .args(["--check-auth-config", &dir.path("synthetic-secret-absent")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "auth configuration error: configuration is not a readable regular file within bounds\n"
    );
}

#[test]
fn malformed_check_invocation_is_refused_and_worker_is_unchanged() {
    let dir = auth_config_support::Dir::new();
    let document = auth_config_support::document(&dir, &ca::Ca::new().pem());
    let path = dir.write("auth.json", document.to_string().as_bytes());
    let joined = format!("--check-auth-config={path}");
    for arguments in [
        vec!["--check-auth-config"],
        vec!["--check-auth-config", &path, "synthetic-secret"],
        vec!["--check-auth-confg", &path],
        vec![joined.as_str()],
        vec![path.as_str()],
        vec!["--help"],
        vec![""],
    ] {
        // A fall-through to serving would report the missing database URL instead.
        let output = command(false).args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(78), "{arguments:?}");
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).unwrap(), USAGE);
    }
    // The worker has no check mode and no auth settings: it reports its own configuration.
    let output = command(true)
        .args(["--check-auth-config", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "configuration error: DATABASE_URL is required\n"
    );
}

#[test]
fn unavailable_database_keeps_liveness_and_bounded_readiness() {
    // Hold a TCP listener that never speaks PostgreSQL to exercise query/connect timeout.
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "postgres://fixture@{}/fixture?sslmode=disable",
        unavailable.local_addr().unwrap()
    );
    for worker in [false, true] {
        let bind = address();
        let mut process = start_with_timeout(worker, &bind, &url, 150);
        wait_status(&mut process, &bind, "/healthz", 200);
        let began = Instant::now();
        assert!(
            response(&bind, "/readyz")
                .unwrap()
                .starts_with("HTTP/1.1 503")
        );
        assert!(began.elapsed() < Duration::from_secs(2));
        assert!(response(&bind, "/healthz").unwrap().ends_with("ok\n"));
        assert!(
            response(&bind, "/unknown")
                .unwrap()
                .starts_with("HTTP/1.1 404")
        );
        // A synthetic credential of the session parser's shape.
        const SESSION: &str = concat!(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ".",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        // ADRs 0017–0019: neither the browser login handoff nor its router is mounted. The
        // synthetic callback path, a form POST, a session check and a logout are unknown
        // routes, no response sets or deletes a cookie or redirects, and the two operational
        // routes still answer GET alone.
        for (method, path, status) in [
            (
                "GET",
                "/callback?code=synthetic&state=synthetic&iss=synthetic",
                404,
            ),
            ("POST", "/callback", 404),
            ("POST", "/login", 404),
            ("GET", "/session", 404),
            ("POST", "/logout", 404),
            ("POST", "/", 404),
            ("POST", "/healthz", 405),
            ("POST", "/readyz", 405),
        ] {
            // Shaped like a same-origin browser request, with an empty body.
            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\
                 Origin: https://app.example.test\r\nContent-Length: 0\r\n\
                 Cookie: __Host-openmettle-session={SESSION}\r\n\
                 Connection: close\r\n\r\n"
            );
            let response = send(&bind, &request).unwrap().to_ascii_lowercase();
            assert!(
                response.starts_with(&format!("http/1.1 {status}")),
                "{method} {path}"
            );
            assert!(!response.contains("set-cookie") && !response.contains("location"));
        }
        stop(&mut process, if worker { "-INT" } else { "-TERM" });
    }
}

#[test]
fn occupied_listener_exits_with_runtime_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let output = command(false)
        .env(
            "OPENMETTLE_API_BIND",
            listener.local_addr().unwrap().to_string(),
        )
        .env("OPENMETTLE_API_DATABASE_URL", "postgres://localhost/test")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    // One JSON event names the failure class; nothing goes to stdout.
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let event: serde_json::Value = serde_json::from_str(stderr.trim_end()).unwrap();
    assert_eq!(event["event"], "process.failed");
    assert_eq!(event["level"], "ERROR");
    assert_eq!(event["role"], "api");
    assert_eq!(event["error.type"], "Bind");
}

#[test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
fn postgres_readiness_and_stopped_worker_survival() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let api_address = address();
    let worker_address = address();
    let mut api = start(false, &api_address, &url);
    let mut worker = start(true, &worker_address, &url);
    wait_status(&mut api, &api_address, "/readyz", 200);
    wait_status(&mut worker, &worker_address, "/readyz", 200);
    stop(&mut worker, "-TERM");
    for _ in 0..3 {
        assert!(
            response(&api_address, "/healthz")
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            response(&api_address, "/readyz")
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
    }
    stop(&mut api, "-TERM");
}

/// The evaluator runs in this harness, not behind a runtime injection endpoint.
/// Regression guard for current structural separation, not in-process adapter qualification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn postgres_readiness_is_independent_of_optional_evaluation() {
    use openmettle_core::capabilities::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let bind = address();
    let mut api = start(false, &bind, &url);
    wait_status(&mut api, &bind, "/readyz", 200);
    let input = Input {
        installed: true,
        enabled: true,
        caller: Caller::Visible(Authorization::Allowed),
    };
    for enabled in [false, true] {
        let result = evaluate(
            Input { enabled, ..input },
            Duration::from_millis(50),
            || {
                assert!(enabled, "disabled observer called");
                async { Observation::ProviderFailure }
            },
        )
        .await
        .unwrap();
        assert!(!result.offered());
        assert_eq!(
            result.readiness.unwrap().reason,
            Some(if enabled {
                Reason::ProviderFailure
            } else {
                Reason::Disabled
            })
        );
        assert!(
            response(&bind, "/readyz")
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
    }
    // Signal only after the fake is polled; prove readiness while it is pending.
    for cancel in [false, true] {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        let (started, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(evaluate(input, Duration::from_secs(5), || async move {
            let _guard = guard;
            started.send(()).unwrap();
            std::future::pending().await
        }));
        tokio::time::timeout(Duration::from_secs(1), received)
            .await
            .unwrap()
            .unwrap();
        assert!(!task.is_finished());
        assert!(
            response(&bind, "/readyz")
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            !task.is_finished(),
            "observation must still be pending during readiness"
        );
        if cancel {
            task.abort();
        }
        let joined = tokio::time::timeout(Duration::from_secs(6), task)
            .await
            .unwrap();
        if cancel {
            assert!(joined.unwrap_err().is_cancelled());
        } else {
            let result = joined.unwrap().unwrap();
            assert_eq!(result.readiness.unwrap().reason, Some(Reason::Timeout));
            assert_eq!(result.readiness.unwrap().status, Status::Unknown);
            assert!(!result.offered());
        }
        assert!(dropped.load(Ordering::SeqCst));
        assert!(
            response(&bind, "/readyz")
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
    }
    assert!(
        response(&bind, "/v1/capabilities")
            .unwrap()
            .starts_with("HTTP/1.1 404")
    );
    stop(&mut api, "-TERM");
}
