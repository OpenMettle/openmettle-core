//! Black-box process tests. Real PostgreSQL is required only by the ignored test.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "support/env.rs"]
mod env_support;
use env_support::scrub_env;
#[path = "support/proc.rs"]
mod proc_support;
use proc_support::{
    PipeDrain, Process, read_string_bounded, run_bounded, wait_exit_bounded,
    wait_http_status_bounded, wait_output_bounded,
};
#[path = "auth_config_support/mod.rs"]
mod auth_config_support;
#[path = "support/pg.rs"]
mod pg;
// The transport fixture's synthetic CA; its leaf certificates are not needed here.
#[allow(dead_code)]
#[path = "provider_http_support/ca.rs"]
mod ca;

/// Bound for start-up refusal, offline check and immediate-failure runs.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound for graceful signal shutdown in runtime tests (`SHUTDOWN_TIMEOUT_MS=1000`).
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound for post-exit stdout/stderr pipe draining once the process has exited.
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

fn role_name(worker: bool) -> &'static str {
    if worker { "worker" } else { "api" }
}
fn run(command: &mut Command, context: &str) -> Output {
    run_bounded(command, REFUSAL_TIMEOUT, context)
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
    scrub_env(&mut command);
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
    wait_http_status_bounded(process, address, path, code, Duration::from_secs(15));
}
fn stop(process: &mut Process, signal: &str) {
    assert!(
        Command::new("kill")
            .args([signal, &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let status = wait_exit_bounded(
        &mut process.0,
        SHUTDOWN_TIMEOUT,
        &format!("shutdown ({signal})"),
    );
    assert!(status.success(), "shutdown ({signal}) exited {status}");
}

#[test]
fn rejects_invalid_config_without_disclosing_values() {
    for worker in [false, true] {
        let role = role_name(worker);
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
            let context = format!("{role} invalid {prefix}_{key}");
            let mut cmd = command(worker);
            cmd.env(
                format!("{prefix}_DATABASE_URL"),
                "postgres://localhost/test",
            )
            .env(format!("{prefix}_{key}"), value);
            let output = run(&mut cmd, &context);
            assert_eq!(output.status.code(), Some(78), "{context}");
            assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-secret"));
        }
        let missing = format!("{role} missing {prefix}_DATABASE_URL");
        assert_eq!(
            run(&mut command(worker), &missing).status.code(),
            Some(78),
            "{missing}"
        );
    }
}

/// ADR 0024: telemetry settings are configuration. An invalid value exits 78 with one fixed
/// line naming the key, before any listener opens or any event is written.
#[test]
fn rejects_invalid_telemetry_settings_with_a_fixed_line() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    for worker in [false, true] {
        let role = role_name(worker);
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        for (label, key, value) in [
            ("unknown format", "LOG_FORMAT", "synthetic-secret"),
            ("uppercase format", "LOG_FORMAT", "JSON"),
            ("trace level", "LOG_LEVEL", "trace"),
            (
                "filter directive",
                "LOG_LEVEL",
                "info,synthetic-secret=debug",
            ),
        ] {
            let context = format!("{role} {prefix}_{key} ({label})");
            let mut cmd = command(worker);
            cmd.env(
                format!("{prefix}_DATABASE_URL"),
                "postgres://localhost/test",
            )
            // Serving would exit 1 on this occupied address instead.
            .env(
                format!("{prefix}_BIND"),
                occupied.local_addr().unwrap().to_string(),
            )
            .env(format!("{prefix}_{key}"), value);
            let output = run(&mut cmd, &context);
            assert_eq!(output.status.code(), Some(78), "{context}");
            assert!(output.stdout.is_empty(), "{context}");
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                format!("configuration error: invalid {key}\n"),
                "{context}"
            );
        }
    }
}

/// ADR 0030: the API's issuance pool settings. Each refusal exits 78 with one fixed line that
/// names the key or category, never a value, before any listener opens. The worker never reads
/// the settings and refuses to start while the API's issuance URL is present.
#[test]
fn issuance_settings_are_refused_with_a_fixed_line() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = occupied.local_addr().unwrap().to_string();
    // An absolute path: parsing accepts it, and a document is never read before a refusal.
    let auth = Some("/CANARY-absent/auth.json");
    let issuance = "postgres://openmettle_issuance:CANARY-issuance@localhost/test";
    let primary = "postgres://openmettle_api:CANARY-api@localhost/test";
    let max = "OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS";
    type Case<'a> = (
        Option<&'a str>,
        &'a str,
        &'a [(&'a str, &'a OsStr)],
        &'a [(&'a str, &'a str)],
        &'a str,
    );
    let url = |value: &'static str| ("OPENMETTLE_API_ISSUANCE_DATABASE_URL", OsStr::new(value));
    let cases: &[Case] = &[
        (
            auth,
            primary,
            &[],
            &[],
            "ISSUANCE_DATABASE_URL is required with AUTH_CONFIG",
        ),
        (
            None,
            primary,
            &[url(issuance)],
            &[],
            "ISSUANCE_DATABASE_URL requires AUTH_CONFIG",
        ),
        (
            None,
            primary,
            &[url("")],
            &[],
            "ISSUANCE_DATABASE_URL requires AUTH_CONFIG",
        ),
        (
            None,
            primary,
            &[],
            &[(max, "2")],
            "ISSUANCE_DB_MAX_CONNECTIONS requires ISSUANCE_DATABASE_URL",
        ),
        (
            auth,
            primary,
            &[url("")],
            &[],
            "invalid ISSUANCE_DATABASE_URL scheme",
        ),
        (
            auth,
            primary,
            &[url("mysql://openmettle_issuance:CANARY@localhost/test")],
            &[],
            "invalid ISSUANCE_DATABASE_URL scheme",
        ),
        (
            auth,
            primary,
            &[url("postgres://openmettle_issuance:CANARY@[::1/test")],
            &[],
            "invalid ISSUANCE_DATABASE_URL",
        ),
        (
            auth,
            primary,
            &[(
                "OPENMETTLE_API_ISSUANCE_DATABASE_URL",
                OsStr::from_bytes(b"postgres://CANARY-\xff"),
            )],
            &[],
            "configuration must be UTF-8",
        ),
        // The two pools must not collapse into one role: the same explicit user, the same user
        // through the `user` parameter, or both from libpq defaults.
        (
            auth,
            primary,
            &[url(
                "postgres://openmettle_api:CANARY-other@localhost/other",
            )],
            &[],
            "ISSUANCE_DATABASE_URL must use a different user",
        ),
        (
            auth,
            primary,
            &[url(
                "postgres://localhost/test?user=openmettle_api&password=CANARY",
            )],
            &[],
            "ISSUANCE_DATABASE_URL must use a different user",
        ),
        (
            auth,
            "postgres://localhost/test",
            &[url("postgres://localhost/other")],
            &[],
            "ISSUANCE_DATABASE_URL must use a different user",
        ),
        (
            auth,
            primary,
            &[url(issuance)],
            &[(max, "0")],
            "configuration outside allowed range",
        ),
        (
            auth,
            primary,
            &[url(issuance)],
            &[(max, "65")],
            "configuration outside allowed range",
        ),
        (
            auth,
            primary,
            &[url(issuance)],
            &[(max, "CANARY")],
            "invalid numeric configuration",
        ),
    ];
    for (index, (auth, database, issuance, extra, line)) in cases.iter().enumerate() {
        let mut command = command(false);
        command
            .env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", database);
        if let Some(path) = auth {
            command.env("OPENMETTLE_API_AUTH_CONFIG", path);
        }
        command
            .envs(issuance.iter().copied())
            .envs(extra.iter().copied());
        let context = format!("api issuance refusal case #{index} ({line})");
        let output = run(&mut command, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert!(output.stdout.is_empty(), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("configuration error: {line}\n"),
            "{context}"
        );
    }
    // A user filled from `PGUSER` counts as that user, on either URL.
    for (label, database, issuance) in [
        (
            "PGUSER fills primary DATABASE_URL",
            "postgres://localhost/test",
            "postgres://openmettle_api@localhost/other",
        ),
        (
            "PGUSER fills ISSUANCE_DATABASE_URL",
            primary,
            "postgres://localhost/other",
        ),
    ] {
        let context = format!("api issuance PGUSER collision ({label})");
        let mut cmd = command(false);
        cmd.env("PGUSER", "openmettle_api")
            .env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", database)
            .env("OPENMETTLE_API_AUTH_CONFIG", "/CANARY-absent/auth.json")
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", issuance);
        let output = run(&mut cmd, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "configuration error: ISSUANCE_DATABASE_URL must use a different user\n",
            "{context}"
        );
    }
    // Accepted settings reach the document loader, which reports the absent file instead.
    for max in [None, Some("1"), Some("64")] {
        let mut command = command(false);
        command
            .env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", primary)
            .env("OPENMETTLE_API_AUTH_CONFIG", "/CANARY-absent/auth.json")
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", issuance);
        if let Some(max) = max {
            command.env("OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS", max);
        }
        let context = format!("api issuance accepted with ISSUANCE_DB_MAX_CONNECTIONS={max:?}");
        let output = run(&mut command, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "auth configuration error: configuration is not a readable regular file within bounds\n",
            "{context}"
        );
    }
    // The worker refuses the API's issuance URL whatever its value, and reads no issuance
    // setting under its own prefix.
    for (label, value) in [
        ("url", OsStr::new(issuance)),
        ("empty", OsStr::new("")),
        ("non-utf8", OsStr::from_bytes(b"CANARY-\xff")),
    ] {
        let context = format!("worker refuses OPENMETTLE_API_ISSUANCE_DATABASE_URL ({label})");
        let mut cmd = command(true);
        cmd.env("OPENMETTLE_WORKER_BIND", &bind)
            .env(
                "OPENMETTLE_WORKER_DATABASE_URL",
                "postgres://localhost/test",
            )
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", value);
        let output = run(&mut cmd, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "configuration error: OPENMETTLE_API_ISSUANCE_DATABASE_URL is refused outside the API\n",
            "{context}"
        );
    }
    // Under its own prefix, unread: the occupied listener is the first failure.
    let mut cmd = command(true);
    cmd.env("OPENMETTLE_WORKER_BIND", &bind)
        .env(
            "OPENMETTLE_WORKER_DATABASE_URL",
            "postgres://localhost/test",
        )
        .env(
            "OPENMETTLE_WORKER_ISSUANCE_DATABASE_URL",
            "invalid://CANARY",
        )
        .env("OPENMETTLE_WORKER_ISSUANCE_DB_MAX_CONNECTIONS", "CANARY");
    let output = run(
        &mut cmd,
        "worker unread OPENMETTLE_WORKER_ISSUANCE_* on occupied listener",
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("CANARY"));
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
    let stdout = read_string_bounded(
        process.0.stdout.take().unwrap(),
        PIPE_DRAIN_TIMEOUT,
        "stdout",
        "post-exit process stdout",
    );
    let stderr = read_string_bounded(
        process.0.stderr.take().unwrap(),
        PIPE_DRAIN_TIMEOUT,
        "stderr",
        "post-exit process stderr",
    );
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

/// Ambient OpenTelemetry SDK variables the binaries must ignore (ADR 0026). The canaries
/// would show up in stderr or on the wire if any were read.
const AMBIENT_OTEL: [(&str, &str); 9] = [
    ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
    (
        "OTEL_EXPORTER_OTLP_HEADERS",
        "authorization=Bearer CANARY-otel-header",
    ),
    (
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
        "x-api-key=CANARY-otel-traces-header",
    ),
    ("OTEL_TRACES_EXPORTER", "otlp"),
    ("OTEL_TRACES_SAMPLER", "always_on"),
    ("OTEL_SERVICE_NAME", "CANARY-otel-service"),
    (
        "OTEL_RESOURCE_ATTRIBUTES",
        "deployment.secret=CANARY-otel-resource",
    ),
    ("OTEL_SDK_DISABLED", "false"),
    ("OTEL_LOG_LEVEL", "debug"),
];

/// A listener counting nothing but whether anyone connected.
fn untouched() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    (listener, address)
}
fn assert_untouched(listener: &TcpListener) {
    match listener.accept() {
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
        Ok(_) => panic!("a connection was made"),
    }
}

/// ADR 0026: export is off unless `OTLP_TRACES_ENDPOINT` is set under the process prefix.
/// Ambient `OTEL_EXPORTER_OTLP_*` variables pointing at a local listener, header canaries and
/// proxy variables change nothing: no connection, and stderr holds exactly the lifecycle.
#[test]
fn otlp_export_is_off_by_default_despite_ambient_otel_variables() {
    let (database, url) = unavailable_database();
    let (collector, collector_address) = untouched();
    let (proxy, proxy_address) = untouched();
    for worker in [false, true] {
        let bind = address();
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        let mut command = command(worker);
        command
            .env(format!("{prefix}_BIND"), &bind)
            .env(format!("{prefix}_DATABASE_URL"), &url)
            .env(format!("{prefix}_DB_TIMEOUT_MS"), "150")
            .env(format!("{prefix}_SHUTDOWN_TIMEOUT_MS"), "1000")
            .envs(AMBIENT_OTEL)
            .env(
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                format!("http://{collector_address}"),
            )
            .env(
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                format!("http://{collector_address}/v1/traces"),
            )
            .env("HTTPS_PROXY", format!("http://{proxy_address}"))
            .env("ALL_PROXY", format!("http://{proxy_address}"));
        let mut process = Process(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        wait_status(&mut process, &bind, "/healthz", 200);
        for target in ["/v1/runs", "/CANARY-path"] {
            let _ = response(&bind, target);
        }
        stop(&mut process, "-TERM");
        let (stdout, stderr) = drain(&mut process);
        assert!(stdout.is_empty(), "{stdout}");
        assert!(!stderr.contains("CANARY"), "{stderr}");
        let names: Vec<String> = stderr
            .lines()
            .map(|line| {
                let event: serde_json::Value = serde_json::from_str(line).unwrap();
                event["event"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(
            names,
            ["process.started", "process.stopping", "process.stopped"],
            "{stderr}"
        );
    }
    assert_untouched(&collector);
    assert_untouched(&proxy);
    drop(database);
}

/// ADR 0026: an invalid `OTLP_*` value exits 78 with one fixed line naming the key, before
/// any listener opens, file contents are echoed or any event is written.
#[test]
fn rejects_invalid_otlp_settings_with_a_fixed_line() {
    const ENDPOINT: &str = "https://collector.example.test:4318/v1/traces";
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = auth_config_support::Dir::new();
    let not_pem = dir.write("CANARY-ca.pem", b"CANARY-not-a-certificate\n");
    let missing = dir.path("CANARY-missing.pem");
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (
            vec![(
                "OTLP_TRACES_ENDPOINT",
                "http://collector.example.test:4318/v1/traces",
            )],
            "OTLP_TRACES_ENDPOINT",
        ),
        (
            vec![("OTLP_TRACES_ENDPOINT", "https://127.0.0.1:4318/v1/traces")],
            "OTLP_TRACES_ENDPOINT",
        ),
        (
            vec![(
                "OTLP_TRACES_ENDPOINT",
                "https://collector.example.test:4318/v1/traces?token=CANARY-query",
            )],
            "OTLP_TRACES_ENDPOINT",
        ),
        (
            vec![("OTLP_TRACES_ENDPOINT", "CANARY-endpoint")],
            "OTLP_TRACES_ENDPOINT",
        ),
        (
            vec![
                ("OTLP_TRACES_ENDPOINT", ENDPOINT),
                ("OTLP_CA_FILE", "CANARY/ca.pem"),
            ],
            "OTLP_CA_FILE",
        ),
        (
            vec![
                ("OTLP_TRACES_ENDPOINT", ENDPOINT),
                ("OTLP_CA_FILE", &missing),
            ],
            "OTLP_CA_FILE",
        ),
        (
            vec![
                ("OTLP_TRACES_ENDPOINT", ENDPOINT),
                ("OTLP_CA_FILE", &not_pem),
            ],
            "OTLP_CA_FILE",
        ),
        (vec![("OTLP_CA_FILE", &not_pem)], "OTLP_CA_FILE"),
        (
            vec![
                ("OTLP_TRACES_ENDPOINT", ENDPOINT),
                ("OTLP_PRIVATE_RANGES", "10.0.0.1/8"),
            ],
            "OTLP_PRIVATE_RANGES",
        ),
        (
            vec![
                ("OTLP_TRACES_ENDPOINT", ENDPOINT),
                ("OTLP_PRIVATE_RANGES", "8.8.8.0/24"),
            ],
            "OTLP_PRIVATE_RANGES",
        ),
        (
            vec![("OTLP_PRIVATE_RANGES", "10.0.0.0/8")],
            "OTLP_PRIVATE_RANGES",
        ),
    ];
    for worker in [false, true] {
        let role = role_name(worker);
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        for (index, (pairs, key)) in cases.iter().enumerate() {
            let mut command = command(worker);
            command
                .env(
                    format!("{prefix}_DATABASE_URL"),
                    "postgres://localhost/test",
                )
                .env(
                    format!("{prefix}_BIND"),
                    occupied.local_addr().unwrap().to_string(),
                )
                .envs(AMBIENT_OTEL);
            for (name, value) in pairs {
                command.env(format!("{prefix}_{name}"), value);
            }
            let keys: Vec<&str> = pairs.iter().map(|(name, _)| *name).collect();
            let context =
                format!("{role} invalid OTLP case #{index} (expected {key}; keys={keys:?})");
            let output = run(&mut command, &context);
            assert_eq!(output.status.code(), Some(78), "{context}");
            assert!(output.stdout.is_empty(), "{context}");
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                format!("configuration error: invalid {key}\n"),
                "{context}"
            );
        }
    }
}

/// ADR 0026 through the API binary with export configured: proxy variables are not used, a
/// collector that cannot be reached costs nothing visible to serving, and SIGTERM still exits
/// 0 within the shutdown deadline. The `.localhost` name resolves locally to loopback, which
/// the address policy refuses, or not at all; either way no socket reaches anything.
#[test]
fn configured_export_ignores_proxies_and_keeps_shutdown_bounded() {
    let (database, url) = unavailable_database();
    let (proxy, proxy_address) = untouched();
    let dir = auth_config_support::Dir::new();
    let ca = dir.write("collector-ca.pem", &ca::Ca::new().pem());
    let bind = address();
    let proxy_url = format!("http://{proxy_address}");
    let mut command = command(false);
    command
        .env("OPENMETTLE_API_BIND", &bind)
        .env("OPENMETTLE_API_DATABASE_URL", &url)
        .env("OPENMETTLE_API_DB_TIMEOUT_MS", "150")
        .env("OPENMETTLE_API_SHUTDOWN_TIMEOUT_MS", "1000")
        .env(
            "OPENMETTLE_API_OTLP_TRACES_ENDPOINT",
            "https://collector.localhost:4318/v1/traces",
        )
        .env("OPENMETTLE_API_OTLP_CA_FILE", &ca)
        .envs(AMBIENT_OTEL);
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(name, &proxy_url);
    }
    command.env("NO_PROXY", "").env("no_proxy", "");
    let mut process = Process(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    wait_status(&mut process, &bind, "/healthz", 200);
    for _ in 0..20 {
        let reply = response(&bind, "/v1/runs").unwrap();
        assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
    }
    let began = Instant::now();
    stop(&mut process, "-TERM");
    let stopping = began.elapsed();
    assert!(stopping < Duration::from_secs(2), "{stopping:?}");
    let stderr = read_string_bounded(
        process.0.stderr.take().unwrap(),
        PIPE_DRAIN_TIMEOUT,
        "stderr",
        "configured export api stderr",
    );
    assert!(!stderr.contains("CANARY"), "{stderr}");
    let names: Vec<String> = stderr
        .lines()
        .map(|line| {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            event["event"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(names.first().map(String::as_str), Some("process.started"));
    assert!(names.iter().any(|n| n == "process.stopped"), "{stderr}");
    assert!(
        names
            .iter()
            .all(|n| n.starts_with("process.") || n == "telemetry.dropped"),
        "{stderr}"
    );
    assert_untouched(&proxy);
    drop(database);
}

/// ADR 0024 through the worker binary at the defaults (JSON, `info`): exactly its lifecycle,
/// with `role=worker`; health polling is `debug` and stays out.
#[test]
fn worker_writes_its_lifecycle_at_the_default_settings() {
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "postgres://fixture:CANARY-db-password@{}/fixture?sslmode=disable",
        unavailable.local_addr().unwrap()
    );
    let bind = address();
    let mut process = start_logging(true, &bind, &url, &[]);
    wait_status(&mut process, &bind, "/healthz", 200);
    stop(&mut process, "-INT");
    let (stdout, stderr) = drain(&mut process);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.contains("CANARY"), "{stderr}");
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let summary: Vec<(&str, &str, &str)> = events
        .iter()
        .map(|e| {
            assert_eq!(e["role"], "worker", "{stderr}");
            (
                e["event"].as_str().unwrap(),
                e["level"].as_str().unwrap(),
                e.get("signal").map_or("", |s| s.as_str().unwrap()),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("process.started", "INFO", ""),
            ("process.stopping", "INFO", "SIGINT"),
            ("process.stopped", "INFO", ""),
        ],
        "{stderr}"
    );
}

/// Sends `count` health checks over one keep-alive connection; each must answer within a
/// second.
fn probe_health(address: &str, count: usize) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut response = Vec::new();
    for i in 0..count {
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        response.clear();
        while !response.ends_with(b"\r\n\r\nok\n") {
            let mut chunk = [0; 512];
            let read = stream.read(&mut chunk);
            let read = read.unwrap_or_else(|e| panic!("health check {i} did not answer: {e}"));
            assert!(read > 0, "connection closed at health check {i}");
            response.extend_from_slice(&chunk[..read]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"), "health check {i}");
    }
}

/// ADR 0024 delivery and ARCHITECTURE-v1.md: an unread stderr pipe costs telemetry lines,
/// not liveness, readiness or shutdown. At `debug` every probe writes a line; three thousand
/// fill the pipe (64 KiB on Linux and macOS) and the queue (1024 lines) several times over.
/// A synchronous write would block the Tokio workers and the probes would time out.
#[test]
fn unread_stderr_never_blocks_serving_or_shutdown() {
    const PROBES: usize = 3000;
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "postgres://fixture:CANARY-db-password@{}/fixture?sslmode=disable",
        unavailable.local_addr().unwrap()
    );
    let bind = address();
    // Nothing reads the process's stderr until it has exited.
    let mut process = start_logging(false, &bind, &url, &[("LOG_LEVEL", "debug")]);
    wait_status(&mut process, &bind, "/healthz", 200);
    probe_health(&bind, PROBES);
    // Readiness still fails promptly within its database deadline.
    for _ in 0..3 {
        let began = Instant::now();
        assert!(
            response(&bind, "/readyz")
                .unwrap()
                .starts_with("HTTP/1.1 503")
        );
        assert!(began.elapsed() < Duration::from_secs(1));
    }
    probe_health(&bind, 10);
    // The whole stop fits SHUTDOWN_TIMEOUT_MS (1000), including the abandoned flush.
    let began = Instant::now();
    stop(&mut process, "-TERM");
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "{:?}",
        began.elapsed()
    );
    let (stdout, stderr) = drain(&mut process);
    assert!(stdout.is_empty());
    assert!(!stderr.contains("CANARY"));
    // Whole JSON lines only, and far fewer than were emitted: the rest were dropped.
    let lines: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["event"], "process.started");
    assert!(lines.len() < PROBES, "{}", lines.len());
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
    // ADR 0029: the optional native profile is checked by the same command.
    let mut native = auth_config_support::document_v2_native(&dir, &bundle);
    native["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    for (label, document, serving_settings) in [
        ("v1", &v1, false),
        ("v1", &v1, true),
        ("v2", &v2, false),
        ("v2", &v2, true),
        ("v2-native", &native, false),
        ("v2-native", &native, true),
    ] {
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
        command.args(["--check-auth-config", &path]);
        let context =
            format!("api --check-auth-config ({label}, serving_settings={serving_settings})");
        let output = run(&mut command, &context);
        assert_eq!(output.status.code(), Some(0), "{context}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "auth configuration valid (local files only)\n",
            "{context}"
        );
        assert!(output.stderr.is_empty(), "{context}");
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
    // ADR 0029: the native profile is unknown in version 1 and judged in version 2.
    let native = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    let mut document = valid.clone();
    document["native"] = native["native"].clone();
    cases.push((
        document.to_string().into_bytes(),
        "configuration has an unknown field",
    ));
    for (pointer, value, category) in [
        (
            "/native",
            serde_json::Value::Null,
            "a configuration field has the wrong type or keyword",
        ),
        (
            "/native/provider_id",
            "synthetic-secret".into(),
            "native profile refused: native provider is not configured",
        ),
        (
            "/native/issuer",
            "http://synthetic-secret.example.test".into(),
            "native profile refused: native issuer is not a canonical HTTPS origin",
        ),
        (
            "/native/callback",
            "https://synthetic-secret.example.test/cb".into(),
            "native profile refused: native callback is not a plain HTTPS path on the issuer origin",
        ),
        (
            "/native/client_id",
            "synthetic secret".into(),
            "native profile refused: native client identifier is not acceptable",
        ),
        (
            "/native/redirect_uri",
            "https://synthetic-secret.example.test/x?y".into(),
            "native profile refused: native app link is not a canonical HTTPS URL",
        ),
        (
            "/native/callback",
            "https://app.example.test/synthetic-secret//x".into(),
            "native profile refused: native callback path is not a plain literal path",
        ),
        (
            "/native/callback",
            "https://app.example.test/readyz".into(),
            "native profile refused: native routes or app link collide with another route",
        ),
        (
            "/native/redirect_uri",
            "https://app.example.test/auth/logout".into(),
            "native profile refused: native routes or app link collide with another route",
        ),
        (
            "/native/rate/interval_milliseconds",
            0.into(),
            "native profile refused: native rate is outside its allowed range",
        ),
        (
            "/native/max_in_flight",
            1025.into(),
            "native profile refused: native in-flight cap is outside its allowed range",
        ),
    ] {
        let mut document = native.clone();
        *document.pointer_mut(pointer).unwrap() = value;
        cases.push((document.to_string().into_bytes(), category));
    }
    let mut reused = native;
    reused["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    reused["cursor_keys"]["active"]["path"] = reused["login"]["keys"]["active"]["path"].clone();
    cases.push((
        reused.to_string().into_bytes(),
        "cursor key count, identifiers or key separation are invalid",
    ));
    for (index, (bytes, category)) in cases.into_iter().enumerate() {
        let path = dir.write("synthetic-secret.json", &bytes);
        let context = format!("api --check-auth-config refusal case #{index} ({category})");
        let mut cmd = command(false);
        cmd.args(["--check-auth-config", &path]);
        let output = run(&mut cmd, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert!(output.stdout.is_empty(), "{context}");
        // The whole diagnostic is one fixed line: no path, value or parser text.
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("auth configuration error: {category}\n"),
            "{context}"
        );
    }
    let mut cmd = command(false);
    cmd.args(["--check-auth-config", &dir.path("synthetic-secret-absent")]);
    let output = run(&mut cmd, "api --check-auth-config absent file");
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
    for (index, arguments) in [
        vec!["--check-auth-config"],
        vec!["--check-auth-config", &path, "synthetic-secret"],
        vec!["--check-auth-confg", &path],
        vec![joined.as_str()],
        vec![path.as_str()],
        vec!["--help"],
        vec![""],
    ]
    .into_iter()
    .enumerate()
    {
        // A fall-through to serving would report the missing database URL instead.
        let context = format!(
            "api malformed check invocation case #{index} (argc={})",
            arguments.len()
        );
        let mut cmd = command(false);
        cmd.args(&arguments);
        let output = run(&mut cmd, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert!(output.stdout.is_empty(), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            USAGE,
            "{context}"
        );
    }
    // The worker has no check mode and no auth settings: it reports its own configuration.
    let mut cmd = command(true);
    cmd.args(["--check-auth-config", &path]);
    let output = run(&mut cmd, "worker --check-auth-config missing DATABASE_URL");
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "configuration error: DATABASE_URL is required\n"
    );
}

/// A database address that accepts connections and never speaks PostgreSQL, with a canary
/// password.
fn unavailable_database() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "postgres://fixture:CANARY-db-password@{}/fixture?sslmode=disable",
        listener.local_addr().unwrap()
    );
    (listener, url)
}
/// The issuance pool's URL (ADR 0030) on the same unanswered address, under its own user.
fn unavailable_issuance(database: &TcpListener) -> String {
    format!(
        "postgres://fixture-issuance:CANARY-issuance-password@{}/fixture?sslmode=disable",
        database.local_addr().unwrap()
    )
}
/// One request on a new connection: the status line's code, the lowercase head and the body.
fn exchange(address: &str, request: &str) -> (u16, String, String) {
    let response = send(address, request).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head["HTTP/1.1 ".len()..][..3].parse().unwrap();
    (status, head.to_ascii_lowercase(), body.to_owned())
}
/// `extra` is further header lines, optionally followed by a blank line and a body.
fn request(method: &str, target: &str, extra: &str) -> String {
    let end = if extra.contains("\r\n\r\n") {
        ""
    } else {
        "\r\n"
    };
    format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}{end}")
}
/// A synthetic credential of the session parser's shape. No session has it.
const SESSION: &str = concat!(
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ".",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
);

/// ADR 0025: a refused `OPENMETTLE_API_AUTH_CONFIG` exits 78 before any listener opens or
/// any event is written, with one fixed line that carries no path, value or parser text.
#[test]
fn api_refuses_invalid_auth_config_with_a_fixed_redacted_line() {
    let dir = auth_config_support::Dir::new();
    let bundle = ca::Ca::new().pem();
    let v1 = auth_config_support::document(&dir, &bundle);
    let v2 = auth_config_support::document_v2(&dir, &bundle);
    let write =
        |name: &str, document: &serde_json::Value| dir.write(name, document.to_string().as_bytes());
    let changed = |pointer: &str, value: serde_json::Value| {
        let mut document = v2.clone();
        *document.pointer_mut(pointer).unwrap() = value;
        write("CANARY-auth.json", &document)
    };
    const SETTING: &str = "configuration error: invalid AUTH_CONFIG";
    const ABSENT: &str =
        "auth configuration error: configuration is not a readable regular file within bounds";
    const COLLISION: &str =
        "auth configuration error: browser profile refused: login paths collide";
    let cases: Vec<(&str, String, &str)> = vec![
        ("empty path", String::new(), SETTING),
        ("relative path", "CANARY-relative/auth.json".into(), SETTING),
        ("dot-relative path", "./CANARY-auth.json".into(), SETTING),
        ("absent file", dir.path("CANARY-absent.json"), ABSENT),
        // A directory is not a regular file.
        ("directory", dir.path(""), ABSENT),
        (
            "broken JSON",
            dir.write("CANARY-broken.json", br#"{"version": 2, "CANARY-member":"#),
            "auth configuration error: configuration is not valid JSON",
        ),
        (
            "v1 document",
            write("CANARY-v1.json", &v1),
            "auth configuration error: serving requires a version 2 browser profile",
        ),
    ];
    // Each of these files is rewritten by the next case, so each runs as it is written.
    let short_key = dir.write("CANARY-short-key", b"CANARY-key-material-31-bytes-00");
    let later: [(&str, serde_json::Value, &str); 7] = [
        (
            "/login/keys/active/path",
            short_key.into(),
            "auth configuration error: a login key is not a readable regular file of exactly 32 bytes",
        ),
        (
            "/login/keys/active/path",
            dir.path("CANARY-absent-key").into(),
            "auth configuration error: a login key is not a readable regular file of exactly 32 bytes",
        ),
        ("/browser/paths/initiation", "/healthz".into(), COLLISION),
        ("/browser/paths/session_check", "/readyz".into(), COLLISION),
        ("/browser/paths/logout", "/healthz".into(), COLLISION),
        // The callback path comes from the provider registration.
        (
            "/providers/0/callback",
            "https://app.example.test/readyz".into(),
            COLLISION,
        ),
        (
            "/browser/origin",
            "https://canary-origin.example.test".into(),
            "auth configuration error: browser profile refused: registered callback is not a plain path on the application origin",
        ),
    ];
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let run_case = |label: &str, path: &str, line: &str| {
        let context = format!("api AUTH_CONFIG refusal ({label}; expected: {line})");
        let mut cmd = command(false);
        cmd.env("OPENMETTLE_API_DATABASE_URL", "postgres://localhost/test")
            // Serving would exit 1 on this occupied address instead.
            .env(
                "OPENMETTLE_API_BIND",
                occupied.local_addr().unwrap().to_string(),
            )
            .env("OPENMETTLE_API_LOG_LEVEL", "debug")
            .env("OPENMETTLE_API_AUTH_CONFIG", path)
            .env(
                "OPENMETTLE_API_ISSUANCE_DATABASE_URL",
                "postgres://fixture-issuance@localhost/test",
            );
        let output = run(&mut cmd, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert!(output.stdout.is_empty(), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("{line}\n"),
            "{context}"
        );
    };
    for (label, path, line) in cases {
        run_case(label, &path, line);
    }
    for (index, (pointer, value, line)) in later.into_iter().enumerate() {
        run_case(
            &format!("case #{index} {pointer}"),
            &changed(pointer, value),
            line,
        );
    }
    // ADR 0029: a refused native profile is the same kind of fixed line, before any listener.
    let native = auth_config_support::document_v2_native(&dir, &bundle);
    for (pointer, value) in [
        ("/native/callback", "https://app.example.test/healthz"),
        (
            "/native/redirect_uri",
            "https://app.example.test/auth/session",
        ),
        ("/native/client_id", "CANARY client"),
    ] {
        let mut document = native.clone();
        *document.pointer_mut(pointer).unwrap() = value.into();
        let line = if pointer == "/native/client_id" {
            "auth configuration error: native profile refused: native client identifier is not acceptable"
        } else {
            "auth configuration error: native profile refused: native routes or app link collide with another route"
        };
        run_case(pointer, &write("CANARY-native.json", &document), line);
    }
    // Earlier settings are still reported first, and a valid file does not excuse them.
    let mut cmd = command(false);
    cmd.env("OPENMETTLE_API_DATABASE_URL", "invalid://CANARY")
        .env("OPENMETTLE_API_AUTH_CONFIG", write("auth.json", &v2));
    let output = run(&mut cmd, "api invalid DATABASE_URL with valid AUTH_CONFIG");
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "configuration error: invalid DATABASE_URL scheme\n"
    );
}

/// ADR 0031: a refused `ARTIFACTS_DIR` exits 78 before any listener opens, with one fixed
/// line that carries no path. A usable directory gains `staging` and `revisions` and serves.
#[test]
fn artifacts_dir_is_validated_before_serving_with_a_fixed_line() {
    let dir = auth_config_support::Dir::new();
    let file = dir.write("CANARY-file", b"x");
    let target = dir.path("CANARY-target");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, dir.path("CANARY-link")).unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    for worker in [false, true] {
        let role = role_name(worker);
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        for (label, path) in [
            ("empty", String::new()),
            ("relative", "CANARY-relative".into()),
            ("absent", dir.path("CANARY-absent")),
            ("regular file", file.clone()),
            ("symlink", dir.path("CANARY-link")),
        ] {
            let context = format!("{role} {prefix}_ARTIFACTS_DIR refusal ({label})");
            let mut cmd = command(worker);
            cmd.env(
                format!("{prefix}_DATABASE_URL"),
                "postgres://localhost/test",
            )
            // Serving would exit 1 on this occupied address instead.
            .env(
                format!("{prefix}_BIND"),
                occupied.local_addr().unwrap().to_string(),
            )
            .env(format!("{prefix}_ARTIFACTS_DIR"), &path);
            let output = run(&mut cmd, &context);
            assert_eq!(output.status.code(), Some(78), "{context}");
            assert!(output.stdout.is_empty(), "{context}");
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "configuration error: invalid ARTIFACTS_DIR\n",
                "{context}"
            );
        }
        let root = dir.path(if worker { "worker" } else { "api" });
        std::fs::create_dir(&root).unwrap();
        let (_database, url) = unavailable_database();
        let bind = address();
        let mut process = Process(
            command(worker)
                .env(format!("{prefix}_BIND"), &bind)
                .env(format!("{prefix}_DATABASE_URL"), &url)
                .env(format!("{prefix}_DB_TIMEOUT_MS"), "150")
                .env(format!("{prefix}_SHUTDOWN_TIMEOUT_MS"), "1000")
                .env(format!("{prefix}_ARTIFACTS_DIR"), &root)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_status(&mut process, &bind, "/healthz", 200);
        for sub in ["staging", "revisions"] {
            assert!(std::path::Path::new(&root).join(sub).is_dir());
        }
    }
}

/// ADR 0025: the worker has no auth settings. Neither prefix's `AUTH_CONFIG`, valid or
/// unusable, changes what it serves or writes.
#[test]
fn worker_ignores_auth_config_and_mounts_no_sign_in_route() {
    let dir = auth_config_support::Dir::new();
    // With a native profile (ADR 0029), so its routes would be mounted if it were read.
    let v2 = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    let valid = dir.write("auth.json", v2.to_string().as_bytes());
    let (_database, url) = unavailable_database();
    for path in [valid.as_str(), "", "CANARY-relative", "/CANARY-absent"] {
        let bind = address();
        // Both prefixes: the worker's own, and the API's in the same environment.
        let mut process = Process(
            command(true)
                .env("OPENMETTLE_WORKER_BIND", &bind)
                .env("OPENMETTLE_WORKER_DATABASE_URL", &url)
                .env("OPENMETTLE_WORKER_DB_TIMEOUT_MS", "150")
                .env("OPENMETTLE_WORKER_SHUTDOWN_TIMEOUT_MS", "1000")
                .env("OPENMETTLE_WORKER_LOG_LEVEL", "debug")
                .env("OPENMETTLE_WORKER_AUTH_CONFIG", path)
                .env("OPENMETTLE_API_AUTH_CONFIG", path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        wait_status(&mut process, &bind, "/healthz", 200);
        for (method, target) in [
            ("POST", "/auth/login"),
            ("GET", "/callback"),
            ("GET", "/auth/session"),
            ("POST", "/auth/logout"),
            ("GET", "/auth/native/authorize"),
            ("POST", "/auth/native/token"),
            ("GET", "/auth/native/session"),
            ("POST", "/auth/native/logout"),
        ] {
            let extra = format!(
                "Origin: https://app.example.test\r\nSec-Fetch-Site: same-origin\r\n\
                 Content-Length: 0\r\nCookie: __Host-openmettle-session={SESSION}\r\n"
            );
            let (status, head, _) = exchange(&bind, &request(method, target, &extra));
            assert_eq!(status, 404, "{method} {target}");
            assert!(!head.contains("set-cookie") && !head.contains("location"));
        }
        stop(&mut process, "-TERM");
        let (stdout, stderr) = drain(&mut process);
        assert!(stdout.is_empty(), "{stdout}");
        assert!(!stderr.contains("CANARY"), "{stderr}");
        let events: Vec<serde_json::Value> = stderr
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events[0]["event"], "process.started", "{stderr}");
        assert_eq!(events.last().unwrap()["event"], "process.stopped");
        // Its lifecycle, health polling and eight unknown routes; no sign-in route template.
        let routes: Vec<&str> = events
            .iter()
            .filter_map(|event| event["http.route"].as_str())
            .filter(|route| *route != "/healthz")
            .collect();
        assert_eq!(routes, ["unmatched"; 8], "{stderr}");
        assert!(
            events
                .iter()
                .all(|event| event["role"] == "worker" || event["http.route"].is_string())
        );
    }
}

/// The API with a valid version-2 document, its issuance pool and the given format; `debug`,
/// so every request writes an event.
fn start_mounted(
    bind: &str,
    url: &str,
    issuance: &str,
    auth: &str,
    format: &str,
    db_timeout_ms: &str,
) -> Process {
    start_logging(
        false,
        bind,
        url,
        &[
            ("AUTH_CONFIG", auth),
            ("ISSUANCE_DATABASE_URL", issuance),
            ("DB_TIMEOUT_MS", db_timeout_ms),
            ("LOG_LEVEL", "debug"),
            ("LOG_FORMAT", format),
        ],
    )
}

/// ADR 0025 through the real API binary, without PostgreSQL or a provider: a valid
/// version-2 document mounts its four routes beside the probes, every refusal is the
/// router's or handoff's fixed response, telemetry holds no planted value in either format,
/// and SIGTERM still exits 0.
#[test]
fn api_mounts_browser_sign_in_routes_from_a_valid_auth_config() {
    let dir = auth_config_support::Dir::new();
    let document = auth_config_support::document_v2(&dir, &ca::Ca::new().pem());
    // Textual login keys, so their bytes can be searched for.
    dir.write("login-key-b", b"CANARY-login-key-active-00000000");
    dir.write("login-key-a", b"CANARY-login-key-decrypt-0000000");
    let auth = dir.write("CANARY-auth.json", document.to_string().as_bytes());
    let (database, url) = unavailable_database();
    database.set_nonblocking(true).unwrap();

    let state = format!("{}.{}", "s".repeat(43), "t".repeat(43));
    let login_cookie = format!(
        "Cookie: __Host-openmettle-login={}.{}\r\n",
        "u".repeat(43),
        "v".repeat(43)
    );
    let bound = format!(
        "/callback?code=CANARY-code&state={state}&iss=https%3A%2F%2Fissuer.example.test%2Frealm"
    );
    let session_cookie = format!("Cookie: __Host-openmettle-session={SESSION}\r\n");
    let same_origin = "Sec-Fetch-Site: same-origin\r\n";
    let origin = "Origin: https://app.example.test\r\nContent-Length: 0\r\n";
    let form = "Origin: https://CANARY-origin.example.test\r\nContent-Length: 39\r\n\
                Content-Type: application/x-www-form-urlencoded\r\n\r\n\
                invitation_code=CANARY-invitation-00000";
    // (method, target, extra head, status, body, route template, Allow)
    type Case<'a> = (&'a str, &'a str, String, u16, &'a str, &'a str, &'a str);
    let cases: Vec<Case> = vec![
        (
            "GET",
            "/healthz",
            "X-Request-Id: CANARY-id\r\n".into(),
            200,
            "ok\n",
            "/healthz",
            "",
        ),
        (
            "GET",
            "/readyz",
            String::new(),
            503,
            "not ready\n",
            "/readyz",
            "",
        ),
        // Initiation: `POST` only, and the `Origin` rule before the form or any work.
        (
            "POST",
            "/auth/login",
            "Content-Length: 0\r\n".into(),
            403,
            "login origin refused\n",
            "/auth/login",
            "",
        ),
        (
            "POST",
            "/auth/login",
            form.into(),
            403,
            "login origin refused\n",
            "/auth/login",
            "",
        ),
        (
            "GET",
            "/auth/login",
            String::new(),
            405,
            "method not allowed\n",
            "/auth/login",
            "POST",
        ),
        // Callback: `GET` only; a malformed response, then a missing and a foreign binding.
        (
            "POST",
            "/callback",
            "Content-Length: 0\r\n".into(),
            405,
            "method not allowed\n",
            "/callback",
            "GET",
        ),
        (
            "HEAD",
            "/callback",
            String::new(),
            405,
            "",
            "/callback",
            "GET",
        ),
        (
            "GET",
            "/callback?code=CANARY-code&state=CANARY-state&iss=CANARY-iss",
            String::new(),
            400,
            "login response refused; restart login\n",
            "/callback",
            "",
        ),
        (
            "GET",
            &bound,
            String::new(),
            400,
            "login browser binding missing or superseded; restart login\n",
            "/callback",
            "",
        ),
        (
            "GET",
            &bound,
            login_cookie,
            400,
            "login browser binding missing or superseded; restart login\n",
            "/callback",
            "",
        ),
        // Session check: Fetch Metadata, then the cookie, then the primary pool.
        (
            "GET",
            "/auth/session",
            String::new(),
            403,
            "session origin refused\n",
            "/auth/session",
            "",
        ),
        (
            "GET",
            "/auth/session",
            session_cookie.clone(),
            403,
            "session origin refused\n",
            "/auth/session",
            "",
        ),
        (
            "GET",
            "/auth/session",
            same_origin.into(),
            403,
            "session not valid\n",
            "/auth/session",
            "",
        ),
        (
            "GET",
            "/auth/session",
            format!("{same_origin}{session_cookie}"),
            503,
            "session unavailable; try again later\n",
            "/auth/session",
            "",
        ),
        // Logout: the initiation `Origin` rule, then the cookie, then the primary pool.
        (
            "POST",
            "/auth/logout",
            format!("Content-Length: 0\r\n{session_cookie}"),
            403,
            "logout origin refused\n",
            "/auth/logout",
            "",
        ),
        (
            "POST",
            "/auth/logout",
            origin.into(),
            403,
            "session not valid\n",
            "/auth/logout",
            "",
        ),
        (
            "POST",
            "/auth/logout",
            format!("{origin}{session_cookie}"),
            503,
            "session unavailable; try again later\n",
            "/auth/logout",
            "",
        ),
        // A body on a route that takes none is refused unread.
        (
            "POST",
            "/auth/logout",
            "Content-Length: 14\r\n\r\nCANARY-payload".into(),
            413,
            "session request body not accepted\n",
            "/auth/logout",
            "",
        ),
        // Paths the document does not name stay unknown.
        (
            "POST",
            "/auth/CANARY-path",
            "Content-Length: 0\r\n".into(),
            404,
            "",
            "unmatched",
            "",
        ),
        (
            "POST",
            "/login",
            "Content-Length: 0\r\n".into(),
            404,
            "",
            "unmatched",
            "",
        ),
        (
            "POST",
            "/healthz",
            "Content-Length: 0\r\n".into(),
            405,
            "",
            "/healthz",
            "GET,HEAD",
        ),
    ];

    for format in ["json", "text"] {
        let bind = address();
        let mut process = start_mounted(
            &bind,
            &url,
            &unavailable_issuance(&database),
            &auth,
            format,
            "150",
        );
        wait_status(&mut process, &bind, "/healthz", 200);
        // Loading and mounting dialled nothing: the lazy pool is still unconnected.
        assert!(database.accept().is_err());
        for (method, target, extra, status, body, route, allow) in &cases {
            let (got, head, text) = exchange(&bind, &request(method, target, extra));
            assert_eq!((got, text.as_str()), (*status, *body), "{method} {target}");
            assert!(!head.contains("set-cookie") && !head.contains("location"));
            assert!(!head.contains("request-id") && !head.contains("canary"));
            let sign_in = route.starts_with("/auth/") || *route == "/callback";
            assert_eq!(head.contains("\r\ncache-control: no-store"), sign_in);
            assert_eq!(head.contains("\r\nreferrer-policy: no-referrer"), sign_in);
            if allow.is_empty() {
                assert!(!head.contains("\r\nallow:"), "{method} {target}");
            } else {
                assert!(
                    head.contains(&format!("\r\nallow: {}", allow.to_ascii_lowercase())),
                    "{method} {target}: {head}"
                );
            }
        }
        // Liveness is unaffected, and the stop fits SHUTDOWN_TIMEOUT_MS (1000).
        assert!(response(&bind, "/healthz").unwrap().ends_with("ok\n"));
        let began = Instant::now();
        stop(&mut process, "-TERM");
        assert!(began.elapsed() < Duration::from_secs(2));
        // Readiness, the session check and the logout dialled the primary database.
        assert!(std::iter::from_fn(|| database.accept().ok()).count() > 0);
        let (stdout, stderr) = drain(&mut process);
        assert!(stdout.is_empty(), "{stdout}");
        for canary in [
            "CANARY",
            "canary",
            SESSION,
            state.as_str(),
            "uuuuuuuu",
            "__Host-",
            "issuer.example.test",
            "app.example.test",
            "invitation",
            dir.path("").as_str(),
        ] {
            assert!(!stderr.contains(canary), "{canary}:\n{stderr}");
        }
        let lines: Vec<&str> = stderr.lines().collect();
        if format == "text" {
            // Health polling precedes the planted requests; the final probe follows them.
            let planted = &lines[lines.len() - 3 - cases.len()..lines.len() - 3];
            for (line, (_, _, _, status, _, route, _)) in planted.iter().zip(&cases) {
                assert!(line.contains("event=\"http.request.completed\""), "{line}");
                assert!(line.contains(&format!("http.route=\"{route}\"")), "{line}");
                assert!(
                    line.contains(&format!("http.response.status_code={status}")),
                    "{line}"
                );
            }
            continue;
        }
        let events: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        // The lifecycle is exactly the unmounted one.
        assert_eq!(
            events[0],
            serde_json::json!({
                "timestamp": events[0]["timestamp"],
                "level": "INFO",
                "event": "process.started",
                "role": "api",
            })
        );
        let names: Vec<&str> = events
            .iter()
            .map(|e| e["event"].as_str().unwrap())
            .collect();
        assert_eq!(
            names[names.len() - 2..],
            ["process.stopping", "process.stopped"]
        );
        assert!(
            names[1..names.len() - 2]
                .iter()
                .all(|name| *name == "http.request.completed")
        );
        let planted = &events[events.len() - 3 - cases.len()..events.len() - 3];
        let mut ids = std::collections::HashSet::new();
        for (event, (method, _, _, status, _, route, _)) in planted.iter().zip(&cases) {
            assert_eq!(event["http.route"], *route);
            assert_eq!(event["http.request.method"], *method);
            assert_eq!(event["http.response.status_code"], *status);
            assert_eq!(
                event["level"],
                if *status >= 500 { "WARN" } else { "DEBUG" }
            );
            // Only the allowlisted fields, with a fresh server-generated identifier.
            let mut fields: Vec<&str> = event
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            assert_eq!(
                fields,
                [
                    "duration_us",
                    "event",
                    "http.request.method",
                    "http.response.status_code",
                    "http.route",
                    "level",
                    "request_id",
                    "timestamp",
                ]
            );
            let id = event["request_id"].as_str().unwrap();
            assert_eq!(id.len(), 36, "{id}");
            assert!(ids.insert(id.to_owned()), "repeated request identifier");
        }
    }
}

/// ADR 0029 through the real API binary, without PostgreSQL or a provider: a native profile
/// mounts the five native routes beside the browser routes and the probes. Previews and
/// refusals touch no pool, and telemetry holds only allowlisted fields and no planted value.
#[test]
fn api_mounts_native_sign_in_routes_beside_the_browser_routes() {
    let dir = auth_config_support::Dir::new();
    let document = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    dir.write("login-key-b", b"CANARY-login-key-active-00000000");
    let auth = dir.write("CANARY-auth.json", document.to_string().as_bytes());
    let (database, url) = unavailable_database();
    database.set_nonblocking(true).unwrap();
    let preview = format!(
        "/auth/native/authorize?client_id=openmettle-desktop\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fnative%2Fcomplete&response_type=code\
         &state={}&code_challenge_method=S256&code_challenge={}",
        "s".repeat(43),
        "c".repeat(43)
    );
    let foreign = preview.replace("openmettle-desktop", "CANARY-client");
    let bearer = format!("Authorization: Bearer {SESSION}\r\n");
    let token = "Content-Type: application/json\r\nContent-Length: 30\r\n\r\n\
                 {\"code\":\"CANARY-code-0000000\"}";
    // (method, target, extra head, status, body prefix, route template)
    let cases: Vec<(&str, &str, String, u16, &str, &str)> = vec![
        ("GET", "/healthz", String::new(), 200, "ok\n", "/healthz"),
        (
            "GET",
            &preview,
            String::new(),
            200,
            "<!doctype html>",
            "/auth/native/authorize",
        ),
        (
            "GET",
            &foreign,
            String::new(),
            403,
            "native sign-in refused\n",
            "/auth/native/authorize",
        ),
        (
            "GET",
            "/auth/native/callback?code=CANARY-code&state=CANARY-state",
            String::new(),
            403,
            "native sign-in refused\n",
            "/auth/native/callback",
        ),
        (
            "POST",
            "/auth/native/token",
            token.into(),
            403,
            "native sign-in refused\n",
            "/auth/native/token",
        ),
        (
            "GET",
            "/auth/native/session",
            String::new(),
            403,
            "native sign-in refused\n",
            "/auth/native/session",
        ),
        (
            "POST",
            "/auth/native/logout",
            "Content-Length: 0\r\nOrigin: https://app.example.test\r\n".into(),
            403,
            "native sign-in refused\n",
            "/auth/native/logout",
        ),
        // A well-formed bearer reaches the primary pool, which cannot connect.
        (
            "GET",
            "/auth/native/session",
            bearer,
            503,
            "native sign-in unavailable\n",
            "/auth/native/session",
        ),
        (
            "POST",
            "/auth/login",
            "Content-Length: 0\r\n".into(),
            403,
            "login origin refused\n",
            "/auth/login",
        ),
    ];
    let bind = address();
    let mut process = start_mounted(
        &bind,
        &url,
        &unavailable_issuance(&database),
        &auth,
        "json",
        "150",
    );
    wait_status(&mut process, &bind, "/healthz", 200);
    assert!(database.accept().is_err());
    for (index, (method, target, extra, status, body, _)) in cases.iter().enumerate() {
        let (got, head, text) = exchange(&bind, &request(method, target, extra));
        assert_eq!(got, *status, "{method} {target}");
        assert!(text.starts_with(body), "{method} {target}: {text}");
        assert!(!head.contains("set-cookie") && !head.contains("location"));
        assert!(!head.contains("request-id") && !head.contains("canary"));
        assert_eq!(
            head.contains("\r\ncache-control: no-store"),
            *target != "/healthz"
        );
        // Every case before the bearer was decided without the primary pool.
        if index == 6 {
            assert!(database.accept().is_err());
        }
    }
    stop(&mut process, "-TERM");
    let (stdout, stderr) = drain(&mut process);
    assert!(stdout.is_empty(), "{stdout}");
    for canary in [
        "CANARY",
        "canary",
        SESSION,
        "sssssssss",
        "ccccccccc",
        "openmettle-desktop",
        "native/complete",
        "0b5c6f4e",
        "app.example.test",
        dir.path("").as_str(),
    ] {
        assert!(!stderr.contains(canary), "{canary}:\n{stderr}");
    }
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let planted = &events[events.len() - 2 - cases.len()..events.len() - 2];
    for (event, (method, _, _, status, _, route)) in planted.iter().zip(&cases) {
        assert_eq!(event["event"], "http.request.completed");
        assert_eq!(event["http.route"], *route);
        assert_eq!(event["http.request.method"], *method);
        assert_eq!(event["http.response.status_code"], *status);
        assert_eq!(event.as_object().unwrap().len(), 8, "{event}");
    }
    assert_eq!(events.last().unwrap()["event"], "process.stopped");
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
        // ADRs 0017–0019 and 0025: without `AUTH_CONFIG` neither the browser login handoff
        // nor its router is mounted. The synthetic callback path, a form POST, a session
        // check and a logout are unknown routes, no response sets or deletes a cookie or
        // redirects, and the two operational routes still answer GET alone.
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

fn gateway() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openmettle-gateway"));
    scrub_env(&mut command);
    command
}

/// `openmettle-gateway` refuses missing or unsupported settings with one fixed line that names
/// the key, never the value, and exits 78 before any listener opens.
#[test]
fn gateway_refuses_incomplete_or_unsupported_settings_with_a_fixed_line() {
    // Serving would exit 1 on this occupied address instead.
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let database = ("DATABASE_URL", "postgres://localhost/test");
    let upstream = ("UPSTREAM_URL", "http://127.0.0.1:30000");
    let model = ("MODEL", "synthetic-model");
    let oversized = "m".repeat(129);
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[upstream, model], "DATABASE_URL is required"),
        (&[database, model], "UPSTREAM_URL is required"),
        (&[database, upstream], "MODEL is required"),
        (&[database, upstream, ("MODEL", "")], "invalid MODEL"),
        (
            &[database, upstream, ("MODEL", &oversized)],
            "invalid MODEL",
        ),
        (
            &[
                database,
                ("UPSTREAM_URL", "https://synthetic-secret.example.test"),
            ],
            "UPSTREAM_URL must use http://",
        ),
        (
            &[database, ("UPSTREAM_URL", "synthetic-secret")],
            "invalid UPSTREAM_URL",
        ),
        (
            &[
                database,
                (
                    "UPSTREAM_URL",
                    "http://synthetic-secret:8000/v1/chat/completions",
                ),
            ],
            "invalid UPSTREAM_URL",
        ),
        (
            &[database, upstream, model, ("UPSTREAM_IDLE_TIMEOUT_MS", "0")],
            "configuration outside allowed range",
        ),
        (
            &[
                database,
                upstream,
                model,
                ("CACHE_MODE", "bogus-cache-mode-canary"),
            ],
            "invalid CACHE_MODE",
        ),
    ];
    for (index, (settings, line)) in cases.iter().enumerate() {
        let mut command = gateway();
        command.env(
            "OPENMETTLE_GATEWAY_BIND",
            occupied.local_addr().unwrap().to_string(),
        );
        for (key, value) in *settings {
            command.env(format!("OPENMETTLE_GATEWAY_{key}"), value);
        }
        let keys: Vec<&str> = settings.iter().map(|(k, _)| *k).collect();
        let context = format!("gateway refusal case #{index} ({line}; keys={keys:?})");
        let output = run(&mut command, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert!(output.stdout.is_empty(), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("configuration error: {line}\n"),
            "{context}"
        );
    }
    // The API's issuance credential is refused here as in the worker.
    let mut cmd = gateway();
    cmd.env("OPENMETTLE_GATEWAY_DATABASE_URL", database.1)
        .env("OPENMETTLE_GATEWAY_UPSTREAM_URL", upstream.1)
        .env("OPENMETTLE_GATEWAY_MODEL", model.1)
        .env(
            "OPENMETTLE_API_ISSUANCE_DATABASE_URL",
            "postgres://CANARY@localhost/test",
        );
    let output = run(
        &mut cmd,
        "gateway refuses OPENMETTLE_API_ISSUANCE_DATABASE_URL",
    );
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "configuration error: OPENMETTLE_API_ISSUANCE_DATABASE_URL is refused outside the API\n"
    );
}

/// The gateway serves the operational probes and the one proxy route, records its role in
/// lifecycle events and drains on SIGTERM, with PostgreSQL and the upstream unavailable.
#[test]
fn gateway_serves_probes_and_its_route_and_stops_on_a_signal() {
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = address();
    let mut process = Process(
        gateway()
            .env("OPENMETTLE_GATEWAY_BIND", &bind)
            .env(
                "OPENMETTLE_GATEWAY_DATABASE_URL",
                format!(
                    "postgres://fixture@{}/fixture?sslmode=disable",
                    unavailable.local_addr().unwrap()
                ),
            )
            .env("OPENMETTLE_GATEWAY_DB_TIMEOUT_MS", "150")
            .env("OPENMETTLE_GATEWAY_SHUTDOWN_TIMEOUT_MS", "1000")
            .env("OPENMETTLE_GATEWAY_UPSTREAM_URL", "http://127.0.0.1:9")
            .env("OPENMETTLE_GATEWAY_MODEL", "synthetic-model")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    wait_status(&mut process, &bind, "/healthz", 200);
    assert!(
        response(&bind, "/readyz")
            .unwrap()
            .starts_with("HTTP/1.1 503")
    );
    for (request, status) in [
        ("GET /v1/chat/completions", 405),
        ("POST /v1/responses", 404),
        ("POST /v1/completions", 404),
    ] {
        let reply = send(
            &bind,
            &format!("{request} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        )
        .unwrap();
        assert!(
            reply.starts_with(&format!("HTTP/1.1 {status}")),
            "{request}"
        );
    }
    // An unusable request ID is refused before the database or the upstream is consulted.
    let reply = send(
        &bind,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .unwrap();
    assert!(reply.starts_with("HTTP/1.1 400"));
    assert!(reply.contains("\"code\":\"validation\""));
    // So is a request without a usable credential: one `Authorization: Bearer` header holding
    // 32 bytes as unpadded base64url.
    let id = "0f8fad5b-d9cb-469f-a165-70867728950e";
    let request = |credential: &str| {
        format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {id}\r\n\
             {credential}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        )
    };
    let secret = "A".repeat(43);
    for credential in [
        String::new(),
        "Authorization: Bearer canary-credential\r\n".to_owned(),
        format!("Authorization: Basic {secret}\r\n"),
        format!("Authorization: Bearer {secret}\r\n").repeat(2),
    ] {
        let reply = send(&bind, &request(&credential)).unwrap();
        assert!(reply.starts_with("HTTP/1.1 401"), "{credential}");
        assert!(reply.contains("\"code\":\"unauthenticated\""));
        assert!(
            reply
                .to_ascii_lowercase()
                .contains("www-authenticate: bearer\r\n")
        );
    }
    // A `Connection` field that cannot be read could hide a hop-by-hop nomination of the
    // credential: a byte that is not ASCII, or a tab, which a header value may hold. The request
    // is refused before the credential or the database is consulted.
    for (unreadable, ending) in [
        ("a byte that is not ASCII", &b"close, Authorization\xff"[..]),
        ("a tab", b"close,\tAuthorization"),
    ] {
        let mut malformed = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {id}\r\n\
             Authorization: Bearer {secret}\r\nContent-Length: 2\r\nConnection: "
        )
        .into_bytes();
        malformed.extend_from_slice(ending);
        malformed.extend_from_slice(b"\r\n\r\n{}");
        let mut stream = TcpStream::connect(&bind).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.write_all(&malformed).unwrap();
        // The server may not read `close` from this field and keep the connection open: read
        // up to the end of the problem document, not to the end of the stream.
        let (mut raw, mut chunk) = (Vec::new(), [0; 4096]);
        while !raw.ends_with(b"}") {
            match stream.read(&mut chunk) {
                Ok(n @ 1..) => raw.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        let reply = String::from_utf8_lossy(&raw);
        assert!(reply.starts_with("HTTP/1.1 400"), "{unreadable}: {reply}");
        assert!(reply.contains("\"code\":\"validation\""), "{unreadable}");
    }
    // A well-formed credential reaches the database, which is unavailable: the dispatch is
    // unconfirmed and nothing is forwarded.
    let reply = send(
        &bind,
        &request(&format!("Authorization: Bearer {secret}\r\n")),
    )
    .unwrap();
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    stop(&mut process, "-TERM");
    let (stdout, stderr) = drain(&mut process);
    assert!(stdout.is_empty());
    assert!(!stderr.contains(&secret) && !stderr.contains("canary-credential"));
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let unconfirmed: Vec<_> = events
        .iter()
        .filter(|e| e["event"] == "gateway.usage.unrecorded")
        .map(|e| (e["gateway.request_id"].as_str(), e["error.type"].as_str()))
        .collect();
    assert_eq!(unconfirmed, [(Some(id), Some("dispatch_unconfirmed"))]);
    let lifecycle: Vec<_> = events
        .iter()
        .filter(|e| e["role"] == "gateway")
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        lifecycle,
        ["process.started", "process.stopping", "process.stopped"]
    );
}

#[test]
fn occupied_listener_exits_with_runtime_error() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cmd = command(false);
    cmd.env(
        "OPENMETTLE_API_BIND",
        listener.local_addr().unwrap().to_string(),
    )
    .env("OPENMETTLE_API_DATABASE_URL", "postgres://localhost/test");
    let output = run(&mut cmd, "api occupied listener bind failure");
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

/// A fresh migrated database owned by `openmettle_owner`, dropped when the test ends. Its
/// administrative connection holds the shared role-state lock, as every test database does.
struct MigratedDb(pg::DisposableDb);
impl MigratedDb {
    async fn new() -> Self {
        let db = pg::DisposableDb::create("om_runtime", false, false, "").await;
        openmettle_core::migrate::apply(
            &openmettle_core::migrate::Settings {
                database: db.options(pg::OWNER),
                connect_timeout: Duration::from_secs(5),
                lock_timeout: Duration::from_secs(10),
                statement_timeout: Duration::from_secs(30),
            },
            openmettle_core::migrate::MIGRATIONS,
        )
        .await
        .unwrap();
        Self(db)
    }
    /// An application role's URL, never the owner's.
    fn url(&self, role: &str) -> String {
        self.0.url(role)
    }
}

/// ADR 0025 on PostgreSQL: the real API binary, as `openmettle_api` on a migrated database,
/// with the sign-in routes mounted. Readiness stays a database query while the configured
/// provider is a reserved name that cannot be reached, and the session routes are answered
/// by the primary database: it refuses an unknown credential, where an unreachable database
/// gives `503`. The issuance pool (ADR 0030) points at an address that never answers, and
/// neither readiness nor a session route ever dials it. No provider is contacted;
/// issued-session journeys are covered by the managed PostgreSQL router tests and the Keycloak
/// qualification.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn postgres_mounted_session_routes_use_the_primary_database() {
    let db = MigratedDb::new().await;
    let dir = auth_config_support::Dir::new();
    // With the native profile (ADR 0029), whose session routes use the same pool and role.
    let document = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    let auth = dir.write("auth.json", document.to_string().as_bytes());
    let bind = address();
    let (issuance, _) = unavailable_database();
    issuance.set_nonblocking(true).unwrap();
    let mut api = start_mounted(
        &bind,
        &db.url(pg::API),
        &unavailable_issuance(&issuance),
        &auth,
        "json",
        "2000",
    );
    wait_status(&mut api, &bind, "/readyz", 200);

    let session =
        format!("Sec-Fetch-Site: same-origin\r\nCookie: __Host-openmettle-session={SESSION}\r\n");
    let logout = format!(
        "Origin: https://app.example.test\r\nContent-Length: 0\r\n\
         Cookie: __Host-openmettle-session={SESSION}\r\n"
    );
    // Repeated, so a connection left unusable by one refusal would surface in the next.
    for _ in 0..3 {
        for (method, target, extra) in [
            ("GET", "/auth/session", session.as_str()),
            ("POST", "/auth/logout", logout.as_str()),
        ] {
            let (status, head, body) = exchange(&bind, &request(method, target, extra));
            assert_eq!(
                (status, body.as_str()),
                (403, "session not valid\n"),
                "{method} {target}"
            );
            assert!(head.contains("\r\ncache-control: no-store"));
            assert!(!head.contains("set-cookie") && !head.contains("location"));
        }
        let bearer = format!("Authorization: Bearer {SESSION}\r\n");
        for (method, target, extra) in [
            ("GET", "/auth/native/session", bearer.clone()),
            (
                "POST",
                "/auth/native/logout",
                format!("Content-Length: 0\r\n{bearer}"),
            ),
        ] {
            let (status, head, body) = exchange(&bind, &request(method, target, &extra));
            assert_eq!(
                (status, body.as_str()),
                (403, "native sign-in refused\n"),
                "{method} {target}"
            );
            assert!(head.contains("\r\ncache-control: no-store"));
        }
        let (status, _, body) = exchange(&bind, &request("GET", "/readyz", ""));
        assert_eq!((status, body.as_str()), (200, "ready\n"));
    }
    assert!(issuance.accept().is_err(), "the issuance pool was dialled");
    stop(&mut api, "-TERM");
    let (stdout, stderr) = drain(&mut api);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.contains(SESSION) && !stderr.contains(pg::PASSWORD));
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    // Twelve refusals by the database, browser and native, none of them a server error.
    let refused = events
        .iter()
        .filter(|event| event["http.response.status_code"] == 403)
        .count();
    assert_eq!(refused, 12, "{stderr}");
    assert!(events.iter().all(|event| event["level"] != "WARN"));
    assert_eq!(events.last().unwrap()["event"], "process.stopped");
}

#[test]
fn worker_scheduling_configuration_is_validated_before_serving() {
    let policy = [
        ("RUN_SLOTS", "1"),
        ("LEASE_MS", "30000"),
        ("EXECUTION_TIMEOUT_MS", "60000"),
        ("EXECUTING_PER_ACTOR", "1"),
        ("EXECUTING_PER_SCOPE", "1"),
    ];
    let invoke = |worker: bool, vars: &[(&str, &str)], message: &str| {
        let role = role_name(worker);
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        let mut child = command(worker);
        child.env(
            format!("{prefix}_DATABASE_URL"),
            "postgres://localhost/test",
        );
        for (key, value) in vars {
            child.env(format!("OPENMETTLE_WORKER_{key}"), value);
        }
        let config = vars
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let context = format!("{role} scheduling config [{config}] (expected: {message})");
        let output = run(&mut child, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("configuration error: {message}\n"),
            "{context}"
        );
    };
    for (key, below, above) in [
        ("SWEEP_MS", "999", "3600001"),
        ("POLL_MS", "99", "60001"),
        ("RUN_SLOTS", "0", "257"),
        ("LEASE_MS", "29999", "600001"),
        ("EXECUTION_TIMEOUT_MS", "59999", "86400001"),
        ("EXECUTING_PER_ACTOR", "0", "1025"),
        ("EXECUTING_PER_SCOPE", "0", "1025"),
    ] {
        invoke(
            false,
            &[(key, "")],
            "worker scheduling settings are refused on the API",
        );
        for value in [below, above, "synthetic-invalid"] {
            let mut vars = policy.to_vec();
            vars.push((key, value));
            invoke(true, &vars, key);
        }
    }
    // ADR 0043: slots and the inference document come together, and the API refuses both.
    invoke(true, &policy, "RUN_SLOTS requires INFERENCE_CONFIG");
    let document = ("INFERENCE_CONFIG", "/etc/openmettle/inference.json");
    invoke(true, &[document], "INFERENCE_CONFIG requires RUN_SLOTS");
    for path in ["inference.json", ""] {
        let mut vars = policy.to_vec();
        vars.push(("INFERENCE_CONFIG", path));
        invoke(true, &vars, "invalid INFERENCE_CONFIG");
    }
    invoke(
        false,
        &[document],
        "worker scheduling settings are refused on the API",
    );
    invoke(
        true,
        &policy[..1],
        "RUN_SLOTS requires lease and claim settings",
    );
    for &var in &policy[1..] {
        invoke(true, &[var], "lease and claim settings require RUN_SLOTS");
    }
    for (change, message) in [
        (
            ("DB_TIMEOUT_MS", "5001"),
            "LEASE_MS must cover six DB_TIMEOUT_MS",
        ),
        (
            ("LEASE_MS", "30001"),
            "EXECUTION_TIMEOUT_MS must cover two leases",
        ),
    ] {
        let mut vars = policy.to_vec();
        vars.push(change);
        invoke(true, &vars, message);
    }
}

/// ADR 0043 through the worker binary: an invalid inference document exits 78 with one fixed
/// line before telemetry, the listener or the database, and a valid one starts the run loop
/// without contacting its gateway, then stops cleanly.
#[test]
fn worker_validates_its_inference_document_before_serving() {
    let catalog: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/conversation-catalog-v1.json")).unwrap();
    let policy = [
        ("RUN_SLOTS", "2"),
        ("LEASE_MS", "30000"),
        ("EXECUTION_TIMEOUT_MS", "60000"),
        ("EXECUTING_PER_ACTOR", "1"),
        ("EXECUTING_PER_SCOPE", "1"),
    ];
    let (database, url) = unavailable_database();
    database.set_nonblocking(true).unwrap();
    let dir = auth_config_support::Dir::new();
    let valid = auth_config_support::inference_document(
        &dir,
        &catalog,
        &ca::Ca::new().pem(),
        "canary-gateway.example.test:8443",
    );
    let mut cases = vec![
        (
            "invalid installation UUID",
            json_with(&valid, "/installation", "CANARY-installation"),
            "gateway installation is not a canonical UUID",
        ),
        (
            "invalid route endpoint query",
            json_with(
                &valid,
                "/routes/a/endpoint",
                "https://canary-gateway.example.test/CANARY?CANARY",
            ),
            "an inference route endpoint, trust, address policy or timeout is invalid",
        ),
        (
            "mismatched route catalog pin",
            json_with(&valid, "/routes/b/pin/revision", "CANARY-revision"),
            "an inference route does not match its catalog profile",
        ),
    ];
    // A document that still carries the key ring ADR 0044 superseded is refused.
    let mut ring = valid.clone();
    ring["gateway_keys"] = serde_json::json!({
        "active": {"id": "gateway-b", "path": dir.write("CANARY-key", &[0xc2; 32])},
        "decrypt_only": []
    });
    cases.push((
        "legacy gateway_keys field",
        ring,
        "configuration has an unknown field",
    ));
    // A plain route names no range to hold the gateway's addresses.
    let mut plain = valid.clone();
    plain["routes"]["a"]["endpoint"] = "http://canary-gateway.example.test:8082/CANARY".into();
    plain["routes"]["a"]
        .as_object_mut()
        .unwrap()
        .remove("trust");
    cases.push((
        "plain HTTP route without private_cidrs",
        plain,
        "a plain HTTP inference route needs private_cidrs holding every gateway address",
    ));
    let mut uncovered = valid.clone();
    uncovered["routes"].as_object_mut().unwrap().remove("b");
    cases.push((
        "missing catalog model route",
        uncovered,
        "inference routes do not name exactly the catalog's models",
    ));
    for (label, document, message) in cases {
        let path = dir.write("inference.json", document.to_string().as_bytes());
        let mut child = command(true);
        child
            .env("OPENMETTLE_WORKER_DATABASE_URL", &url)
            .env("OPENMETTLE_WORKER_INFERENCE_CONFIG", &path);
        for (key, value) in policy {
            child.env(format!("OPENMETTLE_WORKER_{key}"), value);
        }
        let context = format!("worker inference document refusal ({label}; expected: {message})");
        let output = run(&mut child, &context);
        assert_eq!(output.status.code(), Some(78), "{context}");
        assert!(output.stdout.is_empty(), "{context}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("inference configuration error: {message}\n"),
            "{context}"
        );
    }
    // No refused process dialled the database.
    assert!(database.accept().is_err());
    let path = dir.write("inference.json", valid.to_string().as_bytes());
    let bind = address();
    let mut settings: Vec<(&str, &str)> = policy.to_vec();
    settings.push(("INFERENCE_CONFIG", &path));
    let mut process = start_logging(true, &bind, &url, &settings);
    wait_status(&mut process, &bind, "/healthz", 200);
    stop(&mut process, "-TERM");
    let (stdout, stderr) = drain(&mut process);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        !stderr.contains("CANARY") && !stderr.contains("canary"),
        "{stderr}"
    );
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.first().unwrap()["event"], "process.started");
    assert_eq!(events.last().unwrap()["event"], "process.stopped");
}

fn json_with(document: &serde_json::Value, pointer: &str, value: &str) -> serde_json::Value {
    let mut document = document.clone();
    *document.pointer_mut(pointer).unwrap() = value.into();
    document
}

#[test]
fn failed_sweeps_report_fixed_categories_and_retry_next_tick() {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    struct ReaderGuard {
        abort: Arc<AtomicBool>,
        stop_deadline: Arc<Mutex<Option<Instant>>>,
        handle: Option<thread::JoinHandle<()>>,
    }
    impl ReaderGuard {
        fn finish(mut self, timeout: Duration) {
            *self.stop_deadline.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(Instant::now() + timeout);
            let handle = self.handle.take().expect("sweep reader handle missing");
            handle
                .join()
                .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
        }
    }
    impl Drop for ReaderGuard {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                self.abort.store(true, Ordering::Relaxed);
                *self.stop_deadline.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Instant::now());
                let _ = handle.join();
            }
        }
    }

    let dir = auth_config_support::Dir::new();
    let root = dir.path("payloads");
    std::fs::create_dir(&root).unwrap();
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "postgres://fixture:CANARY@{}/fixture",
        unavailable.local_addr().unwrap()
    );
    let mut process = start_logging(
        true,
        &address(),
        &url,
        &[("SWEEP_MS", "1000"), ("ARTIFACTS_DIR", &root)],
    );
    let mut pipe = process.0.stderr.take().unwrap();
    let flags = fcntl_getfl(&pipe).unwrap();
    fcntl_setfl(&pipe, flags | OFlags::NONBLOCK).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let abort = Arc::new(AtomicBool::new(false));
    let reader_abort = Arc::clone(&abort);
    let stop_deadline = Arc::new(Mutex::new(None::<Instant>));
    let reader_deadline = Arc::clone(&stop_deadline);
    let reader = ReaderGuard {
        abort,
        stop_deadline,
        handle: Some(thread::spawn(move || {
            let mut pending = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut sleep = Duration::from_millis(2);
            loop {
                if reader_abort.load(Ordering::Relaxed) {
                    return;
                }
                let maybe_deadline = *reader_deadline.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(deadline) = maybe_deadline {
                    assert!(
                        Instant::now() < deadline,
                        "worker sweep stderr did not reach EOF within {PIPE_DRAIN_TIMEOUT:?}"
                    );
                }
                match pipe.read(&mut chunk) {
                    Ok(0) => {
                        assert!(pending.is_empty(), "trailing partial stderr line");
                        return;
                    }
                    Ok(n) => {
                        pending.extend_from_slice(&chunk[..n]);
                        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                            let raw: Vec<u8> = pending.drain(..=pos).collect();
                            let line = String::from_utf8(raw).unwrap();
                            let line = line.trim_end_matches('\n');
                            assert!(!line.contains("CANARY"));
                            let event: serde_json::Value = serde_json::from_str(line).unwrap();
                            if event["event"] == "worker.sweep.failed" {
                                assert_eq!(event["level"], "WARN");
                                assert_eq!(event["role"], "worker");
                                let _ = tx.send(event["error.type"].as_str().unwrap().to_owned());
                            }
                        }
                        sleep = Duration::from_millis(2);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        if let Some(deadline) = maybe_deadline {
                            let now = Instant::now();
                            assert!(
                                now < deadline,
                                "worker sweep stderr did not reach EOF within {PIPE_DRAIN_TIMEOUT:?}"
                            );
                            thread::sleep(sleep.min(deadline.saturating_duration_since(now)));
                        } else {
                            thread::sleep(sleep);
                        }
                        sleep = (sleep * 2).min(Duration::from_millis(25));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => panic!("failed reading worker sweep stderr: {err}"),
                }
            }
        })),
    };
    for _ in 0..2 {
        for expected in [
            "expire_queued",
            "settle_expired",
            "reconcile_stale_quotas",
            "reconcile_expired",
            "purge_due",
        ] {
            assert_eq!(rx.recv_timeout(Duration::from_secs(6)).unwrap(), expected);
        }
    }
    stop(&mut process, "-TERM");
    reader.finish(PIPE_DRAIN_TIMEOUT);
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else {
        String::new()
    }
}

/// Regression test for the shared bounded process and readiness helpers:
/// 1. A real `openmettle-api` binary that starts instead of refusing fails within the deadline,
///    emits `process.started` into the captured timeout diagnostics, names the configuration label
///    and stops listening after being killed and reaped.
/// 2. `wait_exit_bounded` and `wait_output_bounded` time out promptly, kill and reap a
///    long-running child, and name the configuration label.
/// 3. A child whose background descendant inherits stdout/stderr still times out promptly with its
///    pre-hang diagnostic marker intact and zero leaked reader threads; bounded post-exit pipe
///    readers (`read_string_bounded` and `PipeDrain`) likewise fail within their deadline when a
///    descendant keeps the write end open.
/// 4. `wait_http_status_bounded` fails promptly at its deadline against a slow-drip HTTP peer.
/// 5. `run_bounded` drains stdout and stderr concurrently past OS pipe buffer sizes without
///    deadlocking.
#[test]
fn bounded_process_helpers_time_out_kill_and_name_configuration() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    // 1. Real binary starting instead of refusing.
    let (_database, url) = unavailable_database();
    let bind = address();
    let label = "synthetic-refusal-case: OPENMETTLE_API_BIND=ephemeral";
    let mut cmd = command(false);
    cmd.env("OPENMETTLE_API_BIND", &bind)
        .env("OPENMETTLE_API_DATABASE_URL", &url)
        .env("OPENMETTLE_API_DB_TIMEOUT_MS", "150")
        .env("OPENMETTLE_API_SHUTDOWN_TIMEOUT_MS", "1000");
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_bounded(&mut cmd, Duration::from_secs(1), label)
    }))
    .expect_err("serving binary must time out");
    assert!(
        began.elapsed() < Duration::from_secs(3),
        "run_bounded took too long: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("timed out after"),
        "expected timeout failure message, got: {message}"
    );
    assert!(message.contains(label), "missing label in panic: {message}");
    assert!(
        message.contains("process.started"),
        "expected openmettle-api startup event in timeout diagnostics, got: {message}"
    );
    assert!(
        TcpStream::connect_timeout(&bind.parse().unwrap(), Duration::from_millis(200)).is_err(),
        "timed-out binary kept listening on {bind}"
    );

    // 2. `wait_exit_bounded` kills and reaps a long-running child.
    let mut sleeper = Process(
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let pid = sleeper.0.id();
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_exit_bounded(
            &mut sleeper.0,
            Duration::from_millis(150),
            "synthetic-sleep-exit-case",
        )
    }))
    .expect_err("sleep child must time out");
    assert!(
        began.elapsed() < Duration::from_secs(3),
        "wait_exit_bounded took too long: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("timed out after"),
        "expected timeout failure message, got: {message}"
    );
    assert!(
        message.contains("synthetic-sleep-exit-case"),
        "missing label in panic: {message}"
    );
    assert!(
        sleeper.0.try_wait().unwrap().is_some(),
        "timed-out child was not reaped"
    );
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(!alive, "timed-out child pid {pid} is still alive");

    // 3. `wait_output_bounded` kills and reaps an already-spawned piped child.
    let sleeper = Process(
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let pid = sleeper.0.id();
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_output_bounded(
            sleeper,
            Duration::from_millis(150),
            "synthetic-sleep-output-case",
        )
    }))
    .expect_err("piped sleep child must time out");
    assert!(
        began.elapsed() < Duration::from_secs(3),
        "wait_output_bounded took too long: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("timed out after"),
        "expected timeout failure message, got: {message}"
    );
    assert!(
        message.contains("synthetic-sleep-output-case"),
        "missing label in panic: {message}"
    );
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(!alive, "timed-out piped child pid {pid} is still alive");

    // 4. Inherited descendant pipe: timeout fails well before `sleep 5`, retains pre-hang stderr
    //    diagnostics, and spawns no leaking reader threads.
    let mut inherited = Command::new("sh");
    inherited.args(["-c", "echo marker-before-hang >&2; sleep 5 & wait"]);
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_bounded(
            &mut inherited,
            Duration::from_millis(150),
            "synthetic-inherited-pipe-case",
        )
    }))
    .expect_err("child with inherited grandchild pipe must time out");
    assert!(
        began.elapsed() < Duration::from_millis(1500),
        "run_bounded waited for descendant pipe: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("timed out after"),
        "expected timeout failure message, got: {message}"
    );
    assert!(
        message.contains("synthetic-inherited-pipe-case"),
        "missing label in panic: {message}"
    );
    assert!(
        message.contains("marker-before-hang"),
        "lost pre-hang stderr marker in panic: {message}"
    );

    // 5. Post-exit bounded pipe readers (`read_string_bounded` and `PipeDrain`) fail promptly and
    //    preserve already-written diagnostics when a descendant keeps stderr open after child exit.
    let mut lingering = Process(
        Command::new("sh")
            .args(["-c", "echo post-exit-marker >&2; sleep 5 &"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(
        wait_exit_bounded(
            &mut lingering.0,
            Duration::from_secs(2),
            "post-exit-marker child",
        )
        .success()
    );
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_string_bounded(
            lingering.0.stderr.take().unwrap(),
            Duration::from_millis(150),
            "stderr",
            "synthetic-post-exit-pipe-case",
        )
    }))
    .expect_err("read_string_bounded must time out on inherited pipe");
    assert!(
        began.elapsed() < Duration::from_millis(1500),
        "read_string_bounded waited for descendant pipe: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("synthetic-post-exit-pipe-case") && message.contains("post-exit-marker"),
        "missing label or marker in post-exit pipe panic: {message}"
    );

    let mut lingering_drain = Process(
        Command::new("sh")
            .args(["-c", "echo pipe-drain-marker >&2; sleep 5 &"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let drain = PipeDrain::start(
        lingering_drain.0.stderr.take().unwrap(),
        "stderr",
        "synthetic-pipe-drain-case",
    );
    assert!(
        wait_exit_bounded(
            &mut lingering_drain.0,
            Duration::from_secs(2),
            "pipe-drain-marker child",
        )
        .success()
    );
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drain.finish_string(Duration::from_millis(150))
    }))
    .expect_err("PipeDrain must time out on inherited pipe");
    assert!(
        began.elapsed() < Duration::from_millis(1500),
        "PipeDrain waited for descendant pipe: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("synthetic-pipe-drain-case") && message.contains("pipe-drain-marker"),
        "missing label or marker in PipeDrain panic: {message}"
    );

    // 6. Readiness probe (`wait_http_status_bounded`) fails promptly against a slow-drip peer
    //    sending 1 byte every 200 ms with no newline or EOF (with an independent 3 s server cutoff
    //    beyond the 1.5 s assertion threshold so a read-until-EOF regression still terminates).
    let drip_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let drip_addr = drip_listener.local_addr().unwrap().to_string();
    drip_listener.set_nonblocking(true).unwrap();
    let stop_drip = Arc::new(AtomicBool::new(false));
    let drip_flag = Arc::clone(&stop_drip);
    let drip_server = thread::spawn(move || {
        let server_cutoff = Instant::now() + Duration::from_secs(3);
        while !drip_flag.load(Ordering::Relaxed) && Instant::now() < server_cutoff {
            match drip_listener.accept() {
                Ok((mut stream, _)) => {
                    while !drip_flag.load(Ordering::Relaxed) && Instant::now() < server_cutoff {
                        if stream.write_all(b"H").is_err() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(200));
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    let mut dummy = Process(
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_http_status_bounded(
            &mut dummy,
            &drip_addr,
            "/readyz",
            200,
            Duration::from_millis(500),
        )
    }))
    .expect_err("slow-drip readiness probe must time out");
    stop_drip.store(true, Ordering::Relaxed);
    drip_server.join().unwrap();
    assert!(
        began.elapsed() < Duration::from_millis(1500),
        "slow-drip readiness probe outlived its deadline: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("deadline") && message.contains("/readyz"),
        "unexpected slow-drip probe panic: {message}"
    );

    // 7. `run_bounded` drains stdout and stderr past typical 64 KiB pipe buffers without deadlock.
    let mut flood = Command::new("sh");
    flood.args([
        "-c",
        "dd if=/dev/zero bs=1024 count=128 2>/dev/null && dd if=/dev/zero bs=1024 count=128 1>&2 2>/dev/null",
    ]);
    let output = run_bounded(&mut flood, Duration::from_secs(5), "pipe-flood-drain");
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 128 * 1024);
    assert_eq!(output.stderr.len(), 128 * 1024);

    // 8. Continuously readable pipes cannot defeat deadlines in `read_string_bounded`,
    //    `PipeDrain::finish_string`, or `run_bounded` / `wait_output_bounded`.
    let spawn_continuous_pipe = |duration: Duration| {
        let (reader, mut writer) = std::io::pipe().unwrap();
        let flags = rustix::fs::fcntl_getfl(&writer).unwrap();
        rustix::fs::fcntl_setfl(&writer, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
        let handle = thread::spawn(move || {
            let until = Instant::now() + duration;
            let buf = [b'x'; 4096];
            while Instant::now() < until {
                match writer.write(&buf) {
                    Ok(_) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        (reader, handle)
    };

    let (reader, writer_handle) = spawn_continuous_pipe(Duration::from_millis(250));
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_string_bounded(
            reader,
            Duration::from_millis(30),
            "stderr",
            "synthetic-continuous-pipe-read",
        )
    }))
    .expect_err("continuously readable pipe must time out in read_string_bounded");
    let elapsed = began.elapsed();
    writer_handle.join().unwrap();
    assert!(
        elapsed < Duration::from_millis(200),
        "read_string_bounded overrun on continuously readable pipe: {elapsed:?}"
    );
    let message = panic_text(err);
    assert!(
        message.contains("synthetic-continuous-pipe-read"),
        "missing label in continuous pipe read panic: {message}"
    );

    let (reader, writer_handle) = spawn_continuous_pipe(Duration::from_millis(250));
    let drain = PipeDrain::start(reader, "stderr", "synthetic-continuous-pipe-drain");
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drain.finish_string(Duration::from_millis(30))
    }))
    .expect_err("continuously readable pipe must time out in PipeDrain::finish_string");
    let elapsed = began.elapsed();
    writer_handle.join().unwrap();
    assert!(
        elapsed < Duration::from_millis(200),
        "PipeDrain::finish_string overrun on continuously readable pipe: {elapsed:?}"
    );
    let message = panic_text(err);
    assert!(
        message.contains("synthetic-continuous-pipe-drain"),
        "missing label in continuous PipeDrain panic: {message}"
    );

    let mut continuous_child = Command::new("yes");
    continuous_child.arg("continuously-readable-marker");
    let began = Instant::now();
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_bounded(
            &mut continuous_child,
            Duration::from_millis(60),
            "synthetic-continuous-yes-case",
        )
    }))
    .expect_err("yes child must time out promptly");
    assert!(
        began.elapsed() < Duration::from_millis(1000),
        "run_bounded overrun on yes child: {:?}",
        began.elapsed()
    );
    let message = panic_text(err);
    assert!(
        message.contains("synthetic-continuous-yes-case")
            && message.contains("continuously-readable-marker"),
        "missing label or marker in continuous yes panic: {message}"
    );
}
