//! Black-box process tests. Real PostgreSQL is required only by the ignored test.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "support/env.rs"]
mod env_support;
use env_support::scrub_env;
#[path = "auth_config_support/mod.rs"]
mod auth_config_support;
#[path = "support/pg.rs"]
mod pg;
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
    for (auth, database, issuance, extra, line) in cases {
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
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(78), "{line}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("configuration error: {line}\n")
        );
    }
    // A user filled from `PGUSER` counts as that user, on either URL.
    for (database, issuance) in [
        (
            "postgres://localhost/test",
            "postgres://openmettle_api@localhost/other",
        ),
        (primary, "postgres://localhost/other"),
    ] {
        let output = command(false)
            .env("PGUSER", "openmettle_api")
            .env("OPENMETTLE_API_BIND", &bind)
            .env("OPENMETTLE_API_DATABASE_URL", database)
            .env("OPENMETTLE_API_AUTH_CONFIG", "/CANARY-absent/auth.json")
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", issuance)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78), "{database} {issuance}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "configuration error: ISSUANCE_DATABASE_URL must use a different user\n"
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
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(78), "{max:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "auth configuration error: configuration is not a readable regular file within bounds\n"
        );
    }
    // The worker refuses the API's issuance URL whatever its value, and reads no issuance
    // setting under its own prefix.
    for value in [
        OsStr::new(issuance),
        OsStr::new(""),
        OsStr::from_bytes(b"CANARY-\xff"),
    ] {
        let output = command(true)
            .env("OPENMETTLE_WORKER_BIND", &bind)
            .env(
                "OPENMETTLE_WORKER_DATABASE_URL",
                "postgres://localhost/test",
            )
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", value)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78), "{value:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "configuration error: OPENMETTLE_API_ISSUANCE_DATABASE_URL is refused outside the API\n"
        );
    }
    // Under its own prefix, unread: the occupied listener is the first failure.
    let output = command(true)
        .env("OPENMETTLE_WORKER_BIND", &bind)
        .env(
            "OPENMETTLE_WORKER_DATABASE_URL",
            "postgres://localhost/test",
        )
        .env(
            "OPENMETTLE_WORKER_ISSUANCE_DATABASE_URL",
            "invalid://CANARY",
        )
        .env("OPENMETTLE_WORKER_ISSUANCE_DB_MAX_CONNECTIONS", "CANARY")
        .output()
        .unwrap();
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
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        for (pairs, key) in &cases {
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
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(78), "{pairs:?}");
            assert!(output.stdout.is_empty());
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                format!("configuration error: invalid {key}\n"),
                "{pairs:?}"
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
    let mut stderr = String::new();
    process
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
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
    for (document, serving_settings) in [
        (&v1, false),
        (&v1, true),
        (&v2, false),
        (&v2, true),
        (&native, false),
        (&native, true),
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
    let cases: Vec<(String, &str)> = vec![
        (String::new(), SETTING),
        ("CANARY-relative/auth.json".into(), SETTING),
        ("./CANARY-auth.json".into(), SETTING),
        (dir.path("CANARY-absent.json"), ABSENT),
        // A directory is not a regular file.
        (dir.path(""), ABSENT),
        (
            dir.write("CANARY-broken.json", br#"{"version": 2, "CANARY-member":"#),
            "auth configuration error: configuration is not valid JSON",
        ),
        (
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
    let run = |path: &str, line: &str| {
        let output = command(false)
            .env("OPENMETTLE_API_DATABASE_URL", "postgres://localhost/test")
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
            )
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78), "{line}");
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("{line}\n")
        );
    };
    for (path, line) in cases {
        run(&path, line);
    }
    for (pointer, value, line) in later {
        run(&changed(pointer, value), line);
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
        run(&write("CANARY-native.json", &document), line);
    }
    // Earlier settings are still reported first, and a valid file does not excuse them.
    let output = command(false)
        .env("OPENMETTLE_API_DATABASE_URL", "invalid://CANARY")
        .env("OPENMETTLE_API_AUTH_CONFIG", write("auth.json", &v2))
        .output()
        .unwrap();
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
        let prefix = if worker {
            "OPENMETTLE_WORKER"
        } else {
            "OPENMETTLE_API"
        };
        for path in [
            String::new(),
            "CANARY-relative".into(),
            dir.path("CANARY-absent"),
            file.clone(),
            dir.path("CANARY-link"),
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
                .env(format!("{prefix}_ARTIFACTS_DIR"), &path)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(78), "{path:?}");
            assert!(output.stdout.is_empty());
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "configuration error: invalid ARTIFACTS_DIR\n"
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
        let output = child.output().unwrap();
        assert_eq!(output.status.code(), Some(78));
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("configuration error: {message}\n")
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
    invoke(true, &policy, "RUN_SLOTS requires a worker executor");
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

#[test]
fn failed_sweeps_report_fixed_categories_and_retry_next_tick() {
    use std::io::{BufRead, BufReader};
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
    let pipe = process.0.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let line = line.unwrap();
            assert!(!line.contains("CANARY"));
            let event: serde_json::Value = serde_json::from_str(&line).unwrap();
            if event["event"] == "worker.sweep.failed" {
                assert_eq!(event["level"], "WARN");
                assert_eq!(event["role"], "worker");
                tx.send(event["error.type"].as_str().unwrap().to_owned())
                    .unwrap();
            }
        }
    });
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
    reader.join().unwrap();
}
