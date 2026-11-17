//! Black-box process tests. Real PostgreSQL is required only by the ignored test.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

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
    let mut stream =
        TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(300))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
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
