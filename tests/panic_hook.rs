//! ADR 0024: after telemetry is installed, a panic writes one fixed `process.panicked` event
//! and nothing from the panic itself. The hook is process-wide, so the test re-executes its own
//! binary, filtered to this one test, as the child that installs the production stack on its
//! real stderr and panics with a canary in the payload. It is an ordinary libtest test, so the
//! manifest declares no extra target and the image build (which copies no tests) is unaffected.
use openmettle_core::telemetry::{Format, Process, Settings, Verbosity, install};
use std::process::Command;

const CHILD: &str = "OPENMETTLE_TEST_PANIC_CHILD";
const CANARY: &str = "CANARY-panic-payload-3c1e";
const NAME: &str = "panic_writes_one_fixed_event_and_nothing_from_the_panic";

fn child(mode: &str) -> ! {
    let format = if mode == "text" {
        Format::Text
    } else {
        Format::Json
    };
    let settings = Settings {
        format,
        verbosity: Verbosity::Error,
    };
    let _telemetry = install(settings, Process::Worker).unwrap();
    if mode == "thread" {
        // A panic on another thread: that thread ends, the process carries on and exits 3.
        let joined = std::thread::spawn(|| panic!("{CANARY} on a thread")).join();
        assert!(joined.is_err());
        std::process::exit(3);
    }
    let payload = format!("{CANARY} in a formatted message");
    panic!("{payload}");
}

#[test]
fn panic_writes_one_fixed_event_and_nothing_from_the_panic() {
    if let Ok(mode) = std::env::var(CHILD) {
        child(&mode);
    }
    let exe = std::env::current_exe().unwrap();
    // libtest reports the child's failed test (exit 101) on stdout; the hook writes stderr.
    for (mode, code) in [("json", 101), ("text", 101), ("thread", 3)] {
        let output = Command::new(&exe)
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, mode)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{mode}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        // No payload, message, location or backtrace on either stream.
        for absent in [CANARY, "panicked at", "panic_hook.rs", "RUST_BACKTRACE"] {
            assert!(!stderr.contains(absent), "{mode} stderr: {stderr}");
            assert!(!stdout.contains(absent), "{mode} stdout: {stdout}");
        }
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 1, "{mode}: {stderr}");
        if mode == "text" {
            assert!(
                lines[0].ends_with(" ERROR event=\"process.panicked\" role=\"worker\""),
                "{stderr}"
            );
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let keys: Vec<&str> = event
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys.len(), 4, "{stderr}");
        assert_eq!(event["event"], "process.panicked");
        assert_eq!(event["level"], "ERROR");
        assert_eq!(event["role"], "worker");
        assert!(event["timestamp"].is_string());
    }
}
