//! ADR 0024: after telemetry is installed, a panic writes one fixed `process.panicked` event
//! and nothing from the panic itself. The hook is process-wide, so this runs without the
//! libtest harness: the binary re-executes itself as the child that installs the production
//! stack on its real stderr and panics with a canary in the payload.
use openmettle_core::telemetry::{Format, Process, Settings, Verbosity, install};
use std::process::Command;

const CHILD: &str = "OPENMETTLE_TEST_PANIC_CHILD";
const CANARY: &str = "CANARY-panic-payload-3c1e";

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
        // A panic off the main thread: the thread ends, the process carries on and exits 3.
        let joined = std::thread::spawn(|| panic!("{CANARY} on a thread")).join();
        assert!(joined.is_err());
        std::process::exit(3);
    }
    let payload = format!("{CANARY} in a formatted message");
    panic!("{payload}");
}

fn main() {
    if let Ok(mode) = std::env::var(CHILD) {
        child(&mode);
    }
    let exe = std::env::current_exe().unwrap();
    for (mode, code) in [("json", 101), ("text", 101), ("thread", 3)] {
        let output = Command::new(&exe).env(CHILD, mode).output().unwrap();
        assert_eq!(output.status.code(), Some(code), "{mode}");
        assert!(output.stdout.is_empty(), "{mode}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        // No payload, message, location or backtrace.
        for absent in [CANARY, "panicked at", "panic_hook.rs", "RUST_BACKTRACE"] {
            assert!(!stderr.contains(absent), "{mode}: {stderr}");
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
    println!("panic_hook: the hook writes one fixed event in each case ... ok");
}
