//! Test-only child-process environment hygiene shared by the process-level test crates.
use std::process::Command;

/// Removes inherited deployment configuration (`OPENMETTLE_*`) and libpq defaults (`PG*`)
/// so a spawned binary sees only the variables the test sets explicitly.
pub(crate) fn scrub_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("OPENMETTLE_") || name.starts_with("PG") {
            command.env_remove(key);
        }
    }
}
