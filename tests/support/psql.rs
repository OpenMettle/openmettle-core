//! Test-only transport for exact operator scripts; never linked into production. Runs the
//! pinned psql inside the isolated CI PostgreSQL service container (`POSTGRES_CONTAINER`).
use std::process::{Child, Command, Stdio};

/// Starts `psql -X -q -f -` as `role` on `database` over the container's loopback, with each
/// variable passed as one `-v` argument. The caller writes the script to stdin and closes it.
/// `password` must be the synthetic fixture credential: it is passed in the docker argv.
pub(crate) fn start(
    database: &str,
    role: &str,
    password: &str,
    variables: &[(&str, &str)],
) -> Child {
    let container =
        std::env::var("POSTGRES_CONTAINER").expect("isolated CI PostgreSQL container ID required");
    let mut command = Command::new("docker");
    command.args([
        "exec",
        "-i",
        "-e",
        &format!("PGPASSWORD={password}"),
        &container,
        "psql",
        "-X",
        "-q",
        "-h",
        "127.0.0.1",
        "-U",
        role,
        "-d",
        database,
    ]);
    for (name, value) in variables {
        command.args(["-v", &format!("{name}={value}")]);
    }
    command
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}
