//! Test-only bounded child-process helpers shared by the process-level test crates.
//! Every helper enforces a deadline, drains piped streams concurrently when collecting output so
//! pipe buffers cannot deadlock, and kills and reaps the child before panicking on timeout.
use std::{
    io::{self, Read},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PIPE_EOF_GRACE: Duration = Duration::from_secs(10);
const TIMEOUT_PIPE_GRACE: Duration = Duration::from_millis(500);
const TIMEOUT_OUTPUT_PREVIEW_CHARS: usize = 1024;

/// Child process guard that always kills and reaps on drop.
pub(crate) struct Process(pub(crate) Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs `command` to completion with captured stdout/stderr, failing promptly if it does not exit
/// within `timeout`. On timeout the child is killed and reaped and the panic names `context`.
pub(crate) fn run_bounded(command: &mut Command, timeout: Duration, context: &str) -> Output {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|err| panic!("failed to spawn process for {context}: {err}"));
    wait_output_bounded(Process(child), timeout, context)
}

/// Waits for an already-spawned `process` to exit within `timeout`, draining any piped stdout and
/// stderr concurrently so pipe buffers cannot block the child. Kills and reaps on timeout.
pub(crate) fn wait_output_bounded(
    mut process: Process,
    timeout: Duration,
    context: &str,
) -> Output {
    let stdout_rx = drain_pipe(process.0.stdout.take());
    let stderr_rx = drain_pipe(process.0.stderr.take());
    match poll_exit(&mut process.0, timeout, context) {
        Some(status) => Output {
            status,
            stdout: collect_completed(stdout_rx, "stdout", context),
            stderr: collect_completed(stderr_rx, "stderr", context),
        },
        None => {
            let stdout = collect_after_timeout(stdout_rx);
            let stderr = collect_after_timeout(stderr_rx);
            panic!(
                "process did not exit within {timeout:?} for {context} (killed and reaped); \
                 stdout={stdout:?}, stderr={stderr:?}"
            );
        }
    }
}

/// Waits for `child` to exit within `timeout` without consuming its stdio pipes (callers may
/// intentionally leave stderr unread or read it after exit). Kills and reaps on timeout.
pub(crate) fn wait_exit_bounded(child: &mut Child, timeout: Duration, context: &str) -> ExitStatus {
    poll_exit(child, timeout, context).unwrap_or_else(|| {
        panic!("process did not exit within {timeout:?} for {context} (killed and reaped)")
    })
}

fn poll_exit(child: &mut Child, timeout: Duration, context: &str) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    let mut sleep = INITIAL_POLL_INTERVAL;
    loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|err| panic!("failed to poll process for {context}: {err}"))
        {
            return Some(status);
        }
        let now = Instant::now();
        if now >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(sleep.min(deadline.saturating_duration_since(now)));
        sleep = (sleep * 2).min(MAX_POLL_INTERVAL);
    }
}

fn drain_pipe<R: Read + Send + 'static>(
    pipe: Option<R>,
) -> Option<mpsc::Receiver<io::Result<Vec<u8>>>> {
    let mut pipe = pipe?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let result = pipe.read_to_end(&mut buf).map(|_| buf);
        let _ = tx.send(result);
    });
    Some(rx)
}

fn collect_completed(
    rx: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    stream: &str,
    context: &str,
) -> Vec<u8> {
    match rx {
        None => Vec::new(),
        Some(rx) => match rx.recv_timeout(PIPE_EOF_GRACE) {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => panic!("failed reading {stream} for {context}: {err}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("{stream} pipe did not reach EOF after process exit for {context}")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("{stream} reader thread ended unexpectedly for {context}")
            }
        },
    }
}

fn collect_after_timeout(rx: Option<mpsc::Receiver<io::Result<Vec<u8>>>>) -> String {
    match rx {
        None => String::new(),
        Some(rx) => match rx.recv_timeout(TIMEOUT_PIPE_GRACE) {
            Ok(Ok(bytes)) => preview(&bytes),
            Ok(Err(err)) => format!("<read error: {err}>"),
            Err(_) => "<pipe remained open after child termination>".to_owned(),
        },
    }
}

fn preview(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out: String = text.chars().take(TIMEOUT_OUTPUT_PREVIEW_CHARS).collect();
    if text.chars().nth(TIMEOUT_OUTPUT_PREVIEW_CHARS).is_some() {
        out.push_str("...(truncated)");
    }
    out
}
