//! Test-only bounded child-process and HTTP readiness helpers shared by the process-level test
//! crates. Every helper enforces a deadline, drains piped streams non-blockingly (using
//! `O_NONBLOCK`) so pipe buffers cannot deadlock and descendant processes holding inherited write
//! ends cannot leak reader threads or withhold diagnostics, and kills and reaps timed-out children
//! before panicking with the configuration under test.
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    os::fd::AsFd,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_READS_PER_PASS: usize = 8;
const MAX_CAPTURED_BYTES: usize = 16 * 1024 * 1024;
const TIMEOUT_OUTPUT_PREVIEW_CHARS: usize = 1024;

const MAX_STATUS_LINE_BYTES: usize = 1024;
const PROBE_CONNECT_CAP: Duration = Duration::from_millis(300);
const PROBE_IO_CAP: Duration = Duration::from_secs(2);
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(50);

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
/// stderr non-blockingly in the polling loop so pipe buffers cannot block the child and inherited
/// descendant write ends cannot leak background threads or hide diagnostics on timeout.
pub(crate) fn wait_output_bounded(
    mut process: Process,
    timeout: Duration,
    context: &str,
) -> Output {
    let deadline = Instant::now() + timeout;
    let mut stdout = PipeCollector::new(process.0.stdout.take(), "stdout", context);
    let mut stderr = PipeCollector::new(process.0.stderr.take(), "stderr", context);
    let mut sleep = INITIAL_POLL_INTERVAL;
    let mut exited: Option<ExitStatus> = None;

    loop {
        let progressed = stdout.drain_pass("stdout", context, Some(deadline))
            | stderr.drain_pass("stderr", context, Some(deadline));

        if exited.is_none() {
            exited = process
                .0
                .try_wait()
                .unwrap_or_else(|err| panic!("failed to poll process for {context}: {err}"));
        }

        if let Some(status) = exited {
            if !stdout.eof {
                stdout.drain_pass("stdout", context, Some(deadline));
            }
            if !stderr.eof {
                stderr.drain_pass("stderr", context, Some(deadline));
            }
            if stdout.eof && stderr.eof {
                assert_eq!(
                    stdout.truncated_bytes, 0,
                    "stdout exceeded {MAX_CAPTURED_BYTES} bytes for {context}"
                );
                assert_eq!(
                    stderr.truncated_bytes, 0,
                    "stderr exceeded {MAX_CAPTURED_BYTES} bytes for {context}"
                );
                return Output {
                    status,
                    stdout: stdout.buf,
                    stderr: stderr.buf,
                };
            }
        }

        let now = Instant::now();
        if now >= deadline {
            if exited.is_none() {
                let _ = process.0.kill();
                let _ = process.0.wait();
            }
            stdout.drain_preview_once("stdout", context);
            stderr.drain_preview_once("stderr", context);
            let stdout_preview = preview(&stdout.buf, stdout.truncated_bytes);
            let stderr_preview = preview(&stderr.buf, stderr.truncated_bytes);
            if let Some(status) = exited {
                panic!(
                    "process timed out after {timeout:?} waiting for stdio EOF after exit ({status}) \
                     for {context}; stdout={stdout_preview:?}, stderr={stderr_preview:?}"
                );
            }
            panic!(
                "process timed out after {timeout:?} for {context} (killed and reaped); \
                 stdout={stdout_preview:?}, stderr={stderr_preview:?}"
            );
        }

        if progressed {
            sleep = INITIAL_POLL_INTERVAL;
        } else {
            thread::sleep(sleep.min(deadline.saturating_duration_since(now)));
            sleep = (sleep * 2).min(MAX_POLL_INTERVAL);
        }
    }
}

/// Waits for `child` to exit within `timeout` without consuming its stdio pipes (callers may
/// intentionally leave stderr unread or read it after exit). Kills and reaps on timeout.
pub(crate) fn wait_exit_bounded(child: &mut Child, timeout: Duration, context: &str) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    let mut sleep = INITIAL_POLL_INTERVAL;
    loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|err| panic!("failed to poll process for {context}: {err}"))
        {
            return status;
        }
        let now = Instant::now();
        if now >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("process timed out after {timeout:?} for {context} (killed and reaped)");
        }
        thread::sleep(sleep.min(deadline.saturating_duration_since(now)));
        sleep = (sleep * 2).min(MAX_POLL_INTERVAL);
    }
}

/// Reads a piped child stream (`ChildStdout` / `ChildStderr`) to EOF within `timeout` using
/// non-blocking I/O. Panics naming `context` (with captured output preview) if the pipe remains
/// open past `timeout` (for example if a descendant inherited the write end).
pub(crate) fn read_string_bounded<R: Read + AsFd>(
    pipe: R,
    timeout: Duration,
    stream: &str,
    context: &str,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut collector = PipeCollector::new(Some(pipe), stream, context);
    let mut sleep = INITIAL_POLL_INTERVAL;
    loop {
        let progressed = collector.drain_pass(stream, context, Some(deadline));
        if collector.eof {
            assert_eq!(
                collector.truncated_bytes, 0,
                "{stream} exceeded {MAX_CAPTURED_BYTES} bytes for {context}"
            );
            return String::from_utf8(collector.buf)
                .unwrap_or_else(|err| panic!("non-UTF-8 {stream} for {context}: {err}"));
        }
        let now = Instant::now();
        if now >= deadline {
            collector.drain_preview_once(stream, context);
            let captured = preview(&collector.buf, collector.truncated_bytes);
            panic!(
                "{stream} did not reach EOF within {timeout:?} for {context}; captured={captured:?}"
            );
        }
        if progressed {
            sleep = INITIAL_POLL_INTERVAL;
        } else {
            thread::sleep(sleep.min(deadline.saturating_duration_since(now)));
            sleep = (sleep * 2).min(MAX_POLL_INTERVAL);
        }
    }
}

/// Continuously drains a child pipe on a non-blocking background thread while the process runs,
/// and guarantees bounded shutdown on [`PipeDrain::finish_string`] or [`Drop`] so a descendant
/// holding the write end open can neither block collection nor leak the reader thread.
pub(crate) struct PipeDrain {
    stream: &'static str,
    context: String,
    deadline: Arc<Mutex<Option<Instant>>>,
    handle: Option<thread::JoinHandle<Result<Vec<u8>, String>>>,
}

impl PipeDrain {
    pub(crate) fn start<R: Read + AsFd + Send + 'static>(
        pipe: R,
        stream: &'static str,
        context: impl Into<String>,
    ) -> Self {
        let context = context.into();
        set_nonblocking(&pipe, stream, &context);
        let deadline = Arc::new(Mutex::new(None::<Instant>));
        let thread_deadline = Arc::clone(&deadline);
        let thread_context = context.clone();
        let handle = thread::spawn(move || {
            let mut collector = PipeCollector::from_nonblocking(pipe);
            let mut sleep = INITIAL_POLL_INTERVAL;
            loop {
                let maybe_deadline = *thread_deadline
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                let progressed = collector.drain_pass(stream, &thread_context, maybe_deadline);
                if collector.eof {
                    assert_eq!(
                        collector.truncated_bytes, 0,
                        "{stream} exceeded {MAX_CAPTURED_BYTES} bytes for {thread_context}"
                    );
                    return Ok(collector.buf);
                }
                if let Some(deadline) = maybe_deadline {
                    let now = Instant::now();
                    if now >= deadline {
                        collector.drain_preview_once(stream, &thread_context);
                        return Err(preview(&collector.buf, collector.truncated_bytes));
                    }
                    if progressed {
                        sleep = INITIAL_POLL_INTERVAL;
                    } else {
                        thread::sleep(sleep.min(deadline.saturating_duration_since(now)));
                        sleep = (sleep * 2).min(MAX_POLL_INTERVAL);
                    }
                } else if progressed {
                    sleep = INITIAL_POLL_INTERVAL;
                } else {
                    thread::sleep(sleep);
                    sleep = (sleep * 2).min(MAX_POLL_INTERVAL);
                }
            }
        });
        Self {
            stream,
            context,
            deadline,
            handle: Some(handle),
        }
    }

    pub(crate) fn finish_string(mut self, timeout: Duration) -> String {
        *self.deadline.lock().unwrap_or_else(|err| err.into_inner()) =
            Some(Instant::now() + timeout);
        let handle = self.handle.take().expect("PipeDrain handle missing");
        let result = handle
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
        match result {
            Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|err| {
                panic!("non-UTF-8 {} for {}: {err}", self.stream, self.context)
            }),
            Err(captured) => panic!(
                "{} did not reach EOF within {timeout:?} for {}; captured={captured:?}",
                self.stream, self.context
            ),
        }
    }
}

impl Drop for PipeDrain {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            *self.deadline.lock().unwrap_or_else(|err| err.into_inner()) = Some(Instant::now());
            let _ = handle.join();
        }
    }
}

/// Sends a single `GET <path>` probe to `address` and returns the HTTP status line (without
/// trailing `\r\n`) once `\n` arrives, clamping TCP connect, write and every read to `deadline`
/// and capping the status line at `MAX_STATUS_LINE_BYTES` so slow-drip peers cannot stall probes.
pub(crate) fn probe_http_status_line(
    address: &str,
    path: &str,
    deadline: Instant,
) -> Option<String> {
    let addr: SocketAddr = address.parse().ok()?;
    let connect_timeout = remaining_until(deadline)?.min(PROBE_CONNECT_CAP);
    let mut stream = TcpStream::connect_timeout(&addr, connect_timeout).ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    write_all_bounded(&mut stream, request.as_bytes(), deadline).ok()?;

    let mut line = Vec::with_capacity(64);
    let mut chunk = [0u8; 256];
    loop {
        let remaining = remaining_until(deadline)?;
        stream
            .set_read_timeout(Some(remaining.min(PROBE_IO_CAP)))
            .ok()?;
        let space = MAX_STATUS_LINE_BYTES.saturating_sub(line.len());
        if space == 0 {
            return None;
        }
        let max_read = chunk.len().min(space);
        match stream.read(&mut chunk[..max_read]) {
            Ok(0) => break,
            Ok(n) => {
                let slice = &chunk[..n];
                if let Some(pos) = slice.iter().position(|&b| b == b'\n') {
                    line.extend_from_slice(&slice[..=pos]);
                    break;
                }
                line.extend_from_slice(slice);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    let text = String::from_utf8(line).ok()?;
    let trimmed = text.trim_end_matches(['\r', '\n']);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Polls `GET <path>` on `address` until it returns `expected_status` within `timeout`, failing
/// immediately if `process` exits early or if the overall deadline expires.
pub(crate) fn wait_http_status_bounded(
    process: &mut Process,
    address: &str,
    path: &str,
    expected_status: u16,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let expected_prefix = format!("HTTP/1.1 {expected_status}");
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            panic!(
                "process exited before HTTP probe ({path} on {address} expected {expected_status}): {status}"
            );
        }
        if remaining_until(deadline).is_none() {
            panic!(
                "HTTP probe deadline ({timeout:?}): {path} on {address} expected {expected_status}"
            );
        }
        if probe_http_status_line(address, path, deadline).is_some_and(|line| {
            line.starts_with(&expected_prefix)
                && line
                    .as_bytes()
                    .get(expected_prefix.len())
                    .is_none_or(|&b| b == b' ')
        }) {
            return;
        }
        let Some(remaining) = remaining_until(deadline) else {
            panic!(
                "HTTP probe deadline ({timeout:?}): {path} on {address} expected {expected_status}"
            );
        };
        thread::sleep(PROBE_POLL_INTERVAL.min(remaining));
    }
}

struct PipeCollector<R> {
    pipe: Option<R>,
    buf: Vec<u8>,
    eof: bool,
    truncated_bytes: usize,
}

impl<R: Read + AsFd> PipeCollector<R> {
    fn new(pipe: Option<R>, stream: &str, context: &str) -> Self {
        if let Some(ref fd) = pipe {
            set_nonblocking(fd, stream, context);
        }
        let eof = pipe.is_none();
        Self {
            pipe,
            buf: Vec::new(),
            eof,
            truncated_bytes: 0,
        }
    }

    fn from_nonblocking(pipe: R) -> Self {
        Self {
            pipe: Some(pipe),
            buf: Vec::new(),
            eof: false,
            truncated_bytes: 0,
        }
    }

    fn drain_pass(&mut self, stream: &str, context: &str, deadline: Option<Instant>) -> bool {
        let Some(pipe) = self.pipe.as_mut() else {
            return false;
        };
        let mut progressed = false;
        let mut chunk = [0u8; 8192];
        let mut reads = 0;
        while reads < MAX_READS_PER_PASS {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return progressed;
            }
            match pipe.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    self.pipe = None;
                    return true;
                }
                Ok(n) => {
                    reads += 1;
                    progressed = true;
                    let remaining_cap = MAX_CAPTURED_BYTES.saturating_sub(self.buf.len());
                    let keep = n.min(remaining_cap);
                    self.buf.extend_from_slice(&chunk[..keep]);
                    self.truncated_bytes = self.truncated_bytes.saturating_add(n - keep);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return progressed,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => panic!("failed reading {stream} for {context}: {err}"),
            }
        }
        progressed
    }

    fn drain_preview_once(&mut self, stream: &str, context: &str) {
        if self.buf.len() >= TIMEOUT_OUTPUT_PREVIEW_CHARS * 4 {
            return;
        }
        let Some(pipe) = self.pipe.as_mut() else {
            return;
        };
        let mut chunk = [0u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => {
                    self.pipe = None;
                    return;
                }
                Ok(n) => {
                    let remaining_cap = MAX_CAPTURED_BYTES.saturating_sub(self.buf.len());
                    let keep = n.min(remaining_cap);
                    self.buf.extend_from_slice(&chunk[..keep]);
                    self.truncated_bytes = self.truncated_bytes.saturating_add(n - keep);
                    return;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => panic!("failed reading {stream} for {context}: {err}"),
            }
        }
    }
}

fn set_nonblocking<F: AsFd>(fd: &F, stream: &str, context: &str) {
    let flags = fcntl_getfl(fd)
        .unwrap_or_else(|err| panic!("failed to read {stream} flags for {context}: {err}"));
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)
        .unwrap_or_else(|err| panic!("failed to set {stream} non-blocking for {context}: {err}"));
}

fn remaining_until(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    (now < deadline).then(|| deadline.saturating_duration_since(now))
}

fn write_all_bounded(stream: &mut TcpStream, mut data: &[u8], deadline: Instant) -> io::Result<()> {
    while !data.is_empty() {
        let Some(remaining) = remaining_until(deadline) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe write deadline exceeded",
            ));
        };
        stream.set_write_timeout(Some(remaining.min(PROBE_IO_CAP)))?;
        match stream.write(data) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write probe request",
                ));
            }
            Ok(n) => data = &data[n..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn preview(bytes: &[u8], truncated_bytes: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out: String = text.chars().take(TIMEOUT_OUTPUT_PREVIEW_CHARS).collect();
    if text.chars().nth(TIMEOUT_OUTPUT_PREVIEW_CHARS).is_some() || truncated_bytes > 0 {
        out.push_str("...(truncated)");
    }
    out
}
