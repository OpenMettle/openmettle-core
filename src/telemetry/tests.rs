//! The callsite guard, settings, typed constructors and request-ID middleware, each through
//! the production subscriber stack with a captured writer in place of stderr.
use super::*;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::Write,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// An in-memory stand-in for stderr.
#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

pub(crate) struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'w> MakeWriter<'w> for Capture {
    type Writer = CaptureWriter;
    fn make_writer(&'w self) -> CaptureWriter {
        CaptureWriter(self.0.clone())
    }
}

impl Capture {
    /// Installs the production stack over a fresh capture as this thread's default. A
    /// current-thread runtime keeps every spawned task on this thread.
    pub(crate) fn install(
        format: Format,
        verbosity: Verbosity,
    ) -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let settings = Settings { format, verbosity };
        let guard = tracing::subscriber::set_default(subscriber(settings, capture.clone()));
        (capture, guard)
    }
    /// [`Self::install`] with the OTLP span layer over `tracer` (ADR 0026).
    pub(crate) fn install_traced(
        format: Format,
        verbosity: Verbosity,
        tracer: opentelemetry_sdk::trace::SdkTracer,
    ) -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let settings = Settings { format, verbosity };
        let guard =
            tracing::subscriber::set_default(stack(settings, capture.clone(), Some(tracer)));
        (capture, guard)
    }
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.bytes()).unwrap()
    }
    /// Every line, parsed as one JSON object.
    pub(crate) fn json(&self) -> Vec<serde_json::Map<String, Value>> {
        let text = self.text();
        let lines = text.lines().map(|line| match serde_json::from_str(line) {
            Ok(Value::Object(object)) => object,
            _ => panic!("not a JSON object line: {line}"),
        });
        lines.collect()
    }
    /// Lines whose `event` is `name`.
    pub(crate) fn events(&self, name: &str) -> Vec<serde_json::Map<String, Value>> {
        let lines = self.json().into_iter();
        lines.filter(|line| line["event"] == name).collect()
    }
    /// Fails if any canary's bytes appear anywhere in the output.
    pub(crate) fn assert_absent(&self, canaries: &[&[u8]]) {
        let bytes = self.bytes();
        for canary in canaries {
            assert!(!canary.is_empty());
            assert!(
                !bytes.windows(canary.len()).any(|w| w == *canary),
                "canary {:?} reached the sink:\n{}",
                String::from_utf8_lossy(canary),
                String::from_utf8_lossy(&bytes)
            );
        }
    }
}

/// Canonical lowercase hyphenated UUID with version 4 and the RFC 9562 variant.
pub(crate) fn is_v4(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            14 => *b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

const CANARY: &str = "CANARY-guard-7f3a";

fn parse(pairs: &[(&str, &str)]) -> Result<Settings, &'static str> {
    Settings::parse(|key| {
        let found = pairs.iter().find(|(k, _)| *k == key);
        Ok(found.map(|(_, v)| v.to_string()))
    })
}

#[test]
fn settings_default_to_json_at_info_and_accept_only_the_listed_values() {
    let defaults = Settings {
        format: Format::Json,
        verbosity: Verbosity::Info,
    };
    assert_eq!(parse(&[]), Ok(defaults));
    for (value, format) in [("json", Format::Json), ("text", Format::Text)] {
        assert_eq!(parse(&[("LOG_FORMAT", value)]).unwrap().format, format);
    }
    for (value, verbosity) in [
        ("error", Verbosity::Error),
        ("warn", Verbosity::Warn),
        ("info", Verbosity::Info),
        ("debug", Verbosity::Debug),
    ] {
        assert_eq!(parse(&[("LOG_LEVEL", value)]).unwrap().verbosity, verbosity);
    }
    // Exact lowercase words only; no `trace`, no filter directives, no padding.
    for value in [
        "", "JSON", "Json", " json", "json ", "pretty", "compact", CANARY,
    ] {
        assert_eq!(
            parse(&[("LOG_FORMAT", value)]),
            Err("invalid LOG_FORMAT"),
            "{value:?}"
        );
    }
    for value in [
        "",
        "trace",
        "TRACE",
        "INFO",
        "warning",
        "info,sqlx=trace",
        "openmettle_core=debug",
        "off",
        "0",
        CANARY,
    ] {
        assert_eq!(
            parse(&[("LOG_LEVEL", value)]),
            Err("invalid LOG_LEVEL"),
            "{value:?}"
        );
    }
    // The getter's own refusal (non-UTF-8) is passed through unchanged.
    let refused = Settings::parse(|_| Err("configuration must be UTF-8"));
    assert_eq!(refused, Err("configuration must be UTF-8"));
}

fn config(pairs: &[(&str, &str)]) -> Result<crate::Config, &'static str> {
    crate::Config::parse(crate::Role::Api, |key| {
        let found = pairs.iter().find(|(k, _)| *k == key);
        Ok(found.map(|(_, v)| v.to_string()))
    })
}

/// The API and worker read the keys under their own prefix, after their existing keys.
#[test]
fn serving_configuration_carries_the_settings_after_existing_keys() {
    const URL: (&str, &str) = ("DATABASE_URL", "postgres://localhost/test");
    assert_eq!(config(&[URL]).unwrap().telemetry, parse(&[]).unwrap());
    let telemetry = config(&[URL, ("LOG_FORMAT", "text"), ("LOG_LEVEL", "warn")])
        .unwrap()
        .telemetry;
    assert_eq!(
        (telemetry.format, telemetry.verbosity),
        (Format::Text, Verbosity::Warn)
    );
    for (pairs, error) in [
        (&[URL, ("LOG_FORMAT", "yaml")][..], "invalid LOG_FORMAT"),
        (&[URL, ("LOG_LEVEL", "trace")][..], "invalid LOG_LEVEL"),
        // Existing keys keep precedence.
        (&[("LOG_LEVEL", "trace")][..], "DATABASE_URL is required"),
        (
            &[URL, ("BIND", "x"), ("LOG_FORMAT", "x")][..],
            "invalid BIND",
        ),
    ] {
        assert_eq!(config(pairs).err(), Some(error), "{pairs:?}");
    }
}

#[test]
fn request_ids_are_fresh_canonical_v4_uuids() {
    let ids: BTreeSet<String> = (0..64)
        .map(|_| RequestId::generate().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 64);
    assert!(ids.iter().all(|id| is_v4(id)), "{ids:?}");
    assert_eq!(
        RequestId([0xff; 16]).to_string(),
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    );
    assert!(!is_v4("ffffffff-ffff-ffff-ffff-ffffffffffff"));
}

/// Emits one admitted control event and several refused ones; only the control appears.
fn emit_guarded() {
    tracing::warn!(target: TARGET, event = "guard.control", role = "api");
    // A field outside the allowlist, on the admitted target.
    tracing::warn!(target: TARGET, event = "guard.field", password = CANARY);
    tracing::warn!(target: TARGET, event = "guard.field", url.full = CANARY);
    // Foreign targets with otherwise admitted fields: third-party crates and look-alikes.
    for_each_foreign_target();
    // This test module's default target, a descendant of the admitted one.
    tracing::warn!(event = "guard.module", role = CANARY);
    // Formatted free text: a `message` field, with and without admitted fields beside it.
    tracing::warn!(target: TARGET, "free text {}", CANARY);
    tracing::warn!(target: TARGET, event = "guard.message", "{CANARY}");
    // A foreign span around an admitted event: the span is never entered by the sink, so a
    // text line carries no span context.
    let span = tracing::warn_span!(target: "sqlx::query", "query", db.statement = CANARY);
    span.in_scope(|| tracing::warn!(target: TARGET, event = "guard.in_span", role = "api"));
}

fn for_each_foreign_target() {
    tracing::warn!(target: "sqlx::query", event = "guard.foreign", role = CANARY);
    tracing::warn!(target: "hyper::proto", event = "guard.foreign", role = CANARY);
    tracing::warn!(target: "openidconnect", event = "guard.foreign", role = CANARY);
    tracing::warn!(target: "openmettle_core", event = "guard.foreign", role = CANARY);
    tracing::warn!(target: "openmettle_core::telemetry::x", event = "guard.foreign", role = CANARY);
    tracing::warn!(target: "openmettle_core::telemetryx", event = "guard.foreign", role = CANARY);
}

#[test]
fn guard_refuses_foreign_targets_unlisted_fields_and_free_text_in_both_formats() {
    for format in [Format::Json, Format::Text] {
        let (capture, _guard) = Capture::install(format, Verbosity::Debug);
        emit_guarded();
        capture.assert_absent(&[CANARY.as_bytes(), b"guard.field", b"guard.module"]);
        let text = capture.text();
        assert_eq!(text.lines().count(), 2, "{format:?}: {text}");
        assert!(text.contains("guard.control") && text.contains("guard.in_span"));
        for refused in ["guard.foreign", "guard.message", "query", "free text"] {
            assert!(!text.contains(refused), "{format:?}: {text}");
        }
    }
}

#[test]
fn level_bounds_admitted_events() {
    for (verbosity, expected) in [
        (Verbosity::Error, &["e"][..]),
        (Verbosity::Warn, &["e", "w"]),
        (Verbosity::Info, &["e", "w", "i"]),
        (Verbosity::Debug, &["e", "w", "i", "d"]),
    ] {
        let (capture, _guard) = Capture::install(Format::Json, verbosity);
        tracing::error!(target: TARGET, event = "e");
        tracing::warn!(target: TARGET, event = "w");
        tracing::info!(target: TARGET, event = "i");
        tracing::debug!(target: TARGET, event = "d");
        // `trace` is never offered, so nothing configurable admits it.
        tracing::trace!(target: TARGET, event = "t");
        let events: Vec<_> = capture.json().iter().map(|l| l["event"].clone()).collect();
        assert_eq!(events, expected, "{verbosity:?}");
    }
}

fn keys(line: &serde_json::Map<String, Value>) -> BTreeSet<&str> {
    line.keys().map(String::as_str).collect()
}

/// Every typed constructor passes the guard with exactly its documented fields, so the
/// allowlist and the constructors cannot drift apart silently.
#[test]
fn every_constructor_passes_the_guard_with_its_fields() {
    let (capture, _guard) = Capture::install(Format::Json, Verbosity::Debug);
    process_started(Process::Api);
    process_stopping(Process::Worker, Signal::Interrupt);
    process_stopped(Process::Api);
    process_failed(Process::Api, ProcessFailure::ShutdownDeadline);
    migration_started();
    migration_completed(13);
    migration_failed(MigrationFailure::Refused);
    migration_interrupted(Signal::Terminate);
    process_panicked(Process::Migrate);
    lines_dropped(3);
    spans_dropped(2);
    metric_exports_dropped(1);
    let route = Route(None);
    let id = RequestId::generate();
    let empty_ids = CorrelationIds::default();
    let run_id = "11111111-2222-4333-8444-555555555555";
    let op_id = "66666666-7777-4888-9999-aaaaaaaaaaaa";
    let lease_id = derive_run_lease_id(run_id, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff");
    let correlated = CorrelationIds {
        run_id: Some(run_id.to_owned()),
    };
    request_completed(
        id,
        &route,
        Method::Other,
        404,
        Duration::from_micros(7),
        &empty_ids,
    );
    request_completed(
        None,
        &route,
        Method::Get,
        503,
        Duration::from_micros(9),
        &empty_ids,
    );
    request_completed(
        id,
        &route,
        Method::Post,
        200,
        Duration::from_micros(11),
        &correlated,
    );
    run_stream_failed(id, run_id);
    worker_run_claimed(run_id, &lease_id);
    worker_run_settled(
        run_id,
        &lease_id,
        WorkerRunOutcome::Succeeded,
        Duration::from_micros(15),
    );
    worker_operation_completed(
        run_id,
        &lease_id,
        op_id,
        WorkerOperationKind::Tool,
        WorkerOperationOutcome::Ok,
        Duration::from_micros(5),
    );
    let lines = capture.json();
    let base = ["timestamp", "level", "event", "role"];
    let with =
        |extra: &[&'static str]| -> BTreeSet<&str> { base.iter().chain(extra).copied().collect() };
    let request = |extra: &[&'static str]| -> BTreeSet<&str> {
        [
            "timestamp",
            "level",
            "event",
            "http.route",
            "http.request.method",
        ]
        .iter()
        .chain(["http.response.status_code", "duration_us"].iter())
        .chain(extra)
        .copied()
        .collect()
    };
    let expected = [
        ("process.started", "INFO", with(&[])),
        ("process.stopping", "INFO", with(&["signal"])),
        ("process.stopped", "INFO", with(&[])),
        ("process.failed", "ERROR", with(&["error.type"])),
        ("migration.started", "INFO", with(&[])),
        ("migration.completed", "INFO", with(&["schema_version"])),
        ("migration.failed", "ERROR", with(&["error.type"])),
        // A run that exits 1 is visible at every level.
        ("migration.interrupted", "ERROR", with(&["signal"])),
        ("process.panicked", "ERROR", with(&[])),
        (
            "telemetry.dropped",
            "ERROR",
            ["timestamp", "level", "event", "dropped_lines"].into(),
        ),
        (
            "telemetry.dropped",
            "ERROR",
            ["timestamp", "level", "event", "dropped_spans"].into(),
        ),
        (
            "telemetry.dropped",
            "ERROR",
            ["timestamp", "level", "event", "dropped_metric_exports"].into(),
        ),
        ("http.request.completed", "DEBUG", request(&["request_id"])),
        // No ID is recorded rather than an invented one.
        ("http.request.completed", "WARN", request(&[])),
        (
            "http.request.completed",
            "DEBUG",
            request(&["request_id", "run_id"]),
        ),
        (
            "run.stream.ended",
            "ERROR",
            [
                "timestamp",
                "level",
                "event",
                "request_id",
                "run_id",
                "error.type",
            ]
            .into(),
        ),
        ("worker.run.claimed", "INFO", with(&["run_id", "lease_id"])),
        (
            "worker.run.settled",
            "INFO",
            with(&["run_id", "lease_id", "run.outcome", "duration_us"]),
        ),
        (
            "worker.operation.completed",
            "DEBUG",
            with(&[
                "run_id",
                "lease_id",
                "operation_id",
                "operation.kind",
                "operation.outcome",
                "duration_us",
            ]),
        ),
    ];
    assert_eq!(lines.len(), expected.len(), "{}", capture.text());
    for (line, (event, level, keys_expected)) in lines.iter().zip(expected) {
        assert_eq!(
            (line["event"].as_str(), line["level"].as_str()),
            (Some(event), Some(level))
        );
        assert_eq!(keys(line), keys_expected, "{event}");
        for key in keys(line) {
            assert!(
                ["timestamp", "level"].contains(&key) || FIELDS.contains(&key),
                "{key}"
            );
        }
    }
    let field = |i: usize, key: &str| lines[i][key].clone();
    assert_eq!(field(1, "role"), "worker");
    assert_eq!(field(1, "signal"), "SIGINT");
    assert_eq!(field(3, "error.type"), "ShutdownDeadline");
    assert_eq!(field(5, "schema_version"), 13);
    assert_eq!(field(6, "error.type"), "Refused");
    assert_eq!(field(7, "role"), "migrate");
    assert_eq!(field(8, "role"), "migrate");
    assert_eq!(field(9, "dropped_lines"), 3);
    assert_eq!(field(10, "dropped_spans"), 2);
    assert_eq!(field(11, "dropped_metric_exports"), 1);
    assert_eq!(field(12, "request_id"), id.unwrap().to_string().as_str());
    assert_eq!(field(12, "http.route"), "unmatched");
    assert_eq!(field(12, "http.request.method"), "_OTHER");
    assert_eq!(field(12, "http.response.status_code"), 404);
    assert_eq!(field(12, "duration_us"), 7);
    assert_eq!(field(14, "run_id"), run_id);
    assert_eq!(field(15, "run_id"), run_id);
    assert_eq!(field(16, "run_id"), run_id);
    assert_eq!(field(16, "lease_id"), lease_id.as_str());
    assert_eq!(field(17, "run.outcome"), "succeeded");
    assert_eq!(field(18, "operation.kind"), "tool");
    assert_eq!(field(18, "operation.outcome"), "ok");
}

#[test]
fn derive_run_lease_id_is_deterministic_rotates_and_never_exposes_claim_token() {
    let run_a = "11111111-2222-4333-8444-555555555555";
    let run_b = "11111111-2222-4333-8444-555555555556";
    let token_1 = "aaaa1111-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let token_2 = "ffff1111-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    let id_1 = derive_run_lease_id(run_a, token_1);
    let id_1_repeat = derive_run_lease_id(run_a, token_1);
    let id_2 = derive_run_lease_id(run_a, token_2);
    let id_other_run = derive_run_lease_id(run_b, token_1);

    assert_eq!(id_1, id_1_repeat);
    assert!(is_derived_run_lease_id(&id_1), "{id_1}");
    assert_ne!(id_1, id_2, "new claim_token must rotate lease_id");
    assert_ne!(id_1, id_other_run, "different run_id must change lease_id");
    assert_ne!(id_1, token_1);
    assert!(!id_1.contains(token_1));
    assert!(!id_1.contains(&token_1.replace('-', "")));

    // Correlation defensively rejects unvalidated/canary IDs.
    let corr = Correlation::default();
    corr.set_run_id("not-a-uuid-CANARY");
    assert_eq!(corr.snapshot(), CorrelationIds::default());

    corr.set_run_id(run_a);
    let snap = corr.snapshot();
    assert_eq!(snap.run_id.as_deref(), Some(run_a));
}

/// The shutdown deadline covers draining and the final flush together.
#[test]
fn shutdown_budget_fits_the_flush_inside_the_deadline() {
    for (timeout_ms, flush_ms) in [(1, 0.1), (1000, 100.0), (5000, 250.0), (60000, 250.0)] {
        let timeout = Duration::from_millis(timeout_ms);
        let (drain, flush) = crate::shutdown_budget(timeout);
        assert_eq!(drain + flush, timeout);
        assert_eq!(flush, Duration::from_secs_f64(flush_ms / 1000.0));
    }
}

/// A stand-in for a stderr pipe whose reader stops reading. Each write announces itself and
/// then waits until the gate opens, which may be never.
#[derive(Clone, Default)]
struct Stalled {
    open: Arc<(Mutex<bool>, std::sync::Condvar)>,
    entered: Arc<std::sync::atomic::AtomicUsize>,
    written: Capture,
}

impl Write for Stalled {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (open, changed) = &*self.open;
        let guard = open.lock().unwrap();
        drop(changed.wait_while(guard, |open| !*open).unwrap());
        self.written.make_writer().write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Stalled {
    fn release(&self) {
        let (open, changed) = &*self.open;
        *open.lock().unwrap() = true;
        changed.notify_all();
    }
    /// Waits until the writer thread is blocked inside its first write.
    fn wait_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.entered.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "writer never wrote");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn offer(queue: &sink::Queue, line: &str) {
    queue.make_writer().write_all(line.as_bytes()).unwrap();
}

const JSON_INFO: Settings = Settings {
    format: Format::Json,
    verbosity: Verbosity::Info,
};

/// ADR 0024 delivery: a writer that never returns costs lines, not the emitter's time, and
/// the exit flush gives up at its limit.
#[test]
fn a_writer_that_never_returns_never_blocks_emitting_or_flushing() {
    let stalled = Stalled::default();
    let queue = sink::Queue::spawn(stalled.clone(), 8, JSON_INFO).unwrap();
    offer(&queue, "first\n");
    stalled.wait_entered();
    // Emitting runs on its own thread so that a blocking regression fails here, not hangs.
    let (done, finished) = std::sync::mpsc::channel();
    let emitter = queue.clone();
    std::thread::spawn(move || {
        for i in 0..10_000 {
            offer(&emitter, &format!("line {i}\n"));
        }
        // Ten thousand events through the production stack over the same queue.
        let _default = tracing::subscriber::set_default(subscriber(JSON_INFO, emitter));
        for _ in 0..10_000 {
            process_started(Process::Api);
        }
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(5))
        .expect("emitting blocked on a stalled writer");
    let began = Instant::now();
    assert!(!queue.flush(Duration::from_millis(100)));
    let waited = began.elapsed();
    assert!(waited >= Duration::from_millis(100), "{waited:?}");
    assert!(waited < Duration::from_secs(2), "{waited:?}");
    assert!(stalled.written.bytes().is_empty());
    // Let the thread finish so the test leaves nothing blocked.
    stalled.release();
    assert!(queue.flush(Duration::from_secs(10)));
}

/// Lines refused by a full queue are counted and reported once, after the next successful
/// write, as a guarded `telemetry.dropped` event in the configured format.
#[test]
fn dropped_lines_are_counted_and_reported_after_the_next_write() {
    for format in [Format::Json, Format::Text] {
        let stalled = Stalled::default();
        let settings = Settings {
            format,
            verbosity: Verbosity::Error,
        };
        let queue = sink::Queue::spawn(stalled.clone(), 4, settings).unwrap();
        offer(&queue, "line 0\n");
        // The writer holds line 0, so four more fill the queue and three are dropped.
        stalled.wait_entered();
        for i in 1..=7 {
            offer(&queue, &format!("line {i}\n"));
        }
        assert!(!queue.flush(Duration::from_millis(10)));
        stalled.release();
        assert!(queue.flush(Duration::from_secs(10)));
        let text = stalled.written.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 6, "{text}");
        assert_eq!(lines[0], "line 0");
        assert_eq!(lines[2..], ["line 1", "line 2", "line 3", "line 4"]);
        match format {
            Format::Json => {
                let report: Value = serde_json::from_str(lines[1]).unwrap();
                let keys: BTreeSet<&str> = report
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert_eq!(
                    keys,
                    ["timestamp", "level", "event", "dropped_lines"].into()
                );
                assert_eq!(report["event"], "telemetry.dropped");
                assert_eq!(report["level"], "ERROR");
                assert_eq!(report["dropped_lines"], 3);
            }
            Format::Text => assert!(
                lines[1].ends_with(" ERROR event=\"telemetry.dropped\" dropped_lines=3"),
                "{text}"
            ),
        }
        // The count was reset: further lines bring no second report.
        offer(&queue, "line 8\n");
        assert!(queue.flush(Duration::from_secs(10)));
        assert_eq!(stalled.written.text().lines().count(), 7);
    }
}

/// The guard runs on the emitting thread before a line is queued: refused events are neither
/// queued nor counted as dropped.
#[test]
fn the_guard_applies_before_lines_are_queued() {
    let out = Stalled::default();
    out.release();
    let queue = sink::Queue::spawn(out.clone(), 256, JSON_INFO).unwrap();
    {
        let _default = tracing::subscriber::set_default(subscriber(JSON_INFO, queue.clone()));
        for _ in 0..100 {
            emit_guarded();
        }
        tracing::debug!(target: TARGET, event = "below.level");
    }
    assert!(queue.flush(Duration::from_secs(10)));
    let events: Vec<_> = out
        .written
        .json()
        .iter()
        .map(|l| l["event"].clone())
        .collect();
    assert_eq!(events.len(), 200);
    assert!(
        events
            .iter()
            .all(|e| *e == "guard.control" || *e == "guard.in_span")
    );
    out.written.assert_absent(&[
        CANARY.as_bytes(),
        b"guard.field",
        b"below.level",
        b"telemetry.dropped",
    ]);
}

/// A writer that fails calls selected by a script, then records bytes written on success.
#[derive(Clone)]
struct Flaky {
    outcomes: Arc<Mutex<std::collections::VecDeque<bool>>>,
    written: Capture,
}

impl Flaky {
    fn new(outcomes: impl IntoIterator<Item = bool>) -> Self {
        Self {
            outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            written: Capture::default(),
        }
    }
}

impl Write for Flaky {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let ok = self.outcomes.lock().unwrap().pop_front().unwrap_or(true);
        if ok {
            self.written.make_writer().write(bytes)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            ))
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Failed stream writes are counted as dropped, and if writing the `telemetry.dropped` report
/// itself fails the count is restored and reported after the next successful write.
#[test]
fn write_errors_and_failed_drop_reports_are_preserved_until_recovery() {
    // Outcomes per write_all call:
    // 1. line 0 -> Err (dropped = 1)
    // 2. line 1 -> Err (dropped = 2)
    // 3. line 2 -> Ok; drop report for 2 -> Err (restored to 2)
    // 4. line 3 -> Ok; drop report for 2 -> Ok (reset to 0)
    // 5. line 4 -> Ok (no further report)
    let flaky = Flaky::new([false, false, true, false, true, true, true]);
    let queue = sink::Queue::spawn(flaky.clone(), 16, JSON_INFO).unwrap();
    for i in 0..=4 {
        offer(&queue, &format!("line {i}\n"));
    }
    assert!(queue.flush(Duration::from_secs(10)));
    let text = flaky.written.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "{text}");
    assert_eq!(lines[0], "line 2");
    assert_eq!(lines[1], "line 3");
    let report: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(report["event"], "telemetry.dropped");
    assert_eq!(report["level"], "ERROR");
    assert_eq!(report["dropped_lines"], 2);
    assert_eq!(lines[3], "line 4");
}

/// Retrying a failed `telemetry.dropped` stderr report must never double-count the lost lines
/// in `openmettle.telemetry.dropped{signal="log_lines"}` (ADR 0028).
#[test]
fn write_errors_and_failed_drop_reports_do_not_double_count_log_line_drops() {
    let flaky = Flaky::new([false, false, true, false, true, false, true, true, true]);
    let store = Arc::new(metrics::Metrics::new());
    let queue =
        sink::Queue::spawn_with_metrics(flaky.clone(), 16, JSON_INFO, store.clone()).unwrap();
    for i in 0..=5 {
        offer(&queue, &format!("line {i}\n"));
    }
    assert!(queue.flush(Duration::from_secs(10)));
    // Exactly two application lines failed to write (lines 0 and 1); two failed drop-report
    // writes retried the notice but did not inflate the lost-line counter.
    assert_eq!(store.dropped_count(metrics::DroppedSignal::LogLines), 2);
    let text = flaky.written.text();
    let reports: Vec<Value> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|v| v["event"] == "telemetry.dropped")
        .collect();
    assert_eq!(reports.len(), 1, "{text}");
    assert_eq!(reports[0]["dropped_lines"], 2);
}

/// Under concurrent emitters, `flush` never returns `true` until the caller's own accepted
/// line has been written to the underlying stream.
#[test]
fn flush_waits_for_accepted_lines_under_concurrent_emitters() {
    let out = Capture::default();
    let queue = sink::Queue::spawn(out.make_writer(), sink::CAPACITY, JSON_INFO).unwrap();
    let rounds = 300usize;
    let start = Arc::new(std::sync::Barrier::new(5));
    let end = Arc::new(std::sync::Barrier::new(5));
    let mut workers = Vec::new();
    for w in 0..4 {
        let q = queue.clone();
        let start = start.clone();
        let end = end.clone();
        workers.push(std::thread::spawn(move || {
            for round in 0..rounds {
                start.wait();
                for n in 0..8 {
                    offer(&q, &format!("worker-{w}-{round}-{n}\n"));
                }
                end.wait();
            }
        }));
    }
    for round in 0..rounds {
        start.wait();
        let marker = format!("marker-{round}");
        offer(&queue, &format!("{marker}\n"));
        assert!(queue.flush(Duration::from_secs(10)));
        assert!(
            out.text().lines().any(|l| l == marker),
            "flush returned before {marker} was written"
        );
        end.wait();
        assert!(queue.flush(Duration::from_secs(10)));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(queue.flush(Duration::from_secs(10)));
    assert_eq!(out.text().lines().count(), rounds * (4 * 8 + 1));
}

/// One HTTP/1.1 exchange on a new connection; returns the status code.
pub(crate) async fn exchange(address: SocketAddr, request: &[u8]) -> u16 {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let status = std::str::from_utf8(&response[9..12]).unwrap();
        status.parse().unwrap()
    })
    .await
    .expect("no response within ten seconds")
}

/// The served health routes, built and observed as in `serve`, over a configuration whose
/// database password is a canary and a database that never answers.
#[tokio::test]
async fn health_routes_record_the_template_method_status_and_a_server_id_only() {
    let database = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = database.local_addr().unwrap().port();
    let password = "CANARY-db-password-41c2";
    let url = format!("postgres://fixture:{password}@127.0.0.1:{port}/fixture?sslmode=disable");
    let config = crate::Config::parse(crate::Role::Api, |key| {
        Ok(match key {
            "DATABASE_URL" => Some(url.clone()),
            "DB_TIMEOUT_MS" => Some("200".into()),
            "LOG_LEVEL" => Some("debug".into()),
            _ => None,
        })
    })
    .ok()
    .unwrap();
    let (capture, _guard) = Capture::install(config.telemetry.format, config.telemetry.verbosity);
    let app = observe(crate::routes(crate::Health {
        pool: crate::pool(&config),
        timeout: config.database_timeout,
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let client_id = "0b7d3f52-1a2e-4f6c-9d8b-7e6a5c4b3a21";
    let canaries = [
        "CANARY-query-5e1d",
        "CANARY-cookie-9b07",
        "CANARY-header-c4e8",
        "CANARY-path-02af",
        "CANARY-body-6d3b",
    ];
    let headers = format!(
        "host: localhost\r\ncookie: __Host-openmettle-session={}\r\nx-api-key: {}\r\n\
         x-request-id: {client_id}\r\ntraceparent: 00-{}-01\r\nconnection: close\r\n",
        canaries[1], canaries[2], canaries[2]
    );
    let body = canaries[4];
    let length = body.len();
    let cases = [
        (
            format!(
                "GET /healthz?token={} HTTP/1.1\r\n{headers}\r\n",
                canaries[0]
            ),
            200,
            "/healthz",
            "GET",
        ),
        (
            format!("GET /readyz HTTP/1.1\r\n{headers}\r\n"),
            503,
            "/readyz",
            "GET",
        ),
        (
            format!("POST /healthz HTTP/1.1\r\n{headers}content-length: {length}\r\n\r\n{body}"),
            405,
            "/healthz",
            "POST",
        ),
        (
            format!(
                "PUT /{}/x HTTP/1.1\r\n{headers}content-length: {length}\r\n\r\n{body}",
                canaries[3]
            ),
            404,
            "unmatched",
            "PUT",
        ),
        (
            format!("BREW /healthz HTTP/1.1\r\n{headers}\r\n"),
            405,
            "/healthz",
            "_OTHER",
        ),
    ];
    for (request, status, _, _) in &cases {
        assert_eq!(
            exchange(address, request.as_bytes()).await,
            *status,
            "{request}"
        );
    }
    // The readiness probe reached the canary-configured database.
    assert!(database.accept().is_ok());

    let events = capture.events("http.request.completed");
    assert_eq!(events.len(), cases.len(), "{}", capture.text());
    let mut ids = BTreeSet::new();
    for (event, (_, status, route, method)) in events.iter().zip(&cases) {
        assert_eq!(event["http.route"], *route);
        assert_eq!(event["http.request.method"], *method);
        assert_eq!(event["http.response.status_code"], *status);
        assert_eq!(
            event["level"],
            if *status >= 500 { "WARN" } else { "DEBUG" }
        );
        let id = event["request_id"].as_str().unwrap();
        assert!(is_v4(id), "{id}");
        ids.insert(id.to_owned());
    }
    assert_eq!(ids.len(), cases.len());
    let mut planted: Vec<&[u8]> = canaries.iter().map(|c| c.as_bytes()).collect();
    planted.extend([
        password.as_bytes(),
        client_id.as_bytes(),
        b"CANARY",
        b"BREW",
        b"token=",
    ]);
    capture.assert_absent(&planted);
}

pub(crate) mod otlp;
