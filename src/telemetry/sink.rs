//! Non-blocking delivery of formatted lines to stderr (ADR 0024, "Delivery").
//!
//! The formatting layer runs on the emitting thread, usually a Tokio worker. Its writer only
//! offers the finished line to a bounded queue and never waits. One dedicated thread writes
//! queued lines to the real stream. A line is dropped and counted when the queue is full or
//! the write fails. After the next successful write the thread writes one
//! `telemetry.dropped` event with the count. A stalled or closed stderr therefore costs
//! telemetry lines, never request handling or shutdown.
use super::{Settings, lines_dropped, subscriber};
use std::{
    collections::VecDeque,
    io::Write,
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    thread,
    time::{Duration, Instant},
};
use tracing_subscriber::fmt::MakeWriter;

/// Lines held while the writer is behind: a few hundred kilobytes at most.
pub const CAPACITY: usize = 1024;

struct State {
    lines: VecDeque<Vec<u8>>,
    capacity: usize,
    /// Lines accepted into `lines`. Enqueueing and incrementing this are atomic, so
    /// `handled <= accepted` holds unconditionally and `flush` cannot return before every line
    /// accepted ahead of it has been handled.
    accepted: u64,
    /// Accepted lines the writer has finished with, whether written or not.
    handled: u64,
    /// Lines refused by a full queue or not written, and not yet reported.
    dropped: u64,
    /// True once every emitting [`Queue`] handle is gone.
    closed: bool,
}

struct Shared {
    state: Mutex<State>,
    wake_writer: Condvar,
    wake_flush: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct EmitterGuard {
    shared: Arc<Shared>,
}

impl Drop for EmitterGuard {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.closed = true;
        drop(state);
        self.shared.wake_writer.notify_all();
    }
}

/// The emitting side, used as the formatting layer's writer.
#[derive(Clone)]
pub struct Queue {
    guard: Arc<EmitterGuard>,
}

impl Queue {
    /// Starts the writer thread over `out`. Drop reports are formatted with `settings`
    /// through the same guard and formatter as every other event.
    pub fn spawn<W>(out: W, capacity: usize, settings: Settings) -> std::io::Result<Self>
    where
        W: Write + Send + 'static,
    {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                lines: VecDeque::with_capacity(capacity.min(CAPACITY)),
                capacity,
                accepted: 0,
                handled: 0,
                dropped: 0,
                closed: false,
            }),
            wake_writer: Condvar::new(),
            wake_flush: Condvar::new(),
        });
        let writer = shared.clone();
        thread::Builder::new()
            .name("telemetry-writer".into())
            .spawn(move || write_lines(writer, out, settings))?;
        Ok(Self {
            guard: Arc::new(EmitterGuard { shared }),
        })
    }

    /// Never waits on I/O: a full queue drops the line and counts it.
    fn offer(&self, line: Vec<u8>) {
        let mut state = self.guard.shared.lock();
        if state.lines.len() < state.capacity {
            state.lines.push_back(line);
            state.accepted += 1;
            drop(state);
            self.guard.shared.wake_writer.notify_one();
        } else {
            state.dropped = state.dropped.saturating_add(1);
        }
    }

    /// Waits at most `limit` for the writer to finish every line accepted before this call.
    /// Returns whether it did.
    pub fn flush(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        let mut state = self.guard.shared.lock();
        let target = state.accepted;
        while state.handled < target {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            if left.is_zero() {
                return false;
            }
            let waited = self.guard.shared.wake_flush.wait_timeout(state, left);
            state = waited.unwrap_or_else(PoisonError::into_inner).0;
        }
        true
    }
}

/// One event's bytes, offered to the queue when the formatting layer drops the writer.
pub struct Line<'q> {
    bytes: Vec<u8>,
    queue: &'q Queue,
}

impl Write for Line<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Line<'_> {
    fn drop(&mut self) {
        if !self.bytes.is_empty() {
            self.queue.offer(std::mem::take(&mut self.bytes));
        }
    }
}

impl<'q> MakeWriter<'q> for Queue {
    type Writer = Line<'q>;
    fn make_writer(&'q self) -> Line<'q> {
        Line {
            bytes: Vec::new(),
            queue: self,
        }
    }
}

/// Where the writer thread's own drop report is formatted before it is written.
#[derive(Clone, Default)]
struct Report(Arc<Mutex<Vec<u8>>>);

impl Write for Report {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut buffer = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Report {
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

fn write_all(out: &mut impl Write, bytes: &[u8]) -> bool {
    out.write_all(bytes).and_then(|()| out.flush()).is_ok()
}

/// The writer thread: the only code that waits on the real stream. It ends when every
/// [`Queue`] is gone and all queued lines have been drained.
fn write_lines<W: Write>(shared: Arc<Shared>, mut out: W, settings: Settings) {
    // This thread's events go to a private stack over `report`, never back to the queue.
    let report = Report::default();
    let make = {
        let report = report.clone();
        move || report.clone()
    };
    let _private = tracing::subscriber::set_default(subscriber(settings, make));
    loop {
        let line = {
            let mut state = shared.lock();
            loop {
                if let Some(line) = state.lines.pop_front() {
                    break line;
                }
                if state.closed {
                    return;
                }
                state = shared
                    .wake_writer
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        if write_all(&mut out, &line) {
            let dropped = {
                let mut state = shared.lock();
                let dropped = std::mem::take(&mut state.dropped);
                if dropped == 0 {
                    state.handled += 1;
                }
                dropped
            };
            if dropped > 0 {
                lines_dropped(dropped);
                let reported = write_all(&mut out, &report.take());
                let mut state = shared.lock();
                if !reported {
                    state.dropped = state.dropped.saturating_add(dropped);
                }
                state.handled += 1;
            }
        } else {
            let mut state = shared.lock();
            state.dropped = state.dropped.saturating_add(1);
            state.handled += 1;
        }
        shared.wake_flush.notify_all();
    }
}
