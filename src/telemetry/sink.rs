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
    io::Write,
    sync::{
        Arc, Condvar, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};
use tracing_subscriber::fmt::MakeWriter;

/// Lines held while the writer is behind: a few hundred kilobytes at most.
pub const CAPACITY: usize = 1024;

#[derive(Default)]
struct Progress {
    /// Lines the queue accepted.
    accepted: AtomicU64,
    /// Lines refused by a full queue or a stopped writer, or not written, and not yet
    /// reported.
    dropped: AtomicU64,
    /// Accepted lines the writer has finished with, whether written or not.
    handled: Mutex<u64>,
    changed: Condvar,
}

/// The emitting side, used as the formatting layer's writer.
#[derive(Clone)]
pub struct Queue {
    lines: SyncSender<Vec<u8>>,
    progress: Arc<Progress>,
}

impl Queue {
    /// Starts the writer thread over `out`. Drop reports are formatted with `settings`
    /// through the same guard and formatter as every other event.
    pub fn spawn<W>(out: W, capacity: usize, settings: Settings) -> std::io::Result<Self>
    where
        W: Write + Send + 'static,
    {
        let (lines, received) = sync_channel(capacity);
        let progress = Arc::<Progress>::default();
        let shared = progress.clone();
        thread::Builder::new()
            .name("telemetry-writer".into())
            .spawn(move || write_lines(received, out, &shared, settings))?;
        Ok(Self { lines, progress })
    }

    /// Never waits: a full queue or a stopped writer drops the line and counts it.
    fn offer(&self, line: Vec<u8>) {
        if self.lines.try_send(line).is_ok() {
            self.progress.accepted.fetch_add(1, Ordering::SeqCst);
        } else {
            self.progress.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Waits at most `limit` for the writer to finish every line accepted before this call.
    /// Returns whether it did.
    pub fn flush(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        let target = self.progress.accepted.load(Ordering::SeqCst);
        let handled = self.progress.handled.lock();
        let mut handled = handled.unwrap_or_else(PoisonError::into_inner);
        while *handled < target {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let waited = self.progress.changed.wait_timeout(handled, left);
            handled = waited.unwrap_or_else(PoisonError::into_inner).0;
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
/// [`Queue`] is gone.
fn write_lines<W: Write>(
    received: Receiver<Vec<u8>>,
    mut out: W,
    progress: &Progress,
    settings: Settings,
) {
    // This thread's events go to a private stack over `report`, never back to the queue.
    let report = Report::default();
    let make = {
        let report = report.clone();
        move || report.clone()
    };
    let _private = tracing::subscriber::set_default(subscriber(settings, make));
    for line in received {
        if write_all(&mut out, &line) {
            let dropped = progress.dropped.swap(0, Ordering::SeqCst);
            if dropped > 0 {
                lines_dropped(dropped);
                if !write_all(&mut out, &report.take()) {
                    progress.dropped.fetch_add(dropped, Ordering::SeqCst);
                }
            }
        } else {
            progress.dropped.fetch_add(1, Ordering::SeqCst);
        }
        *progress
            .handled
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += 1;
        progress.changed.notify_all();
    }
}
