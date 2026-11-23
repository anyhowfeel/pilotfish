//! `start_file`: streams the rows of a capture file to the UI on a worker thread.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::bounded;
use wl_model::{CaptureError, Session};

use crate::{filter, reader};

mod validate;
mod worker;

pub const BATCH_ROWS: usize = 500;
pub const FLUSH_EVERY: Duration = Duration::from_millis(50);
const CHANNEL_CAPACITY: usize = 64;
pub(crate) const THREAD_NAME: &str = "native-session";

/// Batches of up to `BATCH_ROWS` rows, flushed at least every `FLUSH_EVERY`, over a bounded
/// channel so the UI sets the pace. `PacketRow.no` is the frame number in the file even when the
/// filter hides frames. The session's `stop` ends the thread; dropping the receiver does too.
pub fn start_file(path: &Path, filter_text: Option<&str>) -> Result<Session, CaptureError> {
    validate::readable_file(path)?;
    let filter =
        match filter_text.filter(|f| !f.trim().is_empty()) {
            Some(text) => Some(filter::parse(text).ok_or_else(|| {
                CaptureError::BadFilter(format!("not supported natively: {text}"))
            })?),
            None => None,
        };
    let source = reader::open(path).map_err(|e| CaptureError::Other(e.to_string()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = bounded(CHANNEL_CAPACITY);
    let thread = thread::Builder::new()
        .name(THREAD_NAME.into())
        .spawn({
            let stop = stop.clone();
            move || worker::run(source, filter, &tx, &stop)
        })
        .map_err(|e| CaptureError::Other(format!("start reader thread: {e}")))?;
    let mut handle = Handle {
        stop,
        thread: Some(thread),
    };
    Ok(Session {
        events: rx,
        backing_file: path.to_path_buf(),
        stop: Box::new(move || handle.shutdown()),
    })
}

/// Ends the worker on request or when the session is dropped, so no thread outlives its session.
struct Handle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Handle {
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "validate_tests.rs"]
mod validate_tests;
#[cfg(test)]
#[path = "worker_tests.rs"]
mod worker_tests;
