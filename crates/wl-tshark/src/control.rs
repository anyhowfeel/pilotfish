//! Lifecycle of a running capture: stop flag, child processes, worker threads.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::Receiver;
use wl_model::{CaptureEvent, Session};

use crate::process::Proc;

/// Owns everything a session spawned. Shutdown is idempotent and also runs on drop,
/// so a dropped `Session` never leaves processes or threads behind.
pub struct Control {
    pub stop: Arc<AtomicBool>,
    /// Producer first (dumpcap / tshark), downstream consumers after it.
    pub procs: Vec<Proc>,
    /// Independent writers (ring-buffer dumpcap): killed together with the producer.
    pub recorders: Vec<Proc>,
    pub threads: Vec<JoinHandle<()>>,
}

impl Control {
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(producer) = self.procs.first() {
            producer.kill();
        }
        for r in &self.recorders {
            r.kill();
        }
        // Downstream processes see EOF and drain the remaining packets by themselves.
        for p in self.procs.iter().skip(1) {
            if p.wait_exit(Duration::from_secs(2)).is_none() {
                p.kill();
            }
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }

    pub fn into_session(
        mut self,
        events: Receiver<CaptureEvent>,
        backing_file: PathBuf,
    ) -> Session {
        Session {
            events,
            backing_file,
            stop: Box::new(move || self.shutdown()),
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.shutdown();
    }
}
