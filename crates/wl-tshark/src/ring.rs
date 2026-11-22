//! Ring-buffer recorder: a second dumpcap that rotates files next to the live stream.

use std::path::Path;
use std::time::Duration;

use wl_model::{CaptureError, CaptureOptions};

use crate::capture_args::ring_args;
use crate::error::{from_dumpcap, io_error};
use crate::process::{Proc, StderrTap, Tools, spawn};

/// Starts the recorder when the ring is enabled. A recorder that dies at once (bad directory,
/// permission) fails the whole capture with dumpcap's message.
pub fn start(tools: &Tools, o: &CaptureOptions) -> Result<Option<Proc>, CaptureError> {
    let base = Path::new(o.save_to.trim());
    let Some(args) = ring_args(o, base).filter(|_| !o.remote.enabled) else {
        return Ok(None);
    };
    if let Some(dir) = base.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| io_error("create ring buffer directory", &e))?;
    }
    let mut child = spawn(&tools.dumpcap, &args, false)?;
    let tap = child.stderr.take().map(StderrTap::spawn);
    let proc = Proc::new(child);
    if let Some(status) = proc.wait_exit(Duration::from_millis(300)) {
        let msg = tap.map(StderrTap::finish).unwrap_or_default();
        return Err(if status.success() {
            CaptureError::Other("ring buffer recorder exited unexpectedly".into())
        } else {
            from_dumpcap(&msg)
        });
    }
    Ok(Some(proc))
}
