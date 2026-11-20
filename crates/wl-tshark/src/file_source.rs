//! `start(File)`: `tshark -r file` streamed through the row pump.
//! The channel is bounded so a 1M-packet file is parsed at the pace the UI consumes it.

use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crossbeam_channel::bounded;
use wl_model::{CaptureError, Session};

use crate::control::Control;
use crate::error::io_error;
use crate::finish::tshark_finish;
use crate::process::{Proc, StderrTap, Tools, spawn};
use crate::row_parser::field_args;
use crate::{pump, validate};

fn check_readable_file(file: &Path) -> Result<(), CaptureError> {
    let meta = std::fs::metadata(file).map_err(|e| match e.kind() {
        ErrorKind::NotFound => CaptureError::Other(format!("file not found: {}", file.display())),
        ErrorKind::PermissionDenied => CaptureError::Permission(format!("{}: {e}", file.display())),
        _ => io_error("open capture file", &e),
    })?;
    if meta.is_dir() {
        return Err(CaptureError::Other(format!(
            "expected a capture file, not a directory: {}",
            file.display()
        )));
    }
    if !meta.is_file() {
        return Err(CaptureError::Other(format!(
            "not a regular file: {}",
            file.display()
        )));
    }
    File::open(file).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => CaptureError::Permission(format!("{}: {e}", file.display())),
        _ => io_error("open capture file", &e),
    })?;
    Ok(())
}

pub fn start(
    tools: &Tools,
    empty_pcap: &Path,
    file: &Path,
    display_filter: Option<&str>,
    opts: &[String],
) -> Result<Session, CaptureError> {
    check_readable_file(file)?;
    if let Some(f) = display_filter.filter(|f| !f.trim().is_empty()) {
        validate::display_filter(tools, empty_pcap, f)?;
    }
    let mut args = vec!["-r".to_string(), file.to_string_lossy().into_owned()];
    args.extend(opts.iter().cloned());
    args.extend(field_args());
    if let Some(f) = display_filter.filter(|f| !f.trim().is_empty()) {
        args.extend(["-Y".into(), f.into()]);
    }
    let mut child = spawn(&tools.tshark, &args, false)?;
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    let proc = Proc::new(child);
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        proc.kill();
        return Err(CaptureError::Other("tshark pipes unavailable".into()));
    };
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = bounded(64);
    let finish = tshark_finish(proc.clone(), StderrTap::spawn(stderr), None);
    let threads = pump::spawn(stdout, tx, stop.clone(), finish);
    let control = Control {
        recorders: Vec::new(),
        stop,
        procs: vec![proc],
        threads,
    };
    Ok(control.into_session(rx, file.to_path_buf()))
}
