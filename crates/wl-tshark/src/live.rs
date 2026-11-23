//! `start(Live)`.
//!
//! Design: `dumpcap -w -` writes pcapng to its stdout; one "tee" thread copies every chunk to the
//! backing file (unbuffered `File`, so each chunk is on disk immediately) AND into the stdin of
//! `tshark -l -r -`, which dissects the stream. Compared to a tail-follow thread on a file this
//! has no polling latency, no partial-block races on rotation, and the file is by construction
//! exactly what tshark saw. (`dumpcap -P` means "write pcap, not pcapng", so it is not used.)
//! Stopping kills dumpcap; tee sees EOF, closes tshark's stdin and tshark drains and exits.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crossbeam_channel::bounded;
use wl_model::{CaptureError, CaptureOptions, Session};

use crate::capture_args::stream_args;
use crate::control::Control;
use crate::error::{from_dumpcap, from_ssh, io_error};
use crate::finish::{ProducerError, tshark_finish};
use crate::process::{Proc, StderrTap, Tools, spawn};
use crate::remote_args::ssh_args;
use crate::row_parser::field_args;
use crate::{pump, ring, validate};

pub struct LiveArgs<'a> {
    pub options: &'a CaptureOptions,
    pub display_filter: Option<&'a str>,
    pub backing_file: &'a Path,
    pub empty_pcap: &'a Path,
    /// Extra tshark options (TLS keylog).
    pub opts: &'a [String],
}

/// The process whose stdout carries the capture: local dumpcap, or ssh running remote tcpdump.
struct Producer {
    program: PathBuf,
    args: Vec<String>,
    classify: fn(&str) -> CaptureError,
}

fn producer(tools: &Tools, o: &CaptureOptions) -> Result<Producer, CaptureError> {
    if !o.remote.enabled {
        return Ok(Producer {
            program: tools.dumpcap.clone(),
            args: stream_args(o),
            classify: from_dumpcap,
        });
    }
    if let Some(problem) = o.remote.problem() {
        return Err(CaptureError::Other(problem.into()));
    }
    Ok(Producer {
        program: crate::find_tool(None, "ssh")
            .ok_or_else(|| CaptureError::ToolMissing("ssh".into()))?,
        args: ssh_args(o),
        classify: from_ssh,
    })
}

/// Copies dumpcap's stream to the backing file and tshark. Returns tshark's stdin (so the caller
/// controls when it sees EOF) and the write error, if the backing file could not be written
/// (disk full, quota): the capture is then incomplete and must be reported, not "Finished".
fn tee<S: Write>(
    mut src: impl Read,
    mut file: impl Write,
    mut sink: S,
) -> (S, Option<std::io::Error>) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut sink_ok = true;
    while let Ok(n) = src.read(&mut buf) {
        if n == 0 {
            break;
        }
        if let Err(e) = file.write_all(&buf[..n]) {
            return (sink, Some(e));
        }
        if sink_ok && sink.write_all(&buf[..n]).is_err() {
            sink_ok = false;
        }
    }
    (sink, None)
}

pub fn start(tools: &Tools, a: &LiveArgs) -> Result<Session, CaptureError> {
    let display = a.display_filter.filter(|f| !f.trim().is_empty());
    if let Some(f) = display {
        validate::display_filter(tools, a.empty_pcap, f)?;
    }
    let file = File::create(a.backing_file).map_err(|e| io_error("create capture file", &e))?;

    let source = producer(tools, a.options)?;
    let mut dumpcap = spawn(&source.program, &source.args, false)?;
    let (d_out, d_err) = (dumpcap.stdout.take(), dumpcap.stderr.take());
    let dumpcap = Proc::new(dumpcap);
    let (Some(d_out), Some(d_err)) = (d_out, d_err) else {
        dumpcap.kill();
        return Err(CaptureError::Other("dumpcap pipes unavailable".into()));
    };
    let d_tap = StderrTap::spawn(d_err);

    let mut targs = vec!["-l".to_string(), "-r".into(), "-".into()];
    targs.extend(a.opts.iter().cloned());
    targs.extend(field_args());
    if let Some(f) = display {
        targs.extend(["-Y".into(), f.into()]);
    }
    let mut tshark = match spawn(&tools.tshark, &targs, true) {
        Ok(c) => c,
        Err(e) => {
            dumpcap.kill();
            return Err(e);
        }
    };
    let (t_in, t_out, t_err) = (
        tshark.stdin.take(),
        tshark.stdout.take(),
        tshark.stderr.take(),
    );
    let tshark = Proc::new(tshark);
    let (Some(t_in), Some(t_out), Some(t_err)) = (t_in, t_out, t_err) else {
        dumpcap.kill();
        tshark.kill();
        return Err(CaptureError::Other("tshark pipes unavailable".into()));
    };

    // dumpcap reports permission / bad capture filter by exiting right away.
    if let Some(status) = dumpcap.wait_exit(Duration::from_millis(300)) {
        tshark.kill();
        drop(file);
        let _ = std::fs::remove_file(a.backing_file);
        let msg = d_tap.finish();
        return Err(if status.success() {
            CaptureError::Other("dumpcap exited unexpectedly".into())
        } else {
            (source.classify)(&msg)
        });
    }

    let recorder = match ring::start(tools, a.options) {
        Ok(r) => r,
        Err(e) => {
            dumpcap.kill();
            tshark.kill();
            return Err(e);
        }
    };

    let producer_err: ProducerError = Arc::new(Mutex::new(None));
    let tee_thread = {
        let (dumpcap, producer_err) = (dumpcap.clone(), producer_err.clone());
        thread::spawn(move || {
            let (sink, write_err) = tee(d_out, file, t_in);
            if let (Some(e), Ok(mut g)) = (&write_err, producer_err.lock()) {
                *g = Some(io_error("write capture file (disk full?)", e));
            }
            let stderr = d_tap.finish();
            let failed = dumpcap
                .wait_exit(Duration::from_secs(1))
                .is_some_and(|s| !s.success());
            if failed
                && write_err.is_none()
                && !stderr.trim().is_empty()
                && let Ok(mut g) = producer_err.lock()
            {
                *g = Some((source.classify)(&stderr));
            }
            drop(sink); // only now: tshark sees EOF, after the error (if any) is recorded
        })
    };
    // NOTE: a deliberate stop() kills dumpcap (non-zero status); `finish(stopped=true)` ignores it.
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = bounded(64);
    let finish = tshark_finish(tshark.clone(), StderrTap::spawn(t_err), Some(producer_err));
    let mut threads = pump::spawn(t_out, tx, stop.clone(), finish);
    threads.push(tee_thread);
    let control = Control {
        stop,
        procs: vec![dumpcap, tshark],
        recorders: recorder.into_iter().collect(),
        threads,
    };
    Ok(control.into_session(rx, a.backing_file.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(Error::new(
                ErrorKind::StorageFull,
                "no space left on device",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tee_reports_backing_file_write_failure_and_returns_sink() {
        let (sink, err) = tee(&b"pcapng bytes"[..], Full, Vec::new());
        assert!(err.is_some_and(|e| e.kind() == ErrorKind::StorageFull));
        assert!(
            sink.is_empty(),
            "nothing is forwarded after the file failed"
        );
    }

    #[test]
    fn hostile_remote_target_is_refused_before_spawning() {
        let tools = Tools {
            tshark: PathBuf::new(),
            dumpcap: PathBuf::new(),
            editcap: None,
            mergecap: None,
            capinfos: None,
        };
        let mut o = CaptureOptions::single("ignored", None);
        o.remote.enabled = true;
        o.remote.host = "-oProxyCommand=touch x".into();
        o.remote.interface = "eth0".into();
        assert!(matches!(producer(&tools, &o), Err(CaptureError::Other(_))));
    }

    #[test]
    fn tee_copies_to_both_outputs() {
        let (mut file, sink) = (Vec::new(), Vec::new());
        let (sink, err) = tee(&b"abc"[..], &mut file, sink);
        assert!(err.is_none());
        assert_eq!(
            (file.as_slice(), sink.as_slice()),
            (&b"abc"[..], &b"abc"[..])
        );
    }
}
