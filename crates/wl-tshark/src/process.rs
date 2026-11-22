//! Tool discovery and child-process helpers (spawn, reap, stderr capture).

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use wl_model::CaptureError;

use crate::error::spawn_error;

#[derive(Debug, Clone)]
pub struct Tools {
    pub tshark: PathBuf,
    pub dumpcap: PathBuf,
    pub editcap: Option<PathBuf>,
    pub mergecap: Option<PathBuf>,
}

pub(crate) fn find_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

impl Tools {
    pub fn locate() -> Result<Tools, CaptureError> {
        let need = |n: &str| find_in_path(n).ok_or_else(|| CaptureError::ToolMissing(n.into()));
        Ok(Tools {
            tshark: need("tshark")?,
            dumpcap: need("dumpcap")?,
            editcap: find_in_path("editcap"),
            mergecap: find_in_path("mergecap"),
        })
    }
}

static SPAWNED: AtomicUsize = AtomicUsize::new(0);

/// Child processes started so far; tests and benchmarks diff it to count scans.
pub fn spawned() -> usize {
    SPAWNED.load(Ordering::Relaxed)
}

/// Runs a tool to completion (stdin closed) and returns its output.
pub fn run<I, S>(tool: &Path, args: I) -> Result<Output, CaptureError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    SPAWNED.fetch_add(1, Ordering::Relaxed);
    Command::new(tool)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| spawn_error(&tool.to_string_lossy(), &e))
}

/// Spawns with piped stdout/stderr (and stdin when `pipe_stdin`).
pub fn spawn(tool: &Path, args: &[String], pipe_stdin: bool) -> Result<Child, CaptureError> {
    SPAWNED.fetch_add(1, Ordering::Relaxed);
    Command::new(tool)
        .args(args)
        .stdin(if pipe_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| spawn_error(&tool.to_string_lossy(), &e))
}

/// Kills and reaps the wrapped child on drop if it was not already reaped.
struct ReapChild(Child);

impl Drop for ReapChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Every child ever spawned and still referenced, so a signal handler can reap them all.
static REGISTRY: Mutex<Vec<Weak<Mutex<ReapChild>>>> = Mutex::new(Vec::new());

/// Kills and reaps every tshark/dumpcap/editcap child that is still alive. Call from a
/// SIGTERM/SIGINT/SIGHUP handler thread: a dying app cannot rely on `Drop` (dumpcap on a quiet
/// interface would otherwise live on, orphaned, until its next write).
pub fn kill_all_children() {
    kill_registered(None);
}

/// Kills registered children; `only` restricts it to one pid (tests must not touch the tshark
/// processes of tests running in parallel).
fn kill_registered(only: Option<u32>) {
    let live: Vec<_> = {
        let mut r = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        r.retain(|w| w.strong_count() > 0);
        r.iter().filter_map(Weak::upgrade).collect()
    };
    for c in live {
        let mut c = c.lock().unwrap_or_else(|e| e.into_inner());
        if only.is_some_and(|pid| pid != c.0.id()) {
            continue;
        }
        if !matches!(c.0.try_wait(), Ok(Some(_))) {
            let _ = c.0.kill();
            let _ = c.0.wait();
        }
    }
}

/// Shared handle to a child so that both the owner and a stop closure can kill / reap it.
#[derive(Clone)]
pub struct Proc(Arc<Mutex<ReapChild>>);

impl Proc {
    pub fn new(child: Child) -> Proc {
        let arc = Arc::new(Mutex::new(ReapChild(child)));
        let mut r = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        r.retain(|w| w.strong_count() > 0);
        r.push(Arc::downgrade(&arc));
        Proc(arc)
    }

    fn lock(&self) -> MutexGuard<'_, ReapChild> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Kill and reap (idempotent, never leaves a zombie).
    pub fn kill(&self) {
        let mut c = self.lock();
        if !matches!(c.0.try_wait(), Ok(Some(_))) {
            let _ = c.0.kill();
            let _ = c.0.wait();
        }
    }

    pub fn try_exit(&self) -> Option<ExitStatus> {
        self.lock().0.try_wait().ok().flatten()
    }

    /// Polls for exit up to `timeout`.
    pub fn wait_exit(&self, timeout: Duration) -> Option<ExitStatus> {
        let end = Instant::now() + timeout;
        loop {
            if let Some(s) = self.try_exit() {
                return Some(s);
            }
            if Instant::now() >= end {
                return None;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Drains a child's stderr on a thread, keeping the first 64 KiB.
pub struct StderrTap(JoinHandle<String>);

impl StderrTap {
    pub fn spawn(mut stderr: impl Read + Send + 'static) -> StderrTap {
        StderrTap(thread::spawn(move || {
            let (mut keep, mut buf) = (Vec::new(), [0u8; 4096]);
            while let Ok(n) = stderr.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if keep.len() < 65_536 {
                    keep.extend_from_slice(&buf[..n]);
                }
            }
            String::from_utf8_lossy(&keep).into_owned()
        }))
    }

    /// Waits for the pipe to close (process gone) and returns the text.
    pub fn finish(self) -> String {
        self.0.join().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_reaps_and_is_idempotent() {
        let child = Command::new("sleep").arg("30").spawn();
        let Ok(child) = child else { return };
        let p = Proc::new(child);
        assert!(p.try_exit().is_none());
        p.kill();
        p.kill();
        assert!(p.try_exit().is_some());
    }

    #[test]
    fn drop_reaps_without_explicit_kill() {
        let Ok(child) = Command::new("sleep").arg("30").spawn() else {
            return;
        };
        let pid = child.id();
        let p = Proc::new(child);
        drop(p);
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err() || !stat.unwrap_or_default().contains(") Z "),
            "process {pid} leaked or became a zombie"
        );
    }

    #[test]
    fn kill_all_children_reaps_registered_processes() {
        let Ok(child) = Command::new("sleep").arg("30").spawn() else {
            return;
        };
        let pid = child.id();
        let p = Proc::new(child);
        kill_registered(Some(pid));
        assert!(p.try_exit().is_some(), "registered child survived");
    }

    #[test]
    fn missing_tool_maps_to_tool_missing() {
        let e = run(Path::new("/nonexistent/tool"), ["x"]).unwrap_err();
        assert!(matches!(e, CaptureError::ToolMissing(_)));
    }
}
