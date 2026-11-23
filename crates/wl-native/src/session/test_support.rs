//! Helpers of the session tests.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use wl_model::{CaptureError, PacketRow, Session};

use super::{THREAD_NAME, start_file};
use crate::decode::Decoder;
use crate::reader;
use crate::test_util::{Frame, PcapStyle, collect, write_pcap};

static LOCK: Mutex<()> = Mutex::new(());

/// Tests that count worker threads must not overlap with tests that start them.
pub fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Worker threads alive in this process; `None` where /proc is not available.
pub fn worker_threads() -> Option<usize> {
    let dir = std::fs::read_dir("/proc/self/task").ok()?;
    let names = dir
        .filter_map(|e| std::fs::read_to_string(e.ok()?.path().join("comm")).ok())
        .filter(|n| n.trim() == THREAD_NAME);
    Some(names.count())
}

pub fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn pcap_file(dir: &Path, frames: &[Frame]) -> std::path::PathBuf {
    let path = dir.join("t.pcap");
    write_pcap(&path, frames, PcapStyle::default());
    path
}

/// What `Decoder` makes of the file, without the session.
pub fn expected_rows(path: &Path) -> Vec<PacketRow> {
    let mut source = reader::open(path).expect("open");
    let (mut decoder, mut data, mut first) = (Decoder::default(), Vec::new(), None);
    let mut rows = Vec::new();
    while let Some(meta) = source.next_packet(&mut data).expect("read") {
        let f = *first.get_or_insert(meta.epoch);
        rows.push(decoder.decode(&meta, &data, f).row);
    }
    rows
}

pub fn run(path: &Path) -> Result<crate::test_util::Received, CaptureError> {
    start_file(path, None).map(|s| collect(&s))
}

pub fn started(path: &Path) -> Session {
    start_file(path, None).expect("start")
}
