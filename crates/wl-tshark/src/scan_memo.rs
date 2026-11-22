//! Per-file memo of whole-capture scans: each runs once per file version, even when several
//! features ask for it at the same time (the second caller waits for the first).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use wl_model::CaptureError;

/// A file version: a growing capture gets a new stamp on every write.
type Stamp = (u64, Option<SystemTime>);

const MAX_FILES: usize = 8;

type Slot<T> = Arc<Mutex<Option<(Stamp, Vec<T>)>>>;

pub struct ScanMemo<T> {
    slots: Mutex<HashMap<PathBuf, Slot<T>>>,
}

impl<T> Default for ScanMemo<T> {
    fn default() -> Self {
        Self {
            slots: Mutex::default(),
        }
    }
}

fn stamp(file: &Path) -> Option<Stamp> {
    let m = std::fs::metadata(file).ok()?;
    Some((m.len(), m.modified().ok()))
}

impl<T: Clone> ScanMemo<T> {
    pub fn get_or_scan(
        &self,
        file: &Path,
        scan: impl FnOnce() -> Result<Vec<T>, CaptureError>,
    ) -> Result<Vec<T>, CaptureError> {
        let Some(now) = stamp(file) else {
            return scan();
        };
        let slot = {
            let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            if slots.len() >= MAX_FILES && !slots.contains_key(file) {
                slots.clear();
            }
            slots.entry(file.to_path_buf()).or_default().clone()
        };
        let mut held = slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((s, v)) = held.as_ref()
            && *s == now
        {
            return Ok(v.clone());
        }
        let v = scan()?;
        *held = Some((now, v.clone()));
        Ok(v)
    }

    pub fn clear(&self) {
        self.slots.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn scans_once_per_file_version_and_not_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.pcap");
        std::fs::write(&f, b"one").unwrap();
        let memo = ScanMemo::<u8>::default();
        let runs = AtomicUsize::new(0);
        let scan = || {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(vec![1])
        };
        memo.get_or_scan(&f, scan).unwrap();
        memo.get_or_scan(&f, scan).unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        std::fs::write(&f, b"longer").unwrap();
        memo.get_or_scan(&f, scan).unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        memo.clear();
        memo.get_or_scan(&f, scan).unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        let failing = ScanMemo::<u8>::default();
        assert!(
            failing
                .get_or_scan(&f, || Err(CaptureError::Other("x".into())))
                .is_err()
        );
        assert!(failing.get_or_scan(&f, scan).is_ok());
    }

    #[test]
    fn concurrent_callers_share_one_scan() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.pcap");
        std::fs::write(&f, b"one").unwrap();
        let memo = ScanMemo::<u8>::default();
        let runs = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    memo.get_or_scan(&f, || {
                        runs.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        Ok(vec![1])
                    })
                });
            }
        });
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
