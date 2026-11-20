//! Regression: `editcap -r` silently keeps only 512 frame ranges; large scattered selections
//! must export completely. Skipped when mergecap/editcap are unavailable.

use std::path::{Path, PathBuf};
use std::process::Command;

use wl_model::{CaptureBackend, CaptureEvent, CaptureSource};
use wl_tshark::TsharkBackend;

fn sample() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sample.pcapng")
}

fn count_rows(b: &TsharkBackend, file: &Path) -> usize {
    let Ok(s) = b.start(CaptureSource::File(file.to_path_buf()), None) else {
        return 0;
    };
    let mut n = 0;
    while let Ok(ev) = s.events.recv() {
        match ev {
            CaptureEvent::Rows(r) => n += r.len(),
            _ => break,
        }
    }
    n
}

#[test]
fn exports_more_than_512_scattered_frames_completely() {
    let Ok(b) = TsharkBackend::new() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let big = dir.path().join("big.pcapng");
    let s = sample();
    let merged = Command::new("mergecap")
        .args(["-a", "-w"])
        .arg(&big)
        .args([&s, &s, &s, &s, &s])
        .status();
    if !merged.is_ok_and(|s| s.success()) {
        return;
    }
    let total = count_rows(&b, &big);
    assert!(total > 1100, "merged capture has {total} frames");
    let odd: Vec<u64> = (1..=total as u64).step_by(2).collect();
    assert!(odd.len() > 512);
    let dest = dir.path().join("out.pcapng");
    b.export(&big, Some(&odd), &dest).expect("export");
    assert_eq!(count_rows(&b, &dest), odd.len());
}
