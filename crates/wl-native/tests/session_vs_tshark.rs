//! Streams every fixture and a set of hand-built captures through `start_file` and compares the
//! rows that arrive with tshark's, frame by frame. Skips when tshark is not installed.

mod support;

use std::path::{Path, PathBuf};

use support::compare::{ALLOWED, compare_rows};
use support::reference;
use wl_model::CaptureEvent;
use wl_native::NativeBackend;
use wl_native::test_util::{PcapStyle, write_pcap};

fn fixtures() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("fixtures dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("pcap" | "pcapng")
            )
        })
        .collect();
    v.sort();
    v
}

fn stream(path: &Path) -> Vec<wl_model::PacketRow> {
    let session = NativeBackend::new().start_file(path, None).expect("start");
    let mut rows = Vec::new();
    for ev in session.events.iter() {
        match ev {
            CaptureEvent::Rows(r) => rows.extend(r),
            CaptureEvent::Finished => {}
            CaptureEvent::Failed(e) => panic!("{}: {e}", path.display()),
        }
    }
    rows
}

/// `Err(())` when tshark is missing.
fn check(name: &str, path: &Path, failures: &mut Vec<String>) -> Result<(), ()> {
    let reference = reference::run(path).ok_or(())?;
    let rows = stream(path);
    let counts = compare_rows(name, &rows, &reference, ALLOWED);
    eprintln!("{}", counts.summary(name));
    let numbers: Vec<u64> = rows.iter().map(|r| r.no).collect();
    if numbers != (1..=rows.len() as u64).collect::<Vec<_>>() {
        failures.push(format!("{name}: frame numbers are not 1..n in order"));
    }
    if rows.len() != reference.len() {
        failures.push(format!(
            "{name}: {} rows streamed, tshark has {}",
            rows.len(),
            reference.len()
        ));
    }
    failures.extend(counts.mismatches);
    Ok(())
}

fn finish(failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn streamed_fixtures_match_tshark() {
    let mut failures = Vec::new();
    for path in fixtures() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        if check(name, &path, &mut failures).is_err() {
            eprintln!("tshark not available, skipping the differential test");
            return;
        }
    }
    finish(failures);
}

#[test]
fn streamed_synthetic_captures_match_tshark() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut failures = Vec::new();
    for case in support::synthetic::all() {
        let path = dir.path().join(format!("{}.pcap", case.name));
        write_pcap(&path, &case.frames, PcapStyle::default());
        if check(&format!("synthetic:{}", case.name), &path, &mut failures).is_err() {
            eprintln!("tshark not available, skipping the differential test");
            return;
        }
    }
    finish(failures);
}
