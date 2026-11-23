//! The real fixtures against tshark, when tshark is installed.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::tests::drain;
use super::{PacketSource, open};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn capture_files() -> Vec<PathBuf> {
    let Ok(dir) = std::fs::read_dir(fixtures()) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = dir
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("pcap" | "pcapng")
            )
        })
        .collect();
    files.sort();
    files
}

/// `frame.number`, `frame.time_epoch`, `frame.len` per packet, or `None` without tshark.
fn tshark_rows(path: &Path) -> Option<Vec<(u64, f64, u32)>> {
    let out = Command::new("tshark")
        .args(["-r"])
        .arg(path)
        .args([
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    text.lines()
        .map(|line| {
            let mut f = line.split('\t');
            Some((
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
            ))
        })
        .collect()
}

fn read_all(path: &Path) -> Vec<(u64, f64, u32)> {
    let mut source: Box<dyn PacketSource> = open(path).expect("open");
    let got = drain(source.as_mut());
    assert!(got.error.is_none(), "{}: {:?}", path.display(), got.error);
    got.packets
        .iter()
        .map(|(m, _)| (m.no, m.epoch, m.orig_len))
        .collect()
}

#[test]
fn every_fixture_reads_to_the_end() {
    for path in capture_files() {
        let rows = read_all(&path);
        assert!(!rows.is_empty(), "{}", path.display());
    }
}

#[test]
fn fixtures_match_tshark_number_time_and_length() {
    for path in capture_files() {
        let Some(want) = tshark_rows(&path) else {
            continue;
        };
        let got = read_all(&path);
        assert_eq!(got.len(), want.len(), "{}", path.display());
        for (g, w) in got.iter().zip(&want) {
            assert_eq!(g.0, w.0, "{}", path.display());
            assert!((g.1 - w.1).abs() < 1e-6, "{} frame {}", path.display(), g.0);
            assert_eq!(g.2, w.2, "{} frame {}", path.display(), g.0);
        }
    }
}
