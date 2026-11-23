//! Computes the I/O series of every fixture capture and of hand-built ones natively and compares
//! them bucket by bucket with `tshark -q -z io,stat`, run the way `wl-tshark` runs it. Skips when
//! tshark is missing.

mod support;

use std::path::Path;
use std::process::Command;

use support::{edge_cases, fixtures};
use wl_model::{DeltaStat, IoGraph, IoSeries, IoSpec};
use wl_native::NativeBackend;

const INTERVALS: [f64; 5] = [1.0, 0.5, 0.1, 0.01, 0.001];
/// Tables longer than this are skipped: tshark prints one line per bucket.
const MAX_ROWS: f64 = 30_000.0;
/// tshark prints the deltas with six decimals.
const DELTA_SLACK: f64 = 6e-7;

const NEGATIVE_DELTA: &str = "the capture has a packet older than the one before it; tshark then prints \
a stale or unrelated value for frame.time_delta, the native series keeps the real (negative) one";

/// `(capture, field, reason)` of a difference that is on purpose.
const ALLOWED: &[(&str, &str, &str)] = &[
    ("synthetic:out-of-order.pcap", "delta", NEGATIVE_DELTA),
    ("synthetic:multi-interface.pcapng", "delta", NEGATIVE_DELTA),
];

fn specs() -> Vec<IoSpec> {
    [DeltaStat::Max, DeltaStat::Min]
        .map(|d| IoSpec {
            filter: String::new(),
            delta: Some(d),
        })
        .to_vec()
}

fn stat_arg(interval: f64) -> String {
    let column = |f: &str, field: &str| format!("{f}({field}){field}");
    let calcs: Vec<String> = [("MAX", "frame.time_delta"), ("MIN", "frame.time_delta")]
        .iter()
        .flat_map(|(f, d)| {
            [
                column("COUNT", "frame"),
                column("SUM", "frame.len"),
                column(f, d),
            ]
        })
        .collect();
    format!("io,stat,{interval},{}", calcs.join(","))
}

fn tshark(path: &Path, interval: f64) -> Option<String> {
    let out = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(["-q", "-z", &stat_arg(interval)])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Value cells of a table row such as `|  0 <> 1 |  2 | 196 |`.
fn row_cells(line: &str) -> Option<Vec<&str>> {
    let mut cells = line.trim().strip_prefix('|')?.split('|').map(str::trim);
    cells
        .next()
        .filter(|first| first.contains("<>"))
        .map(|_| cells.filter(|c| !c.is_empty()).collect())
}

/// The graph tshark printed. Rows of stacked tables are joined by position.
fn parse(text: &str, interval: f64) -> IoGraph {
    let mut rows: Vec<Vec<&str>> = Vec::new();
    let mut at = 0;
    for line in text.lines() {
        if line.starts_with('=') {
            at = 0;
        } else if let Some(cells) = row_cells(line) {
            if at == rows.len() {
                rows.push(Vec::new());
            }
            rows[at].extend(cells);
            at += 1;
        }
    }
    let value = |row: &Vec<&str>, i: usize| row.get(i).and_then(|c| c.parse::<f64>().ok());
    let series = |first: usize| IoSeries {
        packets: rows
            .iter()
            .map(|r| value(r, first).unwrap_or(0.0) as u64)
            .collect(),
        bytes: rows
            .iter()
            .map(|r| value(r, first + 1).unwrap_or(0.0) as u64)
            .collect(),
        delta: rows
            .iter()
            .map(|r| value(r, first + 2).unwrap_or(0.0))
            .collect(),
        error: None,
    };
    let duration = text
        .lines()
        .find_map(|l| l.trim_start_matches([' ', '|']).strip_prefix("Duration:"))
        .and_then(|d| d.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0);
    IoGraph {
        interval,
        duration,
        series: vec![series(0), series(3)],
    }
}

/// tshark prints the duration with the decimals of the interval, three from one second up.
fn duration_slack(interval: f64) -> f64 {
    let decimals = match format!("{interval}").split_once('.') {
        Some((_, fraction)) if interval < 1.0 => fraction.len() as i32,
        _ => 3,
    };
    0.5 * 10f64.powi(-decimals) + 1e-9
}

/// The first buckets where the two series disagree, as `bucket: ours / theirs`.
fn disagreements<T: Copy + std::fmt::Debug>(
    ours: &[T],
    theirs: &[T],
    same: impl Fn(T, T) -> bool,
) -> Option<String> {
    let mut at: Vec<String> = ours
        .iter()
        .zip(theirs)
        .enumerate()
        .filter(|(_, (a, b))| !same(**a, **b))
        .map(|(i, (a, b))| format!("{i}: {a:?} / {b:?}"))
        .collect();
    if ours.len() != theirs.len() {
        at.push(format!("{} buckets / {}", ours.len(), theirs.len()));
    }
    (!at.is_empty()).then(|| at.into_iter().take(5).collect::<Vec<_>>().join(", "))
}

fn differences(ours: &IoGraph, theirs: &IoGraph) -> Vec<(&'static str, String)> {
    let mut bad = Vec::new();
    if (ours.duration - theirs.duration).abs() > duration_slack(ours.interval) {
        bad.push((
            "duration",
            format!("{} / {}", ours.duration, theirs.duration),
        ));
    }
    for (n, (a, b)) in ours.series.iter().zip(&theirs.series).enumerate() {
        let checks = [
            (
                "packets",
                disagreements(&a.packets, &b.packets, |x, y| x == y),
            ),
            ("bytes", disagreements(&a.bytes, &b.bytes, |x, y| x == y)),
            (
                "delta",
                disagreements(&a.delta, &b.delta, |x, y| (x - y).abs() <= DELTA_SLACK),
            ),
        ];
        for (field, found) in checks {
            if let Some(what) = found {
                bad.push((field, format!("series {n}: {what}")));
            }
        }
    }
    bad
}

/// `Err(())` when tshark is missing.
fn check(name: &str, path: &Path, failures: &mut Vec<String>) -> Result<(), ()> {
    let mut compared = 0;
    for interval in INTERVALS {
        let text = tshark(path, interval).ok_or(())?;
        let theirs = parse(&text, interval);
        if theirs.duration / interval > MAX_ROWS {
            continue;
        }
        let ours = NativeBackend::new()
            .io_series(path, &specs(), interval)
            .expect("empty filters are native")
            .unwrap_or_else(|e| panic!("{name} at {interval}: {e}"));
        compared += 1;
        for (field, what) in differences(&ours, &theirs) {
            if !ALLOWED.iter().any(|(n, f, _)| *n == name && *f == field) {
                failures.push(format!("{name} at {interval} {field}: {}", what));
            }
        }
    }
    eprintln!("{name}: {compared} intervals compared");
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
fn fixtures_match_tshark() {
    let mut failures = Vec::new();
    for path in fixtures::fixtures() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_owned();
        if check(&name, &path, &mut failures).is_err() {
            eprintln!("tshark not available, skipping the differential test");
            return;
        }
    }
    finish(failures);
}

#[test]
fn synthetic_captures_match_tshark() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut failures = Vec::new();
    for (file, bytes) in edge_cases::all() {
        let path = dir.path().join(file);
        std::fs::write(&path, bytes).expect("write");
        if check(&format!("synthetic:{file}"), &path, &mut failures).is_err() {
            eprintln!("tshark not available, skipping the differential test");
            return;
        }
    }
    finish(failures);
}
