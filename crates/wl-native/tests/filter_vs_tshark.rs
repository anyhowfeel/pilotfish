//! For every capture and every filter of the corpus, the frames the native filter selects must be
//! the frames `tshark -Y` selects. Skips when tshark is not installed.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use support::filters::CORPUS;
use wl_native::decode::{Decoded, Decoder};
use wl_native::filter::{self, Filter};
use wl_native::reader::open;

/// Wireshark shows the transport header of a fragmented datagram only on its last fragment, after
/// reassembly. The decoder reads it from the first one (see the limits in `decode`), so every
/// `udp`, `tcp` and port test disagrees on that capture by design.
const SKIPPED: &[(&str, &str)] = &[("fragments", "transport is reported on the last fragment")];

/// Frame numbers tshark selects; `None` when tshark is missing, `Err` text when it rejects the
/// filter.
fn tshark_frames(path: &Path, filter: &str) -> Option<Result<Vec<u64>, String>> {
    let out = Command::new("tshark")
        .arg("-r")
        .arg(path)
        .args(["-Y", filter, "-T", "fields", "-e", "frame.number"])
        .output()
        .ok()?;
    if !out.status.success() {
        return Some(Err(String::from_utf8_lossy(&out.stderr).trim().to_string()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(Ok(text
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()))
}

fn decode(path: &Path) -> Vec<Decoded> {
    let mut source = open(path).expect("open capture");
    let (mut decoder, mut data, mut out) = (Decoder::default(), Vec::new(), Vec::new());
    let mut first = None;
    while let Some(meta) = source.next_packet(&mut data).expect("read packet") {
        let first = *first.get_or_insert(meta.epoch);
        out.push(decoder.decode(&meta, &data, first));
    }
    out
}

fn first_difference(got: &[u64], want: &[u64]) -> Option<u64> {
    let missing = want.iter().find(|n| !got.contains(n));
    got.iter().find(|n| !want.contains(n)).or(missing).copied()
}

/// Frames selected per filter and the mismatches, for one capture; `None` without tshark.
fn check(name: &str, path: &Path, filters: &[(&str, Filter)]) -> Option<(Vec<usize>, Vec<String>)> {
    let packets = decode(path);
    let (mut counts, mut failures) = (Vec::new(), Vec::new());
    for (text, native) in filters {
        let want =
            tshark_frames(path, text)?.unwrap_or_else(|e| panic!("tshark rejects {text}: {e}"));
        let got: Vec<u64> = packets
            .iter()
            .filter(|d| native.matches(d))
            .map(|d| d.row.no)
            .collect();
        counts.push(want.len());
        if got != want {
            failures.push(format!(
                "{name}: {text}: native {} frames, tshark {}; first difference {:?}",
                got.len(),
                want.len(),
                first_difference(&got, &want)
            ));
        }
    }
    Some((counts, failures))
}

fn captures(dir: &Path) -> Vec<(String, PathBuf)> {
    let files = support::fixtures::fixtures().into_iter().map(|p| {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        (name, p)
    });
    let mut cases = support::synthetic::all();
    cases.extend(support::filter_cases::all());
    let synthetic = support::write_cases(dir, cases)
        .into_iter()
        .filter(|(name, _)| !SKIPPED.iter().any(|(s, _)| s == name))
        .map(|(name, p)| (format!("synthetic:{name}"), p));
    files.chain(synthetic).collect()
}

#[test]
fn native_filters_select_the_frames_tshark_selects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let captures = captures(dir.path());
    let filters: Vec<(&str, Filter)> = CORPUS
        .iter()
        .map(|f| {
            (
                *f,
                filter::parse(f).unwrap_or_else(|| panic!("not in the subset: {f}")),
            )
        })
        .collect();
    let results: Vec<_> = thread::scope(|s| {
        let jobs: Vec<_> = captures
            .iter()
            .map(|(name, path)| {
                let filters = &filters;
                s.spawn(move || check(name, path, filters))
            })
            .collect();
        jobs.into_iter()
            .map(|j| j.join().expect("worker"))
            .collect()
    });
    let Some(results) = results.into_iter().collect::<Option<Vec<_>>>() else {
        eprintln!("tshark not available, skipping the differential test");
        return;
    };
    for (i, (text, _)) in filters.iter().enumerate() {
        let total: usize = results.iter().map(|(counts, _)| counts[i]).sum();
        let agreeing = results
            .iter()
            .filter(|(_, f)| !f.iter().any(|m| m.contains(&format!(": {text}: "))))
            .count();
        eprintln!(
            "{total:>6} frames, {agreeing}/{} captures agree: {text}",
            captures.len()
        );
    }
    let failures: Vec<&String> = results.iter().flat_map(|(_, f)| f).collect();
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
