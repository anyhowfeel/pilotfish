//! Compares the layer summaries of the no-Wireshark detail pane with the top-level lines of
//! `tshark -V`: the first 50 frames of every fixture and every frame of the synthetic captures.
//! Each layer the decoder produces must appear, in order, among tshark's top-level lines, and
//! the raw bytes must equal the captured ones. Layers only tshark dissects (DNS, HTTP, TLS) are
//! not compared. Skips when tshark is not installed.

mod support;

use std::path::Path;

use support::verbose::{self, normalise};
use wl_model::FrameDetail;
use wl_native::decode::detail::basic;

const FIXTURE_FRAMES: u32 = 50;

/// Deliberate differences: `(our line starts with, tshark's line starts with, why)`.
const ALLOWED: &[(&str, &str, &str)] = &[(
    "Internet Protocol Version 6, Src: ::1:2,",
    "Internet Protocol Version 6, Src: ::0.1.0.2,",
    "Wireshark prints an address below ::/96 as a dotted quad; rows use the standard form",
)];

/// Our layer lines. The decoder nests each 802.1Q tag under the Ethernet node, where Wireshark
/// lists it as a layer of its own.
fn layer_lines(d: &FrameDetail) -> Vec<String> {
    let mut out = Vec::new();
    for layer in &d.layers {
        out.push(normalise(&layer.label));
        let tags = layer
            .children
            .iter()
            .filter(|c| c.label.starts_with("802.1Q"));
        out.extend(tags.map(|c| c.label.clone()));
    }
    out
}

fn allowed(ours: &str, theirs: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(o, t, _)| ours.starts_with(o) && theirs.starts_with(t))
}

/// Each of `ours` must appear in `theirs` after the one before it.
fn first_missing<'a>(ours: &'a [String], theirs: &[String]) -> Option<&'a str> {
    let mut at = 0;
    for line in ours {
        match theirs[at..]
            .iter()
            .position(|t| t == line || allowed(line, t))
        {
            Some(found) => at += found + 1,
            None => return Some(line),
        }
    }
    None
}

/// Returns `(frames compared, failures)`; `Err(())` when tshark is missing.
fn check(name: &str, path: &Path, limit: Option<u32>) -> Result<(usize, Vec<String>), ()> {
    let reference = verbose::run(path, limit).ok_or(())?;
    let cap = support::read(path);
    let mut failures = Vec::new();
    let mut compared = 0;
    for (meta, bytes) in cap.iter().take(limit.map_or(usize::MAX, |n| n as usize)) {
        let detail = match basic(path, meta.no) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("{name} #{}: {e}", meta.no));
                continue;
            }
        };
        compared += 1;
        if &detail.bytes != bytes {
            failures.push(format!("{name} #{}: bytes differ", meta.no));
        }
        let Some(theirs) = reference.get(&meta.no) else {
            failures.push(format!("{name} #{}: tshark has no such frame", meta.no));
            continue;
        };
        let ours = layer_lines(&detail);
        if let Some(line) = first_missing(&ours, theirs) {
            failures.push(format!("{name} #{}: \"{line}\" not in {theirs:?}", meta.no));
        }
    }
    Ok((compared, failures))
}

fn finish(failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_all(cases: Vec<(String, std::path::PathBuf)>, limit: Option<u32>) {
    let mut failures = Vec::new();
    for (name, path) in cases {
        match check(&name, &path, limit) {
            Ok((n, f)) => {
                eprintln!("{name}: {n} frames, {} mismatches", f.len());
                failures.extend(f);
            }
            Err(()) => {
                eprintln!("tshark not available, skipping the differential test");
                return;
            }
        }
    }
    finish(failures);
}

#[test]
fn fixture_frames_match_tshark() {
    let cases = support::fixtures::fixtures()
        .into_iter()
        .map(|p| {
            (
                p.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into()),
                p,
            )
        })
        .collect();
    run_all(cases, Some(FIXTURE_FRAMES));
}

#[test]
fn synthetic_frames_match_tshark() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases = support::write_cases(dir.path(), support::synthetic::all())
        .into_iter()
        .map(|(n, p)| (format!("synthetic:{n}"), p))
        .collect();
    run_all(cases, None);
}
