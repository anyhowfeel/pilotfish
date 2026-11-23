//! Decodes every fixture capture, and a set of hand-built ones, with the native decoder and
//! compares the rows with tshark's, packet by packet. Skips when tshark is not installed.
//!
//! Compared for every frame: epoch, source and destination (text and address), ports, frame
//! length, stream number and transport. The protocol is compared when tshark names one the
//! decoder can produce, and Info for ARP, ICMP, ICMPv6, TCP, UDP and DNS rows after removing
//! the analysis marks that need other packets (see `reference::strip_analysis`).

mod support;

use std::path::Path;

use support::compare::{ALLOWED, compare};
use support::reference;

/// Compares one capture file; `Err(())` when tshark is missing.
fn check(name: &str, path: &Path, failures: &mut Vec<String>) -> Result<(), ()> {
    let reference = reference::run(path).ok_or(())?;
    let cap = support::read(path);
    let counts = compare(name, &cap, &reference, ALLOWED);
    eprintln!("{}", counts.summary(name));
    if cap.len() != reference.len() {
        failures.push(format!(
            "{name}: {} packets read, tshark has {}",
            cap.len(),
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
fn fixtures_match_tshark() {
    let mut failures = Vec::new();
    for path in support::fixtures::fixtures() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
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
    for (name, path) in support::write_cases(dir.path(), support::synthetic::all()) {
        if check(&format!("synthetic:{name}"), &path, &mut failures).is_err() {
            eprintln!("tshark not available, skipping the differential test");
            return;
        }
    }
    finish(failures);
}
