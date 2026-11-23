//! Reads every fixture capture and a set of hand-built ones with `properties::read` and compares
//! every field with what `capinfos -M` prints for the same file. Skips when capinfos is missing.
//!
//! Each capture is compared in both zones. For UTC `capinfos` runs with `TZ=UTC`; for the local
//! zone it keeps the machine's, which is also what the native reader uses, so the local
//! comparison only says something on a machine whose zone is not UTC.

mod support;

use std::path::Path;
use std::process::Command;

use support::{edge_cases, fixtures};
use wl_model::{CaptureProperties, ClockZone, InterfaceInfo};
use wl_native::NativeBackend;

/// The flags `wl-tshark` passes, so both backends answer the same question.
const FLAGS: &[&str] = &[
    "-M", "-t", "-E", "-F", "-I", "-k", "-c", "-s", "-d", "-u", "-a", "-e", "-o", "-y", "-i", "-z",
    "-x",
];

/// `(capture, field, reason)` of a difference that is on purpose. Nothing is allowed today.
const ALLOWED: &[(&str, &str, &str)] = &[];

const ZONES: [ClockZone; 2] = [ClockZone::Utc, ClockZone::Local];

fn capinfos(path: &Path, zone: ClockZone) -> Option<String> {
    let mut command = Command::new("capinfos");
    command.args(FLAGS).arg(path);
    if zone == ClockZone::Utc {
        command.env("TZ", "UTC");
    }
    let out = command.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The leading number of a value such as `12.5 bytes/sec`; `n/a` and the like are 0.
fn number(v: &str) -> f64 {
    v.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0.0)
}

fn interface_field(i: &mut InterfaceInfo, key: &str, v: &str) {
    let slot = match key {
        "Name" => &mut i.name,
        "Description" => &mut i.description,
        "Encapsulation" => &mut i.encapsulation,
        "Capture length" => &mut i.capture_length,
        "Filter string" => &mut i.filter,
        "Number of packets" => &mut i.packets,
        _ => return,
    };
    *slot = v.to_owned();
}

/// What `capinfos` says, in the shape the native reader fills.
fn parse(text: &str) -> CaptureProperties {
    let mut p = CaptureProperties::default();
    for line in text.lines() {
        if line.starts_with("Interface #") {
            p.interfaces.push(InterfaceInfo::default());
        } else if line.starts_with(' ') {
            if let (Some(i), Some((k, v))) = (p.interfaces.last_mut(), line.split_once('=')) {
                interface_field(i, k.trim(), v.trim());
            }
        } else if let Some((key, v)) = line.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
            match key {
                "File name" => p.file_name = v.into(),
                "File type" => p.file_type = v.into(),
                "File encapsulation" => p.encapsulation = v.into(),
                "File size" => p.file_size = number(v) as u64,
                "Data size" => p.data_size = number(v) as u64,
                "Number of packets" => p.packets = number(v) as u64,
                "Capture duration" => p.duration = number(v),
                "Earliest packet time" => p.first_packet = v.into(),
                "Latest packet time" => p.last_packet = v.into(),
                "Data byte rate" => p.bytes_per_sec = number(v),
                "Data bit rate" => p.bits_per_sec = number(v),
                "Average packet size" => p.avg_packet_size = number(v),
                "Average packet rate" => p.avg_packets_per_sec = number(v),
                "Strict time order" => p.strict_order = Some(v.eq_ignore_ascii_case("true")),
                "Capture application" => p.application = v.into(),
                "Capture hardware" => p.hardware = v.into(),
                "Capture oper-sys" => p.os = v.into(),
                k if k.starts_with("Capture comment") => p.comments.push(v.into()),
                _ => {}
            }
        }
    }
    p
}

/// Fields whose values differ, as `field: ours / capinfos`.
fn differences(
    ours: &CaptureProperties,
    theirs: &CaptureProperties,
) -> Vec<(&'static str, String)> {
    let mut bad = Vec::new();
    let mut text = |field, a: &str, b: &str| {
        if a != b {
            bad.push((field, format!("{a:?} / {b:?}")));
        }
    };
    text("file_name", &ours.file_name, &theirs.file_name);
    text("file_type", &ours.file_type, &theirs.file_type);
    text("encapsulation", &ours.encapsulation, &theirs.encapsulation);
    text("first_packet", &ours.first_packet, &theirs.first_packet);
    text("last_packet", &ours.last_packet, &theirs.last_packet);
    text("application", &ours.application, &theirs.application);
    text("hardware", &ours.hardware, &theirs.hardware);
    text("os", &ours.os, &theirs.os);
    text(
        "comments",
        &ours.comments.join("|"),
        &theirs.comments.join("|"),
    );
    let mut whole = |field, a: u64, b: u64| {
        if a != b {
            bad.push((field, format!("{a} / {b}")));
        }
    };
    whole("file_size", ours.file_size, theirs.file_size);
    whole("data_size", ours.data_size, theirs.data_size);
    whole("packets", ours.packets, theirs.packets);
    // capinfos prints 6 decimals (9 for nanosecond files) for the duration and 2 for the rates.
    for (field, a, b, slack) in [
        ("duration", ours.duration, theirs.duration, 1e-6),
        (
            "bytes_per_sec",
            ours.bytes_per_sec,
            theirs.bytes_per_sec,
            0.011,
        ),
        (
            "bits_per_sec",
            ours.bits_per_sec,
            theirs.bits_per_sec,
            0.011,
        ),
        (
            "avg_packet_size",
            ours.avg_packet_size,
            theirs.avg_packet_size,
            0.011,
        ),
        (
            "avg_packets_per_sec",
            ours.avg_packets_per_sec,
            theirs.avg_packets_per_sec,
            0.011,
        ),
    ] {
        if (a - b).abs() > slack {
            bad.push((field, format!("{a} / {b}")));
        }
    }
    if ours.strict_order != theirs.strict_order {
        bad.push((
            "strict_order",
            format!("{:?} / {:?}", ours.strict_order, theirs.strict_order),
        ));
    }
    if ours.interfaces != theirs.interfaces {
        bad.push((
            "interfaces",
            format!("{:?} / {:?}", ours.interfaces, theirs.interfaces),
        ));
    }
    bad
}

/// `Err(())` when capinfos is missing.
fn check(name: &str, path: &Path, failures: &mut Vec<String>) -> Result<(), ()> {
    for zone in ZONES {
        check_in(&format!("{name} [{zone:?}]"), path, zone, failures)?;
    }
    Ok(())
}

fn check_in(
    name: &str,
    path: &Path,
    zone: ClockZone,
    failures: &mut Vec<String>,
) -> Result<(), ()> {
    let text = capinfos(path, zone).ok_or(())?;
    let theirs = parse(&text);
    let ours = NativeBackend::new()
        .capture_properties(path, zone)
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let bad = differences(&ours, &theirs);
    eprintln!(
        "{name}: {} packets, {} differences",
        ours.packets,
        bad.len()
    );
    for (field, what) in bad {
        let known = ALLOWED
            .iter()
            .any(|(n, f, _)| name.starts_with(*n) && *f == field);
        if !known {
            failures.push(format!("{name} {field}: {what}"));
        }
    }
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
fn fixtures_match_capinfos() {
    let mut failures = Vec::new();
    for path in fixtures::fixtures() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_owned();
        if check(&name, &path, &mut failures).is_err() {
            eprintln!("capinfos not available, skipping the differential test");
            return;
        }
    }
    finish(failures);
}

#[test]
fn synthetic_captures_match_capinfos() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut failures = Vec::new();
    for (file, bytes) in edge_cases::all() {
        let path = dir.path().join(file);
        std::fs::write(&path, bytes).expect("write");
        if check(&format!("synthetic:{file}"), &path, &mut failures).is_err() {
            eprintln!("capinfos not available, skipping the differential test");
            return;
        }
    }
    finish(failures);
}
