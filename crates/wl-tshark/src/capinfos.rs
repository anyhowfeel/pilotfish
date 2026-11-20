//! Capture file properties via `capinfos -M` (machine readable) and the lazy SHA256.

use std::path::{Path, PathBuf};

use wl_model::{CaptureError, CaptureProperties, InterfaceInfo};

use crate::error::from_stderr;
use crate::process::{self, Tools, find_in_path};

/// Everything except the file hashes (those read the whole file; see `sha256`).
const INFO_FLAGS: &[&str] = &[
    "-M", "-t", "-E", "-F", "-I", "-k", "-c", "-s", "-d", "-u", "-a", "-e", "-o", "-y", "-i", "-z",
    "-x",
];

fn capinfos_path(tools: &Tools) -> Result<PathBuf, CaptureError> {
    let beside = tools.tshark.with_file_name("capinfos");
    if beside.is_file() {
        return Ok(beside);
    }
    find_in_path("capinfos").ok_or_else(|| CaptureError::ToolMissing("capinfos".into()))
}

fn capinfos(tools: &Tools, flags: &[&str], file: &Path) -> Result<String, CaptureError> {
    let mut args: Vec<String> = flags.iter().map(|f| (*f).to_owned()).collect();
    args.push(file.to_string_lossy().into_owned());
    let out = process::run(&capinfos_path(tools)?, &args)?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn properties(tools: &Tools, file: &Path) -> Result<CaptureProperties, CaptureError> {
    Ok(parse_properties(&capinfos(tools, INFO_FLAGS, file)?))
}

/// SHA256 as lowercase hex (`capinfos -M -H`).
pub fn sha256(tools: &Tools, file: &Path) -> Result<String, CaptureError> {
    let text = capinfos(tools, &["-M", "-H"], file)?;
    text.lines()
        .find_map(|l| l.strip_prefix("SHA256:"))
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| CaptureError::Other("capinfos printed no SHA256".into()))
}

fn number(v: &str) -> f64 {
    v.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0.0)
}

/// Parses the long `capinfos -M` report (`Key:   value` lines plus `Interface #n info:` blocks).
pub fn parse_properties(text: &str) -> CaptureProperties {
    let mut p = CaptureProperties::default();
    for line in text.lines() {
        if line.starts_with("Interface #") {
            p.interfaces.push(InterfaceInfo::default());
        } else if line.starts_with(' ') {
            if let (Some(i), Some((k, v))) = (p.interfaces.last_mut(), line.split_once('=')) {
                interface_field(i, k.trim(), v.trim());
            }
        } else if let Some((key, value)) = line.split_once(':') {
            file_field(&mut p, key.trim(), value.trim());
        }
    }
    p
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

fn file_field(p: &mut CaptureProperties, key: &str, v: &str) {
    match key {
        "File name" => p.file_name = v.to_owned(),
        "File type" => p.file_type = v.to_owned(),
        "File encapsulation" => p.encapsulation = v.to_owned(),
        "File size" => p.file_size = number(v) as u64,
        "Data size" => p.data_size = number(v) as u64,
        "Number of packets" => p.packets = number(v) as u64,
        "Capture duration" => p.duration = number(v),
        "Earliest packet time" => p.first_packet = v.to_owned(),
        "Latest packet time" => p.last_packet = v.to_owned(),
        "Data byte rate" => p.bytes_per_sec = number(v),
        "Data bit rate" => p.bits_per_sec = number(v),
        "Average packet size" => p.avg_packet_size = number(v),
        "Average packet rate" => p.avg_packets_per_sec = number(v),
        "Strict time order" => p.strict_order = Some(v.eq_ignore_ascii_case("true")),
        "Capture application" => p.application = v.to_owned(),
        "Capture hardware" => p.hardware = v.to_owned(),
        "Capture oper-sys" => p.os = v.to_owned(),
        k if k.starts_with("Capture comment") && !v.is_empty() => p.comments.push(v.to_owned()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "File name:           a.pcapng\nFile type:           pcapng\n\
File encapsulation:  ether\nNumber of packets:   369\nFile size:           1300936 bytes\n\
Capture duration:    3.409684 seconds\nEarliest packet time: 2019-03-05 21:35:16.156341\n\
Data bit rate:       3022797.47 bits/sec\nStrict time order:   True\n\
Capture comment:     hello: world\nCapture comment 2:   second\nNumber of interfaces in file: 1\n\
Interface #0 info:\n\
\x20   Name = lo\n\x20   Encapsulation = Ethernet (1 - ether)\n\
\x20   Filter string = tcp port 80\n\x20   Number of packets = 369\n";

    #[test]
    fn parses_summary_comments_and_interfaces() {
        let p = parse_properties(SAMPLE);
        assert_eq!((p.packets, p.file_size), (369, 1_300_936));
        assert_eq!(p.file_type, "pcapng");
        assert!((p.duration - 3.409684).abs() < 1e-9);
        assert_eq!(p.first_packet, "2019-03-05 21:35:16.156341");
        assert_eq!(p.strict_order, Some(true));
        assert_eq!(p.comments, vec!["hello: world", "second"]);
        assert_eq!(p.interfaces.len(), 1);
        let i = &p.interfaces[0];
        assert_eq!((i.name.as_str(), i.filter.as_str()), ("lo", "tcp port 80"));
        assert_eq!(i.packets, "369");
    }

    #[test]
    fn missing_values_default() {
        let p = parse_properties("Capture duration:    n/a\n");
        assert_eq!(p.duration, 0.0);
        assert!(p.interfaces.is_empty());
    }
}
