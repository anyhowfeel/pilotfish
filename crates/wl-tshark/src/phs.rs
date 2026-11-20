//! Protocol Hierarchy Statistics via `tshark -r <file> -q -z io,phs`.

use std::path::Path;

use wl_model::{CaptureError, ProtocolHierarchy, ProtocolHierarchyNode};

use crate::error::from_stderr;
use crate::process::{self, Tools};

/// Runs `tshark -r <file> -q -z io,phs[,<filter>]` and parses the protocol tree.
pub fn protocol_hierarchy(
    tools: &Tools,
    file: &Path,
    display_filter: Option<&str>,
) -> Result<ProtocolHierarchy, CaptureError> {
    let spec = match display_filter.map(str::trim).filter(|s| !s.is_empty()) {
        Some(f) => format!("io,phs,{f}"),
        None => "io,phs".to_owned(),
    };
    let out = process::run(
        &tools.tshark,
        ["-r", &file.to_string_lossy(), "-q", "-z", &spec],
    )?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    Ok(parse_phs(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_node_line(line: &str) -> Option<(String, u16, u64, u64)> {
    let leading = line.bytes().take_while(|&b| b == b' ').count();
    let trimmed = line[leading..].trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let protocol = parts.next()?.to_owned();
    let mut frames = None;
    let mut bytes = None;
    for tok in parts {
        if let Some(v) = tok.strip_prefix("frames:") {
            frames = v.parse::<u64>().ok();
        } else if let Some(v) = tok.strip_prefix("bytes:") {
            bytes = v.parse::<u64>().ok();
        }
    }
    Some((protocol, (leading / 2) as u16, frames?, bytes?))
}

fn pct(part: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        ((part as f64 / total as f64) * 100.0).clamp(0.0, 100.0) as f32
    }
}

/// Parses raw stdout of `tshark -q -z io,phs`.
pub fn parse_phs(raw: &str) -> ProtocolHierarchy {
    let mut filter = String::new();
    let mut parsed = Vec::new();
    for line in raw.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("====") || t == "Protocol Hierarchy Statistics" {
            continue;
        }
        if let Some(rest) = t.strip_prefix("Filter:") {
            filter = rest.trim().to_owned();
            continue;
        }
        if let Some(row) = parse_node_line(line) {
            parsed.push(row);
        }
    }
    let total_frames = parsed
        .iter()
        .filter(|r| r.1 == 0)
        .map(|r| r.2)
        .sum::<u64>()
        .max(parsed.first().map_or(0, |r| r.2));
    let total_bytes = parsed
        .iter()
        .filter(|r| r.1 == 0)
        .map(|r| r.3)
        .sum::<u64>()
        .max(parsed.first().map_or(0, |r| r.3));

    let nodes = parsed
        .into_iter()
        .map(|(protocol, depth, frames, bytes)| ProtocolHierarchyNode {
            protocol,
            depth,
            frames,
            bytes,
            frame_pct: pct(frames, total_frames),
            byte_pct: pct(bytes, total_bytes),
        })
        .collect();

    ProtocolHierarchy {
        filter,
        total_frames,
        total_bytes,
        nodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
===================================================================
Protocol Hierarchy Statistics
Filter: tcp

frame                                    frames:159 bytes:229320
  eth                                    frames:159 bytes:229320
    ip                                   frames:159 bytes:229320
      tcp                                frames:159 bytes:229320
        http                             frames:24 bytes:21546
          data-text-lines                frames:12 bytes:19740
===================================================================
"#;

    #[test]
    fn parses_tree_depths_and_percentages() {
        let phs = parse_phs(SAMPLE);
        assert_eq!(phs.filter, "tcp");
        assert_eq!(phs.total_frames, 159);
        assert_eq!(phs.total_bytes, 229_320);
        assert_eq!(phs.nodes.len(), 6);
        assert_eq!(phs.nodes[0].protocol, "frame");
        assert_eq!(phs.nodes[0].depth, 0);
        assert!((phs.nodes[0].frame_pct - 100.0).abs() < 0.01);
        assert_eq!(phs.nodes[4].protocol, "http");
        assert_eq!(phs.nodes[4].depth, 4);
        assert!((phs.nodes[4].frame_pct - 15.09).abs() < 0.2);
        assert_eq!(phs.nodes[5].depth, 5);
    }

    #[test]
    fn empty_phs_is_safe() {
        let phs = parse_phs("");
        assert_eq!(phs.total_frames, 0);
        assert!(phs.nodes.is_empty());
    }
}
