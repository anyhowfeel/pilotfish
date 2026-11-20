//! Expert Info extraction via `tshark -r <file> -q -z expert`.

use std::path::Path;

use wl_model::{CaptureError, ExpertEntry, ExpertReport, ExpertSeverity};

use crate::error::from_stderr;
use crate::process::{self, Tools};

/// Runs `tshark -r <file> -q -z expert` (with optional display filter) and parses all rows.
pub fn expert_info(
    tools: &Tools,
    file: &Path,
    display_filter: Option<&str>,
) -> Result<ExpertReport, CaptureError> {
    let spec = match display_filter.map(str::trim).filter(|s| !s.is_empty()) {
        Some(f) => format!("expert,chat,{f}"),
        None => "expert".to_owned(),
    };
    let out = process::run(
        &tools.tshark,
        ["-r", &file.to_string_lossy(), "-q", "-z", &spec],
    )?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    Ok(parse_expert(&String::from_utf8_lossy(&out.stdout)))
}

fn section_severity(line: &str) -> Option<ExpertSeverity> {
    let t = line.trim();
    if t.starts_with("Errors (") {
        Some(ExpertSeverity::Error)
    } else if t.starts_with("Warns (") {
        Some(ExpertSeverity::Warn)
    } else if t.starts_with("Notes (") {
        Some(ExpertSeverity::Note)
    } else if t.starts_with("Chats (") {
        Some(ExpertSeverity::Chat)
    } else {
        None
    }
}

fn parse_row(severity: ExpertSeverity, line: &str) -> Option<ExpertEntry> {
    let s = line.trim();
    let (freq_tok, rest) = split_first_ws(s)?;
    let frequency = freq_tok.parse::<u64>().ok()?;
    let (group, rest) = split_first_ws(rest.trim_start())?;
    let (protocol, summary) = split_first_ws(rest.trim_start())?;
    Some(ExpertEntry {
        severity,
        frequency,
        group: group.to_owned(),
        protocol: protocol.to_owned(),
        summary: summary.trim().to_owned(),
    })
}

fn split_first_ws(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(char::is_whitespace)?;
    Some((&s[..idx], &s[idx..]))
}

/// Parses raw stdout of `tshark -q -z expert`.
pub fn parse_expert(raw: &str) -> ExpertReport {
    let mut current: Option<ExpertSeverity> = None;
    let mut entries = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("====") || trimmed.starts_with("Frequency") {
            continue;
        }
        if let Some(sev) = section_severity(trimmed) {
            current = Some(sev);
            continue;
        }
        if let Some(sev) = current
            && let Some(entry) = parse_row(sev, line)
        {
            entries.push(entry);
        }
    }
    ExpertReport { entries }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\n\
Errors (2)\n\
=============\n\
   Frequency      Group           Protocol  Summary\n\
           2  Malformed               HTTP  Malformed Packet\n\
\n\
Warns (9)\n\
=============\n\
   Frequency      Group           Protocol  Summary\n\
           9   Protocol               mDNS  DNS query retransmission. Original request in frame 278\n\
\n\
Notes (32)\n\
=============\n\
   Frequency      Group           Protocol  Summary\n\
          12   Sequence                TCP  This frame initiates the connection closing\n\
          20   Response             ICMPv6  Type indicates an error\n\
\n\
Chats (12)\n\
=============\n\
   Frequency      Group           Protocol  Summary\n\
          12   Sequence                TCP  Connection establish request (SYN): server port 18080\n";

    #[test]
    fn parses_all_severities() {
        let rep = parse_expert(SAMPLE);
        assert_eq!(rep.entries.len(), 5);
        assert_eq!(rep.count_by_severity(ExpertSeverity::Error), 2);
        assert_eq!(rep.count_by_severity(ExpertSeverity::Warn), 9);
        assert_eq!(rep.count_by_severity(ExpertSeverity::Note), 32);
        assert_eq!(rep.count_by_severity(ExpertSeverity::Chat), 12);
        assert_eq!(rep.entries[0].protocol, "HTTP");
        assert_eq!(rep.entries[0].summary, "Malformed Packet");
        assert_eq!(rep.entries[1].protocol, "mDNS");
        assert!(rep.entries[1].summary.contains("retransmission"));
    }

    #[test]
    fn empty_input_yields_empty_report() {
        let rep = parse_expert("");
        assert!(rep.entries.is_empty());
        assert_eq!(rep.total_events(), 0);
    }
}
