//! The top-level lines of tshark's `-V` output, one list per frame.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Runs tshark over the first `limit` frames of `path` (all when `None`) with raw sequence
/// numbers and no name resolution; `None` when tshark is missing or fails.
pub fn run(path: &Path, limit: Option<u32>) -> Option<HashMap<u64, Vec<String>>> {
    let mut cmd = Command::new("tshark");
    cmd.arg("-r").arg(path);
    cmd.args(["-n", "-V", "-o", "tcp.relative_sequence_numbers:FALSE"]);
    if let Some(n) = limit {
        cmd.args(["-c", &n.to_string()]);
    }
    let out = cmd.output().ok().filter(|o| o.status.success())?;
    let mut frames: HashMap<u64, Vec<String>> = HashMap::new();
    let mut current = None;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.is_empty() || line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(no) = line
            .strip_prefix("Frame ")
            .and_then(|r| r.split(':').next())
            .and_then(|n| n.parse::<u64>().ok())
        {
            current = Some(no);
        }
        if let Some(no) = current {
            frames.entry(no).or_default().push(normalise(line));
        }
    }
    Some(frames)
}

/// Removes what depends on the Wireshark version, the capture format or resolution settings: the
/// "Packet, " that 4.6 added to the Frame line, the interface a pcapng frame names and the
/// `(aa:bb:...)` echo after a MAC address.
pub fn normalise(line: &str) -> String {
    let mut s = line.replacen(": Packet, ", ": ", 1);
    if line.starts_with("Frame ")
        && let Some(at) = s.find(" on interface ")
    {
        s.truncate(at);
    }
    while let Some(at) = s.find(" (") {
        let Some(end) = s[at..].find(')') else { break };
        let inner = &s[at + 2..at + end];
        let mac = inner.len() == 17 && inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
        if !mac {
            break;
        }
        s.replace_range(at..at + end + 1, "");
    }
    s
}
