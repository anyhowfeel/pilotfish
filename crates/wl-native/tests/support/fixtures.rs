//! The fixture captures of the repository and the check for an installed tool.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Every `.pcap` and `.pcapng` file in `tests/fixtures`, sorted by name.
pub fn fixtures() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("fixtures dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("pcap" | "pcapng")
            )
        })
        .collect();
    v.sort();
    v
}

/// Whether `tool` starts, so a test can skip quietly on a machine without Wireshark.
pub fn installed(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
