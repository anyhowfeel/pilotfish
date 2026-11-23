//! Detected tshark / dumpcap location + version for the About page (probed once, off-thread).
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static INFO: OnceLock<(String, String)> = OnceLock::new();

fn describe(dir: Option<&Path>, name: &str) -> String {
    let Some(path) = wl_tshark::find_tool(dir, name) else {
        return "not found".into();
    };
    let ver = std::process::Command::new(&path)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(str::to_owned))
        .unwrap_or_default();
    format!("{ver}  {}", path.display()).trim().to_owned()
}

/// Starts the probe in the background (idempotent).
pub fn warm(dir: Option<PathBuf>) {
    std::thread::spawn(move || {
        let dir = dir.as_deref();
        let _ = INFO.set((describe(dir, "tshark"), describe(dir, "dumpcap")));
    });
}

/// `(tshark, dumpcap)` descriptions; placeholders until the probe finishes.
pub fn get() -> (String, String) {
    INFO.get()
        .cloned()
        .unwrap_or_else(|| ("detecting...".into(), "detecting...".into()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_tool_is_reported() {
        assert_eq!(
            super::describe(None, "definitely-not-a-real-tool-xyz"),
            "not found"
        );
    }
}
