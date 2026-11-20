//! Detected tshark / dumpcap location + version for the About page (probed once, off-thread).
use std::path::PathBuf;
use std::sync::OnceLock;

static INFO: OnceLock<(String, String)> = OnceLock::new();

fn find(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn describe(name: &str) -> String {
    let Some(path) = find(name) else {
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
pub fn warm() {
    std::thread::spawn(|| {
        let _ = INFO.set((describe("tshark"), describe("dumpcap")));
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
            super::describe("definitely-not-a-real-tool-xyz"),
            "not found"
        );
    }
}
