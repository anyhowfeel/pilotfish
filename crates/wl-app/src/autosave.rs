//! Where a live capture is kept when the user did not type a path: a file in the saved captures folder.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use wl_model::CaptureOptions;

/// The folder of the saved captures when the settings do not name one.
pub fn default_dir() -> PathBuf {
    dirs::document_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pilotfish")
        .join("captures")
}

/// The folder named in the settings (`~/` stands for the home folder), or the default one.
fn folder(setting: &str) -> PathBuf {
    let s = setting.trim();
    if s.is_empty() {
        return default_dir();
    }
    match (s.strip_prefix("~/"), dirs::home_dir()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(s),
    }
}

/// The part of the file name that tells where the packets came from: letters, digits, `-`, `_`, `.`.
fn source_label(o: &CaptureOptions) -> String {
    let raw = o.interfaces.first().cloned().unwrap_or_else(|| o.label());
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches('_').chars().take(24).collect::<String>();
    if clean.is_empty() {
        "capture".into()
    } else {
        clean
    }
}

/// The path to keep this capture at, or `None` when it keeps the one the user typed or is not saved.
/// A ring buffer always keeps its files, so it gets a path even when automatic saving is off.
pub fn plan(
    o: &CaptureOptions,
    autosave: bool,
    dir_setting: &str,
    now: DateTime<Local>,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if !o.save_to.trim().is_empty() || !(autosave || o.ring.enabled) {
        return None;
    }
    let base = format!(
        "capture-{}-{}",
        now.format("%Y%m%d-%H%M%S"),
        source_label(o)
    );
    let dir = folder(dir_setting);
    let mut path = dir.join(format!("{base}.pcapng"));
    let mut n = 2;
    while exists(&path) {
        path = dir.join(format!("{base}-{n}.pcapng"));
        n += 1;
    }
    Some(path)
}

#[cfg(test)]
#[path = "autosave_tests.rs"]
mod tests;
