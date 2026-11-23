//! Resident memory of a process from `/proc`, in KiB. Everything is `None` or a no-op where
//! `/proc` is missing, so callers skip rather than fail.

use std::fs;

fn status_kb(pid: &str, key: &str) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = text.lines().find_map(|l| l.strip_prefix(key))?;
    line.trim_start_matches(':')
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Peak resident size (`VmHWM`) of this process.
pub fn peak_kb() -> Option<u64> {
    status_kb("self", "VmHWM")
}

/// Current resident size (`VmRSS`) of this process.
pub fn resident_kb() -> Option<u64> {
    status_kb("self", "VmRSS")
}

/// Makes `peak_kb` start again from the current resident size, so one process can measure
/// several runs one after the other.
pub fn reset_peak() -> bool {
    fs::write("/proc/self/clear_refs", "5").is_ok()
}

/// Peak resident size of the direct child process named `name`, if one is running.
pub fn child_peak_kb(name: &str) -> Option<u64> {
    let me = std::process::id().to_string();
    fs::read_dir("/proc")
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|pid| pid.bytes().all(|b| b.is_ascii_digit()))
        .filter(|pid| {
            let text = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).map(str::trim);
            field("Name:") == Some(name) && field("PPid:") == Some(me.as_str())
        })
        .filter_map(|pid| status_kb(&pid, "VmHWM"))
        .max()
}
