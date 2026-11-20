//! Pure helpers of the capture-setup page.

pub const PRESETS: [(&str, &str); 6] = [
    ("Web", "port 80 or port 443"),
    ("DNS", "port 53"),
    ("Not SSH", "not port 22"),
    ("TCP only", "tcp"),
    ("UDP only", "udp"),
    ("ICMP", "icmp"),
];

/// Trimmed capture filter, `None` when blank.
pub fn normalize_filter(raw: &str) -> Option<String> {
    let t = raw.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Clicking an active preset clears it, any other replaces the filter.
pub fn apply_preset(current: &str, preset: &str) -> String {
    if current.trim() == preset {
        String::new()
    } else {
        preset.to_string()
    }
}

/// File name and parent directory for a recent-files row.
pub fn split_path(p: &std::path::Path) -> (String, String) {
    let name = p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let dir = p
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    (name, dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_toggle_and_filter_normalizes() {
        assert_eq!(apply_preset("", "tcp"), "tcp");
        assert_eq!(apply_preset("tcp", "tcp"), "");
        assert_eq!(normalize_filter("  port 80 "), Some("port 80".into()));
        assert_eq!(normalize_filter("   "), None);
    }

    #[test]
    fn splits_path() {
        let (n, d) = split_path(std::path::Path::new("/a/b/c.pcapng"));
        assert_eq!((n.as_str(), d.as_str()), ("c.pcapng", "/a/b"));
    }
}
