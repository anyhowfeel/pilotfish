//! Recent-files model: dedupe by canonical path, drop missing files, pinned first.
//! File-system access is injected (`Stat`) so the logic is testable without touching disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub canonical: PathBuf,
    pub size: u64,
    /// Seconds since the Unix epoch.
    pub modified: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentEntry {
    pub path: PathBuf,
    pub name: String,
    pub dir: String,
    pub size: u64,
    pub modified: Option<u64>,
    pub packets: Option<u64>,
    pub pinned: bool,
}

pub type Stat<'a> = &'a dyn Fn(&Path) -> Option<Meta>;

/// Real file system lookup: `None` when the path is missing or not a regular file.
pub fn stat_fs(p: &Path) -> Option<Meta> {
    let canonical = std::fs::canonicalize(p).ok()?;
    let md = std::fs::metadata(&canonical).ok().filter(|m| m.is_file())?;
    let modified = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    Some(Meta {
        canonical,
        size: md.len(),
        modified,
    })
}

/// Pinned files first (pin order), then the rest of `recent`; each file once.
pub fn resolve(
    recent: &[PathBuf],
    pinned: &[PathBuf],
    counts: &HashMap<PathBuf, u64>,
    stat: Stat<'_>,
) -> Vec<RecentEntry> {
    let pin_set: Vec<PathBuf> = pinned
        .iter()
        .filter_map(|p| stat(p).map(|m| m.canonical))
        .collect();
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut out = Vec::new();
    let all = pinned.iter().chain(recent);
    for p in all {
        let Some(m) = stat(p) else { continue };
        if seen.contains(&m.canonical) {
            continue;
        }
        seen.push(m.canonical.clone());
        let (name, dir) = crate::overview::setup_logic::split_path(&m.canonical);
        out.push(RecentEntry {
            packets: counts.get(&m.canonical).copied(),
            pinned: pin_set.contains(&m.canonical),
            path: m.canonical,
            name,
            dir,
            size: m.size,
            modified: m.modified,
        });
    }
    // Stable: pinned (already first in iteration order) stay ahead of the rest.
    out.sort_by_key(|e| !e.pinned);
    out
}

/// `YYYY-MM-DD` (UTC) of a Unix timestamp.
pub fn format_date(secs: u64) -> String {
    let (y, m, d) = civil(secs / 86_400);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD HH:MM UTC`.
pub fn format_datetime(secs: u64) -> String {
    let rem = secs % 86_400;
    format!(
        "{} {:02}:{:02} UTC",
        format_date(secs),
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Days since 1970-01-01 -> (year, month, day), proleptic Gregorian.
fn civil(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(p: &Path) -> Option<Meta> {
        let s = p.to_string_lossy();
        if s.contains("gone") {
            return None;
        }
        // "rel/a.pcap" and "/abs/a.pcap" are the same file.
        let name = s.rsplit('/').next().unwrap_or_default();
        Some(Meta {
            canonical: PathBuf::from(format!("/abs/{name}")),
            size: 1500,
            modified: Some(1_700_000_000),
        })
    }

    #[test]
    fn dedupes_by_canonical_drops_missing_and_pins_first() {
        let recent: Vec<PathBuf> = ["rel/a.pcap", "/abs/a.pcap", "/x/gone.pcap", "/y/b.pcap"]
            .map(PathBuf::from)
            .to_vec();
        let pinned = vec![PathBuf::from("/q/b.pcap")];
        let counts = HashMap::from([(PathBuf::from("/abs/a.pcap"), 42)]);
        let v = resolve(&recent, &pinned, &counts, &fake);
        let names: Vec<_> = v.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["b.pcap", "a.pcap"]);
        assert!(v[0].pinned && !v[1].pinned);
        assert_eq!((v[1].packets, v[0].packets), (Some(42), None));
        assert_eq!(v[1].dir, "/abs");
    }

    #[test]
    fn formats_dates_in_utc() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(1_700_000_000), "2023-11-14");
        assert_eq!(format_datetime(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(format_date(951_782_400), "2000-02-29");
    }

    #[test]
    fn real_stat_rejects_directories_and_missing() {
        assert!(stat_fs(Path::new("/definitely/not/here")).is_none());
        assert!(stat_fs(Path::new("/tmp")).is_none());
    }
}
