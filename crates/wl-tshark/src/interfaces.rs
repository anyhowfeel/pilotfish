//! `tshark -D` parsing and interface state.

use std::path::Path;

use wl_model::{CaptureError, Interface, SysInfo};

use crate::error::from_stderr;
use crate::netinfo;
use crate::process::{Tools, run};

/// Splits `3. eth0 (Some description)` into name and description.
fn parse_entry(line: &str) -> Option<(String, Option<String>)> {
    let (idx, rest) = line.split_once(". ")?;
    idx.trim().parse::<u32>().ok()?;
    let rest = rest.trim();
    match rest.split_once(" (") {
        Some((name, desc)) if rest.ends_with(')') => Some((
            name.to_string(),
            Some(desc.trim_end_matches(')').to_string()),
        )),
        _ => Some((rest.to_string(), None)),
    }
}

/// `oper_state` is the content of `/sys/class/net/<name>/operstate` when it exists.
pub fn parse_list(text: &str, oper_state: impl Fn(&str) -> Option<String>) -> Vec<Interface> {
    text.lines()
        .filter_map(parse_entry)
        .map(|(name, description)| {
            let loopback = name == "lo"
                || description
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case("loopback"));
            let is_up = match oper_state(&name) {
                // loopback reports "unknown" although it is usable
                Some(s) => s == "up" || s == "unknown",
                None => name == "any",
            };
            Interface {
                name,
                description,
                is_loopback: loopback,
                is_up,
                sys: SysInfo::default(),
            }
        })
        .collect()
}

fn sysfs_state(name: &str) -> Option<String> {
    if name.contains('/') {
        return None;
    }
    let p = Path::new("/sys/class/net").join(name).join("operstate");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn list(tools: &Tools) -> Result<Vec<Interface>, CaptureError> {
    let out = run(&tools.tshark, ["-D"])?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    let default = netinfo::default_route();
    let mut list = parse_list(&String::from_utf8_lossy(&out.stdout), sysfs_state);
    for i in &mut list {
        i.sys = netinfo::sys_info(&i.name, default.as_deref());
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str =
        "1. wlan0\n2. br-d8d (Bridge)\n3. any\n4. lo (Loopback)\n5. sshdump (SSH remote capture)\n";

    #[test]
    fn parses_names_and_descriptions() {
        let v = parse_list(SAMPLE, |n| match n {
            "wlan0" => Some("up".into()),
            "br-d8d" => Some("down".into()),
            "lo" => Some("unknown".into()),
            _ => None,
        });
        assert_eq!(v.len(), 5);
        assert_eq!(
            (v[0].name.as_str(), v[0].description.clone(), v[0].is_up),
            ("wlan0", None, true)
        );
        assert_eq!(v[1].description.as_deref(), Some("Bridge"));
        assert!(!v[1].is_up);
        assert!(v[2].is_up && !v[2].is_loopback);
        assert!(v[3].is_loopback && v[3].is_up);
        assert!(!v[4].is_up);
    }

    #[test]
    fn ignores_noise_lines() {
        assert!(parse_list("garbage\n\n", |_| None).is_empty());
    }
}
