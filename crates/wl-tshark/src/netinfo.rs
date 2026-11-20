//! sysfs / procfs probes for network devices: kind, link speed, default route, byte counters.
//! Everything is a plain file read (no root, no extra dependencies).

use std::path::Path;

use wl_model::SysInfo;

const SYS_NET: &str = "/sys/class/net";
const PROC_ROUTE: &str = "/proc/net/route";

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn safe(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && name != ".."
}

/// Interface carrying the default IPv4 route (lowest metric) from `/proc/net/route` text.
pub fn default_route_iface(table: &str) -> Option<String> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (iface, dest, flags, metric, mask) =
                (f.first()?, f.get(1)?, f.get(3)?, f.get(6)?, f.get(7)?);
            let up_gw = u32::from_str_radix(flags, 16).ok()? & 3 == 3;
            (up_gw && *dest == "00000000" && *mask == "00000000").then(|| {
                (
                    metric.parse::<u32>().unwrap_or(u32::MAX),
                    (*iface).to_string(),
                )
            })
        })
        .min()
        .map(|(_, i)| i)
}

/// Name of the default-route interface on this machine.
pub fn default_route() -> Option<String> {
    default_route_iface(&std::fs::read_to_string(PROC_ROUTE).ok()?)
}

/// `DEVTYPE=` value of a sysfs `uevent` file.
fn devtype(uevent: &str) -> String {
    uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVTYPE="))
        .unwrap_or_default()
        .to_string()
}

/// Probe `<root>/<name>`; `root` is `/sys/class/net` in production.
pub fn sys_info_at(root: &Path, name: &str, default_iface: Option<&str>) -> SysInfo {
    let dir = root.join(name);
    if !safe(name) || !dir.is_dir() {
        return SysInfo::default();
    }
    let num = |f: &str| read(&dir.join(f)).and_then(|s| s.parse::<i64>().ok());
    let devtype = read(&dir.join("uevent"))
        .map(|u| devtype(&u))
        .unwrap_or_default();
    SysInfo {
        present: true,
        wireless: dir.join("wireless").exists()
            || dir.join("phy80211").exists()
            || devtype == "wlan",
        physical: dir.join("device").exists(),
        devtype,
        arphrd: num("type").and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
        speed_mbps: num("speed")
            .and_then(|v| u32::try_from(v).ok())
            .filter(|&v| v > 0),
        default_route: default_iface == Some(name),
    }
}

pub fn sys_info(name: &str, default_iface: Option<&str>) -> SysInfo {
    sys_info_at(Path::new(SYS_NET), name, default_iface)
}

/// rx + tx bytes since boot from `<root>/<name>/statistics`.
pub fn byte_counters_at(root: &Path, name: &str) -> Option<u64> {
    if !safe(name) {
        return None;
    }
    let stat = |f: &str| {
        read(&root.join(name).join("statistics").join(f))?
            .parse::<u64>()
            .ok()
    };
    Some(stat("rx_bytes")?.saturating_add(stat("tx_bytes")?))
}

pub fn byte_counters(name: &str) -> Option<u64> {
    byte_counters_at(Path::new(SYS_NET), name)
}

/// Bytes per second between two counter samples (0 on wrap/reset or a zero interval).
pub fn rate(prev: u64, cur: u64, secs: f64) -> f64 {
    if secs <= 0.0 || cur < prev {
        0.0
    } else {
        (cur - prev) as f64 / secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
        wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
        eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
        br0\t0047720A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";

    #[test]
    fn default_route_picks_lowest_metric_gateway() {
        assert_eq!(default_route_iface(ROUTE).as_deref(), Some("eth0"));
        assert_eq!(default_route_iface("Iface\n"), None);
        assert_eq!(default_route_iface("garbage"), None);
    }

    #[test]
    fn probes_a_fake_sysfs() {
        let t = tempfile::tempdir().expect("tmp");
        let wl = t.path().join("wlan0");
        std::fs::create_dir_all(wl.join("wireless")).expect("mk");
        std::fs::create_dir_all(wl.join("device")).expect("mk");
        std::fs::write(wl.join("type"), "1\n").expect("w");
        std::fs::write(wl.join("speed"), "-1\n").expect("w");
        std::fs::write(wl.join("uevent"), "INTERFACE=wlan0\nDEVTYPE=wlan\n").expect("w");
        let i = sys_info_at(t.path(), "wlan0", Some("wlan0"));
        assert!(i.present && i.wireless && i.physical && i.default_route);
        assert_eq!(
            (i.devtype.as_str(), i.arphrd, i.speed_mbps),
            ("wlan", 1, None)
        );
        assert_eq!(sys_info_at(t.path(), "sshdump", None), SysInfo::default());
        assert_eq!(sys_info_at(t.path(), "../etc", None), SysInfo::default());
    }

    #[test]
    fn counters_and_rate() {
        let t = tempfile::tempdir().expect("tmp");
        let st = t.path().join("eth0/statistics");
        std::fs::create_dir_all(&st).expect("mk");
        std::fs::write(st.join("rx_bytes"), "100\n").expect("w");
        std::fs::write(st.join("tx_bytes"), "50\n").expect("w");
        assert_eq!(byte_counters_at(t.path(), "eth0"), Some(150));
        assert_eq!(byte_counters_at(t.path(), "nope"), None);
        assert_eq!(rate(100, 300, 2.0), 100.0);
        assert_eq!(rate(300, 100, 1.0), 0.0);
        assert_eq!(rate(1, 2, 0.0), 0.0);
    }
}
