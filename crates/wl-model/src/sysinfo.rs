//! Cheap facts about a network device read from sysfs (no new dependencies, no root).

/// Linux `ARPHRD_ETHER`.
pub const ARPHRD_ETHER: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SysInfo {
    /// A `/sys/class/net/<name>` entry exists (false for extcap / pseudo interfaces).
    pub present: bool,
    /// `DEVTYPE` from uevent: `bridge`, `wlan`, `vlan`, `veth` ... (empty when plain).
    pub devtype: String,
    /// Backed by real hardware (`device` link exists).
    pub physical: bool,
    pub wireless: bool,
    /// Link layer type (`ARPHRD_*`).
    pub arphrd: u32,
    pub speed_mbps: Option<u32>,
    /// Carries the IPv4 default route.
    pub default_route: bool,
}
