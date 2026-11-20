//! Pure interface classification: name / description / sysfs facts -> display group + tag,
//! plus search and ordering. No UI, no I/O.

use std::cmp::Ordering;

use wl_model::{ARPHRD_ETHER, Interface};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    Network,
    Virtual,
    Loopback,
    Other,
}

impl Group {
    pub const ALL: [Group; 4] = [
        Group::Network,
        Group::Virtual,
        Group::Loopback,
        Group::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Group::Network => "Network",
            Group::Virtual => "Virtual & bridges",
            Group::Loopback => "Loopback & any",
            Group::Other => "Other (remote, extcap, Bluetooth, system buses)",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class {
    pub group: Group,
    pub tag: &'static str,
}

const fn c(group: Group, tag: &'static str) -> Class {
    Class { group, tag }
}

/// `br-` followed by the 12 hex digits Docker gives user-defined networks.
fn is_docker_net(name: &str) -> bool {
    name.strip_prefix("br-")
        .is_some_and(|h| h.len() >= 12 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Interfaces that have no sysfs entry: extcap tools and capture-only pseudo devices.
fn pseudo_tag(name: &str) -> &'static str {
    match name {
        n if n.starts_with("bluetooth") => "Bluetooth",
        "nflog" | "nfqueue" => "Netfilter",
        n if n.starts_with("dbus-") => "D-Bus",
        n if n.starts_with("usbmon") => "USB",
        _ => "Remote",
    }
}

fn virtual_tag(i: &Interface) -> &'static str {
    let (n, t) = (i.name.as_str(), i.sys.devtype.as_str());
    match () {
        () if n == "docker0" || is_docker_net(n) => "Docker",
        () if n.starts_with("virbr") => "Libvirt",
        () if t == "bridge" || n.starts_with("br") => "Bridge",
        () if t == "veth" || n.starts_with("veth") => "Veth",
        () if n.starts_with("tap") || n.starts_with("tun") => "Tap",
        () if t == "vlan" => "VLAN",
        () if n.starts_with("wg") || t == "wireguard" => "VPN",
        () => "Virtual",
    }
}

pub fn classify(i: &Interface) -> Class {
    if i.is_loopback || i.name == "lo" {
        return c(Group::Loopback, "Loopback");
    }
    if i.name == "any" {
        return c(Group::Loopback, "Any");
    }
    if !i.sys.present {
        return c(Group::Other, pseudo_tag(&i.name));
    }
    if i.sys.physical || i.sys.wireless && !i.name.starts_with("p2p") {
        return match () {
            () if i.sys.wireless => c(Group::Network, "Wi-Fi"),
            () if i.sys.arphrd == ARPHRD_ETHER => c(Group::Network, "Ethernet"),
            () => c(Group::Network, "Network"),
        };
    }
    c(Group::Virtual, virtual_tag(i))
}

/// Case-insensitive match on name, description and tag. Empty query matches everything.
pub fn matches(i: &Interface, query: &str) -> bool {
    let q = query.trim().to_lowercase();
    q.is_empty()
        || i.name.to_lowercase().contains(&q)
        || classify(i).tag.to_lowercase().contains(&q)
        || i.description
            .as_deref()
            .is_some_and(|d| d.to_lowercase().contains(&q))
}

/// Order inside a group: default route, then up, then busiest, then name.
fn within(a: &Interface, b: &Interface, rate: &dyn Fn(&str) -> f64) -> Ordering {
    b.sys
        .default_route
        .cmp(&a.sys.default_route)
        .then(b.is_up.cmp(&a.is_up))
        .then(rate(&b.name).total_cmp(&rate(&a.name)))
        .then_with(|| a.name.cmp(&b.name))
}

/// Indices into `list` per group (all four groups, possibly empty), filtered by `query`.
pub fn grouped(
    list: &[Interface],
    query: &str,
    rate: &dyn Fn(&str) -> f64,
) -> Vec<(Group, Vec<usize>)> {
    Group::ALL
        .map(|g| {
            let mut idx: Vec<usize> = (0..list.len())
                .filter(|&n| classify(&list[n]).group == g && matches(&list[n], query))
                .collect();
            idx.sort_by(|&a, &b| within(&list[a], &list[b], rate));
            (g, idx)
        })
        .to_vec()
}

/// The interface to pre-select: default route, else first up physical, else first up, else first.
pub fn default_interface(list: &[Interface]) -> Option<String> {
    let pick = |f: &dyn Fn(&Interface) -> bool| list.iter().find(|i| f(i));
    pick(&|i| i.sys.default_route && i.is_up)
        .or_else(|| pick(&|i| i.is_up && classify(i).group == Group::Network))
        .or_else(|| pick(&|i| i.is_up && !i.is_loopback && i.name != "any"))
        .or_else(|| pick(&|i| i.is_up))
        .or_else(|| list.first())
        .map(|i| i.name.clone())
}
