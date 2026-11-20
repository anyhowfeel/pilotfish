//! Tests of the pure interface classification.

use super::iface_class::*;
use wl_model::{Interface, SysInfo};

fn net(name: &str, desc: Option<&str>, sys: SysInfo, up: bool) -> Interface {
    Interface {
        name: name.into(),
        description: desc.map(Into::into),
        is_loopback: name == "lo",
        is_up: up,
        sys,
    }
}
fn virt(devtype: &str) -> SysInfo {
    SysInfo {
        present: true,
        devtype: devtype.into(),
        arphrd: 1,
        ..SysInfo::default()
    }
}
fn phys(wireless: bool) -> SysInfo {
    SysInfo {
        present: true,
        physical: true,
        wireless,
        arphrd: 1,
        ..SysInfo::default()
    }
}
fn cls(name: &str, sys: SysInfo) -> (Group, &'static str) {
    let k = classify(&net(name, None, sys, true));
    (k.group, k.tag)
}

#[test]
fn classifies_this_machines_interfaces() {
    let n = Group::Network;
    assert_eq!(cls("wlan0", phys(true)), (n, "Wi-Fi"));
    assert_eq!(cls("eth0", phys(false)), (n, "Ethernet"));
    let v = Group::Virtual;
    assert_eq!(cls("docker0", virt("bridge")), (v, "Docker"));
    assert_eq!(cls("br-d8d13e122944", virt("bridge")), (v, "Docker"));
    assert_eq!(cls("br0", virt("bridge")), (v, "Bridge"));
    assert_eq!(cls("mpqemubr0", virt("bridge")), (v, "Bridge"));
    assert_eq!(cls("virbr0", virt("bridge")), (v, "Libvirt"));
    assert_eq!(cls("veth59096e0", virt("veth")), (v, "Veth"));
    assert_eq!(cls("tap-e165d896471", virt("")), (v, "Tap"));
    assert_eq!(cls("wg0", virt("wireguard")), (v, "VPN"));
    assert_eq!(cls("lo", virt("")), (Group::Loopback, "Loopback"));
    assert_eq!(cls("any", SysInfo::default()), (Group::Loopback, "Any"));
}

#[test]
fn pseudo_interfaces_are_other() {
    let o = Group::Other;
    let none = SysInfo::default;
    assert_eq!(cls("sshdump", none()), (o, "Remote"));
    assert_eq!(cls("ciscodump", none()), (o, "Remote"));
    assert_eq!(cls("bluetooth0", none()), (o, "Bluetooth"));
    assert_eq!(cls("bluetooth-monitor", none()), (o, "Bluetooth"));
    assert_eq!(cls("nflog", none()), (o, "Netfilter"));
    assert_eq!(cls("dbus-session", none()), (o, "D-Bus"));
    assert_eq!(cls("usbmon1", none()), (o, "USB"));
}

#[test]
fn search_matches_name_tag_and_description() {
    let i = net("br-0123456789ab", Some("Bridge"), virt("bridge"), true);
    assert!(matches(&i, "") && matches(&i, "0123") && matches(&i, "DOCKER"));
    assert!(matches(&i, "bridge") && !matches(&i, "wlan"));
}

#[test]
fn groups_sort_default_route_up_busy_then_name() {
    let mut def = phys(false);
    def.default_route = true;
    let list = [
        net("eth2", None, phys(false), true),
        net("eth1", None, phys(false), true),
        net("eth9", None, phys(false), false),
        net("eth0", None, def, true),
        net("lo", None, virt(""), true),
    ];
    let rates = |n: &str| if n == "eth2" { 10.0 } else { 0.0 };
    let g = grouped(&list, "", &rates);
    let names: Vec<_> = g[0].1.iter().map(|&i| list[i].name.as_str()).collect();
    assert_eq!(names, ["eth0", "eth2", "eth1", "eth9"]);
    assert_eq!(g[2].1, vec![4]);
    assert!(g[1].1.is_empty() && g[3].1.is_empty());
    assert_eq!(grouped(&list, "eth1", &rates)[0].1, vec![1]);
}

#[test]
fn default_interface_follows_the_route() {
    let mut def = phys(true);
    def.default_route = true;
    let list = [
        net("docker0", None, virt("bridge"), true),
        net("eth0", None, phys(false), true),
        net("wlan0", None, def, true),
    ];
    assert_eq!(default_interface(&list).as_deref(), Some("wlan0"));
    assert_eq!(default_interface(&list[..2]).as_deref(), Some("eth0"));
    let down = [net("lo", None, virt(""), false)];
    assert_eq!(default_interface(&down).as_deref(), Some("lo"));
    assert_eq!(default_interface(&[]), None);
}
