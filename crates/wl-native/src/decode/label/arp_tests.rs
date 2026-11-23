use std::net::Ipv4Addr;

use super::*;

fn arp(op: u16, sender: [u8; 4], target: [u8; 4]) -> Arp {
    Arp {
        op,
        sender_mac: [2, 0, 0, 0, 0, 0x0a],
        sender_ip: Ipv4Addr::from(sender),
        target_mac: [0; 6],
        target_ip: Ipv4Addr::from(target),
    }
}

#[test]
fn request_and_reply_use_wiresharks_wording() {
    let req = label(&arp(1, [192, 168, 1, 10], [192, 168, 1, 1]));
    assert_eq!(
        (req.protocol, req.info.as_str()),
        ("ARP", "Who has 192.168.1.1? Tell 192.168.1.10")
    );
    let rep = label(&arp(2, [192, 168, 1, 1], [192, 168, 1, 10]));
    assert_eq!(rep.info, "192.168.1.1 is at 02:00:00:00:00:0a");
}

#[test]
fn probes_and_gratuitous_arp_are_named() {
    assert_eq!(
        label(&arp(1, [0; 4], [10, 0, 0, 5])).info,
        "Who has 10.0.0.5? (ARP Probe)"
    );
    assert_eq!(
        label(&arp(1, [10, 0, 0, 5], [10, 0, 0, 5])).info,
        "ARP Announcement for 10.0.0.5"
    );
    let mut with_target = arp(1, [10, 0, 0, 5], [10, 0, 0, 5]);
    with_target.target_mac = [1; 6];
    assert_eq!(
        label(&with_target).info,
        "Gratuitous ARP for 10.0.0.5 (Request)"
    );
    assert_eq!(
        label(&arp(2, [10, 0, 0, 5], [10, 0, 0, 5])).info,
        "Gratuitous ARP for 10.0.0.5 (Reply)"
    );
}

#[test]
fn unknown_opcodes_do_not_panic() {
    assert_eq!(label(&arp(9, [1; 4], [2; 4])).info, "Opcode 9");
}
