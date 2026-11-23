use super::*;
use crate::test_util::{MAC_A, MAC_B, eth_frame, eth_tagged};

#[test]
fn plain_ethernet_reads_addresses_and_type() {
    let l = parse(LinkType::Ethernet, &eth_frame(0x0800, &[0; 20]));
    assert_eq!((l.src, l.dst), (Some(MAC_A), Some(MAC_B)));
    assert_eq!(
        (l.ethertype, l.vlan, l.net, l.offset),
        (Some(0x0800), None, Net::Ipv4, 14)
    );
    assert!(l.ethernet && l.complete);
}

#[test]
fn network_protocol_follows_the_ethertype() {
    for (ty, net) in [
        (0x86dd, Net::Ipv6),
        (0x0806, Net::Arp),
        (0x88cc, Net::Other),
    ] {
        assert_eq!(parse(LinkType::Ethernet, &eth_frame(ty, &[0; 30])).net, net);
    }
}

#[test]
fn single_vlan_tag_is_skipped_and_reported() {
    let l = parse(
        LinkType::Ethernet,
        &eth_tagged(&[(0x8100, 0x2064)], 0x0800, &[0; 20]),
    );
    assert_eq!(
        (l.vlan, l.ethertype, l.offset),
        (Some(100), Some(0x0800), 18)
    );
}

#[test]
fn stacked_tags_report_the_outer_id_and_the_inner_ethertype() {
    let tags = [(0x88a8, 10), (0x8100, 20), (0x8100, 30)];
    let l = parse(LinkType::Ethernet, &eth_tagged(&tags, 0x86dd, &[0; 40]));
    assert_eq!(
        (l.vlan, l.ethertype, l.net, l.offset),
        (Some(10), Some(0x86dd), Net::Ipv6, 26)
    );
}

#[test]
fn absurd_tag_stacks_stop_at_the_depth_cap() {
    let tags = vec![(0x8100, 5); 40];
    let l = parse(LinkType::Ethernet, &eth_tagged(&tags, 0x0800, &[0; 20]));
    assert_eq!(l.offset, 14 + 4 * MAX_VLAN_DEPTH);
    assert_eq!(l.net, Net::Other);
}

#[test]
fn length_field_instead_of_ethertype_is_not_a_network_protocol() {
    let l = parse(LinkType::Ethernet, &eth_frame(0x0040, &[0; 64]));
    assert_eq!((l.net, l.ethertype), (Net::Other, None));
}

#[test]
fn short_ethernet_frames_give_an_incomplete_link() {
    for n in 0..14 {
        let l = parse(LinkType::Ethernet, &eth_frame(0x0800, &[])[..n]);
        assert!(!l.complete && l.src.is_none(), "{n} bytes");
    }
    let cut = &eth_tagged(&[(0x8100, 7)], 0x0800, &[])[..15];
    let l = parse(LinkType::Ethernet, cut);
    assert_eq!((l.vlan, l.net), (None, Net::Other));
    assert!(l.ethernet);
}

#[test]
fn linux_cooked_v1_reads_protocol_and_hardware_address() {
    let mut d = vec![0, 0, 0, 1, 0, 6];
    d.extend_from_slice(&MAC_A);
    d.extend_from_slice(&[0, 0, 0x08, 0x00]);
    d.extend_from_slice(&[0x45; 20]);
    let l = parse(LinkType::LinuxSll, &d);
    assert_eq!(
        (l.net, l.offset, l.src, l.ethernet),
        (Net::Ipv4, 16, Some(MAC_A), false)
    );
    assert!(parse(LinkType::LinuxSll, &d[..15]).net == Net::Other);
}

#[test]
fn linux_cooked_v2_reads_protocol_and_address() {
    let mut d = vec![0x86, 0xdd, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6];
    d.extend_from_slice(&MAC_B);
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(&[0x60; 40]);
    let l = parse(LinkType::LinuxSll2, &d);
    assert_eq!((l.net, l.offset, l.src), (Net::Ipv6, 20, Some(MAC_B)));
    assert!(
        !parse(LinkType::LinuxSll2, &d[..19]).complete
            || parse(LinkType::LinuxSll2, &d[..1]).net == Net::Other
    );
}

#[test]
fn bsd_null_accepts_either_byte_order_and_the_ipv6_family_numbers() {
    for (family, net) in [
        (2u32, Net::Ipv4),
        (24, Net::Ipv6),
        (28, Net::Ipv6),
        (30, Net::Ipv6),
        (10, Net::Ipv6),
        (99, Net::Other),
    ] {
        for bytes in [family.to_le_bytes(), family.to_be_bytes()] {
            let mut d = bytes.to_vec();
            d.extend_from_slice(&[0x45; 20]);
            let l = parse(LinkType::Null, &d);
            assert_eq!((l.net, l.offset), (net, 4), "family {family}");
        }
    }
    assert!(!parse(LinkType::Null, &[2, 0]).complete);
}

#[test]
fn raw_ip_picks_the_version_from_the_first_nibble() {
    assert_eq!(parse(LinkType::RawIp, &[0x45, 0]).net, Net::Ipv4);
    assert_eq!(parse(LinkType::RawIp, &[0x60, 0]).net, Net::Ipv6);
    assert_eq!(parse(LinkType::RawIp, &[0x10, 0]).net, Net::Other);
    let empty = parse(LinkType::RawIp, &[]);
    assert!(!empty.complete && empty.net == Net::Other);
}

#[test]
fn unknown_link_types_are_other() {
    let l = parse(LinkType::Other(147), &[1, 2, 3]);
    assert_eq!((l.net, l.complete, l.ethernet), (Net::Other, false, false));
}
