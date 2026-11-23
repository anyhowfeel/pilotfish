use std::net::{IpAddr, Ipv4Addr};

use super::*;

fn ip(v6: bool, ttl: u8) -> Ip<'static> {
    Ip {
        version: if v6 { 6 } else { 4 },
        src: IpAddr::V4(Ipv4Addr::LOCALHOST),
        dst: IpAddr::V4(Ipv4Addr::LOCALHOST),
        proto: if v6 { 58 } else { 1 },
        first_proto: 1,
        ttl,
        frag: None,
        offset: 0,
        header_len: 20,
        payload_len: 0,
        payload: &[],
    }
}

fn icmp<'a>(v6: bool, kind: u8, code: u8, body: &'a [u8]) -> Icmp<'a> {
    Icmp {
        v6,
        kind,
        code,
        offset: 0,
        body,
    }
}

fn v4(kind: u8, code: u8, body: &[u8]) -> String {
    label(&ip(false, 64), &icmp(false, kind, code, body)).info
}

fn v6(kind: u8, code: u8, body: &[u8]) -> String {
    label(&ip(true, 255), &icmp(true, kind, code, body)).info
}

#[test]
fn echo_request_and_reply_match_wireshark_spacing() {
    let body = [0, 1, 0, 1, 9, 9];
    assert_eq!(v4(8, 0, &body), "Echo (ping) request  id=0x0001, seq=1/256, ttl=64");
    assert_eq!(v4(0, 0, &body), "Echo (ping) reply    id=0x0001, seq=1/256, ttl=64");
    assert_eq!(label(&ip(false, 64), &icmp(false, 8, 0, &body)).protocol, "ICMP");
}

#[test]
fn echo_without_identifiers_still_names_the_message() {
    assert_eq!(v4(8, 0, &[]), "Echo (ping) request");
}

#[test]
fn error_messages_name_the_code() {
    assert_eq!(v4(3, 3, &[0; 4]), "Destination unreachable (Port unreachable)");
    assert_eq!(v4(3, 1, &[0; 4]), "Destination unreachable (Host unreachable)");
    assert_eq!(v4(3, 99, &[0; 4]), "Destination unreachable (Unknown)");
    assert_eq!(v4(11, 0, &[]), "Time-to-live exceeded (Time to live exceeded in transit)");
    assert_eq!(v4(5, 1, &[]), "Redirect             (Redirect for host)");
    assert_eq!(v4(77, 2, &[]), "Unknown (type 77, code 2)");
}

#[test]
fn icmpv6_echo_uses_hop_limit() {
    let body = [0xf2, 0x60, 0, 2];
    assert_eq!(v6(128, 0, &body), "Echo (ping) request id=0xf260, seq=2, hop limit=255");
    assert_eq!(v6(129, 0, &body), "Echo (ping) reply id=0xf260, seq=2, hop limit=255");
    assert_eq!(label(&ip(true, 1), &icmp(true, 128, 0, &body)).protocol, "ICMPv6");
}

#[test]
fn icmpv6_errors() {
    assert_eq!(v6(1, 4, &[0; 4]), "Destination Unreachable (Port unreachable)");
    assert_eq!(v6(1, 0, &[0; 4]), "Destination Unreachable (No route to destination)");
    assert_eq!(v6(2, 0, &[0; 4]), "Packet Too Big");
    assert_eq!(v6(3, 0, &[0; 4]), "Time Exceeded (In-transit)");
}

fn target_body(options: &[u8]) -> Vec<u8> {
    let mut b = vec![0, 0, 0, 0, 0xfe, 0x80];
    b.extend_from_slice(&[0; 13]);
    b.push(1);
    b.extend_from_slice(options);
    b
}

#[test]
fn neighbor_discovery_names_target_and_link_address() {
    let mut ns = target_body(&[1, 1, 2, 0, 0, 0, 0, 0xaa]);
    assert_eq!(v6(135, 0, &ns), "Neighbor Solicitation for fe80::1 from 02:00:00:00:00:aa");
    ns.truncate(20);
    assert_eq!(v6(135, 0, &ns), "Neighbor Solicitation for fe80::1");
    let mut na = target_body(&[2, 1, 2, 0, 0, 0, 0, 0xbb]);
    na[0] = 0x60;
    assert_eq!(v6(136, 0, &na), "Neighbor Advertisement fe80::1 (sol, ovr) is at 02:00:00:00:00:bb");
}

#[test]
fn router_messages_and_mld() {
    assert_eq!(v6(133, 0, &[0, 0, 0, 0, 1, 1, 2, 0, 0, 0, 0, 1]), "Router Solicitation from 02:00:00:00:00:01");
    assert_eq!(v6(134, 0, &[0; 12]), "Router Advertisement");
    assert_eq!(v6(143, 0, &[]), "Multicast Listener Report Message v2");
    assert_eq!(v6(200, 0, &[]), "Unknown (type 200)");
}

#[test]
fn malformed_options_do_not_loop_or_panic() {
    let body = target_body(&[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(v6(135, 0, &body), "Neighbor Solicitation for fe80::1");
    assert_eq!(v6(136, 0, &[]), "Neighbor Advertisement  ()");
}
