use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn v4(last: u8) -> IpAddr {
    Ipv4Addr::new(10, 0, 0, last).into()
}

fn tuple(udp: bool, a: (IpAddr, u16), b: (IpAddr, u16)) -> Tuple {
    Tuple {
        udp,
        src: a,
        dst: b,
        syn_seq: None,
    }
}

fn id(t: &mut StreamTable, tuple: &Tuple) -> u32 {
    t.track(tuple).0.id
}

#[test]
fn both_directions_share_one_number() {
    let mut t = StreamTable::default();
    let ab = tuple(false, (v4(1), 1000), (v4(2), 80));
    let ba = tuple(false, (v4(2), 80), (v4(1), 1000));
    assert_eq!(id(&mut t, &ab), 0);
    assert_eq!(id(&mut t, &ba), 0);
    assert_eq!(id(&mut t, &ab), 0);
}

#[test]
fn the_side_index_tells_which_end_sent() {
    let mut t = StreamTable::default();
    let ab = tuple(false, (v4(1), 1000), (v4(2), 80));
    let ba = tuple(false, (v4(2), 80), (v4(1), 1000));
    let (da, db) = (t.track(&ab).1, t.track(&ba).1);
    assert_ne!(da, db);
    assert_eq!(t.track(&ab).1, da);
}

#[test]
fn numbers_follow_first_appearance_in_an_interleaved_capture() {
    let mut t = StreamTable::default();
    let c = |port| tuple(false, (v4(1), port), (v4(9), 443));
    let r = |port| tuple(false, (v4(9), 443), (v4(1), port));
    let order = [c(1), c(2), r(1), c(3), r(2), c(1), r(3), c(2)];
    let ids: Vec<u32> = order.iter().map(|x| id(&mut t, x)).collect();
    assert_eq!(ids, [0, 1, 0, 2, 1, 0, 2, 1]);
}

#[test]
fn tcp_and_udp_count_separately() {
    let mut t = StreamTable::default();
    let a = (v4(1), 53);
    let b = (v4(2), 53);
    assert_eq!(id(&mut t, &tuple(true, a, b)), 0);
    assert_eq!(id(&mut t, &tuple(false, a, b)), 0);
    assert_eq!(id(&mut t, &tuple(true, (v4(3), 1), b)), 1);
    assert_eq!(id(&mut t, &tuple(false, (v4(3), 1), b)), 1);
}

#[test]
fn ports_and_addresses_both_distinguish_streams() {
    let mut t = StreamTable::default();
    let ids = [
        id(&mut t, &tuple(false, (v4(1), 1), (v4(2), 2))),
        id(&mut t, &tuple(false, (v4(1), 1), (v4(2), 3))),
        id(&mut t, &tuple(false, (v4(1), 1), (v4(3), 2))),
        id(&mut t, &tuple(false, (v4(1), 4), (v4(2), 2))),
    ];
    assert_eq!(ids, [0, 1, 2, 3]);
}

#[test]
fn an_ipv4_pair_and_an_ipv6_pair_with_the_same_bytes_differ() {
    let mut t = StreamTable::default();
    let six = |x: u16| IpAddr::V6(Ipv6Addr::new(0x0a00, x, 0, 0, 0, 0, 0, 0));
    let a = id(&mut t, &tuple(false, (v4(1), 1), (v4(2), 2)));
    let b = id(&mut t, &tuple(false, (six(1), 1), (six(2), 2)));
    assert_ne!(a, b);
}

#[test]
fn the_oldest_stream_is_forgotten_past_the_cap() {
    let mut t = StreamTable::with_capacity(3);
    for port in 1..=4 {
        id(&mut t, &tuple(true, (v4(1), port), (v4(2), 9)));
    }
    assert_eq!(t.len(), 3);
    assert_eq!(id(&mut t, &tuple(true, (v4(1), 4), (v4(2), 9))), 3);
    assert_eq!(id(&mut t, &tuple(true, (v4(1), 1), (v4(2), 9))), 4);
}

fn syn(seq: u32) -> Tuple {
    Tuple {
        syn_seq: Some(seq),
        ..tuple(false, (v4(1), 1000), (v4(2), 80))
    }
}

#[test]
fn a_syn_with_the_same_sequence_number_is_a_retransmission() {
    let mut t = StreamTable::default();
    let (s, dir) = t.track(&syn(100));
    s.half[dir].base = Some(100);
    assert_eq!(t.track(&syn(100)).0.id, 0);
}

#[test]
fn a_syn_with_a_new_sequence_number_opens_a_new_stream() {
    let mut t = StreamTable::default();
    let (s, dir) = t.track(&syn(100));
    s.half[dir].base = Some(100);
    let (s2, d2) = t.track(&syn(900));
    assert_eq!(s2.id, 1);
    assert!(s2.half[d2].base.is_none() && !s2.closed);
    assert_eq!(id(&mut t, &tuple(false, (v4(2), 80), (v4(1), 1000))), 1);
}

#[test]
fn a_syn_after_fin_or_rst_opens_a_new_stream_even_with_the_same_number() {
    let mut t = StreamTable::default();
    let (s, dir) = t.track(&syn(100));
    s.half[dir].base = Some(100);
    s.closed = true;
    assert_eq!(t.track(&syn(100)).0.id, 1);
}

#[test]
fn a_syn_on_a_stream_that_never_saw_one_keeps_the_stream() {
    let mut t = StreamTable::default();
    id(&mut t, &tuple(false, (v4(1), 1000), (v4(2), 80)));
    assert_eq!(t.track(&syn(5)).0.id, 0);
}
