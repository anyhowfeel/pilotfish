use super::*;

fn stamp(secs: u64, nanos: u32) -> Stamp {
    Stamp {
        secs,
        nanos,
        digits: 6,
    }
}

#[test]
fn ticks_split_into_seconds_and_nanoseconds() {
    let s = Stamp::from_ticks(1_700_000_000_123_456, 1_000_000);
    assert_eq!((s.secs, s.nanos, s.digits), (1_700_000_000, 123_456_000, 6));
    let s = Stamp::from_ticks(5, 1_000_000_000);
    assert_eq!((s.secs, s.nanos, s.digits), (0, 5, 9));
    let s = Stamp::from_ticks(1500, 1000);
    assert_eq!((s.secs, s.nanos, s.digits), (1, 500_000_000, 3));
}

#[test]
fn resolutions_round_to_the_decimals_wireshark_names() {
    let digits = |per_second| Stamp::from_ticks(0, per_second).digits;
    assert_eq!(
        [digits(1), digits(10), digits(100), digits(1000)],
        [0, 1, 2, 3]
    );
    assert_eq!(
        [digits(10_000), digits(1_000_000), digits(10_000_000)],
        [6, 6, 9]
    );
    assert_eq!([digits(60), digits(1 << 10), digits(1 << 20)], [2, 6, 9]);
}

#[test]
fn extremes_and_order_follow_the_packets() {
    let mut info = FileInfo::new(Format::Pcap);
    for t in [stamp(10, 0), stamp(10, 0), stamp(12, 5)] {
        info.record_packet(0, Some(t));
    }
    assert!(info.ordered);
    info.record_packet(0, Some(stamp(9, 999)));
    assert!(!info.ordered);
    assert_eq!(info.first.map(|s| s.key()), Some((9, 999)));
    assert_eq!(info.last.map(|s| s.key()), Some((12, 5)));
}

#[test]
fn a_packet_without_a_time_is_counted_but_leaves_the_times_alone() {
    let mut info = FileInfo::new(Format::Pcapng);
    info.interfaces
        .push(InterfaceDesc::new(LinkType::Ethernet, 0, 1_000_000));
    info.record_packet(0, None);
    info.record_packet(7, None);
    assert_eq!((info.interfaces[0].packets, info.first), (1, None));
    assert!(info.ordered);
}
