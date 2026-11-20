//! Flow graph / TCP graph passes against the checked-in fixtures (skipped without tshark).

use std::path::PathBuf;

use wl_model::{CaptureBackend, FlowFlags};
use wl_tshark::TsharkBackend;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn flow_events_find_handshake_and_retransmissions() {
    let Ok(b) = TsharkBackend::new() else { return };
    let r = b
        .flow_events(&fixture("tcp-retrans.pcap"), "tcp.stream eq 0")
        .expect("pass");
    assert_eq!((r.events.len(), r.truncated), (79, false));
    assert!(r.events[0].flags.contains(FlowFlags::SYN));
    assert_eq!(&*r.events[0].src, "10.0.0.2");
    assert_eq!(r.events[0].src_port, Some(51000));
    let count = |f: FlowFlags| r.events.iter().filter(|e| e.flags.contains(f)).count();
    assert_eq!(count(FlowFlags::RETRANS), 4);
    assert!(count(FlowFlags::DUP_ACK) >= 8);
    assert_eq!(count(FlowFlags::LOST), 2);
    assert_eq!(count(FlowFlags::FIN), 2);
}

#[test]
fn tcp_samples_orient_endpoint_a_and_collect_rtt() {
    let Ok(b) = TsharkBackend::new() else { return };
    let s = b
        .tcp_samples(&fixture("tcp-retrans.pcap"), "tcp.stream eq 0")
        .expect("pass");
    assert_eq!(
        (&*s.a, s.a_port, &*s.b),
        ("10.0.0.2", Some(51000), "10.0.0.1")
    );
    assert_eq!(s.samples.len(), 79);
    assert!(s.samples.iter().any(|x| x.rtt.is_some()));
    assert!(s.samples.iter().any(|x| !x.from_a && x.len == 1448));
}

#[test]
fn bad_filter_is_an_error_and_empty_match_is_empty() {
    let Ok(b) = TsharkBackend::new() else { return };
    let f = fixture("tcp-retrans.pcap");
    assert!(b.flow_events(&f, "((").is_err());
    assert!(
        b.flow_events(&f, "tcp.stream eq 99")
            .unwrap()
            .events
            .is_empty()
    );
}
