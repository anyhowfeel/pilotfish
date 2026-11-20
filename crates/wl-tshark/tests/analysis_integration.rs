//! Integration tests for Follow Stream, Expert Info, Protocol Hierarchy, and Filter Fields
//! against `tests/fixtures/sample.pcapng`.

use std::path::PathBuf;

use wl_model::{ExpertSeverity, StreamFormat, StreamProtocol};
use wl_tshark::TsharkBackend;

fn sample_pcap() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/sample.pcapng")
}

fn backend() -> Option<TsharkBackend> {
    TsharkBackend::new().ok()
}

#[test]
fn follow_tcp_ascii_and_hex_on_sample() {
    let Some(b) = backend() else { return };
    let pcap = sample_pcap();
    assert!(pcap.is_file(), "fixture missing: {}", pcap.display());

    let ascii = b
        .follow_stream(&pcap, StreamProtocol::Tcp, 0, StreamFormat::Ascii)
        .expect("follow tcp ascii");
    assert_eq!(ascii.protocol, StreamProtocol::Tcp);
    assert_eq!(ascii.stream_id, 0);
    assert!(!ascii.client.is_empty());
    assert!(!ascii.server.is_empty());
    assert!(ascii.turns.len() >= 2, "expected client+server turns");
    assert!(ascii.turns[0].from_client);
    assert!(ascii.turns[0].text.contains("GET / HTTP/1.1"));
    assert!(
        ascii
            .turns
            .iter()
            .any(|t| !t.from_client && t.text.contains("200 OK"))
    );
    assert!(ascii.total_bytes > 200);

    let hex = b
        .follow_stream(&pcap, StreamProtocol::Tcp, 0, StreamFormat::Hex)
        .expect("follow tcp hex");
    assert_eq!(hex.format, StreamFormat::Hex);
    assert!(hex.turns.len() >= 2);
    assert!(hex.turns[0].text.contains("47 45 54 20"));
    assert_eq!(hex.total_bytes, ascii.total_bytes);
}

#[test]
fn follow_udp_ascii_on_sample() {
    let Some(b) = backend() else { return };
    let pcap = sample_pcap();
    let udp = b
        .follow_stream(&pcap, StreamProtocol::Udp, 0, StreamFormat::Ascii)
        .expect("follow udp ascii");
    assert_eq!(udp.protocol, StreamProtocol::Udp);
    assert!(!udp.turns.is_empty());
    assert!(udp.turns[0].text.contains("hello wirelens"));
    assert!(udp.total_bytes >= 48);
}

#[test]
fn expert_info_on_sample() {
    let Some(b) = backend() else { return };
    let pcap = sample_pcap();
    let report = b.expert_info(&pcap, None).expect("expert info");
    assert!(!report.entries.is_empty());
    assert!(report.count_by_severity(ExpertSeverity::Warn) > 0);
    assert!(report.count_by_severity(ExpertSeverity::Note) > 0);
    assert!(report.count_by_severity(ExpertSeverity::Chat) > 0);

    let tcp_only = b.expert_info(&pcap, Some("tcp")).expect("expert tcp");
    assert!(tcp_only.entries.iter().all(|e| e.protocol == "TCP"));
}

#[test]
fn protocol_hierarchy_on_sample() {
    let Some(b) = backend() else { return };
    let pcap = sample_pcap();
    let phs = b.protocol_hierarchy(&pcap, None).expect("phs");
    assert_eq!(phs.total_frames, 287);
    assert!(phs.total_bytes > 200_000);
    assert!(
        phs.nodes
            .iter()
            .any(|n| n.protocol == "tcp" && n.frames == 159)
    );
    assert!(
        phs.nodes
            .iter()
            .any(|n| n.protocol == "http" && n.frames == 24)
    );
    assert!(
        phs.nodes
            .iter()
            .any(|n| n.protocol == "udp" && n.depth >= 3)
    );

    let filtered = b.protocol_hierarchy(&pcap, Some("tcp")).expect("phs tcp");
    assert_eq!(filtered.filter, "tcp");
    assert_eq!(filtered.total_frames, 159);
}

#[test]
fn filter_fields_loads_from_tshark() {
    let Some(b) = backend() else { return };
    let fields = b.filter_fields(Some(250)).expect("tshark -G fields");
    assert_eq!(fields.len(), 250);
    assert!(fields.iter().all(|f| !f.abbrev.is_empty()));
}
