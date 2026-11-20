use std::net::IpAddr;
use std::sync::Arc;

use wl_model::{PacketRow, Transport};

use super::StatsEngine;

fn row(src: &str, sp: u16, dst: &str, dp: u16, proto: &str, len: u32, rel: f64) -> PacketRow {
    let ip = |s: &str| s.parse::<IpAddr>().ok();
    PacketRow {
        no: 1,
        epoch: rel,
        rel,
        src: Arc::from(src),
        dst: Arc::from(dst),
        src_ip: ip(src),
        dst_ip: ip(dst),
        src_port: Some(sp),
        dst_port: Some(dp),
        transport: Transport::Tcp,
        protocol: Arc::from(proto),
        len,
        info: Arc::from(""),
        stream: None,
    }
}

#[test]
fn totals_and_protocols() {
    let mut e = StatsEngine::new();
    e.ingest_batch(&[
        row("10.0.0.1", 1000, "8.8.8.8", 443, "TLS", 100, 0.0),
        row("8.8.8.8", 443, "10.0.0.1", 1000, "TLS", 300, 0.5),
        row("10.0.0.1", 1001, "1.1.1.1", 80, "HTTP", 50, 1.0),
    ]);
    let s = e.snapshot(10);
    assert_eq!((s.total_packets, s.total_bytes), (3, 450));
    assert_eq!(s.protocols.len(), 2);
    assert_eq!(&*s.protocols[0].name, "TLS");
    assert_eq!((s.protocols[0].packets, s.protocols[0].bytes), (2, 400));
}

#[test]
fn hosts_in_out_and_private() {
    let mut e = StatsEngine::new();
    e.ingest(&row("10.0.0.1", 1, "8.8.8.8", 2, "TCP", 100, 0.0));
    e.ingest(&row("8.8.8.8", 2, "10.0.0.1", 1, "TCP", 40, 0.1));
    let s = e.snapshot(10);
    let me = s.hosts.iter().find(|h| &*h.addr == "10.0.0.1").unwrap();
    assert_eq!(
        (me.packets_out, me.bytes_out, me.packets_in, me.bytes_in),
        (1, 100, 1, 40)
    );
    assert!(me.is_private);
    let ext = s.hosts.iter().find(|h| &*h.addr == "8.8.8.8").unwrap();
    assert!(!ext.is_private);
    assert_eq!((ext.bytes_in, ext.bytes_out), (100, 40));
}

#[test]
fn non_ip_host_is_not_private() {
    let mut e = StatsEngine::new();
    let mut r = row(
        "aa:bb:cc:dd:ee:ff",
        0,
        "ff:ff:ff:ff:ff:ff",
        0,
        "ARP",
        60,
        0.0,
    );
    r.src_port = None;
    r.dst_port = None;
    e.ingest(&r);
    assert!(e.snapshot(5).hosts.iter().all(|h| !h.is_private));
}

#[test]
fn bidirectional_flows_merge() {
    let mut e = StatsEngine::new();
    e.ingest(&row("10.0.0.1", 5000, "10.0.0.2", 22, "SSH", 100, 1.0));
    e.ingest(&row("10.0.0.2", 22, "10.0.0.1", 5000, "SSH", 200, 2.0));
    e.ingest(&row("10.0.0.1", 5000, "10.0.0.2", 22, "TCP", 50, 3.0));
    let s = e.snapshot(10);
    assert_eq!(s.conversations.len(), 1);
    let c = &s.conversations[0];
    assert_eq!((c.packets, c.bytes), (3, 350));
    assert_eq!((c.first_rel, c.last_rel), (1.0, 3.0));
    assert_eq!(&*c.protocol, "SSH");
}

#[test]
fn dominant_protocol_changes() {
    let mut e = StatsEngine::new();
    e.ingest(&row("10.0.0.1", 1, "10.0.0.2", 2, "TCP", 10, 0.0));
    for t in 1..4 {
        e.ingest(&row("10.0.0.2", 2, "10.0.0.1", 1, "HTTP", 10, f64::from(t)));
    }
    assert_eq!(&*e.snapshot(1).conversations[0].protocol, "HTTP");
}

#[test]
fn top_n_ordering_and_limit() {
    let mut e = StatsEngine::new();
    for i in 0..20u32 {
        let dst = format!("10.0.1.{i}");
        e.ingest(&row("10.0.0.1", 1, &dst, 80, "TCP", (i + 1) * 10, 0.0));
    }
    let s = e.snapshot(5);
    assert_eq!(s.conversations.len(), 5);
    assert_eq!(s.hosts.len(), 5);
    let bytes: Vec<u64> = s.conversations.iter().map(|c| c.bytes).collect();
    assert_eq!(bytes, vec![200, 190, 180, 170, 160]);
    // 10.0.0.1 sees everything, so it ranks first.
    assert_eq!(&*s.hosts[0].addr, "10.0.0.1");
    assert!(
        s.hosts
            .windows(2)
            .all(|w| w[0].bytes_in + w[0].bytes_out >= w[1].bytes_in + w[1].bytes_out)
    );
    assert!(e.snapshot(0).hosts.is_empty());
}

#[test]
fn rate_series_fills_gaps() {
    let mut e = StatsEngine::new();
    e.ingest(&row("10.0.0.1", 1, "10.0.0.2", 2, "TCP", 10, 0.2));
    e.ingest(&row("10.0.0.1", 1, "10.0.0.2", 2, "TCP", 20, 3.7));
    let r = e.snapshot(1).rate;
    assert_eq!(r.len(), 4);
    assert_eq!((r[0].packets, r[0].bytes), (1, 10));
    assert_eq!((r[1].packets, r[2].packets), (0, 0));
    assert_eq!((r[3].packets, r[3].bytes), (1, 20));
}

#[test]
fn reset_clears_everything() {
    let mut e = StatsEngine::new();
    e.ingest(&row("10.0.0.1", 1, "10.0.0.2", 2, "TCP", 10, 0.0));
    e.reset();
    assert_eq!(e.snapshot(5), wl_model::StatsSnapshot::default());
}

/// Run: cargo test -p wl-stats --release -- --ignored --nocapture
#[test]
#[ignore]
fn perf_one_million_rows() {
    let hosts: Vec<String> = (0..200)
        .map(|i| format!("10.0.{}.{}", i / 250, i % 250 + 1))
        .collect();
    let protos: Vec<Arc<str>> = ["TCP", "TLS", "DNS", "HTTP", "UDP"]
        .iter()
        .map(|p| Arc::from(*p))
        .collect();
    let mut rows = Vec::with_capacity(1_000_000);
    for i in 0..1_000_000usize {
        let mut r = row(
            &hosts[i % 200],
            1000 + (i % 50) as u16,
            &hosts[(i * 7 + 3) % 200],
            443,
            "TCP",
            64 + (i % 1400) as u32,
            i as f64 / 5000.0,
        );
        r.protocol = protos[i % 5].clone();
        rows.push(r);
    }
    let mut e = StatsEngine::new();
    let t = std::time::Instant::now();
    e.ingest_batch(&rows);
    let dt = t.elapsed();
    println!("1M rows ingested in {dt:?}");
    assert_eq!(e.snapshot(10).total_packets, 1_000_000);
    assert!(dt.as_secs_f64() < 1.0, "too slow: {dt:?}");
}
