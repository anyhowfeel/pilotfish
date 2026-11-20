//! Scan-like high cardinality workload. Run for numbers:
//! `cargo test --release -p wl-stats bench -- --ignored --nocapture`

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use wl_model::{PacketRow, Transport};

use super::StatsEngine;

fn scan_row(i: u32, hosts: u32) -> PacketRow {
    let addr = |n: u32| Arc::<str>::from(Ipv4Addr::from(0x0a00_0000 + n).to_string());
    let (s, d) = (i % hosts, (i.wrapping_mul(7919) + 1) % hosts);
    PacketRow {
        no: u64::from(i),
        epoch: f64::from(i) / 1000.0,
        rel: f64::from(i) / 1000.0,
        src: addr(s),
        dst: addr(d),
        src_ip: Some(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + s))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + d))),
        src_port: Some(40_000),
        dst_port: Some(80),
        transport: Transport::Tcp,
        protocol: Arc::from("TCP"),
        len: 60,
        info: Arc::from(""),
        stream: None,
    }
}

#[test]
#[ignore]
fn bench_ingest_and_snapshot() {
    let rows: Vec<PacketRow> = (0..1_000_000).map(|i| scan_row(i, 100_000)).collect();
    let mut e = StatsEngine::new();
    let t = Instant::now();
    e.ingest_batch(&rows);
    println!("ingest 1M rows: {} ms", t.elapsed().as_millis());
    let t = Instant::now();
    let snaps = 20;
    for _ in 0..snaps {
        let s = e.snapshot(200);
        assert_eq!(s.hosts.len(), 200);
    }
    println!("snapshot(200): {} ms each", t.elapsed().as_millis() / snaps);
}
