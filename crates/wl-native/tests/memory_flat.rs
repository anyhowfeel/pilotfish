//! Streaming a large capture holds memory flat: the peak does not follow the packet count.
//! Reads `/proc`, so it does nothing off Linux.

use wl_model::CaptureEvent;
use wl_native::NativeBackend;
use wl_native::test_util::{peak_kb, reset_peak, resident_kb, write_big_pcap};

const SMALL: u64 = 300_000;
const LARGE: u64 = 2 * SMALL;
/// Observed in debug: 13 MiB of growth at 300k and at 600k packets. The bound is about three times that.
const BOUND_KB: u64 = 40 * 1024;

/// Peak resident growth, in KiB, while the rows of a capture of `packets` packets are drained
/// and dropped. `None` where the peak cannot be measured.
fn growth_kb(packets: u64) -> Option<u64> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.pcap");
    write_big_pcap(&path, packets);
    if !reset_peak() {
        return None;
    }
    let before = resident_kb()?;
    let session = NativeBackend::new().start_file(&path, None).expect("start");
    let mut rows = 0;
    for event in session.events.iter() {
        match event {
            CaptureEvent::Rows(batch) => rows += batch.len() as u64,
            CaptureEvent::Finished => break,
            CaptureEvent::Failed(e) => panic!("{e}"),
        }
    }
    assert_eq!(rows, packets);
    Some(peak_kb()?.saturating_sub(before))
}

#[test]
fn peak_memory_does_not_grow_with_the_packet_count() {
    let (Some(small), Some(large)) = (growth_kb(SMALL), growth_kb(LARGE)) else {
        eprintln!("no /proc memory counters here, skipping");
        return;
    };
    eprintln!("peak growth: {small} KiB for {SMALL} packets, {large} KiB for {LARGE}");
    assert!(small < BOUND_KB, "{small} KiB for {SMALL} packets");
    assert!(large < BOUND_KB, "{large} KiB for {LARGE} packets");
    assert!(
        large * 100 <= small * 125,
        "doubling the packets raised the peak from {small} to {large} KiB"
    );
}
