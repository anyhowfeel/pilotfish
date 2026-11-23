//! Small hand-built capture files for the layouts the fixtures do not have: empty, one packet,
//! cut packets, out of order, other resolutions, several interfaces. Shared by the differential
//! tests of the properties and of the I/O series.

use wl_native::test_util::*;

fn frame(epoch: f64, len: usize) -> Frame {
    Frame::new(epoch, vec![0; len])
}

fn pcap(frames: &[Frame]) -> Vec<u8> {
    pcap_bytes(frames, PcapStyle::default())
}

fn cut_frames() -> Vec<Frame> {
    let mut cut = frame(100.0, 40);
    cut.orig_len = Some(1500);
    vec![cut, frame(101.0, 60)]
}

fn out_of_order() -> Vec<Frame> {
    [100.0, 100.5, 99.0, 102.5, 101.0, 100.2, 101.5, 102.9]
        .iter()
        .map(|t| frame(*t, 60 + (*t as usize % 7)))
        .collect()
}

fn empty_pcapng() -> Vec<u8> {
    let mut out = ng_shb(false);
    out.extend(ng_idb(false, 1, 0, None));
    out
}

/// `(file name, bytes)`; the extension tells the format.
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    let nanos = PcapStyle {
        nanos: true,
        ..PcapStyle::default()
    };
    let big = PcapStyle {
        big_endian: true,
        ..PcapStyle::default()
    };
    let two = [frame(100.0, 60), frame(101.0, 80)];
    vec![
        ("empty.pcap", pcap(&[])),
        ("empty.pcapng", empty_pcapng()),
        ("one-packet.pcap", pcap(&[frame(100.5, 60)])),
        (
            "same-time.pcap",
            pcap(&[frame(100.0, 60), frame(100.0, 70)]),
        ),
        ("cut.pcap", pcap(&cut_frames())),
        ("out-of-order.pcap", pcap(&out_of_order())),
        ("nanos.pcap", pcap_bytes(&two, nanos)),
        ("big-endian.pcap", pcap_bytes(&two, big)),
        ("sample.pcapng", pcapng_bytes(&sample_frames())),
        ("multi-interface.pcapng", multi_interface_pcapng()),
    ]
}
