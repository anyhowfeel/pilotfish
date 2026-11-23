//! Capture files written from frames: pcap in several styles and pcapng.

use std::path::Path;

/// One captured packet of a synthetic file.
#[derive(Debug, Clone)]
pub struct Frame {
    pub epoch: f64,
    pub data: Vec<u8>,
    /// Length on the wire when the capture cut the packet short.
    pub orig_len: Option<u32>,
}

impl Frame {
    pub fn new(epoch: f64, data: Vec<u8>) -> Self {
        Self {
            epoch,
            data,
            orig_len: None,
        }
    }
}

/// How `write_pcap` lays the file out.
#[derive(Debug, Clone, Copy)]
pub struct PcapStyle {
    pub nanos: bool,
    pub big_endian: bool,
    pub link_type: u32,
}

impl Default for PcapStyle {
    fn default() -> Self {
        Self {
            nanos: false,
            big_endian: false,
            link_type: 1,
        }
    }
}

struct Endian(bool);

impl Endian {
    fn u32(&self, v: u32) -> [u8; 4] {
        if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
    fn u16(&self, v: u16) -> [u8; 2] {
        if self.0 {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    }
}

/// The 24-byte global header.
pub fn pcap_header(style: PcapStyle) -> Vec<u8> {
    let e = Endian(style.big_endian);
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&e.u32(if style.nanos {
        0xa1b2_3c4d
    } else {
        0xa1b2_c3d4
    }));
    out.extend_from_slice(&e.u16(2));
    out.extend_from_slice(&e.u16(4));
    out.extend_from_slice(&e.u32(0));
    out.extend_from_slice(&e.u32(0));
    out.extend_from_slice(&e.u32(262_144));
    out.extend_from_slice(&e.u32(style.link_type));
    out
}

/// One record header and its data, appended to `out`.
pub fn push_pcap_record(out: &mut Vec<u8>, style: PcapStyle, f: &Frame) {
    let e = Endian(style.big_endian);
    let sub = if style.nanos {
        (f.epoch.fract() * 1e9).round() as u32
    } else {
        (f.epoch.fract() * 1e6).round() as u32
    };
    out.extend_from_slice(&e.u32(f.epoch.trunc() as u32));
    out.extend_from_slice(&e.u32(sub));
    out.extend_from_slice(&e.u32(f.data.len() as u32));
    out.extend_from_slice(&e.u32(f.orig_len.unwrap_or(f.data.len() as u32)));
    out.extend_from_slice(&f.data);
}

pub fn pcap_bytes(frames: &[Frame], style: PcapStyle) -> Vec<u8> {
    let mut out = pcap_header(style);
    for f in frames {
        push_pcap_record(&mut out, style, f);
    }
    out
}

pub fn write_pcap(path: &Path, frames: &[Frame], style: PcapStyle) {
    std::fs::write(path, pcap_bytes(frames, style)).expect("write pcap");
}
