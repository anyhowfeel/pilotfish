//! Layer summary of one frame for the detail pane when tshark is not available.
//!
//! Sequence and acknowledgment numbers are the raw values: relative numbers need the stream
//! state of every earlier packet, which one frame does not carry.

mod ip;
mod link;
mod transport;

use std::path::Path;

use wl_model::{CaptureError, DetailNode, FrameDetail};

use super::net::NetLayer;
use super::parse::{self, Packet};
use crate::reader::{self, PacketMeta};

/// One node per decoded layer (Frame, link, IP, TCP / UDP / ICMP / ARP) with the fields the
/// decoder reads, and the raw bytes for the hex pane. Walks the file to frame `frame_no`.
pub fn basic(path: &Path, frame_no: u64) -> Result<FrameDetail, CaptureError> {
    let mut source = reader::open(path).map_err(|e| CaptureError::Other(e.to_string()))?;
    let mut data = Vec::new();
    loop {
        match source.next_packet(&mut data) {
            Ok(Some(meta)) if meta.no == frame_no => return Ok(from_packet(&meta, &data)),
            Ok(Some(meta)) if meta.no > frame_no => break,
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => return Err(CaptureError::Other(e.to_string())),
        }
    }
    Err(CaptureError::Other(format!(
        "frame {frame_no} not found in {}",
        path.display()
    )))
}

/// The layers of one packet; the part of [`basic`] that needs no file.
pub fn from_packet(meta: &PacketMeta, bytes: &[u8]) -> FrameDetail {
    let pkt = parse::packet(meta.link, bytes);
    let mut layers = vec![frame(meta, bytes.len())];
    layers.extend(link::link(meta.link, &pkt, bytes));
    layers.extend(network(&pkt, bytes));
    if pkt.ip().is_none_or(|ip| ip.frag.is_none()) {
        layers.extend(transport::segment(&pkt, bytes));
    }
    FrameDetail {
        frame_no: meta.no,
        layers,
        bytes: bytes.to_vec(),
    }
}

fn network(pkt: &Packet, bytes: &[u8]) -> Option<DetailNode> {
    match &pkt.net {
        NetLayer::Ip(ip) => Some(ip::ip(ip, bytes)),
        NetLayer::Arp(a) => Some(link::arp(a, pkt.link.offset, bytes.len())),
        _ => None,
    }
}

fn frame(meta: &PacketMeta, captured: usize) -> DetailNode {
    let wire = meta.orig_len;
    node(
        format!(
            "Frame {}: {wire} bytes on wire ({} bits), {captured} bytes captured ({} bits)",
            meta.no,
            u64::from(wire) * 8,
            captured * 8
        ),
        None,
        vec![
            node(format!("Frame Number: {}", meta.no), None, vec![]),
            node(
                format!("Epoch Arrival Time: {:.9}", meta.epoch),
                None,
                vec![],
            ),
            node(
                format!("Frame Length: {wire} bytes ({} bits)", u64::from(wire) * 8),
                None,
                vec![],
            ),
            node(
                format!("Capture Length: {captured} bytes ({} bits)", captured * 8),
                None,
                vec![],
            ),
        ],
    )
}

pub(super) fn node(
    label: String,
    range: Option<(usize, usize)>,
    children: Vec<DetailNode>,
) -> DetailNode {
    DetailNode {
        label,
        range,
        children,
    }
}

/// A field node covering `len` bytes at `start`, dropped from the range when the frame is cut
/// before its end so the hex pane never highlights past the data.
pub(super) fn field(label: String, start: usize, len: usize, total: usize) -> DetailNode {
    let range = (start + len <= total).then_some((start, start + len));
    node(label, range, vec![])
}

#[cfg(test)]
#[path = "detail_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "basic_tests.rs"]
mod basic_tests;

#[cfg(test)]
#[path = "layers_tests.rs"]
mod layers_tests;

#[cfg(test)]
#[path = "transport_tests.rs"]
mod transport_tests;
