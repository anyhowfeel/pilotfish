//! pcapng files, and hand-assembled blocks in either byte order.

use std::path::Path;

use super::files::Frame;

fn ng_u32(v: u32, be: bool) -> [u8; 4] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}

fn ng_u16(v: u16, be: bool) -> [u8; 2] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}

/// One pcapng block of any type and byte order; `body` is padded to 4 bytes.
pub fn ng_block(kind: u32, body: &[u8], be: bool) -> Vec<u8> {
    let mut padded = body.to_vec();
    pad4(&mut padded);
    let total = ng_u32((padded.len() + 12) as u32, be);
    let mut out = ng_u32(kind, be).to_vec();
    out.extend_from_slice(&total);
    out.extend_from_slice(&padded);
    out.extend_from_slice(&total);
    out
}

/// Section Header Block with unknown section length.
pub fn ng_shb(be: bool) -> Vec<u8> {
    let mut body = ng_u32(0x1a2b_3c4d, be).to_vec();
    body.extend_from_slice(&ng_u16(1, be));
    body.extend_from_slice(&ng_u16(0, be));
    body.extend_from_slice(&(-1i64).to_le_bytes());
    ng_block(0x0a0d_0d0a, &body, be)
}

/// Interface Description Block; `tsresol` becomes an `if_tsresol` option when given.
pub fn ng_idb(be: bool, link: u16, snaplen: u32, tsresol: Option<u8>) -> Vec<u8> {
    let mut body = ng_u16(link, be).to_vec();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&ng_u32(snaplen, be));
    if let Some(r) = tsresol {
        body.extend_from_slice(&ng_u16(9, be));
        body.extend_from_slice(&ng_u16(1, be));
        body.extend_from_slice(&[r, 0, 0, 0]);
        body.extend_from_slice(&[0; 4]);
    }
    ng_block(1, &body, be)
}

/// Enhanced Packet Block with a raw tick count.
pub fn ng_epb(be: bool, if_id: u32, ticks: u64, data: &[u8], orig_len: u32) -> Vec<u8> {
    let mut body = ng_u32(if_id, be).to_vec();
    body.extend_from_slice(&ng_u32((ticks >> 32) as u32, be));
    body.extend_from_slice(&ng_u32(ticks as u32, be));
    body.extend_from_slice(&ng_u32(data.len() as u32, be));
    body.extend_from_slice(&ng_u32(orig_len, be));
    body.extend_from_slice(data);
    ng_block(6, &body, be)
}

/// Simple Packet Block.
pub fn ng_spb(be: bool, data: &[u8], orig_len: u32) -> Vec<u8> {
    let mut body = ng_u32(orig_len, be).to_vec();
    body.extend_from_slice(data);
    ng_block(3, &body, be)
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let mut padded = body.to_vec();
    pad4(&mut padded);
    let total = (padded.len() + 12) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&padded);
    out.extend_from_slice(&total.to_le_bytes());
    out
}

/// Little-endian pcapng with one Ethernet interface at microsecond resolution.
pub fn pcapng_bytes(frames: &[Frame]) -> Vec<u8> {
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1a2b_3c4d_u32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    let mut idb = Vec::new();
    idb.extend_from_slice(&1u16.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&262_144u32.to_le_bytes());
    let mut out = block(0x0a0d_0d0a, &shb);
    out.extend(block(1, &idb));
    for f in frames {
        let ticks = (f.epoch * 1e6).round() as u64;
        let mut epb = Vec::new();
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ticks as u32).to_le_bytes());
        epb.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&f.orig_len.unwrap_or(f.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&f.data);
        out.extend(block(6, &epb));
    }
    out
}

pub fn write_pcapng(path: &Path, frames: &[Frame]) {
    std::fs::write(path, pcapng_bytes(frames)).expect("write pcapng");
}
