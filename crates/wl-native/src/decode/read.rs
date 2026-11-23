//! Bounds-checked big-endian reads. Every decoder goes through these so a short packet yields
//! `None` instead of a panic.

pub fn be16(d: &[u8], at: usize) -> Option<u16> {
    let b = d.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

pub fn be32(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn mac_at(d: &[u8], at: usize) -> Option<[u8; 6]> {
    d.get(at..at.checked_add(6)?)?.try_into().ok()
}

pub fn tail(d: &[u8], from: usize) -> &[u8] {
    d.get(from..).unwrap_or(&[])
}
