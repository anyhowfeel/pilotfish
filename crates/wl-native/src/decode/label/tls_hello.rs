//! The parts of TLS hello messages the Info column and the protocol label need.

use crate::decode::read::be16;

/// Wireshark names a ClientHello by the version inside it, not by the record header.
pub(super) fn client_hello_version(ct: u8, body: &[u8]) -> Option<u16> {
    if ct != 22 || *body.first()? != 1 {
        return None;
    }
    let msg = body.get(4..)?;
    match offered_versions(msg) {
        Some(min) if min >= 0x0304 => Some(0x0304),
        _ => be16(msg, 0),
    }
}

/// The lowest version in a ClientHello's `supported_versions` extension, which Wireshark uses
/// to call a TLS 1.3 only client TLSv1.3.
fn offered_versions(msg: &[u8]) -> Option<u16> {
    let ext = extensions(msg)?;
    let data = ext.into_iter().find(|(ty, _)| *ty == 0x002b)?.1;
    let list = data.get(1..)?;
    list.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .min()
}

/// The (type, data) extensions of a ClientHello body.
fn extensions(msg: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut at = 34;
    at += 1 + usize::from(*msg.get(at)?);
    at += 2 + usize::from(be16(msg, at)?);
    at += 1 + usize::from(*msg.get(at)?);
    let end = (at + 2 + usize::from(be16(msg, at)?)).min(msg.len());
    at += 2;
    let mut out = Vec::new();
    while at + 4 <= end {
        let (ty, len) = (be16(msg, at)?, usize::from(be16(msg, at + 2)?));
        out.push((ty, msg.get(at + 4..(at + 4 + len).min(end))?));
        at += 4 + len;
    }
    Some(out)
}

pub(super) fn server_name(msg: &[u8]) -> Option<String> {
    let data = extensions(msg)?.into_iter().find(|(ty, _)| *ty == 0)?.1;
    let name_len = usize::from(be16(data, 3)?);
    let name = data.get(5..5 + name_len)?;
    Some(String::from_utf8_lossy(name).into_owned())
}

/// The version a ServerHello selects: the `supported_versions` extension wins over the field.
pub(super) fn server_hello_version(msg: &[u8]) -> Option<u16> {
    let mut version = be16(msg, 0)?;
    let sid = usize::from(*msg.get(34)?);
    let mut at = 35 + sid + 3;
    let ext_end = at + 2 + usize::from(be16(msg, at)?);
    at += 2;
    while at + 4 <= ext_end.min(msg.len()) {
        let (ty, len) = (be16(msg, at)?, usize::from(be16(msg, at + 2)?));
        if ty == 0x002b {
            version = be16(msg, at + 4)?;
        }
        at += 4 + len;
    }
    Some(version)
}
