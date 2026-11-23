//! Little-endian pcapng blocks that carry options, for metadata tests.

use super::pcapng::{ng_block, ng_epb};

pub const OPT_COMMENT: u16 = 1;
pub const OPT_NAME_OR_HARDWARE: u16 = 2;
pub const OPT_DESCRIPTION_OR_OS: u16 = 3;
pub const OPT_APPLICATION: u16 = 4;
pub const OPT_TSRESOL: u16 = 9;
pub const OPT_FILTER: u16 = 11;

/// One option: code, length, value padded to 4 bytes.
pub fn ng_opt(code: u16, value: &[u8]) -> Vec<u8> {
    let mut out = code.to_le_bytes().to_vec();
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

fn with_end(options: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = options.concat();
    out.extend_from_slice(&ng_opt(0, &[]));
    out
}

/// Section Header Block carrying `options` (see `ng_opt`).
pub fn ng_shb_opts(options: &[Vec<u8>]) -> Vec<u8> {
    let mut body = 0x1a2b_3c4d_u32.to_le_bytes().to_vec();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(-1i64).to_le_bytes());
    body.extend_from_slice(&with_end(options));
    ng_block(0x0a0d_0d0a, &body, false)
}

/// Interface Description Block carrying `options`.
pub fn ng_idb_opts(link: u16, snaplen: u32, options: &[Vec<u8>]) -> Vec<u8> {
    let mut body = link.to_le_bytes().to_vec();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&snaplen.to_le_bytes());
    body.extend_from_slice(&with_end(options));
    ng_block(1, &body, false)
}

/// Millisecond Ethernet interface `eth0` and a microsecond Linux cooked one, section options,
/// three packets out of order.
pub fn multi_interface_pcapng() -> Vec<u8> {
    let mut out = ng_shb_opts(&[
        ng_opt(OPT_COMMENT, b"first comment"),
        ng_opt(OPT_COMMENT, b"second comment"),
        ng_opt(OPT_NAME_OR_HARDWARE, b"Fancy HW"),
        ng_opt(OPT_DESCRIPTION_OR_OS, b"MyOS 1"),
        ng_opt(OPT_APPLICATION, b"MyApp 2"),
    ]);
    out.extend(ng_idb_opts(
        1,
        1000,
        &[
            ng_opt(OPT_NAME_OR_HARDWARE, b"eth0"),
            ng_opt(OPT_DESCRIPTION_OR_OS, b"the wire"),
            ng_opt(OPT_FILTER, b"\0tcp port 80"),
            ng_opt(9, &[3]),
        ],
    ));
    out.extend(ng_idb_opts(113, 0, &[ng_opt(OPT_NAME_OR_HARDWARE, b"any")]));
    out.extend(ng_epb(false, 0, 100_500, &[0; 60], 60));
    out.extend(ng_epb(false, 1, 100_900, &[0; 40], 80));
    out.extend(ng_epb(false, 0, 100_100, &[0; 60], 60));
    out
}
