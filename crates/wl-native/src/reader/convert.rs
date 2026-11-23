//! Conversions shared by the pcap and pcapng readers.

use super::LinkType;

pub(super) fn link_type(code: i32) -> LinkType {
    match code {
        1 => LinkType::Ethernet,
        0 => LinkType::Null,
        12 | 14 | 101 => LinkType::RawIp,
        113 => LinkType::LinuxSll,
        276 => LinkType::LinuxSll2,
        other => LinkType::Other(other as u32),
    }
}

/// Ticks per second for an `if_tsresol` byte: bit 7 selects base 2, the rest is the exponent.
/// `None` when the result does not fit a u64.
pub(super) fn ticks_per_second(tsresol: u8) -> Option<u64> {
    let exponent = u32::from(tsresol & 0x7f);
    if tsresol & 0x80 == 0 {
        10u64.checked_pow(exponent)
    } else {
        1u64.checked_shl(exponent).filter(|_| exponent < 64)
    }
}

/// Seconds from whole seconds plus a fraction in units of `1 / per_second`.
pub(super) fn epoch(secs: u64, fraction: u64, per_second: u64) -> f64 {
    secs as f64 + fraction as f64 / per_second as f64
}

/// Seconds from a tick count; the integer split keeps the full f64 resolution.
pub(super) fn epoch_from_ticks(ticks: u64, per_second: u64) -> f64 {
    epoch(ticks / per_second, ticks % per_second, per_second)
}
