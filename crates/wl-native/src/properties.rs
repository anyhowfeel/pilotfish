//! File summary for the Properties page (what `capinfos -M` prints), without the hash.

use std::path::Path;

use wl_model::{CaptureError, CaptureProperties, ClockZone, InterfaceInfo};

use crate::reader::{self, FileInfo, Format, Stamp};

mod links;
mod stamp;

const NOT_AVAILABLE: &str = "n/a";

/// One pass over the file. Data size counts the length on the wire, like `capinfos`, so a
/// snap-length cut does not shrink it.
pub fn read(path: &Path, zone: ClockZone) -> Result<CaptureProperties, CaptureError> {
    let file_size = std::fs::metadata(path)
        .map_err(|e| CaptureError::Other(format!("{}: {e}", path.display())))?
        .len();
    let mut source = reader::open(path)?;
    let (mut packets, mut data_size) = (0u64, 0u64);
    let mut buffer = Vec::new();
    while let Some(meta) = source.next_packet(&mut buffer)? {
        packets += 1;
        data_size += u64::from(meta.orig_len);
    }
    Ok(assemble(
        path,
        file_size,
        packets,
        data_size,
        source.info(),
        zone,
    ))
}

fn seconds(stamp: &Stamp) -> f64 {
    stamp.secs as f64 + f64::from(stamp.nanos) / 1e9
}

fn assemble(
    path: &Path,
    file_size: u64,
    packets: u64,
    data_size: u64,
    info: &FileInfo,
    zone: ClockZone,
) -> CaptureProperties {
    let duration = match (&info.first, &info.last) {
        (Some(first), Some(last)) => seconds(last) - seconds(first),
        _ => 0.0,
    };
    let per_second = |amount: f64| {
        if duration > 0.0 {
            amount / duration
        } else {
            0.0
        }
    };
    let shown = |s: &Option<Stamp>| {
        s.as_ref()
            .and_then(|s| stamp::format(s, zone))
            .unwrap_or_else(|| NOT_AVAILABLE.to_owned())
    };
    CaptureProperties {
        file_name: path.to_string_lossy().into_owned(),
        file_type: file_type(info.format).to_owned(),
        encapsulation: links::file_text(info.interfaces.iter().map(|i| i.link)),
        file_size,
        data_size,
        packets,
        duration,
        first_packet: shown(&info.first),
        last_packet: shown(&info.last),
        bytes_per_sec: per_second(data_size as f64),
        bits_per_sec: per_second(data_size as f64 * 8.0),
        avg_packet_size: if packets > 0 {
            data_size as f64 / packets as f64
        } else {
            0.0
        },
        avg_packets_per_sec: per_second(packets as f64),
        strict_order: Some(info.ordered),
        application: info.application.clone(),
        hardware: info.hardware.clone(),
        os: info.os.clone(),
        comments: info.comments.clone(),
        interfaces: info
            .interfaces
            .iter()
            .map(|i| InterfaceInfo {
                name: i.name.clone(),
                description: i.description.clone(),
                encapsulation: links::interface_text(i.link),
                capture_length: i.snaplen.to_string(),
                filter: i.filter.clone(),
                packets: i.packets.to_string(),
            })
            .collect(),
    }
}

fn file_type(format: Format) -> &'static str {
    match format {
        Format::Pcap => "pcap",
        Format::PcapNanos => "nsecpcap",
        Format::Pcapng => "pcapng",
    }
}

#[cfg(test)]
#[path = "properties_pcapng_tests.rs"]
mod pcapng_tests;
#[cfg(test)]
#[path = "properties_tests.rs"]
mod tests;
