//! Capture file properties as titled label/value lines (pure: `CaptureProperties` -> text).

use wl_kit::charts::Unit;
use wl_kit::format;
use wl_model::CaptureProperties;

pub struct Section {
    pub title: &'static str,
    pub rows: Vec<(&'static str, String)>,
}

fn dash(s: &str) -> String {
    if s.trim().is_empty() {
        "\u{2013}".into()
    } else {
        s.trim().to_owned()
    }
}

fn exact_bytes(n: u64) -> String {
    format!("{} ({} bytes)", format::bytes(n), format::count(n))
}

fn duration(secs: f64) -> String {
    if secs < 60.0 {
        format!("{secs:.3} s")
    } else {
        format!("{} ({secs:.3} s)", format::duration(secs))
    }
}

fn order(v: Option<bool>) -> String {
    match v {
        Some(true) => "Strictly increasing".into(),
        Some(false) => "Out of order".into(),
        None => "\u{2013}".into(),
    }
}

/// Everything but the interfaces/comments (those are lists) and the hash (loaded lazily).
pub fn sections(p: &CaptureProperties) -> Vec<Section> {
    let mut out = vec![
        Section {
            title: "File",
            rows: vec![
                ("Name", dash(&p.file_name)),
                ("Format", dash(&p.file_type)),
                ("Encapsulation", dash(&p.encapsulation)),
                ("File size", exact_bytes(p.file_size)),
                ("Data size", exact_bytes(p.data_size)),
            ],
        },
        Section {
            title: "Capture",
            rows: vec![
                ("Packets", format::count(p.packets)),
                ("Duration", duration(p.duration)),
                ("First packet", dash(&p.first_packet)),
                ("Last packet", dash(&p.last_packet)),
                (
                    "Average rate",
                    format!(
                        "{} \u{b7} {}",
                        Unit::BitsPerSec.format(p.bits_per_sec),
                        Unit::PacketsPerSec.format(p.avg_packets_per_sec)
                    ),
                ),
                (
                    "Average packet",
                    format::bytes(p.avg_packet_size.round() as u64),
                ),
                ("Time order", order(p.strict_order)),
            ],
        },
    ];
    let source: Vec<_> = [
        ("Application", &p.application),
        ("Hardware", &p.hardware),
        ("Operating system", &p.os),
    ]
    .into_iter()
    .filter(|(_, v)| !v.trim().is_empty())
    .map(|(k, v)| (k, v.trim().to_owned()))
    .collect();
    if !source.is_empty() {
        out.push(Section {
            title: "Source",
            rows: source,
        });
    }
    out
}

/// Height of one titled card of `rows` rows: title + gaps, then `ROW_H` rows with a hairline
/// between them (the card border is inside the last row).
pub fn card_height(rows: usize) -> f32 {
    const CHROME: f32 = 38.5;
    CHROME + rows as f32 * (super::rows::ROW_H + 1.0)
}

/// Height of all content (sections, comments, interfaces), so the dialog can be sized exactly:
/// egui windows containing a scroll area do not shrink-wrap their content.
pub fn content_height(p: &CaptureProperties, hash_ready: bool) -> f32 {
    let mut h = 8.0;
    for (i, s) in sections(p).iter().enumerate() {
        // The File card also holds the SHA256 row, and its full-width digest line when known.
        let extra = if i == 0 {
            1 + usize::from(hash_ready)
        } else {
            0
        };
        h += card_height(s.rows.len() + extra);
    }
    for n in [p.comments.len(), p.interfaces.len()] {
        if n > 0 {
            h += card_height(n);
        }
    }
    h
}

/// One line per interface: `name (description)`, then its details.
pub fn interface_lines(p: &CaptureProperties) -> Vec<(String, String)> {
    p.interfaces
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let name = match (f.name.is_empty(), f.description.is_empty()) {
                (true, _) => format!("Interface {i}"),
                (false, true) => f.name.clone(),
                (false, false) => format!("{} ({})", f.name, f.description),
            };
            let mut parts = vec![dash(&f.encapsulation)];
            if !f.capture_length.is_empty() {
                parts.push(format!("snaplen {}", f.capture_length));
            }
            if !f.filter.is_empty() {
                parts.push(format!("filter: {}", f.filter));
            }
            if !f.packets.is_empty() {
                parts.push(format!("{} packets", f.packets));
            }
            (name, parts.join(" \u{b7} "))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::InterfaceInfo;

    fn props() -> CaptureProperties {
        CaptureProperties {
            file_name: "a.pcapng".into(),
            file_type: "pcapng".into(),
            file_size: 251_000,
            packets: 2583,
            duration: 363.4,
            bits_per_sec: 1_213_000.0,
            avg_packets_per_sec: 7.1,
            strict_order: Some(true),
            application: "Dumpcap".into(),
            interfaces: vec![InterfaceInfo {
                name: "lo".into(),
                description: "Loopback".into(),
                encapsulation: "Ethernet".into(),
                capture_length: "262144".into(),
                filter: "tcp".into(),
                packets: "5".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn sections_format_values_and_skip_empty_source() {
        let s = sections(&props());
        assert_eq!(s[0].rows[0], ("Name", "a.pcapng".into()));
        assert!(s[0].rows[3].1.contains("251,000 bytes"));
        assert_eq!(s[1].rows[0], ("Packets", "2,583".into()));
        assert!(s[1].rows[1].1.contains("6m 03s") && s[1].rows[1].1.contains("363.400 s"));
        assert!(s[1].rows[4].1.contains("1.2 Mbit/s"));
        assert_eq!(s.len(), 3);
        assert_eq!(s[2].rows, vec![("Application", "Dumpcap".into())]);
        assert_eq!(sections(&CaptureProperties::default()).len(), 2);
    }

    #[test]
    fn content_height_grows_with_every_row() {
        let base = content_height(&CaptureProperties::default(), false);
        assert_eq!(
            content_height(&CaptureProperties::default(), true),
            base + 33.0
        );
        let p = props();
        assert!(content_height(&p, false) > base + 33.0 * 3.0);
        let with_comment = CaptureProperties {
            comments: vec!["c".into()],
            ..CaptureProperties::default()
        };
        assert_eq!(content_height(&with_comment, false), base + card_height(1));
    }

    #[test]
    fn interface_line_joins_details() {
        let l = interface_lines(&props());
        assert_eq!(l[0].0, "lo (Loopback)");
        assert_eq!(
            l[0].1,
            "Ethernet \u{b7} snaplen 262144 \u{b7} filter: tcp \u{b7} 5 packets"
        );
        let anon = CaptureProperties {
            interfaces: vec![InterfaceInfo::default()],
            ..Default::default()
        };
        assert_eq!(
            interface_lines(&anon)[0],
            ("Interface 0".into(), "\u{2013}".into())
        );
    }
}
