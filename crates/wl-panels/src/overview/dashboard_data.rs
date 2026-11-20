//! Pure derivation of everything the dashboard shows from a `StatsSnapshot`.

use wl_kit::egui::Color32;
use wl_kit::format;
use wl_kit::theme::{Palette, protocol_color};
use wl_model::{RatePoint, StatsSnapshot};

use super::services::top_services;

const TOP: usize = 5;

#[derive(Debug, Clone, PartialEq)]
pub struct Kpi {
    pub title: &'static str,
    pub value: String,
    pub sub: Option<String>,
}

#[derive(Default)]
pub struct Derived {
    pub kpis: Vec<Kpi>,
    pub protocol_bar: Vec<(String, f64, Color32)>,
    pub protocol_rows: Vec<(String, f64, String)>,
    pub talkers: Vec<(String, f64, String)>,
    pub services: Vec<(String, f64, String)>,
}

/// Last *complete* 1 s bucket (the newest one is still filling).
fn current(rate: &[RatePoint]) -> Option<RatePoint> {
    match rate.len() {
        0 => None,
        1 => rate.last().copied(),
        n => Some(rate[n - 2]),
    }
}

pub fn derive(s: &StatsSnapshot) -> Derived {
    let cur = current(&s.rate);
    let pps = cur.map_or(0.0, |p| f64::from(p.packets));
    let bps = cur.map_or(0.0, |p| p.bytes as f64);
    let peak = s.rate.iter().map(|p| p.packets).max().unwrap_or(0);
    let avg = if s.total_packets > 0 {
        s.total_bytes as f64 / s.total_packets as f64
    } else {
        0.0
    };
    let private = s.hosts.iter().filter(|h| h.is_private).count();
    let kpi = |title, value: String, sub: Option<String>| Kpi { title, value, sub };
    let kpis = vec![
        kpi("Packets", format::count(s.total_packets), None),
        kpi(
            "Data",
            format::bytes(s.total_bytes),
            Some(format::rate(bps)),
        ),
        kpi(
            "Packets / s",
            format!("{pps:.0}"),
            Some(format!("peak {peak}")),
        ),
        kpi("Avg packet size", format::bytes(avg as u64), None),
        kpi(
            "Active hosts",
            format::count(s.hosts.len() as u64),
            Some(format!("{private} private")),
        ),
        kpi(
            "Active flows",
            format::count(s.conversations.len() as u64),
            None,
        ),
    ];

    let total: f64 = s.protocols.iter().map(|p| p.bytes as f64).sum();
    let mut protocol_bar: Vec<_> = s
        .protocols
        .iter()
        .take(TOP + 2)
        .map(|p| (p.name.to_string(), p.bytes as f64, protocol_color(&p.name)))
        .collect();
    let rest: f64 = s
        .protocols
        .iter()
        .skip(TOP + 2)
        .map(|p| p.bytes as f64)
        .sum();
    if rest > 0.0 {
        protocol_bar.push(("Other".into(), rest, Palette::muted()));
    }
    let protocol_rows = s
        .protocols
        .iter()
        .take(TOP)
        .map(|p| {
            let pct = if total > 0.0 {
                p.bytes as f64 / total * 100.0
            } else {
                0.0
            };
            (
                p.name.to_string(),
                p.bytes as f64,
                format!("{} \u{00B7} {pct:.0}%", format::bytes(p.bytes)),
            )
        })
        .collect();

    let mut hosts: Vec<_> = s
        .hosts
        .iter()
        .map(|h| (h.addr.to_string(), h.bytes_in + h.bytes_out))
        .collect();
    hosts.sort_by_key(|h| std::cmp::Reverse(h.1));
    let talkers = hosts
        .into_iter()
        .take(TOP)
        .map(|(a, b)| (a, b as f64, format::bytes(b)))
        .collect();
    let services = top_services(&s.conversations, TOP)
        .into_iter()
        .map(|v| (v.label, v.bytes as f64, format::bytes(v.bytes)))
        .collect();
    Derived {
        kpis,
        protocol_bar,
        protocol_rows,
        talkers,
        services,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::{HostStat, ProtocolStat};

    #[test]
    fn derives_kpis_and_rankings() {
        let s = StatsSnapshot {
            total_packets: 10,
            total_bytes: 1000,
            protocols: vec![ProtocolStat {
                name: "TCP".into(),
                packets: 10,
                bytes: 1000,
            }],
            hosts: vec![
                HostStat {
                    addr: "a".into(),
                    bytes_in: 1,
                    is_private: true,
                    ..Default::default()
                },
                HostStat {
                    addr: "b".into(),
                    bytes_out: 9,
                    ..Default::default()
                },
            ],
            rate: vec![
                RatePoint {
                    t: 0.0,
                    packets: 4,
                    bytes: 400,
                },
                RatePoint {
                    t: 1.0,
                    packets: 1,
                    bytes: 10,
                },
            ],
            ..Default::default()
        };
        let d = derive(&s);
        assert_eq!(d.kpis.len(), 6);
        assert_eq!(d.kpis[2].value, "4");
        assert_eq!(d.kpis[4].sub.as_deref(), Some("1 private"));
        assert_eq!(d.talkers[0].0, "b");
        assert!(d.protocol_rows[0].2.contains("100%"));
    }

    #[test]
    fn empty_snapshot_is_safe() {
        let d = derive(&StatsSnapshot::default());
        assert_eq!(d.kpis[3].value, wl_kit::format::bytes(0));
        assert!(d.talkers.is_empty());
    }
}
