//! User-defined graph series, colour assignment and the preset menu (pure, tested).

use wl_model::IoSpec;

use super::metric::Metric;

/// Palette slots (`Palette::series(idx)`) — also the maximum number of series.
pub const MAX_SERIES: usize = 6;

#[derive(Debug, Clone, PartialEq)]
pub struct SeriesDef {
    pub name: String,
    /// Text of the filter field (may be mid-edit).
    pub filter: String,
    /// The last committed filter (Enter / focus lost): what the backend is asked for.
    pub applied: String,
    pub metric: Metric,
    /// Index into the theme's series palette; the colour itself is looked up when drawing.
    pub color: usize,
    pub visible: bool,
}

impl SeriesDef {
    pub fn new(name: &str, filter: &str, metric: Metric, color: usize) -> Self {
        Self {
            name: name.into(),
            filter: filter.into(),
            applied: filter.into(),
            metric,
            color,
            visible: true,
        }
    }

    /// The backend query. Cached by it, so renaming or recolouring never recomputes.
    pub fn spec(&self) -> IoSpec {
        IoSpec {
            filter: self.applied.trim().to_owned(),
            delta: self.metric.delta(),
        }
    }

    pub fn commit(&mut self) {
        self.applied.clone_from(&self.filter);
    }

    /// Name shown in legends: the given one, else the filter, else "All packets".
    pub fn display_name(&self) -> &str {
        let n = self.name.trim();
        if !n.is_empty() {
            n
        } else if !self.filter.trim().is_empty() {
            self.filter.trim()
        } else {
            "All packets"
        }
    }
}

/// First palette slot not used by `defs` (wraps to slot 0 when all are taken).
pub fn free_color(defs: &[SeriesDef]) -> usize {
    (0..MAX_SERIES)
        .find(|c| defs.iter().all(|d| d.color != *c))
        .unwrap_or(0)
}

/// The slot after `current` that no other series uses (cycling), or simply the next slot.
pub fn next_color(defs: &[SeriesDef], idx: usize) -> usize {
    let cur = defs[idx].color;
    (1..MAX_SERIES)
        .map(|k| (cur + k) % MAX_SERIES)
        .find(|c| {
            defs.iter()
                .enumerate()
                .all(|(i, d)| i == idx || d.color != *c)
        })
        .unwrap_or((cur + 1) % MAX_SERIES)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Total,
    TcpRetransmissions,
    Dns,
    HttpErrors,
    BroadcastMulticast,
}

impl Preset {
    pub const ALL: [Preset; 5] = [
        Preset::Total,
        Preset::TcpRetransmissions,
        Preset::Dns,
        Preset::HttpErrors,
        Preset::BroadcastMulticast,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Preset::Total => "Total",
            Preset::TcpRetransmissions => "TCP retransmissions",
            Preset::Dns => "DNS",
            Preset::HttpErrors => "HTTP errors",
            Preset::BroadcastMulticast => "Broadcast/multicast",
        }
    }

    /// The series this preset replaces the current ones with.
    pub fn series(self) -> Vec<SeriesDef> {
        let p = Metric::PacketsPerSec;
        let rows: &[(&str, &str, Metric)] = match self {
            Preset::Total => &[("All packets", "", p)],
            Preset::TcpRetransmissions => &[
                ("TCP", "tcp", p),
                (
                    "Retransmissions",
                    "tcp.analysis.retransmission || tcp.analysis.fast_retransmission",
                    p,
                ),
            ],
            Preset::Dns => &[
                ("Queries", "dns.flags.response == 0", p),
                ("Responses", "dns.flags.response == 1", p),
                ("Errors", "dns.flags.rcode != 0", p),
            ],
            Preset::HttpErrors => &[
                ("Requests", "http.request", p),
                (
                    "Client errors",
                    "http.response.code >= 400 && http.response.code < 500",
                    p,
                ),
                ("Server errors", "http.response.code >= 500", p),
            ],
            Preset::BroadcastMulticast => &[
                ("All packets", "", p),
                ("Broadcast", "eth.dst == ff:ff:ff:ff:ff:ff", p),
                (
                    "Multicast",
                    "eth.ig == 1 && eth.dst != ff:ff:ff:ff:ff:ff",
                    p,
                ),
            ],
        };
        rows.iter()
            .enumerate()
            .map(|(i, (n, f, m))| SeriesDef::new(n, f, *m, i))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_trims_and_follows_the_metric() {
        let mut d = SeriesDef::new("x", "  tcp ", Metric::MaxDelta, 0);
        d.filter = "udp".into();
        assert_eq!(d.spec().filter, "tcp", "uncommitted edits are not queried");
        d.commit();
        d.filter = "  tcp ".into();
        d.commit();
        let s = d.spec();
        assert_eq!(s.filter, "tcp");
        assert!(s.delta.is_some());
        assert!(
            SeriesDef::new("x", "tcp", Metric::BitsPerSec, 0)
                .spec()
                .delta
                .is_none()
        );
    }

    #[test]
    fn display_name_falls_back_to_filter_then_all() {
        assert_eq!(
            SeriesDef::new(" ", "dns", Metric::BytesPerSec, 0).display_name(),
            "dns"
        );
        assert_eq!(
            SeriesDef::new("", "", Metric::BytesPerSec, 0).display_name(),
            "All packets"
        );
        assert_eq!(
            SeriesDef::new("A", "dns", Metric::BytesPerSec, 0).display_name(),
            "A"
        );
    }

    #[test]
    fn colours_avoid_each_other() {
        let mut defs = vec![SeriesDef::new("a", "", Metric::BytesPerSec, 0)];
        assert_eq!(free_color(&defs), 1);
        defs.push(SeriesDef::new("b", "", Metric::BytesPerSec, 1));
        assert_eq!(next_color(&defs, 0), 2);
        assert_eq!(next_color(&defs, 1), 2);
        let full: Vec<_> = (0..MAX_SERIES)
            .map(|c| SeriesDef::new("s", "", Metric::BytesPerSec, c))
            .collect();
        assert_eq!(free_color(&full), 0);
        assert_eq!(next_color(&full, 5), 0);
    }

    #[test]
    fn presets_fit_the_palette_with_distinct_colours() {
        for p in Preset::ALL {
            let s = p.series();
            assert!(!s.is_empty() && s.len() <= MAX_SERIES, "{p:?}");
            let mut cols: Vec<_> = s.iter().map(|d| d.color).collect();
            cols.dedup();
            assert_eq!(cols.len(), s.len());
            assert!(s.iter().all(|d| !d.filter.contains(',')), "{p:?}: commas");
        }
        assert_eq!(Preset::Total.series().len(), 1);
    }
}
