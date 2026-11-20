//! Quick-filter chips: pure logic. A census of the protocols seen in the capture, composition
//! of chip toggles into a display filter (`tcp || dns`) and the reverse (filter text -> active
//! chips). The filter text box stays the single source of truth.

use std::collections::HashMap;
use std::sync::Arc;

use crate::packets::filter_expr::protocol_name;

/// One-click filters that are not protocols (exclusive: they replace the filter text).
pub const PRESETS: [(&str, &str); 6] = [
    ("No broadcast", "!(eth.dst == ff:ff:ff:ff:ff:ff)"),
    ("No ARP", "!arp"),
    ("TCP problems", "tcp.analysis.flags"),
    ("TCP SYN", "tcp.flags.syn == 1 && tcp.flags.ack == 0"),
    ("DNS errors", "dns.flags.rcode != 0"),
    ("Not multicast", "!(eth.dst[0] & 1)"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickChip {
    /// Filter expression (also the term in `a || b`), e.g. `tls`.
    pub expr: String,
    /// Display label, e.g. `TLS`.
    pub label: String,
    pub count: u64,
}

/// Packet counts per protocol column value (interned strings, so few distinct keys).
#[derive(Default)]
pub struct Census {
    counts: HashMap<Arc<str>, u64>,
    chips: Vec<QuickChip>,
    dirty: bool,
}

impl Census {
    pub fn add(&mut self, protocol: &Arc<str>) {
        match self.counts.get_mut(&**protocol) {
            Some(c) => *c += 1,
            None => {
                self.counts.insert(protocol.clone(), 1);
            }
        }
        self.dirty = true;
    }

    pub fn clear(&mut self) {
        self.counts.clear();
        self.chips.clear();
        self.dirty = false;
    }

    /// Chips sorted by volume (then name); protocols that map to one filter name are merged.
    pub fn chips(&mut self) -> &[QuickChip] {
        if self.dirty {
            self.chips = build_chips(&self.counts);
            self.dirty = false;
        }
        &self.chips
    }
}

fn build_chips(counts: &HashMap<Arc<str>, u64>) -> Vec<QuickChip> {
    // filter name -> (count, raw spellings seen, biggest raw spelling's count, that spelling)
    let mut merged: HashMap<String, (u64, usize, u64, &str)> = HashMap::new();
    for (p, n) in counts {
        let name = protocol_name(p);
        if name.is_empty() {
            continue;
        }
        let e = merged.entry(name).or_insert((0, 0, 0, p));
        e.0 += n;
        e.1 += 1;
        if *n > e.2 {
            (e.2, e.3) = (*n, p);
        }
    }
    let mut v: Vec<QuickChip> = merged
        .into_iter()
        .map(|(expr, (count, variants, _, raw))| QuickChip {
            // One spelling (`ICMPv6`): keep it. Several (`TLSv1.2`, `TLSv1.3`): the filter name.
            label: if variants == 1 && raw.eq_ignore_ascii_case(&expr) {
                raw.to_owned()
            } else {
                expr.to_ascii_uppercase()
            },
            expr,
            count,
        })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.expr.cmp(&b.expr)));
    v
}

fn is_ident(t: &str) -> bool {
    !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The protocol terms of `text` when it is exactly `a || b || c` (or empty); `None` otherwise.
pub fn terms(text: &str) -> Option<Vec<&str>> {
    let t = text.trim();
    if t.is_empty() {
        return Some(Vec::new());
    }
    let parts: Vec<&str> = t.split("||").map(str::trim).collect();
    parts.iter().all(|p| is_ident(p)).then_some(parts)
}

/// Whether the chip for `expr` is on for this filter text.
pub fn is_active(text: &str, expr: &str) -> bool {
    match terms(text) {
        Some(t) => t.contains(&expr),
        None => text.trim() == expr,
    }
}

/// Filter text after clicking the chip `expr`: adds it to / removes it from the `||` list. A
/// filter that is not a plain list (or a preset) is replaced by the chip.
pub fn toggle(text: &str, expr: &str) -> String {
    match terms(text) {
        Some(mut t) => {
            if let Some(i) = t.iter().position(|x| *x == expr) {
                t.remove(i);
            } else {
                t.push(expr);
            }
            t.join(" || ")
        }
        None => expr.to_owned(),
    }
}

/// Filter text after clicking a preset: switches it on, or off again when already active.
pub fn toggle_preset(text: &str, expr: &str) -> String {
    if text.trim() == expr {
        String::new()
    } else {
        expr.to_owned()
    }
}

/// How many of `widths` fit in `avail` (items separated by `gap`) while leaving `reserve`
/// (the overflow-menu button) free whenever something does not fit.
pub fn fit_count(widths: &[f32], avail: f32, gap: f32, reserve: f32) -> usize {
    let total: f32 = widths.iter().map(|w| w + gap).sum();
    if total <= avail {
        return widths.len();
    }
    let (mut used, mut n) = (0.0, 0);
    for w in widths {
        if used + w + gap > avail - reserve {
            break;
        }
        used += w + gap;
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_composes_and_removes() {
        assert_eq!(toggle("", "tcp"), "tcp");
        assert_eq!(toggle("tcp", "dns"), "tcp || dns");
        assert_eq!(toggle("tcp || dns", "tcp"), "dns");
        assert_eq!(toggle("dns", "dns"), "");
        assert_eq!(toggle("ip.addr == 1.2.3.4", "tls"), "tls");
    }

    #[test]
    fn active_follows_text() {
        assert!(is_active("tcp || dns", "dns"));
        assert!(!is_active("tcp || dns", "udp"));
        assert!(!is_active("", "tcp"));
        assert!(is_active("tcp.port == 1", "tcp.port == 1"));
        assert!(!is_active("tcp.port == 1", "tcp"));
        assert!(is_active("  tcp||dns ", "tcp"));
    }

    #[test]
    fn presets_toggle() {
        let p = PRESETS[1].1;
        assert_eq!(toggle_preset("", p), p);
        assert_eq!(toggle_preset(p, p), "");
        assert_eq!(toggle_preset("tcp", p), p);
    }

    #[test]
    fn census_sorts_by_volume_and_merges_variants() {
        let mut c = Census::default();
        let tls12: Arc<str> = "TLSv1.2".into();
        let tls13: Arc<str> = "TLSv1.3".into();
        let dns: Arc<str> = "DNS".into();
        let tcp: Arc<str> = "TCP".into();
        for p in [&dns, &tls12, &tls13, &tcp, &tcp, &tcp, &tls13] {
            c.add(p);
        }
        let chips = c.chips();
        let got: Vec<_> = chips.iter().map(|c| (c.label.as_str(), c.count)).collect();
        assert_eq!(got, [("TCP", 3), ("TLS", 3), ("DNS", 1)]);
        c.clear();
        assert!(c.chips().is_empty());
    }

    #[test]
    fn fit_count_reserves_menu_room() {
        let w = [50.0; 6];
        assert_eq!(fit_count(&w, 400.0, 4.0, 90.0), 6);
        assert_eq!(fit_count(&w, 300.0, 4.0, 90.0), 3);
        assert_eq!(fit_count(&w, 10.0, 4.0, 90.0), 0);
        assert_eq!(fit_count(&[], 10.0, 4.0, 90.0), 0);
    }
}
