//! Pure filter + sort of host rows (returns indices into the snapshot).

use std::cmp::Ordering;

use wl_model::HostStat;

use crate::overview::sort::SortState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCol {
    Address,
    Scope,
    PacketsIn,
    PacketsOut,
    BytesIn,
    BytesOut,
    Total,
}

/// Display filter selecting every packet of this host.
pub fn host_filter(addr: &str) -> String {
    let field = if addr.contains(':') {
        "ipv6.addr"
    } else {
        "ip.addr"
    };
    format!("{field} == {addr}")
}

pub fn total_bytes(h: &HostStat) -> u64 {
    h.bytes_in + h.bytes_out
}

/// Case-insensitive substring match on the address or the resolved name.
pub fn matches(h: &HostStat, needle: &str, name: Option<&str>) -> bool {
    if needle.is_empty() {
        return true;
    }
    let n = needle.to_lowercase();
    h.addr.to_lowercase().contains(&n) || name.is_some_and(|s| s.to_lowercase().contains(&n))
}

fn cmp(a: &HostStat, b: &HostStat, col: HostCol) -> Ordering {
    match col {
        HostCol::Address => a.addr.cmp(&b.addr),
        HostCol::Scope => a.is_private.cmp(&b.is_private),
        HostCol::PacketsIn => a.packets_in.cmp(&b.packets_in),
        HostCol::PacketsOut => a.packets_out.cmp(&b.packets_out),
        HostCol::BytesIn => a.bytes_in.cmp(&b.bytes_in),
        HostCol::BytesOut => a.bytes_out.cmp(&b.bytes_out),
        HostCol::Total => total_bytes(a).cmp(&total_bytes(b)),
    }
}

pub fn visible(
    hosts: &[HostStat],
    filter: &str,
    sort: SortState<HostCol>,
    name_of: &dyn Fn(&str) -> Option<std::sync::Arc<str>>,
) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..hosts.len())
        .filter(|&i| matches(&hosts[i], filter, name_of(&hosts[i].addr).as_deref()))
        .collect();
    idx.sort_by(|&a, &b| {
        let o = cmp(&hosts[a], &hosts[b], sort.col).then_with(|| hosts[a].addr.cmp(&hosts[b].addr));
        if sort.desc { o.reverse() } else { o }
    });
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(addr: &str, bi: u64, bo: u64, private: bool) -> HostStat {
        HostStat {
            addr: addr.into(),
            bytes_in: bi,
            bytes_out: bo,
            is_private: private,
            ..Default::default()
        }
    }

    #[test]
    fn sorts_and_filters() {
        let hosts = [
            h("10.0.0.1", 5, 5, true),
            h("8.8.8.8", 100, 0, false),
            h("1.1.1.1", 1, 1, false),
        ];
        let none = |_: &str| None;
        let v = visible(&hosts, "", SortState::new(HostCol::Total, true), &none);
        assert_eq!(v, vec![1, 0, 2]);
        let v = visible(&hosts, "", SortState::new(HostCol::Address, false), &none);
        assert_eq!(v, vec![2, 0, 1]);
        let v = visible(&hosts, "8.8", SortState::new(HostCol::Total, true), &none);
        assert_eq!(v, vec![1]);
    }

    #[test]
    fn host_filter_picks_family() {
        assert_eq!(host_filter("1.2.3.4"), "ip.addr == 1.2.3.4");
        assert_eq!(host_filter("fe80::1"), "ipv6.addr == fe80::1");
    }

    #[test]
    fn filter_uses_resolved_name() {
        let hosts = [h("1.1.1.1", 1, 1, false)];
        let named = |_: &str| Some(std::sync::Arc::<str>::from("one.one.one.one"));
        let v = visible(
            &hosts,
            "ONE.one",
            SortState::new(HostCol::Total, true),
            &named,
        );
        assert_eq!(v, vec![0]);
    }
}
