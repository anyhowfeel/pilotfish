//! Behavioural findings from channel summaries and DNS names: port scans, sweeps, beaconing
//! and oversized DNS names. Pure functions over `BehaviorData`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use wl_kit::format;
use wl_model::{BehaviorData, Channel, ChannelKind, InsightSeverity, Proto};

use super::health::{Cap, Findings, push_capped};
use crate::insights::Thresholds;

/// Ports where contacting many hosts is ordinary client behaviour, not a sweep.
const BUSY_PORTS: [u16; 5] = [53, 80, 443, 8080, 8443];
const PER_KIND: usize = 3;
const SCANS: Cap = Cap {
    name: "port scans",
    max: PER_KIND,
};
const SWEEPS: Cap = Cap {
    name: "host sweeps",
    max: PER_KIND,
};
const RHYTHMS: Cap = Cap {
    name: "regular traffic patterns",
    max: PER_KIND,
};

type Addr = Arc<str>;

pub fn detect(data: &BehaviorData, th: &Thresholds, out: &mut Findings) {
    port_scans(&data.channels, th, out);
    sweeps(&data.channels, th, out);
    beacons(&data.channels, th, out);
    long_dns_names(data, th, out);
}

fn new_flows(channels: &[Channel]) -> impl Iterator<Item = &Channel> {
    channels.iter().filter(|c| c.kind == ChannelKind::NewFlows)
}

fn is_v6(addr: &str) -> bool {
    addr.contains(':')
}

fn src_filter(c: &Channel) -> String {
    let field = if is_v6(&c.src) { "ipv6.src" } else { "ip.src" };
    format!("{field} == {}", c.src)
}

fn dst_filter(addr: &str) -> String {
    let field = if is_v6(addr) { "ipv6.dst" } else { "ip.dst" };
    format!("{field} == {addr}")
}

fn dport_filter(c: &Channel) -> String {
    let proto = match c.proto {
        Proto::Udp => "udp",
        Proto::Tcp | Proto::Icmp => "tcp",
    };
    format!("{proto}.dstport == {}", c.dport)
}

fn attempts_filter(c: &Channel) -> String {
    let what = match c.proto {
        Proto::Tcp => "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        Proto::Udp => "udp",
        Proto::Icmp if is_v6(&c.src) => "icmpv6.type == 128",
        Proto::Icmp => "icmp.type == 8",
    };
    format!("{} && {what}", src_filter(c))
}

fn port_scans(channels: &[Channel], th: &Thresholds, out: &mut Findings) {
    let mut ports: BTreeMap<(&Addr, &Addr, Proto), (BTreeSet<u16>, &Channel)> = BTreeMap::new();
    for c in new_flows(channels).filter(|c| c.proto != Proto::Icmp) {
        ports
            .entry((&c.src, &c.dst, c.proto))
            .or_insert_with(|| (BTreeSet::new(), c))
            .0
            .insert(c.dport);
    }
    let mut hits: Vec<_> = ports
        .into_iter()
        .filter(|(_, (p, _))| p.len() >= th.scan_min_ports as usize)
        .collect();
    hits.sort_by_key(|(_, (p, _))| std::cmp::Reverse(p.len()));
    for ((src, dst, proto), (p, c)) in hits {
        let flt = format!("{} && {}", attempts_filter(c), dst_filter(dst));
        push_capped(
            out,
            Some(SCANS),
            InsightSeverity::Warning,
            format!("{} port scan: {src} probes {dst}", proto.label()),
            format!(
                "{src} contacted {} different {} ports on {dst}, a typical scan pattern.",
                p.len(),
                proto.label()
            ),
            Some(&flt),
            format!("{} ports", p.len()),
        );
    }
}

/// Same port tried on many hosts, a few times each: ping sweeps and service hunting.
fn sweeps(channels: &[Channel], th: &Thresholds, out: &mut Findings) {
    let mut targets: BTreeMap<(&Addr, Proto, u16), (BTreeSet<&Addr>, &Channel)> = BTreeMap::new();
    for c in new_flows(channels)
        .filter(|c| c.proto != Proto::Udp && !BUSY_PORTS.contains(&c.dport))
        .filter(|c| c.count <= th.sweep_max_tries_per_host)
    {
        targets
            .entry((&c.src, c.proto, c.dport))
            .or_insert_with(|| (BTreeSet::new(), c))
            .0
            .insert(&c.dst);
    }
    let mut hits: Vec<_> = targets
        .into_iter()
        .filter(|(_, (t, _))| t.len() >= th.sweep_min_hosts as usize)
        .collect();
    hits.sort_by_key(|(_, (t, _))| std::cmp::Reverse(t.len()));
    for ((src, proto, port), (t, c)) in hits {
        let (what, flt) = match proto {
            Proto::Icmp => ("ping sweep".to_owned(), attempts_filter(c)),
            _ => (
                format!("{} sweep on port {port}", proto.label()),
                format!("{} && tcp.dstport == {port}", attempts_filter(c)),
            ),
        };
        push_capped(
            out,
            Some(SWEEPS),
            InsightSeverity::Warning,
            format!("Host {what} from {src}"),
            format!(
                "{src} tried {} different hosts, only a few times each.",
                t.len()
            ),
            Some(&flt),
            format!("{} hosts", t.len()),
        );
    }
}

fn beacons(channels: &[Channel], th: &Thresholds, out: &mut Findings) {
    let min_period = f64::from(th.beacon_min_period_secs);
    let max_jitter = f64::from(th.beacon_max_jitter_pct) / 100.0;
    let mut hits: Vec<&Channel> = channels
        .iter()
        .filter(|c| c.proto != Proto::Icmp && c.count >= th.beacon_min_events)
        .filter(|c| c.gap_mean >= min_period && c.gap_jitter <= max_jitter)
        .collect();
    hits.sort_by(|a, b| a.gap_jitter.total_cmp(&b.gap_jitter));
    for c in hits {
        let (title, unit, flt) = match c.kind {
            ChannelKind::NewFlows => (
                "Regular connections",
                "connections",
                format!(
                    "{} && {} && {}",
                    attempts_filter(c),
                    dst_filter(&c.dst),
                    dport_filter(c)
                ),
            ),
            ChannelKind::Stream => (
                "Regular traffic in one connection",
                "data packets",
                format!(
                    "{} && {} && {} && tcp.len > 0",
                    src_filter(c),
                    dst_filter(&c.dst),
                    dport_filter(c)
                ),
            ),
        };
        let every = format::duration(c.gap_mean);
        push_capped(
            out,
            Some(RHYTHMS),
            InsightSeverity::Warning,
            format!(
                "{title}: {} to {}:{} ({})",
                c.src,
                c.dst,
                c.dport,
                c.proto.label()
            ),
            format!(
                "{} {unit} about every {every} (variation {:.0}%). Machine-driven timing like this is typical of beaconing, but also of polling and keep-alives.",
                c.count,
                c.gap_jitter * 100.0
            ),
            Some(&flt),
            format!("every {every}"),
        );
    }
}

fn is_long(name: &str, th: &Thresholds) -> bool {
    name.len() >= th.dns_long_name as usize
        || name
            .split('.')
            .any(|l| l.len() >= th.dns_long_label as usize)
}

fn long_dns_names(data: &BehaviorData, th: &Thresholds, out: &mut Findings) {
    let long: Vec<_> = data.dns.iter().filter(|q| is_long(&q.name, th)).collect();
    let Some(first) = long.first() else { return };
    let severity = if long.len() >= 5 {
        InsightSeverity::Warning
    } else {
        InsightSeverity::Info
    };
    let distinct: BTreeSet<_> = long.iter().map(|q| q.name.as_str()).collect();
    push_capped(
        out,
        None,
        severity,
        "Unusually long DNS names",
        format!(
            "{} queries use names of {}+ characters or labels of {}+ characters (e.g. {}). Long or random-looking names can indicate DNS tunnelling or generated domains.",
            long.len(),
            th.dns_long_name,
            th.dns_long_label,
            first.name
        ),
        Some(&format!(
            "dns.qry.name.len >= {} || dns.qry.name matches \"[^.]{{{},}}\"",
            th.dns_long_name, th.dns_long_label
        )),
        format!("{} names", distinct.len()),
    );
}

#[cfg(test)]
#[path = "behavior_tests.rs"]
mod tests;
