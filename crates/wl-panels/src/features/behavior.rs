//! Behavioural findings from channel summaries and DNS names: port scans, sweeps, beaconing
//! and oversized DNS names. Pure functions over `BehaviorData`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use wl_kit::format;
use wl_model::{BehaviorData, Channel, ChannelKind, HealthInsight, InsightSeverity, Proto};

use super::health::push_card;

const SCAN_MIN_PORTS: usize = 20;
const SWEEP_MIN_HOSTS: usize = 20;
const SWEEP_MAX_TRIES_PER_HOST: u32 = 3;
/// Ports where contacting many hosts is ordinary client behaviour, not a sweep.
const BUSY_PORTS: [u16; 5] = [53, 80, 443, 8080, 8443];
const BEACON_MIN_EVENTS: u32 = 8;
const BEACON_MIN_PERIOD: f64 = 1.0;
const BEACON_MAX_JITTER: f64 = 0.1;
const DNS_LONG_NAME: usize = 60;
const DNS_LONG_LABEL: usize = 40;
const MAX_CARDS_PER_KIND: usize = 3;

type Addr = Arc<str>;

pub fn detect(data: &BehaviorData, out: &mut Vec<HealthInsight>) {
    port_scans(&data.channels, out);
    sweeps(&data.channels, out);
    beacons(&data.channels, out);
    long_dns_names(data, out);
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

fn attempts_filter(c: &Channel) -> String {
    let what = match c.proto {
        Proto::Tcp => "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        Proto::Udp => "udp",
        Proto::Icmp if is_v6(&c.src) => "icmpv6.type == 128",
        Proto::Icmp => "icmp.type == 8",
    };
    format!("{} && {what}", src_filter(c))
}

fn port_scans(channels: &[Channel], out: &mut Vec<HealthInsight>) {
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
        .filter(|(_, (p, _))| p.len() >= SCAN_MIN_PORTS)
        .collect();
    hits.sort_by_key(|(_, (p, _))| std::cmp::Reverse(p.len()));
    for ((src, dst, proto), (p, c)) in hits.into_iter().take(MAX_CARDS_PER_KIND) {
        let flt = format!("{} && {}", attempts_filter(c), dst_filter(dst));
        push_card(
            out,
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
fn sweeps(channels: &[Channel], out: &mut Vec<HealthInsight>) {
    let mut targets: BTreeMap<(&Addr, Proto, u16), (BTreeSet<&Addr>, &Channel)> = BTreeMap::new();
    for c in new_flows(channels)
        .filter(|c| c.proto != Proto::Udp && !BUSY_PORTS.contains(&c.dport))
        .filter(|c| c.count <= SWEEP_MAX_TRIES_PER_HOST)
    {
        targets
            .entry((&c.src, c.proto, c.dport))
            .or_insert_with(|| (BTreeSet::new(), c))
            .0
            .insert(&c.dst);
    }
    let mut hits: Vec<_> = targets
        .into_iter()
        .filter(|(_, (t, _))| t.len() >= SWEEP_MIN_HOSTS)
        .collect();
    hits.sort_by_key(|(_, (t, _))| std::cmp::Reverse(t.len()));
    for ((src, proto, port), (t, c)) in hits.into_iter().take(MAX_CARDS_PER_KIND) {
        let (what, flt) = match proto {
            Proto::Icmp => ("ping sweep".to_owned(), attempts_filter(c)),
            _ => (
                format!("{} sweep on port {port}", proto.label()),
                format!("{} && tcp.dstport == {port}", attempts_filter(c)),
            ),
        };
        push_card(
            out,
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

fn beacons(channels: &[Channel], out: &mut Vec<HealthInsight>) {
    let mut hits: Vec<&Channel> = channels
        .iter()
        .filter(|c| c.proto != Proto::Icmp && c.count >= BEACON_MIN_EVENTS)
        .filter(|c| c.gap_mean >= BEACON_MIN_PERIOD && c.gap_jitter <= BEACON_MAX_JITTER)
        .collect();
    hits.sort_by(|a, b| a.gap_jitter.total_cmp(&b.gap_jitter));
    for c in hits.into_iter().take(MAX_CARDS_PER_KIND) {
        let (title, unit, flt) = match c.kind {
            ChannelKind::NewFlows => (
                "Regular connections",
                "connections",
                format!("{} && {}", attempts_filter(c), dst_filter(&c.dst)),
            ),
            ChannelKind::Stream => (
                "Regular traffic in one connection",
                "data packets",
                format!(
                    "{} && {} && tcp.dstport == {} && tcp.len > 0",
                    src_filter(c),
                    dst_filter(&c.dst),
                    c.dport
                ),
            ),
        };
        let every = format::duration(c.gap_mean);
        push_card(
            out,
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

fn is_long(name: &str) -> bool {
    name.len() >= DNS_LONG_NAME || name.split('.').any(|l| l.len() >= DNS_LONG_LABEL)
}

fn long_dns_names(data: &BehaviorData, out: &mut Vec<HealthInsight>) {
    let long: Vec<_> = data.dns.iter().filter(|q| is_long(&q.name)).collect();
    let Some(first) = long.first() else { return };
    let severity = if long.len() >= 5 {
        InsightSeverity::Warning
    } else {
        InsightSeverity::Info
    };
    let distinct: BTreeSet<_> = long.iter().map(|q| q.name.as_str()).collect();
    push_card(
        out,
        severity,
        "Unusually long DNS names",
        format!(
            "{} queries use names of {DNS_LONG_NAME}+ characters (e.g. {}). Long or random-looking names can indicate DNS tunnelling or generated domains.",
            long.len(),
            first.name
        ),
        Some(&format!("dns.qry.name.len >= {DNS_LONG_NAME}")),
        format!("{} names", distinct.len()),
    );
}

#[cfg(test)]
#[path = "behavior_tests.rs"]
mod tests;
