//! Plain-language "Why is my network slow?" diagnostic synthesis from Expert Info, PHS & stats.

use wl_kit::format;
use wl_model::{
    BehaviorData, ExpertReport, ExpertSeverity, HealthInsight, InsightSeverity, ProtocolHierarchy,
    StatsSnapshot,
};

fn has_any(s: &str, needles: &[&str]) -> bool {
    needles.iter().any(|k| s.contains(k))
}

fn sum_matching(report: &ExpertReport, pred: impl Fn(&str, &str) -> bool) -> u64 {
    report
        .entries
        .iter()
        .filter(|e| {
            pred(
                &e.protocol.to_ascii_lowercase(),
                &e.summary.to_ascii_lowercase(),
            )
        })
        .map(|e| e.frequency)
        .sum()
}

pub(super) fn push_card(
    out: &mut Vec<HealthInsight>,
    severity: InsightSeverity,
    title: impl Into<String>,
    explanation: String,
    suggested_filter: Option<&str>,
    metric: String,
) {
    out.push(HealthInsight {
        severity,
        title: title.into(),
        explanation,
        suggested_filter: suggested_filter.map(ToOwned::to_owned),
        metric,
    });
}

fn analyze_expert(rep: &ExpertReport, total_packets: u64, out: &mut Vec<HealthInsight>) {
    let errors = rep.count_by_severity(ExpertSeverity::Error);
    if errors > 0 {
        let n = format::count(errors);
        push_card(
            out,
            InsightSeverity::Critical,
            "Malformed or broken protocol frames detected",
            format!("{n} protocol errors flagged by dissectors; corrupted frames can break flows."),
            Some("_ws.malformed || _ws.expert.severity == error"),
            format!("{n} errors"),
        );
    }

    let retrans = sum_matching(rep, |p, s| {
        p == "tcp"
            && has_any(
                s,
                &[
                    "retransmission",
                    "lost segment",
                    "out-of-order",
                    "dup ack",
                    "duplicate ack",
                ],
            )
    });
    if retrans > 0 {
        let sev = if total_packets > 0 && (retrans * 100) / total_packets >= 2 {
            InsightSeverity::Critical
        } else {
            InsightSeverity::Warning
        };
        let n = format::count(retrans);
        push_card(
            out,
            sev,
            "TCP packet loss or retransmissions slowing transfers",
            format!(
                "{n} TCP recovery events (retransmissions/lost segments/dup ACKs) stall throughput."
            ),
            Some(
                "tcp.analysis.retransmission || tcp.analysis.lost_segment || tcp.analysis.dup_ack",
            ),
            format!("{n} TCP events"),
        );
    }

    let checks: &[(&str, &str, &str, &str, u64)] = &[
        (
            "Abrupt TCP connection resets (RST)",
            "connections terminated with RST (crashed server, firewall rejection, or timeout).",
            "tcp.flags.reset == 1",
            "resets",
            sum_matching(rep, |p, s| p == "tcp" && has_any(s, &["reset", "rst"])),
        ),
        (
            "DNS lookups are retrying or failing",
            "DNS/mDNS warnings detected; failing resolution adds delay before connections start.",
            "dns.flags.rcode != 0 || dns.retransmission || mdns",
            "DNS warnings",
            sum_matching(rep, |p, s| {
                p.contains("dns")
                    && has_any(
                        s,
                        &[
                            "retransmission",
                            "error",
                            "no such name",
                            "servfail",
                            "refused",
                        ],
                    )
            }),
        ),
        (
            "ICMP unreachable or error messages seen",
            "ICMP/ICMPv6 errors indicate blocked ports, unreachable hosts, or MTU/routing issues.",
            "icmp.type == 3 || icmpv6.type < 128",
            "ICMP errors",
            sum_matching(rep, |p, s| {
                matches!(p, "icmp" | "icmpv6") && s.contains("error")
            }),
        ),
    ];
    for &(title, detail, flt, unit, cnt) in checks {
        if cnt > 0 {
            let n = format::count(cnt);
            push_card(
                out,
                InsightSeverity::Warning,
                title,
                format!("{n} {detail}"),
                Some(flt),
                format!("{n} {unit}"),
            );
        }
    }

    let warns = rep.count_by_severity(ExpertSeverity::Warn);
    if total_packets >= 20 && ((errors + warns) * 100) / total_packets >= 5 {
        let pct = ((errors + warns) as f64 / total_packets as f64) * 100.0;
        push_card(
            out,
            InsightSeverity::Warning,
            "Elevated anomaly rate across capture",
            format!("{pct:.1}% of frames triggered a warning or error; inspect Expert Info."),
            Some("_ws.expert.severity >= warning"),
            format!("{pct:.1}%"),
        );
    }
}

/// Synthesizes prioritized plain-language diagnostic cards with one-click Wireshark filters.
pub fn synthesize_insights(
    expert: Option<&ExpertReport>,
    phs: Option<&ProtocolHierarchy>,
    behavior: Option<&BehaviorData>,
    stats: &StatsSnapshot,
) -> Vec<HealthInsight> {
    let mut out = Vec::new();
    let total_packets = stats.total_packets.max(phs.map_or(0, |p| p.total_frames));

    if let Some(rep) = expert {
        analyze_expert(rep, total_packets, &mut out);
    }

    if total_packets >= 10
        && stats.total_bytes > 0
        && let Some(top) = stats.hosts.first()
    {
        let host_bytes = top.bytes_in + top.bytes_out;
        let denom = stats
            .hosts
            .iter()
            .map(|h| h.bytes_in + h.bytes_out)
            .sum::<u64>()
            .max(stats.total_bytes);
        let share = ((host_bytes as f64 / denom as f64) * 100.0).min(100.0);
        if share >= 65.0 {
            let field = if top.addr.contains(':') {
                "ipv6.addr"
            } else {
                "ip.addr"
            };
            let flt = format!("{field} == {}", top.addr);
            push_card(
                &mut out,
                InsightSeverity::Info,
                format!("Single dominant talker: {}", top.addr),
                format!(
                    "{} accounts for {share:.0}% of traffic ({}).",
                    top.addr,
                    format::bytes(host_bytes)
                ),
                Some(&flt),
                format!("{share:.0}% of bytes"),
            );
        }
    }

    if let Some(data) = behavior {
        super::behavior::detect(data, &mut out);
    }

    if out.is_empty() && total_packets > 0 {
        let n = format::count(total_packets);
        push_card(
            &mut out,
            InsightSeverity::Info,
            "Network capture looks healthy",
            format!(
                "No retransmissions, resets, DNS failures, or malformed frames across {n} packets."
            ),
            None,
            format!("{n} pkts"),
        );
    }

    out.sort_by_key(|i| i.severity);
    out
}
