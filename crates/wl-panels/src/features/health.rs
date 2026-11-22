//! Plain-language "Why is my network slow?" diagnostic synthesis from Expert Info, PHS & stats.

use std::collections::BTreeMap;

use wl_kit::format;
use wl_model::{
    BehaviorData, ExpertReport, ExpertSeverity, HealthInsight, InsightSeverity, ProtocolHierarchy,
    SecurityData, StatsSnapshot, ThreatIntel,
};

use crate::insights::InsightRules;

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

/// Title of the all-clear card, which the findings list leaves out.
pub const HEALTHY_TITLE: &str = "Network capture looks healthy";

/// A group of findings of which only the strongest `max` are listed; the rest are counted.
#[derive(Clone, Copy)]
pub(super) struct Cap {
    pub name: &'static str,
    pub max: usize,
}

/// Collects findings: muted ones are dropped first, then each capped group keeps its first
/// `max` (callers push strongest first), so muting reveals what the cap had pushed out.
pub(super) struct Findings<'a> {
    rules: &'a InsightRules,
    pub cards: Vec<HealthInsight>,
    shown: BTreeMap<&'static str, (usize, usize)>,
    muted: usize,
}

impl<'a> Findings<'a> {
    pub fn new(rules: &'a InsightRules) -> Self {
        Self {
            rules,
            cards: Vec::new(),
            shown: BTreeMap::new(),
            muted: 0,
        }
    }

    fn admit(&mut self, cap: Option<Cap>, card: HealthInsight) {
        if self.rules.hides(&card) {
            self.muted += 1;
            return;
        }
        if let Some(cap) = cap {
            let (kept, dropped) = self.shown.entry(cap.name).or_default();
            if *kept >= cap.max {
                *dropped += 1;
                return;
            }
            *kept += 1;
        }
        self.cards.push(card);
    }

    /// Appends the notices for what was capped or muted and returns every card.
    pub fn finish(mut self) -> Vec<HealthInsight> {
        for (name, (kept, dropped)) in std::mem::take(&mut self.shown) {
            if dropped > 0 {
                self.cards.push(notice(
                    format!("{dropped} more {name} not shown"),
                    format!(
                        "Only the {kept} strongest {name} are listed. Mute the ones you have reviewed to see the others."
                    ),
                ));
            }
        }
        if self.muted > 0 {
            let n = self.muted;
            self.cards.push(notice(
                format!("{n} findings hidden by mutes"),
                format!(
                    "{n} findings match the muted patterns ({}). Remove a pattern in Settings > Insights to show them again.",
                    self.rules.muted.join(", ")
                ),
            ));
        }
        self.cards
    }
}

fn notice(title: String, explanation: String) -> HealthInsight {
    HealthInsight {
        severity: InsightSeverity::Info,
        title,
        explanation,
        suggested_filter: None,
        metric: String::new(),
    }
}

#[cfg(test)]
pub(super) fn collect(rules: &InsightRules, f: impl FnOnce(&mut Findings)) -> Vec<HealthInsight> {
    let mut out = Findings::new(rules);
    f(&mut out);
    out.finish()
}

pub(super) fn push_card(
    out: &mut Findings,
    severity: InsightSeverity,
    title: impl Into<String>,
    explanation: String,
    suggested_filter: Option<&str>,
    metric: String,
) {
    push_capped(
        out,
        None,
        severity,
        title,
        explanation,
        suggested_filter,
        metric,
    );
}

pub(super) fn push_capped(
    out: &mut Findings,
    cap: Option<Cap>,
    severity: InsightSeverity,
    title: impl Into<String>,
    explanation: String,
    suggested_filter: Option<&str>,
    metric: String,
) {
    out.admit(
        cap,
        HealthInsight {
            severity,
            title: title.into(),
            explanation,
            suggested_filter: suggested_filter.map(ToOwned::to_owned),
            metric,
        },
    );
}

fn analyze_expert(rep: &ExpertReport, total_packets: u64, out: &mut Findings) {
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

/// What the security and tuning parts of the findings are computed from.
#[derive(Clone, Copy)]
pub struct InsightContext<'a> {
    pub security: Option<&'a SecurityData>,
    pub intel: &'a ThreatIntel,
    pub rules: &'a InsightRules,
}

/// Synthesizes prioritized plain-language diagnostic cards with one-click Wireshark filters.
pub fn synthesize_insights(
    expert: Option<&ExpertReport>,
    phs: Option<&ProtocolHierarchy>,
    behavior: Option<&BehaviorData>,
    stats: &StatsSnapshot,
    cx: &InsightContext,
) -> Vec<HealthInsight> {
    let mut out = Findings::new(cx.rules);
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
        super::behavior::detect(data, &cx.rules.thresholds, &mut out);
    }
    let inputs = super::security::Inputs {
        security: cx.security,
        intel: cx.intel,
        hosts: &stats.hosts,
        dns: behavior.map_or(&[][..], |b| &b.dns),
        reveal_secrets: cx.rules.reveal_secrets,
    };
    super::security::detect(&inputs, &mut out);
    let mut out = out.finish();

    if out.is_empty() && total_packets > 0 {
        let n = format::count(total_packets);
        out.push(HealthInsight {
            severity: InsightSeverity::Info,
            title: HEALTHY_TITLE.to_owned(),
            explanation: format!(
                "No retransmissions, resets, DNS failures, or malformed frames across {n} packets."
            ),
            suggested_filter: None,
            metric: format!("{n} pkts"),
        });
    }

    out.sort_by_key(|i| i.severity);
    out
}
