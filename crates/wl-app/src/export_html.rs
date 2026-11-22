//! Self-contained HTML5 summary report generator (zero external assets, XSS-safe).

use std::fmt::Write as _;
use std::path::Path;

use wl_kit::format;
use wl_model::{ExpertReport, HealthInsight, InsightSeverity, ProtocolHierarchy, StatsSnapshot};

use crate::export_data::ExportError;
use crate::report_bookmarks::BookmarkedPacket;

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const REPORT_CSS: &str = ":root{color-scheme:dark light;--bg:#0f1117;--card:#1a1e2a;--bdr:#2b3144;--fg:#e6e8f0;--mut:#8a90a8;--acc:#7c86f7;--ok:#3dd68c;--warn:#f5b94a;--err:#f2616f}\
@media(prefers-color-scheme:light){:root{--bg:#f3f4f9;--card:#fff;--bdr:#d9dce8;--fg:#1c2030;--mut:#677089}}\
body{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:1040px;margin:24px auto;padding:0 16px}\
h1,h2{margin:0 0 12px}h2{margin-top:24px;font-size:16px;border-bottom:1px solid var(--bdr);padding-bottom:6px}\
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}\
.card{background:var(--card);border:1px solid var(--bdr);border-radius:8px;padding:12px}\
.kpi{font:600 22px monospace}.mut{color:var(--mut);font-size:12px}\
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bdr)}\
th,td{padding:6px 10px;border-bottom:1px solid var(--bdr);text-align:left}th{color:var(--mut);font-size:12px}\
.num{text-align:right;font-family:monospace}.tag{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:600}\
.crit{background:#f2616f33;color:var(--err)}.warn{background:#f5b94a33;color:var(--warn)}.info{background:#3dd68c33;color:var(--ok)}\
code{font-family:monospace;font-size:12px}";

/// Builds a self-contained HTML5 summary report with inline CSS.
pub fn build_html_report(
    title: &str,
    stats: &StatsSnapshot,
    insights: &[HealthInsight],
    phs: Option<&ProtocolHierarchy>,
    expert: Option<&ExpertReport>,
    bookmarks: &[BookmarkedPacket],
) -> String {
    let mut h = String::with_capacity(4096);
    let safe_title = html_escape(title);
    let _ = write!(
        h,
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{safe_title} — pilotfish report</title><style>{REPORT_CSS}</style></head><body>\
<h1>pilotfish Report: {safe_title}</h1>\
<div class=\"grid\">\
<div class=\"card\"><div class=\"mut\">Packets</div><div class=\"kpi\">{}</div></div>\
<div class=\"card\"><div class=\"mut\">Total Bytes</div><div class=\"kpi\">{}</div></div>\
<div class=\"card\"><div class=\"mut\">Protocols</div><div class=\"kpi\">{}</div></div>\
<div class=\"card\"><div class=\"mut\">Hosts</div><div class=\"kpi\">{}</div></div>\
</div>",
        format::count(stats.total_packets),
        format::bytes(stats.total_bytes),
        stats.protocols.len(),
        stats.hosts.len(),
    );

    if !insights.is_empty() {
        h.push_str("<h2>Network Health Insights</h2>");
        for ins in insights {
            let cls = match ins.severity {
                InsightSeverity::Critical => "crit",
                InsightSeverity::Warning => "warn",
                InsightSeverity::Info => "info",
            };
            let flt = ins
                .suggested_filter
                .as_deref()
                .map(|f| {
                    format!(
                        " <span class=\"mut\">Filter:</span> <code>{}</code>",
                        html_escape(f)
                    )
                })
                .unwrap_or_default();
            let _ = write!(
                h,
                "<div class=\"card\" style=\"margin-bottom:8px\"><span class=\"tag {cls}\">{}</span> <strong>{}</strong><div class=\"mut\">{}</div>{flt}</div>",
                html_escape(&ins.metric),
                html_escape(&ins.title),
                html_escape(&ins.explanation),
            );
        }
    }

    if !stats.protocols.is_empty() {
        h.push_str("<h2>Top Protocols</h2><table><tr><th>Protocol</th><th class=\"num\">Packets</th><th class=\"num\">Bytes</th></tr>");
        for p in stats.protocols.iter().take(15) {
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                html_escape(&p.name),
                format::count(p.packets),
                format::bytes(p.bytes),
            );
        }
        h.push_str("</table>");
    }

    if let Some(tree) = phs.filter(|t| !t.nodes.is_empty()) {
        h.push_str("<h2>Protocol Hierarchy</h2><table><tr><th>Protocol</th><th class=\"num\">Frames</th><th class=\"num\">Bytes</th><th class=\"num\">Share</th></tr>");
        for n in &tree.nodes {
            let pad = usize::from(n.depth) * 14;
            let _ = write!(
                h,
                "<tr><td style=\"padding-left:{pad}px\"><code>{}</code></td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\">{:.1}%</td></tr>",
                html_escape(&n.protocol),
                format::count(n.frames),
                format::bytes(n.bytes),
                n.byte_pct,
            );
        }
        h.push_str("</table>");
    }

    if let Some(rep) = expert.filter(|r| !r.entries.is_empty()) {
        h.push_str("<h2>Expert Info</h2><table><tr><th>Severity</th><th class=\"num\">Freq</th><th>Protocol</th><th>Summary</th></tr>");
        for e in rep.entries.iter().take(40) {
            let _ = write!(
                h,
                "<tr><td>{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td></tr>",
                e.severity.label(),
                format::count(e.frequency),
                html_escape(&e.protocol),
                html_escape(&e.summary),
            );
        }
        h.push_str("</table>");
    }

    if !bookmarks.is_empty() {
        h.push_str("<h2>Bookmarked Packets</h2><table><tr><th class=\"num\">Frame</th><th class=\"num\">Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th><th>Comment</th></tr>");
        for b in bookmarks {
            let _ = write!(
                h,
                "<tr><td class=\"num\">#{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                b.frame_no,
                html_escape(&b.time),
                html_escape(&b.src),
                html_escape(&b.dst),
                html_escape(&b.protocol),
                html_escape(&b.info),
                html_escape(&b.comment),
            );
        }
        h.push_str("</table>");
    }
    h.push_str("</body></html>");
    h
}

pub fn write_html_report(
    path: &Path,
    title: &str,
    stats: &StatsSnapshot,
    insights: &[HealthInsight],
    phs: Option<&ProtocolHierarchy>,
    expert: Option<&ExpertReport>,
    bookmarks: &[BookmarkedPacket],
) -> Result<(), ExportError> {
    let html = build_html_report(title, stats, insights, phs, expert, bookmarks);
    std::fs::write(path, html).map_err(|source| ExportError::Io {
        path: path.display().to_string(),
        source,
    })
}
