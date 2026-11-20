//! Command Palette item definitions, `#N` frame jump parser, and fuzzy matcher.

use std::cmp::Reverse;

/// Navigation destinations reachable from the Command Palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PalettePage {
    Setup,
    Overview,
    Graphs,
    Packets,
    Hosts,
    Conversations,
    Web,
    Insights,
}

/// High-level action emitted when the user activates a command in `CommandPalette`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaletteAction {
    GoToPage(PalettePage),
    JumpToFrame(u64),
    ApplyFilter(String),
    ToggleTheme,
    OpenSettings,
    ExportCsv,
    ExportStatsJson,
    ExportHtmlReport,
    OpenPcap,
    FileProperties,
    TogglePause,
    StopCapture,
    /// Web page, Files tab (File > Export Objects).
    ExportObjects,
    /// Open the Decode As dialog.
    DecodeAs,
    /// Insights page, DNS tab.
    DnsLog,
}

#[derive(Debug, Clone)]
pub struct PaletteEntry {
    pub category: &'static str,
    pub label: String,
    pub hint: &'static str,
    pub action: PaletteAction,
}

/// Parses `#123`, `frame 123`, or plain `123` as a 1-based frame jump target.
pub fn parse_frame_jump(q: &str) -> Option<u64> {
    let trimmed = q.trim();
    let num = trimmed
        .strip_prefix('#')
        .or_else(|| trimmed.strip_prefix("frame "))
        .or_else(|| trimmed.strip_prefix("goto "))
        .unwrap_or(trimmed)
        .trim();
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    num.parse::<u64>().ok().filter(|&n| n > 0)
}

/// Case-insensitive fuzzy subsequence scorer. Returns `None` when `query` doesn't match.
pub fn fuzzy_score(query: &str, candidate: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let q: Vec<char> = query.to_ascii_lowercase().chars().collect();
    let c: Vec<char> = candidate.to_ascii_lowercase().chars().collect();
    let (mut qi, mut score, mut streak) = (0usize, 0i32, 0i32);
    for (ci, &ch) in c.iter().enumerate() {
        if qi < q.len() && ch == q[qi] {
            qi += 1;
            streak += 1;
            score += 10 + streak * 4;
            if ci == 0 || matches!(c[ci - 1], ' ' | ':' | '.' | '/' | '-') {
                score += 8;
            }
        } else {
            streak = 0;
        }
    }
    (qi == q.len()).then_some(score - (c.len() as i32 / 4))
}

/// Computes ranked matches for `query` (including `#N` frame jumps).
pub fn matches_for(query: &str) -> Vec<PaletteEntry> {
    let q = query.trim();
    let mut out = Vec::new();
    if let Some(frame_no) = parse_frame_jump(q) {
        out.push(PaletteEntry {
            category: "Jump",
            label: format!("Jump to frame #{frame_no}"),
            hint: "Enter",
            action: PaletteAction::JumpToFrame(frame_no),
        });
    }
    let mut scored: Vec<(i32, PaletteEntry)> = builtin_entries()
        .into_iter()
        .filter_map(|e| {
            let hay = format!("{} {}", e.category, e.label);
            fuzzy_score(q, &hay).map(|score| (score, e))
        })
        .collect();
    scored.sort_by_key(|a| Reverse(a.0));
    out.extend(scored.into_iter().map(|(_, e)| e));
    out
}

fn entry(
    category: &'static str,
    label: &str,
    hint: &'static str,
    action: PaletteAction,
) -> PaletteEntry {
    PaletteEntry {
        category,
        label: label.to_owned(),
        hint,
        action,
    }
}

fn builtin_entries() -> Vec<PaletteEntry> {
    use PaletteAction as A;
    use PalettePage as P;
    vec![
        entry(
            "Page",
            "Go to Capture Setup",
            "Setup",
            A::GoToPage(P::Setup),
        ),
        entry(
            "Page",
            "Go to Overview Dashboard",
            "Overview",
            A::GoToPage(P::Overview),
        ),
        entry("Page", "Go to I/O Graphs", "Graphs", A::GoToPage(P::Graphs)),
        entry(
            "File",
            "Capture File Properties",
            "capinfos",
            A::FileProperties,
        ),
        entry("Page", "Go to Packets", "Packets", A::GoToPage(P::Packets)),
        entry("Page", "Go to Hosts", "Hosts", A::GoToPage(P::Hosts)),
        entry(
            "Page",
            "Go to Conversations",
            "Flows",
            A::GoToPage(P::Conversations),
        ),
        entry(
            "Page",
            "Go to Web (HTTP and HTTPS)",
            "Web",
            A::GoToPage(P::Web),
        ),
        entry(
            "Page",
            "Go to Network Health Insights",
            "Insights",
            A::GoToPage(P::Insights),
        ),
        entry(
            "Filter",
            "Filter: TCP traffic (tcp)",
            "tcp",
            A::ApplyFilter("tcp".into()),
        ),
        entry(
            "Filter",
            "Filter: DNS queries (dns)",
            "dns",
            A::ApplyFilter("dns".into()),
        ),
        entry(
            "Filter",
            "Filter: HTTP requests (http)",
            "http",
            A::ApplyFilter("http".into()),
        ),
        entry(
            "Filter",
            "Filter: TLS handshakes (tls)",
            "tls",
            A::ApplyFilter("tls".into()),
        ),
        entry(
            "Filter",
            "Filter: TCP retransmissions",
            "retrans",
            A::ApplyFilter("tcp.analysis.retransmission".into()),
        ),
        entry(
            "Filter",
            "Clear display filter",
            "reset",
            A::ApplyFilter(String::new()),
        ),
        entry("View", "Toggle Dark / Light Theme", "Theme", A::ToggleTheme),
        entry("View", "Open Settings", "Ctrl+,", A::OpenSettings),
        entry("Export", "Export Packets as CSV", ".csv", A::ExportCsv),
        entry("Export", "Export objects...", "Files", A::ExportObjects),
        entry("Analyze", "Decode As...", "tcp.port", A::DecodeAs),
        entry("Analyze", "DNS query log", "DNS", A::DnsLog),
        entry(
            "Export",
            "Export Stats & Insights as JSON",
            ".json",
            A::ExportStatsJson,
        ),
        entry(
            "Export",
            "Export Self-Contained HTML Report",
            ".html",
            A::ExportHtmlReport,
        ),
        entry("File", "Open pcap / pcapng file...", "Open", A::OpenPcap),
        entry(
            "Capture",
            "Toggle Pause / Resume Capture",
            "Pause",
            A::TogglePause,
        ),
        entry("Capture", "Stop Active Capture", "Stop", A::StopCapture),
    ]
}

#[cfg(test)]
#[path = "palette_items_tests.rs"]
mod tests;
