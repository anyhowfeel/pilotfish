//! Actions emitted by the Insights page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsightsAction {
    /// Apply this display filter and jump to Packets.
    ApplyFilter(String),
    /// Re-run tshark analysis.
    Refresh,
    /// Export the HTML report.
    ExportReport,
    /// The DNS tab is visible without data: scan the capture (answer via `dns_mut().set_state`).
    LoadDns,
    /// Select this frame in Packets and switch to that page.
    ShowInPackets(u64),
    /// Hide findings whose title matches this host or pattern from now on.
    Mute(String),
}
