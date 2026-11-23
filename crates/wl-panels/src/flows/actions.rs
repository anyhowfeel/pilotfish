//! Inputs and outputs of the Flows page.

use wl_model::{FlowEvents, FlowSel, StatsSnapshot, TcpSamples, Wireshark};

/// What the Flows page asks the host app to do.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowsAction {
    /// Run the flow-graph pass for this selection.
    LoadFlow(FlowSel),
    /// Run the TCP-graph pass for this selection.
    LoadTcp(FlowSel),
    /// Select this frame in the Packets page and show it.
    ShowInPackets(u64),
    /// Apply this display filter in the Packets page.
    ApplyFilter(String),
}

/// What the host app provides each frame.
pub struct FlowsData<'a> {
    pub stats: &'a StatsSnapshot,
    /// Flow events and the selection they were computed for.
    pub flow: Option<(&'a FlowSel, &'a FlowEvents)>,
    pub tcp: Option<(&'a FlowSel, &'a TcpSamples)>,
    /// Changes whenever `flow` or `tcp` was replaced.
    pub rev: u64,
    pub flow_error: Option<&'a str>,
    pub tcp_error: Option<&'a str>,
    pub wireshark: Wireshark,
}

impl<'a> FlowsData<'a> {
    pub fn empty(stats: &'a StatsSnapshot) -> Self {
        Self {
            stats,
            flow: None,
            tcp: None,
            rev: 0,
            flow_error: None,
            tcp_error: None,
            wireshark: Wireshark::Available,
        }
    }
}
