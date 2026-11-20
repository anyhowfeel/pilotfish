//! Events emitted by the packet panels; the app decides what to do with them.

#[derive(Debug, Clone, PartialEq)]
pub enum PacketsAction {
    /// A frame was selected (the app loads its `FrameDetail`).
    Select(u64),
    /// Apply this display filter to the capture view.
    ApplyFilter(String),
    /// Validate this display filter and report back through `FilterBar::set_status`.
    ValidateFilter(String),
    /// Follow the TCP/UDP stream with this id.
    FollowStream(u32),
    /// Export the given frames (empty = nothing selected).
    Export { selected: Vec<u64> },
    /// Run `CaptureBackend::frame_fields` (filter + tshark fields) and report the result
    /// through `PacketsView::on_fields` with the same id.
    RunFields {
        id: u64,
        filter: String,
        fields: Vec<String>,
    },
    /// Drop every captured packet.
    ClearAll,
    /// Open this conversation on the Flows page.
    OpenFlow(wl_model::FlowSel),
    /// Open Decode As for this dissector table (`tcp.port` / `udp.port`) and port.
    DecodeAs { field: String, port: u16 },
}
