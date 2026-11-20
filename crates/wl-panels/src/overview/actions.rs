//! Actions emitted by the overview panels; the app decides what to do with them.

use std::path::PathBuf;

use wl_model::CaptureOptions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverviewAction {
    /// Start a live capture with the full Capture > Options set.
    StartLive(CaptureOptions),
    /// Validate a capture filter against an interface (answer arrives as `FilterStatus`).
    CheckCaptureFilter {
        interface: String,
        filter: String,
    },
    ClearRecent,
    /// Pin or unpin a recent file.
    TogglePin(PathBuf),
    /// Ask the host app to show an async native file-open dialog.
    RequestOpenFile,
    OpenFile(PathBuf),
    TogglePause,
    Stop,
    /// Apply this display filter to the packet list.
    ApplyFilter(String),
    /// Follow the stream with this `tcp.stream`/`udp.stream` index.
    Follow(u32),
    /// Open this conversation or host set on the Flows page.
    OpenFlow(wl_model::FlowSel),
    /// Compute statistics of the packets between these capture seconds (dashboard window scope).
    WindowStats {
        from: u32,
        to: u32,
    },
}
