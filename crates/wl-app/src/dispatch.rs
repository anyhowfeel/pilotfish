//! Maps panel actions to controller commands (single place, no logic besides translation).
use std::path::PathBuf;

use wl_model::CaptureOptions;
use wl_panels::overview::OverviewAction;
use wl_panels::packets::PacketsAction;

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    RequestOpenFile,
    OpenFile(PathBuf),
    StartLive(CaptureOptions),
    CheckCaptureFilter {
        interface: String,
        filter: String,
    },
    ClearRecent,
    TogglePin(PathBuf),
    TogglePause,
    Stop,
    ApplyFilter(String),
    ValidateFilter(String),
    FollowStream(u32),
    Select(u64),
    /// Empty = export the whole capture.
    Export(Vec<u64>),
    ClearAll,
    OpenFlow(wl_model::FlowSel),
    Fields {
        id: u64,
        filter: String,
        fields: Vec<String>,
    },
    /// Statistics of the packets between these capture seconds (dashboard window scope).
    WindowStats {
        from: u32,
        to: u32,
    },
    /// Open Decode As for this table (`tcp.port` / `udp.port`) and port.
    DecodeAs {
        field: String,
        port: u16,
    },
}

pub fn from_packets(a: PacketsAction) -> Command {
    match a {
        PacketsAction::Select(n) => Command::Select(n),
        PacketsAction::ApplyFilter(f) => Command::ApplyFilter(f),
        PacketsAction::ValidateFilter(f) => Command::ValidateFilter(f),
        PacketsAction::FollowStream(s) => Command::FollowStream(s),
        PacketsAction::Export { selected } => Command::Export(selected),
        PacketsAction::ClearAll => Command::ClearAll,
        PacketsAction::OpenFlow(s) => Command::OpenFlow(s),
        PacketsAction::RunFields { id, filter, fields } => Command::Fields { id, filter, fields },
        PacketsAction::DecodeAs { field, port } => Command::DecodeAs { field, port },
    }
}

pub fn from_overview(a: OverviewAction) -> Command {
    match a {
        OverviewAction::StartLive(o) => Command::StartLive(o),
        OverviewAction::CheckCaptureFilter { interface, filter } => {
            Command::CheckCaptureFilter { interface, filter }
        }
        OverviewAction::ClearRecent => Command::ClearRecent,
        OverviewAction::TogglePin(p) => Command::TogglePin(p),
        OverviewAction::RequestOpenFile => Command::RequestOpenFile,
        OverviewAction::OpenFile(p) => Command::OpenFile(p),
        OverviewAction::TogglePause => Command::TogglePause,
        OverviewAction::Stop => Command::Stop,
        OverviewAction::ApplyFilter(f) => Command::ApplyFilter(f),
        OverviewAction::Follow(s) => Command::FollowStream(s),
        OverviewAction::OpenFlow(s) => Command::OpenFlow(s),
        OverviewAction::WindowStats { from, to } => Command::WindowStats { from, to },
    }
}

pub fn follow_filter(stream: u32) -> String {
    format!("tcp.stream eq {stream} || udp.stream eq {stream}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follow_becomes_filter() {
        assert_eq!(
            from_packets(PacketsAction::FollowStream(3)),
            Command::FollowStream(3)
        );
        assert_eq!(follow_filter(3), "tcp.stream eq 3 || udp.stream eq 3");
    }
}
