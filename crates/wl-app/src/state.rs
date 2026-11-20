//! Small shared state types read by the shell (status bar) and written by the controller.
use wl_kit::egui::Color32;
use wl_kit::theme::Palette;
use wl_model::CaptureSource;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RunState {
    #[default]
    Idle,
    Running,
    Paused,
    Finished,
    Failed,
}

impl RunState {
    pub fn label(self) -> &'static str {
        match self {
            RunState::Idle => "Idle",
            RunState::Running => "Capturing",
            RunState::Paused => "Paused",
            RunState::Finished => "Done",
            RunState::Failed => "Error",
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            RunState::Idle => Palette::muted(),
            RunState::Running => Palette::ok(),
            RunState::Paused => Palette::warn(),
            RunState::Finished => Palette::accent(),
            RunState::Failed => Palette::danger(),
        }
    }
}

/// Everything the top status bar displays.
#[derive(Clone, Debug, Default)]
pub struct StatusInfo {
    pub state: RunState,
    pub source: String,
    pub packets: u64,
    pub rate_pps: f64,
    pub elapsed: f64,
    pub filter: String,
}

pub fn describe_source(src: &CaptureSource) -> String {
    match src {
        CaptureSource::Live { interface, .. } => format!("Live: {interface}"),
        CaptureSource::Capture(o) => format!("Live: {}", o.label()),
        CaptureSource::File(p) => p.file_name().map_or_else(
            || p.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        ),
    }
}
