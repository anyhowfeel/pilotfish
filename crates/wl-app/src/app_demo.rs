//! Screenshot/demo helpers: preselected windows and overlays named on the command line.
use eframe::egui;

use crate::app::App;

impl App {
    /// Screenshot helper: `FROM:TO[:window]` seconds.
    pub(crate) fn preselect_window(&mut self, spec: &str) {
        let mut it = spec.split(':');
        let nums: Vec<f64> = it.by_ref().take(2).filter_map(|n| n.parse().ok()).collect();
        let [a, b] = nums[..] else { return };
        let sel = wl_kit::charts::TimeSelection::from_drag(a, b);
        self.dashboard.set_selection(sel);
        self.gh.panel.set_selection(sel);
        if it.next() == Some("window") {
            self.dashboard.show_window_scope();
        }
    }

    /// Screenshot helper: show a modal/overlay named on the command line.
    pub(crate) fn open_overlay(
        &mut self,
        name: &str,
        file: Option<std::path::PathBuf>,
        ctx: &egui::Context,
    ) {
        let (kind, arg) = name.split_once(':').unwrap_or((name, ""));
        match kind {
            "settings" => self.open_settings_at(wl_panels::settings::Category::parse(arg)),
            "palette" => self.hub.palette.open(),
            "decode-as" => self
                .extras
                .decode
                .open_for("tcp.port", arg.parse().unwrap_or(8080)),
            "stream" => {
                if let Some(f) = file {
                    let n = arg.parse().unwrap_or(0);
                    let (p, fmt) = (wl_model::StreamProtocol::Tcp, wl_model::StreamFormat::Ascii);
                    self.hub.open_stream(f, p, n, fmt, ctx.clone());
                }
            }
            "properties" => {
                if let Some(f) = self.ctrl.backing() {
                    self.props.open(f);
                }
            }
            "bookmarks" => {
                for n in [2, 5, 9] {
                    self.hub.bookmarks.set(n, "interesting handshake");
                }
            }
            _ => {}
        }
    }
}
