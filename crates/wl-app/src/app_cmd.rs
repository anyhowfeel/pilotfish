//! Command execution for `App`: capture control, filtering, stream follow, and hub actions.
use eframe::egui;
use wl_model::{CaptureSource, StreamFormat, StreamProtocol};

use crate::app::App;
use crate::dispatch::{self, Command};
use crate::features_hub::HubCommand;
use crate::page::Page;

impl App {
    /// Re-dissects the open capture (new key log): the filter and the bookmarks stay.
    pub(crate) fn reload_file(&mut self, p: std::path::PathBuf, ctx: &egui::Context) {
        let filter = self.ctrl.display_filter().map(str::to_owned);
        let bookmarks = std::mem::take(&mut self.hub.bookmarks);
        self.open_file(p, filter, ctx);
        self.hub.bookmarks = bookmarks;
    }

    fn open_file(&mut self, p: std::path::PathBuf, filter: Option<String>, ctx: &egui::Context) {
        self.streams.borrow_mut().clear();
        self.packets.clear();
        self.packets.set_follow(false);
        self.hosts.invalidate();
        self.web_link.clear();
        self.flows_link.clear();
        self.flows.reload();
        self.reset_extras();
        self.hub.clear_capture();
        self.dashboard.clear_window_stats();
        self.resolver.procs().clear();
        self.ctrl
            .start(CaptureSource::File(p.clone()), filter.clone());
        self.hub.refresh_insights(p, ctx.clone());
        self.packets
            .filter_bar
            .set_text(filter.as_deref().unwrap_or(""));
    }

    pub fn execute(&mut self, cmd: Command, ctx: &egui::Context) {
        match cmd {
            Command::RequestOpenFile => self.dialogs.ask_open(ctx.clone()),
            Command::OpenFile(p) => {
                self.open_file(p.clone(), None, ctx);
                self.prefs.push_recent(p);
                self.prefs.save();
            }
            Command::StartLive(options) => {
                self.resolver.procs().clear();
                self.streams.borrow_mut().clear();
                self.packets.clear();
                self.packets.set_follow(self.prefs.settings.auto_scroll);
                self.hosts.invalidate();
                self.web_link.clear();
                self.flows_link.clear();
                self.flows.reload();
                self.reset_extras();
                self.hub.clear_capture();
                // Remember the options (not the interface choice) as the next defaults.
                self.prefs.settings.capture = wl_model::CaptureOptions {
                    interfaces: Vec::new(),
                    ..options.clone()
                };
                self.prefs.save();
                // The path of an automatically saved capture is not a default for the next one.
                let mut run = options;
                let saved = crate::autosave::plan(
                    &run,
                    self.prefs.settings.autosave_captures,
                    &self.prefs.settings.capture_dir,
                    chrono::Local::now(),
                    &|p| p.exists(),
                );
                if let Some(path) = &saved {
                    run.save_to = path.display().to_string();
                }
                self.ctrl.start(CaptureSource::Capture(run), None);
                if let Some(path) = saved {
                    self.prefs.push_recent(path);
                    self.prefs.save();
                }
                self.dashboard.clear_window_stats();
                self.page = Page::Packets;
            }
            Command::CheckCaptureFilter { interface, filter } => {
                self.setup_io.check_filter(interface, filter);
            }
            Command::ClearRecent => {
                self.prefs.clear_recent();
                self.prefs.save();
            }
            Command::TogglePin(p) => {
                self.prefs.toggle_pin(&p);
                self.prefs.save();
            }
            Command::OpenFlow(sel) => {
                self.flows.open(sel);
                self.page = Page::Flows;
            }
            Command::TogglePause => self.ctrl.toggle_pause(),
            Command::Stop => self.ctrl.stop(),
            Command::ApplyFilter(f) => {
                let flt = Some(f.trim().to_string()).filter(|s| !s.is_empty());
                self.packets.clear_for_filter(flt.is_some());
                self.packets.set_follow(false);
                self.hosts.invalidate();
                self.streams.borrow_mut().clear();
                self.packets
                    .filter_bar
                    .set_text(flt.as_deref().unwrap_or(""));
                if flt.is_some() {
                    self.prefs.filter_history = self.packets.filter_history();
                    self.prefs.save();
                }
                if !self.ctrl.apply_filter(flt) {
                    self.startup_error =
                        Some("Open a capture before applying a display filter.".into());
                }
                self.page = Page::Packets;
            }
            Command::FollowStream(id) => {
                if let Some(file) = self.ctrl.backing() {
                    self.hub.open_stream(
                        file,
                        StreamProtocol::Tcp,
                        id,
                        StreamFormat::Ascii,
                        ctx.clone(),
                    );
                } else {
                    self.execute(Command::ApplyFilter(dispatch::follow_filter(id)), ctx);
                }
            }
            Command::WindowStats { from, to } => {
                if let Some(file) = self.ctrl.backing() {
                    self.gh.request_window(file, from, to);
                }
            }
            Command::ValidateFilter(f) => self.ctrl.validate_filter(f),
            Command::Select(n) => self.ctrl.request_detail(n),
            Command::Export(frames) => self.dialogs.ask_export(frames, ctx.clone()),
            Command::Fields { id, filter, fields } => {
                if let Some(file) = self.ctrl.backing() {
                    self.fields.request(file, id, filter, fields, ctx.clone());
                }
            }
            Command::DecodeAs { field, port } => self.open_decode_as_for(&field, port),
            Command::ClearAll => {
                self.packets.clear();
                if let Some(CaptureSource::File(p)) = self.ctrl.source().cloned() {
                    self.ctrl.start(CaptureSource::File(p), None);
                }
            }
        }
    }

    pub(crate) fn run_hub_command(&mut self, cmd: HubCommand, ctx: &egui::Context) {
        match cmd {
            HubCommand::Page(p) => self.page = p,
            HubCommand::JumpToFrame(n) => {
                self.page = Page::Packets;
                if self.packets.select_frame(n) {
                    self.ctrl.request_detail(n);
                } else {
                    self.select = Some(n);
                }
            }
            HubCommand::ApplyFilter(f) => self.execute(Command::ApplyFilter(f), ctx),
            HubCommand::ToggleTheme => self.toggle_theme(ctx),
            HubCommand::OpenSettings => self.open_settings(),
            HubCommand::OpenFileDialog => self.execute(Command::RequestOpenFile, ctx),
            HubCommand::FileProperties => {
                if let Some(f) = self.ctrl.backing() {
                    self.props.open(f);
                }
            }
            HubCommand::TogglePause => self.ctrl.toggle_pause(),
            HubCommand::Stop => self.ctrl.stop(),
            HubCommand::ExportObjects => {
                self.page = Page::Web;
                self.web.show_files(None);
            }
            HubCommand::DecodeAs => self.open_decode_as(),
            HubCommand::DnsLog => {
                self.page = Page::Insights;
                self.hub.insights.show_dns();
            }
            HubCommand::ExportCsv => {
                let rows = (0..self.packets.table.state.visible())
                    .filter_map(|i| self.packets.table.state.row_at(i).cloned())
                    .collect();
                self.hub.export_csv(rows, ctx.clone());
            }
            HubCommand::ExportJson => self
                .hub
                .export_json(self.ctrl.snapshot().clone(), ctx.clone()),
            HubCommand::ExportHtml => {
                let title = self.ctrl.status().source.clone();
                let file = self.ctrl.backing();
                self.hub
                    .export_html(title, self.ctrl.snapshot().clone(), file, ctx.clone());
            }
        }
    }
}
