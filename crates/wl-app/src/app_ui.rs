//! UI rendering for `App`: eframe loop, dismissible status banner, page dispatch, overlays.
use eframe::egui::{self, Margin};
use wl_kit::scale;
use wl_kit::theme::{self, Palette, spacing};
use wl_panels::features::{BookmarkBarAction, InsightsAction, bookmark_toolbar_ui};
use wl_panels::graphs::GraphsAction;
use wl_panels::overview::{OverviewAction, SetupData};

use crate::app::{App, send_min_size};
use crate::dispatch::{self, Command};
use crate::features_hub::HubCommand;
use crate::page::Page;
use crate::shell;
use crate::sidebar_stop::Running;
use crate::state::RunState;

impl App {
    pub(crate) fn page_ui(&mut self, ui: &mut egui::Ui) -> Vec<Command> {
        let stats = self.ctrl.snapshot().clone();
        let mut cmds = Vec::new();
        let mut ov: Vec<OverviewAction> = Vec::new();
        match self.page {
            Page::Setup => {
                let activity = self.setup_io.activity();
                let data = SetupData {
                    interfaces: &self.interfaces,
                    activity: &activity,
                    recent: &self.prefs.recent,
                    pinned: &self.prefs.pinned,
                    packet_counts: &self.prefs.packet_counts,
                    filter_status: self.setup_io.status(),
                    running: self.ctrl.is_live() && (self.ctrl.is_busy() || self.ctrl.is_paused()),
                    paused: self.ctrl.is_paused(),
                };
                ov = self.setup.ui(ui, &data);
                drop(activity);
            }
            Page::Overview => ov = self.dashboard.ui(ui, &stats),
            Page::Hosts => ov = self.hosts.ui(ui, &stats),
            Page::Graphs => {
                let live = matches!(
                    self.ctrl.status().state,
                    RunState::Running | RunState::Paused
                ) && self.ctrl.is_live();
                let elapsed = stats.rate.last().map_or(0.0, |p| p.t + 1.0);
                let file = self.ctrl.backing();
                for GraphsAction::ShowPackets(f) in self.gh.ui(ui, file, live, elapsed) {
                    cmds.push(Command::ApplyFilter(f));
                }
            }
            Page::Map => {
                let live = self.ctrl.is_live() && self.ctrl.is_busy() && !self.ctrl.is_paused();
                self.map.set_live(live);
                ov = self.map.ui(ui, self.demo_map.as_ref().unwrap_or(&stats));
            }
            Page::Conversations => ov = self.convs.ui(ui, &stats),
            Page::Flows => {
                let acts = self.flows.ui(ui, &self.flows_link.data(&stats));
                for a in acts {
                    self.flows_action(a, &mut cmds);
                }
            }
            Page::Web => {
                let keys = self.keys.info();
                let data = self.web_link.data(&keys);
                let acts = self.web.ui(ui, &data);
                let ctx = ui.ctx().clone();
                for a in acts {
                    self.web_action(a, &mut cmds, &ctx);
                }
            }
            Page::Insights => {
                for act in self.hub.insights_ui(ui, &stats) {
                    if self.dns_action(&act, &mut cmds) {
                        continue;
                    }
                    match act {
                        InsightsAction::ApplyFilter(f) => cmds.push(Command::ApplyFilter(f)),
                        InsightsAction::ExportReport => {
                            let ctx = ui.ctx().clone();
                            self.run_hub_command(HubCommand::ExportHtml, &ctx);
                        }
                        InsightsAction::LoadDns | InsightsAction::ShowInPackets(_) => {}
                        InsightsAction::Refresh => {
                            if let Some(file) = self.ctrl.backing() {
                                self.hub.refresh_insights(file, ui.ctx().clone());
                            }
                        }
                    }
                }
            }
            Page::Packets => {
                let sel = self.packets.table.selected();
                if let Some(n) = sel
                    && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::B))
                {
                    self.hub.bookmarks.toggle(n);
                    self.hub.bookmark_frame = None;
                }
                if sel != self.hub.bookmark_frame {
                    self.hub.bookmark_frame = sel;
                    self.hub.bookmark_comment = sel
                        .and_then(|n| self.hub.bookmarks.comment(n))
                        .unwrap_or_default()
                        .to_owned();
                }
                if !self.hub.bookmarks.is_empty()
                    && let Some(bm) = bookmark_toolbar_ui(
                        ui,
                        &mut self.hub.bookmarks,
                        sel,
                        &mut self.hub.bookmark_comment,
                    )
                {
                    match bm {
                        BookmarkBarAction::JumpTo(n) => {
                            if self.packets.select_frame(n) {
                                cmds.push(Command::Select(n));
                            }
                        }
                        BookmarkBarAction::FilterBookmarked(f) => {
                            cmds.push(Command::ApplyFilter(f));
                        }
                        BookmarkBarAction::ClearAll => self.hub.bookmarks.clear(),
                    }
                }
                let detail = self.ctrl.detail().filter(|d| Some(d.frame_no) == sel);
                cmds.extend(
                    self.packets
                        .ui(ui, detail)
                        .into_iter()
                        .map(dispatch::from_packets),
                );
            }
        }
        cmds.extend(ov.into_iter().map(dispatch::from_overview));
        cmds
    }
}

impl eframe::App for App {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw: &mut egui::RawInput) {
        if let Some(s) = &mut self.script {
            s.inject(raw);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let start = std::time::Instant::now();
        let ctx = ui.ctx().clone();
        theme::apply(&ctx);
        scale::handle_shortcuts(&ctx);
        self.pump(&ctx);
        if let Some(b) = &mut self.bench {
            b.tick();
            ctx.request_repaint();
        }
        let active = matches!(
            self.ctrl.status().state,
            RunState::Running | RunState::Paused
        );
        let running = active.then(|| {
            if self.ctrl.is_live() {
                Running::Live
            } else {
                Running::Loading
            }
        });
        let filter = self.ctrl.display_filter().map(str::to_owned);
        let sb = shell::sidebar(
            ui,
            self.page,
            self.prefs.settings.sidebar_labels,
            running,
            filter.as_deref(),
        );
        if sb.clear_filter {
            // Clearing re-reads the capture on the Packets page; come back to where we were.
            let page = self.page;
            self.execute(Command::ApplyFilter(String::new()), &ctx);
            self.page = page;
        }
        if sb.stop_capture {
            self.execute(Command::Stop, &ctx);
        }
        if let Some(p) = sb.page {
            self.page = p;
        }
        if let Some(p) = sb.detach {
            if let Some(i) = self.detached.iter().position(|d| *d == p) {
                self.detached.remove(i);
            } else {
                self.detached.push(p);
            }
        }
        if sb.open_settings {
            self.open_settings();
        }
        self.gh.page_changed(self.page, &mut self.dashboard);
        if shell::status_bar(ui, self.ctrl.status())
            && let Some(f) = self.ctrl.backing()
        {
            self.props.open(f);
        }
        let margin = if self.page == Page::Packets {
            spacing::SM
        } else {
            spacing::LG
        };
        let mut cmds = Vec::new();
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(Palette::bg())
                    .inner_margin(Margin::same(margin as i8)),
            )
            .show(ui, |ui| {
                self.banner(ui);
                cmds = self.page_ui(ui);
            });
        cmds.extend(self.detached_ui(&ctx));
        for c in cmds {
            self.execute(c, &ctx);
        }
        self.props.ui(&ctx);
        if let Some(hc) = self.hub.overlay_ui(&ctx, self.ctrl.backing()) {
            self.run_hub_command(hc, &ctx);
        }
        self.decode_as_ui(&ctx);
        let s = scale::ui_scale(&ctx);
        if (s - self.last_scale).abs() > f32::EPSILON {
            self.last_scale = s;
            send_min_size(&ctx, s);
            if !self.settings.is_open() {
                self.prefs.settings.ui_scale = s;
                self.prefs.save();
            }
        }
        self.settings_ui(&ctx);
        wl_kit::widgets::toast::draw(&ctx);
        self.apply_select();
        self.save_layout();
        if let Some(shot) = &mut self.shot {
            shot.tick(&ctx);
        }
        self.script_frame(&ctx, start);
    }
}
