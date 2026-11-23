//! Per-frame event pump: capture rows, background jobs, selection and layout persistence.
use eframe::egui;

use wl_model::{CaptureError, CaptureSource};

use crate::app::App;
use crate::dispatch::Command;
use crate::page::Page;
use crate::state::RunState;
use crate::wireshark::explain;

impl App {
    /// True when `p` is on screen, as the main page or in its own window.
    pub(crate) fn shows(&self, p: Page) -> bool {
        self.page == p || self.detached.contains(&p)
    }

    pub(crate) fn index_streams(&mut self, rows: &[wl_model::PacketRow]) {
        let mut map = self.streams.borrow_mut();
        for r in rows {
            if let Some(s) = r.stream.filter(|_| map.len() < 200_000) {
                map.entry(r.flow_key()).or_insert(s);
            }
        }
    }

    pub(crate) fn apply_select(&mut self) {
        let Some(n) = self.select else { return };
        if self.packets.select_frame(n) {
            self.select = None;
            self.ctrl.request_detail(n);
        }
    }

    pub(crate) fn save_presets(&mut self) {
        if self.packets.filter_presets() != self.prefs.filter_presets && self.shot.is_none() {
            self.prefs.filter_presets = self.packets.filter_presets().to_vec();
            self.prefs.save();
        }
    }

    pub(crate) fn save_layout(&mut self) {
        let t = self.packets.table_prefs();
        if t != self.prefs.table {
            self.prefs.table = t;
            if self.shot.is_none() {
                self.prefs.save(); // screenshot demos must not touch the user's prefs
            }
        }
        let l = self.packets.layout();
        if self.last_layout != Some(l) {
            self.last_layout = Some(l);
            self.prefs.layout = Some(l);
            self.prefs.save();
        }
    }

    /// Feeds the filter boxes with the hosts, ports and names of the capture, when they changed.
    fn refresh_filter_values(&mut self) {
        let stats = self.ctrl.snapshot();
        let key = (
            stats.hosts.len(),
            stats.conversations.len(),
            self.hub.names.1,
        );
        if self.values_key == Some(key) {
            return;
        }
        self.values_key = Some(key);
        let index = wl_panels::features::ValueIndex::from_stats(stats);
        let values = std::sync::Arc::new(index.with_names(self.hub.names.0.clone()));
        self.gh.panel.set_values(values.clone());
        self.packets.set_filter_values(values);
    }

    pub(crate) fn pump(&mut self, ctx: &egui::Context) {
        if self.flows_link.poll() {
            ctx.request_repaint();
        }
        let polled = self.ctrl.poll();
        if !polled.rows.is_empty() {
            self.index_streams(&polled.rows);
            self.packets.push_rows(polled.rows);
        }
        let running = self.ctrl.status().state == RunState::Running;
        if self.was_running && !running {
            self.packets.resort();
        }
        self.was_running = running;
        let remote = self.ctrl.source().is_some_and(CaptureSource::is_remote);
        let local_live = self.ctrl.is_live() && !remote;
        self.resolver.procs().set_active(running && local_live);
        let web_shown = self.shows(Page::Web) && !self.wireshark.is_missing();
        if self.web_link.tick(&mut self.ctrl, web_shown) {
            ctx.request_repaint();
        }
        self.pump_extras();
        let (fields, hub_changed) = self.hub.poll();
        if let Some(f) = fields {
            self.gh.panel.set_catalog(f.clone());
            self.packets.set_filter_catalog(f);
        }
        self.refresh_filter_values();
        if self.resolver.take_updated() {
            self.hosts.invalidate();
            self.map.invalidate();
        }
        if let Ok(list) = self.iface_rx.try_recv() {
            self.setup_io.set_interfaces(&list);
            self.interfaces = list;
        }
        self.setup_io.set_visible(self.shows(Page::Setup));
        self.setup_io.poll();
        self.record_finished_file();
        for (id, res) in self.fields.poll() {
            for a in self.packets.on_fields(id, &res) {
                self.execute(crate::dispatch::from_packets(a), ctx);
            }
        }
        if let Some(p) = self.dialogs.poll_open() {
            self.execute(Command::OpenFile(p), ctx);
            self.page = Page::Packets;
        }
        if let Some((frames, dest)) = self.dialogs.poll_export() {
            self.ctrl.export(frames, dest);
        }
        if let Some((f, r)) = self.ctrl.take_filter_result()
            && f == self.packets.filter_bar.text()
        {
            self.packets.set_filter_status(
                r.map_err(|e: CaptureError| explain(e, "This filter").to_string()),
            );
        }
        if let Some(p) = ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()))
        {
            self.keys.probe_dropped(p, ctx);
        }
        self.pump_keys(ctx);
        let gh_changed = self.gh.pump(&mut self.dashboard);
        if polled.changed || hub_changed || gh_changed || self.props.pump() {
            ctx.request_repaint();
        }
        if self.ctrl.is_busy() {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }
}
