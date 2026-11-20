//! Graphs page + dashboard window scope: owns the panel, the I/O series link and the window-stats
//! job, and keeps the time-window selection shared between Overview and Graphs.

use std::sync::Arc;

use eframe::egui;
use wl_model::CaptureBackend;
use wl_panels::graphs::{GraphsAction, GraphsData, GraphsPanel};
use wl_panels::overview::Dashboard;

use crate::graphs_link::GraphsLink;
use crate::page::Page;
use crate::window_job::WindowJob;

pub struct GraphsHub {
    pub panel: GraphsPanel,
    link: GraphsLink,
    window: WindowJob,
    last_page: Page,
}

impl GraphsHub {
    pub fn new(backend: Arc<dyn CaptureBackend>, ctx: egui::Context) -> Self {
        Self {
            panel: GraphsPanel::default(),
            link: GraphsLink::new(backend.clone(), ctx.clone()),
            window: WindowJob::new(backend, ctx),
            last_page: Page::default(),
        }
    }

    /// Hands the time-window selection over when the user moves between Overview and Graphs.
    pub fn page_changed(&mut self, page: Page, dashboard: &mut Dashboard) {
        if page == self.last_page {
            return;
        }
        match (self.last_page, page) {
            (Page::Overview, _) => self.panel.set_selection(dashboard.selection()),
            (Page::Graphs, _) => dashboard.set_selection(self.panel.selection()),
            _ => {}
        }
        self.last_page = page;
    }

    /// One frame of the Graphs page.
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        file: Option<std::path::PathBuf>,
        live: bool,
        elapsed: f64,
    ) -> Vec<GraphsAction> {
        let req = self.panel.request(elapsed);
        let has_capture = file.is_some();
        self.link.tick(file, &req, live);
        let view = self.link.view(&req);
        let data = GraphsData {
            has_capture,
            loading: view.loading,
            duration: elapsed.max(view.duration),
            interval: view.interval,
            series: view.series,
        };
        self.panel.ui(ui, &data)
    }

    /// Dashboard asked for the statistics of `[from, to]` seconds.
    pub fn request_window(&self, file: std::path::PathBuf, from: u32, to: u32) {
        self.window.request(file, from, to);
    }

    /// Finished window statistics go to the dashboard.
    pub fn pump(&self, dashboard: &mut Dashboard) -> bool {
        match self.window.poll() {
            Some(w) => {
                dashboard.set_window_stats(w.from, w.to, &w.stats);
                true
            }
            None => false,
        }
    }
}
