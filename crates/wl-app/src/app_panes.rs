//! Detached pages: a page can be opened in its own OS window (Shift+click in the sidebar), like
//! Wireshark's separate dialogs, instead of being squeezed into the main window.
use eframe::egui::{self, Margin};
use wl_kit::theme::{Palette, spacing};

use crate::app::App;
use crate::dispatch::Command;

impl App {
    /// Shows every detached page in its own viewport; returns the commands they produced.
    pub(crate) fn detached_ui(&mut self, ctx: &egui::Context) -> Vec<Command> {
        let mut cmds = Vec::new();
        let mut closed = Vec::new();
        let main = self.page;
        for page in self.detached.clone() {
            let id = egui::ViewportId::from_hash_of(("wl_detached", page.label()));
            let builder = egui::ViewportBuilder::default()
                .with_app_id("wirelens")
                .with_title(format!("wirelens \u{2013} {}", page.label()))
                .with_inner_size([980.0, 660.0])
                .with_min_inner_size([520.0, 360.0]);
            ctx.show_viewport_immediate(id, builder, |ctx, _class| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    closed.push(page);
                    return;
                }
                self.page = page;
                let frame = egui::Frame::new()
                    .fill(Palette::bg())
                    .inner_margin(Margin::same(spacing::LG as i8));
                egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
                    cmds.extend(self.page_ui(ui));
                });
                self.page = main;
            });
        }
        self.detached.retain(|p| !closed.contains(p));
        cmds
    }
}
