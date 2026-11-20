//! "Decode As" dialog (Analyze > Decode As): bind a TCP/UDP port to a protocol, list and remove
//! the active rules. The app applies the rules (`-d`) and re-dissects the capture.

mod list;
#[cfg(test)]
mod tests;

use wl_kit::egui::{self, Align, Align2, Key, Layout, RichText, Ui, Window, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{
    close_button, modal_scrim, protocol_pill, section_header, segmented_w, text_field,
};
use wl_model::DecodeAs;

pub use list::matching;

/// Dissector tables offered, in the order of the segmented control.
pub const FIELDS: [&str; 2] = ["tcp.port", "udp.port"];
const WIDTH: f32 = 520.0;
/// Screen heights (minus margins) from which the dialog needs no scrolling.
const FULL_H: f32 = 560.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeAsAction {
    /// Add (or replace) this rule and re-dissect.
    Add(DecodeAs),
    /// Remove the rule at this index of the list passed to `ui`.
    Remove(usize),
    /// The protocol list of this table is needed (answer with `set_protocols`).
    LoadProtocols(String),
}

#[derive(Default)]
pub struct DecodeAsDialog {
    open: bool,
    field: usize,
    port: String,
    search: String,
    selected: Option<String>,
    protocols: [Option<Vec<String>>; 2],
    requested: [bool; 2],
    focus_port: bool,
}

/// Parses the port box (decimal, 0..=65535).
pub fn parse_port(s: &str) -> Option<u32> {
    s.trim().parse::<u16>().ok().map(u32::from)
}

impl DecodeAsDialog {
    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn open(&mut self) {
        self.open = true;
        self.focus_port = true;
    }

    /// Opens with `field` (`tcp.port` / `udp.port`) and `port` pre-filled.
    pub fn open_for(&mut self, field: &str, port: u16) {
        self.field = FIELDS.iter().position(|f| *f == field).unwrap_or(0);
        self.port = port.to_string();
        self.selected = None;
        self.search.clear();
        self.open();
    }

    pub fn close(&mut self) {
        self.open = false;
    }

    pub fn set_protocols(&mut self, field: &str, list: Vec<String>) {
        if let Some(i) = FIELDS.iter().position(|f| *f == field) {
            self.protocols[i] = Some(list);
        }
    }

    /// Forgets cached lists (a new tshark may know other protocols).
    pub fn reset(&mut self) {
        self.protocols = Default::default();
        self.requested = [false; 2];
    }

    pub fn ui(&mut self, ctx: &egui::Context, rules: &[DecodeAs]) -> Vec<DecodeAsAction> {
        let mut out = Vec::new();
        if !self.open {
            return out;
        }
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.open = false;
            return out;
        }
        if modal_scrim(ctx, "decode_as", egui::Order::Middle) {
            self.open = false;
            return out;
        }
        if self.protocols[self.field].is_none() && !self.requested[self.field] {
            self.requested[self.field] = true;
            out.push(DecodeAsAction::LoadProtocols(FIELDS[self.field].to_owned()));
        }
        let mut keep = true;
        // Small windows: the body scrolls instead of the dialog leaving the screen.
        let max_h = (ctx.content_rect().height() - 90.0).max(160.0);
        Window::new("Decode As")
            .id(egui::Id::NULL.with("wl_decode_as_modal"))
            .open(&mut keep)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_width(WIDTH);
                if max_h < FULL_H {
                    egui::ScrollArea::vertical()
                        .id_salt("wl_decode_as_body")
                        .max_height(max_h)
                        .auto_shrink([false, true])
                        .show(ui, |ui| self.content(ui, rules, &mut out));
                } else {
                    self.content(ui, rules, &mut out);
                }
            });
        self.open &= keep;
        out
    }

    fn content(&mut self, ui: &mut Ui, rules: &[DecodeAs], out: &mut Vec<DecodeAsAction>) {
        self.form(ui, out);
        ui.add_space(spacing::MD);
        self.rules_ui(ui, rules, out);
    }

    fn form(&mut self, ui: &mut Ui, out: &mut Vec<DecodeAsAction>) {
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Treat traffic on a port as another protocol. The capture is dissected again with the rule.",
                )
                .color(Palette::muted()),
            )
            .wrap(),
        );
        ui.add_space(spacing::MD);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = spacing::SM;
            let opts = [(0usize, "TCP port"), (1usize, "UDP port")];
            if segmented_w(ui, &mut self.field, &opts, 200.0) {
                self.selected = None;
            }
            ui.label(RichText::new("Port").color(Palette::muted()));
            let edit = ui.add(
                text_field(&mut self.port)
                    .desired_width(80.0)
                    .hint_text("8080"),
            );
            if std::mem::take(&mut self.focus_port) {
                edit.request_focus();
            }
        });
        ui.add_space(spacing::MD);
        ui.add(
            text_field(&mut self.search)
                .hint_text("Search protocols\u{2026}")
                .desired_width(ui.available_width()),
        );
        ui.add_space(spacing::SM);
        let list = self.protocols[self.field].as_deref();
        list::protocol_list(ui, list, &self.search, &mut self.selected);
        ui.add_space(spacing::SM);
        self.add_row(ui, out);
    }

    fn add_row(&mut self, ui: &mut Ui, out: &mut Vec<DecodeAsAction>) {
        let port = parse_port(&self.port);
        ui.horizontal(|ui| {
            let text = match (&self.selected, port) {
                (Some(p), Some(n)) => format!("{} {n}  as  {p}", FIELDS[self.field]),
                (None, _) => "Pick a protocol".to_owned(),
                (_, None) => "Enter a port from 0 to 65535".to_owned(),
            };
            ui.label(RichText::new(text).color(Palette::muted()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let ready = self.selected.is_some() && port.is_some();
                let b = egui::Button::new(RichText::new("Add rule").color(Palette::text()))
                    .fill(Palette::selection_bg());
                let clicked = ui.add_enabled(ready, b).clicked();
                if let (true, Some(protocol), Some(value)) = (clicked, self.selected.clone(), port)
                {
                    out.push(DecodeAsAction::Add(DecodeAs {
                        field: FIELDS[self.field].to_owned(),
                        value,
                        protocol,
                    }));
                }
            });
        });
    }

    fn rules_ui(&mut self, ui: &mut Ui, rules: &[DecodeAs], out: &mut Vec<DecodeAsAction>) {
        section_header(ui, &format!("Active rules ({})", rules.len()));
        if rules.is_empty() {
            ui.label(
                RichText::new("No rules: every port keeps its default decoding.")
                    .color(Palette::muted()),
            );
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("wl_decode_rules")
            .max_height(list::ROW_H * 3.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for (i, r) in rules.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.set_height(list::ROW_H);
                        ui.spacing_mut().item_spacing.x = spacing::SM;
                        let t = format!("{} == {}", r.field, r.value);
                        ui.label(RichText::new(t).monospace().color(Palette::text()));
                        ui.label(RichText::new("as").color(Palette::muted()));
                        protocol_pill(ui, &r.protocol, 64.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if close_button(ui).on_hover_text("Remove rule").clicked() {
                                out.push(DecodeAsAction::Remove(i));
                            }
                        });
                    });
                }
            });
    }
}
