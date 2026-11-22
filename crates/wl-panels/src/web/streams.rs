//! "Streams" tab: WebSocket, Server-Sent Events and gRPC streams (master) and the timeline of
//! the selected one (detail), in the same master/detail layout as the exchanges.

use wl_kit::egui::{Align, Layout, RichText, ScrollArea, Ui, vec2};
use wl_kit::format;
use wl_kit::table::{HEADER_H, TableCols, cell_pad, header_cell, num_cell, text_cell};
use wl_kit::theme::{Palette, row_h, spacing};
use wl_kit::widgets::{PillStyle, empty_state, pill};
use wl_model::{MessageStream, MsgDir, StreamKind, StreamMessage};

use super::actions::WebAction;
use super::detail::placeholder;
use crate::packets::split;

const KIND_W: f32 = 92.0;
const DIR_W: f32 = 28.0;
const STATUS_W: f32 = 120.0;
const COUNT_W: f32 = 76.0;
const TIME_W: f32 = 68.0;
const LABEL_W: f32 = 120.0;

#[derive(Default)]
pub struct StreamsPanel {
    selected: Option<u64>,
    frac: Option<f32>,
}

fn kind_color(kind: StreamKind) -> wl_kit::egui::Color32 {
    match kind {
        StreamKind::WebSocket => Palette::accent(),
        StreamKind::Sse => Palette::ok(),
        StreamKind::Grpc => Palette::warn(),
    }
}

fn arrow(dir: MsgDir) -> &'static str {
    match dir {
        MsgDir::ToServer => "\u{2192}",
        MsgDir::ToClient => "\u{2190}",
    }
}

pub fn title(s: &MessageStream) -> String {
    format!("{}{}", s.host, s.target)
}

fn list_table(ui: &mut Ui, streams: &[MessageStream], selected: Option<u64>) -> Option<u64> {
    let mut picked = None;
    let h = ui.available_height();
    TableCols::new()
        .num(TIME_W)
        .fixed(KIND_W)
        .flex(120.0)
        .num(COUNT_W)
        .fixed(STATUS_W)
        .build(ui)
        .auto_shrink([false, false])
        .max_scroll_height(h)
        .header(HEADER_H, |mut h| {
            h.col(|ui| header_cell(ui, "Time", true));
            h.col(|ui| header_cell(ui, "Type", false));
            h.col(|ui| header_cell(ui, "Endpoint", false));
            h.col(|ui| header_cell(ui, "\u{2191} / \u{2193}", true));
            h.col(|ui| header_cell(ui, "Status", false));
        })
        .body(|body| {
            body.rows(row_h(), streams.len(), |mut row| {
                let s = &streams[row.index()];
                row.set_selected(selected == Some(s.id));
                row.col(|ui| num_cell(ui, &format::time_rel(s.start_rel)));
                row.col(|ui| {
                    cell_pad(ui);
                    pill(ui, s.kind.label(), kind_color(s.kind), PillStyle::badge());
                });
                row.col(|ui| {
                    text_cell(ui, &title(s));
                });
                row.col(|ui| num_cell(ui, &format!("{} / {}", s.sent(), s.received())));
                row.col(|ui| {
                    text_cell(ui, &s.status);
                });
                if row.response().clicked() {
                    picked = Some(s.id);
                }
            });
        });
    picked
}

fn timeline(ui: &mut Ui, s: &MessageStream) -> Option<u64> {
    let mut picked = None;
    let h = ui.available_height();
    TableCols::new()
        .num(TIME_W)
        .fixed(DIR_W)
        .fixed(LABEL_W)
        .flex(120.0)
        .num(COUNT_W)
        .build(ui)
        .auto_shrink([false, false])
        .max_scroll_height(h)
        .header(HEADER_H, |mut h| {
            h.col(|ui| header_cell(ui, "Time", true));
            h.col(|ui| header_cell(ui, "", false));
            h.col(|ui| header_cell(ui, "Event", false));
            h.col(|ui| header_cell(ui, "Payload", false));
            h.col(|ui| header_cell(ui, "Size", true));
        })
        .body(|body| {
            body.rows(row_h(), s.messages.len(), |mut row| {
                let m: &StreamMessage = &s.messages[row.index()];
                row.col(|ui| num_cell(ui, &format::time_rel(m.rel)));
                row.col(|ui| {
                    ui.label(
                        RichText::new(arrow(m.dir))
                            .strong()
                            .color(Palette::accent()),
                    );
                });
                row.col(|ui| {
                    text_cell(ui, &m.label);
                });
                row.col(|ui| {
                    text_cell(ui, &m.payload).on_hover_text(&m.payload);
                });
                row.col(|ui| num_cell(ui, &format::bytes(m.bytes)));
                if row
                    .response()
                    .on_hover_text(format!("Frame #{}", m.frame))
                    .clicked()
                {
                    picked = Some(m.frame);
                }
            });
        });
    picked
}

impl StreamsPanel {
    pub fn select(&mut self, id: u64) {
        self.selected = Some(id);
    }

    pub fn ui(&mut self, ui: &mut Ui, streams: &[MessageStream]) -> Vec<WebAction> {
        if streams.is_empty() {
            empty_state(
                ui,
                "ws",
                "No message streams",
                "WebSocket, Server-Sent Events and gRPC conversations are listed here. \
                 Encrypted ones need a TLS key log.",
            );
            return Vec::new();
        }
        let current = self
            .selected
            .and_then(|id| streams.iter().find(|s| s.id == id));
        let mut out = Vec::new();
        let (mut picked, mut frame) = (None, None);
        let mut frac = self.frac.unwrap_or(0.45);
        ui.style_mut().interaction.selectable_labels = false;
        split::vertical(
            ui,
            &mut frac,
            |ui| picked = list_table(ui, streams, self.selected),
            |ui| match current {
                Some(s) => {
                    ui.add_space(spacing::SM);
                    ScrollArea::horizontal().show(ui, |ui| {
                        ui.allocate_ui_with_layout(
                            vec2(ui.available_width(), ui.available_height()),
                            Layout::top_down(Align::Min),
                            |ui| frame = timeline(ui, s),
                        );
                    });
                }
                None => placeholder(ui, "Select a stream to read its messages"),
            },
        );
        self.frac = Some(frac);
        if let Some(id) = picked {
            self.selected = Some(id);
        }
        out.extend(frame.map(WebAction::ShowInPackets));
        out
    }
}
