//! Left pane: pick the conversation (or 2..N hosts) to draw. Virtualised painted rows.

use std::sync::Arc;

use wl_kit::egui::{
    CornerRadius, CursorIcon, ScrollArea, Sense, Stroke, StrokeKind, Ui, pos2, vec2,
};
use wl_kit::format;
use wl_kit::text::contains_ci;
use wl_kit::theme::{Palette, protocol_color, spacing};
use wl_kit::widgets::text::elided_galley;
use wl_kit::widgets::{empty_state, segmented_w};
use wl_model::{FlowSel, HostStat, StatsSnapshot};

use super::paint::{label_font, mono_font};
use crate::overview::SortState;
use crate::overview::conversations_sort::{FlowCol, duration, endpoints, visible};

pub const ROW: f32 = 48.0;
const MAX_HOSTS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    #[default]
    Conversations,
    Hosts,
}

#[derive(Default)]
pub struct List {
    mode: Mode,
    filter: String,
    picked: Vec<Arc<str>>,
    key: Option<(u64, usize, String, Mode)>,
    rows: Vec<usize>,
}

/// Painted two-line row: `title` over `sub`, optional leading marker rect drawn by `lead`.
fn item(ui: &mut Ui, selected: bool, title: &str, sub: &str, dot: wl_kit::egui::Color32) -> bool {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW), Sense::click());
    let p = ui.painter().with_clip_rect(rect);
    let inner = rect.shrink2(vec2(0.0, 2.0));
    let radius = CornerRadius::same(6);
    if selected {
        p.rect_filled(inner, radius, Palette::selection_bg());
        p.rect_stroke(
            inner,
            radius,
            Stroke::new(1.0, Palette::accent()),
            StrokeKind::Inside,
        );
    } else if resp.hovered() {
        p.rect_filled(inner, radius, Palette::surface_hi());
    }
    let x0 = inner.left() + spacing::MD;
    let text_l = x0 + 14.0;
    let w = inner.right() - spacing::SM - text_l;
    let t = elided_galley(&p, title, label_font(), Palette::text(), w);
    let s = elided_galley(&p, sub, mono_font(), Palette::muted(), w);
    let top = inner.center().y - (t.size().y + 2.0 + s.size().y) / 2.0;
    // The marker sits on the vertical middle of the title line, whatever the font height.
    p.circle_filled(pos2(x0 + 3.0, (top + t.size().y / 2.0).round()), 3.5, dot);
    p.galley(pos2(text_l, top.round()), t.clone(), Palette::text());
    p.galley(
        pos2(text_l, (top + t.size().y + 2.0).round()),
        s,
        Palette::muted(),
    );
    resp.on_hover_cursor(CursorIcon::PointingHand).clicked()
}

/// Hosts ordered by traffic, filtered by substring.
pub fn host_rows(hosts: &[HostStat], needle: &str) -> Vec<usize> {
    let n = needle.to_lowercase();
    let mut idx: Vec<usize> = (0..hosts.len())
        .filter(|&i| n.is_empty() || contains_ci(&hosts[i].addr, &n))
        .collect();
    let bytes = |i: usize| hosts[i].bytes_in + hosts[i].bytes_out;
    idx.sort_by(|&a, &b| bytes(b).cmp(&bytes(a)).then(a.cmp(&b)));
    idx
}

impl List {
    /// Full-width filter field; Escape clears it.
    fn filter_field(&mut self, ui: &mut Ui, w: f32) {
        let edit = ui.add(
            wl_kit::widgets::text_field(&mut self.filter)
                .hint_text("Filter\u{2026}")
                .desired_width(w),
        );
        if edit.has_focus() && ui.input(|i| i.key_pressed(wl_kit::egui::Key::Escape)) {
            self.filter.clear();
        }
    }

    fn refresh(&mut self, s: &StatsSnapshot) {
        let key = (
            s.total_packets,
            s.conversations.len() + s.hosts.len(),
            self.filter.clone(),
            self.mode,
        );
        if self.key.as_ref() == Some(&key) {
            return;
        }
        self.rows = match self.mode {
            Mode::Conversations => visible(
                &s.conversations,
                &self.filter,
                SortState::new(FlowCol::Bytes, true),
            ),
            Mode::Hosts => host_rows(&s.hosts, &self.filter),
        };
        self.key = Some(key);
    }

    /// Draws the pane; returns a newly chosen selection.
    pub fn ui(
        &mut self,
        ui: &mut Ui,
        s: &StatsSnapshot,
        current: Option<&FlowSel>,
    ) -> Option<FlowSel> {
        let mut mode = self.mode;
        let w = ui.available_width();
        let modes = [
            (Mode::Conversations, "Conversations"),
            (Mode::Hosts, "Hosts"),
        ];
        ui.push_id("flow_mode", |ui| segmented_w(ui, &mut mode, &modes, w));
        self.mode = mode;
        ui.add_space(spacing::SM);
        self.filter_field(ui, w);
        ui.add_space(spacing::SM);
        self.refresh(s);
        if self.rows.is_empty() {
            let (title, hint) = match self.mode {
                Mode::Conversations => ("No conversations", "Flows appear once packets arrive."),
                Mode::Hosts => ("No hosts", "Hosts appear once packets arrive."),
            };
            empty_state(ui, "=", title, hint);
            return None;
        }
        if self.mode == Mode::Hosts {
            let hint = format!("Tick 2 to {MAX_HOSTS} hosts ({} ticked)", self.picked.len());
            ui.label(
                wl_kit::egui::RichText::new(hint)
                    .small()
                    .color(Palette::muted()),
            );
        }
        ScrollArea::vertical()
            .id_salt("flow_list")
            .auto_shrink([false, false])
            .show_rows(ui, ROW, self.rows.len(), |ui, range| {
                self.rows(ui, s, current, range)
            })
            .inner
    }

    fn rows(
        &mut self,
        ui: &mut Ui,
        s: &StatsSnapshot,
        current: Option<&FlowSel>,
        range: std::ops::Range<usize>,
    ) -> Option<FlowSel> {
        let mut chosen = None;
        for r in range {
            let idx = self.rows[r];
            if self.mode == Mode::Conversations {
                let c = &s.conversations[idx];
                let sel = FlowSel::Conversation(c.key.clone());
                // Fixed-width fields so the figures line up from one row to the next.
                let sub = format!(
                    "{:<6}{:>6}  {:>10}  {:>8}",
                    c.protocol,
                    format::count(c.packets),
                    format::bytes(c.bytes),
                    format::duration(duration(c))
                );
                let dot = protocol_color(&c.protocol);
                if item(ui, current == Some(&sel), &endpoints(c), &sub, dot) {
                    chosen = Some(sel);
                }
            } else {
                chosen = chosen.or(self.host_row(ui, &s.hosts[idx]));
            }
        }
        chosen
    }

    fn host_row(&mut self, ui: &mut Ui, h: &HostStat) -> Option<FlowSel> {
        let on = self.picked.contains(&h.addr);
        let sub = format!(
            "{} in  {} out",
            format::bytes(h.bytes_in),
            format::bytes(h.bytes_out)
        );
        let dot = if on {
            Palette::accent()
        } else {
            Palette::muted()
        };
        if !item(ui, on, &h.addr, &sub, dot) {
            return None;
        }
        if on {
            self.picked.retain(|a| *a != h.addr);
        } else if self.picked.len() < MAX_HOSTS {
            self.picked.push(h.addr.clone());
        }
        (self.picked.len() >= 2).then(|| FlowSel::Hosts(self.picked.clone()))
    }
}
