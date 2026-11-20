//! Interface picker: search box, grouped card grids, multi-selection.

use std::collections::HashMap;

use wl_kit::egui::{
    Align, CursorIcon, FontId, Layout, Rect, RichText, Sense, Stroke, Ui, pos2, vec2,
};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{centered_row, empty_state, paint_elided, text_field};
use wl_model::Interface;

use super::activity::ActivityMap;
use super::iface_class::{Group, classify, grouped};
use super::interface_card::{CARD_H, CardData, CardEvent, interface_card};

const MIN_CARD_W: f32 = 300.0;
const GROUP_H: f32 = 26.0;
/// The order may re-sort while samples arrive after entering the page, then it stays put.
const SETTLE_SECS: f64 = 4.0;
/// A gap longer than this between frames means the page was left and re-entered.
const REENTRY_GAP: f64 = 3.0;

#[derive(Default)]
pub struct InterfacePicker {
    query: String,
    other_open: bool,
    /// Rates the current ordering was computed from (frozen so cards do not jump around).
    frozen: HashMap<String, f64>,
    entered: f64,
    last_seen: f64,
    known: usize,
}

impl InterfacePicker {
    pub fn ui(
        &mut self,
        ui: &mut Ui,
        interfaces: &[Interface],
        activity: &ActivityMap,
        selected: &mut Vec<String>,
    ) {
        self.refresh_order(ui, interfaces, activity);
        self.header(ui, interfaces.len(), selected.len());
        if interfaces.is_empty() {
            empty_state(
                ui,
                "!",
                "No interfaces found",
                "Check that dumpcap is installed and you may capture.",
            );
            return;
        }
        let rate = |n: &str| self.frozen.get(n).copied().unwrap_or(0.0);
        let groups = grouped(interfaces, &self.query, &rate);
        let searching = !self.query.trim().is_empty();
        let shown: usize = groups.iter().map(|(_, v)| v.len()).sum();
        if shown == 0 {
            ui.add_space(spacing::SM);
            ui.label(RichText::new("No interface matches the search.").color(Palette::muted()));
            return;
        }
        for (group, idx) in groups.iter().filter(|(_, v)| !v.is_empty()) {
            let collapsible = *group == Group::Other && !searching;
            let open = !collapsible || self.other_open;
            if group_header(ui, *group, idx.len(), collapsible, open) && collapsible {
                self.other_open = !self.other_open;
            }
            if open {
                card_grid(ui, interfaces, idx, activity, selected);
            }
            ui.add_space(spacing::SM);
        }
    }

    pub fn open_other(&mut self, open: bool) {
        self.other_open |= open;
    }

    fn refresh_order(&mut self, ui: &Ui, interfaces: &[Interface], activity: &ActivityMap) {
        let now = ui.input(|i| i.time);
        if now - self.last_seen > REENTRY_GAP || interfaces.len() != self.known {
            self.entered = now;
            self.known = interfaces.len();
        }
        self.last_seen = now;
        if now - self.entered < SETTLE_SECS {
            self.frozen = activity.iter().map(|(k, a)| (k.clone(), a.rate)).collect();
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(500));
        }
    }

    fn header(&mut self, ui: &mut Ui, total: usize, selected: usize) {
        centered_row(ui, 30.0, |ui| {
            ui.label(RichText::new("Interfaces").strong().size(15.0));
            ui.label(
                RichText::new(format!("{total} found \u{b7} {selected} selected"))
                    .small()
                    .color(Palette::muted()),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let edit = text_field(&mut self.query)
                    .hint_text("Search interfaces\u{2026}")
                    .desired_width(240.0);
                ui.add(edit);
            });
        });
        let (line, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
        ui.painter().rect_filled(line, 0.0, Palette::border());
        ui.add_space(spacing::SM);
    }
}

/// Returns true when the header was clicked.
fn group_header(ui: &mut Ui, g: Group, n: usize, collapsible: bool, open: bool) -> bool {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), GROUP_H), Sense::click());
    let mut x = rect.left();
    if collapsible {
        paint_chevron(ui, pos2(x + 6.0, rect.center().y), open);
        x += 18.0;
    }
    let label = format!("{}  \u{b7}  {n}", g.label());
    let r = Rect::from_min_max(pos2(x, rect.top()), rect.max);
    let font = FontId::proportional(13.0);
    paint_elided(ui.painter(), r, &label, font, Palette::muted(), Align::Min);
    if collapsible {
        resp.on_hover_cursor(CursorIcon::PointingHand).clicked()
    } else {
        false
    }
}

pub(super) fn paint_chevron(ui: &Ui, c: wl_kit::egui::Pos2, open: bool) {
    let s = Stroke::new(1.5, Palette::muted());
    let pts = if open {
        [
            pos2(c.x - 3.5, c.y - 1.5),
            pos2(c.x, c.y + 2.5),
            pos2(c.x + 3.5, c.y - 1.5),
        ]
    } else {
        [
            pos2(c.x - 1.5, c.y - 3.5),
            pos2(c.x + 2.5, c.y),
            pos2(c.x - 1.5, c.y + 3.5),
        ]
    };
    ui.painter().line_segment([pts[0], pts[1]], s);
    ui.painter().line_segment([pts[1], pts[2]], s);
}

fn card_grid(
    ui: &mut Ui,
    interfaces: &[Interface],
    idx: &[usize],
    activity: &ActivityMap,
    selected: &mut Vec<String>,
) {
    let gap = spacing::MD;
    let w = ui.available_width();
    let cols = (((w + gap) / (MIN_CARD_W + gap)).floor() as usize).max(1);
    let cw = (w - gap * (cols as f32 - 1.0)) / cols as f32;
    let rows = idx.len().div_ceil(cols);
    let h = rows as f32 * (CARD_H + gap) - gap;
    let (area, _) = ui.allocate_exact_size(vec2(w, h), Sense::hover());
    let ctrl = ui.input(|i| i.modifiers.command);
    for (n, &i) in idx.iter().enumerate() {
        let iface = &interfaces[i];
        let min = pos2(
            area.left() + (n % cols) as f32 * (cw + gap),
            area.top() + (n / cols) as f32 * (CARD_H + gap),
        );
        let data = CardData {
            iface,
            class: classify(iface),
            activity: activity.get(&iface.name),
            selected: selected.contains(&iface.name),
        };
        let (_, ev) = interface_card(ui, Rect::from_min_size(min, vec2(cw, CARD_H)), &data);
        apply_event(selected, &iface.name, ev, ctrl);
    }
}

fn apply_event(selected: &mut Vec<String>, name: &str, ev: CardEvent, ctrl: bool) {
    match ev {
        CardEvent::None => {}
        CardEvent::Toggle => toggle(selected, name),
        CardEvent::Select if ctrl => toggle(selected, name),
        CardEvent::Select => *selected = vec![name.to_string()],
    }
}

fn toggle(selected: &mut Vec<String>, name: &str) {
    if let Some(p) = selected.iter().position(|s| s == name) {
        selected.remove(p);
    } else {
        selected.push(name.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn click_selects_exclusively_checkbox_and_ctrl_add() {
        let mut s = vec!["a".to_string()];
        apply_event(&mut s, "b", CardEvent::Select, false);
        assert_eq!(s, ["b"]);
        apply_event(&mut s, "c", CardEvent::Toggle, false);
        assert_eq!(s, ["b", "c"]);
        apply_event(&mut s, "b", CardEvent::Select, true);
        assert_eq!(s, ["c"]);
        apply_event(&mut s, "c", CardEvent::None, false);
        assert_eq!(s, ["c"]);
        apply_event(&mut s, "c", CardEvent::Toggle, false);
        assert!(s.is_empty());
    }
}
