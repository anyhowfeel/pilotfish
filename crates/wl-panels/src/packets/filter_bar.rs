//! Display-filter input with debounced validation, status dot, history and quick chips.

use std::sync::Arc;

use eframe::egui::{self, CursorIcon, Key, RichText, Sense, Ui, Vec2};

use crate::features::{FieldCatalog, FilterAutocomplete, ValueIndex};
use crate::packets::actions::PacketsAction;
use crate::packets::filter_history::History;
use crate::packets::filter_presets::{Presets, SavedFilter};
use crate::packets::kit::{Palette, danger, ok, spacing, warn};
use crate::packets::presets_menu::{self, MenuEdit};
use crate::packets::quick_bar;
use crate::packets::quick_filter::QuickChip;

const DEBOUNCE_S: f64 = 0.35;

#[derive(Debug, Clone, PartialEq)]
pub enum FilterStatus {
    Empty,
    Pending,
    Valid,
    Invalid(String),
}

pub struct FilterBar {
    text: String,
    status: FilterStatus,
    /// Time of the last edit that still needs validation.
    edited_at: Option<f64>,
    history: History,
    presets: Presets,
    presets_edit: MenuEdit,
    autocomplete: FilterAutocomplete,
}

impl Default for FilterBar {
    fn default() -> Self {
        Self {
            text: String::new(),
            status: FilterStatus::Empty,
            edited_at: None,
            history: History::default(),
            presets: Presets::default(),
            presets_edit: MenuEdit::default(),
            autocomplete: FilterAutocomplete::default(),
        }
    }
}

impl FilterBar {
    pub fn set_values(&mut self, values: Arc<ValueIndex>) {
        self.autocomplete.set_values(values);
    }
    pub fn set_catalog(&mut self, catalog: Arc<FieldCatalog>) {
        self.autocomplete.set_catalog(catalog);
    }
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn status(&self) -> &FilterStatus {
        &self.status
    }

    /// Reports the outcome of a `ValidateFilter` request.
    pub fn set_status(&mut self, result: Result<(), String>) {
        if self.edited_at.is_some() {
            return; // stale: the user typed again since the request
        }
        self.status = match result {
            Ok(()) if self.text.trim().is_empty() => FilterStatus::Empty,
            Ok(()) => FilterStatus::Valid,
            Err(e) => FilterStatus::Invalid(e),
        };
    }

    pub fn history(&self) -> Vec<String> {
        self.history.items().to_vec()
    }

    pub fn set_history(&mut self, items: Vec<String>) {
        self.history.set(items);
    }

    pub fn presets(&self) -> &[SavedFilter] {
        self.presets.items()
    }

    pub fn set_presets(&mut self, items: Vec<SavedFilter>) {
        self.presets.set(items);
    }

    /// Programmatic change (context menu, chips): starts validation immediately.
    pub fn set_text(&mut self, text: &str) {
        self.text = text.to_owned();
        self.mark_edited(f64::NEG_INFINITY);
    }

    fn mark_edited(&mut self, now: f64) {
        if self.text.trim().is_empty() {
            self.status = FilterStatus::Empty;
            self.edited_at = None;
        } else {
            self.status = FilterStatus::Pending;
            self.edited_at = Some(now);
        }
    }

    /// Returns the filter to validate if the debounce delay elapsed.
    fn due(&mut self, now: f64) -> Option<String> {
        let at = self.edited_at?;
        (now - at >= DEBOUNCE_S).then(|| {
            self.edited_at = None;
            self.text.trim().to_owned()
        })
    }

    fn apply(&mut self, out: &mut Vec<PacketsAction>) {
        if matches!(self.status, FilterStatus::Invalid(_)) {
            return;
        }
        self.history.push(&self.text);
        out.push(PacketsAction::ApplyFilter(self.text.trim().to_owned()));
    }

    fn dot(&self, ui: &mut Ui) {
        let (color, tip) = match &self.status {
            FilterStatus::Empty => (Palette::muted(), "No display filter".to_owned()),
            FilterStatus::Pending => (warn(), "Validating...".to_owned()),
            FilterStatus::Valid => (ok(), "Valid filter".to_owned()),
            FilterStatus::Invalid(e) => (danger(), e.clone()),
        };
        let (rect, resp) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 4.5, color);
        resp.on_hover_text(tip);
    }

    pub fn ui(&mut self, ui: &mut Ui, chips: &[QuickChip], open_quick: bool) -> Vec<PacketsAction> {
        let mut out = Vec::new();
        let now = ui.input(|i| i.time);
        let mut chosen: Option<String> = None;
        ui.horizontal(|ui| {
            self.dot(ui);
            // Buttons are right-anchored; the text field takes exactly what remains.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let apply_btn = ui
                    .button("Apply")
                    .on_hover_cursor(CursorIcon::PointingHand)
                    .on_hover_text("Apply display filter (Enter)");
                if let Some(expr) =
                    presets_menu::menu(ui, &mut self.presets, &self.text, &mut self.presets_edit)
                {
                    chosen = Some(expr);
                }
                let hist = self.history.items().to_vec();
                ui.add_enabled_ui(!hist.is_empty(), |ui| {
                    ui.menu_button("History", |ui| {
                        for h in &hist {
                            if ui.button(h).clicked() {
                                chosen = Some(h.clone());
                                ui.close();
                            }
                        }
                    });
                });
                let edit = ui.add(
                    wl_kit::widgets::text_field(&mut self.text)
                        .hint_text("Display filter, e.g. tcp.port == 443 && ip.addr == 10.0.0.1")
                        .font(egui::TextStyle::Monospace)
                        .lock_focus(self.autocomplete.is_open())
                        .desired_width(ui.available_width().max(80.0)),
                );
                if edit.has_focus()
                    && !self.text.is_empty()
                    && ui.input(|i| i.key_pressed(Key::Escape))
                {
                    self.text.clear();
                    self.mark_edited(now);
                } else if edit.changed() || self.autocomplete.ui(ui, &mut self.text, &edit) {
                    self.mark_edited(now);
                }
                let taken = self.autocomplete.take_enter();
                let enter = !taken && edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if apply_btn.clicked() || enter {
                    self.apply(&mut out);
                }
            });
        });
        ui.add_space(spacing::XS);
        if let Some(t) = quick_bar::ui(ui, &self.text, chips, open_quick) {
            chosen = Some(t);
        }
        if let FilterStatus::Invalid(e) = &self.status {
            ui.add_space(spacing::XS * 0.5);
            ui.add(egui::Label::new(RichText::new(e).small().color(danger())).truncate())
                .on_hover_text(e);
        }
        if let Some(c) = chosen {
            self.set_text(&c);
            self.status = if c.is_empty() {
                FilterStatus::Empty
            } else {
                FilterStatus::Valid
            };
            self.apply(&mut out);
        }
        if let Some(f) = self.due(now) {
            out.push(PacketsAction::ValidateFilter(f));
        } else if let Some(at) = self.edited_at {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs_f64(
                    (DEBOUNCE_S - (now - at)).max(0.01),
                ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_and_status_flow() {
        let mut b = FilterBar {
            text: "tcp".into(),
            ..Default::default()
        };
        b.mark_edited(10.0);
        assert_eq!(b.status, FilterStatus::Pending);
        assert!(b.due(10.1).is_none());
        assert_eq!(b.due(10.4).as_deref(), Some("tcp"));
        assert!(b.due(11.0).is_none());
        b.set_status(Err("bad".into()));
        assert_eq!(b.status, FilterStatus::Invalid("bad".into()));
        let mut out = vec![];
        b.apply(&mut out);
        assert!(out.is_empty(), "invalid filters are not applied");
        b.set_status(Ok(()));
        b.apply(&mut out);
        assert_eq!(out, [PacketsAction::ApplyFilter("tcp".into())]);
        assert_eq!(b.history(), ["tcp"]);
    }

    #[test]
    fn stale_result_is_ignored_and_empty_resets() {
        let mut b = FilterBar {
            text: "udp".into(),
            ..Default::default()
        };
        b.mark_edited(0.0);
        b.set_status(Ok(()));
        assert_eq!(b.status, FilterStatus::Pending);
        b.text.clear();
        b.mark_edited(1.0);
        assert_eq!(b.status, FilterStatus::Empty);
    }
}
