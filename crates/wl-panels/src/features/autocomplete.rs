//! egui dropdown widget for display-filter field autocomplete.

use std::sync::Arc;

use eframe::egui::{
    self, Align, Area, CornerRadius, Frame, Key, Layout, Margin, Order, Response, RichText, Sense,
    Stroke, Ui, pos2,
};
use wl_kit::theme::{Palette, RADIUS, mono, spacing};

pub use crate::features::autocomplete_catalog::{FieldCatalog, active_token, apply_completion};

const MAX_SUGGESTIONS: usize = 8;

/// Stateful dropdown helper that attaches to any filter `TextEdit` response.
#[derive(Default)]
pub struct FilterAutocomplete {
    catalog: Arc<FieldCatalog>,
    selected: usize,
    dismissed_for: String,
    open: bool,
    enter_taken: bool,
}

impl FilterAutocomplete {
    pub fn new(catalog: Arc<FieldCatalog>) -> Self {
        Self {
            catalog,
            selected: 0,
            dismissed_for: String::new(),
            open: false,
            enter_taken: false,
        }
    }

    /// Replaces the catalog once background `tshark -G fields` completes.
    pub fn set_catalog(&mut self, catalog: Arc<FieldCatalog>) {
        self.catalog = catalog;
    }

    /// True while the suggestion popup is showing; the field should then keep Tab for itself.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// True once after an Enter that accepted a suggestion, so the caller must not also apply.
    pub fn take_enter(&mut self) -> bool {
        std::mem::take(&mut self.enter_taken)
    }

    pub fn catalog(&self) -> &FieldCatalog {
        &self.catalog
    }

    /// Renders dropdown suggestions below `input_resp`. Returns `true` if `expr` was updated.
    pub fn ui(&mut self, ui: &mut Ui, expr: &mut String, input_resp: &Response) -> bool {
        let enter = ui.input(|i| i.key_pressed(Key::Enter));
        let enter_on_popup = self.open && enter && input_resp.lost_focus();
        let was_open = std::mem::take(&mut self.open);
        if !input_resp.has_focus() && !enter_on_popup {
            return false;
        }
        let cursor = expr.chars().count();
        let (_, _, tok) = active_token(expr, cursor);
        if tok.len() < 2 || tok == self.dismissed_for {
            return false;
        }
        let matches: Vec<_> = self
            .catalog
            .suggest(tok, MAX_SUGGESTIONS)
            .into_iter()
            .cloned()
            .collect();
        if matches.is_empty() {
            return false;
        }
        self.selected = self.selected.min(matches.len() - 1);

        let (down, up, tab, back_tab, esc) = ui.input(|i| {
            (
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::Tab) && !i.modifiers.shift,
                i.key_pressed(Key::Tab) && i.modifiers.shift,
                i.key_pressed(Key::Escape),
            )
        });
        if esc {
            self.dismissed_for = tok.to_owned();
            return false;
        }
        let n = matches.len();
        if down || (tab && was_open) {
            self.selected = (self.selected + 1) % n;
        }
        if up || (back_tab && was_open) {
            self.selected = self.selected.checked_sub(1).unwrap_or(n - 1);
        }
        let picked = &matches[self.selected].abbrev;
        let mut chosen = None;
        if enter_on_popup || (enter && was_open && input_resp.has_focus()) {
            if picked == tok {
                self.dismissed_for = tok.to_owned();
                return false;
            }
            chosen = Some(picked.clone());
            self.enter_taken = true;
            input_resp.request_focus();
        }
        self.open = true;

        let pos = pos2(
            input_resp.rect.left(),
            input_resp.rect.bottom() + spacing::XS,
        );
        let width = input_resp.rect.width().clamp(280.0, 520.0);
        Area::new(egui::Id::NULL.with("wl_filter_autocomplete_popup"))
            .order(Order::Foreground)
            .fixed_pos(pos)
            .show(ui.ctx(), |ui| {
                Frame::new()
                    .fill(Palette::surface())
                    .stroke(Stroke::new(1.0, Palette::border()))
                    .corner_radius(CornerRadius::same(RADIUS))
                    .inner_margin(Margin::same(spacing::XS as i8))
                    .show(ui, |ui| {
                        ui.set_width(width);
                        for (idx, item) in matches.iter().enumerate() {
                            let fill = if idx == self.selected {
                                Palette::selection_bg()
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            let resp = Frame::new()
                                .fill(fill)
                                .corner_radius(CornerRadius::same(4))
                                .inner_margin(Margin::symmetric(
                                    spacing::SM as i8,
                                    spacing::XS as i8,
                                ))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(mono(&item.abbrev).color(Palette::text()));
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&item.name)
                                                    .small()
                                                    .color(Palette::muted()),
                                            )
                                            .truncate(),
                                        );
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                ui.label(
                                                    mono(&item.field_type)
                                                        .small()
                                                        .color(Palette::accent()),
                                                );
                                            },
                                        );
                                    });
                                })
                                .response
                                .interact(Sense::click());
                            if resp.clicked() {
                                chosen = Some(item.abbrev.clone());
                            }
                        }
                    });
            });

        if let Some(abbrev) = chosen {
            let (updated, _) = apply_completion(expr, cursor, &abbrev);
            *expr = updated;
            self.dismissed_for.clone_from(&abbrev);
            self.selected = 0;
            return true;
        }
        false
    }
}
