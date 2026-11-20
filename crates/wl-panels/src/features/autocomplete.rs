//! egui dropdown widget for display-filter field autocomplete.

use eframe::egui::{
    self, Align, Area, CornerRadius, Frame, Key, Layout, Margin, Order, Response, RichText, Sense,
    Stroke, Ui, pos2,
};
use wl_kit::theme::{Palette, RADIUS, mono, spacing};
use wl_model::FilterField;

pub use crate::features::autocomplete_catalog::{FieldCatalog, active_token, apply_completion};

const MAX_SUGGESTIONS: usize = 8;

/// Stateful dropdown helper that attaches to any filter `TextEdit` response.
#[derive(Default)]
pub struct FilterAutocomplete {
    catalog: FieldCatalog,
    selected: usize,
    dismissed_for: String,
}

impl FilterAutocomplete {
    pub fn new(catalog: FieldCatalog) -> Self {
        Self {
            catalog,
            selected: 0,
            dismissed_for: String::new(),
        }
    }

    /// Replaces the catalog once background `tshark -G fields` completes.
    pub fn set_fields(&mut self, fields: Vec<FilterField>) {
        if !fields.is_empty() {
            self.catalog = FieldCatalog::from_fields(fields);
        }
    }

    pub fn catalog(&self) -> &FieldCatalog {
        &self.catalog
    }

    /// Renders dropdown suggestions below `input_resp`. Returns `true` if `expr` was updated.
    pub fn ui(&mut self, ui: &mut Ui, expr: &mut String, input_resp: &Response) -> bool {
        if !input_resp.has_focus() {
            return false;
        }
        let cursor = expr.chars().count();
        let (_, _, tok) = active_token(expr, cursor);
        if tok.len() < 2 || tok == self.dismissed_for {
            return false;
        }
        let matches: Vec<FilterField> = self
            .catalog
            .suggest(tok, MAX_SUGGESTIONS)
            .into_iter()
            .cloned()
            .collect();
        if matches.is_empty() {
            return false;
        }
        self.selected = self.selected.min(matches.len() - 1);

        let (down, up, accept, esc) = ui.input(|i| {
            (
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::Tab) || (i.key_pressed(Key::Enter) && i.modifiers.ctrl),
                i.key_pressed(Key::Escape),
            )
        });
        if esc {
            self.dismissed_for = tok.to_owned();
            return false;
        }
        if down {
            self.selected = (self.selected + 1) % matches.len();
        }
        if up {
            self.selected = self.selected.checked_sub(1).unwrap_or(matches.len() - 1);
        }
        let mut chosen: Option<String> = accept.then(|| matches[self.selected].abbrev.clone());

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
            self.dismissed_for.clear();
            self.selected = 0;
            return true;
        }
        false
    }
}
