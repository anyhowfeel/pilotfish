//! egui dropdown widget for display-filter autocomplete: field names, then values of the capture.

use std::sync::Arc;

use eframe::egui::{
    self, Area, CornerRadius, Frame, Key, Layout, Margin, Order, Response, RichText, Sense, Stroke,
    Ui, pos2, text::CCursor, text::CCursorRange, vec2,
};
use wl_kit::theme::{Palette, RADIUS, mono, spacing};

pub use crate::features::autocomplete_catalog::{FieldCatalog, active_token, apply_completion};
use crate::features::autocomplete_context::{Active, Kind, active, quoted_insert};
pub use crate::features::autocomplete_values::ValueIndex;

const MAX_SUGGESTIONS: usize = 8;
const KIND_W: f32 = 78.0;
const ROW_H: f32 = 22.0;

/// One popup row: what is inserted, a short description and the right-hand tag.
struct Item {
    insert: String,
    hint: String,
    tag: String,
}

/// Stateful dropdown helper that attaches to any filter `TextEdit` response.
#[derive(Default)]
pub struct FilterAutocomplete {
    catalog: Arc<FieldCatalog>,
    values: Arc<ValueIndex>,
    selected: usize,
    dismissed_for: String,
    open: bool,
    enter_taken: bool,
}

impl FilterAutocomplete {
    pub fn new(catalog: Arc<FieldCatalog>) -> Self {
        Self {
            catalog,
            ..Self::default()
        }
    }

    /// Replaces the catalog once background `tshark -G fields` completes.
    pub fn set_catalog(&mut self, catalog: Arc<FieldCatalog>) {
        self.catalog = catalog;
    }

    pub fn set_values(&mut self, values: Arc<ValueIndex>) {
        self.values = values;
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

    fn items(&self, a: &Active, expr: &str) -> Vec<Item> {
        match a.kind {
            Kind::Field if a.token.len() >= 2 => self
                .catalog
                .suggest(a.token, MAX_SUGGESTIONS)
                .into_iter()
                .map(|f| Item {
                    insert: f.abbrev.clone(),
                    hint: f.name.clone(),
                    tag: f.field_type.clone(),
                })
                .collect(),
            Kind::Field => Vec::new(),
            Kind::Value { field } => self
                .values
                .suggest(field, a.token, MAX_SUGGESTIONS)
                .into_iter()
                .map(|s| Item {
                    insert: if s.quoted {
                        quoted_insert(expr, a, &s.text)
                    } else {
                        s.text
                    },
                    hint: s.detail,
                    tag: s.hint.to_owned(),
                })
                .collect(),
        }
    }

    /// Renders dropdown suggestions below `input_resp`. Returns `true` if `expr` was updated.
    pub fn ui(&mut self, ui: &mut Ui, expr: &mut String, input_resp: &Response) -> bool {
        let enter = ui.input(|i| i.key_pressed(Key::Enter));
        let enter_on_popup = self.open && enter && input_resp.lost_focus();
        let was_open = std::mem::take(&mut self.open);
        if !input_resp.has_focus() && !enter_on_popup {
            return false;
        }
        let cursor = cursor_char(ui, input_resp, expr);
        let act = active(expr, cursor);
        let (start, end, tok) = (act.start, act.end, act.token.to_owned());
        if tok == self.dismissed_for {
            return false;
        }
        let items = self.items(&act, expr);
        if items.is_empty() {
            return false;
        }
        self.selected = self.selected.min(items.len() - 1);

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
            self.dismissed_for = tok;
            return false;
        }
        let n = items.len();
        if down || (tab && was_open) {
            self.selected = (self.selected + 1) % n;
        }
        if up || (back_tab && was_open) {
            self.selected = self.selected.checked_sub(1).unwrap_or(n - 1);
        }
        let mut chosen = None;
        if enter_on_popup || (enter && was_open && input_resp.has_focus()) {
            if items[self.selected].insert == tok {
                self.dismissed_for = tok;
                return false;
            }
            chosen = Some(items[self.selected].insert.clone());
            self.enter_taken = true;
        }
        self.open = true;
        if let Some(clicked) = popup(ui, input_resp, &items, self.selected) {
            chosen = Some(clicked);
        }

        let Some(text) = chosen else { return false };
        let mut out = String::with_capacity(expr.len() + text.len());
        out.push_str(&expr[..start]);
        out.push_str(&text);
        out.push_str(&expr[end..]);
        let new_cursor = expr[..start].chars().count() + text.chars().count();
        *expr = out;
        move_cursor(ui, input_resp, new_cursor);
        self.dismissed_for = text;
        self.selected = 0;
        true
    }
}

/// Cursor of the text field in characters (end of text when egui has no state yet).
fn cursor_char(ui: &Ui, resp: &Response, expr: &str) -> usize {
    egui::TextEdit::load_state(ui.ctx(), resp.id)
        .and_then(|s| s.cursor.char_range())
        .map_or(usize::MAX, |r| r.primary.index.into())
        .min(expr.chars().count())
}

/// Puts the cursor after the inserted text and keeps the keyboard focus in the field.
fn move_cursor(ui: &Ui, resp: &Response, chars: usize) {
    if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), resp.id) {
        state
            .cursor
            .set_char_range(Some(CCursorRange::one(CCursor::new(chars))));
        state.store(ui.ctx(), resp.id);
    }
    resp.request_focus();
}

/// Draws the rows below the field; returns the text of a clicked row.
fn popup(ui: &Ui, input: &Response, items: &[Item], selected: usize) -> Option<String> {
    let pos = pos2(input.rect.left(), input.rect.bottom() + spacing::XS);
    let width = input.rect.width().clamp(280.0, 520.0);
    let mut clicked = None;
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
                    for (idx, item) in items.iter().enumerate() {
                        if row(ui, item, idx == selected) {
                            clicked = Some(item.insert.clone());
                        }
                    }
                });
        });
    clicked
}

fn row(ui: &mut Ui, item: &Item, selected: bool) -> bool {
    let fill = if selected {
        Palette::selection_bg()
    } else {
        egui::Color32::TRANSPARENT
    };
    Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(spacing::SM as i8, spacing::XS as i8))
        .show(ui, |ui| {
            let total = ui.available_width();
            ui.set_width(total);
            let text_w = total - KIND_W - spacing::SM;
            let name_w = if item.hint.is_empty() {
                0.0
            } else {
                text_w * 0.38
            };
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = spacing::SM;
                cell(ui, text_w - name_w, |ui| {
                    ui.add(egui::Label::new(mono(&item.insert).color(Palette::text())).truncate());
                });
                if name_w > 0.0 {
                    cell(ui, name_w, |ui| {
                        let hint = RichText::new(&item.hint).small().color(Palette::muted());
                        ui.add(egui::Label::new(hint).truncate());
                    });
                }
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(mono(&item.tag).small().color(Palette::accent()));
                });
            });
        })
        .response
        .interact(Sense::click())
        .clicked()
}

/// A fixed-width cell, so a long text is cut instead of running into its neighbour.
fn cell(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(
        vec2(width.max(20.0), ROW_H),
        Layout::left_to_right(egui::Align::Center),
        add,
    );
}
