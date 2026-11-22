use wl_kit::egui::{Align, Color32, Label, Layout, RichText, Sense, Ui, UiBuilder, vec2};
use wl_kit::table::CELL_PAD;
use wl_kit::theme::{Palette, ROW_H, mono, spacing};
use wl_kit::widgets::{badge, section_header};
use wl_stats::{Metric, Presence, Row};

/// Rows drawn per section, to keep frames short on huge diffs.
const MAX_ROWS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Show {
    #[default]
    All,
    Added,
    Removed,
    Changed,
}

impl Show {
    pub fn admits(self, p: Presence) -> bool {
        match self {
            Show::All => true,
            Show::Added => p == Presence::Added,
            Show::Removed => p == Presence::Removed,
            Show::Changed => p == Presence::Changed,
        }
    }
}

fn tag(p: Presence) -> (&'static str, Color32) {
    match p {
        Presence::Added => ("new", Palette::ok()),
        Presence::Removed => ("gone", Palette::danger()),
        Presence::Changed => ("diff", Palette::warn()),
    }
}

const BADGE_W: f32 = 52.0;
const VALUE_W: f32 = 150.0;
const CHANGE_W: f32 = 64.0;
const LABEL_MIN_W: f32 = 120.0;
/// Narrowest table: below this the report scrolls sideways instead of clipping columns.
pub const MIN_WIDTH: f32 = BADGE_W + LABEL_MIN_W + 2.0 * VALUE_W + CHANGE_W;

/// Percent move of `after` against `before`, `None` when either side is missing or zero.
pub(super) fn change<V: Metric>(r: &Row<V>) -> Option<(String, Color32)> {
    let (b, a) = (r.before?.size(), r.after?.size());
    if b == 0 || a == b {
        return None;
    }
    let pct = (a as f64 - b as f64) / b as f64 * 100.0;
    Some((format!("{pct:+.0}%"), Palette::muted()))
}

fn cell(ui: &mut Ui, width: f32, right: bool, add: impl FnOnce(&mut Ui)) {
    let layout = if right {
        Layout::right_to_left(Align::Center)
    } else {
        Layout::left_to_right(Align::Center)
    };
    ui.allocate_ui_with_layout(vec2(width, ROW_H), layout, |ui| {
        ui.set_min_size(vec2(width, ROW_H));
        ui.set_clip_rect(ui.max_rect().intersect(ui.clip_rect()));
        ui.add_space(CELL_PAD);
        add(ui);
    });
}

fn text_label(ui: &mut Ui, text: RichText, align: Align) {
    ui.add(Label::new(text).truncate().halign(align));
}

fn table_row(ui: &mut Ui, width: f32, stripe: bool, cells: impl FnOnce(&mut Ui, f32)) {
    let (rect, _) = ui.allocate_exact_size(vec2(width, ROW_H), Sense::hover());
    if stripe {
        ui.painter()
            .rect_filled(rect, 0.0, ui.visuals().faint_bg_color);
    }
    let label_w = width - BADGE_W - 2.0 * VALUE_W - CHANGE_W;
    let mut row = ui.new_child(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::left_to_right(Align::Center)),
    );
    row.spacing_mut().item_spacing.x = 0.0;
    cells(&mut row, label_w);
}

fn header(ui: &mut Ui, width: f32) {
    let head = |t: &str| {
        RichText::new(t.to_owned())
            .small()
            .strong()
            .color(Palette::muted())
    };
    table_row(ui, width, false, |ui, label_w| {
        cell(ui, BADGE_W, false, |_| {});
        cell(ui, label_w, false, |ui| {
            text_label(ui, head("Name"), Align::LEFT)
        });
        cell(ui, VALUE_W, true, |ui| {
            text_label(ui, head("Before"), Align::RIGHT)
        });
        cell(ui, VALUE_W, true, |ui| {
            text_label(ui, head("After"), Align::RIGHT)
        });
        cell(ui, CHANGE_W, true, |ui| {
            text_label(ui, head("Change"), Align::RIGHT)
        });
    });
}

pub fn section<V: Metric>(
    ui: &mut Ui,
    width: f32,
    title: &str,
    rows: &[Row<V>],
    fmt: fn(&V) -> String,
    show: Show,
) {
    let shown: Vec<&Row<V>> = rows.iter().filter(|r| show.admits(r.presence())).collect();
    if shown.is_empty() {
        return;
    }
    ui.add_space(spacing::SM);
    section_header(ui, &format!("{title} ({})", shown.len()));
    ui.spacing_mut().item_spacing.y = 0.0;
    header(ui, width);
    let value = |v: &Option<V>| v.as_ref().map_or("-".to_owned(), fmt);
    for (i, r) in shown.iter().take(MAX_ROWS).enumerate() {
        let (label, color) = tag(r.presence());
        table_row(ui, width, i % 2 == 0, |ui, label_w| {
            cell(ui, BADGE_W, false, |ui| {
                badge(ui, label, color);
            });
            cell(ui, label_w, false, |ui| {
                text_label(ui, mono(&r.label), Align::LEFT)
            });
            cell(ui, VALUE_W, true, |ui| {
                text_label(
                    ui,
                    RichText::new(value(&r.before)).color(Palette::muted()),
                    Align::RIGHT,
                );
            });
            cell(ui, VALUE_W, true, |ui| {
                text_label(ui, RichText::new(value(&r.after)), Align::RIGHT)
            });
            cell(ui, CHANGE_W, true, |ui| {
                if let Some((text, color)) = change(r) {
                    text_label(ui, RichText::new(text).color(color), Align::RIGHT);
                }
            });
        });
    }
    if shown.len() > MAX_ROWS {
        let more = shown.len() - MAX_ROWS;
        ui.label(RichText::new(format!("{more} more not shown")).color(Palette::muted()));
    }
}
