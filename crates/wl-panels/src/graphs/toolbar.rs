//! Toolbar above the chart: presets menu, interval, draw mode and Y scale. One row when it fits,
//! two rows when the window is narrow (never overlapping, never clipped).

use wl_kit::charts::DrawMode;
use wl_kit::egui::{Align, Layout, RichText, Ui, vec2};
use wl_kit::format;
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::segmented_w;

use super::interval::Interval;
use super::series::Preset;

const INTERVAL_W: f32 = 270.0;
const MODE_W: f32 = 195.0;
const SCALE_W: f32 = 130.0;
pub const TOOLBAR_H: f32 = 28.0;
/// Below this width the toolbar wraps to two rows.
const ONE_ROW_W: f32 = 880.0;
/// Below this width the interval control gets a row of its own (three rows).
const TWO_ROW_W: f32 = 600.0;
/// The bucket-width hint is dropped when less than this is left for it.
const HINT_W: f32 = 96.0;

pub struct ToolbarState<'a> {
    pub interval: &'a mut Interval,
    pub mode: &'a mut DrawMode,
    pub log_y: &'a mut bool,
    /// Resolved bucket width in seconds.
    pub resolved: f64,
    pub busy: bool,
    /// False once the series limit is reached (the Add button greys out).
    pub can_add: bool,
}

/// What the user did in the toolbar this frame.
#[derive(Default)]
pub struct ToolbarOut {
    pub preset: Option<Preset>,
    pub add: bool,
}

fn row<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), TOOLBAR_H),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = spacing::SM;
            add(ui)
        },
    )
    .inner
}

fn presets(ui: &mut Ui) -> Option<Preset> {
    let mut picked = None;
    ui.menu_button("Presets", |ui| {
        for p in Preset::ALL {
            if ui.button(p.label()).clicked() {
                picked = Some(p);
                ui.close();
            }
        }
    });
    picked
}

fn interval(ui: &mut Ui, v: &mut Interval) {
    ui.label(RichText::new("Interval").color(Palette::muted()));
    ui.push_id("interval", |ui| {
        segmented_w(ui, v, &Interval::CHOICES, INTERVAL_W)
    });
}

fn view_options(ui: &mut Ui, mode: &mut DrawMode, log_y: &mut bool) {
    let modes = [
        (DrawMode::Line, "Line"),
        (DrawMode::Area, "Area"),
        (DrawMode::Bars, "Bars"),
    ];
    ui.push_id("mode", |ui| segmented_w(ui, mode, &modes, MODE_W));
    let scales = [(false, "Linear"), (true, "Log Y")];
    ui.push_id("scale", |ui| segmented_w(ui, log_y, &scales, SCALE_W));
}

/// Right-aligned note: the bucket width, or that a pass is running. Skipped without room.
fn hint(ui: &mut Ui, st: &ToolbarState<'_>) {
    if ui.available_width() < HINT_W {
        return;
    }
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        let text = if st.busy {
            "Computing\u{2026}".to_owned()
        } else {
            format!("{} buckets", format::duration(st.resolved))
        };
        ui.label(RichText::new(text).small().color(Palette::muted()));
    });
}

/// Draws the toolbar; returns the preset picked and whether "Add series" was clicked.
pub fn toolbar(ui: &mut Ui, st: ToolbarState<'_>) -> ToolbarOut {
    let mut out = ToolbarOut::default();
    if ui.available_width() >= ONE_ROW_W {
        row(ui, |ui| {
            out.preset = presets(ui);
            out.add = super::rows::add_button(ui, st.can_add);
            interval(ui, st.interval);
            view_options(ui, st.mode, st.log_y);
            hint(ui, &st);
        });
    } else {
        row(ui, |ui| {
            out.preset = presets(ui);
            out.add = super::rows::add_button(ui, st.can_add);
            if ui.available_width() >= TWO_ROW_W {
                interval(ui, st.interval);
            }
        });
        if ui.available_width() < TWO_ROW_W {
            row(ui, |ui| interval(ui, st.interval));
        }
        row(ui, |ui| {
            view_options(ui, st.mode, st.log_y);
            hint(ui, &st);
        });
    }
    out
}
