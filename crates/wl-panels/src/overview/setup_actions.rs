//! Action buttons of the Setup bar: Start / Stop / Pause and Open.

use wl_kit::egui::{self, Align, Button, CursorIcon, FontId, Layout, Rect, RichText, Ui, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{centered_row, paint_elided};
use wl_model::CaptureOptions;

use super::actions::OverviewAction;
use super::setup_bar::{BarData, Verdict};
use super::setup_logic::{normalize_filter, start_blocker};

pub(super) fn action_row(
    ui: &mut Ui,
    o: &CaptureOptions,
    d: &BarData<'_>,
    v: &Verdict,
    out: &mut Vec<OverviewAction>,
) {
    centered_row(ui, 40.0, |ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let open = Button::new("Open pcap\u{2026}").min_size(vec2(120.0, 38.0));
            if ui
                .add(open)
                .on_hover_cursor(CursorIcon::PointingHand)
                .clicked()
            {
                out.push(OverviewAction::RequestOpenFile);
            }
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                if d.running {
                    running_buttons(ui, d.paused, out);
                } else {
                    start_buttons(ui, o, d, v, out);
                }
            });
        });
    });
}

fn running_buttons(ui: &mut Ui, paused: bool, out: &mut Vec<OverviewAction>) {
    let stop_txt = RichText::new("Stop capture")
        .strong()
        .color(Palette::on_danger());
    let stop = Button::new(stop_txt)
        .fill(Palette::danger())
        .min_size(vec2(150.0, 38.0));
    if ui
        .add(stop)
        .on_hover_cursor(CursorIcon::PointingHand)
        .clicked()
    {
        out.push(OverviewAction::Stop);
    }
    let pause_txt = RichText::new(if paused { "Resume" } else { "Pause" }).strong();
    let pause = Button::new(pause_txt).min_size(vec2(96.0, 38.0));
    if ui
        .add(pause)
        .on_hover_cursor(CursorIcon::PointingHand)
        .clicked()
    {
        out.push(OverviewAction::TogglePause);
    }
}

fn start_buttons(
    ui: &mut Ui,
    o: &CaptureOptions,
    d: &BarData<'_>,
    v: &Verdict,
    out: &mut Vec<OverviewAction>,
) {
    let txt = RichText::new("Start capture")
        .strong()
        .size(15.0)
        .color(Palette::on_accent());
    let start = Button::new(txt)
        .fill(Palette::accent())
        .min_size(vec2(170.0, 38.0));
    let problem = start_blocker(d.wireshark, o.problem());
    let enabled = problem.is_none() && v.ok != Some(false);
    let resp = ui.add_enabled(enabled, start);
    if enabled && resp.on_hover_cursor(CursorIcon::PointingHand).clicked() {
        let mut opts = o.clone();
        opts.capture_filter = normalize_filter(&o.capture_filter).unwrap_or_default();
        out.push(OverviewAction::StartLive(opts));
    }
    let (note, color) = match (problem, &v.text) {
        (Some(p), _) => (p.to_string(), Palette::muted()),
        (None, Some(t)) => (t.clone(), v.color),
        (None, None) => (format!("on {}", o.label()), Palette::muted()),
    };
    let w = ui.available_width().max(0.0);
    let (r, resp) = ui.allocate_exact_size(vec2(w, 38.0), egui::Sense::hover());
    let r = Rect::from_min_max(r.min + vec2(spacing::SM, 0.0), r.max);
    paint_elided(
        ui.painter(),
        r,
        &note,
        FontId::proportional(13.0),
        color,
        Align::Min,
    );
    resp.on_hover_text(if v.detail.is_empty() {
        &note
    } else {
        &v.detail
    });
}
