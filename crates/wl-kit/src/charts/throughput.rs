use super::select::TimeSelection;
use super::time_axis::{label, time_ticks};
use eframe::egui::{PointerButton, Pos2, Rect, Stroke, Ui, pos2};
use egui_plot::{Line, Plot, PlotPoints, PlotResponse, PlotTransform};
use wl_model::RatePoint;

use crate::format;
use crate::theme::{Palette, tint};
use crate::widgets::empty_state;

/// Bytes/s over time (area + line). X axis: time elapsed since the start of the capture, so a
/// stopped capture or an opened file reads correctly ("now" only made sense while live).
pub fn throughput_chart(ui: &mut Ui, points: &[RatePoint], height: f32) {
    throughput_chart_select(ui, points, height, &mut None);
}

/// Same chart with a draggable time window: drag to select, click to clear. `selection` is owned
/// by the caller (it survives page changes); the selected span is shaded on the plot.
pub fn throughput_chart_select(
    ui: &mut Ui,
    points: &[RatePoint],
    height: f32,
    selection: &mut Option<TimeSelection>,
) {
    if points.is_empty() {
        ui.allocate_ui(eframe::egui::vec2(ui.available_width(), height), |ui| {
            empty_state(
                ui,
                "~",
                "No traffic yet",
                "Throughput appears once packets arrive.",
            );
        });
        return;
    }
    let pts: PlotPoints<'_> = points
        .iter()
        .map(|p| [p.t + p.dt / 2.0, p.bytes_per_sec()])
        .collect();
    let c = Palette::accent();
    let out = Plot::new("wl_kit_throughput")
        .height(height)
        .allow_drag(false)
        .allow_zoom(false)
        .allow_scroll(false)
        .allow_boxed_zoom(false)
        .allow_double_click_reset(false)
        .include_y(1024.0)
        .show_grid([false, true])
        .include_x(0.0)
        .y_axis_min_width(76.0)
        .y_axis_formatter(|m, _| format::rate(m.value))
        .x_grid_spacer(time_ticks)
        .x_axis_formatter(|m, _| label(m))
        .show(ui, |pu| {
            pu.line(
                Line::new("rate", pts)
                    .color(c)
                    .width(2.0)
                    .fill(0.0)
                    .fill_alpha(0.18),
            );
        });
    handle_drag(ui, &out, selection);
    paint_selection(ui, &out.transform, selection.as_ref());
}

/// Drag = new window, plain click = clear. The drag anchor lives in egui's temp memory.
pub(super) fn handle_drag(ui: &Ui, out: &PlotResponse<()>, selection: &mut Option<TimeSelection>) {
    let anchor_id = out.response.id.with("anchor");
    let x_at = |pos: Pos2| out.transform.value_from_position(pos).x;
    let r = &out.response;
    if r.drag_started_by(PointerButton::Primary)
        && let Some(p) = r.interact_pointer_pos()
    {
        ui.data_mut(|d| d.insert_temp(anchor_id, x_at(p)));
    }
    if r.dragged_by(PointerButton::Primary)
        && let (Some(a), Some(p)) = (
            ui.data(|d| d.get_temp::<f64>(anchor_id)),
            r.interact_pointer_pos(),
        )
    {
        *selection = TimeSelection::from_drag(a, x_at(p));
    }
    if r.clicked() {
        *selection = None;
    }
}

pub(super) fn paint_selection(ui: &Ui, tr: &PlotTransform, selection: Option<&TimeSelection>) {
    let Some(s) = selection else { return };
    let frame = *tr.frame();
    let (x0, x1) = (
        tr.position_from_point_x(s.from),
        tr.position_from_point_x(s.to),
    );
    let band = Rect::from_x_y_ranges(x0..=x1, frame.y_range()).intersect(frame);
    let p = ui.painter().with_clip_rect(frame);
    p.rect_filled(band, 0.0, tint(Palette::accent(), 38));
    for x in [x0, x1] {
        p.line_segment(
            [pos2(x, frame.top()), pos2(x, frame.bottom())],
            Stroke::new(1.0, Palette::accent()),
        );
    }
}
