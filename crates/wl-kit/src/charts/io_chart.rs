//! Multi-series interval chart (Wireshark I/O graph): lines, areas or bars on a shared elapsed-time
//! axis, optional log-Y, drag-to-select time window and a hover crosshair with a value tooltip.

use eframe::egui::{Color32, Rect, Stroke, Ui, pos2};
use egui_plot::{
    Bar, BarChart, GridInput, GridMark, Line, Plot, PlotPoints, PlotTransform, Points,
};

use super::io_scale::{bucket_at, from_plot, log_ticks, runs, to_plot};
use super::select::TimeSelection;
use super::throughput::{handle_drag, paint_selection};
use super::time_axis::{label, time_ticks};
use super::tooltip::{self, TipRow};
use super::unit::{Unit, compact};
use crate::format;
use crate::theme::{Palette, tint};
use crate::widgets::empty_state;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawMode {
    Line,
    Area,
    Bars,
}

/// One drawn series; `values[i]` is the value of bucket `i` (NaN = no data, a gap).
pub struct PlotSeries<'a> {
    pub name: &'a str,
    pub color: Color32,
    pub unit: Unit,
    pub values: &'a [f64],
}

pub struct ChartConfig {
    pub interval: f64,
    pub mode: DrawMode,
    pub log_y: bool,
    pub height: f32,
    /// Capture duration in seconds (X axis extent).
    pub duration: f64,
}

/// The Y axis shows `unit` when every series shares it, plain compact numbers otherwise.
fn shared_unit(series: &[PlotSeries<'_>]) -> Option<Unit> {
    let first = series.first()?.unit;
    series.iter().all(|s| s.unit == first).then_some(first)
}

fn y_max(series: &[PlotSeries<'_>]) -> f64 {
    series
        .iter()
        .flat_map(|s| s.values.iter().copied())
        .filter(|v| v.is_finite())
        .fold(0.0, f64::max)
}

fn log_marks(input: GridInput) -> Vec<GridMark> {
    let top = from_plot(input.bounds.1, true);
    log_ticks(top)
        .into_iter()
        .map(|v| GridMark {
            value: to_plot(v, true),
            step_size: 1.0,
        })
        .collect()
}

/// At most about `max_points` points: the lowest and the highest value of each stretch, in time order,
/// so that no spike is lost and the line stays cheap to draw however many buckets there are.
fn decimate(points: Vec<[f64; 2]>, max_points: usize) -> Vec<[f64; 2]> {
    if points.len() <= max_points || max_points < 4 {
        return points;
    }
    let stretch = points.len().div_ceil(max_points / 2);
    let mut out = Vec::with_capacity(max_points + 2);
    for part in points.chunks(stretch) {
        let (mut lo, mut hi) = (part[0], part[0]);
        for p in part {
            if p[1] < lo[1] {
                lo = *p;
            }
            if p[1] > hi[1] {
                hi = *p;
            }
        }
        match (lo == hi, lo[0] <= hi[0]) {
            (true, _) => out.push(lo),
            (false, true) => out.extend([lo, hi]),
            (false, false) => out.extend([hi, lo]),
        }
    }
    out
}

fn add_series(
    pu: &mut egui_plot::PlotUi<'_>,
    s: &PlotSeries<'_>,
    cfg: &ChartConfig,
    max_points: usize,
) {
    for (start, run) in runs(s.values) {
        let points: Vec<[f64; 2]> = run
            .iter()
            .enumerate()
            .map(|(k, v)| {
                let x = ((start + k) as f64 + 0.5) * cfg.interval;
                [x, to_plot(*v, cfg.log_y)]
            })
            .collect();
        let lone = (run.len() == 1).then(|| points.clone());
        // Never folded into egui_plot's band: its sharp corners draw needles far below the baseline.
        let mut line = Line::new(s.name, PlotPoints::from(decimate(points, max_points)))
            .color(s.color)
            .width(2.0)
            .allow_band(false);
        if cfg.mode == DrawMode::Area {
            line = line.fill(0.0).fill_alpha(0.14);
        }
        pu.line(line);
        if let Some(p) = lone {
            pu.points(
                Points::new(s.name, PlotPoints::from(p))
                    .color(s.color)
                    .radius(3.0),
            );
        }
    }
}

fn add_bars(pu: &mut egui_plot::PlotUi<'_>, series: &[PlotSeries<'_>], cfg: &ChartConfig) {
    let n = series.len().max(1) as f64;
    let w = cfg.interval * 0.84 / n;
    for (k, s) in series.iter().enumerate() {
        let off = (k as f64 - (n - 1.0) / 2.0) * w;
        let bars = s
            .values
            .iter()
            .enumerate()
            .filter(|(_, v)| v.is_finite() && **v > 0.0)
            .map(|(i, v)| {
                Bar::new(
                    (i as f64 + 0.5) * cfg.interval + off,
                    to_plot(*v, cfg.log_y),
                )
                .width(w)
                .fill(s.color)
            })
            .collect();
        pu.bar_chart(BarChart::new(s.name, bars).color(s.color));
    }
}

/// Draws the chart. Returns the bucket under the pointer, if any.
pub fn io_chart(
    ui: &mut Ui,
    series: &[PlotSeries<'_>],
    cfg: &ChartConfig,
    selection: &mut Option<TimeSelection>,
) -> Option<usize> {
    let n = series.iter().map(|s| s.values.len()).max().unwrap_or(0);
    if n == 0 {
        ui.allocate_ui(eframe::egui::vec2(ui.available_width(), cfg.height), |ui| {
            empty_state(ui, "~", "No data", "Add a series or wait for packets.");
        });
        return None;
    }
    let unit = shared_unit(series);
    // About two points per pixel column are all the eye can tell apart.
    let max_points = (ui.available_width().max(100.0) * 2.0) as usize;
    let top = to_plot(y_max(series), cfg.log_y).max(1.0) * 1.08;
    let log = cfg.log_y;
    let mut plot = Plot::new("wl_io_chart")
        .height(cfg.height)
        .allow_drag(false)
        .allow_zoom(false)
        .allow_scroll(false)
        .allow_boxed_zoom(false)
        .allow_double_click_reset(false)
        .show_grid([false, true])
        .include_x(0.0)
        .include_x(cfg.duration.max(n as f64 * cfg.interval))
        .include_y(0.0)
        .include_y(top)
        .y_axis_min_width(76.0)
        .y_axis_formatter(move |m, _| {
            let v = from_plot(m.value, log).max(0.0);
            unit.map_or_else(|| compact(v), |u| u.format(v))
        })
        .x_grid_spacer(time_ticks)
        .x_axis_formatter(|m, _| label(m));
    if log {
        plot = plot.y_grid_spacer(log_marks);
    }
    let out = plot.show(ui, |pu| {
        if cfg.mode == DrawMode::Bars {
            add_bars(pu, series, cfg);
        } else {
            series
                .iter()
                .for_each(|s| add_series(pu, s, cfg, max_points));
        }
    });
    handle_drag(ui, &out, selection);
    paint_selection(ui, &out.transform, selection.as_ref());
    hover(ui, &out.response, &out.transform, series, cfg, n)
}

fn hover(
    ui: &Ui,
    resp: &eframe::egui::Response,
    tr: &PlotTransform,
    series: &[PlotSeries<'_>],
    cfg: &ChartConfig,
    n: usize,
) -> Option<usize> {
    let pos = resp.hover_pos().filter(|p| tr.frame().contains(*p))?;
    let i = bucket_at(tr.value_from_position(pos).x, cfg.interval, n)?;
    let frame: Rect = *tr.frame();
    let x = tr.position_from_point_x((i as f64 + 0.5) * cfg.interval);
    let p = ui.painter().with_clip_rect(frame);
    p.line_segment(
        [pos2(x, frame.top()), pos2(x, frame.bottom())],
        Stroke::new(1.0, tint(Palette::text(), 90)),
    );
    let mut rows = Vec::with_capacity(series.len());
    for s in series {
        let v = s.values.get(i).copied().filter(|v| v.is_finite());
        if let Some(v) = v {
            let y = tr.position_from_point_y(to_plot(v, cfg.log_y));
            p.circle_filled(pos2(x, y), 4.0, s.color);
            p.circle_stroke(pos2(x, y), 4.0, Stroke::new(1.5, Palette::bg()));
        }
        rows.push(TipRow {
            color: s.color,
            name: s.name,
            value: v.map_or_else(|| "\u{2013}".into(), |v| s.unit.format(v)),
        });
    }
    let (a, b) = (i as f64 * cfg.interval, (i + 1) as f64 * cfg.interval);
    let header = format!(
        "{} \u{2013} {}",
        clock_ms(a, cfg.interval),
        clock_ms(b, cfg.interval)
    );
    tooltip::show(ui, resp.id.with("tip"), &header, &rows);
    Some(i)
}

/// Clock with a fraction when the interval is below one second ("0:12.4").
fn clock_ms(t: f64, interval: f64) -> String {
    if interval >= 1.0 {
        format::clock(t)
    } else {
        let tenths = (t.max(0.0) * 10.0).round() as u64;
        format!("{}.{}", format::clock((tenths / 10) as f64), tenths % 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spiky(n: usize) -> Vec<[f64; 2]> {
        (0..n)
            .map(|i| {
                [
                    i as f64,
                    if i % 97 == 0 {
                        1000.0 + i as f64
                    } else {
                        (i % 7) as f64
                    },
                ]
            })
            .collect()
    }

    #[test]
    fn decimating_keeps_every_spike_and_the_time_order_within_the_budget() {
        let pts = spiky(50_000);
        let max = pts.iter().map(|p| p[1]).fold(f64::MIN, f64::max);
        let min = pts.iter().map(|p| p[1]).fold(f64::MAX, f64::min);
        let out = decimate(pts.clone(), 2600);
        assert!(out.len() <= 2600 + 2, "{} points", out.len());
        assert!(
            out.windows(2).all(|w| w[0][0] <= w[1][0]),
            "time never goes back"
        );
        assert_eq!(out.iter().map(|p| p[1]).fold(f64::MIN, f64::max), max);
        assert_eq!(out.iter().map(|p| p[1]).fold(f64::MAX, f64::min), min);
        // Every spike of the signal is still there.
        let spikes = |v: &[[f64; 2]]| v.iter().filter(|p| p[1] >= 1000.0).count();
        assert_eq!(spikes(&out), spikes(&pts));
    }

    #[test]
    fn a_short_series_is_left_alone() {
        let pts = spiky(300);
        assert_eq!(decimate(pts.clone(), 2600), pts);
        assert_eq!(
            decimate(spiky(5000), 3).len(),
            5000,
            "no budget worth the name"
        );
    }

    #[test]
    fn sub_second_clock_has_a_tenth() {
        assert_eq!(clock_ms(12.4, 0.1), "0:12.4");
        assert_eq!(clock_ms(75.0, 1.0), "1:15");
    }
}
