//! Generic time-based XY chart (lines + marker scatter) for stream graphs: same elapsed-time
//! axis as the throughput chart, legend, hover tooltip and drag-a-box-to-zoom.

use eframe::egui::{Color32, PointerButton, Ui};
use egui_plot::{
    Corner, HoverPosition, Legend, Line, MarkerShape, Plot, PlotPoint, PlotPoints, Points,
};

use super::time_axis::{label, time_ticks};

/// Marker of a scatter series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    Circle,
    Cross,
    Diamond,
    Up,
}

impl Marker {
    fn radius(self) -> f32 {
        match self {
            Marker::Circle => 2.5,
            Marker::Cross | Marker::Up => 4.5,
            Marker::Diamond => 5.0,
        }
    }

    fn shape(self) -> MarkerShape {
        match self {
            Marker::Circle => MarkerShape::Circle,
            Marker::Cross => MarkerShape::Cross,
            Marker::Diamond => MarkerShape::Diamond,
            Marker::Up => MarkerShape::Up,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeriesStyle {
    Line,
    Scatter(Marker),
}

/// One named series of `(seconds, value)` points.
pub struct XySeries {
    pub name: String,
    pub color: Color32,
    pub style: SeriesStyle,
    points: Vec<PlotPoint>,
}

impl XySeries {
    pub fn new(
        name: impl Into<String>,
        color: Color32,
        style: SeriesStyle,
        points: Vec<[f64; 2]>,
    ) -> Self {
        Self {
            name: name.into(),
            color,
            style,
            points: points.into_iter().map(PlotPoint::from).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

/// Draws the series. `id` must change with the data set (it keys the zoom state); drag a box to
/// zoom in, double-click to reset. `y_fmt` formats the Y axis and the tooltip value.
pub fn xy_chart(
    ui: &mut Ui,
    id: &str,
    series: &[XySeries],
    y_fmt: &dyn Fn(f64) -> String,
    height: f32,
) {
    let tip = |h: &HoverPosition<'_>| match h {
        HoverPosition::NearDataPoint {
            plot_name,
            position,
            ..
        } => Some(format!(
            "{plot_name}\n{:.4} s\n{}",
            position.x,
            y_fmt(position.y)
        )),
        HoverPosition::Elsewhere { .. } => None,
    };
    Plot::new(id)
        .height(height)
        .allow_drag(false)
        .allow_zoom(false)
        .allow_scroll(false)
        .allow_boxed_zoom(true)
        .boxed_zoom_pointer_button(PointerButton::Primary)
        .allow_double_click_reset(true)
        .include_y(0.0)
        .show_grid([false, true])
        .y_axis_min_width(76.0)
        .y_axis_formatter(|m, _| y_fmt(m.value))
        .x_grid_spacer(time_ticks)
        .x_axis_formatter(|m, _| label(m))
        .label_formatter(tip)
        .legend(Legend::default().position(Corner::LeftTop))
        .show(ui, |pu| {
            for s in series.iter().filter(|s| !s.is_empty()) {
                let pts = PlotPoints::from(s.points.as_slice());
                match s.style {
                    SeriesStyle::Line => {
                        // Never aggregated into a band: the points of a stream graph are few, and a
                        // band fills the envelope between pixel columns, which turns two points at the
                        // same time into a large filled polygon.
                        let line = Line::new(&s.name, pts)
                            .color(s.color)
                            .width(1.8)
                            .allow_band(false);
                        pu.line(line);
                    }
                    SeriesStyle::Scatter(m) => {
                        let p = Points::new(&s.name, pts).color(s.color);
                        pu.points(p.shape(m.shape()).radius(m.radius()).filled(true));
                    }
                }
            }
        });
}
