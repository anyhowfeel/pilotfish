//! Charts: egui_plot throughput + I/O graph + XY charts, and painted proportion/ranked bars.

mod bars;
mod io_chart;
#[cfg(test)]
mod io_chart_tests;
mod io_scale;
mod layout;
mod select;
mod throughput;
#[cfg(test)]
mod throughput_tests;
mod time_axis;
mod tooltip;
mod unit;
mod xy;

pub use bars::{proportion_bar, protocol_ranked_bars, ranked_bars};
pub use io_chart::{ChartConfig, DrawMode, PlotSeries, io_chart};
pub use io_scale::{bucket_at, from_plot, log_ticks, to_plot};
pub use layout::{fraction, segment_widths};
pub use select::{MIN_WINDOW, TimeSelection};
pub use throughput::{throughput_chart, throughput_chart_select};
pub use unit::{Unit, compact};
pub use xy::{Marker, SeriesStyle, XySeries, xy_chart, xy_chart_with_reset};
