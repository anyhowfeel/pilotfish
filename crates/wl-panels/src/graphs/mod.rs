//! Graphs page: a modernised Wireshark I/O Graph (up to six filter series on a shared time axis).

mod cols;
mod interval;
mod metric;
mod panel;
mod rows;
mod series;
mod toolbar;
mod window_row;

#[cfg(test)]
mod layout_tests;

pub use interval::{Interval, auto_interval};
pub use metric::{Metric, totals, window_totals};
pub use panel::{GraphsAction, GraphsData, GraphsPanel, GraphsRequest};
pub use series::{MAX_SERIES, Preset, SeriesDef};
