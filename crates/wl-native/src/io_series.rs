//! Per-interval packet and byte series for the Graphs page, one pass over the file.
//!
//! Gives what `tshark -q -z io,stat,<interval>,...` gives (see `wl-tshark/src/io_stat.rs`):
//! buckets start at the first packet, a packet joins bucket `floor(time / interval)`, the table
//! has `ceil(duration / interval)` rows, and `frame.time_delta` is the distance to the previous
//! packet of the file whether or not it matches the filter.

use std::path::Path;

use wl_model::{CaptureError, IoGraph, IoSpec};

use crate::decode::Decoder;
use crate::filter::{self, Filter};
use crate::reader::{self, Stamp};

mod clock;
mod column;

use clock::Clock;
use column::Column;

/// Smallest interval tshark handles sensibly, as in `wl-tshark`.
const MIN_INTERVAL: f64 = 0.001;

/// `None` when any spec has a filter outside the native subset; the file is not read then.
pub fn compute(
    path: &Path,
    specs: &[IoSpec],
    interval: f64,
) -> Option<Result<IoGraph, CaptureError>> {
    let filters = specs
        .iter()
        .map(|s| match s.filter.trim() {
            "" => Some(None),
            text => filter::parse(text).map(Some),
        })
        .collect::<Option<Vec<Option<Filter>>>>()?;
    let interval = if interval.is_finite() {
        interval.max(MIN_INTERVAL)
    } else {
        1.0
    };
    let columns = specs
        .iter()
        .zip(filters)
        .map(|(spec, filter)| Column::new(spec, filter))
        .collect();
    Some(run(path, columns, interval))
}

fn run(path: &Path, mut columns: Vec<Column>, interval: f64) -> Result<IoGraph, CaptureError> {
    let mut source = reader::open(path)?;
    let mut clock = Clock::new(interval);
    let mut decoder = Decoder::default();
    let filtered = columns.iter().any(|c| c.filter().is_some());
    let mut data = Vec::new();
    let mut first_epoch = None;
    while let Some(meta) = source.next_packet(&mut data)? {
        let at = source.info().current.unwrap_or(Stamp::ZERO);
        let tick = clock.tick(&at)?;
        let origin = *first_epoch.get_or_insert(meta.epoch);
        let decoded = filtered.then(|| decoder.decode(&meta, &data, origin));
        for column in &mut columns {
            let wanted = match (column.filter(), &decoded) {
                (Some(f), Some(d)) => f.matches(d),
                _ => true,
            };
            if wanted {
                column.add(tick.index, meta.orig_len, tick.delta);
            }
        }
    }
    let buckets = clock.buckets()?;
    Ok(IoGraph {
        interval,
        duration: clock.duration(),
        series: columns.into_iter().map(|c| c.finish(buckets)).collect(),
    })
}

#[cfg(test)]
#[path = "io_series_limits_tests.rs"]
mod limits_tests;
#[cfg(test)]
#[path = "io_series_tests.rs"]
mod tests;
