//! Responsive column set of the master table: narrow windows drop the least important columns
//! instead of scrolling sideways.

use wl_kit::table::TableCols;
use wl_kit::theme::spacing;
use wl_kit::widgets::METHOD_PILL_W;

pub const STATUS_COL_W: f32 = 84.0;
const TIME_W: f32 = 68.0;
const TYPE_W: f32 = 52.0;
const SIZE_W: f32 = 76.0;
pub const LAT_W: f32 = 124.0;
const FLEX_MIN: f32 = 80.0;
/// Widths from which the optional columns appear.
const KIND_FROM: f32 = 780.0;
const SIZE_FROM: f32 = 660.0;
const LAT_FROM: f32 = 560.0;
const TIME_FROM: f32 = 470.0;

/// Which optional columns are shown (Method, Host, URL and Status always are).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cols {
    pub time: bool,
    pub kind: bool,
    pub size: bool,
    pub latency: bool,
}

impl Cols {
    pub fn for_width(w: f32) -> Self {
        Self {
            time: w >= TIME_FROM,
            kind: w >= KIND_FROM,
            size: w >= SIZE_FROM,
            latency: w >= LAT_FROM,
        }
    }

    /// Table width below which the columns would not fit (item spacing included).
    pub fn min_width(self) -> f32 {
        let fixed = [
            if self.time { TIME_W } else { 0.0 },
            METHOD_PILL_W + 2.0 * spacing::SM,
            STATUS_COL_W,
            if self.kind { TYPE_W } else { 0.0 },
            if self.size { SIZE_W } else { 0.0 },
            if self.latency { LAT_W } else { 0.0 },
        ];
        let n = 4
            + usize::from(self.time)
            + usize::from(self.kind)
            + usize::from(self.size)
            + usize::from(self.latency);
        fixed.iter().sum::<f32>() + 2.0 * FLEX_MIN + spacing::SM * (n as f32 - 1.0)
    }

    pub fn build(self) -> TableCols {
        let mut t = TableCols::new();
        if self.time {
            t = t.num(TIME_W);
        }
        t = t
            .fixed(METHOD_PILL_W + 2.0 * spacing::SM)
            .flex(FLEX_MIN)
            .flex(FLEX_MIN)
            .fixed(STATUS_COL_W);
        if self.kind {
            t = t.fixed(TYPE_W);
        }
        if self.size {
            t = t.num(SIZE_W);
        }
        if self.latency {
            t = t.fixed(LAT_W);
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_widths_drop_columns_and_always_fit() {
        for w in [380.0_f32, 430.0, 520.0, 600.0, 700.0, 772.0, 900.0, 1400.0] {
            let c = Cols::for_width(w);
            assert!(c.min_width() <= w, "{w}: needs {}", c.min_width());
        }
        let n = Cols::for_width(380.0);
        assert!(!n.time && !n.kind && !n.size && !n.latency);
        let wide = Cols::for_width(1000.0);
        assert!(wide.kind && wide.size && wide.latency);
    }
}
