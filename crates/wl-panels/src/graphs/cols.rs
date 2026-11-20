//! Column geometry shared by the series header and every series row, so they align exactly.

use wl_kit::egui::{Rect, pos2};
use wl_kit::theme::spacing;

pub const ROW_H: f32 = 28.0;
const SWATCH_W: f32 = 24.0;
const BTN_W: f32 = 28.0;
const GAP: f32 = spacing::SM;
/// `(minimum, desired)` widths of the resizable columns; the filter takes what is left over.
const NAME: (f32, f32) = (80.0, 128.0);
const METRIC: (f32, f32) = (104.0, 142.0);
const TOTAL: (f32, f32) = (96.0, 150.0);
const FILTER_MIN: f32 = 100.0;
/// Absolute floor of the filter column when even the reduced layout does not fit.
const FILTER_FLOOR: f32 = 40.0;

/// One rect per column of a row, left to right, separated by `spacing::SM`. `total` is `None`
/// when the row is too narrow for it (the app then shows the totals in the swatch tooltip).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cols {
    pub swatch: Rect,
    pub name: Rect,
    pub filter: Rect,
    pub metric: Rect,
    pub total: Option<Rect>,
    pub eye: Rect,
    pub remove: Rect,
}

impl Cols {
    pub fn new(row: Rect) -> Self {
        let fixed = SWATCH_W + 2.0 * BTN_W;
        // Seven columns with the totals, six without.
        let with_total = |cols: f32| row.width() - fixed - GAP * (cols - 1.0);
        let full = with_total(7.0) - FILTER_MIN - NAME.0 - METRIC.0 - TOTAL.0 >= 0.0;
        let budget = if full {
            with_total(7.0)
        } else {
            with_total(6.0)
        };
        let mins = [NAME.0, METRIC.0, if full { TOTAL.0 } else { 0.0 }];
        let wants = [NAME.1, METRIC.1, if full { TOTAL.1 } else { 0.0 }];
        // Minimums first, then growth up to the desired widths, the rest goes to the filter.
        let mut w = mins;
        let mut extra = (budget - FILTER_MIN - mins.iter().sum::<f32>()).max(0.0);
        for i in 0..3 {
            let grow = extra.min(wants[i] - w[i]);
            w[i] += grow;
            extra -= grow;
        }
        let filter = (budget - w.iter().sum::<f32>()).max(FILTER_FLOOR);
        let mut x = row.left();
        let mut take = |width: f32| {
            let r = Rect::from_min_max(pos2(x, row.top()), pos2(x + width, row.bottom()));
            x += width + GAP;
            r
        };
        Self {
            swatch: take(SWATCH_W),
            name: take(w[0]),
            filter: take(filter),
            metric: take(w[1]),
            total: full.then(|| take(w[2])),
            eye: take(BTN_W),
            remove: take(BTN_W),
        }
    }

    /// Every present column, left to right.
    #[cfg(test)]
    pub fn all(&self) -> Vec<Rect> {
        let mut v = vec![self.swatch, self.name, self.filter, self.metric];
        v.extend(self.total);
        v.extend([self.eye, self.remove]);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_kit::egui::vec2;

    fn row(w: f32) -> Rect {
        Rect::from_min_size(pos2(10.0, 20.0), vec2(w, ROW_H))
    }

    #[test]
    fn columns_tile_the_row_with_equal_gaps() {
        for w in [420.0, 520.0, 600.0, 700.0, 740.0, 1000.0, 1400.0, 2200.0] {
            let c = Cols::new(row(w));
            let all = c.all();
            for pair in all.windows(2) {
                let gap = pair[1].left() - pair[0].right();
                assert!((gap - spacing::SM).abs() < 1e-3, "{w}: gap {gap}");
            }
            assert!(
                (c.remove.right() - row(w).right()).abs() < 1e-3,
                "{w}: right edge"
            );
            assert_eq!(c.swatch.left(), 10.0);
            assert!(all.iter().all(|r| r.height() == ROW_H && r.top() == 20.0));
        }
    }

    #[test]
    fn wide_rows_get_desired_widths_and_a_flexible_filter() {
        let c = Cols::new(row(1400.0));
        assert_eq!(c.name.width(), NAME.1);
        assert_eq!(c.metric.width(), METRIC.1);
        assert_eq!(c.total.map(|t| t.width()), Some(TOTAL.1));
        assert!(c.filter.width() > 600.0);
    }

    #[test]
    fn medium_rows_keep_every_column_at_least_minimum_width() {
        let c = Cols::new(row(560.0));
        assert!(c.name.width() >= NAME.0 && c.metric.width() >= METRIC.0);
        assert!(c.total.is_some_and(|t| t.width() >= TOTAL.0));
        assert!(c.filter.width() >= FILTER_MIN - 1e-3);
    }

    #[test]
    fn narrow_rows_drop_the_totals_before_squeezing_the_rest() {
        let c = Cols::new(row(430.0));
        assert!(c.total.is_none());
        assert!(c.name.width() >= NAME.0 && c.filter.width() >= FILTER_MIN - 1e-3);
    }
}
