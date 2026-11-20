//! Parser of the table printed by `tshark -q -z io,stat,<interval>,<calc>...`.
//!
//! Rows look like `|  10 <> 20  |     3 |  420 | 0.000123 |`. When the header is wider than the
//! terminal budget tshark may split the columns over several stacked tables; their rows are
//! joined by position, so the result is the same either way.

use wl_model::{DeltaStat, IoGraph, IoSeries, IoSpec};

/// Number of table columns a spec occupies: COUNT, SUM and the optional delta statistic.
pub fn columns_of(spec: &IoSpec) -> usize {
    2 + usize::from(spec.delta.is_some())
}

/// Value cells (everything after the interval cell, padding cells dropped) of one data row.
fn row_cells(line: &str) -> Option<Vec<&str>> {
    let inner = line.trim().strip_prefix('|')?;
    let mut cells = inner.split('|').map(str::trim);
    let first = cells.next()?;
    if !first.contains("<>") {
        return None;
    }
    Some(cells.filter(|c| !c.is_empty()).collect())
}

/// Capture duration from the `Duration: 363.4 secs` banner line.
fn duration_of(text: &str) -> f64 {
    text.lines()
        .find_map(|l| {
            let rest = l.trim_start_matches([' ', '|']).strip_prefix("Duration:")?;
            rest.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0.0)
}

/// Joins the rows of all stacked tables: `rows[r]` holds every value of interval `r`.
fn joined_rows(text: &str) -> Vec<Vec<&str>> {
    let mut rows: Vec<Vec<&str>> = Vec::new();
    let mut idx = 0;
    for line in text.lines() {
        if line.starts_with('=') {
            idx = 0; // a new (or the next stacked) table starts
        } else if let Some(cells) = row_cells(line) {
            if idx == rows.len() {
                rows.push(Vec::new());
            }
            rows[idx].extend(cells);
            idx += 1;
        }
    }
    rows
}

fn number(cell: Option<&&str>) -> f64 {
    cell.and_then(|c| c.parse().ok()).unwrap_or(0.0)
}

/// Builds the graph for `specs` (same order as requested) from raw tshark output.
pub fn parse_io_stat(text: &str, specs: &[IoSpec], interval: f64) -> IoGraph {
    let rows = joined_rows(text);
    let mut series: Vec<IoSeries> = specs.iter().map(|_| IoSeries::default()).collect();
    for row in &rows {
        let mut col = 0;
        for (s, spec) in series.iter_mut().zip(specs) {
            s.packets.push(number(row.get(col)) as u64);
            s.bytes.push(number(row.get(col + 1)) as u64);
            if spec.delta.is_some() {
                s.delta.push(number(row.get(col + 2)));
            }
            col += columns_of(spec);
        }
    }
    IoGraph {
        interval,
        duration: duration_of(text),
        series,
    }
}

/// The `COUNT/SUM/MAX/MIN` calc arguments of one spec. tshark only counts a column when the
/// per-column filter mentions the aggregated field, hence `field && (user filter)`.
pub fn calcs(spec: &IoSpec) -> Vec<String> {
    let f = spec.filter.trim();
    let with = |field: &str| {
        if f.is_empty() {
            field.to_owned()
        } else {
            format!("{field}&&({f})")
        }
    };
    let mut v = vec![
        format!("COUNT(frame){}", with("frame")),
        format!("SUM(frame.len){}", with("frame.len")),
    ];
    if let Some(d) = spec.delta {
        let func = if d == DeltaStat::Max { "MAX" } else { "MIN" };
        v.push(format!(
            "{func}(frame.time_delta){}",
            with("frame.time_delta")
        ));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(f: &str, d: Option<DeltaStat>) -> IoSpec {
        IoSpec {
            filter: f.into(),
            delta: d,
        }
    }

    const ONE: &str = "\n=====\n| IO Statistics |\n|  |\n| Duration: 1.6 secs |\n| Interval: 1 secs |\n\
        |---|\n|            |1      |2       |\n| Interval   | COUNT |   SUM  |\n|---|\n\
        |   0 <> 1   |     2 |    196 |\n|   1 <> Dur |    10 |   1000 |\n=====\n";

    #[test]
    fn parses_counts_and_sums_per_interval() {
        let g = parse_io_stat(ONE, &[spec("", None)], 1.0);
        assert_eq!(g.series[0].packets, vec![2, 10]);
        assert_eq!(g.series[0].bytes, vec![196, 1000]);
        assert!((g.duration - 1.6).abs() < 1e-9);
    }

    #[test]
    fn splits_series_and_delta_columns() {
        let t = "=====\n| Duration: 4 secs |\n|  0.0 <> 2.0 |  1 | 10 | 0.5 |  3 | 30 |\n\
                 |  2.0 <> 4.0 |  0 |  0 | 0.0 |  4 | 40 |\n=====\n";
        let g = parse_io_stat(t, &[spec("a", Some(DeltaStat::Max)), spec("b", None)], 2.0);
        assert_eq!(g.series[0].delta, vec![0.5, 0.0]);
        assert_eq!(g.series[1].packets, vec![3, 4]);
        assert_eq!(g.series[1].bytes, vec![30, 40]);
    }

    #[test]
    fn joins_stacked_tables_by_row() {
        let t = "=====\n|  0 <> 1 |  1 | 10 |\n|  1 <> 2 |  2 | 20 |\n=====\n\
                 =====\n|  0 <> 1 |  3 | 30 |\n|  1 <> 2 |  4 | 40 |\n=====\n";
        let g = parse_io_stat(t, &[spec("a", None), spec("b", None)], 1.0);
        assert_eq!(g.series[0].packets, vec![1, 2]);
        assert_eq!(g.series[1].bytes, vec![30, 40]);
    }

    #[test]
    fn empty_output_gives_empty_series() {
        let g = parse_io_stat("", &[spec("x", None)], 1.0);
        assert!(g.series[0].packets.is_empty() && g.duration == 0.0);
    }

    #[test]
    fn calc_strings_embed_the_field_in_the_filter() {
        assert_eq!(
            calcs(&spec("tcp", Some(DeltaStat::Min))),
            vec![
                "COUNT(frame)frame&&(tcp)",
                "SUM(frame.len)frame.len&&(tcp)",
                "MIN(frame.time_delta)frame.time_delta&&(tcp)"
            ]
        );
        assert_eq!(calcs(&spec(" ", None))[0], "COUNT(frame)frame");
    }
}
