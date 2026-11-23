//! What the I/O chart really draws for a dense, spiky series: lines, never a band (whose sharp corners
//! draw needles far below the baseline), and a bounded number of points.

use eframe::egui::{self, Color32, Context, Rect, Shape, pos2, vec2};
use wl_kit::charts::{ChartConfig, DrawMode, PlotSeries, Unit, io_chart};

#[derive(Default)]
struct Seen {
    path_points: Vec<usize>,
    bands: usize,
}

fn walk(s: &Shape, seen: &mut Seen) {
    match s {
        Shape::Vec(v) => v.iter().for_each(|x| walk(x, seen)),
        Shape::Path(p) if p.fill == Color32::TRANSPARENT => seen.path_points.push(p.points.len()),
        Shape::Band(_) => seen.bands += 1,
        _ => {}
    }
}

fn draw(mode: DrawMode, interval: f64) -> Seen {
    let n = (500.0 / interval) as usize;
    let mut seed = 7u64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as f64 / 2147483648.0
    };
    let values: Vec<f64> = (0..n)
        .map(|_| match next() {
            r if r < 0.55 => 0.0,
            r if r < 0.9 => 3000.0,
            _ => 3000.0 + 60000.0 * next(),
        })
        .collect();
    let series = [PlotSeries {
        name: "Throughput",
        color: Color32::from_rgb(100, 170, 240),
        unit: Unit::BytesPerSec,
        values: &values,
    }];
    let cfg = ChartConfig {
        interval,
        mode,
        log_y: false,
        height: 300.0,
        duration: 500.0,
    };
    let ctx = Context::default();
    let mut seen = Seen::default();
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1300.0, 420.0))),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ui| {
            let mut selection = None;
            io_chart(ui, &series, &cfg, &mut selection);
        });
        let shapes = std::mem::take(&mut out.shapes);
        out.drop_without_applying_deltas();
        seen = Seen::default();
        shapes.iter().for_each(|cs| walk(&cs.shape, &mut seen));
    }
    seen
}

#[test]
fn a_dense_series_is_drawn_as_a_line_and_not_as_a_band() {
    for mode in [DrawMode::Line, DrawMode::Area] {
        let seen = draw(mode, 0.1);
        assert_eq!(seen.bands, 0, "{mode:?} was drawn as a band");
        let longest = seen.path_points.iter().copied().max().unwrap_or(0);
        assert!(
            longest > 100,
            "{mode:?}: the series is a stroked path ({:?})",
            seen.path_points
        );
        assert!(
            longest <= 2 * 1300 + 4,
            "{mode:?}: {longest} points are more than the screen can show"
        );
    }
}

#[test]
fn a_sparse_series_keeps_all_its_points() {
    let seen = draw(DrawMode::Line, 5.0);
    assert_eq!(seen.bands, 0);
    assert!(seen.path_points.contains(&100), "{:?}", seen.path_points);
}
