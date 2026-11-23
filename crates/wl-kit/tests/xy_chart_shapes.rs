//! What the XY chart really draws: a line stays a line, even when two of its points share a time.

use eframe::egui::{self, Color32, Context, Rect, Shape, pos2, vec2};
use wl_kit::charts::{SeriesStyle, XySeries, xy_chart};

#[derive(Default)]
struct Seen {
    /// Number of points of every stroked path.
    paths: Vec<usize>,
    bands: usize,
}

fn walk(s: &Shape, seen: &mut Seen) {
    match s {
        Shape::Vec(v) => v.iter().for_each(|x| walk(x, seen)),
        Shape::Path(p) if p.fill == Color32::TRANSPARENT => seen.paths.push(p.points.len()),
        Shape::Band(_) => seen.bands += 1,
        _ => {}
    }
}

fn draw(series: Vec<XySeries>) -> Seen {
    let ctx = Context::default();
    let mut seen = Seen::default();
    // The first frames lay the plot out; the last one is the one to look at.
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1300.0, 800.0))),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ui| {
            xy_chart(ui, "shapes", &series, &|v| format!("{v:.0} B"), 500.0);
        });
        let shapes = std::mem::take(&mut out.shapes);
        out.drop_without_applying_deltas();
        seen = Seen::default();
        shapes.iter().for_each(|cs| walk(&cs.shape, &mut seen));
    }
    seen
}

/// The ACK line of a short TCP exchange: a few points within about two milliseconds, two of them
/// acknowledging at the same instant.
fn ack_line() -> XySeries {
    let t = 200.66;
    XySeries::new(
        "ACK (peer)",
        Color32::from_rgb(244, 163, 100),
        SeriesStyle::Line,
        vec![
            [t + 0.000025, 0.0],
            [t + 0.001418, 170.0],
            [t + 0.001418, 793.0],
            [t + 0.001773, 793.0],
        ],
    )
}

#[test]
fn two_points_at_the_same_time_do_not_turn_a_line_into_a_filled_band() {
    let seen = draw(vec![ack_line()]);
    assert_eq!(seen.bands, 0, "the line was drawn as a filled band");
    assert!(
        seen.paths.contains(&4),
        "the four points are one stroked path: {:?}",
        seen.paths
    );
}

#[test]
fn an_ordinary_line_is_a_stroked_path() {
    let line = XySeries::new(
        "Data",
        Color32::BLUE,
        SeriesStyle::Line,
        vec![[1.0, 0.0], [2.0, 10.0], [3.0, 30.0]],
    );
    let seen = draw(vec![line]);
    assert_eq!(seen.bands, 0);
    assert!(seen.paths.contains(&3), "{:?}", seen.paths);
}
