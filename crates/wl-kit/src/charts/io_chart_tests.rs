//! Headless interaction tests of the multi-series chart: hover bucket and drag selection.
use eframe::egui::{self, Color32, Event, PointerButton, Pos2, RawInput, Rect, vec2};

use super::{ChartConfig, DrawMode, PlotSeries, TimeSelection, Unit, io_chart};

fn cfg(mode: DrawMode, log_y: bool) -> ChartConfig {
    ChartConfig {
        interval: 1.0,
        mode,
        log_y,
        height: 240.0,
        duration: 100.0,
    }
}

/// One frame at a fixed 900x300 screen; returns the hovered bucket.
fn frame(
    ctx: &egui::Context,
    c: &ChartConfig,
    sel: &mut Option<TimeSelection>,
    events: Vec<Event>,
) -> Option<usize> {
    let a: Vec<f64> = (0..100).map(|i| f64::from(i % 10) * 100.0).collect();
    let mut b: Vec<f64> = (0..100).map(f64::from).collect();
    b[40] = f64::NAN;
    let raw = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(900.0, 300.0))),
        events,
        ..Default::default()
    };
    let mut hovered = None;
    ctx.run_ui(raw, |ui| {
        let series = [
            PlotSeries {
                name: "all",
                color: Color32::RED,
                unit: Unit::BytesPerSec,
                values: &a,
            },
            PlotSeries {
                name: "tcp",
                color: Color32::BLUE,
                unit: Unit::PacketsPerSec,
                values: &b,
            },
        ];
        hovered = io_chart(ui, &series, c, sel);
    })
    .drop_without_applying_deltas();
    hovered
}

fn press(pos: Pos2, pressed: bool) -> Event {
    Event::PointerButton {
        pos,
        button: PointerButton::Primary,
        pressed,
        modifiers: Default::default(),
    }
}

#[test]
fn hovering_reports_a_bucket_in_every_mode() {
    for (mode, log) in [
        (DrawMode::Line, false),
        (DrawMode::Area, true),
        (DrawMode::Bars, false),
    ] {
        let ctx = egui::Context::default();
        let (c, mut sel) = (cfg(mode, log), None);
        frame(&ctx, &c, &mut sel, vec![]);
        frame(
            &ctx,
            &c,
            &mut sel,
            vec![Event::PointerMoved(Pos2::new(450.0, 100.0))],
        );
        let h = frame(
            &ctx,
            &c,
            &mut sel,
            vec![Event::PointerMoved(Pos2::new(452.0, 100.0))],
        );
        let i = h.expect("pointer over the plot must hover a bucket");
        assert!((30..70).contains(&i), "{mode:?}: bucket {i}");
    }
}

#[test]
fn no_hover_outside_the_plot() {
    let ctx = egui::Context::default();
    let (c, mut sel) = (cfg(DrawMode::Line, false), None);
    frame(&ctx, &c, &mut sel, vec![]);
    let h = frame(
        &ctx,
        &c,
        &mut sel,
        vec![Event::PointerMoved(Pos2::new(450.0, 290.0))],
    );
    assert_eq!(h, None);
}

#[test]
fn dragging_selects_and_clicking_clears() {
    let ctx = egui::Context::default();
    let (c, mut sel) = (cfg(DrawMode::Area, false), None);
    let (a, b) = (Pos2::new(300.0, 120.0), Pos2::new(600.0, 120.0));
    frame(&ctx, &c, &mut sel, vec![]);
    frame(&ctx, &c, &mut sel, vec![Event::PointerMoved(a)]);
    frame(&ctx, &c, &mut sel, vec![press(a, true)]);
    frame(
        &ctx,
        &c,
        &mut sel,
        vec![Event::PointerMoved(Pos2::new(450.0, 120.0))],
    );
    frame(&ctx, &c, &mut sel, vec![Event::PointerMoved(b)]);
    frame(&ctx, &c, &mut sel, vec![press(b, false)]);
    let s = sel.expect("drag must create a selection");
    assert!(s.duration() > 5.0, "{s:?}");
    frame(&ctx, &c, &mut sel, vec![press(a, true)]);
    frame(&ctx, &c, &mut sel, vec![press(a, false)]);
    assert!(sel.is_none());
}

#[test]
fn empty_data_draws_a_placeholder_without_hover() {
    let ctx = egui::Context::default();
    let raw = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(900.0, 300.0))),
        ..Default::default()
    };
    let mut sel = None;
    let mut out = Some(0);
    ctx.run_ui(raw, |ui| {
        out = io_chart(ui, &[], &cfg(DrawMode::Line, false), &mut sel)
    })
    .drop_without_applying_deltas();
    assert_eq!(out, None);
}
