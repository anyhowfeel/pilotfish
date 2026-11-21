//! Headless interaction tests for the time-window drag on the throughput chart.
use eframe::egui::{self, Event, PointerButton, Pos2, RawInput, Rect, vec2};
use wl_model::RatePoint;

use super::{TimeSelection, throughput_chart_select};

fn series() -> Vec<RatePoint> {
    (0..120)
        .map(|t| RatePoint {
            t: f64::from(t),
            dt: 1.0,
            packets: 3,
            bytes: 1500,
        })
        .collect()
}

/// Runs one frame of the chart at a fixed 900x300 screen with the given pointer events.
fn frame(ctx: &egui::Context, sel: &mut Option<TimeSelection>, events: Vec<Event>) {
    let raw = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(900.0, 300.0))),
        events,
        ..Default::default()
    };
    let pts = series();
    ctx.run_ui(raw, |ui| {
        throughput_chart_select(ui, &pts, 240.0, sel);
    })
    .drop_without_applying_deltas();
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
fn dragging_selects_a_window_and_a_click_clears_it() {
    let ctx = egui::Context::default();
    let mut sel = None;
    let (a, b) = (Pos2::new(300.0, 120.0), Pos2::new(600.0, 120.0));
    frame(&ctx, &mut sel, vec![]);
    frame(&ctx, &mut sel, vec![Event::PointerMoved(a)]);
    frame(&ctx, &mut sel, vec![press(a, true)]);
    frame(
        &ctx,
        &mut sel,
        vec![Event::PointerMoved(Pos2::new(450.0, 120.0))],
    );
    frame(&ctx, &mut sel, vec![Event::PointerMoved(b)]);
    frame(&ctx, &mut sel, vec![press(b, false)]);
    let s = sel.expect("drag must create a selection");
    assert!(s.from < s.to, "{s:?}");
    assert!(
        s.duration() > 5.0,
        "a 300 px drag spans several seconds: {s:?}"
    );
    let on_ms = |t: f64| (t * 1000.0).round() / 1000.0 == t;
    assert!(
        on_ms(s.from) && on_ms(s.to),
        "selection is rounded to the ms: {s:?}"
    );

    // a plain click (press + release on the same spot) clears it
    frame(&ctx, &mut sel, vec![press(a, true)]);
    frame(&ctx, &mut sel, vec![press(a, false)]);
    assert!(sel.is_none(), "click must clear: {sel:?}");
}
