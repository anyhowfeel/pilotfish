//! Pointer interaction and frame-time checks on a live `TopologyView`.

use std::time::{Duration, Instant};

use wl_kit::egui::{self, Context, Rect, pos2, vec2};

use super::TopologyView;
use super::demo::demo_snapshot;

fn frame_with(
    ctx: &Context,
    v: &mut TopologyView,
    snap: &wl_model::StatsSnapshot,
    events: Vec<egui::Event>,
) {
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1200.0, 700.0))),
        events,
        ..Default::default()
    };
    ctx.run_ui(input, |ui| {
        v.ui(ui, snap);
    })
    .drop_without_applying_deltas();
}

#[test]
fn click_selects_node_and_escape_clears() {
    let snap = demo_snapshot(40, 120);
    let (ctx, mut v) = (Context::default(), TopologyView::default());
    for _ in 0..400 {
        frame_with(&ctx, &mut v, &snap, vec![]);
    }
    let (at, _) = v.buf.discs[0];
    let btn = |pressed| egui::Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: Default::default(),
    };
    frame_with(&ctx, &mut v, &snap, vec![egui::Event::PointerMoved(at)]);
    frame_with(&ctx, &mut v, &snap, vec![btn(true)]);
    frame_with(&ctx, &mut v, &snap, vec![btn(false)]);
    assert!(
        matches!(v.sel, super::state::Selection::Node(_)),
        "{:?}",
        v.sel
    );
    let esc = egui::Event::Key {
        key: egui::Key::Escape,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Default::default(),
    };
    frame_with(&ctx, &mut v, &snap, vec![esc]);
    assert_eq!(v.sel, super::state::Selection::None);
}

#[test]
#[ignore]
fn bench_frame_time_300_nodes_400_edges() {
    let snap = demo_snapshot(300, 400);
    let (ctx, mut v) = (Context::default(), TopologyView::default());
    let t = Instant::now();
    let mut first = Duration::ZERO;
    let mut relax = Duration::ZERO;
    for n in 0..700 {
        let s = Instant::now();
        frame_with(&ctx, &mut v, &snap, vec![]);
        if n == 0 {
            first = t.elapsed();
        }
        if (1..60).contains(&n) {
            relax += s.elapsed();
        }
    }
    println!("relaxing frames (1..60) avg {:?}", relax / 59);
    let t = Instant::now();
    let moving = v.layout.is_moving();
    for _ in 0..300 {
        frame_with(&ctx, &mut v, &snap, vec![]);
    }
    println!(
        "first frame {first:?}; still moving after 700 frames: {moving}; frame avg {:?}",
        t.elapsed() / 300
    );
}
