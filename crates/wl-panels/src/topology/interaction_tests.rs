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

fn click_at(
    ctx: &Context,
    v: &mut TopologyView,
    snap: &wl_model::StatsSnapshot,
    at: egui::Pos2,
    shift: bool,
) {
    let modifiers = if shift {
        egui::Modifiers::SHIFT
    } else {
        Default::default()
    };
    let btn = |pressed| egui::Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers,
    };
    // The window system tells egui when Shift goes down or up, and egui remembers it.
    let first = vec![
        egui::Event::ModifiersChanged(modifiers),
        egui::Event::PointerMoved(at),
    ];
    frame_with(ctx, v, snap, first);
    frame_with(ctx, v, snap, vec![btn(true)]);
    frame_with(ctx, v, snap, vec![btn(false)]);
}

/// Middles of links that can be clicked on their own: nothing else lies under the pointer.
fn clickable_links(v: &TopologyView) -> Vec<(usize, egui::Pos2)> {
    (0..v.buf.segs.len())
        .filter_map(|i| {
            let (a, b, _) = v.buf.segs[i];
            let mid = pos2((a.x + b.x) / 2.0, (a.y + b.y) / 2.0);
            let free = super::hit::node_at(&v.buf.discs, mid, 3.0).is_none();
            (free && super::hit::edge_at(&v.buf.segs, mid, 4.0) == Some(i)).then_some((i, mid))
        })
        .collect()
}

#[test]
fn shift_click_picks_several_links_and_a_second_shift_click_takes_one_out() {
    use super::state::Selection;
    let snap = demo_snapshot(40, 120);
    let (ctx, mut v) = (Context::default(), TopologyView::default());
    let settle = |ctx: &Context, v: &mut TopologyView| {
        for _ in 0..400 {
            frame_with(ctx, v, &snap, vec![]);
        }
    };
    settle(&ctx, &mut v);
    // The first click opens the inspector, which shrinks the canvas and fits the graph again.
    let (_, first) = clickable_links(&v)[0];
    click_at(&ctx, &mut v, &snap, first, false);
    assert!(matches!(v.sel, Selection::Pair(..)), "{:?}", v.sel);
    settle(&ctx, &mut v);

    let links = clickable_links(&v);
    assert!(links.len() >= 3, "the demo has links to click on");
    let ((i, at_i), (j, at_j), (k, at_k)) = (links[0], links[1], links[2]);

    click_at(&ctx, &mut v, &snap, at_i, false);
    assert!(matches!(v.sel, Selection::Pair(..)), "{:?}", v.sel);
    click_at(&ctx, &mut v, &snap, at_j, true);
    assert!(
        matches!(&v.sel, Selection::Links(p) if p.len() == 2),
        "{:?}",
        v.sel
    );
    click_at(&ctx, &mut v, &snap, at_k, true);
    assert!(
        matches!(&v.sel, Selection::Links(p) if p.len() == 3),
        "{:?}",
        v.sel
    );
    // The selection is resolved at the start of the next frame.
    frame_with(&ctx, &mut v, &snap, vec![]);
    assert_eq!(v.buf.multi.len(), 3, "the frame resolved the three links");
    for n in [i, j, k] {
        assert!(v.buf.multi.contains(&n));
    }

    // Shift+click on a picked link takes it out; a click on empty space with Shift held keeps the rest.
    click_at(&ctx, &mut v, &snap, at_j, true);
    assert!(
        matches!(&v.sel, Selection::Links(p) if p.len() == 2),
        "{:?}",
        v.sel
    );
    click_at(&ctx, &mut v, &snap, pos2(5.0, 5.0), true);
    assert!(
        matches!(&v.sel, Selection::Links(p) if p.len() == 2),
        "{:?}",
        v.sel
    );
    // A plain click on a link replaces the whole selection.
    click_at(&ctx, &mut v, &snap, at_j, false);
    assert!(matches!(v.sel, Selection::Pair(..)), "{:?}", v.sel);
}
