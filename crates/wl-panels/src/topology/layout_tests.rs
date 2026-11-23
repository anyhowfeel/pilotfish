//! Layout convergence/stability and headless rendering checks.

use std::time::{Duration, Instant};

use wl_kit::egui::{self, Context, Rect, pos2, vec2};
use wl_kit::theme::Mode;

use super::TopologyView;
use super::demo::demo_snapshot;
use super::layout::{Layout, Mode as LayoutMode};
use super::model::{Filters, Graph, test_data::star};

fn settle(l: &mut Layout, max_frames: usize) -> usize {
    for n in 0..max_frames {
        if !l.step(Duration::from_millis(50)) {
            return n;
        }
    }
    max_frames
}

/// The classic physics, which the tests below are about (the default layout is planar).
fn force() -> Layout {
    let mut l = Layout::default();
    l.set_mode(LayoutMode::Force, &Graph::default());
    l
}

fn star_graph() -> Graph {
    Graph::build(&star(), &Filters::default(), &|_| None)
}

#[test]
fn force_layout_converges_without_overlap() {
    let g = star_graph();
    let mut l = force();
    l.sync(&g);
    let frames = settle(&mut l, 2_000);
    assert!(frames < 2_000, "did not settle");
    assert!(!l.is_moving());
    for i in 0..g.nodes.len() {
        for j in i + 1..g.nodes.len() {
            let d = (l.pos[i] - l.pos[j]).length();
            assert!(
                d > g.nodes[i].radius + g.nodes[j].radius,
                "{i} overlaps {j}"
            );
        }
    }
}

#[test]
fn layout_is_deterministic() {
    let g = star_graph();
    let run = || {
        let mut l = force();
        l.sync(&g);
        settle(&mut l, 2_000);
        l.pos
    };
    assert_eq!(run(), run());
}

#[test]
fn positions_persist_and_new_nodes_spawn_near_neighbours() {
    let mut s = star();
    let mut l = force();
    let g = Graph::build(&s, &Filters::default(), &|_| None);
    l.sync(&g);
    settle(&mut l, 2_000);
    let before: Vec<_> = g
        .nodes
        .iter()
        .map(|n| (n.addr.clone(), l.pos[g.find(&n.addr).unwrap()]))
        .collect();
    s.edges.push(super::model::test_data::edge(
        "192.168.74.7",
        "9.9.9.9",
        5_000,
        "UDP",
    ));
    let g2 = Graph::build(&s, &Filters::default(), &|_| None);
    l.sync(&g2);
    let anchor = l.pos[g2.find("192.168.74.7").unwrap()];
    let newcomer = l.pos[g2.find("9.9.9.9").unwrap()];
    assert!(
        (newcomer - anchor).length() < 60.0,
        "spawned far from its neighbour"
    );
    for (a, p) in &before {
        let now = l.pos[g2.find(a).unwrap()];
        assert!((now - *p).length() < 1e-3, "{a} jumped on sync");
    }
    assert!(settle(&mut l, 2_000) < 2_000);
}

#[test]
fn dragged_node_stays_pinned_until_unpinned() {
    let g = star_graph();
    let mut l = force();
    l.sync(&g);
    settle(&mut l, 2_000);
    let target = vec2(500.0, -300.0);
    l.drag(2, target, &g);
    settle(&mut l, 2_000);
    assert!((l.pos[2] - target).length() < 1e-3 && l.pinned[2]);
    l.unpin(2, &g);
    settle(&mut l, 2_000);
    assert!((l.pos[2] - target).length() > 1.0 && !l.pinned[2]);
}

fn run_frames(
    width: f32,
    scale: f32,
    mode: Mode,
    view: &mut TopologyView,
    snap: &wl_model::StatsSnapshot,
    n: usize,
) -> Duration {
    let ctx = Context::default();
    wl_kit::theme::apply_mode(&ctx, mode);
    ctx.set_pixels_per_point(scale);
    let mut last = Duration::ZERO;
    for _ in 0..n {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                pos2(0.0, 0.0),
                vec2(width / scale, width * 0.6 / scale),
            )),
            ..Default::default()
        };
        let t = Instant::now();
        ctx.run_ui(input, |ui| {
            view.ui(ui, snap);
        })
        .drop_without_applying_deltas();
        last = t.elapsed();
    }
    last
}

#[test]
fn renders_at_all_sizes_and_scales_in_both_modes() {
    let snap = demo_snapshot(40, 120);
    for mode in [Mode::Dark, Mode::Light] {
        for width in [1000.0_f32, 1440.0, 2560.0] {
            for scale in [1.0_f32, 1.25, 1.5] {
                let mut v = TopologyView::default();
                run_frames(width, scale, mode, &mut v, &snap, 3);
            }
        }
    }
}

#[test]
fn empty_and_tiny_snapshots_show_placeholders() {
    let mut v = TopologyView::default();
    run_frames(
        1000.0,
        1.0,
        Mode::Dark,
        &mut v,
        &wl_model::StatsSnapshot::default(),
        2,
    );
    let mut one = demo_snapshot(40, 120);
    one.hosts.truncate(1);
    run_frames(1000.0, 1.0, Mode::Dark, &mut v, &one, 2);
}

#[test]
fn converged_view_requests_no_repaint() {
    let snap = demo_snapshot(40, 120);
    let mut v = TopologyView::default();
    let ctx = Context::default();
    let mut delay = Duration::ZERO;
    for _ in 0..600 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1200.0, 700.0))),
            ..Default::default()
        };
        let out = ctx.run_ui(input, |ui| {
            v.ui(ui, &snap);
        });
        delay = out
            .viewport_output
            .values()
            .map(|o| o.repaint_delay)
            .min()
            .unwrap_or_default();
        out.drop_without_applying_deltas();
        if delay == Duration::MAX {
            return;
        }
    }
    panic!("still repainting after 600 frames: {delay:?}");
}
