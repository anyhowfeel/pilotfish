//! The planar mode with a stand-in solver, so no test waits for the real pipeline.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::Duration;

use wl_kit::egui::{self, Context, Rect, Vec2, pos2, vec2};
use wl_kit::theme::Mode as Theme;
use wl_planar::layout::{Layout as Solved, Options};
use wl_planar::{Graph as Planar, Point, count_crossings};

use super::TopologyView;
use super::demo::demo_snapshot;
use super::layout::{Layout, Mode};
use super::model::{Filters, Graph, test_data::star};
use super::planar::{PlanarState, Readout};

fn ring(n: usize) -> Vec<Point> {
    (0..n)
        .map(|i| {
            let a = std::f64::consts::TAU * i as f64 / n as f64;
            Point::new(200.0 * a.cos(), 200.0 * a.sin())
        })
        .collect()
}

fn circle_solver(g: &Planar, _: &Options) -> Solved {
    let pos = ring(g.vertex_count());
    let crossings = count_crossings(g, &pos);
    Solved {
        pos,
        crossings,
        planar: crossings == 0,
    }
}

fn slow_solver(g: &Planar, o: &Options) -> Solved {
    sleep(Duration::from_millis(60));
    circle_solver(g, o)
}

static CALLS: AtomicUsize = AtomicUsize::new(0);

fn counting_solver(g: &Planar, o: &Options) -> Solved {
    CALLS.fetch_add(1, Ordering::SeqCst);
    circle_solver(g, o)
}

fn star_graph() -> Graph {
    Graph::build(&star(), &Filters::default(), &|_| None)
}

fn planar_layout(g: &Graph, solver: super::planner::Solver) -> Layout {
    let mut l = Layout::default();
    l.use_solver(solver, Duration::ZERO);
    l.set_mode(Mode::Planar, g);
    l
}

fn settle(l: &mut Layout) {
    for _ in 0..2_000 {
        if !l.step(Duration::from_millis(10)) {
            return;
        }
        sleep(Duration::from_millis(2));
    }
    panic!("the planar layout never settled");
}

fn actual_crossings(g: &Graph, pos: &[Vec2]) -> usize {
    let links: Vec<_> = g.links.iter().map(|l| (l.a, l.b)).collect();
    let points: Vec<Point> = pos
        .iter()
        .map(|p| Point::new(f64::from(p.x), f64::from(p.y)))
        .collect();
    count_crossings(&Planar::new(g.nodes.len(), &links), &points)
}

#[test]
fn the_readout_says_how_many_crossings_are_left() {
    let r = |crossings, planar| Readout { crossings, planar };
    assert_eq!(r(0, true).text(), "No crossings");
    assert_eq!(r(1, false).text(), "1 crossing");
    assert_eq!(r(7, false).text(), "7 crossings");
    assert_eq!(
        r(0, true).tooltip(),
        "The graph is planar: no link crosses another."
    );
    assert_eq!(
        r(3, false).tooltip(),
        "This graph cannot be drawn without crossings; this layout keeps them to a minimum."
    );
    assert_eq!(
        r(2, true).tooltip(),
        "Counted with the hosts where they are now."
    );
}

#[test]
fn nodes_glide_to_the_solved_positions() {
    let g = star_graph();
    let mut l = planar_layout(&g, circle_solver);
    assert!(l.readout().is_none(), "nothing is known before the answer");
    settle(&mut l);
    for (p, q) in l.pos.iter().zip(ring(g.nodes.len())) {
        assert!((p.x - q.x as f32).abs() < 1.0 && (p.y - q.y as f32).abs() < 1.0);
    }
    let r = l.readout().expect("the answer is in");
    assert_eq!(r.crossings, actual_crossings(&g, &l.pos));
}

#[test]
fn pinned_nodes_keep_their_place_and_the_count_follows_the_drag() {
    let g = star_graph();
    let mut l = planar_layout(&g, circle_solver);
    settle(&mut l);
    let spot = vec2(30.0, -20.0);
    l.drag(1, spot, &g);
    settle(&mut l);
    assert!((l.pos[1] - spot).length() < 1e-3);
    assert_eq!(
        l.readout().map(|r| r.crossings),
        Some(actual_crossings(&g, &l.pos))
    );
    l.unpin(1, &g);
    settle(&mut l);
    assert!((l.pos[1] - spot).length() > 1.0, "it glides back");
    assert_eq!(
        l.readout().map(|r| r.crossings),
        Some(actual_crossings(&g, &l.pos))
    );
}

#[test]
fn the_solver_runs_again_only_when_hosts_or_links_change() {
    let mut s = star();
    let g = Graph::build(&s, &Filters::default(), &|_| None);
    let mut l = planar_layout(&g, counting_solver);
    settle(&mut l);
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    s.edges[0].bytes += 10;
    l.sync(&Graph::build(&s, &Filters::default(), &|_| None));
    settle(&mut l);
    assert_eq!(CALLS.load(Ordering::SeqCst), 1, "same hosts and links");
    s.edges.push(super::model::test_data::edge(
        "192.168.74.7",
        "9.9.9.9",
        5_000,
        "UDP",
    ));
    l.sync(&Graph::build(&s, &Filters::default(), &|_| None));
    settle(&mut l);
    assert_eq!(CALLS.load(Ordering::SeqCst), 2);
}

#[test]
fn an_answer_for_an_older_graph_is_dropped() {
    let mut s = star();
    let first = Graph::build(&s, &Filters::default(), &|_| None);
    s.edges.push(super::model::test_data::edge(
        "192.168.74.7",
        "9.9.9.9",
        5_000,
        "UDP",
    ));
    let second = Graph::build(&s, &Filters::default(), &|_| None);
    let mut state = PlanarState::with_solver(slow_solver, Duration::ZERO);
    assert!(state.request(&first));
    assert!(state.request(&second));
    let mut got = None;
    for _ in 0..500 {
        got = got.or(state.poll());
        if got.is_some() && !state.busy() {
            break;
        }
        sleep(Duration::from_millis(2));
    }
    assert_eq!(got.map(|t| t.len()), Some(second.nodes.len()));
}

#[test]
fn the_solver_is_not_restarted_within_the_minimum_gap() {
    let g = star_graph();
    let mut state = PlanarState::with_solver(circle_solver, Duration::from_secs(60));
    state.request(&g);
    while state.poll().is_none() {
        sleep(Duration::from_millis(2));
    }
    let mut s = star();
    s.edges.pop();
    assert!(state.request(&Graph::build(&s, &Filters::default(), &|_| None)));
    for _ in 0..20 {
        assert!(state.poll().is_none());
        sleep(Duration::from_millis(2));
    }
    assert!(state.busy(), "still waiting its turn");
}

#[test]
fn switching_modes_forgets_the_answer() {
    let g = star_graph();
    let mut l = planar_layout(&g, circle_solver);
    settle(&mut l);
    assert!(l.readout().is_some());
    for m in [Mode::Force, Mode::Planar, Mode::Force] {
        l.set_mode(m, &g);
        settle(&mut l);
        assert_eq!(l.mode(), m);
        assert_eq!(l.readout().is_some(), m == Mode::Planar);
    }
}

#[test]
fn a_solver_that_panics_leaves_the_nodes_where_they_are() {
    fn broken(_: &Planar, _: &Options) -> Solved {
        panic!("no solver yet");
    }
    let g = star_graph();
    let mut l = planar_layout(&g, broken);
    let before = l.pos.clone();
    settle(&mut l);
    assert_eq!(l.pos, before);
    assert!(l.readout().is_none());
}

#[test]
fn the_map_renders_in_planar_mode_inside_its_area_in_both_themes() {
    let snap = demo_snapshot(40, 120);
    let area = Rect::from_min_size(pos2(0.0, 0.0), vec2(1200.0, 700.0));
    for theme in [Theme::Dark, Theme::Light] {
        let mut v = TopologyView::default();
        v.apply_spec("planar");
        v.layout.use_solver(circle_solver, Duration::ZERO);
        let ctx = Context::default();
        wl_kit::theme::apply_mode(&ctx, theme);
        for _ in 0..200 {
            let input = egui::RawInput {
                screen_rect: Some(area),
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                v.ui(ui, &snap);
            })
            .drop_without_applying_deltas();
            sleep(Duration::from_millis(2));
        }
        assert_eq!(v.layout.mode(), Mode::Planar);
        assert!(v.layout.readout().is_some());
        assert!(!v.buf.discs.is_empty());
        for (c, _) in &v.buf.discs {
            assert!(area.contains(*c), "{c:?} is outside the map");
        }
    }
}

#[test]
fn resetting_frees_a_moved_host_and_brings_the_planar_layout_back() {
    let g = star_graph();
    let mut l = planar_layout(&g, circle_solver);
    settle(&mut l);
    let solved: Vec<Vec2> = l.pos.clone();
    l.drag(1, vec2(30.0, -20.0), &g);
    settle(&mut l);
    assert!(l.pinned[1] && (l.pos[1] - solved[1]).length() > 1.0);
    l.forget();
    l.sync(&g);
    settle(&mut l);
    assert!(l.pinned.iter().all(|p| !p), "no host stays pinned");
    for (p, q) in l.pos.iter().zip(&solved) {
        assert!(
            (*p - *q).length() < 1.0,
            "every host is back where the layout puts it"
        );
    }
    assert_eq!(
        l.readout().map(|r| r.crossings),
        Some(actual_crossings(&g, &l.pos))
    );
}
