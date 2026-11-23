use super::*;
use crate::count_crossings;
use crate::layout::peel::peel;

fn p(x: f64, y: f64) -> Point {
    Point::new(x, y)
}

fn run(g: &Graph, core_pos: &[(usize, Point)]) -> Vec<Point> {
    let mut pos = vec![Point::default(); g.vertex_count()];
    for &(v, q) in core_pos {
        pos[v] = q;
    }
    let radius = vec![8.0; g.vertex_count()];
    attach(
        g,
        &peel(g),
        &mut pos,
        &Fit {
            radius: &radius,
            edge_len: 100.0,
        },
    );
    pos
}

fn assert_apart(pos: &[Point], min: f64) {
    for i in 0..pos.len() {
        assert!(pos[i].x.is_finite() && pos[i].y.is_finite());
        for j in i + 1..pos.len() {
            assert!(pos[i].dist(pos[j]) >= min, "{i} and {j} are too close");
        }
    }
}

#[test]
fn trees_on_a_triangle_point_away_from_it_without_crossings() {
    let edges = [
        (0, 1),
        (1, 2),
        (2, 0),
        (0, 3),
        (3, 4),
        (3, 5),
        (1, 6),
        (2, 7),
        (2, 8),
        (2, 9),
    ];
    let g = Graph::new(10, &edges);
    let core = [(0, p(0., 0.)), (1, p(100., 0.)), (2, p(50., 90.))];
    let pos = run(&g, &core);
    assert_eq!(count_crossings(&g, &pos), 0);
    assert_apart(&pos, 16.0);
    let centre = p(50., 30.);
    for (leaf, v) in [(3, 0), (6, 1), (7, 2)] {
        assert!(
            centre.dist(pos[leaf]) > centre.dist(pos[v]),
            "{leaf} points inwards"
        );
    }
}

#[test]
fn a_tree_component_gets_a_radial_layout_around_the_origin() {
    let mut edges = vec![(0, 1), (0, 2), (1, 3), (1, 4), (2, 5), (2, 6)];
    edges.extend((7..37).map(|v| (3, v)));
    let g = Graph::new(37, &edges);
    let pos = run(&g, &[]);
    assert_eq!(count_crossings(&g, &pos), 0);
    assert_apart(&pos, 16.0);
}

#[test]
fn a_big_fan_spreads_its_leaves_apart() {
    let mut edges = vec![(0, 1), (1, 2), (2, 0)];
    edges.extend((3..63).map(|v| (0, v)));
    let g = Graph::new(63, &edges);
    let pos = run(&g, &[(0, p(0., 0.)), (1, p(100., 0.)), (2, p(0., 100.))]);
    assert_eq!(count_crossings(&g, &pos), 0);
    assert_apart(&pos, 16.0);
}

#[test]
fn a_foreign_edge_in_the_way_shrinks_the_fan() {
    let g = Graph::new(7, &[(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3), (0, 6)]);
    let core = [
        (0, p(0., 0.)),
        (1, p(100., 0.)),
        (2, p(0., 100.)),
        (3, p(-60., -40.)),
        (4, p(-60., -300.)),
        (5, p(-200., -300.)),
    ];
    let pos = run(&g, &core);
    assert_eq!(count_crossings(&g, &pos), 0);
    assert!(pos[0].dist(pos[6]) < 100.0);
}

#[test]
fn isolated_vertices_stay_at_the_origin() {
    let g = Graph::new(1, &[]);
    assert_eq!(run(&g, &[]), [p(0., 0.)]);
}
