use std::time::Duration;

use super::*;
use crate::count_crossings;
use crate::testing::Lcg;

fn p(x: f64, y: f64) -> Point {
    Point::new(x, y)
}

fn k4() -> Graph {
    Graph::new(4, &[(0, 1), (1, 3), (3, 2), (2, 0), (0, 3), (1, 2)])
}

fn square() -> Vec<Point> {
    vec![p(0., 0.), p(100., 0.), p(0., 100.), p(100., 100.)]
}

#[test]
fn a_square_with_both_diagonals_becomes_planar() {
    let g = k4();
    let mut pos = square();
    assert_eq!(count_crossings(&g, &pos), 1);
    reduce(&g, &mut pos, &[], &[8.0; 4], None);
    assert_eq!(count_crossings(&g, &pos), 0);
}

#[test]
fn a_drawing_without_crossings_is_left_alone() {
    let g = Graph::new(3, &[(0, 1), (1, 2)]);
    let mut pos = vec![p(0., 0.), p(50., 0.), p(50., 50.)];
    let before = pos.clone();
    reduce(&g, &mut pos, &[], &[], None);
    assert_eq!(pos, before);
}

#[test]
fn an_expired_deadline_changes_nothing() {
    let g = k4();
    let mut pos = square();
    reduce(
        &g,
        &mut pos,
        &[],
        &[8.0; 4],
        Some(Instant::now() - Duration::from_secs(1)),
    );
    assert_eq!(pos, square());
}

#[test]
fn crossings_never_go_up_and_vertices_stay_apart() {
    let mut rng = Lcg(7);
    for round in 0..30 {
        let n = 6 + rng.next(10);
        let edges: Vec<(usize, usize)> = (0..2 * n).map(|_| (rng.next(n), rng.next(n))).collect();
        let g = Graph::new(n, &edges);
        let mut pos: Vec<Point> = (0..n)
            .map(|_| p(rng.next(400) as f64, rng.next(400) as f64))
            .collect();
        let before = count_crossings(&g, &pos);
        reduce(&g, &mut pos, &[], &vec![6.0; n], None);
        assert!(count_crossings(&g, &pos) <= before, "round {round}");
        for i in 0..n {
            for j in i + 1..n {
                assert!(pos[i].dist(pos[j]) > 1.0, "round {round}: {i} on {j}");
            }
        }
    }
}

#[test]
fn it_is_deterministic() {
    let g = Graph::new(
        6,
        &[
            (0, 3),
            (1, 4),
            (2, 5),
            (0, 4),
            (1, 5),
            (2, 3),
            (0, 5),
            (1, 3),
            (2, 4),
        ],
    );
    let start: Vec<Point> = (0..6)
        .map(|i| p((i * 53 % 7) as f64 * 40.0, (i * 31 % 5) as f64 * 40.0))
        .collect();
    let run = || {
        let mut pos = start.clone();
        reduce(&g, &mut pos, &[], &[6.0; 6], None);
        pos
    };
    assert_eq!(run(), run());
}
