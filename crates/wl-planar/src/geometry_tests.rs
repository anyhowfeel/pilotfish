use super::*;

fn p(x: f64, y: f64) -> Point {
    Point::new(x, y)
}

fn cross(a: Point, b: Point, c: Point, d: Point) -> bool {
    edges_cross(a, b, c, d, false)
}

#[test]
fn a_proper_crossing_is_found() {
    assert!(cross(p(0., 0.), p(2., 2.), p(0., 2.), p(2., 0.)));
}

#[test]
fn parallel_and_separate_segments_do_not_cross() {
    assert!(!cross(p(0., 0.), p(2., 0.), p(0., 1.), p(2., 1.)));
    assert!(!cross(p(0., 0.), p(1., 0.), p(2., 0.), p(3., 0.)));
    assert!(!cross(p(0., 0.), p(1., 1.), p(2., 0.), p(3., 1.)));
}

#[test]
fn a_vertex_on_another_edge_counts() {
    assert!(cross(p(0., 0.), p(4., 0.), p(2., 0.), p(2., 3.)));
    assert!(cross(p(0., 0.), p(4., 0.), p(2., 3.), p(2., 0.)));
}

#[test]
fn collinear_overlap_counts_and_collinear_gap_does_not() {
    assert!(cross(p(0., 0.), p(3., 0.), p(2., 0.), p(5., 0.)));
    assert!(!cross(p(0., 0.), p(1., 0.), p(2., 0.), p(5., 0.)));
}

#[test]
fn edges_sharing_a_vertex_only_count_when_they_run_along_each_other() {
    let o = p(0., 0.);
    assert!(!edges_cross(o, p(1., 0.), o, p(0., 1.), true));
    assert!(!edges_cross(o, p(1., 0.), o, p(-1., 0.), true));
    assert!(edges_cross(o, p(2., 0.), o, p(1., 0.), true));
    assert!(edges_cross(p(2., 0.), o, o, p(1., 0.), true));
}

#[test]
fn the_result_does_not_depend_on_the_order_of_the_arguments() {
    let (a, b, c, d) = (p(0., 0.), p(2., 2.), p(0., 2.), p(2., 0.));
    assert_eq!(cross(a, b, c, d), cross(c, d, a, b));
    assert_eq!(cross(a, b, c, d), cross(b, a, d, c));
}

#[test]
fn large_and_tiny_coordinates_keep_their_answers() {
    let k = 1e6;
    assert!(cross(
        p(0., 0.),
        p(2. * k, 2. * k),
        p(0., 2. * k),
        p(2. * k, 0.)
    ));
    let t = 1e-6;
    assert!(cross(
        p(0., 0.),
        p(2. * t, 2. * t),
        p(0., 2. * t),
        p(2. * t, 0.)
    ));
    assert!(!cross(p(0., 0.), p(t, 0.), p(0., t), p(t, t)));
}

fn orderings(a: Point, b: Point, c: Point, d: Point) -> [(Point, Point, Point, Point); 8] {
    [
        (a, b, c, d),
        (b, a, c, d),
        (a, b, d, c),
        (b, a, d, c),
        (c, d, a, b),
        (d, c, a, b),
        (c, d, b, a),
        (d, c, b, a),
    ]
}

/// Points on a coarse grid nudged by amounts around the tolerance, so many pairs are nearly
/// collinear or nearly touching.
fn near_degenerate(seed: &mut u64) -> Point {
    let mut next = || {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*seed >> 33) as f64 / f64::from(1u32 << 31)
    };
    let (gx, gy) = ((next() * 5.0).floor(), (next() * 5.0).floor());
    let nudge = |u: f64| (u - 0.5) * 2e-9;
    Point::new(gx + nudge(next()), gy + nudge(next()))
}

#[test]
fn the_answer_does_not_depend_on_the_order_of_endpoints_or_segments() {
    let mut seed = 42;
    for _ in 0..20_000 {
        let pts: Vec<Point> = (0..4).map(|_| near_degenerate(&mut seed)).collect();
        let (a, b, c, d) = (pts[0], pts[1], pts[2], pts[3]);
        let all: Vec<bool> = orderings(a, b, c, d)
            .iter()
            .map(|&(p, q, r, s)| edges_cross(p, q, r, s, false))
            .collect();
        assert!(
            all.iter().all(|&x| x == all[0]),
            "{a:?} {b:?} {c:?} {d:?}: {all:?}"
        );
    }
}

#[test]
fn the_shared_endpoint_case_is_symmetric_too() {
    let mut seed = 7;
    for _ in 0..20_000 {
        let o = near_degenerate(&mut seed);
        let (x, y) = (near_degenerate(&mut seed), near_degenerate(&mut seed));
        let results = [
            edges_cross(o, x, o, y, true),
            edges_cross(x, o, o, y, true),
            edges_cross(o, x, y, o, true),
            edges_cross(x, o, y, o, true),
            edges_cross(o, y, o, x, true),
        ];
        assert!(
            results.iter().all(|&r| r == results[0]),
            "{o:?} {x:?} {y:?}: {results:?}"
        );
    }
}
