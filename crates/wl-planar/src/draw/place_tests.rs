use super::super::test_support::*;
use super::*;

#[test]
fn every_fixture_is_drawn_without_crossings_in_both_orientations() {
    for (name, g, e) in fixtures() {
        for e in [e.clone(), mirrored(&e)] {
            let pos = straight_line(&g, &e);
            std::panic::catch_unwind(|| assert_clean(&g, &pos))
                .unwrap_or_else(|_| panic!("{name}: unclean drawing {pos:?}"));
        }
    }
}

#[test]
fn drawing_is_deterministic() {
    for (_, g, e) in fixtures() {
        assert_eq!(straight_line(&g, &e), straight_line(&g, &e));
    }
}

#[test]
fn components_do_not_overlap() {
    let (g, e) = from_points(
        &[(0, 1), (1, 2), (2, 0), (3, 4)],
        &[
            (0.0, 0.0),
            (4.0, 0.0),
            (2.0, 3.0),
            (9.0, 0.0),
            (12.0, 0.0),
            (20.0, 0.0),
        ],
    );
    let pos = straight_line(&g, &e);
    let hull = |vs: &[usize]| {
        let xs: Vec<f64> = vs.iter().map(|&v| pos[v].x).collect();
        let ys: Vec<f64> = vs.iter().map(|&v| pos[v].y).collect();
        (
            xs.iter().cloned().fold(f64::INFINITY, f64::min),
            xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            ys.iter().cloned().fold(f64::INFINITY, f64::min),
            ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        )
    };
    let comps = g.components();
    for i in 0..comps.len() {
        for j in i + 1..comps.len() {
            let (a, b) = (hull(&comps[i]), hull(&comps[j]));
            assert!(
                a.1 < b.0 || b.1 < a.0 || a.3 < b.2 || b.3 < a.2,
                "{a:?} {b:?}"
            );
        }
    }
}

#[test]
fn the_drawing_is_centred() {
    let (g, e) = grid(6, 6);
    let pos = straight_line(&g, &e);
    let (min, max) = pos
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), p| {
            (lo.min(p.x), hi.max(p.x))
        });
    assert!((min + max).abs() < 1e-9);
}
