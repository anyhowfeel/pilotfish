use super::super::test_support::*;
use super::*;
use crate::draw::straight_line;
use crate::{Embedding, count_crossings};

fn lengths(g: &Graph, pos: &[Point]) -> Vec<f64> {
    g.valid_edges()
        .map(|e| {
            let (a, b) = g.endpoints(e);
            pos[a].dist(pos[b])
        })
        .collect()
}

/// Standard deviation of the edge lengths over their mean.
fn spread(g: &Graph, pos: &[Point]) -> f64 {
    let lens = lengths(g, pos);
    let mean = lens.iter().sum::<f64>() / lens.len() as f64;
    (lens.iter().map(|l| (l - mean).powi(2)).sum::<f64>() / lens.len() as f64).sqrt() / mean
}

fn relaxed(g: &Graph, e: &Embedding, opts: &Relax) -> (Vec<Point>, Vec<Point>) {
    let drawn = straight_line(g, e);
    let mut pos = drawn.clone();
    relax(g, &mut pos, opts);
    (drawn, pos)
}

fn splitmix(state: &mut u64) -> f64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
}

#[test]
fn relaxing_keeps_every_fixture_crossing_free() {
    for (name, g, e) in fixtures() {
        let (_, pos) = relaxed(&g, &e, &Relax::default());
        std::panic::catch_unwind(|| assert_clean(&g, &pos)).unwrap_or_else(|_| panic!("{name}"));
    }
}

#[test]
fn relaxing_evens_out_edge_lengths() {
    let cases = [
        ("grid 8x8", grid(8, 8)),
        ("triangulated grid 8x8", triangulated_grid(8, 8)),
        ("wheel 12", wheel(12)),
        ("stacked triangulation 40", stacked(40, 11)),
    ];
    for (name, (g, e)) in cases {
        let (drawn, pos) = relaxed(&g, &e, &Relax::default());
        let (before, after) = (spread(&g, &drawn), spread(&g, &pos));
        assert_clean(&g, &pos);
        // A wheel cannot have equal spokes and rim edges, and a stacked triangulation has
        // nested triangles, so those only have to improve.
        let wanted = if name.starts_with("grid") || name.starts_with("triangulated") {
            0.1
        } else {
            0.8
        };
        assert!(
            after < wanted * before.max(1.0),
            "{name}: {before:.3} -> {after:.3}"
        );
    }
}

#[test]
fn the_mean_edge_gets_the_ideal_length_and_the_drawing_is_centred() {
    let (g, e) = grid(6, 6);
    let opts = Relax {
        ideal_len: 37.0,
        ..Relax::default()
    };
    let (_, pos) = relaxed(&g, &e, &opts);
    let lens = lengths(&g, &pos);
    let mean = lens.iter().sum::<f64>() / lens.len() as f64;
    assert!((mean - 37.0).abs() < 1e-6, "{mean}");
    let (lo, hi) = super::super::grid::bounds(&pos);
    assert!((lo.x + hi.x).abs() < 1e-6 && (lo.y + hi.y).abs() < 1e-6);
}

#[test]
fn fixed_vertices_stay_where_they_are() {
    let (g, e) = grid(6, 6);
    let mut pos = straight_line(&g, &e);
    let start = pos.clone();
    let fixed: Vec<bool> = (0..36).map(|v| v % 5 == 0).collect();
    relax(
        &g,
        &mut pos,
        &Relax {
            fixed: fixed.clone(),
            ..Relax::default()
        },
    );
    for v in (0..36).filter(|&v| fixed[v]) {
        assert_eq!(pos[v], start[v]);
    }
    assert!((0..36).any(|v| !fixed[v] && pos[v] != start[v]));
    assert_clean(&g, &pos);
}

#[test]
fn no_iterations_or_an_expired_deadline_only_rescale() {
    let (g, e) = grid(6, 6);
    let drawn = straight_line(&g, &e);
    for opts in [
        Relax {
            iterations: 0,
            ..Relax::default()
        },
        Relax {
            deadline: Some(Instant::now()),
            ..Relax::default()
        },
    ] {
        let mut pos = drawn.clone();
        relax(&g, &mut pos, &opts);
        let ratio = pos[1].dist(pos[0]) / drawn[1].dist(drawn[0]);
        for v in 0..36 {
            assert!((pos[v].dist(pos[0]) - ratio * drawn[v].dist(drawn[0])).abs() < 1e-6);
        }
    }
}

#[test]
fn relaxing_is_deterministic() {
    let (g, e) = stacked(30, 5);
    assert_eq!(
        relaxed(&g, &e, &Relax::default()).1,
        relaxed(&g, &e, &Relax::default()).1
    );
}

#[test]
fn a_drawing_with_crossings_never_gets_more() {
    let mut state = 12345u64;
    let graphs = fixtures()
        .into_iter()
        .map(|f| f.1)
        .chain([stacked(25, 2).0]);
    for g in graphs {
        for _ in 0..3 {
            let mut pos: Vec<Point> = (0..g.vertex_count())
                .map(|_| Point::new(splitmix(&mut state) * 500.0, splitmix(&mut state) * 500.0))
                .collect();
            let before = count_crossings(&g, &pos);
            relax(
                &g,
                &mut pos,
                &Relax {
                    iterations: 40,
                    ..Relax::default()
                },
            );
            assert!(count_crossings(&g, &pos) <= before);
        }
    }
}

#[test]
fn an_empty_graph_and_a_bad_ideal_length_are_left_alone() {
    let (g, _) = from_points(&[], &[]);
    relax(&g, &mut [], &Relax::default());
    let (g, e) = grid(3, 3);
    let drawn = straight_line(&g, &e);
    let mut pos = drawn.clone();
    relax(
        &g,
        &mut pos,
        &Relax {
            ideal_len: f64::NAN,
            ..Relax::default()
        },
    );
    assert_eq!(pos, drawn);
}
