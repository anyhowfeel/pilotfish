use std::cell::Cell;
use std::io::Write;
use std::process::{Command, Stdio};

use super::*;
use crate::testing::{complete, k33, petersen, pseudoforest};

/// networkx's verdict, or `None` when python3 or networkx is not there.
fn oracle(g: &Graph) -> Option<bool> {
    let edges: Vec<String> = g
        .valid_edges()
        .map(|e| format!("[{},{}]", g.endpoints(e).0, g.endpoints(e).1))
        .collect();
    let spec = format!(
        r#"[{{"n":{},"edges":[{}]}}]"#,
        g.vertex_count(),
        edges.join(",")
    );
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/nx_oracle.py");
    let mut child = Command::new("python3")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(spec.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    text.contains("\"planar\"")
        .then(|| text.contains("\"planar\": true"))
}

fn kept_graph(g: &Graph, keep: &[bool]) -> Graph {
    g.with_edges(keep)
}

#[test]
fn the_priority_order_decides_which_edges_survive() {
    let g = complete(4);
    let cycle_first = [0, 3, 5, 4];
    let by_slot = maximal_planar_with(&g, &[], &pseudoforest);
    assert_eq!(by_slot.iter().filter(|k| **k).count(), 4);
    let keep = maximal_planar_with(&g, &cycle_first, &pseudoforest);
    for e in cycle_first {
        assert!(keep[e], "edge {e} was listed first");
    }
    assert_eq!(keep.iter().filter(|k| **k).count(), 4);
}

#[test]
fn the_result_is_maximal() {
    let g = complete(6);
    let keep = maximal_planar_with(&g, &[], &pseudoforest);
    assert!(pseudoforest(&kept_graph(&g, &keep)));
    for e in (0..g.edge_slots()).filter(|&e| !keep[e]) {
        let mut more = keep.clone();
        more[e] = true;
        assert!(!pseudoforest(&kept_graph(&g, &more)), "edge {e} fits");
    }
}

#[test]
fn invalid_edges_and_odd_priorities_are_ignored() {
    let g = Graph::new(3, &[(0, 1), (0, 1), (2, 2), (1, 2)]);
    let keep = maximal_planar_with(&g, &[9, 3, 3, 1], &|_| true);
    assert_eq!(keep, [true, false, false, true]);
}

#[test]
fn bridges_are_never_tested() {
    let tree: Vec<_> = (1..30).map(|v| (v / 2, v)).collect();
    let g = Graph::new(30, &tree);
    let calls = Cell::new(0);
    let keep = maximal_planar_with(&g, &[], &|_| {
        calls.set(calls.get() + 1);
        false
    });
    assert!(keep.iter().all(|k| *k));
    assert_eq!(calls.get(), 0);
}

#[test]
fn an_edge_over_the_planar_edge_bound_is_rejected_without_a_test() {
    let g = complete(5);
    let calls = Cell::new(0);
    let keep = maximal_planar_with(&g, &[], &|_| {
        calls.set(calls.get() + 1);
        true
    });
    assert_eq!(keep.iter().filter(|k| **k).count(), 9);
    assert!(calls.get() <= 6);
}

#[test]
fn the_kept_part_is_planar_and_maximal_by_the_oracle() {
    for (name, g) in [
        ("K5", complete(5)),
        ("K6", complete(6)),
        ("K3,3", k33()),
        ("Petersen", petersen()),
    ] {
        let keep = maximal_planar_with(&g, &[], &|h| oracle(h).unwrap_or(true));
        let Some(planar) = oracle(&kept_graph(&g, &keep)) else {
            return;
        };
        assert!(planar, "{name}: the kept edges are not planar");
        for e in (0..g.edge_slots()).filter(|&e| !keep[e]) {
            let mut more = keep.clone();
            more[e] = true;
            assert_eq!(
                oracle(&kept_graph(&g, &more)),
                Some(false),
                "{name}: edge {e} fits"
            );
        }
    }
}

#[test]
fn k5_and_k33_lose_exactly_the_last_edge() {
    for g in [complete(5), k33()] {
        let keep = maximal_planar_with(&g, &[], &|h| oracle(h).unwrap_or(true));
        if oracle(&g).is_none() {
            return;
        }
        let last = g.edge_slots() - 1;
        assert!(keep.iter().enumerate().all(|(e, k)| *k == (e != last)));
    }
}
