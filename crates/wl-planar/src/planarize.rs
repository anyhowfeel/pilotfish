//! The largest planar part of a graph that is not planar.

use crate::graph::Graph;
use crate::lr;

/// Edges are tried in the order given by `priority` (edge slots, most important first; slots not
/// listed come last in slot order) and each is kept when the kept edges stay planar. The result,
/// indexed by edge slot, is maximal: no rejected valid edge could be added back.
pub fn maximal_planar(g: &Graph, priority: &[usize]) -> Vec<bool> {
    maximal_planar_with(g, priority, &lr::is_planar)
}

/// `maximal_planar` over any planarity predicate that is monotone: a graph is planar whenever a
/// supergraph of it is.
pub fn maximal_planar_with(
    g: &Graph,
    priority: &[usize],
    is_planar: &dyn Fn(&Graph) -> bool,
) -> Vec<bool> {
    let n = g.vertex_count();
    let mut keep = vec![false; g.edge_slots()];
    let mut kept: Vec<(usize, usize)> = Vec::new();
    let mut joined = Components::new(n);
    for e in order(g, priority) {
        let (a, b) = g.endpoints(e);
        // An edge between two pieces is a bridge: it cannot make anything non-planar.
        let accept = joined.find(a) != joined.find(b) || {
            kept.push((a, b));
            let ok = kept.len() <= max_planar_edges(n) && is_planar(&Graph::new(n, &kept));
            kept.pop();
            ok
        };
        if accept {
            keep[e] = true;
            kept.push((a, b));
            joined.union(a, b);
        }
    }
    keep
}

fn max_planar_edges(n: usize) -> usize {
    if n < 3 {
        n.saturating_sub(1)
    } else {
        3 * n - 6
    }
}

fn order(g: &Graph, priority: &[usize]) -> Vec<usize> {
    let mut seen = vec![false; g.edge_slots()];
    let mut out = Vec::with_capacity(g.edge_count());
    let listed = priority.iter().copied();
    for e in listed.chain(0..g.edge_slots()) {
        if g.is_valid(e) && !seen[e] {
            seen[e] = true;
            out.push(e);
        }
    }
    out
}

struct Components(Vec<usize>);

impl Components {
    fn new(n: usize) -> Self {
        Self((0..n).collect())
    }

    fn find(&mut self, mut v: usize) -> usize {
        while self.0[v] != v {
            self.0[v] = self.0[self.0[v]];
            v = self.0[v];
        }
        v
    }

    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        self.0[a] = b;
    }
}

#[cfg(test)]
#[path = "planarize_tests.rs"]
mod tests;
