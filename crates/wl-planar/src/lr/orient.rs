//! First phase of the left-right test: orient every edge along a depth-first search and compute,
//! per edge, the lowpoints and the nesting depth that order the edges leaving each vertex.

use crate::graph::Graph;

const UNSEEN: usize = usize::MAX;

/// All per-edge vectors are indexed by edge slot of the graph; slots that are not valid edges are
/// never read.
pub struct Oriented {
    pub tail: Vec<usize>,
    pub head: Vec<usize>,
    /// Edge by which the search reached each vertex; `None` for roots.
    pub parent_edge: Vec<Option<usize>>,
    pub height: Vec<usize>,
    pub lowpt: Vec<usize>,
    pub lowpt2: Vec<usize>,
    pub nesting: Vec<i64>,
    /// Valid edge slots, ascending.
    pub edges: Vec<usize>,
    /// Edges leaving each vertex by increasing nesting depth.
    pub out: Vec<Vec<usize>>,
    /// First vertex of each component, ascending.
    pub roots: Vec<usize>,
}

pub fn orient(g: &Graph) -> Oriented {
    let (n, m) = (g.vertex_count(), g.edge_slots());
    let mut o = Oriented {
        tail: vec![0; m],
        head: vec![0; m],
        parent_edge: vec![None; n],
        height: vec![UNSEEN; n],
        lowpt: vec![0; m],
        lowpt2: vec![0; m],
        nesting: vec![0; m],
        edges: g.valid_edges().collect(),
        out: Vec::new(),
        roots: Vec::new(),
    };
    let mut seen_edge = vec![false; m];
    let mut next = vec![0usize; n];
    let mut stack = Vec::new();
    for root in 0..n {
        if o.height[root] != UNSEEN {
            continue;
        }
        o.height[root] = 0;
        o.roots.push(root);
        stack.push(root);
        while let Some(&v) = stack.last() {
            let Some((&w, &e)) = g.neighbors(v).get(next[v]).zip(g.incident(v).get(next[v])) else {
                stack.pop();
                if let Some(e) = o.parent_edge[v] {
                    o.close(e);
                }
                continue;
            };
            next[v] += 1;
            if std::mem::replace(&mut seen_edge[e], true) {
                continue;
            }
            (o.tail[e], o.head[e]) = (v, w);
            (o.lowpt[e], o.lowpt2[e]) = (o.height[v], o.height[v]);
            if o.height[w] == UNSEEN {
                o.height[w] = o.height[v] + 1;
                o.parent_edge[w] = Some(e);
                stack.push(w);
            } else {
                o.lowpt[e] = o.height[w];
                o.close(e);
            }
        }
    }
    o.out = order_out(n, &o.tail, &o.edges, &o.nesting);
    o
}

impl Oriented {
    /// Called once the subtree below `e` is finished: fixes its nesting depth and folds its
    /// lowpoints into the edge that led to its tail.
    fn close(&mut self, e: usize) {
        let v = self.tail[e];
        let chordal = self.lowpt2[e] < self.height[v];
        self.nesting[e] = 2 * self.lowpt[e] as i64 + i64::from(chordal);
        let Some(p) = self.parent_edge[v] else { return };
        let (low, low2) = (self.lowpt[e], self.lowpt2[e]);
        if low < self.lowpt[p] {
            self.lowpt2[p] = self.lowpt[p].min(low2);
            self.lowpt[p] = low;
        } else if low > self.lowpt[p] {
            self.lowpt2[p] = self.lowpt2[p].min(low);
        } else {
            self.lowpt2[p] = self.lowpt2[p].min(low2);
        }
    }
}

/// Outgoing edges of every vertex sorted by `key`, ties kept in edge order. A counting sort over
/// all edges at once keeps this linear: keys span at most a few times `n`.
pub fn order_out(n: usize, tail: &[usize], edges: &[usize], key: &[i64]) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new(); n];
    let (Some(&lo), Some(&hi)) = (
        edges.iter().map(|&e| &key[e]).min(),
        edges.iter().map(|&e| &key[e]).max(),
    ) else {
        return out;
    };
    let mut buckets = vec![Vec::new(); (hi - lo) as usize + 1];
    for &e in edges {
        buckets[(key[e] - lo) as usize].push(e);
    }
    for e in buckets.into_iter().flatten() {
        out[tail[e]].push(e);
    }
    out
}

#[cfg(test)]
#[path = "orient_tests.rs"]
mod tests;
