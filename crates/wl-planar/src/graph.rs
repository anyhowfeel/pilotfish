//! A simple undirected graph whose edges keep the index the caller gave them.

/// Vertices are `0..n`. Edge `i` is the `i`-th pair given to `new`; a loop or a repeat of an
/// earlier pair is kept in the list but marked invalid, so indices stay aligned with the caller's
/// own edge list. Only valid edges appear in the adjacency lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph {
    n: usize,
    edges: Vec<(usize, usize)>,
    valid: Vec<bool>,
    /// Neighbours of each vertex, ascending.
    adj: Vec<Vec<usize>>,
    /// Edge index of each entry of `adj`.
    inc: Vec<Vec<usize>>,
}

impl Graph {
    /// Pairs naming a vertex `>= n` are invalid too.
    pub fn new(n: usize, edges: &[(usize, usize)]) -> Self {
        let mut seen = std::collections::HashSet::new();
        let mut valid = Vec::with_capacity(edges.len());
        let mut lists: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
        for (i, &(a, b)) in edges.iter().enumerate() {
            let ok = a != b && a < n && b < n && seen.insert((a.min(b), a.max(b)));
            valid.push(ok);
            if ok {
                lists[a].push((b, i));
                lists[b].push((a, i));
            }
        }
        let (mut adj, mut inc) = (Vec::with_capacity(n), Vec::with_capacity(n));
        for mut l in lists {
            l.sort_unstable();
            adj.push(l.iter().map(|x| x.0).collect());
            inc.push(l.iter().map(|x| x.1).collect());
        }
        Self {
            n,
            edges: edges.to_vec(),
            valid,
            adj,
            inc,
        }
    }

    pub fn vertex_count(&self) -> usize {
        self.n
    }

    /// Length of the edge list, valid or not.
    pub fn edge_slots(&self) -> usize {
        self.edges.len()
    }

    pub fn edge_count(&self) -> usize {
        self.valid.iter().filter(|v| **v).count()
    }

    pub fn is_valid(&self, edge: usize) -> bool {
        self.valid.get(edge).copied().unwrap_or(false)
    }

    /// Endpoints of an edge slot as given.
    pub fn endpoints(&self, edge: usize) -> (usize, usize) {
        self.edges[edge]
    }

    /// Indices of the valid edges, ascending.
    pub fn valid_edges(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.edges.len()).filter(|&i| self.valid[i])
    }

    pub fn neighbors(&self, v: usize) -> &[usize] {
        &self.adj[v]
    }

    /// Edge indices parallel to `neighbors(v)`.
    pub fn incident(&self, v: usize) -> &[usize] {
        &self.inc[v]
    }

    pub fn degree(&self, v: usize) -> usize {
        self.adj[v].len()
    }

    pub fn has_edge(&self, a: usize, b: usize) -> bool {
        a < self.n && self.adj[a].binary_search(&b).is_ok()
    }

    /// The same vertices with only the edges flagged in `keep` (indexed by edge slot).
    pub fn with_edges(&self, keep: &[bool]) -> Self {
        let edges: Vec<(usize, usize)> = (0..self.edges.len())
            .map(|i| {
                if self.valid[i] && keep.get(i).copied().unwrap_or(false) {
                    self.edges[i]
                } else {
                    (0, 0)
                }
            })
            .collect();
        Self::new(self.n, &edges)
    }

    /// Connected components as vertex lists, each ascending, ordered by smallest vertex.
    /// Isolated vertices are components of one.
    pub fn components(&self) -> Vec<Vec<usize>> {
        let mut seen = vec![false; self.n];
        let mut out = Vec::new();
        for s in 0..self.n {
            if seen[s] {
                continue;
            }
            let (mut stack, mut comp) = (vec![s], Vec::new());
            seen[s] = true;
            while let Some(v) = stack.pop() {
                comp.push(v);
                for &w in &self.adj[v] {
                    if !seen[w] {
                        seen[w] = true;
                        stack.push(w);
                    }
                }
            }
            comp.sort_unstable();
            out.push(comp);
        }
        out
    }

    /// The graph on `vertices` (renumbered in the order given) and, per new edge slot, the slot
    /// it had here. Only valid edges between the chosen vertices are kept.
    pub fn induced(&self, vertices: &[usize]) -> (Self, Vec<usize>) {
        let mut map = vec![usize::MAX; self.n];
        for (new, &old) in vertices.iter().enumerate() {
            map[old] = new;
        }
        let (mut edges, mut origin) = (Vec::new(), Vec::new());
        for e in self.valid_edges() {
            let (a, b) = self.edges[e];
            if map[a] != usize::MAX && map[b] != usize::MAX {
                edges.push((map[a], map[b]));
                origin.push(e);
            }
        }
        (Self::new(vertices.len(), &edges), origin)
    }
}

#[cfg(test)]
#[path = "graph_tests.rs"]
mod tests;
