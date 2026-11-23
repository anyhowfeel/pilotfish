//! A rotation system that can grow: new vertices are spliced into corners in constant time.

use std::collections::{HashMap, HashSet};

/// The successor of a neighbour in the rotation of a vertex is looked up in a map, so a face is
/// traced in time proportional to its length however large the degrees are. The tracing rule is
/// the one of `Embedding::faces`: arriving at `v` from `u`, leave towards `next(v, u)`.
///
/// The input must be a planar rotation system of a simple graph.
pub struct Rot {
    /// Neighbours in insertion order, so iteration is deterministic.
    nbrs: Vec<Vec<usize>>,
    succ: HashMap<(usize, usize), usize>,
}

impl Rot {
    pub fn new(lists: &[Vec<usize>]) -> Self {
        let mut rot = Self {
            nbrs: Vec::new(),
            succ: HashMap::new(),
        };
        for l in lists {
            rot.add_vertex(l);
        }
        rot
    }

    pub fn vertex_count(&self) -> usize {
        self.nbrs.len()
    }

    pub fn neighbors(&self, v: usize) -> &[usize] {
        &self.nbrs[v]
    }

    pub fn next(&self, v: usize, from: usize) -> usize {
        self.succ[&(v, from)]
    }

    /// A vertex whose rotation is `cycle`; the neighbours must add it to theirs.
    pub fn add_vertex(&mut self, cycle: &[usize]) -> usize {
        let v = self.nbrs.len();
        for (i, &w) in cycle.iter().enumerate() {
            self.succ.insert((v, w), cycle[(i + 1) % cycle.len()]);
        }
        self.nbrs.push(cycle.to_vec());
        v
    }

    /// Puts `d` right after `p` in the rotation of `v`.
    pub fn insert_after(&mut self, v: usize, p: usize, d: usize) {
        let old = self.succ[&(v, p)];
        self.succ.insert((v, p), d);
        self.succ.insert((v, d), old);
        self.nbrs[v].push(d);
    }

    /// The vertices of the face that contains the half-edge `u -> v`, one per corner, starting
    /// at `u`.
    pub fn face_from(&self, u: usize, v: usize) -> Vec<usize> {
        let (mut walk, mut half) = (Vec::new(), (u, v));
        loop {
            walk.push(half.0);
            half = (half.1, self.next(half.1, half.0));
            if half == (u, v) {
                return walk;
            }
        }
    }

    pub fn faces(&self) -> Vec<Vec<usize>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for u in 0..self.nbrs.len() {
            for &v in &self.nbrs[u] {
                if seen.contains(&(u, v)) {
                    continue;
                }
                let face = self.face_from(u, v);
                for (i, &a) in face.iter().enumerate() {
                    seen.insert((a, face[(i + 1) % face.len()]));
                }
                out.push(face);
            }
        }
        out
    }
}
