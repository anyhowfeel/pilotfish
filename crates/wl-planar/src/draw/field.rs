//! The drawing being relaxed, with grids that keep every question about a move local.

use super::force::REACH;
use super::grid::{Buckets, Frame};
use crate::geometry::Point;
use crate::graph::Graph;

/// Gaps wider than this fraction of the ideal length are all alike.
const CLEARANCE: f64 = 0.001;
/// Cells per side of the grids at most, so that a long edge touches a bounded number of cells.
const MAX_SIDE: usize = 64;

pub(super) struct Field<'a> {
    pub g: &'a Graph,
    pub pos: &'a mut [Point],
    pub len: f64,
    pub clear: f64,
    pub fixed: &'a [bool],
    pub edges: Buckets,
    pub points: Buckets,
    /// Scratch lists of edge slots or vertices, filled by the queries.
    pub near: Vec<u32>,
    pub around: Vec<u32>,
    pub around_edges: Vec<u32>,
    stamp: Vec<u32>,
    round: u32,
}

impl<'a> Field<'a> {
    pub fn new(g: &'a Graph, pos: &'a mut [Point], len: f64, fixed: &'a [bool]) -> Self {
        let mut field = Self {
            g,
            len,
            clear: CLEARANCE * len,
            fixed,
            edges: Buckets::new(Frame::new(pos, REACH * len, MAX_SIDE)),
            points: Buckets::new(Frame::new(pos, REACH * len, MAX_SIDE)),
            near: Vec::new(),
            around: Vec::new(),
            around_edges: Vec::new(),
            stamp: vec![0; g.edge_slots()],
            round: 0,
            pos,
        };
        field.index();
        field
    }

    /// Files every vertex and edge again under a grid fitted to the current drawing, which
    /// shrinks or grows as the relaxation goes.
    pub fn index(&mut self) {
        let empty = || Buckets::new(Frame::new(self.pos, REACH * self.len, MAX_SIDE));
        (self.edges, self.points) = (empty(), empty());
        for e in self.g.valid_edges() {
            let (a, b) = self.g.endpoints(e);
            self.edges.add(self.pos[a], self.pos[b], e as u32);
        }
        for (v, &p) in self.pos.iter().enumerate() {
            self.points.add(p, p, v as u32);
        }
    }

    pub fn move_to(&mut self, v: usize, to: Point) {
        let from = self.pos[v];
        self.points.remove(from, from, v as u32);
        self.points.add(to, to, v as u32);
        for (&e, &y) in self.g.incident(v).iter().zip(self.g.neighbors(v)) {
            self.edges.remove(from, self.pos[y], e as u32);
            self.edges.add(to, self.pos[y], e as u32);
        }
        self.pos[v] = to;
    }

    /// Drops the repeated ids of an edge list, keeping the first of each.
    pub fn dedup(&mut self, ids: &mut Vec<u32>) {
        self.round += 1;
        let (stamp, round) = (&mut self.stamp, self.round);
        ids.retain(|&e| std::mem::replace(&mut stamp[e as usize], round) != round);
    }
}
