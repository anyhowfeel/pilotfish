//! Last phase: turn the relative sides into absolute ones, reorder the edges of every vertex by
//! signed nesting depth, and read the rotation system off a second walk of the tree.

use crate::embedding::Embedding;
use crate::lr::conflict::Constraints;
use crate::lr::orient::{Oriented, order_out};

/// Half-edge `2e` leaves the tail of edge `e`, half-edge `2e + 1` leaves its head. Every vertex
/// owns a circular list of its half-edges.
struct Ring {
    next: Vec<usize>,
    prev: Vec<usize>,
}

impl Ring {
    fn new(halves: usize) -> Self {
        Self {
            next: (0..halves).collect(),
            prev: (0..halves).collect(),
        }
    }

    fn insert_after(&mut self, at: usize, h: usize) {
        let n = self.next[at];
        (self.next[at], self.prev[h]) = (h, at);
        (self.next[h], self.prev[n]) = (n, h);
    }

    fn insert_before(&mut self, at: usize, h: usize) {
        self.insert_after(self.prev[at], h);
    }
}

/// Follow `reference` chains to the root of each and multiply the sides along the way. Every
/// link is cleared once crossed, so the total work stays linear.
fn resolve_sides(c: &mut Constraints, edges: &[usize]) {
    let mut chain = Vec::new();
    for &e in edges {
        let mut cur = e;
        while let Some(r) = c.reference[cur] {
            chain.push(cur);
            cur = r;
        }
        while let Some(x) = chain.pop() {
            if let Some(r) = c.reference[x].take() {
                c.side[x] *= c.side[r];
            }
        }
    }
}

pub fn build(o: &mut Oriented, mut c: Constraints) -> Embedding {
    resolve_sides(&mut c, &o.edges);
    let keys: Vec<i64> = (0..o.nesting.len())
        .map(|e| o.nesting[e] * i64::from(c.side[e]))
        .collect();
    let n = o.height.len();
    o.out = order_out(n, &o.tail, &o.edges, &keys);

    let mut ring = Ring::new(2 * o.tail.len());
    for list in &o.out {
        for pair in list.windows(2) {
            ring.insert_after(2 * pair[0], 2 * pair[1]);
        }
    }
    place_in_edges(o, &c, &mut ring);
    rotations(o, &ring)
}

/// Insert the half-edge towards the tail at the head of every edge, in the order of the tree
/// walk: a tree edge goes just before the first outgoing edge, a return edge next to the
/// reference its side asks for.
fn place_in_edges(o: &Oriented, c: &Constraints, ring: &mut Ring) {
    let n = o.height.len();
    let (mut left, mut right) = (vec![0; n], vec![0; n]);
    let mut next = vec![0usize; n];
    for &root in &o.roots {
        let mut stack = vec![root];
        while let Some(&v) = stack.last() {
            let Some(&e) = o.out[v].get(next[v]) else {
                stack.pop();
                continue;
            };
            next[v] += 1;
            let (w, back) = (o.head[e], 2 * e + 1);
            if o.parent_edge[w] == Some(e) {
                if let Some(&first) = o.out[w].first() {
                    ring.insert_before(2 * first, back);
                }
                (left[v], right[v]) = (2 * e, 2 * e);
                stack.push(w);
            } else if c.side[e] == 1 {
                ring.insert_after(right[w], back);
            } else {
                ring.insert_before(left[w], back);
                left[w] = back;
            }
        }
    }
}

fn rotations(o: &Oriented, ring: &Ring) -> Embedding {
    let target = |h: usize| {
        if h.is_multiple_of(2) {
            o.head[h / 2]
        } else {
            o.tail[h / 2]
        }
    };
    let rotation = (0..o.height.len())
        .map(|v| {
            let start = match (o.parent_edge[v], o.out[v].first()) {
                (Some(p), _) => 2 * p + 1,
                (None, Some(&e)) => 2 * e,
                (None, None) => return Vec::new(),
            };
            let mut list = vec![target(start)];
            let mut h = ring.next[start];
            while h != start {
                list.push(target(h));
                h = ring.next[h];
            }
            list
        })
        .collect();
    Embedding::new(rotation)
}

#[cfg(test)]
#[path = "embed_tests.rs"]
mod tests;
