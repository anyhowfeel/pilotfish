//! Second phase of the left-right test: walk the oriented graph again and keep, on a stack, the
//! pairs of return-edge intervals that must lie on opposite sides of the tree. The graph is
//! planar exactly when no two intervals are forced onto the same side.

use crate::lr::orient::Oriented;

/// Return edges from `low` to `high`, chained through `Tester::reference`.
#[derive(Clone, Copy, Default)]
struct Interval {
    low: Option<usize>,
    high: Option<usize>,
}

impl Interval {
    fn is_empty(&self) -> bool {
        self.low.is_none() && self.high.is_none()
    }
}

/// The two sides of a fork: edges of `left` and `right` may not share a side.
#[derive(Clone, Copy, Default)]
struct Pair {
    left: Interval,
    right: Interval,
}

/// Relative sides: edge `e` lies on side `side[e]` of the edge `reference[e]` points to.
pub struct Constraints {
    pub side: Vec<i8>,
    pub reference: Vec<Option<usize>>,
}

/// The constraints of a planar graph, or `None` when two intervals cannot be separated.
pub fn check(o: &Oriented) -> Option<Constraints> {
    let m = o.tail.len();
    let mut t = Tester {
        o,
        stack: Vec::new(),
        bottom: vec![0; m],
        lowpt_edge: vec![0; m],
        side: vec![1; m],
        reference: vec![None; m],
    };
    let mut next = vec![0usize; o.height.len()];
    for &root in &o.roots {
        t.run(root, &mut next)?;
    }
    Some(Constraints {
        side: t.side,
        reference: t.reference,
    })
}

struct Tester<'a> {
    o: &'a Oriented,
    stack: Vec<Pair>,
    /// Stack height when the search entered each edge.
    bottom: Vec<usize>,
    /// Return edge of lowest endpoint below each edge.
    lowpt_edge: Vec<usize>,
    side: Vec<i8>,
    reference: Vec<Option<usize>>,
}

impl Tester<'_> {
    fn run(&mut self, root: usize, next: &mut [usize]) -> Option<()> {
        let o = self.o;
        let mut dfs = vec![root];
        while let Some(&v) = dfs.last() {
            let Some(&ei) = o.out[v].get(next[v]) else {
                dfs.pop();
                if let Some(e) = o.parent_edge[v] {
                    self.remove_back_edges(e);
                    self.integrate(e)?;
                }
                continue;
            };
            next[v] += 1;
            self.bottom[ei] = self.stack.len();
            if o.parent_edge[o.head[ei]] == Some(ei) {
                dfs.push(o.head[ei]);
            } else {
                self.lowpt_edge[ei] = ei;
                let right = Interval {
                    low: Some(ei),
                    high: Some(ei),
                };
                self.stack.push(Pair {
                    right,
                    ..Pair::default()
                });
                self.integrate(ei)?;
            }
        }
        Some(())
    }

    /// Merge the return edges of `ei`, now finished, into the constraints of its tail.
    fn integrate(&mut self, ei: usize) -> Option<()> {
        let o = self.o;
        let v = o.tail[ei];
        if o.lowpt[ei] >= o.height[v] {
            return Some(());
        }
        let e = o.parent_edge[v]?;
        if o.out[v][0] == ei {
            self.lowpt_edge[e] = self.lowpt_edge[ei];
            Some(())
        } else {
            self.add_constraints(ei, e)
        }
    }

    fn link(&mut self, low: Option<usize>, to: Option<usize>) {
        if let Some(l) = low {
            self.reference[l] = to;
        }
    }

    fn conflicts(&self, i: Interval, b: usize) -> bool {
        i.high.is_some_and(|h| self.o.lowpt[h] > self.o.lowpt[b])
    }

    fn add_constraints(&mut self, ei: usize, e: usize) -> Option<()> {
        let o = self.o;
        let lowpt = &o.lowpt;
        let mut p = Pair::default();
        loop {
            let mut q = self.stack.pop()?;
            if !q.left.is_empty() {
                std::mem::swap(&mut q.left, &mut q.right);
            }
            if !q.left.is_empty() {
                return None;
            }
            if q.right.low.is_some_and(|l| lowpt[l] > lowpt[e]) {
                if p.right.is_empty() {
                    p.right = q.right;
                } else {
                    self.link(p.right.low, q.right.high);
                    p.right.low = q.right.low;
                }
            } else {
                self.link(q.right.low, Some(self.lowpt_edge[e]));
            }
            if self.stack.len() <= self.bottom[ei] {
                break;
            }
        }
        while let Some(&top) = self.stack.last()
            && (self.conflicts(top.left, ei) || self.conflicts(top.right, ei))
        {
            let mut q = top;
            self.stack.pop();
            if self.conflicts(q.right, ei) {
                std::mem::swap(&mut q.left, &mut q.right);
            }
            if self.conflicts(q.right, ei) {
                return None;
            }
            self.link(p.right.low, q.right.high);
            if q.right.low.is_some() {
                p.right.low = q.right.low;
            }
            if p.left.is_empty() {
                p.left = q.left;
            } else {
                self.link(p.left.low, q.left.high);
            }
            p.left.low = q.left.low;
        }
        if !(p.left.is_empty() && p.right.is_empty()) {
            self.stack.push(p);
        }
        Some(())
    }

    fn lowest(&self, p: &Pair) -> usize {
        [p.left.low, p.right.low]
            .into_iter()
            .flatten()
            .map(|l| self.o.lowpt[l])
            .min()
            .unwrap_or(usize::MAX)
    }

    /// Drop the return edges that end at the tail of `e`: they are settled once the search
    /// leaves `e`.
    fn remove_back_edges(&mut self, e: usize) {
        let o = self.o;
        let u = o.tail[e];
        while let Some(top) = self.stack.last().copied()
            && self.lowest(&top) == o.height[u]
        {
            if let Some(l) = top.left.low {
                self.side[l] = -1;
            }
            self.stack.pop();
        }
        if let Some(mut p) = self.stack.pop() {
            self.trim(&mut p.left, p.right.low, u);
            self.trim(&mut p.right, p.left.low, u);
            self.stack.push(p);
        }
        if o.lowpt[e] < o.height[u] {
            let top = self.stack.last().copied().unwrap_or_default();
            let (hl, hr) = (top.left.high, top.right.high);
            let left_higher = hl.is_some_and(|l| hr.is_none_or(|r| o.lowpt[l] > o.lowpt[r]));
            self.reference[e] = if left_higher { hl } else { hr };
        }
    }

    /// Cut the edges ending at `u` off the top of `i`; `other` is the low end of the opposite
    /// interval, which takes over the chain when `i` empties.
    fn trim(&mut self, i: &mut Interval, other: Option<usize>, u: usize) {
        while let Some(h) = i.high
            && self.o.head[h] == u
        {
            i.high = self.reference[h];
        }
        if i.high.is_none()
            && let Some(l) = i.low.take()
        {
            self.reference[l] = other;
            self.side[l] = -1;
        }
    }
}

#[cfg(test)]
#[path = "conflict_tests.rs"]
mod tests;
