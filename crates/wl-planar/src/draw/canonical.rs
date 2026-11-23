//! Canonical ordering of a simple triangulation (de Fraysseix, Pach, Pollack).
//!
//! The vertices are peeled off from the top: the last vertex `v_n` of the order sits on the outer
//! triangle `v_1 v_2 v_n`, and each step removes a vertex of the outer path that has no chord, so
//! what remains keeps a simple outer cycle. A chord is an edge between two outer vertices that is
//! not an edge of the outer path.
//!
//! The rotation is read as counter-clockwise, so the face traced as `v_1 -> v_2 -> v_n` is the
//! outer one, with `v_1` at the left, `v_2` at the right and `v_n` on top.

use super::rot::Rot;

pub struct Canonical {
    /// `v_1, v_2, v_3, ..., v_n`.
    pub order: Vec<usize>,
    /// For each vertex, its neighbours that come earlier in the order, left to right along the
    /// outer path they lay on. A contiguous stretch of that path.
    pub cover: Vec<Vec<usize>>,
}

/// `outer` is a face of the triangulation, `[v_1, v_2, v_n]` in the order the face is traced.
pub fn canonical(rot: &Rot, outer: [usize; 3]) -> Canonical {
    let n = rot.vertex_count();
    let [v1, v2, vn] = outer;
    let (mut left, mut right) = (vec![usize::MAX; n], vec![usize::MAX; n]);
    let (mut outer, mut removed, mut fresh) = (vec![false; n], vec![false; n], vec![false; n]);
    let mut chords = vec![0usize; n];
    for (a, b) in [(v1, vn), (vn, v2)] {
        right[a] = b;
        left[b] = a;
    }
    for v in [v1, v2, vn] {
        outer[v] = true;
    }
    let mut ready = vec![vn];
    let mut removal = Vec::with_capacity(n);
    let mut cover = vec![Vec::new(); n];
    for _ in 2..n {
        let Some(v) = std::iter::from_fn(|| ready.pop())
            .find(|&c| !removed[c] && chords[c] == 0 && c != v1 && c != v2)
        else {
            break;
        };
        let (l, r) = (left[v], right[v]);
        let mut cov = vec![l];
        let mut x = rot.next(v, l);
        while x != r {
            cov.push(x);
            x = rot.next(v, x);
        }
        cov.push(r);
        removed[v] = true;
        for w in cov.windows(2) {
            right[w[0]] = w[1];
            left[w[1]] = w[0];
        }
        let inner = &cov[1..cov.len() - 1];
        if inner.is_empty() && (l, r) != (v1, v2) {
            // The edge `l r` was a chord and is now part of the outer path.
            for w in [l, r] {
                chords[w] -= 1;
                if chords[w] == 0 {
                    ready.push(w);
                }
            }
        }
        for &w in inner {
            outer[w] = true;
            fresh[w] = true;
        }
        for &w in inner {
            for &x in rot.neighbors(w) {
                if outer[x] && !removed[x] && x != left[w] && x != right[w] {
                    chords[w] += 1;
                    if !fresh[x] {
                        chords[x] += 1;
                    }
                }
            }
        }
        for &w in inner {
            fresh[w] = false;
            if chords[w] == 0 {
                ready.push(w);
            }
        }
        cover[v] = cov;
        removal.push(v);
    }
    let mut order = vec![v1, v2];
    order.extend(removal.iter().rev());
    Canonical { order, cover }
}
