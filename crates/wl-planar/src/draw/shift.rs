//! The shift method of de Fraysseix, Pach and Pollack: place the vertices in canonical order on
//! the integer grid, keeping the contour a chain of slope +1 and -1 segments.
//!
//! Adding `v` over the contour stretch `w_p .. w_q` first moves everything right of `w_p` apart (the
//! covered middle by 1, `w_q` and what follows by 2) together with whatever those vertices carry
//! below them, then puts `v` where the slope +1 line from `w_p` meets the slope -1 line from `w_q`.
//! The shifts keep every edge drawn so far crossing-free and make that point a grid point. The
//! drawing fits in `(2n - 4) x (n - 2)`.

use super::canonical::Canonical;

pub fn place(c: &Canonical, n: usize) -> Vec<(i64, i64)> {
    let (mut x, mut y) = (vec![0i64; n], vec![0i64; n]);
    let [v1, v2, v3] = [c.order[0], c.order[1], c.order[2]];
    x[v2] = 2;
    (x[v3], y[v3]) = (1, 1);
    let mut contour = vec![v1, v3, v2];
    // The vertices that move with a contour vertex: itself and what it covers.
    let mut carried: Vec<Vec<usize>> = (0..n).map(|v| vec![v]).collect();
    for &v in &c.order[3..] {
        let cov = &c.cover[v];
        let at = |w: usize| contour.iter().position(|&u| u == w);
        let (Some(p), Some(q)) = (at(cov[0]), at(cov[cov.len() - 1])) else {
            break;
        };
        for (i, &w) in contour.iter().enumerate().skip(p + 1) {
            let by = if i < q { 1 } else { 2 };
            for &u in &carried[w] {
                x[u] += by;
            }
        }
        let (wp, wq) = (contour[p], contour[q]);
        x[v] = (y[wq] - y[wp] + x[wp] + x[wq]) / 2;
        y[v] = (y[wq] + y[wp] + x[wq] - x[wp]) / 2;
        let mut under = vec![v];
        for &w in &contour[p + 1..q] {
            under.append(&mut carried[w]);
        }
        carried[v] = under;
        contour.splice(p + 1..q, [v]);
    }
    x.into_iter().zip(y).collect()
}

#[cfg(test)]
#[path = "shift_tests.rs"]
mod tests;
