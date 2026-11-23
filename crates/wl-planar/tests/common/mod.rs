//! Deterministic random graphs shared by the integration tests.
#![allow(dead_code)]

pub type Edges = Vec<(usize, usize)>;

/// A graph as the tests hand it around: vertex count and edge list.
#[derive(Clone, Debug)]
pub struct Spec {
    pub n: usize,
    pub edges: Edges,
}

/// splitmix64: tiny, fast and identical on every machine.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n`; `n` must be positive.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, self.below(i + 1));
        }
    }
}

pub fn complete(n: usize) -> Edges {
    (0..n)
        .flat_map(|a| (a + 1..n).map(move |b| (a, b)))
        .collect()
}

pub fn bipartite(a: usize, b: usize) -> Edges {
    (0..a)
        .flat_map(|x| (a..a + b).map(move |y| (x, y)))
        .collect()
}

pub fn grid(w: usize, h: usize) -> Edges {
    let mut e = Vec::new();
    for y in 0..h {
        for x in 0..w {
            if x + 1 < w {
                e.push((y * w + x, y * w + x + 1));
            }
            if y + 1 < h {
                e.push((y * w + x, (y + 1) * w + x));
            }
        }
    }
    e
}

/// `m` random pairs on `n` vertices; repeats and loops may occur and are the graph's to ignore.
pub fn gnm(rng: &mut Rng, n: usize, m: usize) -> Spec {
    let edges = (0..m).map(|_| (rng.below(n), rng.below(n))).collect();
    Spec { n, edges }
}

/// A maximal planar graph (3n - 6 edges) grown by inserting each vertex into a random triangle.
pub fn stacked_triangulation(rng: &mut Rng, n: usize) -> Spec {
    if n < 3 {
        return Spec {
            n,
            edges: Vec::new(),
        };
    }
    let mut edges = vec![(0, 1), (1, 2), (0, 2)];
    let mut faces = vec![[0, 1, 2], [0, 1, 2]];
    for v in 3..n {
        let [a, b, c] = faces.swap_remove(rng.below(faces.len()));
        edges.extend([(a, v), (b, v), (c, v)]);
        faces.extend([[a, b, v], [b, c, v], [a, c, v]]);
    }
    Spec { n, edges }
}

/// Every edge replaced by a path of up to `max_extra` inner vertices.
pub fn subdivide(rng: &mut Rng, s: &Spec, max_extra: usize) -> Spec {
    let mut n = s.n;
    let mut edges = Vec::new();
    for &(a, b) in &s.edges {
        let mut prev = a;
        for _ in 0..rng.below(max_extra + 1) {
            edges.push((prev, n));
            prev = n;
            n += 1;
        }
        edges.push((prev, b));
    }
    Spec { n, edges }
}

/// Drops each edge with a probability of up to `max_percent`, itself chosen at random.
pub fn thinned(rng: &mut Rng, s: &Spec, max_percent: usize) -> Spec {
    let percent = rng.below(max_percent);
    let edges = s
        .edges
        .iter()
        .copied()
        .filter(|_| !rng.chance(percent))
        .collect();
    Spec { n: s.n, edges }
}

pub fn add_noise(rng: &mut Rng, s: &Spec, count: usize) -> Spec {
    let mut edges = s.edges.clone();
    edges.extend((0..count).map(|_| (rng.below(s.n), rng.below(s.n))));
    Spec { n: s.n, edges }
}

/// `count` random extra pairs, then a random renaming.
pub fn noisy(rng: &mut Rng, s: &Spec, count: usize) -> Spec {
    let noisy = add_noise(rng, s, count);
    relabel(rng, &noisy)
}

pub fn random_tree(rng: &mut Rng, n: usize) -> Spec {
    let edges = (1..n).map(|v| (rng.below(v), v)).collect();
    Spec { n, edges }
}

/// Randomly renamed vertices, so no family keeps a recognisable numbering.
pub fn relabel(rng: &mut Rng, s: &Spec) -> Spec {
    let mut perm: Vec<usize> = (0..s.n).collect();
    rng.shuffle(&mut perm);
    let edges = s.edges.iter().map(|&(a, b)| (perm[a], perm[b])).collect();
    Spec { n: s.n, edges }
}

pub fn disjoint_union(parts: &[Spec]) -> Spec {
    let (mut n, mut edges) = (0, Vec::new());
    for p in parts {
        edges.extend(p.edges.iter().map(|&(a, b)| (a + n, b + n)));
        n += p.n;
    }
    Spec { n, edges }
}

pub fn planar_by_construction(rng: &mut Rng) -> Spec {
    let n = rng.range(1, 40);
    let base = match rng.below(4) {
        0 => stacked_triangulation(rng, n),
        1 => {
            let (w, h) = (rng.range(1, 7), rng.range(1, 7));
            Spec {
                n: w * h,
                edges: grid(w, h),
            }
        }
        2 => random_tree(rng, n),
        _ => {
            let t = stacked_triangulation(rng, n.min(20));
            subdivide(rng, &t, 3)
        }
    };
    let kept = thinned(rng, &base, 60);
    relabel(rng, &kept)
}

/// The generators in a fixed rotation, so every family is hit evenly.
pub fn sample(rng: &mut Rng, i: usize) -> Spec {
    match i % 8 {
        0 => {
            let n = rng.range(1, 16);
            let m = rng.below(2 * n + 1);
            gnm(rng, n, m)
        }
        1 => {
            let n = rng.range(1, 12);
            let m = rng.below(n * n + 1);
            gnm(rng, n, m)
        }
        2 => planar_by_construction(rng),
        3 => {
            let base = planar_by_construction(rng);
            let extra = rng.range(1, 3);
            noisy(rng, &base, extra)
        }
        4 => {
            let (w, h) = (rng.range(2, 8), rng.range(2, 8));
            let g = Spec {
                n: w * h,
                edges: grid(w, h),
            };
            let kept = thinned(rng, &g, 30);
            let extra = rng.below(4);
            noisy(rng, &kept, extra)
        }
        5 => {
            let k = if rng.chance(50) {
                Spec {
                    n: 5,
                    edges: complete(5),
                }
            } else {
                Spec {
                    n: 6,
                    edges: bipartite(3, 3),
                }
            };
            let sub = subdivide(rng, &k, 3);
            let noise = rng.below(4);
            noisy(rng, &sub, noise)
        }
        6 => {
            let n = rng.range(2, 30);
            let t = random_tree(rng, n);
            let extra = rng.below(4);
            noisy(rng, &t, extra)
        }
        _ => {
            let parts: Vec<Spec> = (0..rng.range(2, 4))
                .map(|_| {
                    let family = rng.below(7);
                    sample(rng, family)
                })
                .collect();
            relabel(rng, &disjoint_union(&parts))
        }
    }
}
