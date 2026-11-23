//! Drawings of random planar graphs, with the embeddings taken from networkx.
//!
//! The tests skip themselves when `python3` or networkx is missing.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wl_planar::draw::{Relax, relax, straight_line};
use wl_planar::{Embedding, Graph, Point, count_crossings};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

type Edges = Vec<(usize, usize)>;

/// Each new vertex goes inside a random triangle, so every face stays a triangle.
fn triangulation(rng: &mut Rng, n: usize) -> (usize, Edges) {
    let mut edges = vec![(0, 1), (1, 2), (2, 0)];
    let mut faces = vec![[0, 1, 2], [0, 2, 1]];
    for v in 3..n.max(3) {
        let [a, b, c] = faces.swap_remove(rng.below(faces.len()));
        edges.extend([(a, v), (b, v), (c, v)]);
        faces.extend([[a, b, v], [b, c, v], [c, a, v]]);
    }
    (n.max(3), edges)
}

fn grid_with_holes(rng: &mut Rng) -> (usize, Edges) {
    let (w, h) = (2 + rng.below(7), 2 + rng.below(7));
    let keep = 50 + rng.below(50);
    let mut edges = Vec::new();
    for y in 0..h {
        for x in 0..w {
            for (nx, ny) in [(x + 1, y), (x, y + 1)] {
                if nx < w && ny < h && rng.chance(keep) {
                    edges.push((y * w + x, ny * w + nx));
                }
            }
        }
    }
    (w * h, edges)
}

/// Whether it is planar is left to the oracle; a few chords keep most of them planar.
fn tree_with_chords(rng: &mut Rng) -> (usize, Edges) {
    let n = 3 + rng.below(40);
    let mut edges: Edges = (1..n).map(|v| (rng.below(v), v)).collect();
    for _ in 0..rng.below(4) {
        edges.push((rng.below(n), rng.below(n)));
    }
    (n, edges)
}

/// A polygon with random non-crossing chords.
fn outerplanar(rng: &mut Rng) -> (usize, Edges) {
    let n = 3 + rng.below(30);
    let mut edges: Edges = (0..n).map(|i| (i, (i + 1) % n)).collect();
    let mut stack = vec![(0, n - 1)];
    while let Some((lo, hi)) = stack.pop() {
        if hi - lo < 2 {
            continue;
        }
        let mid = lo + 1 + rng.below(hi - lo - 1);
        for (a, b) in [(lo, mid), (mid, hi)] {
            if b - a >= 2 && rng.chance(70) {
                edges.push((a, b));
            }
            stack.push((a, b));
        }
    }
    (n, edges)
}

fn union(rng: &mut Rng) -> (usize, Edges) {
    let (mut n, mut edges) = (0, Vec::new());
    for _ in 0..2 + rng.below(3) {
        let (k, es) = single(rng);
        edges.extend(es.iter().map(|&(a, b)| (a + n, b + n)));
        n += k;
    }
    (n + rng.below(4), edges)
}

fn single(rng: &mut Rng) -> (usize, Edges) {
    match rng.below(4) {
        0 => {
            let n = 3 + rng.below(30);
            triangulation(rng, n)
        }
        1 => grid_with_holes(rng),
        2 => tree_with_chords(rng),
        _ => outerplanar(rng),
    }
}

/// Random vertex names and edge order, so nothing depends on how the generators number things.
fn scrambled(rng: &mut Rng, (n, edges): (usize, Edges)) -> (usize, Edges) {
    let mut name: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        name.swap(i, rng.below(i + 1));
    }
    let mut out: Edges = edges.iter().map(|&(a, b)| (name[a], name[b])).collect();
    for i in (1..out.len()).rev() {
        out.swap(i, rng.below(i + 1));
    }
    (n, out)
}

/// networkx's planarity test and embedding for every graph, in one process.
fn oracle(graphs: &[(usize, Edges)]) -> Option<Vec<Option<Embedding>>> {
    let ok = Command::new("python3")
        .args(["-c", "import networkx"])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        return None;
    }
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/nx_oracle.py");
    let mut child = Command::new("python3")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let input = graphs
        .iter()
        .map(|(n, es)| {
            let list: Vec<String> = es.iter().map(|(a, b)| format!("[{a},{b}]")).collect();
            format!("{{\"n\":{n},\"edges\":[{}]}}", list.join(","))
        })
        .collect::<Vec<_>>()
        .join(",");
    std::io::Write::write_all(&mut child.stdin.take()?, format!("[{input}]").as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| parse(&String::from_utf8_lossy(&out.stdout)))
}

enum Json {
    Num(usize),
    Str(String),
    Null,
    List(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// A reader for what `json.dump` writes: no escapes in strings, only non-negative integers.
fn json(text: &str) -> Json {
    fn value(s: &mut std::iter::Peekable<std::str::Chars>) -> Json {
        let skip = |s: &mut std::iter::Peekable<std::str::Chars>| {
            while s.next_if(|c| c.is_whitespace()).is_some() {}
        };
        skip(s);
        match s.peek().copied() {
            Some('[') => {
                s.next();
                let mut items = Vec::new();
                loop {
                    skip(s);
                    if s.next_if_eq(&']').is_some() {
                        return Json::List(items);
                    }
                    items.push(value(s));
                    skip(s);
                    s.next_if_eq(&',');
                }
            }
            Some('{') => {
                s.next();
                let mut items = Vec::new();
                loop {
                    skip(s);
                    if s.next_if_eq(&'}').is_some() {
                        return Json::Object(items);
                    }
                    let Json::Str(key) = value(s) else {
                        return Json::Object(items);
                    };
                    skip(s);
                    s.next_if_eq(&':');
                    items.push((key, value(s)));
                    skip(s);
                    s.next_if_eq(&',');
                }
            }
            Some(c) if c.is_ascii_digit() => {
                let mut n = 0;
                while let Some(d) = s.next_if(char::is_ascii_digit) {
                    n = n * 10 + d as usize - '0' as usize;
                }
                Json::Num(n)
            }
            Some('"') => {
                s.next();
                let text: String = std::iter::from_fn(|| s.next_if(|&c| c != '"')).collect();
                s.next();
                Json::Str(text)
            }
            _ => {
                while s.next_if(|c| c.is_alphabetic()).is_some() {}
                Json::Null
            }
        }
    }
    value(&mut text.chars().peekable())
}

/// Reads the oracle's output: a list of `{"planar": bool, "rotation": [[int]] | null}`.
fn parse(text: &str) -> Vec<Option<Embedding>> {
    let Json::List(answers) = json(text) else {
        return Vec::new();
    };
    answers
        .into_iter()
        .map(|a| {
            let Json::Object(fields) = a else { return None };
            let rotation = fields.into_iter().find(|f| f.0 == "rotation")?.1;
            let Json::List(rows) = rotation else {
                return None;
            };
            let rows = rows
                .into_iter()
                .map(|row| match row {
                    Json::List(r) => r
                        .into_iter()
                        .map(|n| if let Json::Num(n) = n { n } else { 0 })
                        .collect(),
                    _ => Vec::new(),
                })
                .collect();
            Some(Embedding::new(rows))
        })
        .collect()
}

fn point_segment(p: Point, a: Point, b: Point) -> f64 {
    let (dx, dy) = (b.x - a.x, b.y - a.y);
    let t = (((p.x - a.x) * dx + (p.y - a.y) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
    p.dist(Point::new(a.x + t * dx, a.y + t * dy))
}

/// Finite, no crossing, no two vertices together, no vertex on an edge it does not belong to.
fn assert_clean(g: &Graph, pos: &[Point], what: &str) {
    assert_eq!(pos.len(), g.vertex_count(), "{what}");
    assert!(
        pos.iter().all(|p| p.x.is_finite() && p.y.is_finite()),
        "{what}: not finite"
    );
    assert_eq!(count_crossings(g, pos), 0, "{what}: crossings");
    for a in 0..pos.len() {
        for b in a + 1..pos.len() {
            assert!(
                pos[a].dist(pos[b]) > 1e-9,
                "{what}: vertices {a} and {b} coincide"
            );
        }
    }
    for e in g.valid_edges() {
        let (a, b) = g.endpoints(e);
        for v in (0..pos.len()).filter(|&v| v != a && v != b) {
            assert!(
                point_segment(pos[v], pos[a], pos[b]) > 1e-7,
                "{what}: vertex {v} on edge {e}"
            );
        }
    }
}

#[test]
fn random_planar_graphs_are_drawn_and_relaxed_without_crossings() {
    let mut rng = Rng(0xD1CE);
    let mut graphs = Vec::new();
    for i in 0..600 {
        let g = match i % 6 {
            0 => union(&mut rng),
            1 | 2 => single(&mut rng),
            3 => grid_with_holes(&mut rng),
            4 => {
                let n = 3 + rng.below(30);
                triangulation(&mut rng, n)
            }
            _ => outerplanar(&mut rng),
        };
        graphs.push(scrambled(&mut rng, g));
    }
    let Some(answers) = oracle(&graphs) else {
        return;
    };
    assert_eq!(answers.len(), graphs.len());
    let (mut planar, mut crossed_start, mut crossed_end) = (0, 0, 0);
    for (i, ((n, edges), answer)) in graphs.iter().zip(answers).enumerate() {
        let Some(e) = answer else { continue };
        planar += 1;
        let g = Graph::new(*n, edges);
        assert!(
            e.is_planar_embedding(&g),
            "graph {i}: oracle embedding is not planar"
        );
        let what = format!("graph {i} ({n} vertices, {} edges)", g.edge_count());

        let drawn = straight_line(&g, &e);
        assert_clean(&g, &drawn, &format!("{what} drawn"));

        let mut pos = drawn.clone();
        relax(
            &g,
            &mut pos,
            &Relax {
                iterations: 15,
                ..Relax::default()
            },
        );
        assert_clean(&g, &pos, &format!("{what} relaxed"));

        let fixed: Vec<bool> = (0..*n).map(|v| v % 3 == 0).collect();
        let mut held = drawn.clone();
        relax(
            &g,
            &mut held,
            &Relax {
                iterations: 15,
                fixed: fixed.clone(),
                ..Relax::default()
            },
        );
        assert_clean(&g, &held, &format!("{what} relaxed with fixed vertices"));
        assert!(
            (0..*n).filter(|&v| fixed[v]).all(|v| held[v] == drawn[v]),
            "{what}: a fixed vertex moved"
        );

        let mut scatter: Vec<Point> = (0..*n)
            .map(|_| Point::new(rng.unit() * 800.0, rng.unit() * 800.0))
            .collect();
        let before = count_crossings(&g, &scatter);
        relax(
            &g,
            &mut scatter,
            &Relax {
                iterations: 15,
                ..Relax::default()
            },
        );
        let after = count_crossings(&g, &scatter);
        assert!(
            after <= before,
            "{what}: relax raised the crossings from {before} to {after}"
        );
        crossed_start += usize::from(before > 0);
        crossed_end += usize::from(after == 0 && before > 0);
    }
    assert!(planar >= 400, "only {planar} planar graphs");
    assert!(crossed_end <= crossed_start);
}

#[test]
fn a_thousand_vertex_triangulation_is_drawn_without_crossings() {
    let mut rng = Rng(77);
    let graph = triangulation(&mut rng, 1000);
    let Some(mut answers) = oracle(std::slice::from_ref(&graph)) else {
        return;
    };
    let Some(e) = answers.remove(0) else {
        panic!("a triangulation is planar")
    };
    let g = Graph::new(graph.0, &graph.1);

    let drawn = straight_line(&g, &e);
    assert_clean(&g, &drawn, "1000-vertex triangulation");

    let mut pos = drawn.clone();
    relax(
        &g,
        &mut pos,
        &Relax {
            iterations: 3,
            ..Relax::default()
        },
    );
    assert_clean(&g, &pos, "1000-vertex triangulation relaxed");

    let t = Instant::now();
    let mut pos = drawn;
    relax(
        &g,
        &mut pos,
        &Relax {
            deadline: Some(t + Duration::from_millis(50)),
            ..Relax::default()
        },
    );
    assert!(
        t.elapsed() < Duration::from_millis(200),
        "deadline ignored: {:?}",
        t.elapsed()
    );
    assert_clean(
        &g,
        &pos,
        "1000-vertex triangulation relaxed under a deadline",
    );
}

#[test]
fn the_oracle_parser_reads_planar_and_non_planar_answers() {
    let text = r#"[{"planar": true, "rotation": [[1, 2], [0, 2], [1, 0]]}, {"planar": false, "rotation": null}, {"planar": true, "rotation": [[]]}]"#;
    let parsed = parse(text);
    assert_eq!(parsed.len(), 3);
    assert_eq!(
        parsed[0].as_ref().map(|e| e.rotation(1).to_vec()),
        Some(vec![0, 2])
    );
    assert!(parsed[1].is_none());
    assert_eq!(parsed[2].as_ref().map(Embedding::vertex_count), Some(1));
}
