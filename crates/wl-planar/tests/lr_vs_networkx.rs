//! The planarity verdict of `lr::embed` against networkx on thousands of random graphs.

mod common;

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use common::{Rng, Spec, sample};
use wl_planar::{Graph, lr};

const GRAPHS: usize = 7200;
const BATCH: usize = 600;

fn oracle_available() -> bool {
    Command::new("python3")
        .args(["-c", "import networkx"])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn to_json(batch: &[Spec]) -> String {
    let mut out = String::from("[");
    for (i, s) in batch.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"n\":{},\"edges\":[", s.n);
        for (j, (a, b)) in s.edges.iter().enumerate() {
            let sep = if j > 0 { "," } else { "" };
            let _ = write!(out, "{sep}[{a},{b}]");
        }
        out.push_str("]}");
    }
    out.push(']');
    out
}

/// The `planar` flag of every answer, in order.
fn ask_oracle(batch: &[Spec]) -> Option<Vec<bool>> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/nx_oracle.py");
    let mut child = Command::new("python3")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let input = to_json(batch);
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let output = child.wait_with_output().ok()?;
    writer.join().ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let flags: Vec<bool> = text
        .split("\"planar\": ")
        .skip(1)
        .map(|rest| rest.starts_with("true"))
        .collect();
    (flags.len() == batch.len()).then_some(flags)
}

#[test]
fn verdicts_and_embeddings_agree_with_networkx() {
    if !oracle_available() {
        eprintln!("python3 with networkx not found, skipping");
        return;
    }
    let mut rng = Rng::new(0x5EED_1234);
    let (mut planar, mut non_planar) = (0, 0);
    for start in (0..GRAPHS).step_by(BATCH) {
        let batch: Vec<Spec> = (start..(start + BATCH).min(GRAPHS))
            .map(|i| sample(&mut rng, i))
            .collect();
        let expected = ask_oracle(&batch).expect("oracle failed on a batch");
        for (s, &want) in batch.iter().zip(&expected) {
            let g = Graph::new(s.n, &s.edges);
            let got = lr::embed(&g);
            assert_eq!(got.is_some(), want, "verdict differs on {s:?}");
            if let Some(e) = got {
                assert!(e.is_planar_embedding(&g), "invalid embedding of {s:?}");
                planar += 1;
            } else {
                non_planar += 1;
            }
        }
    }
    eprintln!("{GRAPHS} graphs agree with networkx: {planar} planar, {non_planar} non-planar");
    assert!(
        planar > GRAPHS / 5 && non_planar > GRAPHS / 5,
        "families are unbalanced"
    );
}
