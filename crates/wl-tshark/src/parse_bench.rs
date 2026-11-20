//! Ignored micro-benchmark: `WL_LINES=file.tsv cargo test --release -p wl-tshark parse_bench -- --ignored --nocapture`

use std::io::{BufRead, BufReader};
use std::time::Instant;

use crate::interner::Interner;
use crate::row_parser::parse_line;

#[test]
#[ignore]
fn parse_bench() {
    let Some(path) = std::env::var_os("WL_LINES") else {
        return;
    };
    let Ok(f) = std::fs::File::open(path) else {
        return;
    };
    let mut rdr = BufReader::with_capacity(256 * 1024, f);
    let (mut buf, mut i, mut n) = (Vec::new(), Interner::default(), 0u64);
    let t = Instant::now();
    loop {
        buf.clear();
        if !matches!(rdr.read_until(b'\n', &mut buf), Ok(k) if k > 0) {
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        if parse_line(&line, &mut i).is_some() {
            n += 1;
        }
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "parsed {n} rows in {s:.3}s = {:.0} ns/row",
        s * 1e9 / n as f64
    );
}
