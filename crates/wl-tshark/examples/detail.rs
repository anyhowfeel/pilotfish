//! `detail FILE N...`: time `frame_detail` for each frame number (second call hits the cache).

use std::path::Path;
use std::time::Instant;

use wl_model::CaptureBackend;

fn count(nodes: &[wl_model::DetailNode]) -> usize {
    nodes.iter().map(|n| 1 + count(&n.children)).sum()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let Some(file) = a.first() else {
        return eprintln!("usage: detail FILE N...");
    };
    let backend = match wl_tshark::TsharkBackend::new() {
        Ok(b) => b,
        Err(e) => return eprintln!("{e}"),
    };
    for n in a.iter().skip(1).filter_map(|s| s.parse::<u64>().ok()) {
        for pass in ["cold", "warm"] {
            let t = Instant::now();
            match backend.frame_detail(Path::new(file), n) {
                Ok(d) => println!(
                    "frame {n} {pass}: {} ms, {} nodes, {} bytes",
                    t.elapsed().as_millis(),
                    count(&d.layers),
                    d.bytes.len()
                ),
                Err(e) => println!("frame {n} {pass}: error {e}"),
            }
        }
    }
}
