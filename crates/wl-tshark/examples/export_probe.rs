//! `export_probe FILE DEST STEP [COUNT]`: export every STEP-th frame (scattered selection).

use std::path::Path;
use std::time::Instant;

use wl_model::CaptureBackend;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(file), Some(dest), Some(step)) = (a.first(), a.get(1), a.get(2)) else {
        return eprintln!("usage: export_probe FILE DEST STEP [COUNT]");
    };
    let step: u64 = step.parse().unwrap_or(2);
    let count: u64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let frames: Vec<u64> = (0..count).map(|i| 1 + i * step).collect();
    let backend = match wl_tshark::TsharkBackend::new() {
        Ok(b) => b,
        Err(e) => return eprintln!("{e}"),
    };
    let t = Instant::now();
    let r = backend.export(Path::new(file), Some(&frames), Path::new(dest));
    println!(
        "{} frames -> {r:?} in {} ms",
        frames.len(),
        t.elapsed().as_millis()
    );
}
