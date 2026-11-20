//! `cargo run --release -p wl-tshark --example bench_file -- FILE [sleep_us_per_batch]`
//! Streams a file through the backend, reports rows/s and peak RSS of the process tree.

use std::time::{Duration, Instant};

use wl_model::{CaptureBackend, CaptureEvent, CaptureSource};

/// Sum of RSS (KiB) of this process and all descendants.
fn tree_rss_kib() -> u64 {
    let me = std::process::id();
    let mut procs = Vec::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(e.path().join("stat")) else {
            continue;
        };
        let Some(rest) = stat.rsplit_once(") ").map(|x| x.1) else {
            continue;
        };
        let f: Vec<&str> = rest.split(' ').collect();
        let ppid = f.get(1).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
        let rss = f.get(21).and_then(|p| p.parse::<u64>().ok()).unwrap_or(0);
        procs.push((pid, ppid, rss * 4));
    }
    let mut set = vec![me];
    loop {
        let before = set.len();
        for &(p, pp, _) in &procs {
            if set.contains(&pp) && !set.contains(&p) {
                set.push(p);
            }
        }
        if set.len() == before {
            break;
        }
    }
    procs
        .iter()
        .filter(|p| set.contains(&p.0))
        .map(|p| p.2)
        .sum()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(file) = args.next() else {
        eprintln!("usage: bench_file FILE [sleep_us]");
        return;
    };
    let slow_us: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let backend = match wl_tshark::TsharkBackend::new() {
        Ok(b) => b,
        Err(e) => return eprintln!("{e}"),
    };
    let t0 = Instant::now();
    let session = match backend.start(CaptureSource::File(file.into()), None) {
        Ok(s) => s,
        Err(e) => return eprintln!("{e}"),
    };
    let (mut rows, mut peak, mut max_gap, mut n) = (0u64, 0u64, Duration::ZERO, 0u64);
    let mut last = Instant::now();
    while let Ok(ev) = session.events.recv() {
        max_gap = max_gap.max(last.elapsed());
        last = Instant::now();
        match ev {
            CaptureEvent::Rows(r) => rows += r.len() as u64,
            CaptureEvent::Finished => break,
            CaptureEvent::Failed(e) => {
                eprintln!("failed: {e}");
                break;
            }
        }
        if slow_us > 0 {
            std::thread::sleep(Duration::from_micros(slow_us));
        }
        n += 1;
        if n % 100 == 0 {
            peak = peak.max(tree_rss_kib());
        }
    }
    let s = t0.elapsed().as_secs_f64();
    println!(
        "rows={rows} secs={s:.2} rows/s={:.0} peak_rss_mib={} max_gap_ms={}",
        rows as f64 / s,
        peak / 1024,
        max_gap.as_millis()
    );
}
