//! Memory and throughput of the two file backends on one capture.
//!
//!   measure gen FILE [PACKETS]        write a synthetic capture
//!   measure native|tshark FILE [--keep]   drain the rows; --keep holds them, as the UI does

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use wl_model::{CaptureBackend, CaptureEvent, CaptureSource, PacketRow, Session};
use wl_native::NativeBackend;
use wl_native::test_util::{DEFAULT_PACKETS, child_peak_kb, peak_kb, write_big_pcap};
use wl_tshark::TsharkBackend;

fn start(which: &str, file: &Path) -> Session {
    match which {
        "native" => NativeBackend::new()
            .start_file(file, None)
            .expect("native start"),
        "tshark" => TsharkBackend::new()
            .expect("tshark not found")
            .start(CaptureSource::File(file.to_path_buf()), None)
            .expect("tshark start"),
        other => panic!("unknown backend {other}"),
    }
}

/// Polls the largest `VmHWM` the tshark child reaches; it exits before a final read is possible.
fn watch_child(done: Arc<AtomicBool>, peak: Arc<AtomicU64>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            if let Some(kb) = child_peak_kb("tshark") {
                peak.fetch_max(kb, Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(mode), Some(file)) = (args.first(), args.get(1)) else {
        eprintln!("usage: measure gen FILE [PACKETS] | measure native|tshark FILE [--keep]");
        std::process::exit(2);
    };
    let file = PathBuf::from(file);
    if mode == "gen" {
        let n = args
            .get(2)
            .map_or(DEFAULT_PACKETS, |s| s.parse().expect("packet count"));
        let t = Instant::now();
        write_big_pcap(&file, n);
        println!(
            "{n} packets, {} MiB, {:.1} s",
            file_mib(&file),
            t.elapsed().as_secs_f64()
        );
        return;
    }
    let keep = args.iter().any(|a| a == "--keep");
    let base = peak_kb().unwrap_or(0);
    let (done, child_peak) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicU64::new(0)),
    );
    let watcher = watch_child(done.clone(), child_peak.clone());
    let started = Instant::now();
    let session = start(mode, &file);
    let (mut rows, mut kept): (u64, Vec<PacketRow>) = (0, Vec::new());
    for event in session.events.iter() {
        match event {
            CaptureEvent::Rows(batch) => {
                rows += batch.len() as u64;
                if keep {
                    kept.extend(batch);
                }
            }
            CaptureEvent::Finished => break,
            CaptureEvent::Failed(e) => panic!("{e}"),
        }
    }
    let secs = started.elapsed().as_secs_f64();
    done.store(true, Ordering::Relaxed);
    watcher.join().expect("watcher");
    let own = peak_kb().unwrap_or(0);
    let mib = |kb: u64| kb as f64 / 1024.0;
    println!("backend  rows        seconds  rows/s     own peak MiB  child peak MiB  kept");
    println!(
        "{mode:<8} {rows:<11} {secs:<8.1} {:<10.0} {:<13.1} {:<15.1} {}",
        rows as f64 / secs,
        mib(own),
        mib(child_peak.load(Ordering::Relaxed)),
        if keep {
            kept.len().to_string()
        } else {
            "no".into()
        },
    );
    if keep && rows > 0 {
        let grown = own.saturating_sub(base) * 1024;
        println!(
            "bytes per kept row (own peak growth / rows): {}",
            grown / rows
        );
    }
}

fn file_mib(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |m| m.len() >> 20)
}
