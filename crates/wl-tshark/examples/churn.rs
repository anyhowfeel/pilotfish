//! `churn FILE|live:IFACE N [filter]`: start/stop N sessions back to back, then report timing.
//! Afterwards scan /proc for leftover tshark/dumpcap/editcap children.

use std::time::Instant;

use wl_model::{CaptureBackend, CaptureSource};

fn children() -> Vec<String> {
    let me = std::process::id().to_string();
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(stat) = std::fs::read_to_string(e.path().join("stat")) else {
            continue;
        };
        let Some((head, rest)) = stat.rsplit_once(") ") else {
            continue;
        };
        let f: Vec<&str> = rest.split(' ').collect();
        if f.get(1) == Some(&me.as_str()) {
            out.push(format!("{head}) state={}", f[0]));
        }
    }
    out
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(what), Some(n)) = (a.first(), a.get(1).and_then(|s| s.parse::<u32>().ok())) else {
        return eprintln!("usage: churn FILE|live:IFACE N [filter]");
    };
    let filter = a.get(2).cloned();
    let backend = match wl_tshark::TsharkBackend::new() {
        Ok(b) => b,
        Err(e) => return eprintln!("{e}"),
    };
    let (mut worst, mut total) = (0u128, 0u128);
    let t0 = Instant::now();
    for i in 0..n {
        let src = match what.strip_prefix("live:") {
            Some(i) => CaptureSource::Live {
                interface: i.into(),
                capture_filter: None,
            },
            None => CaptureSource::File(what.into()),
        };
        let f = filter.clone().map(|f| format!("{f} && frame.number > {i}"));
        let mut s = match backend.start(src, f) {
            Ok(s) => s,
            Err(e) => return eprintln!("start {i} failed: {e}"),
        };
        let t = Instant::now();
        (s.stop)();
        let ms = t.elapsed().as_millis();
        worst = worst.max(ms);
        total += ms;
    }
    println!(
        "{n} cycles in {:.2}s; stop avg {} ms worst {worst} ms",
        t0.elapsed().as_secs_f64(),
        total / u128::from(n.max(1))
    );
    println!("leftover children: {:?}", children());
}
