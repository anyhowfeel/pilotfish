//! Lifecycle probe: `hold (live IFACE|file PATH) SECS [stop|drop|panic|hang]`.
//! Starts a session, drains it for SECS, then ends it in the requested way
//! (`hang` just sleeps so an outside signal can be sent).

use std::time::{Duration, Instant};

use wl_model::{CaptureBackend, CaptureSource};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(kind), Some(what)) = (a.first(), a.get(1)) else {
        return eprintln!("usage: hold live IFACE|file PATH SECS [stop|drop|panic|hang]");
    };
    let secs: u64 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(2);
    let mode = a.get(3).map_or("stop", String::as_str);
    let src = if kind == "live" {
        CaptureSource::Live {
            interface: what.clone(),
            capture_filter: None,
        }
    } else {
        CaptureSource::File(what.into())
    };
    let backend = match wl_tshark::TsharkBackend::new() {
        Ok(b) => b,
        Err(e) => return eprintln!("{e}"),
    };
    let mut s = match backend.start(src, None) {
        Ok(s) => s,
        Err(e) => return eprintln!("start failed: {e}"),
    };
    println!("pid={}", std::process::id());
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        match s.events.recv_timeout(Duration::from_millis(50)) {
            Ok(wl_model::CaptureEvent::Finished) => println!("event: Finished"),
            Ok(wl_model::CaptureEvent::Failed(e)) => println!("event: Failed({e})"),
            _ => {}
        }
    }
    match mode {
        "stop" => {
            let t = Instant::now();
            (s.stop)();
            println!("stop took {} ms", t.elapsed().as_millis());
        }
        "drop" => drop(s),
        "panic" => panic!("simulated app panic"),
        _ => std::thread::sleep(Duration::from_secs(3600)),
    }
}
