//! `web FILE [KEYLOG]`: time and print `http_exchanges`, `tls_sessions` and the first detail.

use std::path::{Path, PathBuf};
use std::time::Instant;

use wl_model::CaptureBackend;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let Some(file) = a.first() else {
        return eprintln!("usage: web FILE [KEYLOG]");
    };
    let backend = match wl_tshark::TsharkBackend::new() {
        Ok(b) => b,
        Err(e) => return eprintln!("{e}"),
    };
    if let Some(k) = a.get(1) {
        backend.set_tls_keylog(Some(PathBuf::from(k)));
    }
    let file = Path::new(file);
    let t = Instant::now();
    let ex = backend.http_exchanges(file);
    println!(
        "http_exchanges: {:?} in {} ms",
        ex.as_ref().map(Vec::len),
        t.elapsed().as_millis()
    );
    let t = Instant::now();
    let tls = backend.tls_sessions(file);
    println!(
        "tls_sessions: {:?} in {} ms",
        tls.as_ref().map(Vec::len),
        t.elapsed().as_millis()
    );
    for e in ex.iter().flatten().take(5) {
        println!(
            "{} {} {}{} -> {:?} {:?}ms",
            e.id, e.method, e.host, e.uri, e.status, e.time_ms
        );
    }
    for s in tls.iter().flatten().take(5) {
        println!("{s:?}");
    }
    if let Some(first) = ex.iter().flatten().next() {
        let t = Instant::now();
        println!("{:#?}", backend.http_detail(file, first));
        println!("detail in {} ms", t.elapsed().as_millis());
    }
}
