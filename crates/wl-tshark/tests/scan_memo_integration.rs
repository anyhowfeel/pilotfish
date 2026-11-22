//! Whole-capture scans run once per file version, however many features ask for them.
//! Alone in its binary: it diffs the process-wide spawn counter.

use std::path::PathBuf;

use wl_model::CaptureBackend;
use wl_tshark::{TsharkBackend, processes_spawned};

#[test]
fn repeated_scans_of_one_file_spawn_no_new_tshark() {
    let Ok(b) = TsharkBackend::new() else { return };
    b.set_tls_keylog(None);
    let file =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/web-tls.pcapng");

    let start = processes_spawned();
    let first = (
        b.tls_sessions(&file).expect("tls"),
        b.http_exchanges(&file).expect("http"),
        b.dns_queries(&file).expect("dns"),
        b.credentials(&file).expect("credentials"),
    );
    let after_first = processes_spawned();
    assert!(after_first - start >= 4);

    std::thread::scope(|s| {
        for _ in 0..3 {
            s.spawn(|| {
                assert_eq!(b.tls_sessions(&file).expect("tls").len(), first.0.len());
                assert_eq!(b.http_exchanges(&file).expect("http").len(), first.1.len());
                b.dns_queries(&file).expect("dns");
                b.credentials(&file).expect("credentials");
            });
        }
    });
    assert_eq!(processes_spawned(), after_first);

    b.set_tls_keylog(None);
    b.tls_sessions(&file).expect("tls");
    assert!(
        processes_spawned() > after_first,
        "a key log change rescans"
    );
}
