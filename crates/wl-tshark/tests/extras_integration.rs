//! Export Objects, Decode As and the DNS log against real captures. Skips without tshark.

use std::path::PathBuf;

use wl_model::{CaptureBackend, DecodeAs, Rcode};
use wl_tshark::{TsharkBackend, objects_save};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn backend() -> Option<TsharkBackend> {
    TsharkBackend::new().ok()
}

#[test]
fn dns_log_pairs_transactions() {
    let Some(b) = backend() else { return };
    let q = b.dns_queries(&fixture("dns-log.pcap")).expect("dns");
    assert!(q.len() > 80, "{}", q.len());
    let nx = q
        .iter()
        .filter(|r| r.rcode == Some(Rcode::NxDomain))
        .count();
    assert_eq!(nx, 13);
    assert!(q.iter().any(|r| r.rcode == Some(Rcode::ServFail)));
    let open: Vec<_> = q.iter().filter(|r| r.rcode.is_none()).collect();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].name, "mail.example.org");
    assert!(q.iter().any(|r| r.retransmission));
    let a = q
        .iter()
        .find(|r| r.answers == ["140.82.121.5"])
        .expect("github");
    assert_eq!(a.name, "api.github.com");
    assert!(a.rtt_ms.is_some_and(|ms| (ms - 95.0).abs() < 1.0));
    assert_eq!(a.client, "10.0.0.2");
}

#[test]
fn decode_as_changes_dissection_and_clears_with_empty_rules() {
    let Some(b) = backend() else { return };
    let f = fixture("web-http.pcapng");
    let before = b.http_exchanges(&f).expect("http").len();
    assert!(before > 0);
    // Binding the server port to a different protocol hides the HTTP exchanges.
    let ex = b.http_exchanges(&f).expect("http");
    let port = ex[0].host.rsplit(':').next().and_then(|p| p.parse().ok());
    let rule = DecodeAs {
        field: "tcp.port".into(),
        value: port.expect("port"),
        protocol: "echo".into(),
    };
    b.set_decode_as(vec![rule]);
    assert_eq!(b.http_exchanges(&f).expect("http").len(), 0);
    b.set_decode_as(Vec::new());
    assert_eq!(b.http_exchanges(&f).expect("http").len(), before);
}

#[test]
fn decode_protocols_lists_http_for_tcp() {
    let Some(b) = backend() else { return };
    let p = b.decode_protocols("tcp.port").expect("list");
    assert!(p.iter().any(|x| x == "http"));
    assert!(b.decode_protocols("ip.proto").expect("list").is_empty());
}

#[test]
fn http_objects_are_listed_saved_and_contained() {
    let Some(b) = backend() else { return };
    let set = b
        .export_objects(&fixture("web-http.pcapng"), "http")
        .expect("objects");
    assert!(!set.objects.is_empty());
    assert!(!set.truncated);
    assert!(set.objects.iter().all(|o| o.path.starts_with(&set.dir)));
    assert!(
        set.objects
            .iter()
            .any(|o| !o.host.is_empty() && o.packet.is_some())
    );
    let dest = tempfile::tempdir().expect("tmp");
    let n = objects_save::save_all(&set, dest.path()).expect("save");
    assert_eq!(n, set.objects.len());
    assert!(
        b.export_objects(&fixture("web-http.pcapng"), "../x")
            .is_err()
    );
    let other = b
        .export_objects(&fixture("web-http.pcapng"), "smb")
        .expect("smb");
    assert!(other.objects.is_empty());
}

#[test]
fn big_capture_objects_have_metadata() {
    let Some(b) = backend() else { return };
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let pcap = PathBuf::from(home).join("Downloads/source.pcap");
    if !pcap.exists() {
        return;
    }
    let set = b.export_objects(&pcap, "http").expect("objects");
    assert!(!set.objects.is_empty());
    assert!(set.objects.iter().any(|o| o.packet.is_some()));
    if std::env::var_os("WL_SHOW").is_some() {
        for o in &set.objects {
            eprintln!(
                "{:>3} {:<40} {:<26} {:>8} {:<28} {:?}",
                o.id, o.name, o.content_type, o.size, o.host, o.packet
            );
        }
    }
}
