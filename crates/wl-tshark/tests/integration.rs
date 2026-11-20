//! Needs tshark + dumpcap (skipped otherwise) and capture rights on `lo`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wl_model::{CaptureBackend, CaptureError, CaptureSource};

mod common;
use common::{backend, collect, send_udp};
fn make_pcap(path: &Path, port: u16, count: usize) -> bool {
    let filter = format!("udp port {port}");
    let count_s = count.to_string();
    let args = ["-q", "-i", "lo", "-f", &filter, "-c", &count_s, "-w"];
    let Ok(mut child) = Command::new("dumpcap")
        .args(args)
        .arg(path)
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    std::thread::sleep(Duration::from_millis(700));
    send_udp(port, count);
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if let Ok(Some(st)) = child.try_wait() {
            return st.success();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    false
}
fn fixture(dir: &Path, port: u16) -> Option<PathBuf> {
    let p = dir.join("t.pcapng");
    make_pcap(&p, port, 20).then_some(p)
}

#[test]
fn file_rows_detail_and_cache() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().unwrap();
    let Some(pcap) = fixture(dir.path(), 40001) else {
        return;
    };
    let mut s = b.start(CaptureSource::File(pcap.clone()), None).unwrap();
    let (rows, err) = collect(&s);
    assert!(err.is_none() && rows.len() == 20, "{err:?}");
    assert_eq!((rows[0].no, rows[0].dst_port), (1, Some(40001)));
    assert_eq!(
        (rows[0].transport, s.backing_file.as_path()),
        (wl_model::Transport::Udp, pcap.as_path())
    );
    (s.stop)();

    let d = b.frame_detail(&pcap, 3).unwrap();
    assert_eq!(d.frame_no, 3);
    assert!(d.layers[0].label.starts_with("Frame 3"));
    assert!(
        d.layers
            .iter()
            .any(|l| l.label.starts_with("User Datagram"))
    );
    assert_eq!(d.layers[0].range, Some((0, d.bytes.len())));
    let t0 = Instant::now();
    assert_eq!(b.frame_detail(&pcap, 3).unwrap(), d);
    assert!(
        t0.elapsed() < Duration::from_millis(5),
        "cache miss: {:?}",
        t0.elapsed()
    );
    assert!(b.frame_detail(&pcap, 0).is_err() && b.frame_detail(&pcap, 9999).is_err());

    let filtered = b
        .start(CaptureSource::File(pcap), Some("frame.number <= 5".into()))
        .unwrap();
    assert_eq!(collect(&filtered).0.len(), 5);
}

#[test]
fn empty_truncated_corrupt_and_directory_files() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().unwrap();
    let dir_err = b.start(CaptureSource::File(dir.path().to_path_buf()), None);
    assert!(matches!(dir_err, Err(CaptureError::Other(ref m)) if m.contains("directory")));
    assert!(b.frame_detail(dir.path(), 1).is_err());

    let empty = dir.path().join("empty.pcap");
    std::fs::write(
        &empty,
        b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\0\0\0\0\0\0\0\0\xff\xff\0\0\x01\0\0\0",
    )
    .unwrap();
    let (rows, err) = collect(&b.start(CaptureSource::File(empty), None).unwrap());
    assert!(rows.is_empty() && err.is_none(), "{err:?}");

    let sample =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sample.pcapng");
    let raw = std::fs::read(&sample).unwrap();
    let trunc = dir.path().join("trunc.pcapng");
    std::fs::write(&trunc, &raw[..500.min(raw.len())]).unwrap();
    let (rows, err) = collect(&b.start(CaptureSource::File(trunc), None).unwrap());
    assert!(!rows.is_empty() && err.is_some());

    let bad = dir.path().join("bad.pcap");
    std::fs::write(&bad, b"definitely not a capture file").unwrap();
    assert!(
        collect(&b.start(CaptureSource::File(bad), None).unwrap())
            .1
            .is_some()
    );
}

#[test]
fn filters_validate() {
    let Some(b) = backend() else { return };
    assert!(
        b.check_filter("tcp.port == 80 && ip.src == 10.0.0.1")
            .is_ok()
    );
    assert!(b.check_filter("").is_ok());
    assert!(
        matches!(b.check_filter("ip.src =="), Err(CaptureError::BadFilter(m)) if !m.is_empty())
    );
    assert!(matches!(
        b.start(CaptureSource::File("/nonexistent.pcap".into()), None),
        Err(CaptureError::Other(_))
    ));
}

#[test]
fn export_subset_and_all() {
    let Some(b) = backend() else { return };
    let dir = tempfile::tempdir().unwrap();
    let Some(pcap) = fixture(dir.path(), 40002) else {
        return;
    };
    let (sub, all) = (dir.path().join("sub.pcap"), dir.path().join("all.pcapng"));
    b.export(&pcap, Some(&[1, 3, 4, 5]), &sub).unwrap();
    b.export(&pcap, None, &all).unwrap();
    let count = |p: PathBuf| {
        collect(&b.start(CaptureSource::File(p), None).unwrap())
            .0
            .len()
    };
    assert_eq!((count(sub), count(all)), (4, 20));
    assert!(
        b.export(&pcap, Some(&[]), &dir.path().join("x.pcap"))
            .is_err()
    );
}

#[test]
fn lists_loopback() {
    let Some(b) = backend() else { return };
    if let Some(lo) = b.interfaces().unwrap().iter().find(|i| i.name == "lo") {
        assert!(lo.is_loopback && lo.is_up);
    }
}
