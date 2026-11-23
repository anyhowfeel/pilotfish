use std::os::unix::fs::PermissionsExt;

use wl_model::CaptureError;

use super::start_file;
use super::test_support::*;

fn message(e: Option<CaptureError>) -> String {
    e.expect("an error").to_string()
}

#[test]
fn a_missing_file_is_reported_by_path() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("nope.pcap");
    let msg = message(start_file(&path, None).err());
    assert_eq!(msg, format!("file not found: {}", path.display()));
}

#[test]
fn a_directory_is_not_a_capture() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let msg = message(start_file(dir.path(), None).err());
    assert!(
        msg.starts_with("expected a capture file, not a directory"),
        "{msg}"
    );
}

#[test]
fn an_unreadable_file_is_a_permission_error() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("locked.pcap");
    std::fs::write(&path, b"x").expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::File::open(&path).is_ok() {
        return; // running as root
    }
    assert!(matches!(
        start_file(&path, None).err(),
        Some(CaptureError::Permission(_))
    ));
}

#[test]
fn a_file_that_is_not_a_capture_gives_the_readers_message() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("junk.pcap");
    std::fs::write(&path, b"this is not a capture file at all").expect("write");
    assert_eq!(
        start_file(&path, None).err(),
        Some(CaptureError::Other("not a pcap or pcapng file".into()))
    );
}

#[test]
fn an_empty_file_is_not_a_capture() {
    let _g = serial();
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("empty.pcap");
    std::fs::write(&path, b"").expect("write");
    assert!(matches!(
        start_file(&path, None).err(),
        Some(CaptureError::Other(_))
    ));
}

#[test]
fn a_failed_start_leaves_no_thread() {
    let _g = serial();
    let Some(before) = worker_threads() else {
        return;
    };
    let dir = tempfile::tempdir().expect("dir");
    let _ = start_file(&dir.path().join("nope.pcap"), None);
    assert_eq!(worker_threads(), Some(before));
}
