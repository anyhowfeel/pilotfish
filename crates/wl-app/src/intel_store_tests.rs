use super::*;

fn write(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
}

#[test]
fn missing_folder_loads_nothing() {
    let l = load_dir(Path::new("/nonexistent/wl-intel"));
    assert!(l.intel.is_empty() && l.errors.is_empty());
    assert_eq!(summary(&l.intel), "No lists found");
}

#[test]
fn json_is_ja4db_and_other_files_are_blocklists_named_after_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "ja4db.json",
        r#"[{"application":"Chrome","ja4_fingerprint":"t13d1516h2_8daaf6152771_02713d6af862"}]"#,
    );
    write(
        tmp.path(),
        "feodo.csv",
        "# header\n2024-01-01,198.51.100.7,443,online\n",
    );
    write(tmp.path(), "hosts.txt", "0.0.0.0 bad.example.net\n");
    write(tmp.path(), ".hidden", "203.0.113.1\n");
    let l = load_dir(tmp.path());
    assert!(l.errors.is_empty(), "{:?}", l.errors);
    assert_eq!(l.intel.ip("198.51.100.7"), Some("feodo"));
    assert_eq!(l.intel.domain("bad.example.net"), Some("hosts"));
    assert_eq!(l.intel.ip("203.0.113.1"), None);
    assert!(
        l.intel
            .fingerprint("t13d1516h2_8daaf6152771_02713d6af862")
            .is_some()
    );
    assert_eq!(summary(&l.intel), "1 address, 1 domain, 1 fingerprint");
}

#[test]
fn bad_files_are_reported_and_do_not_stop_the_others() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "broken.json", "{not json");
    std::fs::write(tmp.path().join("blob.bin"), [0xff, 0xfe, 0x00]).unwrap();
    write(tmp.path(), "ok.txt", "198.51.100.7\n");
    let l = load_dir(tmp.path());
    assert_eq!(l.errors.len(), 2, "{:?}", l.errors);
    assert!(l.errors.iter().any(|e| e.starts_with("broken.json")));
    assert!(
        l.errors
            .iter()
            .any(|e| e.starts_with("blob.bin: not a text file"))
    );
    assert_eq!(l.intel.ip("198.51.100.7"), Some("ok"));
}

#[test]
fn added_files_are_copied_into_the_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("mine.txt");
    std::fs::write(&src, "198.51.100.7\n").unwrap();
    let dir = tmp.path().join("intel");
    add_file(&src, &dir).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join("mine.txt")).unwrap(),
        "198.51.100.7\n"
    );
    assert!(add_file(Path::new("/"), &dir).is_err());
}

#[test]
fn a_load_replaces_the_shared_lists() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "a.txt", "198.51.100.7\n");
    let mut store = IntelStore::in_dir(tmp.path().to_path_buf());
    assert!(store.current().is_empty());
    store.tx.send(Msg::Loaded(load_dir(tmp.path()))).unwrap();
    assert!(store.poll(&egui::Context::default()));
    assert_eq!(store.current().ip("198.51.100.7"), Some("a"));
    assert_eq!(store.info().summary, "1 address, 0 domains, 0 fingerprints");
    assert!(!store.poll(&egui::Context::default()));
}
