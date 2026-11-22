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
    store.tx.send(Msg::Loaded(0, load_dir(tmp.path()))).unwrap();
    assert!(store.poll(&egui::Context::default()));
    assert_eq!(store.current().ip("198.51.100.7"), Some("a"));
    assert_eq!(store.info().summary, "1 address, 0 domains, 0 fingerprints");
    assert!(!store.poll(&egui::Context::default()));
}

#[test]
fn adding_a_file_already_in_the_folder_keeps_its_content() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "mine.txt", "198.51.100.7\n");
    add_file(&tmp.path().join("mine.txt"), tmp.path()).unwrap();
    let dotted = tmp.path().join(".").join("mine.txt");
    add_file(&dotted, tmp.path()).unwrap();
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("mine.txt")).unwrap(),
        "198.51.100.7\n"
    );
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
}

#[test]
fn a_different_file_with_the_same_name_gets_a_new_name() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("intel");
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    write(&a, "list.txt", "198.51.100.7\n");
    write(&b, "list.txt", "203.0.113.1\n");
    add_file(&a.join("list.txt"), &dir).unwrap();
    add_file(&b.join("list.txt"), &dir).unwrap();
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    assert_eq!(read("list.txt"), "198.51.100.7\n");
    assert_eq!(read("list-1.txt"), "203.0.113.1\n");
}

#[test]
fn an_older_load_never_replaces_a_newer_one() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "new.txt", "198.51.100.7\n");
    let mut store = IntelStore::in_dir(tmp.path().to_path_buf());
    store.generation = 2;
    let stale = Loaded::default();
    store.tx.send(Msg::Loaded(1, stale)).unwrap();
    assert!(!store.poll(&egui::Context::default()));
    store.tx.send(Msg::Loaded(2, load_dir(tmp.path()))).unwrap();
    assert!(store.poll(&egui::Context::default()));
    assert_eq!(store.current().ip("198.51.100.7"), Some("new"));
    store.tx.send(Msg::Loaded(1, Loaded::default())).unwrap();
    store.poll(&egui::Context::default());
    assert_eq!(store.current().ip("198.51.100.7"), Some("new"));
}

#[test]
fn ja4db_csv_files_are_read_as_fingerprints_and_ranges_are_counted() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "ja4plus.csv",
        "application,user_agent_string,ja4_fingerprint\nChrome,\"Mozilla/5.0, like Gecko.com\",t13d1516h2_8daaf6152771_02713d6af862\n",
    );
    write(tmp.path(), "drop.txt", "\u{feff}10.0.0.0/8\n");
    let l = load_dir(tmp.path());
    assert!(l.errors.is_empty(), "{:?}", l.errors);
    let (_, ranges, domains, prints) = l.intel.counts();
    assert_eq!((ranges, domains, prints), (1, 0, 1));
    assert_eq!(l.intel.ip("10.1.2.3"), Some("drop"));
    assert_eq!(
        summary(&l.intel),
        "0 addresses, 1 ranges, 0 domains, 1 fingerprints"
    );
}

#[test]
fn a_json_lines_file_is_reported_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "ja4.json",
        "{\"application\":\"a\",\"ja4\":\"x\"}\n{\"application\":\"b\",\"ja4\":\"y\"}\n",
    );
    let l = load_dir(tmp.path());
    assert!(
        l.errors[0].starts_with("ja4.json: JSON Lines"),
        "{:?}",
        l.errors
    );
}
