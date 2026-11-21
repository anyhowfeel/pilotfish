use super::*;

/// A valid, empty MaxMind database (one tree node, no records) with the given type name.
fn tiny_mmdb(db_type: &str) -> Vec<u8> {
    let string = |s: &str| {
        let mut v = vec![0x40 | s.len() as u8];
        v.extend(s.as_bytes());
        v
    };
    let uint = |ctrl: u8, n: u64| {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        let mut v = vec![ctrl | bytes.len() as u8];
        v.extend(bytes);
        v
    };
    let mut meta = vec![0xE0 | 9];
    for (key, value) in [
        ("node_count", uint(0xC0, 1)),
        ("record_size", uint(0xA0, 24)),
        ("ip_version", uint(0xA0, 4)),
        ("database_type", string(db_type)),
        ("languages", vec![0x00, 0x04]),
        ("binary_format_major_version", uint(0xA0, 2)),
        ("binary_format_minor_version", uint(0xA0, 0)),
        ("build_epoch", {
            let mut v = uint(0x00, 1_700_000_000);
            v.insert(1, 0x02);
            v
        }),
        ("description", vec![0xE0]),
    ] {
        meta.extend(string(key));
        meta.extend(value);
    }
    let mut db = vec![0, 0, 1, 0, 0, 1];
    db.extend([0u8; 16]);
    db.extend(b"\xAB\xCD\xEFMaxMind.com");
    db.extend(meta);
    db
}

fn store() -> (tempfile::TempDir, GeoStore) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = GeoStore::in_dir(tmp.path().join("geo"));
    (tmp, store)
}

#[test]
fn the_tiny_database_is_accepted_by_the_reader() {
    let (tmp, _) = store();
    let p = tmp.path().join("x.mmdb");
    std::fs::write(&p, tiny_mmdb("DBIP-Country-Lite")).unwrap();
    assert!(validate(&p).is_ok());
}

#[test]
fn month_urls_cover_this_month_and_the_previous_one() {
    assert_eq!(latest_months(2026, 11), [(2026, 11), (2026, 10)]);
    assert_eq!(latest_months(2027, 1), [(2027, 1), (2026, 12)]);
    assert_eq!(
        url_for("dbip-asn-lite", (2026, 3)),
        "https://download.db-ip.com/free/dbip-asn-lite-2026-03.mmdb.gz"
    );
}

#[test]
fn an_empty_folder_proposes_both_downloads_and_nothing_else() {
    let (_tmp, s) = store();
    let info = s.info();
    assert_eq!(info.rows.len(), 2);
    assert!(
        info.rows
            .iter()
            .all(|r| r.state == GeoDbState::Missing && !r.custom)
    );
}

#[test]
fn installed_busy_and_failed_states_show_in_their_rows() {
    let (_tmp, mut s) = store();
    std::fs::create_dir_all(&s.dir).unwrap();
    std::fs::write(
        s.path_of("dbip-country-lite"),
        tiny_mmdb("DBIP-Country-Lite"),
    )
    .unwrap();
    s.busy.insert("dbip-asn");
    let info = s.info();
    assert!(matches!(info.rows[0].state, GeoDbState::Ready(_)));
    assert_eq!(info.rows[1].state, GeoDbState::Downloading);
    s.busy.clear();
    s.failed.insert("dbip-asn", "offline".into());
    assert_eq!(s.info().rows[1].state, GeoDbState::Failed("offline".into()));
}

#[test]
fn a_chosen_database_is_validated_copied_listed_and_removable() {
    let (tmp, mut s) = store();
    let bad = tmp.path().join("notes.mmdb");
    std::fs::write(&bad, b"not a database").unwrap();
    assert!(add_file(&bad, &s.dir).is_err());
    assert!(!s.dir.join("notes.mmdb").exists());

    let good = tmp.path().join("mine.mmdb");
    std::fs::write(&good, tiny_mmdb("GeoLite2-ASN")).unwrap();
    add_file(&good, &s.dir).unwrap();
    let info = s.info();
    let row = info.rows.iter().find(|r| r.custom).expect("custom row");
    assert_eq!(row.id, "mine.mmdb");

    s.remove("mine.mmdb");
    assert!(s.error.is_none() && !s.dir.join("mine.mmdb").exists());
}

#[test]
fn remove_refuses_paths_outside_the_folder() {
    let (tmp, mut s) = store();
    let outside = tmp.path().join("keep.mmdb");
    std::fs::write(&outside, b"x").unwrap();
    s.remove("../keep.mmdb");
    assert!(outside.exists());
    assert!(s.error.is_some());
}

#[test]
fn polling_applies_a_finished_download_once() {
    let (_tmp, mut s) = store();
    s.busy.insert("dbip-asn");
    s.tx.send(Msg::Downloaded("dbip-asn", Err("offline".into())))
        .unwrap();
    assert!(s.poll());
    assert!(!s.poll());
    assert_eq!(s.info().rows[1].state, GeoDbState::Failed("offline".into()));
}

/// Needs the network: `cargo test -p wl-app downloads_a_real -- --ignored`.
#[test]
#[ignore]
fn downloads_a_real_database_and_it_answers_lookups() {
    let (_tmp, s) = store();
    fetch("dbip-country-lite", &s.dir).expect("download");
    let db = GeoDb::from_dirs(std::slice::from_ref(&s.dir)).expect("readable database");
    let g = db.lookup("8.8.8.8").expect("8.8.8.8 is known");
    assert_eq!(g.country_code.as_deref(), Some("US"));
    assert!(!s.dir.join("dbip-country-lite.mmdb.part").exists());
}
