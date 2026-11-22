//! Unit tests (kept in their own file to respect the 250-line limit).
use super::*;

#[test]
fn recent_is_dedup_and_bounded() {
    let mut p = Prefs::default();
    for i in 0..20 {
        p.push_recent(format!("/f{i}").into());
    }
    p.push_recent("/f15".into());
    assert_eq!(p.recent.len(), MAX_RECENT);
    assert_eq!(p.recent[0], PathBuf::from("/f15"));
    assert_eq!(p.recent.iter().filter(|f| f.ends_with("f15")).count(), 1);
}

#[test]
fn tidy_dedupes_canonical_paths_and_drops_missing() {
    let dir = std::env::temp_dir().join(format!("wl-prefs-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
    let f = dir.join("a.pcap");
    std::fs::write(&f, b"x").expect("write");
    let rel = dir.join("sub/../a.pcap");
    let mut p = Prefs {
        recent: vec![rel.clone(), f.clone(), dir.join("gone.pcap")],
        pinned: vec![rel, dir.join("gone.pcap")],
        ..Prefs::default()
    };
    p.packet_counts.insert(PathBuf::from("/not/listed"), 3);
    let p = p.tidy();
    let canon = std::fs::canonicalize(&f).expect("canon");
    assert_eq!(p.recent, vec![canon.clone()]);
    assert_eq!(p.pinned, vec![canon]);
    assert!(p.packet_counts.is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn pin_clear_and_counts() {
    let mut p = Prefs::default();
    p.push_recent("/f1".into());
    p.toggle_pin(Path::new("/f1"));
    p.record_packets(Path::new("/f1"), 7);
    p.clear_recent();
    assert!(p.recent.is_empty());
    assert_eq!(p.pinned, vec![PathBuf::from("/f1")]);
    assert_eq!(p.packet_counts.get(Path::new("/f1")), Some(&7));
    p.toggle_pin(Path::new("/f1"));
    assert!(p.pinned.is_empty() && p.packet_counts.is_empty());
}

#[test]
fn defaults_are_dark_at_100_percent() {
    let p = Prefs::default();
    assert_eq!(p.settings.theme, ThemeChoice::Dark);
    assert_eq!(p.settings.ui_scale, 1.0);
}

#[test]
fn migrates_v1_file() {
    let old = r#"{"ui_scale":1.5,"light_mode":true,"recent":["/a.pcap"],"filter_history":["tcp"]}"#;
    let p = serde_json::from_str::<Prefs>(old).expect("parse").migrate();
    assert_eq!(p.version, VERSION);
    assert_eq!(p.settings.ui_scale, 1.5);
    assert_eq!(p.settings.theme, ThemeChoice::Light);
    assert_eq!(p.recent, vec![PathBuf::from("/a.pcap")]);
    let json = serde_json::to_string(&p).expect("ser");
    assert!(!json.contains("light_mode"), "legacy keys are dropped");
}

#[test]
fn migration_clamps_and_roundtrips() {
    let p = serde_json::from_str::<Prefs>(r#"{"ui_scale":9.0}"#)
        .expect("parse")
        .migrate();
    assert_eq!(p.settings.ui_scale, 2.0);
    let json = serde_json::to_string(&p).expect("ser");
    let back = serde_json::from_str::<Prefs>(&json).expect("de").migrate();
    assert_eq!(back, p);
}

#[test]
fn garbage_settings_fields_fall_back_to_defaults() {
    assert_eq!(
        serde_json::from_str::<Prefs>("{}").expect("p").migrate(),
        Prefs::default()
    );
}

#[test]
fn insight_rules_survive_a_prefs_round_trip_and_are_clamped_on_load() {
    let mut p = Prefs::default();
    p.settings.insights.mute("10.0.0.9");
    p.settings.insights.thresholds.scan_min_ports = 7;
    let json = serde_json::to_string(&p).expect("ser");
    let back: Prefs = serde_json::from_str(&json).expect("de");
    assert_eq!(back.settings.insights, p.settings.insights);

    p.settings.insights.thresholds.scan_min_ports = 0;
    p.settings.insights.muted.push("  ".into());
    let fixed = p.migrate().settings.insights;
    assert_eq!(fixed.thresholds.scan_min_ports, 2);
    assert_eq!(fixed.muted, ["10.0.0.9"]);
}
