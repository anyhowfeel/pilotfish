use chrono::TimeZone;

use super::*;

fn at() -> DateTime<Local> {
    Local
        .with_ymd_and_hms(2026, 11, 23, 17, 5, 9)
        .single()
        .expect("a valid time")
}

fn wlan() -> CaptureOptions {
    CaptureOptions::single("wlan0", None)
}

fn never(_: &Path) -> bool {
    false
}

#[test]
fn a_capture_goes_to_the_folder_with_the_time_and_the_interface_in_its_name() {
    let p = plan(&wlan(), true, "/data/caps", at(), &never).expect("a path");
    assert_eq!(
        p,
        PathBuf::from("/data/caps/capture-20261123-170509-wlan0.pcapng")
    );
}

#[test]
fn an_empty_folder_setting_means_the_default_folder() {
    let p = plan(&wlan(), true, "  ", at(), &never).expect("a path");
    assert_eq!(p.parent(), Some(default_dir().as_path()));
    assert!(default_dir().ends_with("pilotfish/captures"));
}

#[test]
fn the_path_the_user_typed_wins() {
    let mut o = wlan();
    o.save_to = "/home/me/run.pcapng".into();
    assert_eq!(plan(&o, true, "/data/caps", at(), &never), None);
}

#[test]
fn switching_it_off_keeps_the_temporary_file() {
    assert_eq!(plan(&wlan(), false, "/data/caps", at(), &never), None);
}

#[test]
fn a_ring_buffer_always_keeps_its_files() {
    let mut o = wlan();
    o.ring.enabled = true;
    assert!(plan(&o, false, "/data/caps", at(), &never).is_some());
}

#[test]
fn a_name_that_is_taken_gets_a_number_instead_of_being_overwritten() {
    let taken = |p: &Path| {
        let n = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        n.ends_with("wlan0.pcapng") || n.ends_with("wlan0-2.pcapng")
    };
    let p = plan(&wlan(), true, "/data/caps", at(), &taken).expect("a path");
    assert!(
        p.ends_with("capture-20261123-170509-wlan0-3.pcapng"),
        "{p:?}"
    );
}

#[test]
fn odd_interface_names_stay_safe_in_a_file_name() {
    let o = CaptureOptions::single(r"\Device\NPF_{4B1/../x}", None);
    let name = plan(&o, true, "/c", at(), &never).expect("a path");
    let name = name
        .file_name()
        .and_then(|n| n.to_str())
        .expect("a name")
        .to_owned();
    assert!(!name.contains(['/', '\\', '{', '}']), "{name}");
    assert!(
        name.starts_with("capture-20261123-170509-") && name.ends_with(".pcapng"),
        "{name}"
    );
}

#[test]
fn several_interfaces_are_named_after_the_first_one() {
    let mut o = wlan();
    o.interfaces.push("eth0".into());
    let p = plan(&o, true, "/c", at(), &never).expect("a path");
    assert!(p.ends_with("capture-20261123-170509-wlan0.pcapng"), "{p:?}");
}

#[test]
fn a_tilde_stands_for_the_home_folder() {
    let Some(home) = dirs::home_dir() else { return };
    let p = plan(&wlan(), true, "~/caps", at(), &never).expect("a path");
    assert_eq!(p.parent(), Some(home.join("caps").as_path()));
}
