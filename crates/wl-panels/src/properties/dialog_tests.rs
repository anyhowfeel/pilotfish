//! Headless checks of the properties dialog: states render, the window stays on screen and is
//! sized to its content (no cut-off rows, no dead space).

use wl_kit::egui::{Context, Id, Pos2, RawInput, Rect, vec2};
use wl_model::{CaptureProperties, InterfaceInfo};

use super::*;

fn props() -> CaptureProperties {
    CaptureProperties {
        file_name: "/very/long/path/to/some/capture-file.pcapng".into(),
        file_type: "pcapng".into(),
        packets: 2583,
        duration: 363.4,
        file_size: 1 << 20,
        comments: vec!["first comment".into()],
        interfaces: vec![InterfaceInfo {
            name: "eth0".into(),
            ..InterfaceInfo::default()
        }],
        application: "Dumpcap".into(),
        ..CaptureProperties::default()
    }
}

fn window_rect(d: &mut PropertiesDialog, w: f32, h: f32) -> Option<Rect> {
    let ctx = Context::default();
    for _ in 0..3 {
        let raw = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(w, h))),
            ..Default::default()
        };
        ctx.run_ui(raw, |ui| {
            d.ui(ui.ctx());
        })
        .drop_without_applying_deltas();
    }
    ctx.memory(|m| m.area_rect(Id::NULL.with("wl_file_properties")))
}

#[test]
fn closed_dialog_draws_nothing() {
    let mut d = PropertiesDialog::default();
    assert!(window_rect(&mut d, 900.0, 600.0).is_none());
}

#[test]
fn every_state_renders_inside_the_window() {
    for (w, h) in [(667.0, 427.0), (1000.0, 640.0), (1440.0, 900.0)] {
        let mut loading = PropertiesDialog::default();
        loading.begin();
        let mut failed = PropertiesDialog::default();
        failed.begin();
        failed.set_properties(Err("capinfos: file not found".into()));
        let mut ready = PropertiesDialog::default();
        ready.begin();
        ready.set_properties(Ok(props()));
        ready.set_hash(Ok("ab".repeat(32)));
        let screen = Rect::from_min_size(Pos2::ZERO, vec2(w, h));
        for d in [&mut loading, &mut failed, &mut ready] {
            let r = window_rect(d, w, h).expect("open dialog has a window");
            assert!(screen.contains_rect(r), "{w}x{h}: {r:?} leaves the screen");
        }
    }
}

#[test]
fn window_height_matches_the_content_when_it_fits() {
    let mut d = PropertiesDialog::default();
    d.begin();
    d.set_properties(Ok(props()));
    d.set_hash(Ok("cd".repeat(32)));
    let r = window_rect(&mut d, 1440.0, 1200.0).unwrap();
    let est = lines::content_height(&props(), true);
    // the dialog is exactly its content plus title bar and margins
    let chrome = r.height() - est;
    assert!(
        (chrome - TITLE_AND_MARGINS).abs() < 1.0,
        "window {} vs content {est}",
        r.height()
    );
}

#[test]
fn hash_states_follow_the_lazy_computation() {
    let mut d = PropertiesDialog::default();
    d.begin();
    assert_eq!(d.hash, HashState::Idle);
    d.set_hash_computing();
    assert_eq!(d.hash, HashState::Computing);
    d.set_hash(Err("x".into()));
    assert_eq!(d.hash, HashState::Failed("x".into()));
    d.set_hash(Ok("aa".into()));
    assert_eq!(d.hash, HashState::Ready("aa".into()));
    d.begin();
    assert_eq!(
        d.hash,
        HashState::Idle,
        "reopening forgets the old file's hash"
    );
}
