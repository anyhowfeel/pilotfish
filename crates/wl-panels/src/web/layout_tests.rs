//! Headless layout checks at several widths and scales, in both themes, in every page state.
use wl_kit::egui::{self, Context, Rect, pos2, vec2};
use wl_kit::theme::Mode;

use super::model::Sel;
use super::{KeysInfo, WebAction, WebData, WebPanel, WebStatus, demo_data, demo_detail};

fn run(width: f32, height: f32, scale: f32, mode: Mode, mut f: impl FnMut(&mut egui::Ui)) {
    let ctx = Context::default();
    wl_kit::theme::apply_mode(&ctx, mode);
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                pos2(0.0, 0.0),
                vec2(width / scale, height / scale),
            )),
            ..Default::default()
        };
        ctx.set_pixels_per_point(scale);
        ctx.run_ui(input, |ui| f(ui)).drop_without_applying_deltas();
    }
}

#[test]
fn page_stays_inside_its_area_at_all_widths_and_scales() {
    let (ex, tls) = demo_data();
    let detail = demo_detail(&ex[4]);
    let sels = [
        Some(Sel::Http(ex[4].id)),
        Some(Sel::Tls(tls[1].first_frame)),
        None,
    ];
    for mode in [Mode::Dark, Mode::Light] {
        for sel in sels {
            for width in [1000.0_f32, 1280.0, 1600.0] {
                for scale in [1.0_f32, 1.5] {
                    let mut panel = WebPanel {
                        selected: sel,
                        ..Default::default()
                    };
                    run(width, 640.0, scale, mode, |ui| {
                        let area = ui.max_rect();
                        let d = WebData {
                            rev: 1,
                            exchanges: &ex,
                            tls: &tls,
                            detail: Some(&detail),
                            status: WebStatus::Ready,
                            keys: &KeysInfo::default(),
                        };
                        panel.ui(ui, &d);
                        assert!(
                            area.expand(1.0).contains_rect(ui.min_rect()),
                            "{mode:?} {sel:?} {width}@{scale}: {:?} outside {area:?}",
                            ui.min_rect()
                        );
                    });
                }
            }
        }
    }
}

#[test]
fn empty_loading_and_error_states_render() {
    let mut panel = WebPanel::default();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        for status in [
            WebStatus::Ready,
            WebStatus::Loading,
            WebStatus::Error("boom"),
        ] {
            let d = WebData {
                rev: 0,
                exchanges: &[],
                tls: &[],
                detail: None,
                status,
                keys: &KeysInfo::default(),
            };
            assert!(panel.ui(ui, &d).is_empty());
        }
    });
}

#[test]
fn selecting_a_row_requests_its_detail_once() {
    let (ex, tls) = demo_data();
    let mut panel = WebPanel {
        selected: Some(Sel::Http(ex[2].id)),
        ..Default::default()
    };
    let mut loads = 0;
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        let d = WebData {
            rev: 1,
            exchanges: &ex,
            tls: &tls,
            detail: None,
            status: WebStatus::Ready,
            keys: &KeysInfo::default(),
        };
        loads += panel
            .ui(ui, &d)
            .iter()
            .filter(|a| matches!(a, WebAction::LoadDetail(_)))
            .count();
    });
    assert_eq!(loads, 1);
}
