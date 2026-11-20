//! Headless dialog tests: every category renders at every size; preview/cancel/apply semantics.
use wl_kit::egui::{self, Context, Event, Key, Modifiers, Rect, pos2, vec2};
use wl_kit::theme::Mode;

use super::{AboutInfo, Category, Settings, SettingsAction, SettingsDialog, ThemeChoice};

fn frame(
    ctx: &Context,
    w: f32,
    h: f32,
    scale: f32,
    events: Vec<Event>,
    d: &mut SettingsDialog,
) -> Option<SettingsAction> {
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(
            pos2(0.0, 0.0),
            vec2(w / scale, h / scale),
        )),
        events,
        ..Default::default()
    };
    ctx.set_pixels_per_point(scale);
    let mut out = None;
    ctx.run_ui(input, |ui| out = d.ui(ui.ctx()))
        .drop_without_applying_deltas();
    out
}

fn esc() -> Event {
    Event::Key {
        key: Key::Escape,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Modifiers::NONE,
    }
}

#[test]
fn every_category_renders_at_all_sizes_and_scales() {
    for mode in [Mode::Dark, Mode::Light] {
        let ctx = Context::default();
        wl_kit::theme::apply_mode(&ctx, mode);
        for (w, h) in [(700.0, 500.0), (1000.0, 640.0), (1600.0, 900.0)] {
            for scale in [1.0, 1.5] {
                for cat in Category::ALL {
                    let mut d = SettingsDialog::default();
                    d.open(Settings::default(), AboutInfo::default(), Some(cat));
                    for _ in 0..3 {
                        let _ = frame(&ctx, w, h, scale, vec![], &mut d);
                    }
                    assert!(d.is_open());
                }
            }
        }
    }
}

#[test]
fn changed_draft_previews_once_and_escape_reverts() {
    let ctx = Context::default();
    let mut d = SettingsDialog::default();
    let original = Settings::default();
    d.open(original.clone(), AboutInfo::default(), None);
    assert_eq!(frame(&ctx, 1000.0, 640.0, 1.0, vec![], &mut d), None);
    d.draft.theme = ThemeChoice::Light;
    d.draft.ui_scale = 1.5;
    let preview = frame(&ctx, 1000.0, 640.0, 1.0, vec![], &mut d);
    assert!(matches!(&preview, Some(SettingsAction::Preview(s)) if s.ui_scale == 1.5));
    assert_eq!(frame(&ctx, 1000.0, 640.0, 1.0, vec![], &mut d), None);
    let cancel = frame(&ctx, 1000.0, 640.0, 1.0, vec![esc()], &mut d);
    assert_eq!(cancel, Some(SettingsAction::Cancel(original)));
    assert!(!d.is_open());
}

#[test]
fn closed_dialog_emits_nothing() {
    let ctx = Context::default();
    let mut d = SettingsDialog::default();
    assert_eq!(frame(&ctx, 1000.0, 640.0, 1.0, vec![], &mut d), None);
}
