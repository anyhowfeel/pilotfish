//! Headless layout checks of the Files tab in every state, both themes and several sizes.
use std::sync::Arc;

use wl_kit::theme::Mode;
use wl_model::ObjectSet;

use super::model::tests::obj;
use super::*;
use crate::test_util::run;

fn set(n: u32, truncated: bool) -> Arc<ObjectSet> {
    let objects = (0..n)
        .map(|i| {
            let (name, ct) = if i % 3 == 0 {
                (
                    format!("a-rather-long-file-name-number-{i}.html"),
                    "text/html",
                )
            } else if i % 3 == 1 {
                (format!("logo{i}.png"), "image/png")
            } else {
                (format!("blob{i}.bin"), "application/octet-stream")
            };
            obj(
                i,
                &name,
                ct,
                1_000 * u64::from(i + 1),
                "www.example.com",
                Some(u64::from(i) * 3 + 2),
            )
        })
        .collect();
    Arc::new(ObjectSet {
        protocol: "http".into(),
        dir: "/tmp/x".into(),
        objects,
        truncated,
    })
}

#[test]
fn stays_inside_its_area_in_every_state() {
    let states = [
        ObjectsState::Idle,
        ObjectsState::Loading,
        ObjectsState::Error("boom".into()),
        ObjectsState::Ready(set(0, false)),
        ObjectsState::Ready(set(40, false)),
        ObjectsState::Ready(set(40, true)),
    ];
    for mode in [Mode::Dark, Mode::Light] {
        for state in &states {
            for sel in [None, Some(1u32)] {
                for width in [600.0_f32, 1000.0, 1600.0] {
                    for scale in [1.0_f32, 1.5] {
                        let mut p = ObjectsPanel {
                            state: state.clone(),
                            requested: Some(0),
                            selected: sel.filter(|_| matches!(state, ObjectsState::Ready(s) if !s.objects.is_empty())),
                            ..Default::default()
                        };
                        p.preview.data = p.selected.map(|id| PreviewData {
                            id,
                            preview: Preview::Image {
                                w: 2,
                                h: 2,
                                rgba: vec![200; 16],
                            },
                        });
                        run(width, 640.0, scale, mode, |ui| {
                            let area = ui.max_rect();
                            p.ui(ui);
                            assert!(
                                area.expand(1.0).contains_rect(ui.min_rect()),
                                "{mode:?} {width}@{scale}: {:?} outside {area:?}",
                                ui.min_rect()
                            );
                        });
                    }
                }
            }
        }
    }
}

#[test]
fn asks_for_data_once_per_protocol_and_previews_on_selection() {
    let mut p = ObjectsPanel::default();
    let mut acts = Vec::new();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| acts.extend(p.ui(ui)));
    assert_eq!(acts, [ObjectsAction::Load("http".into())]);
    p.set_result("smb", Ok(set(3, false)));
    assert!(p.set().is_none(), "result for another protocol is ignored");
    p.set_result("http", Ok(set(3, false)));
    p.selected = Some(0);
    let mut acts = Vec::new();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| acts.extend(p.ui(ui)));
    assert!(acts.contains(&ObjectsAction::Preview(0)));
    p.select_protocol("smb");
    acts.clear();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| acts.extend(p.ui(ui)));
    assert_eq!(acts, [ObjectsAction::Load("smb".into())]);
}
