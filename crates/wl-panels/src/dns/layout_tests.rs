//! Headless layout checks of the DNS tab in every state, both themes and several sizes.
use std::sync::Arc;

use wl_kit::theme::Mode;
use wl_model::{DnsQuery, Rcode};

use super::model::tests::q;
use super::*;
use crate::test_util::run;

fn many() -> Vec<DnsQuery> {
    (0..80u64)
        .map(|i| {
            let rc = match i % 7 {
                0 => Some(Rcode::NxDomain),
                1 => Some(Rcode::ServFail),
                2 => None,
                _ => Some(Rcode::NoError),
            };
            let name = format!("host-{}.example.com", i % 9);
            let mut r = q(i * 2 + 1, &name, rc, rc.map(|_| 3.0 + i as f64));
            r.retransmission = i % 11 == 0;
            r
        })
        .collect()
}

#[test]
fn stays_inside_its_area_in_every_state() {
    let states = [
        DnsState::Idle,
        DnsState::Loading,
        DnsState::Error("boom".into()),
        DnsState::Ready(Arc::new(Vec::new())),
        DnsState::Ready(Arc::new(many())),
    ];
    for mode in [Mode::Dark, Mode::Light] {
        for state in &states {
            for width in [700.0_f32, 1000.0, 1600.0] {
                for scale in [1.0_f32, 1.5] {
                    let mut panel = DnsPanel::default();
                    panel.set_state(state.clone());
                    run(width, 640.0, scale, mode, |ui| {
                        let area = ui.max_rect();
                        panel.ui(ui);
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

#[test]
fn idle_asks_for_data_and_the_filter_narrows_rows() {
    let mut p = DnsPanel::default();
    let mut acts = Vec::new();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| acts = p.ui(ui));
    assert_eq!(acts, [DnsAction::Load]);
    p.set_state(DnsState::Ready(Arc::new(many())));
    p.set_query("host-3");
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        assert!(p.ui(ui).is_empty());
    });
    assert!(!p.order.is_empty() && p.order.len() < 80);
}
