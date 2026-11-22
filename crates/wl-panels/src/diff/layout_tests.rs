//! Headless layout checks of the Capture Diff page at tiled and full widths.
use std::sync::Arc;

use wl_kit::theme::Mode;
use wl_stats::{CaptureDiff, Row, Traffic};

use super::*;
use crate::test_util::run;

fn traffic_row(label: &str, before: Option<u64>, after: Option<u64>) -> Row<Traffic> {
    let t = |b| Traffic {
        packets: b / 100,
        bytes: b,
    };
    Row {
        label: label.into(),
        before: before.map(t),
        after: after.map(t),
    }
}

fn diff() -> CaptureDiff {
    CaptureDiff {
        before: Traffic {
            packets: 1_234_567,
            bytes: 987_654_321,
        },
        after: Traffic {
            packets: 7_654_321,
            bytes: 123_456_789,
        },
        hosts: vec![
            traffic_row("203.0.113.200", None, Some(5_000_000)),
            traffic_row(
                "a-very-long-hostname.internal.example.com",
                Some(9_000),
                None,
            ),
            traffic_row("192.168.1.12", Some(4_000_000), Some(6_000_000)),
        ],
        ..CaptureDiff::default()
    }
}

#[test]
fn report_stays_inside_its_area_at_tiled_and_full_widths() {
    let state = DiffState::Ready(Arc::new(diff()));
    let data = DiffData {
        state: &state,
        base: "before.pcapng",
        other: Some("after.pcapng"),
    };
    for mode in [Mode::Dark, Mode::Light] {
        for width in [390.0_f32, 700.0, 1230.0] {
            let mut panel = DiffPanel::default();
            run(width, 640.0, 1.0, mode, |ui| {
                let area = ui.max_rect();
                panel.ui(ui, &data);
                assert!(
                    area.expand(1.0).contains_rect(ui.min_rect()),
                    "{mode:?} {width}: {:?} outside {area:?}",
                    ui.min_rect()
                );
            });
        }
    }
}

#[test]
fn change_is_a_signed_percentage_only_when_both_sides_differ() {
    let pct = |b, a| section::change(&traffic_row("h", b, a)).map(|c| c.0);
    assert_eq!(pct(Some(100), Some(150)), Some("+50%".into()));
    assert_eq!(pct(Some(200), Some(100)), Some("-50%".into()));
    assert_eq!(pct(Some(100), Some(100)), None);
    assert_eq!(pct(None, Some(100)), None);
    assert_eq!(pct(Some(100), None), None);
}
