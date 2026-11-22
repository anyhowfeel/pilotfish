//! Headless layout checks: the page must stay inside its area at every width and scale.
use wl_kit::egui::{self, Context, Rect, pos2, vec2};
use wl_kit::theme::Mode;
use wl_model::{
    ExpertEntry, ExpertReport, ExpertSeverity, HostStat, ProtocolHierarchy, StatsSnapshot,
};

use super::InsightsPanel;
use crate::test_util::plain;

fn report() -> ExpertReport {
    let e = |severity, frequency, protocol: &str, summary: &str| ExpertEntry {
        severity,
        frequency,
        group: "Proto".into(),
        protocol: protocol.into(),
        summary: summary.into(),
    };
    ExpertReport {
        entries: vec![
            e(ExpertSeverity::Error, 2, "HTTP", "Malformed Packet"),
            e(ExpertSeverity::Warn, 50, "TCP", "TCP Retransmission"),
            e(ExpertSeverity::Warn, 40, "TCP", "Connection reset (RST)"),
            e(ExpertSeverity::Warn, 4, "mDNS", "DNS query retransmission"),
            e(
                ExpertSeverity::Note,
                20,
                "ICMPv6",
                "Type indicates an error",
            ),
        ],
    }
}

fn stats() -> StatsSnapshot {
    StatsSnapshot {
        total_packets: 200,
        total_bytes: 100_000,
        hosts: vec![HostStat {
            addr: "2606:4700:4700::1111".into(),
            bytes_in: 90_000,
            bytes_out: 5_000,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn run(width: f32, height: f32, scale: f32, mode: Mode, f: impl FnMut(&mut egui::Ui)) {
    let mut f = f;
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
    let (rep, st) = (report(), stats());
    let phs: Option<ProtocolHierarchy> = None;
    let mut panel = InsightsPanel::default();
    for mode in [Mode::Dark, Mode::Light] {
        for width in [700.0_f32, 1000.0, 1600.0] {
            for scale in [1.0_f32, 1.5] {
                run(width, 700.0, scale, mode, |ui| {
                    let area = ui.max_rect();
                    panel.ui(ui, &st, Some(&rep), phs.as_ref(), None, &plain());
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

#[test]
fn empty_and_healthy_states_render() {
    let mut panel = InsightsPanel::default();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        panel.ui(ui, &StatsSnapshot::default(), None, None, None, &plain());
        panel.ui(
            ui,
            &stats(),
            Some(&ExpertReport::default()),
            None,
            None,
            &plain(),
        );
    });
}
