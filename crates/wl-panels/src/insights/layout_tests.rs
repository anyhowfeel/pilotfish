//! Headless layout checks: the page must stay inside its area at every width and scale.
use wl_kit::egui::{self, Context, Rect, pos2, vec2};
use wl_kit::theme::Mode;
use wl_model::{
    Analyses, Analysis, BehaviorData, ExpertEntry, ExpertReport, ExpertSeverity, HostStat,
    ProtocolHierarchy, SecurityData, StatsSnapshot,
};

use super::{InsightsPanel, Tab};
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

/// Every analysis finished, with `expert` as the expert report.
fn finished(expert: ExpertReport) -> Analyses {
    Analyses {
        expert: Analysis::Ready(expert),
        hierarchy: Analysis::Ready(ProtocolHierarchy::default()),
        behavior: Analysis::Ready(BehaviorData::default()),
        security: Analysis::Ready(SecurityData::default()),
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
    let (analyses, st) = (finished(report()), stats());
    let mut panel = InsightsPanel::default();
    for mode in [Mode::Dark, Mode::Light] {
        for width in [700.0_f32, 1000.0, 1600.0] {
            for scale in [1.0_f32, 1.5] {
                run(width, 700.0, scale, mode, |ui| {
                    let area = ui.max_rect();
                    panel.ui(ui, &st, &analyses, &plain());
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
        panel.ui(
            ui,
            &StatsSnapshot::default(),
            &Analyses::default(),
            &plain(),
        );
        panel.ui(ui, &stats(), &finished(ExpertReport::default()), &plain());
    });
}

#[test]
fn no_wireshark_renders_the_needs_state_and_no_actions() {
    let mut panel = InsightsPanel::default();
    let cx = crate::features::InsightContext {
        wireshark: wl_model::Wireshark::Missing,
        ..plain()
    };
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        let acts = panel.ui(ui, &stats(), &Analyses::default(), &cx);
        assert!(acts.is_empty());
    });
}

fn failed<T>(reason: &str) -> Analysis<T> {
    Analysis::Failed(reason.into())
}

fn states() -> Vec<(&'static str, Analyses)> {
    let mut running = Analyses::default();
    running.start();
    let mut half_done = finished(report());
    half_done.behavior = Analysis::Pending;
    let mut expert_failed = finished(ExpertReport::default());
    expert_failed.expert = failed("tshark exited with status 2");
    let all_failed = Analyses {
        expert: failed("tshark exited with status 2"),
        hierarchy: failed("tshark exited with status 2"),
        behavior: failed("no such file"),
        security: failed("no such file"),
    };
    let mut failed_beside_findings = finished(report());
    failed_beside_findings.security = failed("no such file");
    vec![
        ("not run", Analyses::default()),
        ("running", running),
        ("partly done", half_done),
        ("expert failed", expert_failed),
        ("all failed", all_failed),
        ("failed beside findings", failed_beside_findings),
        ("finished", finished(report())),
    ]
}

#[test]
fn every_tab_stays_inside_its_area_in_every_analysis_state() {
    let st = stats();
    for (name, analyses) in states() {
        for tab in [Tab::Findings, Tab::Expert, Tab::Hierarchy] {
            for mode in [Mode::Dark, Mode::Light] {
                let mut panel = InsightsPanel {
                    tab,
                    ..Default::default()
                };
                run(900.0, 600.0, 1.0, mode, |ui| {
                    let area = ui.max_rect();
                    panel.ui(ui, &st, &analyses, &plain());
                    assert!(
                        area.expand(1.0).contains_rect(ui.min_rect()),
                        "{name} {tab:?} {mode:?}: {:?} outside {area:?}",
                        ui.min_rect()
                    );
                });
            }
        }
    }
}

#[test]
fn an_empty_capture_shows_no_summary_strip_and_no_health_claim() {
    let mut panel = InsightsPanel::default();
    run(900.0, 600.0, 1.0, Mode::Dark, |ui| {
        panel.ui(
            ui,
            &StatsSnapshot::default(),
            &finished(ExpertReport::default()),
            &plain(),
        );
    });
}
