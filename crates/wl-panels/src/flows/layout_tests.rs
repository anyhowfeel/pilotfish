//! Headless checks of the Flows page: stays inside its area at every width/scale/theme,
//! requests its data exactly once, and paints only the visible rows of huge flows.
use std::time::Instant;

use wl_kit::egui::{self, Context, Rect, pos2, vec2};
use wl_kit::theme::Mode;
use wl_model::{
    FlowEvent, FlowEvents, FlowFlags, FlowKey, FlowSel, StatsSnapshot, TcpSample, TcpSamples,
    Transport,
};

use super::{FlowsAction, FlowsData, FlowsPanel, Tab};

/// Runs 3 frames on a page area of `width` x `height` points.
fn run(width: f32, height: f32, scale: f32, mode: Mode, mut f: impl FnMut(&mut egui::Ui)) -> usize {
    let ctx = Context::default();
    wl_kit::theme::apply_mode(&ctx, mode);
    let mut shapes = 0;
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(width, height))),
            ..Default::default()
        };
        ctx.set_pixels_per_point(scale);
        let out = ctx.run_ui(input, |ui| f(ui));
        shapes = out.shapes.len();
        out.drop_without_applying_deltas();
    }
    shapes
}

fn synth(n: usize, hosts: usize) -> FlowEvents {
    let names: Vec<std::sync::Arc<str>> = (0..hosts)
        .map(|i| format!("10.0.0.{}", i + 1).into())
        .collect();
    let events = (0..n)
        .map(|i| {
            let (s, d) = (i % hosts, (i + 1) % hosts);
            let mut flags = FlowFlags::ACK;
            if i == 0 {
                flags = FlowFlags::SYN;
            } else if i % 50 == 7 {
                flags = flags.with(FlowFlags::RETRANS);
            }
            FlowEvent {
                frame: i as u64 + 1,
                rel: i as f64 * 0.001,
                src: names[s].clone(),
                dst: names[d].clone(),
                src_port: Some(4000 + s as u16),
                dst_port: Some(80),
                protocol: if i % 9 == 0 { "TLSv1.3" } else { "TCP" }.into(),
                label: "[PSH, ACK] a rather long informational label that must be elided".into(),
                flags,
                seq: Some(i as u32 * 10),
                ack: Some(i as u32),
                len: 10,
            }
        })
        .collect();
    FlowEvents {
        events,
        truncated: n > 100_000,
    }
}

fn tcp(n: usize) -> TcpSamples {
    let samples = (0..n)
        .map(|i| TcpSample {
            frame: i as u64 + 1,
            rel: i as f64 * 0.01,
            from_a: i % 2 == 0,
            seq: i as u64 * 1448,
            ack: i as u64 * 700,
            len: if i % 2 == 0 { 1448 } else { 0 },
            window: 60_000 - (i as u64 % 40) * 500,
            rtt: (i % 2 == 1).then_some(0.02 + (i % 7) as f64 * 0.003),
            flags: if i % 31 == 0 {
                FlowFlags::RETRANS
            } else {
                FlowFlags::ACK
            },
        })
        .collect();
    TcpSamples {
        a: "10.0.0.1".into(),
        b: "10.0.0.2".into(),
        a_port: Some(4000),
        b_port: Some(80),
        samples,
        truncated: false,
    }
}

fn conv() -> FlowSel {
    FlowSel::Conversation(FlowKey {
        a: "10.0.0.1".into(),
        b: "10.0.0.2".into(),
        transport: Transport::Tcp,
        a_port: Some(4000),
        b_port: Some(80),
    })
}

#[test]
fn page_stays_inside_its_area_in_every_state() {
    let stats = StatsSnapshot::default();
    let sel = conv();
    let (ev, samples) = (synth(500, 3), tcp(300));
    for mode in [Mode::Dark, Mode::Light] {
        // Page areas in points: the smallest window at scale 1.5, a default one, a big one.
        for (w, h) in [(470.0_f32, 380.0_f32), (804.0, 560.0), (1244.0, 860.0)] {
            for scale in [1.0_f32, 1.5] {
                for tab in Tab::ALL {
                    let mut panel = FlowsPanel::default();
                    panel.open(sel.clone());
                    panel.set_tab(tab);
                    run(w, h, scale, mode, |ui| {
                        let area = ui.max_rect();
                        let mut d = FlowsData::empty(&stats);
                        d.flow = Some((&sel, &ev));
                        d.tcp = Some((&sel, &samples));
                        d.rev = 1;
                        panel.ui(ui, &d);
                        assert!(
                            area.expand(1.0).contains_rect(ui.min_rect()),
                            "{mode:?} {tab:?} {w}x{h}@{scale}: {:?} outside {area:?}",
                            ui.min_rect()
                        );
                    });
                }
            }
        }
    }
}

#[test]
fn data_is_requested_once_per_view() {
    let stats = StatsSnapshot::default();
    let mut panel = FlowsPanel::default();
    let sel = conv();
    panel.open(sel.clone());
    let mut seen: Vec<FlowsAction> = Vec::new();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        seen.extend(panel.ui(ui, &FlowsData::empty(&stats)));
    });
    assert_eq!(seen, [FlowsAction::LoadFlow(sel.clone())]);
    panel.set_tab(Tab::Rtt);
    seen.clear();
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        seen.extend(panel.ui(ui, &FlowsData::empty(&stats)));
    });
    assert_eq!(seen, [FlowsAction::LoadTcp(sel)]);
}

#[test]
fn stale_results_of_another_selection_are_ignored() {
    let stats = StatsSnapshot::default();
    let (ev, other) = (synth(10, 2), FlowSel::Stream(9));
    let mut panel = FlowsPanel::default();
    panel.open(conv());
    run(1000.0, 640.0, 1.0, Mode::Dark, |ui| {
        let mut d = FlowsData::empty(&stats);
        d.flow = Some((&other, &ev));
        d.rev = 1;
        panel.ui(ui, &d);
        assert!(
            panel.graph.lanes().hosts.is_empty(),
            "foreign data was used"
        );
    });
}

#[test]
fn huge_flows_paint_only_the_visible_rows() {
    let stats = StatsSnapshot::default();
    let (sel, ev) = (conv(), synth(100_000, 2));
    let mut panel = FlowsPanel::default();
    panel.open(sel.clone());
    let shapes = run(1440.0, 900.0, 1.0, Mode::Dark, |ui| {
        let mut d = FlowsData::empty(&stats);
        d.flow = Some((&sel, &ev));
        d.rev = 1;
        panel.ui(ui, &d);
    });
    assert!(
        (100..1500).contains(&shapes),
        "{shapes} shapes for 100k events"
    );
}

#[test]
#[ignore = "timing: cargo test --release -p wl-panels flows::layout_tests::frame_time -- --ignored --nocapture"]
fn frame_time_of_a_100k_flow() {
    let stats = StatsSnapshot::default();
    let (sel, ev) = (conv(), synth(100_000, 3));
    let mut panel = FlowsPanel::default();
    panel.open(sel.clone());
    let ctx = Context::default();
    wl_kit::theme::apply_mode(&ctx, Mode::Dark);
    let mut times = Vec::new();
    for i in 0..120 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1440.0, 900.0))),
            ..Default::default()
        };
        let t = Instant::now();
        ctx.run_ui(input, |ui| {
            let mut d = FlowsData::empty(&stats);
            d.flow = Some((&sel, &ev));
            d.rev = 1;
            panel.ui(ui, &d);
        })
        .drop_without_applying_deltas();
        if i >= 20 {
            times.push(t.elapsed().as_secs_f64() * 1e3);
        }
    }
    times.sort_by(f64::total_cmp);
    println!(
        "100k flow frame: median {:.3} ms, p95 {:.3} ms, max {:.3} ms",
        times[times.len() / 2],
        times[times.len() * 95 / 100],
        times[times.len() - 1]
    );
}
