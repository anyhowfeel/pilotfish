//! Headless layout checks: nothing may leave its card, across dark/light, scales and widths.

use std::path::PathBuf;
use std::sync::Arc;

use wl_kit::egui::{self, vec2};
use wl_kit::theme::{Mode, Palette};
use wl_model::{
    ConversationStat, FlowKey, HostStat, Interface, ProtocolStat, RatePoint, StatsSnapshot,
    Transport,
};

use super::harness::run;
use super::*;
use crate::overview::cards::card;
use crate::overview::grid::{Card, place};

fn snapshot() -> StatsSnapshot {
    let hosts = (0..40)
        .map(|i| HostStat {
            addr: Arc::from(format!("192.168.{}.{}", i / 8, i)),
            packets_in: 1000 * i,
            packets_out: 10 * i,
            bytes_in: 123_456 * i,
            bytes_out: 7_890 * i,
            is_private: i % 2 == 0,
        })
        .collect();
    let conversations = (0..40u16)
        .map(|i| ConversationStat {
            key: FlowKey {
                a: "192.168.100.200".into(),
                b: "2606:4700:4700:0000:0000:0000:0000:1111".into(),
                transport: Transport::Tcp,
                a_port: Some(50000 + i),
                b_port: Some(443),
            },
            packets: 100 + u64::from(i),
            bytes: 1_000_000 * u64::from(i + 1),
            first_rel: 0.0,
            last_rel: 12.5,
            protocol: if i % 2 == 0 {
                "TLSv1.3".into()
            } else {
                "DHCPv6".into()
            },
            server_port: None,
        })
        .collect();
    let protocols = [
        "TCP", "TLSv1.3", "DNS", "UDP", "QUIC", "HTTP", "ICMPv6", "DHCPv6",
    ]
    .iter()
    .enumerate()
    .map(|(i, n)| ProtocolStat {
        name: (*n).into(),
        packets: 100,
        bytes: 10_000 / (i as u64 + 1),
    })
    .collect();
    let rate = (0..60)
        .map(|t| RatePoint {
            t: f64::from(t),
            dt: 1.0,
            packets: 50 + t as u32,
            bytes: 4000 * (t as u64 + 1),
        })
        .collect();
    StatsSnapshot {
        total_packets: 5000,
        total_bytes: 9_000_000,
        protocols,
        hosts,
        conversations,
        rate,
        edges: Vec::new(),
    }
}

fn ifaces() -> Vec<Interface> {
    [
        "lo",
        "eth0",
        "a-very-long-interface-name-that-needs-eliding-0",
    ]
    .iter()
    .map(|n| Interface {
        name: (*n).into(),
        description: Some("Some long description of the device ".repeat(3)),
        is_loopback: *n == "lo",
        is_up: true,
        sys: Default::default(),
    })
    .collect()
}

#[test]
fn dashboard_cards_contain_their_content() {
    let stats = snapshot();
    for mode in [Mode::Dark, Mode::Light] {
        for (width, height) in [(1000.0_f32, 640.0_f32), (1440.0, 900.0), (2560.0, 1440.0)] {
            for scale in [1.0_f32, 1.25, 1.5] {
                let w = (width / scale - 220.0).max(400.0);
                let (placed, _) = place(w);
                run(width, height, scale, mode, |ui| {
                    for p in &placed {
                        if matches!(p.card, Card::Kpi(_)) {
                            continue;
                        }
                        let d = super::dashboard_data::derive(&stats);
                        let rect = p.rect.translate(vec2(0.0, 10.0));
                        let used = card(ui, rect, "Card", |ui| match p.card {
                            Card::Throughput => wl_kit::charts::throughput_chart(
                                ui,
                                &stats.rate,
                                super::cards::content_height(rect),
                            ),
                            Card::Protocols => {
                                wl_kit::charts::proportion_bar(ui, &d.protocol_bar, 16.0);
                                wl_kit::charts::protocol_ranked_bars(ui, &d.protocol_rows);
                            }
                            Card::Talkers => {
                                wl_kit::charts::ranked_bars(ui, &d.talkers, Palette::accent())
                            }
                            _ => wl_kit::charts::ranked_bars(ui, &d.services, Palette::ok()),
                        });
                        assert!(
                            rect.expand(1.0).contains_rect(used),
                            "{mode:?} {:?} at {width}x{height}@{scale}: {used:?} not in {rect:?}",
                            p.card
                        );
                    }
                });
            }
        }
    }
}

#[test]
fn panels_run_without_overflow_in_dark_and_light() {
    let stats = snapshot();
    let ifs = ifaces();
    let recent = vec![PathBuf::from(
        "/home/user/captures/a-really-long-file-name-for-a-capture.pcapng",
    )];
    let (mut dash, mut hosts, mut flows, mut setup) = (
        Dashboard::default(),
        HostsPanel::default(),
        ConversationsPanel::default(),
        CaptureSetup::default(),
    );
    for mode in [Mode::Dark, Mode::Light] {
        for (width, height) in [
            (1000.0, 640.0),
            (1366.0, 768.0),
            (1440.0, 900.0),
            (1920.0, 1080.0),
            (2560.0, 1440.0),
        ] {
            for scale in [1.0, 1.25, 1.5] {
                run(width, height, scale, mode, |ui| {
                    dash.ui(ui, &stats);
                    hosts.ui(ui, &stats);
                    flows.ui(ui, &stats);
                    setup.ui(
                        ui,
                        &SetupData {
                            interfaces: &ifs,
                            activity: &Default::default(),
                            recent: &recent,
                            pinned: &[],
                            packet_counts: &Default::default(),
                            filter_status: None,
                            running: false,
                            paused: false,
                        },
                    );
                    dash.ui(ui, &StatsSnapshot::default());
                });
            }
        }
    }
}

#[test]
fn kpi_cells_fit_stat_cards() {
    for mode in [Mode::Dark, Mode::Light] {
        for width in [1000.0_f32, 1440.0, 2560.0] {
            for scale in [1.0_f32, 1.25, 1.5] {
                let (placed, _) = place((width / scale - 220.0).max(400.0));
                run(width, 900.0, scale, mode, |ui| {
                    for p in placed.iter().filter(|p| matches!(p.card, Card::Kpi(_))) {
                        let mut cell = ui.new_child(egui::UiBuilder::new().max_rect(p.rect));
                        wl_kit::widgets::stat_card(
                            &mut cell,
                            "Active hosts",
                            "123.4 MiB",
                            Some("12 private"),
                        );
                        let used = cell.min_rect();
                        assert!(
                            p.rect.expand(1.0).contains_rect(used),
                            "{mode:?} {width}@{scale}: {used:?} not in {:?}",
                            p.rect
                        );
                    }
                });
            }
        }
    }
}

struct WithProcesses;

impl NameResolver for WithProcesses {
    fn name(&self, _addr: &str) -> Option<Arc<str>> {
        None
    }

    fn processes(&self, _addr: &str) -> Vec<wl_model::ProcessInfo> {
        ["firefox", "curl"]
            .into_iter()
            .zip([1234, 77])
            .map(|(n, pid)| wl_model::ProcessInfo {
                pid,
                name: n.into(),
            })
            .collect()
    }

    fn flow_process(&self, _key: &FlowKey) -> Option<wl_model::ProcessInfo> {
        self.processes("").into_iter().next()
    }

    fn has_processes(&self) -> bool {
        true
    }
}

#[test]
fn process_columns_fit_when_data_exists() {
    let stats = snapshot();
    let (mut hosts, mut convs) = (HostsPanel::default(), ConversationsPanel::default());
    hosts.set_resolver(Box::new(WithProcesses));
    convs.set_resolver(Box::new(WithProcesses));
    for mode in [Mode::Dark, Mode::Light] {
        for (w, h) in [(1000.0, 640.0), (1920.0, 1080.0)] {
            run(w, h, 1.0, mode, |ui| {
                hosts.ui(ui, &stats);
                convs.ui(ui, &stats);
            });
        }
    }
}
