use wl_kit::egui::{Id, Rect, pos2, vec2};
use wl_kit::theme::Mode;
use wl_model::DecodeAs;

use super::*;
use crate::test_util::run;

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn search_prefers_prefix_matches() {
    let all = names(&["dns", "http", "http2", "mdns", "tls"]);
    assert_eq!(matching(&all, "dns"), ["dns", "mdns"]);
    assert_eq!(matching(&all, "HTTP"), ["http", "http2"]);
    assert_eq!(matching(&all, "").len(), 5);
    assert!(matching(&all, "zzz").is_empty());
}

#[test]
fn port_parsing() {
    assert_eq!(parse_port(" 8080 "), Some(8080));
    assert_eq!(parse_port("65536"), None);
    assert_eq!(parse_port("-1"), None);
    assert_eq!(parse_port(""), None);
}

#[test]
fn requests_protocols_once_per_table() {
    let mut d = DecodeAsDialog::default();
    d.open_for("udp.port", 5300);
    let ctx = wl_kit::egui::Context::default();
    let mut asks = 0;
    for _ in 0..3 {
        ctx.run_ui(Default::default(), |ui| {
            asks += d
                .ui(ui.ctx(), &[])
                .iter()
                .filter(|a| matches!(a, DecodeAsAction::LoadProtocols(f) if f == "udp.port"))
                .count();
        })
        .drop_without_applying_deltas();
    }
    assert_eq!(asks, 1);
}

#[test]
fn dialog_stays_on_screen_in_every_state() {
    let many: Vec<String> = (0..300).map(|i| format!("proto{i}")).collect();
    let rules: Vec<DecodeAs> = (0..6)
        .map(|i| DecodeAs {
            field: "tcp.port".into(),
            value: 8000 + i,
            protocol: "http".into(),
        })
        .collect();
    for mode in [Mode::Dark, Mode::Light] {
        for (w, h) in [(1000.0_f32, 640.0_f32), (1440.0, 900.0)] {
            for scale in [1.0_f32, 1.5] {
                for rules in [&rules[..], &[][..]] {
                    let mut d = DecodeAsDialog::default();
                    d.open_for("tcp.port", 8080);
                    d.set_protocols("tcp.port", many.clone());
                    d.selected = Some("proto3".into());
                    let mut frame = 0;
                    run(w, h, scale, mode, |ui| {
                        d.ui(ui.ctx(), rules);
                        frame += 1;
                        if frame < 3 {
                            return;
                        }
                        let r = ui
                            .ctx()
                            .memory(|m| m.area_rect(Id::NULL.with("wl_decode_as_modal")))
                            .expect("window");
                        let screen = Rect::from_min_size(pos2(0.0, 0.0), vec2(w, h) / scale);
                        assert!(screen.contains_rect(r), "{mode:?} {w}@{scale}: {r:?}");
                    });
                }
            }
        }
    }
}
