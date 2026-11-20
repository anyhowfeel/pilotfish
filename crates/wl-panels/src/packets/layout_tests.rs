//! Headless layout checks: run the whole view across dark/light, scales and sizes,
//! and verify follow-live re-engagement behavior.

use eframe::egui::{self, Rect, vec2};
use wl_kit::theme::Mode;
use wl_model::{DetailNode, FrameDetail, PacketRow, Transport};

use crate::packets::{PacketTable, PacketsView};

pub(super) fn rows(n: u64) -> Vec<PacketRow> {
    let protos = ["TCP", "TLSv1.3", "ICMPv6", "DHCPv6", "QUIC", "GPRS-NS"];
    (1..=n)
        .map(|no| PacketRow {
            no,
            epoch: 0.0,
            rel: no as f64 * 0.001,
            src: "192.168.100.200".into(),
            dst: "2001:db8:85a3::8a2e:370:7334".into(),
            src_ip: None,
            dst_ip: None,
            src_port: Some(443),
            dst_port: Some(55555),
            transport: Transport::Tcp,
            protocol: protos[(no as usize) % protos.len()].into(),
            len: 1514,
            info: "Application Data, a very long info string that must be elided with a tooltip "
                .repeat(4)
                .into(),
            stream: Some(1),
        })
        .collect()
}

fn detail() -> FrameDetail {
    let leaf = |l: &str, r| DetailNode {
        label: l.into(),
        range: Some(r),
        children: vec![],
    };
    FrameDetail {
        frame_no: 2,
        layers: vec![
            DetailNode {
                label: "Frame 2: 100 bytes".into(),
                range: Some((0, 100)),
                children: vec![leaf("Arrival", (0, 4))],
            },
            DetailNode {
                label: "Transmission Control Protocol".into(),
                range: Some((34, 54)),
                children: vec![leaf("Source Port: 443", (34, 36))],
            },
        ],
        bytes: (0..100u8).collect(),
    }
}

fn run(
    view: &mut PacketsView,
    ppp: f32,
    w: f32,
    h: f32,
    mode: Mode,
    d: &FrameDetail,
) -> (Rect, Rect) {
    let ctx = egui::Context::default();
    wl_kit::theme::apply_mode(&ctx, mode);
    let screen = Rect::from_min_size(egui::Pos2::ZERO, vec2(w / ppp, h / ppp));
    let mut used = screen;
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(screen),
            ..Default::default()
        };
        ctx.set_pixels_per_point(ppp);
        ctx.run_ui(input, |ui| {
            view.ui(ui, Some(d));
            used = ui.min_rect();
        })
        .drop_without_applying_deltas();
    }
    (screen, used)
}

#[test]
fn fits_screen_at_all_modes_scales_and_sizes() {
    let d = detail();
    for mode in [Mode::Dark, Mode::Light] {
        for ppp in [1.0, 1.25, 1.5] {
            for (w, h) in [
                (1000.0, 640.0),
                (1366.0, 768.0),
                (1440.0, 900.0),
                (1920.0, 1080.0),
                (2560.0, 1440.0),
            ] {
                let mut view = PacketsView::default();
                view.push_rows(rows(300));
                view.table.state.select_pos(1);
                let (screen, used) = run(&mut view, ppp, w, h, mode, &d);
                assert!(
                    screen.expand(1.0).contains_rect(used),
                    "overflow at {mode:?} ppp={ppp} {w}x{h}: {used:?} not in {screen:?}"
                );
            }
        }
    }
}

#[test]
fn empty_view_and_missing_detail_do_not_panic() {
    for mode in [Mode::Dark, Mode::Light] {
        let mut view = PacketsView::default();
        let ctx = egui::Context::default();
        wl_kit::theme::apply_mode(&ctx, mode);
        ctx.run_ui(egui::RawInput::default(), |ui| {
            view.ui(ui, None);
        })
        .drop_without_applying_deltas();
    }
}

fn many_chips() -> Vec<crate::packets::quick_filter::QuickChip> {
    (0..30)
        .map(|i| crate::packets::quick_filter::QuickChip {
            expr: format!("proto{i}"),
            label: format!("PROTO{i}"),
            count: 1000 * (30 - i),
        })
        .collect()
}

pub(super) fn frame_used(ppp: f32, mode: Mode, f: impl FnMut(&mut egui::Ui)) -> Rect {
    let ctx = egui::Context::default();
    wl_kit::theme::apply_mode(&ctx, mode);
    ctx.set_pixels_per_point(ppp);
    let mut f = f;
    let mut used = Rect::NOTHING;
    for _ in 0..3 {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                vec2(1000.0 / ppp, 640.0 / ppp),
            )),
            ..Default::default()
        };
        ctx.run_ui(input, |ui| {
            f(ui);
            used = ui.min_rect();
        })
        .drop_without_applying_deltas();
    }
    used
}

#[test]
fn each_panel_fits_its_width() {
    let d = detail();
    let mut bar = crate::packets::FilterBar::default();
    let chips = many_chips();
    let mut table = PacketTable::default();
    table.push_rows(rows(50));
    let mut tree = crate::packets::DetailTree::default();
    let mut hex = crate::packets::HexView::default();
    for mode in [Mode::Dark, Mode::Light] {
        for ppp in [1.0, 1.25, 1.5] {
            let max_w = 1000.0 / ppp + 1.0;
            assert!(frame_used(ppp, mode, |ui| drop(bar.ui(ui, &chips, false))).width() <= max_w);
            assert!(frame_used(ppp, mode, |ui| drop(table.ui(ui))).width() <= max_w);
            assert!(frame_used(ppp, mode, |ui| drop(tree.ui(ui, Some(&d), ""))).width() <= max_w);
            assert!(
                frame_used(ppp, mode, |ui| hex.ui(ui, Some(&d), Some((3, 9)))).width() <= max_w
            );
        }
    }
}

#[test]
fn follow_live_pauses_on_scroll_up_and_reengages_at_bottom() {
    let mut t = PacketTable::default();
    t.set_follow(true);
    assert!(t.is_following());
    // Scrolling up pauses follow, keeping follow armed.
    t.update_follow_from_scroll(true, false, true, true);
    assert!(!t.is_following());
    // Scrolling away from the bottom marks that we left bottom.
    t.update_follow_from_scroll(false, false, false, true);
    assert!(!t.is_following());
    // Scrolling back to the bottom re-engages follow automatically.
    t.update_follow_from_scroll(false, true, true, true);
    assert!(t.is_following());
    // Explicitly disabling follow (e.g. file capture) never auto-reengages.
    t.set_follow(false);
    t.update_follow_from_scroll(false, false, false, true);
    t.update_follow_from_scroll(false, true, true, true);
    assert!(!t.is_following());
}

#[test]
fn http_tree_renders_pills_and_aligned_headers_within_width() {
    let leaf = |l: &str| DetailNode {
        label: l.into(),
        range: Some((0, 1)),
        children: vec![],
    };
    let http = |start: &str| DetailNode {
        label: "Hypertext Transfer Protocol".into(),
        range: Some((0, 50)),
        children: vec![
            DetailNode {
                label: start.into(),
                range: Some((0, 20)),
                children: vec![leaf("Request Method: GET")],
            },
            leaf("Host: www.wikipedia.com\\r\\n"),
            leaf("User-Agent: curl/8.23.0 with a very long value that has to be elided\\r\\n"),
            leaf("Accept: */*\\r\\n"),
        ],
    };
    for start in ["GET / HTTP/1.1\\r\\n", "HTTP/1.1 404 Not Found\\r\\n"] {
        let d = FrameDetail {
            frame_no: 9,
            layers: vec![http(start)],
            bytes: vec![0; 64],
        };
        let mut tree = crate::packets::DetailTree::default();
        for mode in [Mode::Dark, Mode::Light] {
            for ppp in [1.0, 1.5] {
                let used = frame_used(ppp, mode, |ui| drop(tree.ui(ui, Some(&d), "")));
                assert!(used.width() <= 1000.0 / ppp + 1.0, "{start} {mode:?} {ppp}");
            }
        }
    }
}

#[cfg(test)]
#[path = "layout_tests_more.rs"]
mod more;
