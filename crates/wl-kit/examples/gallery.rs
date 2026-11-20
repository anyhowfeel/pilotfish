//! Widget gallery. `cargo run -p wl-kit --example gallery -- [--scale 1.25] [--light] [--shot out.png]`
use eframe::egui::{self, Color32, Ui, vec2};
use wl_kit::{charts, format, scale, table, theme, widgets};
use wl_model::RatePoint;

struct Gallery {
    shot: Option<String>,
    frames: u32,
    toggle: bool,
    sel: usize,
    rate: Vec<RatePoint>,
    window: Option<charts::TimeSelection>,
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let val = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let sc: f32 = val("--scale").and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let w: f32 = val("--width")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1100.0);
    if args.iter().any(|a| a == "--light") {
        theme::set_mode(theme::Mode::Light);
    }
    let shot = val("--shot");
    let rate = (0..90)
        .map(|i| {
            let t = f64::from(i);
            RatePoint {
                t,
                packets: 10,
                bytes: (40_000.0 + 30_000.0 * (t / 7.0).sin() + (t * 900.0)) as u64,
            }
        })
        .collect();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([w, 1000.0]),
        ..Default::default()
    };
    eframe::run_native(
        "wl-kit gallery",
        opts,
        Box::new(move |cc| {
            scale::set_ui_scale(&cc.egui_ctx, sc);
            Ok(Box::new(Gallery {
                shot,
                frames: 0,
                toggle: true,
                sel: 1,
                rate,
                window: charts::TimeSelection::from_drag(22.0, 51.0),
            }))
        }),
    )
}

impl eframe::App for Gallery {
    fn ui(&mut self, ui: &mut Ui, _f: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        theme::apply(&ctx);
        scale::handle_shortcuts(&ctx);
        self.frames += 1;
        if let Some(path) = self.shot.clone() {
            ctx.request_repaint();
            if self.frames == 8 {
                let c2 = ctx.clone();
                let cb = egui::ScreenshotCallback::new(move |img| {
                    let [w, h] = img.size;
                    let raw: Vec<u8> = img.pixels.iter().flat_map(|p| p.to_array()).collect();
                    let _ =
                        image::save_buffer(path, &raw, w as u32, h as u32, image::ColorType::Rgba8);
                    c2.send_viewport_cmd(egui::ViewportCommand::Close);
                    c2.request_repaint();
                });
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(cb));
            }
        }
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| self.content(ui));
        });
    }
}

impl Gallery {
    fn content(&mut self, ui: &mut Ui) {
        use theme::{Palette, spacing};
        widgets::section_header(ui, "Stat cards");
        ui.columns(4, |c| {
            widgets::stat_card(
                &mut c[0],
                "Packets",
                &format::count(1_234_567),
                Some("+1,204 / s"),
            );
            widgets::stat_card(&mut c[1], "Bytes", &format::bytes(1_536_000_000), None);
            widgets::stat_card(
                &mut c[2],
                "Throughput",
                &format::rate(48_213.0),
                Some("peak 1.2 MiB/s"),
            );
            widgets::stat_card(
                &mut c[3],
                "Duration",
                &format::duration(3723.0),
                Some("since 12:04"),
            );
        });
        widgets::section_header(ui, "Badges / toggles / labels");
        ui.horizontal_wrapped(|ui| {
            for p in [
                "TCP", "UDP", "DNS", "HTTP", "TLSv1.3", "QUIC", "ICMPv6", "ARP", "DHCPv6",
                "MyProto",
            ] {
                widgets::protocol_pill(ui, p, 68.0);
            }
            widgets::pill_toggle(ui, &mut self.toggle, "Live");
            let mut off = false;
            widgets::pill_toggle(ui, &mut off, "Resolve names");
            widgets::elided_label(
                ui,
                "a very long hostname.example.internal.corp.local",
                140.0,
            );
            ui.label(egui::RichText::new("ok").color(Palette::ok()));
            ui.label(egui::RichText::new("warn").color(Palette::warn()));
            ui.label(egui::RichText::new("danger").color(Palette::danger()));
        });
        widgets::section_header(ui, "Throughput");
        charts::throughput_chart_select(ui, &self.rate, 170.0, &mut self.window);
        widgets::section_header(ui, "Proportion + ranked");
        let items: Vec<(String, f64, Color32)> = [
            ("TCP", 620.0),
            ("UDP", 180.0),
            ("DNS", 90.0),
            ("TLS", 70.0),
            ("ICMP", 3.0),
            ("ARP", 0.5),
        ]
        .iter()
        .map(|(n, v)| (n.to_string(), *v, theme::protocol_color(n)))
        .collect();
        charts::proportion_bar(ui, &items, 26.0);
        ui.add_space(spacing::MD);
        ui.columns(2, |c| {
            let rows: Vec<(String, f64, String)> = [
                ("192.168.1.10", 9_000_000.0),
                ("2606:4700:4700::1111", 4_000_000.0),
                (
                    "a-really-long-hostname.cdn.example-provider.net",
                    2_500_000.0,
                ),
                ("10.0.0.2", 12_000.0),
            ]
            .iter()
            .map(|(n, v)| (n.to_string(), *v, format::bytes(*v as u64)))
            .collect();
            charts::ranked_bars(&mut c[0], &rows, Palette::accent());
            charts::ranked_bars(&mut c[1], &rows[..2], Palette::ok());
        });
        widgets::section_header(ui, "Table");
        ui.allocate_ui(vec2(ui.available_width(), 150.0), |ui| {
            table::TableCols::new()
                .fixed(60.0)
                .num(100.0)
                .fixed(90.0)
                .flex(120.0)
                .num(90.0)
                .build(ui)
                .header(table::HEADER_H, |mut h| {
                    for (t, r) in [
                        ("No.", true),
                        ("Time", true),
                        ("Proto", false),
                        ("Info", false),
                        ("Length", true),
                    ] {
                        h.col(|ui| table::header_cell(ui, t, r));
                    }
                })
                .body(|body| {
                    body.rows(theme::ROW_H, 20, |mut row| {
                        let i = row.index();
                        table::selectable_row(&mut row, self.sel == i);
                        row.col(|ui| table::num_cell(ui, &format!("{}", i + 1)));
                        row.col(|ui| table::num_cell(ui, &format::time_rel(i as f64 * 0.137)));
                        row.col(|ui| {
                            widgets::badge(ui, "TCP", theme::protocol_color("TCP"));
                        });
                        row.col(|ui| {
                            table::text_cell(
                                ui,
                                "443 -> 51234 [ACK] Seq=1 Ack=1 Win=501 Len=0 TSval=1 TSecr=2",
                            );
                        });
                        row.col(|ui| table::num_cell(ui, &format!("{}", 54 + i * 7)));
                        if row.response().clicked() {
                            self.sel = i;
                        }
                    });
                });
        });
        widgets::empty_state(
            ui,
            "~",
            "Nothing captured",
            "Pick an interface and press Start.",
        );
    }
}
