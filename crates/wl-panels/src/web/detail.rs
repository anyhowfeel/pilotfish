//! Detail pane body: HTTP exchange (timing + request/response cards) and TLS session.

use wl_kit::egui::{self, Layout, RichText, ScrollArea, Ui};
use wl_kit::format;
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::lock_icon;
use wl_model::{HttpDetail, HttpExchange, TlsSession};

use super::actions::WebAction;
use super::card::card;
use super::cells::{cert_cn, cipher_short};
use super::curl::curl_command;
use super::detail_header::{http_header, tls_header};
use super::headers::headers_table;
use super::message_card::{Content, Side, message_card};
use super::timing::timing_card;

/// Below this pane width the request and response cards stack instead of sitting side by side.
const SIDE_BY_SIDE_W: f32 = 760.0;

/// Cached pretty body texts of the selected exchange: `[request, response]`.
pub type Shown = [Option<String>; 2];

fn content<'a>(detail: Option<&'a HttpDetail>, shown: &'a Shown, side: Side) -> Content<'a> {
    let Some(d) = detail else {
        return Content::Loading;
    };
    let (m, s) = match side {
        Side::Request => (d.request.as_ref(), shown[0].as_deref()),
        Side::Response => (d.response.as_ref(), shown[1].as_deref()),
    };
    m.map_or(Content::Missing, |msg| Content::Message { msg, shown: s })
}

pub fn http_detail(
    ui: &mut Ui,
    ex: &HttpExchange,
    detail: Option<&HttpDetail>,
    shown: &Shown,
    max_ms: f64,
    out: &mut Vec<WebAction>,
) {
    let curl = || curl_command(ex, detail.and_then(|d| d.request.as_ref()));
    http_header(ui, ex, &curl, out);
    ui.add_space(spacing::SM);
    ScrollArea::vertical()
        .id_salt("web_detail_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = spacing::SM;
            timing_card(ui, ex, max_ms);
            let (req, resp) = (
                content(detail, shown, Side::Request),
                content(detail, shown, Side::Response),
            );
            if ui.available_width() >= SIDE_BY_SIDE_W {
                ui.columns(2, |cols| {
                    message_card(&mut cols[0], ex, Side::Request, &req, "req");
                    message_card(&mut cols[1], ex, Side::Response, &resp, "resp");
                });
            } else {
                message_card(ui, ex, Side::Request, &req, "req");
                message_card(ui, ex, Side::Response, &resp, "resp");
            }
        });
}

fn tls_rows(t: &TlsSession) -> Vec<(String, String)> {
    let r = |k: &str, v: String| (k.to_owned(), v);
    let mut rows = vec![
        r("Server name", t.server_name.to_string()),
        r("TLS version", t.version.to_string()),
    ];
    if let Some(a) = &t.alpn {
        rows.push(r("ALPN", a.to_string()));
    }
    if let Some(c) = &t.cipher {
        rows.push(r("Cipher", format!("{} ({})", cipher_short(c), c)));
    }
    if let Some(s) = &t.cert_subject {
        rows.push(r("Certificate", cert_cn(s).to_owned()));
    }
    for (label, fp) in [("JA3", &t.ja3), ("JA4", &t.ja4), ("JA3S", &t.ja3s)] {
        if let Some(v) = fp {
            rows.push(r(label, v.to_string()));
        }
    }
    if let Some(c) = &t.client {
        rows.push(r("Known client", c.to_string()));
    }
    if let Some(l) = &t.threat {
        rows.push(r("Threat list", l.to_string()));
    }
    rows.push(r("Connection", format!("{} to {}", t.src, t.dst)));
    rows.push(r("Bytes", format::bytes(t.bytes)));
    rows.push(r("First frame", format!("#{}", t.first_frame)));
    rows
}

pub fn tls_detail(ui: &mut Ui, t: &TlsSession, out: &mut Vec<WebAction>) {
    tls_header(ui, t, out);
    ui.add_space(spacing::SM);
    ScrollArea::vertical()
        .id_salt("web_detail_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = spacing::SM;
            card(
                ui,
                "TLS handshake",
                |_| {},
                |ui| headers_table(ui, &tls_rows(t)),
            );
            card(
                ui,
                "",
                |_| {},
                |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = spacing::MD;
                        lock_icon(ui, 20.0, Palette::muted());
                        ui.add(
                            egui::Label::new(
                                RichText::new(
                                    "Content is encrypted. Provide an SSLKEYLOGFILE in \
                                 Settings > Capture to decrypt.",
                                )
                                .color(Palette::muted()),
                            )
                            .wrap(),
                        );
                    });
                },
            );
        });
}

/// Centred muted message filling the pane (nothing selected).
pub fn placeholder(ui: &mut Ui, text: &str) {
    ui.with_layout(
        Layout::centered_and_justified(egui::Direction::TopDown),
        |ui| {
            ui.label(RichText::new(text).color(Palette::muted()));
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_matches_add_rows_to_the_handshake_table() {
        let mut t = super::super::demo::session(1, "example.com");
        let labels =
            |t: &TlsSession| -> Vec<String> { tls_rows(t).into_iter().map(|(k, _)| k).collect() };
        assert!(!labels(&t).contains(&"Threat list".to_owned()));
        t.client = Some("Chrome".into());
        t.threat = Some("sslbl".into());
        let rows = tls_rows(&t);
        assert!(rows.contains(&("Known client".to_owned(), "Chrome".to_owned())));
        assert!(rows.contains(&("Threat list".to_owned(), "sslbl".to_owned())));
    }
}
