//! Cells of the Web master table (HTTP and TLS rows).

use egui_extras::TableRow;
use wl_kit::egui::{self, Align2, CornerRadius, FontId, Rect, RichText, Ui, vec2};
use wl_kit::format;
use wl_kit::table::{CELL_PAD, cell_pad, num_cell, text_cell};
use wl_kit::theme::{Palette, spacing, tint};
use wl_kit::widgets::{
    METHOD_PILL_W, PillStyle, STATUS_PILL_W, lock_icon, method_pill, pill, status_pill,
};
use wl_model::{HttpExchange, TlsSession};

use super::cells::{cert_cn, cipher_short, latency, short_type};
use super::columns::Cols;
use super::timing::fraction;

const BAR_W: f32 = 40.0;
const THREAT_PILL_W: f32 = 110.0;

pub fn time_text(secs: f64) -> String {
    format!("{secs:.3}")
}

fn muted_cell(ui: &mut Ui, text: &str) {
    ui.add_space(CELL_PAD);
    ui.label(RichText::new(text).color(Palette::muted()));
}

pub fn http_cells(row: &mut TableRow<'_, '_>, e: &HttpExchange, max_ms: f64, c: Cols) {
    row.col(|ui| {
        cell_pad(ui);
        method_pill(ui, &e.method, METHOD_PILL_W);
    });
    row.col(|ui| {
        text_cell(ui, &e.host).on_hover_text(&*e.host);
    });
    row.col(|ui| {
        text_cell(ui, &e.uri).on_hover_text(&*e.uri);
    });
    row.col(|ui| {
        cell_pad(ui);
        status_pill(ui, e.status, STATUS_PILL_W);
    });
    if c.kind {
        row.col(|ui| muted_cell(ui, short_type(e.content_type.as_deref())));
    }
    if c.size {
        row.col(|ui| num_cell(ui, &format::bytes(e.req_bytes + e.resp_bytes)));
    }
    if c.latency {
        row.col(|ui| latency_cell(ui, e.time_ms, max_ms));
    }
}

fn tls_summary(t: &TlsSession) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.extend(t.client.as_ref().map(|c| format!("client {c}")));
    parts.extend(t.alpn.as_ref().map(|a| a.to_string()));
    parts.extend(t.cipher.as_deref().map(cipher_short));
    parts.extend(t.cert_subject.as_deref().map(|c| cert_cn(c).to_owned()));
    parts.join(" \u{b7} ")
}

pub fn tls_cells(row: &mut TableRow<'_, '_>, t: &TlsSession, c: Cols) {
    row.col(|ui| {
        cell_pad(ui);
        let v = t.version.replace("TLS ", "TLS");
        let style = PillStyle::column(METHOD_PILL_W).with_dot(false);
        pill(ui, &v, Palette::info(), style);
    });
    row.col(|ui| {
        ui.add_space(CELL_PAD);
        ui.spacing_mut().item_spacing.x = spacing::SM;
        let lock = if t.threat.is_some() {
            Palette::danger()
        } else {
            Palette::ok()
        };
        lock_icon(ui, 14.0, lock);
        let l = egui::Label::new(&*t.server_name)
            .truncate()
            .selectable(false);
        ui.add(l).on_hover_text(&*t.server_name);
        if let Some(list) = &t.threat {
            let style = PillStyle::column(THREAT_PILL_W).with_dot(false);
            pill(ui, &format!("listed: {list}"), Palette::danger(), style);
        }
    });
    row.col(|ui| {
        let s = tls_summary(t);
        ui.add_space(CELL_PAD);
        let l = egui::Label::new(RichText::new(&s).color(Palette::muted()))
            .truncate()
            .selectable(false);
        ui.add(l).on_hover_text(&s);
    });
    row.col(|ui| {
        cell_pad(ui);
        let style = PillStyle::column(STATUS_PILL_W).with_dot(false);
        pill(ui, "encrypted", Palette::ok(), style);
    });
    if c.kind {
        row.col(|ui| muted_cell(ui, "tls"));
    }
    if c.size {
        row.col(|ui| num_cell(ui, &format::bytes(t.bytes)));
    }
    if c.latency {
        row.col(|_| {});
    }
}

/// Thin latency bar scaled to the slowest request, with the value right-aligned.
fn latency_cell(ui: &mut Ui, ms: Option<f64>, max_ms: f64) {
    let rect = ui.max_rect();
    let Some(ms) = ms else {
        num_cell(ui, "-");
        return;
    };
    let bar = Rect::from_min_size(
        egui::pos2(rect.left() + CELL_PAD, rect.center().y - 3.0),
        vec2(BAR_W, 6.0),
    );
    let p = ui.painter();
    let r = CornerRadius::same(3);
    p.rect_filled(bar, r, Palette::surface_hi());
    let mut fill = bar;
    fill.set_width(BAR_W * fraction(ms, max_ms));
    p.rect_filled(fill, r, tint(Palette::accent(), 230));
    let right = egui::pos2(rect.right() - CELL_PAD, rect.center().y);
    p.text(
        right,
        Align2::RIGHT_CENTER,
        latency(ms),
        FontId::monospace(12.5),
        Palette::text(),
    );
}
