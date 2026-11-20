//! Request / response card: start line with pills, aligned headers, body preview.

use wl_kit::egui::{self, CursorIcon, RichText, Ui};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{METHOD_PILL_W, STATUS_PILL_W, centered_row, method_pill, toast};
use wl_kit::widgets::{status_color, status_pill};
use wl_model::{HttpExchange, HttpMessage};

use super::body::body_view;
use super::card::{card, muted};
use super::headers::headers_table;

/// Messages with at most this many headers show them expanded.
const HEADERS_OPEN_MAX: usize = 6;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Request,
    Response,
}

/// What a card shows while headers are still loading or missing.
pub enum Content<'a> {
    Loading,
    Missing,
    Message {
        msg: &'a HttpMessage,
        shown: Option<&'a str>,
    },
}

fn start_line(ui: &mut Ui, ex: &HttpExchange, side: Side) {
    centered_row(ui, 26.0, |ui| {
        ui.spacing_mut().item_spacing.x = spacing::SM;
        match side {
            Side::Request => {
                method_pill(ui, &ex.method, METHOD_PILL_W);
                let w = ui.available_width() - 70.0;
                ui.scope(|ui| {
                    ui.set_max_width(w.max(40.0));
                    ui.add(
                        egui::Label::new(RichText::new(&*ex.uri).strong().color(Palette::text()))
                            .truncate(),
                    )
                    .on_hover_text(&*ex.uri);
                });
                ui.label(RichText::new(&*ex.version).color(Palette::muted()));
            }
            Side::Response => {
                ui.label(RichText::new(&*ex.version).color(Palette::muted()));
                status_pill(ui, ex.status, STATUS_PILL_W);
                if let Some(r) = &ex.reason {
                    let c = status_color(ex.status_class());
                    ui.label(RichText::new(&**r).strong().color(c));
                }
            }
        }
    });
}

fn headers_text(msg: &HttpMessage) -> String {
    let mut s = msg.start_line.clone();
    for (k, v) in &msg.headers {
        s.push_str(&format!("\n{k}: {v}"));
    }
    s
}

pub fn message_card(ui: &mut Ui, ex: &HttpExchange, side: Side, content: &Content, salt: &str) {
    let title = if side == Side::Request {
        "Request"
    } else {
        "Response"
    };
    let mut copy = None;
    card(
        ui,
        title,
        |ui| {
            if let Content::Message { msg, .. } = content
                && ui
                    .small_button("Copy headers")
                    .on_hover_cursor(CursorIcon::PointingHand)
                    .clicked()
            {
                copy = Some(headers_text(msg));
            }
        },
        |ui| {
            start_line(ui, ex, side);
            match content {
                Content::Loading => muted(ui, "Loading headers\u{2026}"),
                Content::Missing => muted(
                    ui,
                    if side == Side::Request {
                        "The request was not captured."
                    } else {
                        "No response captured for this request."
                    },
                ),
                Content::Message { msg, shown } => {
                    let n = format!("Headers ({})", msg.headers.len());
                    // A long header list pushes the body out of view: fold it up front.
                    egui::CollapsingHeader::new(RichText::new(n).small().color(Palette::muted()))
                        .id_salt(("web_headers", salt, title))
                        .default_open(msg.headers.len() <= HEADERS_OPEN_MAX)
                        .show(ui, |ui| headers_table(ui, &msg.headers));
                    ui.label(RichText::new("Body").small().color(Palette::muted()));
                    body_view(ui, msg, *shown, salt);
                }
            }
        },
    );
    if let Some(t) = copy {
        ui.ctx().copy_text(t);
        toast::push(ui.ctx(), "Headers copied");
    }
}
