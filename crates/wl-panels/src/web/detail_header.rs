//! Pinned header of the detail pane: identity line plus action buttons (one row when it fits).

use wl_kit::egui::{self, CursorIcon, Layout, RichText, TextStyle, Ui, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{
    METHOD_PILL_W, PillStyle, STATUS_PILL_W, centered_row, lock_icon, method_pill, pill,
    status_pill, text_width, toast,
};
use wl_model::{HttpExchange, TlsSession};

use super::actions::WebAction;

const ROW_H: f32 = 28.0;
/// Identity part keeps at least this width before the buttons drop to their own row.
const MIN_IDENTITY_W: f32 = 240.0;

/// A header button: label and tooltip.
type Btn<'a> = (&'a str, String);

fn copy(ui: &Ui, text: String, what: &str) {
    ui.ctx().copy_text(text);
    toast::push(ui.ctx(), format!("{what} copied"));
}

pub(super) fn rule(ui: &mut Ui) {
    let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), egui::Sense::hover());
    ui.painter().rect_filled(r, 0.0, Palette::border());
}

/// Width of the action strip: the primary button plus the "More" menu button.
fn strip_width(ui: &Ui, btns: &[Btn]) -> f32 {
    let font = TextStyle::Button.resolve(ui.style());
    let pad = 2.0 * ui.spacing().button_padding.x;
    let w = |label: &str| text_width(ui, label, font.clone()) + pad;
    let primary = btns.first().map_or(0.0, |(l, _)| w(l));
    let more = if btns.len() > 1 {
        w(MORE) + spacing::SM
    } else {
        0.0
    };
    primary + more
}

const MORE: &str = "More";

/// First action as the accent button, the others in a "More" menu; returns the clicked index.
fn strip(ui: &mut Ui, btns: &[Btn]) -> Option<usize> {
    let mut hit = None;
    ui.spacing_mut().item_spacing.x = spacing::SM;
    if let Some((label, tip)) = btns.first() {
        let primary = egui::Button::new(RichText::new(*label).strong().color(Palette::on_accent()))
            .fill(Palette::accent());
        let r = ui
            .add(primary)
            .on_hover_cursor(CursorIcon::PointingHand)
            .on_hover_text(tip);
        if r.clicked() {
            hit = Some(0);
        }
    }
    if btns.len() > 1 {
        ui.menu_button(MORE, |ui| {
            for (i, (label, tip)) in btns.iter().enumerate().skip(1) {
                if ui.button(*label).on_hover_text(tip).clicked() {
                    hit = Some(i);
                    ui.close();
                }
            }
        });
    }
    hit
}

/// Identity (`left`) and buttons share one row when wide enough, else stack.
fn header(ui: &mut Ui, left: impl FnOnce(&mut Ui), btns: &[Btn]) -> Option<usize> {
    let (w, bw) = (ui.available_width(), strip_width(ui, btns) + 2.0);
    let mut hit = None;
    if w - bw - spacing::MD >= MIN_IDENTITY_W {
        ui.horizontal(|ui| {
            let lw = w - bw - spacing::MD;
            ui.allocate_ui_with_layout(
                vec2(lw, ROW_H),
                Layout::left_to_right(egui::Align::Center),
                |ui| {
                    // Reserve the whole identity width so the buttons stay on the right edge.
                    ui.set_min_size(vec2(lw, ROW_H));
                    left(ui);
                },
            );
            ui.allocate_ui_with_layout(
                vec2(bw, ROW_H),
                Layout::left_to_right(egui::Align::Center),
                |ui| {
                    hit = strip(ui, btns);
                },
            );
        });
    } else {
        centered_row(ui, ROW_H, left);
        ui.add_space(spacing::XS);
        ui.horizontal_wrapped(|ui| hit = strip(ui, btns));
    }
    ui.add_space(spacing::XS);
    rule(ui);
    hit
}

pub fn http_header(
    ui: &mut Ui,
    ex: &HttpExchange,
    curl: &dyn Fn() -> String,
    out: &mut Vec<WebAction>,
) {
    let mut btns: Vec<Btn> = Vec::new();
    let frame = ex.req_frame.or(ex.resp_frame);
    if frame.is_some() {
        btns.push((
            "Show in Packets",
            "Select the request frame in Packets".into(),
        ));
    }
    let filter = ex.stream.map(|s| format!("tcp.stream == {s}"));
    if let Some(f) = &filter {
        btns.push(("Apply filter", f.clone()));
    }
    btns.push(("Copy URL", ex.full_url()));
    btns.push((
        "Copy as curl",
        "Build a curl command for this request".into(),
    ));
    let left = |ui: &mut Ui| {
        ui.spacing_mut().item_spacing.x = spacing::SM;
        method_pill(ui, &ex.method, METHOD_PILL_W);
        status_pill(ui, ex.status, STATUS_PILL_W);
        let url = format!("{}{}", ex.host, ex.uri);
        ui.add(egui::Label::new(RichText::new(&url).strong().color(Palette::text())).truncate())
            .on_hover_text(ex.full_url());
    };
    let Some(i) = header(ui, left, &btns) else {
        return;
    };
    match btns[i].0 {
        "Show in Packets" => out.extend(frame.map(WebAction::ShowInPackets)),
        "Apply filter" => out.extend(filter.map(WebAction::ApplyFilter)),
        "Copy URL" => copy(ui, ex.full_url(), "URL"),
        _ => copy(ui, curl(), "curl command"),
    }
}

pub fn tls_header(ui: &mut Ui, t: &TlsSession, out: &mut Vec<WebAction>) {
    let mut btns: Vec<Btn> = vec![(
        "Show in Packets",
        "Select the first frame of this session".into(),
    )];
    let filter = t.stream.map(|s| format!("tcp.stream == {s}"));
    if let Some(f) = &filter {
        btns.push(("Apply filter", f.clone()));
    }
    btns.push(("Copy server name", t.server_name.to_string()));
    let left = |ui: &mut Ui| {
        ui.spacing_mut().item_spacing.x = spacing::SM;
        lock_icon(ui, 16.0, Palette::ok());
        pill(ui, "encrypted", Palette::ok(), PillStyle::badge());
        ui.add(
            egui::Label::new(
                RichText::new(&*t.server_name)
                    .strong()
                    .color(Palette::text()),
            )
            .truncate(),
        )
        .on_hover_text(&*t.server_name);
    };
    let Some(i) = header(ui, left, &btns) else {
        return;
    };
    match btns[i].0 {
        "Show in Packets" => out.push(WebAction::ShowInPackets(t.first_frame)),
        "Apply filter" => out.extend(filter.map(WebAction::ApplyFilter)),
        _ => copy(ui, t.server_name.to_string(), "Server name"),
    }
}
