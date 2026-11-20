//! Inspector card for the selected host or host pair (docked right of the canvas).

use wl_kit::charts::{proportion_bar, ranked_bars};
use wl_kit::egui::{
    self, Align, Button, CornerRadius, Frame, Layout, Margin, Rect, RichText, ScrollArea, Sense,
    Stroke, Ui, UiBuilder, pos2, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, protocol_color, spacing};
use wl_kit::widgets::{badge, close_button, protocol_pill, section_header};

use super::filters;
use super::model::Graph;
use super::state::Resolved;
use crate::overview::OverviewAction;

pub const CARD_W: f32 = 300.0;
const ROW_H: f32 = 22.0;
const LABEL_W: f32 = 124.0;
pub(super) const DIR_W: f32 = 160.0;

/// One `label ........ value` row, value monospace right-aligned and elided.
pub(super) fn kv(ui: &mut Ui, label: &str, value: &str) {
    kv_w(ui, label, value, LABEL_W);
}

/// `kv` with an explicit label column width (long labels such as host names).
pub(super) fn kv_w(ui: &mut Ui, label: &str, value: &str, label_w: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::hover());
    let split = rect.left() + label_w.min(rect.width() * 0.62);
    let left = Rect::from_min_max(rect.min, pos2(split - spacing::XS, rect.bottom()));
    let right = Rect::from_min_max(pos2(split, rect.top()), rect.max);
    let font = egui::TextStyle::Body.resolve(ui.style());
    let p = ui.painter();
    wl_kit::widgets::text::paint_in(p, left, label, font, Palette::muted(), Align::Min);
    let mono_font = egui::TextStyle::Monospace.resolve(ui.style());
    wl_kit::widgets::text::paint_in(p, right, value, mono_font, Palette::text(), Align::Max);
}

fn filter_button(ui: &mut Ui, expr: &str, out: &mut Vec<OverviewAction>) {
    ui.add_space(spacing::SM);
    let b = Button::new(RichText::new("Filter packets").color(Palette::text()))
        .fill(Palette::selection_bg())
        .stroke(Stroke::new(1.0, Palette::accent()))
        .min_size(vec2(ui.available_width(), 30.0));
    if ui.add(b).on_hover_text(expr).clicked() {
        out.push(OverviewAction::ApplyFilter(expr.to_owned()));
    }
}

/// Opens the hosts of a link on the Flows page (sequence diagram between them).
fn flow_button(ui: &mut Ui, hosts: &[std::sync::Arc<str>], out: &mut Vec<OverviewAction>) {
    ui.add_space(spacing::XS);
    let b = Button::new(RichText::new("Open in Flow graph").color(Palette::text()))
        .stroke(Stroke::new(1.0, Palette::border()))
        .min_size(vec2(ui.available_width(), 30.0));
    if ui.add(b).clicked() {
        out.push(OverviewAction::OpenFlow(wl_model::FlowSel::Hosts(
            hosts.to_vec(),
        )));
    }
}

fn title(ui: &mut Ui, main: &str, sub: Option<&str>, badge_text: &str, c: egui::Color32) -> bool {
    let mut close = false;
    ui.horizontal(|ui| {
        ui.add(egui::Label::new(RichText::new(main).strong().size(15.0)).truncate());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            close = close_button(ui).clicked();
            badge(ui, badge_text, c);
        });
    });
    if let Some(s) = sub {
        ui.add(egui::Label::new(RichText::new(s).color(Palette::muted())).truncate());
    }
    close
}

fn node_body(ui: &mut Ui, g: &Graph, i: usize, out: &mut Vec<OverviewAction>) {
    let n = &g.nodes[i];
    kv(ui, "Total", &format::bytes(n.bytes));
    kv(ui, "Sent", &format::bytes(n.bytes_out));
    kv(ui, "Received", &format::bytes(n.bytes_in));
    kv(ui, "Packets sent", &format::count(n.packets_out));
    kv(ui, "Packets received", &format::count(n.packets_in));
    kv(ui, "Peers", &n.degree.to_string());
    section_header(ui, "Top peers");
    let rows: Vec<(String, f64, String)> = g
        .peers(i)
        .into_iter()
        .take(6)
        .map(|(p, l)| {
            (
                g.nodes[p].label().to_owned(),
                g.links[l].bytes as f64,
                format::bytes(g.links[l].bytes),
            )
        })
        .collect();
    ranked_bars(ui, &rows, Palette::accent());
    filter_button(ui, &filters::host(&n.addr), out);
}

fn link_body(ui: &mut Ui, g: &Graph, i: usize, out: &mut Vec<OverviewAction>) {
    let l = &g.links[i];
    let (a, b) = (&g.nodes[l.a], &g.nodes[l.b]);
    let pct = |x: u64| format!("{:.0}%", 100.0 * x as f64 / l.bytes.max(1) as f64);
    kv(ui, "Bytes", &format::bytes(l.bytes));
    kv(ui, "Packets", &format::count(l.packets));
    kv(
        ui,
        "Duration",
        &format::duration((l.last_rel - l.first_rel).max(0.0)),
    );
    ui.horizontal(|ui| {
        ui.label(RichText::new("Protocol").color(Palette::muted()));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            protocol_pill(ui, &l.protocol, 0.0);
        });
    });
    section_header(ui, "Direction");
    let back = l.bytes - l.a_to_b;
    let items = [
        (
            a.label().to_owned(),
            l.a_to_b as f64,
            protocol_color(&l.protocol),
        ),
        (b.label().to_owned(), back as f64, Palette::muted()),
    ];
    proportion_bar(ui, &items, 8.0);
    kv_w(
        ui,
        &format!("{} sent", a.label()),
        &format!("{}  {}", format::bytes(l.a_to_b), pct(l.a_to_b)),
        DIR_W,
    );
    kv_w(
        ui,
        &format!("{} sent", b.label()),
        &format!("{}  {}", format::bytes(back), pct(back)),
        DIR_W,
    );
    filter_button(ui, &filters::pair(&a.addr, &b.addr), out);
    flow_button(ui, &[a.addr.clone(), b.addr.clone()], out);
}

/// Draws the card inside `rect`; returns true when the user closed it.
pub fn show(
    ui: &mut Ui,
    rect: Rect,
    g: &Graph,
    sel: Resolved,
    out: &mut Vec<OverviewAction>,
) -> bool {
    let mut close = false;
    let mut child = ui.new_child(UiBuilder::new().max_rect(rect));
    let frame = Frame::new()
        .fill(Palette::surface())
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(spacing::MD as i8));
    frame.show(&mut child, |ui| {
        ui.set_min_size(rect.size() - vec2(2.0 * spacing::MD + 2.0, 2.0 * spacing::MD + 2.0));
        ui.set_max_width(rect.width() - 2.0 * spacing::MD - 2.0);
        ui.spacing_mut().item_spacing.y = spacing::XS;
        match sel {
            Resolved::Node(i) => {
                let n = &g.nodes[i];
                let named = n.name.is_some().then_some(&*n.addr);
                let txt = if n.private { "Private" } else { "Public" };
                let c = Palette::scope(n.private);
                close = title(ui, n.label(), named, txt, c);
                ui.add_space(spacing::XS);
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| node_body(ui, g, i, out));
            }
            Resolved::Link(i) => {
                let l = &g.links[i];
                close = title(
                    ui,
                    g.nodes[l.a].label(),
                    Some(g.nodes[l.b].label()),
                    "Pair",
                    Palette::accent(),
                );
                ui.add_space(spacing::XS);
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| link_body(ui, g, i, out));
            }
            Resolved::None => {}
        }
    });
    close
}
