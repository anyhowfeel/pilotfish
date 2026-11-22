//! Hover tooltips for nodes and links.

use wl_kit::egui::{Response, RichText, Ui};
use wl_kit::format;
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::protocol_pill;

use super::card::{DIR_W, kv, kv_w};
use super::model::Graph;
use super::state::Resolved;
use crate::overview::NameResolver;
use wl_model::summarize;

const WIDTH: f32 = 250.0;

pub fn show(resp: &Response, g: &Graph, hover: Resolved, r: &dyn NameResolver) {
    match hover {
        Resolved::None => {}
        Resolved::Node(i) => {
            resp.clone().on_hover_ui_at_pointer(|ui| node(ui, g, i, r));
        }
        Resolved::Link(i) => {
            resp.clone().on_hover_ui_at_pointer(|ui| link(ui, g, i));
        }
    }
}

fn head(ui: &mut Ui, text: &str) {
    ui.add(egui_label(text));
}

fn egui_label(text: &str) -> wl_kit::egui::Label {
    wl_kit::egui::Label::new(RichText::new(text).strong().color(Palette::text())).truncate()
}

fn node(ui: &mut Ui, g: &Graph, i: usize, r: &dyn NameResolver) {
    let n = &g.nodes[i];
    ui.set_width(WIDTH);
    head(ui, n.label());
    if n.name.is_some() {
        ui.label(RichText::new(&*n.addr).color(Palette::muted()));
    }
    if let Some(geo) = r.geo(&n.addr) {
        ui.label(RichText::new(geo.summary()).color(Palette::muted()));
        if let Some(c) = &geo.country {
            ui.label(RichText::new(&**c).color(Palette::muted()));
        }
    }
    let procs = r.processes(&n.addr);
    if !procs.is_empty() {
        kv(ui, "Process", &summarize(&procs));
    }
    ui.add_space(spacing::XS);
    kv(ui, "Total", &format::bytes(n.bytes));
    kv(ui, "Packets", &format::count(n.packets_in + n.packets_out));
    kv(ui, "Peers", &n.degree.to_string());
}

/// `A <-> B`, packets, bytes, direction split, protocol and duration.
fn link(ui: &mut Ui, g: &Graph, i: usize) {
    let l = &g.links[i];
    ui.set_width(WIDTH);
    head(
        ui,
        &format!("{} <-> {}", g.nodes[l.a].label(), g.nodes[l.b].label()),
    );
    ui.add_space(spacing::XS);
    let pct = |x: u64| format!("{:.0}%", 100.0 * x as f64 / l.bytes.max(1) as f64);
    kv(ui, "Packets", &format::count(l.packets));
    kv(ui, "Bytes", &format::bytes(l.bytes));
    let back = l.bytes - l.a_to_b;
    let (a, b) = (g.nodes[l.a].label(), g.nodes[l.b].label());
    kv_w(
        ui,
        &format!("{a} sent"),
        &format!("{}  {}", format::bytes(l.a_to_b), pct(l.a_to_b)),
        DIR_W,
    );
    kv_w(
        ui,
        &format!("{b} sent"),
        &format!("{}  {}", format::bytes(back), pct(back)),
        DIR_W,
    );
    kv(
        ui,
        "Duration",
        &format::duration((l.last_rel - l.first_rel).max(0.0)),
    );
    ui.horizontal(|ui| {
        ui.label(RichText::new("Protocol").color(Palette::muted()));
        protocol_pill(ui, &l.protocol, 0.0);
    });
}
