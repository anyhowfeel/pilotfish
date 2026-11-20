//! Right-click menu of a packet row. Emits actions; never mutates table state.

use eframe::egui::Ui;
use wl_model::{PacketRow, Transport};

use crate::packets::{actions::PacketsAction, filter_expr};

fn filter_item(ui: &mut Ui, label: &str, expr: Option<String>, out: &mut Vec<PacketsAction>) {
    let enabled = expr.is_some();
    let resp = ui.add_enabled(enabled, eframe::egui::Button::new(label));
    if let (true, Some(e)) = (resp.clicked(), expr) {
        out.push(PacketsAction::ApplyFilter(e));
        ui.close();
    }
}

fn copy_item(ui: &mut Ui, label: &str, text: impl FnOnce() -> String) {
    if ui.button(label).clicked() {
        ui.ctx().copy_text(text());
        ui.close();
    }
}

/// Dissector table and port "Decode as..." starts from: the lower (server side) port of a
/// TCP or UDP packet.
pub fn decode_target(r: &PacketRow) -> Option<(&'static str, u16)> {
    let field = match r.transport {
        Transport::Tcp => "tcp.port",
        Transport::Udp => "udp.port",
        _ => return None,
    };
    let port = match (r.src_port, r.dst_port) {
        (Some(a), Some(b)) => a.min(b),
        (Some(p), None) | (None, Some(p)) => p,
        (None, None) => return None,
    };
    Some((field, port))
}

pub fn show(
    ui: &mut Ui,
    r: &PacketRow,
    out: &mut Vec<PacketsAction>,
    time_ref: &mut Option<(u64, f64)>,
) {
    ui.menu_button("Apply as filter", |ui| {
        filter_item(ui, "Source address", filter_expr::source(r), out);
        filter_item(ui, "Destination address", filter_expr::destination(r), out);
        filter_item(ui, "Protocol", Some(filter_expr::protocol(r)), out);
        filter_item(ui, "Source port", filter_expr::port(r, false), out);
        filter_item(ui, "Destination port", filter_expr::port(r, true), out);
    });
    let follow = ui.add_enabled(
        r.stream.is_some(),
        eframe::egui::Button::new("Follow stream"),
    );
    if let (true, Some(s)) = (follow.clicked(), r.stream) {
        out.push(PacketsAction::FollowStream(s));
        ui.close();
    }
    if ui.button("Open in Flow graph").clicked() {
        out.push(PacketsAction::OpenFlow(wl_model::FlowSel::Conversation(
            r.flow_key(),
        )));
        ui.close();
    }
    ui.separator();
    if time_ref.is_some_and(|(no, _)| no == r.no) {
        if ui.button("Clear time reference").clicked() {
            *time_ref = None;
            ui.close();
        }
    } else if ui.button("Set time reference").clicked() {
        *time_ref = Some((r.no, r.epoch));
    }
    let target = decode_target(r);
    if ui
        .add_enabled(target.is_some(), eframe::egui::Button::new("Decode as..."))
        .clicked()
        && let Some((field, port)) = target
    {
        out.push(PacketsAction::DecodeAs {
            field: field.to_owned(),
            port,
        });
        ui.close();
    }
    ui.separator();
    copy_item(ui, "Copy summary", || filter_expr::summary(r));
    copy_item(ui, "Copy source", || r.src.to_string());
    copy_item(ui, "Copy destination", || r.dst.to_string());
    ui.separator();
    if ui.button("Export this packet...").clicked() {
        out.push(PacketsAction::Export {
            selected: vec![r.no],
        });
        ui.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(t: Transport, s: Option<u16>, d: Option<u16>) -> PacketRow {
        PacketRow {
            no: 1,
            epoch: 0.0,
            rel: 0.0,
            src: "a".into(),
            dst: "b".into(),
            src_ip: None,
            dst_ip: None,
            src_port: s,
            dst_port: d,
            transport: t,
            protocol: "TCP".into(),
            len: 0,
            info: "".into(),
            stream: None,
        }
    }

    #[test]
    fn decode_target_uses_the_server_port() {
        let r = row(Transport::Tcp, Some(51234), Some(8080));
        assert_eq!(decode_target(&r), Some(("tcp.port", 8080)));
        let r = row(Transport::Udp, Some(53), Some(40000));
        assert_eq!(decode_target(&r), Some(("udp.port", 53)));
        assert_eq!(decode_target(&row(Transport::Icmp, None, None)), None);
        assert_eq!(decode_target(&row(Transport::Tcp, None, None)), None);
    }
}
