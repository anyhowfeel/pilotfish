//! Expert Info table and Protocol Hierarchy tree subviews for `InsightsPanel`.

use eframe::egui::{
    self, Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, Stroke, Ui, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, mono, protocol_color, row_h, spacing};
use wl_kit::widgets::{badge, empty_state, section_header};
use wl_model::{ExpertReport, ExpertSeverity, ProtocolHierarchy};

use super::actions::InsightsAction;

pub fn severity_color(sev: ExpertSeverity) -> Color32 {
    match sev {
        ExpertSeverity::Error => Palette::danger(),
        ExpertSeverity::Warn => Palette::warn(),
        ExpertSeverity::Note => Palette::accent(),
        ExpertSeverity::Chat => Palette::muted(),
    }
}

pub fn expert_view(
    ui: &mut Ui,
    severity_filter: &mut Option<ExpertSeverity>,
    expert: Option<&ExpertReport>,
    actions: &mut Vec<InsightsAction>,
) {
    let Some(rep) = expert else {
        empty_state(
            ui,
            "!",
            "Expert Info not loaded",
            "Click Refresh to run tshark Expert Info analysis.",
        );
        return;
    };
    ui.horizontal_wrapped(|ui| {
        ui.selectable_value(severity_filter, None, "All");
        for sev in ExpertSeverity::ALL {
            let label = format!("{} ({})", sev.label(), rep.count_by_severity(sev));
            ui.selectable_value(severity_filter, Some(sev), label);
        }
    });
    ui.add_space(spacing::SM);
    if rep.entries.is_empty() {
        empty_state(
            ui,
            "ok",
            "No Expert Info entries",
            "No protocol warnings, notes, or errors in this capture.",
        );
        return;
    }
    for e in rep
        .entries
        .iter()
        .filter(|e| severity_filter.is_none_or(|s| s == e.severity))
    {
        Frame::new()
            .fill(Palette::surface())
            .stroke(Stroke::new(1.0, Palette::border()))
            .corner_radius(CornerRadius::same(RADIUS))
            .inner_margin(Margin::symmetric(spacing::MD as i8, spacing::XS as i8))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    badge(ui, e.severity.label(), severity_color(e.severity));
                    ui.label(
                        mono(format!("{:>6}", format::count(e.frequency))).color(Palette::text()),
                    );
                    badge(ui, &e.protocol, protocol_color(&e.protocol));
                    ui.label(RichText::new(&e.group).small().color(Palette::muted()));
                    ui.add(
                        egui::Label::new(RichText::new(&e.summary).color(Palette::text()))
                            .truncate(),
                    )
                    .on_hover_text(&e.summary);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let proto_flt = e.protocol.to_ascii_lowercase();
                        if ui
                            .small_button("Filter")
                            .on_hover_text(&proto_flt)
                            .clicked()
                        {
                            actions.push(InsightsAction::ApplyFilter(proto_flt));
                        }
                    });
                });
            });
        ui.add_space(spacing::XS);
    }
}

pub fn phs_view(ui: &mut Ui, phs: Option<&ProtocolHierarchy>, actions: &mut Vec<InsightsAction>) {
    let Some(tree) = phs else {
        empty_state(
            ui,
            "%",
            "Protocol Hierarchy not loaded",
            "Click Refresh to compute tshark io,phs statistics.",
        );
        return;
    };
    if tree.nodes.is_empty() {
        empty_state(
            ui,
            "%",
            "No protocol hierarchy data",
            "Capture contains zero frames.",
        );
        return;
    }
    section_header(
        ui,
        &format!(
            "Protocol Hierarchy — {} frames • {}",
            format::count(tree.total_frames),
            format::bytes(tree.total_bytes)
        ),
    );
    for node in &tree.nodes {
        let color = protocol_color(&node.protocol);
        ui.horizontal(|ui| {
            ui.set_min_height(row_h());
            ui.add_space(f32::from(node.depth) * spacing::MD);
            if ui.button(mono(&node.protocol)).clicked() {
                actions.push(InsightsAction::ApplyFilter(node.protocol.clone()));
            }
            let bar_w = 120.0;
            let (rect, _) = ui.allocate_exact_size(vec2(bar_w, 8.0), egui::Sense::hover());
            ui.painter().rect_filled(rect, 4.0, Palette::surface_hi());
            let fill_w = (bar_w * (node.byte_pct / 100.0)).clamp(2.0, bar_w);
            let fill = egui::Rect::from_min_size(rect.min, vec2(fill_w, rect.height()));
            ui.painter().rect_filled(fill, 4.0, color);
            ui.label(mono(format!("{:5.1}%", node.byte_pct)).color(Palette::text()));
            ui.label(
                mono(format!(
                    "{} pkts • {}",
                    format::count(node.frames),
                    format::bytes(node.bytes)
                ))
                .color(Palette::muted()),
            );
        });
    }
}
