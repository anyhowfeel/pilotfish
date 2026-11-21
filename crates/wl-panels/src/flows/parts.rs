//! Small pure pieces of the Flows page: summary lines, legend, loading / error states.

use wl_kit::egui::{Ui, vec2};
use wl_kit::format;
use wl_kit::theme::spacing;
use wl_kit::widgets::{chip_dot, empty_state};
use wl_model::{FlowEvents, FlowSel, TcpSamples};

use super::marks::Mark;
use super::paint;

/// TCP graphs need one TCP connection.
pub fn tcp_capable(sel: &FlowSel) -> bool {
    match sel {
        FlowSel::Stream(_) => true,
        FlowSel::Conversation(k) => k.transport == wl_model::Transport::Tcp,
        FlowSel::Hosts(_) => false,
    }
}

pub fn summary(e: &FlowEvents, hosts: usize) -> String {
    let span = match (e.events.first(), e.events.last()) {
        (Some(a), Some(b)) => format::duration(b.rel - a.rel),
        _ => String::new(),
    };
    format!(
        "{} packets  \u{b7}  {} hosts  \u{b7}  {span}",
        format::count(e.events.len() as u64),
        hosts
    )
}

pub fn tcp_summary(t: &TcpSamples) -> String {
    let span = match (t.samples.first(), t.samples.last()) {
        (Some(a), Some(b)) => format::duration(b.rel - a.rel),
        _ => String::new(),
    };
    let mut s = format!(
        "{} TCP segments  \u{b7}  {span}",
        format::count(t.samples.len() as u64)
    );
    if t.other_streams > 0 {
        s.push_str(&format!(
            "  \u{b7}  first of {} connections on these ports",
            t.other_streams + 1
        ));
    }
    s
}

pub fn loading_or_error(ui: &mut Ui, error: Option<&str>, what: &str) {
    match error {
        Some(e) => empty_state(ui, "!", "Could not read this flow", e),
        None => empty_state(ui, "\u{2026}", what, "tshark is reading the capture."),
    }
}

/// Colour key of the highlighted packets that exist in this flow.
pub fn legend(ui: &mut Ui, counts: &[(Mark, usize)]) {
    if counts.is_empty() {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::SM);
        for (m, n) in counts {
            chip_dot(
                ui,
                &format!("{} {n}", m.label()),
                false,
                paint::mark_color(*m),
            );
        }
    });
    ui.add_space(spacing::SM);
}
