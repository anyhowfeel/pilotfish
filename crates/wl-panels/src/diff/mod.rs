//! Capture Diff page: what changed between the open capture and a second one.

#[cfg(test)]
mod layout_tests;
mod section;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use wl_kit::egui::{RichText, ScrollArea, Ui};
use wl_kit::format;
use wl_kit::theme::{Palette, mono, spacing};
use wl_kit::widgets::{empty_state, segmented, stat_card};
use wl_model::{Rcode, Wireshark};
use wl_stats::{CaptureDiff, Micros, Traffic};

use crate::needs::needs_wireshark;
use section::{MIN_WIDTH, Show, section};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffAction {
    PickFile,
}

#[derive(Debug, Clone, Default)]
pub enum DiffState {
    #[default]
    Idle,
    Loading,
    Ready(Arc<CaptureDiff>),
    Error(String),
}

pub struct DiffData<'a> {
    pub state: &'a DiffState,
    pub base: &'a str,
    pub other: Option<&'a str>,
    pub wireshark: Wireshark,
}

#[derive(Default)]
pub struct DiffPanel {
    show: Show,
}

fn traffic(t: &Traffic) -> String {
    format!(
        "{} \u{b7} {} pkts",
        format::bytes(t.bytes),
        format::count(t.packets)
    )
}

fn micros(m: &Micros) -> String {
    format!("{:.1} ms", m.0 as f64 / 1000.0)
}

fn count(n: &u64) -> String {
    format::count(*n)
}

fn rcode(n: &u64) -> String {
    match n.checked_sub(1) {
        Some(code) => Rcode::from_code(code as u8).label(),
        None => "no response".to_owned(),
    }
}

impl DiffPanel {
    pub fn ui(&mut self, ui: &mut Ui, data: &DiffData) -> Vec<DiffAction> {
        let mut out = Vec::new();
        // Latencies and web names come from tshark passes, so a diff without them would mislead.
        if data.wireshark.is_missing() {
            needs_wireshark(ui, "Capture diff");
            return out;
        }
        self.toolbar(ui, data, &mut out);
        ui.add_space(spacing::SM);
        match data.state {
            DiffState::Idle => empty_state(
                ui,
                "diff",
                "Compare two captures",
                "Pick a second capture to see the new, missing and changed hosts, services, latencies and web names.",
            ),
            DiffState::Loading => empty_state(ui, "...", "Comparing", "Reading both captures."),
            DiffState::Error(e) => empty_state(ui, "!", "Could not compare", e),
            DiffState::Ready(d) if d.is_empty() => empty_state(
                ui,
                "=",
                "No difference",
                "Hosts, services, latencies and web names are the same in both captures.",
            ),
            DiffState::Ready(d) => self.report(ui, d),
        }
        out
    }

    fn toolbar(&mut self, ui: &mut Ui, data: &DiffData, out: &mut Vec<DiffAction>) {
        ui.horizontal_wrapped(|ui| {
            ui.label(mono(if data.base.is_empty() {
                "No capture"
            } else {
                data.base
            }));
            ui.label(RichText::new("vs").color(Palette::muted()));
            ui.label(mono(data.other.unwrap_or("-")));
            if ui.button("Choose capture...").clicked() {
                out.push(DiffAction::PickFile);
            }
            segmented(
                ui,
                &mut self.show,
                &[
                    (Show::All, "All"),
                    (Show::Added, "New"),
                    (Show::Removed, "Gone"),
                    (Show::Changed, "Diff"),
                ],
            );
        });
    }

    fn report(&self, ui: &mut Ui, d: &CaptureDiff) {
        let width = (ui.available_width() - ui.spacing().scroll.allocated_width()).max(MIN_WIDTH);
        ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.columns(2, |c| {
                    for (col, title, t) in [
                        (0, "First capture", &d.before),
                        (1, "Second capture", &d.after),
                    ] {
                        let pkts = format!("{} pkts", format::count(t.packets));
                        stat_card(&mut c[col], title, &format::bytes(t.bytes), Some(&pkts));
                    }
                });
                ScrollArea::horizontal().show(ui, |ui| {
                    ui.set_min_width(width);
                    let s = self.show;
                    section(ui, width, "Hosts", &d.hosts, traffic, s);
                    section(ui, width, "Services", &d.services, traffic, s);
                    section(ui, width, "Latency (mean)", &d.latency, micros, s);
                    section(ui, width, "HTTP hosts (requests)", &d.http_hosts, count, s);
                    section(ui, width, "HTTP status codes", &d.statuses, count, s);
                    section(
                        ui,
                        width,
                        "TLS server names (sessions)",
                        &d.tls_names,
                        count,
                        s,
                    );
                    section(ui, width, "Unanswered requests", &d.unanswered, count, s);
                    section(ui, width, "Status per URL", &d.url_statuses, count, s);
                    section(ui, width, "DNS response codes", &d.dns_rcodes, rcode, s);
                    section(ui, width, "DNS answers", &d.dns_answers, count, s);
                });
            });
    }
}
