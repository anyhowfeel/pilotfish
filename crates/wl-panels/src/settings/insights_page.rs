//! "Insights" settings page: detection thresholds, secret display and the muted findings.
use wl_kit::egui::{RichText, Ui};
use wl_kit::theme::Palette;
use wl_kit::widgets::{number_row, settings_card, settings_row, toggle_row};

use crate::insights::InsightRules;

pub fn page(ui: &mut Ui, rules: &mut InsightRules) {
    thresholds(ui, rules);
    settings_card(ui, "Secrets", |ui| {
        toggle_row(
            ui,
            true,
            "Show secrets",
            "Cleartext credentials are masked in Insights unless this is on. Reports always mask them.",
            &mut rules.reveal_secrets,
        );
    });
    muted(ui, rules);
}

fn thresholds(ui: &mut Ui, rules: &mut InsightRules) {
    let t = &mut rules.thresholds;
    let rows: [(&str, &str, &mut u32, _, &str); 8] = [
        (
            "Port scan",
            "Different ports on one host before it counts as a scan.",
            &mut t.scan_min_ports,
            2..=1_000,
            " ports",
        ),
        (
            "Sweep: hosts",
            "Different hosts hit on one port before it counts as a sweep.",
            &mut t.sweep_min_hosts,
            2..=1_000,
            " hosts",
        ),
        (
            "Sweep: tries per host",
            "A host tried more often than this is not part of a sweep.",
            &mut t.sweep_max_tries_per_host,
            1..=100,
            " tries",
        ),
        (
            "Steady rhythm: events",
            "Connections or packets needed before a rhythm is judged.",
            &mut t.beacon_min_events,
            4..=1_000,
            " events",
        ),
        (
            "Steady rhythm: period",
            "Shortest interval that can be reported; faster is treated as normal traffic.",
            &mut t.beacon_min_period_secs,
            1..=3_600,
            " s",
        ),
        (
            "Steady rhythm: variation",
            "Largest relative spread of the intervals still called regular.",
            &mut t.beacon_max_jitter_pct,
            1..=50,
            " %",
        ),
        (
            "Long DNS name",
            "Total length that makes a DNS name unusual.",
            &mut t.dns_long_name,
            8..=253,
            " chars",
        ),
        (
            "Long DNS label",
            "Length of a single label that makes a DNS name unusual.",
            &mut t.dns_long_label,
            8..=63,
            " chars",
        ),
    ];
    settings_card(ui, "Detection thresholds", |ui| {
        for (i, (label, desc, value, range, suffix)) in rows.into_iter().enumerate() {
            number_row(ui, i == 0, label, desc, value, range, suffix);
        }
    });
}

fn muted(ui: &mut Ui, rules: &mut InsightRules) {
    settings_card(ui, "Muted findings", |ui| {
        if rules.muted.is_empty() {
            ui.label(
                RichText::new("Right-click a finding on the Insights page to mute a host or a kind of finding.")
                    .small()
                    .color(Palette::muted()),
            );
            return;
        }
        let mut remove = None;
        for (i, pattern) in rules.muted.iter().enumerate() {
            settings_row(ui, i == 0, pattern, "", |ui| {
                if ui.button("Unmute").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            rules.muted.remove(i);
        }
    });
}
