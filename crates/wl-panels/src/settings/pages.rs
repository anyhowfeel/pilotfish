//! Appearance, Capture and Display category bodies (pure form code over `Settings`).
use wl_kit::egui::Ui;
use wl_kit::widgets::{choice_row, number_row, settings_card, slider_row, text_row, toggle_row};

use super::model::{Density, PillLook, Settings, ThemeChoice};

pub fn appearance(ui: &mut Ui, s: &mut Settings) {
    settings_card(ui, "Theme and size", |ui| {
        choice_row(
            ui,
            true,
            "Theme",
            "Dark, light, or follow the operating system.",
            &mut s.theme,
            &[
                (ThemeChoice::Dark, "Dark"),
                (ThemeChoice::Light, "Light"),
                (ThemeChoice::System, "System"),
            ],
        );
        let mut pct = s.ui_scale * 100.0;
        if slider_row(
            ui,
            false,
            "UI scale",
            "Ctrl + / Ctrl - / Ctrl 0 also work anywhere.",
            &mut pct,
            75.0..=200.0,
            "%",
        ) {
            s.ui_scale = (pct / 12.5).round() * 0.125;
        }
        choice_row(
            ui,
            false,
            "Density",
            "Row height of tables and lists.",
            &mut s.density,
            &[
                (Density::Compact, "Compact"),
                (Density::Comfortable, "Comfortable"),
            ],
        );
    });
    settings_card(ui, "Details", |ui| {
        choice_row(
            ui,
            true,
            "Protocol pills",
            "How protocol names are drawn in tables.",
            &mut s.pill_look,
            &[
                (PillLook::Tinted, "Tinted"),
                (PillLook::Solid, "Solid"),
                (PillLook::Dot, "Dot"),
            ],
        );
        toggle_row(
            ui,
            false,
            "Sidebar labels",
            "Off collapses the sidebar to icons only.",
            &mut s.sidebar_labels,
        );
    });
}

pub fn capture(ui: &mut Ui, s: &mut Settings) {
    settings_card(ui, "Defaults", |ui| {
        text_row(
            ui,
            true,
            "Default interface",
            "Preselected on the Capture page. Empty = the default route.",
            &mut s.default_interface,
            "e.g. eth0",
        );
        text_row(
            ui,
            false,
            "Capture filter",
            "BPF filter applied to new captures.",
            &mut s.capture.capture_filter,
            "e.g. port 53",
        );
    });
    crate::capture_form::capture_options(ui, &mut s.capture);
}

pub fn display(ui: &mut Ui, s: &mut Settings) {
    settings_card(ui, "Packet list", |ui| {
        toggle_row(
            ui,
            false,
            "Auto-scroll live captures",
            "Follow new packets by default.",
            &mut s.auto_scroll,
        );
        number_row(
            ui,
            false,
            "Rows kept in memory",
            "Oldest rows are dropped first.",
            &mut s.max_rows,
            10_000..=20_000_000,
            "",
        );
    });
}
