//! One-line TLS key log control of the Web page: pick, clear, and embed into a new capture.

use wl_kit::egui::{self, RichText, Ui};
use wl_kit::theme::{Palette, spacing};

use super::actions::{KeysInfo, WebAction};

const NO_EDITCAP: &str = "editcap (Wireshark) was not found on PATH.";

pub fn keys_bar(ui: &mut Ui, keys: &KeysInfo, out: &mut Vec<WebAction>) {
    ui.add_space(spacing::SM);
    ui.label(RichText::new("TLS keys").small().color(Palette::muted()));
    match &keys.file {
        Some(name) => {
            ui.label(RichText::new(name).monospace().small());
            if one_line(ui, "Change").clicked() {
                out.push(WebAction::PickKeylog);
            }
            if one_line(ui, "Clear").clicked() {
                out.push(WebAction::ClearKeylog);
            }
            let embed = ui
                .add_enabled(keys.can_embed, small_button("Embed into .pcapng"))
                .on_hover_text("Save a copy of the capture that carries the keys.")
                .on_disabled_hover_text(NO_EDITCAP);
            if embed.clicked() {
                out.push(WebAction::EmbedKeys);
            }
        }
        None => {
            if one_line(ui, "Load key log\u{2026}").clicked() {
                out.push(WebAction::PickKeylog);
            }
            ui.label(
                RichText::new("or drop an SSLKEYLOGFILE on the window")
                    .small()
                    .color(Palette::muted()),
            )
            .on_hover_text("Decrypts HTTPS sessions whose keys were logged.");
        }
    }
}

fn small_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(text)
        .small()
        .wrap_mode(egui::TextWrapMode::Extend)
}

fn one_line(ui: &mut Ui, text: &str) -> egui::Response {
    ui.add(small_button(text))
}
