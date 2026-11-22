//! One-line TLS key log control of the Web page: pick, clear, and embed into a new capture.

use wl_kit::egui::{self, RichText, Ui};
use wl_kit::theme::{Palette, spacing};

use super::actions::{KeysInfo, WebAction};

const NO_EDITCAP: &str = "editcap (Wireshark) was not found on PATH.";

pub fn keys_bar(ui: &mut Ui, keys: &KeysInfo, out: &mut Vec<WebAction>) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = spacing::SM;
        ui.label(RichText::new("TLS keys").small().color(Palette::muted()));
        match &keys.file {
            Some(name) => {
                ui.label(RichText::new(name).monospace().small());
                if ui.small_button("Change").clicked() {
                    out.push(WebAction::PickKeylog);
                }
                if ui.small_button("Clear").clicked() {
                    out.push(WebAction::ClearKeylog);
                }
                let embed = ui
                    .add_enabled(
                        keys.can_embed,
                        egui::Button::new("Embed into .pcapng").small(),
                    )
                    .on_hover_text("Save a copy of the capture that carries the keys.")
                    .on_disabled_hover_text(NO_EDITCAP);
                if embed.clicked() {
                    out.push(WebAction::EmbedKeys);
                }
            }
            None => {
                if ui.small_button("Load key log\u{2026}").clicked() {
                    out.push(WebAction::PickKeylog);
                }
                ui.label(
                    RichText::new("or drop an SSLKEYLOGFILE on the window to decrypt HTTPS")
                        .small()
                        .color(Palette::muted()),
                );
            }
        }
    });
}
