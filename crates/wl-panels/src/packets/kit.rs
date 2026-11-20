//! Single seam to `wl-kit`: every other file in this module imports styling from here.

pub use wl_kit::theme::{Palette, protocol_color, row_h, spacing};

use eframe::egui::Color32;

pub fn ok() -> Color32 {
    Palette::ok()
}
pub fn warn() -> Color32 {
    Palette::warn()
}
pub fn danger() -> Color32 {
    Palette::danger()
}
