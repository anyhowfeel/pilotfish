//! Window icon: the wirelens logo, embedded as a PNG.
use std::sync::Arc;

use eframe::egui;

const ICON_PNG: &[u8] = include_bytes!("../../../assets/logo/wirelens-256.png");

/// The logo as window icon data (RGBA), or `None` if the embedded PNG cannot be decoded.
pub fn window_icon() -> Option<Arc<egui::IconData>> {
    let img = image::load_from_memory(ICON_PNG).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    Some(Arc::new(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    }))
}
