//! The logo, embedded as PNG for the window icon.
use std::sync::Arc;

use eframe::egui;

const WINDOW_PNG: &[u8] = include_bytes!("../../../assets/logo/wirelens-256.png");

fn decode(png: &[u8]) -> Option<image::RgbaImage> {
    image::load_from_memory(png)
        .ok()
        .map(image::DynamicImage::into_rgba8)
}

/// The logo as window icon data (RGBA), or `None` if the embedded PNG cannot be decoded.
pub fn window_icon() -> Option<Arc<egui::IconData>> {
    let img = decode(WINDOW_PNG)?;
    let (width, height) = img.dimensions();
    Some(Arc::new(egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    }))
}
