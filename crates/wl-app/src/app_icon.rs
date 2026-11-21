//! The wirelens logo, embedded as PNG: window icon and sidebar badge.
use std::sync::Arc;

use eframe::egui;
use wl_kit::theme::Mode;

const WINDOW_PNG: &[u8] = include_bytes!("../../../assets/logo/wirelens-256.png");
const BADGE_LIGHT_PNG: &[u8] = include_bytes!("../../../assets/logo/wirelens-128.png");
const BADGE_DARK_PNG: &[u8] = include_bytes!("../../../assets/logo/wirelens-dark-256.png");

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

/// The logo for the sidebar: the dark variant on the dark theme, the blue one on the light theme.
/// Loaded once per context and variant.
pub fn badge_texture(ctx: &egui::Context, mode: Mode) -> Option<egui::TextureHandle> {
    let (png, name) = match mode {
        Mode::Dark => (BADGE_DARK_PNG, "wirelens_badge_dark"),
        Mode::Light => (BADGE_LIGHT_PNG, "wirelens_badge_light"),
    };
    let id = egui::Id::NULL.with(name);
    if let Some(tex) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return Some(tex);
    }
    let img = decode(png)?;
    let size = [img.width() as usize, img.height() as usize];
    let color = egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw());
    let tex = ctx.load_texture(name, color, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
    Some(tex)
}
