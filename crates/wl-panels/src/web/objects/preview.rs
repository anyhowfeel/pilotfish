//! Preview card of the selected object: text (monospace), small images, or a short notice.

use wl_kit::egui::{
    self, Align, Color32, ColorImage, CornerRadius, Frame, Layout, Margin, RichText, ScrollArea,
    Stroke, TextureHandle, TextureOptions, Ui, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::chip;
use wl_model::ExportObject;

use super::model::{PREVIEW_TEXT_BYTES, PreviewKind, preview_kind};
use crate::web::body::display_text;

/// Decoded preview content, produced off the UI thread by the app.
#[derive(Debug, Clone, PartialEq)]
pub enum Preview {
    Text { text: String, truncated: bool },
    Image { w: usize, h: usize, rgba: Vec<u8> },
    Unavailable(String),
}

/// A preview for one object id.
#[derive(Debug, Clone, PartialEq)]
pub struct PreviewData {
    pub id: u32,
    pub preview: Preview,
}

/// Preview of the selected object plus its GPU texture (images).
#[derive(Default)]
pub struct PreviewCache {
    pub data: Option<PreviewData>,
    texture: Option<(u32, TextureHandle)>,
}

impl PreviewCache {
    pub fn clear(&mut self) {
        self.data = None;
        self.texture = None;
    }

    fn texture(&mut self, ui: &Ui, id: u32, w: usize, h: usize, rgba: &[u8]) -> TextureHandle {
        if let Some((tid, t)) = &self.texture
            && *tid == id
        {
            return t.clone();
        }
        let img = ColorImage::from_rgba_unmultiplied([w, h], rgba);
        let t = ui
            .ctx()
            .load_texture(format!("wl_object_{id}"), img, TextureOptions::LINEAR);
        self.texture = Some((id, t.clone()));
        t
    }
}

fn notice(ui: &mut Ui, text: &str) {
    ui.add_space(spacing::SM);
    ui.label(RichText::new(text).color(Palette::muted()));
}

/// Draws the card inside the current rect (height decided by the caller).
pub fn show(ui: &mut Ui, o: &ExportObject, cache: &mut PreviewCache) {
    Frame::new()
        .fill(Palette::surface())
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(spacing::MD as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(ui.available_height());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = spacing::SM;
                let w = (ui.available_width() - 190.0).max(80.0);
                ui.allocate_ui_with_layout(
                    vec2(w, 22.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&o.name).strong().color(Palette::text()),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&o.name);
                    },
                );
                chip(ui, &o.content_type, false);
                chip(ui, &format::bytes(o.size), true);
            });
            ui.add_space(spacing::SM);
            body(ui, o, cache);
        });
}

fn body(ui: &mut Ui, o: &ExportObject, cache: &mut PreviewCache) {
    let ready = cache.data.as_ref().filter(|d| d.id == o.id).cloned();
    match (preview_kind(o), ready.map(|d| d.preview)) {
        (PreviewKind::None, _) => notice(ui, "No preview for this type. Use Save to export it."),
        (_, None) => notice(ui, "Loading preview\u{2026}"),
        (_, Some(Preview::Unavailable(why))) => notice(ui, &why),
        (_, Some(Preview::Text { text, truncated })) => {
            let shown = display_text(text.trim_start());
            ScrollArea::both()
                .id_salt("wl_object_text")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(&shown).monospace().color(Palette::text()))
                            .selectable(true),
                    );
                    if truncated {
                        ui.add_space(spacing::XS);
                        ui.label(
                            RichText::new(format!(
                                "Preview limited to the first {}",
                                format::bytes(PREVIEW_TEXT_BYTES as u64)
                            ))
                            .small()
                            .color(Palette::muted()),
                        );
                    }
                });
        }
        (_, Some(Preview::Image { w, h, rgba })) => {
            let tex = cache.texture(ui, o.id, w, h, &rgba);
            let avail = ui.available_size();
            let fit = (avail.x / w as f32).min(avail.y / h as f32);
            let scale = if fit.is_finite() {
                fit.clamp(0.01, 1.0)
            } else {
                1.0
            };
            let size = vec2(w as f32, h as f32) * scale;
            ui.add(
                egui::Image::new(&tex)
                    .fit_to_exact_size(size)
                    .tint(Color32::WHITE),
            );
        }
    }
}
