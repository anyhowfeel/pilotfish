//! Body preview: pretty-printed JSON when it parses, monospace scroll box, truncation notice.

use wl_kit::egui::{self, CornerRadius, Frame, Margin, RichText, ScrollArea, Stroke, Ui};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_model::HttpMessage;

use super::card::muted;
use super::html_text;

/// Lines shown before "Show more": enough to read a typical response without scrolling.
const PREVIEW_LINES: usize = 24;

/// Pretty-prints `text` when it is a complete JSON object or array.
pub fn pretty_json(text: &str) -> Option<String> {
    let t = text.trim();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(t).ok()?;
    serde_json::to_string_pretty(&v).ok()
}

/// Text to show for a body preview: pretty JSON, readable text of an HTML page, or the raw text.
pub fn display_text(preview: &str) -> String {
    if html_text::is_html(preview) {
        return html_text::to_text(preview);
    }
    pretty_json(preview).unwrap_or_else(|| preview.to_owned())
}

/// True when the backend capped the preview below the real body length.
pub fn is_truncated(msg: &HttpMessage) -> bool {
    msg.body_preview
        .as_ref()
        .is_some_and(|p| msg.body_len > p.len() as u64)
}

const IMAGE_MAX_H: f32 = 360.0;

fn decode_image(bytes: &[u8]) -> Option<egui::ColorImage> {
    let img = image::load_from_memory(bytes).ok()?.to_rgba8();
    let size = [img.width() as usize, img.height() as usize];
    Some(egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw()))
}

/// Decoded image shown at its natural size, shrunk to the available width and `IMAGE_MAX_H`.
fn image_view(ui: &mut Ui, bytes: &[u8], salt: &str) {
    let id = ui.scope_id().with(("web_body_image", salt, bytes.len()));
    let tex = ui
        .data(|d| d.get_temp::<egui::TextureHandle>(id))
        .or_else(|| {
            let tex = ui.ctx().load_texture(
                format!("web_body_{salt}"),
                decode_image(bytes)?,
                Default::default(),
            );
            ui.data_mut(|d| d.insert_temp(id, tex.clone()));
            Some(tex)
        });
    let Some(tex) = tex else {
        muted(ui, "Image could not be decoded");
        return;
    };
    let size = tex.size_vec2();
    let scale = (ui.available_width() / size.x)
        .min(IMAGE_MAX_H / size.y)
        .min(1.0);
    ui.add(egui::Image::new(&tex).fit_to_exact_size(size * scale));
    muted(
        ui,
        &format!(
            "{} x {} px, {}",
            size.x,
            size.y,
            format::bytes(bytes.len() as u64)
        ),
    );
}

/// "Preview | Source" (HTML) or "Pretty | Raw" switch; true when the raw text is selected.
fn raw_toggle(ui: &mut Ui, id: egui::Id, html: bool) -> bool {
    let (nice, plain) = if html {
        ("Preview", "Source")
    } else {
        ("Pretty", "Raw")
    };
    let mut raw = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    ui.horizontal(|ui| {
        ui.selectable_value(&mut raw, false, RichText::new(nice).small());
        ui.selectable_value(&mut raw, true, RichText::new(plain).small());
    });
    ui.data_mut(|d| d.insert_temp(id, raw));
    raw
}

fn no_text_note(msg: &HttpMessage) -> String {
    if msg.body_len == 0 {
        "No body".to_owned()
    } else {
        format!(
            "{} body, no text preview (binary or compressed)",
            format::bytes(msg.body_len)
        )
    }
}

/// Body section of a message card. `shown` is the cached `display_text` of the preview.
pub fn body_view(ui: &mut Ui, msg: &HttpMessage, shown: Option<&str>, salt: &str) {
    if let Some(bytes) = &msg.body_image {
        image_view(ui, bytes, salt);
        return;
    }
    let (Some(pretty), Some(raw)) = (shown.filter(|t| !t.is_empty()), msg.body_preview.as_deref())
    else {
        muted(ui, &no_text_note(msg));
        return;
    };
    let id = ui.scope_id().with(("web_body_open", salt));
    let text = if pretty != raw && !raw_toggle(ui, id.with("raw"), html_text::is_html(raw)) {
        pretty
    } else {
        raw
    };
    text_box(ui, text, id, salt);
    if is_truncated(msg) {
        let n = format!(
            "Preview truncated: {} of {}",
            format::bytes(raw.len() as u64),
            format::bytes(msg.body_len)
        );
        ui.label(RichText::new(n).small().color(Palette::warn()));
    }
}

fn text_box(ui: &mut Ui, text: &str, id: egui::Id, salt: &str) {
    let open = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    let lines: Vec<&str> = text.lines().collect();
    let long = lines.len() > PREVIEW_LINES;
    let visible = if long && !open {
        lines[..PREVIEW_LINES].join("\n")
    } else {
        text.to_owned()
    };
    Frame::new()
        .fill(Palette::bg())
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS - 2))
        .inner_margin(Margin::same(spacing::MD as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Horizontal scroll only: a vertical one nested in the page scroll traps the wheel.
            ScrollArea::horizontal()
                .id_salt(("web_body", salt))
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(visible).monospace().color(Palette::text()))
                            .wrap_mode(egui::TextWrapMode::Extend),
                    );
                });
        });
    if long {
        let label = if open {
            "Show less".to_owned()
        } else {
            format!("Show {} more lines", lines.len() - PREVIEW_LINES)
        };
        let link = egui::Label::new(RichText::new(label).small().color(Palette::accent()))
            .sense(egui::Sense::click());
        if ui
            .add(link)
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            ui.data_mut(|d| d.insert_temp(id, !open));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_is_pretty_printed_and_text_untouched() {
        let p = pretty_json(r#"{"a":1,"b":[true,null]}"#).unwrap();
        assert!(p.contains("\n  \"a\": 1"));
        assert_eq!(pretty_json("<html></html>"), None);
        assert_eq!(pretty_json(r#"{"cut":"#), None);
        assert_eq!(display_text("plain"), "plain");
    }

    #[test]
    fn pretty_json_keeps_the_original_key_order() {
        let p = pretty_json(r#"{"name":"x","version":1,"items":[1],"a":{"z":1,"b":2}}"#).unwrap();
        let at = |k: &str| p.find(k).unwrap();
        assert!(at("\"name\"") < at("\"version\"") && at("\"version\"") < at("\"items\""));
        assert!(at("\"items\"") < at("\"a\"") && at("\"z\"") < at("\"b\""));
    }

    #[test]
    fn truncation_detected() {
        let m = HttpMessage {
            body_preview: Some("abc".into()),
            body_len: 10,
            ..Default::default()
        };
        assert!(is_truncated(&m));
        let m = HttpMessage { body_len: 3, ..m };
        assert!(!is_truncated(&m));
    }
}
