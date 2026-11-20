//! Body preview: pretty-printed JSON when it parses, monospace scroll box, truncation notice.

use wl_kit::egui::{self, CornerRadius, Frame, Margin, RichText, ScrollArea, Stroke, Ui};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_model::HttpMessage;

use super::card::muted;

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

/// Text to show for a body preview (pretty JSON or the raw text).
pub fn display_text(preview: &str) -> String {
    pretty_json(preview).unwrap_or_else(|| preview.to_owned())
}

/// True when the backend capped the preview below the real body length.
pub fn is_truncated(msg: &HttpMessage) -> bool {
    msg.body_preview
        .as_ref()
        .is_some_and(|p| msg.body_len > p.len() as u64)
}

/// Body section of a message card. `shown` is the cached `display_text` of the preview.
pub fn body_view(ui: &mut Ui, msg: &HttpMessage, shown: Option<&str>, salt: &str) {
    let Some(text) = shown.filter(|t| !t.is_empty()) else {
        let note = if msg.body_len == 0 {
            "No body".to_owned()
        } else {
            format!(
                "{} body, no text preview (binary or compressed)",
                format::bytes(msg.body_len)
            )
        };
        muted(ui, &note);
        return;
    };
    let id = ui.scope_id().with(("web_body_open", salt));
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
        let more = lines.len() - PREVIEW_LINES;
        let label = if open {
            "Show less".to_owned()
        } else {
            format!("Show {more} more lines")
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
    if is_truncated(msg) {
        let n = format!(
            "Preview truncated: {} of {}",
            format::bytes(text.len() as u64),
            format::bytes(msg.body_len)
        );
        ui.label(RichText::new(n).small().color(Palette::warn()));
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
