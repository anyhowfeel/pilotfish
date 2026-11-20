//! HTTP method and status pills: one implementation, calm CVD-safe family colours from the theme.

use eframe::egui::{Color32, Rect, Response, Ui};
use wl_model::StatusClass;

use crate::theme::Palette;
use crate::widgets::pill::{PillStyle, pill, pill_at};

/// Uniform width of method pills in tables ("DELETE" / "OPTIONS" fit).
pub const METHOD_PILL_W: f32 = 64.0;
/// Uniform width of status pills in tables ("404").
pub const STATUS_PILL_W: f32 = 52.0;

/// Colour family of an HTTP method: reads are blue, creates green, updates orange, deletes red.
pub fn method_color(method: &str) -> Color32 {
    match method.trim().to_ascii_uppercase().as_str() {
        "GET" => Palette::series(0),
        "POST" => Palette::series(2),
        "PUT" | "PATCH" => Palette::series(1),
        "DELETE" => Palette::series(4),
        "HEAD" | "OPTIONS" | "CONNECT" | "TRACE" => Palette::series(5),
        _ => Palette::muted(),
    }
}

/// Colour of a status class.
pub fn status_color(class: StatusClass) -> Color32 {
    match class {
        StatusClass::Info => Palette::info(),
        StatusClass::Success => Palette::ok(),
        StatusClass::Redirect => Palette::accent(),
        StatusClass::ClientError => Palette::warn(),
        StatusClass::ServerError => Palette::danger(),
        StatusClass::Unknown => Palette::muted(),
    }
}

/// Class of a numeric status code.
pub fn class_of(code: u16) -> StatusClass {
    match code {
        100..=199 => StatusClass::Info,
        200..=299 => StatusClass::Success,
        300..=399 => StatusClass::Redirect,
        400..=499 => StatusClass::ClientError,
        500..=599 => StatusClass::ServerError,
        _ => StatusClass::Unknown,
    }
}

fn style(min: f32) -> PillStyle {
    PillStyle::column(min).with_dot(false)
}

/// Method pill laid out in the flow of `ui`.
pub fn method_pill(ui: &mut Ui, method: &str, min_width: f32) -> Response {
    pill(ui, method, method_color(method), style(min_width))
}

/// Status pill ("200", "404") laid out in the flow of `ui`.
pub fn status_pill(ui: &mut Ui, code: Option<u16>, min_width: f32) -> Response {
    match code {
        Some(c) => pill(
            ui,
            &c.to_string(),
            status_color(class_of(c)),
            style(min_width),
        ),
        None => pill(ui, "--", Palette::muted(), style(min_width)),
    }
}

/// Method pill painted at an absolute position (tree rows); returns its rect.
pub fn method_pill_at(ui: &Ui, left: f32, cy: f32, method: &str) -> Rect {
    pill_at(ui, left, cy, method, method_color(method), style(0.0))
}

/// Status pill painted at an absolute position; `label` is e.g. "200 OK".
pub fn status_pill_at(ui: &Ui, left: f32, cy: f32, code: u16, label: &str) -> Rect {
    let c = status_color(class_of(code));
    pill_at(ui, left, cy, label, c, style(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{Mode, set_mode};

    #[test]
    fn classes_and_colours() {
        assert_eq!(class_of(204), StatusClass::Success);
        assert_eq!(class_of(404), StatusClass::ClientError);
        assert_eq!(class_of(503), StatusClass::ServerError);
        assert_eq!(class_of(0), StatusClass::Unknown);
        for m in [Mode::Dark, Mode::Light] {
            set_mode(m);
            assert_eq!(method_color("get"), method_color("GET"));
            let all = ["GET", "POST", "PUT", "DELETE", "HEAD"].map(method_color);
            for (i, a) in all.iter().enumerate() {
                for b in &all[i + 1..] {
                    assert_ne!(a, b);
                }
            }
        }
        set_mode(Mode::Dark);
    }
}
