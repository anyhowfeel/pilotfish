//! UI scale (egui zoom factor) with Ctrl +/-/0 shortcuts.

use eframe::egui::{self, Key, Modifiers};

pub const MIN: f32 = 0.75;
pub const MAX: f32 = 2.0;
const STEP: f32 = 0.125;

pub fn clamp(s: f32) -> f32 {
    if s.is_finite() {
        s.clamp(MIN, MAX)
    } else {
        1.0
    }
}

pub fn set_ui_scale(ctx: &egui::Context, scale: f32) {
    ctx.set_zoom_factor(clamp(scale));
}

pub fn ui_scale(ctx: &egui::Context) -> f32 {
    ctx.zoom_factor()
}

/// Call once per frame: Ctrl+= / Ctrl++ zoom in, Ctrl+- zoom out, Ctrl+0 reset.
pub fn handle_shortcuts(ctx: &egui::Context) {
    ctx.options_mut(|o| o.zoom_with_keyboard = false);
    let (inc, dec, reset) = ctx.input_mut(|i| {
        let c = Modifiers::COMMAND;
        (
            i.consume_key(c, Key::Equals) | i.consume_key(c, Key::Plus),
            i.consume_key(c, Key::Minus),
            i.consume_key(c, Key::Num0),
        )
    });
    let cur = ctx.zoom_factor();
    let next = if reset {
        1.0
    } else if inc {
        cur + STEP
    } else if dec {
        cur - STEP
    } else {
        return;
    };
    set_ui_scale(ctx, next);
    crate::widgets::toast::push(ctx, format!("Zoom {:.0}%", clamp(next) * 100.0));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps() {
        assert_eq!(clamp(0.1), MIN);
        assert_eq!(clamp(5.0), MAX);
        assert_eq!(clamp(f32::NAN), 1.0);
        assert_eq!(clamp(1.25), 1.25);
    }
}
