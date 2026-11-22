//! Pill drawing styles (tinted / solid / dot), switched from Settings > Appearance.
use eframe::egui::Color32;

use crate::theme::Mode;
use crate::theme::contrast::lerp_color;

/// How pills are drawn (Settings > Appearance > Protocol pills).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    Tinted,
    Solid,
    Dot,
}

static LOOK: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn set_look(l: Look) {
    LOOK.store(l as u8, std::sync::atomic::Ordering::Relaxed);
}

pub(super) fn look() -> Look {
    match LOOK.load(std::sync::atomic::Ordering::Relaxed) {
        1 => Look::Solid,
        2 => Look::Dot,
        _ => Look::Tinted,
    }
}

/// Text colour for a solid pill: near-black on light fills, near-white on dark ones.
pub(super) fn solid_ink(fill: Color32) -> Color32 {
    let l =
        (0.299 * f32::from(fill.r()) + 0.587 * f32::from(fill.g()) + 0.114 * f32::from(fill.b()))
            / 255.0;
    if l > 0.55 {
        Color32::from_rgb(0x0C, 0x0F, 0x14)
    } else {
        Color32::from_rgb(0xF5, 0xF7, 0xFA)
    }
}

/// Subtle tinted fill alpha for pills in the given mode.
pub const fn pill_fill_alpha(m: Mode) -> u8 {
    match m {
        Mode::Dark => 32,
        Mode::Light => 24,
    }
}

/// Subtle 1px border alpha for pills in the given mode.
pub const fn pill_border_alpha(m: Mode) -> u8 {
    match m {
        Mode::Dark => 64,
        Mode::Light => 54,
    }
}

/// Foreground text color inside a pill, tuned to guarantee WCAG AA contrast over the tinted fill.
pub fn pill_fg_for(color: Color32, m: Mode) -> Color32 {
    let target = crate::theme::pill_ink_target(m);
    match m {
        Mode::Dark => lerp_color(color, target, 0.36),
        Mode::Light => lerp_color(color, target, 0.20),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::Palette;
    use crate::theme::contrast::{blend_over, contrast_ratio};

    #[test]
    fn semantic_pill_text_is_readable_in_both_themes() {
        for mode in [Mode::Dark, Mode::Light] {
            let c = Palette::colors_for(mode);
            for (name, color) in [("accent", c.accent), ("ok", c.ok), ("warn", c.warn)] {
                for (bg_name, bg) in [("surface", c.surface), ("bg", c.bg), ("alt", c.row_alt)] {
                    let fill = blend_over(color, pill_fill_alpha(mode), bg);
                    let ratio = contrast_ratio(pill_fg_for(color, mode), fill);
                    assert!(ratio >= 4.5, "{mode:?} {name} on {bg_name}: {ratio:.2}");
                }
            }
        }
    }
}
