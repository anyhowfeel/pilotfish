//! Palette definitions (dark and light). Colours were picked in OKLCH, see the tests in
//! `theme/tests.rs` for the contrast and colour-blind constraints they must satisfy.

use eframe::egui::Color32;

use super::palette::Colors;

pub(crate) const fn rgb(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// Cool Slate (Dark): faint cool slate neutrals (C <= 0.012, H ~ 255°) + technical blue.
pub const SLATE_DARK: Colors = Colors {
    bg: rgb(0x0F1215),
    panel: rgb(0x16191D),
    surface: rgb(0x1E2125),
    surface_hi: rgb(0x282C30),
    border: rgb(0x373B41),
    text: rgb(0xEAECEF),
    muted: rgb(0xA7ACB2),
    accent: rgb(0x63A4F1),
    ok: rgb(0x66BF88),
    warn: rgb(0xEB9659),
    danger: rgb(0xEB7A79),
    info: rgb(0x60B8E3),
    on_accent: rgb(0x090C10),
    on_danger: rgb(0x100B0A),
    row_alt: rgb(0x14171B),
    selection_bg: rgb(0x343A44),
    series: [
        rgb(0x5B99E6),
        rgb(0xF4A467),
        rgb(0x7AD0A0),
        rgb(0xDD93CB),
        rgb(0xE4706B),
        rgb(0x80CEF6),
    ],
};

/// Cool Slate (Light): "night sky by day" - white with a trace of violet over soft periwinkle
/// neutrals, deep navy text and a deep blue accent (hue ~250, kept clear of purple).
pub const SLATE_LIGHT: Colors = Colors {
    bg: rgb(0xF3F2FB),
    panel: rgb(0xE6E4F4),
    surface: rgb(0xFEFDFF),
    surface_hi: rgb(0xD8D7EA),
    border: rgb(0xBFBED5),
    text: rgb(0x151828),
    muted: rgb(0x4A4C60),
    accent: rgb(0x3550A6),
    ok: rgb(0x12603A),
    warn: rgb(0x8F4306),
    danger: rgb(0x9A2A34),
    info: rgb(0x0B5C94),
    on_accent: rgb(0xF9FAFF),
    on_danger: rgb(0xFCF9F9),
    row_alt: rgb(0xE9E8F6),
    selection_bg: rgb(0xC4D2FB),
    series: [
        rgb(0x3550A6),
        rgb(0x944809),
        rgb(0x1B6B45),
        rgb(0xA23B73),
        rgb(0x851A1F),
        rgb(0x0C6783),
    ],
};
