//! Semantic color tokens, selectable `Theme` variants, and mode-aware `Palette` accessors.

use eframe::egui::Color32;

use super::contrast::relative_luminance;
use super::palette_defs::{SLATE_DARK, SLATE_LIGHT};
use super::{Mode, mode, theme};

/// Named color theme identities (each provides paired Dark and Light modes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Theme {
    /// Cool neutral slate surfaces + confident technical blue accent.
    #[default]
    Slate,
}

impl Theme {
    pub const ALL: [Theme; 1] = [Theme::Slate];

    pub const fn as_str(self) -> &'static str {
        match self {
            Theme::Slate => "slate",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Theme::Slate => "Cool Slate",
        }
    }

    pub fn parse(s: &str) -> Option<Theme> {
        match s.trim().to_ascii_lowercase().as_str() {
            "slate" | "cool-slate" | "default" => Some(Theme::Slate),
            _ => None,
        }
    }

    pub const fn colors(self, m: Mode) -> &'static Colors {
        match (self, m) {
            (Theme::Slate, Mode::Dark) => &SLATE_DARK,
            (Theme::Slate, Mode::Light) => &SLATE_LIGHT,
        }
    }
}

/// Semantic colors of one theme mode.
#[derive(Clone, Copy, Debug)]
pub struct Colors {
    pub bg: Color32,
    pub panel: Color32,
    pub surface: Color32,
    pub surface_hi: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub danger: Color32,
    pub info: Color32,
    pub on_accent: Color32,
    pub on_danger: Color32,
    pub row_alt: Color32,
    pub selection_bg: Color32,
    pub series: [Color32; 6],
}

/// Mode- and theme-aware semantic color accessors: `Palette::surface()` etc.
pub struct Palette;

impl Palette {
    pub fn colors() -> &'static Colors {
        theme().colors(mode())
    }
    pub fn colors_for(m: Mode) -> &'static Colors {
        theme().colors(m)
    }
    pub fn bg() -> Color32 {
        Self::colors().bg
    }
    pub fn panel() -> Color32 {
        Self::colors().panel
    }
    pub fn surface() -> Color32 {
        Self::colors().surface
    }
    pub fn surface_hi() -> Color32 {
        Self::colors().surface_hi
    }
    pub fn border() -> Color32 {
        Self::colors().border
    }
    pub fn text() -> Color32 {
        Self::colors().text
    }
    pub fn muted() -> Color32 {
        Self::colors().muted
    }
    pub fn accent() -> Color32 {
        Self::colors().accent
    }
    pub fn ok() -> Color32 {
        Self::colors().ok
    }
    pub fn warn() -> Color32 {
        Self::colors().warn
    }
    pub fn danger() -> Color32 {
        Self::colors().danger
    }
    pub fn info() -> Color32 {
        Self::colors().info
    }
    pub fn on_accent() -> Color32 {
        Self::colors().on_accent
    }
    pub fn on_danger() -> Color32 {
        Self::colors().on_danger
    }
    pub fn row_alt() -> Color32 {
        Self::colors().row_alt
    }
    /// Host scope colour shared by tables and the map: private = green, public = orange.
    pub fn scope(private: bool) -> Color32 {
        if private { Self::ok() } else { Self::warn() }
    }

    pub fn selection_bg() -> Color32 {
        Self::colors().selection_bg
    }
    pub fn chart_series() -> &'static [Color32; 6] {
        &Self::colors().series
    }
    pub fn series(idx: usize) -> Color32 {
        let s = Self::chart_series();
        s[idx % s.len()]
    }

    /// High-contrast ink color (near-black or near-white) for text drawn directly atop `fill`.
    pub fn on_color(fill: Color32) -> Color32 {
        if relative_luminance(fill) > 0.22 {
            Self::colors_for(Mode::Dark).bg
        } else {
            Self::colors_for(Mode::Light).on_accent
        }
    }
}
