//! `Settings`: every user preference edited by the dialog. Pure data, serde defaults so old
//! files keep loading; `clamped()` makes any value safe to apply.
use serde::{Deserialize, Serialize};
use wl_model::CaptureOptions;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ThemeChoice {
    #[default]
    Dark,
    Light,
    System,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Density {
    Compact,
    #[default]
    Comfortable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PillLook {
    #[default]
    Tinted,
    Solid,
    Dot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TimeFormat {
    #[default]
    Relative,
    Absolute,
    Delta,
    Utc,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    // Appearance
    pub theme: ThemeChoice,
    pub ui_scale: f32,
    pub density: Density,
    pub pill_look: PillLook,
    pub mono_font_size: f32,
    pub sidebar_labels: bool,
    // Capture
    pub default_interface: String,
    /// Defaults of Capture > Options (filter, promiscuous, snaplen, ring buffer, auto-stop ...).
    pub capture: CaptureOptions,
    pub temp_dir: String,
    // Display
    pub time_format: TimeFormat,
    pub auto_scroll: bool,
    pub color_rules: bool,
    pub max_rows: u32,
    // Names
    pub resolve_dns: bool,
    pub resolve_mac_vendor: bool,
    pub resolve_services: bool,
    pub name_cache_size: u32,
    // Performance
    pub stats_hz: u32,
    pub batch_size: u32,
    pub fps_cap: u32,
    pub detail_cache: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: ThemeChoice::Dark,
            ui_scale: 1.0,
            density: Density::Comfortable,
            pill_look: PillLook::Tinted,
            mono_font_size: 12.5,
            sidebar_labels: true,
            default_interface: String::new(),
            capture: CaptureOptions::default(),
            temp_dir: String::new(),
            time_format: TimeFormat::Relative,
            auto_scroll: true,
            color_rules: true,
            max_rows: 2_000_000,
            resolve_dns: true,
            resolve_mac_vendor: true,
            resolve_services: true,
            name_cache_size: 50_000,
            stats_hz: 4,
            batch_size: 2_000,
            fps_cap: 60,
            detail_cache: 64,
        }
    }
}

impl Settings {
    /// Copy with every numeric field forced into its supported range.
    pub fn clamped(mut self) -> Self {
        self.ui_scale = if self.ui_scale.is_finite() {
            self.ui_scale.clamp(0.75, 2.0)
        } else {
            1.0
        };
        self.mono_font_size = self.mono_font_size.clamp(10.0, 18.0);
        self.capture = self.capture.clamped();
        self.max_rows = self.max_rows.clamp(10_000, 20_000_000);
        self.name_cache_size = self.name_cache_size.clamp(1_000, 1_000_000);
        self.stats_hz = self.stats_hz.clamp(1, 30);
        self.batch_size = self.batch_size.clamp(100, 50_000);
        self.fps_cap = self.fps_cap.clamp(15, 240);
        self.detail_cache = self.detail_cache.clamp(8, 1_024);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_json_yields_defaults() {
        let s: Settings = serde_json::from_str("{}").expect("parse");
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn partial_old_file_keeps_unknown_defaults() {
        let s: Settings = serde_json::from_str(r#"{"theme":"Light","ui_scale":1.5}"#).expect("p");
        assert_eq!(s.theme, ThemeChoice::Light);
        assert_eq!(s.ui_scale, 1.5);
        assert!(s.sidebar_labels);
    }

    #[test]
    fn clamp_bounds_and_nan() {
        let s = Settings {
            ui_scale: f32::NAN,
            stats_hz: 0,
            fps_cap: 9_999,
            ..Settings::default()
        }
        .clamped();
        assert_eq!(s.ui_scale, 1.0);
        assert_eq!(s.stats_hz, 1);
        assert_eq!(s.fps_cap, 240);
    }

    #[test]
    fn round_trips() {
        let s = Settings {
            theme: ThemeChoice::System,
            density: Density::Compact,
            ..Settings::default()
        };
        let j = serde_json::to_string(&s).expect("ser");
        assert_eq!(serde_json::from_str::<Settings>(&j).expect("de"), s);
    }
}
