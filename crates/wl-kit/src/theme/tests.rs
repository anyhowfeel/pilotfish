//! Numerical verification of WCAG AA, APCA Lc, neutral chroma, surface ladders, and hard bans.

use eframe::egui::Color32;

use super::Mode;
use super::contrast::{
    apca_lc, contrast_ratio, oklab_distance, oklch_chroma, oklch_hue_deg, relative_luminance,
    rgb_to_oklab,
};
use super::palette::{Colors, Theme};
use super::protocol::ProtocolFamily;

const AA_NORMAL: f64 = 4.5;
/// Neutrals stay nearly achromatic; the light theme carries a deliberate trace of periwinkle.
const MAX_NEUTRAL_CHROMA: f64 = 0.035;
const MAX_CALM_CHROMA: f64 = 0.16;

fn assert_semantic_aa_and_apca(name: &str, c: &Colors) {
    let bgs = [
        ("bg", c.bg),
        ("panel", c.panel),
        ("surface", c.surface),
        ("surface_hi", c.surface_hi),
        ("row_alt", c.row_alt),
    ];
    let fgs = [
        ("text", c.text),
        ("muted", c.muted),
        ("accent", c.accent),
        ("ok", c.ok),
        ("warn", c.warn),
        ("danger", c.danger),
        ("info", c.info),
    ];
    for (bg_name, bg) in bgs {
        for (fg_name, fg) in fgs {
            let cr = contrast_ratio(fg, bg);
            assert!(
                cr >= AA_NORMAL,
                "{name}: {fg_name} on {bg_name} contrast {cr:.2} < {AA_NORMAL}"
            );
        }
        assert!(
            apca_lc(c.text, bg).abs() >= 80.0,
            "{name}: text on {bg_name} |APCA Lc| < 80"
        );
        assert!(
            apca_lc(c.muted, bg).abs() >= 50.0,
            "{name}: muted on {bg_name} |APCA Lc| < 50"
        );
    }
    assert!(
        contrast_ratio(c.text, c.selection_bg) >= AA_NORMAL,
        "{name}: text on selection_bg < {AA_NORMAL}"
    );
    assert!(
        contrast_ratio(c.muted, c.selection_bg) >= AA_NORMAL,
        "{name}: muted on selection_bg < {AA_NORMAL}"
    );
    assert!(
        contrast_ratio(c.on_accent, c.accent) >= AA_NORMAL,
        "{name}: on_accent on accent < {AA_NORMAL}"
    );
    assert!(
        contrast_ratio(c.on_danger, c.danger) >= AA_NORMAL,
        "{name}: on_danger on danger < {AA_NORMAL}"
    );
}

#[test]
fn all_themes_semantic_palettes_meet_wcag_aa_and_apca() {
    for t in Theme::ALL {
        for m in [Mode::Dark, Mode::Light] {
            assert_semantic_aa_and_apca(&format!("{}/{m:?}", t.as_str()), t.colors(m));
        }
    }
}

#[test]
fn neutrals_are_near_achromatic_and_no_pure_black_or_white() {
    let pure_black = Color32::from_rgb(0, 0, 0);
    let pure_white = Color32::from_rgb(255, 255, 255);
    for t in Theme::ALL {
        for m in [Mode::Dark, Mode::Light] {
            let c = t.colors(m);
            for (tok, col) in [
                ("bg", c.bg),
                ("panel", c.panel),
                ("surface", c.surface),
                ("surface_hi", c.surface_hi),
                ("border", c.border),
                ("text", c.text),
                ("muted", c.muted),
                ("row_alt", c.row_alt),
            ] {
                let ch = oklch_chroma(col);
                assert!(
                    ch <= MAX_NEUTRAL_CHROMA,
                    "{}/{m:?} neutral {tok} chroma {ch:.4} > {MAX_NEUTRAL_CHROMA}",
                    t.as_str()
                );
            }
            for col in [
                c.bg,
                c.panel,
                c.surface,
                c.surface_hi,
                c.border,
                c.text,
                c.muted,
                c.accent,
                c.ok,
                c.warn,
                c.danger,
                c.info,
                c.on_accent,
                c.on_danger,
                c.row_alt,
                c.selection_bg,
            ] {
                assert!(
                    col != pure_black && col != pure_white,
                    "{}/{m:?} contains banned pure black/white {col:?}",
                    t.as_str()
                );
            }
            let warn_h = oklch_hue_deg(c.warn);
            assert!(
                (40.0..=64.0).contains(&warn_h),
                "{}/{m:?} warn hue {warn_h:.1}° must be orange-amber (40°..=64°), never yellow",
                t.as_str()
            );
        }
    }
}

#[test]
fn surface_hierarchy_and_row_states_are_clearly_separated() {
    for t in Theme::ALL {
        let d = t.colors(Mode::Dark);
        let [d_bg, d_p, d_s, d_hi] =
            [d.bg, d.panel, d.surface, d.surface_hi].map(relative_luminance);
        assert!(d_bg < d_p && d_p < d_s && d_s < d_hi);
        let [obg, op, os, ohi] =
            [d.bg, d.panel, d.surface, d.surface_hi].map(|c| rgb_to_oklab(c)[0]);
        assert!(op - obg >= 0.025 && os - op >= 0.025 && ohi - os >= 0.025);
        assert!(oklab_distance(d.bg, d.row_alt) >= 0.018);
        assert!(oklab_distance(d.row_alt, d.surface_hi) >= 0.05);
        assert!(oklab_distance(d.selection_bg, d.row_alt) >= 0.05);
        assert!(oklab_distance(d.selection_bg, d.surface_hi) >= 0.035);

        let l = t.colors(Mode::Light);
        let [l_s, l_bg, l_p, l_hi] =
            [l.surface, l.bg, l.panel, l.surface_hi].map(relative_luminance);
        assert!(l_s > l_bg && l_bg > l_p && l_p > l_hi);
        let [ls, lbg, lp, lhi] =
            [l.surface, l.bg, l.panel, l.surface_hi].map(|c| rgb_to_oklab(c)[0]);
        assert!(ls - lbg >= 0.024 && lbg - lp >= 0.024 && lp - lhi >= 0.024);
        assert!(oklab_distance(l.bg, l.row_alt) >= 0.018);
        assert!(oklab_distance(l.row_alt, l.surface_hi) >= 0.035);
        assert!(oklab_distance(l.selection_bg, l.row_alt) >= 0.035);
        assert!(oklab_distance(l.selection_bg, l.surface_hi) >= 0.035);
    }
}

#[test]
fn saturation_and_semantic_family_cohesion() {
    for t in Theme::ALL {
        for m in [Mode::Dark, Mode::Light] {
            let c = t.colors(m);
            let semantics = [c.ok, c.warn, c.danger, c.info];
            let ls: Vec<f64> = semantics.iter().map(|&col| rgb_to_oklab(col)[0]).collect();
            let l_span = ls.iter().copied().fold(f64::MIN, f64::max)
                - ls.iter().copied().fold(f64::MAX, f64::min);
            assert!(
                l_span <= 0.05,
                "{}/{m:?} semantic lightness span {l_span:.3} > 0.05",
                t.as_str()
            );
            for col in [c.accent, c.ok, c.warn, c.danger, c.info]
                .into_iter()
                .chain(c.series)
            {
                assert!(oklch_chroma(col) <= MAX_CALM_CHROMA);
            }
        }
    }
    for fam in ProtocolFamily::ALL {
        for m in [Mode::Dark, Mode::Light] {
            assert!(oklch_chroma(fam.color(m)) <= MAX_CALM_CHROMA);
        }
    }
}

#[test]
fn chart_series_are_aa_and_distinct() {
    for t in Theme::ALL {
        for m in [Mode::Dark, Mode::Light] {
            let c = t.colors(m);
            for (i, &col) in c.series.iter().enumerate() {
                assert!(contrast_ratio(col, c.surface) >= AA_NORMAL);
                assert!(contrast_ratio(col, c.bg) >= AA_NORMAL);
                for &other in c.series.iter().skip(i + 1) {
                    assert!(oklab_distance(col, other) >= 0.09);
                }
            }
        }
    }
}

#[test]
fn theme_parse_roundtrips() {
    for t in Theme::ALL {
        assert_eq!(Theme::parse(t.as_str()), Some(t));
    }
    assert_eq!(Theme::parse("unknown"), None);
}
