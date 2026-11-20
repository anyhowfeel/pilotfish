//! Color-vision deficiency (CVD) simulation in linear sRGB (Viénot, Brettel & Mollon, 1999).

use eframe::egui::Color32;

use super::contrast::{encode_srgb, linearize_srgb};

/// Simulate deuteranopia (missing M-cones / green-blind) on an opaque sRGB color.
pub fn simulate_deuteranopia(c: Color32) -> Color32 {
    let r = linearize_srgb(c.r());
    let g = linearize_srgb(c.g());
    let b = linearize_srgb(c.b());
    let rg = 0.290_31 * r + 0.709_69 * g;
    let b2 = -0.021_97 * r + 0.021_97 * g + b;
    Color32::from_rgb(encode_srgb(rg), encode_srgb(rg), encode_srgb(b2))
}

/// Simulate protanopia (missing L-cones / red-blind) on an opaque sRGB color.
pub fn simulate_protanopia(c: Color32) -> Color32 {
    let r = linearize_srgb(c.r());
    let g = linearize_srgb(c.g());
    let b = linearize_srgb(c.b());
    let rg = 0.112_38 * r + 0.887_62 * g;
    let b2 = 0.004_01 * r - 0.004_01 * g + b;
    Color32::from_rgb(encode_srgb(rg), encode_srgb(rg), encode_srgb(b2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::contrast::{blend_over, contrast_ratio, oklab_distance};
    use crate::theme::palette::{Palette, Theme};
    use crate::theme::protocol::ProtocolFamily;
    use crate::theme::{Mode, set_theme};
    use crate::widgets::pill_look::{pill_fg_for, pill_fill_alpha};

    const AA_NORMAL: f64 = 4.5;

    #[test]
    fn protocol_families_and_pills_meet_wcag_aa_across_all_themes() {
        for t in Theme::ALL {
            set_theme(t);
            for mode in [Mode::Dark, Mode::Light] {
                let c = t.colors(mode);
                let bgs = [c.bg, c.surface, c.surface_hi, c.row_alt];
                let alpha = pill_fill_alpha(mode);
                for fam in ProtocolFamily::ALL {
                    let proto = fam.color(mode);
                    let fg = pill_fg_for(proto, mode);
                    let on_cr = contrast_ratio(Palette::on_color(proto), proto);
                    assert!(
                        on_cr >= AA_NORMAL,
                        "{}/{mode:?} {fam:?}: on_color contrast {on_cr:.2} < {AA_NORMAL}",
                        t.as_str()
                    );
                    for bg in bgs {
                        let direct_cr = contrast_ratio(proto, bg);
                        assert!(
                            direct_cr >= AA_NORMAL,
                            "{}/{mode:?} {fam:?} direct contrast {direct_cr:.2} < {AA_NORMAL}",
                            t.as_str()
                        );
                        let pill_bg = blend_over(proto, alpha, bg);
                        let pill_cr = contrast_ratio(fg, pill_bg);
                        assert!(
                            pill_cr >= AA_NORMAL,
                            "{}/{mode:?} {fam:?} pill contrast {pill_cr:.2} < {AA_NORMAL}",
                            t.as_str()
                        );
                    }
                    let sel_pill_bg = blend_over(proto, alpha, c.selection_bg);
                    let sel_pill_cr = contrast_ratio(fg, sel_pill_bg);
                    assert!(
                        sel_pill_cr >= AA_NORMAL,
                        "{}/{mode:?} {fam:?} pill on selection_bg contrast {sel_pill_cr:.2} < {AA_NORMAL}",
                        t.as_str()
                    );
                }
            }
        }
        set_theme(Theme::default());
    }

    #[test]
    fn protocol_families_are_distinguishable_under_deuteranopia_and_protanopia() {
        for mode in [Mode::Dark, Mode::Light] {
            let fams = ProtocolFamily::ALL;
            for i in 0..fams.len() {
                for j in (i + 1)..fams.len() {
                    let c1 = fams[i].color(mode);
                    let c2 = fams[j].color(mode);
                    let d_norm = oklab_distance(c1, c2);
                    let d_deut =
                        oklab_distance(simulate_deuteranopia(c1), simulate_deuteranopia(c2));
                    let d_prot = oklab_distance(simulate_protanopia(c1), simulate_protanopia(c2));
                    assert!(
                        d_norm >= 0.095,
                        "{mode:?} normal {:?}-{:?} ΔE_OK={d_norm:.4} < 0.095",
                        fams[i],
                        fams[j]
                    );
                    assert!(
                        d_deut >= 0.048,
                        "{mode:?} deuteranopia {:?}-{:?} ΔE_OK={d_deut:.4} < 0.048",
                        fams[i],
                        fams[j]
                    );
                    assert!(
                        d_prot >= 0.055,
                        "{mode:?} protanopia {:?}-{:?} ΔE_OK={d_prot:.4} < 0.055",
                        fams[i],
                        fams[j]
                    );
                }
            }
        }
    }

    #[test]
    fn chart_series_are_distinguishable_under_cvd() {
        for t in Theme::ALL {
            for mode in [Mode::Dark, Mode::Light] {
                let s = t.colors(mode).series;
                for i in 0..s.len() {
                    for j in (i + 1)..s.len() {
                        let dd = oklab_distance(
                            simulate_deuteranopia(s[i]),
                            simulate_deuteranopia(s[j]),
                        );
                        let dp =
                            oklab_distance(simulate_protanopia(s[i]), simulate_protanopia(s[j]));
                        assert!(
                            dd >= 0.048 && dp >= 0.055,
                            "{}/{mode:?} series[{i}] vs [{j}] deut={dd:.4} prot={dp:.4}",
                            t.as_str()
                        );
                    }
                }
            }
        }
    }
}
