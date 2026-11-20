//! WCAG 2.1 luminance, APCA perceptual contrast, alpha compositing, and OKLab/OKLCH math.

use eframe::egui::Color32;

/// Linearize a single sRGB channel (`0..=255`) using the WCAG 2.1 threshold.
fn linearize_wcag(channel: u8) -> f64 {
    let s = f64::from(channel) / 255.0;
    if s <= 0.03928 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

/// Linearize a single sRGB channel (`0..=255`) using the IEC 61966-2-1 threshold.
pub(crate) fn linearize_srgb(channel: u8) -> f64 {
    let s = f64::from(channel) / 255.0;
    if s <= 0.04045 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

/// Convert a linear sRGB value in `[0.0, 1.0]` back to `u8`.
pub(crate) fn encode_srgb(linear: f64) -> u8 {
    let x = linear.clamp(0.0, 1.0);
    let s = if x <= 0.003_130_8 {
        12.92 * x
    } else {
        1.055 * x.powf(1.0 / 2.4) - 0.055
    };
    (s.clamp(0.0, 1.0) * 255.0).round() as u8
}

/// WCAG 2.1 relative luminance in `[0.0, 1.0]`.
pub fn relative_luminance(c: Color32) -> f64 {
    0.2126 * linearize_wcag(c.r()) + 0.7152 * linearize_wcag(c.g()) + 0.0722 * linearize_wcag(c.b())
}

/// Alpha-composite translucent `fg` over opaque `bg` in sRGB space.
pub fn blend_over(fg: Color32, alpha: u8, bg: Color32) -> Color32 {
    let a = f32::from(alpha) / 255.0;
    let inv = 1.0 - a;
    let mix = |f: u8, b: u8| -> u8 { (f32::from(f) * a + f32::from(b) * inv).round() as u8 };
    Color32::from_rgb(
        mix(fg.r(), bg.r()),
        mix(fg.g(), bg.g()),
        mix(fg.b(), bg.b()),
    )
}

/// WCAG 2.1 contrast ratio between two opaque colors (always >= 1.0).
pub fn contrast_ratio(a: Color32, b: Color32) -> f64 {
    let la = relative_luminance(a);
    let lb = relative_luminance(b);
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// APCA-W3 (0.0.98G-4g) signed perceptual lightness contrast `Lc` for `text` over `bg`.
pub fn apca_lc(text: Color32, bg: Color32) -> f64 {
    let y = |c: Color32| -> f64 {
        0.212_672_9 * (f64::from(c.r()) / 255.0).powf(2.4)
            + 0.715_152_2 * (f64::from(c.g()) / 255.0).powf(2.4)
            + 0.072_175_0 * (f64::from(c.b()) / 255.0).powf(2.4)
    };
    let mut yt = y(text);
    let mut yb = y(bg);
    if yt < 0.022 {
        yt += (0.022 - yt).powf(1.414);
    }
    if yb < 0.022 {
        yb += (0.022 - yb).powf(1.414);
    }
    if (yb - yt).abs() < 0.0005 {
        return 0.0;
    }
    if yb > yt {
        let sapc = (yb.powf(0.56) - yt.powf(0.57)) * 1.14;
        if sapc < 0.1 {
            0.0
        } else {
            (sapc - 0.027) * 100.0
        }
    } else {
        let sapc = (yb.powf(0.65) - yt.powf(0.62)) * 1.14;
        if sapc > -0.1 {
            0.0
        } else {
            (sapc + 0.027) * 100.0
        }
    }
}

/// Mix `a` toward `b` by `t` in `[0.0, 1.0]`.
pub fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| -> u8 { (f32::from(x) * (1.0 - t) + f32::from(y) * t).round() as u8 };
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// Convert opaque sRGB `Color32` to perceptual OKLab `[L, a, b]`.
pub fn rgb_to_oklab(c: Color32) -> [f64; 3] {
    let r = linearize_srgb(c.r());
    let g = linearize_srgb(c.g());
    let b = linearize_srgb(c.b());
    let l = (0.412_221_470_8 * r + 0.536_332_536_3 * g + 0.051_445_992_9 * b).cbrt();
    let m = (0.211_903_498_2 * r + 0.680_699_545_1 * g + 0.107_396_956_6 * b).cbrt();
    let s = (0.088_302_461_9 * r + 0.281_718_837_6 * g + 0.629_978_700_5 * b).cbrt();
    [
        0.210_454_255_3 * l + 0.793_617_785_0 * m - 0.004_072_046_8 * s,
        1.977_998_495_1 * l - 2.428_592_205_0 * m + 0.450_593_709_9 * s,
        0.025_904_037_1 * l + 0.782_771_766_2 * m - 0.808_675_766_0 * s,
    ]
}

/// Euclidean perceptual distance in OKLab space.
pub fn oklab_distance(a: Color32, b: Color32) -> f64 {
    let [l1, a1, b1] = rgb_to_oklab(a);
    let [l2, a2, b2] = rgb_to_oklab(b);
    ((l1 - l2).powi(2) + (a1 - a2).powi(2) + (b1 - b2).powi(2)).sqrt()
}

/// OKLCH chroma (`sqrt(a^2 + b^2)`), a perceptually uniform measure of saturation.
pub fn oklch_chroma(c: Color32) -> f64 {
    let [_, a, b] = rgb_to_oklab(c);
    a.hypot(b)
}

/// OKLCH hue angle in `[0.0, 360.0)` degrees.
pub fn oklch_hue_deg(c: Color32) -> f64 {
    let [_, a, b] = rgb_to_oklab(c);
    b.atan2(a).to_degrees().rem_euclid(360.0)
}
