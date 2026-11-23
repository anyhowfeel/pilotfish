//! Floating overlays on the canvas: controls (top-right), legend (bottom-left), counts (bottom-right).

use wl_kit::egui::{
    self, Align2, Area, Color32, CornerRadius, FontId, Frame, Id, Margin, Rect, RichText, Sense,
    Stroke, TextEdit, Ui, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, mono, protocol_color, spacing, tint};
use wl_kit::widgets::{Glyph, chip, chip_tip, icon_button, pill_toggle, segmented_w};

use super::layout::Mode;
use super::model::Graph;
use super::planar::Readout;
use super::scale::{edge_alpha, edge_width};
use super::state::Options;

pub const CLUSTER_MIN_W: f32 = 308.0;
const CLUSTER_MAX_W: f32 = 520.0;
/// From this cluster width the intensity slider shares the row of the toggle chips.
const WIDE_W: f32 = 500.0;
const SEG_W: f32 = 184.0;
const OPTIONS_W: f32 = 76.0;
const MODES: [(Mode, &str); 2] = [(Mode::Planar, "Planar"), (Mode::Force, "Force")];
pub const ZOOM_STEP: f32 = 1.25;

#[derive(Default)]
pub struct Cmd {
    pub zoom: Option<f32>,
    pub fit: bool,
    pub search_enter: bool,
    /// Occupied area (for keeping the fitted graph clear of it).
    pub rect: Option<Rect>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LegendKind {
    Full,
    /// Protocol colours only (small canvases).
    Compact,
    Hidden,
}

fn float_frame() -> Frame {
    Frame::new()
        .fill(tint(Palette::surface(), 238))
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(CornerRadius::same(RADIUS))
        .inner_margin(Margin::same(spacing::SM as i8))
}

fn overlay(
    ctx: &egui::Context,
    id: &str,
    anchor: Align2,
    canvas: Rect,
    add: impl FnOnce(&mut Ui),
) -> Rect {
    let m = spacing::MD;
    let pos = match anchor {
        Align2::RIGHT_TOP => canvas.right_top() + vec2(-m, m),
        Align2::LEFT_BOTTOM => canvas.left_bottom() + vec2(m, -m),
        _ => canvas.right_bottom() + vec2(-m, -m),
    };
    Area::new(Id::NULL.with(("topology", id)))
        .order(egui::Order::Middle)
        .fixed_pos(pos)
        .pivot(anchor)
        .show(ctx, |ui| {
            float_frame().show(ui, add);
        })
        .response
        .rect
}

/// Width of the controls cluster for a canvas of width `canvas_w`.
pub fn cluster_width(canvas_w: f32) -> f32 {
    (canvas_w - 2.0 * spacing::MD - 2.0 * spacing::SM - 2.0).clamp(CLUSTER_MIN_W, CLUSTER_MAX_W)
}

fn intensity_slider(ui: &mut Ui, v: &mut f32, width: f32) -> bool {
    ui.label(
        RichText::new("Min intensity")
            .size(12.0)
            .color(Palette::muted()),
    );
    ui.spacing_mut().slider_width = width;
    let wd = &mut ui.visuals_mut().widgets;
    wd.inactive.bg_fill = Palette::border();
    wd.hovered.bg_fill = Palette::border();
    let s = egui::Slider::new(v, 0.0..=0.95)
        .show_value(false)
        .trailing_fill(true);
    let changed = ui.add(s).changed();
    let pct = format!("{:>3.0}%", *v * 100.0);
    ui.label(mono(pct).size(11.5).color(Palette::muted()));
    changed
}

/// Search, layout switch, zoom buttons, toggle chips and the intensity slider.
pub fn controls(
    ctx: &egui::Context,
    canvas: Rect,
    o: &mut Options,
    search: &mut String,
    compact: bool,
    open: &mut bool,
) -> Cmd {
    let mut cmd = Cmd::default();
    let w = cluster_width(canvas.width());
    cmd.rect = Some(overlay(ctx, "controls", Align2::RIGHT_TOP, canvas, |ui| {
        ui.set_width(w);
        ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::SM);
        ui.horizontal(|ui| {
            let mut fixed = 3.0 * 28.0 + 4.0 * spacing::SM;
            fixed += if compact { OPTIONS_W } else { SEG_W };
            let r = ui.add(
                TextEdit::singleline(search)
                    .hint_text("Find host")
                    .desired_width((w - fixed).max(60.0))
                    .margin(vec2(spacing::SM, 5.0)),
            );
            cmd.search_enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if compact {
                let (rect, _) = ui.allocate_exact_size(vec2(OPTIONS_W, 26.0), Sense::hover());
                ui.put(rect, |ui: &mut Ui| pill_toggle(ui, open, "Options"));
            } else {
                segmented_w(ui, &mut o.mode, &MODES, SEG_W);
            }
            if icon_button(ui, "Zoom out  -", Glyph::Minus).clicked() {
                cmd.zoom = Some(1.0 / ZOOM_STEP);
            }
            if icon_button(ui, "Zoom in  +", Glyph::Plus).clicked() {
                cmd.zoom = Some(ZOOM_STEP);
            }
            cmd.fit = icon_button(ui, "Fit to view  0", Glyph::Fit).clicked();
        });
        if compact && !*open {
            return;
        }
        if compact {
            segmented_w(ui, &mut o.mode, &MODES, w);
        }
        ui.horizontal(|ui| {
            let f = &mut o.filters;
            pill_toggle(ui, &mut f.hide_private_pairs, "Hide private-private");
            pill_toggle(ui, &mut o.labels, "Labels");
            pill_toggle(ui, &mut o.directions, "Directions");
            pill_toggle(ui, &mut o.encrypted, "Encrypted");
            if w >= WIDE_W {
                intensity_slider(ui, &mut f.min_intensity, 70.0);
            }
        });
        if w < WIDE_W {
            ui.horizontal(|ui| {
                intensity_slider(ui, &mut o.filters.min_intensity, w - 124.0);
            });
        }
    }));
    cmd
}

/// Dot + text as ONE widget so wrapped rows never split them.
fn item(ui: &mut Ui, color: Color32, text: &str) {
    let g =
        ui.painter()
            .layout_no_wrap(text.to_owned(), FontId::proportional(11.5), Palette::text());
    let (r, _) = ui.allocate_exact_size(vec2(13.0 + g.size().x, 16.0), Sense::hover());
    ui.painter()
        .circle_filled(r.left_center() + vec2(4.0, 0.0), 4.0, color);
    let at = egui::pos2(r.left() + 13.0, r.center().y - g.size().y / 2.0);
    ui.painter().galley(at, g, Palette::text());
}

/// Edge-width scale (3 samples from the real byte range), node scopes and protocol colours.
pub fn legend(ctx: &egui::Context, canvas: Rect, g: &Graph, kind: LegendKind) -> Rect {
    let (LegendKind::Full | LegendKind::Compact, Some(scale)) = (kind, g.scale) else {
        return Rect::NOTHING;
    };
    overlay(ctx, "legend", Align2::LEFT_BOTTOM, canvas, |ui| {
        ui.set_max_width((canvas.width() * 0.5).clamp(200.0, 380.0));
        ui.spacing_mut().item_spacing = vec2(spacing::MD, spacing::XS + 2.0);
        if kind == LegendKind::Full {
            let muted = RichText::new("Link width = bytes")
                .size(11.5)
                .color(Palette::muted());
            ui.label(muted);
            ui.horizontal(|ui| {
                for t in [0.0_f32, 0.5, 1.0] {
                    let (r, _) = ui.allocate_exact_size(vec2(26.0, 16.0), Sense::hover());
                    let c = tint(Palette::text(), edge_alpha(t));
                    let stroke = Stroke::new(edge_width(t), c);
                    ui.painter()
                        .line_segment([r.left_center(), r.right_center()], stroke);
                    let txt = mono(format::bytes(scale.value_at(t)))
                        .size(11.5)
                        .color(Palette::muted());
                    ui.label(txt);
                }
            });
        }
        ui.horizontal_wrapped(|ui| {
            if kind == LegendKind::Full {
                item(ui, Palette::scope(true), "Private");
                item(ui, Palette::scope(false), "Public");
            }
            let mut seen: Vec<Color32> = Vec::new();
            for l in &g.links {
                let c = protocol_color(&l.protocol);
                if seen.len() < 6 && !seen.contains(&c) {
                    seen.push(c);
                    item(ui, c, &l.protocol);
                }
            }
        });
    })
}

pub fn counts(ctx: &egui::Context, canvas: Rect, g: &Graph, crossings: Option<Readout>) -> Rect {
    overlay(ctx, "counts", Align2::RIGHT_BOTTOM, canvas, |ui| {
        // The overlay starts unconstrained: give it room or the chip text is elided ("6 lin...").
        ui.set_max_width((canvas.width() * 0.5).clamp(200.0, 380.0));
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = spacing::SM;
            let text = format!("{} hosts \u{b7} {} links", g.nodes.len(), g.links.len());
            chip(ui, &text, true);
            if g.hidden > 0 {
                chip(ui, &format!("+{} more hidden", g.hidden), true);
            }
            if let Some(r) = crossings {
                chip_tip(ui, &r.text(), true, r.tooltip());
            }
        });
    })
}
