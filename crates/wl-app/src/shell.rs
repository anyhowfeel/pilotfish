//! Window chrome: sidebar navigation and the top status bar.
use wl_kit::egui::{
    self, Align2, Color32, CursorIcon, FontId, Margin, Rect, Sense, Stroke, pos2, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, mono, spacing};

use crate::icons;
use crate::page::Page;
use crate::sidebar_brand::brand;
use crate::sidebar_stop::{Running, clear_filter_button, stop_button};
use crate::state::StatusInfo;

pub const NAV_W: f32 = 196.0;
/// Icon-only rail width (sidebar labels hidden in settings).
pub const NAV_W_COMPACT: f32 = 68.0;
pub(crate) const NAV_ROW_H: f32 = 38.0;
pub(crate) const ICON_W: f32 = 28.0;
const BAR_H: f32 = 40.0;

#[derive(Default)]
pub struct SidebarOut {
    pub page: Option<Page>,
    pub open_settings: bool,
    pub stop_capture: bool,
    pub clear_filter: bool,
    /// Page to open (or close) in its own window (Shift+click on a nav entry).
    pub detach: Option<Page>,
}

/// Sidebar width for the given label preference.
pub fn nav_width(labels: bool) -> f32 {
    if labels { NAV_W } else { NAV_W_COMPACT }
}

/// Draws the sidebar; returns navigation and open-settings intents.
pub fn sidebar(
    ui: &mut egui::Ui,
    current: Page,
    labels: bool,
    running: Option<Running>,
    filter: Option<&str>,
) -> SidebarOut {
    let mut out = SidebarOut::default();
    let frame = egui::Frame::new()
        .fill(Palette::panel())
        .inner_margin(Margin::same(spacing::MD as i8));
    let resp = egui::Panel::left("nav")
        .resizable(false)
        .exact_size(nav_width(labels))
        .frame(frame)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = spacing::XS;
            brand(ui, labels);
            ui.add_space(spacing::MD);
            for page in Page::ALL {
                let paint = |p: &egui::Painter, r: Rect, c| icons::paint(p, page, r, c);
                let tip = format!("{}  \u{b7}  Shift+click: new window", page.label());
                if nav_entry(ui, &paint, page.label(), &tip, page == current, labels).clicked() {
                    if ui.input(|i| i.modifiers.shift) {
                        out.detach = Some(page);
                    } else {
                        out.page = Some(page);
                    }
                }
            }
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.spacing_mut().item_spacing.y = spacing::XS;
                let gear = |p: &egui::Painter, r: Rect, c| icons::paint_gear(p, r, c);
                out.open_settings =
                    nav_entry(ui, &gear, "Settings", "Settings  Ctrl+,", false, labels).clicked();
                let (line, _) =
                    ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
                ui.painter().rect_filled(line, 0.0, Palette::border());
                if let Some(r) = running {
                    ui.add_space(spacing::XS);
                    out.stop_capture = stop_button(ui, r, labels, NAV_ROW_H, ICON_W).clicked();
                }
                if let Some(f) = filter {
                    ui.add_space(spacing::XS);
                    out.clear_filter =
                        clear_filter_button(ui, f, labels, NAV_ROW_H, ICON_W).clicked();
                }
            });
        });
    let r = resp.response.rect;
    ui.painter().line_segment(
        [pos2(r.right(), r.top()), pos2(r.right(), r.bottom())],
        Stroke::new(1.0, Palette::border()),
    );
    out
}

type IconFn<'a> = &'a dyn Fn(&egui::Painter, Rect, Color32);

fn nav_entry(
    ui: &mut egui::Ui,
    icon: IconFn,
    label: &str,
    tip: &str,
    selected: bool,
    labels: bool,
) -> egui::Response {
    let (rect, resp) =
        ui.allocate_exact_size(vec2(ui.available_width(), NAV_ROW_H), Sense::click());
    let p = ui.painter();
    if selected || resp.hovered() {
        p.rect_filled(
            rect,
            RADIUS,
            if selected {
                Palette::surface_hi()
            } else {
                Palette::surface()
            },
        );
    }
    if selected {
        let bar = Rect::from_min_size(
            rect.left_top() + vec2(0.0, 8.0),
            vec2(3.0, rect.height() - 16.0),
        );
        p.rect_filled(bar, 2.0, Palette::accent());
    }
    let color = if selected {
        Palette::text()
    } else {
        Palette::muted()
    };
    let icon_x = if labels {
        rect.left() + spacing::MD + ICON_W / 2.0
    } else {
        rect.center().x
    };
    icon(
        p,
        Rect::from_center_size(pos2(icon_x, rect.center().y), vec2(18.0, 18.0)),
        if selected { Palette::accent() } else { color },
    );
    if labels {
        let label_rect = Rect::from_min_max(
            pos2(rect.left() + spacing::MD + ICON_W + spacing::SM, rect.top()),
            rect.right_bottom(),
        );
        p.with_clip_rect(label_rect).text(
            pos2(label_rect.left(), label_rect.center().y),
            Align2::LEFT_CENTER,
            label,
            FontId::proportional(14.5),
            color,
        );
    }
    let resp = resp.on_hover_cursor(CursorIcon::PointingHand);
    if labels && tip == label {
        resp
    } else {
        resp.on_hover_text(tip)
    }
}

/// Top status bar: state dot, source, packets, rate, elapsed, filter. Returns true when the
/// source name was clicked (open the capture file properties).
pub fn status_bar(ui: &mut egui::Ui, s: &StatusInfo) -> bool {
    let mut open_properties = false;
    let frame = egui::Frame::new()
        .fill(Palette::panel())
        .inner_margin(Margin::symmetric(spacing::LG as i8, 0));
    let bar = egui::Panel::top("status")
        .resizable(false)
        .exact_size(BAR_H)
        .frame(frame)
        .show(ui, |ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = spacing::SM;
                let rate = format!("{} pkt/s", format::count(s.rate_pps.round() as u64));
                metric(ui, "Elapsed", &format::duration(s.elapsed), "00 h 00 m");
                metric(ui, "Rate", &rate, "000,000 pkt/s");
                metric(ui, "Packets", &format::count(s.packets), "000,000,000");
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = spacing::SM;
                    let (r, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.5, s.state.color());
                    ui.label(
                        egui::RichText::new(s.state.label())
                            .color(s.state.color())
                            .strong(),
                    );
                    sep(ui);
                    let src = if s.source.is_empty() {
                        "No capture"
                    } else {
                        s.source.as_str()
                    };
                    let label = egui::Label::new(egui::RichText::new(src).color(Palette::text()))
                        .truncate()
                        .sense(Sense::click());
                    let resp = ui.add(label).on_hover_cursor(CursorIcon::PointingHand);
                    open_properties = resp
                        .on_hover_text(format!("{src}\nClick for capture file properties"))
                        .clicked();
                    if !s.filter.is_empty() {
                        sep(ui);
                        ui.add(
                            egui::Label::new(mono(&s.filter).color(Palette::accent())).truncate(),
                        )
                        .on_hover_text(&s.filter);
                    }
                });
            });
        });
    let r = bar.response.rect;
    ui.painter().line_segment(
        [pos2(r.left(), r.bottom()), pos2(r.right(), r.bottom())],
        Stroke::new(1.0, Palette::border()),
    );
    open_properties
}

fn sep(ui: &mut egui::Ui) {
    let (r, _) = ui.allocate_exact_size(vec2(1.0, 16.0), Sense::hover());
    ui.painter().rect_filled(r, 0.0, Palette::border());
}

/// A labelled value in a cell as wide as `widest` (monospace), value right-aligned, so the
/// neighbouring labels and separators never shift when the digits change.
fn metric(ui: &mut egui::Ui, name: &str, value: &str, widest: &str) {
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let w = ui
        .painter()
        .layout_no_wrap(widest.to_owned(), font, Palette::text())
        .size()
        .x;
    let layout = egui::Layout::right_to_left(egui::Align::Center);
    ui.allocate_ui_with_layout(vec2(w, BAR_H), layout, |ui| {
        ui.label(mono(value).color(Palette::text()));
    });
    ui.label(egui::RichText::new(name).small().color(Palette::muted()));
    sep(ui);
}
