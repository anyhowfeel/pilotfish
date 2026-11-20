//! Painting of the dialog chrome: backdrop, header, rail/tabs, scroll body, footer.
use wl_kit::egui::{
    self, Align, Align2, Area, Button, CornerRadius, CursorIcon, FontId, Id, Layout, Order, Rect,
    RichText, ScrollArea, Sense, Shadow, Stroke, Ui, UiBuilder, pos2, vec2,
};
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{close_button, modal_scrim};

use super::category::Category;
use super::layout::Geometry;
use super::model::Settings;
use super::pages;
use super::pages_more::{self, AboutAction, AboutInfo};

const R: u8 = RADIUS + 4;

pub struct Out {
    pub cancel: bool,
    pub apply: bool,
    pub reset: bool,
    pub about: AboutAction,
}

pub fn show(
    ctx: &egui::Context,
    g: &Geometry,
    draft: &mut Settings,
    cat: &mut Category,
    about: &AboutInfo,
) -> Out {
    let mut out = Out {
        cancel: false,
        apply: false,
        reset: false,
        about: AboutAction::None,
    };
    out.cancel |= modal_scrim(ctx, "settings", Order::Foreground);
    Area::new(Id::NULL.with("wl_settings_dialog"))
        .order(Order::Foreground)
        .fixed_pos(g.dialog.min)
        .movable(false)
        .show(ctx, |ui| {
            ui.set_clip_rect(g.dialog.expand(40.0));
            paint_chrome(ui, g);
            header(
                &mut child(ui, g.header, Layout::left_to_right(Align::Center)),
                &mut out,
            );
            nav(ui, g, cat);
            body(ui, g, draft, *cat, about, &mut out);
            footer(
                &mut child(ui, g.footer, Layout::right_to_left(Align::Center)),
                &mut out,
            );
            ui.allocate_rect(g.dialog, Sense::hover());
        });
    out
}

fn child(ui: &mut Ui, rect: Rect, layout: Layout) -> Ui {
    ui.new_child(UiBuilder::new().max_rect(rect).layout(layout))
}

fn paint_chrome(ui: &mut Ui, g: &Geometry) {
    let p = ui.painter();
    p.add(
        Shadow {
            offset: [0, 8],
            blur: 28,
            spread: 2,
            color: egui::Color32::from_black_alpha(110),
        }
        .as_shape(g.dialog, R),
    );
    p.rect_filled(g.dialog, R, Palette::bg());
    let top = CornerRadius {
        nw: R,
        ne: R,
        sw: 0,
        se: 0,
    };
    let bottom = CornerRadius {
        nw: 0,
        ne: 0,
        sw: R,
        se: R,
    };
    p.rect_filled(g.header, top, Palette::panel());
    p.rect_filled(g.footer, bottom, Palette::panel());
    if g.rail {
        p.rect_filled(g.nav, 0.0, Palette::panel());
        let x = g.nav.right();
        p.line_segment(
            [pos2(x, g.nav.top()), pos2(x, g.nav.bottom())],
            Stroke::new(1.0, Palette::border()),
        );
    }
    let line = Stroke::new(1.0, Palette::border());
    p.line_segment([g.header.left_bottom(), g.header.right_bottom()], line);
    p.line_segment([g.footer.left_top(), g.footer.right_top()], line);
    p.rect_stroke(g.dialog, R, line, egui::StrokeKind::Inside);
}

fn header(ui: &mut Ui, out: &mut Out) {
    ui.add_space(spacing::LG);
    ui.label(
        RichText::new("Settings")
            .strong()
            .size(17.0)
            .color(Palette::text()),
    );
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.add_space(spacing::LG);
        out.cancel |= close_button(ui).clicked();
    });
}

fn nav(ui: &mut Ui, g: &Geometry, cat: &mut Category) {
    if g.rail {
        let mut col = child(
            ui,
            g.nav.shrink2(vec2(spacing::SM, spacing::SM)),
            Layout::top_down(Align::Min),
        );
        col.spacing_mut().item_spacing.y = 2.0;
        for c in Category::ALL {
            if rail_item(&mut col, c, c == *cat).clicked() {
                *cat = c;
            }
        }
    } else {
        let mut row = child(
            ui,
            g.nav.shrink2(vec2(spacing::SM, 4.0)),
            Layout::left_to_right(Align::Center),
        );
        ScrollArea::horizontal()
            .id_salt("wl_settings_tabs")
            .show(&mut row, |ui| {
                ui.horizontal_centered(|ui| {
                    for c in Category::ALL {
                        if ui.selectable_label(c == *cat, c.label()).clicked() {
                            *cat = c;
                        }
                    }
                });
            });
        let y = g.nav.bottom();
        ui.painter().line_segment(
            [pos2(g.nav.left(), y), pos2(g.nav.right(), y)],
            Stroke::new(1.0, Palette::border()),
        );
    }
}

fn rail_item(ui: &mut Ui, c: Category, selected: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 34.0), Sense::click());
    let p = ui.painter();
    if selected || resp.hovered() {
        let fill = if selected {
            Palette::surface_hi()
        } else {
            Palette::surface()
        };
        p.rect_filled(rect, RADIUS, fill);
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
    p.text(
        pos2(rect.left() + spacing::MD + 4.0, rect.center().y),
        Align2::LEFT_CENTER,
        c.label(),
        FontId::proportional(14.0),
        color,
    );
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

fn body(
    ui: &mut Ui,
    g: &Geometry,
    draft: &mut Settings,
    cat: Category,
    about: &AboutInfo,
    out: &mut Out,
) {
    let rect = g.body.shrink2(vec2(spacing::LG, 0.0));
    let mut b = child(ui, rect, Layout::top_down(Align::Min));
    ScrollArea::vertical()
        .id_salt(("wl_settings_body", cat.label()))
        .auto_shrink([false, false])
        .show(&mut b, |ui| {
            // Keep content clear of the floating scrollbar.
            ui.set_max_width((ui.max_rect().width() - 14.0).max(120.0));
            ui.add_space(spacing::MD);
            match cat {
                Category::Appearance => pages::appearance(ui, draft),
                Category::Capture => pages::capture(ui, draft),
                Category::Display => pages::display(ui, draft),
                Category::Names => pages_more::names(ui, draft),
                Category::Performance => pages_more::performance(ui, draft),
                Category::Shortcuts => pages_more::shortcuts(ui),
                Category::About => out.about = pages_more::about(ui, about),
            }
        });
}

fn footer(ui: &mut Ui, out: &mut Out) {
    ui.add_space(spacing::LG);
    ui.spacing_mut().item_spacing.x = spacing::SM;
    let apply = Button::new(RichText::new("Apply").color(Palette::on_accent()).strong())
        .fill(Palette::accent())
        .min_size(vec2(84.0, 30.0));
    out.apply |= ui.add(apply).clicked();
    let cancel = Button::new("Cancel").min_size(vec2(84.0, 30.0));
    out.cancel |= ui.add(cancel).clicked();
    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
        ui.add_space(spacing::LG);
        let reset = Button::new(RichText::new("Reset to defaults").color(Palette::muted()))
            .min_size(vec2(0.0, 30.0));
        out.reset |= ui.add(reset).clicked();
    });
}
