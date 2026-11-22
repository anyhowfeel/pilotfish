//! One finding = one card: severity dot + title + muted description + evidence chips on the
//! left, right-anchored equal-width actions (they wrap under the text when the card is narrow).
use wl_kit::egui::{
    self, Align, Button, FontId, Frame, Id, Layout, Margin, Rect, Response, RichText, TextWrapMode,
    Ui, text::LayoutJob, vec2,
};
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{Severity, accent_card, chip, chip_copy, severity_dot, toast};
use wl_model::HealthInsight;

use super::actions::InsightsAction;
use super::category::Category;
use super::logic::severity_of;
use super::rules::mute_choices;

const ACTION_W: f32 = 132.0;
const BTN_H: f32 = 30.0;
/// Below this card width the actions move under the text.
const NARROW: f32 = 520.0;
const DESC_ROWS: usize = 2;

/// Draws the card; returns its rect (for scroll-into-view).
pub fn finding_card(
    ui: &mut Ui,
    f: &HealthInsight,
    cat: Category,
    selected: bool,
    actions: &mut Vec<InsightsAction>,
) -> Rect {
    let id = Id::NULL.with(("wl_finding", &f.title));
    let mut open = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    let sev = severity_of(f.severity);
    let card = accent_card(ui, sev, selected, |ui| {
        let avail = ui.available_width();
        let narrow = avail < NARROW;
        let text_w = if narrow {
            avail
        } else {
            avail - ACTION_W - spacing::LG
        };
        ui.spacing_mut().item_spacing.y = spacing::XS + 2.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = spacing::LG;
            ui.vertical(|ui| {
                ui.set_width(text_w);
                ui.spacing_mut().item_spacing.y = spacing::XS + 2.0;
                let title = title_row(ui, f, sev);
                let desc = description(ui, &f.explanation, text_w, open);
                for target in [title, desc] {
                    mute_menu(target, f, actions);
                }
                evidence(ui, f, text_w);
                if open {
                    hint(ui, cat);
                }
                if toggle(ui, open) {
                    open = !open;
                }
            });
            if !narrow {
                action_column(ui, f, actions);
            }
        });
        if narrow {
            ui.horizontal(|ui| action_buttons(ui, f, actions, ACTION_W));
        }
    });
    ui.data_mut(|d| d.insert_temp(id, open));
    card.response.rect
}

fn title_row(ui: &mut Ui, f: &HealthInsight, sev: Severity) -> Response {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = spacing::SM;
        severity_dot(ui, sev, 10.0);
        ui.add(
            egui::Label::new(
                RichText::new(&f.title)
                    .strong()
                    .size(15.0)
                    .color(Palette::text()),
            )
            .wrap_mode(TextWrapMode::Wrap)
            .sense(egui::Sense::click()),
        )
    })
    .inner
}

fn mute_menu(target: Response, f: &HealthInsight, actions: &mut Vec<InsightsAction>) {
    target.context_menu(|ui| {
        for choice in mute_choices(f) {
            if ui.button(choice.label).clicked() {
                actions.push(InsightsAction::Mute(choice.pattern));
                ui.close();
            }
        }
    });
}

/// Muted description, clamped to two rows unless `open`.
fn description(ui: &mut Ui, text: &str, width: f32, open: bool) -> Response {
    let mut job = LayoutJob::simple(
        text.to_owned(),
        FontId::proportional(13.5),
        Palette::muted(),
        width,
    );
    if !open {
        job.wrap.max_rows = DESC_ROWS;
        job.wrap.overflow_character = Some('\u{2026}');
    }
    let galley = ui.painter().layout_job(job);
    let (rect, resp) = ui.allocate_exact_size(galley.size(), egui::Sense::click());
    ui.painter().galley(rect.min, galley, Palette::muted());
    resp
}

fn evidence(ui: &mut Ui, f: &HealthInsight, width: f32) {
    ui.horizontal_wrapped(|ui| {
        ui.set_max_width(width);
        ui.spacing_mut().item_spacing = vec2(spacing::SM, spacing::XS);
        if !f.metric.is_empty() {
            chip(ui, &f.metric, true);
        }
        if let Some(flt) = &f.suggested_filter
            && chip_copy(ui, flt).clicked()
        {
            ui.ctx().copy_text(flt.clone());
            toast::push(ui.ctx(), "Filter copied");
        }
    });
}

fn hint(ui: &mut Ui, cat: Category) {
    Frame::new()
        .fill(Palette::bg())
        .corner_radius(RADIUS)
        .inner_margin(Margin::same(spacing::MD as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new("What it means / what to try")
                    .strong()
                    .small()
                    .color(Palette::text()),
            );
            ui.add(egui::Label::new(RichText::new(cat.hint()).color(Palette::muted())).wrap());
        });
}

fn toggle(ui: &mut Ui, open: bool) -> bool {
    ui.add(
        egui::Label::new(
            RichText::new(if open { "Hide details" } else { "Show details" })
                .small()
                .color(Palette::accent()),
        )
        .sense(egui::Sense::click()),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
    .clicked()
}

fn action_column(ui: &mut Ui, f: &HealthInsight, actions: &mut Vec<InsightsAction>) {
    ui.with_layout(Layout::top_down(Align::Max), |ui| {
        ui.set_width(ACTION_W);
        ui.spacing_mut().item_spacing.y = spacing::SM;
        action_buttons(ui, f, actions, ACTION_W);
    });
}

fn action_buttons(ui: &mut Ui, f: &HealthInsight, actions: &mut Vec<InsightsAction>, w: f32) {
    let Some(flt) = &f.suggested_filter else {
        return;
    };
    let inspect = Button::new(
        RichText::new("Show packets")
            .strong()
            .color(Palette::on_accent()),
    )
    .fill(Palette::accent());
    if ui
        .add_sized([w, BTN_H], inspect)
        .on_hover_text(format!("Apply  {flt}  and open Packets"))
        .clicked()
    {
        actions.push(InsightsAction::ApplyFilter(flt.clone()));
    }
}
