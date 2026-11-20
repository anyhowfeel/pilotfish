//! Title row of the Flows page: conversation title, summary line and the action buttons.
//! Wide panes keep the buttons right of the title; narrow ones put them on their own row so
//! nothing can overflow the pane.

use wl_kit::egui::{Align, Button, Label, Layout, RichText, Ui};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::chip_dot;
use wl_model::FlowSel;

use super::actions::FlowsAction;

/// From this pane width on, the buttons sit beside the title.
const WIDE_W: f32 = 560.0;

pub struct Header<'a> {
    pub sel: &'a FlowSel,
    /// Frame currently selected in the diagram (enables "Show in Packets").
    pub frame: Option<u64>,
    pub summary: &'a str,
    pub truncated: bool,
}

#[derive(Default)]
pub struct Clicked {
    pub reload: bool,
}

fn buttons(ui: &mut Ui, h: &Header, rtl: bool, out: &mut Vec<FlowsAction>) -> Clicked {
    let mut c = Clicked::default();
    let mut one = |ui: &mut Ui, i: usize| match i {
        0 => c.reload |= ui.button("Reload").clicked(),
        1 => {
            let b = ui.add_enabled(h.frame.is_some(), Button::new("Show in Packets"));
            if b.clicked()
                && let Some(f) = h.frame
            {
                out.push(FlowsAction::ShowInPackets(f));
            }
        }
        _ => {
            if ui.button("Filter in Packets").clicked() {
                out.push(FlowsAction::ApplyFilter(h.sel.filter()));
            }
        }
    };
    let order: [usize; 3] = if rtl { [2, 1, 0] } else { [0, 1, 2] };
    for i in order {
        one(ui, i);
    }
    c
}

fn title(ui: &mut Ui, sel: &FlowSel) {
    let t = RichText::new(sel.title())
        .strong()
        .size(15.0)
        .color(Palette::text());
    ui.add(Label::new(t).truncate());
}

pub fn show(ui: &mut Ui, h: &Header, out: &mut Vec<FlowsAction>) -> Clicked {
    let mut clicked = Clicked::default();
    if ui.available_width() >= WIDE_W {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = spacing::SM;
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                clicked = buttons(ui, h, true, out);
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| title(ui, h.sel));
            });
        });
    } else {
        title(ui, h.sel);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = spacing::SM;
            clicked = buttons(ui, h, false, out);
        });
    }
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(h.summary).color(Palette::muted()));
        if h.truncated {
            let text = "Truncated to the first 50 000 packets";
            chip_dot(ui, text, false, Some(Palette::warn()));
        }
    });
    clicked
}
