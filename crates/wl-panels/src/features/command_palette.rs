//! Keyboard-first fuzzy Command Palette UI (`Ctrl+K`, `Esc`, `Up`/`Down`, `Enter`).

use eframe::egui::{
    self, Align, Align2, CornerRadius, Frame, Key, Layout, Margin, RichText, ScrollArea, Sense,
    Stroke, Window, vec2,
};
use wl_kit::theme::{Palette, RADIUS, mono, spacing};

pub use crate::features::palette_items::{
    PaletteAction, PaletteEntry, PalettePage, fuzzy_score, matches_for, parse_frame_jump,
};

#[derive(Default)]
pub struct CommandPalette {
    open: bool,
    query: String,
    selected: usize,
    focus_input: bool,
}

impl CommandPalette {
    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn open(&mut self) {
        self.open = true;
        self.query.clear();
        self.selected = 0;
        self.focus_input = true;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.query.clear();
    }

    pub fn toggle(&mut self) {
        if self.open {
            self.close();
        } else {
            self.open();
        }
    }

    /// Handles global `Ctrl+K` / `Cmd+K` shortcut to toggle the palette.
    pub fn handle_shortcut(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::K)) {
            self.toggle();
        }
    }

    pub fn matches_for(query: &str) -> Vec<PaletteEntry> {
        matches_for(query)
    }

    /// Renders the centered Command Palette overlay when open.
    pub fn ui(&mut self, ctx: &egui::Context) -> Option<PaletteAction> {
        self.handle_shortcut(ctx);
        if !self.open {
            return None;
        }
        let (esc, down, up, enter) = ctx.input(|i| {
            (
                i.key_pressed(Key::Escape),
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::Enter),
            )
        });
        if esc {
            self.close();
            return None;
        }

        let items = Self::matches_for(&self.query);
        if !items.is_empty() {
            self.selected = self.selected.min(items.len() - 1);
            if down {
                self.selected = (self.selected + 1) % items.len();
            }
            if up {
                self.selected = self.selected.checked_sub(1).unwrap_or(items.len() - 1);
            }
        } else {
            self.selected = 0;
        }

        let mut chosen: Option<PaletteAction> =
            (enter && !items.is_empty()).then(|| items[self.selected].action.clone());

        if wl_kit::widgets::modal_scrim(ctx, "palette", egui::Order::Middle) {
            self.close();
            return None;
        }
        Window::new("Command Palette")
            .id(egui::Id::NULL.with("wl_command_palette"))
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_TOP, vec2(0.0, 72.0))
            .fixed_size(vec2(540.0, 360.0))
            .frame(
                Frame::new()
                    .fill(Palette::surface())
                    .stroke(Stroke::new(1.0, Palette::accent()))
                    .corner_radius(CornerRadius::same(RADIUS + 2))
                    .inner_margin(Margin::same(spacing::MD as i8)),
            )
            .show(ctx, |ui| {
                let edit = ui.add(
                    wl_kit::widgets::text_field(&mut self.query)
                        .hint_text("Type a command, filter, or #frame (Esc to close)...")
                        .desired_width(f32::INFINITY),
                );
                if self.focus_input {
                    edit.request_focus();
                    self.focus_input = false;
                }
                if edit.changed() {
                    self.selected = 0;
                }
                ui.add_space(spacing::SM);
                ScrollArea::vertical()
                    .id_salt("wl_palette_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if items.is_empty() {
                            ui.label(RichText::new("No matching commands").color(Palette::muted()));
                            return;
                        }
                        for (idx, item) in items.iter().enumerate() {
                            let fill = if idx == self.selected {
                                Palette::selection_bg()
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            let resp = Frame::new()
                                .fill(fill)
                                .corner_radius(CornerRadius::same(6))
                                .inner_margin(Margin::symmetric(
                                    spacing::SM as i8,
                                    spacing::XS as i8,
                                ))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            mono(item.category).small().color(Palette::accent()),
                                        );
                                        ui.label(RichText::new(&item.label).color(Palette::text()));
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                ui.label(
                                                    mono(item.hint).small().color(Palette::muted()),
                                                );
                                            },
                                        );
                                    });
                                })
                                .response
                                .interact(Sense::click());
                            if resp.hovered() {
                                self.selected = idx;
                            }
                            if resp.clicked() {
                                chosen = Some(item.action.clone());
                            }
                        }
                    });
            });

        if chosen.is_some() {
            self.close();
        }
        chosen
    }
}
