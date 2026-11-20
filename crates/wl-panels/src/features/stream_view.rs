//! Follow TCP/UDP Stream modal with client/server coloring, ASCII/Hex toggle, search, copy.

use eframe::egui::{
    self, Align, Align2, CornerRadius, Frame, Key, Layout, Margin, RichText, ScrollArea, Stroke,
    Ui, Window, vec2,
};
use wl_kit::format;
use wl_kit::theme::{Palette, RADIUS, mono, spacing, tint};
use wl_kit::widgets::badge;
use wl_model::{StreamConversation, StreamFormat, StreamProtocol};

pub use crate::features::stream_text::{count_search_matches, format_conversation_text};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamViewAction {
    Close,
    ReloadFormat {
        protocol: StreamProtocol,
        stream_id: u32,
        format: StreamFormat,
    },
    ApplyFilter(String),
}

#[derive(Default)]
pub struct StreamView {
    open: bool,
    loading: bool,
    error: Option<String>,
    conversation: Option<StreamConversation>,
    format: StreamFormat,
    query: String,
    target: Option<(StreamProtocol, u32)>,
}

impl StreamView {
    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn begin_load(&mut self, protocol: StreamProtocol, stream_id: u32, format: StreamFormat) {
        self.open = true;
        self.loading = true;
        self.error = None;
        self.format = format;
        self.target = Some((protocol, stream_id));
    }

    pub fn set_conversation(&mut self, conv: StreamConversation) {
        self.open = true;
        self.loading = false;
        self.error = None;
        self.format = conv.format;
        self.target = Some((conv.protocol, conv.stream_id));
        self.conversation = Some(conv);
    }

    pub fn set_error(&mut self, msg: String) {
        self.open = true;
        self.loading = false;
        self.error = Some(msg);
    }

    pub fn close(&mut self) {
        self.open = false;
        self.loading = false;
    }

    /// Renders the Follow Stream window when open. Returns any triggered action.
    pub fn ui(&mut self, ctx: &egui::Context) -> Option<StreamViewAction> {
        if !self.open {
            return None;
        }
        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.close();
            return Some(StreamViewAction::Close);
        }
        let mut action = None;
        let mut keep_open = self.open;
        let title = match self.target {
            Some((proto, id)) => format!("Follow {} Stream #{id}", proto.as_str().to_uppercase()),
            None => "Follow Stream".to_owned(),
        };

        if wl_kit::widgets::modal_scrim(ctx, "stream", egui::Order::Middle) {
            self.close();
            return Some(StreamViewAction::Close);
        }
        Window::new(title)
            .id(egui::Id::NULL.with("wl_stream_view_modal"))
            .open(&mut keep_open)
            .collapsible(false)
            .resizable(true)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .default_size(vec2(760.0, 520.0))
            .min_size(vec2(480.0, 320.0))
            .show(ctx, |ui| {
                self.toolbar(ui, &mut action);
                ui.add_space(spacing::SM);
                self.body(ui);
            });

        if !keep_open {
            self.close();
            action = Some(StreamViewAction::Close);
        }
        action
    }

    fn toolbar(&mut self, ui: &mut Ui, action: &mut Option<StreamViewAction>) {
        ui.horizontal_wrapped(|ui| {
            let mut next_fmt = self.format;
            if ui
                .selectable_label(self.format == StreamFormat::Ascii, "ASCII")
                .clicked()
            {
                next_fmt = StreamFormat::Ascii;
            }
            if ui
                .selectable_label(self.format == StreamFormat::Hex, "Hex")
                .clicked()
            {
                next_fmt = StreamFormat::Hex;
            }
            if next_fmt != self.format
                && let Some((protocol, stream_id)) = self.target
            {
                self.format = next_fmt;
                self.loading = true;
                *action = Some(StreamViewAction::ReloadFormat {
                    protocol,
                    stream_id,
                    format: next_fmt,
                });
            }
            ui.separator();
            ui.add(
                wl_kit::widgets::text_field(&mut self.query)
                    .hint_text("Search stream...")
                    .desired_width(180.0),
            );
            if let Some(conv) = &self.conversation
                && !self.query.is_empty()
            {
                let hits = count_search_matches(conv, &self.query);
                ui.label(
                    RichText::new(format!("{hits} matches"))
                        .small()
                        .color(Palette::muted()),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some((proto, id)) = self.target
                    && ui.button("Filter stream").clicked()
                {
                    *action = Some(StreamViewAction::ApplyFilter(proto.display_filter(id)));
                }
                if let Some(conv) = &self.conversation
                    && ui.button("Copy all").clicked()
                {
                    ui.ctx().copy_text(format_conversation_text(conv));
                }
            });
        });
    }

    fn body(&self, ui: &mut Ui) {
        if self.loading {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Reassembling stream via tshark...").color(Palette::muted()),
                );
            });
            return;
        }
        if let Some(err) = &self.error {
            ui.label(RichText::new(err).color(Palette::danger()));
            return;
        }
        let Some(conv) = &self.conversation else {
            return;
        };
        ui.horizontal_wrapped(|ui| {
            badge(ui, &format!("Client: {}", conv.client), Palette::accent());
            badge(ui, &format!("Server: {}", conv.server), Palette::ok());
            ui.label(
                RichText::new(format!(
                    "{} turns • {}",
                    conv.turns.len(),
                    format::bytes(conv.total_bytes as u64)
                ))
                .small()
                .color(Palette::muted()),
            );
        });
        ui.add_space(spacing::SM);
        if conv.turns.is_empty() {
            ui.label(RichText::new("Stream contains no payload bytes.").color(Palette::muted()));
            return;
        }
        let needle = self.query.to_ascii_lowercase();
        ScrollArea::vertical()
            .id_salt("wl_stream_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (idx, turn) in conv.turns.iter().enumerate() {
                    if !needle.is_empty() && !turn.text.to_ascii_lowercase().contains(&needle) {
                        continue;
                    }
                    let (accent, who) = if turn.from_client {
                        (Palette::accent(), "Client")
                    } else {
                        (Palette::ok(), "Server")
                    };
                    Frame::new()
                        .fill(tint(accent, 22))
                        .stroke(Stroke::new(1.0, tint(accent, 90)))
                        .corner_radius(CornerRadius::same(RADIUS))
                        .inner_margin(Margin::same(spacing::SM as i8))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("#{idx} {who}"))
                                        .strong()
                                        .color(accent),
                                );
                                ui.label(
                                    RichText::new(format::bytes(turn.byte_len as u64))
                                        .small()
                                        .color(Palette::muted()),
                                );
                            });
                            ui.add(
                                egui::Label::new(mono(&turn.text).color(Palette::text())).wrap(),
                            );
                        });
                    ui.add_space(spacing::XS);
                }
            });
    }
}
