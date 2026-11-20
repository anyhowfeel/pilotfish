//! Capture file properties dialog (Wireshark: Statistics > Capture File Properties).

mod lines;
mod rows;

#[cfg(test)]
mod dialog_tests;

use wl_kit::egui::{
    self, Align2, Context, Id, Key, Order, RichText, ScrollArea, Ui, UiBuilder, Window, vec2,
};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::{modal_scrim, settings_card};
use wl_model::CaptureProperties;

use rows::{kv_full_row, kv_row};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HashState {
    #[default]
    Idle,
    Computing,
    Ready(String),
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertiesAction {
    ComputeHash,
}

#[derive(Default)]
pub struct PropertiesDialog {
    open: bool,
    loading: bool,
    error: Option<String>,
    props: Option<CaptureProperties>,
    hash: HashState,
}

const BUTTON_W: f32 = 92.0;
/// Title bar plus the window frame's margins: `fixed_size` is the outer size.
const TITLE_AND_MARGINS: f32 = 82.0;

impl PropertiesDialog {
    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn file_size(&self) -> Option<u64> {
        self.props.as_ref().map(|p| p.file_size)
    }

    /// Opens the dialog in its loading state, forgetting the previous file.
    pub fn begin(&mut self) {
        *self = Self {
            open: true,
            loading: true,
            ..Self::default()
        };
    }

    pub fn close(&mut self) {
        self.open = false;
    }

    pub fn set_properties(&mut self, r: Result<CaptureProperties, String>) {
        self.loading = false;
        match r {
            Ok(p) => self.props = Some(p),
            Err(e) => self.error = Some(e),
        }
    }

    pub fn set_hash_computing(&mut self) {
        self.hash = HashState::Computing;
    }

    pub fn set_hash(&mut self, r: Result<String, String>) {
        self.hash = match r {
            Ok(h) => HashState::Ready(h),
            Err(e) => HashState::Failed(e),
        };
    }

    pub fn ui(&mut self, ctx: &Context) -> Option<PropertiesAction> {
        if !self.open {
            return None;
        }
        if ctx.input(|i| i.key_pressed(Key::Escape)) || modal_scrim(ctx, "props", Order::Middle) {
            self.open = false;
            return None;
        }
        let mut open = true;
        let mut action = None;
        Window::new("Capture file properties")
            .id(Id::NULL.with("wl_file_properties"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
            .fixed_size(vec2(580.0, self.height(ctx)))
            .show(ctx, |ui| action = self.body(ui));
        self.open &= open;
        action
    }

    /// Dialog height: the content when it fits the window, else what the window allows.
    fn height(&self, ctx: &Context) -> f32 {
        let room = (ctx.content_rect().height() - 60.0).clamp(160.0, 900.0);
        let content = match (&self.props, self.loading) {
            (Some(p), false) => lines::content_height(p, matches!(self.hash, HashState::Ready(_))),
            _ => 40.0,
        };
        (content + TITLE_AND_MARGINS).min(room)
    }

    fn body(&self, ui: &mut Ui) -> Option<PropertiesAction> {
        if self.loading {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Reading capture with capinfos\u{2026}").color(Palette::muted()),
                );
            });
            return None;
        }
        if let Some(e) = &self.error {
            ui.label(RichText::new(e).color(Palette::danger()));
            return None;
        }
        let p = self.props.as_ref()?;
        let mut action = None;
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = spacing::XS;
                for (si, s) in lines::sections(p).into_iter().enumerate() {
                    settings_card(ui, s.title, |ui| {
                        for (i, (k, v)) in s.rows.iter().enumerate() {
                            kv_row(ui, i == 0, k, v, false, 0.0);
                        }
                        if si == 0 {
                            action = self.hash_row(ui);
                        }
                    });
                }
                self.lists(ui, p);
            });
        action
    }

    fn hash_row(&self, ui: &mut Ui) -> Option<PropertiesAction> {
        let text = match &self.hash {
            HashState::Idle => "not computed".to_owned(),
            HashState::Computing => "computing\u{2026}".to_owned(),
            HashState::Ready(_) => "computed".to_owned(),
            HashState::Failed(e) => e.clone(),
        };
        let slot = kv_row(ui, false, "SHA256", &text, false, BUTTON_W + spacing::SM);
        if let HashState::Ready(h) = &self.hash {
            // The 64 hex digits need the whole card width: their own full-width line.
            kv_full_row(ui, h);
        }
        let mut action = None;
        let btn = egui::Rect::from_center_size(
            slot.right_center() - vec2(BUTTON_W / 2.0, 0.0),
            vec2(BUTTON_W, 24.0),
        );
        ui.scope_builder(UiBuilder::new().max_rect(btn), |ui| match &self.hash {
            HashState::Ready(h) => {
                if ui
                    .add_sized(btn.size(), egui::Button::new("Copy"))
                    .clicked()
                {
                    ui.ctx().copy_text(h.clone());
                }
            }
            HashState::Computing => {
                ui.add_sized(btn.size(), egui::Spinner::new());
            }
            _ => {
                if ui
                    .add_sized(btn.size(), egui::Button::new("Compute"))
                    .clicked()
                {
                    action = Some(PropertiesAction::ComputeHash);
                }
            }
        });
        action
    }

    fn lists(&self, ui: &mut Ui, p: &CaptureProperties) {
        if !p.comments.is_empty() {
            settings_card(ui, "Comments", |ui| {
                for (i, c) in p.comments.iter().enumerate() {
                    kv_row(ui, i == 0, &format!("Comment {}", i + 1), c, false, 0.0);
                }
            });
        }
        let ifaces = lines::interface_lines(p);
        if !ifaces.is_empty() {
            settings_card(ui, "Interfaces", |ui| {
                for (i, (name, detail)) in ifaces.iter().enumerate() {
                    kv_row(ui, i == 0, name, detail, false, 0.0);
                }
            });
        }
    }
}
