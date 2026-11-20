//! Capture setup page: scrollable interfaces / options / recent files above a sticky action bar.

use std::collections::HashMap;
use std::path::PathBuf;

use wl_kit::egui::{Align, CursorIcon, FontId, Rect, ScrollArea, Sense, Ui, pos2, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::paint_elided;
use wl_model::{CaptureOptions, Interface};

use super::actions::OverviewAction;
use super::activity::ActivityMap;
use super::iface_class::default_interface;
use super::recent::{RecentEntry, resolve, stat_fs};
use super::recent_ui::recent_section;
use super::setup_bar::{BarData, BarState, FilterStatus, sticky_bar};
use super::setup_interfaces::InterfacePicker;
use crate::capture_form::{capture_options, summary};

pub struct SetupData<'a> {
    pub interfaces: &'a [Interface],
    pub activity: &'a ActivityMap,
    pub recent: &'a [PathBuf],
    pub pinned: &'a [PathBuf],
    pub packet_counts: &'a HashMap<PathBuf, u64>,
    pub filter_status: Option<&'a FilterStatus>,
    pub running: bool,
    pub paused: bool,
}

/// Widest the options form grows; wider pages leave the rest empty instead of stretching rows.
const FORM_MAX_W: f32 = 880.0;
/// Recent entries are re-read from disk at most this often.
const RECENT_TTL: f64 = 5.0;

pub struct CaptureSetup {
    options: CaptureOptions,
    preferred: String,
    selection_ready: bool,
    options_open: bool,
    picker: InterfacePicker,
    bar: BarState,
    sticky_h: f32,
    recent: Vec<RecentEntry>,
    recent_src: (Vec<PathBuf>, Vec<PathBuf>, usize),
    recent_at: f64,
}

impl Default for CaptureSetup {
    fn default() -> Self {
        Self {
            options: CaptureOptions::default(),
            preferred: String::new(),
            selection_ready: false,
            options_open: false,
            picker: InterfacePicker::default(),
            bar: BarState::default(),
            sticky_h: 170.0,
            recent: Vec::new(),
            recent_src: Default::default(),
            recent_at: f64::NEG_INFINITY,
        }
    }
}

impl CaptureSetup {
    /// Applies the saved Capture > Options defaults; the current interface selection is kept.
    pub fn set_defaults(&mut self, defaults: &CaptureOptions, preferred_interface: &str) {
        let keep = std::mem::take(&mut self.options.interfaces);
        self.options = CaptureOptions {
            interfaces: keep,
            ..defaults.clone()
        };
        self.preferred = preferred_interface.to_string();
    }

    /// Opens collapsed sections (`options`, `other`); used by screenshots.
    pub fn expand(&mut self, spec: &str) {
        self.options_open |= spec.contains("options");
        self.picker.open_other(spec.contains("other"));
    }

    /// Interfaces currently ticked for capture.
    pub fn selected_interfaces(&self) -> &[String] {
        &self.options.interfaces
    }

    #[cfg(test)]
    pub(super) fn open_options_for_test(&mut self) {
        self.options_open = true;
    }

    pub fn ui(&mut self, ui: &mut Ui, data: &SetupData<'_>) -> Vec<OverviewAction> {
        let mut out = Vec::new();
        self.sync_selection(data.interfaces);
        self.refresh_recent(ui, data);
        let scroll_h = (ui.available_height() - self.sticky_h - spacing::SM).max(100.0);
        ScrollArea::vertical()
            .max_height(scroll_h)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.picker.ui(
                    ui,
                    data.interfaces,
                    data.activity,
                    &mut self.options.interfaces,
                );
                ui.add_space(spacing::MD);
                self.options_section(ui);
                if !self.recent.is_empty() {
                    ui.add_space(spacing::LG);
                    recent_section(ui, &self.recent, &mut out);
                }
            });
        ui.add_space(spacing::SM);
        let bar = BarData {
            running: data.running,
            paused: data.paused,
            status: data.filter_status,
        };
        let measured = sticky_bar(ui, &mut self.bar, &mut self.options, &bar, &mut out);
        if (measured - self.sticky_h).abs() > 1.0 && measured > 60.0 {
            self.sticky_h = measured;
            ui.ctx().request_repaint();
        }
        out
    }

    /// Drops vanished interfaces and picks the default one the first time a list is available.
    fn sync_selection(&mut self, list: &[Interface]) {
        if list.is_empty() {
            return;
        }
        self.options
            .interfaces
            .retain(|s| list.iter().any(|i| &i.name == s));
        if !self.selection_ready {
            self.selection_ready = true;
            let wanted = list.iter().find(|i| i.name == self.preferred);
            if let Some(n) = wanted
                .map(|i| i.name.clone())
                .or_else(|| default_interface(list))
            {
                self.options.interfaces = vec![n];
            }
        }
    }

    fn refresh_recent(&mut self, ui: &Ui, d: &SetupData<'_>) {
        let now = ui.input(|i| i.time);
        let src = (d.recent.to_vec(), d.pinned.to_vec(), d.packet_counts.len());
        if src != self.recent_src || now - self.recent_at > RECENT_TTL {
            self.recent = resolve(d.recent, d.pinned, d.packet_counts, &stat_fs);
            self.recent_src = src;
            self.recent_at = now;
        }
    }

    fn options_section(&mut self, ui: &mut Ui) {
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 28.0), Sense::click());
        let cy = rect.center().y;
        super::setup_interfaces::paint_chevron(ui, pos2(rect.left() + 6.0, cy), self.options_open);
        let title = Rect::from_min_size(pos2(rect.left() + 18.0, rect.top()), vec2(150.0, 28.0));
        let bold = FontId::proportional(15.0);
        paint_elided(
            ui.painter(),
            title,
            "Capture options",
            bold,
            Palette::text(),
            Align::Min,
        );
        let sum = Rect::from_min_max(pos2(title.right(), rect.top()), rect.max);
        let small = FontId::proportional(12.5);
        paint_elided(
            ui.painter(),
            sum,
            &summary(&self.options),
            small,
            Palette::muted(),
            Align::Min,
        );
        if resp.on_hover_cursor(CursorIcon::PointingHand).clicked() {
            self.options_open = !self.options_open;
        }
        if self.options_open {
            ui.add_space(spacing::XS);
            ui.scope(|ui| {
                ui.set_max_width(FORM_MAX_W.min(ui.available_width()));
                capture_options(ui, &mut self.options);
            });
        }
    }
}
