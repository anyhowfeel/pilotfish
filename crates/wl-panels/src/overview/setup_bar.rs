//! Sticky bottom bar of the Setup page: capture filter (presets + live validation) and actions.

use wl_kit::egui::{self, Color32, Frame, Key, Margin, Stroke, Ui};
use wl_kit::theme::{Palette, RADIUS, spacing};
use wl_kit::widgets::{centered_row, pill_toggle, text_field};
use wl_model::{CaptureOptions, Wireshark};

use super::actions::OverviewAction;
use super::setup_actions::action_row;
use super::setup_logic::{PRESETS, apply_preset};

/// Result of checking a capture filter against an interface with the backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterStatus {
    pub interface: String,
    pub filter: String,
    pub result: Result<(), String>,
}

/// Quiet time after the last keystroke before the filter is sent for validation.
const DEBOUNCE: f64 = 0.4;

#[derive(Default)]
pub struct BarState {
    edit_at: f64,
    last_text: String,
    requested: Option<(String, String)>,
}

pub struct BarData<'a> {
    pub running: bool,
    pub paused: bool,
    pub status: Option<&'a FilterStatus>,
    pub wireshark: Wireshark,
}

/// Draws the bar and returns its outer height.
pub fn sticky_bar(
    ui: &mut Ui,
    st: &mut BarState,
    o: &mut CaptureOptions,
    d: &BarData<'_>,
    out: &mut Vec<OverviewAction>,
) -> f32 {
    Frame::new()
        .fill(Palette::panel())
        .stroke(Stroke::new(1.0, Palette::border()))
        .corner_radius(RADIUS)
        .inner_margin(Margin::symmetric(spacing::MD as i8, spacing::SM as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            filter_row(ui, o);
            ui.add_space(spacing::XS);
            presets(ui, o);
            ui.add_space(spacing::SM);
            let v = verdict(ui, st, o, d.status, out);
            action_row(ui, o, d, &v, out);
        })
        .response
        .rect
        .height()
}

fn filter_row(ui: &mut Ui, o: &mut CaptureOptions) {
    centered_row(ui, 28.0, |ui| {
        let edit = text_field(&mut o.capture_filter)
            .hint_text("BPF capture filter, e.g. host 192.168.1.5 and port 80")
            .font(egui::TextStyle::Monospace)
            .desired_width(ui.available_width());
        if ui.add(edit).has_focus() && ui.input(|i| i.key_pressed(Key::Escape)) {
            o.capture_filter.clear();
        }
    });
}

fn presets(ui: &mut Ui, o: &mut CaptureOptions) {
    ui.horizontal_wrapped(|ui| {
        for (label, expr) in PRESETS {
            let mut on = o.capture_filter.trim() == expr;
            if pill_toggle(ui, &mut on, label).changed() {
                o.capture_filter = apply_preset(&o.capture_filter, expr);
            }
        }
    });
}

/// What the bar says about the capture filter.
pub(super) struct Verdict {
    pub text: Option<String>,
    pub color: Color32,
    /// `Some(valid)` once the backend answered.
    pub ok: Option<bool>,
    pub detail: String,
}

/// Decides the filter message and schedules a validation request once typing settles.
fn verdict(
    ui: &Ui,
    st: &mut BarState,
    o: &CaptureOptions,
    status: Option<&FilterStatus>,
    out: &mut Vec<OverviewAction>,
) -> Verdict {
    let filter = o.capture_filter.trim().to_string();
    let now = ui.input(|i| i.time);
    if filter != st.last_text {
        st.last_text = filter.clone();
        st.edit_at = now;
    }
    let mut v = Verdict {
        text: None,
        color: Palette::muted(),
        ok: None,
        detail: String::new(),
    };
    let (Some(iface), false) = (o.interfaces.first(), filter.is_empty() || o.remote.enabled) else {
        return v;
    };
    match status.filter(|s| &s.interface == iface && s.filter == filter) {
        Some(s) => match &s.result {
            Ok(()) => {
                v.text = Some(format!("Valid capture filter for {iface}."));
                v.color = Palette::ok();
                v.ok = Some(true);
            }
            Err(e) => {
                v.text = Some(first_line(e));
                v.color = Palette::danger();
                v.ok = Some(false);
                v.detail = e.clone();
            }
        },
        None => {
            let key = (iface.clone(), filter);
            if now - st.edit_at >= DEBOUNCE {
                if st.requested.as_ref() != Some(&key) {
                    out.push(OverviewAction::CheckCaptureFilter {
                        interface: key.0.clone(),
                        filter: key.1.clone(),
                    });
                    st.requested = Some(key);
                }
            } else {
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(150));
            }
            v.text = Some("Checking capture filter\u{2026}".to_string());
        }
    }
    v
}

fn first_line(msg: &str) -> String {
    msg.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("Capturing on"))
        .unwrap_or("Invalid capture filter")
        .to_string()
}
