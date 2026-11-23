//! Scope of the dashboard cards: the whole capture, or only the time window picked on the chart.
//! Window statistics are computed by the app (a second pass over the capture limited to the window)
//! and handed back as a snapshot; this module holds the state and the summary row.

use wl_kit::charts::TimeSelection;
use wl_kit::egui::{self, Align, Layout, RichText, Ui, vec2};
use wl_kit::format;
use wl_kit::theme::Palette;
use wl_kit::widgets::segmented_w;
use wl_model::{RatePoint, StatsSnapshot};

use super::actions::OverviewAction;
use super::dashboard_data::{Derived, derive};

/// Fixed height of the window summary row (always reserved: the chart never jumps).
pub const WINDOW_ROW_H: f32 = 28.0;
const SCOPE_W: f32 = 132.0;
const STEP_W: f32 = 270.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    #[default]
    All,
    Window,
}

/// Statistics of one window, once the app has computed them.
pub struct WindowStats {
    from: u32,
    to: u32,
    pub derived: Derived,
}

/// Millisecond bounds of a selection.
pub fn bounds(sel: &TimeSelection) -> (u32, u32) {
    let ms = |t: f64| (t.max(0.0) * 1000.0).round() as u32;
    (ms(sel.from), ms(sel.to))
}

#[derive(Default)]
pub struct WindowScope {
    pub scope: Scope,
    stats: Option<WindowStats>,
    /// Window already asked from the app (so the request is sent once).
    requested: Option<(u32, u32)>,
}

impl WindowScope {
    /// Called every frame: falls back to `All` without a selection and asks for the window's
    /// statistics the first time `Window` is shown for it.
    pub fn sync(&mut self, sel: Option<&TimeSelection>, actions: &mut Vec<OverviewAction>) {
        let Some(sel) = sel else {
            self.scope = Scope::All;
            return;
        };
        let b = bounds(sel);
        if self.scope == Scope::Window && self.requested != Some(b) {
            self.requested = Some(b);
            actions.push(OverviewAction::WindowStats { from: b.0, to: b.1 });
        }
    }

    pub fn set_stats(&mut self, from: u32, to: u32, s: &StatsSnapshot) {
        self.stats = Some(WindowStats {
            from,
            to,
            derived: derive(s),
        });
    }

    /// Forget results (new capture).
    pub fn clear(&mut self) {
        self.stats = None;
        self.requested = None;
    }

    /// Derived data of the selected window, if it is the one currently shown.
    pub fn ready(&self, sel: Option<&TimeSelection>) -> Option<&Derived> {
        let b = bounds(sel?);
        self.stats
            .as_ref()
            .filter(|w| (w.from, w.to) == b)
            .map(|w| &w.derived)
    }

    /// True when the cards should show window data (computed or still computing).
    pub fn windowed(&self, sel: Option<&TimeSelection>) -> bool {
        self.scope == Scope::Window && sel.is_some()
    }
}

/// Bucket width of the throughput chart: the native (finest) one, or a coarser one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RateStep {
    #[default]
    Auto,
    Ms10,
    Ms100,
    S1,
    S10,
}

impl RateStep {
    const OPTIONS: [(RateStep, &'static str); 5] = [
        (RateStep::Auto, "Auto"),
        (RateStep::Ms10, "10 ms"),
        (RateStep::Ms100, "100 ms"),
        (RateStep::S1, "1 s"),
        (RateStep::S10, "10 s"),
    ];

    /// Bucket width in seconds; 0 keeps the native resolution.
    pub fn secs(self) -> f64 {
        match self {
            RateStep::Auto => 0.0,
            RateStep::Ms10 => 0.01,
            RateStep::Ms100 => 0.1,
            RateStep::S1 => 1.0,
            RateStep::S10 => 10.0,
        }
    }
}

fn selection_summary(ui: &mut Ui, sel: &TimeSelection, rate: &[RatePoint]) {
    let (packets, bytes) = sel.totals(rate);
    let text = format!(
        "{} \u{2013} {}   {} packets \u{00b7} {}",
        format::clock_precise(sel.from),
        format::clock_precise(sel.to),
        format::count(packets),
        format::bytes(bytes)
    );
    ui.label(RichText::new(text).color(Palette::text()));
}

fn selection_actions(
    ui: &mut Ui,
    sel: TimeSelection,
    selection: &mut Option<TimeSelection>,
    scope: &mut Scope,
    actions: &mut Vec<OverviewAction>,
) {
    if ui.button("Clear").clicked() {
        *selection = None;
    }
    let show = egui::Button::new(
        RichText::new("Show packets")
            .strong()
            .color(Palette::on_accent()),
    )
    .fill(Palette::accent());
    if ui.add(show).clicked() {
        actions.push(OverviewAction::ApplyFilter(sel.filter_expr()));
    }
    let opts = [(Scope::All, "All"), (Scope::Window, "Window")];
    segmented_w(ui, scope, &opts, SCOPE_W);
}

/// Hint or the selected window with its totals and actions, plus the chart's step selector.
pub fn window_row(
    ui: &mut Ui,
    selection: &mut Option<TimeSelection>,
    scope: &mut Scope,
    step: &mut RateStep,
    rate: &[RatePoint],
    actions: &mut Vec<OverviewAction>,
) {
    ui.allocate_ui_with_layout(
        vec2(ui.available_width(), WINDOW_ROW_H),
        Layout::left_to_right(Align::Center),
        |ui| {
            if let Some(sel) = *selection {
                selection_summary(ui, &sel, rate);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                segmented_w(ui, step, &RateStep::OPTIONS, STEP_W);
                ui.label(RichText::new("Step").small().color(Palette::muted()));
                if let Some(sel) = *selection {
                    selection_actions(ui, sel, selection, scope, actions);
                }
            });
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel(a: f64, b: f64) -> TimeSelection {
        TimeSelection { from: a, to: b }
    }

    #[test]
    fn request_is_sent_once_per_window_and_only_in_window_scope() {
        let mut w = WindowScope::default();
        let mut acts = Vec::new();
        w.sync(Some(&sel(2.0, 9.0)), &mut acts);
        assert!(acts.is_empty(), "scope All asks for nothing");
        w.scope = Scope::Window;
        w.sync(Some(&sel(2.0, 9.0)), &mut acts);
        w.sync(Some(&sel(2.0, 9.0)), &mut acts);
        assert_eq!(
            acts,
            vec![OverviewAction::WindowStats {
                from: 2000,
                to: 9000
            }]
        );
        w.sync(Some(&sel(3.0, 9.0)), &mut acts);
        assert_eq!(acts.len(), 2);
    }

    #[test]
    fn clearing_the_selection_returns_to_all() {
        let mut w = WindowScope {
            scope: Scope::Window,
            ..WindowScope::default()
        };
        w.sync(None, &mut Vec::new());
        assert_eq!(w.scope, Scope::All);
    }

    #[test]
    fn results_only_count_for_their_own_window() {
        let mut w = WindowScope::default();
        w.set_stats(2000, 9000, &StatsSnapshot::default());
        assert!(w.ready(Some(&sel(2.0, 9.0))).is_some());
        assert!(w.ready(Some(&sel(2.0, 10.0))).is_none());
        assert!(w.ready(None).is_none());
        w.clear();
        assert!(w.ready(Some(&sel(2.0, 9.0))).is_none());
    }
}
