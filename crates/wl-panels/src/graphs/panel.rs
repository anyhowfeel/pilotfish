//! Graphs page (Wireshark I/O Graph): series editor, interval chart and time-window actions.

use std::collections::HashMap;
use std::sync::Arc;

use wl_kit::charts::{ChartConfig, DrawMode, PlotSeries, TimeSelection, io_chart};
use wl_kit::egui::{ScrollArea, Ui, vec2};
use wl_kit::theme::{Palette, spacing};
use wl_kit::widgets::empty_state;
use wl_model::{IoSeries, IoSpec};

use super::interval::Interval;
use super::metric::Metric;
use super::rows::{self, RowCtx, RowEdit, WindowSel};
use super::series::{MAX_SERIES, Preset, SeriesDef, free_color, next_color};
use super::toolbar::{ToolbarState, toolbar};
use super::window_row::{WINDOW_ROW_H, window_row};
use crate::features::{FieldCatalog, FilterAutocomplete, ValueIndex};

const CHART_MIN_H: f32 = 150.0;

/// What the app tells the panel each frame.
pub struct GraphsData<'a> {
    pub has_capture: bool,
    /// A backend pass is running for the current request.
    pub loading: bool,
    /// Capture duration so far (drives the automatic interval).
    pub duration: f64,
    /// Bucket width `series` was computed with.
    pub interval: f64,
    pub series: &'a HashMap<IoSpec, Arc<IoSeries>>,
}

/// What the panel asks the app to compute.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphsRequest {
    pub interval: f64,
    pub specs: Vec<IoSpec>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GraphsAction {
    /// Open the packets of a time window in the Packets page (display filter).
    ShowPackets(String),
}

pub struct GraphsPanel {
    defs: Vec<SeriesDef>,
    interval: Interval,
    mode: DrawMode,
    log_y: bool,
    selection: Option<TimeSelection>,
    autocomplete: FilterAutocomplete,
}

impl Default for GraphsPanel {
    fn default() -> Self {
        let p = Metric::PacketsPerSec;
        Self {
            defs: vec![
                SeriesDef::new("All packets", "", p, 0),
                SeriesDef::new("TCP", "tcp", p, 1),
                SeriesDef::new("UDP", "udp", p, 2),
            ],
            interval: Interval::Auto,
            mode: DrawMode::Area,
            log_y: false,
            selection: None,
            autocomplete: FilterAutocomplete::default(),
        }
    }
}

impl GraphsPanel {
    pub fn series(&self) -> &[SeriesDef] {
        &self.defs
    }

    pub fn selection(&self) -> Option<TimeSelection> {
        self.selection
    }

    pub fn set_selection(&mut self, s: Option<TimeSelection>) {
        self.selection = s;
    }

    pub fn set_values(&mut self, values: Arc<ValueIndex>) {
        self.autocomplete.set_values(values);
    }

    pub fn set_catalog(&mut self, catalog: Arc<FieldCatalog>) {
        self.autocomplete.set_catalog(catalog);
    }

    pub fn load_preset(&mut self, p: Preset) {
        self.defs = p.series();
    }

    /// Comma separated view options (screenshots): `line|area|bars`, `log`,
    /// `100ms|1s|10s|1min|auto`, `total|tcp|dns|http|bcast` (a preset).
    pub fn apply_spec(&mut self, spec: &str) {
        for token in spec.split(',').map(str::trim) {
            match token {
                "line" => self.mode = DrawMode::Line,
                "area" => self.mode = DrawMode::Area,
                "bars" => self.mode = DrawMode::Bars,
                "log" => self.log_y = true,
                "100ms" => self.interval = Interval::Ms100,
                "1s" => self.interval = Interval::S1,
                "10s" => self.interval = Interval::S10,
                "1min" => self.interval = Interval::M1,
                "auto" => self.interval = Interval::Auto,
                "total" => self.load_preset(Preset::Total),
                "tcp" => self.load_preset(Preset::TcpRetransmissions),
                "dns" => self.load_preset(Preset::Dns),
                "http" => self.load_preset(Preset::HttpErrors),
                "bcast" => self.load_preset(Preset::BroadcastMulticast),
                _ => {}
            }
        }
    }

    pub fn request(&self, duration: f64) -> GraphsRequest {
        let mut specs: Vec<IoSpec> = Vec::new();
        for s in self.defs.iter().filter(|d| d.visible).map(SeriesDef::spec) {
            if !specs.contains(&s) {
                specs.push(s);
            }
        }
        GraphsRequest {
            interval: self.interval.seconds(duration),
            specs,
        }
    }

    pub fn ui(&mut self, ui: &mut Ui, data: &GraphsData<'_>) -> Vec<GraphsAction> {
        let mut actions = Vec::new();
        if !data.has_capture {
            empty_state(
                ui,
                "~",
                "No capture to graph",
                "Open a capture file or start a live capture to draw I/O graphs.",
            );
            return actions;
        }
        // The chart takes the height the toolbar and editor leave; on a short window everything
        // scrolls instead of squeezing the chart below `CHART_MIN_H`.
        let page_h = ui.available_height();
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = spacing::SM;
                let top = ui.cursor().top();
                let resolved = self.interval.seconds(data.duration);
                let picked = toolbar(
                    ui,
                    ToolbarState {
                        interval: &mut self.interval,
                        mode: &mut self.mode,
                        log_y: &mut self.log_y,
                        resolved,
                        busy: data.loading,
                        can_add: self.defs.len() < MAX_SERIES,
                    },
                );
                if let Some(p) = picked.preset {
                    self.load_preset(p);
                }
                if picked.add {
                    let name = format!("Series {}", self.defs.len() + 1);
                    let c = free_color(&self.defs);
                    self.defs
                        .push(SeriesDef::new(&name, "", Metric::PacketsPerSec, c));
                }
                self.editor(ui, data);
                let used = ui.cursor().top() - top;
                let chart_h = (page_h - used - WINDOW_ROW_H - spacing::SM).max(CHART_MIN_H);
                self.chart(ui, data, chart_h);
                window_row(ui, &mut self.selection, &mut actions);
            });
        actions
    }

    fn editor(&mut self, ui: &mut Ui, data: &GraphsData<'_>) {
        ui.spacing_mut().item_spacing.y = spacing::XS;
        rows::header(ui, self.selection.is_some());
        let window = self.selection.map(|s| WindowSel {
            from: s.from,
            to: s.to,
            interval: data.interval,
        });
        let mut remove = None;
        for i in 0..self.defs.len() {
            let spec = self.defs[i].spec();
            let cx = RowCtx {
                index: i,
                data: data.series.get(&spec),
                window,
                autocomplete: &mut self.autocomplete,
            };
            match rows::row(ui, &mut self.defs[i], cx) {
                RowEdit::Remove => remove = Some(i),
                RowEdit::CycleColor => self.defs[i].color = next_color(&self.defs, i),
                RowEdit::None => {}
            }
        }
        if let Some(i) = remove {
            self.defs.remove(i);
        }
        ui.spacing_mut().item_spacing.y = spacing::SM;
    }

    fn chart(&mut self, ui: &mut Ui, data: &GraphsData<'_>, height: f32) {
        let values: Vec<(usize, Vec<f64>)> = self
            .defs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.visible)
            .filter_map(|(i, d)| {
                let s = data.series.get(&d.spec()).filter(|s| s.error.is_none())?;
                Some((i, d.metric.values(s, data.interval)))
            })
            .collect();
        if values.is_empty() {
            ui.allocate_ui(vec2(ui.available_width(), height), |ui| {
                let (title, hint) = if data.loading {
                    ("Computing graph\u{2026}", "tshark is reading the capture.")
                } else {
                    ("Nothing to draw", "Show at least one valid series.")
                };
                empty_state(ui, "~", title, hint);
            });
            return;
        }
        let plot: Vec<PlotSeries<'_>> = values
            .iter()
            .map(|(i, v)| PlotSeries {
                name: self.defs[*i].display_name(),
                color: Palette::series(self.defs[*i].color),
                unit: self.defs[*i].metric.unit(),
                values: v,
            })
            .collect();
        let cfg = ChartConfig {
            interval: data.interval,
            mode: self.mode,
            log_y: self.log_y,
            height,
            duration: data.duration,
        };
        io_chart(ui, &plot, &cfg, &mut self.selection);
    }
}
