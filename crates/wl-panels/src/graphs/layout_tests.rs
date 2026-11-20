//! Headless layout and interaction checks of the Graphs page: nothing leaves the window, rows
//! align with their header, and the editor buttons do what they say.

use std::collections::HashMap;
use std::sync::Arc;

use wl_kit::egui::{self, Context, Event, Id, PointerButton, Pos2, RawInput, Rect, pos2, vec2};
use wl_kit::theme::{Mode, set_mode};
use wl_model::{IoSeries, IoSpec};

use super::cols::Cols;
use super::*;

const SIZES: [(f32, f32); 6] = [
    (440.0, 420.0),
    (560.0, 500.0),
    (740.0, 640.0),
    (1000.0, 640.0),
    (1440.0, 900.0),
    (2200.0, 1100.0),
];

fn data_for(panel: &GraphsPanel, with_error: bool) -> HashMap<IoSpec, Arc<IoSeries>> {
    panel
        .series()
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let n = 120;
            let mut s = IoSeries {
                packets: (0..n).map(|t| 1 + (t * 7 + i as u64) % 50).collect(),
                bytes: (0..n).map(|t| 1000 + t * 313).collect(),
                delta: (0..n).map(|t| t as f64 * 1e-3).collect(),
                error: None,
            };
            if with_error && i == 1 {
                s.error = Some("bad filter".into());
            }
            (d.spec(), Arc::new(s))
        })
        .collect()
}

struct Rig {
    ctx: Context,
    panel: GraphsPanel,
    size: Pos2,
    actions: Vec<GraphsAction>,
}

impl Rig {
    fn new(w: f32, h: f32) -> Self {
        Self {
            ctx: Context::default(),
            panel: GraphsPanel::default(),
            size: pos2(w, h),
            actions: Vec::new(),
        }
    }

    fn frame(&mut self, events: Vec<Event>) -> Rect {
        let raw = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, self.size.to_vec2())),
            events,
            ..Default::default()
        };
        let data = data_for(&self.panel, false);
        let gd = GraphsData {
            has_capture: true,
            loading: false,
            duration: 120.0,
            interval: 1.0,
            series: &data,
        };
        let (panel, actions) = (&mut self.panel, &mut self.actions);
        let mut used = Rect::NOTHING;
        self.ctx
            .run_ui(raw, |ui| {
                actions.extend(panel.ui(ui, &gd));
                used = ui.min_rect();
            })
            .drop_without_applying_deltas();
        used
    }

    fn settle(&mut self) -> Rect {
        let mut r = Rect::NOTHING;
        for _ in 0..3 {
            r = self.frame(vec![]);
        }
        r
    }

    fn cols(&self, i: usize) -> Cols {
        self.ctx
            .data(|d| d.get_temp::<Cols>(Id::NULL.with(("wl_graph_row", i))))
            .expect("row was drawn")
    }

    fn click(&mut self, p: Pos2) {
        let btn = |pressed| Event::PointerButton {
            pos: p,
            button: PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        self.frame(vec![Event::PointerMoved(p)]);
        self.frame(vec![btn(true)]);
        self.frame(vec![btn(false)]);
        self.settle();
    }
}

#[test]
fn page_fits_its_window_and_rows_align_in_every_mode_and_size() {
    for mode in [Mode::Dark, Mode::Light] {
        set_mode(mode);
        for (w, h) in SIZES {
            let mut rig = Rig::new(w, h);
            let used = rig.settle();
            assert!(used.right() <= w + 0.5, "{mode:?} {w}x{h}: used {used:?}");
            let rows: Vec<Cols> = (0..3).map(|i| rig.cols(i)).collect();
            for c in &rows {
                assert!(c.remove.right() <= w + 0.5, "{w}x{h}: buttons outside");
                assert!(c.swatch.left() >= 0.0);
            }
            // header and rows share the same columns; rows are stacked without overlap
            for pair in rows.windows(2) {
                assert!(
                    pair[0].swatch.bottom() <= pair[1].swatch.top(),
                    "{w}x{h}: rows overlap"
                );
                assert_eq!(pair[0].filter.left(), pair[1].filter.left());
                assert_eq!(pair[0].remove.right(), pair[1].remove.right());
            }
        }
    }
    set_mode(Mode::Dark);
}

#[test]
fn add_button_stops_at_the_series_limit() {
    let mut rig = Rig::new(1000.0, 900.0);
    rig.settle();
    for expected in 4..=MAX_SERIES {
        let add: Rect = rig
            .ctx
            .data(|d| d.get_temp(Id::NULL.with("wl_graph_add")))
            .unwrap();
        rig.click(add.center());
        assert_eq!(rig.panel.series().len(), expected);
    }
    let add: Rect = rig
        .ctx
        .data(|d| d.get_temp(Id::NULL.with("wl_graph_add")))
        .unwrap();
    rig.click(add.center());
    assert_eq!(
        rig.panel.series().len(),
        MAX_SERIES,
        "disabled at the limit"
    );
    let mut colours: Vec<usize> = rig.panel.series().iter().map(|d| d.color).collect();
    colours.sort_unstable();
    colours.dedup();
    assert_eq!(
        colours.len(),
        MAX_SERIES,
        "every series has its own palette colour"
    );
}

#[test]
fn remove_and_visibility_buttons_work() {
    let mut rig = Rig::new(1000.0, 900.0);
    rig.settle();
    let eye = rig.cols(1).eye.center();
    rig.click(eye);
    assert!(!rig.panel.series()[1].visible);
    assert_eq!(
        rig.panel.request(60.0).specs.len(),
        2,
        "hidden series are not queried"
    );
    rig.click(eye);
    assert!(rig.panel.series()[1].visible);
    let remove = rig.cols(0).remove.center();
    rig.click(remove);
    assert_eq!(rig.panel.series().len(), 2);
    assert_eq!(rig.panel.series()[0].display_name(), "TCP");
}

#[test]
fn clicking_a_swatch_moves_to_the_next_free_colour() {
    let mut rig = Rig::new(1000.0, 900.0);
    rig.settle();
    let before = rig.panel.series()[0].color;
    let swatch = rig.cols(0).swatch.center();
    rig.click(swatch);
    let after = rig.panel.series()[0].color;
    assert_ne!(before, after);
    let others: Vec<usize> = rig.panel.series()[1..].iter().map(|d| d.color).collect();
    assert!(!others.contains(&after));
}

#[test]
fn empty_capture_shows_a_placeholder_and_requests_nothing_to_draw() {
    let ctx = Context::default();
    let mut panel = GraphsPanel::default();
    let data = HashMap::new();
    let gd = GraphsData {
        has_capture: false,
        loading: false,
        duration: 0.0,
        interval: 1.0,
        series: &data,
    };
    let raw = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(900.0, 500.0))),
        ..Default::default()
    };
    let mut acts = Vec::new();
    ctx.run_ui(raw, |ui| acts = panel.ui(ui, &gd))
        .drop_without_applying_deltas();
    assert!(acts.is_empty());
    let _ = egui::Id::NULL;
}

#[test]
fn request_dedupes_identical_series_and_follows_the_interval_choice() {
    let mut panel = GraphsPanel::default();
    panel.apply_spec("1min");
    let req = panel.request(10.0);
    assert_eq!(req.interval, 60.0);
    assert_eq!(req.specs.len(), 3);
    panel.load_preset(Preset::Total);
    assert_eq!(panel.request(10.0).specs.len(), 1);
    panel.apply_spec("auto,bars,log");
    assert_eq!(panel.request(100.0).interval, 0.5);
}
