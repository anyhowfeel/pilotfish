//! Zooming into an XY chart with a box and getting back to the whole data.

use eframe::egui::{self, Color32, Context, Event, PointerButton, Pos2, Rect, Shape, pos2, vec2};
use wl_kit::charts::{SeriesStyle, XySeries, xy_chart, xy_chart_with_reset};

fn series() -> Vec<XySeries> {
    let pts: Vec<[f64; 2]> = (0..40)
        .map(|i| [f64::from(i), f64::from((i * 7) % 23)])
        .collect();
    vec![XySeries::new(
        "Window",
        Color32::LIGHT_BLUE,
        SeriesStyle::Line,
        pts,
    )]
}

struct Page {
    ctx: Context,
    reset: bool,
    path: Vec<Pos2>,
}

impl Page {
    fn new() -> Self {
        Self {
            ctx: Context::default(),
            reset: false,
            path: Vec::new(),
        }
    }

    fn frame(&mut self, events: Vec<Event>) {
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1000.0, 600.0))),
            events,
            ..Default::default()
        };
        let reset = std::mem::take(&mut self.reset);
        let s = series();
        let mut out = self.ctx.run_ui(input, |ui| {
            if reset {
                xy_chart_with_reset(ui, "zoom", &s, &|v| format!("{v:.0}"), 400.0, true);
            } else {
                xy_chart(ui, "zoom", &s, &|v| format!("{v:.0}"), 400.0);
            }
        });
        let shapes = std::mem::take(&mut out.shapes);
        out.drop_without_applying_deltas();
        let mut best: Vec<Pos2> = Vec::new();
        fn walk(s: &Shape, best: &mut Vec<Pos2>) {
            match s {
                Shape::Vec(v) => v.iter().for_each(|x| walk(x, best)),
                Shape::Path(p) if p.points.len() > best.len() && p.fill == Color32::TRANSPARENT => {
                    *best = p.points.clone();
                }
                _ => {}
            }
        }
        shapes.iter().for_each(|c| walk(&c.shape, &mut best));
        self.path = best;
    }

    fn settle(&mut self) {
        for _ in 0..4 {
            self.frame(vec![]);
        }
    }

    fn button(pos: Pos2, pressed: bool) -> Event {
        Event::PointerButton {
            pos,
            button: PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        }
    }

    fn box_zoom(&mut self, from: Pos2, to: Pos2) {
        self.frame(vec![Event::PointerMoved(from)]);
        self.frame(vec![Self::button(from, true)]);
        self.frame(vec![Event::PointerMoved(pos2(
            (from.x + to.x) / 2.0,
            (from.y + to.y) / 2.0,
        ))]);
        self.frame(vec![Event::PointerMoved(to)]);
        self.frame(vec![Self::button(to, false)]);
        self.settle();
    }

    fn double_click(&mut self, at: Pos2) {
        self.frame(vec![Event::PointerMoved(at)]);
        for _ in 0..2 {
            self.frame(vec![Self::button(at, true)]);
            self.frame(vec![Self::button(at, false)]);
        }
        self.settle();
    }
}

fn same(a: &[Pos2], b: &[Pos2]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(p, q)| (*p - *q).length() < 0.5)
}

#[test]
fn a_box_zoom_changes_the_view_and_the_reset_brings_the_whole_data_back() {
    let mut page = Page::new();
    page.settle();
    let whole = page.path.clone();
    assert!(whole.len() >= 40, "the series is a path: {}", whole.len());

    page.box_zoom(pos2(300.0, 150.0), pos2(500.0, 300.0));
    assert!(!same(&page.path, &whole), "the box zoom moved the data");

    page.reset = true;
    page.frame(vec![]);
    page.settle();
    assert!(
        same(&page.path, &whole),
        "the reset brought the whole data back"
    );
}

#[test]
fn a_double_click_on_the_chart_resets_a_box_zoom() {
    let mut page = Page::new();
    page.settle();
    let whole = page.path.clone();
    page.box_zoom(pos2(300.0, 150.0), pos2(500.0, 300.0));
    assert!(!same(&page.path, &whole));
    page.double_click(pos2(600.0, 250.0));
    assert!(
        same(&page.path, &whole),
        "the double click did not bring the whole data back"
    );
}
