//! Headless typing tests: popup contents, Enter accepting a suggestion, cursor placement.
use std::sync::Arc;

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, vec2};
use wl_model::{HostStat, StatsSnapshot};

use super::autocomplete::{FilterAutocomplete, ValueIndex};

struct Field {
    ctx: egui::Context,
    text: String,
    auto: FilterAutocomplete,
    id: egui::Id,
}

impl Field {
    fn new() -> Self {
        let stats = StatsSnapshot {
            hosts: ["10.0.0.9", "10.0.1.7", "192.168.1.5"]
                .map(|a| HostStat {
                    addr: a.into(),
                    ..Default::default()
                })
                .to_vec(),
            ..Default::default()
        };
        let mut auto = FilterAutocomplete::default();
        auto.set_values(Arc::new(ValueIndex::from_stats(&stats)));
        Self {
            ctx: egui::Context::default(),
            text: String::new(),
            auto,
            id: egui::Id::NULL.with("filter_under_test"),
        }
    }

    /// One frame; returns whether the autocomplete rewrote the text.
    fn frame(&mut self, events: Vec<Event>) -> bool {
        let raw = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(900.0, 400.0))),
            events,
            ..Default::default()
        };
        let (text, auto, id) = (&mut self.text, &mut self.auto, self.id);
        let mut changed = false;
        self.ctx
            .run_ui(raw, |ui| {
                let resp = ui.add(egui::TextEdit::singleline(text).id(id));
                resp.request_focus();
                if !resp.changed() {
                    changed = auto.ui(ui, text, &resp);
                }
            })
            .drop_without_applying_deltas();
        changed
    }

    fn type_text(&mut self, s: &str) {
        self.frame(vec![]);
        self.frame(vec![Event::Text(s.to_owned())]);
        self.frame(vec![]);
    }

    fn press(&mut self, key: Key) -> bool {
        self.frame(vec![Event::Key {
            key,
            physical_key: Some(key),
            pressed: true,
            repeat: false,
            modifiers: Modifiers::NONE,
        }])
    }

    fn cursor(&self) -> usize {
        egui::TextEdit::load_state(&self.ctx, self.id)
            .and_then(|s| s.cursor.char_range())
            .map_or(usize::MAX, |r| r.primary.index.into())
    }
}

#[test]
fn a_value_position_opens_the_popup_with_hosts() {
    let mut f = Field::new();
    f.type_text("ip.addr==10.");
    assert!(f.auto.is_open(), "hosts starting with 10. must be offered");
}

#[test]
fn a_field_without_known_values_stays_quiet_after_an_operator() {
    let mut f = Field::new();
    f.type_text("http.host==ex");
    assert!(!f.auto.is_open(), "no field names after an operator");
}

#[test]
fn enter_accepts_the_suggestion_and_puts_the_cursor_after_it() {
    let mut f = Field::new();
    f.type_text("ip.addr==10.");
    assert!(
        f.press(Key::Enter),
        "Enter must accept the first suggestion"
    );
    assert_eq!(f.text, "ip.addr==10.0.0.9");
    assert!(
        f.auto.take_enter(),
        "the caller must not also apply the filter"
    );
    f.frame(vec![]);
    assert_eq!(
        f.cursor(),
        f.text.chars().count(),
        "cursor at the end of the inserted value"
    );
}

#[test]
fn completing_a_field_moves_the_cursor_to_its_end() {
    let mut f = Field::new();
    f.type_text("ip.add");
    assert!(f.press(Key::Enter));
    assert_eq!(f.text, "ip.addr");
    f.frame(vec![]);
    assert_eq!(f.cursor(), 7);
}
