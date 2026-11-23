//! The one empty state for a feature that only Wireshark can provide.

use wl_kit::egui::Ui;
use wl_kit::widgets::empty_state;
use wl_model::{NEEDS_HINT, needs_title};

pub fn needs_wireshark(ui: &mut Ui, feature: &str) {
    empty_state(ui, "i", &needs_title(feature), NEEDS_HINT);
}
