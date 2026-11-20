//! Selection, follow-live and keyboard navigation of the packet table.

use eframe::egui::{Key, Ui};

use crate::packets::table::PacketTable;
use crate::packets::table_state::Nav;

impl PacketTable {
    pub fn selected(&self) -> Option<u64> {
        self.state.selected()
    }

    pub fn set_follow(&mut self, follow: bool) {
        self.follow = follow;
        self.follow_armed = follow;
        self.left_bottom = false;
    }

    pub fn is_following(&self) -> bool {
        self.follow
    }

    /// Re-engages follow-live when the user scrolls back down to the bottom of the list.
    pub(crate) fn update_follow_from_scroll(
        &mut self,
        scrolled_up: bool,
        scrolled_down: bool,
        saw_last_row: bool,
        has_rows: bool,
    ) {
        if scrolled_up && self.follow {
            self.follow = false;
            return;
        }
        if self.follow_armed && !self.follow && has_rows {
            if !saw_last_row {
                self.left_bottom = true;
            } else if scrolled_down || self.left_bottom {
                self.follow = true;
                self.left_bottom = false;
            }
        }
    }

    /// Programmatically selects frame `no` and schedules scrolling it into view.
    pub fn select_frame(&mut self, no: u64) -> bool {
        let Some(pos) = self.state.pos_by_no(no) else {
            return false;
        };
        if self.state.select_pos(pos) == Some(no) {
            self.follow = false;
            self.scroll_to_selected = true;
            true
        } else {
            false
        }
    }

    pub(super) fn handle_keys(&mut self, ui: &Ui, page: usize) -> Option<u64> {
        if !self.focused || ui.ctx().egui_wants_keyboard_input() {
            return None;
        }
        let keys = [
            (Key::ArrowUp, Nav::Up),
            (Key::ArrowDown, Nav::Down),
            (Key::PageUp, Nav::PageUp(page)),
            (Key::PageDown, Nav::PageDown(page)),
            (Key::Home, Nav::Home),
            (Key::End, Nav::End),
        ];
        let nav = ui.input(|i| {
            keys.into_iter()
                .find(|(k, _)| i.key_pressed(*k))
                .map(|p| p.1)
        })?;
        self.follow = nav == Nav::End && self.follow_armed;
        self.state.navigate(nav)
    }
}
