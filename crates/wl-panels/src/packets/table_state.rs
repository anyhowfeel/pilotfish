//! Pure packet-table state: rows, sort/search index, selection. No egui here.
//! Sorting and searching only ever touch `order` (a `Vec<u32>` of row indices).

use wl_model::PacketRow;

use crate::packets::columns::Col;
use crate::packets::order;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Up,
    Down,
    PageUp(usize),
    PageDown(usize),
    Home,
    End,
}

#[derive(Default)]
pub struct TableState {
    rows: Vec<PacketRow>,
    order: Vec<u32>,
    sort: Option<(Col, bool)>,
    quick: String,
    selected: Option<u64>,
    /// Position of `selected` inside `order`, if visible.
    sel_pos: Option<usize>,
    /// `order[..sorted_len]` is sorted; entries after it are rows streamed in since, kept
    /// in arrival order so nothing visible moves while a capture runs (see `resort`).
    sorted_len: usize,
    /// True if `rows` were ever pushed with non-monotonic `no` (disables binary search).
    non_monotonic: bool,
}

/// The default egui fonts lack the right-arrow tshark puts in Info; show `->` instead.
fn normalize(mut r: PacketRow) -> PacketRow {
    if r.info.contains('\u{2192}') {
        r.info = r.info.replace('\u{2192}', "->").into();
    }
    r
}

impl TableState {
    pub fn push_rows(&mut self, rows: Vec<PacketRow>) {
        let base = self.rows.len();
        let mut prev_no = self.rows.last().map(|r| r.no);
        self.rows.extend(rows.into_iter().map(normalize));
        for r in &self.rows[base..] {
            self.non_monotonic |= prev_no.is_some_and(|p| r.no < p);
            prev_no = Some(r.no);
        }
        // Always append: with a sort active the new rows form an unsorted tail, so existing
        // rows keep their position while streaming. `resort` folds the tail in.
        let fresh = order::filter_range(&self.rows, base..self.rows.len(), &self.quick);
        self.order.extend(fresh);
        if self.sort.is_none() {
            self.sorted_len = self.order.len();
        }
    }

    pub fn clear(&mut self) {
        let old = std::mem::take(&mut self.rows);
        // Dropping millions of `Arc<str>` rows would stall a frame; do it off-thread.
        if old.len() > 50_000 {
            std::thread::spawn(move || drop(old));
        }
        *self = Self {
            quick: std::mem::take(&mut self.quick),
            sort: self.sort,
            ..Self::default()
        };
    }

    pub fn total(&self) -> usize {
        self.rows.len()
    }

    pub fn visible(&self) -> usize {
        self.order.len()
    }

    pub fn row_at(&self, pos: usize) -> Option<&PacketRow> {
        self.rows.get(*self.order.get(pos)? as usize)
    }

    pub fn row_by_no(&self, no: u64) -> Option<&PacketRow> {
        if !self.non_monotonic {
            let i = self.rows.partition_point(|r| r.no < no);
            self.rows.get(i).filter(|r| r.no == no)
        } else {
            self.rows.iter().find(|r| r.no == no)
        }
    }

    /// Position of frame `no` inside the current visible `order`, if present.
    pub fn pos_by_no(&self, no: u64) -> Option<usize> {
        if self.sort.is_none() && !self.non_monotonic {
            let pos = self
                .order
                .partition_point(|&i| self.rows[i as usize].no < no);
            self.order
                .get(pos)
                .filter(|&&i| self.rows[i as usize].no == no)
                .map(|_| pos)
        } else {
            self.order
                .iter()
                .position(|&i| self.rows[i as usize].no == no)
        }
    }

    pub fn selected(&self) -> Option<u64> {
        self.selected
    }

    pub fn selected_pos(&self) -> Option<usize> {
        self.sel_pos
    }

    pub fn select_pos(&mut self, pos: usize) -> Option<u64> {
        let no = self.row_at(pos)?.no;
        self.selected = Some(no);
        self.sel_pos = Some(pos);
        Some(no)
    }

    /// Keyboard navigation; returns the newly selected frame number.
    pub fn navigate(&mut self, nav: Nav) -> Option<u64> {
        let n = self.order.len();
        if n == 0 {
            return None;
        }
        let cur = self.sel_pos;
        let target = match (nav, cur) {
            (Nav::Home, _) => 0,
            (Nav::End, _) => n - 1,
            (Nav::Down, None) | (Nav::PageDown(_), None) => 0,
            (Nav::Up, None) | (Nav::PageUp(_), None) => n - 1,
            (Nav::Down, Some(c)) => (c + 1).min(n - 1),
            (Nav::Up, Some(c)) => c.saturating_sub(1),
            (Nav::PageDown(k), Some(c)) => (c + k).min(n - 1),
            (Nav::PageUp(k), Some(c)) => c.saturating_sub(k),
        };
        self.select_pos(target)
    }

    pub fn sort(&self) -> Option<(Col, bool)> {
        self.sort
    }

    /// Header click: ascending -> descending -> unsorted.
    pub fn cycle_sort(&mut self, col: Col) {
        self.sort = match self.sort {
            Some((c, true)) if c == col => Some((col, false)),
            Some((c, false)) if c == col => None,
            _ => Some((col, true)),
        };
        self.rebuild();
    }

    pub fn quick(&self) -> &str {
        &self.quick
    }

    pub fn set_quick(&mut self, text: &str) {
        let lower = text.trim().to_lowercase();
        if lower != self.quick {
            self.quick = lower;
            self.rebuild();
        }
    }

    /// Folds rows streamed in since the last sort into the sorted order. Called on user
    /// request and when a capture ends, never per live batch (it would shuffle visible rows).
    pub fn resort(&mut self) {
        let Some((col, asc)) = self.sort else { return };
        if self.order.len() <= self.sorted_len {
            return;
        }
        let fresh = self.order.split_off(self.sorted_len);
        order::merge_sorted(&self.rows, &mut self.order, fresh, col, asc);
        self.sorted_len = self.order.len();
        self.restore_sel_pos();
    }

    fn rebuild(&mut self) {
        self.order = order::filter_range(&self.rows, 0..self.rows.len(), &self.quick);
        if let Some((col, asc)) = self.sort {
            order::sort(&self.rows, &mut self.order, col, asc);
        }
        self.sorted_len = self.order.len();
        self.restore_sel_pos();
    }

    fn restore_sel_pos(&mut self) {
        self.sel_pos = self.selected.and_then(|no| {
            self.order
                .iter()
                .position(|&i| self.rows[i as usize].no == no)
        });
    }
}
