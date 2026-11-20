//! Find Packet state machine: runs the plan (local scan or backend request), steps through
//! matches and selects them in the table. No egui here.

use wl_model::FrameFields;

use crate::packets::actions::PacketsAction;
use crate::packets::find_local;
use crate::packets::find_query::{FindQuery, Plan, plan};
use crate::packets::table::PacketTable;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Idle,
    Searching,
    /// 1-based index of the current match (0 = none selected yet) and the total.
    Found {
        index: usize,
        total: usize,
        capped: bool,
    },
    NotFound,
    Error(String),
}

struct Hits {
    filter: String,
    /// `table.total()` when searched: new rows make the result stale.
    total_rows: usize,
    frames: Vec<u64>,
}

#[derive(Default)]
pub struct FindState {
    pub open: bool,
    pub query: FindQuery,
    pub status: Status,
    /// The bar grabs keyboard focus on the next frame.
    pub focus: bool,
    hits: Option<Hits>,
    /// (request id, filter, rows at request time, direction to jump when it arrives)
    pending: Option<(u64, String, usize, bool)>,
    pub(super) next_id: u64,
}

/// Index into ascending `frames` of the match after/before `from` (wrapping).
pub fn pick(frames: &[u64], from: Option<u64>, forward: bool) -> Option<usize> {
    let n = frames.len();
    if n == 0 {
        return None;
    }
    let after = from.map(|f| frames.partition_point(|&x| x <= f));
    let before = from.map(|f| frames.partition_point(|&x| x < f));
    Some(match (forward, after, before) {
        (true, Some(a), _) => a % n,
        (true, None, _) => 0,
        (false, _, Some(b)) => (b + n - 1) % n,
        (false, _, None) => n - 1,
    })
}

impl FindState {
    pub fn open(&mut self) {
        self.open = true;
        self.focus = true;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.pending = None;
    }

    /// The query changed: cached results no longer apply.
    pub fn invalidate(&mut self) {
        self.hits = None;
        self.pending = None;
        self.status = Status::Idle;
    }

    /// Jump to the next / previous match (running the search first if needed).
    pub fn step(&mut self, forward: bool, table: &mut PacketTable, out: &mut Vec<PacketsAction>) {
        match plan(&self.query) {
            Plan::Empty => self.status = Status::Idle,
            Plan::Invalid(e) => self.status = Status::Error(e),
            Plan::Local(re) => {
                let from = table.state.selected_pos();
                match find_local::next(&table.state, &re, from, forward) {
                    Some(p) => {
                        let (idx, total) = find_local::stats(&table.state, &re, p);
                        self.status = Status::Found {
                            index: idx,
                            total,
                            capped: total >= find_local::COUNT_CAP,
                        };
                        if let Some(no) = table.state.row_at(p).map(|r| r.no) {
                            self.select(no, table, out);
                        }
                    }
                    None => self.status = Status::NotFound,
                }
            }
            Plan::Backend(filter) => {
                let fresh = self
                    .hits
                    .as_ref()
                    .is_some_and(|h| h.filter == filter && h.total_rows == table.state.total());
                if fresh {
                    self.jump(forward, table, out);
                } else {
                    self.next_id += 1;
                    let total = table.state.total();
                    self.pending = Some((self.next_id, filter.clone(), total, forward));
                    self.status = Status::Searching;
                    out.push(PacketsAction::RunFields {
                        id: self.next_id,
                        filter,
                        fields: Vec::new(),
                    });
                }
            }
        }
    }

    /// Backend answer for request `id` (ignored when stale).
    pub fn on_result(
        &mut self,
        id: u64,
        res: &Result<Vec<FrameFields>, String>,
        table: &mut PacketTable,
        out: &mut Vec<PacketsAction>,
    ) -> bool {
        let Some((_, filter, total_rows, forward)) = self.pending.take_if(|p| p.0 == id) else {
            return false;
        };
        match res {
            Ok(rows) => {
                let mut frames: Vec<u64> = rows.iter().map(|r| r.0).collect();
                frames.sort_unstable();
                self.hits = Some(Hits {
                    filter,
                    total_rows,
                    frames,
                });
                self.jump(forward, table, out);
            }
            Err(e) => self.status = Status::Error(e.clone()),
        }
        true
    }

    fn jump(&mut self, forward: bool, table: &mut PacketTable, out: &mut Vec<PacketsAction>) {
        let Some(h) = &self.hits else { return };
        let total = h.frames.len();
        match pick(&h.frames, table.selected(), forward) {
            None => self.status = Status::NotFound,
            Some(i) => {
                let no = h.frames[i];
                self.status = Status::Found {
                    index: i + 1,
                    total,
                    capped: false,
                };
                self.select(no, table, out);
            }
        }
    }

    fn select(&mut self, no: u64, table: &mut PacketTable, out: &mut Vec<PacketsAction>) {
        if table.select_frame(no) {
            out.push(PacketsAction::Select(no));
        } else {
            self.status = Status::Error(format!("Frame {no} is hidden by the current filter"));
        }
    }
}

#[cfg(test)]
#[path = "find_state_tests.rs"]
mod tests;
