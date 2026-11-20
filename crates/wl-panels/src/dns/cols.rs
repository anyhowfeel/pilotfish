//! Responsive column set of the DNS table.

use wl_kit::table::TableCols;

use super::model::SortCol;

pub(super) const FRAME_W: f32 = 60.0;
pub(super) const TIME_W: f32 = 72.0;
pub(super) const ADDR_W: f32 = 112.0;
pub(super) const TYPE_W: f32 = 64.0;
pub const RCODE_W: f32 = 104.0;
pub(super) const RTT_W: f32 = 76.0;
pub(super) const FLAG_W: f32 = 56.0;
pub(super) const FLEX_MIN: f32 = 120.0;
/// Widths from which the optional columns appear.
pub(super) const BASIC_FROM: f32 = 600.0;
pub(super) const ANSWERS_FROM: f32 = 720.0;
pub(super) const SERVER_FROM: f32 = 860.0;
pub(super) const WIDE_FROM: f32 = 1000.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cols {
    /// Client and record type (dropped on very narrow pages).
    pub basic: bool,
    pub answers: bool,
    pub server: bool,
    /// Frame number and retransmission flag.
    pub wide: bool,
}

impl Cols {
    pub fn for_width(w: f32) -> Self {
        Self {
            basic: w >= BASIC_FROM,
            answers: w >= ANSWERS_FROM,
            server: w >= SERVER_FROM,
            wide: w >= WIDE_FROM,
        }
    }

    #[cfg(test)]
    pub(super) fn count(self) -> usize {
        4 + 2 * usize::from(self.basic)
            + usize::from(self.answers)
            + usize::from(self.server)
            + 2 * usize::from(self.wide)
    }

    #[cfg(test)]
    pub fn min_width(self) -> f32 {
        use wl_kit::theme::spacing;
        let fixed = TIME_W + RCODE_W + RTT_W;
        let opt = [
            (self.basic, ADDR_W + TYPE_W),
            (self.server, ADDR_W),
            (self.wide, FRAME_W + FLAG_W),
            (self.answers, FLEX_MIN),
        ];
        let extra: f32 = opt.iter().filter(|(on, _)| *on).map(|(_, w)| w).sum();
        fixed + extra + FLEX_MIN + spacing::SM * (self.count() as f32 - 1.0)
    }

    pub(super) fn build(self) -> TableCols {
        let mut t = TableCols::new();
        if self.wide {
            t = t.num(FRAME_W);
        }
        t = t.num(TIME_W);
        if self.basic {
            t = t.fixed(ADDR_W);
        }
        if self.server {
            t = t.fixed(ADDR_W);
        }
        t = t.flex(FLEX_MIN);
        if self.basic {
            t = t.fixed(TYPE_W);
        }
        t = t.fixed(RCODE_W);
        if self.answers {
            t = t.flex(FLEX_MIN);
        }
        t = t.num(RTT_W);
        if self.wide {
            t = t.fixed(FLAG_W);
        }
        t
    }

    pub(super) fn heads(self) -> Vec<(&'static str, Option<SortCol>, bool)> {
        let mut h = Vec::new();
        if self.wide {
            h.push(("Frame", Some(SortCol::Frame), true));
        }
        h.push(("Time", Some(SortCol::Time), true));
        if self.basic {
            h.push(("Client", Some(SortCol::Client), false));
        }
        if self.server {
            h.push(("Server", Some(SortCol::Server), false));
        }
        h.push(("Query", Some(SortCol::Name), false));
        if self.basic {
            h.push(("Type", Some(SortCol::Type), false));
        }
        h.push(("Response", Some(SortCol::Rcode), false));
        if self.answers {
            h.push(("Answers", None, false));
        }
        h.push(("RTT", Some(SortCol::Rtt), true));
        if self.wide {
            h.push(("Flags", None, false));
        }
        h
    }
}
