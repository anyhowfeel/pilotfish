//! Generic sort state for table columns.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortState<C> {
    pub col: C,
    pub desc: bool,
}

impl<C: Copy + PartialEq> SortState<C> {
    pub fn new(col: C, desc: bool) -> Self {
        Self { col, desc }
    }

    /// Clicking the active column flips direction; a new column starts descending.
    pub fn toggle(&mut self, col: C) {
        if self.col == col {
            self.desc = !self.desc;
        } else {
            self.col = col;
            self.desc = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_flips_then_switches() {
        let mut s = SortState::new(1, true);
        s.toggle(1);
        assert!(!s.desc);
        s.toggle(2);
        assert_eq!((s.col, s.desc), (2, true));
    }
}
