//! Local Find Packet over the packet-list columns of the loaded rows (pure, tested).

use std::fmt::Write;

use regex::Regex;
use wl_model::PacketRow;

use crate::packets::table_state::TableState;

/// Matches stop being counted here ("9999+") so a one-letter query stays instant.
pub const COUNT_CAP: usize = 9_999;

pub fn row_matches(re: &Regex, r: &PacketRow, scratch: &mut String) -> bool {
    if re.is_match(&r.src)
        || re.is_match(&r.dst)
        || re.is_match(&r.protocol)
        || re.is_match(&r.info)
    {
        return true;
    }
    scratch.clear();
    let _ = write!(scratch, "{}\t{}", r.no, r.len);
    scratch.split('\t').any(|s| re.is_match(s))
}

/// Next matching visible position after (`forward`) or before `from`, wrapping around.
pub fn next(state: &TableState, re: &Regex, from: Option<usize>, forward: bool) -> Option<usize> {
    let n = state.visible();
    if n == 0 {
        return None;
    }
    let mut scratch = String::new();
    let start = match (from, forward) {
        (Some(p), true) => p + 1,
        (Some(p), false) => p + n - 1,
        (None, true) => 0,
        (None, false) => n - 1,
    };
    (0..n)
        .map(|k| {
            if forward {
                (start + k) % n
            } else {
                (start + n - k) % n
            }
        })
        .find(|&p| {
            state
                .row_at(p)
                .is_some_and(|r| row_matches(re, r, &mut scratch))
        })
}

/// `(1-based index of `at` among the matches, total matches)`, both capped at `COUNT_CAP`.
pub fn stats(state: &TableState, re: &Regex, at: usize) -> (usize, usize) {
    let (mut idx, mut total) = (0, 0);
    let mut scratch = String::new();
    for p in 0..state.visible() {
        if state
            .row_at(p)
            .is_some_and(|r| row_matches(re, r, &mut scratch))
        {
            total += 1;
            if p <= at {
                idx = total;
            }
            if total >= COUNT_CAP {
                break;
            }
        }
    }
    (idx, total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::Transport;

    fn row(no: u64, info: &str) -> PacketRow {
        PacketRow {
            no,
            epoch: 0.0,
            rel: 0.0,
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            transport: Transport::Tcp,
            protocol: "TCP".into(),
            len: 60,
            info: info.into(),
            stream: None,
        }
    }

    fn state() -> TableState {
        let mut s = TableState::default();
        s.push_rows(vec![
            row(1, "SYN"),
            row(2, "ACK"),
            row(3, "syn ack"),
            row(4, "FIN"),
        ]);
        s
    }

    #[test]
    fn next_and_prev_wrap() {
        let s = state();
        let re = Regex::new("(?i)syn").unwrap();
        assert_eq!(next(&s, &re, None, true), Some(0));
        assert_eq!(next(&s, &re, Some(0), true), Some(2));
        assert_eq!(next(&s, &re, Some(2), true), Some(0));
        assert_eq!(next(&s, &re, Some(0), false), Some(2));
        assert_eq!(next(&s, &re, None, false), Some(2));
        assert_eq!(next(&s, &Regex::new("zzz").unwrap(), None, true), None);
    }

    #[test]
    fn counts_and_numeric_columns() {
        let s = state();
        let re = Regex::new("(?i)syn").unwrap();
        assert_eq!(stats(&s, &re, 2), (2, 2));
        assert_eq!(stats(&s, &re, 1), (1, 2));
        // frame numbers and lengths are searchable too
        assert_eq!(stats(&s, &Regex::new("^4$").unwrap(), 0), (0, 1));
        assert_eq!(stats(&s, &Regex::new("^60$").unwrap(), 3), (4, 4));
    }
}
