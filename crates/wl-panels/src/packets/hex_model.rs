//! Pure hex-dump geometry and formatting. All x positions are in character cells,
//! so a monospace font makes every column line up at any scale.

use std::fmt::Write;
use std::ops::Range;

pub const ROW_BYTES: usize = 16;
/// Characters: "00000000" + 2 gap.
pub const HEX_START: f32 = 10.0;
/// Hex block is 16*3 - 1 + 1 (group gap) = 48 chars, then 2 gap.
pub const ASCII_START: f32 = HEX_START + 48.0 + 2.0;
pub const TOTAL_CHARS: f32 = ASCII_START + ROW_BYTES as f32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    Hex,
    Ascii,
}

pub fn rows(len: usize) -> usize {
    len.div_ceil(ROW_BYTES)
}

/// Char-cell x of the first hex digit of byte column `i` (0..16).
pub fn hex_x(i: usize) -> f32 {
    HEX_START + (i * 3 + usize::from(i >= 8)) as f32
}

pub fn ascii_x(i: usize) -> f32 {
    ASCII_START + i as f32
}

/// Maps a char-cell x (relative to row start) to a byte column and zone.
pub fn byte_at(cell_x: f32) -> Option<(usize, Zone)> {
    if cell_x >= ASCII_START {
        let i = (cell_x - ASCII_START) as usize;
        return (i < ROW_BYTES).then_some((i, Zone::Ascii));
    }
    (0..ROW_BYTES)
        .find(|&i| cell_x >= hex_x(i) - 0.5 && cell_x < hex_x(i) + 2.5)
        .map(|i| (i, Zone::Hex))
}

/// Converts a `DetailNode::range` `(start, end_exclusive)` to a clamped byte range.
pub fn span(range: Option<(usize, usize)>, len: usize) -> Option<Range<usize>> {
    let (s, e) = range?;
    let e = e.min(len);
    (s < e).then_some(s..e)
}

/// Columns of `row` covered by `sel`, as a contiguous `a..b`.
pub fn cols_in_row(row: usize, sel: &Range<usize>, len: usize) -> Option<Range<usize>> {
    let base = row * ROW_BYTES;
    let end = (base + ROW_BYTES).min(len);
    let (s, e) = (sel.start.max(base), sel.end.min(end));
    (s < e).then(|| s - base..e - base)
}

pub fn offset_text(row: usize, out: &mut String) {
    out.clear();
    let _ = write!(out, "{:08x}", row * ROW_BYTES);
}

/// "00 01 .. 07  08 .. 0f" (short rows are not padded; the ascii column is positioned by cells).
pub fn hex_text(bytes: &[u8], out: &mut String) {
    out.clear();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
            if i == 8 {
                out.push(' ');
            }
        }
        let _ = write!(out, "{b:02x}");
    }
}

pub fn ascii_text(bytes: &[u8], out: &mut String) {
    out.clear();
    out.extend(bytes.iter().map(|&b| {
        if (0x20..0x7f).contains(&b) {
            b as char
        } else {
            '.'
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_is_consistent_with_text() {
        let mut s = String::new();
        hex_text(&[0u8; 16], &mut s);
        assert_eq!(s.len(), 48);
        // byte 8 starts after the double space.
        assert_eq!(
            s.char_indices()
                .filter(|(_, c)| *c == '0')
                .nth(16)
                .map(|p| p.0),
            Some(25)
        );
        assert_eq!(hex_x(8) - HEX_START, 25.0);
        assert_eq!(hex_x(15) - HEX_START + 2.0, 48.0);
    }

    #[test]
    fn hit_testing() {
        assert_eq!(byte_at(hex_x(3) + 1.0), Some((3, Zone::Hex)));
        assert_eq!(byte_at(hex_x(9)), Some((9, Zone::Hex)));
        assert_eq!(byte_at(ascii_x(15) + 0.4), Some((15, Zone::Ascii)));
        assert_eq!(byte_at(ASCII_START + 16.5), None);
        assert_eq!(byte_at(1.0), None);
    }

    #[test]
    fn spans_and_row_cols() {
        assert_eq!(span(Some((2, 100)), 10), Some(2..10));
        assert_eq!(span(Some((5, 5)), 10), None);
        assert_eq!(span(None, 10), None);
        let sel = 14..20;
        assert_eq!(cols_in_row(0, &sel, 32), Some(14..16));
        assert_eq!(cols_in_row(1, &sel, 32), Some(0..4));
        assert_eq!(cols_in_row(2, &sel, 32), None);
        assert_eq!(rows(33), 3);
    }

    #[test]
    fn ascii_masks_control_bytes() {
        let mut s = String::new();
        ascii_text(&[0x41, 0x00, 0x7f, 0x7e], &mut s);
        assert_eq!(s, "A..~");
    }
}
