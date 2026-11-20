//! Pure responsive layout of the dashboard: KPI cells first, then wide/narrow cards.

use wl_kit::egui::{Rect, pos2, vec2};
use wl_kit::theme::spacing::LG;

pub const KPI_COUNT: usize = 6;
pub const KPI_H: f32 = 98.0;
pub const CARD_H: f32 = 340.0;
const GAP: f32 = LG;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Card {
    Kpi(usize),
    Throughput,
    Protocols,
    Talkers,
    Services,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Placed {
    pub card: Card,
    /// Relative to the grid origin (top-left).
    pub rect: Rect,
}

pub fn card_columns(width: f32) -> usize {
    match width {
        w if w < 760.0 => 1,
        w if w < 1180.0 => 2,
        _ => 3,
    }
}

fn kpi_columns(width: f32) -> usize {
    match width {
        w if w < 560.0 => 2,
        w if w < 1000.0 => 3,
        _ => KPI_COUNT,
    }
}

/// Greedy row packing; the last card of each row stretches over the free columns.
pub fn pack(spans: &[usize], cols: usize) -> Vec<Vec<(usize, usize)>> {
    let mut rows: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut used = 0;
    for (i, &s) in spans.iter().enumerate() {
        let s = s.clamp(1, cols);
        if used + s > cols || rows.is_empty() {
            rows.push(Vec::new());
            used = 0;
        }
        rows.last_mut().expect("row pushed").push((i, s));
        used += s;
    }
    for row in &mut rows {
        let sum: usize = row.iter().map(|c| c.1).sum();
        if let Some(last) = row.last_mut() {
            last.1 += cols - sum;
        }
    }
    rows
}

fn place_rows(
    out: &mut Vec<Placed>,
    cards: &[Card],
    rows: &[Vec<(usize, usize)>],
    cols: usize,
    width: f32,
    top: f32,
    h: f32,
) -> f32 {
    let col_w = (width - GAP * (cols as f32 - 1.0)) / cols as f32;
    let mut y = top;
    for row in rows {
        let mut c = 0;
        for &(i, span) in row {
            let x = c as f32 * (col_w + GAP);
            let w = col_w * span as f32 + GAP * (span as f32 - 1.0);
            out.push(Placed {
                card: cards[i],
                rect: Rect::from_min_size(pos2(x, y), vec2(w, h)),
            });
            c += span;
        }
        y += h + GAP;
    }
    y
}

/// All card rectangles for a grid `width` wide, plus the total height.
pub fn place(width: f32) -> (Vec<Placed>, f32) {
    let mut out = Vec::new();
    let kpis: Vec<Card> = (0..KPI_COUNT).map(Card::Kpi).collect();
    let kc = kpi_columns(width);
    let krows = pack(&[1; KPI_COUNT], kc);
    let y = place_rows(&mut out, &kpis, &krows, kc, width, 0.0, KPI_H);
    let cc = card_columns(width);
    let cards = [
        Card::Throughput,
        Card::Protocols,
        Card::Talkers,
        Card::Services,
    ];
    let crows = pack(&[2, 1, 1, 1], cc);
    let y = place_rows(&mut out, &cards, &crows, cc, width, y, CARD_H);
    (out, (y - GAP).max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_stretches_last_card() {
        assert_eq!(
            pack(&[2, 1, 1, 1], 3),
            vec![vec![(0, 2), (1, 1)], vec![(2, 1), (3, 2)]]
        );
        assert_eq!(
            pack(&[2, 1, 1, 1], 1),
            vec![vec![(0, 1)], vec![(1, 1)], vec![(2, 1)], vec![(3, 1)]]
        );
        assert_eq!(
            pack(&[2, 1, 1, 1], 2),
            vec![vec![(0, 2)], vec![(1, 1), (2, 1)], vec![(3, 2)]]
        );
    }

    #[test]
    fn cards_tile_the_width_without_overlap() {
        for w in [500.0, 700.0, 1000.0, 1600.0, 2560.0] {
            let (placed, h) = place(w);
            assert_eq!(placed.len(), KPI_COUNT + 4);
            for p in &placed {
                assert!(
                    p.rect.left() >= -0.01 && p.rect.right() <= w + 0.01,
                    "{w}: {p:?}"
                );
                assert!(p.rect.bottom() <= h + 0.01);
            }
            for (i, a) in placed.iter().enumerate() {
                for b in &placed[i + 1..] {
                    assert!(
                        !a.rect.shrink(0.5).intersects(b.rect),
                        "{w}: {a:?} overlaps {b:?}"
                    );
                }
            }
        }
    }
}
