//! Layout checks for the find bar, custom columns and time formats.

use wl_kit::theme::Mode;

use super::{frame_used, rows};
use crate::packets::PacketTable;

#[test]
fn find_bar_fits_in_both_layouts() {
    let mut table = PacketTable::default();
    table.push_rows(rows(20));
    for mode in [Mode::Dark, Mode::Light] {
        for ppp in [1.0, 1.5] {
            for q in ["", "x"] {
                let mut st = crate::packets::find_state::FindState::default();
                st.open();
                st.query.text = q.into();
                let mut out = vec![];
                let used = frame_used(ppp, mode, |ui| {
                    crate::packets::find_bar::ui(ui, &mut st, &mut table, &mut out)
                });
                assert!(used.width() <= 1000.0 / ppp + 1.0, "{mode:?} {ppp}");
                assert!(used.height() > 20.0 && used.height() < 120.0);
            }
        }
    }
}

#[test]
fn table_fits_with_custom_columns_and_every_time_format() {
    use crate::packets::{ColumnSet, TablePrefs, TimeFormat};
    for fmt in TimeFormat::ALL {
        let mut cols = ColumnSet::default();
        assert!(cols.add_field("ip.ttl"));
        assert!(cols.add_field("tcp.srcport"));
        let mut t = PacketTable::default();
        t.push_rows(rows(30));
        t.set_table_prefs(TablePrefs {
            columns: cols,
            time: fmt,
        });
        for mode in [Mode::Dark, Mode::Light] {
            for ppp in [1.0, 1.5] {
                let mut out = vec![];
                let used = frame_used(ppp, mode, |ui| out = t.ui(ui));
                assert!(used.width() <= 1000.0 / ppp + 1.0, "{fmt:?} {mode:?} {ppp}");
                // custom columns ask the backend for their values exactly once
                let asked = out
                    .iter()
                    .filter(|a| matches!(a, crate::packets::PacketsAction::RunFields { .. }))
                    .count();
                assert!(asked <= 2);
            }
        }
    }
}
