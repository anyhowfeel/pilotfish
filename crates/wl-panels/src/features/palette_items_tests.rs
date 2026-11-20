//! Unit tests (kept in their own file to respect the 250-line limit).
use super::*;

#[test]
fn parses_frame_jumps_and_fuzzy_matches() {
    assert_eq!(parse_frame_jump("#42"), Some(42));
    assert_eq!(parse_frame_jump("frame 7"), Some(7));
    assert_eq!(parse_frame_jump("0"), None);
    assert_eq!(parse_frame_jump("tcp"), None);

    assert_eq!(matches_for("#15")[0].action, PaletteAction::JumpToFrame(15));
    assert_eq!(
        matches_for("html")[0].action,
        PaletteAction::ExportHtmlReport
    );
    assert_eq!(
        matches_for("retrans")[0].action,
        PaletteAction::ApplyFilter("tcp.analysis.retransmission".into())
    );
}
