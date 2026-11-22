use wl_stats::Presence;

use super::section::Show;

#[test]
fn show_filters_by_presence() {
    assert!(Show::All.admits(Presence::Removed));
    assert!(Show::Added.admits(Presence::Added));
    assert!(!Show::Added.admits(Presence::Changed));
    assert!(Show::Changed.admits(Presence::Changed));
}
