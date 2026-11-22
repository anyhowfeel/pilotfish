use eframe::egui;
use wl_model::{PacketBookmark, SecurityData};

use super::*;

fn hub() -> FeaturesHub {
    FeaturesHub::new(None, egui::Context::default())
}

fn comment(frame_no: u64, text: &str) -> Msg {
    Msg::Comments(vec![PacketBookmark {
        frame_no,
        comment: text.into(),
    }])
}

#[test]
fn results_of_the_previous_capture_are_dropped() {
    let mut h = hub();
    let old = Some(h.generation);
    h.clear_capture();
    let empty = || SecurityData {
        credentials: Vec::new(),
        tls: Vec::new(),
    };
    h.tx.send((old, Msg::Security(empty()))).unwrap();
    h.tx.send((old, comment(1, "from the old file"))).unwrap();
    h.tx.send((Some(h.generation), Msg::Security(empty())))
        .unwrap();
    h.poll();
    assert!(h.security.is_some());
    assert!(h.bookmarks.is_empty());
}

#[test]
fn imported_comments_only_fill_empty_bookmarks() {
    let mut h = hub();
    h.bookmarks.set(3, "typed by the user");
    h.bookmarks.toggle(4);
    h.tx.send((Some(h.generation), comment(3, "imported")))
        .unwrap();
    h.tx.send((Some(h.generation), comment(4, "imported")))
        .unwrap();
    h.poll();
    assert_eq!(h.bookmarks.comment(3), Some("typed by the user"));
    assert_eq!(h.bookmarks.comment(4), Some("imported"));
}

#[test]
fn a_new_capture_starts_without_the_old_bookmarks() {
    let mut h = hub();
    h.bookmarks.set(3, "x");
    h.clear_capture();
    assert!(h.bookmarks.is_empty());
}
