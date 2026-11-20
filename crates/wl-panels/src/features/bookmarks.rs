//! Packet bookmarks & annotations with prev/next jump, filter builder, and JSON persistence.

use std::collections::BTreeMap;

use eframe::egui::{self, RichText, Ui};
use serde::{Deserialize, Serialize};
use wl_kit::theme::Palette;
use wl_kit::widgets::badge;
use wl_model::PacketBookmark;

use crate::features::bookmarks_json;

/// Actions emitted by `bookmark_toolbar_ui`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookmarkBarAction {
    JumpTo(u64),
    FilterBookmarked(String),
    ClearAll,
}

/// Ordered store of bookmarked 1-based frame numbers and optional comments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkStore {
    entries: BTreeMap<u64, String>,
}

impl BookmarkStore {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_bookmarked(&self, frame_no: u64) -> bool {
        self.entries.contains_key(&frame_no)
    }

    pub fn comment(&self, frame_no: u64) -> Option<&str> {
        self.entries.get(&frame_no).map(String::as_str)
    }

    /// Toggles bookmark status for `frame_no`. Returns `true` if now bookmarked.
    pub fn toggle(&mut self, frame_no: u64) -> bool {
        if self.entries.remove(&frame_no).is_some() {
            false
        } else {
            self.entries.insert(frame_no, String::new());
            true
        }
    }

    pub fn set(&mut self, frame_no: u64, comment: impl Into<String>) {
        self.entries.insert(frame_no, comment.into());
    }

    pub fn remove(&mut self, frame_no: u64) -> bool {
        self.entries.remove(&frame_no).is_some()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn all(&self) -> Vec<PacketBookmark> {
        self.entries
            .iter()
            .map(|(&frame_no, comment)| PacketBookmark {
                frame_no,
                comment: comment.clone(),
            })
            .collect()
    }

    pub fn from_vec(items: Vec<PacketBookmark>) -> Self {
        Self {
            entries: items.into_iter().map(|b| (b.frame_no, b.comment)).collect(),
        }
    }

    /// Next bookmarked frame strictly after `current`, wrapping to the first.
    pub fn next_from(&self, current: Option<u64>) -> Option<u64> {
        if let Some(cur) = current
            && let Some((&next, _)) = self.entries.range((cur + 1)..).next()
        {
            return Some(next);
        }
        self.entries.keys().next().copied()
    }

    /// Previous bookmarked frame strictly before `current`, wrapping to the last.
    pub fn prev_from(&self, current: Option<u64>) -> Option<u64> {
        if let Some(cur) = current
            && let Some((&prev, _)) = self.entries.range(..cur).next_back()
        {
            return Some(prev);
        }
        self.entries.keys().next_back().copied()
    }

    /// Builds a Wireshark display filter matching all bookmarked frames.
    pub fn filter_expr(&self) -> Option<String> {
        if self.entries.is_empty() {
            return None;
        }
        let parts: Vec<String> = self
            .entries
            .keys()
            .map(|n| format!("frame.number == {n}"))
            .collect();
        Some(parts.join(" || "))
    }

    pub fn to_json(&self) -> String {
        bookmarks_json::encode(&self.all())
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        Ok(Self::from_vec(bookmarks_json::decode(json)?))
    }
}

/// Compact toolbar for starring the selected frame, editing its comment, and navigating bookmarks.
pub fn bookmark_toolbar_ui(
    ui: &mut Ui,
    store: &mut BookmarkStore,
    selected_frame: Option<u64>,
    comment_buf: &mut String,
) -> Option<BookmarkBarAction> {
    let mut action = None;
    // Right-side data is computed up front so the two sides never borrow `store` together.
    let (len, filter) = (store.len(), store.filter_expr());
    let (next, prev) = (
        store.next_from(selected_frame),
        store.prev_from(selected_frame),
    );
    egui::containers::Sides::new().show(
        ui,
        |ui| {
            if let Some(frame_no) = selected_frame {
                let starred = store.is_bookmarked(frame_no);
                let btn = if starred { "Bookmarked" } else { "Bookmark" };
                if ui.add(egui::Button::new(btn).selected(starred)).clicked() {
                    if store.toggle(frame_no) {
                        *comment_buf = store.comment(frame_no).unwrap_or_default().to_owned();
                    } else {
                        comment_buf.clear();
                    }
                }
                if starred {
                    let edit = ui.add(
                        wl_kit::widgets::text_field(comment_buf)
                            .hint_text(format!("Comment on frame #{frame_no}..."))
                            .desired_width(220.0),
                    );
                    if edit.changed() {
                        store.set(frame_no, comment_buf.clone());
                    }
                }
            } else {
                ui.label(
                    RichText::new("Select a frame to bookmark")
                        .small()
                        .color(Palette::muted()),
                );
            }
        },
        |ui| {
            if len == 0 {
                return;
            }
            if ui.small_button("Next").clicked()
                && let Some(n) = next
            {
                action = Some(BookmarkBarAction::JumpTo(n));
            }
            if ui.small_button("Prev").clicked()
                && let Some(n) = prev
            {
                action = Some(BookmarkBarAction::JumpTo(n));
            }
            if let Some(flt) = filter
                && ui.small_button("Filter marked").clicked()
            {
                action = Some(BookmarkBarAction::FilterBookmarked(flt));
            }
            badge(ui, &format!("{len} marked"), Palette::warn());
        },
    );
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bookmark_navigation_filter_and_json_roundtrip() {
        let mut s = BookmarkStore::default();
        assert!(s.toggle(10));
        s.set(3, "SYN \"retransmit\"\ncheck RTT");
        s.set(25, "RST from server");
        assert_eq!(s.len(), 3);
        assert_eq!(s.next_from(Some(3)), Some(10));
        assert_eq!(s.next_from(Some(25)), Some(3));
        assert_eq!(s.prev_from(Some(10)), Some(3));
        assert_eq!(s.prev_from(Some(3)), Some(25));
        assert_eq!(
            s.filter_expr().as_deref(),
            Some("frame.number == 3 || frame.number == 10 || frame.number == 25")
        );

        let json = s.to_json();
        assert_eq!(BookmarkStore::from_json(&json).unwrap(), s);
        let via_serde: Vec<PacketBookmark> = serde_json::from_str(&json).unwrap();
        assert_eq!(BookmarkStore::from_vec(via_serde), s);
    }
}
