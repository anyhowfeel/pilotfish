//! Bookmarked packets with the columns the HTML report shows next to their comments.

use std::path::Path;

use wl_model::{CaptureBackend, FrameFields, PacketBookmark};
use wl_panels::features::BookmarkStore;

pub const FIELDS: [&str; 6] = [
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "_ws.col.protocol",
];
const INFO: &str = "_ws.col.info";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BookmarkedPacket {
    pub frame_no: u64,
    pub comment: String,
    pub time: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub info: String,
}

fn fields() -> Vec<String> {
    FIELDS
        .iter()
        .chain([&INFO])
        .map(|f| (*f).to_owned())
        .collect()
}

fn first<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() { b } else { a }
}

/// Joins bookmarks with what tshark said about their frames (blank cells when it said nothing).
pub fn join(bookmarks: &[PacketBookmark], found: &[FrameFields]) -> Vec<BookmarkedPacket> {
    bookmarks
        .iter()
        .map(|b| {
            let v = found
                .iter()
                .find(|(n, _)| *n == b.frame_no)
                .map_or(&[][..], |(_, v)| v.as_slice());
            let get = |i: usize| v.get(i).map_or("", String::as_str);
            BookmarkedPacket {
                frame_no: b.frame_no,
                comment: b.comment.clone(),
                time: get(0).to_owned(),
                src: first(get(1), get(3)).to_owned(),
                dst: first(get(2), get(4)).to_owned(),
                protocol: get(5).to_owned(),
                info: get(6).to_owned(),
            }
        })
        .collect()
}

pub fn load(
    backend: &dyn CaptureBackend,
    file: Option<&Path>,
    bookmarks: &[PacketBookmark],
) -> Vec<BookmarkedPacket> {
    let found = file
        .zip(BookmarkStore::from_vec(bookmarks.to_vec()).filter_expr())
        .and_then(|(f, filter)| backend.frame_fields(f, &filter, &fields()).ok())
        .unwrap_or_default();
    join(bookmarks, &found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bm(n: u64, c: &str) -> PacketBookmark {
        PacketBookmark {
            frame_no: n,
            comment: c.into(),
        }
    }

    #[test]
    fn joins_by_frame_number_and_falls_back_to_ipv6() {
        let found = vec![
            (
                7,
                ["0.5", "", "", "fe80::1", "fe80::2", "ICMPv6", "echo"]
                    .map(String::from)
                    .to_vec(),
            ),
            (
                3,
                ["1.0", "10.0.0.1", "10.0.0.2", "", "", "TCP", "SYN"]
                    .map(String::from)
                    .to_vec(),
            ),
        ];
        let rows = join(&[bm(3, "syn"), bm(7, "v6"), bm(9, "gone")], &found);
        assert_eq!(
            (
                rows[0].src.as_str(),
                rows[0].protocol.as_str(),
                rows[0].info.as_str()
            ),
            ("10.0.0.1", "TCP", "SYN")
        );
        assert_eq!(
            (rows[1].src.as_str(), rows[1].dst.as_str()),
            ("fe80::1", "fe80::2")
        );
        assert_eq!(
            rows[2],
            BookmarkedPacket {
                frame_no: 9,
                comment: "gone".into(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn loads_the_packet_columns_from_a_real_capture() {
        let Ok(b) = wl_tshark::TsharkBackend::new() else {
            return;
        };
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/sample.pcapng");
        let rows = load(&b, Some(&file), &[bm(2, "look"), bm(4, "")]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].comment, "look");
        assert!(
            rows.iter()
                .all(|r| !r.protocol.is_empty() && !r.time.is_empty()),
            "{rows:?}"
        );
        assert!(load(&b, None, &[bm(2, "x")])[0].protocol.is_empty());
    }
}
