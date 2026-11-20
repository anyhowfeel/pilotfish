//! Pure logic of the Files tab: protocols, sorting/filtering, preview eligibility.

use std::cmp::Ordering;

use wl_model::ExportObject;

use crate::overview::SortState;

/// (tshark name, label) of the protocols `--export-objects` can list.
pub const PROTOCOLS: [(&str, &str); 5] = [
    ("http", "HTTP"),
    ("smb", "SMB"),
    ("tftp", "TFTP"),
    ("imf", "IMF"),
    ("dicom", "DICOM"),
];
/// Bytes of a text object shown in the preview.
pub const PREVIEW_TEXT_BYTES: usize = 64 * 1024;
/// Largest image decoded for the preview.
pub const PREVIEW_IMAGE_MAX: u64 = 8 * 1024 * 1024;
/// Objects above this size get a warning colour in the list.
pub const LARGE: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCol {
    Packet,
    Host,
    Name,
    Type,
    Size,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKind {
    Text,
    Image,
    None,
}

pub fn preview_kind(o: &ExportObject) -> PreviewKind {
    let ct = o.content_type.to_ascii_lowercase();
    let is_text = ct.starts_with("text/")
        || ["json", "javascript", "xml", "x-www-form-urlencoded"]
            .iter()
            .any(|k| ct.contains(k));
    if is_text {
        PreviewKind::Text
    } else if matches!(ct.as_str(), "image/png" | "image/jpeg" | "image/gif")
        && o.size <= PREVIEW_IMAGE_MAX
    {
        PreviewKind::Image
    } else {
        PreviewKind::None
    }
}

fn cmp(a: &ExportObject, b: &ExportObject, col: SortCol) -> Ordering {
    match col {
        SortCol::Packet => a
            .packet
            .unwrap_or(u64::MAX)
            .cmp(&b.packet.unwrap_or(u64::MAX)),
        SortCol::Host => a
            .host
            .to_ascii_lowercase()
            .cmp(&b.host.to_ascii_lowercase()),
        SortCol::Name => a
            .name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase()),
        SortCol::Type => a.content_type.cmp(&b.content_type),
        SortCol::Size => a.size.cmp(&b.size),
    }
}

/// Indices of the objects to show: filtered by `query` (name, host, type), then sorted.
pub fn build(all: &[ExportObject], query: &str, sort: SortState<SortCol>) -> Vec<u32> {
    let q = query.trim().to_ascii_lowercase();
    let mut idx: Vec<u32> = (0..all.len() as u32)
        .filter(|&i| {
            let o = &all[i as usize];
            q.is_empty()
                || [&o.name, &o.host, &o.content_type]
                    .iter()
                    .any(|s| s.to_ascii_lowercase().contains(&q))
        })
        .collect();
    idx.sort_by(|&a, &b| {
        let o = cmp(&all[a as usize], &all[b as usize], sort.col);
        if sort.desc { o.reverse() } else { o }.then(a.cmp(&b))
    });
    idx
}

pub fn total_size(all: &[ExportObject]) -> u64 {
    all.iter().map(|o| o.size).sum()
}

#[cfg(test)]
pub(super) mod tests {
    use std::path::PathBuf;

    use super::*;

    pub fn obj(
        id: u32,
        name: &str,
        ct: &str,
        size: u64,
        host: &str,
        packet: Option<u64>,
    ) -> ExportObject {
        ExportObject {
            id,
            name: name.into(),
            save_name: name.into(),
            content_type: ct.into(),
            size,
            host: host.into(),
            packet,
            path: PathBuf::from(name),
        }
    }

    #[test]
    fn preview_kinds() {
        assert_eq!(
            preview_kind(&obj(0, "a", "text/html", 5, "", None)),
            PreviewKind::Text
        );
        assert_eq!(
            preview_kind(&obj(0, "a", "application/json", 5, "", None)),
            PreviewKind::Text
        );
        assert_eq!(
            preview_kind(&obj(0, "a", "image/png", 5, "", None)),
            PreviewKind::Image
        );
        assert_eq!(
            preview_kind(&obj(0, "a", "image/png", PREVIEW_IMAGE_MAX + 1, "", None)),
            PreviewKind::None
        );
        assert_eq!(
            preview_kind(&obj(0, "a", "application/zip", 5, "", None)),
            PreviewKind::None
        );
    }

    #[test]
    fn filter_and_sort() {
        let all = [
            obj(0, "b.js", "application/javascript", 30, "x.com", Some(9)),
            obj(1, "a.png", "image/png", 10, "y.com", Some(3)),
            obj(2, "c.bin", "application/octet-stream", 20, "", None),
        ];
        let by = |c, d| build(&all, "", SortState::new(c, d));
        assert_eq!(by(SortCol::Packet, false), [1, 0, 2]);
        assert_eq!(by(SortCol::Size, true), [0, 2, 1]);
        assert_eq!(by(SortCol::Name, false), [1, 0, 2]);
        assert_eq!(
            build(&all, "Y.COM", SortState::new(SortCol::Name, false)),
            [1]
        );
        assert_eq!(
            build(&all, "image", SortState::new(SortCol::Name, false)),
            [1]
        );
        assert_eq!(total_size(&all), 60);
    }
}
