//! Preview of an exported object, decoded off the UI thread: text head or a downscaled image.

use std::io::Cursor;

use image::{DynamicImage, ImageReader, Limits};
use wl_model::{ExportObject, ObjectSet};
use wl_panels::web::{
    PREVIEW_IMAGE_MAX, PREVIEW_TEXT_BYTES, Preview, PreviewData, PreviewKind, preview_kind,
};
use wl_tshark::objects_save::read_head;

/// Longest side of a decoded preview image, in pixels.
const MAX_SIDE: u32 = 1024;
/// Memory a decoder may allocate for one preview.
const MAX_ALLOC: u64 = 128 * 1024 * 1024;

pub fn build(set: &ObjectSet, o: &ExportObject) -> PreviewData {
    let preview = match preview_kind(o) {
        PreviewKind::Text => text(set, o),
        PreviewKind::Image => image(set, o),
        PreviewKind::None => Preview::Unavailable("No preview for this type.".into()),
    };
    PreviewData { id: o.id, preview }
}

fn text(set: &ObjectSet, o: &ExportObject) -> Preview {
    match read_head(set, o, PREVIEW_TEXT_BYTES) {
        Ok(bytes) => Preview::Text {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            truncated: o.size > PREVIEW_TEXT_BYTES as u64,
        },
        Err(e) => Preview::Unavailable(format!("Could not read the object: {e}")),
    }
}

fn image(set: &ObjectSet, o: &ExportObject) -> Preview {
    let bytes = match read_head(set, o, PREVIEW_IMAGE_MAX as usize) {
        Ok(b) => b,
        Err(e) => return Preview::Unavailable(format!("Could not read the object: {e}")),
    };
    match decode(&bytes) {
        Some(img) => {
            let rgba = img.to_rgba8();
            Preview::Image {
                w: rgba.width() as usize,
                h: rgba.height() as usize,
                rgba: rgba.into_raw(),
            }
        }
        None => Preview::Unavailable("The image could not be decoded (partial or corrupt).".into()),
    }
}

fn decode(bytes: &[u8]) -> Option<DynamicImage> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let mut limits = Limits::default();
    limits.max_alloc = Some(MAX_ALLOC);
    reader.limits(limits);
    let img = reader.decode().ok()?;
    Some(if img.width().max(img.height()) > MAX_SIDE {
        img.thumbnail(MAX_SIDE, MAX_SIDE)
    } else {
        img
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn set_with(name: &str, ct: &str, data: &[u8]) -> (tempfile::TempDir, ObjectSet, ExportObject) {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join(name);
        fs::write(&path, data).expect("write");
        let o = ExportObject {
            id: 0,
            name: name.into(),
            save_name: name.into(),
            content_type: ct.into(),
            size: data.len() as u64,
            host: String::new(),
            packet: None,
            path,
        };
        let set = ObjectSet {
            protocol: "http".into(),
            dir: dir.path().to_path_buf(),
            objects: vec![o.clone()],
            truncated: false,
        };
        (dir, set, o)
    }

    #[test]
    fn text_preview_is_capped() {
        let big = vec![b'a'; PREVIEW_TEXT_BYTES + 10];
        let (_d, set, o) = set_with("a.txt", "text/plain", &big);
        match build(&set, &o).preview {
            Preview::Text { text, truncated } => {
                assert_eq!(text.len(), PREVIEW_TEXT_BYTES);
                assert!(truncated);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn png_is_decoded_and_garbage_is_reported() {
        let mut png = Vec::new();
        DynamicImage::new_rgba8(4, 3)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .expect("encode");
        let (_d, set, o) = set_with("a.png", "image/png", &png);
        assert!(matches!(
            build(&set, &o).preview,
            Preview::Image { w: 4, h: 3, .. }
        ));
        let (_d, set, o) = set_with("b.png", "image/png", b"not an image");
        assert!(matches!(build(&set, &o).preview, Preview::Unavailable(_)));
        let (_d, set, o) = set_with("c.zip", "application/zip", b"PK");
        assert!(matches!(build(&set, &o).preview, Preview::Unavailable(_)));
    }
}
