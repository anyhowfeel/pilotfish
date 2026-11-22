//! Single-line payload previews for the message timeline.

const MAX_CHARS: usize = 160;
const MAX_HEX_BYTES: usize = 24;

fn clip(mut s: String) -> String {
    if let Some((i, _)) = s.char_indices().nth(MAX_CHARS) {
        s.truncate(i);
        s.push('\u{2026}');
    }
    s
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn text(bytes: &[u8]) -> String {
    clip(one_line(&String::from_utf8_lossy(bytes)))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s: Vec<String> = bytes
        .iter()
        .take(MAX_HEX_BYTES)
        .map(|b| format!("{b:02x}"))
        .collect();
    if bytes.len() > MAX_HEX_BYTES {
        s.push("\u{2026}".into());
    }
    s.join(" ")
}

/// Printable runs of a protobuf message (field tags and varints are noise), joined by spaces.
pub fn protobuf(bytes: &[u8]) -> String {
    let mut runs: Vec<String> = Vec::new();
    let mut cur = String::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else if !cur.is_empty() {
            runs.push(std::mem::take(&mut cur));
        }
    }
    runs.push(cur);
    let text: Vec<String> = runs.into_iter().filter(|r| r.len() >= 2).collect();
    if text.is_empty() {
        hex(bytes)
    } else {
        clip(text.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_one_line_and_clipped() {
        assert_eq!(text(b"a\n  b\tc"), "a b c");
        let long = "x".repeat(300);
        assert_eq!(text(long.as_bytes()).chars().count(), MAX_CHARS + 1);
    }

    #[test]
    fn hex_is_capped() {
        assert_eq!(hex(&[1, 0xab]), "01 ab");
        assert!(hex(&[0; 40]).ends_with('\u{2026}'));
    }

    #[test]
    fn protobuf_shows_string_fields_or_falls_back_to_hex() {
        assert_eq!(protobuf(b"\x0a\x0bHello world"), "Hello world");
        assert_eq!(protobuf(&[0x08, 0x96, 0x01]), "08 96 01");
    }
}
