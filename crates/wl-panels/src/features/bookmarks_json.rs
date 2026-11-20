//! Minimal zero-dependency RFC-8259 JSON codec for `PacketBookmark` slices.

use wl_model::PacketBookmark;

pub fn encode(items: &[PacketBookmark]) -> String {
    let mut out = String::from("[");
    for (i, b) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"frame_no\":{},\"comment\":\"{}\"}}",
            b.frame_no,
            escape_json(&b.comment)
        ));
    }
    out.push(']');
    out
}

pub fn decode(json: &str) -> Result<Vec<PacketBookmark>, String> {
    let inner = json
        .trim()
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .ok_or_else(|| "expected JSON array".to_owned())?
        .trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for obj in split_objects(inner)? {
        out.push(PacketBookmark {
            frame_no: extract_u64(obj, "frame_no")?,
            comment: extract_string(obj, "comment")?,
        });
    }
    Ok(out)
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn split_objects(s: &str) -> Result<Vec<&str>, String> {
    let (mut objs, mut depth, mut in_str, mut esc, mut start) =
        (Vec::new(), 0usize, false, false, None);
    for (i, ch) in s.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => in_str = true,
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth = depth.checked_sub(1).ok_or("unbalanced JSON braces")?;
                if depth == 0
                    && let Some(st) = start.take()
                {
                    objs.push(&s[st..=i]);
                }
            }
            _ => {}
        }
    }
    if depth != 0 || in_str {
        return Err("unterminated JSON object".into());
    }
    Ok(objs)
}

fn extract_u64(obj: &str, key: &str) -> Result<u64, String> {
    let pat = format!("\"{key}\"");
    let pos = obj.find(&pat).ok_or_else(|| format!("missing {key}"))?;
    let after = obj[pos + pat.len()..]
        .split_once(':')
        .ok_or("missing ':'")?
        .1
        .trim_start();
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<u64>().map_err(|_| format!("invalid {key}"))
}

fn extract_string(obj: &str, key: &str) -> Result<String, String> {
    let pat = format!("\"{key}\"");
    let pos = obj.find(&pat).ok_or_else(|| format!("missing {key}"))?;
    let after = obj[pos + pat.len()..]
        .split_once(':')
        .ok_or("missing ':'")?
        .1
        .trim_start();
    let mut chars = after.chars();
    if chars.next() != Some('"') {
        return Err(format!("expected string for {key}"));
    }
    let (mut out, mut esc) = (String::new(), false);
    for ch in chars {
        if esc {
            out.push(match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            esc = false;
        } else if ch == '\\' {
            esc = true;
        } else if ch == '"' {
            return Ok(out);
        } else {
            out.push(ch);
        }
    }
    Err(format!("unterminated string for {key}"))
}
