//! Names of exported objects: percent decoding, content type by extension, and matching the
//! files tshark wrote with the HTTP exchanges they came from (host, frame, content type).

use wl_model::HttpExchange;

/// `%2f` -> `/` (invalid escapes stay as they are; invalid UTF-8 is replaced).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `name(3)` -> (`name`, 3); names without a suffix are occurrence 0.
pub fn split_dup(name: &str) -> (&str, u32) {
    if let Some(stem) = name.strip_suffix(')')
        && let Some((base, n)) = stem.rsplit_once('(')
        && let Ok(n) = n.parse::<u32>()
    {
        return (base, n);
    }
    (name, 0)
}

/// Best-effort MIME type from a file extension.
pub fn content_type_for(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map_or("", |(_, e)| e)
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "text/xml",
        "txt" | "log" | "csv" | "eml" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "woff" | "woff2" => "font/woff",
        "dcm" => "application/dicom",
        _ => "application/octet-stream",
    }
}

/// The name tshark derives from a request URI: the last path segment, or the whole URI when the
/// path ends in a slash. Compared decoded, so `%3f` and `?` agree.
fn uri_name(uri: &str) -> String {
    let seg = uri.rsplit('/').next().unwrap_or("");
    (if seg.is_empty() { uri } else { seg }).to_owned()
}

/// For every file `(name written by tshark, size)` the index of the exchange it came from.
/// Files of one name are matched to the exchanges of that name in capture order; an exchange
/// whose wire size equals the file size wins over the next one in line.
pub fn match_http(files: &[(String, u64)], ex: &[HttpExchange]) -> Vec<Option<usize>> {
    let mut by_name: Vec<(String, Vec<usize>)> = Vec::new();
    let mut order: Vec<usize> = (0..ex.len())
        .filter(|&i| ex[i].resp_frame.is_some() && ex[i].resp_bytes > 0)
        .collect();
    order.sort_by_key(|&i| ex[i].resp_frame);
    for i in order {
        let key = uri_name(&ex[i].uri);
        match by_name.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(i),
            None => by_name.push((key, vec![i])),
        }
    }
    let mut idx: Vec<usize> = (0..files.len()).collect();
    idx.sort_by_key(|&f| split_dup(&files[f].0).1);
    let mut out = vec![None; files.len()];
    for f in idx {
        let decoded = percent_decode(split_dup(&files[f].0).0);
        let Some((_, cands)) = by_name.iter_mut().find(|(k, _)| *k == decoded) else {
            continue;
        };
        let pick = cands
            .iter()
            .position(|&i| ex[i].resp_bytes >= files[f].1)
            .unwrap_or(0);
        if !cands.is_empty() {
            out[f] = Some(cands.remove(pick));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(percent_decode("a%2fb%3fc=1"), "a/b?c=1");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
    }

    #[test]
    fn splits_duplicate_suffix() {
        assert_eq!(split_dup("x.png(2)"), ("x.png", 2));
        assert_eq!(split_dup("x.png"), ("x.png", 0));
        assert_eq!(split_dup("f(a)"), ("f(a)", 0));
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type_for("A.PNG"), "image/png");
        assert_eq!(content_type_for("noext"), "application/octet-stream");
    }

    fn ex(frame: u64, uri: &str, bytes: u64) -> HttpExchange {
        HttpExchange {
            id: frame,
            stream: None,
            req_frame: Some(frame - 1),
            resp_frame: Some(frame),
            method: "GET".into(),
            host: format!("h{frame}").into(),
            uri: uri.into(),
            version: "HTTP/1.1".into(),
            status: Some(200),
            reason: None,
            content_type: None,
            req_bytes: 0,
            resp_bytes: bytes,
            start_rel: 0.0,
            time_ms: None,
        }
    }

    #[test]
    fn matches_files_to_exchanges_in_order() {
        let exs = [ex(10, "/", 300), ex(20, "/x.js?v=1", 50), ex(30, "/", 900)];
        let files = [
            ("%2f(1)".to_owned(), 800),
            ("x.js%3fv=1".to_owned(), 40),
            ("%2f".to_owned(), 250),
        ];
        let m = match_http(&files, &exs);
        assert_eq!(m, [Some(2), Some(1), Some(0)]);
    }

    #[test]
    fn unknown_files_have_no_match() {
        let m = match_http(&[("zzz".to_owned(), 1)], &[ex(2, "/a", 5)]);
        assert_eq!(m, [None]);
    }
}
