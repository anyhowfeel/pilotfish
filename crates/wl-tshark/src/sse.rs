//! Server-Sent Events from the raw server-to-client bytes of one HTTP response: skips the
//! headers, undoes chunked transfer coding and cuts the body into events at blank lines.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SseEvent {
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: String,
    pub comment: Option<String>,
}

#[derive(Debug)]
enum Chunk {
    Size(Vec<u8>),
    Data(usize),
    Crlf(u8),
    Done,
}

#[derive(Debug, Default)]
pub struct SseDecoder {
    head: Vec<u8>,
    in_body: bool,
    chunk: Option<Chunk>,
    line: Vec<u8>,
    block: SseEvent,
    block_open: bool,
}

fn is_chunked(head: &[u8]) -> bool {
    String::from_utf8_lossy(head)
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
}

impl SseDecoder {
    /// Feeds the next segment; returns the events it completed.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let mut out = Vec::new();
        for &b in bytes {
            if self.in_body {
                self.body_byte(b, &mut out);
                continue;
            }
            self.head.push(b);
            if self.head.ends_with(b"\r\n\r\n") {
                self.in_body = true;
                self.chunk = is_chunked(&self.head).then(|| Chunk::Size(Vec::new()));
            }
        }
        out
    }

    fn body_byte(&mut self, b: u8, out: &mut Vec<SseEvent>) {
        let Some(state) = self.chunk.take() else {
            return self.text_byte(b, out);
        };
        self.chunk = Some(match state {
            Chunk::Size(s) if b == b'\n' => {
                let hex = String::from_utf8_lossy(&s);
                let hex = hex.split(';').next().unwrap_or("").trim();
                match usize::from_str_radix(hex, 16) {
                    Ok(0) | Err(_) => Chunk::Done,
                    Ok(n) => Chunk::Data(n),
                }
            }
            Chunk::Size(mut s) => {
                s.push(b);
                Chunk::Size(s)
            }
            Chunk::Data(n) => {
                self.chunk = None;
                self.text_byte(b, out);
                if n == 1 {
                    Chunk::Crlf(2)
                } else {
                    Chunk::Data(n - 1)
                }
            }
            Chunk::Crlf(1) => Chunk::Size(Vec::new()),
            Chunk::Crlf(n) => Chunk::Crlf(n - 1),
            Chunk::Done => Chunk::Done,
        });
    }

    fn text_byte(&mut self, b: u8, out: &mut Vec<SseEvent>) {
        if b != b'\n' {
            self.line.push(b);
            return;
        }
        let line = String::from_utf8_lossy(&self.line)
            .trim_end_matches('\r')
            .to_owned();
        self.line.clear();
        if line.is_empty() {
            if std::mem::take(&mut self.block_open) {
                out.push(std::mem::take(&mut self.block));
            }
            return;
        }
        self.block_open = true;
        self.field(&line);
    }

    fn field(&mut self, line: &str) {
        if let Some(c) = line.strip_prefix(':') {
            self.block.comment = Some(c.trim().to_owned());
            return;
        }
        let (name, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value).to_owned();
        match name {
            "event" => self.block.event = Some(value),
            "id" => self.block.id = Some(value),
            "data" => {
                if !self.block.data.is_empty() {
                    self.block.data.push('\n');
                }
                self.block.data.push_str(&value);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n";

    fn decode(parts: &[&[u8]]) -> Vec<SseEvent> {
        let mut d = SseDecoder::default();
        parts.iter().flat_map(|p| d.push(p)).collect()
    }

    fn chunk(s: &str) -> Vec<u8> {
        format!("{:x}\r\n{s}\r\n", s.len()).into_bytes()
    }

    #[test]
    fn plain_body_events_with_fields_and_multiline_data() {
        let body = b"event: tick\nid: 7\ndata: a\ndata: b\n\ndata: x\r\n\r\n";
        let ev = decode(&[HEAD, b"\r\n", body]);
        assert_eq!(ev.len(), 2);
        assert_eq!(
            (
                ev[0].event.as_deref(),
                ev[0].id.as_deref(),
                ev[0].data.as_str()
            ),
            (Some("tick"), Some("7"), "a\nb")
        );
        assert_eq!(ev[1].data, "x");
    }

    #[test]
    fn chunked_events_split_across_segments() {
        let head = [HEAD, b"Transfer-Encoding: chunked\r\n\r\n"].concat();
        let c1 = chunk("data: one\n\nda");
        let c2 = chunk("ta: two\n\n");
        let all = [c1, c2, b"0\r\n\r\n".to_vec()].concat();
        let (a, b) = all.split_at(9);
        let ev = decode(&[&head, a, b]);
        assert_eq!(
            ev.iter().map(|e| e.data.as_str()).collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn comments_are_reported_and_open_blocks_wait() {
        let ev = decode(&[HEAD, b"\r\n", b": keep-alive\n\ndata: unfinished\n"]);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].comment.as_deref(), Some("keep-alive"));
    }

    #[test]
    fn nothing_before_the_headers_end() {
        assert!(decode(&[b"HTTP/1.1 200 OK\r\n", b"data: x\n\n"]).is_empty());
    }
}
