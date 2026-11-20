//! Follow TCP/UDP stream via `tshark -r <file> -q -z follow,<proto>,<fmt>,<id>`.

use std::path::Path;

use wl_model::{CaptureError, StreamConversation, StreamFormat, StreamProtocol, StreamTurn};

use crate::error::from_stderr;
use crate::process::{self, Tools};

/// Runs `tshark -r <file> -q -z follow,<proto>,<fmt>,<id>` and parses the conversation.
pub fn follow_stream(
    tools: &Tools,
    file: &Path,
    protocol: StreamProtocol,
    stream_id: u32,
    format: StreamFormat,
) -> Result<StreamConversation, CaptureError> {
    let spec = format!(
        "follow,{},{},{stream_id}",
        protocol.as_str(),
        format.as_str()
    );
    let out = process::run(
        &tools.tshark,
        ["-r", &file.to_string_lossy(), "-q", "-z", &spec],
    )?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    match format {
        StreamFormat::Ascii => Ok(parse_follow_ascii(protocol, stream_id, &out.stdout)),
        StreamFormat::Hex => Ok(parse_follow_hex(
            protocol,
            stream_id,
            &String::from_utf8_lossy(&out.stdout),
        )),
    }
}

fn parse_headers(text: &str) -> (String, String, usize) {
    let (mut client, mut server) = (String::new(), String::new());
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        offset += line.len();
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Node 0:") {
            client = rest.trim().to_owned();
        } else if let Some(rest) = trimmed.strip_prefix("Node 1:") {
            server = rest.trim().to_owned();
            break;
        }
    }
    (client, server, offset)
}

/// Parses `tshark -q -z follow,<proto>,ascii,<id>` stdout bytes into structured turns.
pub fn parse_follow_ascii(
    protocol: StreamProtocol,
    stream_id: u32,
    raw: &[u8],
) -> StreamConversation {
    let lossy = String::from_utf8_lossy(raw);
    let (client, server, body_start) = parse_headers(&lossy);
    let mut turns = Vec::new();
    let mut total_bytes = 0usize;
    let mut pos = body_start.min(raw.len());

    while pos < raw.len() {
        let Some(nl) = raw[pos..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let header_bytes = &raw[pos..pos + nl];
        pos += nl + 1;
        let header = String::from_utf8_lossy(header_bytes);
        let trimmed = header.trim_end_matches('\r');
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("====") {
            break;
        }
        let (from_client, num_str) = match trimmed.strip_prefix('\t') {
            Some(rest) => (false, rest.trim()),
            None => (true, trimmed.trim()),
        };
        let Ok(byte_len) = num_str.parse::<usize>() else {
            continue;
        };
        let end = (pos + byte_len).min(raw.len());
        let chunk = String::from_utf8_lossy(&raw[pos..end]).into_owned();
        pos = end;
        if raw.get(pos) == Some(&b'\n') {
            pos += 1;
        }
        total_bytes += byte_len;
        turns.push(StreamTurn {
            from_client,
            text: chunk,
            byte_len,
        });
    }

    StreamConversation {
        protocol,
        stream_id,
        format: StreamFormat::Ascii,
        client,
        server,
        turns,
        total_bytes,
    }
}

/// Counts how many hex byte tokens appear on one `follow,...,hex` line.
fn count_hex_line_bytes(line: &str) -> usize {
    // Format: "00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HT TP/1.1.."
    let Some(after_off) = line.get(10..) else {
        return 0;
    };
    let hex_part = after_off.get(..49).unwrap_or(after_off);
    hex_part
        .split_whitespace()
        .filter(|tok| tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit()))
        .count()
}

/// Parses `tshark -q -z follow,<proto>,hex,<id>` output into client/server hex turns.
pub fn parse_follow_hex(protocol: StreamProtocol, stream_id: u32, raw: &str) -> StreamConversation {
    let (client, server, body_start) = parse_headers(raw);
    let mut turns: Vec<StreamTurn> = Vec::new();
    let mut total_bytes = 0usize;

    for line in raw[body_start.min(raw.len())..].lines() {
        let clean = line.trim_end_matches('\r');
        if clean.is_empty() {
            continue;
        }
        if clean.starts_with("====") {
            break;
        }
        let (from_client, content) = match clean.strip_prefix('\t') {
            Some(rest) => (false, rest),
            None => (true, clean),
        };
        let n = count_hex_line_bytes(content);
        total_bytes += n;
        if let Some(last) = turns.last_mut().filter(|t| t.from_client == from_client) {
            last.text.push('\n');
            last.text.push_str(content);
            last.byte_len += n;
        } else {
            turns.push(StreamTurn {
                from_client,
                text: content.to_owned(),
                byte_len: n,
            });
        }
    }

    StreamConversation {
        protocol,
        stream_id,
        format: StreamFormat::Hex,
        client,
        server,
        turns,
        total_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ASCII: &str = "\n===================================================================\n\
Follow: tcp,ascii\n\
Filter: tcp.stream eq 0\n\
Node 0: 127.0.0.1:47902\n\
Node 1: 127.0.0.1:18080\n\
18\n\
GET / HTTP/1.1\r\n\r\n\n\
\t17\n\
HTTP/1.0 200 OK\r\n\n\
===================================================================\n";

    const SAMPLE_HEX: &str = "\n===================================================================\n\
Follow: tcp,hex\n\
Filter: tcp.stream eq 0\n\
Node 0: 127.0.0.1:47902\n\
Node 1: 127.0.0.1:18080\n\
00000000  47 45 54 20 2f 0d 0a                              GET /..\n\
\t00000000  4f 4b 0d 0a                                       OK..\n\
===================================================================\n";

    #[test]
    fn parses_ascii_turns() {
        let conv = parse_follow_ascii(StreamProtocol::Tcp, 0, SAMPLE_ASCII.as_bytes());
        assert_eq!(conv.client, "127.0.0.1:47902");
        assert_eq!(conv.server, "127.0.0.1:18080");
        assert_eq!(conv.turns.len(), 2);
        assert!(conv.turns[0].from_client);
        assert_eq!(conv.turns[0].byte_len, 18);
        assert!(conv.turns[0].text.starts_with("GET / HTTP/1.1"));
        assert!(!conv.turns[1].from_client);
        assert_eq!(conv.turns[1].byte_len, 17);
        assert_eq!(conv.total_bytes, 35);
    }

    #[test]
    fn parses_hex_turns() {
        let conv = parse_follow_hex(StreamProtocol::Tcp, 0, SAMPLE_HEX);
        assert_eq!(conv.turns.len(), 2);
        assert!(conv.turns[0].from_client);
        assert_eq!(conv.turns[0].byte_len, 7);
        assert!(!conv.turns[1].from_client);
        assert_eq!(conv.turns[1].byte_len, 4);
        assert_eq!(conv.total_bytes, 11);
    }

    #[test]
    fn handles_empty_stream() {
        let empty = "Node 0: :0\nNode 1: :0\n===================================\n";
        let conv = parse_follow_ascii(StreamProtocol::Udp, 99, empty.as_bytes());
        assert!(conv.turns.is_empty());
        assert_eq!(conv.total_bytes, 0);
    }
}
