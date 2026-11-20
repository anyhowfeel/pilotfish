//! Pure formatting and search helpers for `StreamConversation`.

use wl_model::StreamConversation;

/// Formats a conversation into plain copyable text with client/server markers.
pub fn format_conversation_text(conv: &StreamConversation) -> String {
    let mut out = format!(
        "# {} stream {} ({} <-> {}, {} bytes)\n",
        conv.protocol.as_str().to_uppercase(),
        conv.stream_id,
        conv.client,
        conv.server,
        conv.total_bytes
    );
    for turn in &conv.turns {
        let dir = if turn.from_client { ">>>" } else { "<<<" };
        out.push_str(&format!("\n{dir} ({} B)\n{}\n", turn.byte_len, turn.text));
    }
    out
}

/// Counts case-insensitive occurrences of `query` across all turns.
pub fn count_search_matches(conv: &StreamConversation, query: &str) -> usize {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return 0;
    }
    conv.turns
        .iter()
        .map(|t| t.text.to_ascii_lowercase().matches(&q).count())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::{StreamFormat, StreamProtocol, StreamTurn};

    #[test]
    fn formats_and_searches_stream() {
        let conv = StreamConversation {
            protocol: StreamProtocol::Tcp,
            stream_id: 2,
            format: StreamFormat::Ascii,
            client: "10.0.0.1:5000".into(),
            server: "10.0.0.2:80".into(),
            turns: vec![
                StreamTurn {
                    from_client: true,
                    text: "GET /hello HTTP/1.1".into(),
                    byte_len: 19,
                },
                StreamTurn {
                    from_client: false,
                    text: "HTTP/1.1 200 OK\nhello world".into(),
                    byte_len: 27,
                },
            ],
            total_bytes: 46,
        };
        let txt = format_conversation_text(&conv);
        assert!(txt.contains("TCP stream 2"));
        assert!(txt.contains(">>> (19 B)"));
        assert!(txt.contains("<<< (27 B)"));
        assert_eq!(count_search_matches(&conv, "HELLO"), 2);
        assert_eq!(count_search_matches(&conv, ""), 0);
    }
}
