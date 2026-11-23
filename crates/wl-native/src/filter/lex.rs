//! Splits filter text into tokens. Anything that is not part of the supported syntax (quotes,
//! brackets, a lone `=` or `&`) makes the whole filter unsupported.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<'a> {
    /// A field name or a value: letters, digits and `_ . : /`.
    Word(&'a str),
    Not,
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Open,
    Close,
    OpenSet,
    CloseSet,
    Comma,
}

pub fn lex(text: &str) -> Option<Vec<Token<'_>>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        let (token, len) = match (b, next) {
            (b' ' | b'\t' | b'\r' | b'\n', _) => {
                i += 1;
                continue;
            }
            (b'=', Some(b'=')) => (Token::Eq, 2),
            (b'!', Some(b'=')) => (Token::Ne, 2),
            (b'<', Some(b'=')) => (Token::Le, 2),
            (b'>', Some(b'=')) => (Token::Ge, 2),
            (b'&', Some(b'&')) => (Token::And, 2),
            (b'|', Some(b'|')) => (Token::Or, 2),
            (b'!', _) => (Token::Not, 1),
            (b'<', _) => (Token::Lt, 1),
            (b'>', _) => (Token::Gt, 1),
            (b'(', _) => (Token::Open, 1),
            (b')', _) => (Token::Close, 1),
            (b'{', _) => (Token::OpenSet, 1),
            (b'}', _) => (Token::CloseSet, 1),
            (b',', _) => (Token::Comma, 1),
            _ if is_word(b) => {
                let end = bytes[i..]
                    .iter()
                    .position(|c| !is_word(*c))
                    .map_or(bytes.len(), |p| i + p);
                (keyword(&text[i..end]), end - i)
            }
            _ => return None,
        };
        out.push(token);
        i += len;
    }
    Some(out)
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/')
}

fn keyword(word: &str) -> Token<'_> {
    match word {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "eq" => Token::Eq,
        "ne" => Token::Ne,
        "lt" => Token::Lt,
        "le" => Token::Le,
        "gt" => Token::Gt,
        "ge" => Token::Ge,
        "in" => Token::In,
        _ => Token::Word(word),
    }
}
