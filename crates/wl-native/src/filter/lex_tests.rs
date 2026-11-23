use super::lex::{Token, lex};

fn tokens(text: &str) -> Vec<Token<'_>> {
    lex(text).expect("lexes")
}

#[test]
fn words_carry_dots_colons_and_slashes() {
    assert_eq!(
        tokens("ip.addr == 10.0.0.0/8"),
        [Token::Word("ip.addr"), Token::Eq, Token::Word("10.0.0.0/8")]
    );
    assert_eq!(tokens("fe80::1"), [Token::Word("fe80::1")]);
    assert_eq!(
        tokens("aa:bb:cc:dd:ee:ff"),
        [Token::Word("aa:bb:cc:dd:ee:ff")]
    );
}

#[test]
fn operators_need_no_spaces() {
    assert_eq!(
        tokens("a==1&&b!=2||c<=3"),
        [
            Token::Word("a"),
            Token::Eq,
            Token::Word("1"),
            Token::And,
            Token::Word("b"),
            Token::Ne,
            Token::Word("2"),
            Token::Or,
            Token::Word("c"),
            Token::Le,
            Token::Word("3"),
        ]
    );
    assert_eq!(
        tokens("a>=1"),
        [Token::Word("a"), Token::Ge, Token::Word("1")]
    );
    assert_eq!(
        tokens("a<1"),
        [Token::Word("a"), Token::Lt, Token::Word("1")]
    );
    assert_eq!(
        tokens("a>1"),
        [Token::Word("a"), Token::Gt, Token::Word("1")]
    );
}

#[test]
fn a_bang_before_equals_is_not_equal() {
    assert_eq!(tokens("!="), [Token::Ne]);
    assert_eq!(tokens("!a"), [Token::Not, Token::Word("a")]);
}

#[test]
fn keywords_replace_symbols() {
    let words = [
        ("and", Token::And),
        ("or", Token::Or),
        ("not", Token::Not),
        ("eq", Token::Eq),
        ("ne", Token::Ne),
        ("lt", Token::Lt),
        ("le", Token::Le),
        ("gt", Token::Gt),
        ("ge", Token::Ge),
        ("in", Token::In),
    ];
    for (text, token) in words {
        assert_eq!(tokens(text), [token], "{text}");
    }
}

#[test]
fn keywords_are_lower_case_and_whole_words() {
    assert_eq!(tokens("AND"), [Token::Word("AND")]);
    assert_eq!(tokens("android"), [Token::Word("android")]);
    assert_eq!(tokens("index"), [Token::Word("index")]);
}

#[test]
fn sets_and_groups() {
    assert_eq!(
        tokens("( {1,2} )"),
        [
            Token::Open,
            Token::OpenSet,
            Token::Word("1"),
            Token::Comma,
            Token::Word("2"),
            Token::CloseSet,
            Token::Close,
        ]
    );
}

#[test]
fn whitespace_of_any_kind_separates() {
    assert_eq!(tokens(" \t\r\n a \n"), [Token::Word("a")]);
    assert!(tokens("").is_empty());
    assert!(tokens("   ").is_empty());
}

#[test]
fn syntax_outside_the_subset_does_not_lex() {
    for text in [
        "a = 1",
        "a & 1",
        "a | b",
        "a ^^ b",
        "a ~ b",
        "a == \"x\"",
        "a[0]",
        "a == 'x'",
        "a == ff-ff",
        "a == 1;",
        "a @ b",
        "a\0",
        "é",
    ] {
        assert!(lex(text).is_none(), "{text:?}");
    }
}
