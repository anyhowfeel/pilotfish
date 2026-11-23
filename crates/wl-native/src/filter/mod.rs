//! The small display-filter subset the native backend can evaluate exactly like Wireshark.
//! Anything outside it is left to tshark.
//!
//! Supported: `&&` `||` `!` (and `and` `or` `not`), parentheses, `==` `!=` `<` `<=` `>` `>=`
//! (and `eq` `ne` `lt` `le` `gt` `ge`), `field in {a, b}`, bare fields as presence tests. Fields
//! are listed in `field.rs`. Values are decimal or `0x` integers, IPv4 and IPv6 addresses with an
//! optional prefix length, and colon-separated MAC addresses.

mod ast;
mod eval;
mod field;
mod lex;
mod literal;
mod parse;
mod values;

use crate::decode::Decoded;

/// A parsed filter that only uses supported fields and operators.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    expr: ast::Expr,
}

/// `None` when `text` uses anything the native evaluator does not handle (the caller then asks
/// tshark). An empty filter is not a filter: it is `None` too, callers check for it first.
pub fn parse(text: &str) -> Option<Filter> {
    let tokens = lex::lex(text)?;
    parse::parse(&tokens).map(|expr| Filter { expr })
}

impl Filter {
    pub fn matches(&self, packet: &Decoded) -> bool {
        self.expr.eval(packet)
    }
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod eval_tests;
#[cfg(test)]
#[path = "field_tests.rs"]
mod field_tests;
#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod fuzz_tests;
#[cfg(test)]
#[path = "lex_tests.rs"]
mod lex_tests;
#[cfg(test)]
#[path = "parse_tests.rs"]
mod parse_tests;
