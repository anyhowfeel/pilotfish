//! Recursive descent over the tokens. Precedence, loosest to tightest: `||`, `&&`, `!`, then a
//! comparison, a set test or a bare field.

use super::ast::{Expr, Op};
use super::field::{Field, Kind};
use super::lex::Token;
use super::literal::Lit;

/// Deeper nesting is refused so that a hostile filter cannot exhaust the stack.
const MAX_DEPTH: usize = 32;

pub fn parse(tokens: &[Token<'_>]) -> Option<Expr> {
    let mut p = Parser { tokens, at: 0 };
    let expr = p.or(0)?;
    (p.at == tokens.len()).then_some(expr)
}

struct Parser<'t, 'a> {
    tokens: &'t [Token<'a>],
    at: usize,
}

impl<'a> Parser<'_, 'a> {
    fn peek(&self) -> Option<Token<'a>> {
        self.tokens.get(self.at).copied()
    }

    fn take(&mut self, want: Token<'_>) -> bool {
        let hit = self.peek() == Some(want);
        self.at += usize::from(hit);
        hit
    }

    fn next(&mut self) -> Option<Token<'a>> {
        let t = self.peek();
        self.at += usize::from(t.is_some());
        t
    }

    fn or(&mut self, depth: usize) -> Option<Expr> {
        let mut terms = vec![self.and(depth)?];
        while self.take(Token::Or) {
            terms.push(self.and(depth)?);
        }
        Some(flat(terms, Expr::Or))
    }

    fn and(&mut self, depth: usize) -> Option<Expr> {
        let mut terms = vec![self.not(depth)?];
        while self.take(Token::And) {
            terms.push(self.not(depth)?);
        }
        Some(flat(terms, Expr::And))
    }

    fn not(&mut self, depth: usize) -> Option<Expr> {
        if depth > MAX_DEPTH {
            return None;
        }
        if self.take(Token::Not) {
            return Some(Expr::Not(Box::new(self.not(depth + 1)?)));
        }
        if self.take(Token::Open) {
            let inner = self.or(depth + 1)?;
            return self.take(Token::Close).then_some(inner);
        }
        self.test()
    }

    fn test(&mut self) -> Option<Expr> {
        let Some(Token::Word(name)) = self.next() else {
            return None;
        };
        let (field, kind) = Field::lookup(name)?;
        let op = match self.peek() {
            Some(Token::Eq) => Op::Eq,
            Some(Token::Ne) => Op::Ne,
            Some(Token::Lt) => Op::Lt,
            Some(Token::Le) => Op::Le,
            Some(Token::Gt) => Op::Gt,
            Some(Token::Ge) => Op::Ge,
            Some(Token::In) => {
                self.at += 1;
                return self.set(field, kind);
            }
            _ => return Some(Expr::Present(field)),
        };
        self.at += 1;
        let ordered = matches!(kind, Kind::Int(_));
        if !ordered && !matches!(op, Op::Eq | Op::Ne) {
            return None;
        }
        Some(Expr::Cmp(field, op, self.literal(kind)?))
    }

    fn set(&mut self, field: Field, kind: Kind) -> Option<Expr> {
        if !self.take(Token::OpenSet) {
            return None;
        }
        let mut items = vec![self.literal(kind)?];
        while self.take(Token::Comma) {
            items.push(self.literal(kind)?);
        }
        self.take(Token::CloseSet).then_some(Expr::In(field, items))
    }

    fn literal(&mut self, kind: Kind) -> Option<Lit> {
        match self.next()? {
            Token::Word(w) => Lit::parse(kind, w),
            _ => None,
        }
    }
}

fn flat(mut terms: Vec<Expr>, make: fn(Vec<Expr>) -> Expr) -> Expr {
    if terms.len() == 1 {
        terms.remove(0)
    } else {
        make(terms)
    }
}
