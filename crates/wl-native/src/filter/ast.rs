use super::field::Field;
use super::literal::Lit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// `And` and `Or` hold their operands flat so a long chain of `&&` does not make a deep tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Or(Vec<Expr>),
    And(Vec<Expr>),
    Not(Box<Expr>),
    Present(Field),
    Cmp(Field, Op, Lit),
    In(Field, Vec<Lit>),
}
