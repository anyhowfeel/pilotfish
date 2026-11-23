use std::cmp::Ordering;

use super::ast::{Expr, Op};
use super::field::Field;
use super::literal::Lit;
use crate::decode::Decoded;

impl Expr {
    pub fn eval(&self, d: &Decoded) -> bool {
        match self {
            Expr::Or(v) => v.iter().any(|e| e.eval(d)),
            Expr::And(v) => v.iter().all(|e| e.eval(d)),
            Expr::Not(e) => !e.eval(d),
            Expr::Present(f) => f.present(d),
            Expr::Cmp(f, op, lit) => compare(*f, *op, lit, d),
            Expr::In(f, set) => {
                let vals = f.values(d);
                vals.iter()
                    .flatten()
                    .any(|v| set.iter().any(|l| l.equals(v)))
            }
        }
    }
}

/// Wireshark compares every occurrence of a field: `==` and the orderings hold when any one
/// does, `!=` when the field is there and none equals the value.
fn compare(field: Field, op: Op, lit: &Lit, d: &Decoded) -> bool {
    let vals = field.values(d);
    let mut present = vals.iter().flatten().peekable();
    match op {
        Op::Eq => present.any(|v| lit.equals(v)),
        Op::Ne => present.peek().is_some() && !present.any(|v| lit.equals(v)),
        Op::Lt => present.any(|v| lit.order(v) == Some(Ordering::Less)),
        Op::Le => present.any(|v| matches!(lit.order(v), Some(Ordering::Less | Ordering::Equal))),
        Op::Gt => present.any(|v| lit.order(v) == Some(Ordering::Greater)),
        Op::Ge => {
            present.any(|v| matches!(lit.order(v), Some(Ordering::Greater | Ordering::Equal)))
        }
    }
}
