use super::ast::{Expr, Op};
use super::field::Field;
use super::literal::Lit;
use super::parse;

fn ast(text: &str) -> Expr {
    parse(text).unwrap_or_else(|| panic!("{text} parses")).expr
}

fn rejected(text: &str) -> bool {
    parse(text).is_none()
}

const TCP: Expr = Expr::Present(Field::Tcp);
const UDP: Expr = Expr::Present(Field::Udp);
const ICMP: Expr = Expr::Present(Field::Icmp);

fn not(e: Expr) -> Expr {
    Expr::Not(Box::new(e))
}

#[test]
fn and_binds_tighter_than_or() {
    assert_eq!(
        ast("tcp || udp && icmp"),
        Expr::Or(vec![TCP, Expr::And(vec![UDP, ICMP])])
    );
    assert_eq!(
        ast("tcp && udp || icmp"),
        Expr::Or(vec![Expr::And(vec![TCP, UDP]), ICMP])
    );
}

#[test]
fn not_binds_tighter_than_and() {
    assert_eq!(ast("!tcp && udp"), Expr::And(vec![not(TCP), UDP]));
    assert_eq!(ast("tcp && !udp"), Expr::And(vec![TCP, not(UDP)]));
}

#[test]
fn not_covers_the_whole_comparison() {
    assert_eq!(
        ast("!tcp.port == 80"),
        not(Expr::Cmp(Field::TcpPort, Op::Eq, Lit::Num(80)))
    );
}

#[test]
fn parentheses_override_precedence() {
    assert_eq!(
        ast("(tcp || udp) && icmp"),
        Expr::And(vec![Expr::Or(vec![TCP, UDP]), ICMP])
    );
    assert_eq!(ast("!(tcp || udp)"), not(Expr::Or(vec![TCP, UDP])));
    assert_eq!(ast("((tcp))"), TCP);
}

#[test]
fn double_negation_is_kept() {
    assert_eq!(ast("!!tcp"), not(not(TCP)));
    assert_eq!(ast("not not tcp"), not(not(TCP)));
}

#[test]
fn chains_are_flat() {
    assert_eq!(ast("tcp && udp && icmp"), Expr::And(vec![TCP, UDP, ICMP]));
    assert_eq!(ast("tcp or udp or icmp"), Expr::Or(vec![TCP, UDP, ICMP]));
}

#[test]
fn word_and_symbol_spellings_are_the_same_filter() {
    let pairs = [
        ("tcp && udp", "tcp and udp"),
        ("tcp || udp", "tcp or udp"),
        ("!tcp", "not tcp"),
        ("tcp.port == 80", "tcp.port eq 80"),
        ("tcp.port != 80", "tcp.port ne 80"),
        ("tcp.port < 80", "tcp.port lt 80"),
        ("tcp.port <= 80", "tcp.port le 80"),
        ("tcp.port > 80", "tcp.port gt 80"),
        ("tcp.port >= 80", "tcp.port ge 80"),
        ("tcp.port==80&&udp", "tcp.port == 80 && udp"),
    ];
    for (a, b) in pairs {
        assert_eq!(ast(a), ast(b), "{a} vs {b}");
    }
}

#[test]
fn comparisons_carry_field_operator_and_value() {
    assert_eq!(
        ast("frame.number >= 10"),
        Expr::Cmp(Field::FrameNumber, Op::Ge, Lit::Num(10))
    );
    assert_eq!(
        ast("tcp.port == 0x50"),
        Expr::Cmp(Field::TcpPort, Op::Eq, Lit::Num(80))
    );
    assert_eq!(
        ast("tcp.flags.syn == true"),
        Expr::Cmp(Field::Syn, Op::Eq, Lit::Num(1))
    );
}

#[test]
fn sets_take_commas_only() {
    assert_eq!(
        ast("tcp.port in {80, 443}"),
        Expr::In(Field::TcpPort, vec![Lit::Num(80), Lit::Num(443)])
    );
    assert_eq!(
        ast("tcp.port in {80}"),
        Expr::In(Field::TcpPort, vec![Lit::Num(80)])
    );
    assert!(rejected("tcp.port in {80 443}"));
    assert!(rejected("tcp.port in {}"));
    assert!(rejected("tcp.port in {80,}"));
    assert!(rejected("tcp.port in {80"));
    assert!(rejected("tcp.port in 80"));
    assert!(rejected("tcp.port in {80..90}"));
    assert!(rejected("tcp.port not in {80}"));
}

#[test]
fn unknown_or_unsupported_input_is_rejected() {
    for text in [
        "",
        "   ",
        "foo",
        "foo == 1",
        "mdns",
        "dns.flags.rcode != 0",
        "dns.qry.name == x",
        "tls.handshake.type == 1",
        "icmp.type == 8",
        "tcp.flags == 2",
        "tcp.flags.urg == 1",
        "http.host == x",
        "tcp.analysis.retransmission",
        "tcp.analysis.flags",
        "len(tcp.port) > 2",
        "tcp.port[0] == 1",
        "eth.dst[0] & 1",
        "frame contains \"x\"",
        "ip.src contains 1",
        "tcp.port matches 1",
        "frame.time_relative > 1",
        "sll.pkttype == 1",
        "vlan",
        "vlan.id == 100",
        "tcp.port ~= 80",
        "tcp.port any_eq 80",
        "tcp.port === 80",
        "tcp.port == udp.port",
        "80 == tcp.port",
        "tcp.port ==",
        "== 80",
        "tcp &&",
        "&& tcp",
        "tcp tcp",
        "tcp udp",
        "(tcp",
        "tcp)",
        "()",
        "tcp ^^ udp",
        "tcp xor udp",
        "!",
        "tcp.port = 80",
        "tcp.port == 80 == 80",
        "tcp.port == 80 80",
    ] {
        assert!(rejected(text), "{text:?} should be refused");
    }
}

#[test]
fn values_must_fit_the_field() {
    for text in [
        "tcp.port == 65536",
        "tcp.port == 0x10000",
        "tcp.port == -1",
        "tcp.port == 08",
        "tcp.port == 1.5",
        "tcp.port == abc",
        "tcp.port == 0x",
        "tcp.port == 0x+1",
        "ip.ttl == 256",
        "frame.number == 4294967296",
        "tcp.flags.syn == 2",
        "tcp.flags.syn < 1",
        "tcp.flags.syn == yes",
        "ip.addr == 1.2.3",
        "ip.addr == 1.2.3.256",
        "ip.addr == 01.2.3.4",
        "ip.addr == 1.2.3.4/33",
        "ip.addr == 1.2.3.4/",
        "ip.addr == 1.2.3.4/08",
        "ip.addr == ::1",
        "ip.addr > 1.2.3.4",
        "ip.addr == 80",
        "ipv6.addr == 1.2.3.4",
        "ipv6.addr == ::1/129",
        "ipv6.addr == fe80:::1",
        "eth.dst == ff:ff:ff:ff:ff",
        "eth.dst == ff:ff:ff:ff:ff:ff:ff",
        "eth.dst == fff:ff:ff:ff:ff:ff",
        "eth.dst == gg:ff:ff:ff:ff:ff",
        "eth.dst == ff:ff:ff:ff:ff:ff/8",
        "eth.dst < ff:ff:ff:ff:ff:ff",
        "tcp == 1",
        "tcp > 1",
    ] {
        assert!(rejected(text), "{text:?} should be refused");
    }
}

#[test]
fn nesting_is_capped_without_overflowing_the_stack() {
    let deep = |n: usize| format!("{}tcp{}", "(".repeat(n), ")".repeat(n));
    assert!(parse(&deep(20)).is_some());
    assert!(rejected(&deep(33_000)));
    assert!(rejected(&format!("{}tcp", "!".repeat(100_000))));
    assert!(rejected(&"(".repeat(100_000)));
}

#[test]
fn long_flat_chains_are_fine() {
    let long = vec!["tcp"; 50_000].join(" && ");
    assert!(parse(&long).is_some());
}
