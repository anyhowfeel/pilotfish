use std::net::Ipv4Addr;

use super::*;
use crate::test_util::{dns_query_payload, dns_response_payload};

#[test]
fn standard_query() {
    let q = dns_query_payload(0x56ce, "github.com");
    assert_eq!(
        info(&q, false).as_deref(),
        Some("Standard query 0x56ce A github.com")
    );
}

#[test]
fn response_lists_question_and_answers_with_a_compression_pointer() {
    let r = dns_response_payload(7, "example.com", Ipv4Addr::new(93, 184, 216, 34));
    assert_eq!(
        info(&r, false).as_deref(),
        Some("Standard query response 0x0007 A example.com A 93.184.216.34")
    );
}

#[test]
fn error_codes_are_named() {
    let mut r = dns_query_payload(1, "nope.test");
    r[2] = 0x81;
    r[3] = 0x83;
    assert_eq!(
        info(&r, false).as_deref(),
        Some("Standard query response 0x0001 No such name A nope.test")
    );
}

#[test]
fn mdns_questions_carry_the_qm_or_qu_mark() {
    let mut q = dns_query_payload(0, "_googlecast._tcp.local");
    let n = q.len();
    q[n - 3] = 12;
    assert_eq!(
        info(&q, true).as_deref(),
        Some("Standard query 0x0000 PTR _googlecast._tcp.local, \"QM\" question")
    );
    q[n - 2] = 0x80;
    assert!(info(&q, true).unwrap().ends_with("\"QU\" question"));
}

fn record(name: &[u8], ty: u16, rdata: &[u8]) -> Vec<u8> {
    let mut r = name.to_vec();
    r.extend_from_slice(&ty.to_be_bytes());
    r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(rdata);
    r
}

fn response(records: &[Vec<u8>]) -> Vec<u8> {
    let mut m = dns_query_payload(9, "a.test");
    m[2] = 0x81;
    m[3] = 0x80;
    m[7] = records.len() as u8;
    for r in records {
        m.extend_from_slice(r);
    }
    m
}

#[test]
fn record_data_is_rendered_per_type() {
    let ptr = [0xc0, 12];
    let cname = record(&ptr, 5, &[3, b'b', b'b', b'b', 0]);
    let aaaa = record(
        &ptr,
        28,
        &[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    let mx = record(&ptr, 15, &[0, 10, 4, b'm', b'a', b'i', b'l', 0]);
    let m = response(&[cname, aaaa, mx]);
    assert_eq!(
        info(&m, false).as_deref(),
        Some("Standard query response 0x0009 A a.test CNAME bbb AAAA 2001:db8::1 MX 10 mail")
    );
}

#[test]
fn unknown_types_are_named_by_number() {
    let m = response(&[record(&[0xc0, 12], 999, &[1, 2])]);
    assert!(info(&m, false).unwrap().ends_with("Unknown (999)"));
    assert_eq!(type_name(41), "OPT");
}

#[test]
fn pointer_loops_and_forward_pointers_end_cleanly() {
    let mut m = dns_query_payload(1, "a.test");
    m[12] = 0xc0;
    m[13] = 12;
    assert_eq!(info(&m, false).as_deref(), Some("Standard query 0x0001"));
    let mut m2 = dns_query_payload(1, "a.test");
    m2[12] = 0xc0;
    m2[13] = 0xff;
    assert_eq!(info(&m2, false).as_deref(), Some("Standard query 0x0001"));
}

#[test]
fn reserved_label_types_are_rejected() {
    let mut m = dns_query_payload(1, "a.test");
    m[12] = 0x80;
    assert_eq!(info(&m, false).as_deref(), Some("Standard query 0x0001"));
}

#[test]
fn control_bytes_in_names_are_escaped() {
    let mut m = dns_query_payload(1, "a.test");
    m[13] = 0x07;
    assert!(info(&m, false).unwrap().contains("\\007"));
}

#[test]
fn every_truncation_of_a_response_is_safe() {
    let m = response(&[record(&[0xc0, 12], 1, &[1, 2, 3, 4])]);
    for n in 0..m.len() {
        let out = info(&m[..n], false);
        assert_eq!(out.is_some(), n >= 12, "{n}");
    }
}

#[test]
fn a_huge_record_count_is_capped() {
    let mut m = dns_query_payload(1, "a.test");
    m[4] = 0xff;
    m[5] = 0xff;
    m[6] = 0xff;
    m[7] = 0xff;
    assert!(info(&m, false).is_some());
}

#[test]
fn opcodes_are_named() {
    let mut m = dns_query_payload(1, "a.test");
    m[2] = 0x28;
    assert!(info(&m, false).unwrap().starts_with("Update 0x0001"));
    m[2] = 0x78;
    assert!(info(&m, false).unwrap().starts_with("Unknown operation"));
}
