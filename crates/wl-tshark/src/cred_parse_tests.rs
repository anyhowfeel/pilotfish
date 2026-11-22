use super::*;

/// One tshark line with only the named columns filled in.
fn line(cols: &[(&str, &str)]) -> String {
    let mut v = vec![String::new(); FIELDS.len()];
    v[0] = "7".into();
    v[1] = "10.0.0.2".into();
    v[3] = "10.0.0.9".into();
    for (name, val) in cols {
        let i = FIELDS.iter().position(|f| f == name).expect("field");
        v[i] = (*val).into();
    }
    v.join("\t")
}

fn scan(lines: &[String]) -> Vec<Credential> {
    let (mut p, mut out) = (Parser::default(), Vec::new());
    for l in lines {
        p.push_line(l, &mut out);
    }
    out
}

fn one(cols: &[(&str, &str)]) -> Vec<Credential> {
    scan(&[line(cols)])
}

fn b64(s: &str) -> String {
    STANDARD.encode(s)
}

#[test]
fn basic_auth_is_decoded() {
    let c = one(&[(
        "http.authorization",
        &format!("Basic {}", b64("alice:pa:ss")),
    )]);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].kind, CredKind::HttpBasic);
    assert_eq!(c[0].user.as_deref(), Some("alice"));
    assert_eq!(c[0].secret.as_deref(), Some("pa:ss"));
    assert_eq!(
        (&*c[0].src, &*c[0].dst, c[0].frame),
        ("10.0.0.2", "10.0.0.9", 7)
    );
}

#[test]
fn undecodable_basic_and_modern_schemes_are_ignored() {
    assert!(one(&[("http.authorization", "Basic !!!")]).is_empty());
    assert!(one(&[("http.authorization", "Basic bm9jb2xvbg==")]).is_empty());
    for scheme in [
        "Digest username=x",
        "NTLM abc",
        "Negotiate abc",
        "Kerberos abc",
    ] {
        assert!(
            one(&[("http.authorization", scheme)]).is_empty(),
            "{scheme}"
        );
    }
}

#[test]
fn bearer_and_unknown_schemes_are_tokens() {
    let c = one(&[("http.authorization", "Bearer abc.def.ghi")]);
    assert_eq!(
        (c[0].kind, c[0].secret.as_deref()),
        (CredKind::HttpBearer, Some("abc.def.ghi"))
    );
    let c = one(&[("http.authorization", "Token t0k3n-value")]);
    assert_eq!(c[0].kind, CredKind::ApiKey);
    assert_eq!(c[0].field.as_deref(), Some("Authorization"));
}

#[test]
fn api_key_headers_are_found_among_request_lines() {
    let lines = "Host: x\\r\\n,X-API-Key: sk_live_123456\\r\\n,Accept: */*\\r\\n";
    let c = one(&[("http.request.line", lines)]);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].field.as_deref(), Some("X-API-Key"));
    assert_eq!(c[0].secret.as_deref(), Some("sk_live_123456"));
    assert!(one(&[("http.request.line", "X-Api-Key: ab\\r\\n")]).is_empty());
}

#[test]
fn query_string_secrets_need_a_known_name_and_a_real_value() {
    let c = one(&[(
        "http.request.uri",
        "/s?q=cats&api_key=KEY123456&page=2&Access_Token=abcd",
    )]);
    let got: Vec<_> = c
        .iter()
        .map(|c| (c.field.as_deref(), c.secret.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("api_key"), Some("KEY123456")),
            (Some("Access_Token"), Some("abcd"))
        ]
    );
    assert!(one(&[("http.request.uri", "/s?key=1&q=password")]).is_empty());
    assert!(one(&[("http.request.uri", "/api_key=abcdefgh")]).is_empty());
}

#[test]
fn ftp_and_pop3_pair_user_with_password() {
    let c = scan(&[
        line(&[("ftp.request.command", "USER"), ("ftp.request.arg", "bob")]),
        line(&[
            ("ftp.request.command", "pass"),
            ("ftp.request.arg", "hunter2"),
        ]),
        line(&[
            ("pop.request.command", "USER"),
            ("pop.request.parameter", "erin"),
        ]),
        line(&[
            ("pop.request.command", "PASS"),
            ("pop.request.parameter", "letmein99"),
        ]),
    ]);
    let got: Vec<_> = c
        .iter()
        .map(|c| (c.kind, c.user.as_deref(), c.secret.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (CredKind::Ftp, Some("bob"), Some("hunter2")),
            (CredKind::Pop3, Some("erin"), Some("letmein99")),
        ]
    );
}

#[test]
fn anonymous_ftp_is_not_a_credential() {
    let c = scan(&[
        line(&[
            ("ftp.request.command", "USER"),
            ("ftp.request.arg", "Anonymous"),
        ]),
        line(&[
            ("ftp.request.command", "PASS"),
            ("ftp.request.arg", "me@example.org"),
        ]),
    ]);
    assert!(c.is_empty());
}

#[test]
fn passwords_of_other_connections_are_not_paired() {
    let mut other = line(&[("ftp.request.command", "PASS"), ("ftp.request.arg", "pw")]);
    other = other.replacen("10.0.0.9", "10.0.0.10", 1);
    let c = scan(&[
        line(&[("ftp.request.command", "USER"), ("ftp.request.arg", "bob")]),
        other,
    ]);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].user, None);
}

#[test]
fn smtp_plain_and_login() {
    let plain = format!("PLAIN {}", b64("\0carol\0mailpass1"));
    let c = scan(&[
        line(&[("smtp.req.command", "AUTH"), ("smtp.req.parameter", &plain)]),
        line(&[("smtp.auth.username", &b64("dave"))]),
        line(&[("smtp.auth.password", &b64("davepass"))]),
    ]);
    let got: Vec<_> = c
        .iter()
        .map(|c| (c.user.as_deref(), c.secret.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("carol"), Some("mailpass1")),
            (Some("dave"), Some("davepass"))
        ]
    );
    assert!(c.iter().all(|c| c.kind == CredKind::Smtp));
}

#[test]
fn smtp_auth_without_payload_is_ignored() {
    let c = one(&[
        ("smtp.req.command", "AUTH"),
        ("smtp.req.parameter", "LOGIN"),
    ]);
    assert!(c.is_empty());
}

#[test]
fn ntlm_authenticate_reports_the_account_only() {
    let c = one(&[
        ("ntlmssp.messagetype", "0x00000003"),
        ("ntlmssp.auth.username", "alice"),
        ("ntlmssp.auth.domain", "CORP"),
    ]);
    assert_eq!(c.len(), 1);
    assert_eq!(
        (c[0].kind, c[0].user.as_deref(), c[0].secret.as_deref()),
        (CredKind::Ntlm, Some("CORP\\alice"), None)
    );
    assert!(one(&[("ntlmssp.messagetype", "0x00000001")]).is_empty());
}

#[test]
fn ipv6_endpoints_and_bad_rows() {
    let mut l = line(&[("http.authorization", "Bearer abcdefgh")]);
    l = l.replacen("10.0.0.2", "", 1).replacen("10.0.0.9", "", 1);
    let mut cols: Vec<&str> = l.split('\t').collect();
    cols[2] = "fe80::1";
    cols[4] = "fe80::2";
    let c = scan(&[cols.join("\t"), "garbage".into(), String::new()]);
    assert_eq!(c.len(), 1);
    assert_eq!((&*c[0].src, &*c[0].dst), ("fe80::1", "fe80::2"));
}

#[test]
fn plain_identifiers_named_key_or_token_are_not_secrets() {
    assert!(one(&[("http.request.uri", "/s?key=name&token=next_page_abc")]).is_empty());
}

#[test]
fn password_parameters_are_decoded_before_they_are_kept() {
    let c = one(&[(
        "http.request.uri",
        "/login?pwd=p%40ss+word&passwd=%zz1234&password=ab%2",
    )]);
    let got: Vec<_> = c
        .iter()
        .map(|c| (c.field.as_deref(), c.secret.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("pwd"), Some("p@ss word")),
            (Some("passwd"), Some("%zz1234")),
            (Some("password"), Some("ab%2")),
        ]
    );
}

#[test]
fn signed_aws_requests_are_not_api_keys() {
    let auth = "AWS4-HMAC-SHA256 Credential=AKIA/20240101/us-east-1/s3/aws4_request, Signature=abc";
    assert!(one(&[("http.authorization", auth)]).is_empty());
}

#[test]
fn proxy_basic_credentials_are_found() {
    let c = one(&[(
        "http.proxy_authorization",
        &format!("Basic {}", b64("proxyuser:proxypw")),
    )]);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].kind, CredKind::HttpBasic);
    assert_eq!(c[0].field.as_deref(), Some("Proxy-Authorization"));
}

#[test]
fn an_empty_basic_password_is_kept_as_an_empty_secret() {
    let c = one(&[("http.authorization", &format!("Basic {}", b64("token123:")))]);
    assert_eq!(c[0].secret.as_deref(), Some(""));
}

fn on_stream(stream: &str, cols: &[(&str, &str)]) -> String {
    let mut all = cols.to_vec();
    all.push(("tcp.stream", stream));
    line(&all)
}

#[test]
fn users_wait_for_their_password_in_the_same_connection_only() {
    let user = |s, n| {
        on_stream(
            s,
            &[("ftp.request.command", "USER"), ("ftp.request.arg", n)],
        )
    };
    let pass = |s, p| {
        on_stream(
            s,
            &[("ftp.request.command", "PASS"), ("ftp.request.arg", p)],
        )
    };
    let c = scan(&[
        user("1", "bob"),
        user("2", "carl"),
        pass("1", "pw-one"),
        pass("2", "pw-two"),
    ]);
    let got: Vec<_> = c
        .iter()
        .map(|c| (c.user.as_deref(), c.secret.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("bob"), Some("pw-one")),
            (Some("carl"), Some("pw-two"))
        ]
    );
}

#[test]
fn a_user_of_one_protocol_is_not_paired_with_a_password_of_another() {
    let c = scan(&[
        on_stream(
            "4",
            &[("ftp.request.command", "USER"), ("ftp.request.arg", "bob")],
        ),
        on_stream(
            "4",
            &[
                ("pop.request.command", "PASS"),
                ("pop.request.parameter", "pw"),
            ],
        ),
        on_stream("4", &[("smtp.auth.password", &b64("smtppw"))]),
    ]);
    assert_eq!(c.len(), 2);
    assert!(c.iter().all(|c| c.user.is_none()));
}

#[test]
fn smtp_auth_is_case_insensitive_and_accepts_an_initial_login_user() {
    let plain = format!("plain {}", b64("\0carol\0mailpass1"));
    let c = scan(&[
        line(&[("smtp.req.command", "auth"), ("smtp.req.parameter", &plain)]),
        on_stream(
            "9",
            &[
                ("smtp.req.command", "AUTH"),
                ("smtp.req.parameter", &format!("LOGIN {}", b64("dave"))),
            ],
        ),
        on_stream("9", &[("smtp.auth.password", &b64("davepass"))]),
    ]);
    let got: Vec<_> = c
        .iter()
        .map(|c| (c.user.as_deref(), c.secret.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (Some("carol"), Some("mailpass1")),
            (Some("dave"), Some("davepass"))
        ]
    );
}

#[test]
fn pending_users_stay_bounded() {
    let mut p = Parser::default();
    let mut out = Vec::new();
    for n in 0..MAX_PENDING_USERS * 3 {
        let l = on_stream(
            &n.to_string(),
            &[("ftp.request.command", "USER"), ("ftp.request.arg", "bob")],
        );
        p.push_line(&l, &mut out);
    }
    assert!(p.users.len() <= MAX_PENDING_USERS);
}

#[test]
fn tunnelled_packets_use_the_outer_addresses() {
    let mut l = line(&[("http.authorization", "Bearer abcdefgh")]);
    l = l.replacen("10.0.0.2", "10.0.0.2,192.168.1.2", 1).replacen(
        "10.0.0.9",
        "10.0.0.9,192.168.1.9",
        1,
    );
    let c = scan(&[l]);
    assert_eq!((&*c[0].src, &*c[0].dst), ("10.0.0.2", "10.0.0.9"));
}
