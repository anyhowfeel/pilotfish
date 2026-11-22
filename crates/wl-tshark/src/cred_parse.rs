//! Turns the fields of one packet into cleartext credentials. Pure: no tshark involved.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use wl_model::{CredKind, Credential};

use crate::tsv_pass::{columns, opt};

pub const FIELDS: [&str; 21] = [
    "frame.number",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "http.request.uri",
    "http.authorization",
    "http.request.line",
    "ftp.request.command",
    "ftp.request.arg",
    "smtp.req.command",
    "smtp.req.parameter",
    "smtp.auth.username",
    "smtp.auth.password",
    "pop.request.command",
    "pop.request.parameter",
    "ntlmssp.messagetype",
    "ntlmssp.auth.username",
    "ntlmssp.auth.domain",
    "http.proxy_authorization",
    "tcp.stream",
];

pub const FILTER: &str = "http.request || ftp.request || smtp.req || smtp.auth.username \
                          || smtp.auth.password || pop.request || ntlmssp.messagetype == 3";

const SECRET_HEADERS: [&str; 7] = [
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-api-token",
    "private-token",
];
/// Names that clearly hold a secret; a bare `key` or `token` is too often a plain identifier.
const SECRET_PARAMS: [&str; 15] = [
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "auth_token",
    "session_token",
    "refresh_token",
    "id_token",
    "private_key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "x-api-key",
];
/// Request signatures and challenge schemes carry no replayable secret.
const SIGNED_SCHEMES: [&str; 5] = [
    "digest",
    "ntlm",
    "negotiate",
    "kerberos",
    "aws4-hmac-sha256",
];
/// Half-finished USER commands kept at once; a hostile capture cannot grow the map beyond it.
const MAX_PENDING_USERS: usize = 4_096;
const MIN_SECRET_LEN: usize = 4;
const ANONYMOUS: [&str; 2] = ["anonymous", "ftp"];
/// tshark joins repeated header lines with a comma after the literal `\r\n`.
const LINE_SEP: &str = "\\r\\n,";
const LINE_END: &str = "\\r\\n";

/// A user name waits for its password in the same connection and protocol.
type Pending = (CredKind, String);

#[derive(Default)]
pub struct Parser {
    users: HashMap<Pending, String>,
}

struct Packet<'a> {
    frame: u64,
    src: Arc<str>,
    dst: Arc<str>,
    out: &'a mut Vec<Credential>,
}

impl Packet<'_> {
    fn push(&mut self, kind: CredKind, user: Option<String>, secret: Option<String>, field: &str) {
        self.out.push(Credential {
            kind,
            frame: self.frame,
            src: self.src.clone(),
            dst: self.dst.clone(),
            user,
            secret,
            field: opt(field).map(str::to_owned),
            count: 1,
        });
    }
}

impl Parser {
    pub fn push_line(&mut self, line: &str, out: &mut Vec<Credential>) {
        let f: [&str; FIELDS.len()] = columns(line);
        let [
            frame,
            ip_src,
            ip6_src,
            ip_dst,
            ip6_dst,
            uri,
            auth,
            lines,
            ftp_cmd,
            ftp_arg,
            smtp_cmd,
            smtp_param,
            smtp_user,
            smtp_pass,
            pop_cmd,
            pop_arg,
            ntlm_type,
            ntlm_user,
            ntlm_domain,
            proxy_auth,
            stream,
        ] = f;
        let (Ok(frame), Some(src), Some(dst)) = (
            frame.trim().parse(),
            opt(first(ip_src)).or(opt(first(ip6_src))),
            opt(first(ip_dst)).or(opt(first(ip6_dst))),
        ) else {
            return;
        };
        let conn = opt(first(stream)).map_or_else(|| format!("{src}>{dst}"), str::to_owned);
        let mut pkt = Packet {
            frame,
            src: Arc::from(src),
            dst: Arc::from(dst),
            out,
        };
        authorization(&mut pkt, auth, "Authorization");
        authorization(&mut pkt, proxy_auth, "Proxy-Authorization");
        for (name, value) in header_secrets(lines).chain(query_secrets(uri)) {
            pkt.push(CredKind::ApiKey, None, Some(value), &name);
        }
        self.login(&mut pkt, &conn, CredKind::Ftp, (ftp_cmd, ftp_arg));
        self.login(&mut pkt, &conn, CredKind::Pop3, (pop_cmd, pop_arg));
        self.smtp(
            &mut pkt,
            &conn,
            (smtp_cmd, smtp_param),
            (smtp_user, smtp_pass),
        );
        if ntlm_type == "0x00000003" && !ntlm_user.is_empty() {
            let user = if ntlm_domain.is_empty() {
                ntlm_user.to_owned()
            } else {
                format!("{ntlm_domain}\\{ntlm_user}")
            };
            pkt.push(CredKind::Ntlm, Some(user), None, "");
        }
    }

    fn remember(&mut self, kind: CredKind, conn: &str, user: String) {
        if self.users.len() >= MAX_PENDING_USERS {
            self.users.clear();
        }
        self.users.insert((kind, conn.to_owned()), user);
    }

    fn take(&mut self, kind: CredKind, conn: &str) -> Option<String> {
        self.users.remove(&(kind, conn.to_owned()))
    }

    fn login(&mut self, pkt: &mut Packet, conn: &str, kind: CredKind, (cmd, arg): (&str, &str)) {
        match cmd.to_ascii_uppercase().as_str() {
            "USER" => self.remember(kind, conn, arg.to_owned()),
            "PASS" => {
                let user = self.take(kind, conn);
                if !user.as_deref().is_some_and(is_anonymous) {
                    pkt.push(kind, user, Some(arg.to_owned()), "");
                }
            }
            _ => {}
        }
    }

    fn smtp(&mut self, pkt: &mut Packet, conn: &str, cmd: (&str, &str), auth: (&str, &str)) {
        if cmd.0.eq_ignore_ascii_case("AUTH") {
            let mut words = cmd.1.split_whitespace();
            let mechanism = words.next().unwrap_or_default().to_ascii_uppercase();
            let initial = words.next();
            match (mechanism.as_str(), initial) {
                ("PLAIN", Some(b64)) => {
                    if let Some((user, pass)) = sasl_plain(b64) {
                        pkt.push(CredKind::Smtp, Some(user), Some(pass), "");
                    }
                }
                ("LOGIN", Some(b64)) => {
                    if let Some(user) = decode_text(b64) {
                        self.remember(CredKind::Smtp, conn, user);
                    }
                }
                _ => {}
            }
        }
        if let Some(user) = decode_text(auth.0) {
            self.remember(CredKind::Smtp, conn, user);
        }
        if let Some(pass) = decode_text(auth.1) {
            pkt.push(
                CredKind::Smtp,
                self.take(CredKind::Smtp, conn),
                Some(pass),
                "",
            );
        }
    }
}

/// With `occurrence=a` a tunnelled packet lists outer and inner values: `a,b`.
fn first(value: &str) -> &str {
    value.split(',').next().unwrap_or_default().trim()
}

fn is_anonymous(user: &str) -> bool {
    ANONYMOUS.iter().any(|a| user.eq_ignore_ascii_case(a))
}

fn decode_text(b64: &str) -> Option<String> {
    let bytes = STANDARD.decode(b64.trim()).ok()?;
    String::from_utf8(bytes).ok().filter(|s| !s.is_empty())
}

/// SASL PLAIN: `authzid NUL user NUL password`.
fn sasl_plain(b64: &str) -> Option<(String, String)> {
    let text = decode_text(b64)?;
    let mut parts = text.rsplitn(3, '\0');
    let (pass, user) = (parts.next()?, parts.next()?);
    Some((user.to_owned(), pass.to_owned()))
}

fn authorization(pkt: &mut Packet, value: &str, header: &str) {
    let Some((scheme, token)) = value.trim().split_once(' ') else {
        return;
    };
    let token = token.trim();
    match scheme.to_ascii_lowercase().as_str() {
        "basic" => {
            if let Some((user, pass)) = decode_text(token)
                .and_then(|t| t.split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())))
            {
                pkt.push(CredKind::HttpBasic, Some(user), Some(pass), header);
            }
        }
        "bearer" => pkt.push(CredKind::HttpBearer, None, Some(token.to_owned()), header),
        s if SIGNED_SCHEMES.contains(&s) => {}
        _ => pkt.push(CredKind::ApiKey, None, Some(token.to_owned()), header),
    }
}

fn header_secrets(lines: &str) -> impl Iterator<Item = (String, String)> + '_ {
    lines.split(LINE_SEP).filter_map(|l| {
        let (name, value) = l.trim_end_matches(LINE_END).split_once(':')?;
        let (name, value) = (name.trim(), value.trim());
        (SECRET_HEADERS.contains(&name.to_ascii_lowercase().as_str())
            && value.len() >= MIN_SECRET_LEN)
            .then(|| (name.to_owned(), value.to_owned()))
    })
}

fn query_secrets(uri: &str) -> impl Iterator<Item = (String, String)> + '_ {
    let query = uri.split_once('?').map_or("", |(_, q)| q);
    query.split('&').filter_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        let value = percent_decode(value);
        (SECRET_PARAMS.contains(&name.to_ascii_lowercase().as_str())
            && value.len() >= MIN_SECRET_LEN)
            .then(|| (name.to_owned(), value))
    })
}

/// Form decoding of a query value: `%XX` bytes and `+` as a space.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
            .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
        match hex {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
#[path = "cred_parse_tests.rs"]
mod tests;
