//! Turns the fields of one packet into cleartext credentials. Pure: no tshark involved.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use wl_model::{CredKind, Credential};

use crate::tsv_pass::{columns, opt};

pub const FIELDS: [&str; 19] = [
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
const SECRET_PARAMS: [&str; 10] = [
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "auth_token",
    "token",
    "key",
    "secret",
    "client_secret",
    "password",
];
const MIN_SECRET_LEN: usize = 4;
const ANONYMOUS: [&str; 2] = ["anonymous", "ftp"];
/// tshark joins repeated header lines with a comma after the literal `\r\n`.
const LINE_SEP: &str = "\\r\\n,";
const LINE_END: &str = "\\r\\n";

type Pair = (Arc<str>, Arc<str>);

#[derive(Default)]
pub struct Parser {
    users: HashMap<Pair, String>,
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
        ] = f;
        let (Ok(frame), Some(src), Some(dst)) = (
            frame.trim().parse(),
            opt(ip_src).or(opt(ip6_src)),
            opt(ip_dst).or(opt(ip6_dst)),
        ) else {
            return;
        };
        let pair: Pair = (Arc::from(src), Arc::from(dst));
        let mut pkt = Packet {
            frame,
            src: pair.0.clone(),
            dst: pair.1.clone(),
            out,
        };
        authorization(&mut pkt, auth);
        for (name, value) in header_secrets(lines).chain(query_secrets(uri)) {
            pkt.push(CredKind::ApiKey, None, Some(value), &name);
        }
        self.login(&mut pkt, pair.clone(), CredKind::Ftp, (ftp_cmd, ftp_arg));
        self.login(&mut pkt, pair.clone(), CredKind::Pop3, (pop_cmd, pop_arg));
        self.smtp(
            &mut pkt,
            pair,
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

    fn login(&mut self, pkt: &mut Packet, pair: Pair, kind: CredKind, (cmd, arg): (&str, &str)) {
        match cmd.to_ascii_uppercase().as_str() {
            "USER" => {
                self.users.insert(pair, arg.to_owned());
            }
            "PASS" => {
                let user = self.users.remove(&pair);
                if !user.as_deref().is_some_and(is_anonymous) {
                    pkt.push(kind, user, Some(arg.to_owned()), "");
                }
            }
            _ => {}
        }
    }

    fn smtp(&mut self, pkt: &mut Packet, pair: Pair, cmd: (&str, &str), auth: (&str, &str)) {
        if cmd.0.eq_ignore_ascii_case("AUTH")
            && let Some((user, pass)) = cmd.1.strip_prefix("PLAIN ").and_then(sasl_plain)
        {
            pkt.push(CredKind::Smtp, Some(user), Some(pass), "");
        }
        if let Some(user) = decode_text(auth.0) {
            self.users.insert(pair.clone(), user);
        }
        if let Some(pass) = decode_text(auth.1) {
            pkt.push(CredKind::Smtp, self.users.remove(&pair), Some(pass), "");
        }
    }
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

fn authorization(pkt: &mut Packet, value: &str) {
    let Some((scheme, token)) = value.trim().split_once(' ') else {
        return;
    };
    let token = token.trim();
    match scheme.to_ascii_lowercase().as_str() {
        "basic" => {
            if let Some((user, pass)) = decode_text(token)
                .and_then(|t| t.split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())))
            {
                pkt.push(CredKind::HttpBasic, Some(user), Some(pass), "Authorization");
            }
        }
        "bearer" => pkt.push(
            CredKind::HttpBearer,
            None,
            Some(token.to_owned()),
            "Authorization",
        ),
        "digest" | "ntlm" | "negotiate" | "kerberos" => {}
        _ => pkt.push(
            CredKind::ApiKey,
            None,
            Some(token.to_owned()),
            "Authorization",
        ),
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
        (SECRET_PARAMS.contains(&name.to_ascii_lowercase().as_str())
            && value.len() >= MIN_SECRET_LEN)
            .then(|| (name.to_owned(), value.to_owned()))
    })
}

#[cfg(test)]
#[path = "cred_parse_tests.rs"]
mod tests;
