//! Secrets found in cleartext protocols, and what the scans of the Insights page produce.

use std::sync::Arc;

use crate::TlsSession;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CredKind {
    HttpBasic,
    HttpBearer,
    ApiKey,
    Ftp,
    Smtp,
    Pop3,
    Ntlm,
}

impl CredKind {
    pub fn label(self) -> &'static str {
        match self {
            CredKind::HttpBasic => "HTTP Basic login",
            CredKind::HttpBearer => "HTTP bearer token",
            CredKind::ApiKey => "API key or token",
            CredKind::Ftp => "FTP login",
            CredKind::Smtp => "SMTP login",
            CredKind::Pop3 => "POP3 login",
            CredKind::Ntlm => "NTLM login",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub kind: CredKind,
    pub frame: u64,
    pub src: Arc<str>,
    pub dst: Arc<str>,
    pub user: Option<String>,
    pub secret: Option<String>,
    /// Header or query parameter that carried the secret.
    pub field: Option<String>,
    /// How many times the same login was seen (keep-alive and retry repeats are merged).
    pub count: u32,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("kind", &self.kind)
            .field("frame", &self.frame)
            .field("src", &self.src)
            .field("dst", &self.dst)
            .field("user", &self.user)
            .field("secret", &self.masked_secret())
            .field("field", &self.field)
            .field("count", &self.count)
            .finish()
    }
}

impl Credential {
    pub fn masked_secret(&self) -> Option<String> {
        self.secret.as_deref().map(mask)
    }
}

/// Results of the passes that feed the Insights security findings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecurityData {
    pub credentials: Vec<Credential>,
    pub tls: Vec<TlsSession>,
}

const PREFIX_MIN_LEN: usize = 12;
const PREFIX_LEN: usize = 3;

/// Hides a secret but keeps what helps to recognise it: a short prefix of long values (token
/// types such as `sk_`), and always the length.
pub fn mask(secret: &str) -> String {
    let n = secret.chars().count();
    if n >= PREFIX_MIN_LEN {
        let head: String = secret.chars().take(PREFIX_LEN).collect();
        format!("{head}**** ({n} chars)")
    } else {
        format!("**** ({n} chars)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_secrets_leak_only_their_length() {
        assert_eq!(mask("hunter2"), "**** (7 chars)");
        assert_eq!(mask(""), "**** (0 chars)");
    }

    #[test]
    fn long_secrets_keep_a_three_character_prefix() {
        assert_eq!(mask("sk_live_abcdef123456"), "sk_**** (20 chars)");
    }

    #[test]
    fn mask_counts_characters_not_bytes() {
        assert_eq!(mask("pässwörd"), "**** (8 chars)");
    }

    #[test]
    fn masked_secret_follows_the_secret() {
        let mut c = Credential {
            kind: CredKind::Ftp,
            frame: 1,
            src: "a".into(),
            dst: "b".into(),
            user: None,
            secret: None,
            field: None,
            count: 1,
        };
        assert_eq!(c.masked_secret(), None);
        c.secret = Some("abc".into());
        assert_eq!(c.masked_secret().as_deref(), Some("**** (3 chars)"));
    }

    #[test]
    fn debug_output_never_contains_the_secret() {
        let c = Credential {
            kind: CredKind::HttpBasic,
            frame: 1,
            src: "a".into(),
            dst: "b".into(),
            user: Some("alice".into()),
            secret: Some("s3cretPass".into()),
            field: None,
            count: 1,
        };
        let text = format!("{c:?} {:?}", vec![c.clone()]);
        assert!(!text.contains("s3cretPass"), "{text}");
        assert!(text.contains("**** (10 chars)"));
    }
}
