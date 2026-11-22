//! SSH capture target: where `tcpdump` runs and which account runs it. Pure data and validation.
use serde::{Deserialize, Serialize};

pub const SSH_PORT: u32 = 22;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteTarget {
    pub enabled: bool,
    pub host: String,
    pub user: String,
    pub port: u32,
    pub interface: String,
    /// Run tcpdump through `sudo -n` (never prompts).
    pub sudo: bool,
}

impl Default for RemoteTarget {
    fn default() -> Self {
        RemoteTarget {
            enabled: false,
            host: String::new(),
            user: String::new(),
            port: SSH_PORT,
            interface: String::new(),
            sudo: false,
        }
    }
}

fn plain(s: &str, extra: &[char]) -> bool {
    !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

impl RemoteTarget {
    /// `user@host`, or just `host` when no user is given.
    pub fn destination(&self) -> String {
        match self.user.trim() {
            "" => self.host.trim().to_string(),
            u => format!("{u}@{}", self.host.trim()),
        }
    }

    /// Why this target cannot be used, in plain words.
    pub fn problem(&self) -> Option<&'static str> {
        let (host, user, iface) = (self.host.trim(), self.user.trim(), self.interface.trim());
        if host.is_empty() {
            return Some("Enter the remote host.");
        }
        if !plain(host, &['.', '-', ':', '_', '%']) {
            return Some("The host contains characters that are not allowed.");
        }
        if !user.is_empty() && !plain(user, &['.', '-', '_']) {
            return Some("The user name contains characters that are not allowed.");
        }
        if iface.is_empty() {
            return Some("Enter the remote interface (for example eth0 or any).");
        }
        if !plain(iface, &['.', '-', '_', ':', '@']) {
            return Some("The interface name contains characters that are not allowed.");
        }
        if !(1..=65_535).contains(&self.port) {
            return Some("The SSH port must be between 1 and 65535.");
        }
        None
    }

    /// Short label for the status bar ("user@host:eth0").
    pub fn label(&self) -> String {
        format!("{}:{}", self.destination(), self.interface.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> RemoteTarget {
        RemoteTarget {
            enabled: true,
            host: "10.0.0.7".into(),
            user: "ops".into(),
            interface: "eth0".into(),
            ..RemoteTarget::default()
        }
    }

    #[test]
    fn valid_target_has_no_problem() {
        assert_eq!(target().problem(), None);
        assert_eq!(target().label(), "ops@10.0.0.7:eth0");
    }

    #[test]
    fn hostile_values_are_rejected() {
        for bad in [
            "-oProxyCommand=x",
            "a b",
            "h;id",
            "h$(id)",
            "h'x",
            "h\"x",
            "a\nb",
        ] {
            let mut t = target();
            t.host = bad.into();
            assert!(t.problem().is_some(), "host {bad:?}");
            let mut t = target();
            t.user = bad.into();
            assert!(t.problem().is_some(), "user {bad:?}");
            let mut t = target();
            t.interface = bad.into();
            assert!(t.problem().is_some(), "interface {bad:?}");
        }
    }

    #[test]
    fn missing_fields_and_bad_port_are_reported() {
        let mut t = target();
        t.port = 0;
        assert!(t.problem().is_some_and(|p| p.contains("port")));
        t.port = 22;
        t.host.clear();
        assert!(t.problem().is_some_and(|p| p.contains("host")));
        t = target();
        t.interface = " ".into();
        assert!(t.problem().is_some_and(|p| p.contains("interface")));
    }

    #[test]
    fn user_is_optional() {
        let mut t = target();
        t.user.clear();
        assert_eq!(t.problem(), None);
        assert_eq!(t.destination(), "10.0.0.7");
    }
}
