//! Persisted session state, user-editable color rules, and async name-resolution toggle.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wl_model::{ColorRule, PacketBookmark, PacketRow};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorRuleSet {
    pub rules: Vec<ColorRule>,
}

impl Default for ColorRuleSet {
    fn default() -> Self {
        Self {
            rules: default_color_rules(),
        }
    }
}

pub fn default_color_rules() -> Vec<ColorRule> {
    [
        ("TCP Reset / Bad", "RST", [242, 97, 111]),
        ("TCP Retransmission", "Retransmission", [245, 185, 74]),
        ("HTTP", "HTTP", [61, 214, 140]),
        ("TLS / HTTPS", "TLS", [124, 134, 247]),
        ("DNS", "DNS", [86, 182, 242]),
        ("ICMP", "ICMP", [214, 134, 247]),
    ]
    .into_iter()
    .map(|(name, pattern, color_rgb)| ColorRule {
        name: name.into(),
        pattern: pattern.into(),
        color_rgb,
        enabled: true,
    })
    .collect()
}

impl ColorRuleSet {
    /// Returns the RGB color of the first enabled rule matching `row.protocol` or `row.info`.
    pub fn match_row(&self, row: &PacketRow) -> Option<[u8; 3]> {
        let proto = row.protocol.to_ascii_lowercase();
        let info = row.info.to_ascii_lowercase();
        for rule in &self.rules {
            let pat = rule.pattern.trim().to_ascii_lowercase();
            if rule.enabled
                && !pat.is_empty()
                && (proto == pat || proto.contains(&pat) || info.contains(&pat))
            {
                return Some(rule.color_rgb);
            }
        }
        None
    }

    pub fn add_rule(&mut self, rule: ColorRule) {
        self.rules.push(rule);
    }

    pub fn toggle(&mut self, idx: usize) -> bool {
        let Some(r) = self.rules.get_mut(idx) else {
            return false;
        };
        r.enabled = !r.enabled;
        true
    }

    pub fn remove(&mut self, idx: usize) -> Option<ColorRule> {
        (idx < self.rules.len()).then(|| self.rules.remove(idx))
    }
}

/// Persisted workspace session (theme, last capture/filter, name resolution, color rules, bookmarks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionState {
    pub dark_mode: bool,
    pub resolve_names: bool,
    pub last_file: Option<PathBuf>,
    pub last_page: String,
    pub last_filter: String,
    pub color_rules: Vec<ColorRule>,
    pub bookmarks: Vec<PacketBookmark>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            dark_mode: true,
            resolve_names: true,
            last_file: None,
            last_page: "Overview".into(),
            last_filter: String::new(),
            color_rules: default_color_rules(),
            bookmarks: Vec::new(),
        }
    }
}

impl SessionState {
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("pilotfish").join("session.json"))
    }

    /// Loads session JSON from `path`, gracefully falling back to defaults if missing or corrupt.
    pub fn load_from(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save_to(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    pub fn apply_theme(&self) {
        wl_kit::theme::set_mode(if self.dark_mode {
            wl_kit::theme::Mode::Dark
        } else {
            wl_kit::theme::Mode::Light
        });
    }

    pub fn toggle_theme(&mut self) -> bool {
        self.dark_mode = !self.dark_mode;
        self.apply_theme();
        self.dark_mode
    }
}

/// Gate controlling whether reverse-DNS host resolution is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameResolutionToggle {
    pub enabled: bool,
}

impl Default for NameResolutionToggle {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl NameResolutionToggle {
    pub fn set(&mut self, enabled: bool) -> bool {
        let changed = self.enabled != enabled;
        self.enabled = enabled;
        changed
    }

    pub fn resolve_or_raw(
        &self,
        addr: &str,
        lookup: impl FnOnce(&str) -> Option<String>,
    ) -> Option<String> {
        self.enabled.then(|| lookup(addr)).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::Transport;

    fn row(proto: &str, info: &str) -> PacketRow {
        PacketRow {
            no: 1,
            epoch: 0.0,
            rel: 0.0,
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            transport: Transport::Tcp,
            protocol: proto.into(),
            len: 64,
            info: info.into(),
            stream: None,
        }
    }

    #[test]
    fn color_rules_match_toggle_and_remove() {
        let mut set = ColorRuleSet::default();
        assert_eq!(
            set.match_row(&row("TCP", "[RST, ACK] Seq=1")),
            Some([242, 97, 111])
        );
        assert_eq!(
            set.match_row(&row("DNS", "Standard query")),
            Some([86, 182, 242])
        );
        assert!(set.toggle(0));
        assert_eq!(set.match_row(&row("TCP", "[RST, ACK] Seq=1")), None);
        assert!(set.remove(0).is_some());
    }

    #[test]
    fn session_persists_and_handles_corrupt_files() {
        let path = std::env::temp_dir().join(format!("wl-session-{}.json", std::process::id()));
        let mut state = SessionState {
            dark_mode: false,
            resolve_names: false,
            last_file: Some(PathBuf::from("/tmp/demo.pcapng")),
            last_page: "Packets".into(),
            last_filter: "tcp.port == 443".into(),
            bookmarks: vec![PacketBookmark {
                frame_no: 4,
                comment: "TLS ClientHello".into(),
            }],
            ..Default::default()
        };
        state.save_to(&path).unwrap();
        assert_eq!(SessionState::load_from(&path), state);
        std::fs::write(&path, b"{not valid json").unwrap();
        assert_eq!(SessionState::load_from(&path), SessionState::default());
        let _ = std::fs::remove_file(&path);

        let mut nr = NameResolutionToggle::default();
        assert_eq!(
            nr.resolve_or_raw("1.1.1.1", |_| Some("one.one".into()))
                .as_deref(),
            Some("one.one")
        );
        assert!(nr.set(false));
        assert_eq!(
            nr.resolve_or_raw("1.1.1.1", |_| Some("one.one".into())),
            None
        );
        assert!(state.toggle_theme());
    }
}
