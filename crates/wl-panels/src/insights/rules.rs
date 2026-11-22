//! What the user tunes on the Insights page: detection thresholds, the findings to hide and
//! whether secrets are shown. Stored with the settings.
use serde::{Deserialize, Serialize};
use wl_kit::text::contains_ci;
use wl_model::HealthInsight;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    pub scan_min_ports: u32,
    pub sweep_min_hosts: u32,
    pub sweep_max_tries_per_host: u32,
    pub beacon_min_events: u32,
    pub beacon_min_period_secs: u32,
    pub beacon_max_jitter_pct: u32,
    pub dns_long_name: u32,
    pub dns_long_label: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            scan_min_ports: 20,
            sweep_min_hosts: 20,
            sweep_max_tries_per_host: 3,
            beacon_min_events: 8,
            beacon_min_period_secs: 1,
            beacon_max_jitter_pct: 10,
            dns_long_name: 60,
            dns_long_label: 40,
        }
    }
}

impl Thresholds {
    pub fn clamped(mut self) -> Self {
        self.scan_min_ports = self.scan_min_ports.clamp(2, 1_000);
        self.sweep_min_hosts = self.sweep_min_hosts.clamp(2, 1_000);
        self.sweep_max_tries_per_host = self.sweep_max_tries_per_host.clamp(1, 100);
        self.beacon_min_events = self.beacon_min_events.clamp(4, 1_000);
        self.beacon_min_period_secs = self.beacon_min_period_secs.clamp(1, 3_600);
        self.beacon_max_jitter_pct = self.beacon_max_jitter_pct.clamp(1, 50);
        self.dns_long_label = self.dns_long_label.clamp(8, 63);
        self.dns_long_name = self.dns_long_name.clamp(self.dns_long_label, 253);
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct InsightRules {
    pub thresholds: Thresholds,
    /// Findings naming one of these hosts, or whose title contains one of these words, are hidden.
    pub muted: Vec<String>,
    /// Session only: never written to the settings file.
    #[serde(skip)]
    pub reveal_secrets: bool,
}

/// Shorter text patterns would match nearly every title.
const MIN_PATTERN_LEN: usize = 3;

fn is_valid_pattern(p: &str) -> bool {
    p.parse::<std::net::IpAddr>().is_ok() || p.chars().count() >= MIN_PATTERN_LEN
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuteChoice {
    pub label: String,
    pub pattern: String,
}

impl InsightRules {
    pub fn clamped(mut self) -> Self {
        self.thresholds = self.thresholds.clamped();
        self.muted.retain(|p| is_valid_pattern(p.trim()));
        self.muted.dedup();
        self
    }

    pub fn hides(&self, f: &HealthInsight) -> bool {
        let hosts = title_hosts(&f.title);
        self.muted.iter().filter(|p| is_valid_pattern(p)).any(|p| {
            if p.parse::<std::net::IpAddr>().is_ok() {
                hosts.contains(p)
            } else {
                contains_ci(&f.title, &p.to_lowercase())
            }
        })
    }

    /// Adds a pattern; false when it was too short to be specific or already muted.
    pub fn mute(&mut self, pattern: &str) -> bool {
        let pattern = pattern.trim();
        let new = is_valid_pattern(pattern) && !self.muted.iter().any(|p| p == pattern);
        if new {
            self.muted.push(pattern.to_owned());
        }
        new
    }
}

/// What a right-click on `f` offers to hide: each host named in the title, the kind of finding
/// (the title up to its colon) and the exact title.
pub fn mute_choices(f: &HealthInsight) -> Vec<MuteChoice> {
    let mut out: Vec<MuteChoice> = Vec::new();
    let mut add = |label: String, pattern: &str| {
        if is_valid_pattern(pattern) && !out.iter().any(|c| c.pattern == pattern) {
            out.push(MuteChoice {
                label,
                pattern: pattern.to_owned(),
            });
        }
    };
    for host in title_hosts(&f.title) {
        add(format!("Mute host {host}"), &host);
    }
    if let Some((kind, _)) = f.title.split_once(':') {
        add(format!("Mute \"{kind}\" findings"), kind);
    }
    add("Mute this finding".to_owned(), &f.title);
    out
}

fn title_hosts(title: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for word in title.split_whitespace() {
        let word = word.trim_matches(|c: char| matches!(c, ':' | ',' | '(' | ')'));
        let bare = word.rsplit_once(':').map_or(word, |(h, _)| h);
        let host = [word, bare]
            .into_iter()
            .find(|w| w.parse::<std::net::IpAddr>().is_ok());
        if let Some(h) = host.filter(|h| !hosts.iter().any(|x| x == h)) {
            hosts.push(h.to_owned());
        }
    }
    hosts
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
