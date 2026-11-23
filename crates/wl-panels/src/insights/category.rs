//! Finding categories: keyword inference from a finding and plain-language hints.
use wl_model::HealthInsight;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    Dns,
    Icmp,
    TcpHealth,
    Latency,
    TopTalkers,
    Security,
    Anomalies,
}

impl Category {
    pub const ALL: [Category; 7] = [
        Category::Dns,
        Category::Icmp,
        Category::TcpHealth,
        Category::Latency,
        Category::TopTalkers,
        Category::Security,
        Category::Anomalies,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Dns => "DNS",
            Category::Icmp => "ICMP",
            Category::TcpHealth => "TCP health",
            Category::Latency => "Latency / RTT",
            Category::TopTalkers => "Top talkers",
            Category::Security => "TLS / security",
            Category::Anomalies => "Anomalies",
        }
    }

    /// Plain-language "what it means / what to try" shown when a finding is expanded.
    pub fn hint(self) -> &'static str {
        match self {
            Category::Dns => {
                "Slow or failing name lookups delay every new connection. Check the configured resolver, try another one, and look for repeated queries for the same name."
            }
            Category::Icmp => {
                "Routers and hosts use ICMP to report blocked ports, unreachable networks and MTU problems. Inspect which destinations trigger them and check firewall or routing rules."
            }
            Category::TcpHealth => {
                "Retransmissions, resets and zero windows mean packets are lost or a peer cannot keep up. Look for a congested link, a flaky Wi-Fi hop, or an overloaded server."
            }
            Category::Latency => {
                "High round-trip times make every request feel slow. Compare RTT per conversation to find the slow hop or the distant server."
            }
            Category::TopTalkers => {
                "One host dominating traffic is normal for a download or backup, but unexpected for idle machines. Inspect it to see what it is talking to."
            }
            Category::Security => {
                "Cleartext logins, blocklist matches, handshake failures, old protocol versions and certificate problems show up here. Switch cleartext protocols to TLS, change exposed secrets, and check client and server TLS settings."
            }
            Category::Anomalies => {
                "Dissectors flagged frames as malformed or unusual. They can be caused by capture truncation, offloading, or broken senders."
            }
        }
    }
}

/// Maps a finding to its category from its title and filter (keyword based, stable).
pub fn category_of(i: &HealthInsight) -> Category {
    let t = format!(
        "{} {}",
        i.title.to_ascii_lowercase(),
        i.suggested_filter
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
    );
    let has = |ks: &[&str]| ks.iter().any(|k| t.contains(k));
    let title = i.title.to_ascii_lowercase();
    if ["blocklisted", "malicious", "cleartext"]
        .iter()
        .any(|k| title.contains(k))
    {
        Category::Security
    } else if has(&["dns"]) {
        Category::Dns
    } else if has(&["icmp"]) {
        Category::Icmp
    } else if has(&["rtt", "latency", "round-trip"]) {
        Category::Latency
    } else if has(&["tls", "ssl", "certificate"]) {
        Category::Security
    } else if has(&["tcp", "retrans", "reset", "zero window"]) {
        Category::TcpHealth
    } else if has(&["talker"]) {
        Category::TopTalkers
    } else {
        Category::Anomalies
    }
}
