//! The views of the Flows page.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Tab {
    #[default]
    Flow,
    Sequence,
    Throughput,
    Rtt,
    Window,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Flow,
        Tab::Sequence,
        Tab::Throughput,
        Tab::Rtt,
        Tab::Window,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Flow => "Flow graph",
            Tab::Sequence => "Time-sequence",
            Tab::Throughput => "Throughput",
            Tab::Rtt => "RTT",
            Tab::Window => "Window size",
        }
    }

    /// Compact label for narrow windows.
    pub fn short(self) -> &'static str {
        match self {
            Tab::Flow => "Flow",
            Tab::Sequence => "Seq",
            Tab::Throughput => "Rate",
            Tab::Rtt => "RTT",
            Tab::Window => "Win",
        }
    }

    pub fn is_tcp(self) -> bool {
        self != Tab::Flow
    }

    /// Parses the screenshot flag `--flow-tab`.
    pub fn parse(s: &str) -> Option<Tab> {
        let s = s.to_ascii_lowercase();
        Tab::ALL
            .into_iter()
            .find(|t| t.label().to_ascii_lowercase().contains(&s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names() {
        assert_eq!(Tab::parse("rtt"), Some(Tab::Rtt));
        assert_eq!(Tab::parse("time-sequence"), Some(Tab::Sequence));
        assert_eq!(Tab::parse("window"), Some(Tab::Window));
        assert_eq!(Tab::parse("flow"), Some(Tab::Flow));
        assert_eq!(Tab::parse("zzz"), None);
    }
}
