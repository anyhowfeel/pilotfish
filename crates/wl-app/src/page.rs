//! Navigation pages.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Page {
    #[default]
    Setup,
    Overview,
    Graphs,
    Packets,
    Hosts,
    Map,
    Conversations,
    Flows,
    Web,
    Insights,
    Diff,
}

impl Page {
    pub const ALL: [Page; 11] = [
        Page::Setup,
        Page::Overview,
        Page::Graphs,
        Page::Packets,
        Page::Hosts,
        Page::Map,
        Page::Conversations,
        Page::Flows,
        Page::Web,
        Page::Insights,
        Page::Diff,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Page::Setup => "Capture",
            Page::Overview => "Overview",
            Page::Graphs => "Graphs",
            Page::Packets => "Packets",
            Page::Hosts => "Hosts",
            Page::Map => "Map",
            Page::Conversations => "Conversations",
            Page::Flows => "Flows",
            Page::Web => "Web",
            Page::Insights => "Insights",
            Page::Diff => "Diff",
        }
    }

    pub fn parse(s: &str) -> Option<Page> {
        match s.to_ascii_lowercase().as_str() {
            "setup" | "capture" => Some(Page::Setup),
            "overview" | "dashboard" => Some(Page::Overview),
            "graphs" | "graph" | "io" => Some(Page::Graphs),
            "packets" => Some(Page::Packets),
            "hosts" => Some(Page::Hosts),
            "map" | "topology" => Some(Page::Map),
            "conversations" => Some(Page::Conversations),
            "flows" | "flow" | "flowgraph" => Some(Page::Flows),
            "web" | "http" | "https" => Some(Page::Web),
            "insights" | "health" | "expert" => Some(Page::Insights),
            "diff" | "compare" => Some(Page::Diff),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        for p in Page::ALL {
            assert_eq!(Page::parse(p.label()), Some(p));
        }
        assert_eq!(Page::parse("nope"), None);
    }
}
