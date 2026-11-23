//! Whether Wireshark's tools are installed. The app decides once; panels only read it.

use crate::CaptureError;
use crate::host_os::{HostOs, install_advice};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Wireshark {
    #[default]
    Available,
    Missing,
}

impl Wireshark {
    /// `Missing` only for the error that says a tool is not installed; any other failure
    /// is a real one and does not change what the machine has.
    pub fn from_tools<T>(found: &Result<T, CaptureError>) -> Self {
        match found {
            Err(e) if e.is_tool_missing() => Wireshark::Missing,
            _ => Wireshark::Available,
        }
    }

    pub fn is_missing(self) -> bool {
        self == Wireshark::Missing
    }
}

/// Title of the empty state a page shows in place of data it cannot produce.
pub fn needs_title(feature: &str) -> String {
    format!("{feature} needs Wireshark")
}

/// What to do next, and what still works. Shared by every page and message.
pub fn needs_hint() -> String {
    needs_hint_on(HostOs::current())
}

fn needs_hint_on(os: HostOs) -> String {
    format!(
        "{} Then restart pilotfish. Opening a capture and browsing it works without it.",
        install_advice(os)
    )
}

/// One-line form for banners, toasts and tooltips.
pub fn needs_message(feature: &str) -> String {
    needs_message_on(HostOs::current(), feature)
}

fn needs_message_on(os: HostOs, feature: &str) -> String {
    format!(
        "{}. {} Then restart pilotfish.",
        needs_title(feature),
        install_advice(os)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_missing_tool_means_missing() {
        let missing: Result<(), _> = Err(CaptureError::ToolMissing("tshark".into()));
        let broken: Result<(), _> = Err(CaptureError::Other("boom".into()));
        assert_eq!(Wireshark::from_tools(&missing), Wireshark::Missing);
        assert_eq!(Wireshark::from_tools(&broken), Wireshark::Available);
        assert_eq!(Wireshark::from_tools(&Ok(())), Wireshark::Available);
    }

    #[test]
    fn the_messages_name_the_feature() {
        assert_eq!(needs_title("Web analysis"), "Web analysis needs Wireshark");
        assert_eq!(
            needs_message_on(HostOs::Mac, "Follow stream"),
            "Follow stream needs Wireshark. Install Wireshark from wireshark.org or with \
             `brew install --cask wireshark`, or choose its folder in Settings. \
             Then restart pilotfish."
        );
        assert!(needs_hint_on(HostOs::Linux).contains("package manager"));
    }

    #[test]
    fn a_missing_tool_reads_as_a_sentence() {
        let e = CaptureError::ToolMissing("tshark".into());
        let text = e.to_string();
        assert!(text.starts_with("tshark was not found. "), "{text}");
        assert!(text.contains("choose its folder in Settings"), "{text}");
        assert!(text.contains("Looked on PATH"), "{text}");
    }
}
