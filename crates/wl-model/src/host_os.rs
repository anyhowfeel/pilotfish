//! The operating system families whose Wireshark setup differs, with the wording that depends on it.
//! Functions take the OS as a parameter so every wording is testable on any host.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    Mac,
    Windows,
    Linux,
}

impl HostOs {
    pub fn current() -> HostOs {
        if cfg!(target_os = "macos") {
            HostOs::Mac
        } else if cfg!(windows) {
            HostOs::Windows
        } else {
            HostOs::Linux
        }
    }
}

/// What to do when Wireshark's tools cannot be found.
pub fn install_advice(os: HostOs) -> &'static str {
    match os {
        HostOs::Mac => {
            "Install Wireshark from wireshark.org or with `brew install --cask wireshark`, \
             or choose its folder in Settings."
        }
        HostOs::Windows => {
            "Install Wireshark from wireshark.org, or choose its folder in Settings."
        }
        HostOs::Linux => {
            "Install Wireshark with your package manager, or choose its folder in Settings."
        }
    }
}

/// Where the lookup went, so a user can tell why an installed Wireshark was missed.
pub fn searched_places(os: HostOs) -> &'static str {
    match os {
        HostOs::Mac => {
            "Looked on PATH, in the Wireshark app, the Homebrew and MacPorts folders and the login shell PATH."
        }
        HostOs::Windows => "Looked on PATH and in the Program Files Wireshark folders.",
        HostOs::Linux => "Looked on PATH and in /usr/bin, /usr/local/bin, /usr/sbin and /sbin.",
    }
}

pub(crate) fn missing_text(tool: &str) -> String {
    let os = HostOs::current();
    format!(
        "{tool} was not found. {} {}",
        install_advice(os),
        searched_places(os)
    )
}

/// Steps for a capture device that dumpcap may not open on macOS (ChmodBPF).
pub const MAC_CAPTURE_STEPS: &str = "Install ChmodBPF from the Wireshark disk image, or reinstall Wireshark.\n\
     Make sure you are in the access_bpf group.\n\
     Log out and back in.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_os_has_its_own_advice() {
        assert!(install_advice(HostOs::Mac).contains("brew install --cask wireshark"));
        assert!(!install_advice(HostOs::Linux).contains("brew"));
        assert!(install_advice(HostOs::Windows).contains("wireshark.org"));
        for os in [HostOs::Mac, HostOs::Windows, HostOs::Linux] {
            assert!(install_advice(os).ends_with("in Settings."));
            assert!(searched_places(os).starts_with("Looked on PATH"));
        }
    }
}
