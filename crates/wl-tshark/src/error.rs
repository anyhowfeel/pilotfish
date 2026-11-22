//! Mapping of tool failures (stderr text, io errors) onto `CaptureError`.

use std::io;

use wl_model::CaptureError;

/// Error for a failed process spawn; a missing binary is `ToolMissing`.
pub fn spawn_error(tool: &str, e: &io::Error) -> CaptureError {
    match e.kind() {
        io::ErrorKind::NotFound => CaptureError::ToolMissing(tool.to_string()),
        io::ErrorKind::PermissionDenied => CaptureError::Permission(format!("{tool}: {e}")),
        _ => CaptureError::Other(format!("{tool}: {e}")),
    }
}

pub fn io_error(what: &str, e: &io::Error) -> CaptureError {
    CaptureError::Other(format!("{what}: {e}"))
}

/// Drops tool chatter and the `tshark: ` prefix, keeping the readable message
/// (including the caret diagram tshark prints for filter syntax errors).
pub fn clean_stderr(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .filter(|l| {
            !l.trim().is_empty()
                && !l.starts_with("Running as user")
                && !l.starts_with("Capturing on")
        })
        .map(|l| {
            l.strip_prefix("tshark: ")
                .or_else(|| l.strip_prefix("dumpcap: "))
                .or_else(|| l.strip_prefix("editcap: "))
                .unwrap_or(l)
        })
        .collect();
    lines.join("\n")
}

fn is_permission(lower: &str) -> bool {
    lower.contains("permission") || lower.contains("not permitted") || lower.contains("privilege")
}

/// Generic failure of tshark/editcap.
pub fn from_stderr(stderr: &str) -> CaptureError {
    let msg = clean_stderr(stderr);
    if is_permission(&msg.to_lowercase()) {
        CaptureError::Permission(msg)
    } else if msg.is_empty() {
        CaptureError::Other("tool exited with an error".into())
    } else {
        CaptureError::Other(msg)
    }
}

/// Failure of a tshark run that was given a display filter (`-Y`).
/// tshark reports bad filters on stderr with exit code 4 (or text mentioning "filter").
pub fn from_display_filter_failure(stderr: &str, code: Option<i32>) -> CaptureError {
    let msg = clean_stderr(stderr);
    let lower = msg.to_lowercase();
    let looks_bad = code == Some(4)
        || lower.contains("filter")
        || lower.contains("unexpected")
        || lower.contains("not a valid")
        || lower.contains("cannot be converted");
    if is_permission(&lower) {
        CaptureError::Permission(msg)
    } else if looks_bad && !msg.is_empty() {
        CaptureError::BadFilter(msg)
    } else {
        from_stderr(stderr)
    }
}

/// Failure of dumpcap (capture filter errors, permissions, unknown device ...).
pub fn from_dumpcap(stderr: &str) -> CaptureError {
    let msg = clean_stderr(stderr);
    let lower = msg.to_lowercase();
    if lower.contains("invalid capture filter") || lower.contains("syntax error") {
        CaptureError::BadFilter(msg)
    } else if lower.contains("monitor mode") || lower.contains("rfmon") {
        CaptureError::Permission(format!(
            "Monitor mode is not available on this interface. It needs a Wi-Fi adapter that \
             supports it and elevated privileges (run as root or grant dumpcap CAP_NET_ADMIN).\n{msg}"
        ))
    } else if lower.contains("no such device") || lower.contains("no suitable device") {
        CaptureError::Other(format!("Interface not found or not available.\n{msg}"))
    } else {
        from_stderr(stderr)
    }
}

/// Failure of the `ssh ... tcpdump` pipeline: names the layer that broke.
pub fn from_ssh(stderr: &str) -> CaptureError {
    let msg = clean_stderr(stderr);
    let lower = msg.to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    let tcpdump = lower.contains("tcpdump");
    if has(&[
        "host key verification failed",
        "remote host identification has changed",
    ]) {
        CaptureError::Permission(format!(
            "The SSH host key is unknown or has changed. Verify the host's fingerprint \
             out-of-band before trusting it; do not add it to known_hosts blindly.\n{msg}"
        ))
    } else if has(&["permission denied ("]) {
        CaptureError::Permission(format!(
            "SSH authentication failed. Pilotfish never asks for a password: load your key into \
             ssh-agent or configure key login.\n{msg}"
        ))
    } else if has(&[
        "a password is required",
        "may not run sudo",
        "a terminal is required",
    ]) {
        CaptureError::Permission(format!(
            "sudo on the remote host needs a password. Allow tcpdump without one (NOPASSWD) \
             or log in as root.\n{msg}"
        ))
    } else if tcpdump && has(&["not found", "no such file"]) {
        CaptureError::Other(format!(
            "tcpdump is not installed on the remote host.\n{msg}"
        ))
    } else if tcpdump && has(&["syntax error"]) {
        CaptureError::BadFilter(msg)
    } else if tcpdump && has(&["no such device"]) {
        CaptureError::Other(format!("Interface not found on the remote host.\n{msg}"))
    } else if has(&[
        "operation not permitted",
        "don't have permission",
        "permission denied",
    ]) {
        CaptureError::Permission(format!(
            "The remote user may not capture packets. Enable sudo for it or run as root.\n{msg}"
        ))
    } else if has(&[
        "could not resolve",
        "connection refused",
        "timed out",
        "no route to host",
    ]) {
        CaptureError::Other(format!("Cannot reach the remote host.\n{msg}"))
    } else {
        from_stderr(stderr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_detected() {
        let e = from_dumpcap(
            "dumpcap: You don't have permission to capture on that device (socket: Operation not permitted)",
        );
        assert!(matches!(e, CaptureError::Permission(_)));
    }

    #[test]
    fn capturing_on_banner_is_dropped() {
        let e = from_dumpcap(
            "Capturing on 'eth0'\ndumpcap: Invalid capture filter \"x(\" for interface 'eth0'.\n",
        );
        assert_eq!(
            e,
            CaptureError::BadFilter("Invalid capture filter \"x(\" for interface 'eth0'.".into())
        );
    }

    #[test]
    fn monitor_mode_failure_is_readable() {
        let e = from_dumpcap(
            "dumpcap: The capture session could not be initiated on interface 'wlan0' (That device doesn't support monitor mode)",
        );
        match e {
            CaptureError::Permission(m) => assert!(m.starts_with("Monitor mode is not available")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn capture_filter_is_bad_filter() {
        let e = from_dumpcap(
            "dumpcap: Invalid capture filter \"foo(\" for interface 'lo':\n\nsyntax error\n",
        );
        match e {
            CaptureError::BadFilter(m) => assert!(m.starts_with("Invalid capture filter")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn display_filter_message_is_cleaned() {
        let e =
            from_display_filter_failure("tshark: Unexpected end of filter expression.\n", Some(4));
        assert_eq!(
            e,
            CaptureError::BadFilter("Unexpected end of filter expression.".into())
        );
    }

    #[test]
    fn unknown_failure_is_other() {
        let e = from_display_filter_failure("tshark: The file \"x\" doesn't exist.\n", Some(2));
        assert!(matches!(e, CaptureError::Other(_)));
    }

    #[test]
    fn missing_binary() {
        let e = spawn_error("tshark", &io::Error::from(io::ErrorKind::NotFound));
        assert!(matches!(e, CaptureError::ToolMissing(_)));
    }

    fn ssh_kind(stderr: &str) -> (&'static str, String) {
        match from_ssh(stderr) {
            CaptureError::Permission(m) => ("permission", m),
            CaptureError::BadFilter(m) => ("filter", m),
            CaptureError::Other(m) => ("other", m),
            CaptureError::ToolMissing(m) => ("tool", m),
        }
    }

    #[test]
    fn ssh_failures_name_the_broken_layer() {
        let cases = [
            (
                "ops@h: Permission denied (publickey,password).",
                "permission",
                "authentication",
            ),
            ("Host key verification failed.", "permission", "out-of-band"),
            (
                "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
                "permission",
                "has changed",
            ),
            ("sudo: a password is required", "permission", "NOPASSWD"),
            ("bash: tcpdump: command not found", "other", "not installed"),
            ("sh: 1: tcpdump: not found", "other", "not installed"),
            (
                "tcpdump: eth9: No such device exists",
                "other",
                "Interface not found",
            ),
            (
                "tcpdump: eth0: You don't have permission to perform this capture",
                "permission",
                "sudo",
            ),
            (
                "tcpdump: syntax error in filter expression: syntax error",
                "filter",
                "syntax error",
            ),
            (
                "ssh: Could not resolve hostname nope: Name or service not known",
                "other",
                "Cannot reach",
            ),
            (
                "ssh: connect to host h port 22: Connection refused",
                "other",
                "Cannot reach",
            ),
        ];
        for (stderr, kind, text) in cases {
            let (k, m) = ssh_kind(stderr);
            assert_eq!(k, kind, "{stderr}");
            assert!(m.contains(text), "{stderr}: {m}");
        }
    }
}
