//! Pure builders of the `ssh` argument list that streams a remote `tcpdump` capture.

use wl_model::{CaptureOptions, SNAPLEN_MAX};

/// POSIX single-quoting: the remote shell sees exactly `s`, whatever it contains.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The command line the remote shell runs: tcpdump writing pcap to stdout, unbuffered.
pub fn remote_command(o: &CaptureOptions) -> String {
    let r = &o.remote;
    let mut c: Vec<String> = Vec::new();
    if r.sudo {
        c.extend(["sudo".into(), "-n".into()]);
    }
    c.extend(["tcpdump".into(), "-U".into(), "-n".into()]);
    c.extend(["-i".into(), shell_quote(r.interface.trim())]);
    if o.snaplen < SNAPLEN_MAX {
        c.extend(["-s".into(), o.snaplen.to_string()]);
    }
    if o.stop.packets > 0 {
        c.extend(["-c".into(), o.stop.packets.to_string()]);
    }
    c.extend(["-w".into(), "-".into()]);
    let filter = o.capture_filter.trim();
    if !filter.is_empty() {
        c.push(shell_quote(filter));
    }
    c.join(" ")
}

/// Arguments for the local `ssh`. Never prompts (`BatchMode`); `--` keeps a destination that
/// starts with a dash from being read as an option.
pub fn ssh_args(o: &CaptureOptions) -> Vec<String> {
    let r = &o.remote;
    let mut a: Vec<String> = ["-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        .map(String::from)
        .to_vec();
    a.extend(["-p".into(), r.port.to_string()]);
    a.extend(["--".into(), r.destination(), remote_command(o)]);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> CaptureOptions {
        let mut o = CaptureOptions::single("ignored", Some(" port 53 "));
        o.remote.enabled = true;
        o.remote.host = "10.0.0.7".into();
        o.remote.user = "ops".into();
        o.remote.interface = "eth0".into();
        o
    }

    #[test]
    fn default_command_line() {
        assert_eq!(
            ssh_args(&opts()),
            [
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                "22",
                "--",
                "ops@10.0.0.7",
                "tcpdump -U -n -i 'eth0' -w - 'port 53'"
            ]
        );
    }

    #[test]
    fn sudo_snaplen_count_and_port() {
        let mut o = opts();
        o.remote.sudo = true;
        o.remote.port = 2222;
        o.snaplen = 96;
        o.stop.packets = 50;
        o.capture_filter.clear();
        let a = ssh_args(&o);
        assert_eq!(a[5..7], ["-p", "2222"]);
        assert_eq!(
            a.last().map(String::as_str),
            Some("sudo -n tcpdump -U -n -i 'eth0' -s 96 -c 50 -w -")
        );
    }

    #[test]
    fn quoting_neutralises_shell_metacharacters() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("$(id);`id`"), "'$(id);`id`'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn hostile_filter_stays_one_quoted_word() {
        let mut o = opts();
        o.capture_filter = "port 1' ; rm -rf ~ ; echo '$(reboot)".into();
        let cmd = remote_command(&o);
        assert_eq!(
            cmd,
            r#"tcpdump -U -n -i 'eth0' -w - 'port 1'\'' ; rm -rf ~ ; echo '\''$(reboot)'"#
        );
    }

    #[test]
    fn hostile_interface_is_quoted() {
        let mut o = opts();
        o.remote.interface = "eth0; id".into();
        assert!(remote_command(&o).contains("-i 'eth0; id' "));
        o.remote.interface = "-w /etc/passwd".into();
        assert!(remote_command(&o).contains("-i '-w /etc/passwd' "));
    }

    #[test]
    fn destination_is_one_argument_after_double_dash() {
        let mut o = opts();
        o.remote.host = "-oProxyCommand=touch x".into();
        o.remote.user = String::new();
        let a = ssh_args(&o);
        assert_eq!(a[7], "--");
        assert_eq!(a[8], "-oProxyCommand=touch x");
        assert_eq!(a.len(), 10);
    }
}
