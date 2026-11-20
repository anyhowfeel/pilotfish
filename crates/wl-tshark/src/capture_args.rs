//! Pure builders of `dumpcap` argument lists from `CaptureOptions`.

use std::path::Path;

use wl_model::{CaptureOptions, SNAPLEN_MAX};

fn common(o: &CaptureOptions) -> Vec<String> {
    let mut a = vec!["-q".to_string()];
    for i in &o.interfaces {
        a.extend(["-i".into(), i.clone()]);
    }
    let filter = o.capture_filter.trim();
    if !filter.is_empty() {
        a.extend(["-f".into(), filter.into()]);
    }
    if o.snaplen < SNAPLEN_MAX {
        a.extend(["-s".into(), o.snaplen.to_string()]);
    }
    if o.buffer_mb > 0 {
        a.extend(["-B".into(), o.buffer_mb.to_string()]);
    }
    if !o.promiscuous {
        a.push("-p".into());
    }
    if o.monitor {
        a.push("-I".into());
    }
    a
}

fn kb(mb: u32) -> String {
    (u64::from(mb) * 1000).to_string()
}

/// Streaming capture (`-w -`) that feeds the live view. Auto-stop conditions apply here.
pub fn stream_args(o: &CaptureOptions) -> Vec<String> {
    let mut a = common(o);
    if o.stop.secs > 0 {
        a.extend(["-a".into(), format!("duration:{}", o.stop.secs)]);
    }
    if o.stop.mb > 0 {
        a.extend(["-a".into(), format!("filesize:{}", kb(o.stop.mb))]);
    }
    if o.stop.packets > 0 {
        a.extend(["-c".into(), o.stop.packets.to_string()]);
    }
    a.extend(["-w".into(), "-".into()]);
    a
}

/// Second dumpcap that records the ring buffer files (`None` when the ring is off).
/// dumpcap cannot rotate files while writing to stdout, hence a separate recorder.
pub fn ring_args(o: &CaptureOptions, base: &Path) -> Option<Vec<String>> {
    if !o.ring.enabled {
        return None;
    }
    let mut a = common(o);
    a.extend(["-w".into(), base.display().to_string()]);
    a.extend(["-b".into(), format!("files:{}", o.ring.files)]);
    if o.ring.file_mb > 0 {
        a.extend(["-b".into(), format!("filesize:{}", kb(o.ring.file_mb))]);
    }
    if o.ring.secs > 0 {
        a.extend(["-b".into(), format!("duration:{}", o.ring.secs)]);
    }
    Some(a)
}

/// Compile-only check of a capture filter (`-d` prints the BPF program and exits).
pub fn check_args(interface: &str, filter: &str) -> Vec<String> {
    ["-i", interface, "-f", filter, "-d"]
        .map(String::from)
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> CaptureOptions {
        CaptureOptions::single("eth0", Some(" port 53 "))
    }

    #[test]
    fn defaults_are_minimal() {
        assert_eq!(
            stream_args(&opts()),
            ["-q", "-i", "eth0", "-f", "port 53", "-w", "-"]
        );
    }

    #[test]
    fn every_option_maps_to_a_flag() {
        let mut o = opts();
        o.interfaces.push("wlan0".into());
        o.promiscuous = false;
        o.monitor = true;
        o.snaplen = 96;
        o.buffer_mb = 8;
        o.stop.secs = 30;
        o.stop.mb = 5;
        o.stop.packets = 1000;
        let a = stream_args(&o).join(" ");
        assert!(
            a.contains("-i eth0 -i wlan0 -f port 53 -s 96 -B 8 -p -I"),
            "{a}"
        );
        assert!(
            a.contains("-a duration:30 -a filesize:5000 -c 1000 -w -"),
            "{a}"
        );
    }

    #[test]
    fn ring_needs_to_be_enabled() {
        let mut o = opts();
        assert_eq!(ring_args(&o, Path::new("/t/x.pcapng")), None);
        o.ring.enabled = true;
        o.ring.files = 4;
        o.ring.file_mb = 20;
        o.ring.secs = 60;
        let a = ring_args(&o, Path::new("/t/x.pcapng"))
            .expect("ring")
            .join(" ");
        assert!(
            a.ends_with("-w /t/x.pcapng -b files:4 -b filesize:20000 -b duration:60"),
            "{a}"
        );
        assert!(!a.contains("-a "));
    }

    #[test]
    fn check_is_compile_only() {
        assert_eq!(check_args("lo", "tcp"), ["-i", "lo", "-f", "tcp", "-d"]);
    }
}
