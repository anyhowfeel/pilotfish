//! Command line interface.
use std::path::PathBuf;

use clap::Parser;

use crate::page::Page;

#[derive(Parser, Debug, Clone, Default)]
#[command(
    name = "wirelens",
    version,
    about = "Packet capture viewer built on tshark"
)]
pub struct Cli {
    /// Capture file (.pcap/.pcapng) to open.
    pub file: Option<PathBuf>,
    /// Start a live capture on this interface.
    #[arg(long, value_name = "IFACE")]
    pub live: Option<String>,
    /// Save a screenshot of the window to this PNG and exit.
    #[arg(hide = true, long, value_name = "PNG")]
    pub screenshot: Option<PathBuf>,
    /// Page to open: capture, overview, graphs, packets, hosts, map, conversations, flows, web,
    /// insights.
    #[arg(long, value_name = "NAME")]
    pub page: Option<String>,
    /// UI scale factor, e.g. 1.25.
    #[arg(long, value_name = "F")]
    pub scale: Option<f32>,
    /// Initial window size, e.g. 1440x900.
    #[arg(long, value_name = "WxH")]
    pub size: Option<String>,
    /// Open this capture file (alias of the positional argument).
    #[arg(hide = true, long = "open", value_name = "FILE")]
    pub open: Option<PathBuf>,
    /// Milliseconds to wait before taking the screenshot.
    #[arg(hide = true, long, value_name = "N", default_value_t = 1500)]
    pub wait_ms: u64,
    /// Select this frame once loaded (detail + hex panes), for screenshots.
    #[arg(hide = true, long, value_name = "N")]
    pub select: Option<u64>,
    /// Print frame-time statistics after N frames and exit.
    #[arg(hide = true, long, value_name = "N")]
    pub bench_frames: Option<u32>,
    /// Run the scripted UI benchmark (pages, scroll, sort, search...) and exit.
    #[arg(hide = true, long)]
    pub bench_script: bool,
    /// Open a page in its own window (repeatable), like Shift+click in the sidebar.
    #[arg(long, value_name = "PAGE")]
    pub detach: Vec<String>,
    /// Display filter applied to the opened capture (like typing it in the filter bar).
    #[arg(long, value_name = "EXPR")]
    pub filter: Option<String>,
    /// Open an overlay for screenshots: settings[:category], palette, stream, bookmarks, properties.
    #[arg(hide = true, long, value_name = "NAME")]
    pub overlay: Option<String>,
    /// Feed the Map page ~40 synthetic hosts / 120 links (screenshots without a capture).
    #[arg(hide = true, long)]
    pub demo_map: bool,
    /// Select this host on the Map page (screenshots).
    #[arg(hide = true, long, value_name = "ADDR")]
    pub map_select: Option<String>,
    /// Map view options for screenshots: radial,directions,nolabels.
    #[arg(hide = true, long, value_name = "LIST")]
    pub map_view: Option<String>,
    /// Feed the Web page synthetic HTTP/TLS traffic (no tshark), for screenshots.
    #[arg(hide = true, long)]
    pub demo_web: bool,
    /// Pre-select a Web row: http:<id> or tls:<first frame> (screenshots).
    #[arg(hide = true, long, value_name = "SPEC")]
    pub web_select: Option<String>,
    /// Expand Setup sections for screenshots: options,other.
    #[arg(hide = true, long, value_name = "LIST")]
    pub setup_expand: Option<String>,
    /// Open this conversation on the Flows page: a `tcp.stream` number or `host,host[,host...]`.
    #[arg(hide = true, long, value_name = "SPEC")]
    pub flow_select: Option<String>,
    /// Flows page view: flow, sequence, throughput, rtt or window.
    #[arg(hide = true, long, value_name = "TAB")]
    pub flow_tab: Option<String>,
    /// Select this frame on the Flows page once loaded (screenshots).
    #[arg(hide = true, long, value_name = "N")]
    pub flow_frame: Option<u64>,
    /// Pre-set packet-panel UI state for screenshots, e.g. "text=tcp || dns;menu=quick".
    #[arg(hide = true, long, value_name = "SPEC")]
    pub packets_demo: Option<String>,
    /// Pre-select a time window FROM:TO seconds (screenshots); append `:window` to scope the
    /// Overview cards to it.
    #[arg(hide = true, long, value_name = "SPEC")]
    pub window: Option<String>,
    /// Graphs view options for screenshots: line|area|bars,log,100ms|1s|10s|1min|auto,
    /// total|tcp|dns|http|bcast.
    #[arg(hide = true, long, value_name = "LIST")]
    pub graph_view: Option<String>,
    /// "Decode As" rule applied at startup, e.g. tcp.port==8080,http (repeatable).
    #[arg(long = "decode-as", value_name = "RULE")]
    pub decode_as: Vec<String>,
    /// Web page tab for screenshots: files or files:<protocol> (smb, tftp, imf, dicom).
    #[arg(hide = true, long, value_name = "TAB")]
    pub web_tab: Option<String>,
    /// Insights tab for screenshots: dns.
    #[arg(hide = true, long, value_name = "TAB")]
    pub insights_tab: Option<String>,
    /// Start in the light theme.
    #[arg(long)]
    pub light: bool,
}

impl Cli {
    pub fn file(&self) -> Option<&PathBuf> {
        self.open.as_ref().or(self.file.as_ref())
    }

    pub fn page(&self) -> Option<Page> {
        self.page
            .as_deref()
            .and_then(Page::parse)
            .or(self.demo_map.then_some(Page::Map))
            .or(self.demo_web.then_some(Page::Web))
            .or(self.flow_select.is_some().then_some(Page::Flows))
    }

    /// `--decode-as` values that parse as `table==port,protocol`.
    pub fn decode_rules(&self) -> Vec<wl_model::DecodeAs> {
        self.decode_as
            .iter()
            .filter_map(|s| {
                let (lhs, protocol) = s.split_once(',')?;
                let (field, value) = lhs.split_once("==")?;
                Some(wl_model::DecodeAs {
                    field: field.trim().to_owned(),
                    value: value.trim().parse().ok()?,
                    protocol: protocol.trim().to_owned(),
                })
            })
            .collect()
    }

    pub fn size(&self) -> Option<[f32; 2]> {
        let (w, h) = self.size.as_deref()?.split_once('x')?;
        Some([w.trim().parse().ok()?, h.trim().parse().ok()?])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_size_and_page() {
        let c = Cli::parse_from([
            "wl-app", "--size", "1440x900", "--page", "hosts", "--light", "a.pcap",
        ]);
        assert_eq!(c.size(), Some([1440.0, 900.0]));
        assert_eq!(c.page(), Some(Page::Hosts));
        assert!(c.light);
        assert_eq!(c.file().unwrap().to_str(), Some("a.pcap"));
    }

    #[test]
    fn decode_as_rules_parse() {
        let c = Cli::parse_from([
            "wl-app",
            "--decode-as",
            "tcp.port==8080,http",
            "--decode-as",
            "nonsense",
        ]);
        let r = c.decode_rules();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].field.as_str(), r[0].value), ("tcp.port", 8080));
        assert_eq!(r[0].protocol, "http");
    }

    #[test]
    fn bad_size_is_none() {
        let c = Cli::parse_from(["wl-app", "--size", "big"]);
        assert_eq!(c.size(), None);
    }
}
