//! Data export: RFC-4180 CSV of packets, JSON of stats + insights, and HTML report re-exports.

use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;
use thiserror::Error;
use wl_model::{HealthInsight, PacketRow, StatsSnapshot};

#[allow(unused_imports)]
pub use crate::export_html::{build_html_report, write_html_report};

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("failed to write {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

/// Serializes `rows` as strict RFC-4180 CSV with CRLF line endings.
pub fn packets_to_csv(rows: &[PacketRow]) -> String {
    let mut out = String::from(
        "No,Time,Epoch,Source,SrcPort,Destination,DstPort,Protocol,Length,Stream,Info\r\n",
    );
    for r in rows {
        let sp = r.src_port.map_or_else(String::new, |p| p.to_string());
        let dp = r.dst_port.map_or_else(String::new, |p| p.to_string());
        let st = r.stream.map_or_else(String::new, |s| s.to_string());
        let _ = write!(
            out,
            "{},{:.6},{:.6},{},{},{},{},{},{},{},{}\r\n",
            r.no,
            r.rel,
            r.epoch,
            csv_escape(&r.src),
            sp,
            csv_escape(&r.dst),
            dp,
            csv_escape(&r.protocol),
            r.len,
            st,
            csv_escape(&r.info),
        );
    }
    out
}

pub fn write_packets_csv(path: &Path, rows: &[PacketRow]) -> Result<(), ExportError> {
    std::fs::write(path, packets_to_csv(rows)).map_err(|source| ExportError::Io {
        path: path.display().to_string(),
        source,
    })
}

#[derive(Serialize)]
struct StatsExport<'a> {
    stats: &'a StatsSnapshot,
    insights: &'a [HealthInsight],
}

/// Serializes `StatsSnapshot` and `HealthInsight` cards to pretty JSON.
pub fn stats_to_json(
    stats: &StatsSnapshot,
    insights: &[HealthInsight],
) -> Result<String, ExportError> {
    Ok(serde_json::to_string_pretty(&StatsExport {
        stats,
        insights,
    })?)
}

pub fn write_stats_json(
    path: &Path,
    stats: &StatsSnapshot,
    insights: &[HealthInsight],
) -> Result<(), ExportError> {
    let body = stats_to_json(stats, insights)?;
    std::fs::write(path, body).map_err(|source| ExportError::Io {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_bookmarks::BookmarkedPacket;
    use wl_model::{InsightSeverity, ProtocolStat, Transport};

    fn sample_row() -> PacketRow {
        PacketRow {
            no: 1,
            epoch: 1700.5,
            rel: 0.125,
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            src_ip: None,
            dst_ip: None,
            src_port: Some(54321),
            dst_port: Some(80),
            transport: Transport::Tcp,
            protocol: "HTTP".into(),
            len: 120,
            info: "GET /a,b \"quoted\"\nline".into(),
            stream: Some(0),
        }
    }

    #[test]
    fn csv_escapes_rfc4180_and_writes_disk() {
        let csv = packets_to_csv(&[sample_row()]);
        assert!(csv.starts_with("No,Time,Epoch,"));
        assert!(csv.contains("\"GET /a,b \"\"quoted\"\"\nline\"\r\n"));

        let path = std::env::temp_dir().join(format!("wl-csv-{}.csv", std::process::id()));
        write_packets_csv(&path, &[sample_row()]).unwrap();
        let read_back = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_back, csv);
    }

    #[test]
    fn json_and_html_exports_escape_and_include_sections() {
        let stats = StatsSnapshot {
            total_packets: 42,
            total_bytes: 8192,
            protocols: vec![ProtocolStat {
                name: "TCP".into(),
                packets: 42,
                bytes: 8192,
            }],
            ..Default::default()
        };
        let insights = vec![HealthInsight {
            severity: InsightSeverity::Warning,
            title: "Retrans <script>".into(),
            explanation: "Packet loss".into(),
            suggested_filter: Some("tcp.analysis.retransmission".into()),
            metric: "3 events".into(),
        }];
        let json = stats_to_json(&stats, &insights).unwrap();
        assert!(json.contains("\"total_packets\": 42"));
        assert!(json.contains("tcp.analysis.retransmission"));

        let bm = [BookmarkedPacket {
            frame_no: 7,
            comment: "Check <b>SYN</b>".into(),
            time: "0.123".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            protocol: "TCP".into(),
            info: "SYN <x>".into(),
        }];
        let html = build_html_report("cap<1>", &stats, &insights, None, None, &bm);
        assert!(html.contains("cap&lt;1&gt;"));
        assert!(html.contains("Retrans &lt;script&gt;"));
        assert!(html.contains("Check &lt;b&gt;SYN&lt;/b&gt;"));
        assert!(html.contains("SYN &lt;x&gt;") && html.contains("10.0.0.2"));
        assert!(!html.contains("<script>"));

        let hpath = std::env::temp_dir().join(format!("wl-rep-{}.html", std::process::id()));
        write_html_report(&hpath, "cap<1>", &stats, &insights, None, None, &bm).unwrap();
        assert_eq!(std::fs::read_to_string(&hpath).unwrap(), html);
        let _ = std::fs::remove_file(&hpath);
    }
}
