//! Time column display formats (Wireshark: View > Time Display Format) and the time
//! reference ("T=0") marker. Pure and tested.

use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use wl_model::PacketRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum TimeFormat {
    /// Seconds since the first packet (or since the time reference).
    #[default]
    Relative,
    Local,
    Utc,
    /// Seconds since the previous captured packet (`frame.number - 1`).
    DeltaPrevious,
    /// Seconds since the previous displayed packet.
    DeltaDisplayed,
}

impl TimeFormat {
    pub const ALL: [TimeFormat; 5] = [
        TimeFormat::Relative,
        TimeFormat::Local,
        TimeFormat::Utc,
        TimeFormat::DeltaPrevious,
        TimeFormat::DeltaDisplayed,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TimeFormat::Relative => "Seconds since first packet",
            TimeFormat::Local => "Time of day (local)",
            TimeFormat::Utc => "Time of day (UTC)",
            TimeFormat::DeltaPrevious => "Delta from previous captured",
            TimeFormat::DeltaDisplayed => "Delta from previous displayed",
        }
    }

    pub fn column_title(self) -> &'static str {
        match self {
            TimeFormat::Relative => "Time",
            TimeFormat::Local => "Time (local)",
            TimeFormat::Utc => "Time (UTC)",
            TimeFormat::DeltaPrevious => "Delta (prev)",
            TimeFormat::DeltaDisplayed => "Delta (shown)",
        }
    }

    /// (initial, minimum) column width in points.
    pub fn widths(self) -> (f32, f32) {
        match self {
            TimeFormat::Local | TimeFormat::Utc => (124.0, 100.0),
            _ => (88.0, 60.0),
        }
    }

    /// Whether the cell needs the previous displayed row.
    pub fn needs_displayed_prev(self) -> bool {
        self == TimeFormat::DeltaDisplayed
    }
}

/// Inputs besides the row itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeCtx {
    pub format: TimeFormat,
    /// Frame marked as `T=0`: (frame number, its epoch).
    pub reference: Option<(u64, f64)>,
    /// Epoch of the previous captured frame.
    pub prev_captured: Option<f64>,
    /// Epoch of the previous displayed row.
    pub prev_displayed: Option<f64>,
}

fn secs(v: f64) -> String {
    wl_kit::format::time_rel(v)
}

fn time_of_day(epoch: f64, utc: bool) -> String {
    let whole = epoch.floor();
    let nanos = ((epoch - whole) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
    let Some(t) = DateTime::<Utc>::from_timestamp(whole as i64, nanos) else {
        return "--".into();
    };
    if utc {
        t.format("%H:%M:%S%.6f").to_string()
    } else {
        t.with_timezone(&Local).format("%H:%M:%S%.6f").to_string()
    }
}

/// Text of the time cell, `*REF*` for the reference frame.
pub fn text(r: &PacketRow, c: &TimeCtx) -> String {
    if c.reference.is_some_and(|(no, _)| no == r.no) && c.format == TimeFormat::Relative {
        return "*REF*".into();
    }
    match c.format {
        TimeFormat::Relative => secs(match c.reference {
            Some((_, e)) => r.epoch - e,
            None => r.rel,
        }),
        TimeFormat::Local => time_of_day(r.epoch, false),
        TimeFormat::Utc => time_of_day(r.epoch, true),
        TimeFormat::DeltaPrevious => secs(c.prev_captured.map_or(0.0, |p| r.epoch - p)),
        TimeFormat::DeltaDisplayed => secs(c.prev_displayed.map_or(0.0, |p| r.epoch - p)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::Transport;

    fn row(no: u64, epoch: f64, rel: f64) -> PacketRow {
        PacketRow {
            no,
            epoch,
            rel,
            src: "a".into(),
            dst: "b".into(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            transport: Transport::Tcp,
            protocol: "TCP".into(),
            len: 1,
            info: "".into(),
            stream: None,
        }
    }

    #[test]
    fn relative_uses_reference_and_marks_it() {
        let r = row(5, 1000.5, 2.5);
        let mut c = TimeCtx::default();
        assert_eq!(text(&r, &c), "2.500000");
        c.reference = Some((3, 1000.0));
        assert_eq!(text(&r, &c), "0.500000");
        assert_eq!(text(&row(2, 999.0, 1.0), &c), "-1.000000");
        c.reference = Some((5, 1000.5));
        assert_eq!(text(&r, &c), "*REF*");
    }

    #[test]
    fn deltas() {
        let r = row(5, 10.25, 0.0);
        let c = TimeCtx {
            format: TimeFormat::DeltaPrevious,
            prev_captured: Some(10.0),
            ..Default::default()
        };
        assert_eq!(text(&r, &c), "0.250000");
        let c = TimeCtx {
            format: TimeFormat::DeltaDisplayed,
            prev_displayed: None,
            ..c
        };
        assert_eq!(text(&r, &c), "0.000000");
    }

    #[test]
    fn utc_time_of_day() {
        let r = row(1, 86_400.0 + 3_661.123456, 0.0);
        let c = TimeCtx {
            format: TimeFormat::Utc,
            ..Default::default()
        };
        assert_eq!(text(&r, &c), "01:01:01.123456");
        let local = text(
            &r,
            &TimeCtx {
                format: TimeFormat::Local,
                ..Default::default()
            },
        );
        assert_eq!(local.len(), 15);
    }
}
