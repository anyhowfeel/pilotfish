//! Packet times as `capinfos` prints them: `YYYY-MM-DD HH:MM:SS.ffffff`, with as many decimals
//! as the packet's interface resolves.

use std::fmt::Display;

use chrono::{DateTime, Local, TimeZone, Utc};
use wl_model::ClockZone;

use crate::reader::Stamp;

/// `None` when the time is outside the range a calendar date can show.
pub fn format(stamp: &Stamp, zone: ClockZone) -> Option<String> {
    match zone {
        ClockZone::Utc => render(stamp, &Utc),
        ClockZone::Local => render(stamp, &Local),
    }
}

fn render<Tz>(stamp: &Stamp, tz: &Tz) -> Option<String>
where
    Tz: TimeZone,
    Tz::Offset: Display,
{
    let secs = i64::try_from(stamp.secs).ok()?;
    let time = DateTime::from_timestamp(secs, 0)?.with_timezone(tz);
    let mut out = time.format("%Y-%m-%d %H:%M:%S").to_string();
    if stamp.digits > 0 {
        let nanos = format!("{:09}", stamp.nanos);
        out.push('.');
        out.push_str(&nanos[..usize::from(stamp.digits)]);
    }
    Some(out)
}

#[cfg(test)]
#[path = "stamp_tests.rs"]
mod tests;
