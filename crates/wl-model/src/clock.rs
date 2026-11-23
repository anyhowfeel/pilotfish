//! Which time zone capture file times are shown in.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ClockZone {
    /// The zone of the machine, like `capinfos` and Wireshark.
    #[default]
    Local,
    Utc,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_is_the_default() {
        assert_eq!(ClockZone::default(), ClockZone::Local);
    }

    #[test]
    fn serde_round_trip() {
        for zone in [ClockZone::Local, ClockZone::Utc] {
            let json = serde_json::to_string(&zone).expect("serialize");
            assert_eq!(
                serde_json::from_str::<ClockZone>(&json).expect("parse"),
                zone
            );
        }
    }
}
