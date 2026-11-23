use chrono::FixedOffset;

use super::*;

/// 2023-11-14 23:33:20 UTC.
const LATE: u64 = 1_700_000_000 + 4_800;

fn stamp(secs: u64, nanos: u32, digits: u8) -> Stamp {
    Stamp {
        secs,
        nanos,
        digits,
    }
}

fn east(hours: i32) -> FixedOffset {
    FixedOffset::east_opt(hours * 3600).expect("offset")
}

#[test]
fn utc_shows_the_instant_as_is() {
    assert_eq!(
        format(&stamp(LATE, 0, 0), ClockZone::Utc).as_deref(),
        Some("2023-11-14 23:33:20")
    );
}

#[test]
fn a_fixed_offset_shifts_the_clock_and_the_date() {
    let s = stamp(LATE, 0, 0);
    assert_eq!(render(&s, &east(1)).as_deref(), Some("2023-11-15 00:33:20"));
    assert_eq!(
        render(&s, &east(-5)).as_deref(),
        Some("2023-11-14 18:33:20")
    );
    assert_eq!(
        render(&s, &east(13)).as_deref(),
        Some("2023-11-15 12:33:20")
    );
}

#[test]
fn an_offset_that_changes_between_dates_applies_to_each_time() {
    let winter = 1_700_000_000;
    let summer = 1_720_000_000;
    let brussels = |secs: u64, hours: i32| render(&stamp(secs, 0, 0), &east(hours));
    assert_eq!(brussels(winter, 1).as_deref(), Some("2023-11-14 23:13:20"));
    assert_eq!(brussels(summer, 2).as_deref(), Some("2024-07-03 11:46:40"));
}

#[test]
fn decimals_follow_the_resolution_of_the_interface() {
    for (digits, text) in [
        (0, "2023-11-14 23:33:20"),
        (3, "2023-11-14 23:33:20.123"),
        (6, "2023-11-14 23:33:20.123456"),
        (9, "2023-11-14 23:33:20.123456789"),
    ] {
        assert_eq!(
            format(&stamp(LATE, 123_456_789, digits), ClockZone::Utc).as_deref(),
            Some(text)
        );
    }
}

#[test]
fn the_decimals_do_not_move_with_the_zone() {
    let s = stamp(LATE, 123_456_000, 6);
    assert_eq!(
        render(&s, &east(9)).as_deref(),
        Some("2023-11-15 08:33:20.123456")
    );
}

#[test]
fn a_time_beyond_the_calendar_is_none() {
    assert_eq!(format(&stamp(u64::MAX, 0, 0), ClockZone::Utc), None);
    assert_eq!(format(&stamp(i64::MAX as u64, 0, 0), ClockZone::Utc), None);
}

#[test]
fn local_is_the_machine_zone() {
    let s = stamp(LATE, 0, 0);
    let expected = DateTime::from_timestamp(LATE as i64, 0)
        .expect("time")
        .with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    assert_eq!(format(&s, ClockZone::Local), Some(expected));
}
