//! Which backend answers a request. Pure: the filter subset is passed in as a closure.

use wl_model::{CaptureSource, IoSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Native,
    Deep,
}

/// A blank filter selects everything, so it never needs a filter engine.
fn usable(filter: &str, supports: &impl Fn(&str) -> bool) -> bool {
    filter.trim().is_empty() || supports(filter)
}

pub fn start_route(
    source: &CaptureSource,
    filter: Option<&str>,
    decode_as_active: bool,
    supports: impl Fn(&str) -> bool,
) -> Route {
    let CaptureSource::File(_) = source else {
        return Route::Deep;
    };
    if decode_as_active || !usable(filter.unwrap_or(""), &supports) {
        return Route::Deep;
    }
    Route::Native
}

pub fn filter_route(filter: &str, supports: impl Fn(&str) -> bool) -> Route {
    if usable(filter, &supports) {
        Route::Native
    } else {
        Route::Deep
    }
}

pub fn io_route(specs: &[IoSpec], supports: impl Fn(&str) -> bool) -> Route {
    if specs.iter().all(|s| usable(&s.filter, &supports)) {
        Route::Native
    } else {
        Route::Deep
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use wl_model::CaptureOptions;

    use super::*;

    fn only_tcp(f: &str) -> bool {
        f == "tcp"
    }

    fn file() -> CaptureSource {
        CaptureSource::File(PathBuf::from("a.pcap"))
    }

    fn live() -> CaptureSource {
        CaptureSource::Live {
            interface: "eth0".into(),
            capture_filter: None,
        }
    }

    fn capture() -> CaptureSource {
        CaptureSource::Capture(CaptureOptions::single("eth0", None))
    }

    #[test]
    fn start_routes_follow_the_table() {
        use Route::{Deep, Native};
        let cases: Vec<(&str, CaptureSource, Option<&str>, bool, Route)> = vec![
            ("file, no filter", file(), None, false, Native),
            ("file, empty filter", file(), Some(""), false, Native),
            ("file, blank filter", file(), Some("  \t"), false, Native),
            ("file, subset filter", file(), Some("tcp"), false, Native),
            ("file, other filter", file(), Some("http"), false, Deep),
            ("file, decode as", file(), None, true, Deep),
            (
                "file, subset and decode as",
                file(),
                Some("tcp"),
                true,
                Deep,
            ),
            ("file, blank and decode as", file(), Some(" "), true, Deep),
            ("live", live(), None, false, Deep),
            ("live, subset filter", live(), Some("tcp"), false, Deep),
            ("capture", capture(), None, false, Deep),
        ];
        for (name, source, filter, decode_as, want) in cases {
            assert_eq!(
                start_route(&source, filter, decode_as, only_tcp),
                want,
                "{name}"
            );
        }
    }

    #[test]
    fn a_blank_filter_never_asks_the_subset() {
        let never = |_: &str| -> bool { panic!("asked") };
        assert_eq!(start_route(&file(), Some(" "), false, never), Route::Native);
        assert_eq!(filter_route("", never), Route::Native);
        assert_eq!(io_route(&[spec("")], never), Route::Native);
    }

    #[test]
    fn check_filter_routes() {
        assert_eq!(filter_route("tcp", only_tcp), Route::Native);
        assert_eq!(filter_route("", only_tcp), Route::Native);
        assert_eq!(filter_route("   ", only_tcp), Route::Native);
        assert_eq!(filter_route("http", only_tcp), Route::Deep);
    }

    fn spec(filter: &str) -> IoSpec {
        IoSpec {
            filter: filter.into(),
            delta: None,
        }
    }

    #[test]
    fn io_routes() {
        assert_eq!(io_route(&[], only_tcp), Route::Native);
        assert_eq!(io_route(&[spec("")], only_tcp), Route::Native);
        assert_eq!(io_route(&[spec("tcp"), spec("")], only_tcp), Route::Native);
        assert_eq!(io_route(&[spec("tcp"), spec("dns")], only_tcp), Route::Deep);
        assert_eq!(io_route(&[spec("dns")], only_tcp), Route::Deep);
    }
}
