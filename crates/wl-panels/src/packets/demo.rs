//! Screenshot helper: `--packets-demo "text=tcp || dns;menu=quick"` pre-sets panel state
//! (filter text, an open menu, a find query) so every UI state can be captured headlessly.

use crate::packets::find_query::{FindMode, FindQuery, FindScope};
use crate::packets::time_format::TimeFormat;

const MENU_AFTER_S: f64 = 1.2;

#[derive(Default, Debug, PartialEq)]
pub struct Demo {
    pub text: Option<String>,
    menu: Option<String>,
    pub find: Option<String>,
    pub columns: Vec<String>,
    pub time: Option<TimeFormat>,
    pub time_ref: Option<u64>,
    menu_since: Option<f64>,
}

impl Demo {
    pub fn parse(spec: &str) -> Demo {
        let mut d = Demo::default();
        for part in spec.split(';') {
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            let v = v.to_owned();
            match k.trim() {
                "text" => d.text = Some(v),
                "menu" => d.menu = Some(v),
                "find" => d.find = Some(v),
                "col" => d.columns.push(v),
                "time" => {
                    d.time = match v.as_str() {
                        "local" => Some(TimeFormat::Local),
                        "utc" => Some(TimeFormat::Utc),
                        "prev" => Some(TimeFormat::DeltaPrevious),
                        "shown" => Some(TimeFormat::DeltaDisplayed),
                        _ => Some(TimeFormat::Relative),
                    }
                }
                "ref" => d.time_ref = v.parse().ok(),
                _ => {}
            }
        }
        d
    }

    /// `mode|scope|text` of a find query (e.g. `string|list|echo`) -> parsed query.
    pub fn find_query(&self) -> Option<FindQuery> {
        let mut it = self.find.as_deref()?.splitn(3, '|');
        let mode = match it.next()? {
            "filter" => FindMode::Filter,
            "hex" => FindMode::Hex,
            "regex" => FindMode::Regex,
            _ => FindMode::Text,
        };
        let scope = match it.next()? {
            "details" => FindScope::Details,
            "bytes" => FindScope::Bytes,
            _ => FindScope::List,
        };
        Some(FindQuery {
            mode,
            scope,
            case_sensitive: false,
            text: it.next()?.to_owned(),
        })
    }

    /// True exactly once, `MENU_AFTER_S` seconds after the first call (the first frames of a
    /// screenshot run are laid out at another size and would close the popup), when menu
    /// `name` was asked for. `now` is the UI time in seconds.
    pub fn take_menu(&mut self, name: &str, now: f64) -> bool {
        if self.menu.as_deref() != Some(name) {
            return false;
        }
        let t0 = *self.menu_since.get_or_insert(now);
        if now - t0 < MENU_AFTER_S {
            return false;
        }
        self.menu = None;
        true
    }

    /// Whether a requested menu is still waiting (the caller keeps repainting).
    pub fn menu_pending(&self) -> bool {
        self.menu.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keys_and_consumes_menu_once() {
        let mut d = Demo::parse("text=tcp || dns;menu=quick;bogus;find=string:x;col=ip.ttl");
        assert_eq!(d.text.as_deref(), Some("tcp || dns"));
        assert_eq!(d.find.as_deref(), Some("string:x"));
        assert_eq!(d.columns, ["ip.ttl"]);
        assert!(d.find_query().is_none());
        let d2 = Demo::parse("find=regex|bytes|a|b");
        let q = d2.find_query().unwrap();
        assert_eq!(
            (q.mode, q.scope, q.text.as_str()),
            (FindMode::Regex, FindScope::Bytes, "a|b")
        );
        assert!(!d.take_menu("columns", 0.0));
        let opened = (0..100)
            .filter(|i| d.take_menu("quick", f64::from(*i) * 0.1))
            .count();
        assert_eq!(opened, 1);
        assert!(!d.menu_pending());
    }
}
