//! tshark's `-T json` repeats keys inside one object (`http.request.line` once per header), which
//! `serde_json::Value` would collapse. `Ordered` keeps every (key, value) pair in document order.

use std::fmt;

use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use serde_json::Value;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Ordered(pub Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Ordered, A::Error> {
                let mut v = Vec::new();
                while let Some(kv) = m.next_entry::<String, Value>()? {
                    v.push(kv);
                }
                Ok(Ordered(v))
            }
        }
        d.deserialize_map(V)
    }
}

impl Ordered {
    /// Every string value stored under `key`, in order.
    pub fn strings<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(k, _)| k == key)
            .filter_map(|(_, v)| v.as_str())
    }

    pub fn first_str<'a>(&'a self, key: &'a str) -> Option<&'a str> {
        self.strings(key).next()
    }
}

/// `http` may be one object, or an array when a frame carries several messages.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(Ordered),
    Many(Vec<Ordered>),
}

#[derive(Debug, Deserialize)]
pub struct Layers {
    pub http: Option<OneOrMany>,
}

#[derive(Debug, Deserialize)]
pub struct Source {
    pub layers: Layers,
}

#[derive(Debug, Deserialize)]
pub struct Packet {
    #[serde(rename = "_source")]
    pub source: Source,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_duplicate_keys_in_order() {
        let o: Ordered = serde_json::from_str(r#"{"a":"1","b":{"x":1},"a":"2"}"#).expect("json");
        assert_eq!(o.strings("a").collect::<Vec<_>>(), ["1", "2"]);
        assert_eq!(o.0[1].0, "b");
    }
}
