//! PDML (`tshark -T pdml`) -> detail tree with byte ranges.

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use wl_model::{CaptureError, DetailNode};

#[derive(Default)]
struct Attrs {
    name: String,
    showname: String,
    show: String,
    pos: Option<usize>,
    size: Option<usize>,
    hidden: bool,
}

fn attrs(e: &BytesStart) -> Attrs {
    let mut a = Attrs::default();
    for at in e.attributes().flatten() {
        let val = at
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| at.value.into_owned());
        match at.key.as_ref() {
            "name" => a.name = val,
            "showname" => a.showname = val,
            "show" => a.show = val,
            "pos" => a.pos = val.parse().ok(),
            "size" => a.size = val.parse().ok(),
            "hide" => a.hidden = val == "yes",
            _ => {}
        }
    }
    a
}

fn label(is_proto: bool, a: &Attrs) -> String {
    if !a.showname.is_empty() {
        a.showname.clone()
    } else if is_proto || a.show.is_empty() {
        a.name.clone()
    } else if a.name.is_empty() {
        a.show.clone()
    } else {
        format!("{}: {}", a.name, a.show)
    }
}

fn node(is_proto: bool, a: &Attrs) -> DetailNode {
    let range = match (a.pos, a.size) {
        (Some(p), Some(s)) if s > 0 => p.checked_add(s).map(|end| (p, end)),
        _ => None,
    };
    DetailNode {
        label: label(is_proto, a),
        range,
        children: Vec::new(),
    }
}

/// "geninfo" duplicates the Frame layer and spans all bytes; fields flagged `hide` are hidden by Wireshark too.
fn skipped(is_proto: bool, a: &Attrs) -> bool {
    a.hidden || (is_proto && a.name == "geninfo")
}

fn kind(name: &str) -> Option<bool> {
    match name {
        "proto" => Some(true),
        "field" => Some(false),
        _ => None,
    }
}

#[derive(Default)]
struct Builder {
    layers: Vec<DetailNode>,
    stack: Vec<DetailNode>,
    skip: usize,
}

impl Builder {
    fn attach(&mut self, n: DetailNode) {
        match self.stack.last_mut() {
            Some(parent) => parent.children.push(n),
            None => self.layers.push(n),
        }
    }

    fn open(&mut self, e: &BytesStart, empty: bool) {
        let Some(is_proto) = kind(e.name().as_ref()) else {
            return;
        };
        if self.skip > 0 {
            self.skip += usize::from(!empty);
            return;
        }
        let a = attrs(e);
        if skipped(is_proto, &a) {
            self.skip += usize::from(!empty);
        } else if empty {
            self.attach(node(is_proto, &a));
        } else {
            self.stack.push(node(is_proto, &a));
        }
    }

    fn close(&mut self, name: &str) {
        if kind(name).is_none() {
            return;
        }
        if self.skip > 0 {
            self.skip -= 1;
        } else if let Some(n) = self.stack.pop() {
            self.attach(n);
        }
    }
}

pub fn parse(xml: &[u8]) -> Result<Vec<DetailNode>, CaptureError> {
    let text = String::from_utf8_lossy(xml);
    let mut reader = Reader::from_str(&text);
    let mut b = Builder::default();
    loop {
        match reader
            .read_event()
            .map_err(|e| CaptureError::Other(format!("invalid PDML: {e}")))?
        {
            Event::Start(e) => b.open(&e, false),
            Event::Empty(e) => b.open(&e, true),
            Event::End(e) => b.close(e.name().as_ref()),
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(b.layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0"?><pdml><packet>
<proto name="geninfo" pos="0" showname="General information" size="98"><field name="num" show="2" size="98" pos="0"/></proto>
<proto name="frame" showname="Frame 2: Packet, 98 bytes" size="98" pos="0">
  <field name="frame.number" showname="Frame Number: 2" size="0" pos="0" show="2"/>
</proto>
<proto name="ip" showname="Internet Protocol Version 4" size="20" pos="14">
  <field name="ip.dsfield" showname="DS Field: 0x00" size="1" pos="15" show="0x00">
    <field name="ip.dsfield.dscp" showname="DSCP: Default" size="1" pos="15" show="0"/>
  </field>
  <field name="ip.hidden" showname="hidden thing" hide="yes" size="1" pos="16" show="1"><field name="x" showname="child of hidden" size="1" pos="16"/></field>
  <field name="ip.flags" showname="Don&#x27;t fragment: Not set" size="1" pos="20" show="0"/>
  <field name="" show="Expert info" size="0" pos="0"/>
</proto></packet></pdml>"#;

    #[test]
    fn builds_tree_with_ranges() {
        let layers = parse(XML.as_bytes()).unwrap();
        let names: Vec<_> = layers.iter().map(|l| l.label.as_str()).collect();
        assert_eq!(
            names,
            ["Frame 2: Packet, 98 bytes", "Internet Protocol Version 4"]
        );
        assert_eq!(layers[0].range, Some((0, 98)));
        let ip = &layers[1];
        assert_eq!(ip.range, Some((14, 34)));
        assert_eq!(ip.children.len(), 3);
        assert_eq!(ip.children[0].range, Some((15, 16)));
        assert_eq!(ip.children[0].children[0].label, "DSCP: Default");
        assert_eq!(ip.children[1].label, "Don't fragment: Not set");
        assert_eq!(ip.children[2].label, "Expert info");
        assert_eq!(ip.children[2].range, None);
    }

    #[test]
    fn malformed_xml_is_an_error() {
        assert!(parse(br#"<pdml><proto name="a"></pdml>"#).is_err() || parse(b"<<<").is_err());
    }

    #[test]
    fn handles_empty_overflow_and_non_utf8_attrs() {
        assert!(parse(b"").unwrap().is_empty());
        let overflow = format!(
            r#"<pdml><packet><proto name="p" pos="{}" size="10"/></packet></pdml>"#,
            usize::MAX
        );
        let layers = parse(overflow.as_bytes()).unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].range, None);

        let mut raw = br#"<pdml><packet><proto name="x" showname="hi "#.to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(br#"" pos="0" size="2"/></packet></pdml>"#);
        let layers = parse(&raw).unwrap();
        assert_eq!(layers.len(), 1);
        assert!(layers[0].label.starts_with("hi "));
        assert!(layers[0].label.contains('\u{fffd}'));
    }
}
