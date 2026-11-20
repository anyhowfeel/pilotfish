//! Pure dissection-tree logic: flattening with open state + search, paths, byte ranges.

use std::collections::HashSet;

use wl_model::DetailNode;

/// One visible line of the tree. `idx` is the node's pre-order index (stable per frame).
#[derive(Debug, Clone, PartialEq)]
pub struct FlatRow {
    pub idx: usize,
    pub depth: u16,
    pub has_children: bool,
    pub open: bool,
    pub matches: bool,
    pub label: String,
    pub range: Option<(usize, usize)>,
}

fn node_matches(n: &DetailNode, q: &str) -> bool {
    !q.is_empty() && n.label.to_lowercase().contains(q)
}

fn subtree_matches(n: &DetailNode, q: &str) -> bool {
    node_matches(n, q) || n.children.iter().any(|c| subtree_matches(c, q))
}

fn walk(
    n: &DetailNode,
    depth: u16,
    idx: &mut usize,
    open: &HashSet<usize>,
    q: &str,
    out: &mut Vec<FlatRow>,
) {
    let my = *idx;
    *idx += 1;
    let has_children = !n.children.is_empty();
    // Searching force-expands every ancestor of a match.
    let is_open = has_children
        && (open.contains(&my)
            || (!q.is_empty() && n.children.iter().any(|c| subtree_matches(c, q))));
    out.push(FlatRow {
        idx: my,
        depth,
        has_children,
        open: is_open,
        matches: node_matches(n, q),
        label: super::http_row::clean(&n.label).to_owned(),
        range: n.range,
    });
    if is_open {
        for c in &n.children {
            walk(c, depth + 1, idx, open, q, out);
        }
    } else {
        *idx += count(&n.children);
    }
}

fn count(nodes: &[DetailNode]) -> usize {
    nodes.iter().map(|n| 1 + count(&n.children)).sum()
}

pub fn flatten(layers: &[DetailNode], open: &HashSet<usize>, query: &str) -> Vec<FlatRow> {
    let q = query.trim().to_lowercase();
    let mut out = Vec::new();
    let mut idx = 0;
    for l in layers {
        walk(l, 0, &mut idx, open, &q, &mut out);
    }
    out
}

/// Smart default: only the two innermost (most specific) protocol layers are expanded.
pub fn default_open(layers: &[DetailNode]) -> HashSet<usize> {
    let mut starts = Vec::new();
    let mut idx = 0;
    for l in layers {
        starts.push(idx);
        idx += 1 + count(&l.children);
    }
    starts.iter().rev().take(2).copied().collect()
}

pub fn all_open(layers: &[DetailNode]) -> HashSet<usize> {
    (0..count(layers)).collect()
}

fn find<'a>(
    nodes: &'a [DetailNode],
    target: usize,
    idx: &mut usize,
    path: &mut Vec<&'a str>,
) -> Option<&'a DetailNode> {
    for n in nodes {
        let my = *idx;
        *idx += 1;
        path.push(&n.label);
        if my == target {
            return Some(n);
        }
        if let Some(f) = find(&n.children, target, idx, path) {
            return Some(f);
        }
        path.pop();
    }
    None
}

/// "Frame > Ethernet II > Destination: ..." for the node with pre-order index `target`.
pub fn path_of(layers: &[DetailNode], target: usize) -> Option<String> {
    let mut path = Vec::new();
    find(layers, target, &mut 0, &mut path)?;
    Some(path.join(" > "))
}

/// Text after the first ": " of a label, or the whole label.
pub fn value_of(label: &str) -> &str {
    label.split_once(": ").map_or(label, |(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(label: &str, children: Vec<DetailNode>) -> DetailNode {
        DetailNode {
            label: label.into(),
            range: Some((0, 1)),
            children,
        }
    }

    fn tree() -> Vec<DetailNode> {
        vec![
            n("Frame 1", vec![n("Arrival: now", vec![])]),
            n("Ethernet", vec![n("Dst: aa", vec![]), n("Src: bb", vec![])]),
            n("TCP", vec![n("Port: 443", vec![n("Flag: S", vec![])])]),
        ]
    }

    #[test]
    fn default_opens_last_two_layers() {
        let t = tree();
        let open = default_open(&t);
        let rows = flatten(&t, &open, "");
        let labels: Vec<_> = rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Frame 1",
                "Ethernet",
                "Dst: aa",
                "Src: bb",
                "TCP",
                "Port: 443"
            ]
        );
    }

    #[test]
    fn indices_are_stable_across_collapsed_subtrees() {
        let t = tree();
        let collapsed = flatten(&t, &HashSet::new(), "");
        let all = flatten(&t, &all_open(&t), "");
        assert_eq!(collapsed.last().unwrap().idx, 5);
        assert_eq!(all.iter().find(|r| r.label == "TCP").unwrap().idx, 5);
        assert_eq!(all.len(), 8);
    }

    #[test]
    fn search_expands_ancestors_and_flags_matches() {
        let t = tree();
        let rows = flatten(&t, &HashSet::new(), "flag");
        assert!(rows.iter().any(|r| r.label == "Flag: S" && r.matches));
        assert!(rows.iter().any(|r| r.label == "Port: 443" && r.open));
        assert!(!rows.iter().any(|r| r.label.starts_with("Dst")));
    }

    #[test]
    fn paths_and_values() {
        let t = tree();
        assert_eq!(path_of(&t, 7).unwrap(), "TCP > Port: 443 > Flag: S");
        assert_eq!(path_of(&t, 1).unwrap(), "Frame 1 > Arrival: now");
        assert!(path_of(&t, 99).is_none());
        assert_eq!(value_of("Source Port: 443"), "443");
        assert_eq!(value_of("Frame 1"), "Frame 1");
    }
}
