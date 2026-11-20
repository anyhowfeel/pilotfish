//! Host search: case-insensitive substring on address or resolved name (pure).

use super::model::Graph;

/// Fills `out` with the indices of matching nodes (heaviest first); empty needle matches nothing.
pub fn matches(g: &Graph, needle: &str, out: &mut Vec<usize>) {
    out.clear();
    let n = needle.trim().to_lowercase();
    if n.is_empty() {
        return;
    }
    out.extend(g.nodes.iter().enumerate().filter_map(|(i, node)| {
        let hit = node.addr.to_lowercase().contains(&n)
            || node
                .name
                .as_deref()
                .is_some_and(|s| s.to_lowercase().contains(&n));
        hit.then_some(i)
    }));
}

#[cfg(test)]
mod tests {
    use super::super::model::{Filters, test_data::star};
    use super::*;

    #[test]
    fn matches_addr_and_name_case_insensitively() {
        let g = Graph::build(&star(), &Filters::default(), &|a| {
            (a == "8.8.8.8").then(|| "DNS.Google".into())
        });
        let mut out = Vec::new();
        matches(&g, "192.168.74.", &mut out);
        assert_eq!(out.len(), 3);
        matches(&g, "google", &mut out);
        assert_eq!(out, [g.find("8.8.8.8").unwrap()]);
        matches(&g, "  ", &mut out);
        assert!(out.is_empty());
    }
}
