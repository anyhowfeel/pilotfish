use super::test_data::star;
use super::*;

fn build(f: Filters) -> Graph {
    Graph::build(&star(), &f, &|_| None)
}

#[test]
fn nodes_ranked_by_bytes_and_links_resolved() {
    let g = build(Filters::default());
    assert_eq!(g.nodes.len(), 5);
    assert_eq!(&*g.nodes[0].addr, "192.168.74.124");
    assert_eq!(g.links.len(), 4);
    assert_eq!(g.nodes[0].radius, crate::topology::scale::R_MAX);
    let gw = g.find("192.168.74.1").unwrap();
    assert_eq!(g.nodes[gw].degree, 3);
    assert!(g.nodes[gw].hub);
    assert!(!g.nodes[g.find("8.8.8.8").unwrap()].private);
    assert_eq!(g.peers(gw).len(), 3);
}

#[test]
fn hide_private_pairs_drops_lan_links_and_orphans() {
    let g = build(Filters {
        hide_private_pairs: true,
        ..Filters::default()
    });
    assert_eq!(g.links.len(), 2);
    assert!(g.find("192.168.74.7").is_none());
}

#[test]
fn min_intensity_hides_light_links() {
    let g = build(Filters {
        min_intensity: 0.8,
        ..Filters::default()
    });
    assert_eq!(g.links.len(), 1);
    assert_eq!(g.links[0].t, 1.0);
}

#[test]
fn names_are_resolved() {
    let g = Graph::build(&star(), &Filters::default(), &|a| {
        (a == "8.8.8.8").then(|| Arc::from("dns.google"))
    });
    assert_eq!(g.nodes[g.find("8.8.8.8").unwrap()].label(), "dns.google");
}

#[test]
fn node_cap_counts_hidden() {
    let mut s = StatsSnapshot::default();
    for i in 0..(MAX_NODES + 20) {
        s.edges.push(test_data::edge(
            "hub",
            &format!("n{i:04}"),
            1_000 + i as u64,
            "UDP",
        ));
    }
    let g = Graph::build(&s, &Filters::default(), &|_| None);
    assert_eq!(g.nodes.len(), MAX_NODES);
    assert_eq!(g.hidden, 21);
    assert!(g.links.len() < s.edges.len());
}
