#!/usr/bin/env python3
"""Reference answers from networkx for the tests of wl-planar.

Reads a JSON list of graphs `{"n": 5, "edges": [[0, 1], ...]}` on stdin and prints a JSON list of
`{"planar": bool, "rotation": [[...], ...] | null}`, where `rotation[v]` is the clockwise order of
the neighbours of `v` in a planar embedding. Loops and repeated edges are ignored like `Graph::new`
does.
"""
import json
import sys

import networkx as nx


def answer(spec):
    g = nx.Graph()
    g.add_nodes_from(range(spec["n"]))
    for a, b in spec["edges"]:
        if a != b and 0 <= a < spec["n"] and 0 <= b < spec["n"]:
            g.add_edge(a, b)
    planar, emb = nx.check_planarity(g)
    if not planar:
        return {"planar": False, "rotation": None}
    return {
        "planar": True,
        "rotation": [list(emb.neighbors_cw_order(v)) for v in range(spec["n"])],
    }


if __name__ == "__main__":
    json.dump([answer(s) for s in json.load(sys.stdin)], sys.stdout)
