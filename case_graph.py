"""
Renders the cross-case correlation graph for NETRA — visual proof of shared infrastructure
across separate investigations.

    python case_graph.py

Produces case_graph.png: one node per case (identifier), one edge per shared
signal (same carrier, same region, same platform account hit, same MX domain).
"""
import os
import sys
import graphviz
from case_correlation import find_correlations
from db import distinct_identifiers, DB_PATH

EDGE_COLORS = {
    "carrier": "#1a7f37",
    "region": "#9a6700",
    "platform_account": "#7a1a7a",
    "domain_via_mx": "#1a4d7a",
}


def build_graph(db_path: str = DB_PATH, output_path: str = "case_graph"):
    if db_path == "netra.db" and not os.path.exists("netra.db") and os.path.exists("dossier.db"):
        db_path = "dossier.db"
    identifiers = distinct_identifiers(db_path)
    correlations = find_correlations(db_path)

    if not identifiers:
        print(f"No cases in {db_path} yet — run an investigation first.")
        return None

    dot = graphviz.Graph("NetraCaseCorrelation", format="png")
    dot.attr(bgcolor="white", fontname="Helvetica", overlap="false", splines="true")
    dot.attr("node", fontname="Helvetica", fontsize="10", shape="box", style="filled",
              fillcolor="#2b2b2b", fontcolor="white")
    dot.attr("edge", fontname="Helvetica", fontsize="8")

    for identifier in identifiers:
        dot.node(identifier, identifier)

    seen_pairs = set()
    for c in correlations:
        pair_key = (c["identifier_a"], c["identifier_b"], c["signal_type"], c["shared_value"])
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)
        color = EDGE_COLORS.get(c["signal_type"], "#555555")
        dot.edge(
            c["identifier_a"], c["identifier_b"],
            label=f"{c['signal_type']}: {c['shared_value']}",
            color=color, fontcolor=color,
        )

    dot.render(output_path, cleanup=True)
    return correlations


def main():
    correlations = build_graph()
    if correlations is None:
        return

    if not correlations:
        print("No cross-case correlations found yet — cases don't share any tracked signal.")
        print("(Graph still generated showing isolated case nodes: case_graph.png)")
        return

    print(f"Found {len(correlations)} cross-case correlation(s):\n")
    for c in correlations:
        print(f"  {c['identifier_a']}  <-->  {c['identifier_b']}")
        print(f"    shared {c['signal_type']}: {c['shared_value']}\n")
    print("Graph saved to case_graph.png")


if __name__ == "__main__":
    main()
