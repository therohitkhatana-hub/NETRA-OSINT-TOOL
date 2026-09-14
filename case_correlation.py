"""
Cross-case correlation for NETRA — find shared entities (carrier, domain, platform
hits, region) across DIFFERENT cases stored in netra.db, making multi-complaint
infrastructure patterns visible.
"""
import os
import re
from collections import defaultdict
from db import get_all_findings, DB_PATH

# Each pattern extracts a normalized "signal token" from a finding's fact text.
# Two different cases sharing a signal token get linked in the correlation graph.
SIGNAL_PATTERNS = {
    "carrier": re.compile(r"carrier:\s*([A-Za-z0-9 ]+?)(?:\s*\(|$)", re.IGNORECASE),
    "region": re.compile(r"region/circle:\s*([A-Za-z ]+?)(?:\s*\(|$)", re.IGNORECASE),
    "platform_account": re.compile(r"account found on ([a-zA-Z0-9_]+)", re.IGNORECASE),
    "domain_via_mx": re.compile(r"MX records?:\s*.*?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.IGNORECASE),
}


def extract_signals(findings: list) -> dict:
    """identifier -> {signal_type: set(values)}"""
    signals = defaultdict(lambda: defaultdict(set))
    for f in findings:
        for signal_type, pattern in SIGNAL_PATTERNS.items():
            match = pattern.search(f.fact)
            if match:
                value = match.group(1).strip().lower()
                if value:
                    signals[f.identifier][signal_type].add(value)
    return signals


def find_correlations(db_path: str = DB_PATH) -> list[dict]:
    """
    Returns a list of {identifier_a, identifier_b, signal_type, shared_value}
    for every pair of DIFFERENT identifiers (cases) that share a signal.
    """
    if db_path == "netra.db" and not os.path.exists("netra.db") and os.path.exists("dossier.db"):
        db_path = "dossier.db"
    all_findings = get_all_findings(db_path)
    signals = extract_signals(all_findings)
    identifiers = list(signals.keys())

    correlations = []
    for i in range(len(identifiers)):
        for j in range(i + 1, len(identifiers)):
            id_a, id_b = identifiers[i], identifiers[j]
            if id_a == id_b:
                continue
            for signal_type in SIGNAL_PATTERNS:
                shared = signals[id_a][signal_type] & signals[id_b][signal_type]
                for value in shared:
                    correlations.append({
                        "identifier_a": id_a,
                        "identifier_b": id_b,
                        "signal_type": signal_type,
                        "shared_value": value,
                    })
    return correlations
