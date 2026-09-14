"""
NETRA Storage Layer.
Every OSINT module returns a list of Finding objects.
Persisted into SQLite database (netra.db) with index support.
"""
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional

# Default database for NETRA
DB_PATH = "netra.db"


@dataclass
class Finding:
    identifier: str          # the phone/email being investigated
    source: str               # e.g. "numverify", "hibp", "gravatar", "phonenumbers"
    fact: str                 # human-readable finding, e.g. "line type: VOIP"
    confidence: float         # 0.0–1.0, set by scoring.py after cross-validation
    raw_reference: str        # short pointer to raw API response / URL, for citation
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


def init_db(path: str = DB_PATH):
    # Seamless backward-compatibility fallback if dossier.db exists and netra.db doesn't
    if path == "netra.db" and not os.path.exists("netra.db") and os.path.exists("dossier.db"):
        path = "dossier.db"

    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,
            source TEXT NOT NULL,
            fact TEXT NOT NULL,
            confidence REAL NOT NULL,
            raw_reference TEXT,
            timestamp REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_identifier ON findings(identifier)")
    conn.commit()
    return conn


def save_findings(conn, findings: list[Finding]):
    conn.executemany(
        """INSERT INTO findings (identifier, source, fact, confidence, raw_reference, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [(f.identifier, f.source, f.fact, f.confidence, f.raw_reference, f.timestamp) for f in findings]
    )
    conn.commit()


def get_findings(conn, identifier: str) -> list[Finding]:
    rows = conn.execute(
        "SELECT identifier, source, fact, confidence, raw_reference, timestamp FROM findings WHERE identifier = ?",
        (identifier,)
    ).fetchall()
    return [Finding(*row) for row in rows]


def get_all_findings(path: str = DB_PATH) -> list[Finding]:
    """Every finding from every case ever investigated — used by case_graph.py
    for cross-case correlation and by search_cases.py's index rebuild."""
    if path == "netra.db" and not os.path.exists("netra.db") and os.path.exists("dossier.db"):
        path = "dossier.db"
    conn = sqlite3.connect(path)
    rows = conn.execute(
        "SELECT identifier, source, fact, confidence, raw_reference, timestamp FROM findings"
    ).fetchall()
    conn.close()
    return [Finding(*row) for row in rows]


def distinct_identifiers(path: str = DB_PATH) -> list[str]:
    """List of every unique phone/email/domain ever investigated — i.e. every 'case'."""
    if path == "netra.db" and not os.path.exists("netra.db") and os.path.exists("dossier.db"):
        path = "dossier.db"
    conn = sqlite3.connect(path)
    rows = conn.execute("SELECT DISTINCT identifier FROM findings").fetchall()
    conn.close()
    return [r[0] for r in rows]
