"""
NETRA Local Full-Text Search Index — pure-Python local search using Whoosh.

Every finding produced by any module across every investigation ever run gets
written here. This gives NETRA free-text search across all past cases.
"""
import os
from whoosh.index import create_in, open_dir, exists_in
from whoosh.fields import Schema, TEXT, ID, NUMERIC
from whoosh.qparser import QueryParser

INDEX_DIR = "search_index"


def _get_index():
    if not os.path.exists(INDEX_DIR):
        os.makedirs(INDEX_DIR)
    if not exists_in(INDEX_DIR):
        schema = Schema(
            identifier=ID(stored=True),
            source=ID(stored=True),
            fact=TEXT(stored=True),
            confidence=NUMERIC(stored=True),
            raw_reference=TEXT(stored=True),
            timestamp=NUMERIC(stored=True),
        )
        return create_in(INDEX_DIR, schema)
    return open_dir(INDEX_DIR)


def index_findings(findings: list):
    """Call this after any investigation to make its findings permanently searchable."""
    if not findings:
        return
    ix = _get_index()
    writer = ix.writer()
    for f in findings:
        writer.add_document(
            identifier=f.identifier,
            source=f.source,
            fact=f.fact,
            confidence=f.confidence,
            raw_reference=str(f.raw_reference),
            timestamp=f.timestamp,
        )
    writer.commit()


def search_index(query_text: str, limit: int = 20) -> list[dict]:
    """Free-text search across every finding from every past investigation."""
    ix = _get_index()
    with ix.searcher() as searcher:
        parser = QueryParser("fact", ix.schema)
        query = parser.parse(query_text)
        results = searcher.search(query, limit=limit)
        return [
            {
                "identifier": r["identifier"],
                "source": r["source"],
                "fact": r["fact"],
                "confidence": r["confidence"],
            }
            for r in results
        ]
