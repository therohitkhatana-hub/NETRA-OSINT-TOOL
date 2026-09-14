"""
Cross-case search — search every finding across all NETRA investigations.

    python search_cases.py "search phrase"
"""
import sys
import warnings
warnings.filterwarnings("ignore")

from own_index import search_index


def main():
    if len(sys.argv) < 2:
        print("Usage: python search_cases.py \"search phrase\"")
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    results = search_index(query)

    if not results:
        print(f"No past findings match: {query}")
        return

    print(f"Found {len(results)} match(es) for '{query}' across all past investigations:\n")
    for r in results:
        print(f"  [{r['confidence']:.2f}] ({r['source']}) [{r['identifier']}]")
        print(f"    {r['fact']}\n")


if __name__ == "__main__":
    main()
