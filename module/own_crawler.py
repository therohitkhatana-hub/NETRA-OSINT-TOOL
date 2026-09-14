"""
Scoped crawler module for NETRA — OWN IMPLEMENTATION querying primary sources directly.
  - Reddit's public search JSON endpoint
  - GitHub's code search API
  - Common Crawl's CDX index
"""
import requests
from db import Finding

REDDIT_SEARCH_URL = "https://www.reddit.com/search.json"
GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"
COMMONCRAWL_COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"


def reddit_search(identifier: str, max_results: int = 5) -> list[Finding]:
    """Free, public, no key. Reddit's own search API, queried directly."""
    try:
        resp = requests.get(
            REDDIT_SEARCH_URL,
            params={"q": f'"{identifier}"', "limit": max_results, "sort": "new"},
            headers={"User-Agent": "netra-osint-tool/1.0 (own crawler module)"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(identifier, "reddit_search", f"lookup failed: {e}", 0.0, "error")]

    posts = data.get("data", {}).get("children", [])
    if not posts:
        return [Finding(identifier, "reddit_search", "no public Reddit mentions found", 0.3, "reddit_no_hits")]

    findings = []
    for post in posts:
        p = post.get("data", {})
        title = p.get("title", "untitled")
        subreddit = p.get("subreddit", "unknown")
        permalink = f"https://reddit.com{p.get('permalink', '')}"
        findings.append(Finding(
            identifier, "reddit_search",
            f"LEAD (unverified): r/{subreddit} — '{title}' — {permalink}",
            0.35, permalink,
        ))
    return findings


def github_code_search(identifier: str, max_results: int = 5) -> list[Finding]:
    import os
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        resp = requests.get(
            GITHUB_CODE_SEARCH_URL,
            params={"q": f'"{identifier}"'},
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 403:
            return [Finding(identifier, "github_code_search", "rate-limited (unauthenticated GitHub API) — set GITHUB_TOKEN for higher limit", 0.0, "rate_limited")]
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(identifier, "github_code_search", f"lookup failed: {e}", 0.0, "error")]

    items = data.get("items", [])
    if not items:
        return [Finding(identifier, "github_code_search", "identifier does not appear in any public GitHub code", 0.4, "github_code_no_hits")]

    findings = []
    for item in items[:max_results]:
        repo = item.get("repository", {}).get("full_name", "unknown repo")
        path = item.get("path", "unknown file")
        html_url = item.get("html_url", "")
        findings.append(Finding(
            identifier, "github_code_search",
            f"FLAG: identifier found literally in public code — {repo}/{path} — {html_url}",
            0.6, html_url,
        ))
    return findings


def commoncrawl_domain_history(domain: str) -> list[Finding]:
    try:
        collinfo = requests.get(COMMONCRAWL_COLLINFO_URL, timeout=10).json()
        if not collinfo:
            return [Finding(domain, "commoncrawl", "could not retrieve Common Crawl index list", 0.0, "error")]
        latest_cdx_api = collinfo[0]["cdx-api"]

        resp = requests.get(
            latest_cdx_api,
            params={"url": f"{domain}/*", "output": "json", "limit": 5},
            timeout=15,
        )
        if resp.status_code == 404 or not resp.text.strip():
            return [Finding(domain, "commoncrawl", "domain not found in latest Common Crawl snapshot", 0.35, "commoncrawl_no_hits")]
        resp.raise_for_status()

        lines = [l for l in resp.text.strip().split("\n") if l.strip()]
        return [Finding(
            domain, "commoncrawl",
            f"found {len(lines)} indexed URL(s) for this domain in Common Crawl's latest snapshot ({collinfo[0].get('id', 'unknown')})",
            0.5, f"commoncrawl:{collinfo[0].get('id', 'unknown')}",
        )]
    except requests.RequestException as e:
        return [Finding(domain, "commoncrawl", f"lookup failed: {e}", 0.0, "error")]
