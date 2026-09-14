"""
Public records module for NETRA — legitimate public data sources beyond breach checking.
  - GitHub commit search: commit author emails via GitHub's public API
  - Wayback Machine (archive.org) CDX API: domain archival history
  - emailrep.io: reputation and breach/disposable analysis
  - General web-mention search: DuckDuckGo search for exact identifiers
"""
import requests
from datetime import datetime
from db import Finding

GITHUB_COMMIT_SEARCH_URL = "https://api.github.com/search/commits"
WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"
EMAILREP_URL = "https://emailrep.io/{}"


def emailrep_lookup(email: str) -> list[Finding]:
    import os
    headers = {}
    api_key = os.getenv("EMAILREP_API_KEY")
    if api_key:
        headers["Key"] = api_key

    try:
        resp = requests.get(EMAILREP_URL.format(email), headers=headers, timeout=10)
        if resp.status_code == 429:
            return [Finding(email, "emailrep", "rate-limited (free tier) — try again shortly or set EMAILREP_API_KEY", 0.0, "rate_limited")]
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(email, "emailrep", f"lookup failed: {e}", 0.0, "error")]

    findings = []
    reputation = data.get("reputation", "unknown")
    suspicious = data.get("suspicious", False)
    findings.append(Finding(
        email, "emailrep",
        f"reputation: {reputation} (suspicious: {suspicious}, based on {data.get('references', 0)} references)",
        0.75, "emailrep_summary",
    ))

    details = data.get("details") or {}
    if details.get("malicious_activity"):
        findings.append(Finding(email, "emailrep", "FLAG: associated with known malicious activity (phishing/fraud) per emailrep.io", 0.8, "emailrep_malicious"))
    if details.get("blacklisted"):
        findings.append(Finding(email, "emailrep", "FLAG: blacklisted for spam/malicious behavior per emailrep.io", 0.75, "emailrep_blacklist"))
    if details.get("credentials_leaked"):
        findings.append(Finding(email, "emailrep", "credentials associated with this email have appeared in a leak (corroborates breach-check findings)", 0.7, "emailrep_creds_leaked"))
    if details.get("new_domain"):
        days = details.get("days_since_domain_creation", "unknown")
        findings.append(Finding(email, "emailrep", f"FLAG: emailrep.io independently confirms domain is new ({days} days old)", 0.65, "emailrep_new_domain"))
    if details.get("disposable"):
        findings.append(Finding(email, "emailrep", "FLAG: disposable/throwaway email provider per emailrep.io", 0.7, "emailrep_disposable"))
    if not details.get("valid_mx", True):
        findings.append(Finding(email, "emailrep", "FLAG: no valid MX record per emailrep.io (corroborates domain check)", 0.6, "emailrep_no_mx"))

    profiles = (data.get("details") or {}).get("profiles", [])
    if profiles:
        findings.append(Finding(
            email, "emailrep",
            f"independently-detected social/platform presence: {', '.join(profiles)}",
            0.7, "emailrep_profiles",
        ))

    return findings


def github_commit_search(email: str) -> list[Finding]:
    try:
        resp = requests.get(
            GITHUB_COMMIT_SEARCH_URL,
            params={"q": f"author-email:{email}"},
            headers={"Accept": "application/vnd.github.cloak-preview+json"},
            timeout=10,
        )
        if resp.status_code == 422:
            return []
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(email, "github_commits", f"lookup failed: {e}", 0.0, "error")]

    items = data.get("items", [])
    if not items:
        return [Finding(email, "github_commits", "no public GitHub commits found for this email", 0.4, "github_no_hits")]

    seen_users = set()
    findings = []
    for item in items[:10]:
        author = item.get("author") or {}
        username = author.get("login")
        repo = (item.get("repository") or {}).get("full_name")
        if username and username not in seen_users:
            seen_users.add(username)
            findings.append(Finding(
                email, "github_commits",
                f"public GitHub commit(s) authored under username '{username}' (e.g. in {repo})",
                0.75, f"github:{username}",
            ))
    if not findings:
        findings.append(Finding(email, "github_commits", f"{len(items)} public commit(s) found but author identity unclear", 0.5, "github_ambiguous"))
    return findings


def wayback_history(domain: str) -> list[Finding]:
    try:
        resp = requests.get(
            WAYBACK_CDX_URL,
            params={"url": domain, "output": "json", "limit": "1", "fl": "timestamp"},
            timeout=10,
        )
        resp.raise_for_status()
        rows = resp.json()
    except (requests.RequestException, ValueError) as e:
        return [Finding(domain, "wayback_machine", f"lookup failed: {e}", 0.0, "error")]

    if len(rows) < 2:
        return [Finding(domain, "wayback_machine", "no archive.org history found for this domain", 0.4, "wayback_no_history")]

    first_seen_raw = rows[1][0]
    first_seen = datetime.strptime(first_seen_raw, "%Y%m%d%H%M%S")
    return [Finding(
        domain, "wayback_machine",
        f"earliest archive.org snapshot: {first_seen.date()} ({(datetime.now() - first_seen).days} days of history)",
        0.6, f"wayback:{first_seen_raw}",
    )]


def web_mention_search(identifier: str, max_results: int = 5) -> list[Finding]:
    try:
        from ddgs import DDGS
        with DDGS() as ddgs:
            results = list(ddgs.text(f'"{identifier}"', max_results=max_results))
    except Exception as e:
        return [Finding(identifier, "web_mention_search", f"search failed: {e}", 0.0, "error")]

    if not results:
        return [Finding(identifier, "web_mention_search", "no public web mentions found", 0.3, "no_mentions")]

    findings = []
    for r in results:
        title = r.get("title", "untitled")
        href = r.get("href", "")
        findings.append(Finding(
            identifier, "web_mention_search",
            f"LEAD (unverified): '{title}' — {href}",
            0.3, href,
        ))
    return findings
