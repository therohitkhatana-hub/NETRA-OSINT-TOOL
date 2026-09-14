"""
Threat-intelligence blocklist cross-referencing for NETRA.
  - URLhaus (abuse.ch): public malware/phishing database
  - Spamhaus DBL: DNS-based blocklist check
"""
import requests
import dns.resolver
from db import Finding

URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"


def urlhaus_check(domain: str) -> list[Finding]:
    try:
        resp = requests.post(URLHAUS_HOST_URL, data={"host": domain}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(domain, "urlhaus", f"lookup failed: {e}", 0.0, "error")]

    status = data.get("query_status")
    if status == "no_results":
        return [Finding(domain, "urlhaus", "not found in URLhaus malware/phishing database", 0.4, "urlhaus_clean")]
    if status != "ok":
        return [Finding(domain, "urlhaus", f"lookup inconclusive (status: {status})", 0.0, "urlhaus_inconclusive")]

    url_count = data.get("url_count", 0)
    findings = [Finding(
        domain, "urlhaus",
        f"FLAG: domain appears in URLhaus with {url_count} associated malicious URL(s)",
        0.85, "urlhaus_hit",
    )]

    urls = data.get("urls", [])[:3]
    for u in urls:
        threat = u.get("threat", "unknown")
        date_added = u.get("date_added", "unknown date")
        findings.append(Finding(
            domain, "urlhaus",
            f"  associated threat: {threat} (reported {date_added})",
            0.8, u.get("urlhaus_reference", "urlhaus"),
        ))
    return findings


def spamhaus_dbl_check(domain: str) -> list[Finding]:
    query_domain = f"{domain}.dbl.spamhaus.org"
    try:
        answers = dns.resolver.resolve(query_domain, "A", lifetime=5)
        codes = [str(r) for r in answers]
        return [Finding(
            domain, "spamhaus_dbl",
            f"FLAG: domain is listed on Spamhaus DBL (return code: {', '.join(codes)}) — associated with spam/abuse/malware",
            0.8, f"spamhaus:{codes}",
        )]
    except dns.resolver.NXDOMAIN:
        return [Finding(domain, "spamhaus_dbl", "not listed on Spamhaus DBL", 0.4, "spamhaus_clean")]
    except Exception as e:
        return [Finding(domain, "spamhaus_dbl", f"lookup failed: {e}", 0.0, "error")]
