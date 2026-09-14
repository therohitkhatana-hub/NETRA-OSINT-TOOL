"""
Domain reconnaissance module for NETRA — passive reads of public domain data.
  - Shodan InternetDB: ports, vulns, CVEs
  - Certificate Transparency: crt.sh subdomains
  - HTTP Security Headers auditing
  - DNS full infrastructure fingerprinting
  - robots.txt & sitemap.xml inspection
"""
import socket
import requests
import dns.resolver
from db import Finding

SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{}"
CRTSH_URL = "https://crt.sh/"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "enforces HTTPS-only connections",
    "Content-Security-Policy": "restricts what content/scripts can load",
    "X-Frame-Options": "prevents clickjacking via iframe embedding",
    "X-Content-Type-Options": "prevents MIME-type sniffing attacks",
    "Referrer-Policy": "controls what referrer data leaks to other sites",
}


def shodan_internetdb(domain: str) -> list[Finding]:
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        return [Finding(domain, "shodan_internetdb", f"could not resolve IP: {e}", 0.0, "dns_resolve_error")]

    try:
        resp = requests.get(SHODAN_INTERNETDB_URL.format(ip), timeout=10)
        if resp.status_code == 404:
            return [Finding(domain, "shodan_internetdb", f"no data indexed for IP {ip} (not necessarily secure — just not scanned/indexed)", 0.3, "internetdb_404")]
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(domain, "shodan_internetdb", f"lookup failed: {e}", 0.0, "error")]

    findings = []
    ports = data.get("ports", [])
    if ports:
        findings.append(Finding(domain, "shodan_internetdb", f"open ports detected on {ip}: {', '.join(map(str, ports))}", 0.7, f"internetdb:{ip}"))

    vulns = data.get("vulns", [])
    if vulns:
        findings.append(Finding(
            domain, "shodan_internetdb",
            f"FLAG: {len(vulns)} known CVE(s) associated with this IP: {', '.join(vulns[:5])}",
            0.75, f"internetdb_vulns:{ip}",
        ))

    tags = data.get("tags", [])
    if tags:
        findings.append(Finding(domain, "shodan_internetdb", f"tags: {', '.join(tags)}", 0.5, f"internetdb_tags:{ip}"))

    if not findings:
        findings.append(Finding(domain, "shodan_internetdb", f"no open ports/vulns indexed for {ip}", 0.4, "internetdb_clean"))

    return findings


def crtsh_subdomains(domain: str, max_results: int = 15) -> list[Finding]:
    try:
        resp = requests.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        return [Finding(domain, "crtsh", f"lookup failed: {e}", 0.0, "error")]

    subdomains = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*."):
                subdomains.add(name)

    if not subdomains:
        return [Finding(domain, "crtsh", "no subdomains found in certificate transparency logs", 0.4, "crtsh_no_hits")]

    sorted_subs = sorted(subdomains)[:max_results]
    findings = [Finding(
        domain, "crtsh",
        f"found {len(subdomains)} subdomain(s) via certificate transparency (showing up to {max_results}): {', '.join(sorted_subs)}",
        0.6, "crtsh_subdomains",
    )]

    interesting_keywords = ["firebase", "s3", "storage", "admin", "staging", "dev", "test", "internal", "api", "db"]
    flagged = [s for s in sorted_subs if any(kw in s for kw in interesting_keywords)]
    if flagged:
        findings.append(Finding(
            domain, "crtsh",
            f"FLAG: subdomain name(s) suggest cloud/admin/internal infrastructure worth manual review: {', '.join(flagged)}",
            0.55, "crtsh_interesting_subdomains",
        ))

    return findings


def http_security_headers(domain: str) -> list[Finding]:
    try:
        resp = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
    except requests.RequestException:
        try:
            resp = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
        except requests.RequestException as e:
            return [Finding(domain, "http_headers", f"site unreachable: {e}", 0.0, "error")]

    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    present = [h for h in SECURITY_HEADERS if h in resp.headers]

    findings = [Finding(domain, "http_headers", f"security headers present: {', '.join(present) if present else 'none'}", 0.5, "headers_present")]
    if len(missing) >= 3:
        findings.append(Finding(
            domain, "http_headers",
            f"FLAG: {len(missing)}/5 standard security headers missing ({', '.join(missing)}) — inconsistent with a maintained production site",
            0.5, "headers_missing",
        ))
    return findings


def dns_full_fingerprint(domain: str) -> list[Finding]:
    findings = []
    for record_type in ["A", "AAAA", "NS", "CAA"]:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            values = sorted(str(r) for r in answers)
            findings.append(Finding(domain, "dns_fingerprint", f"{record_type} record(s): {', '.join(values)}", 0.55, f"dns_{record_type}"))
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            findings.append(Finding(domain, "dns_fingerprint", "domain does not exist (NXDOMAIN)", 0.7, "dns_nxdomain"))
            break
        except Exception:
            continue
    return findings


def robots_sitemap_check(domain: str) -> list[Finding]:
    findings = []
    try:
        resp = requests.get(f"https://{domain}/robots.txt", timeout=8)
        if resp.status_code == 200 and resp.text.strip():
            disallowed = [
                line.split(":", 1)[1].strip()
                for line in resp.text.splitlines()
                if line.lower().startswith("disallow:") and line.split(":", 1)[1].strip()
            ]
            if disallowed:
                findings.append(Finding(
                    domain, "robots_txt",
                    f"robots.txt lists {len(disallowed)} disallowed path(s), e.g.: {', '.join(disallowed[:5])}",
                    0.4, "robots_disallowed_paths",
                ))
    except requests.RequestException:
        pass

    try:
        resp = requests.get(f"https://{domain}/sitemap.xml", timeout=8)
        if resp.status_code == 200 and "<url" in resp.text.lower():
            url_count = resp.text.lower().count("<loc>")
            findings.append(Finding(domain, "sitemap_xml", f"sitemap.xml found, listing ~{url_count} URL(s)", 0.4, "sitemap_found"))
    except requests.RequestException:
        pass

    if not findings:
        findings.append(Finding(domain, "robots_sitemap", "no robots.txt/sitemap.xml found or neither contains notable content", 0.3, "robots_sitemap_empty"))
    return findings
