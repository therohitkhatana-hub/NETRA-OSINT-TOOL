"""
Email module for NETRA — FREE, keyless baseline intelligence.
  - breach data (XposedOrNot), domain forensics (WHOIS/SPF/DMARC/MX)
  - identity corroboration (Gravatar, own account-presence checker, GitHub, emailrep.io)
  - own scoped crawler (Reddit, GitHub code search, Common Crawl)
  - threat-intel blocklists (URLhaus, Spamhaus DBL)
  - domain recon (Shodan InternetDB, crt.sh subdomains, HTTP headers, DNS fingerprint, robots/sitemap)
"""
import os
import socket
import hashlib
import requests
import dns.resolver
import whois
from datetime import datetime, timezone
from db import Finding
from modules.account_presence import check_account_presence
from modules.public_records import github_commit_search, wayback_history, web_mention_search, emailrep_lookup
from modules.own_crawler import reddit_search, github_code_search, commoncrawl_domain_history
from modules.threat_intel import urlhaus_check, spamhaus_dbl_check
from modules.recon import shodan_internetdb, crtsh_subdomains, http_security_headers, dns_full_fingerprint, robots_sitemap_check
from modules.firebase_pentest import firebase_recon

XON_URL = "https://api.xposedornot.com/v1/breach-analytics"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
GRAVATAR_URL = "https://www.gravatar.com/avatar/{}?d=404"

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "tempmail.com", "throwawaymail.com", "yopmail.com",
}

MAJOR_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "aol.com", "live.com", "rediffmail.com", "yahoo.co.in",
}

ROLE_PREFIXES = {"info", "admin", "support", "noreply", "no-reply", "contact", "sales", "help", "hello"}


def lookup_email(identifier: str) -> list[Finding]:
    findings = []
    findings.extend(_check_xposedornot(identifier))
    findings.extend(_check_domain_dns(identifier))
    findings.extend(_check_gravatar(identifier))
    findings.extend(_check_role_account(identifier))
    findings.extend(check_account_presence(identifier))
    findings.extend(github_commit_search(identifier))
    findings.extend(web_mention_search(identifier))
    findings.extend(emailrep_lookup(identifier))
    findings.extend(reddit_search(identifier))
    findings.extend(github_code_search(identifier))

    if "@" in identifier:
        domain = identifier.split("@", 1)[1].lower()
        if domain not in MAJOR_PROVIDERS:
            findings.extend(_check_whois(domain))
            findings.extend(_check_spf_dmarc(domain))
            findings.extend(wayback_history(domain))
            findings.extend(commoncrawl_domain_history(domain))
            findings.extend(urlhaus_check(domain))
            findings.extend(spamhaus_dbl_check(domain))
            findings.extend(shodan_internetdb(domain))
            findings.extend(crtsh_subdomains(domain))
            findings.extend(http_security_headers(domain))
            findings.extend(dns_full_fingerprint(domain))
            findings.extend(robots_sitemap_check(domain))
            findings.extend(firebase_recon(identifier))

    if os.getenv("HIBP_API_KEY"):
        findings.extend(_check_hibp(identifier))

    return findings


def _check_xposedornot(identifier: str) -> list[Finding]:
    try:
        resp = requests.get(XON_URL, params={"email": identifier}, timeout=10)
        if resp.status_code == 404:
            return [Finding(identifier, "xposedornot", "no known breaches found", 0.7, "xon_404")]
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(identifier, "xposedornot", f"lookup failed: {e}", 0.0, "error")]

    exposed = (data.get("ExposedBreaches") or {}).get("breaches_details", [])
    if not exposed:
        summary = (data.get("BreachesSummary") or {}).get("site", "")
        if not summary:
            return [Finding(identifier, "xposedornot", "no known breaches found", 0.7, "xon_empty")]
        return [Finding(identifier, "xposedornot", f"found in breach(es): {summary}", 0.75, "xon_summary_only")]

    findings = []
    for b in exposed:
        name = b.get("breach", "unknown")
        date = b.get("xposed_date", "unknown date")
        industry = b.get("industry", "unknown industry")
        risk = b.get("password_risk", "unknown")
        exposed_data = b.get("xposed_data", "")
        findings.append(Finding(
            identifier, "xposedornot",
            f"breach '{name}' ({date}, {industry}) — password risk: {risk} — exposed fields: {exposed_data}",
            0.8, f"xon:{name}",
        ))
    return findings


def _check_whois(domain: str) -> list[Finding]:
    """Free, no key — direct WHOIS protocol query."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return [Finding(domain, "whois", "domain registration date unavailable (registrar may be withholding it)", 0.3, "whois_no_date")]

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days

        findings = [Finding(domain, "whois", f"domain registered: {creation.date()} ({age_days} days ago), registrar: {w.registrar or 'unknown'}", 0.75, "whois_creation")]

        if age_days < 90:
            findings.append(Finding(
                domain, "whois",
                f"FLAG: domain is only {age_days} days old — newly-registered domains are disproportionately used in scam/phishing infrastructure",
                0.65, "whois_age_flag",
            ))
        return findings
    except Exception as e:
        return [Finding(domain, "whois", f"WHOIS lookup failed: {e}", 0.0, "error")]


def _check_spf_dmarc(domain: str) -> list[Finding]:
    """Free — pure DNS TXT record lookups."""
    findings = []

    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        spf_found = any("v=spf1" in str(r).lower() for r in answers)
    except Exception:
        spf_found = False
    findings.append(Finding(
        domain, "dns_spf",
        f"SPF record: {'present' if spf_found else 'MISSING'}",
        0.6 if spf_found else 0.55, "spf_check",
    ))
    if not spf_found:
        findings.append(Finding(domain, "dns_spf", "FLAG: no SPF record — mail-sending infrastructure not properly configured, common in scam domains", 0.45, "spf_flag"))

    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        dmarc_found = any("v=dmarc1" in str(r).lower() for r in dmarc_answers)
    except Exception:
        dmarc_found = False
    findings.append(Finding(
        domain, "dns_dmarc",
        f"DMARC record: {'present' if dmarc_found else 'MISSING'}",
        0.6 if dmarc_found else 0.55, "dmarc_check",
    ))
    if not dmarc_found:
        findings.append(Finding(domain, "dns_dmarc", "FLAG: no DMARC record — domain vulnerable to spoofing / not maintained to business standard", 0.45, "dmarc_flag"))

    return findings


def _check_gravatar(identifier: str) -> list[Finding]:
    if "@" not in identifier:
        return []
    email_hash = hashlib.md5(identifier.strip().lower().encode()).hexdigest()
    try:
        resp = requests.get(GRAVATAR_URL.format(email_hash), timeout=8)
        if resp.status_code == 200:
            return [Finding(identifier, "gravatar", "email has an associated Gravatar profile image — linked to a real, maintained online identity", 0.55, "gravatar_hit")]
        if resp.status_code == 404:
            return [Finding(identifier, "gravatar", "no Gravatar profile associated with this email", 0.4, "gravatar_miss")]
        return [Finding(identifier, "gravatar", f"lookup inconclusive (HTTP {resp.status_code})", 0.0, "gravatar_inconclusive")]
    except requests.RequestException as e:
        return [Finding(identifier, "gravatar", f"lookup failed: {e}", 0.0, "error")]


def _check_role_account(identifier: str) -> list[Finding]:
    if "@" not in identifier:
        return []
    local_part = identifier.split("@", 1)[0].lower()
    if local_part in ROLE_PREFIXES:
        return [Finding(identifier, "role_account_check", f"'{local_part}@' is a generic role account, not tied to a specific individual — deprioritize for personal-identity correlation", 0.5, "role_check")]
    return []


def _check_hibp(identifier: str) -> list[Finding]:
    api_key = os.getenv("HIBP_API_KEY")
    try:
        resp = requests.get(
            HIBP_URL.format(identifier),
            headers={"hibp-api-key": api_key, "user-agent": "netra-osint-tool/1.0"},
            timeout=10,
        )
        if resp.status_code == 404:
            return [Finding(identifier, "hibp", "no known breaches found (HIBP)", 0.7, "hibp_404")]
        resp.raise_for_status()
        breaches = resp.json()
    except requests.RequestException as e:
        return [Finding(identifier, "hibp", f"lookup failed: {e}", 0.0, "error")]

    return [
        Finding(identifier, "hibp", f"found in breach: {b.get('Name')} ({b.get('BreachDate')})", 0.85, f"hibp:{b.get('Name')}")
        for b in breaches
    ]


def _check_domain_dns(identifier: str) -> list[Finding]:
    if "@" not in identifier:
        return [Finding(identifier, "domain_check", "malformed email — no @ found", 0.9, "format_check")]

    domain = identifier.split("@", 1)[1].lower()
    findings = []

    if domain in DISPOSABLE_DOMAINS:
        findings.append(Finding(identifier, "domain_check", f"FLAG: {domain} is a known disposable/throwaway email provider", 0.7, "disposable_list"))

    try:
        mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_hosts = sorted(str(r.exchange).rstrip(".") for r in mx_records)
        findings.append(Finding(identifier, "domain_check", f"MX records: {', '.join(mx_hosts)}", 0.65, "mx_check"))
    except Exception:
        findings.append(Finding(identifier, "domain_check", f"domain {domain} has no MX records — cannot receive mail, likely invalid/fake", 0.7, "mx_check_fail"))

    return findings
