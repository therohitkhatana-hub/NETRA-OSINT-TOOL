"""
Batch Firebase project investigation for NETRA — runs passive-only reconnaissance.
For each Firebase RTDB hostname given:
  1. Exposure status ONLY (shallow=true, key names/values never stored)
  2. Associated Firebase Hosting site check (<project-id>.web.app / .firebaseapp.com)
  3. GitHub code search for the hostname
  4. General web-mention search (DuckDuckGo) and Reddit search

Every finding is saved into database under the hostname as its "case".

Usage:
    python firebase_investigate.py rto-32-default-rtdb.firebaseio.com
"""
import sys
import re
import requests
from datetime import datetime

from db import Finding, init_db, save_findings, DB_PATH
from own_index import index_findings
from modules.public_records import github_commit_search, web_mention_search
from modules.own_crawler import reddit_search, github_code_search
from report import generate_pdf


def normalize_hostname(raw: str) -> str:
    """Strips https://, http://, query params, and trailing slashes to extract clean hostname."""
    cleaned = raw.strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.split("/")[0].split("?")[0].strip()
    if not cleaned.endswith(".firebaseio.com") and ".firebasedatabase.app" not in cleaned:
        if "." not in cleaned:
            # If user just passed a project ID, default to -default-rtdb.firebaseio.com
            cleaned = f"{cleaned}-default-rtdb.firebaseio.com"
    return cleaned


def extract_project_id(hostname: str) -> str:
    """Extract project ID from hostname."""
    m = re.match(r"^([a-zA-Z0-9_-]+?)(?:-default-rtdb)?\.(?:firebaseio\.com|firebasedatabase\.app)$", hostname, re.IGNORECASE)
    if m:
        return m.group(1)
    return hostname.split(".")[0]


def check_exposure_status(hostname: str) -> Finding:
    """Same shallow=true technique as firebase_exposure_check.py — status only,
    contents never extracted."""
    url = f"https://{hostname}/.json"
    try:
        resp = requests.get(url, params={"shallow": "true"}, timeout=10)
    except requests.RequestException as e:
        return Finding(hostname, "firebase_exposure", f"UNREACHABLE: {e}", 0.0, "connection_error")

    if resp.status_code == 200:
        try:
            data = resp.json()
            key_count = len(data) if isinstance(data, dict) else 0
            return Finding(
                hostname, "firebase_exposure",
                f"FLAG: OPEN — database is publicly readable ({key_count} top-level key(s) present, "
                "names/values deliberately not stored). Report through official channel, do not query further.",
                0.9, "firebase_open",
            )
        except ValueError:
            return Finding(hostname, "firebase_exposure", "FLAG: OPEN — HTTP 200 but non-JSON response (still worth reporting)", 0.7, "firebase_open_nonjson")
    elif resp.status_code in (401, 403):
        return Finding(hostname, "firebase_exposure", "SECURED — access denied by security rules", 0.6, "firebase_secured")
    else:
        return Finding(hostname, "firebase_exposure", f"INCONCLUSIVE — unexpected status {resp.status_code}", 0.2, "firebase_inconclusive")


def check_hosting_site(hostname: str) -> list[Finding]:
    """Passive existence + <title> check for the project's associated public
    website, if any. Firebase project ID = prefix before -default-rtdb / .firebaseio.com."""
    project_id = extract_project_id(hostname)
    if not project_id:
        return []

    findings = []
    for domain_suffix in ["web.app", "firebaseapp.com"]:
        site_url = f"https://{project_id}.{domain_suffix}"
        try:
            resp = requests.get(site_url, timeout=8)
            if resp.status_code == 200:
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else "(no title found)"
                findings.append(Finding(
                    hostname, "firebase_hosting",
                    f"associated public site found: {site_url} — page title: '{title}'",
                    0.6, site_url,
                ))
        except requests.RequestException:
            continue

    if not findings:
        findings.append(Finding(hostname, "firebase_hosting", "no associated public web.app/firebaseapp.com site found", 0.3, "hosting_no_hits"))
    return findings


def investigate_firebase_project(hostname: str) -> list[Finding]:
    hostname = normalize_hostname(hostname)
    findings = [check_exposure_status(hostname)]
    findings.extend(check_hosting_site(hostname))
    findings.extend(github_code_search(hostname))
    findings.extend(web_mention_search(hostname))
    findings.extend(reddit_search(hostname))
    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python firebase_investigate.py <hostname1> [hostname2] ...")
        print("Example: python firebase_investigate.py rto-32-default-rtdb.firebaseio.com")
        sys.exit(1)

    raw_hostnames = sys.argv[1:]
    conn = init_db()

    for raw in raw_hostnames:
        hostname = normalize_hostname(raw)
        print(f"\n{'=' * 60}")
        print(f"Investigating: {hostname}")
        print("=" * 60)

        findings = investigate_firebase_project(hostname)
        save_findings(conn, findings)
        try:
            index_findings(findings)
        except Exception:
            pass

        for f in sorted(findings, key=lambda x: -x.confidence):
            tier = "HIGH" if f.confidence >= 0.75 else "MED" if f.confidence >= 0.5 else "LOW"
            print(f"  [{tier} conf={f.confidence:.2f}] ({f.source}) {f.fact}")

        pdf_result = {"phone_findings": [], "email_findings": findings, "linkage_findings": []}
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", hostname)
        pdf_path = generate_pdf(pdf_result, phone=None, email=hostname, output_path=f"firebase_case_{safe_name}.pdf")
        print(f"  Report saved: {pdf_path}")

    conn.close()
    print(f"\n{'=' * 60}")
    print(f"Investigated {len(raw_hostnames)} project(s). All findings saved to database.")
    print("Run 'python case_graph.py' to check for cross-project correlations.")
    print("Run 'python search_cases.py \"phrase\"' to search across all of this and past cases.")


if __name__ == "__main__":
    main()
