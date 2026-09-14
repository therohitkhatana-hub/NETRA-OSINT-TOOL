<div align="center">

```
    _   ________________  ___ 
   / | / / ____/_  __/ __ \/   |
  /  |/ / __/   / / / /_/ / /| |
 / /|  / /___  / / / _, _/ ___ |
/_/ |_/_____/ /_/ /_/ |_/_/  |_|
```

# NETRA (नेत्र) — Cyber Crime OSINT & Intelligence System
### Automated Open-Source Intelligence Framework for Law Enforcement & Security Analysts

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Status: Complete](https://img.shields.io/badge/status-production--ready-brightgreen.svg?style=for-the-badge)](https://github.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-purple.svg?style=for-the-badge)](LICENSE)
[![Zero Keys Required](https://img.shields.io/badge/API%20Keys-Zero%20Required-success.svg?style=for-the-badge)](README.md)
[![Jaipur Police Cyber Crime Dept](https://img.shields.io/badge/Cybersecurity%20Project-Jaipur%20Police%20Cyber%20Crime-orange.svg?style=for-the-badge)](README.md)

<p align="center">
  <b>Developed by Rohit Khatana</b><br>
  <i>Cybersecurity Internship Project | Jaipur Police Cyber Crime Dept</i>
</p>

---

[Key Features](#-key-features) •
[Architecture](#-system-architecture) •
[Quick Start](#-quick-start) •
[Interactive Launcher](#-interactive-launcher) •
[CLI Usage](#-command-line-usage) •
[Intelligence Modules](#-intelligence-modules-breakdown) •
[Cross-Case Correlation](#-cross-case-correlation--graph) •
[Legal & Ethics](#-legal-ethics--responsible-osint-policy) •
[Project Structure](#-project-structure)

---

</div>

## 📌 Overview

**NETRA (नेत्र — "The Eye")** is an automated, forensic-grade OSINT orchestration framework designed for investigating phone numbers, email addresses, domain names, and cloud infrastructure.

Built from the ground up for real-world cyber crime investigations, NETRA avoids black-box libraries, paid breach marketplaces, and invasive non-consensual trackers. Instead, it queries legitimate, keyless, public primary sources, correlates findings across multiple cases, calculates explainable confidence scores, and produces investigator-ready PDF dossiers complete with visual risk gauges and full chain-of-evidence source citations.

---

## ⚡ Key Features

- **100% Free & Zero-Key Baseline**: The entire core pipeline functions without paid subscriptions, API keys, or accounts.
- **Zero Third-Party OSINT Wrapper Dependencies**: Account presence checking, primary-source crawling, and domain fingerprinting are built as native, inspectable implementations rather than wrappers over third-party CLI tools.
- **Explainable Confidence Scoring**: Rule-based scoring heuristics rather than opaque black-box machine learning models — critical when presenting evidence in judicial or law enforcement proceedings.
- **Forensic Chain-of-Custody Citations**: Every single finding carries an exact `source` and `raw_reference` tag, logging where the signal originated.
- **Cross-Case Correlation & Graph Visualizer**: Automatically cross-references identifiers across multiple past cases to identify shared telecom carriers, geographic circles, email servers, and platform handles.
- **Local Whoosh Full-Text Index**: Pure-Python, serverless search engine allowing investigators to query free-text across years of historical findings.
- **Passive Cloud Reconnaissance (Firebase)**: Responsible `shallow=true` configuration discovery that proves exposure without extracting or storing private database records.
- **Court-Ready PDF Reports**: Automated ReportLab PDF generation featuring executive summaries, visual risk score dials, categorized tables, and full citation appendices.

---

## 🏛 System Architecture

```
                    ┌─────────────────────────────────────────┐
                    │      INVESTIGATOR INPUT TARGET          │
                    │   (Phone Number / Email / Firebase)     │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │           NETRA ORCHESTRATOR            │
                    │            (orchestrator.py)            │
                    └──────┬─────────────┬─────────────┬──────┘
                           │             │             │
              ┌────────────┘             │             └────────────┐
              ▼                          ▼                          ▼
     ┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
     │ PHONE PIPELINE  │       │ EMAIL PIPELINE  │       │ FIREBASE RECON   │
     ├─────────────────┤       ├─────────────────┤       ├──────────────────┤
     │ • phonenumbers  │       │ • XposedOrNot   │       │ • Shallow check  │
     │ • Fraud Pattern │       │ • DNS/SPF/DMARC │       │ • Hosting title  │
     │ • Web Mentions  │       │ • WHOIS age     │       │ • GitHub search  │
     │ • Carrier/Geo   │       │ • Account Check │       │ • Web/Reddit OSINT│
     └────────┬────────┘       │ • Gravatar/Rep  │       └────────┬─────────┘
              │                └────────┬────────┘                │
              └────────────┐            │            ┌────────────┘
                           ▼            ▼            ▼
                    ┌─────────────────────────────────────────┐
                    │     CROSS-VALIDATION & SCORING          │
                    │        (Rule-Based Engine)              │
                    └────────────────────┬────────────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
      │   SQLITE STORAGE   │  │ LOCAL SEARCH INDEX │  │    PDF DOSSIER     │
      │    (netra.db)      │  │     (Whoosh)       │  │ (netra_report.pdf) │
      └──────────┬─────────┘  └────────────────────┘  └────────────────────┘
                 │
                 ▼
      ┌────────────────────┐
      │  CRIMEGRAPH ENGINE │
      │  (Cross-Case Link) │
      └────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.10+** installed on your system.
- Graphviz (Optional, needed only for rendering `.png` correlation network diagrams).

### 1-Click Launch (Windows)
Double-click the included batch launcher:
```cmd
Run Netra.bat
```
> *The script automatically creates an isolated virtual environment (`venv`), installs all required dependencies quietly, and launches the animated terminal interface.*

---

### Manual Setup (Linux / macOS / Windows)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/NETRA.git
   cd NETRA
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\activate

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the interactive interface**:
   ```bash
   python launch.py
   ```

---

## 💻 Interactive Launcher

Run `python launch.py` for a guided, terminal-based visual interface featuring real-time spinner feedback and formatted tables:

```
    _   ________________  ___ 
   / | / / ____/_  __/ __ \/   |
  /  |/ / __/   / / / /_/ / /| |
 / /|  / /___  / / / _, _/ ___ |
/_/ |_/_____/ /_/ /_/ |_/_/  |_|

NETRA - Cyber Crime OSINT & Intelligence System
Jaipur Police Cyber Crime Dept | Rohit Khatana

[1] Standard Target Investigation (Phone & Email)
[2] Passive Firebase Project Reconnaissance (Responsible OSINT)

Select mode [1]: 1
Phone number (e.g. +919876543210): +919876543210
Email address: suspect@example.com
```

---

## ⌨️ Command Line Usage

NETRA includes scriptable command-line utilities for batch jobs, shell scripts, and headless automation:

### 1. Direct Target Investigation (`main.py`)
```bash
# Investigate a phone number
python main.py --phone "+919876543210"

# Investigate an email address
python main.py --email "target@domain.com"

# Investigate both simultaneously with custom PDF output
python main.py --phone "+919876543210" --email "target@domain.com" --out case_042.pdf

# Console output only (skip PDF generation)
python main.py --phone "+919876543210" --no-pdf
```

### 2. Historical Cross-Case Search (`search_cases.py`)
Search across every finding ever recorded in your investigation history:
```bash
python search_cases.py "State Bank support"
python search_cases.py "VOIP"
```

### 3. Cross-Case Correlation Network (`case_graph.py`)
Analyze links between separate investigation files and generate a network graph:
```bash
python case_graph.py
```
> *Outputs `case_graph.png` showing visual connection nodes for matching carriers, geographic regions, and platform handles.*

### 4. Passive Firebase Project Investigation (`firebase_investigate.py`)
```bash
python firebase_investigate.py target-project-default-rtdb.firebaseio.com
```

### 5. Quick RTDB Status Probe (`firebase_exposure_check.py`)
```bash
python firebase_exposure_check.py target-project-default-rtdb.firebaseio.com
```

---

## 🔍 Intelligence Modules Breakdown

### 📱 Phone Intelligence (`modules/phone_lookup.py`)
- **Offline Analysis**: Uses Google's `phonenumbers` engine to resolve telecom circle, state/country, original carrier allocation, timezone, and international formats (E.164, National).
- **Line Type Classification**: Flags `VOIP`, `PREMIUM_RATE`, and `PAGER` numbers often used in boiler-room scams.
- **Pattern Heuristics**: Custom algorithms detect artificial digit patterns (repeated digits `9999`, sequential runs `1234`) characteristic of bulk burner SIMs.
- **Public Footprint**: Scrapes unverified public mentions via DuckDuckGo and Reddit.

### ✉️ Email Intelligence (`modules/email_lookup.py`)
- **Breach Auditing**: Queries XposedOrNot for breach history, exposure dates, leaked data classes, and password risk ratings.
- **DNS Forensics**: Audits MX records, SPF records, and DMARC spoof-protection policies.
- **Domain Age Calculation**: Direct WHOIS queries flag domains registered less than 90 days ago.
- **Role Account Flagging**: Detects generic mailboxes (`admin@`, `support@`, `info@`).
- **Identity Corroboration**: Checks Gravatar identity avatars, GitHub commit-author emails, and Wayback Machine archives.

### 👤 Account Presence Scanner (`modules/account_presence.py`)
Native implementation verifying email registration status across platforms without accessing credentials:
- **GitHub**: Evaluates CSRF authenticity tokens via signup verification endpoint.
- **Spotify**: Analyzes status responses from registration validation endpoints.
- **Imgur**: Direct AJAX validation inspection.
- **Adobe**: Inspects challenge progression in authentication state flows.
- **Instagram**: Decodes client registration attempt responses.

### 🌐 Scoped Crawler (`modules/own_crawler.py`)
Primary-source querying without external aggregator APIs:
- **Reddit Search**: Surfaces public complaints, fraud reports, and user threads mentioning the target.
- **GitHub Code Search**: Identifies leaked tokens, configuration files, and source code referencing the identifier.
- **Common Crawl**: Queries open CDX indices for historical domain presence.

### 🛡️ Threat Intelligence & Domain Recon (`modules/threat_intel.py` & `recon.py`)
- **URLhaus**: Real-time checking against abuse.ch malicious URL blocklists.
- **Spamhaus DBL**: DNS-based verification against domain blocklists.
- **Shodan InternetDB**: Passive inspection of open ports, services, and CVE vulnerabilities.
- **crt.sh Certificate Transparency**: Identifies subdomains (`admin.`, `dev.`, `firebase.`, `api.`).
- **HTTP Security Audit**: Evaluates HSTS, CSP, and X-Frame-Options headers.

---

## 📊 Cross-Case Correlation & Graph

Unlike simple lookup tools, NETRA stores every finding in SQLite (`netra.db`). The correlation engine searches for shared entities across distinct investigation targets:

| Shared Signal | Description | Investigative Significance |
|---|---|---|
| `carrier` | Shared telecom provider | Corroborates syndicated burner purchases in the same telecom circle |
| `region` | Geographic circle | Localizes syndicate operating region |
| `platform_account` | Same platform registration | Links burner phone and fake email to common identities |
| `domain_via_mx` | Same mail server domain | Discovers shared phishing mail infrastructure |

---

## 📄 PDF Investigation Dossier

NETRA produces standardized PDF reports ready for chain-of-custody documentation:

1. **Executive Summary**: Overview of target identifiers, total finding count, and high/medium/low confidence tiers.
2. **Visual Risk Gauge**: 0–100 scale computed from accumulated severity flags.
3. **Structured Findings**: Grouped by Phone, Email, and Cross-Linkage findings.
4. **Source Citation Appendix**: Complete audit table listing every piece of raw data, timestamp, and source reference.

---

## ⚙️ Configuration & Optional API Keys

NETRA works **100% out of the box with zero keys**. Optional enrichment keys can be added to `.env`:

```env
# Optional: Live carrier/VOIP verification
NUMVERIFY_API_KEY=

# Optional: Secondary breach intelligence
HIBP_API_KEY=

# Optional: Higher rate limits on reputation lookups
EMAILREP_API_KEY=

# Optional (Recommended): Raises GitHub code search limit from 10 to 30 req/min
GITHUB_TOKEN=
```

---

## ⚖️ Legal, Ethics & Responsible OSINT Policy

NETRA was built in adherence to strict ethical and legal boundaries:
- **No Breach Marketplace Access**: Does not query paid credential dumps (DeHashed, Snusbase).
- **No Non-Consensual Trackers**: Excludes covert IP loggers, Grabify links, and silent geolocation beacons.
- **No Account Takeover Probing**: Does not weaponize password recovery flows to extract masked personal hints.
- **No Active Exploitation**: The Firebase reconnaissance module checks `shallow=true` configuration status only; it strictly does not dump, iterate, or store private database records.

---

## 📁 Project Structure

```
NETRA/
├── Run Netra.bat              # 1-click Windows launcher
├── launch.py                  # Interactive animated terminal interface
├── main.py                    # Scriptable CLI runner
├── orchestrator.py            # Investigation coordinator
├── db.py                      # Storage layer (netra.db) & Finding model
├── scoring.py                 # Cross-validation & confidence heuristics
├── report.py                  # ReportLab PDF dossier generation
├── risk_gauge.py              # Matplotlib visual risk score dial
├── case_correlation.py        # Cross-case correlation detection
├── case_graph.py              # Visual case network graph generator
├── own_index.py               # Whoosh full-text search indexer
├── search_cases.py            # CLI cross-case search tool
├── firebase_investigate.py    # Passive Firebase project OSINT
├── firebase_exposure_check.py # Shallow RTDB exposure check
├── requirements.txt           # Python package dependencies
├── .env.example               # Configuration template
├── README.md                  # Complete project documentation
└── modules/                   # 10 core intelligence modules
    ├── __init__.py
    ├── account_presence.py    # Native 5-platform username detection
    ├── email_lookup.py        # Email breach, MX, WHOIS, SPF/DMARC
    ├── firebase_pentest.py    # Authorized Firebase probing
    ├── manual_leads.py        # Actionable investigator tips
    ├── own_crawler.py         # Primary-source web crawler
    ├── phone_lookup.py        # Offline phone analysis & fraud heuristics
    ├── public_records.py      # Public search & GitHub commits
    ├── recon.py               # Shodan InternetDB & crt.sh subdomains
    └── threat_intel.py        # URLhaus & Spamhaus DBL threat feeds
```

---

## 👨‍💻 Author & Acknowledgements

- **Rohit Khatana** — Developer & Security Researcher
- **Jaipur Police Cyber Crime Dept** — Cybersecurity Internship

---

<div align="center">
  <sub>NETRA is an open-source cybersecurity research and investigative aid. Use responsibly and in accordance with local legal frameworks.</sub>
</div>
