"""
Phone number module for NETRA — FREE, offline, no API key or internet required.
Pulls metadata from the `phonenumbers` library and runs heuristic fraud-pattern detection.
"""
import os
import re
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone
from db import Finding
from modules.public_records import web_mention_search
from modules.own_crawler import reddit_search

NUMVERIFY_URL = "http://apilayer.net/api/validate"

NUMBER_TYPE_MAP = {
    0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE",
    3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
    6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER", 9: "UAN", 10: "VOICEMAIL",
    27: "UNKNOWN",
}


def lookup_phone(identifier: str) -> list[Finding]:
    findings = _offline_lookup(identifier)
    findings.extend(web_mention_search(identifier))
    findings.extend(reddit_search(identifier))
    if os.getenv("NUMVERIFY_API_KEY"):
        findings.extend(_numverify_enrichment(identifier))
    return findings


def _offline_lookup(identifier: str) -> list[Finding]:
    try:
        parsed = phonenumbers.parse(identifier, None)
    except phonenumbers.NumberParseException as e:
        return [Finding(
            identifier, "phonenumbers (offline)",
            f"could not parse number — include country code, e.g. +91XXXXXXXXXX ({e})",
            0.3, "parse_error",
        )]

    findings = []
    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)

    findings.append(Finding(
        identifier, "phonenumbers (offline)",
        f"validity: {'VALID' if is_valid else 'possible but not confirmed valid' if is_possible else 'INVALID'}",
        0.85 if is_valid else 0.5 if is_possible else 0.3, "libphonenumber_validation",
    ))

    if not is_possible:
        return findings

    # --- Formatted variants ---
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    findings.append(Finding(identifier, "phonenumbers (offline)", f"E164 canonical form: {e164}", 0.8, "format"))
    findings.append(Finding(identifier, "phonenumbers (offline)", f"national format: {national}", 0.6, "format"))

    # --- Region / geocoding ---
    region = geocoder.description_for_number(parsed, "en")
    country_code = phonenumbers.region_code_for_number(parsed)
    if region:
        findings.append(Finding(identifier, "phonenumbers (offline)", f"region/circle: {region} (country: {country_code})", 0.75, "geocoder"))

    # --- Carrier ---
    carrier_name = carrier.name_for_number(parsed, "en")
    if carrier_name:
        findings.append(Finding(
            identifier, "phonenumbers (offline)",
            f"originally allocated to carrier: {carrier_name} (note: Mobile Number Portability may mean current carrier differs)",
            0.65, "carrier",
        ))
    else:
        findings.append(Finding(identifier, "phonenumbers (offline)", "carrier: unknown/unpublished for this range", 0.4, "carrier"))

    # --- Timezone ---
    zones = pn_timezone.time_zones_for_number(parsed)
    if zones:
        findings.append(Finding(identifier, "phonenumbers (offline)", f"timezone(s): {', '.join(zones)}", 0.6, "timezone"))

    # --- Line type + VOIP flag ---
    num_type = phonenumbers.number_type(parsed)
    type_str = NUMBER_TYPE_MAP.get(num_type, "UNKNOWN")
    findings.append(Finding(identifier, "phonenumbers (offline)", f"line type: {type_str}", 0.7, "type"))
    if type_str in ("VOIP", "PERSONAL_NUMBER", "PAGER"):
        findings.append(Finding(
            identifier, "phonenumbers (offline)",
            f"FLAG: {type_str} line type — commonly used in scam operations to avoid traceability",
            0.6, "type_flag",
        ))

    # --- Heuristic: sequential / repeated digit patterns ---
    findings.extend(_pattern_heuristics(identifier, national))

    return findings


def _pattern_heuristics(identifier: str, national_format: str) -> list[Finding]:
    digits = re.sub(r"\D", "", national_format)
    findings = []

    # Repeated single digit run of 4+ (e.g. "9999" inside the number)
    if re.search(r"(\d)\1{3,}", digits):
        findings.append(Finding(
            identifier, "pattern_heuristics",
            "FLAG: number contains a run of 4+ repeated digits — mildly associated with easily-memorable burner numbers",
            0.35, "digit_pattern",
        ))

    # Ascending or descending sequential run of 4+ (e.g. "1234", "6543")
    seq_asc = "0123456789"
    seq_desc = "9876543210"
    for i in range(len(digits) - 3):
        chunk = digits[i:i+4]
        if chunk in seq_asc or chunk in seq_desc:
            findings.append(Finding(
                identifier, "pattern_heuristics",
                f"FLAG: number contains a sequential digit run ('{chunk}') — mildly associated with easily-memorable burner numbers",
                0.35, "digit_pattern",
            ))
            break

    return findings


def _numverify_enrichment(identifier: str) -> list[Finding]:
    api_key = os.getenv("NUMVERIFY_API_KEY")
    try:
        resp = requests.get(NUMVERIFY_URL, params={"access_key": api_key, "number": identifier}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [Finding(identifier, "numverify", f"enrichment lookup failed: {e}", 0.0, "error")]

    if not data.get("valid"):
        return []

    return [Finding(
        identifier, "numverify",
        f"live carrier confirmation: {data.get('carrier', 'unknown')} ({data.get('line_type', 'unknown')})",
        0.85, str(data),
    )]
