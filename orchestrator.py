"""
NETRA Orchestrator: the single entrypoint the CLI (and web API) calls.
Fans out to modules, saves raw findings, cross-validates, returns the scored set.
"""
from db import init_db, save_findings, Finding
from modules.phone_lookup import lookup_phone
from modules.email_lookup import lookup_email
from scoring import cross_validate, link_phone_and_email
from own_index import index_findings


def investigate(phone: str | None = None, email: str | None = None) -> dict:
    conn = init_db()
    result = {"phone_findings": [], "email_findings": [], "linkage_findings": []}

    if phone:
        phone_findings = cross_validate(lookup_phone(phone))
        save_findings(conn, phone_findings)
        result["phone_findings"] = phone_findings

    if email:
        email_findings = cross_validate(lookup_email(email))
        save_findings(conn, email_findings)
        result["email_findings"] = email_findings

    if phone and email:
        linkage = link_phone_and_email(result["phone_findings"], result["email_findings"])
        if linkage:
            save_findings(conn, linkage)
        result["linkage_findings"] = linkage

    conn.close()

    # Feed every finding from this case into the local search index, so it's
    # permanently free-text searchable across all past investigations.
    all_findings = result["phone_findings"] + result["email_findings"] + result["linkage_findings"]
    try:
        index_findings(all_findings)
    except Exception:
        pass  # indexing failure should never block the actual investigation

    return result
