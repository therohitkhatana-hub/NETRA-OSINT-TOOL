"""
Cross-validation and confidence scoring for NETRA.
Boosts confidence when independent sources agree, and (in the two-identifier case)
checks whether phone and email findings corroborate.

Deliberately rule-based, not ML: explainable scoring matters more than raw accuracy
when the output might end up referenced in an investigation.
"""
from db import Finding


def cross_validate(findings: list[Finding]) -> list[Finding]:
    """Boost confidence for facts that multiple independent sources agree on,
    and boost overall risk when multiple independent flags stack up on one identifier."""
    fact_sources = {}
    for f in findings:
        fact_sources.setdefault(f.fact.lower(), []).append(f.source)

    for f in findings:
        sources_agreeing = fact_sources[f.fact.lower()]
        if len(set(sources_agreeing)) > 1:
            f.confidence = min(1.0, f.confidence + 0.15)

    flag_count = sum(1 for f in findings if "FLAG" in f.fact)
    if flag_count >= 3:
        identifier = findings[0].identifier if findings else "unknown"
        findings.append(Finding(
            identifier=identifier,
            source="cross_validation",
            fact=f"FLAG: {flag_count} independent risk indicators stacked on this single identifier — "
                 "individually weak signals, but their accumulation raises overall priority",
            confidence=0.55,
            raw_reference="derived_from_flag_count",
        ))

    return findings


def link_phone_and_email(phone_findings: list[Finding], email_findings: list[Finding]) -> list[Finding]:
    """
    If both a phone and an email were submitted for the same case, look for
    corroborating signals across the two (e.g. both flagged as high-risk).
    Returns extra 'linkage' findings, doesn't mutate the originals.
    """
    linkage = []
    phone_flagged = any("FLAG" in f.fact for f in phone_findings)
    email_flagged = any("FLAG" in f.fact for f in email_findings)

    if phone_flagged and email_flagged:
        linkage.append(Finding(
            identifier="linked_case",
            source="cross_validation",
            fact="Both submitted phone and email carry independent risk flags — "
                 "combined signal strengthens suspicion of coordinated fraud infrastructure",
            confidence=0.75,
            raw_reference="derived_from_both_modules",
        ))

    return linkage
