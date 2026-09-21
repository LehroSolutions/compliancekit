from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from .pii import PIIFinding

POPIA_CONDITIONS: dict[str, str] = {
    "accountability": "Accountability",
    "processing_limitation": "Processing Limitation",
    "purpose_specification": "Purpose Specification",
    "further_processing_limitation": "Further Processing Limitation",
    "information_quality": "Information Quality",
    "openness": "Openness",
    "security_safeguards": "Security Safeguards",
    "data_subject_participation": "Data Subject Participation",
}

PII_TO_POPIA_CONDITION: dict[str, str] = {
    "sa_id_number": "security_safeguards",
    "sa_phone": "processing_limitation",
    "sa_company_registration": "openness",
    "email": "processing_limitation",
    "passport_number": "security_safeguards",
    "bank_account": "security_safeguards",
    "tax_number": "purpose_specification",
}


def _risk_level(total_findings: int) -> str:
    if total_findings >= 15:
        return "high"
    if total_findings >= 6:
        return "medium"
    return "low"


def build_compliance_summary(findings: Sequence[PIIFinding]) -> dict[str, object]:
    """Build a POPIA-aligned summary without exporting raw PII values."""
    by_label = Counter(finding.label for finding in findings)
    by_condition_keys = Counter(
        PII_TO_POPIA_CONDITION.get(finding.label, "accountability") for finding in findings
    )

    condition_breakdown = {
        POPIA_CONDITIONS[condition_key]: count
        for condition_key, count in sorted(by_condition_keys.items())
    }

    remediation = []
    if by_condition_keys.get("security_safeguards", 0):
        remediation.append("Encrypt storage and enforce strict access controls for sensitive identifiers.")
    if by_condition_keys.get("processing_limitation", 0):
        remediation.append("Validate consent and remove unnecessary personal data from processing flows.")
    if by_condition_keys.get("purpose_specification", 0):
        remediation.append("Document clear collection purpose and retention windows for tax-related records.")

    return {
        "total_findings": len(findings),
        "risk_level": _risk_level(len(findings)),
        "findings_by_type": dict(sorted(by_label.items())),
        "findings_by_popia_condition": condition_breakdown,
        "remediation_recommendations": remediation,
    }

