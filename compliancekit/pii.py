from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

SA_ID_NUMBER = re.compile(r"\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{4}[01]\d{2}\b")
SA_PHONE = re.compile(r"(?<!\d)(?:\+27|0)[1-8]\d{8}(?!\d)")
SA_COMPANY_REG = re.compile(r"\b\d{4}/\d{6}/\d{2}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PASSPORT = re.compile(r"\b[A-Z][0-9]{8}\b")
BANK_ACCOUNT = re.compile(r"\b\d{8,11}\b")
TAX_NUMBER = re.compile(r"\b\d{10}\b")


@dataclass(frozen=True)
class PIIFinding:
    label: str
    value: str
    start: int
    end: int
    confidence: float
    context: str


def _luhn_checksum(value: str) -> bool:
    digits = [int(ch) for ch in value]
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _window(text: str, start: int, end: int, size: int = 24) -> str:
    left = max(0, start - size)
    right = min(len(text), end + size)
    return text[left:right]


def _add_findings(
    text: str,
    pattern: re.Pattern[str],
    label: str,
    confidence: float,
    findings: list[PIIFinding],
    validator: Callable[[str], bool] | None = None,
) -> None:
    for match in pattern.finditer(text):
        value = match.group(0)
        if validator and not validator(value):
            continue
        findings.append(
            PIIFinding(
                label=label,
                value=value,
                start=match.start(),
                end=match.end(),
                confidence=confidence,
                context=_window(text, match.start(), match.end()),
            )
        )


def _with_context(findings: Iterable[PIIFinding], keyword_pattern: re.Pattern[str]) -> list[PIIFinding]:
    contextual: list[PIIFinding] = []
    for finding in findings:
        if keyword_pattern.search(finding.context.lower()):
            contextual.append(finding)
    return contextual


def detect_pii(text: str) -> list[PIIFinding]:
    """Detect South African-centric PII entities from free text."""
    findings: list[PIIFinding] = []

    _add_findings(text, SA_ID_NUMBER, "sa_id_number", 0.97, findings, validator=_luhn_checksum)
    _add_findings(text, SA_PHONE, "sa_phone", 0.95, findings)
    _add_findings(text, SA_COMPANY_REG, "sa_company_registration", 0.99, findings)
    _add_findings(text, EMAIL, "email", 0.98, findings)
    _add_findings(text, PASSPORT, "passport_number", 0.88, findings)

    bank_candidates: list[PIIFinding] = []
    _add_findings(text, BANK_ACCOUNT, "bank_account", 0.7, bank_candidates)
    findings.extend(_with_context(bank_candidates, re.compile(r"\b(bank|account|iban|branch)\b")))

    tax_candidates: list[PIIFinding] = []
    _add_findings(text, TAX_NUMBER, "tax_number", 0.75, tax_candidates)
    findings.extend(_with_context(tax_candidates, re.compile(r"\b(tax|sars|tin)\b")))

    # De-duplicate overlapping entries.
    dedup: dict[tuple[str, int, int], PIIFinding] = {}
    for finding in findings:
        dedup[(finding.label, finding.start, finding.end)] = finding
    return sorted(dedup.values(), key=lambda item: item.start)

