from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pii import PIIFinding, detect_pii
from .popia import build_compliance_summary


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _serialize_finding(finding: PIIFinding) -> dict[str, object]:
    return {
        "label": finding.label,
        "value_masked": _mask(finding.value),
        "start": finding.start,
        "end": finding.end,
        "confidence": finding.confidence,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ComplianceKit POPIA-aligned PII scanner.")
    parser.add_argument("--file", type=Path, help="Text file to scan. If omitted, stdin is used.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Skip detailed finding output and only print the compliance summary.",
    )
    args = parser.parse_args()

    if args.file:
        text = args.file.read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    findings = detect_pii(text)
    summary = build_compliance_summary(findings)
    payload = {
        "summary": summary,
        "findings": [] if args.summary_only else [_serialize_finding(item) for item in findings],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Total findings: {summary['total_findings']}")
    print(f"Risk level: {summary['risk_level']}")
    for label, count in summary["findings_by_type"].items():
        print(f"- {label}: {count}")
    if not args.summary_only and findings:
        print("\nFindings (masked):")
        for finding in payload["findings"]:
            print(
                f"- {finding['label']} @ {finding['start']}:{finding['end']} "
                f"({finding['value_masked']}, conf={finding['confidence']})"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

