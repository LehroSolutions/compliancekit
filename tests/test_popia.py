from __future__ import annotations

import unittest

from compliancekit.pii import PIIFinding
from compliancekit.popia import build_compliance_summary


class PopiaSummaryTests(unittest.TestCase):
    def test_summary_shape_and_counts(self) -> None:
        findings = [
            PIIFinding("email", "jane@example.co.za", 0, 20, 0.98, "email context"),
            PIIFinding("bank_account", "12345678", 21, 29, 0.7, "bank account context"),
            PIIFinding("sa_id_number", "8001015009087", 30, 43, 0.97, "id context"),
        ]
        summary = build_compliance_summary(findings)
        self.assertEqual(summary["total_findings"], 3)
        self.assertEqual(summary["risk_level"], "low")
        self.assertEqual(summary["findings_by_type"]["email"], 1)
        self.assertIn("Security Safeguards", summary["findings_by_popia_condition"])
        self.assertGreaterEqual(len(summary["remediation_recommendations"]), 1)


if __name__ == "__main__":
    unittest.main()
