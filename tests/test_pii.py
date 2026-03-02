from __future__ import annotations

import unittest

from compliancekit.pii import detect_pii


class PIIDetectionTests(unittest.TestCase):
    def test_detects_core_south_african_patterns(self) -> None:
        text = "Client ID 8001015009087, phone +27821234567, email jane@example.co.za and SARS tax 1234567890."
        findings = detect_pii(text)
        labels = {item.label for item in findings}
        self.assertIn("sa_id_number", labels)
        self.assertIn("sa_phone", labels)
        self.assertIn("email", labels)
        self.assertIn("tax_number", labels)

    def test_bank_account_requires_context(self) -> None:
        plain_number_text = "Reference number 12345678 should not be treated as a bank account."
        contextual_text = "Please verify bank account 12345678 at branch level."
        plain_labels = {item.label for item in detect_pii(plain_number_text)}
        contextual_labels = {item.label for item in detect_pii(contextual_text)}
        self.assertNotIn("bank_account", plain_labels)
        self.assertIn("bank_account", contextual_labels)


if __name__ == "__main__":
    unittest.main()
