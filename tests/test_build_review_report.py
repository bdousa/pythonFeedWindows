from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_review_report.py"
SPEC = importlib.util.spec_from_file_location("build_review_report", SCRIPT_PATH)
assert SPEC and SPEC.loader
review_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review_report)


class LicensePolicyTests(unittest.TestCase):
    def test_known_policy_license_is_approved(self):
        license_type = review_report.canonical_license_type("", "MIT License", [])

        policy = review_report.evaluate_license_policy(license_type)

        self.assertEqual("MIT", policy["type"])
        self.assertTrue(policy["approved"])
        self.assertEqual("approved", policy["status"])

    def test_unknown_license_is_automatically_rejected_even_when_duplicate(self):
        policy = review_report.evaluate_license_policy("GPL-3.0")
        statuses = {
            "dependencies": {"status": "passed"},
            "monitor": {"status": "passed"},
            "code": {"status": "passed"},
        }
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        state, reasons = review_report.build_recommendation(
            counts, counts, 1, policy, "pass", statuses, duplicate=True
        )

        self.assertEqual("auto_rejected", state)
        self.assertIn("not on the approved list", reasons[0])
        self.assertIn("already present", reasons[1])

    def test_approved_duplicate_is_reported_as_duplicate(self):
        policy = review_report.evaluate_license_policy("MIT")
        statuses = {
            "dependencies": {"status": "passed"},
            "monitor": {"status": "passed"},
            "code": {"status": "passed"},
        }
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        state, _ = review_report.build_recommendation(
            counts, counts, 1, policy, "pass", statuses, duplicate=True
        )

        self.assertEqual("duplicate", state)


if __name__ == "__main__":
    unittest.main()
