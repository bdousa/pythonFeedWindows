from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_license_policy.py"
SPEC = importlib.util.spec_from_file_location("check_license_policy", SCRIPT_PATH)
assert SPEC and SPEC.loader
license_precheck = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(license_precheck)


class LicensePrecheckTests(unittest.TestCase):
    def test_unapproved_license_writes_rejection_summary_before_scan(self):
        pypi = {
            "info": {
                "name": "restricted-package",
                "version": "1.0.0",
                "license_expression": "GPL-3.0",
                "classifiers": [],
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "packages.json"
            manifest.write_text('{"packages": {}}', encoding="utf-8")
            output_dir = root / "review_output"
            arguments = [
                "check_license_policy.py",
                "--package-name", "restricted-package",
                "--package-version", "latest",
                "--manifest-path", str(manifest),
                "--output-dir", str(output_dir),
            ]
            with patch.object(license_precheck, "fetch_pypi_metadata", return_value=pypi), patch.object(sys, "argv", arguments):
                self.assertEqual(0, license_precheck.main())

            decision = json.loads((output_dir / "approval-decision.json").read_text(encoding="utf-8"))
            summary = (output_dir / "approval-report.md").read_text(encoding="utf-8")

        self.assertEqual("auto_rejected", decision["state"])
        self.assertFalse(decision["manualApprovalRequired"])
        self.assertIn("not on the approved list", summary)
        self.assertIn("Snyk and AI Foundry reviews were skipped", summary)


if __name__ == "__main__":
    unittest.main()
