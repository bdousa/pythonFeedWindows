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
    def test_servicenow_declared_license_overrides_missing_pypi_license(self):
        pypi = {
            "info": {
                "name": "azure-core",
                "version": "1.41.0",
                "license_expression": "MIT",
                "license": "",
                "classifiers": [],
                "project_urls": {"Source": "https://github.com/Azure/azure-sdk-for-python"},
            }
        }
        service_now_context = {
            "ticket": "RITM0123456",
            "requestItems": [
                {
                    "requestItem": {"number": "RITM0123456"},
                    "catalogVariables": [
                        {"name": "package_license_type", "value": "MIT License"}
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "packages.json"
            manifest.write_text('{"packages": {}}', encoding="utf-8")
            context_path = root / "servicenow-request-context.json"
            context_path.write_text(json.dumps(service_now_context), encoding="utf-8")
            output_dir = root / "review_output"
            arguments = [
                "check_license_policy.py",
                "--package-name", "azure-core",
                "--package-version", "latest",
                "--manifest-path", str(manifest),
                "--output-dir", str(output_dir),
                "--servicenow-context", str(context_path),
            ]
            github_license_response = {"license": {"spdx_id": "MIT"}}
            with patch.object(license_precheck, "fetch_pypi_metadata", return_value=pypi), patch.object(
                license_precheck, "http_get_json_silent", return_value=(github_license_response, {})
            ), patch.object(sys, "argv", arguments):
                self.assertEqual(0, license_precheck.main())

            decision = json.loads((output_dir / "license-precheck.json").read_text(encoding="utf-8"))

        self.assertEqual("license_verified", decision["state"])
        self.assertTrue(decision["manualApprovalRequired"])
        self.assertEqual("MIT", decision["license"]["type"])
        self.assertIn("ServiceNow catalog variable", decision["license"]["evidenceSource"])

    def test_github_license_is_used_when_servicenow_and_pypi_are_missing_license(self):
        pypi = {
            "info": {
                "name": "azure-core",
                "version": "1.41.0",
                "license_expression": "",
                "license": "",
                "classifiers": [],
                "project_urls": {"Source": "https://github.com/Azure/azure-sdk-for-python"},
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "packages.json"
            manifest.write_text('{"packages": {}}', encoding="utf-8")
            output_dir = root / "review_output"
            arguments = [
                "check_license_policy.py",
                "--package-name", "azure-core",
                "--package-version", "latest",
                "--manifest-path", str(manifest),
                "--output-dir", str(output_dir),
            ]
            github_license_response = {"license": {"spdx_id": "MIT"}}
            with patch.object(license_precheck, "fetch_pypi_metadata", return_value=pypi), patch.object(
                license_precheck, "http_get_json_silent", return_value=(github_license_response, {})
            ), patch.object(sys, "argv", arguments):
                self.assertEqual(0, license_precheck.main())

            decision = json.loads((output_dir / "license-precheck.json").read_text(encoding="utf-8"))

        self.assertEqual("license_requires_review", decision["state"])
        self.assertIn("ServiceNow", decision["reason"])

    def test_unapproved_license_is_rejected_before_scan(self):
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

            decision = json.loads((output_dir / "license-precheck.json").read_text(encoding="utf-8"))
            approval_decision_exists = (output_dir / "approval-decision.json").exists()

        self.assertEqual("license_rejected", decision["state"])
        self.assertFalse(decision["manualApprovalRequired"])
        self.assertIn("Rejected due to unapproved license type", decision["reason"])
        self.assertTrue(approval_decision_exists)

    def test_existing_package_version_is_rejected_as_duplicate_before_scan(self):
        pypi = {
            "info": {
                "name": "already-reviewed",
                "version": "1.0.0",
                "license_expression": "MIT",
                "classifiers": [],
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = root / "packages.json"
            manifest.write_text(
                '{"packages": {"already-reviewed": {"name": "already_reviewed", '
                '"versions": [{"version": "1.0.0"}]}}}',
                encoding="utf-8",
            )
            output_dir = root / "review_output"
            arguments = [
                "check_license_policy.py",
                "--package-name", "already-reviewed",
                "--package-version", "latest",
                "--manifest-path", str(manifest),
                "--output-dir", str(output_dir),
            ]
            with patch.object(license_precheck, "fetch_pypi_metadata", return_value=pypi), patch.object(sys, "argv", arguments):
                self.assertEqual(0, license_precheck.main())

            decision = json.loads((output_dir / "approval-decision.json").read_text(encoding="utf-8"))
            summary = (output_dir / "approval-report.md").read_text(encoding="utf-8")

        self.assertEqual("duplicate", decision["state"])
        self.assertFalse(decision["manualApprovalRequired"])
        self.assertIn("DUPLICATE (AUTO-REJECTED)", summary)
        self.assertIn("already present", summary)

    def test_license_rejection_report_is_not_labeled_as_duplicate(self):
        decision = {
            "state": "license_rejected",
            "packageName": "restricted-package",
            "reasons": ["Rejected due to unapproved license type: GPL-3.0."],
            "license": {
                "type": "GPL-3.0",
                "evidenceSource": "ServiceNow catalog variable `package_license_type`",
                "source": "KB0025632",
            },
        }

        summary = license_precheck.render_markdown(decision)

        self.assertIn("LICENSE REJECTED", summary)
        self.assertNotIn("DUPLICATE (AUTO-REJECTED)", summary)
        self.assertIn("license is not approved", summary)

    def test_all_approved_composite_spdx_expression_can_be_verified(self):
        evidence = {
            "serviceNow": "Apache-2.0",
            "serviceNowComponents": ["Apache-2.0"],
            "pypi": "Apache-2.0",
            "pypiComponents": ["MPL-2.0", "Apache-2.0", "MIT"],
            "github": "Apache-2.0",
            "githubComponents": ["Apache-2.0"],
            "githubSource": "GitHub repository license (ijl/orjson)",
            "serviceNowError": "",
        }

        state, policy, reasons, terminal_rejection = license_precheck.evaluate_license_evidence(evidence)

        self.assertEqual("license_verified", state)
        self.assertFalse(terminal_rejection)
        self.assertTrue(policy["approved"])
        self.assertIn("Apache-2.0", reasons[0])

    def test_composite_spdx_expression_with_unapproved_component_is_rejected(self):
        evidence = {
            "serviceNow": "Apache-2.0",
            "serviceNowComponents": ["Apache-2.0"],
            "pypi": "Apache-2.0",
            "pypiComponents": ["Apache-2.0", "GPL-3.0"],
            "github": "Apache-2.0",
            "githubComponents": ["Apache-2.0"],
            "githubSource": "GitHub repository license (example/package)",
            "serviceNowError": "",
        }

        state, _, reasons, terminal_rejection = license_precheck.evaluate_license_evidence(evidence)

        self.assertEqual("license_rejected", state)
        self.assertTrue(terminal_rejection)
        self.assertIn("GPL-3.0", reasons[0])


if __name__ == "__main__":
    unittest.main()
