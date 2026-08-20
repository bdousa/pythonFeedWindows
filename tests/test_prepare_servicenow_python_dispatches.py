from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


spec = importlib.util.spec_from_file_location(
    "prepare_servicenow_python_dispatches", SCRIPTS_DIR / "prepare_servicenow_python_dispatches.py"
)
assert spec and spec.loader
intake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intake)


class PythonServiceNowIntakeValidationTests(unittest.TestCase):
    def test_malformed_version_is_the_only_error_for_an_otherwise_valid_request(self):
        fields = {
            "packageName": "AdaptiveCards",
            "requestedVersion": "AdaptiveCards @ 3.1.0",
            "declaredLicense": "MIT",
            "openSourceUrl": "https://pypi.org/project/AdaptiveCards/",
            "intendedUse": "Render notification cards.",
            "targetEnvironments": "dev, test, prod",
            "alternativeRationale": "No approved alternative meets this need.",
            "executionContext": "Web/API service",
            "internetExposure": "Internet-facing",
        }

        errors = intake.format_errors(fields)

        self.assertEqual(1, len(errors))
        self.assertTrue(errors[0].startswith("Requested Version 'AdaptiveCards @ 3.1.0'"))

    def test_validation_comment_is_neutral_and_lists_each_error(self):
        comment = intake.validation_comment(["Requested Version 'bad value' must be exact."])

        self.assertIn("[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:", comment)
        self.assertIn("- Requested Version 'bad value' must be exact.", comment)
        self.assertIn("After correcting the form values, add a new comment containing only: Fixed", comment)
        self.assertNotIn("System.Object[]", comment)
        for forbidden in ("SAR", "SnykAutoReview", "intake", "hourly", "dispatch"):
            self.assertNotIn(forbidden.lower(), comment.lower())

    def test_fixed_after_validation_marker_requests_revalidation(self):
        comments = """2026-08-20 - Automation (Additional comments)
[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:
- Requested Version is invalid.

2026-08-20 - Requester (Additional comments)
Fixed
"""

        self.assertEqual("requester_confirmed_fixed", intake.validation_state(comments))

    def test_unacknowledged_validation_marker_waits_without_dispatch(self):
        comments = "[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:\n- Requested Version is invalid."

        self.assertEqual("awaiting_requester_correction", intake.validation_state(comments))


if __name__ == "__main__":
    unittest.main()
