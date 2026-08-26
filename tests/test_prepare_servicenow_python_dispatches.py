from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


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
    def test_workflows_dispatch_line_context_and_leave_batch_ritms_open(self):
        root = Path(__file__).resolve().parents[1]
        intake_workflow = (root / ".github/workflows/servicenow-package-intake.yml").read_text(encoding="utf-8")
        worker_workflow = (root / ".github/workflows/package-validation-windows.yml").read_text(encoding="utf-8")

        self.assertIn("servicenow_package_line_b64", intake_workflow)
        self.assertIn("base64.b64encode", intake_workflow)
        self.assertIn('title="Package validation — $package — $version — $ticket"', intake_workflow)
        self.assertIn("servicenow_package_line_b64", worker_workflow)
        self.assertIn("--package-line-json", worker_workflow)
        self.assertIn("inputs.servicenow_package_line_b64 == ''", worker_workflow)

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

    def test_registry_url_supplies_high_confidence_package_name_suggestion(self):
        fields = {
            "packageName": "reqeusts",
            "requestedVersion": "2.32.5",
            "declaredLicense": "Apache-2.0",
            "openSourceUrl": "https://pypi.org/project/requests/2.32.5/",
            "intendedUse": "HTTP client",
            "targetEnvironments": "dev",
            "alternativeRationale": "No alternative",
            "executionContext": "Web/API service",
            "internetExposure": "Internet-facing",
        }

        errors = intake.format_errors(fields)

        self.assertIn("Did you mean 'requests'? The registry/source URL identifies that PyPI package.", errors)

    def test_validation_comment_is_neutral_and_lists_each_error(self):
        comment = intake.validation_comment(["Requested Version 'bad value' must be exact."])

        self.assertIn("[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:", comment)
        self.assertIn("- Requested Version 'bad value' must be exact.", comment)
        self.assertIn("After correcting the form values, add a new comment containing only: Fixed", comment)
        self.assertNotIn("System.Object[]", comment)
        for forbidden in ("SAR", "SnykAutoReview", "intake", "hourly", "dispatch"):
            self.assertNotIn(forbidden.lower(), comment.lower())

    def test_fixed_below_newest_validation_marker_does_not_acknowledge_request(self):
        comments = """2026-08-20 - Automation (Additional comments)
[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:
- Requested Version is invalid.

2026-08-20 - Requester (Additional comments)
Fixed
"""

        self.assertEqual("awaiting_requester_correction", intake.validation_state(comments))

    def test_unacknowledged_validation_marker_waits_without_dispatch(self):
        comments = "[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:\n- Requested Version is invalid."

        self.assertEqual("awaiting_requester_correction", intake.validation_state(comments))

    def test_fixed_above_newest_first_validation_marker_requests_revalidation(self):
        comments = """2026-08-26 - Requester (Additional comments)
Fixed

2026-08-26 - Automation (Additional comments)
[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:
- Package Name is invalid.
"""

        self.assertEqual("requester_confirmed_fixed", intake.validation_state(comments))

    def test_multiple_sentinel_is_case_insensitive_and_requires_all_four_fields(self):
        fields = {
            "packageName": "multiple",
            "requestedVersion": " Multiple ",
            "openSourceUrl": "MULTIPLE",
            "declaredLicense": "mUlTiPlE",
        }
        self.assertTrue(intake.is_multiple_request(fields))

        fields["declaredLicense"] = "MIT"
        with self.assertRaisesRegex(ValueError, "must all be Multiple"):
            intake.is_multiple_request(fields)

    def test_package_list_parses_multiple_rows_and_rejects_invalid_format(self):
        notes = """PACKAGE LIST
package name, version, registry/source URL, license
requests, 2.32.5, https://pypi.org/project/requests/2.32.5/, Apache-2.0
urllib3, 2.2.3, https://pypi.org/project/urllib3/2.2.3/, MIT
END PACKAGE LIST
Additional request context.
"""
        lines = intake.parse_package_list(notes)

        self.assertEqual(2, len(lines))
        self.assertEqual("requests", lines[0]["packageName"])
        self.assertEqual("2.2.3", lines[1]["requestedVersion"])

        with self.assertRaisesRegex(ValueError, "header must be exactly"):
            intake.parse_package_list("PACKAGE LIST\nwrong\nrequests, 1, https://pypi.org, MIT\nEND PACKAGE LIST")
        with self.assertRaisesRegex(ValueError, "exactly four"):
            intake.parse_package_list("PACKAGE LIST\npackage name, version, registry/source URL, license\nrequests, 1, https://pypi.org\nEND PACKAGE LIST")

    def test_multiple_batch_validation_blocks_all_lines_when_any_row_is_invalid(self):
        source = {
            "requestItems": [{
                "requestItem": {"number": "RITM0000002", "sys_id": "sys-id", "comments": ""},
                "catalogVariables": [
                    {"name": "package_ecosystem", "value": "Python/PyPI"},
                    {"name": "package_name", "value": "Multiple"},
                    {"name": "requested_version", "value": "Multiple"},
                    {"name": "open_source_registry_url", "value": "Multiple"},
                    {"name": "package_license_type", "value": "Multiple"},
                    {"name": "how_are_you_going_to_use_the_package", "value": "Use in service"},
                    {"name": "target_environment_s", "value": "dev"},
                    {"name": "why_is_an_approved_internal_alternative_not_sufficient", "value": "No alternative"},
                    {"name": "execution_context", "value": "Web/API service"},
                    {"name": "internet_exposure", "value": "Internet-facing"},
                    {"name": "comments", "value": "PACKAGE LIST\npackage name, version, registry/source URL, license\nrequests, 2.32.5, https://pypi.org/project/requests/2.32.5/, Apache-2.0\ninvalid, bad version, https://pypi.org/project/invalid/, MIT\nEND PACKAGE LIST"},
                ],
            }],
        }
        source["requestItems"][0]["requestItem"]["requested_for.email"] = "requester@example.com"
        with patch.object(intake, "send_review_required_email") as send_email, patch.object(
            intake, "update_awaiting_requester_information"
        ) as update_request:
            results = intake.prepare_dispatches(
                source, "example.service-now.com", "user", "password", "https://logic.example.com/trigger"
            )

        self.assertEqual("validation_requested", results[0]["status"])
        self.assertEqual(1, len(results))
        self.assertIn("Package list line", results[0]["errors"][0])
        send_email.assert_called_once()
        update_request.assert_called_once()

    def test_correction_notification_requires_recipient_and_endpoint(self):
        with self.assertRaisesRegex(RuntimeError, "LOGIC_APP_URL"):
            intake.send_review_required_email("", "requester@example.com", "RITM1", "https://example.com", ["Bad field"])
        with self.assertRaisesRegex(RuntimeError, "requester email"):
            intake.send_review_required_email("https://logic.example.com", "", "RITM1", "https://example.com", ["Bad field"])


if __name__ == "__main__":
    unittest.main()
