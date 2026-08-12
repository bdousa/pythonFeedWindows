from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ai_review = load_module("build_ai_security_review", "build_ai_security_review.py")
request_updates = load_module("comment_servicenow_package_request", "comment_servicenow_package_request.py")


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class ServiceNowRequestTests(unittest.TestCase):
    def test_revised_target_environment_is_exposed_under_both_names(self):
        context = {
            "requestItems": [{
                "requestItem": {"number": "RITM0000001"},
                "catalogVariables": [
                    {"name": "target_environment_s", "value": "All"},
                    {"name": "package_name", "value": "example"},
                ],
            }],
        }

        normalized = ai_review.normalize_service_now_context(context)

        self.assertEqual("All", normalized["fields"]["targetEnvironments"])
        self.assertEqual("All", normalized["fields"]["environment"])
        self.assertNotIn("environment", normalized["missingFields"])
        self.assertIn("notes", normalized["fields"])
        self.assertNotIn("notes", normalized["missingFields"])

    def test_closed_complete_update_uses_verified_state_value(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return _Response()

        with patch.object(request_updates, "urlopen", fake_urlopen):
            request_updates.update_request_item(
                "example.service-now.com", "user", "password", "sys-id", "Approved", True
            )

        self.assertEqual("https://example.service-now.com/api/now/table/sc_req_item/sys-id", captured["url"])
        self.assertEqual({"comments": "Approved", "state": "3"}, captured["payload"])
        self.assertEqual(60, captured["timeout"])


if __name__ == "__main__":
    unittest.main()