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

    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


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
        captured = {"requests": []}

        def fake_urlopen(request, timeout):
            captured["requests"].append({"url": request.full_url, "payload": request.data, "timeout": timeout})
            if request.data is None:
                return _Response({"result": []})
            return _Response({"result": {"state": "3", "active": "false"}})

        with patch.object(request_updates, "urlopen", fake_urlopen):
            request_updates.update_request_item(
                "example.service-now.com", "user", "password", "sys-id", "Approved", True
            )

        ritm_update = captured["requests"][0]
        self.assertEqual("https://example.service-now.com/api/now/table/sc_req_item/sys-id", ritm_update["url"])
        self.assertEqual({"comments": "Approved", "state": "3"}, json.loads(ritm_update["payload"].decode("utf-8")))
        self.assertEqual(60, ritm_update["timeout"])
        self.assertIn("sc_task?", captured["requests"][1]["url"])

    def test_active_catalog_tasks_are_closed_with_outcome_reason(self):
        requests = []

        def fake_urlopen(request, timeout):
            requests.append({"url": request.full_url, "payload": request.data})
            if "sc_task?" in request.full_url:
                return _Response({"result": [{"sys_id": "task-sys-id", "number": "TASK0000001"}]})
            return _Response({"result": {"number": "TASK0000001", "state": "3", "active": "false"}})

        with patch.object(request_updates, "urlopen", fake_urlopen):
            closed = request_updates.close_active_catalog_tasks(
                "example.service-now.com", "credential", "ritm-sys-id", "Rejected due to unapproved license type"
            )

        self.assertEqual(["TASK0000001"], closed)
        self.assertIn("sc_task?", requests[0]["url"])
        self.assertIn("request_item%3Dritm-sys-id%5Eactive%3Dtrue", requests[0]["url"])
        self.assertEqual(
            {"state": "3", "close_notes": "Rejected due to unapproved license type"},
            json.loads(requests[1]["payload"].decode("utf-8")),
        )

    def test_parent_request_closes_only_when_no_active_request_items_remain(self):
        requests = []

        def fake_urlopen(request, timeout):
            requests.append({"url": request.full_url, "payload": request.data})
            if "sc_req_item/ritm-sys-id?" in request.full_url:
                return _Response({"result": {"request": {"value": "req-sys-id"}}})
            if "sc_req_item?" in request.full_url:
                return _Response({"result": []})
            if "sc_request/req-sys-id" in request.full_url:
                return _Response({"result": {"number": "REQ0000001", "state": "3", "active": "false"}})
            raise AssertionError(f"Unexpected ServiceNow request: {request.full_url}")

        with patch.object(request_updates, "urlopen", fake_urlopen):
            closed = request_updates.close_parent_request_if_complete(
                "example.service-now.com", "credential", "ritm-sys-id"
            )

        self.assertEqual("REQ0000001", closed)
        self.assertEqual({"state": "3"}, json.loads(requests[-1]["payload"].decode("utf-8")))

    def test_parent_request_remains_open_when_another_ritm_is_active(self):
        requests = []

        def fake_urlopen(request, timeout):
            requests.append({"url": request.full_url, "payload": request.data})
            if "sc_req_item/ritm-sys-id?" in request.full_url:
                return _Response({"result": {"request": {"value": "req-sys-id"}}})
            if "sc_req_item?" in request.full_url:
                return _Response({"result": [{"sys_id": "other-active-ritm"}]})
            raise AssertionError(f"Unexpected ServiceNow request: {request.full_url}")

        with patch.object(request_updates, "urlopen", fake_urlopen):
            closed = request_updates.close_parent_request_if_complete(
                "example.service-now.com", "credential", "ritm-sys-id"
            )

        self.assertEqual("", closed)
        self.assertEqual(2, len(requests))


if __name__ == "__main__":
    unittest.main()