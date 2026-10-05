from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

spec = importlib.util.spec_from_file_location(
    "finalize_approval_decision", SCRIPTS_DIR / "finalize_approval_decision.py"
)
assert spec and spec.loader
finalize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalize)


class FinalApprovalDecisionTests(unittest.TestCase):
    def test_proposed_license_rejection_is_preserved_for_the_gate(self):
        report = {
            "decision": {
                "state": "license_rejected",
                "reasons": ["Rejected due to unapproved license type: GPL-3.0."],
            }
        }

        state, reasons = finalize.decision_for(report, None)

        self.assertEqual("license_rejected", state)
        self.assertEqual(["Rejected due to unapproved license type: GPL-3.0."], reasons)

    def test_other_nonautomatic_results_remain_pending_review(self):
        report = {"decision": {"state": "pending_review", "reasons": ["Review required."]}}

        state, reasons = finalize.decision_for(report, None)

        self.assertEqual("pending_review", state)
        self.assertEqual(["Review required."], reasons)


if __name__ == "__main__":
    unittest.main()
