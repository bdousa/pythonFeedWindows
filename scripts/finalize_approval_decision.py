#!/usr/bin/env python3
"""Turn scanned package and ServiceNow evidence into a publish-routing decision."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_review_report import render_markdown


REQUIRED_TICKET_FIELDS = (
    "packageEcosystem", "openSourceUrl", "packageName", "declaredLicense",
    "intendedUse", "targetEnvironments", "alternativeRationale",
    "executionContext", "internetExposure",
)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}.")
    return value


def decision_for(report: dict, context: dict | None) -> tuple[str, list[str]]:
    base = (report.get("decision") or {}).get("state")
    if base != "auto_approved":
        return "pending_review", list((report.get("decision") or {}).get("reasons") or ["Automated checks require review."])
    if not context or context.get("status") != "available":
        return "pending_review", ["A ServiceNow package request is required for automatic approval."]

    fields = context.get("fields") or {}
    missing = [name for name in REQUIRED_TICKET_FIELDS if not str(fields.get(name) or "").strip()]
    if missing:
        return "pending_review", ["ServiceNow request is missing required field(s): " + ", ".join(missing)]
    if fields.get("packageEcosystem") != "Python/PyPI":
        return "pending_review", ["ServiceNow package ecosystem is not Python/PyPI."]
    if fields.get("packageName", "").replace("_", "-").casefold() != str(report.get("packageName") or "").replace("_", "-").casefold():
        return "pending_review", ["ServiceNow package name does not match the scanned package."]

    ai_review = report.get("aiSecurityReview") or {}
    if ai_review.get("status") != "ok" or ai_review.get("verdict") != "low-concern" or ai_review.get("confidence") != "high":
        return "pending_review", ["Foundry agent did not return a high-confidence low-concern recommendation for this request."]

    return "approved", [
        "Approved automatically: ticket context is complete, license evidence agrees with policy, all Snyk counts are zero, maintenance evidence is current, and the Foundry agent returned a high-confidence low-concern review."
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-json", type=Path, required=True)
    parser.add_argument("--report-md", type=Path, required=True)
    parser.add_argument("--servicenow-context", type=Path)
    args = parser.parse_args()

    report = load_json(args.report_json)
    context = load_json(args.servicenow_context) if args.servicenow_context else None
    normalized_context = None
    if context:
        from build_ai_security_review import normalize_service_now_context
        normalized_context = normalize_service_now_context(context)
    state, reasons = decision_for(report, normalized_context)
    report["recommendation"] = state
    report["decision"] = {
        "state": state,
        "reason": reasons[0],
        "reasons": reasons,
        "manualApprovalRequired": state == "pending_review",
    }
    report["reasons"] = reasons + [reason for reason in report.get("reasons") or [] if reason not in reasons]
    args.report_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.report_md.write_text(render_markdown(report) + "\n", encoding="utf-8")
    args.report_json.with_name("approval-decision.json").write_text(
        json.dumps(report["decision"], indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())