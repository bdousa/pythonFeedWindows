#!/usr/bin/env python3
"""Precheck duplicate versions and route license-policy exceptions to manual review."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_review_report import (  # noqa: E402
    canonical_license_type,
    extract_github_repo,
    evaluate_license_policy,
    fetch_pypi_metadata,
    find_existing_manifest_version,
    github_request_headers,
    http_get_json_silent,
    preferred_license_text,
)


SERVICENOW_LICENSE_VARIABLE = "package_license_type"


def service_now_declared_license(context_path: Path) -> str:
    """Read the declared license from exactly one inspected ServiceNow request item."""
    try:
        context = json.loads(context_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read ServiceNow request context from {context_path}.") from exc

    request_items = context.get("requestItems") if isinstance(context, dict) else None
    if not isinstance(request_items, list) or len(request_items) != 1:
        raise ValueError(
            "ServiceNow request context must contain exactly one request item; supply an RITM number."
        )

    request_item = request_items[0]
    variables = request_item.get("catalogVariables") if isinstance(request_item, dict) else None
    if not isinstance(variables, list):
        raise ValueError("ServiceNow request context does not contain catalog variables.")

    for variable in variables:
        if not isinstance(variable, dict):
            continue
        if str(variable.get("name") or "") == SERVICENOW_LICENSE_VARIABLE:
            declared_license = str(variable.get("value") or "").strip()
            if declared_license:
                return declared_license
            break

    raise ValueError(
        f"The ServiceNow request does not provide a value for {SERVICENOW_LICENSE_VARIABLE}."
    )


def github_license_type(info: dict) -> tuple[str, str]:
    """Return an SPDX license declared by the package's GitHub repository."""
    repository = extract_github_repo(info)
    if not repository:
        return "", ""

    owner, repo = repository
    payload, _ = http_get_json_silent(
        f"https://api.github.com/repos/{owner}/{repo}/license",
        github_request_headers(os.getenv("GITHUB_TOKEN")),
    )
    license_data = payload.get("license") if isinstance(payload, dict) else None
    spdx_id = str(license_data.get("spdx_id") or "").strip() if isinstance(license_data, dict) else ""
    if not spdx_id or spdx_id.upper() in {"NOASSERTION", "OTHER", ""}:
        return "", ""

    return canonical_license_type(spdx_id, "", []), f"GitHub repository license ({owner}/{repo})"


def pypi_license_type(info: dict) -> str:
    license_expression, legacy_license = preferred_license_text(info)
    return canonical_license_type(license_expression, legacy_license, info.get("classifiers") or [])


def collect_license_evidence(info: dict, servicenow_context: Path | None) -> dict:
    """Collect independently declared license evidence in policy-normalized form."""
    service_now_type = "NOASSERTION"
    service_now_error = ""
    if servicenow_context:
        try:
            service_now_type = canonical_license_type("", service_now_declared_license(servicenow_context), [])
        except ValueError as exc:
            service_now_error = str(exc)
    else:
        service_now_error = "No ServiceNow request context was supplied."

    github_type, github_source = github_license_type(info)
    return {
        "serviceNow": service_now_type,
        "pypi": pypi_license_type(info),
        "github": github_type or "NOASSERTION",
        "githubSource": github_source,
        "serviceNowError": service_now_error,
    }


def evaluate_license_evidence(evidence: dict) -> tuple[str, dict, list[str], bool]:
    """Route license evidence to rejection, scan, or manual review.

    A non-approved declared license is a terminal rejection. Incomplete or
    conflicting evidence remains reviewable but can never be auto-approved.
    """
    service_now_type = evidence["serviceNow"]
    pypi_type = evidence["pypi"]
    github_type = evidence["github"]
    declared_types = [value for value in (service_now_type, pypi_type, github_type) if value != "NOASSERTION"]
    unapproved = [value for value in declared_types if not evaluate_license_policy(value)["approved"]]
    policy = evaluate_license_policy(service_now_type)
    policy["evidence"] = evidence
    policy["evidenceSource"] = f"ServiceNow catalog variable `{SERVICENOW_LICENSE_VARIABLE}`"

    if unapproved:
        return "license_rejected", policy, [
            "Rejected due to unapproved license type: " + ", ".join(sorted(set(unapproved))) + "."
        ], True
    if not service_now_type or service_now_type == "NOASSERTION":
        return "license_requires_review", policy, [
            "ServiceNow does not provide a recognizable package license type; manual approval is required."
        ], False
    if pypi_type == "NOASSERTION" or github_type == "NOASSERTION":
        missing = []
        if pypi_type == "NOASSERTION":
            missing.append("PyPI")
        if github_type == "NOASSERTION":
            missing.append("GitHub")
        return "license_requires_review", policy, [
            "License evidence is incomplete in " + " and ".join(missing) + "; manual approval is required."
        ], False
    if len(set(declared_types)) != 1:
        return "license_requires_review", policy, [
            "ServiceNow, PyPI, and GitHub license evidence does not agree; manual approval is required."
        ], False
    return "license_verified", policy, [
        f"License {service_now_type} is approved per {policy['source']} and matches ServiceNow, PyPI, and GitHub evidence."
    ], False


def render_markdown(decision: dict) -> str:
    license_rejected = decision["state"] == "license_rejected"
    recommendation = "LICENSE REJECTED" if license_rejected else "DUPLICATE (AUTO-REJECTED)"
    skipped_reason = (
        "Snyk and AI Foundry reviews were skipped because the license is not approved."
        if license_rejected
        else "Snyk and AI Foundry reviews were skipped because this package version was already validated."
    )
    lines = [
        f"# Approval Report: {decision['packageName']}",
        "",
        f"**Recommendation:** {recommendation}",
        "",
        "## Approval State",
        "",
        f"- State: `{decision['state']}`",
        "- Manual approval gate: not entered (automatic rejection)",
        "- Automatic rejection reason(s):",
    ]
    lines.extend(f"  - {reason}" for reason in decision["reasons"])
    lines.extend([
        "",
        "## License Policy Check",
        "",
        f"- Detected license type: `{decision['license']['type']}`",
        f"- License evidence: {decision['license']['evidenceSource']}",
        f"- Policy KB: {decision['license']['source']}",
        f"- {skipped_reason}",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--manifest-path", type=Path, default=Path("packages.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--servicenow-context",
        type=Path,
        help="Inspection JSON containing the ServiceNow package_license_type catalog variable.",
    )
    args = parser.parse_args()

    pypi = fetch_pypi_metadata(args.package_name)
    info = pypi.get("info") or {}
    license_evidence = collect_license_evidence(info, args.servicenow_context)
    license_state, license_policy, license_reasons, terminal_license_rejection = evaluate_license_evidence(
        license_evidence
    )
    resolved_version = (
        info.get("version")
        if args.package_version.strip().lower() in {"", "latest"}
        else args.package_version
    ) or "unknown"
    duplicate = find_existing_manifest_version(args.manifest_path, args.package_name, resolved_version)
    duplicate_reason = "The requested package version is already present in packages.json."
    auto_rejected = duplicate or terminal_license_rejection
    if duplicate:
        state = "duplicate"
        reasons = [duplicate_reason]
    else:
        state = license_state
        reasons = license_reasons

    decision = {
        "state": state,
        "reason": reasons[0],
        "reasons": reasons,
        "manualApprovalRequired": not auto_rejected,
        "packageName": info.get("name") or args.package_name,
        "requestedVersion": args.package_version,
        "resolvedVersion": resolved_version,
        "duplicate": duplicate,
        "license": license_policy,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "license-precheck.json").write_text(
        json.dumps(decision, indent=2) + "\n", encoding="utf-8"
    )
    if auto_rejected:
        (args.output_dir / "approval-decision.json").write_text(
            json.dumps(decision, indent=2) + "\n", encoding="utf-8"
        )
        (args.output_dir / "approval-report.json").write_text(
            json.dumps(decision, indent=2) + "\n", encoding="utf-8"
        )
        (args.output_dir / "approval-report.md").write_text(
            render_markdown(decision), encoding="utf-8"
        )

    print(json.dumps(decision, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
