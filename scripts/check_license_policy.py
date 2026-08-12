#!/usr/bin/env python3
"""Precheck duplicate versions and route license-policy exceptions to manual review."""

from __future__ import annotations

import argparse
import json
import os
import re
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
SPDX_OPERATOR_PATTERN = re.compile(r"\b(?:AND|OR|WITH)\b|[()]")
SPDX_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
SPDX_OPERATORS = {"AND", "OR", "WITH"}


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


def license_components(value: str, *, is_expression: bool = False) -> list[str]:
    """Return policy identifiers from a simple license value or SPDX expression.

    A catalog field such as ``MIT License`` is treated as one value. SPDX
    expressions are tokenized so every component participates in policy checks.
    """
    candidate = str(value or "").strip()
    if not candidate:
        return []
    if not is_expression or not SPDX_OPERATOR_PATTERN.search(candidate):
        normalized = canonical_license_type("", candidate, [])
        return [] if normalized == "NOASSERTION" else [normalized]

    components = []
    for token in SPDX_IDENTIFIER_PATTERN.findall(candidate):
        if token.upper() in SPDX_OPERATORS:
            continue
        normalized = canonical_license_type(token, "", [])
        if normalized and normalized not in components:
            components.append(normalized)
    return components


def pypi_license_components(info: dict) -> list[str]:
    """Resolve all declared PyPI license components without losing SPDX terms."""
    license_expression, legacy_license = preferred_license_text(info)
    if license_expression:
        return license_components(license_expression, is_expression=True)
    license_type = canonical_license_type("", legacy_license, info.get("classifiers") or [])
    return [] if license_type == "NOASSERTION" else [license_type]


def collect_license_evidence(info: dict, servicenow_context: Path | None) -> dict:
    """Collect independently declared license evidence in policy-normalized form."""
    service_now_type = "NOASSERTION"
    service_now_components: list[str] = []
    service_now_error = ""
    if servicenow_context:
        try:
            service_now_components = license_components(service_now_declared_license(servicenow_context))
            service_now_type = service_now_components[0] if service_now_components else "NOASSERTION"
        except ValueError as exc:
            service_now_error = str(exc)
    else:
        service_now_error = "No ServiceNow request context was supplied."

    pypi_components = pypi_license_components(info)
    github_type, github_source = github_license_type(info)
    github_components = [] if not github_type else [github_type]
    return {
        "serviceNow": service_now_type,
        "serviceNowComponents": service_now_components,
        "pypi": pypi_license_type(info),
        "pypiComponents": pypi_components,
        "github": github_type or "NOASSERTION",
        "githubComponents": github_components,
        "githubSource": github_source,
        "serviceNowError": service_now_error,
    }


def evaluate_license_evidence(evidence: dict) -> tuple[str, dict, list[str], bool]:
    """Route license evidence to rejection, scan, or manual review.

    A non-approved declared license is a terminal rejection. Incomplete or
    conflicting evidence remains reviewable but can never be auto-approved.
    """
    service_now_components = set(evidence.get("serviceNowComponents") or [])
    pypi_components = set(evidence.get("pypiComponents") or [])
    github_components = set(evidence.get("githubComponents") or [])
    # Backward-compatible handling for pre-existing evidence artifacts.
    if not service_now_components and evidence.get("serviceNow") not in {None, "", "NOASSERTION"}:
        service_now_components.add(evidence["serviceNow"])
    if not pypi_components and evidence.get("pypi") not in {None, "", "NOASSERTION"}:
        pypi_components.add(evidence["pypi"])
    if not github_components and evidence.get("github") not in {None, "", "NOASSERTION"}:
        github_components.add(evidence["github"])

    service_now_type = evidence.get("serviceNow") or "NOASSERTION"
    all_components = service_now_components | pypi_components | github_components
    unapproved = [value for value in all_components if not evaluate_license_policy(value)["approved"]]
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
    if not pypi_components or not github_components:
        missing = []
        if not pypi_components:
            missing.append("PyPI")
        if not github_components:
            missing.append("GitHub")
        return "license_requires_review", policy, [
            "License evidence is incomplete in " + " and ".join(missing) + "; manual approval is required."
        ], False
    shared_components = service_now_components & pypi_components & github_components
    if not shared_components:
        return "license_requires_review", policy, [
            "ServiceNow, PyPI, and GitHub license evidence has no shared approved license component; manual approval is required."
        ], False
    return "license_verified", policy, [
        "Approved license component(s) " + ", ".join(sorted(shared_components))
        + f" match ServiceNow, PyPI, and GitHub evidence per {policy['source']}."
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
