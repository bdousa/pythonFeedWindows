#!/usr/bin/env python3
"""Fail fast when a PyPI package's license is not approved by policy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_review_report import (  # noqa: E402
    canonical_license_type,
    evaluate_license_policy,
    fetch_pypi_metadata,
    find_existing_manifest_version,
    preferred_license_text,
)


def render_markdown(decision: dict) -> str:
    lines = [
        f"# Approval Report: {decision['packageName']}",
        "",
        "**Recommendation:** AUTO-REJECTED (UNAPPROVED LICENSE)",
        "",
        "## Approval State",
        "",
        "- State: `auto_rejected`",
        "- Manual approval gate: not entered (automatic rejection)",
        "- Automatic rejection reason(s):",
    ]
    lines.extend(f"  - {reason}" for reason in decision["reasons"])
    lines.extend([
        "",
        "## License Policy Check",
        "",
        f"- Detected license type: `{decision['license']['type']}`",
        f"- Policy KB: {decision['license']['source']}",
        "- Snyk and AI Foundry reviews were skipped because this package cannot be approved under the license policy.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--manifest-path", type=Path, default=Path("packages.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    pypi = fetch_pypi_metadata(args.package_name)
    info = pypi.get("info") or {}
    license_expression, legacy_license = preferred_license_text(info)
    license_type = canonical_license_type(
        license_expression, legacy_license, info.get("classifiers") or []
    )
    license_policy = evaluate_license_policy(license_type)
    resolved_version = (
        info.get("version")
        if args.package_version.strip().lower() in {"", "latest"}
        else args.package_version
    ) or "unknown"
    duplicate = find_existing_manifest_version(args.manifest_path, args.package_name, resolved_version)
    auto_rejected = not license_policy["approved"]

    decision = {
        "state": "auto_rejected" if auto_rejected else "license_approved",
        "reason": license_policy["reason"],
        "reasons": [license_policy["reason"]],
        "manualApprovalRequired": not auto_rejected,
        "packageName": info.get("name") or args.package_name,
        "requestedVersion": args.package_version,
        "resolvedVersion": resolved_version,
        "duplicate": duplicate,
        "license": license_policy,
    }
    if auto_rejected and duplicate:
        decision["reasons"].append("The requested package version is already present in packages.json.")

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
