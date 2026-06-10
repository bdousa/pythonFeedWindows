#!/usr/bin/env python3

import argparse
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def now_display() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_manifest(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def fetch_pypi_data(package_name: str) -> dict | None:
    url = f"https://pypi.org/pypi/{package_name.replace('_', '-')}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError:
        return None


def extract_version_from_filename(file_name: str) -> str:
    wheel_match = re.match(r"^[^-]+-([0-9]+\.[0-9]+(?:\.[0-9]+)?[^-]*)-", file_name)
    if wheel_match:
        return wheel_match.group(1)
    if file_name.endswith(".tar.gz"):
        stem = file_name[:-7]
        parts = stem.split("-")
        if len(parts) >= 2:
            return "-".join(parts[1:])
    return ""


def resolve_validated_version(package: dict) -> str:
    latest_validated = package.get("latestVersion", "") or ""
    if latest_validated and latest_validated != "latest":
        return latest_validated
    versions = package.get("versions") or []
    latest_entry = next((entry for entry in versions if entry.get("version") == latest_validated), None)
    if latest_entry is None and versions:
        latest_entry = versions[0]
    if not latest_entry:
        return latest_validated
    for file_name in latest_entry.get("files") or []:
        resolved = extract_version_from_filename(file_name)
        if resolved:
            return resolved
    return latest_validated


def build_report(manifest: dict) -> dict:
    packages = manifest.get("packages", {})
    candidates = []
    unchanged = []
    errors = []

    for package_name in sorted(packages, key=str.lower):
        package = packages[package_name]
        if package.get("lifecycleState", "active") != "active":
            continue

        latest_validated = package.get("latestVersion", "")
        resolved_validated = resolve_validated_version(package)
        pypi_data = fetch_pypi_data(package_name)
        if not pypi_data:
            errors.append({
                "package": package_name,
                "reason": "PyPI metadata lookup failed",
                "latestValidated": latest_validated,
            })
            continue

        info = pypi_data.get("info", {})
        upstream_version = info.get("version", "")
        record = {
            "package": package_name,
            "latestValidated": latest_validated,
            "resolvedValidatedVersion": resolved_validated,
            "upstreamVersion": upstream_version,
            "summary": info.get("summary", ""),
            "projectUrl": info.get("project_url") or info.get("home_page") or f"https://pypi.org/project/{package_name}/",
        }
        if upstream_version and upstream_version != resolved_validated:
            record["action"] = "review-candidate"
            record["reason"] = "New upstream version detected"
            candidates.append(record)
        else:
            unchanged.append(record)

    return {
        "generatedAt": today_utc(),
        "candidateCount": len(candidates),
        "unchangedCount": len(unchanged),
        "errorCount": len(errors),
        "candidates": candidates,
        "unchanged": unchanged,
        "errors": errors,
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Nightly Package Audit",
        "",
        f"Generated: {now_display()}",
        "",
        "## Summary",
        "",
        f"- Review candidates: {report['candidateCount']}",
        f"- Unchanged active packages: {report['unchangedCount']}",
        f"- Metadata lookup errors: {report['errorCount']}",
        "",
    ]

    if report["candidates"]:
        lines.extend([
            "## Review Candidates",
            "",
            "| Package | Latest Validated | Resolved Version | Upstream Version | Reason |",
            "|---------|------------------|------------------|------------------|--------|",
        ])
        for candidate in report["candidates"]:
            lines.append(
                f"| `{candidate['package']}` | `{candidate['latestValidated']}` | `{candidate.get('resolvedValidatedVersion', '')}` | `{candidate['upstreamVersion']}` | {candidate['reason']} |"
            )
        lines.append("")

    if report["errors"]:
        lines.extend([
            "## Lookup Errors",
            "",
            "| Package | Latest Validated | Error |",
            "|---------|------------------|-------|",
        ])
        for error in report["errors"]:
            lines.append(f"| `{error['package']}` | `{error['latestValidated']}` | {error['reason']} |")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a nightly audit report for active packages.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    report = build_report(load_manifest(Path(args.manifest)))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "nightly-audit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output_dir / "nightly-audit.md").write_text(render_markdown(report) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())