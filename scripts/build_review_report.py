#!/usr/bin/env python3

import argparse
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def safe_parse_iso(value: str):
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def fetch_pypi_metadata(package_name: str) -> dict:
    url = f"https://pypi.org/pypi/{package_name.replace('_', '-')}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def parse_severity_counts(text: str) -> dict:
    lowered = text.lower()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for severity in counts:
        matches = re.findall(rf"(\d+)\s+{severity}", lowered)
        counts[severity] = max((int(match) for match in matches), default=0)
    if "no known vulnerabilities" in lowered or "0 vulnerable dependency paths" in lowered:
        return counts
    return counts


def summarize_license(license_name: str, classifiers: list[str]) -> str:
    license_classifiers = [item.split("::")[-1].strip() for item in classifiers if item.startswith("License ::")]
    if license_classifiers:
        return license_classifiers[-1]
    if not license_name:
        return "unknown"
    first_line = next((line.strip() for line in license_name.splitlines() if line.strip()), "")
    if len(first_line) > 120:
        return first_line[:117].rstrip() + "..."
    return first_line or "unknown"


def detect_license_risk(license_name: str, classifiers: list[str]) -> tuple[str, list[str]]:
    combined = " ".join([license_name or "", *classifiers]).lower()
    risky_tokens = ["agpl", "gpl", "copyleft", "sspl"]
    if any(token in combined for token in risky_tokens):
        return "review", ["Potentially restrictive license detected"]
    if not combined.strip():
        return "review", ["License metadata is missing or unclear"]
    return "pass", []


def build_recommendation(dep_counts: dict, code_counts: dict, last_release_days: int | None, license_status: str) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if dep_counts["critical"] > 0 or code_counts["critical"] > 0:
        reasons.append("Critical security findings detected")
        return "reject", reasons
    if dep_counts["high"] > 0 or code_counts["high"] > 0:
        reasons.append("High severity findings require explicit review")
    if last_release_days is not None and last_release_days > 365:
        reasons.append("Package has not shipped an upstream release in over a year")
    if license_status == "review":
        reasons.append("License posture requires review")
    if reasons:
        return "review", reasons
    return "approve", ["No critical or high severity blockers detected", "Package metadata looks compatible with current policy"]


def build_report(args: argparse.Namespace) -> dict:
    requirements_text = read_text(Path(args.requirements))
    dep_summary = read_text(Path(args.snyk_dependencies_summary))
    code_summary = read_text(Path(args.snyk_code_summary))
    dependency_lines = [line.strip() for line in requirements_text.splitlines() if line.strip() and not line.startswith("#")]

    metadata: dict = {}
    metadata_error = ""
    try:
        metadata = fetch_pypi_metadata(args.package_name)
    except urllib.error.URLError as exc:
        metadata_error = str(exc)

    info = metadata.get("info", {}) if metadata else {}
    releases = metadata.get("releases", {}) if metadata else {}
    classifiers = info.get("classifiers") or []
    os_classifiers = [item for item in classifiers if item.startswith("Operating System ::")]
    release_dates = []
    for files in releases.values():
        for file_info in files or []:
            parsed = safe_parse_iso(file_info.get("upload_time") or file_info.get("upload_time_iso_8601") or "")
            if parsed:
                release_dates.append(parsed)
    last_release_days = None
    latest_release_date = ""
    if release_dates:
        latest_release = max(release_dates)
        latest_release_date = latest_release.strftime("%Y-%m-%d")
        last_release_days = (datetime.now(timezone.utc) - latest_release).days

    dep_counts = parse_severity_counts(dep_summary)
    code_counts = parse_severity_counts(code_summary)
    license_status, license_reasons = detect_license_risk(info.get("license", ""), classifiers)
    recommendation, recommendation_reasons = build_recommendation(dep_counts, code_counts, last_release_days, license_status)

    reasons = []
    reasons.extend(license_reasons)
    reasons.extend(recommendation_reasons)
    if not os_classifiers:
        reasons.append("OS compatibility classifiers are missing")
    if metadata_error:
        reasons.append(f"PyPI metadata lookup failed: {metadata_error}")

    return {
        "packageName": args.package_name,
        "requestedVersion": args.package_version,
        "reportDate": utc_today(),
        "runUrl": args.run_url,
        "recommendation": recommendation,
        "reasons": reasons,
        "dependencyCount": len(dependency_lines),
        "snyk": {
            "dependencies": dep_counts,
            "code": code_counts,
        },
        "metadata": {
            "latestVersion": info.get("version", ""),
            "summary": info.get("summary", ""),
            "licenseSummary": summarize_license(info.get("license", ""), classifiers),
            "classifiers": classifiers,
            "osClassifiers": os_classifiers,
            "latestReleaseDate": latest_release_date,
            "daysSinceLatestRelease": last_release_days,
            "projectUrl": info.get("project_url") or info.get("home_page") or f"https://pypi.org/project/{args.package_name}/",
        },
    }


def render_markdown(report: dict) -> str:
    dep_counts = report["snyk"]["dependencies"]
    code_counts = report["snyk"]["code"]
    metadata = report["metadata"]
    reasons = report.get("reasons", [])
    lines = [
        f"# Approval Report: {report['packageName']}",
        "",
        "## Recommendation",
        "",
        f"- Recommendation: **{report['recommendation'].upper()}**",
        f"- Requested version: `{report['requestedVersion']}`",
        f"- Report date: `{report['reportDate']}`",
        f"- Workflow run: {report['runUrl']}",
        "",
        "## Security Summary",
        "",
        f"- Dependencies: critical={dep_counts['critical']}, high={dep_counts['high']}, medium={dep_counts['medium']}, low={dep_counts['low']}",
        f"- Source code: critical={code_counts['critical']}, high={code_counts['high']}, medium={code_counts['medium']}, low={code_counts['low']}",
        f"- Total dependencies reviewed: {report['dependencyCount']}",
        "",
        "## Package Metadata",
        "",
        f"- Latest PyPI version: `{metadata.get('latestVersion', '')}`",
        f"- Latest upstream release: `{metadata.get('latestReleaseDate', '') or 'unknown'}`",
        f"- Days since latest upstream release: `{metadata.get('daysSinceLatestRelease', 'unknown')}`",
        f"- License: `{metadata.get('licenseSummary', '') or 'unknown'}`",
        f"- Project URL: {metadata.get('projectUrl', '')}",
        "",
        "## Review Notes",
        "",
    ]
    if reasons:
        for reason in reasons:
            lines.append(f"- {reason}")
    else:
        lines.append("- No additional review notes.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a package approval report from workflow artifacts.")
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--snyk-dependencies-summary", required=True)
    parser.add_argument("--snyk-code-summary", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    report = build_report(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "approval-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output_dir / "approval-report.md").write_text(render_markdown(report) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())