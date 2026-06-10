#!/usr/bin/env python3

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "PythonFeed-Update Nightly Audit"
SEVERITY_LEVELS = ("critical", "high", "medium", "low")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def now_display() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_pypi_version(package_name: str) -> str:
    url = f"https://pypi.org/pypi/{package_name.replace('_', '-')}/json"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        return (data.get("info") or {}).get("version") or ""
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, ValueError):
        return ""


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
    latest = package.get("latestVersion", "") or ""
    if latest and latest != "latest":
        return latest
    versions = package.get("versions") or []
    latest_entry = next((v for v in versions if v.get("version") == latest), None) or (versions[0] if versions else None)
    if not latest_entry:
        return latest
    for file_name in latest_entry.get("files") or []:
        resolved = extract_version_from_filename(file_name)
        if resolved:
            return resolved
    return latest


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def run_silent(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=str(cwd) if cwd else None, check=True, capture_output=True, text=True)


def create_venv(venv_dir: Path) -> None:
    run_silent([sys.executable, "-m", "venv", str(venv_dir)])
    python = str(venv_python(venv_dir))
    run_silent([python, "-m", "pip", "install", "--quiet", "--upgrade", "pip"])


def pip_install(venv_dir: Path, spec: str) -> None:
    python = str(venv_python(venv_dir))
    run_silent([python, "-m", "pip", "install", "--quiet", spec])


def pip_freeze(venv_dir: Path, target: Path) -> None:
    python = str(venv_python(venv_dir))
    result = run_silent([python, "-m", "pip", "freeze"])
    target.write_text(result.stdout, encoding="utf-8")


def resolve_executable(command: str) -> str | None:
    resolved = shutil.which(command)
    if resolved:
        return resolved
    if os.name == "nt" and not command.lower().endswith((".cmd", ".exe", ".bat", ".ps1")):
        for suffix in (".cmd", ".exe", ".bat"):
            resolved = shutil.which(command + suffix)
            if resolved:
                return resolved
    return None


def run_snyk(snyk_cmd: str, requirements_path: Path, snyk_org: str, json_output: Path) -> tuple[int, str]:
    executable = resolve_executable(snyk_cmd)
    if not executable:
        return 127, (
            f"Snyk executable not found via PATH (looked up '{snyk_cmd}'). "
            "On Windows runners npm installs the 'snyk.cmd' shim; ensure it is on PATH."
        )
    command = [executable, "test", f"--file={requirements_path.name}", f"--json-file-output={json_output.name}"]
    if snyk_org:
        command.append(f"--org={snyk_org}")
    completed = subprocess.run(command, cwd=str(requirements_path.parent), capture_output=True, text=True)
    combined = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, combined


def normalize_findings(snyk_json_path: Path) -> list[dict]:
    if not snyk_json_path.exists():
        return []
    try:
        data = json.loads(snyk_json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    payloads = data if isinstance(data, list) else [data]
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for vuln in payload.get("vulnerabilities") or []:
            key = (vuln.get("id", ""), vuln.get("packageName", ""), vuln.get("version", ""))
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "id": vuln.get("id", ""),
                "title": vuln.get("title", ""),
                "severity": (vuln.get("severity") or "unknown").lower(),
                "package": vuln.get("packageName") or vuln.get("name", ""),
                "version": vuln.get("version", ""),
                "fixedIn": vuln.get("fixedIn") or [],
                "url": vuln.get("url", ""),
            })
    return findings


def count_severities(findings: list[dict]) -> dict:
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for finding in findings:
        if finding["severity"] in counts:
            counts[finding["severity"]] += 1
    return counts


def load_baseline(baselines_dir: Path, package_name: str) -> dict | None:
    path = baselines_dir / f"{package_name}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def save_baseline(baselines_dir: Path, package_name: str, baseline: dict) -> None:
    baselines_dir.mkdir(parents=True, exist_ok=True)
    path = baselines_dir / f"{package_name}.json"
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def finding_key(finding: dict) -> str:
    return f"{finding.get('id', '')}|{finding.get('package', '')}|{finding.get('version', '')}"


def compute_delta(baseline_findings: list[dict], current_findings: list[dict]) -> dict:
    baseline_by_key = {finding_key(f): f for f in baseline_findings}
    current_by_key = {finding_key(f): f for f in current_findings}
    new_keys = current_by_key.keys() - baseline_by_key.keys()
    resolved_keys = baseline_by_key.keys() - current_by_key.keys()
    severity_changed: list[dict] = []
    for key in current_by_key.keys() & baseline_by_key.keys():
        if current_by_key[key]["severity"] != baseline_by_key[key]["severity"]:
            severity_changed.append({
                "key": key,
                "from": baseline_by_key[key]["severity"],
                "to": current_by_key[key]["severity"],
                "title": current_by_key[key]["title"],
                "package": current_by_key[key]["package"],
            })
    return {
        "new": [current_by_key[k] for k in sorted(new_keys)],
        "resolved": [baseline_by_key[k] for k in sorted(resolved_keys)],
        "severityChanged": severity_changed,
    }


def classify_status(delta: dict, scan_error: str, version_drift: bool) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if scan_error:
        return "error", [scan_error]
    blocking = any(finding.get("severity") in ("critical", "high") for finding in delta["new"])
    severity_escalated = any(
        SEVERITY_RANK.get(change["to"], 5) < SEVERITY_RANK.get(change["from"], 5)
        for change in delta["severityChanged"]
    )
    if blocking:
        reasons.append("New critical or high vulnerability detected")
    if severity_escalated:
        reasons.append("Existing vulnerability severity increased")
    if version_drift:
        reasons.append("Upstream PyPI version is newer than validated version")
    if reasons:
        return "review-candidate", reasons
    if delta["new"] or delta["resolved"] or delta["severityChanged"]:
        return "changes-detected", ["Findings changed but no new blocking items"]
    return "unchanged", []


def scan_package(args: argparse.Namespace, package_name: str, version: str) -> tuple[list[dict], str]:
    if args.skip_scan:
        return [], "Scan skipped via --skip-scan"
    work_dir = Path(tempfile.mkdtemp(prefix=f"audit-{package_name}-"))
    venv_dir = work_dir / "venv"
    try:
        create_venv(venv_dir)
        spec = f"{package_name}=={version}" if version and version != "latest" else package_name
        pip_install(venv_dir, spec)
        requirements_path = work_dir / "requirements.txt"
        pip_freeze(venv_dir, requirements_path)
        snyk_json = work_dir / "snyk.json"
        return_code, output = run_snyk(args.snyk_cmd, requirements_path, args.snyk_org, snyk_json)
        if return_code not in (0, 1):
            tail = " | ".join(output.strip().splitlines()[-5:]) or "no output"
            return [], f"Snyk scan failed (exit {return_code}): {tail}"
        return normalize_findings(snyk_json), ""
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip().splitlines()[-3:]
        message = " | ".join(stderr) if stderr else f"exit {exc.returncode}"
        return [], f"Setup command failed ({' '.join(exc.cmd[:3])}): {message}"


def build_report(args: argparse.Namespace) -> dict:
    manifest = load_manifest(Path(args.manifest))
    baselines_dir = Path(args.baselines_dir)
    packages = manifest.get("packages", {})
    records: list[dict] = []

    for package_name in sorted(packages, key=str.lower):
        package = packages[package_name]
        if package.get("lifecycleState", "active") != "active":
            continue

        resolved_version = resolve_validated_version(package)
        upstream_version = fetch_pypi_version(package_name)
        version_drift = bool(upstream_version and resolved_version and upstream_version != resolved_version)

        baseline = load_baseline(baselines_dir, package_name)
        baseline_findings = (baseline or {}).get("findings", [])

        print(f"[nightly-audit] scanning {package_name}=={resolved_version or 'latest'}")
        current_findings, scan_error = scan_package(args, package_name, resolved_version)
        delta = compute_delta(baseline_findings, current_findings)
        status, reasons = classify_status(delta, scan_error, version_drift)

        records.append({
            "package": package_name,
            "validatedVersion": resolved_version,
            "upstreamVersion": upstream_version,
            "versionDrift": version_drift,
            "scanStatus": "error" if scan_error else "ok",
            "scanError": scan_error,
            "status": status,
            "reasons": reasons,
            "currentCounts": count_severities(current_findings),
            "baselineCounts": count_severities(baseline_findings) if baseline else None,
            "baselineDate": (baseline or {}).get("scannedAt", ""),
            "delta": delta,
            "findings": current_findings,
        })

        if not scan_error:
            save_baseline(baselines_dir, package_name, {
                "package": package_name,
                "version": resolved_version,
                "scannedAt": today_utc(),
                "counts": count_severities(current_findings),
                "findings": current_findings,
            })

    summary = {
        "totalPackages": len(records),
        "reviewCandidates": sum(1 for r in records if r["status"] == "review-candidate"),
        "changesDetected": sum(1 for r in records if r["status"] == "changes-detected"),
        "unchanged": sum(1 for r in records if r["status"] == "unchanged"),
        "errors": sum(1 for r in records if r["status"] == "error"),
    }

    return {"generatedAt": today_utc(), "summary": summary, "packages": records}


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Nightly Package Audit",
        "",
        f"Generated: {now_display()}",
        "",
        "## Summary",
        "",
        f"- Total active packages scanned: {summary['totalPackages']}",
        f"- Review candidates: {summary['reviewCandidates']}",
        f"- Changes detected (non-blocking): {summary['changesDetected']}",
        f"- Unchanged: {summary['unchanged']}",
        f"- Scan errors: {summary['errors']}",
        "",
    ]

    review_candidates = [p for p in report["packages"] if p["status"] == "review-candidate"]
    if review_candidates:
        lines.extend([
            "## Review Candidates",
            "",
            "| Package | Validated | Upstream | New Crit/High | Reasons |",
            "|---------|-----------|----------|---------------|---------|",
        ])
        for pkg in review_candidates:
            blocking = sum(1 for f in pkg["delta"]["new"] if f["severity"] in ("critical", "high"))
            reasons = "; ".join(pkg["reasons"]) or "-"
            lines.append(
                f"| `{pkg['package']}` | `{pkg['validatedVersion']}` | `{pkg['upstreamVersion'] or 'unknown'}` | {blocking} | {reasons} |"
            )
        lines.append("")

    error_packages = [p for p in report["packages"] if p["status"] == "error"]
    if error_packages:
        lines.extend([
            "## Scan Errors",
            "",
            "| Package | Version | Error |",
            "|---------|---------|-------|",
        ])
        for pkg in error_packages:
            lines.append(f"| `{pkg['package']}` | `{pkg['validatedVersion']}` | {pkg['scanError']} |")
        lines.append("")

    lines.extend(["## Per-Package Detail", ""])
    for pkg in report["packages"]:
        lines.append(f"### `{pkg['package']}` ({pkg['status']})")
        lines.append("")
        lines.append(f"- Validated version: `{pkg['validatedVersion']}`")
        lines.append(f"- Upstream PyPI version: `{pkg['upstreamVersion'] or 'unknown'}`")
        lines.append(f"- Baseline: {pkg['baselineDate'] or 'no prior baseline'}")
        counts = pkg["currentCounts"]
        lines.append(
            f"- Current findings: critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, low={counts['low']}"
        )
        delta = pkg["delta"]
        if delta["new"]:
            lines.append(f"- New findings: {len(delta['new'])}")
            for finding in delta["new"][:10]:
                ref = finding.get("url") or ""
                lines.append(
                    f"  - `{finding['severity']}` `{finding['package']}@{finding['version']}` {finding['title']} {ref}".rstrip()
                )
            if len(delta["new"]) > 10:
                lines.append(f"  - ... and {len(delta['new']) - 10} more")
        if delta["resolved"]:
            lines.append(f"- Resolved findings: {len(delta['resolved'])}")
        if delta["severityChanged"]:
            lines.append(f"- Severity changes: {len(delta['severityChanged'])}")
            for change in delta["severityChanged"][:10]:
                lines.append(
                    f"  - `{change['package']}` {change['from']} -> {change['to']} ({change['title']})"
                )
        if pkg["scanError"]:
            lines.append(f"- Scan error: {pkg['scanError']}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Nightly per-package vulnerability audit with baseline deltas.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--baselines-dir", default="audit-baselines")
    parser.add_argument("--snyk-cmd", default=os.environ.get("SNYK_CMD", "snyk"))
    parser.add_argument("--snyk-org", default=os.environ.get("SNYK_ORG", ""))
    parser.add_argument("--skip-scan", action="store_true")
    args = parser.parse_args()

    report = build_report(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "nightly-audit.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output_dir / "nightly-audit.md").write_text(render_markdown(report) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())