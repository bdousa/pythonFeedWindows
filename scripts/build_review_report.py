#!/usr/bin/env python3

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "PythonFeed-Update Review Bot"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LEVELS = ("critical", "high", "medium", "low")


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


def http_get_json(url: str, headers: dict | None = None, timeout: int = 30):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
        return json.loads(body), dict(response.headers.items())


def http_get_json_silent(url: str, headers: dict | None = None, timeout: int = 30):
    try:
        return http_get_json(url, headers, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, ValueError):
        return None, None


def fetch_pypi_metadata(package_name: str) -> dict:
    url = f"https://pypi.org/pypi/{package_name.replace('_', '-')}/json"
    data, _ = http_get_json_silent(url)
    return data or {}


def fetch_download_counts(package_name: str) -> dict | None:
    url = f"https://pypistats.org/api/packages/{package_name.replace('_', '-').lower()}/recent"
    data, _ = http_get_json_silent(url)
    if not isinstance(data, dict):
        return None
    return data.get("data") or None


def github_request_headers(token: str | None) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def extract_github_repo(info: dict) -> tuple[str, str] | None:
    candidates: list[str] = []
    for key in ("home_page", "download_url", "project_url"):
        value = info.get(key)
        if value:
            candidates.append(value)
    for value in (info.get("project_urls") or {}).values():
        if value:
            candidates.append(value)
    for url in candidates:
        match = re.match(r"^https?://github\.com/([^/]+)/([^/#?]+)", url)
        if match:
            owner = match.group(1)
            repo = re.sub(r"\.git$", "", match.group(2))
            return owner, repo
    return None


def fetch_github_repo_info(owner: str, repo: str, token: str | None) -> dict:
    headers = github_request_headers(token)
    result: dict = {"owner": owner, "repo": repo, "url": f"https://github.com/{owner}/{repo}"}

    repo_data, _ = http_get_json_silent(f"https://api.github.com/repos/{owner}/{repo}", headers)
    if isinstance(repo_data, dict):
        result["language"] = repo_data.get("language") or "unknown"
        result["defaultBranch"] = repo_data.get("default_branch", "")
        result["stars"] = repo_data.get("stargazers_count")
        result["openIssues"] = repo_data.get("open_issues_count")
        result["forks"] = repo_data.get("forks_count")
        result["pushedAt"] = repo_data.get("pushed_at", "")
        result["description"] = repo_data.get("description", "")
        result["archived"] = repo_data.get("archived", False)

    commits_data, _ = http_get_json_silent(
        f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1", headers
    )
    if isinstance(commits_data, list) and commits_data:
        commit = commits_data[0]
        commit_info = commit.get("commit") or {}
        committer = commit_info.get("committer") or {}
        result["lastCommitDate"] = committer.get("date", "")
        result["lastCommitSha"] = commit.get("sha", "")
        first_line = (commit_info.get("message") or "").splitlines()[0] if commit_info.get("message") else ""
        result["lastCommitMessage"] = first_line[:200]

    contributors_payload, contributors_headers = http_get_json_silent(
        f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=1&anon=true", headers
    )
    contributors_count = None
    if contributors_headers:
        link_header = contributors_headers.get("Link") or contributors_headers.get("link") or ""
        match = re.search(r"[?&]page=(\d+)[^>]*>;\s*rel=\"last\"", link_header)
        if match:
            contributors_count = int(match.group(1))
    if contributors_count is None and isinstance(contributors_payload, list):
        contributors_count = len(contributors_payload)
    result["contributorsCount"] = contributors_count
    return result


def load_manifest_preview(path: Path, package_name: str) -> dict:
    if not path or not path.exists():
        return {}
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    package = (manifest.get("packages") or {}).get(package_name) or {}
    latest_version = package.get("latestVersion", "")
    versions = package.get("versions") or []
    latest_entry = next((entry for entry in versions if entry.get("version") == latest_version), None)
    if latest_entry is None and versions:
        latest_entry = versions[0]
    if not latest_entry:
        return {}
    return {
        "version": latest_entry.get("version", ""),
        "installUrl": latest_entry.get("installUrl", ""),
        "packageType": latest_entry.get("packageType", ""),
        "releaseTag": latest_entry.get("releaseTag", ""),
        "releaseUrl": latest_entry.get("releaseUrl", ""),
        "files": latest_entry.get("files", []),
    }


def list_package_files(package_dir: Path) -> list[str]:
    if not package_dir or not package_dir.exists():
        return []
    return sorted(p.name for p in package_dir.iterdir() if p.is_file())


def read_text(path: Path) -> str:
    if not path or not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def parse_severity_counts(text: str) -> dict:
    counts = {level: 0 for level in SEVERITY_LEVELS}
    if not text:
        return counts
    lowered = text.lower()
    for severity in SEVERITY_LEVELS:
        matches = re.findall(rf"(\d+)\s+{severity}", lowered)
        if matches:
            counts[severity] = max(int(value) for value in matches)
    return counts


def load_snyk_dependency_findings(path: Path) -> list[dict]:
    if not path or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    payloads = data if isinstance(data, list) else [data]
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for vuln in payload.get("vulnerabilities") or []:
            identifiers = vuln.get("identifiers") or {}
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
                "identifiers": identifiers,
                "url": vuln.get("url", ""),
                "from": vuln.get("from") or [],
            })
    return findings


def load_snyk_code_findings(path: Path) -> list[dict]:
    if not path or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list):
        return []
    severity_map = {"error": "high", "warning": "medium", "note": "low"}
    findings: list[dict] = []
    for run in runs:
        rules = {rule.get("id"): rule for rule in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
        for result in run.get("results") or []:
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            level = (result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning").lower()
            severity = severity_map.get(level, level)
            message = (result.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text", "")
            locations = []
            for loc in result.get("locations") or []:
                physical = loc.get("physicalLocation") or {}
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region") or {}
                uri = artifact.get("uri", "")
                start = region.get("startLine")
                locations.append(f"{uri}:{start}" if start else uri)
            findings.append({
                "ruleId": rule_id,
                "title": rule.get("shortDescription", {}).get("text", "") or rule_id,
                "severity": severity,
                "message": message,
                "locations": locations,
            })
    return findings


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


def evaluate_os_compatibility(classifiers: list[str]) -> dict:
    os_classifiers = [item for item in classifiers if item.startswith("Operating System ::")]
    labels = [item.split("::")[-1].strip() for item in os_classifiers]
    summary = {
        "classifiers": os_classifiers,
        "labels": labels,
        "windowsCompatible": False,
        "osIndependent": False,
        "otherOsOnly": False,
        "missing": not os_classifiers,
        "status": "pass",
        "notes": [],
    }
    if not os_classifiers:
        summary["status"] = "review"
        summary["notes"].append("No OS classifiers declared")
        return summary

    summary["osIndependent"] = any("OS Independent" in c for c in os_classifiers)
    summary["windowsCompatible"] = any("Microsoft" in c and "Windows" in c for c in os_classifiers)

    other_os_tokens = ["POSIX", "Linux", "MacOS", "Mac OS", "Unix", "BSD", "iOS", "Android"]
    has_other_os = any(any(token in c for token in other_os_tokens) for c in os_classifiers)
    only_other_os = has_other_os and not summary["windowsCompatible"] and not summary["osIndependent"]
    summary["otherOsOnly"] = only_other_os

    if summary["osIndependent"] or summary["windowsCompatible"]:
        summary["status"] = "pass"
        if has_other_os and not summary["osIndependent"]:
            summary["notes"].append("Declares other OS classifiers alongside Windows; verify the chosen artifact is the Windows build")
    elif only_other_os:
        summary["status"] = "block"
        summary["notes"].append("Package declares only non-Windows operating systems")
    else:
        summary["status"] = "review"
        summary["notes"].append("Could not confirm Windows compatibility from classifiers")
    return summary


def build_recommendation(dep_counts, code_counts, last_release_days, license_status, os_status):
    reasons: list[str] = []
    if dep_counts["critical"] > 0 or code_counts["critical"] > 0:
        reasons.append("Critical security findings detected")
        return "reject", reasons
    if os_status == "block":
        reasons.append("Package is not compatible with the Windows feed")
        return "reject", reasons
    if dep_counts["high"] > 0 or code_counts["high"] > 0:
        reasons.append("High severity findings require explicit review")
    if last_release_days is not None and last_release_days > 365:
        reasons.append("Package has not shipped an upstream release in over a year")
    if license_status == "review":
        reasons.append("License posture requires review")
    if os_status == "review":
        reasons.append("OS compatibility metadata requires review")
    if reasons:
        return "review", reasons
    return "approve", ["No critical or high severity blockers detected", "Metadata looks consistent with current policy"]


def build_report(args: argparse.Namespace) -> dict:
    pypi = fetch_pypi_metadata(args.package_name)
    info = pypi.get("info", {}) if pypi else {}
    releases = pypi.get("releases", {}) if pypi else {}
    classifiers = info.get("classifiers") or []

    release_dates = []
    for files in releases.values():
        for file_info in files or []:
            parsed = safe_parse_iso(file_info.get("upload_time") or file_info.get("upload_time_iso_8601") or "")
            if parsed:
                release_dates.append(parsed)
    first_release_date = ""
    latest_release_date = ""
    package_age_days = None
    last_release_days = None
    if release_dates:
        first_release = min(release_dates)
        latest_release = max(release_dates)
        first_release_date = first_release.strftime("%Y-%m-%d")
        latest_release_date = latest_release.strftime("%Y-%m-%d")
        now_utc = datetime.now(timezone.utc)
        package_age_days = (now_utc - first_release).days
        last_release_days = (now_utc - latest_release).days
    recent_release_count = sum(
        1 for d in release_dates if (datetime.now(timezone.utc) - d).days <= 180
    )

    license_status, license_reasons = detect_license_risk(info.get("license", ""), classifiers)
    license_summary = summarize_license(info.get("license", ""), classifiers)
    os_summary = evaluate_os_compatibility(classifiers)

    source_repo = extract_github_repo(info)
    github_info: dict = {}
    if source_repo:
        owner, repo = source_repo
        github_info = fetch_github_repo_info(owner, repo, args.github_token or os.environ.get("GITHUB_TOKEN"))

    download_counts = fetch_download_counts(args.package_name)

    dep_text = read_text(Path(args.snyk_dependencies_summary))
    code_text = read_text(Path(args.snyk_code_summary))
    dep_counts = parse_severity_counts(dep_text)
    code_counts = parse_severity_counts(code_text)

    dep_findings = load_snyk_dependency_findings(Path(args.snyk_dependencies_json)) if args.snyk_dependencies_json else []
    code_findings = load_snyk_code_findings(Path(args.snyk_code_json)) if args.snyk_code_json else []

    if dep_findings:
        json_counts = {level: 0 for level in SEVERITY_LEVELS}
        for finding in dep_findings:
            if finding["severity"] in json_counts:
                json_counts[finding["severity"]] += 1
        dep_counts = json_counts
    if code_findings:
        json_counts = {level: 0 for level in SEVERITY_LEVELS}
        for finding in code_findings:
            if finding["severity"] in json_counts:
                json_counts[finding["severity"]] += 1
        code_counts = json_counts

    requirements_text = read_text(Path(args.requirements))
    dependency_lines = [
        line.strip() for line in requirements_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    manifest_preview = load_manifest_preview(Path(args.manifest_preview), args.package_name) if args.manifest_preview else {}
    if manifest_preview.get("files"):
        package_files = manifest_preview["files"]
    elif args.package_dir:
        package_files = list_package_files(Path(args.package_dir))
    else:
        package_files = []

    recommendation, recommendation_reasons = build_recommendation(
        dep_counts, code_counts, last_release_days, license_status, os_summary["status"]
    )

    reasons: list[str] = []
    reasons.extend(license_reasons)
    reasons.extend(recommendation_reasons)
    reasons.extend(os_summary["notes"])

    project_urls = info.get("project_urls") or {}
    source_repo_url = (
        project_urls.get("Source")
        or project_urls.get("Source Code")
        or project_urls.get("Repository")
        or project_urls.get("Code")
        or (github_info.get("url") if github_info else "")
    )

    return {
        "packageName": args.package_name,
        "requestedVersion": args.package_version,
        "reportDate": utc_today(),
        "runUrl": args.run_url,
        "recommendation": recommendation,
        "reasons": reasons,
        "install": {
            "command": manifest_preview.get("installUrl", ""),
            "packageType": manifest_preview.get("packageType", ""),
            "releaseTag": manifest_preview.get("releaseTag", ""),
            "releaseUrl": manifest_preview.get("releaseUrl", ""),
            "validatedVersion": manifest_preview.get("version", ""),
        },
        "metadata": {
            "name": info.get("name", args.package_name),
            "latestVersion": info.get("version", ""),
            "summary": info.get("summary", ""),
            "author": info.get("author") or "",
            "authorEmail": info.get("author_email") or "",
            "maintainer": info.get("maintainer") or "",
            "maintainerEmail": info.get("maintainer_email") or "",
            "license": info.get("license", "") or "",
            "licenseSummary": license_summary,
            "licenseClassifiers": [c.split("::")[-1].strip() for c in classifiers if c.startswith("License ::")],
            "requiresPython": info.get("requires_python") or "",
            "projectUrl": info.get("project_url") or info.get("home_page") or f"https://pypi.org/project/{args.package_name}/",
            "homePage": info.get("home_page") or "",
            "documentationUrl": project_urls.get("Documentation") or project_urls.get("Docs") or "",
            "sourceRepoUrl": source_repo_url,
            "classifiers": classifiers,
            "osCompatibility": os_summary,
            "firstReleaseDate": first_release_date,
            "latestReleaseDate": latest_release_date,
            "packageAgeDays": package_age_days,
            "daysSinceLatestRelease": last_release_days,
            "totalReleases": len(releases or {}),
            "recentReleases180d": recent_release_count,
            "files": package_files,
        },
        "github": github_info,
        "downloads": download_counts,
        "snyk": {
            "dependencies": {"counts": dep_counts, "findings": dep_findings, "rawSummary": dep_text},
            "code": {"counts": code_counts, "findings": code_findings, "rawSummary": code_text},
        },
        "dependencies": {
            "totalReviewed": len(dependency_lines),
            "lines": dependency_lines,
        },
    }


def recommendation_badge(value: str) -> str:
    mapping = {"approve": "APPROVE", "review": "REVIEW REQUIRED", "reject": "REJECT"}
    return mapping.get(value.lower(), value.upper())


def os_status_label(status: str) -> str:
    return {"pass": "Compatible", "review": "Review needed", "block": "Incompatible"}.get(status, status)


def format_number(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value) if value not in (None, "") else "unknown"


def truncate(text: str, limit: int = 6000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n... (truncated)"


def severity_rank(finding: dict) -> int:
    return SEVERITY_ORDER.get((finding.get("severity") or "").lower(), 9)


def render_ai_security_review(ai_review: dict) -> list[str]:
    lines: list[str] = []
    status = (ai_review.get("status") or "").lower()
    model = ai_review.get("model") or ""
    generated_at = ai_review.get("generatedAt") or ""
    lines.append("## AI Security Review")
    lines.append("")
    lines.append("> Advisory only. The human approver makes the final approve/reject decision.")
    lines.append("")
    if status != "ok":
        reason = ai_review.get("reason") or "AI security review was not available for this run."
        lines.append(f"- Status: **unavailable**")
        if model:
            lines.append(f"- Model: `{model}`")
        if generated_at:
            lines.append(f"- Attempted at: {generated_at}")
        lines.append(f"- Reason: {reason}")
        if ai_review.get("rawResponsePreview"):
            lines.append("")
            lines.append("<details><summary>Raw model response (truncated)</summary>")
            lines.append("")
            lines.append("```")
            lines.append(str(ai_review["rawResponsePreview"]))
            lines.append("```")
            lines.append("")
            lines.append("</details>")
        lines.append("")
        return lines

    verdict = ai_review.get("verdict") or "review-needed"
    verdict_label = {
        "low-concern": "Low concern",
        "review-needed": "Review needed",
        "high-concern": "High concern",
    }.get(verdict, verdict)
    confidence = ai_review.get("confidence") or "medium"
    lines.append(f"**Verdict:** {verdict_label}  •  **Confidence:** {confidence}")
    lines.append("")
    if model or generated_at:
        meta_bits = []
        if model:
            meta_bits.append(f"model `{model}`")
        if generated_at:
            meta_bits.append(f"generated {generated_at}")
        lines.append(f"_Generated by AI reviewer ({', '.join(meta_bits)})._")
        lines.append("")
    summary = ai_review.get("summary") or ""
    if summary:
        lines.append(summary)
        lines.append("")

    key_points = ai_review.get("keyPoints") or []
    if key_points:
        lines.append("**Key Points**")
        lines.append("")
        for point in key_points:
            lines.append(f"- {point}")
        lines.append("")

    concerning = ai_review.get("concerningFindings") or []
    if concerning:
        lines.append("**Findings That May Be Concerning**")
        lines.append("")
        for item in concerning:
            reference = item.get("reference") or item.get("evidence") or ""
            reasoning = item.get("reasoning") or ""
            lines.append(f"- _Reference:_ `{reference}`")
            if reasoning:
                lines.append(f"  _Reasoning:_ {reasoning}")
        lines.append("")

    benign = ai_review.get("likelyBenignFindings") or []
    if benign:
        lines.append("**Findings That Appear Likely Benign**")
        lines.append("")
        for item in benign:
            reference = item.get("reference") or item.get("evidence") or ""
            reasoning = item.get("reasoning") or ""
            lines.append(f"- _Reference:_ `{reference}`")
            if reasoning:
                lines.append(f"  _Reasoning:_ {reasoning}")
        lines.append("")

    notes = ai_review.get("approverNotes") or []
    if notes:
        lines.append("**Notes for the Human Approver**")
        lines.append("")
        for note in notes:
            lines.append(f"- {note}")
        lines.append("")

    return lines


def render_markdown(report: dict) -> str:
    metadata = report["metadata"]
    install = report["install"]
    github = report["github"] or {}
    downloads = report["downloads"] or {}
    snyk = report["snyk"]
    os_compat = metadata["osCompatibility"]
    dep_counts = snyk["dependencies"]["counts"]
    code_counts = snyk["code"]["counts"]

    lines: list[str] = []
    lines.append(f"# Approval Report: {report['packageName']}")
    lines.append("")
    lines.append(f"**Recommendation:** {recommendation_badge(report['recommendation'])}")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Package | `{report['packageName']}` |")
    lines.append(f"| Requested version | `{report['requestedVersion']}` |")
    lines.append(f"| Validated version | `{install.get('validatedVersion') or metadata.get('latestVersion') or 'unknown'}` |")
    lines.append(f"| Latest upstream version | `{metadata.get('latestVersion') or 'unknown'}` |")
    lines.append(f"| Report date | {report['reportDate']} |")
    lines.append(f"| Workflow run | {report['runUrl']} |")
    if install.get("releaseUrl"):
        lines.append(f"| Release | {install['releaseUrl']} |")
    lines.append("")

    ai_review = report.get("aiSecurityReview")
    if ai_review:
        lines.extend(render_ai_security_review(ai_review))

    lines.append("## Installation")
    lines.append("")
    if install.get("command"):
        lines.append("```bash")
        lines.append(install["command"])
        lines.append("```")
        lines.append("")
    else:
        lines.append("_Install command not available yet; preview manifest was not provided._")
        lines.append("")
    if install.get("packageType"):
        lines.append(f"- Package type: `{install['packageType']}`")
    lines.append("- Prerequisites: Python 3.13.x, Windows 64-bit")
    lines.append("")

    lines.append("## Package Analysis")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Name | `{metadata['name']}` |")
    lines.append(f"| Summary | {metadata['summary'] or '_not provided_'} |")
    author_value = metadata['author'] or '_not provided_'
    if metadata['authorEmail']:
        author_value = f"{author_value} <{metadata['authorEmail']}>"
    lines.append(f"| Author | {author_value} |")
    maintainer_value = metadata['maintainer'] or '_same as author_'
    if metadata['maintainerEmail']:
        maintainer_value = f"{maintainer_value} <{metadata['maintainerEmail']}>"
    lines.append(f"| Maintainer | {maintainer_value} |")
    lines.append(f"| License | `{metadata['licenseSummary']}` |")
    if metadata['licenseClassifiers']:
        lines.append(f"| License classifiers | {', '.join(metadata['licenseClassifiers'])} |")
    lines.append(f"| Required interpreter | `{metadata['requiresPython'] or 'unspecified'}` |")
    lines.append(f"| Project URL | {metadata['projectUrl'] or '_not provided_'} |")
    if metadata['homePage']:
        lines.append(f"| Home page | {metadata['homePage']} |")
    if metadata['sourceRepoUrl']:
        lines.append(f"| Source repository | {metadata['sourceRepoUrl']} |")
    if metadata['documentationUrl']:
        lines.append(f"| Documentation | {metadata['documentationUrl']} |")
    lines.append(f"| OS compatibility | {os_status_label(os_compat['status'])} |")
    if os_compat['labels']:
        lines.append(f"| OS classifiers | {', '.join(os_compat['labels'])} |")
    if downloads:
        last_day = downloads.get('last_day')
        last_week = downloads.get('last_week')
        last_month = downloads.get('last_month')
        downloads_cell = f"day={format_number(last_day)}, week={format_number(last_week)}, month={format_number(last_month)}"
        lines.append(f"| Downloads (pypistats.org) | {downloads_cell} |")
    lines.append("")

    lines.append("### Source Repository Insights")
    lines.append("")
    if github:
        lines.append(f"- Repository: {github.get('url', '')}")
        lines.append(f"- Primary language: `{github.get('language') or 'unknown'}`")
        lines.append(f"- Last commit: {github.get('lastCommitDate') or 'unknown'}")
        lines.append(f"- Contributors: {format_number(github.get('contributorsCount'))}")
        if github.get('stars') is not None:
            lines.append(f"- Stars: {format_number(github.get('stars'))}")
        if github.get('forks') is not None:
            lines.append(f"- Forks: {format_number(github.get('forks'))}")
        if github.get('openIssues') is not None:
            lines.append(f"- Open issues: {format_number(github.get('openIssues'))}")
        if github.get('archived'):
            lines.append("- Repository is archived")
        if github.get('lastCommitMessage'):
            lines.append(f"- Last commit message: {github['lastCommitMessage']}")
    else:
        lines.append("- No GitHub source repository could be resolved from PyPI metadata.")
    lines.append("")

    lines.append("## Security Risk Assessment")
    lines.append("")
    if metadata.get("packageAgeDays") is not None:
        years = metadata['packageAgeDays'] // 365
        lines.append(f"- Package age: {metadata['packageAgeDays']} days (~{years} years)")
    if metadata.get("daysSinceLatestRelease") is not None:
        days = metadata['daysSinceLatestRelease']
        if days > 365:
            label = "CRITICAL: No release in over a year"
        elif days > 180:
            label = "WARNING: No release in over 6 months"
        elif days > 90:
            label = "CAUTION: No release in over 3 months"
        else:
            label = "OK: Recently maintained"
        lines.append(f"- Days since latest upstream release: {days} ({label})")
    if metadata.get("recentReleases180d") is not None:
        lines.append(f"- Recent releases (last 180 days): {metadata['recentReleases180d']}")
    if metadata.get("totalReleases"):
        lines.append(f"- Total upstream releases on PyPI: {metadata['totalReleases']}")
    lines.append(f"- License posture: `{metadata['licenseSummary']}`")
    lines.append(f"- OS compatibility posture: {os_status_label(os_compat['status'])}")
    for note in os_compat['notes']:
        lines.append(f"  - {note}")
    lines.append("")

    lines.append("## OS Compatibility Policy")
    lines.append("")
    lines.append("- OK: Packages marked `OS Independent`")
    lines.append("- OK: Packages with `Microsoft :: Windows` classifiers")
    lines.append("- Review: Packages without any OS classifiers")
    lines.append("- Block: Packages that declare only non-Windows operating systems")
    lines.append("")
    lines.append(f"This package: **{os_status_label(os_compat['status'])}**")
    if os_compat['osIndependent']:
        lines.append("- OS Independent: yes")
    if os_compat['windowsCompatible']:
        lines.append("- Windows compatible: yes")
    if os_compat['otherOsOnly']:
        lines.append("- Declares only non-Windows operating systems")
    if os_compat['missing']:
        lines.append("- Missing OS classifiers")
    lines.append("")

    lines.append("## Dependency Overview")
    lines.append("")
    lines.append(f"- Total dependencies installed for scan: {report['dependencies']['totalReviewed']}")
    lines.append(f"- Package being reviewed: `{report['packageName']}`")
    if report['dependencies']['lines']:
        lines.append("")
        lines.append("<details><summary>Installed packages (pip freeze)</summary>")
        lines.append("")
        lines.append("```")
        for entry in report['dependencies']['lines']:
            lines.append(entry)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
    lines.append("")

    lines.append("## Vulnerability Summary")
    lines.append("")
    lines.append("| Severity | Dependencies | Source code |")
    lines.append("|----------|--------------|-------------|")
    for severity in SEVERITY_LEVELS:
        lines.append(f"| {severity.title()} | {dep_counts.get(severity, 0)} | {code_counts.get(severity, 0)} |")
    lines.append("")

    dep_findings = snyk["dependencies"]["findings"]
    if dep_findings:
        lines.append("### Dependency Vulnerabilities")
        lines.append("")
        lines.append("| Severity | Package | Version | Title | Fix | Reference |")
        lines.append("|----------|---------|---------|-------|-----|-----------|")
        for finding in sorted(dep_findings, key=severity_rank):
            fix_list = finding.get("fixedIn") or []
            fix_display = ", ".join(fix_list) if fix_list else "no fix"
            reference = finding.get("url") or ""
            if not reference:
                identifiers = finding.get("identifiers") or {}
                cves = identifiers.get("CVE") if isinstance(identifiers, dict) else None
                if cves:
                    reference = cves[0]
            title = (finding.get("title") or "").replace("|", "\\|")
            lines.append(
                f"| {finding['severity']} | `{finding['package']}` | `{finding['version']}` | {title} | {fix_display} | {reference or '-'} |"
            )
        lines.append("")
    else:
        lines.append("### Dependency Vulnerabilities")
        lines.append("")
        lines.append("- No structured Snyk dependency findings parsed.")
        lines.append("")

    code_findings = snyk["code"]["findings"]
    if code_findings:
        lines.append("### Source Code Findings")
        lines.append("")
        lines.append("| Severity | Rule | Location | Message |")
        lines.append("|----------|------|----------|---------|")
        for finding in sorted(code_findings, key=severity_rank):
            location = finding["locations"][0] if finding["locations"] else "-"
            message = (finding.get("message") or "").replace("|", "\\|")
            lines.append(
                f"| {finding['severity']} | `{finding['ruleId']}` | `{location}` | {message} |"
            )
        lines.append("")
    else:
        lines.append("### Source Code Findings")
        lines.append("")
        lines.append("- No structured Snyk source-code findings parsed.")
        lines.append("")

    lines.append("### Raw Snyk Output")
    lines.append("")
    lines.append("<details><summary>Dependency scan (raw)</summary>")
    lines.append("")
    lines.append("```")
    lines.append(truncate(snyk["dependencies"]["rawSummary"] or "(no output)"))
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    lines.append("<details><summary>Source code scan (raw)</summary>")
    lines.append("")
    lines.append("```")
    lines.append(truncate(snyk["code"]["rawSummary"] or "(no output)"))
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    lines.append("## Package Files")
    lines.append("")
    if metadata["files"]:
        for name in metadata["files"]:
            lines.append(f"- `{name}`")
    else:
        lines.append("- _no files captured_")
    lines.append("")

    lines.append("## Review Notes")
    lines.append("")
    if report["reasons"]:
        for reason in report["reasons"]:
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
    parser.add_argument("--snyk-dependencies-json", default="")
    parser.add_argument("--snyk-code-json", default="")
    parser.add_argument("--manifest-preview", default="")
    parser.add_argument("--package-dir", default="")
    parser.add_argument("--github-token", default="")
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
