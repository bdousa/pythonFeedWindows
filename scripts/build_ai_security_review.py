#!/usr/bin/env python3

"""Run an advisory AI security review over the generated approval report.

Reads review_output/approval-report.json, builds an evidence-only prompt from
the structured Snyk + package data, calls Azure AI Foundry, parses the JSON
response, then injects an ``aiSecurityReview`` block into the report JSON and
regenerates the Markdown using the same renderer that produced it originally.
Fails open: on any error the script still updates the report with an
``unavailable`` status block and exits zero so the workflow continues.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_review_report import render_markdown  # noqa: E402

DEFAULT_API_VERSION = "v1"
MAX_DEP_FINDINGS = 30
MAX_CODE_FINDINGS = 30
MESSAGE_TRUNCATE = 320
REPORT_MARKDOWN_TRUNCATE = 20000
REQUEST_TIMEOUT = 90
MAX_CATALOG_ARTIFACTS = 6
MAX_LIKELY_ALTERNATIVES = 12
CATALOG_DOMAIN_TERMS = {
    "ai",
    "api",
    "async",
    "audio",
    "azure",
    "cli",
    "csv",
    "data",
    "docx",
    "excel",
    "html",
    "http",
    "image",
    "json",
    "lake",
    "langchain",
    "llm",
    "ml",
    "openai",
    "pdf",
    "spark",
    "sql",
    "test",
    "xml",
    "yaml",
}
CATALOG_STOP_TERMS = {
    "abi3",
    "amd64",
    "any",
    "cp310",
    "cp311",
    "cp312",
    "cp313",
    "for",
    "high",
    "library",
    "linux",
    "manylinux",
    "none",
    "package",
    "performance",
    "py2",
    "py3",
    "python",
    "thon",
    "universal",
    "wheel",
    "whl",
    "win",
    "win32",
    "x64",
    "x86",
}


def truncate_text(value: str, limit: int = MESSAGE_TRUNCATE) -> str:
    if not value:
        return ""
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def truncate_block(value: str, limit: int = REPORT_MARKDOWN_TRUNCATE) -> str:
    if not value:
        return ""
    if len(value) <= limit:
        return value
    return value[: limit - 80].rstrip() + "\n\n... (approval report markdown truncated)"


def shrink_dep_findings(findings: list[dict]) -> list[dict]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_rank.get((f.get("severity") or "unknown").lower(), 9))
    trimmed: list[dict] = []
    for finding in sorted_findings[:MAX_DEP_FINDINGS]:
        trimmed.append({
            "id": finding.get("id", ""),
            "severity": (finding.get("severity") or "unknown").lower(),
            "package": finding.get("package", ""),
            "version": finding.get("version", ""),
            "title": truncate_text(finding.get("title") or ""),
            "fixedIn": finding.get("fixedIn") or [],
            "url": finding.get("url") or "",
        })
    return trimmed


def shrink_code_findings(findings: list[dict]) -> list[dict]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_rank.get((f.get("severity") or "unknown").lower(), 9))
    trimmed: list[dict] = []
    for finding in sorted_findings[:MAX_CODE_FINDINGS]:
        locations = finding.get("locations") or []
        first_location = locations[0] if locations else ""
        trimmed.append({
            "severity": (finding.get("severity") or "unknown").lower(),
            "ruleId": finding.get("ruleId") or "",
            "title": truncate_text(finding.get("title") or ""),
            "message": truncate_text(finding.get("message") or ""),
            "location": first_location,
        })
    return trimmed


def package_terms(*values: object) -> set[str]:
    terms: set[str] = set()
    for value in values:
        if isinstance(value, list):
            text = " ".join(str(item) for item in value)
        else:
            text = str(value or "")
        normalized = "".join(ch.lower() if ch.isalnum() else " " for ch in text)
        for word in normalized.split():
            if len(word) >= 4 and word not in CATALOG_STOP_TERMS and not word.isdigit():
                terms.add(word)
            if word.startswith("py") and len(word) > 4 and word not in CATALOG_STOP_TERMS:
                stripped = word[2:]
                if stripped not in CATALOG_STOP_TERMS:
                    terms.add(stripped)
            for domain_term in CATALOG_DOMAIN_TERMS:
                if domain_term in word:
                    terms.add(domain_term)
    return terms


def latest_catalog_entry(details: dict) -> dict:
    versions = details.get("versions") or []
    latest_version = str(details.get("latestVersion") or "")
    for entry in versions:
        if str(entry.get("version") or "") == latest_version:
            return entry
    return versions[-1] if versions else {}


def summarize_package_catalog(package_name: str, package_summary: str, package_files: list[str]) -> dict:
    manifest_path = SCRIPT_DIR.parent / "packages.json"
    catalog = {
        "path": "packages.json",
        "status": "missing",
        "currentPackagePresent": False,
        "matchingBasis": [],
        "likelyAlternativeCandidates": [],
        "alternativeCandidates": [],
    }
    if not manifest_path.exists():
        return catalog

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        catalog["status"] = "unreadable"
        catalog["error"] = truncate_text(str(exc))
        return catalog

    packages = manifest.get("packages") or {}
    current_key = (package_name or "").strip().lower()
    target_terms = package_terms(package_name, package_summary, package_files)
    candidates: list[dict] = []
    likely_candidates: list[dict] = []
    for name in sorted(packages):
        details = packages.get(name) or {}
        normalized_name = name.strip().lower()
        if normalized_name == current_key:
            catalog["currentPackagePresent"] = True
            continue

        latest_entry = latest_catalog_entry(details)
        latest_artifacts = (latest_entry.get("files") or [])[:MAX_CATALOG_ARTIFACTS]
        candidate = {
            "name": details.get("name") or name,
            "latestVersion": details.get("latestVersion"),
            "latestReleaseTag": details.get("latestReleaseTag"),
            "lifecycleState": details.get("lifecycleState"),
            "installable": details.get("installable"),
            "latestPackageType": latest_entry.get("packageType"),
            "latestArtifacts": latest_artifacts,
        }
        candidate_terms = package_terms(candidate["name"], candidate["latestReleaseTag"], latest_artifacts)
        matched_terms = sorted(target_terms & candidate_terms)
        if matched_terms:
            likely_candidate = dict(candidate)
            likely_candidate["matchedTerms"] = matched_terms
            likely_candidate["matchScore"] = len(matched_terms)
            likely_candidates.append(likely_candidate)
        candidates.append(candidate)

    catalog["status"] = "ok"
    catalog["matchingBasis"] = sorted(target_terms)
    catalog["likelyAlternativeCandidates"] = sorted(
        likely_candidates,
        key=lambda item: (-item["matchScore"], item["name"].lower()),
    )[:MAX_LIKELY_ALTERNATIVES]
    catalog["alternativeCandidates"] = candidates
    return catalog


def normalize_service_now_context(context: dict | None) -> dict:
    """Return the narrowly scoped request fields relevant to package review."""
    if not context:
        return {"status": "not-provided"}

    items = context.get("requestItems") if isinstance(context, dict) else None
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        return {"status": "invalid", "reason": "Expected exactly one ServiceNow request item."}

    item = items[0].get("requestItem") or {}
    variables = items[0].get("catalogVariables") or []
    values = {
        str(variable.get("name") or ""): str(variable.get("value") or "").strip()
        for variable in variables
        if isinstance(variable, dict)
    }
    fields = {
        "openSourceUrl": values.get("open_source_url_github_pypy_npm_ect", ""),
        "system": values.get("system", ""),
        "packageName": values.get("package_name", ""),
        "declaredLicense": values.get("package_license_type", ""),
        "intendedUse": values.get("how_are_you_going_to_use_the_package", ""),
        "environment": values.get("what_environment", ""),
        "notes": values.get("comments", ""),
    }
    missing_fields = [name for name, value in fields.items() if not value]
    request = item.get("request") or {}
    return {
        "status": "available",
        "ticketId": item.get("number"),
        "requestId": request.get("display_value") if isinstance(request, dict) else request,
        "openedAt": item.get("opened_at"),
        "state": item.get("state"),
        "catalogItem": (item.get("cat_item") or {}).get("display_value")
        if isinstance(item.get("cat_item"), dict)
        else item.get("cat_item"),
        "fields": fields,
        "missingFields": missing_fields,
    }


def build_evidence_bundle(
    report: dict, report_markdown: str, service_now_context: dict | None = None
) -> dict:
    metadata = report.get("metadata") or {}
    github = report.get("github") or {}
    snyk = report.get("snyk") or {}
    dep_section = snyk.get("dependencies") or {}
    code_section = snyk.get("code") or {}
    install = report.get("install") or {}
    package_name = report.get("packageName")
    package_summary = truncate_text(metadata.get("summary") or "")
    package_files = metadata.get("files") or []
    return {
        "package": {
            "name": package_name,
            "requestedVersion": report.get("requestedVersion"),
            "validatedVersion": install.get("validatedVersion") or metadata.get("latestVersion"),
            "latestUpstreamVersion": metadata.get("latestVersion"),
            "summary": package_summary,
            "license": metadata.get("licenseSummary"),
            "requiresPython": metadata.get("requiresPython"),
            "totalReleases": metadata.get("totalReleases"),
            "daysSinceLatestRelease": metadata.get("daysSinceLatestRelease"),
            "recentReleases180d": metadata.get("recentReleases180d"),
            "osCompatibilityStatus": (metadata.get("osCompatibility") or {}).get("status"),
            "osLabels": (metadata.get("osCompatibility") or {}).get("labels"),
            "packageFiles": package_files,
        },
        "baseRecommendation": {
            "decision": report.get("recommendation"),
            "reasons": report.get("reasons") or [],
        },
        "github": {
            "url": github.get("url"),
            "archived": github.get("archived"),
            "lastCommitDate": github.get("lastCommitDate"),
            "lastCommitMessage": truncate_text(github.get("lastCommitMessage") or ""),
            "stars": github.get("stars"),
            "forks": github.get("forks"),
            "openIssues": github.get("openIssues"),
            "contributorsCount": github.get("contributorsCount"),
            "primaryLanguage": github.get("language"),
        } if github else None,
        "snyk": {
            "dependencySeverityCounts": dep_section.get("counts"),
            "codeSeverityCounts": code_section.get("counts"),
            "dependencyFindings": shrink_dep_findings(dep_section.get("findings") or []),
            "codeFindings": shrink_code_findings(code_section.get("findings") or []),
        },
        "currentPackageCatalog": summarize_package_catalog(package_name or "", package_summary, package_files),
        "serviceNowRequest": normalize_service_now_context(service_now_context),
        "installedDependencies": (report.get("dependencies") or {}).get("lines") or [],
        "approvalReportMarkdown": {
            "path": "review_output/approval-report.md",
            "content": truncate_block(report_markdown),
        },
    }


def build_user_prompt(evidence: dict) -> str:
    return (
        "Review this Windows package approval evidence using your configured security-review instructions. "
        "The evidence includes the structured approval-report.json fields, the current packages.json catalog snapshot, and the generated "
        "review_output/approval-report.md content that existed before this AI review was appended. "
        "For catalog overlap, currentPackageCatalog.currentPackagePresent only reports an exact package-name match; "
        "inspect currentPackageCatalog.likelyAlternativeCandidates for already-approved packages that may serve the same use case. "
        "serviceNowRequest is requester-supplied business context, not independently verified security evidence. Use it to assess "
        "whether the validated package matches the request, whether the declared license matches package.license, and how the "
        "declared intended use and environment affect the consequence of the evidenced risks. A production environment must lead "
        "to more conservative review of evidenced high or uncertain findings; a development or test environment does not waive "
        "security, compatibility, license, or evidence-completeness requirements. Do not infer data sensitivity, internet exposure, "
        "or compensating controls from an environment label alone. Flag missing, ambiguous, or conflicting ticket fields for human "
        "review, including a mismatch between serviceNowRequest.fields.packageName and package.name. Cite serviceNowRequest dotted "
        "paths and values whenever request context informs a conclusion. "
        "Return only the JSON review object expected by the approval report.\n\n"
        "EVIDENCE:\n"
        + json.dumps(evidence, indent=2, sort_keys=True)
    )


def agent_responses_url(endpoint: str, agent_name: str, api_version: str) -> str:
    url = endpoint.strip().rstrip("/")
    normalized = url.replace("\\", "/")
    if normalized.endswith("/responses"):
        responses_endpoint = url
    elif "/agents/" in normalized:
        responses_endpoint = url + "/endpoint/protocols/openai/responses"
    else:
        if not agent_name:
            raise ValueError(
                "AZURE_AI_FOUNDRY_AGENT_NAME is required when AZURE_AI_FOUNDRY_ENDPOINT is the project endpoint."
            )
        responses_endpoint = (
            url
            + "/agents/"
            + quote(agent_name, safe="")
            + "/endpoint/protocols/openai/responses"
        )

    separator = "&" if "?" in responses_endpoint else "?"
    if "api-version=" not in responses_endpoint:
        responses_endpoint += separator + "api-version=" + quote(api_version, safe="")
    return responses_endpoint


def call_foundry_agent(
    endpoint: str,
    api_key: str,
    agent_name: str,
    api_version: str,
    evidence: dict,
) -> tuple[str, str]:
    """Call the configured Azure AI Foundry agent. Returns (raw_text, error_message)."""
    body = {
        "input": build_user_prompt(evidence),
    }

    try:
        url = agent_responses_url(endpoint, agent_name, api_version)
    except ValueError as exc:
        return "", str(exc)

    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "api-key": api_key,
            "User-Agent": "pythonFeedWindows AI Security Reviewer",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:600]
        except Exception:  # noqa: BLE001
            pass
        return "", f"HTTP {exc.code} {exc.reason}: {detail}".strip()
    except urllib.error.URLError as exc:
        return "", f"Network error contacting Foundry: {exc.reason}"
    except (json.JSONDecodeError, TimeoutError, ValueError) as exc:
        return "", f"Invalid response from Foundry: {exc}"

    text = (payload.get("output_text") or "").strip()
    if not text:
        for item in payload.get("output") or []:
            for piece in item.get("content") or []:
                candidate = piece.get("text")
                if isinstance(candidate, str) and candidate.strip():
                    text = candidate.strip()
                    break
            if text:
                break
    if not text:
        return "", "Empty agent response"
    return text, ""


def parse_ai_json(raw_text: str) -> tuple[dict, str]:
    candidate = raw_text.strip()
    if candidate.startswith("```"):
        # Strip code fences if the model added them despite instructions.
        candidate = candidate.strip("`")
        first_newline = candidate.find("\n")
        if first_newline != -1:
            candidate = candidate[first_newline + 1 :]
        if candidate.endswith("```"):
            candidate = candidate[:-3]
        candidate = candidate.strip()
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        return {}, f"Failed to parse model JSON: {exc}"
    if not isinstance(parsed, dict):
        return {}, "Model JSON was not an object"
    return parsed, ""


def normalize_ai_review(parsed: dict) -> dict:
    def as_list(value) -> list:
        return value if isinstance(value, list) else []

    def as_finding_list(value) -> list[dict]:
        result: list[dict] = []
        for item in as_list(value):
            if not isinstance(item, dict):
                continue
            reference = str(item.get("reference") or item.get("evidence") or "").strip()
            reasoning = str(item.get("reasoning") or "").strip()
            if not reference and not reasoning:
                continue
            result.append({"reference": reference, "reasoning": reasoning})
        return result

    verdict = str(parsed.get("verdict") or "").lower()
    if verdict not in {"low-concern", "review-needed", "high-concern"}:
        verdict = "review-needed"
    confidence = str(parsed.get("confidence") or "").lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "medium"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": str(parsed.get("summary") or "").strip(),
        "keyPoints": [str(p).strip() for p in as_list(parsed.get("keyPoints")) if str(p).strip()],
        "concerningFindings": as_finding_list(parsed.get("concerningFindings")),
        "likelyBenignFindings": as_finding_list(parsed.get("likelyBenignFindings")),
        "approverNotes": [str(p).strip() for p in as_list(parsed.get("approverNotes")) if str(p).strip()],
    }


def unavailable_review(reason: str) -> dict:
    return {
        "status": "unavailable",
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reason": reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an advisory AI security review using Azure AI Foundry.")
    parser.add_argument("--report-json", required=True)
    parser.add_argument("--report-md", required=True)
    parser.add_argument(
        "--servicenow-context",
        help="Optional JSON emitted by inspect_servicenow_package_request.py for the associated request item.",
    )
    parser.add_argument("--agent-name", default=os.environ.get("AZURE_AI_FOUNDRY_AGENT_NAME", ""))
    parser.add_argument("--api-version", default=os.environ.get("AZURE_AI_FOUNDRY_API_VERSION", DEFAULT_API_VERSION))
    args = parser.parse_args()

    report_path = Path(args.report_json)
    md_path = Path(args.report_md)
    if not report_path.exists():
        print(f"[ai-review] Report JSON not found at {report_path}; skipping AI step.", file=sys.stderr)
        return 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    report_markdown = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
    service_now_context = None
    if args.servicenow_context:
        context_path = Path(args.servicenow_context)
        try:
            service_now_context = json.loads(context_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[ai-review] ServiceNow context unavailable: {exc}", file=sys.stderr)

    endpoint = os.environ.get("AZURE_AI_FOUNDRY_ENDPOINT", "").strip()
    api_key = os.environ.get("AZURE_AI_FOUNDRY_API_KEY", "").strip()
    agent_name = args.agent_name.strip()
    api_version = args.api_version.strip() or DEFAULT_API_VERSION

    if not endpoint or not api_key:
        reason = "AZURE_AI_FOUNDRY_ENDPOINT or AZURE_AI_FOUNDRY_API_KEY is not configured"
        print(f"[ai-review] {reason}; recording unavailable status.", file=sys.stderr)
        report["aiSecurityReview"] = unavailable_review(reason)
    else:
        evidence = build_evidence_bundle(report, report_markdown, service_now_context)
        raw_text, call_error = call_foundry_agent(endpoint, api_key, agent_name, api_version, evidence)
        if call_error:
            print(f"[ai-review] Foundry call failed: {call_error}", file=sys.stderr)
            report["aiSecurityReview"] = unavailable_review(call_error)
        else:
            parsed, parse_error = parse_ai_json(raw_text)
            if parse_error:
                print(f"[ai-review] {parse_error}; raw response truncated to 400 chars: {raw_text[:400]}", file=sys.stderr)
                review = unavailable_review(parse_error)
                review["rawResponsePreview"] = raw_text[:400]
                report["aiSecurityReview"] = review
            else:
                review = normalize_ai_review(parsed)
                review["status"] = "ok"
                review["generatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                report["aiSecurityReview"] = review
                print(
                    f"[ai-review] verdict={review['verdict']} confidence={review['confidence']} "
                    f"concerning={len(review['concerningFindings'])} benign={len(review['likelyBenignFindings'])}"
                )

    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
