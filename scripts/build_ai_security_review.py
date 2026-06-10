#!/usr/bin/env python3

"""Run an advisory AI security review over the generated approval report.

Reads review_output/approval-report.json, builds an evidence-only prompt from
the structured Snyk + package data, calls Azure AI Foundry (Responses API),
parses the JSON response, then injects an ``aiSecurityReview`` block into the
report JSON and regenerates the Markdown using the same renderer that produced
it originally. Fails open: on any error the script still updates the report
with an ``unavailable`` status block and exits zero so the workflow continues.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from build_review_report import render_markdown  # noqa: E402

DEFAULT_MODEL = "gpt-5.4-mini"
MAX_DEP_FINDINGS = 30
MAX_CODE_FINDINGS = 30
MESSAGE_TRUNCATE = 320
REQUEST_TIMEOUT = 90


SYSTEM_PROMPT = """You are an advisory security reviewer for a Python package approval pipeline that feeds a Windows-focused internal package mirror. Your job is to triage Snyk findings and package metadata so a human approver can quickly understand the real risk.

You must follow these rules:
1. Reason ONLY from the JSON evidence object in the user message. Do not invent facts. Do not bring in knowledge that is not present in the evidence.
2. Every confident claim MUST cite specific evidence already present in the JSON: a Snyk finding id, rule id, package@version, file:line location, fix version, release date, license string, classifier, or a named report field. If you cannot cite specific evidence for a claim, mark the claim as uncertain.
3. Distinguish runtime-exploitable risk from contextual risk. A path traversal in a CLI script that needs a local command-line argument is not the same risk as one in a server-side request handler. A tar slip in static lexer data is not the same as one in extraction logic actually executed at runtime.
4. Distinguish dependency vulnerabilities (known CVEs in packages we install) from code findings (static analysis hits in shipped source files).
5. Be explicit about uncertainty. If the evidence is insufficient to judge something, say so and put the unanswered question in openQuestions.
6. You are advisory only. Do NOT make the approve/reject decision. The human approver decides.
7. Output ONLY a single JSON object. Do not include any text outside the JSON. Do not wrap it in code fences.

Use exactly these field names in the output JSON:
{
  "verdict": "low-concern" | "review-needed" | "high-concern",
  "confidence": "low" | "medium" | "high",
  "summary": "1-3 paragraph natural language overview tied to the evidence",
  "keyPoints": ["short bullet pointing back to specific evidence", ...],
  "concerningFindings": [
    {"evidence": "cite Snyk id / rule / location / package@version / report field", "reasoning": "why this matters in this package context"}
  ],
  "likelyBenignFindings": [
    {"evidence": "...", "reasoning": "..."}
  ],
  "approverNotes": ["actionable things the human should sanity-check"],
  "openQuestions": ["things the evidence cannot answer"]
}

If a category has nothing to report, use an empty array for it. If overall there is no security signal worth flagging, set verdict to low-concern with confidence reflecting how much evidence backed that judgment."""


def truncate_text(value: str, limit: int = MESSAGE_TRUNCATE) -> str:
    if not value:
        return ""
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


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


def build_evidence_bundle(report: dict) -> dict:
    metadata = report.get("metadata") or {}
    github = report.get("github") or {}
    snyk = report.get("snyk") or {}
    dep_section = snyk.get("dependencies") or {}
    code_section = snyk.get("code") or {}
    install = report.get("install") or {}
    return {
        "package": {
            "name": report.get("packageName"),
            "requestedVersion": report.get("requestedVersion"),
            "validatedVersion": install.get("validatedVersion") or metadata.get("latestVersion"),
            "latestUpstreamVersion": metadata.get("latestVersion"),
            "summary": truncate_text(metadata.get("summary") or ""),
            "license": metadata.get("licenseSummary"),
            "requiresPython": metadata.get("requiresPython"),
            "totalReleases": metadata.get("totalReleases"),
            "daysSinceLatestRelease": metadata.get("daysSinceLatestRelease"),
            "recentReleases180d": metadata.get("recentReleases180d"),
            "osCompatibilityStatus": (metadata.get("osCompatibility") or {}).get("status"),
            "osLabels": (metadata.get("osCompatibility") or {}).get("labels"),
            "packageFiles": metadata.get("files") or [],
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
        "installedDependencies": (report.get("dependencies") or {}).get("lines") or [],
    }


def build_user_prompt(evidence: dict) -> str:
    return (
        "Use ONLY the evidence in the JSON below. Cite specific Snyk ids, rule ids, "
        "package@version, file:line, fix versions, release dates, or other named "
        "report fields when you make a confident claim. Mark anything you cannot "
        "verify from the evidence as uncertain.\n\n"
        "Return one JSON object that matches the schema described in the system "
        "instructions. Do not include any text outside the JSON.\n\n"
        "EVIDENCE:\n"
        + json.dumps(evidence, indent=2, sort_keys=True)
    )


def call_foundry(endpoint: str, api_key: str, model: str, evidence: dict) -> tuple[str, str]:
    """Call Azure AI Foundry Responses API. Returns (raw_text, error_message)."""
    body = {
        "model": model,
        "input": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(evidence)},
        ],
        "text": {"format": {"type": "json_object"}},
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "api-key": api_key,
            "User-Agent": "PythonFeed-Update AI Security Reviewer",
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
        return "", "Empty model response"
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
            evidence = str(item.get("evidence") or "").strip()
            reasoning = str(item.get("reasoning") or "").strip()
            if not evidence and not reasoning:
                continue
            result.append({"evidence": evidence, "reasoning": reasoning})
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
        "openQuestions": [str(p).strip() for p in as_list(parsed.get("openQuestions")) if str(p).strip()],
    }


def unavailable_review(model: str, reason: str) -> dict:
    return {
        "status": "unavailable",
        "model": model,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reason": reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an advisory AI security review using Azure AI Foundry.")
    parser.add_argument("--report-json", required=True)
    parser.add_argument("--report-md", required=True)
    parser.add_argument("--model", default=os.environ.get("AZURE_AI_FOUNDRY_MODEL", DEFAULT_MODEL))
    args = parser.parse_args()

    report_path = Path(args.report_json)
    md_path = Path(args.report_md)
    if not report_path.exists():
        print(f"[ai-review] Report JSON not found at {report_path}; skipping AI step.", file=sys.stderr)
        return 0

    report = json.loads(report_path.read_text(encoding="utf-8"))

    endpoint = os.environ.get("AZURE_AI_FOUNDRY_ENDPOINT", "").strip()
    api_key = os.environ.get("AZURE_AI_FOUNDRY_API_KEY", "").strip()

    if not endpoint or not api_key:
        reason = "AZURE_AI_FOUNDRY_ENDPOINT or AZURE_AI_FOUNDRY_API_KEY is not configured"
        print(f"[ai-review] {reason}; recording unavailable status.", file=sys.stderr)
        report["aiSecurityReview"] = unavailable_review(args.model, reason)
    else:
        evidence = build_evidence_bundle(report)
        raw_text, call_error = call_foundry(endpoint, api_key, args.model, evidence)
        if call_error:
            print(f"[ai-review] Foundry call failed: {call_error}", file=sys.stderr)
            report["aiSecurityReview"] = unavailable_review(args.model, call_error)
        else:
            parsed, parse_error = parse_ai_json(raw_text)
            if parse_error:
                print(f"[ai-review] {parse_error}; raw response truncated to 400 chars: {raw_text[:400]}", file=sys.stderr)
                review = unavailable_review(args.model, parse_error)
                review["rawResponsePreview"] = raw_text[:400]
                report["aiSecurityReview"] = review
            else:
                review = normalize_ai_review(parsed)
                review["status"] = "ok"
                review["model"] = args.model
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
