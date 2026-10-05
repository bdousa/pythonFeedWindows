#!/usr/bin/env python3
"""Validate active Python/PyPI ServiceNow requests before GitHub Actions dispatch."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen

from build_ai_security_review import normalize_service_now_context
from inspect_servicenow_package_request import normalize_instance

VALIDATION_MARKERS = (
    "[PACKAGE_REQUEST_VALIDATION_REQUIRED]",
    "[SAR_VALIDATION_REQUIRED]",  # Preserve acknowledgement behavior for legacy comments.
)
REQUIRED_FIELDS = {
    "packageName": "Package Name",
    "requestedVersion": "Requested Version",
    "declaredLicense": "Package License Type",
    "openSourceUrl": "Open-source/Registry URL",
    "intendedUse": "How will the package be used?",
    "targetEnvironments": "Target environment(s)",
    "alternativeRationale": "Why an approved internal alternative is not sufficient",
    "executionContext": "Execution context",
    "internetExposure": "Internet exposure",
}
PYPI_PACKAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PYPI_VERSION_PATTERN = re.compile(
    r"^v?\d+(?:\.\d+)*(?:[A-Za-z]+\d*)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[A-Za-z0-9.-]+)?$",
    re.IGNORECASE,
)
FIXED_LINE_PATTERN = re.compile(r"(?im)(?:^|\r?\n)\s*fixed[.!]?\s*(?=\r?$|\r?\n)")
PACKAGE_LIST_HEADER = "package name, version, registry/source URL, license"
MULTIPLE_PACKAGE_TEMPLATE = "\n".join((
    "PACKAGE LIST",
    PACKAGE_LIST_HEADER,
    "requests, 2.32.5, https://pypi.org/project/requests/2.32.5/, Apache-2.0",
    "urllib3, 2.2.3, https://pypi.org/project/urllib3/2.2.3/, MIT",
    "END PACKAGE LIST",
))
REGISTRY_ENRICHMENT_MARKER = "PACKAGE_REGISTRY_ENRICHMENT"


class RegistryUnavailableError(RuntimeError):
    """Raised when PyPI cannot be queried reliably enough to dispatch."""


def validation_state(rendered_comments: str) -> str:
    """Return acknowledgement state from the requester-visible activity rendering."""
    marker_index = min(
        (index for marker in VALIDATION_MARKERS if (index := rendered_comments.lower().find(marker.lower())) >= 0),
        default=-1,
    )
    if marker_index < 0:
        return "not_requested"
    fixed_match = FIXED_LINE_PATTERN.search(rendered_comments)
    # ServiceNow renders its activity stream newest-first, so a requester Fixed
    # entry appears above the older validation marker.
    if fixed_match and fixed_match.start() < marker_index:
        return "requester_confirmed_fixed"
    return "awaiting_requester_correction"


def package_name_from_registry_url(source_url: str) -> str:
    """Return a PyPI project name only when the official URL states it exactly."""
    parsed = urlparse(source_url)
    if parsed.hostname not in {"pypi.org", "www.pypi.org"}:
        return ""
    segments = [unquote(segment) for segment in parsed.path.split("/") if segment]
    if len(segments) >= 2 and segments[0].casefold() == "project" and PYPI_PACKAGE_PATTERN.fullmatch(segments[1]):
        return segments[1]
    return ""


def github_repository_slug(source_url: str) -> str:
    """Return an owner/repository identity for a GitHub repository URL."""
    parsed = urlparse(source_url)
    if (parsed.hostname or "").casefold() not in {"github.com", "www.github.com"}:
        return ""
    segments = [unquote(segment).strip() for segment in parsed.path.split("/") if segment.strip()]
    if len(segments) < 2:
        return ""
    repository = re.sub(r"(?i)\.git$", "", segments[1])
    if not segments[0] or not repository:
        return ""
    return f"{segments[0]}/{repository}".casefold()


def _pypi_github_repositories(info: dict[str, Any]) -> list[str]:
    """Return GitHub repository identities explicitly published in PyPI metadata."""
    urls = [str(info.get("home_page") or "")]
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        urls.extend(str(value or "") for value in project_urls.values())
    return sorted({slug for url in urls if (slug := github_repository_slug(url))})


def is_placeholder(value: str) -> bool:
    """Return whether a requester supplied a common non-answer placeholder."""
    return bool(re.fullmatch(
        r"(?:n\s*/?\s*a|n\.\s*a\.|not\s+applicable|none|unknown|tbd|todo|pending|\?|-)",
        value.strip(),
        re.IGNORECASE,
    ))


def _pypi_json(url: str) -> dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "pythonFeedWindows-ServiceNow-intake/1.0"})
    try:
        with urlopen(request, timeout=15) as response:
            payload = json.load(response)
    except HTTPError as exc:
        if exc.code == 404:
            return {}
        raise RegistryUnavailableError(f"PyPI returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise RegistryUnavailableError(f"PyPI could not be reached: {reason}") from exc
    if not isinstance(payload, dict):
        raise RegistryUnavailableError("PyPI returned an unexpected response.")
    return payload


def _pypi_license(info: dict[str, Any]) -> str:
    """Return only concise, unambiguous license metadata suitable for the form."""
    for key in ("license_expression", "license"):
        value = str(info.get(key) or "").strip()
        if (
            value
            and len(value) <= 200
            and not re.search(r"[\r\n,|]", value)
            and not re.match(r"(?i)^(?:unknown|n/?a|none|see\s+license\s+in)", value)
        ):
            return value
    return ""


def resolve_pypi_package(package_name: str, requested_version: str) -> dict[str, Any]:
    """Resolve canonical package coordinates from PyPI's official JSON API."""
    metadata = _pypi_json(f"https://pypi.org/pypi/{quote(package_name, safe='')}/json")
    if not metadata:
        return {"status": "not_found", "packageName": package_name}
    info = metadata.get("info") if isinstance(metadata.get("info"), dict) else {}
    canonical_name = str(info.get("name") or package_name).strip()
    submitted_version = requested_version.strip()
    if not submitted_version or is_placeholder(submitted_version) or submitted_version.casefold() == "latest":
        selected_version = str(info.get("version") or "").strip()
        version_metadata = metadata
    else:
        candidate_version = submitted_version[1:] if submitted_version.lower().startswith("v") else submitted_version
        version_metadata = _pypi_json(
            f"https://pypi.org/pypi/{quote(canonical_name, safe='')}/{quote(candidate_version, safe='')}/json"
        )
        if not version_metadata:
            return {
                "status": "version_not_found",
                "packageName": canonical_name,
                "requestedVersion": submitted_version,
            }
        version_info = version_metadata.get("info") if isinstance(version_metadata.get("info"), dict) else {}
        selected_version = str(version_info.get("version") or candidate_version).strip()
    if not selected_version:
        raise RegistryUnavailableError("PyPI did not identify a current package version.")
    selected_info = version_metadata.get("info") if isinstance(version_metadata.get("info"), dict) else {}
    return {
        "status": "resolved",
        "packageName": str(selected_info.get("name") or canonical_name).strip(),
        "requestedVersion": selected_version,
        "openSourceUrl": f"https://pypi.org/project/{quote(canonical_name, safe='')}/{quote(selected_version, safe='')}/",
        "declaredLicense": _pypi_license(selected_info),
        "githubRepositories": _pypi_github_repositories(selected_info),
        "registry": "PyPI",
    }


def enrich_with_pypi(fields: dict[str, str]) -> tuple[dict[str, str], list[dict[str, str]], list[str]]:
    """Cross-check and safely replace package coordinates with official PyPI data."""
    enriched = dict(fields)
    changes: list[dict[str, str]] = []
    errors: list[str] = []
    submitted_name = enriched.get("packageName", "").strip()
    source_name = package_name_from_registry_url(enriched.get("openSourceUrl", "").strip())
    lookup_name = source_name or submitted_name
    if not lookup_name or is_placeholder(lookup_name) or not PYPI_PACKAGE_PATTERN.fullmatch(lookup_name):
        return enriched, changes, errors
    requested_version = enriched.get("requestedVersion", "").strip()
    if requested_version and not is_placeholder(requested_version) and requested_version.casefold() != "latest" and not PYPI_VERSION_PATTERN.fullmatch(requested_version):
        return enriched, changes, errors
    resolved = resolve_pypi_package(lookup_name, requested_version)
    if resolved["status"] == "not_found":
        errors.append(f"Package Name '{lookup_name}' was not found in the official PyPI registry.")
        return enriched, changes, errors
    if resolved["status"] == "version_not_found":
        errors.append(
            f"Requested Version '{requested_version}' was not found for '{resolved['packageName']}' in the official PyPI registry."
        )
        return enriched, changes, errors
    submitted_repository = github_repository_slug(enriched.get("openSourceUrl", "").strip())
    registry_repositories = {
        str(repository).casefold()
        for repository in resolved.get("githubRepositories", [])
        if str(repository).strip()
    }
    if submitted_repository and submitted_repository not in registry_repositories:
        errors.append(
            f"The submitted GitHub repository '{submitted_repository}' is not identified by the PyPI project "
            f"'{resolved['packageName']}'. A same-name PyPI project cannot replace a different GitHub project; "
            "provide an exact HTTPS wheel asset URL and SHA256 for GitHub-only review."
        )
        return enriched, changes, errors
    labels = {
        "packageName": "Package Name",
        "requestedVersion": "Requested Version",
        "openSourceUrl": "Open-source/Registry URL",
        "declaredLicense": "Package License Type",
    }
    for field_name, label in labels.items():
        resolved_value = str(resolved.get(field_name) or "").strip()
        submitted_value = enriched.get(field_name, "").strip()
        if not resolved_value:
            continue
        if submitted_value != resolved_value:
            changes.append({
                "field": field_name,
                "label": label,
                "submitted": submitted_value,
                "resolved": resolved_value,
                "registry": "PyPI",
            })
            enriched[field_name] = resolved_value
    return enriched, changes, errors


def registry_enrichment_marker(changes: list[dict[str, str]]) -> str:
    """Return a stable marker for one exact set of registry-resolved values."""
    canonical = [
        {
            "field": change["field"],
            "resolved": change["resolved"],
            "lineNumber": change.get("lineNumber", ""),
        }
        for change in changes
    ]
    canonical.sort(key=lambda value: (str(value["lineNumber"]), value["field"], value["resolved"]))
    digest = hashlib.sha256(json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()).hexdigest()[:20]
    return f"[{REGISTRY_ENRICHMENT_MARKER}] [id:{digest}]"


def format_errors(fields: dict[str, str]) -> list[str]:
    """Validate the single-package Python request contract without calling PyPI."""
    errors = []
    for name, label in REQUIRED_FIELDS.items():
        value = fields.get(name, "").strip()
        if not value:
            errors.append(f"{label} is required.")
        elif is_placeholder(value):
            errors.append(f"{label} must contain a specific value, not the placeholder '{value}'.")
    package_name = fields.get("packageName", "").strip()
    if package_name and not is_placeholder(package_name) and (
        package_name.casefold() == "multiple" or not PYPI_PACKAGE_PATTERN.fullmatch(package_name)
    ):
        errors.append(f"Package Name '{package_name}' is not a valid single Python/PyPI package identifier.")
    requested_version = fields.get("requestedVersion", "").strip()
    if requested_version and not is_placeholder(requested_version) and requested_version.casefold() != "latest" and not PYPI_VERSION_PATTERN.fullmatch(requested_version):
        errors.append(
            f"Requested Version '{requested_version}' must be 'latest' or an exact Python/PyPI package version (for example 3.1.0)."
        )
    source_url = fields.get("openSourceUrl", "").strip()
    if source_url and not is_placeholder(source_url) and not re.fullmatch(r"https?://[^\s]+", source_url, re.IGNORECASE):
        errors.append(f"Open-source/Registry URL '{source_url}' must be an absolute http or https URL.")
    suggested_name = package_name_from_registry_url(source_url)
    if suggested_name and package_name and suggested_name.casefold() != package_name.casefold():
        errors.append(f"Did you mean '{suggested_name}'? The registry/source URL identifies that PyPI package.")
    license_type = fields.get("declaredLicense", "").strip()
    if license_type and not is_placeholder(license_type) and (
        license_type.casefold() == "multiple" or re.search(r"[\r\n,|]", license_type) or len(license_type) > 200
    ):
        errors.append("Package License Type must contain one license declaration, not a list or multi-package placeholder.")
    return errors


def validation_comment(errors: list[str]) -> str:
    lines = ["[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:", ""]
    lines.extend(f"- {error}" for error in errors)
    lines.extend((
        "",
        "If you intended to request multiple packages:",
        "1. Set Package Name, Requested Version, Open-source/Registry URL, and Package License Type to exactly: Multiple",
        "2. Replace the Notes/comments content with this exact format. PACKAGE LIST must be the first content; add other comments only after END PACKAGE LIST:",
        "",
        MULTIPLE_PACKAGE_TEMPLATE,
        "",
        "After correcting the form values, add a new comment containing only: Fixed",
    ))
    return "\n".join(lines)


def multiple_package_guidance_html() -> str:
    """Return the documented multi-package contract for review-required email."""
    return (
        "<p><strong>If you intended to request multiple packages:</strong></p>"
        "<ol>"
        "<li>Set <strong>Package Name</strong>, <strong>Requested Version</strong>, "
        "<strong>Open-source/Registry URL</strong>, and <strong>Package License Type</strong> "
        "to exactly <code>Multiple</code>.</li>"
        "<li>Replace the Notes/comments content with this exact format. "
        "<code>PACKAGE LIST</code> must be the first content; add other comments only after "
        "<code>END PACKAGE LIST</code>:</li>"
        f"</ol><pre>{html.escape(MULTIPLE_PACKAGE_TEMPLATE)}</pre>"
    )


def parse_package_list(notes: str) -> list[dict[str, str]]:
    """Parse the documented, bounded comma-separated package list."""
    lines = notes.splitlines()
    try:
        start = [index for index, line in enumerate(lines) if line.strip() == "PACKAGE LIST"]
        end = [index for index, line in enumerate(lines) if line.strip() == "END PACKAGE LIST"]
        if len(start) != 1 or len(end) != 1 or end[0] <= start[0] + 1:
            raise ValueError("Notes/comments must contain one PACKAGE LIST section with a header and END PACKAGE LIST marker.")
        if any(line.strip() for line in lines[:start[0]]):
            raise ValueError("PACKAGE LIST must be the first content in Notes/comments. Add additional comments only after END PACKAGE LIST.")
        if lines[start[0] + 1].strip() != PACKAGE_LIST_HEADER:
            raise ValueError(f"The PACKAGE LIST header must be exactly: {PACKAGE_LIST_HEADER}")

        package_lines: list[dict[str, str]] = []
        for index in range(start[0] + 2, end[0]):
            raw_line = lines[index]
            if not raw_line.strip():
                raise ValueError(f"Package list line {index + 1} is blank. Enter one package per row.")
            columns = [column.strip() for column in raw_line.split(",")]
            if len(columns) != 4 or any(not column for column in columns):
                raise ValueError(
                    f"Package list line {index + 1} must contain exactly four non-empty comma-separated values: "
                    "package name, version, registry/source URL, license."
                )
            package_lines.append({
                "lineNumber": str(index + 1),
                "packageName": columns[0],
                "requestedVersion": columns[1],
                "openSourceUrl": columns[2],
                "declaredLicense": columns[3],
            })
        if not package_lines:
            raise ValueError("PACKAGE LIST must contain at least one package row.")
        seen: set[tuple[str, str]] = set()
        for line in package_lines:
            key = (line["packageName"].casefold(), line["requestedVersion"].casefold())
            if key in seen:
                raise ValueError(f"PACKAGE LIST contains duplicate package/version row: {line['packageName']}|{line['requestedVersion']}.")
            seen.add(key)
        return package_lines
    except ValueError:
        raise


def is_multiple_request(fields: dict[str, str]) -> bool:
    values = [fields.get(name, "").strip().casefold() == "multiple" for name in (
        "packageName", "requestedVersion", "openSourceUrl", "declaredLicense",
    )]
    if any(values) and not all(values):
        raise ValueError(
            "Package Name, Requested Version, Open-source/Registry URL, and Package License Type "
            "must all be Multiple for a multiple-package request."
        )
    return all(values)


def update_awaiting_requester_information(
    instance: str, username: str, password: str, sys_id: str, message: str
) -> None:
    """Record correction details and set the verified active Pending RITM state."""
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = Request(
        f"https://{instance}/api/now/table/sc_req_item/{sys_id}",
        # Verified in this ServiceNow instance: sc_req_item state -5 is Pending.
        # The configured ServiceNow workflow renders the requester-information stage.
        data=json.dumps({"comments": message, "state": "-5"}).encode("utf-8"),
        headers={
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="PATCH",
    )
    with urlopen(request, timeout=60) as response:
        if response.status not in {200, 201}:
            raise RuntimeError(f"ServiceNow correction update returned HTTP {response.status}.")


def add_registry_enrichment_comment(
    instance: str, username: str, password: str, sys_id: str, changes: list[dict[str, str]]
) -> None:
    """Write an audit-only comment for registry corrections without changing state."""
    lines = [f"{registry_enrichment_marker(changes)} Official PyPI data was used before package review:", ""]
    for change in changes:
        submitted = change["submitted"] or "<blank>"
        prefix = f"Package list line {change['lineNumber']} — " if change.get("lineNumber") else ""
        lines.append(f"- {prefix}{change['label']}: '{submitted}' -> '{change['resolved']}'")
    lines.append("")
    lines.append("These registry-resolved values will be used by the package review. Business and usage fields were not changed.")
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = Request(
        f"https://{instance}/api/now/table/sc_req_item/{sys_id}",
        data=json.dumps({"comments": "\n".join(lines)}).encode("utf-8"),
        headers={
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="PATCH",
    )
    with urlopen(request, timeout=60) as response:
        if response.status not in {200, 201}:
            raise RuntimeError(f"ServiceNow registry-enrichment comment returned HTTP {response.status}.")


def request_url(instance: str, sys_id: str) -> str:
    return f"https://{instance}/sc_req_item.do?sys_id={sys_id}"


def send_review_required_email(
    endpoint: str,
    recipient: str,
    ticket: str,
    ticket_url: str,
    errors: list[str],
) -> None:
    if not endpoint:
        raise RuntimeError("REVIEW_REQUIRED_LOGIC_APP_URL is required to notify the requester.")
    if not recipient:
        raise RuntimeError("The ServiceNow requester email is unavailable; cannot send the review-required notification.")
    error_items = "".join(f"<li>{html.escape(error)}</li>" for error in errors)
    body = {
        "toEmail": recipient,
        "ritmNumber": ticket,
        "ritmUrl": ticket_url,
        "htmlBody": (
            "<p>The following field values need correction:</p>"
            f"<ul>{error_items}</ul>{multiple_package_guidance_html()}"
        ),
    }
    request = Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=60) as response:
            if response.status not in {200, 201, 202}:
                raise RuntimeError(f"Review-required notification returned HTTP {response.status}.")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"Review-required notification failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Review-required notification failed: {exc.reason}") from exc


def prepare_dispatches(
    source: dict[str, Any], instance: str, username: str, password: str, notification_url: str
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in source.get("requestItems", []):
        context = normalize_service_now_context({"requestItems": [item]})
        fields = context.get("fields") or {}
        if fields.get("packageEcosystem") != "Python/PyPI":
            continue
        request_item = item.get("requestItem") if isinstance(item, dict) else {}
        ticket = str(context.get("ticketId") or "").strip()
        request_sys_id = str((request_item or {}).get("sys_id") or "").strip()
        recipient = str((request_item or {}).get("requested_for.email") or (request_item or {}).get("opened_by.email") or "").strip()
        state = validation_state(str((request_item or {}).get("comments") or ""))
        rendered_comments = str((request_item or {}).get("comments") or "")
        shared_fields = {name: str(fields.get(name) or "") for name in REQUIRED_FIELDS}
        try:
            multiple_request = is_multiple_request(shared_fields)
            package_lines = parse_package_list(str(fields.get("notes") or "")) if multiple_request else []
            errors = []
        except ValueError as exc:
            multiple_request = False
            package_lines = []
            errors = [str(exc)]
        registry_changes: list[dict[str, str]] = []
        registry_unavailable = ""
        if multiple_request:
            for line in package_lines:
                line_fields = dict(shared_fields)
                line_fields.update({name: line[name] for name in ("packageName", "requestedVersion", "openSourceUrl", "declaredLicense")})
                try:
                    enriched_fields, line_changes, registry_errors = enrich_with_pypi(line_fields)
                except RegistryUnavailableError as exc:
                    registry_unavailable = str(exc)
                    break
                for name in ("packageName", "requestedVersion", "openSourceUrl", "declaredLicense"):
                    line[name] = enriched_fields[name]
                registry_changes.extend({**change, "lineNumber": line["lineNumber"]} for change in line_changes)
                line_errors = [*registry_errors, *format_errors(enriched_fields)]
                errors.extend(f"Package list line {line['lineNumber']}: {error}" for error in line_errors)
            if not registry_unavailable:
                canonical_rows: dict[tuple[str, str], str] = {}
                for line in package_lines:
                    key = (line["packageName"].casefold(), line["requestedVersion"].casefold())
                    if key in canonical_rows:
                        errors.append(
                            f"Package list lines {canonical_rows[key]} and {line['lineNumber']} resolve to the same "
                            f"PyPI package/version: {line['packageName']}|{line['requestedVersion']}."
                        )
                    else:
                        canonical_rows[key] = line["lineNumber"]
        elif not errors:
            try:
                shared_fields, registry_changes, registry_errors = enrich_with_pypi(shared_fields)
                errors = [*registry_errors, *format_errors(shared_fields)]
            except RegistryUnavailableError as exc:
                registry_unavailable = str(exc)
        if registry_unavailable:
            results.append({
                "ticket": ticket,
                "status": "registry_unavailable",
                "error": registry_unavailable,
            })
            continue
        if errors:
            if state == "awaiting_requester_correction":
                results.append({"ticket": ticket, "status": "awaiting_requester_correction", "errors": errors})
                continue
            try:
                if not request_sys_id:
                    raise RuntimeError("ServiceNow request item sys_id is missing.")
                send_review_required_email(notification_url, recipient, ticket, request_url(instance, request_sys_id), errors)
                update_awaiting_requester_information(instance, username, password, request_sys_id, validation_comment(errors))
                results.append({"ticket": ticket, "status": "validation_requested", "errors": errors, "recipient": recipient})
            except Exception as exc:  # noqa: BLE001
                results.append({"ticket": ticket, "status": "failed_correction_notification", "errors": errors, "error": str(exc)})
            continue
        if state == "awaiting_requester_correction":
            results.append({"ticket": ticket, "status": "awaiting_requester_acknowledgement"})
            continue
        if registry_changes and registry_enrichment_marker(registry_changes) not in rendered_comments:
            try:
                if not request_sys_id:
                    raise RuntimeError("ServiceNow request item sys_id is missing.")
                add_registry_enrichment_comment(
                    instance, username, password, request_sys_id, registry_changes
                )
            except Exception as exc:  # noqa: BLE001
                results.append({
                    "ticket": ticket,
                    "status": "failed_registry_enrichment_audit",
                    "error": str(exc),
                })
                continue
        dispatch_lines = package_lines if multiple_request else [{
            "packageName": shared_fields["packageName"].strip(),
            "requestedVersion": shared_fields["requestedVersion"].strip() or "latest",
            "openSourceUrl": shared_fields["openSourceUrl"].strip(),
            "declaredLicense": shared_fields["declaredLicense"].strip(),
        }]
        for line in dispatch_lines:
            results.append({
                "ticket": ticket,
                "package": line["packageName"],
                "version": line["requestedVersion"] or "latest",
                "lineContext": line if multiple_request else None,
                "registryOverride": line if registry_changes and not multiple_request else None,
                "registryChanges": registry_changes,
                "status": "ready_for_dispatch",
            })
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--instance", default=os.getenv("SERVICENOW_INSTANCE", ""))
    parser.add_argument("--username", default=os.getenv("SERVICENOW_USERNAME", ""))
    parser.add_argument("--password", default=os.getenv("SERVICENOW_PASSWORD", ""))
    parser.add_argument("--review-required-logic-app-url", default=os.getenv("REVIEW_REQUIRED_LOGIC_APP_URL", ""))
    args = parser.parse_args()
    if not args.instance or not args.username or not args.password:
        raise RuntimeError("SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD are required.")
    source = json.loads(args.input.read_text(encoding="utf-8"))
    results = prepare_dispatches(
        source,
        normalize_instance(args.instance),
        args.username,
        args.password,
        args.review_required_logic_app_url,
    )
    output = {"results": results}
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
