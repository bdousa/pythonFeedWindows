#!/usr/bin/env python3
"""Validate active Python/PyPI ServiceNow requests before GitHub Actions dispatch."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
from pathlib import Path
from typing import Any
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


def format_errors(fields: dict[str, str]) -> list[str]:
    """Validate the single-package Python request contract without calling PyPI."""
    errors = [f"{label} is required." for name, label in REQUIRED_FIELDS.items() if not fields.get(name, "").strip()]
    package_name = fields.get("packageName", "").strip()
    if package_name and (package_name.casefold() == "multiple" or not PYPI_PACKAGE_PATTERN.fullmatch(package_name)):
        errors.append(f"Package Name '{package_name}' is not a valid single Python/PyPI package identifier.")
    requested_version = fields.get("requestedVersion", "").strip()
    if requested_version and requested_version.casefold() != "latest" and not PYPI_VERSION_PATTERN.fullmatch(requested_version):
        errors.append(
            f"Requested Version '{requested_version}' must be 'latest' or an exact Python/PyPI package version (for example 3.1.0)."
        )
    source_url = fields.get("openSourceUrl", "").strip()
    if source_url and not re.fullmatch(r"https?://[^\s]+", source_url, re.IGNORECASE):
        errors.append(f"Open-source/Registry URL '{source_url}' must be an absolute http or https URL.")
    license_type = fields.get("declaredLicense", "").strip()
    if license_type and (license_type.casefold() == "multiple" or re.search(r"[\r\n,|]", license_type) or len(license_type) > 200):
        errors.append("Package License Type must contain one license declaration, not a list or multi-package placeholder.")
    return errors


def validation_comment(errors: list[str]) -> str:
    lines = ["[PACKAGE_REQUEST_VALIDATION_REQUIRED] The following field values need correction:", ""]
    lines.extend(f"- {error}" for error in errors)
    lines.extend(("", "After correcting the form values, add a new comment containing only: Fixed"))
    return "\n".join(lines)


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


def add_comment(instance: str, username: str, password: str, sys_id: str, message: str) -> None:
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = Request(
        f"https://{instance}/api/now/table/sc_req_item/{sys_id}",
        data=json.dumps({"comments": message}).encode("utf-8"),
        headers={
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="PATCH",
    )
    with urlopen(request, timeout=60) as response:
        if response.status not in {200, 201}:
            raise RuntimeError(f"ServiceNow validation comment returned HTTP {response.status}.")


def prepare_dispatches(source: dict[str, Any], instance: str, username: str, password: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in source.get("requestItems", []):
        context = normalize_service_now_context({"requestItems": [item]})
        fields = context.get("fields") or {}
        if fields.get("packageEcosystem") != "Python/PyPI":
            continue
        request_item = item.get("requestItem") if isinstance(item, dict) else {}
        ticket = str(context.get("ticketId") or "").strip()
        request_sys_id = str((request_item or {}).get("sys_id") or "").strip()
        state = validation_state(str((request_item or {}).get("comments") or ""))
        shared_fields = {name: str(fields.get(name) or "") for name in REQUIRED_FIELDS}
        try:
            multiple_request = is_multiple_request(shared_fields)
            package_lines = parse_package_list(str(fields.get("notes") or "")) if multiple_request else []
            errors = []
        except ValueError as exc:
            multiple_request = False
            package_lines = []
            errors = [str(exc)]
        if multiple_request:
            for line in package_lines:
                line_fields = dict(shared_fields)
                line_fields.update({name: line[name] for name in ("packageName", "requestedVersion", "openSourceUrl", "declaredLicense")})
                line_errors = format_errors(line_fields)
                errors.extend(f"Package list line {line['lineNumber']}: {error}" for error in line_errors)
        elif not errors:
            errors = format_errors(shared_fields)
        if errors:
            if state == "awaiting_requester_correction":
                results.append({"ticket": ticket, "status": "awaiting_requester_correction", "errors": errors})
                continue
            try:
                if not request_sys_id:
                    raise RuntimeError("ServiceNow request item sys_id is missing.")
                add_comment(instance, username, password, request_sys_id, validation_comment(errors))
                results.append({"ticket": ticket, "status": "validation_requested", "errors": errors})
            except Exception as exc:  # noqa: BLE001
                results.append({"ticket": ticket, "status": "failed_validation_comment", "errors": errors, "error": str(exc)})
            continue
        if state == "awaiting_requester_correction":
            results.append({"ticket": ticket, "status": "awaiting_requester_acknowledgement"})
            continue
        dispatch_lines = package_lines if multiple_request else [{
            "packageName": fields["packageName"].strip(),
            "requestedVersion": fields["requestedVersion"].strip() or "latest",
            "openSourceUrl": fields["openSourceUrl"].strip(),
            "declaredLicense": fields["declaredLicense"].strip(),
        }]
        for line in dispatch_lines:
            results.append({
                "ticket": ticket,
                "package": line["packageName"],
                "version": line["requestedVersion"] or "latest",
                "lineContext": line if multiple_request else None,
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
    args = parser.parse_args()
    if not args.instance or not args.username or not args.password:
        raise RuntimeError("SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD are required.")
    source = json.loads(args.input.read_text(encoding="utf-8"))
    results = prepare_dispatches(source, normalize_instance(args.instance), args.username, args.password)
    output = {"results": results}
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
