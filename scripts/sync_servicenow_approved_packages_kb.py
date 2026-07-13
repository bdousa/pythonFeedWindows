#!/usr/bin/env python3
"""Synchronize the approved Python package KB table from packages.json.

Each active, installable package version in the manifest is rendered as one KB
row.  The manifest's validationDate is the approval date and releaseUrl links
to the GitHub release that published the approved artifact.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class ApprovedVersion:
    package: str
    version: str
    validation_date: str
    release_url: str


def normalize_instance(value: str) -> str:
    instance = value.strip().rstrip("/")
    if instance.startswith(("http://", "https://")):
        instance = instance.split("://", 1)[1].split("/", 1)[0]
    if "." not in instance:
        instance = f"{instance}.service-now.com"
    return instance


def service_now_request(
    instance: str,
    username: str,
    password: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        f"https://{instance}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            return json.load(response)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"ServiceNow {method} {path} failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"ServiceNow request failed: {exc.reason}") from exc


def load_approved_versions(manifest_path: Path) -> list[ApprovedVersion]:
    with manifest_path.open(encoding="utf-8-sig") as handle:
        manifest = json.load(handle)

    approved: set[ApprovedVersion] = set()
    for key, package in manifest.get("packages", {}).items():
        if package.get("lifecycleState", "active") != "active" or not package.get("installable", True):
            continue
        package_name = str(package.get("name") or key).strip()
        for entry in package.get("versions", []):
            version = str(entry.get("version") or "").strip()
            validation_date = str(entry.get("validationDate") or "").strip()
            release_url = str(entry.get("releaseUrl") or "").strip()
            if package_name and version and validation_date:
                approved.add(ApprovedVersion(package_name, version, validation_date, release_url))

    return sorted(
        approved,
        key=lambda item: (item.package.casefold(), item.validation_date, item.version.casefold()),
    )


def render_table_body(approved: list[ApprovedVersion]) -> str:
    rows = [
        "<thead><tr><th>Package</th><th>Version</th><th>Approved Date</th><th>Release</th></tr></thead>",
        "<tbody>",
    ]
    for item in approved:
        release = (
            f'<a href="{html.escape(item.release_url, quote=True)}">GitHub release</a>'
            if item.release_url
            else ""
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.package)}</td>"
            f"<td>{html.escape(item.version)}</td>"
            f"<td>{html.escape(item.validation_date)}</td>"
            f"<td>{release}</td>"
            "</tr>"
        )
    rows.append("</tbody>")
    return "\n".join(rows)


def find_article(
    instance: str, username: str, password: str, kb_number: str
) -> dict[str, Any]:
    query = urlencode(
        {
            "sysparm_query": f"number={kb_number}^latest=true",
            "sysparm_fields": "sys_id,number,text,sys_updated_on,latest,workflow_state,active",
            "sysparm_limit": "10",
            "sysparm_display_value": "false",
        }
    )
    result = service_now_request(
        instance, username, password, "GET", f"/api/now/table/kb_knowledge?{query}"
    ).get("result", [])
    if not result:
        raise RuntimeError(f"KB article {kb_number} was not visible with latest=true.")
    return sorted(result, key=lambda article: article.get("sys_updated_on", ""), reverse=True)[0]


def replace_section_table(text: str, section_heading: str, table_body: str) -> tuple[str, bool]:
    words = [re.escape(word) for word in section_heading.split() if word]
    if not words:
        raise ValueError("Section heading must contain text.")
    separators = r"(?:\s|&nbsp;|<[^>]+>)*"
    heading_pattern = separators.join(words)
    heading_match = re.search(heading_pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not heading_match:
        raise RuntimeError(f"Could not locate KB section heading '{section_heading}'.")

    table_start = text.lower().find("<table", heading_match.end())
    if table_start < 0 or table_start - heading_match.start() > 5000:
        raise RuntimeError(f"Could not locate a table following KB section '{section_heading}'.")
    table_match = re.match(r"(?is)(<table\b[^>]*>)(.*?)(</table>)", text[table_start:])
    if not table_match:
        raise RuntimeError(f"The table following KB section '{section_heading}' is not closed.")

    updated_table = f"{table_match.group(1)}\n{table_body}\n{table_match.group(3)}"
    updated_text = text[:table_start] + updated_table + text[table_start + table_match.end() :]
    return updated_text, updated_text != text


def write_summary(path: Path | None, lines: list[str]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("packages.json"))
    parser.add_argument("--instance", default=os.getenv("SERVICENOW_INSTANCE", ""))
    parser.add_argument("--username", default=os.getenv("SERVICENOW_USERNAME", ""))
    parser.add_argument("--password", default=os.getenv("SERVICENOW_PASSWORD", ""))
    parser.add_argument("--kb-number", default="KB0027176")
    parser.add_argument("--section-heading", default="Approved Packages")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--summary-path", type=Path)
    args = parser.parse_args()

    if not args.instance or not args.username or not args.password:
        raise RuntimeError(
            "SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD are required."
        )
    if not args.manifest.is_file():
        raise RuntimeError(f"Manifest not found: {args.manifest}")

    approved = load_approved_versions(args.manifest)
    if not approved:
        raise RuntimeError("No active approved package versions with validationDate were found in packages.json.")

    instance = normalize_instance(args.instance)
    article = find_article(instance, args.username, args.password, args.kb_number)
    updated_text, changed = replace_section_table(
        str(article.get("text") or ""), args.section_heading, render_table_body(approved)
    )

    status = "already_current"
    if changed and not args.dry_run:
        service_now_request(
            instance,
            args.username,
            args.password,
            "PATCH",
            f"/api/now/table/kb_knowledge/{article['sys_id']}",
            {"text": updated_text},
        )
        status = "updated_kb"
    elif changed:
        status = "dry_run"

    payload = {
        "status": status,
        "kbNumber": args.kb_number,
        "kbSysId": article["sys_id"],
        "section": args.section_heading,
        "approvedVersionCount": len(approved),
        "manifest": str(args.manifest),
    }
    print(json.dumps(payload, indent=2))
    write_summary(
        args.summary_path,
        [
            "## ServiceNow approved Python packages KB sync",
            "",
            f"- Status: **{status}**",
            f"- KB: `{args.kb_number}`",
            f"- Section: {args.section_heading}",
            f"- Approved package versions from `packages.json`: {len(approved)}",
        ],
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
