#!/usr/bin/env python3
"""Add an auditable customer-visible outcome comment to one ServiceNow RITM."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from inspect_servicenow_package_request import find_request_items, normalize_instance


def add_comment(instance: str, username: str, password: str, ritm_sys_id: str, message: str) -> None:
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = Request(
        f"https://{instance}/api/now/table/sc_req_item/{ritm_sys_id}",
        data=json.dumps({"comments": message}).encode("utf-8"),
        headers={
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="PATCH",
    )
    try:
        with urlopen(request, timeout=60) as response:
            if response.status not in {200, 201}:
                raise RuntimeError(f"ServiceNow comment update returned HTTP {response.status}.")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"ServiceNow comment update failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"ServiceNow comment update failed: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ticket", required=True, help="ServiceNow RITM number; parent REQ values are rejected.")
    parser.add_argument("--message", required=True)
    parser.add_argument("--instance", default=os.getenv("SERVICENOW_INSTANCE", ""))
    parser.add_argument("--username", default=os.getenv("SERVICENOW_USERNAME", ""))
    parser.add_argument("--password", default=os.getenv("SERVICENOW_PASSWORD", ""))
    args = parser.parse_args()

    if not args.ticket.upper().startswith("RITM"):
        raise ValueError("Supply one RITM number to prevent commenting on multiple request items.")
    if not args.instance or not args.username or not args.password:
        raise RuntimeError("SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD are required.")

    items = find_request_items(
        normalize_instance(args.instance), args.username, args.password, args.ticket.strip()
    )
    if len(items) != 1:
        raise RuntimeError("A ticket comment requires exactly one matching RITM.")
    add_comment(
        normalize_instance(args.instance), args.username, args.password,
        str(items[0].get("sys_id") or ""), args.message.strip(),
    )
    print(f"Added ServiceNow comment to {args.ticket.strip()}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)