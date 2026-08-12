#!/usr/bin/env python3
"""Record an auditable outcome comment and optionally complete one ServiceNow RITM."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from inspect_servicenow_package_request import find_request_items, normalize_instance


def update_request_item(
    instance: str, username: str, password: str, ritm_sys_id: str, message: str, close_complete: bool
) -> None:
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    payload = {"comments": message}
    if close_complete:
        # Verified in this instance's sc_req_item state choices:
        # state 3 = Closed Complete. The platform maintains the stage field.
        payload["state"] = "3"
    request = Request(
        f"https://{instance}/api/now/table/sc_req_item/{ritm_sys_id}",
        data=json.dumps(payload).encode("utf-8"),
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
                raise RuntimeError(f"ServiceNow request-item update returned HTTP {response.status}.")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"ServiceNow request-item update failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"ServiceNow request-item update failed: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ticket", required=True, help="ServiceNow RITM number; parent REQ values are rejected.")
    parser.add_argument("--message", required=True)
    parser.add_argument(
        "--close-complete",
        action="store_true",
        help="Set the RITM to the verified Closed Complete state after recording the outcome.",
    )
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
    update_request_item(
        normalize_instance(args.instance), args.username, args.password,
        str(items[0].get("sys_id") or ""), args.message.strip(), args.close_complete,
    )
    result = "and closed it as Closed Complete" if args.close_complete else ""
    print(f"Updated ServiceNow request {args.ticket.strip()} {result}.".rstrip())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)