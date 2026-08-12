#!/usr/bin/env python3
"""Record an auditable outcome comment and optionally complete one ServiceNow RITM."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from inspect_servicenow_package_request import find_request_items, normalize_instance


def service_now_patch(
    instance: str, credential: str, table: str, sys_id: str, payload: dict
) -> dict:
    request = Request(
        f"https://{instance}/api/now/table/{table}/{sys_id}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Basic {credential}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="PATCH",
    )
    with urlopen(request, timeout=60) as response:
        if response.status not in {200, 201}:
            raise RuntimeError(f"ServiceNow {table} update returned HTTP {response.status}.")
        response_payload = json.load(response)
    result = response_payload.get("result") if isinstance(response_payload, dict) else None
    if not isinstance(result, dict):
        raise RuntimeError(f"ServiceNow {table} update did not return a result record.")
    return result


def close_active_catalog_tasks(instance: str, credential: str, ritm_sys_id: str, message: str) -> list[str]:
    """Close active sc_task records linked to one RITM and return their numbers."""
    query = urlencode({
        "sysparm_query": f"request_item={ritm_sys_id}^active=true",
        "sysparm_fields": "sys_id,number",
        "sysparm_limit": "100",
        "sysparm_display_value": "false",
    })
    request = Request(
        f"https://{instance}/api/now/table/sc_task?{query}",
        headers={"Authorization": f"Basic {credential}", "Accept": "application/json"},
    )
    with urlopen(request, timeout=60) as response:
        response_payload = json.load(response)
    tasks = response_payload.get("result") if isinstance(response_payload, dict) else None
    if not isinstance(tasks, list):
        raise RuntimeError("ServiceNow catalog-task lookup returned an unexpected response.")

    closed_tasks = []
    for task in tasks:
        task_sys_id = str(task.get("sys_id") or "")
        if not task_sys_id:
            continue
        result = service_now_patch(
            instance, credential, "sc_task", task_sys_id,
            {"state": "3", "close_notes": message},
        )
        state = str(result.get("state") or "")
        active = str(result.get("active") or "").lower()
        if state != "3" or active not in {"false", "0"}:
            raise RuntimeError(
                "ServiceNow accepted the catalog-task update but did not close it "
                f"(task={task.get('number')!r}, state={state!r}, active={active!r})."
            )
        closed_tasks.append(str(result.get("number") or task.get("number") or task_sys_id))
    return closed_tasks


def close_parent_request_if_complete(instance: str, credential: str, ritm_sys_id: str) -> str:
    """Close the parent REQ only when every RITM under it is inactive."""
    request = Request(
        f"https://{instance}/api/now/table/sc_req_item/{ritm_sys_id}?"
        "sysparm_fields=request&sysparm_display_value=false",
        headers={"Authorization": f"Basic {credential}", "Accept": "application/json"},
    )
    with urlopen(request, timeout=60) as response:
        response_payload = json.load(response)
    ritm = response_payload.get("result") if isinstance(response_payload, dict) else None
    parent = ritm.get("request") if isinstance(ritm, dict) else None
    request_sys_id = str(parent.get("value") or "") if isinstance(parent, dict) else str(parent or "")
    if not request_sys_id:
        return ""

    query = urlencode({
        "sysparm_query": f"request={request_sys_id}^active=true",
        "sysparm_fields": "sys_id",
        "sysparm_limit": "1",
        "sysparm_display_value": "false",
    })
    active_items_request = Request(
        f"https://{instance}/api/now/table/sc_req_item?{query}",
        headers={"Authorization": f"Basic {credential}", "Accept": "application/json"},
    )
    with urlopen(active_items_request, timeout=60) as response:
        active_payload = json.load(response)
    active_items = active_payload.get("result") if isinstance(active_payload, dict) else None
    if isinstance(active_items, list) and active_items:
        return ""

    result = service_now_patch(instance, credential, "sc_request", request_sys_id, {"state": "3"})
    state = str(result.get("state") or "")
    active = str(result.get("active") or "").lower()
    if state != "3" or active not in {"false", "0"}:
        raise RuntimeError(
            "ServiceNow accepted the parent-request update but did not close it "
            f"(state={state!r}, active={active!r})."
        )
    return str(result.get("number") or request_sys_id)


def update_request_item(
    instance: str, username: str, password: str, ritm_sys_id: str, message: str, close_complete: bool
) -> None:
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    payload = {"comments": message}
    if close_complete:
        # Verified in this instance's sc_req_item state choices:
        # state 3 = Closed Complete. The platform maintains the stage field.
        payload["state"] = "3"
    try:
        result = service_now_patch(instance, credential, "sc_req_item", ritm_sys_id, payload)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"ServiceNow request-item update failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"ServiceNow request-item update failed: {exc.reason}") from exc

    if close_complete:
        state = str(result.get("state") or "")
        active = str(result.get("active") or "").lower()
        if state != "3" or active not in {"false", "0"}:
            raise RuntimeError(
                "ServiceNow accepted the outcome comment but did not close the RITM "
                f"(returned state={state!r}, active={active!r})."
            )
        closed_tasks = close_active_catalog_tasks(instance, credential, ritm_sys_id, message)
        if closed_tasks:
            print(f"Closed linked ServiceNow catalog task(s): {', '.join(closed_tasks)}.")
        closed_request = close_parent_request_if_complete(instance, credential, ritm_sys_id)
        if closed_request:
            print(f"Closed parent ServiceNow request: {closed_request}.")


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