#!/usr/bin/env python3
"""Read a ServiceNow package-request ticket and enumerate its catalog variables.

The script is intentionally read-only. It supports either an RITM number or
its parent REQ number, writes no changes to ServiceNow, and returns both the
catalog-variable technical names and their submitted values. Use its output to
verify the form-to-workflow mapping before automating package validation.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def normalize_instance(value: str) -> str:
    instance = value.strip().rstrip("/")
    if instance.startswith(("http://", "https://")):
        instance = instance.split("://", 1)[1].split("/", 1)[0]
    if "." not in instance:
        instance = f"{instance}.service-now.com"
    return instance


def service_now_get(
    instance: str, username: str, password: str, table: str, query: dict[str, str]
) -> list[dict[str, Any]]:
    credential = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    path = f"/api/now/table/{table}?{urlencode(query)}"
    request = Request(
        f"https://{instance}{path}",
        headers={"Authorization": f"Basic {credential}", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"ServiceNow GET {path} failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"ServiceNow request failed: {exc.reason}") from exc

    result = payload.get("result", [])
    if not isinstance(result, list):
        raise RuntimeError(f"ServiceNow returned an unexpected response for table {table}.")
    return result


def find_request_items(
    instance: str, username: str, password: str, ticket: str
) -> list[dict[str, Any]]:
    fields = "sys_id,number,short_description,request,cat_item,state,stage,opened_at,opened_by,requested_for"
    # A catalog request normally has a REQ number and one or more RITM records.
    # The dot-walk query also lets callers pass a REQ number directly.
    items = service_now_get(
        instance,
        username,
        password,
        "sc_req_item",
        {
            "sysparm_query": f"number={ticket}^ORrequest.number={ticket}",
            "sysparm_fields": fields,
            "sysparm_limit": "100",
            "sysparm_display_value": "true",
        },
    )
    if not items:
        raise RuntimeError(
            f"No requested item was found for {ticket}. Supply its RITM number or parent REQ number, "
            "and confirm the integration account can read sc_req_item."
        )
    return items


def find_latest_category_request_item(
    instance: str, username: str, password: str, category: str
) -> list[dict[str, Any]]:
    catalog_items = service_now_get(
        instance,
        username,
        password,
        "sc_cat_item",
        {
            "sysparm_query": f"category.title={category}^active=true",
            "sysparm_fields": "sys_id,name,short_description,category",
            "sysparm_limit": "100",
            "sysparm_display_value": "true",
        },
    )
    catalog_item_ids = [str(item.get("sys_id") or "") for item in catalog_items if item.get("sys_id")]
    if not catalog_item_ids:
        raise RuntimeError(
            f"No active catalog items were found in the {category!r} category. "
            "Verify the category label and the integration account access."
        )

    fields = "sys_id,number,short_description,request,cat_item,state,stage,opened_at,opened_by,requested_for"
    items = service_now_get(
        instance,
        username,
        password,
        "sc_req_item",
        {
            "sysparm_query": f"cat_itemIN{','.join(catalog_item_ids)}^ORDERBYDESCsys_created_on",
            "sysparm_fields": fields,
            "sysparm_limit": "1",
            "sysparm_display_value": "true",
        },
    )
    if not items:
        raise RuntimeError(f"No request items were found for catalog category {category!r}.")
    return items


def find_latest_request_category_item(
    instance: str, username: str, password: str, category: str
) -> list[dict[str, Any]]:
    categories = service_now_get(
        instance,
        username,
        password,
        "u_request_category",
        {
            "sysparm_query": f"u_category={category}^u_deprecated=false",
            "sysparm_fields": "sys_id,u_category,u_item",
            "sysparm_limit": "100",
            "sysparm_display_value": "false",
        },
    )
    category_ids = [str(value.get("sys_id") or "") for value in categories if value.get("sys_id")]
    if not category_ids:
        raise RuntimeError(
            f"No active request-category records were found for {category!r}. "
            "Verify the form's Category value."
        )

    options = service_now_get(
        instance,
        username,
        password,
        "sc_item_option_mtom",
        {
            "sysparm_query": "sc_item_option.item_option_new.name=devops_category"
            f"^sc_item_option.valueIN{','.join(category_ids)}^ORDERBYDESCrequest_item.sys_created_on",
            "sysparm_fields": "request_item",
            "sysparm_limit": "1",
            "sysparm_display_value": "false",
        },
    )
    request_item_ids = [
        str(value["request_item"].get("value") or "")
        if isinstance(value.get("request_item"), dict)
        else str(value.get("request_item") or "")
        for value in options
        if value.get("request_item")
    ]
    if not request_item_ids:
        raise RuntimeError(f"No request items were found for request category {category!r}.")

    fields = "sys_id,number,short_description,request,cat_item,state,stage,opened_at,opened_by,requested_for"
    return service_now_get(
        instance,
        username,
        password,
        "sc_req_item",
        {
            "sysparm_query": f"sys_id={request_item_ids[0]}",
            "sysparm_fields": fields,
            "sysparm_limit": "1",
            "sysparm_display_value": "true",
        },
    )


def find_latest_short_description_item(
    instance: str, username: str, password: str, short_description: str
) -> list[dict[str, Any]]:
    fields = "sys_id,number,short_description,request,cat_item,state,stage,opened_at,opened_by,requested_for"
    items = service_now_get(
        instance,
        username,
        password,
        "sc_req_item",
        {
            "sysparm_query": f"short_description={short_description}^ORDERBYDESCsys_created_on",
            "sysparm_fields": fields,
            "sysparm_limit": "1",
            "sysparm_display_value": "true",
        },
    )
    if not items:
        raise RuntimeError(f"No request items were found with short description {short_description!r}.")
    return items


def catalog_variables(
    instance: str, username: str, password: str, item_sys_id: str
) -> list[dict[str, str]]:
    links = service_now_get(
        instance,
        username,
        password,
        "sc_item_option_mtom",
        {
            "sysparm_query": f"request_item={item_sys_id}",
            "sysparm_fields": "sc_item_option,sc_item_option.value,"
            "sc_item_option.item_option_new.name,"
            "sc_item_option.item_option_new.question_text,"
            "sc_item_option.item_option_new.type",
            "sysparm_limit": "1000",
            "sysparm_display_value": "true",
        },
    )

    variables: list[dict[str, str]] = []
    for link in links:
        variables.append(
            {
                "name": str(link.get("sc_item_option.item_option_new.name") or ""),
                "question": str(link.get("sc_item_option.item_option_new.question_text") or ""),
                "type": str(link.get("sc_item_option.item_option_new.type") or ""),
                "value": str(link.get("sc_item_option.value") or ""),
            }
        )
    return sorted(variables, key=lambda value: (value["question"].casefold(), value["name"].casefold()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    request_source = parser.add_mutually_exclusive_group(required=True)
    request_source.add_argument("--ticket", help="ServiceNow RITM or parent REQ number.")
    request_source.add_argument(
        "--latest-category",
        help="Inspect the newest request item for this ServiceNow catalog category.",
    )
    request_source.add_argument(
        "--latest-catalog-item",
        help="Inspect the newest request item for this catalog-item sys_id.",
    )
    request_source.add_argument(
        "--latest-request-category",
        help="Inspect the newest request item for the form's custom Category value.",
    )
    request_source.add_argument(
        "--latest-short-description",
        help="Inspect the newest request item matching this exact short description.",
    )
    parser.add_argument("--instance", default=os.getenv("SERVICENOW_INSTANCE", ""))
    parser.add_argument("--username", default=os.getenv("SERVICENOW_USERNAME", ""))
    parser.add_argument("--password", default=os.getenv("SERVICENOW_PASSWORD", ""))
    parser.add_argument("--output", type=Path, help="Optional JSON output path.")
    args = parser.parse_args()

    if not args.instance or not args.username or not args.password:
        raise RuntimeError(
            "SERVICENOW_INSTANCE, SERVICENOW_USERNAME, and SERVICENOW_PASSWORD are required."
        )

    instance = normalize_instance(args.instance)
    if args.ticket:
        request_items = find_request_items(instance, args.username, args.password, args.ticket.strip())
        source = {"ticket": args.ticket.strip()}
    elif args.latest_category:
        request_items = find_latest_category_request_item(
            instance, args.username, args.password, args.latest_category.strip()
        )
        source = {"latestCategory": args.latest_category.strip()}
    elif args.latest_catalog_item:
        request_items = service_now_get(
            instance,
            args.username,
            args.password,
            "sc_req_item",
            {
                "sysparm_query": f"cat_item={args.latest_catalog_item.strip()}^ORDERBYDESCsys_created_on",
                "sysparm_fields": "sys_id,number,short_description,request,cat_item,state,stage,opened_at,opened_by,requested_for",
                "sysparm_limit": "1",
                "sysparm_display_value": "true",
            },
        )
        if not request_items:
            raise RuntimeError(
                f"No request items were found for catalog item {args.latest_catalog_item.strip()!r}."
            )
        source = {"latestCatalogItem": args.latest_catalog_item.strip()}
    else:
        if args.latest_request_category:
            request_items = find_latest_request_category_item(
                instance, args.username, args.password, args.latest_request_category.strip()
            )
            source = {"latestRequestCategory": args.latest_request_category.strip()}
        else:
            request_items = find_latest_short_description_item(
                instance, args.username, args.password, args.latest_short_description.strip()
            )
            source = {"latestShortDescription": args.latest_short_description.strip()}
    output_items = []
    for item in request_items:
        item_sys_id = str(item.get("sys_id") or "")
        output_items.append({
            "requestItem": item,
            "catalogVariables": catalog_variables(instance, args.username, args.password, item_sys_id),
        })

    output = {**source, "requestItems": output_items}
    rendered = json.dumps(output, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote inspection result to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
