#!/usr/bin/env python3

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def utc_display_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def load_manifest(path: Path) -> dict:
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    else:
        manifest = {"schemaVersion": 1, "generatedAt": "", "packages": {}}
    return normalize_manifest(manifest)


def normalize_manifest(manifest: dict) -> dict:
    manifest.setdefault("schemaVersion", 1)
    manifest.setdefault("generatedAt", "")
    packages = manifest.setdefault("packages", {})
    for package_name, package in packages.items():
        package.setdefault("name", package_name)
        package.setdefault("latestVersion", "")
        package.setdefault("latestReleaseTag", "")
        package.setdefault("versions", [])
        package.setdefault("lifecycleState", "active")
        package.setdefault("installable", package.get("lifecycleState", "active") == "active")
    return manifest


def write_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def determine_package_type(file_name: str) -> str:
    if re.search(r"cp313-cp313-win_amd64\.whl$", file_name):
        return "Python 3.13 64-bit wheel"
    if re.search(r"cp313-.*\.whl$", file_name):
        return "Python 3.13 wheel"
    if re.search(r"py3-none-any\.whl$", file_name):
        return "Universal wheel (Python 3+)"
    if re.search(r"py2\.py3-none-any\.whl$", file_name):
        return "Universal wheel (Python 3+)"
    if file_name.endswith(".whl"):
        return "Wheel (check compatibility)"
    if file_name.endswith(".tar.gz"):
        return "Source distribution"
    return "Unknown"


def parse_version_from_filename(file_name: str) -> str:
    wheel_match = re.match(r"^[^-]+-([0-9]+\.[0-9]+(?:\.[0-9]+)?[^-]*)-", file_name)
    if wheel_match:
        return wheel_match.group(1)
    if file_name.endswith(".tar.gz"):
        stem = file_name[:-7]
        parts = stem.split("-")
        if len(parts) >= 2:
            return "-".join(parts[1:])
    return ""


def clean_version_parts(value: str):
    cleaned = re.sub(r"[^0-9.].*$", "", value or "").strip(".")
    if not cleaned:
        return None
    try:
        return tuple(int(piece) for piece in cleaned.split("."))
    except ValueError:
        return None


def should_update_latest(existing_latest: str, version_display: str) -> bool:
    if not existing_latest or version_display == existing_latest:
        return True
    if version_display == "latest" and existing_latest != "latest":
        return False
    if existing_latest == "latest" and version_display != "latest":
        return False
    if existing_latest != "latest" and version_display != "latest":
        new_parts = clean_version_parts(version_display)
        old_parts = clean_version_parts(existing_latest)
        if new_parts and old_parts and new_parts < old_parts:
            return False
    return True


def find_main_package_file(package_dir: Path, package_name: str) -> Path:
    normalized_name = package_name.replace("-", "_").lower()
    candidates = []
    for file_path in sorted(package_dir.iterdir()):
        if not file_path.is_file():
            continue
        name_lower = file_path.name.lower()
        if name_lower.startswith(f"{package_name.lower()}-") or name_lower.startswith(f"{normalized_name}-"):
            candidates.append(file_path)
    if not candidates:
        raise FileNotFoundError(f"Could not identify the downloaded package file for {package_name}.")
    return candidates[0]


def sorted_package_items(manifest: dict, state: str):
    packages = []
    for package_name in sorted(manifest.get("packages", {}).keys(), key=str.lower):
        package = manifest["packages"][package_name]
        if package.get("lifecycleState", "active") == state:
            packages.append((package_name, package))
    return packages


def render_active_table(manifest: dict, lines: list[str]) -> None:
    lines.append("## Available Packages (latest validated version)")
    lines.append("")
    lines.append("| Package | Latest Version | Validated | Install (latest) | Release | Older Validated Versions |")
    lines.append("|---------|----------------|-----------|------------------|---------|--------------------------|")
    active_packages = sorted_package_items(manifest, "active")
    if not active_packages:
        lines.append("| - | - | - | - | - | - |")
        return

    for package_name, package in active_packages:
        latest_version = package.get("latestVersion", "")
        latest_entry = next((entry for entry in package.get("versions", []) if entry.get("version") == latest_version), None)
        latest_install = latest_entry.get("installUrl", "") if latest_entry else ""
        latest_date = latest_entry.get("validationDate", "") if latest_entry else ""
        latest_release_url = latest_entry.get("releaseUrl", "") if latest_entry else ""
        latest_release = f"[release]({latest_release_url})" if latest_release_url else ""
        older_versions = [entry for entry in package.get("versions", []) if entry.get("version") != latest_version]
        older_versions.sort(key=lambda item: item.get("validationDate", ""), reverse=True)
        if older_versions:
            older_items = []
            for entry in older_versions:
                install_value = entry.get("installUrl", "").replace("<", "&lt;").replace(">", "&gt;")
                release_value = entry.get("releaseUrl", "")
                release_markup = f' - <a href="{release_value}">release</a>' if release_value else ""
                older_items.append(
                    f"<li><strong>{entry.get('version', '')}</strong> - Validated: {entry.get('validationDate', '')} - <code>{install_value}</code>{release_markup}</li>"
                )
            versions_cell = f"<details><summary>{len(older_versions)} older version(s)</summary><ul>{''.join(older_items)}</ul></details>"
        else:
            versions_cell = "-"
        lines.append(
            f"| `{package_name}` | `{latest_version}` | {latest_date} | `{latest_install}` | {latest_release} | {versions_cell} |"
        )


def render_deprecated_table(manifest: dict, lines: list[str]) -> None:
    deprecated_packages = sorted_package_items(manifest, "deprecated")
    if not deprecated_packages:
        return
    lines.append("")
    lines.append("## Deprecated Packages")
    lines.append("")
    lines.append("Deprecated packages are tracked for audit purposes only and are no longer approved for use from this feed.")
    lines.append("")
    for package_name, package in deprecated_packages:
        deprecated_at = package.get("deprecatedAt", "") or "unknown"
        reason = package.get("deprecationReason", "") or "not provided"
        last_version = package.get("latestVersion", "") or "unknown"
        tracked = len(package.get("versions", []))
        lines.append(f"- **`{package_name}`** - deprecated {deprecated_at}")
        lines.append(f"  - Reason: {reason}")
        lines.append(f"  - Last validated version: `{last_version}`")
        lines.append(f"  - Versions tracked: {tracked}")


def render_readme(manifest: dict) -> str:
    lines: list[str] = []
    lines.append("# Security Validated Python Packages")
    lines.append("")
    lines.append("This repository contains Python packages validated through automated security scanning and manual approval.")
    lines.append("")
    lines.append("> The canonical package index is [`packages.json`](./packages.json). This README is generated from that manifest and should not be edited by hand.")
    lines.append("")
    lines.append("## Requirements")
    lines.append("- **Python 3.13.x** (required for compatibility)")
    lines.append("- **Windows 64-bit** environment")
    lines.append("")
    render_active_table(manifest, lines)
    render_deprecated_table(manifest, lines)
    lines.append("")
    lines.append(f"*Generated from `packages.json` on {utc_display_time()}*")
    lines.append("")
    return "\n".join(lines)


def upsert_release(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest_path)
    package_dir = Path(args.package_dir)
    manifest = load_manifest(manifest_path)

    main_file = find_main_package_file(package_dir, args.package_name)
    package_files = [file_path.name for file_path in sorted(package_dir.iterdir()) if file_path.is_file()]
    actual_version = parse_version_from_filename(main_file.name)
    if not actual_version:
        requested_version = (args.package_version or "").strip()
        actual_version = requested_version if requested_version and requested_version != "latest" else "latest"

    version_display = actual_version if actual_version and actual_version != "latest" else "latest"
    release_tag = f"{args.package_name}-v{version_display}" if version_display != "latest" else f"{args.package_name}-latest"
    install_url = (
        f"pip install https://github.com/{args.repo_owner}/{args.repo_name}/releases/download/"
        f"{release_tag}/{main_file.name}"
    )
    release_url = f"https://github.com/{args.repo_owner}/{args.repo_name}/releases/tag/{release_tag}"
    validation_date = utc_today()
    version_entry = {
        "version": version_display,
        "releaseTag": release_tag,
        "validationDate": validation_date,
        "installUrl": install_url,
        "packageType": determine_package_type(main_file.name),
        "releaseUrl": release_url,
        "pipelineUrl": args.pipeline_url,
        "buildId": str(args.build_id),
        "files": package_files,
    }

    package = manifest["packages"].get(args.package_name)
    if not package:
        package = {
            "name": args.package_name,
            "latestVersion": version_display,
            "latestReleaseTag": release_tag,
            "versions": [],
            "lifecycleState": "active",
            "installable": True,
        }
        manifest["packages"][args.package_name] = package

    package["name"] = args.package_name
    package.setdefault("versions", [])
    package["lifecycleState"] = "active"
    package["installable"] = True
    package.pop("deprecatedAt", None)
    package.pop("deprecationReason", None)

    replaced = False
    rebuilt_versions = []
    for existing in package["versions"]:
        if existing.get("version") == version_display:
            rebuilt_versions.append(version_entry)
            replaced = True
        else:
            rebuilt_versions.append(existing)
    if not replaced:
        rebuilt_versions.append(version_entry)
    package["versions"] = rebuilt_versions

    if should_update_latest(package.get("latestVersion", ""), version_display):
        package["latestVersion"] = version_display
        package["latestReleaseTag"] = release_tag

    manifest["generatedAt"] = utc_now_iso()
    manifest_output = Path(args.manifest_output or args.manifest_path)
    readme_output = Path(args.readme_output)
    write_manifest(manifest, manifest_output)
    write_text(readme_output, render_readme(manifest))
    return 0


def set_lifecycle(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest_path)
    manifest = load_manifest(manifest_path)
    package = manifest["packages"].get(args.package_name)
    if not package:
        raise KeyError(f"Package not found in manifest: {args.package_name}")

    if args.lifecycle_action == "deprecate":
        package["lifecycleState"] = "deprecated"
        package["installable"] = False
        package["deprecatedAt"] = utc_today()
        package["deprecationReason"] = (args.reason or "").strip()
    elif args.lifecycle_action == "restore":
        package["lifecycleState"] = "active"
        package["installable"] = True
        package.pop("deprecatedAt", None)
        package.pop("deprecationReason", None)
    elif args.lifecycle_action == "delete":
        del manifest["packages"][args.package_name]
    else:
        raise ValueError(f"Unsupported lifecycle action: {args.lifecycle_action}")

    manifest["generatedAt"] = utc_now_iso()
    manifest_output = Path(args.manifest_output or args.manifest_path)
    write_manifest(manifest, manifest_output)
    write_text(Path(args.readme_output), render_readme(manifest))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage package manifest and generated README.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    upsert = subparsers.add_parser("upsert-release", help="Upsert a validated package version into the manifest.")
    upsert.add_argument("--manifest-path", required=True)
    upsert.add_argument("--manifest-output")
    upsert.add_argument("--readme-output", required=True)
    upsert.add_argument("--package-name", required=True)
    upsert.add_argument("--package-version", default="latest")
    upsert.add_argument("--package-dir", required=True)
    upsert.add_argument("--repo-owner", required=True)
    upsert.add_argument("--repo-name", required=True)
    upsert.add_argument("--pipeline-url", required=True)
    upsert.add_argument("--build-id", required=True)
    upsert.set_defaults(func=upsert_release)

    lifecycle = subparsers.add_parser("set-lifecycle", help="Change package lifecycle state.")
    lifecycle.add_argument("--manifest-path", required=True)
    lifecycle.add_argument("--manifest-output")
    lifecycle.add_argument("--readme-output", required=True)
    lifecycle.add_argument("--package-name", required=True)
    lifecycle.add_argument("--lifecycle-action", required=True, choices=["deprecate", "restore", "delete"])
    lifecycle.add_argument("--reason", default="")
    lifecycle.set_defaults(func=set_lifecycle)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())