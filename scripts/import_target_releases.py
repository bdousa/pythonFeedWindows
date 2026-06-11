#!/usr/bin/env python3
"""Import existing non-legacy GitHub releases into packages.json.

The legacy migration copies old release assets into this repository, but the
new repository can also contain already-published validation releases that are
not yet represented in the manifest. This script imports canonical versioned
release tags (``package-vX.Y.Z``), preserves existing legacy entries, updates
``latestReleaseTag`` to the imported release when appropriate, and regenerates
README.md.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import manifest_tools  # noqa: E402


DEFAULT_TARGET_OWNER = "bdousa"
DEFAULT_TARGET_REPO = "PythonFeed-Update"
REPORT_ASSETS = {"approval-report.json", "approval-report.md"}


_FIELD_RE_TEMPLATE = r"\|\s*{field}\s*\|\s*`?([^|`\r\n]+)`?\s*\|"


def gh_path() -> str:
    found = shutil.which("gh")
    if not found:
        raise RuntimeError("GitHub CLI 'gh' was not found on PATH.")
    return found


def run_gh(args: list[str]) -> str:
    result = subprocess.run(
        [gh_path(), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"gh command failed (exit {result.returncode}): {' '.join(args)}\n"
            f"stderr: {(result.stderr or '').strip()}"
        )
    return result.stdout


def load_releases(owner: str, repo: str) -> list[dict]:
    output = run_gh(
        [
            "api",
            f"repos/{owner}/{repo}/releases",
            "--paginate",
            "--jq",
            ".[]",
        ]
    )
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def parse_versioned_tag(tag: str) -> Optional[tuple[str, str]]:
    if tag.startswith("legacy-") or tag.endswith("-latest") or "-v" not in tag:
        return None
    package_name, version = tag.rsplit("-v", 1)
    if not package_name or not version:
        return None
    return package_name, version


def field_value(body: str, field: str) -> str:
    pattern = _FIELD_RE_TEMPLATE.format(field=re.escape(field))
    match = re.search(pattern, body or "", re.IGNORECASE)
    return match.group(1).replace("`", "").strip() if match else ""


def workflow_run(body: str) -> str:
    value = field_value(body, "Workflow run")
    if value:
        return value
    match = re.search(r"https://github\.com/[^\s|)]+/actions/runs/\d+", body or "")
    return match.group(0) if match else ""


def build_id_from_url(url: str) -> str:
    match = re.search(r"/actions/runs/(\d+)", url or "")
    return match.group(1) if match else ""


def asset_names(release: dict) -> list[str]:
    return [asset.get("name", "") for asset in release.get("assets", []) if asset.get("name")]


def package_prefixes(package_name: str) -> tuple[str, str]:
    return package_name.lower(), package_name.replace("-", "_").lower()


def main_package_file(package_name: str, assets: list[str]) -> str:
    hyphen_prefix, underscore_prefix = package_prefixes(package_name)
    package_files = [name for name in assets if name not in REPORT_ASSETS]
    for name in package_files:
        lower_name = name.lower()
        if lower_name.startswith(f"{hyphen_prefix}-") or lower_name.startswith(f"{underscore_prefix}-"):
            return name
    return package_files[0] if package_files else ""


def clean_files(assets: list[str]) -> list[str]:
    return [name for name in assets if name not in REPORT_ASSETS]


def should_promote(package: dict, version: str, release_tag: str) -> bool:
    if package.get("latestReleaseTag") == release_tag:
        return True
    latest_tag = package.get("latestReleaseTag", "")
    latest_version = package.get("latestVersion", "")
    if latest_tag.startswith("legacy-") and version != "latest":
        return True
    return manifest_tools.should_update_latest(latest_version, version)


def release_to_entry(release: dict, package_name: str, version: str, owner: str, repo: str) -> dict:
    body = release.get("body") or ""
    validated_version = field_value(body, "Validated version") or version
    if validated_version == "latest":
        validated_version = version
    validation_date = field_value(body, "Report date")
    if not validation_date and release.get("published_at"):
        validation_date = release["published_at"][:10]
    assets = asset_names(release)
    primary_file = main_package_file(package_name, assets)
    pipeline_url = workflow_run(body)
    release_tag = release["tag_name"]
    return {
        "version": validated_version,
        "releaseTag": release_tag,
        "validationDate": validation_date,
        "installUrl": (
            f"pip install https://github.com/{owner}/{repo}/releases/download/"
            f"{release_tag}/{primary_file}"
        ),
        "packageType": manifest_tools.determine_package_type(primary_file),
        "releaseUrl": f"https://github.com/{owner}/{repo}/releases/tag/{release_tag}",
        "pipelineUrl": pipeline_url,
        "buildId": build_id_from_url(pipeline_url),
        "files": clean_files(assets),
    }


def upsert_entry(manifest: dict, package_name: str, entry: dict) -> str:
    package = manifest["packages"].setdefault(
        package_name,
        {
            "name": package_name,
            "latestVersion": "",
            "latestReleaseTag": "",
            "versions": [],
            "lifecycleState": "active",
            "installable": True,
        },
    )
    package["name"] = package_name
    package.setdefault("versions", [])
    package.setdefault("lifecycleState", "active")
    package.setdefault("installable", package.get("lifecycleState") == "active")

    replaced = False
    for index, existing in enumerate(package["versions"]):
        if existing.get("releaseTag") == entry["releaseTag"]:
            package["versions"][index] = entry
            replaced = True
            break
    if not replaced:
        package["versions"].append(entry)

    if should_promote(package, entry["version"], entry["releaseTag"]):
        package["latestVersion"] = entry["version"]
        package["latestReleaseTag"] = entry["releaseTag"]

    return "updated" if replaced else "added"


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Import existing target repo releases into packages.json.")
    parser.add_argument("--manifest-path", default=str(repo_root / "packages.json"))
    parser.add_argument("--manifest-output", default=None)
    parser.add_argument("--readme-output", default=str(repo_root / "README.md"))
    parser.add_argument("--target-owner", default=DEFAULT_TARGET_OWNER)
    parser.add_argument("--target-repo", default=DEFAULT_TARGET_REPO)
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-readme", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    manifest_path = Path(args.manifest_path)
    manifest = manifest_tools.load_manifest(manifest_path)
    only = {name.lower() for name in args.only}

    releases = load_releases(args.target_owner, args.target_repo)
    candidates = []
    for release in releases:
        parsed = parse_versioned_tag(release.get("tag_name", ""))
        if not parsed:
            continue
        package_name, version = parsed
        if only and package_name.lower() not in only:
            continue
        candidates.append((package_name, version, release))

    candidates.sort(key=lambda item: item[0].lower())
    changes = []
    for package_name, version, release in candidates:
        entry = release_to_entry(release, package_name, version, args.target_owner, args.target_repo)
        action = upsert_entry(manifest, package_name, entry)
        changes.append((action, package_name, entry["version"], entry["releaseTag"]))

    print(f"Versioned target releases considered: {len(candidates)}")
    for action, package_name, version, release_tag in changes:
        print(f"  - {action}: {package_name} {version} ({release_tag})")

    if args.dry_run:
        print("Dry run complete. No files were written.")
        return 0

    manifest["generatedAt"] = manifest_tools.utc_now_iso()
    manifest_output = Path(args.manifest_output or args.manifest_path)
    manifest_tools.write_manifest(manifest, manifest_output)
    if not args.skip_readme:
        manifest_tools.write_text(Path(args.readme_output), manifest_tools.render_readme(manifest))
    print("Import complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
