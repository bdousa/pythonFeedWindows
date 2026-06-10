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


def format_generated_at(manifest: dict) -> str:
    generated_at = (manifest.get("generatedAt") or "").strip()
    if generated_at:
        try:
            parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            pass
    return utc_display_time()


def append_usage_sections(lines: list[str]) -> None:
    lines.append("## 🚀 Usage Instructions")
    lines.append("")
    lines.append("### 🐍 Python 3.13.x Installation Requirements")
    lines.append("All packages in this repository require Python 3.13.x for compatibility. If you don't have Python 3.13 installed, follow the instructions below for your platform:")
    lines.append("")
    lines.append("### 🪟 Windows Installation")
    lines.append("")
    lines.append("Currently these are all x64 packages, not x86 (32-bit)")
    lines.append("")
    lines.append("#### Official Python Installer")
    lines.append("")
    lines.append("Download Python 3.13.x from python.org")
    lines.append("")
    lines.append("Run the installer with these important settings:")
    lines.append("- ✅ Check \"Add Python to PATH\"")
    lines.append("- ✅ Check \"Install for all users\" (if you have admin rights)")
    lines.append("- ✅ Choose \"Customize installation\" → Advanced Options → Check \"Add Python to environment variables\"")
    lines.append("")
    lines.append("### Package Installation Instructions")
    lines.append("#### Option 1: Direct Install")
    lines.append("Use the quick install commands from the package sections above.")
    lines.append("")
    lines.append("#### Option 2: Requirements File")
    lines.append("")
    lines.append("Create a requirements.txt with direct GitHub URLs:")
    lines.append("```")
    lines.append("https://github.com/bdousa/pythonFeed/releases/download/requests-v2.32.4/requests-2.32.4-py3-none-any.whl")
    lines.append("https://github.com/bdousa/pythonFeed/releases/download/numpy-v1.24.3/numpy-1.24.3-cp311-cp311-linux_x86_64.whl")
    lines.append("```")
    lines.append("")
    lines.append("## 🔍 Security Validation Process")
    lines.append("All packages in this repository have been validated through our comprehensive security pipeline:")
    lines.append("- ✅ **Vulnerability Scanning** - Scanned with Snyk for known CVEs")
    lines.append("- ✅ **Source Code Analysis** - Static analysis for security issues")
    lines.append("- ✅ **Dependency Analysis** - All dependencies scanned for vulnerabilities")
    lines.append("- ✅ **License Compliance** - License compatibility verified")
    lines.append("- ✅ **Manual Review** - Security team approval required")
    lines.append("- ✅ **Package Integrity** - Cryptographic verification of packages")
    lines.append("")
    lines.append("## 📋 Request New Package Review")
    lines.append("To request validation of a new package:")
    lines.append("1. **Azure DevOps Request**: Go to [ServiceNow Request Portal](https://bdous.service-now.com/sp?id=sc_cat_item&sys_id=c746dd861b3e6910182c63d07e4bcbac)")
    lines.append("2. **Select Category**: Choose '3rd party library approval'")
    lines.append("3. **Approval Process**: Packages typically validated within 3 business days")


def append_readme_footer(lines: list[str], manifest: dict) -> None:
    lines.append("")
    lines.append(f"*Last updated: {format_generated_at(manifest)}*")
    lines.append("")
    lines.append("*Powered by Azure DevOps Security Pipeline*")


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


def install_label_for(package_type: str) -> str:
    pt = (package_type or "").lower()
    if "source distribution" in pt:
        return "Download source distribution"
    if "wheel" in pt:
        return "Download wheel"
    return "Download package"


def artifact_url(install_command: str) -> str:
    match = re.search(r"https?://\S+", install_command or "")
    if not match:
        return ""
    return match.group(0).rstrip("'\")")


def render_quick_stats(manifest: dict, lines: list[str]) -> None:
    active = sorted_package_items(manifest, "active")
    deprecated = sorted_package_items(manifest, "deprecated")
    most_recent_date = ""
    most_recent_name = ""
    for name, package in active:
        for entry in package.get("versions", []):
            v_date = entry.get("validationDate", "")
            if v_date > most_recent_date:
                most_recent_date = v_date
                most_recent_name = name
    lines.append("## 📊 Quick Stats")
    lines.append(f"- **Active packages:** {len(active)}")
    lines.append(f"- **Deprecated packages:** {len(deprecated)}")
    if most_recent_date:
        lines.append(f"- **Most recent validation:** {most_recent_date} (`{most_recent_name}`)")
    lines.append("- **Target runtime:** Python 3.13.x on Windows x64")
    lines.append("")


def render_recently_validated(manifest: dict, lines: list[str], limit: int = 5) -> None:
    recent: list[tuple[str, str, str]] = []
    for name, package in sorted_package_items(manifest, "active"):
        latest_version = package.get("latestVersion", "")
        latest_entry = next(
            (entry for entry in package.get("versions", []) if entry.get("version") == latest_version),
            None,
        )
        if latest_entry:
            recent.append((latest_entry.get("validationDate", ""), name, latest_version))
    if not recent:
        return
    recent.sort(reverse=True)
    lines.append("## 🆕 Recently Validated")
    lines.append("")
    lines.append("| Package | Version | Validated |")
    lines.append("|---------|---------|-----------|")
    for date, name, version in recent[:limit]:
        lines.append(f"| [`{name}`](#{name}) | `{version}` | {date} |")
    lines.append("")


def render_quick_jump(manifest: dict, lines: list[str]) -> None:
    letters = sorted({name[0].lower() for name, _ in sorted_package_items(manifest, "active") if name})
    if not letters:
        return
    lines.append("## 🔎 Quick Jump")
    lines.append("")
    lines.append(" · ".join(f"[{letter.upper()}](#{letter})" for letter in letters))
    lines.append("")


def render_active_packages(manifest: dict, lines: list[str]) -> None:
    lines.append("## 📦 Available Packages")
    lines.append("")
    active = sorted_package_items(manifest, "active")
    if not active:
        lines.append("No active validated packages are currently listed.")
        lines.append("")
        return

    current_letter = ""
    for package_name, package in active:
        first_letter = package_name[0].lower() if package_name else ""
        if first_letter != current_letter:
            current_letter = first_letter
            lines.append(f"### {current_letter.upper()}")
            lines.append("")

        latest_version = package.get("latestVersion", "")
        latest_entry = next(
            (entry for entry in package.get("versions", []) if entry.get("version") == latest_version),
            {},
        ) or {}
        older_versions = [entry for entry in package.get("versions", []) if entry.get("version") != latest_version]
        older_versions.sort(key=lambda item: item.get("validationDate", ""), reverse=True)

        install_command = latest_entry.get("installUrl", "")
        artifact = artifact_url(install_command)
        release_url = latest_entry.get("releaseUrl", "")
        pipeline_url = latest_entry.get("pipelineUrl", "")
        build_id = latest_entry.get("buildId", "")
        package_type = latest_entry.get("packageType", "")
        download_label = install_label_for(package_type)

        lines.append(f"#### `{package_name}`")
        lines.append(f"- **Latest version:** `{latest_version}`")
        lines.append(f"- **Validated:** {latest_entry.get('validationDate', '') or 'unknown'}")
        if package_type:
            lines.append(f"- **Package type:** {package_type}")
        if artifact:
            lines.append(f"- **{download_label}:** [download]({artifact})")
        if release_url:
            lines.append(f"- **Release notes:** [release]({release_url})")
        if pipeline_url:
            label = f"build #{build_id}" if build_id else "pipeline run"
            lines.append(f"- **Validation run:** [{label}]({pipeline_url})")
        lines.append("- **Quick command:**")
        lines.append("```text")
        lines.append(install_command or "pip install <package-url>")
        lines.append("```")

        if older_versions:
            lines.append(f"<details><summary>{len(older_versions)} older validated version(s)</summary>")
            lines.append("")
            for entry in older_versions:
                entry_artifact = artifact_url(entry.get("installUrl", ""))
                entry_release = entry.get("releaseUrl", "")
                entry_type = entry.get("packageType", "")
                entry_label = install_label_for(entry_type)
                lines.append(f"- **{entry.get('version', '')}** - Validated: {entry.get('validationDate', '')}")
                if entry_type:
                    lines.append(f"  - Package type: {entry_type}")
                if entry_artifact:
                    lines.append(f"  - {entry_label}: [download]({entry_artifact})")
                if entry_release:
                    lines.append(f"  - Release: [release]({entry_release})")
            lines.append("")
            lines.append("</details>")
        lines.append("")


def render_readme(manifest: dict) -> str:
    lines: list[str] = []
    lines.append("# Security Validated Python Packages")
    lines.append("")
    lines.append("This repository contains Python packages validated through automated security scanning and manual approval.")
    lines.append("")
    lines.append("> ⚠️ **Compatibility:** Windows x64 only. Python 3.13.x required.")
    lines.append("")
    lines.append("> The canonical package index is [`packages.json`](./packages.json). This README is generated from that manifest and should not be edited by hand.")
    lines.append("")
    render_quick_stats(manifest, lines)
    lines.append("## ✅ Requirements")
    lines.append("- **Python 3.13.x** (required for compatibility)")
    lines.append("- **Windows 64-bit** environment")
    lines.append("")
    render_quick_jump(manifest, lines)
    render_recently_validated(manifest, lines)
    render_active_packages(manifest, lines)
    render_deprecated_table(manifest, lines)
    lines.append("")
    append_usage_sections(lines)
    append_readme_footer(lines, manifest)
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