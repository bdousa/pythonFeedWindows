#!/usr/bin/env python3
"""Migrate legacy GitHub releases into this repo and rewrite manifest links.

This script walks ``packages.json`` for version entries whose ``installUrl`` or
``releaseUrl`` still references the legacy ``bdousa/pythonFeedWindows`` repo,
copies the matching GitHub releases (with all assets) into
``bdousa/pythonFeedWindows`` under prefixed legacy tags
(``legacy-{originalTag}``), rewrites the manifest entries to point at the new
target repo, and regenerates ``README.md`` from the updated manifest.

Validation metadata (``version``, ``validationDate``, ``packageType``,
``pipelineUrl``, ``buildId``, ``files``) is preserved exactly. Optional
``legacySource*`` traceability fields are added to migrated entries.

Requirements:
- GitHub CLI ``gh`` installed and authenticated (``gh auth login``).
- Run from any working directory; pass absolute or relative paths as needed.

Typical usage:
    # Inspect what would change
    python scripts/migrate_legacy_releases.py --dry-run

    # Apply: download legacy assets, create prefixed releases, rewrite manifest
    python scripts/migrate_legacy_releases.py --apply
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Allow ``import manifest_tools`` when invoked as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import manifest_tools  # noqa: E402


DEFAULT_SOURCE_OWNER = "bdousa"
DEFAULT_SOURCE_REPO = "pythonFeedWindows"
DEFAULT_TARGET_OWNER = "bdousa"
DEFAULT_TARGET_REPO = "pythonFeedWindows"
DEFAULT_LEGACY_PREFIX = "legacy-"


@dataclass
class LegacyEntry:
    """A version entry referencing the legacy repo and its mapped target."""

    package_name: str
    version: str
    source_tag: str
    target_tag: str
    primary_file: str
    files: list[str]
    install_url_old: str
    release_url_old: str
    install_url_new: str
    release_url_new: str
    is_latest: bool
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# gh CLI helpers
# ---------------------------------------------------------------------------


def _gh_path() -> str:
    found = shutil.which("gh")
    if not found:
        raise RuntimeError(
            "GitHub CLI 'gh' was not found on PATH. Install it from "
            "https://cli.github.com/ and run 'gh auth login' before --apply."
        )
    return found


def _run_gh(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    cmd = [_gh_path(), *args]
    result = subprocess.run(
        cmd,
        check=False,
        capture_output=capture,
        text=True,
    )
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        raise RuntimeError(
            f"gh command failed (exit {result.returncode}): {' '.join(args)}\n"
            f"stderr: {stderr}\nstdout: {stdout}"
        )
    return result


def ensure_gh_auth() -> None:
    result = _run_gh(["auth", "status"], check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "GitHub CLI is not authenticated. Run 'gh auth login' (with "
            "repo scope) before running with --apply."
        )


def gh_get_release(owner: str, repo: str, tag: str) -> Optional[dict]:
    result = _run_gh(
        ["api", f"repos/{owner}/{repo}/releases/tags/{tag}"],
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def gh_download_assets(
    owner: str,
    repo: str,
    tag: str,
    destination: Path,
) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    _run_gh(
        [
            "release",
            "download",
            tag,
            "--repo",
            f"{owner}/{repo}",
            "--dir",
            str(destination),
            "--skip-existing",
        ]
    )
    return sorted(p for p in destination.iterdir() if p.is_file())


def gh_create_release(
    owner: str,
    repo: str,
    tag: str,
    title: str,
    body: str,
    asset_paths: list[Path],
) -> None:
    notes_file = None
    try:
        notes_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".md",
            delete=False,
            encoding="utf-8",
        )
        notes_file.write(body)
        notes_file.close()
        args = [
            "release",
            "create",
            tag,
            "--repo",
            f"{owner}/{repo}",
            "--title",
            title,
            "--notes-file",
            notes_file.name,
        ]
        args.extend(str(path) for path in asset_paths)
        _run_gh(args)
    finally:
        if notes_file is not None:
            try:
                Path(notes_file.name).unlink()
            except OSError:
                pass


def gh_upload_assets(
    owner: str,
    repo: str,
    tag: str,
    asset_paths: list[Path],
    clobber: bool = False,
) -> None:
    if not asset_paths:
        return
    args = [
        "release",
        "upload",
        tag,
        "--repo",
        f"{owner}/{repo}",
    ]
    if clobber:
        args.append("--clobber")
    args.extend(str(path) for path in asset_paths)
    _run_gh(args)


# ---------------------------------------------------------------------------
# Manifest analysis
# ---------------------------------------------------------------------------


_PIP_URL_RE = re.compile(r"https?://\S+")


def extract_url(install_url: str) -> str:
    match = _PIP_URL_RE.search(install_url or "")
    return match.group(0).rstrip("'\")") if match else ""


def references_source(entry: dict, source_owner: str, source_repo: str) -> bool:
    needle = f"github.com/{source_owner}/{source_repo}/"
    return needle in (entry.get("installUrl") or "") or needle in (
        entry.get("releaseUrl") or ""
    )


def primary_asset_name(entry: dict) -> str:
    url = extract_url(entry.get("installUrl", ""))
    if url:
        tail = url.rstrip("/").split("/")[-1]
        if tail:
            return tail
    files = entry.get("files") or []
    return files[0] if files else ""


def build_legacy_entries(
    manifest: dict,
    source_owner: str,
    source_repo: str,
    target_owner: str,
    target_repo: str,
    legacy_prefix: str,
) -> list[LegacyEntry]:
    entries: list[LegacyEntry] = []
    packages = manifest.get("packages", {})
    for package_name in sorted(packages.keys(), key=str.lower):
        package = packages[package_name]
        latest_tag = package.get("latestReleaseTag", "")
        for version_entry in package.get("versions", []):
            if not references_source(version_entry, source_owner, source_repo):
                continue
            source_tag = version_entry.get("releaseTag", "")
            if not source_tag:
                continue
            target_tag = f"{legacy_prefix}{source_tag}"
            primary_file = primary_asset_name(version_entry)
            files = list(version_entry.get("files") or [])
            if primary_file and primary_file not in files:
                files.insert(0, primary_file)
            install_url_old = version_entry.get("installUrl", "")
            release_url_old = version_entry.get("releaseUrl", "")
            new_install_url = (
                f"pip install https://github.com/{target_owner}/{target_repo}/"
                f"releases/download/{target_tag}/{primary_file}"
                if primary_file
                else ""
            )
            new_release_url = (
                f"https://github.com/{target_owner}/{target_repo}/releases/tag/"
                f"{target_tag}"
            )
            entries.append(
                LegacyEntry(
                    package_name=package_name,
                    version=version_entry.get("version", ""),
                    source_tag=source_tag,
                    target_tag=target_tag,
                    primary_file=primary_file,
                    files=files,
                    install_url_old=install_url_old,
                    release_url_old=release_url_old,
                    install_url_new=new_install_url,
                    release_url_new=new_release_url,
                    is_latest=bool(latest_tag) and latest_tag == source_tag,
                )
            )
    return entries


# ---------------------------------------------------------------------------
# Manifest rewriting
# ---------------------------------------------------------------------------


def rewrite_manifest_entry(
    manifest: dict,
    legacy_entry: LegacyEntry,
    source_owner: str,
    source_repo: str,
    source_release: Optional[dict],
) -> None:
    package = manifest["packages"][legacy_entry.package_name]
    for version_entry in package.get("versions", []):
        if version_entry.get("releaseTag") != legacy_entry.source_tag:
            continue
        version_entry["releaseTag"] = legacy_entry.target_tag
        if legacy_entry.install_url_new:
            version_entry["installUrl"] = legacy_entry.install_url_new
        version_entry["releaseUrl"] = legacy_entry.release_url_new
        version_entry["legacySourceRepo"] = f"{source_owner}/{source_repo}"
        version_entry["legacySourceReleaseTag"] = legacy_entry.source_tag
        if source_release and source_release.get("published_at"):
            version_entry["legacySourcePublishedAt"] = source_release[
                "published_at"
            ]
        break
    if package.get("latestReleaseTag") == legacy_entry.source_tag:
        package["latestReleaseTag"] = legacy_entry.target_tag


# ---------------------------------------------------------------------------
# Release body builder
# ---------------------------------------------------------------------------


def build_release_body(
    legacy_entry: LegacyEntry,
    source_owner: str,
    source_repo: str,
    source_release: Optional[dict],
) -> str:
    lines = [
        "Legacy release copied into this repository for historical package validation.",
        "",
        f"- Package: `{legacy_entry.package_name}`",
        f"- Version: `{legacy_entry.version}`",
        f"- Legacy source tag: `{legacy_entry.source_tag}`",
    ]
    if source_release and source_release.get("published_at"):
        lines.append(
            f"- Original GitHub published at: {source_release['published_at']}"
        )
    lines.append("")
    lines.append(
        "Validation metadata is tracked in [packages.json](https://github.com/bdousa/pythonFeedWindows/blob/main/packages.json)."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main command
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description=(
            "Migrate legacy GitHub releases into the target repo and rewrite "
            "manifest links."
        )
    )
    parser.add_argument(
        "--manifest-path",
        default=str(repo_root / "packages.json"),
    )
    parser.add_argument(
        "--manifest-output",
        default=None,
        help="Defaults to --manifest-path.",
    )
    parser.add_argument(
        "--readme-output",
        default=str(repo_root / "README.md"),
    )
    parser.add_argument("--source-owner", default=DEFAULT_SOURCE_OWNER)
    parser.add_argument("--source-repo", default=DEFAULT_SOURCE_REPO)
    parser.add_argument("--target-owner", default=DEFAULT_TARGET_OWNER)
    parser.add_argument("--target-repo", default=DEFAULT_TARGET_REPO)
    parser.add_argument("--legacy-prefix", default=DEFAULT_LEGACY_PREFIX)
    parser.add_argument(
        "--workdir",
        default=None,
        help=(
            "Directory used to stage downloaded release assets. Defaults to a "
            "temporary directory cleaned up after the run."
        ),
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        help=(
            "Limit migration to the given package names. May be passed "
            "multiple times."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Report planned actions without contacting GitHub or writing files.",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Perform the migration.",
    )
    parser.add_argument(
        "--skip-readme",
        action="store_true",
        help="Do not regenerate README.md.",
    )
    return parser.parse_args(argv)


def filter_entries(
    entries: list[LegacyEntry],
    only: list[str],
) -> list[LegacyEntry]:
    if not only:
        return entries
    allowed = {name.lower() for name in only}
    return [entry for entry in entries if entry.package_name.lower() in allowed]


def report_plan(entries: list[LegacyEntry]) -> None:
    print(f"Planned migrations: {len(entries)}")
    for entry in entries:
        suffix = " [latest]" if entry.is_latest else ""
        print(
            f"  - {entry.package_name} {entry.version}: "
            f"{entry.source_tag} -> {entry.target_tag}{suffix}"
        )
        if entry.primary_file:
            print(f"      primary asset: {entry.primary_file}")
        if entry.files and entry.files != [entry.primary_file]:
            extras = [f for f in entry.files if f != entry.primary_file]
            if extras:
                print(f"      additional files in manifest: {', '.join(extras)}")


def preflight_checks(
    entries: list[LegacyEntry],
    source_owner: str,
    source_repo: str,
    target_owner: str,
    target_repo: str,
) -> tuple[dict[str, dict], list[str]]:
    """Validate that every source release exists and no target tag collides.

    Returns a mapping of source_tag -> source release JSON, and a list of
    blocking errors. The caller is expected to abort if errors are non-empty.
    """

    source_releases: dict[str, dict] = {}
    errors: list[str] = []
    for entry in entries:
        source = gh_get_release(source_owner, source_repo, entry.source_tag)
        if source is None:
            errors.append(
                f"missing source release: {source_owner}/{source_repo}@"
                f"{entry.source_tag} (package {entry.package_name})"
            )
            continue
        source_releases[entry.source_tag] = source
        existing_assets = {asset["name"] for asset in source.get("assets", [])}
        if entry.primary_file and entry.primary_file not in existing_assets:
            errors.append(
                f"primary asset missing on source release "
                f"{entry.source_tag}: {entry.primary_file}"
            )
        existing_target = gh_get_release(
            target_owner, target_repo, entry.target_tag
        )
        if existing_target is not None:
            errors.append(
                f"target tag already exists: {target_owner}/{target_repo}@"
                f"{entry.target_tag} (package {entry.package_name})"
            )
    return source_releases, errors


def migrate(
    entries: list[LegacyEntry],
    *,
    source_owner: str,
    source_repo: str,
    target_owner: str,
    target_repo: str,
    workdir: Path,
    manifest: dict,
) -> None:
    source_releases, errors = preflight_checks(
        entries,
        source_owner,
        source_repo,
        target_owner,
        target_repo,
    )
    if errors:
        print("Preflight failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        raise SystemExit(2)

    for entry in entries:
        source_release = source_releases.get(entry.source_tag)
        asset_dir = workdir / entry.target_tag
        print(
            f"-> {entry.package_name} {entry.version}: downloading from "
            f"{source_owner}/{source_repo}@{entry.source_tag}"
        )
        downloaded = gh_download_assets(
            source_owner,
            source_repo,
            entry.source_tag,
            asset_dir,
        )
        if entry.primary_file and not any(
            path.name == entry.primary_file for path in downloaded
        ):
            raise RuntimeError(
                f"primary asset {entry.primary_file} was not downloaded for "
                f"{entry.source_tag}"
            )
        title = f"{entry.package_name} {entry.version} (legacy)"
        body = build_release_body(
            entry, source_owner, source_repo, source_release
        )
        print(
            f"   creating {target_owner}/{target_repo}@{entry.target_tag} "
            f"with {len(downloaded)} asset(s)"
        )
        gh_create_release(
            target_owner,
            target_repo,
            entry.target_tag,
            title,
            body,
            downloaded,
        )
        rewrite_manifest_entry(
            manifest,
            entry,
            source_owner,
            source_repo,
            source_release,
        )


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    manifest_path = Path(args.manifest_path)
    manifest = manifest_tools.load_manifest(manifest_path)

    entries = build_legacy_entries(
        manifest,
        args.source_owner,
        args.source_repo,
        args.target_owner,
        args.target_repo,
        args.legacy_prefix,
    )
    entries = filter_entries(entries, args.only)

    if not entries:
        print("No manifest entries reference the legacy repo. Nothing to do.")
        return 0

    report_plan(entries)

    if args.dry_run:
        print("\nDry run complete. No GitHub or filesystem changes were made.")
        return 0

    ensure_gh_auth()

    cleanup_workdir = False
    if args.workdir:
        workdir = Path(args.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        workdir = Path(tempfile.mkdtemp(prefix="legacy-releases-"))
        cleanup_workdir = True

    try:
        migrate(
            entries,
            source_owner=args.source_owner,
            source_repo=args.source_repo,
            target_owner=args.target_owner,
            target_repo=args.target_repo,
            workdir=workdir,
            manifest=manifest,
        )
    finally:
        if cleanup_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    manifest["generatedAt"] = manifest_tools.utc_now_iso()
    manifest_output = Path(args.manifest_output or args.manifest_path)
    manifest_tools.write_manifest(manifest, manifest_output)

    if not args.skip_readme:
        readme_output = Path(args.readme_output)
        manifest_tools.write_bundle_requirements_files(manifest, readme_output.parent / "bundles")
        manifest_tools.write_text(
            readme_output, manifest_tools.render_readme(manifest)
        )

    print("\nMigration complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
