# Python Package Feed Pipeline

This repository manages a Windows-focused Python package feed. Packages are scanned, reviewed, published as GitHub Releases, and tracked in `packages.json`. The workflows in `.github/workflows/` are the operational entry points.

## Purpose

The pipeline exists to:

- validate Python packages before they are approved for internal use
- publish approved artifacts as GitHub Releases in this repository
- keep `packages.json`, `README.md`, `bundles/`, and `audit-baselines/` aligned with the approved state
- provide a basic approval trail through workflow artifacts, release notes, and manifest history

## Key Features

- automated dependency vulnerability scanning with Snyk
- automated source code scanning with Snyk Code
- package metadata analysis from PyPI
- license posture checks
- Windows compatibility checks against package classifiers
- manual approval before publishing
- automated publishing to GitHub Releases
- manifest, README, and bundle generation from approved results

## Repository Components

Core files and folders:

- `packages.json`: canonical manifest of approved packages and lifecycle state
- `README.md`: generated catalog for consumers; do not edit by hand
- `bundles/`: generated requirements-style bundle files for multi-artifact installs
- `audit-baselines/`: persisted vulnerability baselines used by the nightly audit
- `scripts/manifest_tools.py`: updates the manifest, bundle files, and generated README
- `scripts/build_review_report.py`: compiles the manual review packet from scan output and package metadata
- `scripts/build_ai_security_review.py`: adds an advisory AI summary to the approval report when Azure AI Foundry is configured
- `scripts/nightly_rescan.py`: rescans active packages and refreshes vulnerability baselines

## Workflow Overview

There are four workflows:

1. `package-validation-windows.yml`
2. `bulk-package-validation.yml`
3. `nightly-package-audit.yml`
4. `package-lifecycle.yml`

### 1. Package Validation Workflow

Workflow: `.github/workflows/package-validation-windows.yml`

This is the main approval pipeline for a new package or a new version of an existing package.

High-level flow:

1. Normalize the requested package name.
2. Create a Python 3.13 virtual environment on a Windows runner.
3. Download the requested package from PyPI and install its dependency set.
4. Extract package contents for source analysis.
5. Run Snyk dependency scanning and Snyk code scanning.
6. Build a preview of the resulting `packages.json` and `README.md` changes.
7. Build a structured approval report in JSON and Markdown.
8. Optionally run an advisory AI security review and append it to the report.
9. Upload artifacts for human review.
10. Pause on the `PackageApproval` environment.
11. If approved and `publish_to_feed=true`, publish release artifacts and update the manifest.

Inputs:

- `package_name`: required package name
- `package_version`: optional version; use `latest` for newest upstream version
- `publish_to_feed`: if `false`, the workflow stops after review artifacts and approval; no release or manifest update occurs

Outputs and side effects:

- workflow artifacts containing scan output and approval reports
- a GitHub Release tagged like `<package>-v<version>` when publishing is enabled
- uploaded package files attached to the release
- updated `packages.json`
- regenerated `README.md`
- regenerated bundle file(s) under `bundles/` when the validated entry has multiple installable artifacts

### 2. Bulk Package Validation Workflow

Workflow: `.github/workflows/bulk-package-validation.yml`

This workflow is a dispatcher. It does not perform scanning itself. It triggers one `package-validation-windows.yml` run per package.

Use it when a batch of packages needs to be validated with the same settings.

Inputs:

- `publish_to_feed`: forwarded to each per-package validation run
- `package_version`: forwarded to each run (blank sets version to latest)
- `package_list`: comma-separated list of package names
- `delay_seconds`: optional delay between dispatches to reduce API throttling (default set to 5)

Notes:

- this workflow uses the built-in GitHub token to call `gh workflow run`
- each dispatched run still waits on the `PackageApproval` environment before publishing
- if `publish_to_feed=false`, the batch acts as a dry run for scanning and review generation

### 3. Nightly Package Audit Workflow

Workflow: `.github/workflows/nightly-package-audit.yml`

This workflow rescans active packages already present in the feed and compares the findings to the stored baselines in `audit-baselines/`.

High-level flow:

1. Run on a nightly schedule or manually.
2. Install and authenticate Snyk.
3. Call `scripts/nightly_rescan.py`.
4. Rescan every active package, or a single named package when manually targeted.
5. Compare current findings to the saved baseline for each package.
6. Refresh baseline JSON files when scans succeed.
7. Commit baseline changes back to `main` when the run is the full nightly pass.
8. Upload the markdown and JSON audit report as workflow artifacts.

Inputs:

- `package`: optional manual override to scan only one package

Important behavior:

- only active packages are scanned
- deactivated or deprecated packages are skipped
- targeted manual runs do not commit baseline changes back to the repository
- the workflow rebases on `main` before pushing refreshed baselines

### 4. Package Lifecycle Workflow

Workflow: `.github/workflows/package-lifecycle.yml`

This workflow changes the lifecycle state of a package already tracked in `packages.json`.

Supported actions:

- `deprecate`
- `restore`
- `delete`

Inputs:

- `package_name`: required manifest key
- `lifecycle_action`: required action
- `reason`: optional deprecation or deletion reason
- `purge_release_artifacts`: for delete only; when true, also removes tracked GitHub releases and tags

High-level flow:

1. Optionally collect the tracked release tags from the manifest before delete.
2. Call `scripts/manifest_tools.py set-lifecycle` to update `packages.json` and regenerate `README.md`.
3. Optionally purge the tracked GitHub Release records and tags.
4. Commit the lifecycle change and push it to `main`.

Use this workflow when a package should no longer be installable from the approved feed, or when a previous lifecycle decision needs to be reversed.

## Standard Approval Path

Normal package approval follows this path:

1. Trigger `package-validation-windows.yml` for a package and version.
2. Review the uploaded artifacts and the step summary.
3. Approve or reject at the `PackageApproval` environment gate.
4. If approved and `publish_to_feed=true`, the publish job creates or updates the GitHub Release and commits manifest updates.
5. Consumers install from the release URL or the generated bundle file.

### Stage Model

The main validation pipeline still breaks cleanly into three stages:

1. Security scan stage
2. Manual approval stage
3. Publish artifact stage

That older framing is still useful because it matches how the current workflow is structured:

- `security-scan` gathers evidence and builds the approval packet
- `manual-approval` pauses on the `PackageApproval` environment
- `publish-artifact` only runs after approval and only when `publish_to_feed=true`

## Secrets and Credentials

This repository uses GitHub Actions secrets plus built-in GitHub tokens.

### Secret Inventory

`SNYK_TOKEN`

- Source: GitHub repository secret
- Used by: `package-validation-windows.yml`, `nightly-package-audit.yml`
- Purpose: authenticates the Snyk CLI
- Required for: dependency scanning and code scanning

`SNYK_ORG`

- Source: GitHub repository secret
- Used by: `package-validation-windows.yml`, `nightly-package-audit.yml`
- Purpose: selects the Snyk organization for test and monitor operations
- Required for: all Snyk-backed scans in the workflows

`REPO_WRITE_TOKEN`

- Source: GitHub repository secret
- Used by: `package-validation-windows.yml`, `package-lifecycle.yml`, `nightly-package-audit.yml`
- Purpose: pushes commits to `main`, manages releases, and deletes release tags when needed
- Expected access: Contents read/write and Metadata read on this repository; release management must also be allowed by the token's scope
- Required for:
  - publishing validated packages
  - committing lifecycle changes
  - purging release artifacts
  - non-default pushes from nightly baseline refreshes

`AZURE_AI_FOUNDRY_API_KEY`

- Source: GitHub repository secret
- Used by: `package-validation-windows.yml`
- Purpose: authenticates the Azure AI Foundry advisory review call
- Required for: AI review only
- Optional: yes; the workflow fails open and records `unavailable` when it is not set

`AZURE_AI_FOUNDRY_ENDPOINT`

- Source: GitHub repository secret
- Used by: `package-validation-windows.yml`
- Purpose: Azure AI Foundry agent endpoint. This may be the full agent Responses endpoint, the agent endpoint, or the project endpoint when `AZURE_AI_FOUNDRY_AGENT_NAME` is also set.
- Required for: AI review only
- Optional: yes; the workflow fails open and records `unavailable` when it is not set

`AZURE_AI_FOUNDRY_AGENT_NAME`

- Source: GitHub repository secret
- Used by: `package-validation-windows.yml`
- Purpose: agent name used to build the Responses endpoint when `AZURE_AI_FOUNDRY_ENDPOINT` is the project endpoint
- Required for: AI review only when the endpoint is the project endpoint
- Optional: yes when `AZURE_AI_FOUNDRY_ENDPOINT` already points at the agent or full agent Responses endpoint

`AZURE_AI_FOUNDRY_API_VERSION`

- Source: GitHub repository secret
- Used by: `package-validation-windows.yml`
- Purpose: API version for the agent Responses call
- Required for: no; defaults to `v1`
- Optional: yes

`GITHUB_TOKEN`

- Source: built-in GitHub Actions token automatically provided to each run
- Used by:
  - `bulk-package-validation.yml` through `github.token` for workflow dispatches
  - `package-validation-windows.yml` when building the review report's GitHub metadata
- Purpose:
  - trigger other workflows in the same repository
  - query GitHub repository metadata for the approval report
- Notes: this is not manually stored as a repository secret in this pipeline

### Where These Secrets Come From

For this repository, the expected sources are:

1. GitHub repository secrets for `SNYK_TOKEN`, `SNYK_ORG`, `REPO_WRITE_TOKEN`, `AZURE_AI_FOUNDRY_API_KEY`, `AZURE_AI_FOUNDRY_ENDPOINT`, and any optional Foundry agent settings needed by the chosen endpoint shape
2. GitHub Actions built-in run token for `GITHUB_TOKEN`
3. GitHub environment protection rules on `PackageApproval` for human approval, rather than a secret value

If a secret is missing, the workflow usually fails early with an explicit error message. The AI review step is the exception; it records an unavailable status and allows the pipeline to continue.

## Approval and Rejection Guidelines

Keep this policy basic for now and refine it later.

### Reviewer Checklist

Before approving or rejecting, review at least these items:

- the recommendation and reasons in `review_output/approval-report.md`
- dependency findings and source code findings
- package metadata such as license, release age, and OS compatibility posture
- the manifest preview to confirm the package/version being published is the one requested
- the AI review summary, if present, as advisory input rather than the final decision
- the package's dependency footprint to catch obviously excessive or unexpected transitive installs

### Approve When

- the package is actually needed for a supported business use case
- the package appears compatible with Windows and Python 3.13
- there are no critical findings in Snyk dependency or code results
- any high findings have been reviewed and accepted with a documented reason
- the license does not appear restrictive for internal use
- the package is maintained enough that it is not obviously abandoned
- the approval report looks internally consistent with the package requested
- the dependency set looks reasonable for the package's stated purpose

### Reject When

- the package is not needed or has no clear business justification
- the package is not compatible with Windows or Python 3.13
- critical vulnerabilities are present
- high-severity findings exist and no acceptable risk rationale is available
- the package license is clearly incompatible or unclear enough to block approval
- the package looks abandoned, suspicious, or materially inconsistent with the request
- the workflow artifacts are incomplete or the report cannot support a safe decision
- the dependency graph is excessive, suspicious, or clearly inconsistent with the expected package behavior

### Escalate for Manual Review When

- the package has high findings but the exploitability is unclear
- the package uses native extensions or platform-specific wheels and compatibility is uncertain
- the package only ships a source distribution and the runtime risk is not clear
- license metadata is missing or ambiguous
- the repository or release history looks stale, but not clearly disqualifying
- the AI review disagrees with the base recommendation or has low confidence
- business need exists, but the package introduces risk that should be explicitly accepted outside the normal approval path

### Decision Notes

When you approve a package with any non-trivial concern, document the reason clearly enough that a later reviewer can understand:

- what was found
- why the finding was considered acceptable in context
- whether the decision depends on business need, compensating controls, or follow-up monitoring

## How to Use the Workflows

### Validate a Single Package

Use `package-validation-windows.yml`.

Recommended defaults:

- `package_version=latest`
- `publish_to_feed=false` for the first pass if you want to review results before allowing publication

Typical usage:

1. Open Actions in GitHub.
2. Run `Package Validation Windows`.
3. Enter the package name.
4. Choose a version or leave `latest`.
5. Set `publish_to_feed`.
6. Review the generated artifact set and step summary.
7. Approve or reject in the `PackageApproval` environment.

During review, also check whether the dependency scan was uploaded to the Snyk organization configured by `SNYK_ORG`. The workflow runs `snyk monitor` for the dependency set so the package can be tracked in Snyk outside the single workflow run.

### Validate Multiple Packages

Use `bulk-package-validation.yml`.

Recommended defaults:

- start with `publish_to_feed=false`
- provide a comma-separated package list
- keep a small dispatch delay to avoid API bursts

This is best for queued onboarding work where each package still receives an individual review packet.

### Run the Nightly Audit Manually

Use `nightly-package-audit.yml`.

Common cases:

- validate that baselines still reflect the current dependency risk
- scan one package on demand by filling the optional `package` input
- confirm whether new vulnerabilities have appeared since the last baseline

### Change Lifecycle State

Use `package-lifecycle.yml`.

Recommended handling:

- `deprecate` when the package should remain visible for audit purposes but no longer be approved for use
- `restore` when a deprecated package is being reinstated
- `delete` only when the manifest entry should be removed entirely
- `purge_release_artifacts=true` only after confirming that no consumers still depend on those release artifacts

## Review Artifacts to Inspect

For a package validation run, the main review artifacts are:

- `review_output/approval-report.md`: human-readable review packet
- `review_output/approval-report.json`: structured report used by downstream tooling and the AI review
- `preview_output/packages.preview.json`: preview of the manifest entry that would be written
- `preview_output/README.preview.md`: preview of the generated README changes
- `snyk_dependencies.json` and `snyk_dependencies_summary.txt`: dependency findings
- `snyk_code.json` and `snyk_code_summary.txt`: source code findings
- `requirements.txt`: resolved dependency set that was scanned

The approval report itself is intended to consolidate the main decision inputs from the older process into one place:

- package metadata from PyPI
- license posture and OS compatibility posture
- dependency overview from the scanned environment
- structured dependency vulnerability findings
- structured source code findings
- GitHub repository metadata when discoverable
- optional AI advisory review output

For the nightly audit, inspect:

- `audit_output/nightly-audit.md`
- `audit_output/nightly-audit.json`
- changed files in `audit-baselines/`

## Operational Notes

- The feed targets Windows x64 and Python 3.13.
- The nightly audit script reads `packages.json` using `utf-8-sig` so it tolerates a BOM.
- The nightly scan uses a temporary virtual environment per package and points Snyk at that environment's Python interpreter.
- The bulk dispatcher passes `--repo` to `gh workflow run`, which avoids repository discovery issues in non-checked-out contexts.
- `README.md` is generated output. Treat `packages.json` and the workflows/scripts as the source of truth.

## Security Controls

Current controls implemented by the pipeline include:

- Snyk dependency scanning against the resolved installed dependency set
- Snyk Code scanning against extracted package contents
- license posture review based on PyPI metadata and classifiers
- OS compatibility review based on package classifiers
- GitHub metadata enrichment for repository health context when source repository links are available
- mandatory human approval before publication

### OS Compatibility Policy

This part of the old documentation needed correction. The current implementation does not automatically block Windows-specific packages.

The actual policy today is:

- approve OS posture when the package is marked `OS Independent`
- approve OS posture when the package explicitly declares `Microsoft :: Windows`
- require review when no OS classifiers are present
- block only packages that declare only non-Windows operating systems

## Troubleshooting

Common cases to watch for:

### Package Not Found on PyPI

- Symptom: the package metadata fetch or `pip download` fails because the package name or version does not exist
- Response: verify the exact PyPI package name and the requested version

### Missing Secret or Authentication Failure

- Symptom: the workflow fails early with messages about `SNYK_TOKEN`, `SNYK_ORG`, or `REPO_WRITE_TOKEN`
- Response: confirm the repository secrets exist and that the token has the expected access

### Publish Permission Failure

- Symptom: release creation, upload, or push to `main` fails during `publish-artifact`
- Response: verify that `REPO_WRITE_TOKEN` can read/write contents and manage releases in this repository

### OS Compatibility Unclear

- Symptom: the approval report marks OS compatibility as review-needed because classifiers are missing or ambiguous
- Response: inspect the package's wheel or source distribution mix and confirm whether the package can actually support the Windows feed

## Best Practices

### For Reviewers

- review the complete approval packet, not only the top-line recommendation
- pay special attention to critical and high findings
- weigh business need against the package's actual risk profile
- document non-obvious approval reasoning for later auditability
- escalate when the evidence is incomplete or contradictory

### For Pipeline Maintenance

- keep repository secrets current and validated
- monitor the Snyk organization for new findings in already-approved packages
- revisit approval criteria as package mix and risk tolerance evolve
- keep release and manifest automation aligned so approved artifacts remain traceable

## Suggested Future Improvements

Areas to tighten in later iterations:

- define a more explicit risk-acceptance template for high findings
- document named owners or approver groups for `PackageApproval`
- capture retention expectations for workflow artifacts and release notes
- add examples of approved and rejected packages
- document rollback handling for a published package that later fails nightly audit