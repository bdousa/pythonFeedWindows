import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/package-validation-windows.yml"


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell is required")
class PublishScannedPackagesTests(unittest.TestCase):
    def setUp(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        artifact = workflow.split("- name: Upload scan artifacts", 1)[1].split(
            "\n  manual-approval:", 1
        )[0]
        self.assertIn("            package_download/", artifact)
        publish = workflow.split("- name: Publish validated package", 1)[1]
        staging = publish.split("          if (-not (Test-Path 'publish_inputs/package_download'", 1)[1]
        staging = "          if (-not (Test-Path 'publish_inputs/package_download'" + staging
        staging = staging.split('          gh repo view ', 1)[0]
        self.script = "$ErrorActionPreference = 'Stop'\n" + textwrap.dedent(staging)

    def run_staging(self, directory, source_url="", source_sha256=""):
        env = os.environ.copy()
        env.update(PACKAGE_SOURCE_URL=source_url, PACKAGE_SOURCE_SHA256=source_sha256)
        return subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", self.script],
            cwd=directory,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_publishes_all_scanned_distributions_including_source_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            packages = Path(directory) / "publish_inputs/package_download"
            packages.mkdir(parents=True)
            for name in ("example-1.0-py3-none-any.whl", "dependency-1.0.tar.gz"):
                (packages / name).write_bytes(name.encode())
            result = self.run_staging(directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            published = Path(directory) / "package_publish"
            self.assertEqual(
                {p.name: p.read_bytes() for p in packages.iterdir()},
                {p.name: p.read_bytes() for p in published.iterdir()},
            )

    def test_missing_or_empty_scan_artifact_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_staging(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Rerun the security scan", result.stderr)
            (Path(directory) / "publish_inputs/package_download").mkdir(parents=True)
            result = self.run_staging(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No scanned package files", result.stderr)

    def test_source_wheel_checksum_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            packages = Path(directory) / "publish_inputs/package_download"
            packages.mkdir(parents=True)
            content = b"scanned wheel"
            (packages / "example-1.0-py3-none-any.whl").write_bytes(content)
            url = "https://example.com/example-1.0-py3-none-any.whl"
            result = self.run_staging(directory, url, hashlib.sha256(content).hexdigest())
            self.assertEqual(result.returncode, 0, result.stderr)
            result = self.run_staging(directory, url, "0" * 64)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("checksum changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
