"""The container entrypoint must expose the M4 vulnerability CLI."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Source checkout keeps the script under docker/. The test image installs it
# as /usr/local/bin/asa and does not keep the docker/ directory.
ENTRYPOINT_CANDIDATES = (
    ROOT / "docker" / "entrypoint.sh",
    Path("/usr/local/bin/asa"),
)


def entrypoint_path() -> Path:
    for path in ENTRYPOINT_CANDIDATES:
        if path.is_file():
            return path
    raise AssertionError("ASA entrypoint was not found")


class TestDockerEntrypoint(unittest.TestCase):
    def test_help_lists_m4_vulnerability_command(self):
        script = entrypoint_path()
        result = subprocess.run(
            ["sh", str(script), "help"],
            check=False,
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("vulnerability <arguments>", result.stdout)
        self.assertIn("import-cves", result.stdout)
        self.assertIn("import-cpe-match", result.stdout)
        self.assertIn("assess", result.stdout)
        self.assertIn("app.vulnerability.cli", script.read_text(encoding="utf-8"))

    def test_vulnerability_help_reaches_m4_cli(self):
        result = subprocess.run(
            ["sh", str(entrypoint_path()), "vulnerability", "--help"],
            check=False,
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("import-cves", result.stdout)
        self.assertIn("import-cpe-match", result.stdout)
        self.assertIn("assess", result.stdout)

    def test_unknown_command_is_rejected(self):
        result = subprocess.run(
            ["sh", str(entrypoint_path()), "exploit"],
            check=False,
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown ASA command", result.stderr)


if __name__ == "__main__":
    unittest.main()
