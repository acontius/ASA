"""The release archive must not contain scan data or local databases."""

from __future__ import annotations

import tarfile
import unittest
from tempfile import TemporaryDirectory

from tools.build_release_archive import build


class TestReleaseArchive(unittest.TestCase):
    def test_archive_is_source_only(self):
        with TemporaryDirectory() as tmp:
            archive, checksum = build(__import__("pathlib").Path(tmp))
            self.assertTrue(checksum.exists())
            with tarfile.open(archive, "r:gz") as handle:
                names = handle.getnames()
            self.assertIn("app/vulnerability/cli.py", names)
            self.assertIn("tests/fixtures/cve_feed_sample.json", names)
            self.assertIn("LICENSE", names)
            blob = "\n".join(names)
            self.assertNotIn("PartOfMe.json", blob)
            self.assertNotIn(".sqlite", blob)
            self.assertFalse(any(name.startswith("out/") or "/out/" in name for name in names))
            self.assertFalse(any(name.startswith("Data/") for name in names))


if __name__ == "__main__":
    unittest.main()
