"""Dictionary importer tests. The fixture is synthetic, not an NVD download."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import FIXTURES

from app.cpe.importer import FeedFormatError, import_dictionary
from app.cpe.store import connect


SAMPLE = FIXTURES / "cpe_dictionary_sample.json"


def _count(db_path: Path) -> int:
    db = connect(str(db_path))
    try:
        return db.execute("SELECT COUNT(*) FROM cpe_entries").fetchone()[0]
    finally:
        db.close()


class TestImporter(unittest.TestCase):
    def test_sample_and_idempotent_reimport(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "dict.sqlite"
            first = import_dictionary(str(SAMPLE), str(db_path))
            self.assertEqual(first.imported, 6)
            self.assertEqual(first.deprecated, 1)
            self.assertEqual(first.invalid, 0)
            self.assertEqual(first.source_timestamp, "2026-01-01T00:00:00.000")
            second = import_dictionary(str(SAMPLE), str(db_path))
            self.assertEqual(second.duplicates, 6)
            self.assertEqual(second.imported, 0)
            self.assertEqual(_count(db_path), 6)

    def test_wrong_version_rolls_back(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "chunks"
            src.mkdir()
            good = json.loads(SAMPLE.read_text(encoding="utf-8"))
            (src / "a.json").write_text(json.dumps(good), encoding="utf-8")
            bad = {"format": "NVD_CPE", "version": "1.0", "products": []}
            (src / "b.json").write_text(json.dumps(bad), encoding="utf-8")
            db_path = Path(tmp) / "dict.sqlite"
            with self.assertRaises(FeedFormatError):
                import_dictionary(str(src), str(db_path))
            self.assertEqual(_count(db_path), 0)
            db = connect(str(db_path))
            meta = db.execute("SELECT COUNT(*) FROM dictionary_metadata").fetchone()[0]
            db.close()
            self.assertEqual(meta, 0)

    def test_invalid_cpe_and_missing_fields_are_skipped(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text(
                json.dumps(
                    {
                        "format": "NVD_CPE",
                        "version": "2.0",
                        "timestamp": "2026-01-02T00:00:00.000",
                        "products": [
                            {"cpe": {"cpeName": "nope", "cpeNameId": "bad-name"}},
                            {"cpe": {"cpeNameId": "missing-name"}},
                            {"not_cpe": True},
                            {
                                "cpe": {
                                    "deprecated": False,
                                    "cpeName": "cpe:2.3:a:ex:kept:1:*:*:*:*:*:*:*",
                                    "cpeNameId": "77777777-7777-7777-7777-777777777777",
                                    "titles": [{"title": "kept", "lang": "en"}],
                                }
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            db_path = Path(tmp) / "dict.sqlite"
            stats = import_dictionary(str(path), str(db_path))
            self.assertEqual(stats.invalid, 1)
            self.assertEqual(stats.skipped, 2)
            self.assertEqual(stats.imported, 1)

    def test_duplicate_uuid_inside_one_feed(self):
        with TemporaryDirectory() as tmp:
            body = {
                "deprecated": False,
                "cpeName": "cpe:2.3:a:ex:dup:1:*:*:*:*:*:*:*",
                "cpeNameId": "88888888-8888-8888-8888-888888888888",
                "titles": [{"title": "dup", "lang": "en"}],
            }
            path = Path(tmp) / "feed.json"
            path.write_text(
                json.dumps({"format": "NVD_CPE", "version": "2.0", "products": [{"cpe": body}, {"cpe": body}]}),
                encoding="utf-8",
            )
            stats = import_dictionary(str(path), str(Path(tmp) / "dict.sqlite"))
            self.assertEqual(stats.imported, 1)
            self.assertEqual(stats.duplicates, 1)

    def test_two_chunks(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "chunks"
            src.mkdir()
            (src / "01.json").write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
            (src / "02.json").write_text(
                json.dumps(
                    {
                        "format": "NVD_CPE",
                        "version": "2.0",
                        "timestamp": "2026-02-01T00:00:00.000",
                        "products": [
                            {
                                "cpe": {
                                    "deprecated": False,
                                    "cpeName": "cpe:2.3:a:ex:extra:2:*:*:*:*:*:*:*",
                                    "cpeNameId": "99999999-9999-9999-9999-999999999999",
                                    "titles": [{"title": "extra", "lang": "en"}],
                                }
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stats = import_dictionary(str(src), str(Path(tmp) / "dict.sqlite"))
            self.assertEqual(stats.files, 2)
            self.assertEqual(stats.imported, 7)
            self.assertEqual(stats.source_timestamp, "2026-02-01T00:00:00.000")


if __name__ == "__main__":
    unittest.main()
