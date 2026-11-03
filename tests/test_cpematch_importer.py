"""CPE Match 2.0 importer tests. Fixtures are synthetic."""

from __future__ import annotations

import gzip
import json
import sqlite3
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.helpers import FIXTURES

from app.vulnerability.cpematch_importer import import_cpe_matches
from app.vulnerability.feedio import FeedFormatError


def _doc(items: list[dict]) -> dict:
    return {
        "format": "NVD_CPE_Match_String",
        "version": "2.0",
        "timestamp": "2026-01-01T00:00:00.000",
        "matchStrings": [{"matchString": item} for item in items],
    }


def _match(criteria_id: str, names: list[str], **extra) -> dict:
    body = {
        "matchCriteriaId": criteria_id,
        "criteria": "cpe:2.3:a:example:item:*:*:*:*:*:*:*:*",
        "status": extra.pop("status", "Active"),
        "created": "2026-01-01T00:00:00.000",
        "lastModified": "2026-01-02T00:00:00.000",
        "matches": [{"cpeName": f"cpe:2.3:a:example:item:{name}:*:*:*:*:*:*:*", "cpeNameId": name} for name in names],
    }
    body.update(extra)
    return body


class TestCpeMatchImporter(unittest.TestCase):
    def test_valid_feed_preserves_ranges_and_multiple_names(self):
        with TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "intel.sqlite")
            stats = import_cpe_matches(str(FIXTURES / "cpematch_sample.json"), db)
            self.assertEqual(stats.inserted, 5)
            self.assertEqual(stats.inactive, 1)
            conn = sqlite3.connect(db)
            nginx = conn.execute("SELECT * FROM cpe_match_criteria WHERE match_criteria_id = 'CRIT-NGINX'").fetchone()
            self.assertEqual(nginx[1], "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
            self.assertEqual(nginx[2], "Active")
            self.assertEqual(nginx[3], "1.24.0")
            self.assertIsNone(nginx[4])
            self.assertIsNone(nginx[5])
            self.assertEqual(nginx[6], "1.25.0")
            names = conn.execute("SELECT cpe_name_id FROM cpe_match_entries WHERE match_criteria_id = 'CRIT-MULTI' ORDER BY 1").fetchall()
            self.assertEqual(len(names), 2)
            index = conn.execute("SELECT name FROM sqlite_master WHERE name = 'idx_cpe_match_name'").fetchone()
            self.assertIsNotNone(index)
            conn.close()

    def test_wrong_schema_version(self):
        doc = _doc([_match("CRIT-1", ["cpe-1"])])
        doc["version"] = "1.0"
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(FeedFormatError):
                import_cpe_matches(str(path), str(Path(tmp) / "intel.sqlite"))

    def test_missing_match_strings(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text('{"format":"NVD_CPE_Match_String","version":"2.0"}', encoding="utf-8")
            with self.assertRaises(FeedFormatError):
                import_cpe_matches(str(path), str(Path(tmp) / "intel.sqlite"))

    def test_duplicate_criteria_replaces_mappings(self):
        doc = _doc([_match("CRIT-1", ["cpe-old"]), _match("CRIT-1", ["cpe-new"])])
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            db = str(Path(tmp) / "intel.sqlite")
            path.write_text(json.dumps(doc), encoding="utf-8")
            stats = import_cpe_matches(str(path), db)
            self.assertEqual(stats.inserted, 1)
            self.assertEqual(stats.updated, 1)
            conn = sqlite3.connect(db)
            ids = [row[0] for row in conn.execute("SELECT cpe_name_id FROM cpe_match_entries")]
            self.assertEqual(ids, ["cpe-new"])
            conn.close()

    def test_duplicate_cpe_uuid_is_counted_once(self):
        body = _match("CRIT-1", ["cpe-1", "cpe-1"])
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            db = str(Path(tmp) / "intel.sqlite")
            path.write_text(json.dumps(_doc([body])), encoding="utf-8")
            stats = import_cpe_matches(str(path), db)
            self.assertEqual(stats.duplicate_cpes, 1)
            conn = sqlite3.connect(db)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM cpe_match_entries").fetchone()[0], 1)
            conn.close()

    def test_missing_and_inactive_mappings(self):
        doc = _doc(
            [
                _match("CRIT-EMPTY", [], status="Active"),
                _match("CRIT-DEAD", ["cpe-1"], status="Inactive"),
            ]
        )
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            db = str(Path(tmp) / "intel.sqlite")
            path.write_text(json.dumps(doc), encoding="utf-8")
            stats = import_cpe_matches(str(path), db)
            self.assertGreaterEqual(stats.missing_mappings, 1)
            self.assertEqual(stats.inactive, 1)
            conn = sqlite3.connect(db)
            status = conn.execute("SELECT status FROM cpe_match_criteria WHERE match_criteria_id = 'CRIT-DEAD'").fetchone()[0]
            empty = conn.execute("SELECT COUNT(*) FROM cpe_match_entries WHERE match_criteria_id = 'CRIT-EMPTY'").fetchone()[0]
            conn.close()
            self.assertEqual(status, "Inactive")
            self.assertEqual(empty, 0)

    def test_multiple_chunks_gzip_and_zip(self):
        with TemporaryDirectory() as tmp:
            folder = Path(tmp) / "chunks"
            folder.mkdir()
            (folder / "a.json").write_text(json.dumps(_doc([_match("CRIT-A", ["cpe-a"])])), encoding="utf-8")
            with gzip.open(folder / "b.json.gz", "wt", encoding="utf-8") as handle:
                json.dump(_doc([_match("CRIT-B", ["cpe-b"])]), handle)
            zip_path = folder / "c.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("c1.json", json.dumps(_doc([_match("CRIT-C", ["cpe-c"])])))
                archive.writestr("c2.json", json.dumps(_doc([_match("CRIT-D", [f"cpe-{i}" for i in range(600)])])))
            stats = import_cpe_matches(str(folder), str(Path(tmp) / "intel.sqlite"))
            self.assertEqual(stats.inserted, 4)
            conn = sqlite3.connect(str(Path(tmp) / "intel.sqlite"))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM cpe_match_entries WHERE match_criteria_id = 'CRIT-D'").fetchone()[0], 600)
            conn.close()

    def test_repeatable_import(self):
        with TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "intel.sqlite")
            source = str(FIXTURES / "cpematch_sample.json")
            import_cpe_matches(source, db)
            again = import_cpe_matches(source, db)
            self.assertEqual(again.inserted, 0)
            self.assertEqual(again.updated, 5)
            conn = sqlite3.connect(db)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM cpe_match_criteria").fetchone()[0], 5)
            conn.close()

    def test_transaction_rollback_keeps_previous_file(self):
        with TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            bad = Path(tmp) / "bad.json"
            db = str(Path(tmp) / "intel.sqlite")
            good.write_text(json.dumps(_doc([_match("CRIT-A", ["cpe-a"])])), encoding="utf-8")
            bad.write_text('{"format":"NVD_CPE_Match_String","version":"1.0","matchStrings":[]}', encoding="utf-8")
            import_cpe_matches(str(good), db)
            with self.assertRaises(FeedFormatError):
                import_cpe_matches(str(bad), db)
            conn = sqlite3.connect(db)
            self.assertEqual(conn.execute("SELECT match_criteria_id FROM cpe_match_criteria").fetchone()[0], "CRIT-A")
            conn.close()


if __name__ == "__main__":
    unittest.main()
